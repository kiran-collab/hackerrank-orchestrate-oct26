"""Per-case audit: resolve identity, link resources, reconstruct state at audit_at, plan steps."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from ghost_audit.extract import RESOURCE_RE, Corpus, Record, activity_records, build_corpus, parse_ts, prefix_of, system_for
from ghost_audit.identity import IdentityIndex, Subject
from ghost_audit.intent import classify
from ghost_audit.observe import Observation, interpret
from ghost_audit.policy import DEFAULT_CATEGORY, OP_ORDER, OP_PHASE, OP_STATE, PHASE_ORDER, TREATMENTS, Policy

WORKFLOW_SLACK = timedelta(hours=1)
# Window candidates no evidence file corroborates must be this many times closer in time to win.
UNCORROBORATED_FACTOR = 3.0
RETENTION_PREFIXES = {"audit_record", "legal_hold"}


@dataclass
class Case:
    case_id: str
    email: str
    requested_at: datetime
    reported_status: str
    reported_at: datetime
    audit_at: datetime
    request_text: str


@dataclass
class ResourceState:
    resource_id: str
    system: str
    state: str | None
    evidence_id: str
    observed_at: datetime | None
    category: str
    link_reasons: set[str] = field(default_factory=set)
    retain_until: datetime | None = None  # retention period / legal hold end, when the evidence states one


@dataclass
class CaseResult:
    case: Case
    status: str
    steps: list[dict]
    subject: str | None = None
    resources: list[ResourceState] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def load_cases(path: Path) -> list[Case]:
    with open(path, newline="", encoding="utf-8") as f:
        out = []
        for r in csv.DictReader(f):
            req, rep, aud = (parse_ts(r[k]) for k in ("requested_at", "reported_at", "audit_at"))
            assert req and rep and aud, r["case_id"]
            out.append(Case(r["case_id"], r["email"].strip(), req, r["reported_status"].strip(), rep, aud,
                            r["request_text"]))
    return out


class Auditor:
    def __init__(self, dataset: Path, image_texts: dict[str, str] | None = None, intent_fallback=None):
        self.dataset = dataset
        self.identity = IdentityIndex(dataset)
        self.policy = Policy(dataset)
        self.corpus: Corpus = build_corpus(dataset, image_texts)
        self.activities: list[Record] = activity_records(dataset)
        self.intent_fallback = intent_fallback  # callable(text) -> 'DELETE'|'NOT_DELETE', e.g. an LLM
        self.observations: list[Observation] = [interpret(r) for r in self.corpus.records]
        for o in self.observations:
            doc = o.record.fields.get("_document_text")
            if isinstance(doc, str):
                doc_tokens = _tokens_of_text(doc)
                subjects = {u for u in self.identity.owners_of(doc_tokens)}
                emails = {t for t in doc_tokens if t.startswith("email:")}
                unowned = {t for t in emails if not self.identity.owner.get(t)}
                if len(subjects) == 1 and not unowned:
                    # Single-subject document (every email in it is this subject's): every ID concerns them.
                    o.tokens |= doc_tokens
                    o.pii_tokens |= {t for t in doc_tokens if not t.startswith("user:")}
                    if o.state == "REDACTED" and o.record.prefix in ("support", "tombstone"):
                        o.state = "EXPOSED"
        self.by_resource: dict[str, list[Observation]] = {}
        for o in self.observations:
            self.by_resource.setdefault(o.record.resource_id, []).append(o)
        self.acts_by_resource: dict[str, list[Record]] = {}
        for a in self.activities:
            self.acts_by_resource.setdefault(a.resource_id, []).append(a)
        # Which subjects each resource is tied to by direct identifiers (for exclusion of decoys).
        self._strong_cache: dict[tuple, dict[str, set[str]]] = {}
        self._weak: dict[str, set[str]] = {}
        self._ambiguous: dict[str, set[str]] = {}
        self.resource_owners: dict[str, set[str]] = {}
        for o in self.observations:
            self.resource_owners.setdefault(o.record.resource_id, set()).update(self.identity.owners_of(o.tokens))
        for a in self.activities:
            if a.fields.get("event_type") == "LINK_RESOURCE_IDENTITY":
                owners = self.identity.owners_of(_tokens_of_text(a.fields.get("details", "")))
                self.resource_owners.setdefault(a.resource_id, set()).update(owners)

    # ------------------------------------------------------------ linking

    def strong_links(self, subject: Subject, cutoff: datetime) -> dict[str, set[str]]:
        """Resources tied to the subject by an exact identifier in evidence available by `cutoff`
        (the case's audit_at). Exception: retention records (security audit, legal hold) are
        immutable, so a later capture still proves they existed and belong to the subject."""
        ck = (subject.user_id, cutoff)
        if ck in self._strong_cache:
            return self._strong_cache[ck]
        toks = subject.tokens()
        linked: dict[str, set[str]] = {}
        for o in self.observations:
            if o.record.source_time > cutoff and o.record.prefix not in RETENTION_PREFIXES:
                continue
            hit = o.tokens & toks
            if hit and self.identity.owners_of(hit) == {subject.user_id}:
                linked.setdefault(o.record.resource_id, set()).add(f"identifier:{o.record.source_id}")
        for a in self.activities:
            if a.fields.get("event_type") == "LINK_RESOURCE_IDENTITY" and a.observed_at <= cutoff:
                if self.identity.owners_of(_tokens_of_text(a.fields.get("details", ""))) == {subject.user_id}:
                    linked.setdefault(a.resource_id, set()).add(f"catalog:{a.source_id}")
        # Cross-references (e.g. a search document's source_resource_id) extend the link graph.
        for rid in list(linked):
            for o in self.by_resource.get(rid, []):
                if o.record.source_time > cutoff:
                    continue
                for k, v in o.record.fields.items():
                    if k.endswith("resource_id") and k != "resource_id" and isinstance(v, str) and RESOURCE_RE.fullmatch(v):
                        linked.setdefault(v, set()).add(f"reference:{o.record.source_id}")
        self._strong_cache[ck] = linked
        return linked

    def workflow_candidates(self, case: Case) -> set[str]:
        """Resources the deletion worker touched between request and report for this case."""
        lo, hi = case.requested_at, case.reported_at + WORKFLOW_SLACK
        return {a.resource_id for a in self.activities
                if a.fields.get("source_system") == "deletion_worker" and lo <= a.observed_at <= hi}

    def prepare(self, cases: list[Case]) -> None:
        """Global one-owner-per-resource assignment of deletion-workflow resources.

        Identifier links are authoritative. Resources the deletion worker touched without any
        identifier (a deleted account, an anonymized analytics row) are attributed through the
        worker's batch windows: every authorized case claims the resources processed between its
        request and its report. Claims are resolved as a min-cost one-to-one matching:

          cost = |worker event - case.reported_at|  (+ penalty if no evidence corroborates it)

        Accounts: each subject without an identifier-linked account gets at most one. Other
        families: only evidence-corroborated resources are attributed, each to one subject.
        Ties inside one batch (several subjects, identical timing, no identifiers) are genuinely
        undecidable from the evidence; the cheapest claim wins with a stable ordering.
        """
        self._weak = {}
        self._ambiguous = {}
        windows: dict[str, list[Case]] = {}
        subjects: dict[str, Subject] = {}
        for c in cases:
            if self.intent(c.request_text) != "DELETE":  # same decision as audit()
                continue
            subj = self.identity.resolve_email(c.email)
            if subj is None:
                continue
            subjects[subj.user_id] = subj
            windows.setdefault(subj.user_id, []).append(c)
        cutoff = {uid: max(c.audit_at for c in cs) for uid, cs in windows.items()}
        strong_owner: dict[str, set[str]] = {}
        for uid, subj in subjects.items():
            for rid in self.strong_links(subj, cutoff[uid]):
                strong_owner.setdefault(rid, set()).add(uid)
        for rid, owners in self.resource_owners.items():
            strong_owner.setdefault(rid, set()).update(owners)

        # (cost, uid, rid) claims
        claims: list[tuple[float, str, str]] = []
        for uid, cs in windows.items():
            own = set(self.strong_links(subjects[uid], cutoff[uid]))
            for c in cs:
                lo, hi = c.requested_at, c.reported_at + WORKFLOW_SLACK
                for a in self.activities:
                    if a.fields.get("source_system") != "deletion_worker" or not lo <= a.observed_at <= hi:
                        continue
                    r = a.resource_id
                    if r in own or (strong_owner.get(r) and strong_owner[r] != {uid}):
                        continue
                    cost = abs((a.observed_at - c.reported_at).total_seconds())
                    if r not in self.by_resource:
                        if prefix_of(r) != "account":
                            continue  # anonymous and never evidenced: nothing to verify
                        cost *= UNCORROBORATED_FACTOR
                    claims.append((cost, uid, r))
        has_account = {uid for uid, subj in subjects.items()
                       if any(prefix_of(r) == "account" for r in self.strong_links(subj, cutoff[uid]))}
        assigned: dict[str, set[str]] = {uid: set() for uid in subjects}
        taken: set[str] = set()

        # Accounts first: they also define each subject's position in its batch.
        acct_claims = sorted((x for x in claims if prefix_of(x[2]) == "account"), key=lambda x: (x[0], x[2], x[1]))
        claimants = {}
        for _, uid, r in acct_claims:
            claimants.setdefault(r, set()).add(uid)
        progress = True
        while progress:  # unique claims first, then cheapest
            progress = False
            for cost, uid, r in acct_claims:
                if r in taken or uid in has_account:
                    continue
                rivals = {u for u in claimants[r] if u not in has_account}
                if rivals == {uid}:
                    assigned[uid].add(r); taken.add(r); has_account.add(uid); progress = True
        for cost, uid, r in acct_claims:
            if r not in taken and uid not in has_account:
                assigned[uid].add(r); taken.add(r); has_account.add(uid)

        other = [x for x in claims if prefix_of(x[2]) != "account"]
        by_rid: dict[str, list[tuple[float, str]]] = {}
        for cost, uid, r in other:
            by_rid.setdefault(r, []).append((cost, uid))
        # A resource only one subject can claim is theirs. When several subjects share one worker
        # batch, nothing in the evidence orders them, so the cheapest claim wins (stable ordering).
        for r, cl in sorted(by_rid.items()):
            _cost, uid = min(cl)
            assigned[uid].add(r)
            taken.add(r)
        self._weak = assigned

    def link(self, case: Case, subject: Subject) -> dict[str, set[str]]:
        linked = {k: set(v) for k, v in self.strong_links(subject, case.audit_at).items()}
        for rid in self._weak.get(subject.user_id, set()):
            if rid in self.workflow_candidates(case):
                linked.setdefault(rid, set()).add("workflow:assigned")
        accts = [r for r in linked if prefix_of(r) == "account"]
        if len(accts) > 1:
            def last_seen(r):
                obs = [o.record.observed_at for o in self.by_resource.get(r, []) if o.record.observed_at <= case.audit_at]
                acts = [a.observed_at for a in self.acts_by_resource.get(r, []) if a.observed_at <= case.audit_at]
                return max(obs + acts, default=datetime.min.replace(tzinfo=case.audit_at.tzinfo))
            keep = max(accts, key=last_seen)
            for r in accts:
                if r != keep:
                    del linked[r]
        if not any(prefix_of(r) == "account" for r in linked):
            # Still no account: fall back to the window candidate nearest the reported time.
            accts = [r for r in self._ambiguous.get(subject.user_id, set()) & self.workflow_candidates(case)
                     if prefix_of(r) == "account"]
            if accts:
                def gap(r):
                    times = [a.observed_at for a in self.acts_by_resource.get(r, [])]
                    return min(abs((t - case.reported_at).total_seconds()) for t in times) if times else 1e12
                linked.setdefault(min(accts, key=gap), set()).add("workflow:nearest")
        return linked

    # ------------------------------------------------------------ state at audit_at

    def state_at(self, rid: str, case: Case, subject: Subject) -> ResourceState:
        system = system_for(rid) or "unknown"
        category = DEFAULT_CATEGORY.get(prefix_of(rid), "UNKNOWN")
        best: tuple[datetime, int, Observation] | None = None
        toks = subject.tokens()
        for o in self.by_resource.get(rid, []):
            r = o.record
            if r.source_time > case.audit_at or r.observed_at > case.audit_at or o.state is None:
                continue
            if o.category_hint:
                category = o.category_hint
            # A document row proves state when it names the resource ID itself, or (for rows matched
            # only through a catalog alias such as an attachment file name) carries this subject's IDs.
            if r.fields.get("_via") == "alias" and not (o.tokens & toks):
                continue
            rank = (r.observed_at, _state_priority(o.state))
            if best is None or rank > best[:2]:
                best = (r.observed_at, _state_priority(o.state), o)
        # Retention end dates are properties of the record itself (immutable), so any capture counts.
        retain_until = None
        for o in self.by_resource.get(rid, []):
            for k in ("retention_until", "retained_until", "hold_until", "retain_until"):
                ts = parse_ts(o.record.fields.get(k)) if o.record.fields.get(k) else None
                if ts and (retain_until is None or ts > retain_until):
                    retain_until = ts
            status = str(o.record.fields.get("hold_status") or o.record.fields.get("status") or "").upper()
            if o.record.prefix == "legal_hold" and status in ("RELEASED", "EXPIRED", "INACTIVE", "LIFTED"):
                retain_until = min(retain_until or o.record.observed_at, o.record.observed_at)
        state = best[2].state if best else None
        evidence = best[2].record.source_id if best else ""
        observed = best[0] if best else None
        # Full-table dumps prove absence by omission.
        for fid, (snap, coverage) in self.corpus.full_tables.items():
            if snap > case.audit_at or system not in coverage or rid in coverage[system]:
                continue
            if observed is None or snap > observed:
                state, evidence, observed = "ABSENT", fid.split("#")[0], snap
        if prefix_of(rid) == "support" and category == "SUPPORT_MESSAGE" and best is not None:
            text = json.dumps(best[2].record.fields, default=str).lower()
            if any(k in text for k in ("attachment", ".pdf", "support_replica", "legacy_contact")):
                category = "SUPPORT_ATTACHMENT"
        if state == "EXPOSED" and category in ("SUPPORT_ATTACHMENT", "MARKETING_PROFILE", "SEARCH_INDEX_ENTRY",
                                               "USER_PROFILE", "USER_EXPORT", "CACHE_ENTRY"):
            state = "PRESENT"
        return ResourceState(rid, system, state, evidence, observed, category, retain_until=retain_until)

    # ------------------------------------------------------------ planning

    def intent(self, text: str) -> str:
        """DELETE only when the text authorizes deletion. Wording the rules cannot place goes to the
        LLM classifier when configured; otherwise it does not authorize deletion (safe default:
        a missed deletion is recoverable, a wrong one is not)."""
        verdict = classify(text)
        if verdict == "AMBIGUOUS":
            verdict = self.intent_fallback(text) if self.intent_fallback else "NOT_DELETE"
        return verdict

    def audit(self, case: Case) -> CaseResult:
        intent = self.intent(case.request_text)
        if intent != "DELETE":
            return CaseResult(case, "NOT_APPLICABLE", [], notes=[f"intent={intent}"])
        subject = self.identity.resolve_email(case.email)
        if subject is None:
            return CaseResult(case, "INCOMPLETE", [], notes=["subject not resolved"])
        linked = self.link(case, subject)
        states = []
        for rid, reasons in sorted(linked.items()):
            st = self.state_at(rid, case, subject)
            st.link_reasons = reasons
            states.append(st)
        steps, status = self.plan(states, case)
        return CaseResult(case, status, steps, subject.user_id, states)

    def plan(self, states: list[ResourceState], case: Case) -> tuple[list[dict], str]:
        findings, remediation, verification = [], [], []
        for st in states:
            treatment = self.policy.treatment(st.category)
            if treatment is None:
                continue
            if treatment == "RETAIN" and st.retain_until is not None and st.retain_until < case.audit_at:
                # Rules 12/13 retain only within the retention period / while the hold is active.
                # Once that has lapsed there is no basis to keep the subject's record: delete it.
                treatment = "DELETE"
            find_op, fix_op, verify_op, ok_states = TREATMENTS[treatment]
            if st.state is None:
                if treatment == "RETAIN" and st.category == "SECURITY_AUDIT_LOG":
                    verification.append((verify_op, st, ""))  # retained; existence known from later capture
                continue
            if treatment == "RETAIN":
                if st.state != "ABSENT":
                    verification.append((verify_op, st, st.evidence_id))
                continue
            if st.state in ok_states:
                verification.append((verify_op, st, st.evidence_id))
            else:
                findings.append((find_op, st, st.evidence_id))
                remediation.append((fix_op, st, ""))
                verification.append((verify_op, st, ""))
        status = "INCOMPLETE" if findings else "COMPLETE"
        if status == "COMPLETE":
            # A COMPLETE verdict must be proven: drop checks with no evidence captured by audit_at.
            verification = [v for v in verification if v[2]]
        if status == "INCOMPLETE":
            # Future-state checks carry no evidence; keep only the subject's account and the
            # retained/remediated records (already-compliant extras are not re-verified).
            remediated = {st.resource_id for _, st, _ in remediation}
            verification = [(op, st, "") for op, st, _ in verification
                            if st.resource_id in remediated or op == "VERIFY_RECORD_PRESENT"
                            or st.category == "USER_PROFILE"]
        rows = findings + remediation + verification
        rows.sort(key=lambda x: (PHASE_ORDER[OP_PHASE[x[0]]], OP_ORDER[x[0]], x[1].system, x[1].resource_id))
        steps = [
            {"step_no": i, "phase": OP_PHASE[op], "system_id": st.system, "resource_id": st.resource_id,
             "operation": op, "state": OP_STATE[op], "evidence_id": ev}
            for i, (op, st, ev) in enumerate(rows, start=1)
        ]
        return steps, status


def _state_priority(state: str | None) -> int:
    # At identical timestamps prefer the observation that reveals a problem.
    return {"EXPOSED": 3, "PRESENT": 3, "ACTIVE": 3, "ABSENT": 1, "REDACTED": 1, "ANONYMIZED": 1,
            "DISABLED": 1, "BLOCKED": 1}.get(state or "", 0)


def _tokens_of_text(text: str) -> set[str]:
    from ghost_audit.identity import tokens_in

    return tokens_in(text)


def run(dataset: Path, requests: Path, context: list[Path] = (), **kw) -> list[CaseResult]:
    auditor = Auditor(dataset, **kw)
    cases = load_cases(requests)
    auditor.prepare(cases + [c for p in context for c in load_cases(p)])
    return [auditor.audit(c) for c in cases]
