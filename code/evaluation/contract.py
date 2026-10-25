"""Ground-truth-free validation of a predictions file against the problem statement.

Runs on any output.csv, so it also covers the 518 evaluation rows that have no public answers.
Each check is a rule from problem_statement.md / AGENTS.md section 6; violations are reported
with the case and rule name so a regression points straight at the broken guarantee.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

OPS = [  # (phase, operation, state) in the statement's order - also the required sort order
    ("FINDING", "REPORT_REMAINING_RECORD", "PRESENT"), ("FINDING", "REPORT_EXPOSED_PII", "PRESENT"),
    ("FINDING", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"), ("FINDING", "REPORT_RESTORE_RISK", "ACTIVE"),
    ("REMEDIATION", "DISABLE_DATA_FLOW", "DISABLED"), ("REMEDIATION", "BLOCK_RESTORE", "BLOCKED"),
    ("REMEDIATION", "DELETE_RECORD", "ABSENT"), ("REMEDIATION", "REDACT_RECORD", "REDACTED"),
    ("REMEDIATION", "ANONYMIZE_RECORD", "ANONYMIZED"),
    ("VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT"), ("VERIFICATION", "VERIFY_RECORD_PRESENT", "PRESENT"),
    ("VERIFICATION", "VERIFY_RECORD_REDACTED", "REDACTED"),
    ("VERIFICATION", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
    ("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"), ("VERIFICATION", "VERIFY_RESTORE_BLOCKED", "BLOCKED"),
]
PHASE_OF = {o: p for p, o, _ in OPS}
STATE_OF = {o: s for _, o, s in OPS}
OP_RANK = {o: i for i, (_, o, _) in enumerate(OPS)}
PHASE_RANK = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
KEYS = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
# remediation -> the verification that must follow it, and the finding that must precede it
REMEDY_VERIFY = {"DISABLE_DATA_FLOW": "VERIFY_DATA_FLOW_DISABLED", "BLOCK_RESTORE": "VERIFY_RESTORE_BLOCKED",
                 "DELETE_RECORD": "VERIFY_RECORD_ABSENT", "REDACT_RECORD": "VERIFY_RECORD_REDACTED",
                 "ANONYMIZE_RECORD": "VERIFY_RECORD_ANONYMIZED"}
REMEDY_FINDING = {"DISABLE_DATA_FLOW": {"REPORT_ACTIVE_DATA_FLOW"}, "BLOCK_RESTORE": {"REPORT_RESTORE_RISK"},
                  "DELETE_RECORD": {"REPORT_REMAINING_RECORD"},
                  "REDACT_RECORD": {"REPORT_EXPOSED_PII"}, "ANONYMIZE_RECORD": {"REPORT_EXPOSED_PII"}}


# Rules the statement implies but does not state outright: reported, but they do not fail the gate.
WARNING_RULES = {"authorized_without_steps"}


def _ts(v: str) -> datetime:
    return datetime.fromisoformat(v.replace("Z", "+00:00"))


def _case_num(cid: str) -> tuple:
    p, _, n = cid.rpartition("_")
    return (p, int(n)) if n.isdigit() else (cid, 0)


def evidence_index(dataset: Path) -> dict[str, datetime]:
    """Every citable ID -> the time it became available (file capture / event time)."""
    idx: dict[str, datetime] = {}
    for name, id_col, t_col in (("evidence_files.csv", "file_id", "captured_at"),
                                ("system_activity.csv", "activity_id", "event_time"),
                                ("user_audit_log.csv", "audit_id", "event_time")):
        p = dataset / name
        if p.exists():
            with open(p, newline="", encoding="utf-8") as f:
                for r in csv.DictReader(f):
                    idx[r[id_col]] = _ts(r[t_col])
    return idx


def validate(predictions: Path, requests: Path, dataset: Path) -> dict:
    violations: list[dict] = []

    def bad(case: str, rule: str, detail: str = "") -> None:
        violations.append({"case_id": case, "rule": rule, "detail": detail,
                           "severity": "warning" if rule in WARNING_RULES else "error"})

    with open(requests, newline="", encoding="utf-8") as f:
        reqs = {r["case_id"]: r for r in csv.DictReader(f)}
    with open(predictions, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader, [])
        rows = list(reader)
    if header != ["case_id", "deletion_status", "steps_json"]:
        bad("*", "header", str(header))
    ids = [r[0] for r in rows]
    if Counter(ids) != Counter(reqs.keys()):
        bad("*", "row_set", f"missing={sorted(set(reqs) - set(ids))[:5]} extra={sorted(set(ids) - set(reqs))[:5]}")
    if ids != sorted(ids, key=_case_num):
        bad("*", "row_order", "rows not sorted by case_id")
    ev = evidence_index(dataset)

    for row in rows:
        if len(row) != 3:
            bad(row[0] if row else "?", "column_count", str(len(row)))
            continue
        cid, status, raw = row
        try:
            steps = json.loads(raw)
        except json.JSONDecodeError as exc:
            bad(cid, "json", str(exc))
            continue
        if not isinstance(steps, list):
            bad(cid, "json_array")
            continue
        if status not in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"):
            bad(cid, "status_enum", status)
        audit_at = _ts(reqs[cid]["audit_at"]) if cid in reqs else None
        if status == "NOT_APPLICABLE" and steps:
            bad(cid, "not_applicable_empty")
        if status in ("COMPLETE", "INCOMPLETE") and not steps:
            bad(cid, "authorized_without_steps")
        if [s.get("step_no") for s in steps] != list(range(1, len(steps) + 1)):
            bad(cid, "step_numbers")
        seen = set()
        for s in steps:
            if set(s) != KEYS:
                bad(cid, "step_keys", str(sorted(s)))
                continue
            op = s["operation"]
            if op not in PHASE_OF:
                bad(cid, "operation_enum", op)
                continue
            if s["phase"] != PHASE_OF[op]:
                bad(cid, "phase_for_operation", f"{op} in {s['phase']}")
            if s["state"] != STATE_OF[op]:
                bad(cid, "state_for_operation", f"{op} -> {s['state']}")
            k = (s["phase"], s["system_id"], s["resource_id"], op)
            if k in seen:
                bad(cid, "duplicate_step", str(k))
            seen.add(k)
            eid = s["evidence_id"]
            if status == "COMPLETE":
                if s["phase"] != "VERIFICATION":
                    bad(cid, "complete_only_verification", op)
                if not eid:
                    bad(cid, "complete_needs_evidence", s["resource_id"])
            if status == "INCOMPLETE":
                if s["phase"] == "FINDING" and not eid:
                    bad(cid, "finding_needs_evidence", s["resource_id"])
                if s["phase"] != "FINDING" and eid:
                    bad(cid, "future_step_no_evidence", s["resource_id"])
            if eid:
                if eid not in ev:
                    bad(cid, "evidence_exists", eid)
                elif audit_at and ev[eid] > audit_at:
                    bad(cid, "evidence_before_audit", f"{eid} captured {ev[eid].isoformat()} > audit_at")
        order = [(PHASE_RANK.get(s.get("phase"), 9), OP_RANK.get(s.get("operation"), 99), s.get("system_id"),
                  s.get("resource_id")) for s in steps if set(s) == KEYS]
        if order != sorted(order):
            bad(cid, "step_order", "phase > operation > system_id > resource_id order violated")
        if status == "INCOMPLETE":
            ops = {(s["operation"], s["system_id"], s["resource_id"]) for s in steps if set(s) == KEYS}
            if not any(s.get("phase") == "FINDING" for s in steps):
                bad(cid, "incomplete_needs_finding")
            for op, sysid, rid in ops:
                if op in REMEDY_VERIFY and (REMEDY_VERIFY[op], sysid, rid) not in ops:
                    bad(cid, "remediation_verified", f"{op} {rid}")
                if op in REMEDY_FINDING and not any((f, sysid, rid) in ops for f in REMEDY_FINDING[op]):
                    bad(cid, "remediation_has_finding", f"{op} {rid}")
                if PHASE_OF.get(op) == "FINDING" and not any(
                        (r, sysid, rid) in ops for r, fs in REMEDY_FINDING.items() if op in fs):
                    bad(cid, "finding_remediated", f"{op} {rid}")

    by_rule = Counter(v["rule"] for v in violations)
    errors = [v for v in violations if v["severity"] == "error"]
    return {"rows": len(rows), "violations": len(errors), "warnings": len(violations) - len(errors),
            "by_rule": dict(by_rule), "examples": violations[:25], "passed": not errors}
