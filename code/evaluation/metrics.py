"""Ground-truth scoring of predictions against expected answers.

Everything is computed from two CSVs in the submission format (case_id,deletion_status,steps_json),
so the agent is evaluated black-box, exactly as a grader would see it.

Dimensions (mirroring the problem statement's scoring):
  status      case-level accuracy, per-class precision/recall/F1, confusion matrix
  steps       exact step match (all 6 fields) - precision/recall/F1, overall/per phase/per operation
  discovery   which (system, resource) pairs were reported at all - identity resolution & coverage
  findings    FINDING steps only - remaining data / exposure / flows / restore risks
  policy      for resources present in both, does the planned operation set agree
  evidence    for steps matching on everything but evidence_id, is the cited evidence identical
  sequence    exact ordered array match, and normalized LCS similarity of the step order
Confidence intervals: case-level bootstrap (fixed seed, deterministic).
"""

from __future__ import annotations

import csv
import json
import random
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

STATUSES = ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE")
STEP_FIELDS = ("phase", "system_id", "resource_id", "operation", "state", "evidence_id")


@dataclass
class Row:
    case_id: str
    status: str
    steps: list[dict]
    parse_error: str | None = None


def load_rows(path: Path) -> dict[str, Row]:
    out = {}
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            try:
                steps = json.loads(r["steps_json"]) if r.get("steps_json") else []
                if not isinstance(steps, list):
                    raise ValueError("steps_json is not an array")
                out[r["case_id"]] = Row(r["case_id"], r["deletion_status"], steps)
            except (ValueError, TypeError) as exc:
                out[r["case_id"]] = Row(r["case_id"], r.get("deletion_status", ""), [], str(exc))
    return out


def key(s: dict, fields=STEP_FIELDS) -> tuple:
    return tuple(s.get(f) for f in fields)


def _prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    return {"precision": p, "recall": r, "f1": 2 * p * r / (p + r) if p + r else 0.0, "tp": tp, "fp": fp, "fn": fn}


def _lcs(a: list, b: list) -> int:
    prev = [0] * (len(b) + 1)
    for x in a:
        cur = [0]
        for j, y in enumerate(b):
            cur.append(prev[j] + 1 if x == y else max(prev[j + 1], cur[j]))
        prev = cur
    return prev[-1]


@dataclass
class CaseScore:
    case_id: str
    exp_status: str
    got_status: str
    tp: int
    fp: int
    fn: int
    seq_exact: bool
    lcs_ratio: float
    missing: list[tuple]
    extra: list[tuple]


def score_case(exp: Row, got: Row | None) -> CaseScore:
    got = got or Row(exp.case_id, "<missing row>", [])
    e, g = Counter(key(s) for s in exp.steps), Counter(key(s) for s in got.steps)
    tp = sum((e & g).values())
    ek, gk = [key(s) for s in exp.steps], [key(s) for s in got.steps]
    denom = max(len(ek), len(gk))
    return CaseScore(
        exp.case_id, exp.status, got.status, tp, sum(g.values()) - tp, sum(e.values()) - tp,
        exp.status == got.status and ek == gk,
        _lcs(ek, gk) / denom if denom else 1.0,
        sorted(set(e) - set(g)), sorted(set(g) - set(e)),
    )


def evaluate(expected: dict[str, Row], predicted: dict[str, Row], bootstrap: int = 1000, seed: int = 7) -> dict:
    ids = sorted(expected)
    cases = [score_case(expected[i], predicted.get(i)) for i in ids]

    # status
    confusion = {a: {b: 0 for b in (*STATUSES, "other")} for a in STATUSES}
    for c in cases:
        confusion[c.exp_status][c.got_status if c.got_status in STATUSES else "other"] += 1
    per_class = {}
    for s in STATUSES:
        tp = confusion[s][s]
        fp = sum(confusion[o][s] for o in STATUSES if o != s)
        fn = sum(v for k, v in confusion[s].items() if k != s)
        per_class[s] = _prf(tp, fp, fn) | {"support": sum(confusion[s].values())}

    # steps, overall / per phase / per operation
    def bucketed(field: str) -> dict:
        tp, fp, fn = Counter(), Counter(), Counter()
        for i in ids:
            e = Counter(key(s) for s in expected[i].steps)
            g = Counter(key(s) for s in (predicted.get(i) or Row(i, "", [])).steps)
            for k, n in (e | g).items():
                b = k[STEP_FIELDS.index(field)]
                m = min(e[k], g[k])
                tp[b] += m
                fp[b] += g[k] - m
                fn[b] += e[k] - m
        return {b: _prf(tp[b], fp[b], fn[b]) for b in sorted(set(tp) | set(fp) | set(fn))}

    steps = _prf(sum(c.tp for c in cases), sum(c.fp for c in cases), sum(c.fn for c in cases))

    # discovery / findings / policy / evidence
    d_tp = d_fp = d_fn = f_tp = f_fp = f_fn = 0
    pol_ok = pol_n = ev_ok = ev_n = 0
    for i in ids:
        e_steps, g_steps = expected[i].steps, (predicted.get(i) or Row(i, "", [])).steps
        er = {(s["system_id"], s["resource_id"]) for s in e_steps}
        gr = {(s["system_id"], s["resource_id"]) for s in g_steps}
        d_tp += len(er & gr)
        d_fp += len(gr - er)
        d_fn += len(er - gr)
        ef = {key(s) for s in e_steps if s.get("phase") == "FINDING"}
        gf = {key(s) for s in g_steps if s.get("phase") == "FINDING"}
        f_tp += len(ef & gf)
        f_fp += len(gf - ef)
        f_fn += len(ef - gf)
        ops_e, ops_g = defaultdict(set), defaultdict(set)
        for s in e_steps:
            ops_e[(s["system_id"], s["resource_id"])].add(s["operation"])
        for s in g_steps:
            ops_g[(s["system_id"], s["resource_id"])].add(s["operation"])
        for r in er & gr:
            pol_n += 1
            pol_ok += ops_e[r] == ops_g[r]
        noev = lambda s: key(s, STEP_FIELDS[:-1])  # noqa: E731
        g_by = defaultdict(list)
        for s in g_steps:
            g_by[noev(s)].append(s["evidence_id"])
        for s in e_steps:
            if g_by.get(noev(s)):
                ev_n += 1
                ev_ok += s["evidence_id"] in g_by[noev(s)]

    def aggregate(subset: list[CaseScore]) -> dict:
        n = len(subset)
        tp, fp, fn = sum(c.tp for c in subset), sum(c.fp for c in subset), sum(c.fn for c in subset)
        return {"status_accuracy": sum(c.exp_status == c.got_status for c in subset) / n,
                "sequence_accuracy": sum(c.seq_exact for c in subset) / n,
                "step_f1": _prf(tp, fp, fn)["f1"]}

    rng = random.Random(seed)
    samples = [aggregate([rng.choice(cases) for _ in cases]) for _ in range(bootstrap)] if cases else []
    ci = {}
    for m in ("status_accuracy", "sequence_accuracy", "step_f1"):
        vals = sorted(s[m] for s in samples)
        ci[m] = [vals[int(0.025 * len(vals))], vals[int(0.975 * len(vals)) - 1]] if vals else [0, 0]

    return {
        "cases": len(cases),
        "missing_rows": [i for i in ids if i not in predicted],
        "unexpected_rows": sorted(set(predicted) - set(expected)),
        "parse_errors": {i: r.parse_error for i, r in predicted.items() if r.parse_error},
        "status": {"accuracy": aggregate(cases)["status_accuracy"], "per_class": per_class, "confusion": confusion},
        "steps": steps,
        "steps_by_phase": bucketed("phase"),
        "steps_by_operation": bucketed("operation"),
        "discovery": _prf(d_tp, d_fp, d_fn),
        "findings": _prf(f_tp, f_fp, f_fn),
        "policy_agreement": pol_ok / pol_n if pol_n else 1.0,
        "evidence_accuracy": ev_ok / ev_n if ev_n else 1.0,
        "sequence": {"exact": aggregate(cases)["sequence_accuracy"],
                     "mean_lcs_ratio": sum(c.lcs_ratio for c in cases) / len(cases) if cases else 1.0},
        "bootstrap_95ci": ci,
        "failures": [c.__dict__ for c in cases if not c.seq_exact],
    }
