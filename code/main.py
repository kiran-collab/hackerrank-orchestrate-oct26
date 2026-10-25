"""Ghost Data Still Exists - deletion audit agent.

    python3 code/main.py                       # audit dataset/deletion_requests.csv -> ./output.csv
    python3 code/main.py --vision --llm-intent # use Claude for screenshots / ambiguous requests

Paths are resolved relative to the repository root, so this runs from any directory.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
import time
from pathlib import Path

CODE_DIR = Path(__file__).resolve().parent
REPO = CODE_DIR.parent
sys.path.insert(0, str(CODE_DIR))

from ghost_audit import usage  # noqa: E402
from ghost_audit.media import transcribe_images  # noqa: E402
from ghost_audit.solver import Auditor, CaseResult, load_cases  # noqa: E402

STEP_KEYS = ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")
log = logging.getLogger("ghost_audit")


def case_sort_key(case_id: str) -> tuple:
    prefix, _, num = case_id.rpartition("_")
    return (prefix, int(num)) if num.isdigit() else (case_id, 0)


def serialize(steps: list[dict]) -> str:
    return json.dumps([{k: s[k] for k in STEP_KEYS} for s in steps], separators=(",", ":"), ensure_ascii=False)


def write_output(results: list[CaseResult], path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["case_id", "deletion_status", "steps_json"])
        for r in sorted(results, key=lambda r: case_sort_key(r.case.case_id)):
            w.writerow([r.case.case_id, r.status, serialize(r.steps)])


def validate_output(path: Path, expected_ids: list[str]) -> list[str]:
    """Contract checks from the README submission checklist."""
    problems = []
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    if rows[0] != ["case_id", "deletion_status", "steps_json"]:
        problems.append(f"bad header {rows[0]}")
    ids = [r[0] for r in rows[1:]]
    if sorted(ids) != sorted(expected_ids):
        problems.append("case ids do not match the request file")
    for case_id, status, raw in rows[1:]:
        steps = json.loads(raw)
        if status not in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"):
            problems.append(f"{case_id}: bad status {status}")
        if status == "NOT_APPLICABLE" and steps:
            problems.append(f"{case_id}: NOT_APPLICABLE with steps")
        if [s["step_no"] for s in steps] != list(range(1, len(steps) + 1)):
            problems.append(f"{case_id}: step numbers not consecutive")
        phases = [s["phase"] for s in steps]
        if phases != sorted(phases, key=["FINDING", "REMEDIATION", "VERIFICATION"].index):
            problems.append(f"{case_id}: phases out of order")
        for s in steps:
            if set(s) != set(STEP_KEYS):
                problems.append(f"{case_id}: step keys {sorted(s)}")
            if status == "COMPLETE" and not s["evidence_id"]:
                problems.append(f"{case_id}: COMPLETE step without evidence")
            if status == "INCOMPLETE" and s["phase"] != "FINDING" and s["evidence_id"]:
                problems.append(f"{case_id}: future step with evidence")
    return problems


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dataset", type=Path, default=REPO / "dataset")
    p.add_argument("--requests", type=Path, default=None, help="default: <dataset>/deletion_requests.csv")
    p.add_argument("--output", type=Path, default=REPO / "output.csv")
    p.add_argument("--vision", action="store_true", help="transcribe screenshots with Claude vision")
    p.add_argument("--llm-intent", action="store_true", help="Claude decides request texts the rules cannot place")
    p.add_argument("--usage-out", type=Path, default=CODE_DIR / "evaluation" / "usage_run.json")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":%(message)r}')
    requests = args.requests or args.dataset / "deletion_requests.csv"
    t0 = time.time()

    images = transcribe_images(args.dataset, use_vision=args.vision)
    intent = None
    if args.llm_intent:
        try:
            from ghost_audit.llm import IntentClassifier

            intent = IntentClassifier()
        except Exception as exc:
            log.warning("LLM intent disabled: %s", exc)
    auditor = Auditor(args.dataset, image_texts=images, intent_fallback=intent)
    for failure in auditor.corpus.failures:
        log.warning("evidence not read: %s", failure)

    cases = load_cases(requests)
    # Global attribution context: every participant-visible request file in the dataset, so a case
    # gets the same answer whichever request file is being audited.
    context = {(requests.resolve(), c.case_id): c for c in cases}
    for extra in sorted(args.dataset.glob("*deletion_requests.csv")):
        if extra.resolve() != requests.resolve():
            for c in load_cases(extra):
                context.setdefault((extra.resolve(), c.case_id), c)
    auditor.prepare(list(context.values()))

    results: list[CaseResult] = []
    for c in cases:
        try:
            results.append(auditor.audit(c))
        except Exception as exc:  # isolate: one bad case must not lose the other rows
            log.error("case %s failed: %s", c.case_id, exc, exc_info=True)
            results.append(CaseResult(c, "INCOMPLETE", [], notes=[f"error: {exc}"]))
    write_output(results, args.output)
    problems = validate_output(args.output, [c.case_id for c in cases])
    usage_summary = usage.write(args.usage_out, len(cases))

    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    print(json.dumps({"output": str(args.output), "rows": len(results), "status_counts": counts,
                      "contract_problems": problems[:20], "evidence_unread": auditor.corpus.failures,
                      "model_calls": usage_summary["overall"]["calls"],
                      "seconds": round(time.time() - t0, 2)}, indent=2))
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
