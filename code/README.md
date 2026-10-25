# Deletion Audit Agent — solution

For each request in `dataset/deletion_requests.csv` the agent decides whether deletion was
authorized, reconstructs the subject's identifiers and every record that still exposes them as
of `audit_at`, applies `deletion_rules.csv`, and emits ordered findings, remediation, and
verification steps.

## Run

```bash
python3 code/main.py                    # -> ./output.csv (518 rows), contract-checked
python3 code/evaluation/main.py         # evaluation harness: score, contract, robustness, regression gate
python3 code/evaluation/main.py --quick # skip the metamorphic robustness suite
```

Python 3.10+. The core uses only the standard library. Optional extras (`pip install -r code/requirements.txt`):

| Package | Needed for |
|---|---|
| `pypdf` | PDF text when `pdftotext` is not installed |
| `rapidocr-onnxruntime` | re-transcribing screenshots (a transcript cache ships in `code/cache/`) |
| `anthropic` | `--vision` (Claude transcribes screenshots) and `--llm-intent` (Claude decides ambiguous requests); set `ANTHROPIC_API_KEY` |

Flags: `--dataset DIR`, `--requests CSV`, `--output CSV`, `--vision`, `--llm-intent`, `-v`.

## Pipeline

```
evidence_files.csv ──► extract.py ──► Records ──► observe.py ──► Observations (identity tokens + state)
  SQL  (sqlite3, in-memory; replica tables kept apart)                       │
  JSON (recursive: any object with resource_id)                              │
  logs (5 syntaxes, grouped by trace: *_started key ↔ *_completed state)    │
  txt / PDF (pdftotext|pypdf) / PNG (media.py: OCR rows, or Claude vision)  ▼
user_identities + user_audit_log ──► identity.py ──► Subject (current + historical emails, phones, hashes, user_id)
system_activity.csv ──► worker windows + data-catalog links                 │
                                                                            ▼
solver.py   intent → resolve subject → link resources → state at audit_at → policy → ordered steps
main.py     run all cases (failures isolated per case) → output.csv → contract validation
```

### Key decisions

- **Intent first.** Explicit "do not delete" language beats deletion vocabulary; negated, hypothetical,
  single-field, and newsletter-removal wording is masked before matching; access, correction, export,
  opt-out, and login help are `NOT_APPLICABLE` with `[]`. Text the rules cannot place goes to the LLM
  (`--llm-intent`) or, without one, does **not** authorize deletion: a wrong deletion is irreversible.
- **Exact identifier matching.** Emails (case-insensitive), phones (digits), SHA-256 email hashes
  (recomputed for historical emails), `user_id`. Names count only when unique across subjects.
  Look-alike decoys (`g.silva76.jr@…`) are never linked.
- **Identity facts do not expire; state does.** A resource may be linked through evidence captured
  later, but its state and any cited evidence come only from sources captured at or before `audit_at`.
- **Absence needs proof.** A record counts as absent only on an explicit 404/NOT_FOUND/zero-hit
  observation, or by omission from a dedicated point-in-time table dump (`customer_profiles_*`,
  `search_documents_*`). Presence in *any* replica table means the record remains (replication drift).
- **Anonymous deleted resources** (a 404 account, an anonymized analytics row) are attributed via the
  deletion worker's batch window between request and report, as a global one-owner-per-resource
  min-cost matching across all requests; candidates no evidence corroborates must be 3× closer in time.
- **Documents and screenshots.** Single-subject documents link every resource they name; list screens
  link identifiers only to the resource on the same row.
- **Policy.** `deletion_rules.csv` maps each record's category to DELETE / REDACT / ANONYMIZE / RETAIN;
  support attachments are deleted, shared conversations redacted; data flows disabled; backups retained
  with restore blocked; tombstones redacted to the stable `user_id`; security audit logs and active legal holds retained. Retention ends when the evidence says so: an
  expired `retention_until` / `retained_until` (or a released hold) removes the RETAIN basis and the
  record is deleted.
- **Steps.** Phase → operation order from the problem statement → `system_id` → `resource_id`.
  Remediation therefore disables flows and blocks restores before changing records. `COMPLETE` rows
  contain only evidence-backed checks; `INCOMPLETE` future steps carry `evidence_id: ""`.

### Files

| Path | Role |
|---|---|
| `main.py` | CLI, output writer, contract validator |
| `ghost_audit/extract.py` | all parsers → `Record` |
| `ghost_audit/observe.py` | record → identity tokens + state |
| `ghost_audit/identity.py` | subject resolution, token normalization |
| `ghost_audit/solver.py` | linking, global attribution, state at `audit_at`, planning |
| `ghost_audit/policy.py` | rules loader, operation catalogue and ordering |
| `ghost_audit/intent.py` | multilingual deletion-authorization rules |
| `ghost_audit/media.py` | screenshot transcription (cache → Claude vision → RapidOCR) |
| `ghost_audit/llm.py` | optional Claude intent classifier (structured JSON output) |
| `ghost_audit/usage.py` | per-model call/token/cost accounting |
| `prompts/` | prompts for the optional model paths |
| `evaluation/main.py` | evaluation harness driver (black-box: runs `main.py`, scores the CSVs) |
| `evaluation/metrics.py` | ground-truth scoring with bootstrap confidence intervals |
| `evaluation/contract.py` | ground-truth-free output contract + evidence provenance validator |
| `evaluation/metamorphic.py` | perturbation tests that must not change any answer |
| `evaluation/custom_cases/` | synthetic dataset with hand-derived expected answers |
| `evaluation/*.md` | `evaluation_report.md`, `harness_report.md` (generated), `usage_report.md` |
| `cache/image_transcripts.json` | OCR transcripts keyed by image SHA-256 |

Results: `evaluation/evaluation_report.md`. Model usage: `evaluation/usage_report.md`.
