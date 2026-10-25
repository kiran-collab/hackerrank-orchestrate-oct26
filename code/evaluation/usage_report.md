# Usage Report — final full-dataset run

Run that produced the submitted `output.csv`:

```bash
python3 code/main.py          # default configuration
```

Machine-readable counters from that run: `code/evaluation/usage_run.json` (written by `ghost_audit/usage.py`,
which every model call records into).

## Models and calls

| Provider | Model | Purpose | Calls | Input tokens | Output tokens | Est. cost (USD) |
|---|---|---|---|---|---|---|
| — | — | — | 0 | 0 | 0 | 0.00 |
| **Overall** | | | **0** | **0** | **0** | **0.00** |

| Requests | Total tokens | Avg tokens / request | Est. cost / request |
|---|---|---|---|
| 518 | 0 | 0 | $0.00 |

The final run made **no LLM or VLM calls**. Every decision is deterministic code:

- Request intent: multilingual rules (`ghost_audit/intent.py`) classified all 518 texts; none fell
  through to the ambiguous path, so the optional LLM classifier would not have been called even if enabled.
- Screenshots: 11 PNGs transcribed by **RapidOCR** (local ONNX model, no network, no tokens), cached
  by file SHA-256 in `code/cache/image_transcripts.json`.
- PDFs: text layer via `pdftotext` / `pypdf`.

Wall-clock: under 1 s for the audit of 518 requests with cached transcripts; first-time OCR of the
11 screenshots adds 8.3 s on a laptop CPU, and a fresh OCR pass reproduces the cache byte for byte.
All 518 evaluation texts and all 32 sample texts are decided by the rules (none is AMBIGUOUS).
Text the rules cannot place would go to the LLM with `--llm-intent`; without it, it does not
authorize deletion.

## Optional model paths (not used for the submitted output)

| Flag | Model | When it runs | Pricing used for estimates (per MTok in / out) |
|---|---|---|---|
| `--vision` | `claude-opus-5-5` | Transcribe screenshots instead of OCR (prompt: `code/prompts/image_transcription.md`) | $4.00 / $20.00 |
| `--llm-intent` | `claude-opus-5-5` | Only for request texts the rules mark AMBIGUOUS (prompt: `code/prompts/intent_classification.md`). Opus rather than a smaller model because these are the hardest texts and a wrong DELETE is destructive; at ~600 tokens per call the cost difference is fractions of a cent | $4.00 / $20.00 |

Both read `ANTHROPIC_API_KEY` from the environment, record every call in `usage_run.json`, and
fall back to the deterministic path on any API error. They were not exercised in this
environment because no API key was available, so their cost is not reported as measured.
Expected scale if enabled: vision is one call per screenshot (11 calls, not per request);
intent is at most one call per ambiguous request (0 on this dataset).
