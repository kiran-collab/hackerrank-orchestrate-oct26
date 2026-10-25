"""Image evidence -> row-structured transcripts.

Screenshots are business screens (consoles, inspectors). We need their text *and*
their layout, because list screens mix several customers and an identifier only
belongs to the resource on the same row. Transcripts are lists of rows; each row
is the text boxes sharing a baseline, left to right.

Engines, in order of preference:
  1. cache (code/cache/image_transcripts.json, keyed by file SHA-256) - deterministic reruns
  2. Claude vision (if ANTHROPIC_API_KEY is set and --vision is requested)
  3. RapidOCR (local ONNX OCR, no network)
If none is available the image is reported as unread; the audit still runs.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
from pathlib import Path

from ghost_audit import usage

log = logging.getLogger("ghost_audit.media")

CACHE_PATH = Path(__file__).resolve().parent.parent / "cache" / "image_transcripts.json"

VISION_PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "image_transcription.md"

_OCR_FIXES = [
    (re.compile(r"(?<=_)[oO](?=\d)|(?<=\d)[oO](?=\d)|(?<=_)[oO]{2}(?=\d)"), lambda m: "0" * len(m.group(0))),
    (re.compile(r"(audit_record_)([oO0]+)(\d*)"), lambda m: m.group(1) + "0" * len(m.group(2)) + m.group(3)),
]


_ID_JOIN = re.compile(
    r"((?:user|account|search|analytics|support|export|data_flow|backup|audit_record|tombstone|legal_hold|"
    r"cache|email_delivery|marketing|object)_\d+)\s*[-·•]\s*"
)


def clean_ocr(text: str) -> str:
    for rx, repl in _OCR_FIXES:
        text = rx.sub(repl, text)
    # OCR renders "user_20 · analytics_7438 · a@b.com" as "user_20-analytics_7438-a@b.com".
    return _ID_JOIN.sub(r"\1 | ", text)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rows_from_boxes(boxes) -> list[str]:
    """Group OCR boxes into rows by vertical centre, then order left to right."""
    items = []
    for box, text, _conf in boxes:
        ys = [p[1] for p in box]
        xs = [p[0] for p in box]
        items.append(((min(ys) + max(ys)) / 2, min(xs), max(ys) - min(ys), text))
    items.sort()
    rows: list[list[tuple]] = []
    for it in items:
        if rows and abs(it[0] - rows[-1][0][0]) <= max(6.0, 0.45 * it[2]):
            rows[-1].append(it)
        else:
            rows.append([it])
    return [" | ".join(t for *_, t in sorted(r, key=lambda x: x[1])) for r in rows]


def _ocr_rows(path: Path) -> list[str] | None:
    try:
        from rapidocr_onnxruntime import RapidOCR
    except ImportError:
        return None
    global _ENGINE
    try:
        _ENGINE
    except NameError:
        _ENGINE = RapidOCR()
    boxes, _ = _ENGINE(str(path))
    return [clean_ocr(r) for r in _rows_from_boxes(boxes or [])]


def _vision_rows(path: Path, model: str) -> list[str] | None:
    """Claude vision transcription in the same row format as OCR."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None
    import anthropic

    client = anthropic.Anthropic(max_retries=3)
    prompt = VISION_PROMPT_PATH.read_text(encoding="utf-8")
    data = base64.standard_b64encode(path.read_bytes()).decode()
    resp = client.messages.create(
        model=model,
        max_tokens=8000,
        messages=[{"role": "user", "content": [
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": data}},
            {"type": "text", "text": prompt},
        ]}],
    )
    usage.record(model, resp.usage.input_tokens, resp.usage.output_tokens, purpose="image_transcription")
    if resp.stop_reason == "refusal":
        log.warning("vision refused %s", path.name)
        return None
    text = "".join(b.text for b in resp.content if b.type == "text")
    return [clean_ocr(line) for line in text.splitlines() if line.strip()]


def transcribe_images(dataset: Path, use_vision: bool = False, vision_model: str = "claude-opus-5-5",
                      refresh: bool = False) -> dict[str, str]:
    """file_id -> transcript (rows joined by newlines)."""
    import csv

    cache: dict = {}
    if CACHE_PATH.exists() and not refresh:
        cache = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    out: dict[str, str] = {}
    dirty = False
    with open(dataset / "evidence_files.csv", newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            path = dataset / row["file_path"]
            if path.suffix.lower() not in (".png", ".jpg", ".jpeg"):
                continue
            digest = _sha(path)
            hit = cache.get(digest)
            if hit and (not use_vision or hit.get("engine", "").startswith("claude")):
                out[row["file_id"]] = "\n".join(hit["rows"])
                continue
            rows, engine = None, None
            if use_vision:
                try:
                    rows, engine = _vision_rows(path, vision_model), vision_model
                except Exception as exc:  # network/API failure: degrade to OCR
                    log.warning("vision failed for %s: %s", path.name, exc)
            if rows is None:
                rows, engine = _ocr_rows(path), "rapidocr"
            if rows is None:
                log.warning("no image engine available for %s", path.name)
                continue
            cache[digest] = {"file": path.name, "engine": engine, "rows": rows}
            out[row["file_id"]] = "\n".join(rows)
            dirty = True
    if dirty:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        CACHE_PATH.write_text(json.dumps(cache, indent=1, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return out
