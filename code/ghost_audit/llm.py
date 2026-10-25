"""Optional Claude intent classifier for request texts the deterministic rules cannot place.

Used only when ANTHROPIC_API_KEY is set and --llm-intent is passed. Output is a constrained
JSON object, validated before use; any failure falls back to NOT_DELETE (never a deletion by accident).
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from ghost_audit import usage

log = logging.getLogger("ghost_audit.llm")

PROMPT = (Path(__file__).resolve().parent.parent / "prompts" / "intent_classification.md").read_text(encoding="utf-8")

SCHEMA = {
    "type": "object",
    "properties": {
        "authorizes_deletion": {"type": "boolean"},
        "reason": {"type": "string"},
    },
    "required": ["authorizes_deletion", "reason"],
    "additionalProperties": False,
}


class IntentClassifier:
    def __init__(self, model: str = "claude-opus-5-5"):
        import anthropic

        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        self.anthropic = anthropic
        self.client = anthropic.Anthropic(max_retries=3, timeout=60)
        self.model = model
        self.cache: dict[str, str] = {}

    def __call__(self, text: str) -> str:
        if text in self.cache:
            return self.cache[text]
        verdict = "NOT_DELETE"  # safe default if the call fails: never authorize deletion by accident
        try:
            resp = self.client.messages.create(
                model=self.model,
                max_tokens=512,
                system=PROMPT,
                messages=[{"role": "user", "content": f"<request_text>{text}</request_text>"}],
                output_config={"effort": "low", "format": {"type": "json_schema", "schema": SCHEMA}},
            )
            usage.record(self.model, resp.usage.input_tokens, resp.usage.output_tokens, purpose="intent")
            if resp.stop_reason not in ("refusal", "max_tokens"):
                data = json.loads("".join(b.text for b in resp.content if b.type == "text"))
                verdict = "DELETE" if data["authorizes_deletion"] is True else "NOT_DELETE"
        except (self.anthropic.APIError, json.JSONDecodeError, KeyError) as exc:
            log.warning("intent LLM failed, using default: %s", exc)
        self.cache[text] = verdict
        return verdict
