"""Model-call accounting for usage_report.md. Every LLM/VLM call records here."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

# USD per million tokens (input, output). Claude API list prices.
PRICES = {
    "claude-opus-5-5": (4.00, 20.00),
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-haiku-5-5": (0.10, 0.50),
}

_calls: dict[str, dict] = defaultdict(lambda: {"calls": 0, "input_tokens": 0, "output_tokens": 0, "purposes": set()})


def record(model: str, input_tokens: int, output_tokens: int, purpose: str) -> None:
    c = _calls[model]
    c["calls"] += 1
    c["input_tokens"] += input_tokens
    c["output_tokens"] += output_tokens
    c["purposes"].add(purpose)


def summary(requests: int) -> dict:
    per_model = {}
    tot_in = tot_out = tot_calls = 0
    tot_cost = 0.0
    for model, c in sorted(_calls.items()):
        pin, pout = PRICES.get(model, (0.0, 0.0))
        cost = c["input_tokens"] / 1e6 * pin + c["output_tokens"] / 1e6 * pout
        per_model[model] = {"calls": c["calls"], "input_tokens": c["input_tokens"],
                            "output_tokens": c["output_tokens"], "estimated_cost_usd": round(cost, 4),
                            "purposes": sorted(c["purposes"])}
        tot_in += c["input_tokens"]
        tot_out += c["output_tokens"]
        tot_calls += c["calls"]
        tot_cost += cost
    total = tot_in + tot_out
    return {
        "requests": requests,
        "per_model": per_model,
        "overall": {"calls": tot_calls, "input_tokens": tot_in, "output_tokens": tot_out, "total_tokens": total,
                    "avg_tokens_per_request": round(total / requests, 2) if requests else 0,
                    "estimated_cost_usd": round(tot_cost, 4),
                    "estimated_cost_per_request_usd": round(tot_cost / requests, 6) if requests else 0},
    }


def write(path: Path, requests: int) -> dict:
    s = summary(requests)
    path.write_text(json.dumps(s, indent=2), encoding="utf-8")
    return s
