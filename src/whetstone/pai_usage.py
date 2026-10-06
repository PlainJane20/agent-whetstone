"""Token usage from a pydantic-ai run result, across versions (`usage` is a method in 1.x and a
property in 2.x). Informational only: any failure returns zeros."""
from __future__ import annotations


def usage_tokens(result) -> tuple[int, int]:
    try:
        u = result.usage
        if callable(u):
            u = u()
        return int(getattr(u, "input_tokens", 0) or 0), int(getattr(u, "output_tokens", 0) or 0)
    except Exception:
        return 0, 0
