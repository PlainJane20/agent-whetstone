"""Shared helpers for the evals: metadata, JSON output, intervals, defense configurations."""
from __future__ import annotations

import json
import math
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

RESULTS = Path(__file__).resolve().parent / "results"
ROOT = Path(__file__).resolve().parents[1]
SEED = 0
TRIALS = 5

CAVEAT = [
    "All attacks, all benign messages, the screening rules and the gullible target's susceptibility",
    "profile were written by the same author. The target is a SIMULATION of a gullible agent, not a",
    "language model. These numbers show that the harness works and how defenses compare against THIS",
    "model; they are not an estimate of real-world security or of how any real LLM behaves.",
]

DEFENSE_CONFIGS = {
    "none": [],
    "input_screen": ["input_screen"],
    "spotlight": ["spotlight"],
    "egress_filter": ["egress_filter"],
    "tool_policy": ["tool_policy"],
    "all_four": ["all"],
}


def meta() -> dict:
    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                                capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        commit = ""
    return {"environment": "SIMULATED (synthetic inbox, fake tools, fake CANARY secrets, simulated target)",
            "python": sys.version.split()[0], "platform": platform.platform(),
            "machine": platform.machine(),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "git_commit": commit, "seed": SEED, "trials_per_attack": TRIALS, "caveat": CAVEAT}


def save(name: str, payload: dict) -> Path:
    RESULTS.mkdir(parents=True, exist_ok=True)
    path = RESULTS / f"{name}.json"
    path.write_text(json.dumps(payload, indent=2) + "\n")
    return path


def pct(sorted_vals: list[float], q: float) -> float:
    if not sorted_vals:
        return float("nan")
    idx = min(len(sorted_vals) - 1, max(0, int(round(q * (len(sorted_vals) - 1)))))
    return sorted_vals[idx]


def wilson(k: int, n: int, z: float = 1.96) -> list[float]:
    """95% Wilson score interval for k successes of n. Treats runs as independent, which the
    shared attacks and shared target seeds make only approximately true; read it as a rough band."""
    if n == 0:
        return [0.0, 0.0]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def rate(k: int, n: int) -> dict:
    return {"k": k, "n": n, "rate": round(k / n, 4) if n else 0.0, "ci95": wilson(k, n)}
