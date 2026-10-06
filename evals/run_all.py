"""Run every eval and save JSON to evals/results/. One command:

    python -m evals.run_all

Exits non-zero on a harness regression: an oracle that fails its sanity cases, a vacuous baseline
(ASR outside 20-90%), the full defense stack not beating no defense, or an audit chain / replay
mismatch. Those are gates on the instrument, not claims about real-world security. The
generalisation, mutation and latency evals only report; they have no pass/fail threshold.
"""
from __future__ import annotations

import os
import sys

os.environ.setdefault("PYDANTIC_AI_NO_BANNER", "1")

from . import audit_replay, baseline, defenses, generalisation, latency, mutation, oracle_sanity  # noqa: E402


def main() -> int:
    rc = 0
    for mod in (oracle_sanity, baseline, defenses, generalisation, mutation, latency, audit_replay):
        rc |= mod.main()
    print("evals", "FAILED a gate" if rc else "OK (all gates passed)")
    return 1 if rc else 0


if __name__ == "__main__":
    sys.exit(main())
