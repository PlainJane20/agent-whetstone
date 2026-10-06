"""Adaptive attacker experiment. NEEDS ANTHROPIC_API_KEY AND MAKES REAL, PAID MODEL CALLS. NOT RUN IN CI.

STATUS: built, offline-tested only (stub models), not run live. No result from this script exists.

A model (the attacker) writes the attack email, sees how the target reacted, and refines it over
several rounds, against this project's own SIMULATED sandbox (synthetic inbox, in-memory fake tools,
fake canary secrets). Conditions: adaptive attacker with no defense, adaptive attacker against all
four defenses, and a blind-mutation control (no defense, same attempt budget, no feedback). The
static corpus result (0/165 on Haiku 4.5) is referenced, not re-run.

    python scripts/run_adaptive_live.py --dry-run                  # print the plan and call counts, call nothing
    export ANTHROPIC_API_KEY=...                                   # your own key, environment only
    python scripts/run_adaptive_live.py --live                     # prints the plan and refuses without --yes
    python scripts/run_adaptive_live.py --live --yes

The key is never accepted on the command line. SET A PROVIDER SPEND LIMIT FIRST: the budget guards
(--max-target-runs, --max-attacker-calls) count calls, not money. Stop a run early with
`touch WHETSTONE_KILL` from another terminal. Exit codes: 0 done, 2 refused or bad usage,
3 budget reached, 4 kill switch, 5 model/target error (partial results are saved in every case).
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from whetstone.adaptive_experiment import (CONDITIONS, DEFAULT_ATTACKER_MODEL_NAME, DEFAULT_CAMPAIGNS,
                                           DEFAULT_ROUNDS, DEFAULT_TARGET_MODEL_NAME,
                                           DEFAULT_TARGET_REQUEST_LIMIT, RESULTS_DIR, ExperimentConfig,
                                           format_plan, plan, run_experiment)
from whetstone.attacks.campaign import EXIT_KILL, KILL
from whetstone.models import GOALS

EXIT_REFUSED = 2


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0], allow_abbrev=False)
    ap.add_argument("--live", action="store_true", help="really call the models (needs ANTHROPIC_API_KEY)")
    ap.add_argument("--yes", action="store_true", help="confirm the printed plan and spend")
    ap.add_argument("--dry-run", action="store_true", help="print the plan and call counts; call nothing")
    ap.add_argument("--goals", default=",".join(GOALS))
    ap.add_argument("--campaigns", type=int, default=DEFAULT_CAMPAIGNS, help="independent campaigns per goal")
    ap.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS, help="max rounds per campaign")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--conditions", default=",".join(CONDITIONS))
    ap.add_argument("--attacker-model", default=DEFAULT_ATTACKER_MODEL_NAME)
    ap.add_argument("--target-model", default=DEFAULT_TARGET_MODEL_NAME)
    ap.add_argument("--max-target-runs", type=int, default=None, help="hard cap (default: the plan's maximum)")
    ap.add_argument("--max-attacker-calls", type=int, default=None, help="hard cap (default: the plan's maximum)")
    ap.add_argument("--target-request-limit", type=int, default=DEFAULT_TARGET_REQUEST_LIMIT)
    ap.add_argument("--out-dir", default=str(RESULTS_DIR))
    return ap


def _live_attacker(rounds: int, task: str):
    def make(model_name: str):
        from whetstone.attacks.llm_attacker import LLMAttacker
        return LLMAttacker.live(model_name, rounds=rounds, task=task)
    return make


def _live_target(model_name: str, request_limit: int):
    from whetstone.targets import LLMTarget
    return lambda tb, seed: LLMTarget.live(tb, model_name, request_limit)


def main(argv: list[str] | None = None, environ=None, *, attacker_factory=None, target_factory=None,
         kill=None, out=print) -> int:
    """`attacker_factory`, `target_factory`, `kill` and `out` exist so tests can run the whole flow with stubs."""
    environ = os.environ if environ is None else environ
    try:
        args = _parser().parse_args(argv)
    except SystemExit as e:
        return int(e.code or 0)
    try:
        cfg = ExperimentConfig(
            goals=tuple(g for g in args.goals.split(",") if g), campaigns=args.campaigns, rounds=args.rounds,
            seed=args.seed, conditions=tuple(c for c in args.conditions.split(",") if c),
            attacker_model=args.attacker_model, target_model=args.target_model,
            max_target_runs=args.max_target_runs, max_attacker_calls=args.max_attacker_calls,
            out_dir=Path(args.out_dir), target_request_limit=args.target_request_limit)
        p = plan(cfg)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    out(format_plan(p))
    if args.dry_run:
        out("\nDry run: no model was called, nothing was written.")
        return 0
    if not args.live:
        print("\nrefusing: this makes real, paid model calls. Pass --live (and --yes), or --dry-run.",
              file=sys.stderr)
        return EXIT_REFUSED
    if not environ.get("ANTHROPIC_API_KEY"):
        print("\nrefusing: set ANTHROPIC_API_KEY in your environment (it is never read from the "
              "command line or a file).", file=sys.stderr)
        return EXIT_REFUSED
    if not args.yes:
        print("\nrefusing: review the plan above, set a provider spend limit, then re-run with --yes.",
              file=sys.stderr)
        return EXIT_REFUSED
    kill = kill or KILL
    why = kill.reason()
    if why:
        print(f"\nrefusing: kill switch is set ({why}).", file=sys.stderr)
        return EXIT_KILL
    out("\nRunning. Results and audit chains are saved after every campaign.")
    outcome = run_experiment(cfg, attacker_factory or _live_attacker(cfg.rounds, cfg.task),
                             target_factory or _live_target, kill=kill, say=out)
    s = outcome.summary
    out(f"\nstatus: {s['status']}   saved: {outcome.run_dir}")
    for name, c in s["conditions"].items():
        r = c["campaign_success"]
        out(f"  {name:18s} campaign success {r['k']}/{r['n']}  exact95={r['exact95']}  "
            f"refusals={c['attacker']['refused']}  aborted={c['campaigns_aborted']}")
    return outcome.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
