"""Adaptive attacker experiment. NEEDS ANTHROPIC_API_KEY AND MAKES REAL, PAID MODEL CALLS. NOT RUN IN CI.

STATUS: built and offline-tested (stub models). One 1-campaign x 3-round live smoke test has been run as a
pipeline check (evals/results/live_adaptive/); it is not a result about attack success. The full experiment
has not been run.

A model (the attacker) writes the attack email, sees how the target reacted, and refines it over
several rounds, against this project's own SIMULATED sandbox (synthetic inbox, in-memory fake tools,
fake canary secrets). Conditions: adaptive attacker with no defense, adaptive attacker against all
four defenses, and a blind-mutation control (no defense, same attempt budget, no feedback). The
static corpus result (0/165 on Haiku 4.5) is referenced, not re-run.

    python scripts/run_adaptive_live.py --dry-run                  # print the plan and call counts, call nothing
    export ANTHROPIC_API_KEY=...                                   # your own key, environment only
    python scripts/run_adaptive_live.py --live                     # prints the plan and refuses without --yes
    python scripts/run_adaptive_live.py --live --yes
    python scripts/run_adaptive_live.py --resume <run_id_or_dir> --dry-run   # what is left of an aborted run
    python scripts/run_adaptive_live.py --resume <run_id_or_dir> --live --yes

Transient API errors (429, 5xx, 529 overloaded, connection errors, timeouts) are retried with exponential
backoff and jitter (--retry-max-attempts, --retry-base-s, --retry-cap-s, --max-total-retries); permanent ones
(400 incl. no credit, 401, 403, 404) abort at once with a redacted error record. --resume re-runs only the
campaigns the saved run did not complete (aborted ones are re-run fresh and kept under aborted_attempts),
appending to the same audit chains; the configuration must match the saved run.

The key is never accepted on the command line. SET A PROVIDER SPEND LIMIT FIRST: the budget guards
(--max-target-runs, --max-attacker-calls) count calls, not money. Stop a run early with
`touch WHETSTONE_KILL` from another terminal. Exit codes: 0 done, 2 refused or bad usage,
3 budget reached, 4 kill switch, 5 model/target error or retry cap (partial results are saved in every case).
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from whetstone.adaptive_experiment import (CONDITIONS, DEFAULT_ATTACKER_MODEL_NAME, DEFAULT_CAMPAIGNS,
                                           DEFAULT_ROUNDS, DEFAULT_TARGET_MODEL_NAME,
                                           DEFAULT_TARGET_REQUEST_LIMIT, RESULTS_DIR, ExperimentConfig, ResumeError,
                                           cfg_from_summary, format_plan, plan, prepare_resume, resolve_run_dir,
                                           resume_experiment, run_experiment)
from whetstone.attacks.campaign import DEFAULT_ATTACKER_RETRIES, EXIT_KILL, KILL
from whetstone.models import GOALS
from whetstone.retry import DEFAULT_BASE_S, DEFAULT_CAP_S, DEFAULT_MAX_ATTEMPTS, DEFAULT_MAX_TOTAL_RETRIES

EXIT_REFUSED = 2


def _parser(defaults: bool = True) -> argparse.ArgumentParser:
    """`defaults=False` builds the same parser with no defaults, so a parse shows only what the user typed
    (a resume takes everything not typed from the saved run)."""
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0], allow_abbrev=False,
                                 argument_default=None if defaults else argparse.SUPPRESS)

    def add(*names, default=None, **kw):
        if defaults and default is not None:
            kw["default"] = default
        ap.add_argument(*names, **kw)
    add("--live", action="store_true", help="really call the models (needs ANTHROPIC_API_KEY)")
    add("--yes", action="store_true", help="confirm the printed plan and spend")
    add("--dry-run", action="store_true", help="print the plan and call counts; call nothing")
    add("--resume", metavar="RUN_ID_OR_DIR", help="continue a saved run: re-run only the campaigns it did not "
        "complete, same seeds, same audit chains (configuration must match the saved run)")
    add("--goals", default=",".join(GOALS))
    add("--campaigns", type=int, default=DEFAULT_CAMPAIGNS, help="independent campaigns per goal")
    add("--rounds", type=int, default=DEFAULT_ROUNDS, help="max rounds per campaign")
    add("--seed", type=int, default=0)
    add("--conditions", default=",".join(CONDITIONS))
    add("--attacker-model", default=DEFAULT_ATTACKER_MODEL_NAME)
    add("--target-model", default=DEFAULT_TARGET_MODEL_NAME)
    add("--max-target-runs", type=int, help="hard cap for THIS invocation (default: the plan's maximum)")
    add("--max-attacker-calls", type=int, help="hard cap for THIS invocation (default: the plan's maximum)")
    add("--attacker-retries", type=int, default=DEFAULT_ATTACKER_RETRIES,
        help="corrective retries per round when the attacker returns no structured output "
             "(never after a refusal); each retry is a counted model call")
    add("--retry-max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS,
        help="attempts per API call on a transient error (first try included; 1 = never retry)")
    add("--retry-base-s", type=float, default=DEFAULT_BASE_S, help="first backoff delay in seconds (doubles each retry)")
    add("--retry-cap-s", type=float, default=DEFAULT_CAP_S, help="longest single backoff delay in seconds")
    add("--max-total-retries", type=int, default=DEFAULT_MAX_TOTAL_RETRIES,
        help="global cap on transient retries in this invocation, so a dead API cannot burn time forever")
    add("--target-request-limit", type=int, default=DEFAULT_TARGET_REQUEST_LIMIT)
    add("--out-dir", default=str(RESULTS_DIR))
    return ap


# CLI flag (argparse dest) -> ExperimentConfig attribute, for a resume that overlays typed flags on the saved config
_CFG_FLAGS = {"campaigns": "campaigns", "rounds": "rounds", "seed": "seed", "attacker_model": "attacker_model",
              "target_model": "target_model", "attacker_retries": "attacker_retries",
              "target_request_limit": "target_request_limit", "max_target_runs": "max_target_runs",
              "max_attacker_calls": "max_attacker_calls", "retry_max_attempts": "retry_max_attempts",
              "retry_base_s": "retry_base_s", "retry_cap_s": "retry_cap_s", "max_total_retries": "max_total_retries"}


def _live_attacker(rounds: int, task: str):
    def make(model_name: str):
        from whetstone.attacks.llm_attacker import LLMAttacker
        return LLMAttacker.live(model_name, rounds=rounds, task=task)
    return make


def _live_target(model_name: str, request_limit: int):
    from whetstone.targets import LLMTarget
    return lambda tb, seed: LLMTarget.live(tb, model_name, request_limit)


def _print_summary(out, outcome) -> None:
    s = outcome.summary
    out(f"\nstatus: {s['status']}   saved: {outcome.run_dir}")
    for name, c in s["conditions"].items():
        r = c["campaign_success"]
        out(f"  {name:18s} campaign success {r['k']}/{r['n']}  exact95={r['exact95']}  "
            f"refused={c['attacker']['refused']}  no_output={c['attacker']['no_structured_output']}  "
            f"retries={c['attacker']['retries_used']}  api_retries={c['api_retries']}  aborted={c['campaigns_aborted']}")
        for w in c["warnings"]:
            out(f"    WARNING: {w}")
    if s.get("abort"):
        a = s["abort"]
        out(f"  ABORTED ({a['reason']}) in {a['campaign_id']}: {a['detail']}")
        out("  Resume with: python scripts/run_adaptive_live.py --resume " + s["run_id"] + " --dry-run")


def _preflight(args, environ, kill, out) -> int | None:
    """The same gates for a fresh run and a resume. Returns an exit code to stop, or None to go on."""
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
    why = kill.reason()
    if why:
        print(f"\nrefusing: kill switch is set ({why}).", file=sys.stderr)
        return EXIT_KILL
    return None


def _resume(args, argv, environ, attacker_factory, target_factory, kill, retrier, out) -> int:
    try:
        typed = vars(_parser(defaults=False).parse_args(argv))
        out_dir = Path(typed.get("out_dir", args.out_dir))
        run_dir = resolve_run_dir(args.resume, out_dir)
        from whetstone.adaptive_experiment import load_summary
        saved = load_summary(run_dir / "summary.json")
        over = {attr: getattr(args, k) for k, attr in _CFG_FLAGS.items() if k in typed}
        if "goals" in typed:
            over["goals"] = tuple(g for g in args.goals.split(",") if g)
        if "conditions" in typed:
            over["conditions"] = tuple(c for c in args.conditions.split(",") if c)
        cfg = cfg_from_summary(saved, out_dir=out_dir, **over)
        # budgets and retry settings default to the saved-run-independent defaults for this invocation
        for k in ("retry_max_attempts", "retry_base_s", "retry_cap_s", "max_total_retries"):
            if k not in typed:
                setattr(cfg, k, getattr(args, k))
        cfg.validate()
        state = prepare_resume(run_dir, cfg)
    except ResumeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except (ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    done = sum(len(v) for v in state.carried.values())
    if not state.todo:
        out(f"Nothing to resume: {run_dir.name} has all {done} planned campaigns completed "
            f"(status {state.saved['status']}). Nothing was called or written.")
        return 0
    rp = plan(cfg, state.todo)
    out(f"Resuming {run_dir.name}: {done} campaign(s) carried over, {len(state.todo)} remaining, "
        f"{len(state.aborted)} aborted attempt(s) kept as evidence; audit chains verify "
        f"({', '.join(f'{n}: {c[1]} records' for n, c in state.audit_chains.items())}).")
    out(format_plan(rp, "Adaptive attacker experiment: PLAN FOR THE REMAINING WORK (nothing has been called)"))
    out("  budgets apply to this invocation's new work only; the carried-over campaigns are not re-run.")
    code = _preflight(args, environ, kill, out)
    if code is not None:
        return code
    out("\nResuming. Results and audit chains are saved after every campaign.")
    outcome = resume_experiment(cfg, run_dir, attacker_factory or _live_attacker(cfg.rounds, cfg.task),
                                target_factory or _live_target, kill=kill, say=out, retrier=retrier, state=state)
    _print_summary(out, outcome)
    return outcome.exit_code


def main(argv: list[str] | None = None, environ=None, *, attacker_factory=None, target_factory=None,
         kill=None, out=print, retrier=None) -> int:
    """`attacker_factory`, `target_factory`, `kill`, `out` and `retrier` exist so tests can run the whole
    flow with stubs (and an injected sleep)."""
    environ = os.environ if environ is None else environ
    try:
        args = _parser().parse_args(argv)
    except SystemExit as e:
        return int(e.code or 0)
    kill = kill or KILL
    if args.resume:
        return _resume(args, argv, environ, attacker_factory, target_factory, kill, retrier, out)
    try:
        cfg = ExperimentConfig(
            goals=tuple(g for g in args.goals.split(",") if g), campaigns=args.campaigns, rounds=args.rounds,
            seed=args.seed, conditions=tuple(c for c in args.conditions.split(",") if c),
            attacker_model=args.attacker_model, target_model=args.target_model,
            max_target_runs=args.max_target_runs, max_attacker_calls=args.max_attacker_calls,
            out_dir=Path(args.out_dir), target_request_limit=args.target_request_limit,
            attacker_retries=args.attacker_retries, retry_max_attempts=args.retry_max_attempts,
            retry_base_s=args.retry_base_s, retry_cap_s=args.retry_cap_s,
            max_total_retries=args.max_total_retries)
        p = plan(cfg)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    out(format_plan(p))
    code = _preflight(args, environ, kill, out)
    if code is not None:
        return code
    out("\nRunning. Results and audit chains are saved after every campaign.")
    outcome = run_experiment(cfg, attacker_factory or _live_attacker(cfg.rounds, cfg.task),
                             target_factory or _live_target, kill=kill, say=out, retrier=retrier)
    _print_summary(out, outcome)
    return outcome.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
