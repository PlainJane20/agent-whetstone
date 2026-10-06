"""CLI: python -m whetstone {run-attacks, run-defenses, spar, report}.

Everything runs offline against the SIMULATED sandbox. `--target llm` is built but has never
been run in this repository; it needs your own ANTHROPIC_API_KEY (environment only) and the
explicit --live flag. See scripts/run_live.md.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .attacks import FAMILIES, MutatingAttacker, ScriptedAttacker, base_corpus
from .audit import AuditLog, load_and_verify
from .benign import benign_corpus, split_benign
from .defenses import NAMES, RuleProposerDefender, build_stack
from .harness import (RunConfig, benign_rates, gullible_factory, run_corpus, spar, summarize)

EPILOG = ("Defensive use only. Whetstone attacks only its own SIMULATED sandbox with synthetic data "
          "and fake canary secrets. Do not point it at systems you do not own.")


def _factory(args):
    if args.target == "gullible":
        return gullible_factory()
    if not args.live:
        raise SystemExit("error: --target llm needs --live (it calls a real model with your own key; "
                         "it has never been run in this repository)")
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise SystemExit("error: set ANTHROPIC_API_KEY in your environment (never on the command line)")
    if not args.model:
        raise SystemExit("error: --model is required with --target llm")
    from .targets import LLMTarget
    return lambda tb, seed: LLMTarget.live(tb, args.model)


def _print_table(title: str, s: dict) -> None:
    print(f"{title}: ASR {s['successes']}/{s['n']} = {s['asr']:.1%}  (target attempted {s['attempted']}; "
          f"blocked_by {s['blocked_by'] or '-'})")
    for k, v in s["by_technique"].items():
        print(f"  {k:24s} {v['successes']:3d}/{v['n']:3d}  {v['asr']:6.1%}")


def _attacks(args):
    return base_corpus(tuple(args.technique) if args.technique else None)


def cmd_run_attacks(args) -> int:
    cfg = RunConfig(seed=args.seed, trials=args.trials)
    audit = AuditLog(args.audit) if args.audit else None
    res = run_corpus(_attacks(args), build_stack([]), _factory(args), cfg, audit)
    s = summarize(res)
    if args.json:
        print(json.dumps(s, indent=2))
    else:
        _print_table("no defense", s)
    return 0


def cmd_run_defenses(args) -> int:
    names = [n.strip() for n in args.defenses.split(",") if n.strip()]
    try:
        stack = build_stack(names)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    cfg = RunConfig(seed=args.seed, trials=args.trials)
    f = _factory(args)
    audit = AuditLog(args.audit) if args.audit else None
    atks = _attacks(args)
    base = summarize(run_corpus(atks, build_stack([]), f, cfg))
    res = summarize(run_corpus(atks, stack, f, cfg, audit))
    b = benign_rates(benign_corpus(), build_stack(names), f, cfg)
    out = {"defenses": stack.names, "baseline_asr": base["asr"], "asr": res["asr"],
           "blocked_by": res["blocked_by"], "benign": b, "by_technique": res["by_technique"]}
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print(f"defenses {stack.names}: ASR {base['asr']:.1%} -> {res['asr']:.1%}; "
              f"benign FPR {b['fpr']:.1%} ({b['task_disrupted']}/{b['n']}); blocked_by {res['blocked_by']}")
        for k, v in res["by_technique"].items():
            print(f"  {k:24s} {v['asr']:6.1%}")
    return 0


def cmd_spar(args) -> int:
    cfg = RunConfig(seed=args.seed, trials=args.trials)
    tr, va, _ = split_benign(args.seed)
    defender = RuleProposerDefender([e.render() for e in tr], [e.render() for e in va])
    if args.no_learn:
        defender.propose = lambda r, res: defender.ruleset
    attacker = ScriptedAttacker() if args.attacker == "scripted" else MutatingAttacker(seed=args.seed)
    audit = AuditLog(args.audit) if args.audit else None
    others = [n for n in args.also.split(",") if n]
    reports, _ = spar(attacker, defender, others, args.rounds, gullible_factory(), cfg, audit)
    print("round  rules(v)  attacks  ASR     broken  new_rules")
    for r in reports:
        print(f"{r.round_no:5d}  v{r.ruleset_version:<7d} {r.n_attacks:7d}  {r.asr:6.1%}  {r.lineages_broken:6d}  {r.new_rules:9d}")
    return 0


def cmd_report(args) -> int:
    rc = 0
    d = Path(args.results)
    for name in ("oracle_sanity", "baseline", "defenses", "generalisation", "mutation", "latency", "audit_replay"):
        p = d / f"{name}.json"
        if not p.exists():
            print(f"{name}: missing ({p})")
            rc = 1
            continue
        j = json.loads(p.read_text())
        m = j.get("meta", {})
        print(f"{name}: present (commit {m.get('git_commit', '?')}, python {m.get('python', '?')})")
    p = d / "defenses.json"
    if p.exists():
        print("\nconfig            ASR     canary leak  FPR(all)")
        for k, r in json.loads(p.read_text())["rows"].items():
            print(f"{k:16s} {r['asr']['rate']:6.1%}  {r['canary_leak_rate']['rate']:10.1%}  {r['fpr_all']['rate']:7.1%}")
    audit = Path(args.audit) if args.audit else d / "audit_sample.jsonl"
    if audit.exists():
        ok, bad, n = load_and_verify(audit)
        print(f"\naudit chain {audit}: {n} records, " + ("verified" if ok else f"BROKEN at record {bad}"))
        rc |= 0 if ok else 1
    print("\nSIMULATED results on author-written data; not a measure of real-world security.")
    return rc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="whetstone", description="A sparring partner for AI agents.",
                                 epilog=EPILOG)
    ap.add_argument("--version", action="version", version=f"whetstone {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p, defenses=False):
        p.add_argument("--seed", type=int, default=0)
        p.add_argument("--trials", type=int, default=5)
        p.add_argument("--technique", action="append", choices=FAMILIES, help="limit to a family")
        p.add_argument("--target", choices=("gullible", "llm"), default="gullible")
        p.add_argument("--live", action="store_true", help="required for --target llm (never run here)")
        p.add_argument("--model", help="model name for --target llm")
        p.add_argument("--audit", help="write a hash-chained audit log (JSONL) to this path")
        p.add_argument("--json", action="store_true")

    p = sub.add_parser("run-attacks", help="baseline: attacks vs the target with no defense")
    common(p)
    p.set_defaults(fn=cmd_run_attacks)
    p = sub.add_parser("run-defenses", help="attacks with defenses on, plus false-positive rate")
    common(p)
    p.add_argument("--defenses", default="all", help=f"comma list of {NAMES} or 'all'")
    p.set_defaults(fn=cmd_run_defenses)
    p = sub.add_parser("spar", help="attacker vs defender rounds (InputScreen rules are learned)")
    p.add_argument("--rounds", type=int, default=5)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--trials", type=int, default=3)
    p.add_argument("--attacker", choices=("scripted", "mutating"), default="mutating")
    p.add_argument("--also", default="", help="extra defenses besides input_screen, comma list")
    p.add_argument("--no-learn", action="store_true", help="static rules (control)")
    p.add_argument("--audit")
    p.set_defaults(fn=cmd_spar)
    p = sub.add_parser("report", help="summarise committed eval results and verify an audit chain")
    p.add_argument("--results", default=str(Path(__file__).resolve().parents[2] / "evals" / "results"))
    p.add_argument("--audit")
    p.set_defaults(fn=cmd_report)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
