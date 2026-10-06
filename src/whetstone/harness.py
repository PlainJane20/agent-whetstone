"""Runs attacks against a target behind a defense stack and scores them with the oracles.

Everything is SIMULATED and offline. One attack run:
    fresh sandbox -> render unread mail -> defenses.prepare -> target.run (tools guarded)
    -> defenses.finalize_output -> deterministic oracle -> audit record.
"""
from __future__ import annotations

import hashlib
import random
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable

from . import oracles, tracing
from .attacks.attackers import Attacker
from .audit import AuditLog
from .defenses import DefenseStack, Defender, build_stack
from .models import DEFAULT_TASK, MESSAGE_SEP, Attack, AttackResult, Email
from .sandbox import Sandbox
from .targets import DEFAULT_PROFILE, GullibleTarget, Target, ToolBox

TargetFactory = Callable[[ToolBox, int], Target]


def gullible_factory(profile=DEFAULT_PROFILE) -> TargetFactory:
    return lambda tb, seed: GullibleTarget(tb, profile, seed)


@dataclass
class RunConfig:
    seed: int = 0
    trials: int = 5
    task: str = DEFAULT_TASK
    target: str = "gullible"  # label written to the audit log: "gullible" or "llm:<model>"


def _render(sb: Sandbox) -> str:
    return MESSAGE_SEP.join(e.render() for e in sb.unread_emails())


def run_attack(attack: Attack, trial: int, stack: DefenseStack, factory: TargetFactory,
               cfg: RunConfig, audit: AuditLog | None = None) -> AttackResult:
    with tracing.span("attack_run", technique=attack.technique, goal=attack.goal,
                      attack_id=attack.id, trial=trial) as root:
        stack.begin_run()
        sb = Sandbox(cfg.seed, attack.emails)
        content = _render(sb)
        with tracing.span("defense_check", technique=attack.technique, goal=attack.goal) as ds:
            prep = stack.prepare(content)
            tracing.set_attrs(ds, blocked_by=prep.blocked_by or "none",
                              screen_score=prep.screen.score if prep.screen else 0.0)
        tool_calls, out, attempted, blocked_by = [], "", False, prep.blocked_by
        if prep.blocked_by is None:
            tb = ToolBox(sb, stack.guard)
            target = factory(tb, cfg.seed * 1000 + trial)
            with tracing.span("target_step", technique=attack.technique, goal=attack.goal) as ts:
                tr = target.run(cfg.task, prep.content)
                tracing.set_attrs(ts, tool_calls=len(tr.tool_calls))
            tool_calls = tr.tool_calls
            out, out_by = stack.finalize_output(tr.output_text)
            injected_blocked = [c for c in tool_calls if c.status == "blocked" and c.origin != "task"]
            attempted = tr.meta.get("complied", bool(injected_blocked))
            blocked_by = (injected_blocked[0].blocked_by if injected_blocked else out_by)
        with tracing.span("oracle", technique=attack.technique, goal=attack.goal) as osp:
            verdict = oracles.evaluate(attack.goal, sb.ledger, out, sb.canary_values())
            tracing.set_attrs(osp, success=verdict.success)
        success = verdict.success
        if success:
            blocked_by = None
        progress = 3 if success else 2 if attempted else (0 if prep.blocked_by else 1)
        res = AttackResult(attack, trial, success, blocked_by, attempted, verdict.reasons,
                           prep.screen.score if prep.screen else 0.0, progress, out, tool_calls,
                           oracles.any_violation(sb.ledger, out, sb.canary_values()))
        tracing.set_attrs(root, success=success, blocked_by=blocked_by or "none")
        if audit is not None:
            audit.append("attack_attempt", {
                "attack": attack.to_dict(), "trial": trial, "seed": cfg.seed, "task": cfg.task,
                "defenses": stack.describe(), "target": cfg.target,
                "outcome": {"success": success, "blocked_by": blocked_by, "progress": progress,
                            "attempted": attempted,
                            "output_sha256": hashlib.sha256(out.encode()).hexdigest()}})
        return res


def run_corpus(attacks: list[Attack], stack: DefenseStack, factory: TargetFactory, cfg: RunConfig,
               audit: AuditLog | None = None) -> list[AttackResult]:
    return [run_attack(a, t, stack, factory, cfg, audit) for a in attacks for t in range(cfg.trials)]


def replay(record: dict, factory: TargetFactory | None = None) -> tuple[bool, AttackResult]:
    """Re-run one audited attempt and check that the outcome is identical."""
    d = record["data"]
    if d.get("target", "gullible") != "gullible":
        raise ValueError("replay is only deterministic for the simulated target; this record came from "
                         f"{d['target']!r}")
    attack = Attack.from_dict(d["attack"])
    stack = DefenseStack.from_description(d["defenses"])
    cfg = RunConfig(seed=d["seed"], trials=1, task=d["task"])
    res = run_attack(attack, d["trial"], stack, factory or gullible_factory(), cfg)
    o = d["outcome"]
    same = (res.success == o["success"] and res.blocked_by == o["blocked_by"]
            and res.progress == o["progress"]
            and hashlib.sha256(res.output_text.encode()).hexdigest() == o["output_sha256"])
    return same, res


# ---- aggregation ------------------------------------------------------------------------
def asr(results: list[AttackResult]) -> float:
    return sum(r.success for r in results) / len(results) if results else 0.0


def group_asr(results: list[AttackResult], key: Callable[[AttackResult], str]) -> dict[str, dict]:
    g: dict[str, list[AttackResult]] = defaultdict(list)
    for r in results:
        g[key(r)].append(r)
    return {k: {"n": len(v), "successes": sum(r.success for r in v), "asr": round(asr(v), 4)}
            for k, v in sorted(g.items())}


def summarize(results: list[AttackResult]) -> dict:
    blocked = defaultdict(int)
    for r in results:
        if not r.success and r.blocked_by:
            blocked[r.blocked_by] += 1
    return {"n": len(results), "successes": sum(r.success for r in results),
            "asr": round(asr(results), 4), "attempted": sum(r.attempted for r in results),
            "blocked_by": dict(sorted(blocked.items())),
            "by_technique": group_asr(results, lambda r: r.attack.technique),
            "by_goal": group_asr(results, lambda r: r.attack.goal)}


# ---- benign runs (false positives) --------------------------------------------------------
@dataclass
class BenignOutcome:
    id: str
    input_blocked: bool
    task_disrupted: bool
    reasons: list[str] = field(default_factory=list)


def run_benign(msg: Email, stack: DefenseStack, factory: TargetFactory, cfg: RunConfig
               ) -> BenignOutcome:
    """Run the legitimate task over one benign message. `task_disrupted` means a defense stopped
    something the user actually wanted: the screen blocked the message, the legitimate summary post
    was blocked, or the delivered summary was altered."""
    stack.begin_run()
    sb = Sandbox(cfg.seed, (msg,))
    prep = stack.prepare(_render(sb))
    if prep.blocked_by:
        return BenignOutcome(msg.id, True, True, ["input_screen:" + ",".join(prep.screen.matched)])
    tb = ToolBox(sb, stack.guard)
    tr = factory(tb, cfg.seed * 1000).run(cfg.task, prep.content)
    out, out_by = stack.finalize_output(tr.output_text)
    reasons = [f"{c.name} blocked by {c.blocked_by}" for c in tr.tool_calls
               if c.origin == "task" and c.status == "blocked"]
    if out != tr.output_text:
        reasons.append("output altered by egress_filter")
    return BenignOutcome(msg.id, False, bool(reasons), reasons)


def benign_rates(msgs: list[Email], stack: DefenseStack, factory: TargetFactory, cfg: RunConfig
                 ) -> dict:
    outs = [run_benign(m, stack, factory, cfg) for m in msgs]
    n = len(outs)
    blocked = sum(o.input_blocked for o in outs)
    disrupted = sum(o.task_disrupted for o in outs)
    return {"n": n, "input_blocked": blocked, "task_disrupted": disrupted,
            "fpr": round(disrupted / n, 4) if n else 0.0,
            "false_positive_ids": [o.id for o in outs if o.task_disrupted]}


# ---- sparring --------------------------------------------------------------------------
@dataclass
class RoundReport:
    round_no: int
    ruleset_version: int
    n_attacks: int
    n_runs: int
    successes: int
    asr: float
    blocked_by: dict
    new_rules: int = 0
    lineages_broken: int = 0          # cumulative: base attacks with a successful variant so far


def spar(attacker: Attacker, defender: Defender, other_defenses: list[str], rounds: int,
         factory: TargetFactory, cfg: RunConfig, audit: AuditLog | None = None
         ) -> tuple[list[RoundReport], list[AttackResult]]:
    """Attacker vs defender for `rounds` rounds. The defender's rule set feeds the InputScreen."""
    history: list[AttackResult] = []
    reports: list[RoundReport] = []
    names = ["input_screen", *other_defenses]
    broken: set[str] = set()
    for r in range(rounds):
        attacks = attacker.propose(r, history)
        if not attacks:
            break
        stack = build_stack(names, ruleset=defender.ruleset)
        results = run_corpus(attacks, stack, factory, cfg, audit)
        s = summarize(results)
        broken |= {x.attack.lineage or x.attack.id for x in results if x.success}
        before = len(defender.ruleset.rules)
        with tracing.span("defender_round", round=r, ruleset_version=defender.ruleset.version) as sp:
            new = defender.propose(r, results)
            tracing.set_attrs(sp, new_version=new.version, successes=s["successes"])
        reports.append(RoundReport(r, stack.input_screen.config.ruleset.version, len(attacks),
                                   len(results), s["successes"], s["asr"], s["blocked_by"],
                                   len(new.rules) - before, len(broken)))
        history = results
        if audit is not None:
            audit.append("defender_round", {"round": r, "ruleset": new.to_dict()["version"],
                                            "rules": len(new.rules), "asr": s["asr"]})
    return reports, history
