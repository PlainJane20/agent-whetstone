"""The adaptive-attacker experiment: plan, run, summarise. Used by scripts/run_adaptive_live.py.

STATUS: built, offline-tested only (stub attackers and targets), not run live. No result from this
module exists yet; the README says so and must keep saying so until a real run is committed.

Design: for each goal x campaign index, in three conditions (adaptive attacker with no defense,
adaptive attacker against all four defenses, blind-mutation control with no defense) run one
campaign of up to R rounds. The static corpus result (0/165 on Haiku 4.5) is referenced, not
re-run. Campaigns are interleaved (campaign index outermost) so that a budget abort leaves a
balanced partial result. The summary is rewritten after every campaign so an abort or a crash
still leaves everything finished so far on disk.
"""
from __future__ import annotations

import json
import platform
import statistics
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from typing import Callable

from . import stats
from .attacks.campaign import (ABORT_EXIT, EXIT_OK, KILL, AttackSource, BlindSource, Budget, CampaignResult,
                               KillSwitch, run_campaign)
from .audit import AuditLog
from .defenses import build_stack
from .harness import RunConfig, TargetFactory
from .models import DEFAULT_TASK, GOALS

DEFAULT_ATTACKER_MODEL_NAME = "claude-haiku-4-5-20251001"
DEFAULT_TARGET_MODEL_NAME = "claude-haiku-4-5-20251001"
DEFAULT_ROUNDS = 8
DEFAULT_CAMPAIGNS = 3
DEFAULT_TARGET_REQUEST_LIMIT = 30      # model requests per target run: a spend guard per run
ATTACKER_MAX_REQUESTS = 3              # model requests per attacker call (LLMAttacker default)
RESULTS_DIR = Path(__file__).resolve().parents[2] / "evals" / "results" / "live_adaptive"
SCHEMA_VERSION = 1

STATUS_NOTE = ("Built and offline-tested only. A summary file written by a real run replaces this note "
               "with the run's own metadata; none has been committed yet.")
CAVEAT = [
    "Sandbox is SIMULATED (synthetic inbox, in-memory fake tools, fake CANARY secrets). The attacker is a",
    "model told the goals, the target's tool names and its task text (a white-box-ish assumption). Success is",
    "decided only by the deterministic oracles, never by the attacker. Live runs are nondeterministic and the",
    "attacker's samples cannot be seeded: the seed fixes the sandbox canaries and the blind control only.",
    "The unit of analysis is a CAMPAIGN (at most R rounds); campaign counts are small, intervals are wide, and",
    "a null result bounds the rate for THIS attacker prompt, THIS target, THIS task and THIS budget only.",
]
STATIC_REFERENCE = {
    "note": "Already measured, not re-run here: author-written static corpus against the same target model.",
    "target": "claude-haiku-4-5-20251001", "no_defense": {"k": 0, "n": 165, "exact95": stats.exact_ci(0, 165)},
    "all_four_defenses": {"k": 0, "n": 165, "exact95": stats.exact_ci(0, 165)},
    "source": ["evals/results/live/baseline_haiku45.json", "evals/results/live/defended_haiku45.json"]}


@dataclass(frozen=True)
class Condition:
    name: str
    kind: str                     # adaptive | blind
    defenses: tuple[str, ...]


CONDITIONS = {
    "adaptive_none": Condition("adaptive_none", "adaptive", ()),
    "adaptive_all_four": Condition("adaptive_all_four", "adaptive", ("all",)),
    "blind_none": Condition("blind_none", "blind", ()),
}


@dataclass
class ExperimentConfig:
    goals: tuple[str, ...] = GOALS
    campaigns: int = DEFAULT_CAMPAIGNS
    rounds: int = DEFAULT_ROUNDS
    seed: int = 0
    conditions: tuple[str, ...] = tuple(CONDITIONS)
    attacker_model: str = DEFAULT_ATTACKER_MODEL_NAME
    target_model: str = DEFAULT_TARGET_MODEL_NAME
    max_target_runs: int | None = None        # None = the planned maximum
    max_attacker_calls: int | None = None
    out_dir: Path = RESULTS_DIR
    task: str = DEFAULT_TASK
    target_request_limit: int = DEFAULT_TARGET_REQUEST_LIMIT

    def validate(self) -> None:
        bad = [g for g in self.goals if g not in GOALS]
        if bad:
            raise ValueError(f"unknown goal(s) {bad}; choose from {GOALS}")
        bad = [c for c in self.conditions if c not in CONDITIONS]
        if bad:
            raise ValueError(f"unknown condition(s) {bad}; choose from {tuple(CONDITIONS)}")
        if self.campaigns < 1 or self.rounds < 1:
            raise ValueError("campaigns and rounds must be at least 1")
        if not self.goals or not self.conditions:
            raise ValueError("need at least one goal and one condition")
        for v in (self.max_target_runs, self.max_attacker_calls):
            if v is not None and v < 0:
                raise ValueError("budgets cannot be negative")


# ---- plan --------------------------------------------------------------------------------
def plan(cfg: ExperimentConfig) -> dict:
    """Pure arithmetic: how many campaigns, rounds, target runs and attacker calls at most."""
    cfg.validate()
    per = {}
    for name in cfg.conditions:
        c = CONDITIONS[name]
        n = len(cfg.goals) * cfg.campaigns
        per[name] = {"kind": c.kind, "defenses": list(c.defenses), "campaigns": n,
                     "max_target_runs": n * cfg.rounds,
                     "max_attacker_calls": n * cfg.rounds if c.kind == "adaptive" else 0}
    tot_t = sum(p["max_target_runs"] for p in per.values())
    tot_a = sum(p["max_attacker_calls"] for p in per.values())
    budget_t = tot_t if cfg.max_target_runs is None else cfg.max_target_runs
    budget_a = tot_a if cfg.max_attacker_calls is None else cfg.max_attacker_calls
    return {"goals": list(cfg.goals), "campaigns_per_goal": cfg.campaigns, "rounds": cfg.rounds,
            "conditions": per, "total_campaigns": sum(p["campaigns"] for p in per.values()),
            "max_target_runs": tot_t, "max_attacker_calls": tot_a,
            "budget": {"max_target_runs": budget_t, "max_attacker_calls": budget_a},
            "may_abort_on_budget": budget_t < tot_t or budget_a < tot_a,
            "target_request_limit_per_run": cfg.target_request_limit,
            "attacker_requests_per_call": ATTACKER_MAX_REQUESTS,
            "attacker_model": cfg.attacker_model, "target_model": cfg.target_model, "seed": cfg.seed}


def format_plan(p: dict) -> str:
    L = ["Adaptive attacker experiment: PLAN (nothing has been called)",
         f"  goals ({len(p['goals'])}): {', '.join(p['goals'])}",
         f"  campaigns per goal: {p['campaigns_per_goal']}   rounds per campaign (max): {p['rounds']}",
         f"  attacker model: {p['attacker_model']}   target model: {p['target_model']}   seed: {p['seed']}",
         "  conditions (upper bounds; a campaign stops at its first success):"]
    for name, c in p["conditions"].items():
        d = ",".join(c["defenses"]) or "no defense"
        L.append(f"    {name:18s} {c['kind']:8s} defenses={d:12s} campaigns={c['campaigns']:3d}  "
                 f"target runs <= {c['max_target_runs']:4d}  attacker calls <= {c['max_attacker_calls']:4d}")
    L += [f"  TOTAL upper bound: {p['total_campaigns']} campaigns, {p['max_target_runs']} target runs, "
          f"{p['max_attacker_calls']} attacker calls",
          f"  hard budget this invocation: max_target_runs={p['budget']['max_target_runs']}, "
          f"max_attacker_calls={p['budget']['max_attacker_calls']}"
          + ("   (BELOW the plan: the run may abort part-way and save partial results)"
             if p["may_abort_on_budget"] else ""),
          f"  model API requests: each attacker call is up to {p['attacker_requests_per_call']} requests (normally 1); "
          f"each target run is one agent run of several requests (capped at {p['target_request_limit_per_run']}). "
          "The per-run request count was not measured for this experiment; treat the request total as unknown.",
          "  Set a spend limit with your provider BEFORE running. Kill switch: touch WHETSTONE_KILL (or set "
          "WHETSTONE_KILL_SWITCH=1)."]
    return "\n".join(L)


# ---- running -----------------------------------------------------------------------------
@dataclass
class ExperimentOutcome:
    summary: dict
    exit_code: int
    run_dir: Path
    results: dict[str, list[CampaignResult]] = field(default_factory=dict)


def _version(pkg: str) -> str:
    try:
        return metadata.version(pkg)
    except metadata.PackageNotFoundError:
        return "not installed"


def library_versions() -> dict:
    return {"python": sys.version.split()[0], "platform": platform.platform(),
            "agent-whetstone": _version("agent-whetstone"), "pydantic-ai-slim": _version("pydantic-ai-slim"),
            "pydantic": _version("pydantic"), "anthropic": _version("anthropic"),
            "opentelemetry-api": _version("opentelemetry-api")}


def _git_commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=Path(__file__).parent,
                              capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        return ""


def _tok(rounds, who: str) -> dict:
    key = "attacker_tokens" if who == "attacker" else "target_tokens"
    i = o = 0
    for r in rounds:
        t = getattr(r, key)
        if t:
            i += t.get("input", t.get("input_tokens", 0))
            o += t.get("output", t.get("output_tokens", 0))
    return {"input": i, "output": o}


def summarize_condition(cond: Condition, results: list[CampaignResult], planned: int) -> dict:
    done = [r for r in results if r.status != "aborted"]
    aborted = [r for r in results if r.status == "aborted"]
    wins = [r for r in done if r.success]
    rounds = [x for r in results for x in r.rounds]
    outcomes = Counter(x.outcome for x in rounds)
    model_calls = len(rounds) if cond.kind == "adaptive" else 0
    atts = [r.first_success_round for r in wins]
    per_goal = {}
    for g in sorted({r.goal for r in results}):
        gd = [r for r in done if r.goal == g]
        per_goal[g] = {**stats.rate(sum(r.success for r in gd), len(gd)),
                       "attempts_to_first_success": [r.first_success_round for r in gd if r.success]}
    return {
        "kind": cond.kind, "defenses": list(cond.defenses), "campaigns_planned": planned,
        "campaigns_completed": len(done), "campaigns_aborted": len(aborted),
        "campaign_success": stats.rate(len(wins), len(done)),
        "attempts_to_first_success": {"values": atts, "mean": round(statistics.mean(atts), 2) if atts else None,
                                      "median": statistics.median(atts) if atts else None},
        "per_goal": per_goal,
        "rounds_by_outcome": dict(sorted(outcomes.items())),
        "blocked_by": dict(sorted(Counter(x.blocked_by for x in rounds if x.blocked_by).items())),
        "attacker": {"model_calls": model_calls, "refused": outcomes.get("attacker_refused", 0),
                     "refusal_rate": round(outcomes.get("attacker_refused", 0) / model_calls, 4) if model_calls else None,
                     "rejected_by_guardrails": outcomes.get("attack_rejected", 0),
                     "tokens": _tok(rounds, "attacker")},
        "target": {"runs": sum(1 for x in rounds if x.outcome in ("success", "failure")),
                   "tokens": _tok(rounds, "target")},
        "techniques_tried": dict(sorted(Counter(x.technique for x in rounds if x.technique).items())),
        "campaigns": [r.to_dict() for r in results]}


def compare(summary_conditions: dict) -> dict:
    """Adaptive versus blind (and defended versus undefended adaptive), when both sides have data."""
    out = {}

    def pair(a: str, b: str, label: str) -> None:
        if a in summary_conditions and b in summary_conditions:
            ra, rb = summary_conditions[a]["campaign_success"], summary_conditions[b]["campaign_success"]
            if ra["n"] and rb["n"]:
                out[label] = {"a": a, "b": b, "a_rate": ra, "b_rate": rb,
                              "difference_a_minus_b": round(ra["rate"] - rb["rate"], 4),
                              "fisher_exact_p_two_sided": stats.fisher_exact_two_sided(ra["k"], ra["n"], rb["k"], rb["n"]),
                              "note": "campaigns treated as independent; small n, low power"}
    pair("adaptive_none", "blind_none", "adaptive_vs_blind_no_defense")
    pair("adaptive_none", "adaptive_all_four", "undefended_vs_defended_adaptive")
    return out


def _build_summary(cfg: ExperimentConfig, p: dict, budget: Budget, results: dict[str, list[CampaignResult]],
                   status: str, abort: dict | None, run_id: str, started: str, audits: dict) -> dict:
    conds = {n: summarize_condition(CONDITIONS[n], results.get(n, []), p["conditions"][n]["campaigns"])
             for n in cfg.conditions}
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status, "abort": abort, "run_id": run_id,
        "environment": "SIMULATED sandbox (synthetic inbox, in-memory fake tools, fake CANARY secrets); "
                       "model attacker and model target",
        "meta": {"started_utc": started, "finished_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 "date": started[:10], "seed": cfg.seed, "attacker_model": cfg.attacker_model,
                 "target_model": cfg.target_model, "task": cfg.task, "rounds": cfg.rounds,
                 "campaigns_per_goal": cfg.campaigns, "goals": list(cfg.goals),
                 "libraries": library_versions(), "git_commit": _git_commit(),
                 "target_request_limit_per_run": cfg.target_request_limit, "caveat": CAVEAT},
        "plan": p,
        "budget": budget.to_dict(),
        "conditions": conds,
        "comparison": compare(conds),
        "static_corpus_reference": STATIC_REFERENCE,
        "audit": audits,
    }


def run_experiment(cfg: ExperimentConfig, attacker_factory: Callable[[str], AttackSource],
                   target_factory: Callable[[str, int], TargetFactory], *, kill: KillSwitch | None = None,
                   run_id: str | None = None, say: Callable[[str], None] = lambda s: None) -> ExperimentOutcome:
    """Run the plan. `attacker_factory(model_name)` and `target_factory(model_name, request_limit)` are
    injected so tests never touch a model; the live script passes the real ones."""
    p = plan(cfg)
    kill = kill or KILL
    now = datetime.now(timezone.utc)
    started = now.isoformat(timespec="seconds")
    run_id = run_id or f"{now.strftime('%Y%m%d-%H%M%S')}-seed{cfg.seed}"
    run_dir = Path(cfg.out_dir) / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    budget = Budget(p["budget"]["max_target_runs"], p["budget"]["max_attacker_calls"])
    audits = {n: AuditLog(run_dir / f"audit_{n}.jsonl") for n in cfg.conditions}
    results: dict[str, list[CampaignResult]] = {n: [] for n in cfg.conditions}
    factory = target_factory(cfg.target_model, cfg.target_request_limit)
    adaptive = (attacker_factory(cfg.attacker_model)
                if any(CONDITIONS[n].kind == "adaptive" for n in cfg.conditions) else None)
    abort: dict | None = None
    summary_path = run_dir / "summary.json"

    def write(status: str) -> dict:
        info = {n: {"path": a.path.name, "records": len(a.records()), "head": a.head(),
                    "chain_verified": a.verify()[0]} for n, a in audits.items()}
        s = _build_summary(cfg, p, budget, results, status, abort, run_id, started, info)
        summary_path.write_text(json.dumps(s, indent=2) + "\n")
        return s

    write("in_progress")
    try:
        for c in range(cfg.campaigns):
            for goal in cfg.goals:
                for name in cfg.conditions:
                    cond = CONDITIONS[name]
                    seed = cfg.seed + c
                    source = adaptive if cond.kind == "adaptive" else BlindSource(goal, seed)
                    rc = RunConfig(seed=seed, trials=1, task=cfg.task, target=f"llm:{cfg.target_model}")
                    cid = f"{name}:{goal}:c{c}:s{seed}"
                    res = run_campaign(goal, source, factory, build_stack(list(cond.defenses)), rc,
                                       rounds=cfg.rounds, budget=budget, campaign_id=cid, condition=name,
                                       audit=audits[name], kill=kill)
                    results[name].append(res)
                    say(f"[{cid}] {res.status}" + (f" at round {res.first_success_round}" if res.success else "")
                        + (f" ({res.abort_reason})" if res.abort_reason else ""))
                    write("in_progress")
                    if res.status == "aborted":
                        abort = {"reason": res.abort_reason, "detail": res.abort_detail, "campaign_id": cid}
                        raise StopIteration
    except StopIteration:
        pass
    status = "complete" if abort is None else f"aborted:{abort['reason']}"
    summary = write(status)
    code = EXIT_OK if abort is None else ABORT_EXIT.get(abort["reason"], 5)
    return ExperimentOutcome(summary, code, run_dir, results)
