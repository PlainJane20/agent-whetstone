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
import os
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
from .attacks.campaign import (ABORT_EXIT, DEFAULT_ATTACKER_RETRIES, EXIT_OK, KILL, AttackSource, BlindSource, Budget,
                               CampaignResult, KillSwitch, RoundRecord, run_campaign)
from .audit import AuditLog, load_and_verify
from .defenses import build_stack
from .harness import RunConfig, TargetFactory
from .models import DEFAULT_TASK, GOALS
from .retry import (DEFAULT_BASE_S, DEFAULT_CAP_S, DEFAULT_MAX_ATTEMPTS, DEFAULT_MAX_TOTAL_RETRIES, Retrier,
                    RetryPolicy)

DEFAULT_ATTACKER_MODEL_NAME = "claude-haiku-4-5-20251001"
DEFAULT_TARGET_MODEL_NAME = "claude-haiku-4-5-20251001"
DEFAULT_ROUNDS = 8
DEFAULT_CAMPAIGNS = 3
DEFAULT_TARGET_REQUEST_LIMIT = 30      # model requests per target run: a spend guard per run
ATTACKER_MAX_REQUESTS = 3              # model requests per attacker call (LLMAttacker default)
RESULTS_DIR = Path(__file__).resolve().parents[2] / "evals" / "results" / "live_adaptive"
SCHEMA_VERSION = 3          # 3: api_retries, abort_error, aborted_attempts, resumed. 2: refusals split from non-outputs.
SUPPORTED_SCHEMAS = (1, 2, 3)   # readers accept all (see load_summary)

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
    attacker_retries: int = DEFAULT_ATTACKER_RETRIES   # corrective retries per round on a non-output (not on a refusal)
    retry_max_attempts: int = DEFAULT_MAX_ATTEMPTS     # per logical API call, first try included (transient errors only)
    retry_base_s: float = DEFAULT_BASE_S
    retry_cap_s: float = DEFAULT_CAP_S
    max_total_retries: int = DEFAULT_MAX_TOTAL_RETRIES  # global cap on transient retries in one invocation

    def retry_policy(self) -> RetryPolicy:
        return RetryPolicy(self.retry_max_attempts, self.retry_base_s, self.retry_cap_s, self.max_total_retries)

    def validate(self) -> None:
        bad = [g for g in self.goals if g not in GOALS]
        if bad:
            raise ValueError(f"unknown goal(s) {bad}; choose from {GOALS}")
        bad = [c for c in self.conditions if c not in CONDITIONS]
        if bad:
            raise ValueError(f"unknown condition(s) {bad}; choose from {tuple(CONDITIONS)}")
        if self.campaigns < 1 or self.rounds < 1:
            raise ValueError("campaigns and rounds must be at least 1")
        if self.attacker_retries < 0:
            raise ValueError("attacker_retries cannot be negative")
        self.retry_policy().validate()
        if not self.goals or not self.conditions:
            raise ValueError("need at least one goal and one condition")
        for v in (self.max_target_runs, self.max_attacker_calls):
            if v is not None and v < 0:
                raise ValueError("budgets cannot be negative")


# ---- plan --------------------------------------------------------------------------------
def plan_order(cfg: ExperimentConfig) -> list[tuple[int, str, str]]:
    """The deterministic campaign order: campaign index outermost, then goal, then condition."""
    return [(c, goal, name) for c in range(cfg.campaigns) for goal in cfg.goals for name in cfg.conditions]


def campaign_id(cfg: ExperimentConfig, c: int, goal: str, name: str) -> str:
    return f"{name}:{goal}:c{c}:s{cfg.seed + c}"


def plan(cfg: ExperimentConfig, todo: list[tuple[int, str, str]] | None = None) -> dict:
    """Pure arithmetic: how many campaigns, rounds, target runs and attacker calls at most. The attacker-call
    upper bound is rounds x (1 + retries): a retry is a model call and counts against the budget. With `todo`
    (a resume), only those campaigns are counted. Transient-API-error retries of the same call are NOT
    counted here: they are bounded separately by the retry policy (max_total_retries)."""
    cfg.validate()
    per = {}
    for name in cfg.conditions:
        c = CONDITIONS[name]
        n = len(cfg.goals) * cfg.campaigns if todo is None else sum(1 for t in todo if t[2] == name)
        per[name] = {"kind": c.kind, "defenses": list(c.defenses), "campaigns": n,
                     "max_target_runs": n * cfg.rounds,
                     "max_attacker_calls": n * cfg.rounds * (1 + cfg.attacker_retries) if c.kind == "adaptive" else 0}
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
            "attacker_retries_per_round": cfg.attacker_retries,
            "attacker_model": cfg.attacker_model, "target_model": cfg.target_model, "seed": cfg.seed,
            "retry_policy": cfg.retry_policy().to_dict()}


def format_plan(p: dict, title: str = "Adaptive attacker experiment: PLAN (nothing has been called)") -> str:
    L = [title,
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
          f"  attacker calls include up to {p['attacker_retries_per_round']} corrective retry per round when the "
          f"attacker returns no structured output (not after a genuine refusal): upper bound = rounds x "
          f"(1 + {p['attacker_retries_per_round']}); typical use is far lower.",
          f"  hard budget this invocation: max_target_runs={p['budget']['max_target_runs']}, "
          f"max_attacker_calls={p['budget']['max_attacker_calls']}"
          + ("   (BELOW the plan: the run may abort part-way and save partial results)"
             if p["may_abort_on_budget"] else ""),
          f"  model API requests: each attacker call is up to {p['attacker_requests_per_call']} requests (normally 1); "
          f"each target run is one agent run of several requests (capped at {p['target_request_limit_per_run']}). "
          "The per-run request count was not measured for this experiment; treat the request total as unknown.",
          f"  transient API errors (429/5xx/529, connection, timeout) are retried with backoff: up to "
          f"{p['retry_policy']['max_attempts']} attempts per call, base {p['retry_policy']['base_s']}s, cap "
          f"{p['retry_policy']['cap_s']}s, at most {p['retry_policy']['max_total_retries']} retries in total. "
          "A retry re-sends the SAME request and may be billed again; retries are not in the call bounds above "
          "and are reported as api_retries. Permanent errors (400 incl. no credit, 401, 403, 404) abort at once.",
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
    adaptive = cond.kind == "adaptive"
    model_calls = sum(x.attacker_calls for x in rounds) if adaptive else 0
    n_rounds = len(rounds) if adaptive else 0
    retries = sum(x.retries for x in rounds) if adaptive else 0
    recovered = sum(1 for x in rounds if x.retries and x.outcome not in ("attacker_no_structured_output", "attacker_refused"))
    wasted = [r.campaign_id for r in results if r.all_rounds_wasted]

    def rate(k: int):
        return round(k / n_rounds, 4) if n_rounds else None
    atts = [r.first_success_round for r in wins]
    per_goal = {}
    for g in sorted({r.goal for r in results}):
        gd = [r for r in done if r.goal == g]
        per_goal[g] = {**stats.rate(sum(r.success for r in gd), len(gd)),
                       "attempts_to_first_success": [r.first_success_round for r in gd if r.success]}
    return {
        "kind": cond.kind, "defenses": list(cond.defenses), "campaigns_planned": planned,
        "campaigns_completed": len(done), "campaigns_aborted": len(aborted),
        "api_retries": sum(r.api_retries for r in results),
        "campaign_success": stats.rate(len(wins), len(done)),
        "attempts_to_first_success": {"values": atts, "mean": round(statistics.mean(atts), 2) if atts else None,
                                      "median": statistics.median(atts) if atts else None},
        "per_goal": per_goal,
        "rounds_by_outcome": dict(sorted(outcomes.items())),
        "blocked_by": dict(sorted(Counter(x.blocked_by for x in rounds if x.blocked_by).items())),
        "attacker": {"model_calls": model_calls, "rounds": n_rounds,
                     "refused": outcomes.get("attacker_refused", 0),
                     "refusal_rate": rate(outcomes.get("attacker_refused", 0)),
                     "no_structured_output": outcomes.get("attacker_no_structured_output", 0),
                     "no_structured_output_rate": rate(outcomes.get("attacker_no_structured_output", 0)),
                     "retries_used": retries, "retries_recovered": recovered,
                     "rejected_by_guardrails": outcomes.get("attack_rejected", 0),
                     "rates_are_per": "adaptive round (model_calls also counts retries); refusal vs "
                                      "no-structured-output is a keyword heuristic",
                     "tokens": _tok(rounds, "attacker")},
        "campaigns_all_rounds_wasted": len(wasted),
        "warnings": ([f"{len(wasted)} campaign(s) had every round wasted (refusal / no structured output / "
                      f"guardrail rejection; the target was never run): {wasted}. Their 0 successes say "
                      "nothing about the target."] if wasted else []),
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


def _atomic_write(path: Path, text: str) -> None:
    """Write via a temp file in the same directory, then rename: a crash never leaves a half-written summary."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text)
    os.replace(tmp, path)


def _build_summary(cfg: ExperimentConfig, p: dict, budget: Budget, results: dict[str, list[CampaignResult]],
                   status: str, abort: dict | None, run_id: str, started: str, audits: dict, *,
                   meta: dict | None = None, aborted_attempts: list | None = None, resumed: dict | None = None,
                   retrier: Retrier | None = None, resume_plan: dict | None = None) -> dict:
    conds = {n: summarize_condition(CONDITIONS[n], results.get(n, []), p["conditions"][n]["campaigns"])
             for n in cfg.conditions}
    finished = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if meta is None:
        meta = {"attacker_retries": cfg.attacker_retries, "started_utc": started, "finished_utc": finished,
                "date": started[:10], "seed": cfg.seed, "attacker_model": cfg.attacker_model,
                "target_model": cfg.target_model, "task": cfg.task, "rounds": cfg.rounds,
                "campaigns_per_goal": cfg.campaigns, "goals": list(cfg.goals),
                "libraries": library_versions(), "git_commit": _git_commit(),
                "target_request_limit_per_run": cfg.target_request_limit, "caveat": CAVEAT}
    else:       # a resume keeps the original run's metadata; only the finish time moves
        meta = {**meta, "finished_utc": finished}
    total_retries = sum(c["api_retries"] for c in conds.values())
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status, "abort": abort, "run_id": run_id,
        "environment": "SIMULATED sandbox (synthetic inbox, in-memory fake tools, fake CANARY secrets); "
                       "model attacker and model target",
        "meta": meta,
        "plan": p,
        "budget": budget.to_dict(),
        "api_retries": {"in_current_campaigns": total_retries,
                        "this_invocation": retrier.total_retries if retrier else 0,
                        "policy": cfg.retry_policy().to_dict(),
                        "note": "transient API errors retried with backoff; a retry re-sends the same request, "
                                "is not a new round or call against the budget, and may be billed again"},
        "conditions": conds,
        "aborted_attempts": list(aborted_attempts or []),
        "resumed": resumed,
        "resume_plan": resume_plan,
        "comparison": compare(conds),
        "static_corpus_reference": STATIC_REFERENCE,
        "audit": audits,
    }


def _abort_dict(res: CampaignResult, cid: str) -> dict:
    return {"reason": res.abort_reason, "detail": res.abort_detail, "campaign_id": cid, "error": res.abort_error}


def _execute(cfg: ExperimentConfig, p: dict, run_dir: Path, run_id: str, started: str, budget: Budget,
             audits: dict, results: dict[str, list[CampaignResult]], todo: list[tuple[int, str, str]],
             attacker_factory, target_factory, kill: KillSwitch, retrier: Retrier,
             say: Callable[[str], None], build_kw: dict) -> ExperimentOutcome:
    """The shared campaign loop of a fresh run and a resume: runs `todo` in order, rewrites summary.json
    atomically after every campaign, stops at the first abort."""
    factory = target_factory(cfg.target_model, cfg.target_request_limit)
    needs_attacker = any(CONDITIONS[n].kind == "adaptive" for _, _, n in todo)
    adaptive = attacker_factory(cfg.attacker_model) if needs_attacker else None
    abort: dict | None = None
    summary_path = run_dir / "summary.json"

    def write(status: str) -> dict:
        info = {n: {"path": a.path.name, "records": len(a.records()), "head": a.head(),
                    "chain_verified": a.verify()[0]} for n, a in audits.items()}
        s = _build_summary(cfg, p, budget, results, status, abort, run_id, started, info, retrier=retrier,
                           **build_kw)
        _atomic_write(summary_path, json.dumps(s, indent=2) + "\n")
        return s

    write("in_progress")
    for c, goal, name in todo:
        cond = CONDITIONS[name]
        seed = cfg.seed + c
        source = adaptive if cond.kind == "adaptive" else BlindSource(goal, seed)
        rc = RunConfig(seed=seed, trials=1, task=cfg.task, target=f"llm:{cfg.target_model}")
        cid = campaign_id(cfg, c, goal, name)
        res = run_campaign(goal, source, factory, build_stack(list(cond.defenses)), rc,
                           rounds=cfg.rounds, budget=budget, campaign_id=cid, condition=name,
                           audit=audits[name], kill=kill, attacker_retries=cfg.attacker_retries, retrier=retrier)
        results[name].append(res)
        say(f"[{cid}] {res.status}" + (f" at round {res.first_success_round}" if res.success else "")
            + (f" ({res.abort_reason})" if res.abort_reason else "")
            + (f" [api retries: {res.api_retries}]" if res.api_retries else ""))
        if res.status == "aborted":
            abort = _abort_dict(res, cid)
            say(f"  abort detail: {res.abort_detail}")
            break
        write("in_progress")
    status = "complete" if abort is None else f"aborted:{abort['reason']}"
    summary = write(status)
    code = EXIT_OK if abort is None else ABORT_EXIT.get(abort["reason"], 5)
    return ExperimentOutcome(summary, code, run_dir, results)


def run_experiment(cfg: ExperimentConfig, attacker_factory: Callable[[str], AttackSource],
                   target_factory: Callable[[str, int], TargetFactory], *, kill: KillSwitch | None = None,
                   run_id: str | None = None, say: Callable[[str], None] = lambda s: None,
                   retrier: Retrier | None = None) -> ExperimentOutcome:
    """Run the plan. `attacker_factory(model_name)` and `target_factory(model_name, request_limit)` are
    injected so tests never touch a model; the live script passes the real ones. `retrier` is injectable
    (sleep, clock, rng) so tests never wait."""
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
    return _execute(cfg, p, run_dir, run_id, started, budget, audits, results, plan_order(cfg), attacker_factory,
                    target_factory, kill, retrier or Retrier(cfg.retry_policy()), say, {})


# ---- resuming ---------------------------------------------------------------------------------
class ResumeError(ValueError):
    """A run cannot be resumed (missing, unreadable, config mismatch, broken audit chain)."""


# meta key -> getter on the config; only keys present in the saved meta are compared (v1 summaries lack some)
_MATCH = {"goals": lambda c: list(c.goals), "rounds": lambda c: c.rounds, "campaigns_per_goal": lambda c: c.campaigns,
          "seed": lambda c: c.seed, "attacker_model": lambda c: c.attacker_model,
          "target_model": lambda c: c.target_model, "task": lambda c: c.task,
          "attacker_retries": lambda c: c.attacker_retries,
          "target_request_limit_per_run": lambda c: c.target_request_limit}


def resolve_run_dir(spec: str | Path, out_dir: Path = RESULTS_DIR) -> Path:
    """`spec` is a run directory, or a run id inside `out_dir`."""
    for cand in (Path(spec), Path(out_dir) / str(spec)):
        if (cand / "summary.json").is_file():
            return cand
    raise ResumeError(f"no summary.json found for {spec!r} (looked at {Path(spec)} and {Path(out_dir) / str(spec)})")


def cfg_from_summary(saved: dict, **overrides) -> ExperimentConfig:
    """The ExperimentConfig that produced `saved` (budgets, retry policy and out_dir are per-invocation and
    come from `overrides` or the defaults)."""
    m = saved["meta"]
    cfg = ExperimentConfig(
        goals=tuple(m["goals"]), campaigns=m["campaigns_per_goal"], rounds=m["rounds"], seed=m["seed"],
        conditions=tuple(saved["conditions"]), attacker_model=m["attacker_model"], target_model=m["target_model"],
        task=m.get("task", DEFAULT_TASK),
        target_request_limit=m.get("target_request_limit_per_run", DEFAULT_TARGET_REQUEST_LIMIT),
        attacker_retries=m.get("attacker_retries", DEFAULT_ATTACKER_RETRIES))
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg


def config_mismatches(saved: dict, cfg: ExperimentConfig) -> list[str]:
    bad = []
    m = saved["meta"]
    for key, get in _MATCH.items():
        if key in m and m[key] != get(cfg):
            bad.append(f"{key}: saved run has {m[key]!r}, this invocation has {get(cfg)!r}")
    if list(saved["conditions"]) != list(cfg.conditions):
        bad.append(f"conditions: saved run has {list(saved['conditions'])!r}, this invocation has {list(cfg.conditions)!r}")
    return bad


def campaign_from_dict(d: dict) -> CampaignResult:
    """Rebuild a CampaignResult from its summary.json record (unknown/missing round fields tolerated)."""
    fields = set(RoundRecord.__dataclass_fields__)
    rounds = [RoundRecord(**{k: v for k, v in r.items() if k in fields}) for r in d.get("rounds", [])]
    return CampaignResult(
        campaign_id=d["campaign_id"], goal=d["goal"], condition=d["condition"], attacker_model=d["attacker_model"],
        target=d["target"], seed=d["seed"], rounds_planned=d["rounds_planned"], rounds=rounds, status=d["status"],
        abort_reason=d.get("abort_reason"), abort_detail=d.get("abort_detail", ""),
        abort_error=d.get("abort_error"), api_retries=d.get("api_retries", 0))


@dataclass
class ResumeState:
    run_dir: Path
    saved: dict
    carried: dict[str, list[CampaignResult]]          # completed campaigns, in saved order
    aborted: list[dict]                               # aborted-attempt records (earlier ones first)
    todo: list[tuple[int, str, str]]
    audit_chains: dict[str, tuple[bool, int]]


def prepare_resume(run_dir: Path, cfg: ExperimentConfig) -> ResumeState:
    """Read-only: load, check the config and the audit chains, and work out what is left. Raises ResumeError."""
    try:
        saved = load_summary(Path(run_dir) / "summary.json")
    except (OSError, ValueError, KeyError) as exc:
        raise ResumeError(f"cannot read {Path(run_dir) / 'summary.json'}: {exc}") from exc
    bad = config_mismatches(saved, cfg)
    if bad:
        raise ResumeError("refusing to resume: this configuration does not match the saved run:\n  - "
                          + "\n  - ".join(bad))
    carried: dict[str, list[CampaignResult]] = {n: [] for n in cfg.conditions}
    aborted = list(saved.get("aborted_attempts") or [])
    done_ids: set[str] = set()
    for name in cfg.conditions:
        for d in saved["conditions"][name].get("campaigns", []):
            if d["status"] == "aborted":
                aborted.append({"campaign_id": d["campaign_id"], "condition": name,
                                "abort_reason": d.get("abort_reason"), "abort_detail": d.get("abort_detail", ""),
                                "abort_error": d.get("abort_error"),
                                "moved_at_resume_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                "campaign": d})
            else:
                carried[name].append(campaign_from_dict(d))
                done_ids.add(d["campaign_id"])
    todo = [t for t in plan_order(cfg) if campaign_id(cfg, t[0], t[1], t[2]) not in done_ids]
    chains = {}
    for name in cfg.conditions:
        path = Path(run_dir) / f"audit_{name}.jsonl"
        if not path.is_file():
            if carried[name] or any(a["condition"] == name for a in aborted):
                raise ResumeError(f"audit log {path.name} is missing but the summary has campaigns for {name}")
            chains[name] = (True, 0)
            continue
        ok, bad_at, n = load_and_verify(path)
        if not ok:
            raise ResumeError(f"refusing to resume: audit chain {path.name} does not verify (first bad record {bad_at})")
        chains[name] = (ok, n)
    return ResumeState(Path(run_dir), saved, carried, aborted, todo, chains)


def resume_experiment(cfg: ExperimentConfig, run_dir: Path, attacker_factory: Callable[[str], AttackSource],
                      target_factory: Callable[[str, int], TargetFactory], *, kill: KillSwitch | None = None,
                      say: Callable[[str], None] = lambda s: None, retrier: Retrier | None = None,
                      state: ResumeState | None = None) -> ExperimentOutcome:
    """Run only the campaigns the saved run did not complete, in the original order, with the same seeds,
    appending to the same hash-chained audit logs. Aborted campaigns are re-run fresh and their records are
    kept under `aborted_attempts`. Budgets apply to this invocation's new work only. A complete run is a no-op
    (nothing is written)."""
    kill = kill or KILL
    st = state or prepare_resume(Path(run_dir), cfg)
    saved = st.saved
    if not st.todo:
        return ExperimentOutcome(saved, EXIT_OK, st.run_dir, st.carried)
    full = plan(cfg)
    rplan = plan(cfg, st.todo)
    budget = Budget(rplan["budget"]["max_target_runs"], rplan["budget"]["max_attacker_calls"])
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    prev = saved.get("resumed") or {}
    carried_n = sum(len(v) for v in st.carried.values())
    entry = {"resumed_utc": now, "carried_over_campaigns": carried_n, "remaining_campaigns": len(st.todo),
             "aborted_attempts_total": len(st.aborted), "from_status": saved["status"],
             "from_abort": saved.get("abort"), "prior_budget_used": saved.get("budget"),
             "git_commit": _git_commit(), "libraries": library_versions(),
             "retry_policy": cfg.retry_policy().to_dict(),
             "carried_from_schema_version": saved.get("loaded_from_schema_version"),
             "carried_schema_note": saved.get("schema_note")}
    resumed = {"count": prev.get("count", 0) + 1, "first_resumed_utc": prev.get("first_resumed_utc", now),
               "last_resumed_utc": now, "carried_over_campaigns": carried_n, "remaining_at_resume": len(st.todo),
               "history": [*prev.get("history", []), entry]}
    audits = {n: AuditLog(st.run_dir / f"audit_{n}.jsonl") for n in cfg.conditions}
    for n, a in audits.items():          # mark the boundary inside every chain; appends with the last hash
        a.append("experiment_resumed", {"run_id": saved["run_id"], "resumed_utc": now, "condition": n,
                                        "carried_over_campaigns": len(st.carried[n]),
                                        "remaining_campaigns": sum(1 for t in st.todo if t[2] == n),
                                        "previous_head": a.head()})
    results = {n: list(v) for n, v in st.carried.items()}
    return _execute(cfg, full, st.run_dir, saved["run_id"], saved["meta"]["started_utc"], budget, audits, results,
                    st.todo, attacker_factory, target_factory, kill, retrier or Retrier(cfg.retry_policy()), say,
                    {"meta": saved["meta"], "aborted_attempts": st.aborted, "resumed": resumed,
                     "resume_plan": rplan})


# ---- reading ---------------------------------------------------------------------------------
V1_NOTE = ("schema_version 1 summary (written before refusals and non-outputs were told apart): its "
           "'attacker_refused' rounds and 'refused' / 'refusal_rate' may include plain-text format failures, so "
           "they can overstate refusals. Fields added in v2 are filled with None where not recorded.")
_V3_DEFAULTS = {"aborted_attempts": [], "resumed": None, "resume_plan": None, "api_retries": None}
_V2_ATTACKER_DEFAULTS = {"no_structured_output": None, "no_structured_output_rate": None, "retries_used": None,
                         "retries_recovered": None, "rounds": None}


def load_summary(path) -> dict:
    """Read a summary.json of schema version 1, 2 or 3. Older versions are returned unchanged except that the
    newer fields are added as None/empty (v1: the v2 fields too) and `loaded_from_schema_version` / `schema_note` say so; the file
    on disk is never modified. Unknown versions raise ValueError."""
    s = json.loads(Path(path).read_text())
    v = s.get("schema_version")
    if v not in SUPPORTED_SCHEMAS:
        raise ValueError(f"unsupported summary schema_version {v!r}; supported: {SUPPORTED_SCHEMAS}")
    s["loaded_from_schema_version"] = v
    if v < 3:
        for k, d in _V3_DEFAULTS.items():
            s.setdefault(k, d)
        for c in s.get("conditions", {}).values():
            c.setdefault("api_retries", None)
            for camp in c.get("campaigns", []):
                camp.setdefault("abort_error", None)
                camp.setdefault("api_retries", None)
    if v == 1:
        s["schema_note"] = V1_NOTE
        for c in s.get("conditions", {}).values():
            for k, d in _V2_ATTACKER_DEFAULTS.items():
                c.get("attacker", {}).setdefault(k, d)
            c.setdefault("campaigns_all_rounds_wasted", None)
            c.setdefault("warnings", [])
    return s
