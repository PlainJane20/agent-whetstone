"""Adaptive campaign loop: for one goal, up to R rounds of write -> plant -> run -> score -> feed back.

STATUS: built, offline-tested only (stub attackers and stub targets), not run live.

Each round: the attacker (model) writes an email given the feedback so far; the email is
validated by deterministic guardrails; a fresh sandbox is built with it planted among the benign
inbox; the SAME harness (`run_attack`, optional defense stack) runs the target; the deterministic
oracle scores it. The attacker never judges success. The loop stops on the first success, when
rounds run out, or when a hard guard trips (budget, kill switch, hard error), in which case the
partial result is kept and the caller is told why.

Every round writes one hash-chained audit record (target label, attacker model, campaign id).
"""
from __future__ import annotations

import hashlib
import os
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol

from .. import tracing
from ..audit import AuditLog
from ..defenses import DefenseStack
from ..harness import RunConfig, TargetFactory, run_attack
from ..models import GOALS, Attack
from ..sandbox import make_canaries
from .attackers import BlindMutator
from .corpus import base_corpus
from .feedback import (Generation, RoundFeedback, _clip, draft_to_attack, feedback_from_result)
from .guardrails import validate_draft

OUTCOMES = ("success", "failure", "attacker_refused", "attack_rejected")
EXIT_OK, EXIT_BUDGET, EXIT_KILL, EXIT_ERROR = 0, 3, 4, 5
ABORT_EXIT = {"budget_attacker_calls": EXIT_BUDGET, "budget_target_runs": EXIT_BUDGET,
              "kill_switch": EXIT_KILL, "attacker_error": EXIT_ERROR, "target_error": EXIT_ERROR}


# ---- guards ------------------------------------------------------------------------------
class KillSwitch:
    """A global stop. Trip it in code (`trip`), by setting WHETSTONE_KILL_SWITCH=1 in the
    environment, or by creating the file named by WHETSTONE_KILL_FILE (default ./WHETSTONE_KILL)
    from another terminal. Checked before every attacker call and every target run."""

    ENV = "WHETSTONE_KILL_SWITCH"
    FILE_ENV = "WHETSTONE_KILL_FILE"

    def __init__(self, path: str | Path | None = None, environ=None) -> None:
        self._reason: str | None = None
        self._path = path
        self._environ = environ if environ is not None else os.environ

    def trip(self, reason: str = "tripped in code") -> None:
        self._reason = reason

    def reset(self) -> None:
        self._reason = None

    def reason(self) -> str | None:
        if self._reason:
            return self._reason
        if str(self._environ.get(self.ENV, "")).strip().lower() in ("1", "true", "yes", "on"):
            return f"{self.ENV} is set"
        path = self._path or self._environ.get(self.FILE_ENV) or "WHETSTONE_KILL"
        if Path(path).exists():
            return f"kill file {path} exists"
        return None


KILL = KillSwitch()


@dataclass
class Budget:
    """Hard per-invocation caps, shared by every campaign of one run."""
    max_target_runs: int
    max_attacker_calls: int
    target_runs: int = 0
    attacker_calls: int = 0

    def can_call_attacker(self) -> bool:
        return self.attacker_calls < self.max_attacker_calls

    def can_run_target(self) -> bool:
        return self.target_runs < self.max_target_runs

    def to_dict(self) -> dict:
        return {"max_target_runs": self.max_target_runs, "max_attacker_calls": self.max_attacker_calls,
                "used_target_runs": self.target_runs, "used_attacker_calls": self.attacker_calls}


# ---- attack sources ----------------------------------------------------------------------
class AttackSource(Protocol):
    label: str                 # model name, or "blind_mutation"
    uses_model: bool           # does each step cost an attacker model call?

    def next(self, goal: str, round_no: int, rounds: int, feedback: list[RoundFeedback]) -> Generation: ...


class BlindSource:
    """Control: the existing BlindMutator, one goal, never looks at results. Costs no model calls.
    One attempt per round, so a campaign of R rounds is R blind attempts: the same attempt budget
    as an adaptive campaign. Base attacks are shuffled by seed so the budget is not spent on the
    first few families only."""

    label = "blind_mutation"
    uses_model = False

    def __init__(self, goal: str, seed: int = 0) -> None:
        base = [a for a in base_corpus() if a.goal == goal]
        random.Random(f"{seed}|{goal}").shuffle(base)
        self._m = BlindMutator(base=base, seed=seed, variants_per_parent=1, budget=len(base))
        self._queue: list[Attack] = []
        self._batches = 0

    def next(self, goal: str, round_no: int, rounds: int, feedback: list[RoundFeedback]) -> Generation:
        while not self._queue:
            self._batches += 1
            if self._batches > 50:
                raise RuntimeError("blind mutator ran out of distinct variants")
            self._queue = self._m.propose(self._batches, [])
        return Generation(attack=self._queue.pop(0))


# ---- records -----------------------------------------------------------------------------
@dataclass
class RoundRecord:
    round_no: int
    outcome: str                       # one of OUTCOMES
    technique: str = ""
    subject: str = ""
    body: str = ""                     # the attack text (kept in results and audit, never in span attributes)
    rationale: str = ""
    blocked_by: str | None = None
    tool_names: list[str] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)      # guardrail rejection reasons
    refusal_text: str = ""
    attacker_tokens: dict | None = None
    target_tokens: dict | None = None

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class CampaignResult:
    campaign_id: str
    goal: str
    condition: str
    attacker_model: str
    target: str
    seed: int
    rounds_planned: int
    rounds: list[RoundRecord] = field(default_factory=list)
    status: str = "exhausted"          # success | exhausted | aborted
    abort_reason: str | None = None
    abort_detail: str = ""

    @property
    def success(self) -> bool:
        return self.status == "success"

    @property
    def first_success_round(self) -> int | None:
        return next((r.round_no for r in self.rounds if r.outcome == "success"), None)

    def to_dict(self) -> dict:
        return {"campaign_id": self.campaign_id, "goal": self.goal, "condition": self.condition,
                "attacker_model": self.attacker_model, "target": self.target, "seed": self.seed,
                "rounds_planned": self.rounds_planned, "status": self.status,
                "abort_reason": self.abort_reason, "abort_detail": self.abort_detail,
                "first_success_round": self.first_success_round,
                "rounds": [r.to_dict() for r in self.rounds]}


def _capturing(factory: TargetFactory, box: list) -> TargetFactory:
    """Wrap a target factory so the campaign can read the target's meta (token usage) afterwards."""
    def make(tb, seed):
        inner = factory(tb, seed)

        class _Proxy:
            def run(self, task, untrusted_content):
                r = inner.run(task, untrusted_content)
                box.append(r.meta)
                return r
        return _Proxy()
    return make


# ---- the loop ----------------------------------------------------------------------------
def run_campaign(goal: str, source: AttackSource, factory: TargetFactory, stack: DefenseStack,
                 cfg: RunConfig, *, rounds: int = 8, budget: Budget, campaign_id: str,
                 condition: str = "", audit: AuditLog | None = None, kill: KillSwitch | None = None
                 ) -> CampaignResult:
    if goal not in GOALS:
        raise ValueError(f"unknown goal {goal!r}; choose from {GOALS}")
    kill = kill or KILL
    out = CampaignResult(campaign_id, goal, condition, source.label, cfg.target, cfg.seed, rounds)
    canaries = tuple(make_canaries(cfg.seed).values())
    feedback: list[RoundFeedback] = []
    defenses = stack.describe()

    def audit_round(rec: RoundRecord, attack: Attack | None, output_sha: str = "") -> None:
        if audit is None:
            return
        audit.append("adaptive_round", {
            "campaign_id": campaign_id, "condition": condition, "goal": goal, "round": rec.round_no,
            "attacker_model": source.label, "target": cfg.target, "seed": cfg.seed, "task": cfg.task,
            "defenses": defenses, "attack": attack.to_dict() if attack else None,
            "draft": ({"technique": rec.technique, "subject": rec.subject, "body": rec.body,
                       "rationale": rec.rationale} if attack is None and rec.technique else None),
            "outcome": {"outcome": rec.outcome, "blocked_by": rec.blocked_by, "violations": rec.violations,
                        "refusal_text": rec.refusal_text, "output_sha256": output_sha},
            "tool_names": rec.tool_names, "attacker_tokens": rec.attacker_tokens,
            "target_tokens": rec.target_tokens})

    def abort(reason: str, detail: str = "") -> None:
        out.status, out.abort_reason, out.abort_detail = "aborted", reason, detail

    with tracing.span("campaign", goal=goal, condition=condition, attacker_model=source.label,
                      target=cfg.target, campaign_id=campaign_id, rounds_planned=rounds) as csp:
        for n in range(1, rounds + 1):
            why = kill.reason()
            if why:
                abort("kill_switch", why)
                break
            if source.uses_model and not budget.can_call_attacker():
                abort("budget_attacker_calls", f"max_attacker_calls={budget.max_attacker_calls}")
                break
            if not budget.can_run_target():
                abort("budget_target_runs", f"max_target_runs={budget.max_target_runs}")
                break
            with tracing.span("round", round=n, goal=goal, condition=condition) as rsp:
                if source.uses_model:
                    budget.attacker_calls += 1       # count before the call: it may be billed even if it fails
                try:
                    with tracing.span("attacker_call", model=source.label, round=n, goal=goal) as asp:
                        gen = source.next(goal, n, rounds, feedback)
                        tracing.set_attrs(asp, refused=gen.refused, input_tokens=gen.input_tokens,
                                          output_tokens=gen.output_tokens)
                except Exception as exc:             # auth, network, quota: stop cleanly, keep partials
                    abort("attacker_error", f"{type(exc).__name__}: {_clip(str(exc), 200)}")
                    break
                atokens = ({"input": gen.input_tokens, "output": gen.output_tokens}
                           if source.uses_model else None)
                if gen.refused or (gen.draft is None and gen.attack is None):
                    rec = RoundRecord(n, "attacker_refused", refusal_text=gen.refusal_text,
                                      attacker_tokens=atokens)
                    feedback.append(RoundFeedback(n, "-", "-", "", "attacker_refused",
                                                  note=gen.refusal_text or "no output"))
                    audit_round(rec, None)
                    tracing.set_attrs(rsp, outcome=rec.outcome)
                    out.rounds.append(rec)
                    continue
                attack = gen.attack
                if attack is None:
                    d = gen.draft
                    bad = validate_draft(d)
                    if bad:
                        rec = RoundRecord(n, "attack_rejected", d.technique, d.subject, d.body,
                                          d.rationale, violations=bad, attacker_tokens=atokens)
                        feedback.append(RoundFeedback(n, d.technique, _clip(d.subject, 120), "",
                                                      "attack_rejected", note="; ".join(bad)))
                        audit_round(rec, None)
                        tracing.set_attrs(rsp, outcome=rec.outcome)
                        out.rounds.append(rec)
                        continue
                    attack = draft_to_attack(d, goal, f"llm/{campaign_id}/r{n}", n)
                e = attack.emails[0]
                box: list = []
                budget.target_runs += 1
                try:
                    res = run_attack(attack, n, stack, _capturing(factory, box), cfg, None)
                except Exception as exc:
                    abort("target_error", f"{type(exc).__name__}: {_clip(str(exc), 200)}")
                    break
                usage = (box[-1].get("usage") if box else None)
                rec = RoundRecord(
                    n, "success" if res.success else "failure", attack.technique, e.subject, e.body,
                    gen.draft.rationale if gen.draft else "", res.blocked_by,
                    [c.name for c in res.tool_calls], attacker_tokens=atokens, target_tokens=usage)
                feedback.append(feedback_from_result(n, res, canaries))
                audit_round(rec, attack, hashlib.sha256(res.output_text.encode()).hexdigest())
                tracing.set_attrs(rsp, outcome=rec.outcome, technique=attack.technique,
                                  blocked_by=res.blocked_by or "none")
                out.rounds.append(rec)
                if res.success:
                    out.status = "success"
                    break
        tracing.set_attrs(csp, status=out.status, rounds_run=len(out.rounds),
                          abort_reason=out.abort_reason)
    if audit is not None:
        audit.append("campaign_end", {"campaign_id": campaign_id, "condition": condition, "goal": goal,
                                      "attacker_model": source.label, "target": cfg.target,
                                      "status": out.status, "abort_reason": out.abort_reason,
                                      "rounds_run": len(out.rounds),
                                      "first_success_round": out.first_success_round})
    return out
