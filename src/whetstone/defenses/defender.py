"""Defenders propose new rule sets from what the attackers achieved. `LLMDefender` is a stub."""
from __future__ import annotations

from typing import Protocol

from ..models import AttackResult
from .input_screen import RuleSet, default_ruleset
from .proposer import Proposal, RuleProposer


class Defender(Protocol):
    ruleset: RuleSet

    def propose(self, round_no: int, results: list[AttackResult]) -> RuleSet: ...


class RuleProposerDefender:
    """Offline defender: each round, learn rules from the attacks that succeeded this round."""

    def __init__(self, benign_train: list[str], benign_val: list[str],
                 proposer: RuleProposer | None = None, base: RuleSet | None = None) -> None:
        self.proposer = proposer or RuleProposer()
        self.benign_train, self.benign_val = benign_train, benign_val
        self.ruleset = base or default_ruleset()
        self.history: list[Proposal] = []

    def propose(self, round_no: int, results: list[AttackResult]) -> RuleSet:
        wins = {r.attack.id: r.attack for r in results if r.success}
        if not wins:
            return self.ruleset
        prop = self.proposer.propose(list(wins.values()), self.benign_train, self.benign_val,
                                     self.ruleset)
        self.history.append(prop)
        self.ruleset = prop.ruleset
        return self.ruleset


class LLMDefender:
    """NOT BUILT, NOT RUN. A model-driven rule or prompt writer behind the same protocol."""

    ruleset = default_ruleset()

    def propose(self, round_no: int, results: list[AttackResult]) -> RuleSet:
        raise NotImplementedError("LLMDefender is not built and has never been run")
