"""Attackers. All offline. `LLMAttacker` is a stub: NOT built, NOT run."""
from __future__ import annotations

import random
from collections import Counter
from typing import Protocol

from ..models import Attack, AttackResult
from .corpus import base_corpus
from .mutators import ALL_MUTATIONS, mutate


class Attacker(Protocol):
    def propose(self, round_no: int, history: list[AttackResult]) -> list[Attack]: ...


class ScriptedAttacker:
    """Plays a fixed list once (round 0) and nothing afterwards."""

    def __init__(self, attacks: list[Attack] | None = None) -> None:
        self.attacks = list(attacks) if attacks is not None else base_corpus()

    def propose(self, round_no: int, history: list[AttackResult]) -> list[Attack]:
        return list(self.attacks) if round_no == 0 else []


class MutatingAttacker:
    """Round 0: the base attacks. Later rounds: mutate the attacks that nearly worked.

    "Nearly worked" uses the result's `progress`: 2 = the target attempted the injected action
    but a guard blocked it, 1 = the content got past screening and the target declined, 0 =
    screened out. Higher progress is mutated first. Mutators that previously produced progress
    are drawn more often. Feedback includes `blocked_by`, so this is a white-box-ish adaptive
    attacker, not a blind one (see THREAT_MODEL.md).
    """

    def __init__(self, base: list[Attack] | None = None, seed: int = 0, budget: int = 120,
                 variants_per_parent: int = 2) -> None:
        self.base = list(base) if base is not None else base_corpus()
        self.rng = random.Random(seed)
        self.budget = budget
        self.k = variants_per_parent
        self.weights: Counter = Counter()
        self._counter = 0
        self._seen: set[tuple] = set()
        self.broken: set[str] = set()      # lineages that already have a success: stop mutating them

    def _new_id(self, a: Attack) -> str:
        self._counter += 1
        return f"{a.lineage or a.id}~m{self._counter}"

    def _weights(self, names: list[str]) -> list[int]:
        return [1 + self.weights[n] for n in names]

    def _parents(self, history: list[AttackResult]) -> list[AttackResult]:
        """Failed attacks to mutate next, best progress first. Learns which mutators help."""
        for r in history:
            if r.success:
                self.broken.add(r.attack.lineage or r.attack.id)
            if r.attack.mutations and (r.success or r.progress >= 1):
                self.weights[r.attack.mutations[-1]] += r.progress
        best: dict[str, AttackResult] = {}
        for r in history:
            if r.success or (r.attack.lineage or r.attack.id) in self.broken:
                continue
            cur = best.get(r.attack.id)
            if cur is None or (r.progress, r.screen_score) > (cur.progress, cur.screen_score):
                best[r.attack.id] = r
        return sorted(best.values(), key=lambda r: (-r.progress, -r.screen_score, r.attack.id))

    def propose(self, round_no: int, history: list[AttackResult]) -> list[Attack]:
        if round_no == 0:
            return list(self.base)
        parents = self._parents(history)
        out: list[Attack] = []
        for r in parents:
            names = list(ALL_MUTATIONS)
            w = self._weights(names)
            made = 0
            tries = 0
            while made < self.k and tries < 12 and len(out) < self.budget:
                tries += 1
                name = self.rng.choices(names, w)[0]
                v = mutate(r.attack, name, self.rng, self._new_id(r.attack))
                if v is None:
                    continue
                key = (v.lineage, tuple(e.body for e in v.emails))
                if key in self._seen:
                    continue
                self._seen.add(key)
                out.append(v)
                made += 1
            if len(out) >= self.budget:
                break
        return out


class BlindMutator(MutatingAttacker):
    """Control for the adaptive attacker: same mutators and budget, but it never looks at results.
    Every round it mutates every base attack, uniformly at random."""

    def _weights(self, names: list[str]) -> list[int]:
        return [1] * len(names)

    def _parents(self, history: list[AttackResult]) -> list[AttackResult]:
        return [AttackResult(a, 0, False, None, False, [], 0.0, 0) for a in self.base]


class LLMAttacker:
    """NOT BUILT, NOT RUN. A placeholder for a model-driven attacker behind the same protocol.

    A live attacker would need an API key and would only ever be pointed at this project's
    own sandbox. Nothing in this repository calls a model for attack generation.
    """

    def propose(self, round_no: int, history: list[AttackResult]) -> list[Attack]:
        raise NotImplementedError("LLMAttacker is not built and has never been run")
