"""RuleProposer: deterministically synthesise screening rules from attacks that succeeded.

Offline, no model. The algorithm:
1. Take the BODIES of successful attacks (not headers: the corpus uses one fixed attacker
   sender, and a rule on it would be a cheat that "generalises" perfectly).
2. Build word n-grams (n in 2..4) from every decoded view of every body.
3. Keep n-grams that appear in >= min_support distinct attacks and in NO benign
   training message.
4. Greedily pick the candidate covering the most uncovered attacks (ties: longer n-gram, then
   alphabetical) until nothing new is covered or max_rules is reached.
5. Validate each pick against a HELD-OUT benign validation set; reject it if it matches more than
   max_val_fp benign messages. This bounds false positives; it does not eliminate them.
6. Emit a new versioned RuleSet (parent version + 1) with provenance on every rule.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..models import Attack
from ..textnorm import views
from .input_screen import Rule, RuleSet

_TOK = re.compile(r"[a-zà-ÿ0-9_']+")
_STOP = frozenset("a an the of to in on at and or for with is are be your you my me it this that "
                  "as by from".split())


def _tokens(text: str) -> list[str]:
    return _TOK.findall(text)


def _ngrams(text: str, lo: int, hi: int) -> set[tuple[str, ...]]:
    toks = _tokens(text)
    out = set()
    for n in range(lo, hi + 1):
        for i in range(len(toks) - n + 1):
            g = tuple(toks[i:i + n])
            if sum(1 for t in g if t not in _STOP) >= 2:      # skip all-stopword n-grams
                out.add(g)
    return out


_ADDR_TOK, _CHAN_TOK = "zzaddr", "zzchan"
_ADDR_RX = r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"
_CHAN_RX = r"#[\w-]+"


def mask_iocs(text: str) -> str:
    """Replace email addresses and channel names with placeholder tokens, so a learned rule is about
    the instruction and not about one attacker's destination."""
    return re.sub(_CHAN_RX, f" {_CHAN_TOK} ", re.sub(_ADDR_RX, f" {_ADDR_TOK} ", text))


def _doc_ngrams(text: str, lo: int, hi: int, mask: bool = False) -> set[tuple[str, ...]]:
    grams: set = set()
    if mask:
        text = mask_iocs(text)
    for name, v in views(text):
        if name != "rot13":      # the rot13 view of plain text is just a second copy of it
            grams |= _ngrams(v, lo, hi)
    return grams


def _tok_pattern(t: str) -> str:
    return {_ADDR_TOK: _ADDR_RX, _CHAN_TOK: _CHAN_RX}.get(t) or re.escape(t)


def _pattern(g: tuple[str, ...]) -> str:
    return r"\b" + r"\W+".join(_tok_pattern(t) for t in g) + r"\b"


def _matches(pattern: str, text: str) -> bool:
    rx = re.compile(pattern, re.IGNORECASE)
    return any(rx.search(v) for _, v in views(text))


@dataclass
class ProposerConfig:
    ngram_min: int = 2
    ngram_max: int = 4
    min_support: int = 2
    max_rules: int = 12
    max_val_fp: int = 0
    mask_iocs: bool = False          # learn instruction wording, not one attacker's address/channel


@dataclass
class Proposal:
    ruleset: RuleSet
    accepted: list[dict] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)
    candidates: int = 0
    uncovered: int = 0


class RuleProposer:
    def __init__(self, config: ProposerConfig | None = None) -> None:
        self.config = config or ProposerConfig()

    def propose(self, successes: list[Attack], benign_train: list[str], benign_val: list[str],
                base: RuleSet) -> Proposal:
        c = self.config
        texts = [" \n ".join(e.body for e in a.emails) for a in successes]
        docs = [_doc_ngrams(t, c.ngram_min, c.ngram_max, c.mask_iocs) for t in texts]
        benign: set = set()
        for b in benign_train:
            benign |= _doc_ngrams(b, c.ngram_min, c.ngram_max, c.mask_iocs)
        support: dict[tuple, set[int]] = {}
        for i, d in enumerate(docs):
            for g in d:
                if g not in benign:
                    support.setdefault(g, set()).add(i)
        cands = {g: s for g, s in support.items() if len(s) >= c.min_support}
        prop = Proposal(base, candidates=len(cands))
        covered: set[int] = set()
        new_rules: list[Rule] = []
        pool = dict(cands)
        while pool and len(new_rules) < c.max_rules:
            best = max(pool, key=lambda g: (len(pool[g] - covered), len(g), " ".join(g)[::-1]))
            gain = pool[best] - covered
            if not gain:
                break
            pat = _pattern(best)
            fp = sum(1 for b in benign_val if _matches(pat, b))
            name = "proposed:" + "_".join(best)
            if fp > c.max_val_fp:
                prop.rejected.append({"rule": name, "reason": f"matches {fp} held-out benign messages",
                                      "support": len(pool[best])})
                del pool[best]
                continue
            new_rules.append(Rule(name[:80], pat, 1.0, "proposed", len(pool[best])))
            prop.accepted.append({"rule": name, "support": len(pool[best]), "new_coverage": len(gain),
                                  "benign_val_matches": fp})
            covered |= pool[best]
            del pool[best]
        prop.uncovered = len(successes) - len(covered)
        prop.ruleset = base.extend(new_rules, f"proposed from {len(successes)} successful attacks"
                                              f" ({len(new_rules)} rules, {prop.uncovered} uncovered)")
        return prop
