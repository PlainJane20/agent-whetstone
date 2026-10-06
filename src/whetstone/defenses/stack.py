"""DefenseStack: composes the four guardrails and exposes the three hook points.

    prepare(content)        before the target sees anything: InputScreen, then Spotlighting
    guard(name, args)       before every tool call: ToolPolicy, then EgressFilter on the args
    finalize_output(text)   before the answer is delivered: EgressFilter

Any subset can be enabled. `describe()` / `from_description()` round-trip the configuration so
an audit record can be replayed with exactly the same defenses.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .egress import EgressConfig, EgressFilter
from .input_screen import InputScreen, InputScreenConfig, RuleSet, ScreenResult, default_ruleset
from .spotlight import SpotlightConfig, Spotlighting
from .tool_policy import ToolPolicy, ToolPolicyConfig

NAMES = ("input_screen", "spotlight", "egress_filter", "tool_policy")


@dataclass
class Prepared:
    blocked_by: str | None
    content: str
    screen: ScreenResult | None


@dataclass
class DefenseStack:
    input_screen: InputScreen | None = None
    spotlight: Spotlighting | None = None
    egress: EgressFilter | None = None
    tool_policy: ToolPolicy | None = None

    @property
    def names(self) -> list[str]:
        return [n for n, c in zip(NAMES, (self.input_screen, self.spotlight, self.egress,
                                          self.tool_policy)) if c is not None]

    def begin_run(self) -> None:
        if self.tool_policy:
            self.tool_policy.reset()

    def prepare(self, content: str) -> Prepared:
        screen = None
        if self.input_screen:
            screen = self.input_screen.scan(content)
            if screen.blocked:
                return Prepared("input_screen", content, screen)
        if self.spotlight:
            content = self.spotlight.wrap(content)
        return Prepared(None, content, screen)

    def guard(self, name: str, args: dict[str, Any]) -> str | None:
        if self.tool_policy and self.tool_policy.check(name, args):
            return "tool_policy"
        if self.egress and self.egress.check_call(name, args):
            return "egress_filter"
        return None

    def finalize_output(self, text: str) -> tuple[str, str | None]:
        if self.egress:
            safe, reasons = self.egress.filter_output(text)
            if reasons:
                return safe, "egress_filter"
        return text, None

    # -- configuration round trip -------------------------------------------------------
    def describe(self) -> dict:
        return {n: c.describe() for n, c in zip(NAMES, (self.input_screen, self.spotlight,
                                                        self.egress, self.tool_policy)) if c}

    @staticmethod
    def from_description(d: dict) -> "DefenseStack":
        s = DefenseStack()
        if "input_screen" in d:
            c = d["input_screen"]
            s.input_screen = InputScreen(InputScreenConfig(
                RuleSet.from_dict(c["ruleset"]), c["threshold"], c["normalise"], c["decode"], c["depth"]))
        if "spotlight" in d:
            s.spotlight = Spotlighting(SpotlightConfig(**d["spotlight"]))
        if "egress_filter" in d:
            c = d["egress_filter"]
            s.egress = EgressFilter(EgressConfig(tuple(c["secrets"]), tuple(c["encodings"]),
                                                 c["strip_external_images"],
                                                 tuple(c["allowed_image_hosts"])))
        if "tool_policy" in d:
            c = d["tool_policy"]
            s.tool_policy = ToolPolicy(ToolPolicyConfig(
                frozenset(c["allowed_tools"]), tuple(c["recipient_domains"]), tuple(c["channels"]),
                tuple(c["folders"]), c["confirm_external_forward"], c["confirm_delete"],
                c["max_forwards"]))
        return s


def build_stack(names: list[str] | tuple[str, ...] = (), *, ruleset: RuleSet | None = None,
                spotlight_seed: int | None = 0, randomise: bool = True,
                egress_encodings: tuple[str, ...] | None = None) -> DefenseStack:
    """Build a stack from defense names ("all" enables every one)."""
    names = NAMES if "all" in names else tuple(names)
    unknown = set(names) - set(NAMES)
    if unknown:
        raise ValueError(f"unknown defense(s): {sorted(unknown)}; choose from {NAMES} or 'all'")
    s = DefenseStack()
    if "input_screen" in names:
        s.input_screen = InputScreen(InputScreenConfig(ruleset or default_ruleset()))
    if "spotlight" in names:
        s.spotlight = Spotlighting(SpotlightConfig(randomise=randomise, seed=spotlight_seed))
    if "egress_filter" in names:
        cfg = EgressConfig() if egress_encodings is None else EgressConfig(encodings=egress_encodings)
        s.egress = EgressFilter(cfg)
    if "tool_policy" in names:
        s.tool_policy = ToolPolicy()
    return s
