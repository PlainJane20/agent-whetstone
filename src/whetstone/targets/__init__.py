"""Targets: a simulated gullible agent (used for every number) and an LLM target (run live once, by hand)."""
from .base import Guard, Target, ToolBox
from .gullible import DEFAULT_PROFILE, GullibleTarget, SusceptibilityProfile
from .llm import LLMTarget

__all__ = ["Guard", "Target", "ToolBox", "DEFAULT_PROFILE", "GullibleTarget",
           "SusceptibilityProfile", "LLMTarget"]
