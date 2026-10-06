"""ToolPolicy: a deterministic allow-list for tools, recipients and channels.

External forwarding and deletion need a confirmation. In an unattended run the default
confirmation callback denies, which is the safe default; a human-in-the-loop product would
supply a real one. State (forward and delete counters) is per run: call `reset()`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from ..models import INTERNAL_CHANNEL, INTERNAL_DOMAIN
from ..sandbox import TOOL_KINDS


def deny_all(name: str, args: dict[str, Any]) -> bool:
    return False


@dataclass
class ToolPolicyConfig:
    allowed_tools: frozenset = field(default_factory=lambda: frozenset(TOOL_KINDS))
    recipient_domains: tuple[str, ...] = (INTERNAL_DOMAIN,)
    channels: tuple[str, ...] = (INTERNAL_CHANNEL,)
    folders: tuple[str, ...] = ("inbox", "archive", "important")
    confirm_external_forward: bool = True
    confirm_delete: bool = True
    max_forwards: int = 3
    confirm: Callable[[str, dict], bool] = deny_all


class ToolPolicy:
    name = "tool_policy"

    def __init__(self, config: ToolPolicyConfig | None = None) -> None:
        self.config = config or ToolPolicyConfig()
        self.reset()

    def reset(self) -> None:
        self.forwards = 0
        self.deletes = 0

    def check(self, name: str, args: dict[str, Any]) -> str | None:
        """None to allow, or a short reason string to block."""
        c = self.config
        if name not in c.allowed_tools:
            return "tool_not_allowed"
        if name == "forward_email":
            to = str(args.get("to", ""))
            if not any(to.lower().endswith("@" + d) for d in c.recipient_domains):
                if c.confirm_external_forward and not c.confirm(name, args):
                    return "external_recipient_needs_confirmation"
            self.forwards += 1
            if self.forwards > c.max_forwards:
                return "forward_limit"
        elif name == "post_message":
            if args.get("channel") not in c.channels:
                return "channel_not_allowed"
        elif name == "move_email":
            if args.get("folder") not in c.folders:
                return "folder_not_allowed"
        elif name == "delete_email":
            if c.confirm_delete and not c.confirm(name, args):
                return "delete_needs_confirmation"
            self.deletes += 1
        return None

    def describe(self) -> dict:
        c = self.config
        return {"allowed_tools": sorted(c.allowed_tools), "recipient_domains": list(c.recipient_domains),
                "channels": list(c.channels), "folders": list(c.folders),
                "confirm_external_forward": c.confirm_external_forward,
                "confirm_delete": c.confirm_delete, "max_forwards": c.max_forwards}
