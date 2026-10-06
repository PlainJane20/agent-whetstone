"""Target protocol and the tool box that sits between a target and the sandbox."""
from __future__ import annotations

from typing import Any, Callable, Protocol

from ..models import ToolCall, TargetResult
from ..sandbox import Sandbox, ToolResult

# guard(name, args) -> None to allow, or the name of the defense that blocks the call
Guard = Callable[[str, dict[str, Any]], "str | None"]


class Target(Protocol):
    def run(self, task: str, untrusted_content: str) -> TargetResult: ...


class ToolBox:
    """Every tool call a target makes goes through here: guard first, then the sandbox.

    The box keeps the log of attempted calls (executed, blocked or errored). The sandbox's own
    effects ledger only records calls that actually ran.
    """

    def __init__(self, sandbox: Sandbox, guard: Guard | None = None) -> None:
        self.sandbox = sandbox
        self.guard = guard
        self.calls: list[ToolCall] = []

    def call(self, tool: str, origin: str = "task", **args: Any) -> ToolResult:
        tc = ToolCall(name=tool, args=dict(args), origin=origin)
        self.calls.append(tc)
        blocked = self.guard(tool, dict(args)) if self.guard else None
        if blocked:
            tc.status, tc.blocked_by = "blocked", blocked
            tc.result = f"blocked by {blocked}"
            return ToolResult(False, error=tc.result)
        res = self.sandbox.call(tool, **args)
        tc.status = "executed" if res.ok else "error"
        tc.result = res.value or res.error
        return res
