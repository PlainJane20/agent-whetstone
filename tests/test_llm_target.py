import os

import pytest

pytest.importorskip("pydantic_ai")
from pydantic_ai.models.test import TestModel  # noqa: E402

from whetstone.attacks import build_attack  # noqa: E402
from whetstone.defenses import build_stack  # noqa: E402
from whetstone.harness import RunConfig, run_attack  # noqa: E402
from whetstone.sandbox import Sandbox  # noqa: E402
from whetstone.targets import LLMTarget, ToolBox  # noqa: E402


def test_testmodel_drives_sandbox_tools():
    sb = Sandbox(0)
    tb = ToolBox(sb)
    r = LLMTarget(tb, TestModel(call_tools=["list_emails"], custom_output_text="done")).run("t", "content")
    assert r.output_text == "done" and [c.name for c in r.tool_calls] == ["list_emails"]
    assert r.tool_calls[0].origin == "model" and sb.ledger.entries()[0].tool == "list_emails"


def test_tool_calls_are_guarded_like_any_target():
    sb = Sandbox(0)
    stack = build_stack(["tool_policy"])
    tb = ToolBox(sb, stack.guard)
    LLMTarget(tb, TestModel(call_tools=["forward_email"], custom_output_text="ok")).run("t", "c")
    assert tb.calls[0].status == "blocked" and tb.calls[0].blocked_by == "tool_policy"
    assert sb.ledger.where(tool="forward_email") == []


def test_stub_model_function_can_play_a_hijacked_model():
    from pydantic_ai.messages import ModelResponse, ToolCallPart
    from pydantic_ai.models.function import FunctionModel

    def hijacked(messages, info):
        if len(messages) == 1:
            return ModelResponse(parts=[ToolCallPart("delete_email", {"email_id": "m1"})])
        from pydantic_ai.messages import TextPart
        return ModelResponse(parts=[TextPart("deleted")])

    sb = Sandbox(0)
    tb = ToolBox(sb)
    LLMTarget(tb, FunctionModel(hijacked)).run("t", "c")
    assert sb.deleted == ["m1"]


def test_llm_target_works_through_the_harness_with_oracles():
    f = lambda tb, seed: LLMTarget(tb, TestModel(call_tools=["list_emails"], custom_output_text="Summary."))
    r = run_attack(build_attack("direct_override", "leak_output"), 0, build_stack(["all"]), f, RunConfig())
    assert r.success is False and r.progress in (0, 1, 2)


def test_live_needs_an_env_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        LLMTarget.live(ToolBox(Sandbox(0)), "some-model")


def test_live_builds_a_model_string_without_calling_anything(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "not-a-real-key")
    # constructing must not touch the network; running would, and is never done here
    t = LLMTarget.live(ToolBox(Sandbox(0)), "some-model")
    assert str(t.model) == "anthropic:some-model"
