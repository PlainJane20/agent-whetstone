import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from whetstone import tracing
from whetstone.attacks import build_attack
from whetstone.defenses import RuleProposerDefender, build_stack
from whetstone.attacks import ScriptedAttacker
from whetstone.harness import RunConfig, gullible_factory, run_attack, spar
from conftest import profile_of


@pytest.fixture
def spans():
    exp = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exp))
    tracing.configure(provider)
    yield exp
    tracing.configure(None)


def by_name(exp, name):
    return [s for s in exp.get_finished_spans() if s.name == f"whetstone.{name}"]


CFG = RunConfig(seed=0, trials=1)


def test_all_span_kinds_emitted(spans):
    run_attack(build_attack("direct_override", "leak_forward"), 0, build_stack(["tool_policy"]),
               gullible_factory(profile_of(1.0)), CFG)
    assert {"whetstone.attack_run", "whetstone.target_step", "whetstone.defense_check",
            "whetstone.oracle"} <= {s.name for s in spans.get_finished_spans()}


def test_attack_run_span_carries_technique_goal_blocked_by_success(spans):
    run_attack(build_attack("direct_override", "leak_forward"), 0, build_stack(["tool_policy"]),
               gullible_factory(profile_of(1.0)), CFG)
    [s] = by_name(spans, "attack_run")
    assert s.attributes["technique"] == "direct_override" and s.attributes["goal"] == "leak_forward"
    assert s.attributes["success"] is False and s.attributes["blocked_by"] == "tool_policy"


def test_successful_attack_is_marked_success(spans):
    run_attack(build_attack("direct_override", "leak_forward"), 0, build_stack([]), gullible_factory(profile_of(1.0)), CFG)
    [s] = by_name(spans, "attack_run")
    assert s.attributes["success"] is True and s.attributes["blocked_by"] == "none"
    assert by_name(spans, "oracle")[0].attributes["success"] is True


def test_screened_attack_has_no_target_step(spans):
    run_attack(build_attack("direct_override", "leak_forward"), 0, build_stack(["input_screen"]),
               gullible_factory(profile_of(1.0)), CFG)
    assert by_name(spans, "target_step") == []
    assert by_name(spans, "defense_check")[0].attributes["blocked_by"] == "input_screen"


def test_spans_nest_under_attack_run(spans):
    run_attack(build_attack("role_play", "leak_post"), 0, build_stack([]), gullible_factory(), CFG)
    root = by_name(spans, "attack_run")[0]
    for name in ("defense_check", "target_step", "oracle"):
        assert by_name(spans, name)[0].parent.span_id == root.context.span_id


def test_defender_round_span(spans):
    from whetstone.benign import split_benign
    tr, va, _ = split_benign(0)
    spar(ScriptedAttacker([build_attack("direct_override", "leak_forward")]),
         RuleProposerDefender([e.render() for e in tr], [e.render() for e in va]), [], 1,
         gullible_factory(profile_of(1.0)), CFG)
    [s] = by_name(spans, "defender_round")
    assert s.attributes["round"] == 0 and "new_version" in s.attributes


def test_tracing_is_noop_without_a_provider():
    tracing.configure(None)
    r = run_attack(build_attack("role_play", "leak_post"), 0, build_stack([]), gullible_factory(), CFG)
    assert r.attack.id == "role_play/leak_post"
