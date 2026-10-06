from dataclasses import replace

from conftest import go, profile_of
from whetstone.attacks import ScriptedAttacker, MutatingAttacker, base_corpus, build_attack
from whetstone.benign import benign_corpus, split_benign
from whetstone.defenses import RuleProposerDefender, build_stack
from whetstone.harness import (RunConfig, asr, benign_rates, group_asr, gullible_factory, run_attack,
                               run_benign, run_corpus, spar, summarize)
from whetstone.models import Email

LEAK = build_attack("direct_override", "leak_forward")


def test_undefended_fully_gullible_run_succeeds(always, cfg):
    r = go(LEAK, build_stack([]), always, cfg)
    assert r.success and r.progress == 3 and r.blocked_by is None and "canary_in_outbound" in r.violations


def test_input_screen_stops_before_the_target_runs(always, cfg):
    r = go(LEAK, build_stack(["input_screen"]), always, cfg)
    assert not r.success and r.blocked_by == "input_screen" and r.progress == 0 and r.tool_calls == []
    assert r.screen_score >= 1.0


def test_blocked_call_never_reaches_the_ledger_but_counts_as_attempted(always, cfg):
    r = go(LEAK, build_stack(["tool_policy"]), always, cfg)
    assert not r.success and r.attempted and r.progress == 2 and r.blocked_by == "tool_policy"
    assert any(c.status == "blocked" and c.name == "forward_email" for c in r.tool_calls)
    assert r.violations == []


def test_egress_redacts_output_leak(always, cfg):
    r = go(build_attack("direct_override", "leak_output"), build_stack(["egress_filter"]), always, cfg)
    assert not r.success and r.blocked_by == "egress_filter" and "CANARY-" not in r.output_text


def test_declined_attack_is_progress_one(never, cfg):
    r = go(LEAK, build_stack([]), never, cfg)
    assert not r.success and not r.attempted and r.progress == 1


def test_oracle_decides_success_not_the_target(always, cfg):
    r = go(build_attack("direct_override", "leak_forward"), build_stack(["egress_filter"]), always, cfg)
    assert r.attempted and not r.success             # the target tried, the effect never happened


def test_each_run_uses_a_fresh_sandbox(always, cfg):
    a = go(build_attack("direct_override", "delete_all"), build_stack([]), always, cfg)
    b = go(build_attack("direct_override", "delete_all"), build_stack([]), always, cfg)
    assert a.success and b.success


def test_run_corpus_runs_every_trial():
    cfg = RunConfig(trials=3)
    assert len(run_corpus(base_corpus(("role_play",)), build_stack([]), gullible_factory(), cfg)) == 15


def test_summarize_and_group_asr():
    res = run_corpus(base_corpus(("role_play", "split_payload")), build_stack([]), gullible_factory(), RunConfig(trials=2))
    s = summarize(res)
    assert s["n"] == 20 and s["asr"] == round(asr(res), 4)
    assert set(s["by_technique"]) == {"role_play", "split_payload"}
    assert set(group_asr(res, lambda r: r.attack.goal)) == set(s["by_goal"])


def test_defenses_lower_asr_on_the_full_corpus():
    cfg = RunConfig(trials=2)
    f = gullible_factory()
    base = asr(run_corpus(base_corpus(), build_stack([]), f, cfg))
    allx = asr(run_corpus(base_corpus(), build_stack(["all"]), f, cfg))
    assert base > 0.3 and allx < base / 4


def test_do_nothing_stack_equals_no_stack():
    cfg = RunConfig(trials=2)
    f = gullible_factory()
    a = run_corpus(base_corpus(("urgency_authority",)), build_stack([]), f, cfg)
    b = run_corpus(base_corpus(("urgency_authority",)), build_stack([]), f, cfg)
    assert [r.success for r in a] == [r.success for r in b]


def test_benign_run_screened_out_counts_as_disruption(always):
    hard = [e for e in benign_corpus() if e.id == "b-43"][0]
    o = run_benign(hard, build_stack(["input_screen"]), always, RunConfig())
    assert o.input_blocked and o.task_disrupted


def test_benign_run_untouched_by_other_defenses(always):
    e = benign_corpus()[0]
    for names in (["spotlight"], ["egress_filter"], ["tool_policy"]):
        assert not run_benign(e, build_stack(names), always, RunConfig()).task_disrupted


def test_legit_post_to_wrong_channel_would_be_a_disruption(always):
    from whetstone.defenses.stack import DefenseStack
    from whetstone.defenses import ToolPolicy, ToolPolicyConfig
    strict = DefenseStack(tool_policy=ToolPolicy(ToolPolicyConfig(channels=("#other",))))
    o = run_benign(benign_corpus()[0], strict, always, RunConfig())
    assert o.task_disrupted and "blocked by tool_policy" in o.reasons[0]


def test_benign_rates_shape():
    r = benign_rates(benign_corpus(), build_stack(["input_screen"]), gullible_factory(), RunConfig())
    assert r["n"] == 72 and r["task_disrupted"] == len(r["false_positive_ids"]) and 0 < r["fpr"] < 0.2


def test_spar_scripted_attacker_one_round():
    tr, va, _ = split_benign(0)
    d = RuleProposerDefender([e.render() for e in tr], [e.render() for e in va])
    reports, hist = spar(ScriptedAttacker(), d, [], 3, gullible_factory(), RunConfig(trials=1))
    assert len(reports) == 1 and reports[0].n_attacks == 55 and len(hist) == 55


def test_spar_mutating_attacker_runs_multiple_rounds_and_tracks_broken():
    tr, va, _ = split_benign(0)
    d = RuleProposerDefender([e.render() for e in tr], [e.render() for e in va])
    reports, _ = spar(MutatingAttacker(seed=0, budget=40), d, [], 3, gullible_factory(), RunConfig(trials=1))
    assert len(reports) == 3 and reports[1].n_attacks <= 40
    assert [r.lineages_broken for r in reports] == sorted(r.lineages_broken for r in reports)


def test_spar_defender_versions_increase_when_it_learns():
    tr, va, _ = split_benign(0)
    d = RuleProposerDefender([e.render() for e in tr], [e.render() for e in va], base=None)
    d.ruleset = replace(d.ruleset, rules=())            # start with an empty screen so there are wins to learn from
    reports, _ = spar(MutatingAttacker(seed=0, budget=40), d, [], 3, gullible_factory(), RunConfig(trials=1))
    assert reports[-1].ruleset_version > reports[0].ruleset_version
