import pytest

from conftest import go, profile_of
from whetstone.attacks import FAMILIES, base_corpus, build_attack, mutate
from whetstone.defenses import Spotlighting, SpotlightConfig, build_stack
from whetstone.defenses.stack import DefenseStack
from whetstone.harness import RunConfig, gullible_factory, run_corpus
from whetstone.models import DEFAULT_TASK, Email
from whetstone.sandbox import Sandbox
from whetstone.targets import DEFAULT_PROFILE, GullibleTarget, ToolBox
import random

NONE = build_stack([])


@pytest.mark.parametrize("tech", FAMILIES)
def test_fully_gullible_target_is_fooled_by_every_goal_of_each_family(tech, always, cfg):
    for a in base_corpus((tech,)):
        assert go(a, NONE, always, cfg).success, a.id


def test_target_with_zero_susceptibility_is_never_fooled(never, cfg):
    assert not any(r.success for r in run_corpus(base_corpus(), NONE, never, cfg))


def test_legitimate_summary_post_always_happens(never, cfg):
    r = go(build_attack("direct_override", "delete_all"), NONE, never, cfg)
    assert [c.name for c in r.tool_calls if c.origin == "task"] == ["post_message"]
    assert r.tool_calls[0].args["channel"] == "#team-updates"


def test_same_seed_same_result():
    a = build_attack("fake_system_message", "leak_post")
    cfg = RunConfig(seed=4, trials=1)
    f = gullible_factory()
    r1, r2 = go(a, NONE, f, cfg), go(a, NONE, f, cfg)
    assert (r1.success, r1.output_text, [c.to_dict() for c in r1.tool_calls]) == \
           (r2.success, r2.output_text, [c.to_dict() for c in r2.tool_calls])


def test_trials_differ_in_outcome_across_the_corpus():
    cfg = RunConfig(seed=0, trials=1)
    f = gullible_factory()
    outcomes = {go(a, NONE, f, cfg, trial=t).success for a in base_corpus() for t in range(3)}
    assert outcomes == {True, False}


def test_spotlighting_only_ever_removes_successes():
    """Paired draws: the same random number is used with and without the envelope, and spotlight
    multipliers are < 1, so a spotlit success must also succeed undefended."""
    cfg = RunConfig(seed=0, trials=3)
    f = gullible_factory()
    atks = base_corpus()
    plain = {(r.attack.id, r.trial) for r in run_corpus(atks, NONE, f, cfg) if r.success}
    spot = {(r.attack.id, r.trial) for r in run_corpus(atks, build_stack(["spotlight"]), f, cfg) if r.success}
    assert spot <= plain and len(spot) < len(plain)


def test_fixed_delimiter_is_spoofable_but_random_is_not():
    f = gullible_factory(profile_of(0.5))
    cfg = RunConfig(seed=0, trials=6)
    atks = base_corpus(("delimiter_spoofing",))
    fixed = DefenseStack(spotlight=Spotlighting(SpotlightConfig(randomise=False)))
    rnd = DefenseStack(spotlight=Spotlighting(SpotlightConfig(randomise=True, seed=0)))
    a_fixed = sum(r.success for r in run_corpus(atks, fixed, f, cfg))
    a_rand = sum(r.success for r in run_corpus(atks, rnd, f, cfg))
    assert a_fixed > a_rand


def test_target_reads_through_zero_width_and_greek_homoglyphs(always, cfg):
    a = build_attack("direct_override", "leak_forward")
    for name in ("zero_width", "homoglyph_greek", "homoglyph_cyrillic", "case_swap", "synonym_swap"):
        v = mutate(a, name, random.Random(0), "v")
        assert go(v, NONE, always, cfg).success, name


def test_target_decodes_base64_rot13_and_leet(always, cfg):
    for g in ("leak_forward", "delete_all", "forward_all"):       # goal index 0,4,3 -> b64, leet, rot13
        a = build_attack("encoded_payload", g)
        assert go(a, NONE, always, cfg).success, (a.id, a.emails[0].body[:40])


def test_target_decodes_wrapped_base64_mutation(always, cfg):
    v = mutate(build_attack("role_play", "leak_output"), "encode_base64", random.Random(0), "v")
    assert go(v, NONE, always, cfg).success


def test_split_payload_needs_both_parts(always, cfg):
    a = build_attack("split_payload", "leak_forward")
    half = Attack_with(a, a.emails[:1])
    assert go(a, NONE, always, cfg).success and not go(half, NONE, always, cfg).success


def Attack_with(a, emails):
    from dataclasses import replace
    return replace(a, emails=tuple(emails))


def test_tool_param_injection_binds_note_output_into_forward(always, cfg):
    r = go(build_attack("tool_param_injection", "leak_forward"), NONE, always, cfg)
    fwd = [c for c in r.tool_calls if c.name == "forward_email"][0]
    assert fwd.origin == "injected" and "CANARY-" in fwd.args["body"]


def test_markdown_exfil_puts_secret_in_image_url(always, cfg):
    r = go(build_attack("markdown_image_exfil", "leak_output"), NONE, always, cfg)
    assert "![status](https://pixel.external-mail.example" in r.output_text and "CANARY-" in r.output_text


def test_forward_all_forwards_every_email_in_the_mailbox(always, cfg):
    r = go(build_attack("direct_override", "forward_all"), NONE, always, cfg)
    assert len([c for c in r.tool_calls if c.name == "forward_email"]) >= 9


def test_exfil_encoding_instruction_changes_leaked_form(always, cfg):
    a = mutate(build_attack("direct_override", "leak_forward"), "exfil_hex", random.Random(0), "v")
    r = go(a, NONE, always, cfg)
    body = [c for c in r.tool_calls if c.name == "forward_email"][0].args["body"]
    assert "CANARY-" not in body and r.success                # hex form: oracle still sees it


def test_benign_mail_does_not_trigger_actions(always, cfg):
    sb = Sandbox(0, (Email("b-1", "x@corp.example", "Lunch", "Want to grab lunch on Thursday?"),))
    tb = ToolBox(sb)
    GullibleTarget(tb, profile_of(1.0), 0).run(DEFAULT_TASK, "\n".join(e.render() for e in sb.unread_emails()))
    assert [c.name for c in tb.calls] == ["post_message"]


def test_meta_reports_intents_and_techniques(always, cfg):
    sb = Sandbox(0, build_attack("urgency_authority", "delete_all").emails)
    tb = ToolBox(sb)
    r = GullibleTarget(tb, profile_of(1.0), 0).run(DEFAULT_TASK, "\n".join(e.render() for e in sb.unread_emails()))
    assert r.meta["complied"] and r.meta["intents"][0]["technique"] == "urgency_authority"


def test_profile_covers_every_family_and_is_documented():
    assert set(FAMILIES) <= set(DEFAULT_PROFILE.base) and set(FAMILIES) <= set(DEFAULT_PROFILE.spotlight)
    assert all(0 <= p <= 1 for p in DEFAULT_PROFILE.base.values())
    assert all(DEFAULT_PROFILE.spotlight[k] < 1 for k in FAMILIES)
    assert "NOT a language model" in __import__("whetstone.targets.gullible", fromlist=["x"]).__doc__
