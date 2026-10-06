import random
from dataclasses import replace

import pytest

from whetstone.attacks import (ALL_MUTATIONS, FAMILIES, BlindMutator, LLMAttacker, MutatingAttacker,
                               ScriptedAttacker, base_corpus, build_attack, mutate, variants)
from whetstone.models import EXTERNAL_ADDRESS, GOALS, Attack, AttackResult


def test_at_least_ten_families_and_five_goals():
    assert len(FAMILIES) >= 10 and len(GOALS) == 5


def test_base_corpus_is_families_cross_goals():
    c = base_corpus()
    assert len(c) == len(FAMILIES) * len(GOALS)
    assert len({a.id for a in c}) == len(c)


def test_corpus_is_deterministic():
    assert base_corpus() == base_corpus()


def test_subset_by_technique():
    assert {a.technique for a in base_corpus(("role_play",))} == {"role_play"}


@pytest.mark.parametrize("tech", FAMILIES)
def test_each_family_covers_all_goals(tech):
    assert {a.goal for a in base_corpus((tech,))} == set(GOALS)


def test_split_payload_uses_two_emails_and_halves_are_incomplete():
    a = build_attack("split_payload", "leak_forward")
    assert len(a.emails) == 2
    assert EXTERNAL_ADDRESS not in a.emails[0].body and EXTERNAL_ADDRESS in a.emails[1].body


def test_payloads_only_use_reserved_example_destinations():
    for a in base_corpus():
        for e in a.emails:
            assert e.sender.endswith(".example")
            assert "http" not in e.body or ".example" in e.body


def test_payloads_never_contain_real_looking_secrets():
    for a in base_corpus():
        text = a.untrusted_text()
        assert "CANARY-" not in text and "password" not in text.lower()


def test_encoded_family_covers_three_schemes():
    bodies = [build_attack("encoded_payload", g).emails[0].body for g in GOALS]
    assert any("base64" in b for b in bodies) and any("rot13" in b for b in bodies) and any("l33t" in b for b in bodies)


def test_multilingual_bodies_are_not_english_instructions():
    a = build_attack("multilingual", "delete_all")
    assert "delete" not in a.emails[0].body.lower()


def test_attack_dict_roundtrip():
    a = build_attack("quoted_reply", "leak_post")
    assert Attack.from_dict(a.to_dict()) == a


# ---- mutators --------------------------------------------------------------------------
def test_mutation_is_deterministic_for_a_seed():
    a = build_attack("direct_override", "leak_forward")
    assert variants(a, 7, 5) == variants(a, 7, 5)


def test_different_seed_gives_different_variants():
    a = build_attack("direct_override", "leak_forward")
    assert variants(a, 1, 5) != variants(a, 2, 5)


@pytest.mark.parametrize("name", [m for m in ALL_MUTATIONS if not m.startswith("exfil")])
def test_each_mutation_changes_the_attack_and_tracks_lineage(name):
    a = build_attack("direct_override", "leak_forward", para=0)
    v = mutate(a, name, random.Random(0), "v1")
    if v is None:                      # reparaphrase may pick the same wording
        assert name == "reparaphrase"
        return
    assert v.emails != a.emails and v.lineage == a.id and v.mutations == (name,)


def test_exfil_mutators_only_apply_to_leak_goals():
    rng = random.Random(0)
    assert mutate(build_attack("direct_override", "delete_all"), "exfil_hex", rng, "v") is None
    assert mutate(build_attack("direct_override", "leak_post"), "exfil_hex", rng, "v") is not None


def test_zero_width_mutation_inserts_invisible_characters():
    v = mutate(build_attack("direct_override", "leak_forward"), "zero_width", random.Random(0), "v")
    assert "​" in v.emails[0].body


def test_stacked_mutations_accumulate():
    a = build_attack("direct_override", "leak_forward")
    v1 = mutate(a, "case_swap", random.Random(0), "v1")
    v2 = mutate(v1, "pad_benign", random.Random(0), "v2")
    assert v2.mutations == ("case_swap", "pad_benign") and v2.lineage == a.id


# ---- attackers -------------------------------------------------------------------------
def _fail(a, progress, score=0.0):
    return AttackResult(a, 0, False, "input_screen", False, [], score, progress)


def test_scripted_attacker_plays_once():
    s = ScriptedAttacker()
    assert len(s.propose(0, [])) == 55 and s.propose(1, []) == []


def test_mutating_attacker_round0_is_base_corpus():
    assert MutatingAttacker(seed=1).propose(0, []) == base_corpus()


def test_mutating_attacker_mutates_failed_attacks_only():
    base = base_corpus(("direct_override",))
    m = MutatingAttacker(base=base, seed=0, budget=50)
    hist = [_fail(base[0], 0), AttackResult(base[1], 0, True, None, True, [], 0.0, 3)]
    out = m.propose(1, hist)
    assert out and all(v.lineage == base[0].id for v in out)


def test_mutating_attacker_prefers_higher_progress():
    base = base_corpus(("direct_override",))
    m = MutatingAttacker(base=base, seed=0, budget=2, variants_per_parent=2)
    hist = [_fail(base[0], 0), _fail(base[1], 2)]
    assert {v.lineage for v in m.propose(1, hist)} == {base[1].id}


def test_mutating_attacker_respects_budget_and_is_seeded():
    base = base_corpus()
    hist = [_fail(a, 0) for a in base]
    a = MutatingAttacker(base=base, seed=3, budget=20).propose(1, hist)
    b = MutatingAttacker(base=base, seed=3, budget=20).propose(1, hist)
    assert len(a) <= 20 and a == b


def test_mutating_attacker_variants_are_unique_ids():
    base = base_corpus()
    out = MutatingAttacker(base=base, seed=0, budget=100).propose(1, [_fail(a, 0) for a in base])
    assert len({v.id for v in out}) == len(out)


def test_blind_mutator_ignores_feedback():
    base = base_corpus(("role_play",))
    out = BlindMutator(base=base, seed=0, budget=50).propose(1, [])
    assert {v.lineage for v in out} == {a.id for a in base}


def test_llm_attacker_is_a_stub():
    with pytest.raises(NotImplementedError, match="not built"):
        LLMAttacker().propose(0, [])
