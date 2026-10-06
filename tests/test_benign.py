from collections import Counter

from whetstone.benign import CATEGORIES, benign_corpus, category_of, is_hard, split_benign


def test_at_least_sixty_messages_and_unique_ids():
    c = benign_corpus()
    assert len(c) >= 60 and len({e.id for e in c}) == len(c)


def test_half_are_hard_cases():
    hard = sum(is_hard(e.id) for e in benign_corpus())
    assert hard >= 30


def test_hard_categories_present():
    assert {"imperative", "security_talk", "encoded_data", "urgent_legit", "markdown", "multilingual",
            "secrets_talk"} <= set(CATEGORIES)


def test_hard_cases_really_are_hard():
    by = {e.id: e for e in benign_corpus()}
    sec = [e for e in by.values() if category_of(e.id) == "security_talk"]
    assert any("ignore all previous instructions" in e.body.lower() for e in sec)
    assert any("base64" in e.subject.lower() for e in by.values())
    assert any("urgent" in e.body.lower() for e in by.values() if category_of(e.id) == "urgent_legit")


def test_synthetic_only_reserved_domains():
    assert all(e.sender.endswith(".example") for e in benign_corpus())


def test_benign_contains_no_canary_strings():
    assert not any("CANARY-" in e.render() for e in benign_corpus())


def test_split_is_deterministic_disjoint_and_stratified():
    a, b, c = split_benign(0)
    assert split_benign(0) == (a, b, c)
    ids = [e.id for e in a + b + c]
    assert len(ids) == len(set(ids)) == len(benign_corpus())
    for part in (a, b, c):
        assert 0 < sum(is_hard(e.id) for e in part) < len(part)


def test_different_split_seed_changes_membership():
    assert {e.id for e in split_benign(0)[0]} != {e.id for e in split_benign(1)[0]}
