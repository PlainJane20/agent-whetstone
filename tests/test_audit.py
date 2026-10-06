import json

from whetstone.attacks import build_attack
from whetstone.audit import GENESIS, AuditLog, load_and_verify, verify_records
from whetstone.defenses import build_stack
from whetstone.harness import RunConfig, gullible_factory, replay, run_attack, run_corpus


def test_empty_chain_verifies():
    assert AuditLog().verify() == (True, None) and AuditLog().head() == GENESIS


def test_chain_links_records():
    log = AuditLog()
    a, b = log.append("e", {"i": 1}), log.append("e", {"i": 2})
    assert a["prev"] == GENESIS and b["prev"] == a["hash"] and log.verify() == (True, None)


def test_edit_is_detected_at_the_edited_record():
    log = AuditLog()
    for i in range(4):
        log.append("e", {"i": i})
    recs = log.records()
    recs[2]["data"]["i"] = 99
    assert verify_records(recs) == (False, 2)


def test_deletion_and_reorder_are_detected():
    log = AuditLog()
    for i in range(4):
        log.append("e", {"i": i})
    recs = log.records()
    assert verify_records(recs[:1] + recs[2:])[0] is False
    assert verify_records([recs[1], recs[0], *recs[2:]])[0] is False


def test_truncation_keeps_a_valid_prefix_which_the_head_hash_exposes():
    log = AuditLog()
    for i in range(3):
        log.append("e", {"i": i})
    head = log.head()
    prefix = log.records()[:2]
    assert verify_records(prefix) == (True, None) and prefix[-1]["hash"] != head


def test_file_persistence_and_reopen(tmp_path):
    p = tmp_path / "a.jsonl"
    AuditLog(p).append("e", {"i": 1})
    log2 = AuditLog(p)
    log2.append("e", {"i": 2})
    assert load_and_verify(p) == (True, None, 2)


def test_tampered_file_fails_verification(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    for i in range(3):
        log.append("e", {"i": i})
    lines = p.read_text().splitlines()
    rec = json.loads(lines[1]); rec["data"]["i"] = 7; lines[1] = json.dumps(rec, sort_keys=True)
    p.write_text("\n".join(lines) + "\n")
    assert load_and_verify(p)[:2] == (False, 1)


def test_every_attack_attempt_is_audited_with_full_context():
    log = AuditLog()
    cfg = RunConfig(seed=0, trials=2)
    run_corpus([build_attack("role_play", "leak_post")], build_stack(["tool_policy"]), gullible_factory(), cfg, log)
    recs = log.records()
    assert len(recs) == 2 and all(r["event"] == "attack_attempt" for r in recs)
    d = recs[0]["data"]
    assert d["attack"]["technique"] == "role_play" and d["defenses"]["tool_policy"] and "outcome" in d


def test_replay_reproduces_outcomes_exactly():
    log = AuditLog()
    cfg = RunConfig(seed=2, trials=3)
    atks = [build_attack(t, g) for t in ("direct_override", "tool_param_injection") for g in ("leak_forward", "delete_all")]
    run_corpus(atks, build_stack(["all"]), gullible_factory(), cfg, log)
    assert all(replay(r)[0] for r in log.records())


def test_replay_detects_a_changed_outcome():
    log = AuditLog()
    run_attack(build_attack("fake_system_message", "leak_output"), 0, build_stack([]), gullible_factory(),
               RunConfig(seed=0, trials=1), log)
    rec = log.records()[0]
    rec["data"]["outcome"]["output_sha256"] = "0" * 64
    assert replay(rec)[0] is False
