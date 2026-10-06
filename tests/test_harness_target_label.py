"""The audit log must say which target ran, so a live result is never mistaken for a simulated one."""
import pytest

from whetstone import harness
from whetstone.attacks import base_corpus
from whetstone.audit import AuditLog
from whetstone.defenses import build_stack


def _run(tmp_path, label):
    log = AuditLog(tmp_path / "a.jsonl")
    cfg = harness.RunConfig(seed=0, trials=1, target=label)
    atk = base_corpus(("direct_override",))[:1]
    harness.run_corpus(atk, build_stack([]), harness.gullible_factory(), cfg, log)
    return log.records()[0]


def test_default_label_is_gullible(tmp_path):
    assert _run(tmp_path, "gullible")["data"]["target"] == "gullible"


def test_live_label_is_recorded(tmp_path):
    assert _run(tmp_path, "llm:claude-haiku-4-5-20251001")["data"]["target"] == "llm:claude-haiku-4-5-20251001"


def test_replay_refuses_non_simulated_records(tmp_path):
    rec = _run(tmp_path, "llm:some-model")
    with pytest.raises(ValueError, match="only deterministic"):
        harness.replay(rec)
