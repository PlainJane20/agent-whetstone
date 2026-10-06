"""The evals are code too: run the cheap ones and check they gate on what they claim."""
import json

import pytest

from evals import audit_replay, baseline, common, defenses, generalisation, oracle_sanity
from whetstone import oracles


def test_oracle_sanity_all_cases_pass():
    out = oracle_sanity.run()
    assert out["all_ok"] and out["known_bad"]["fired"] == out["known_bad"]["n"] >= 10
    assert out["known_good"]["silent"] == out["known_good"]["n"] >= 8


def test_oracle_sanity_can_fail(monkeypatch):
    """Negative control: a broken oracle must make the sanity eval fail."""
    monkeypatch.setitem(oracles.GOAL_ORACLES, "delete_all",
                        lambda ledger, out, can: oracles.OracleVerdict("delete_all", True, []))
    assert not oracle_sanity.run()["all_ok"]
    monkeypatch.setitem(oracles.GOAL_ORACLES, "delete_all",
                        lambda ledger, out, can: oracles.OracleVerdict("delete_all", False, []))
    assert not oracle_sanity.run()["all_ok"]


def test_oracle_sanity_covers_every_goal():
    assert {c["oracle"] for c in oracle_sanity.run()["cases"]} == set(oracles.GOAL_ORACLES)


def test_baseline_is_not_vacuous():
    out = baseline.run()
    assert 0.2 < out["overall"]["rate"] < 0.9 and len(out["by_technique"]) == 11 and len(out["by_goal"]) == 5
    assert out["overall"]["n"] == 55 * 5


def test_baseline_is_reproducible():
    a, b = baseline.run(), baseline.run()
    assert a["overall"] == b["overall"] and a["by_technique"] == b["by_technique"]


def test_defenses_eval_orders_configs_sensibly():
    rows = defenses.run()["rows"]
    assert rows["none"]["fpr_all"]["k"] == 0 and rows["none"]["asr"]["rate"] > 0.3
    assert rows["all_four"]["asr"]["rate"] < rows["input_screen"]["asr"]["rate"] <= rows["none"]["asr"]["rate"]
    assert rows["egress_filter"]["canary_leak_rate"]["k"] == 0


def test_generalisation_reports_three_experiments_and_all_folds():
    out = generalisation.run()
    for key in ("E1_standard", "E2_ioc_masked", "E3_unseen_wording_ioc_masked"):
        e = out[key]
        assert len(e["folds"]) == 3 and set(e["pooled_heldout_asr"]) >= {"none", "proposed_only"}
        tested = [f for fold in e["folds"] for f in fold["test_families"]]
        assert len(tested) == len(set(tested)) == 11             # every family is held out exactly once
        for fold in e["folds"]:
            assert not set(fold["train_families"]) & set(fold["test_families"])


def test_audit_replay_eval_passes(tmp_path, monkeypatch):
    monkeypatch.setattr(common, "RESULTS", tmp_path)
    monkeypatch.setattr(audit_replay, "RESULTS", tmp_path)
    out = audit_replay.run()
    assert out["chain_verifies"] and out["replay_identical"] == out["replayed"] > 0 and out["tamper_detected"]


def test_committed_results_exist_and_record_the_caveat():
    for name in ("baseline", "defenses", "generalisation", "mutation", "latency", "oracle_sanity", "audit_replay"):
        j = json.loads((common.RESULTS / f"{name}.json").read_text())
        assert "SIMULATED" in j["meta"]["environment"]
        assert "SIMULATION of a gullible agent" in " ".join(j["meta"]["caveat"])


def test_latency_json_has_caveats_and_percentiles():
    j = json.loads((common.RESULTS / "latency.json").read_text())
    assert j["caveats"] and j["input_screen_scan"]["p95_ms"] >= j["input_screen_scan"]["p50_ms"]


def test_no_network_modules_used_by_the_package():
    import pathlib, re
    src = "\n".join(p.read_text() for p in pathlib.Path("src/whetstone").rglob("*.py"))
    assert not re.search(r"^\s*(import|from)\s+(requests|httpx|urllib\.request|socket|aiohttp)\b", src, re.M)
