import json

import pytest

from whetstone.audit import load_and_verify
from whetstone.cli import main


def test_run_attacks_json(capsys):
    assert main(["run-attacks", "--technique", "role_play", "--trials", "1", "--json"]) == 0
    s = json.loads(capsys.readouterr().out)
    assert s["n"] == 5 and set(s["by_technique"]) == {"role_play"}


def test_run_attacks_text_table(capsys):
    main(["run-attacks", "--technique", "role_play", "--trials", "1"])
    assert "no defense: ASR" in capsys.readouterr().out


def test_run_defenses_reports_baseline_and_fpr(capsys):
    assert main(["run-defenses", "--defenses", "input_screen", "--technique", "direct_override", "--trials", "1"]) == 0
    out = capsys.readouterr().out
    assert "ASR" in out and "benign FPR" in out


def test_run_defenses_rejects_unknown_defense(capsys):
    assert main(["run-defenses", "--defenses", "magic"]) == 2
    assert "unknown defense" in capsys.readouterr().err


def test_run_defenses_writes_a_verifiable_audit_log(tmp_path):
    p = tmp_path / "a.jsonl"
    main(["run-defenses", "--defenses", "all", "--technique", "role_play", "--trials", "1", "--audit", str(p)])
    ok, bad, n = load_and_verify(p)
    assert ok and n == 5


def test_spar_prints_rounds(capsys):
    assert main(["spar", "--rounds", "2", "--trials", "1", "--attacker", "scripted"]) == 0
    assert "round" in capsys.readouterr().out


def test_llm_target_requires_explicit_live_flag():
    with pytest.raises(SystemExit) as e:
        main(["run-attacks", "--target", "llm", "--technique", "role_play"])
    assert "--live" in str(e.value)


def test_llm_target_requires_key_in_environment(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(SystemExit) as e:
        main(["run-attacks", "--target", "llm", "--live", "--model", "x"])
    assert "ANTHROPIC_API_KEY" in str(e.value)


def test_report_verifies_committed_audit_chain(capsys):
    assert main(["report"]) == 0
    out = capsys.readouterr().out
    assert "verified" in out and "SIMULATED" in out


def test_report_fails_on_missing_results(tmp_path, capsys):
    assert main(["report", "--results", str(tmp_path)]) == 1


def test_epilog_states_defensive_scope(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    assert "Do not point it at systems you do not own" in " ".join(capsys.readouterr().out.split())
