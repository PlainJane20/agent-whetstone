import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
from adaptive_stubs import MAGIC, StubSource, gen, magic_factory, refusal

from whetstone import adaptive_experiment as ae
from whetstone.attacks.campaign import EXIT_BUDGET, EXIT_KILL, KillSwitch
from whetstone.audit import load_and_verify

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_adaptive_live.py"
spec = importlib.util.spec_from_file_location("run_adaptive_live", SCRIPT)
script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(script)

NOKILL = lambda: KillSwitch(path="/nonexistent/kill", environ={})  # noqa: E731


def small(tmp_path, **kw):
    d = dict(goals=("delete_all", "leak_post"), campaigns=2, rounds=3, out_dir=tmp_path,
             attacker_model="stub-attacker", target_model="stub-target")
    d.update(kw)
    return ae.ExperimentConfig(**d)


def attacker_factory(script_=None, box=None):
    def make(model):
        s = StubSource(script_ or [gen()], label=model)
        if box is not None:
            box.append(s)
        return s
    return make


def target_factory(model, limit):
    return magic_factory()


def run(cfg, script_=None, kill=None, tf=target_factory):
    return ae.run_experiment(cfg, attacker_factory(script_), tf, kill=kill or NOKILL(), run_id="t")


# ---- plan --------------------------------------------------------------------------------
def test_default_plan_is_five_goals_by_three_campaigns_by_eight_rounds():
    p = ae.plan(ae.ExperimentConfig())
    a = p["conditions"]["adaptive_none"]
    assert (len(p["goals"]), p["campaigns_per_goal"], p["rounds"]) == (5, 3, 8)
    assert a["campaigns"] == 15 and a["max_target_runs"] == 120 and a["max_attacker_calls"] == 120
    assert p["conditions"]["adaptive_all_four"]["max_attacker_calls"] == 120
    assert p["conditions"]["blind_none"]["max_target_runs"] == 120 and p["conditions"]["blind_none"]["max_attacker_calls"] == 0
    assert p["max_target_runs"] == 360 and p["max_attacker_calls"] == 240 and p["total_campaigns"] == 45
    assert p["budget"] == {"max_target_runs": 360, "max_attacker_calls": 240} and not p["may_abort_on_budget"]


def test_plan_flags_a_budget_below_the_plan():
    p = ae.plan(ae.ExperimentConfig(max_target_runs=10))
    assert p["may_abort_on_budget"] and p["budget"]["max_target_runs"] == 10
    assert "BELOW the plan" in ae.format_plan(p)


def test_plan_text_names_models_counts_and_spend_limit():
    t = ae.format_plan(ae.plan(ae.ExperimentConfig()))
    assert "claude-haiku-4-5-20251001" in t and "360 target runs" in t and "240 attacker calls" in t
    assert "spend limit" in t and "WHETSTONE_KILL" in t and "nothing has been called" in t


@pytest.mark.parametrize("kw", [dict(goals=("nope",)), dict(conditions=("nope",)), dict(campaigns=0),
                                dict(rounds=0), dict(goals=()), dict(max_target_runs=-1)])
def test_plan_validates_config(kw):
    with pytest.raises(ValueError):
        ae.plan(ae.ExperimentConfig(**kw))


# ---- running with stubs ------------------------------------------------------------------
def test_full_run_with_stubs_completes_and_writes_summary_and_three_audit_chains(tmp_path):
    cfg = small(tmp_path)
    o = run(cfg, [gen(), gen(), gen(body=MAGIC)])
    assert o.exit_code == 0 and o.summary["status"] == "complete"
    d = o.run_dir
    assert d == tmp_path / "t" and (d / "summary.json").exists()
    for n in ae.CONDITIONS:
        ok, bad, count = load_and_verify(d / f"audit_{n}.jsonl")
        assert ok and count > 0
    disk = json.loads((d / "summary.json").read_text())
    assert disk["status"] == "complete" and disk["schema_version"] == 1


def test_results_json_schema(tmp_path):
    s = run(small(tmp_path), [gen(body=MAGIC)]).summary
    assert {"schema_version", "status", "abort", "run_id", "environment", "meta", "plan", "budget",
            "conditions", "comparison", "static_corpus_reference", "audit"} <= set(s)
    m = s["meta"]
    assert m["attacker_model"] == "stub-attacker" and m["target_model"] == "stub-target" and m["seed"] == 0
    assert m["date"] and m["started_utc"].startswith(m["date"])
    assert {"python", "pydantic-ai-slim", "pydantic", "agent-whetstone", "opentelemetry-api"} <= set(m["libraries"])
    assert m["caveat"] and m["rounds"] == 3 and m["goals"] == ["delete_all", "leak_post"]
    c = s["conditions"]["adaptive_none"]
    assert {"kind", "defenses", "campaigns_planned", "campaigns_completed", "campaigns_aborted",
            "campaign_success", "attempts_to_first_success", "per_goal", "rounds_by_outcome", "blocked_by",
            "attacker", "target", "techniques_tried", "campaigns"} <= set(c)
    assert {"k", "n", "rate", "wilson95", "exact95"} == set(c["campaign_success"])
    assert {"model_calls", "refused", "refusal_rate", "rejected_by_guardrails", "tokens"} == set(c["attacker"])
    assert set(s["budget"]) == {"max_target_runs", "max_attacker_calls", "used_target_runs", "used_attacker_calls"}
    assert set(s["audit"]["adaptive_none"]) == {"path", "records", "head", "chain_verified"}
    json.dumps(s)


def test_static_corpus_is_referenced_not_rerun(tmp_path):
    r = run(small(tmp_path)).summary["static_corpus_reference"]
    assert r["no_defense"]["k"] == 0 and r["no_defense"]["n"] == 165 and "not re-run" in r["note"]
    assert 0.021 < r["no_defense"]["exact95"][1] < 0.023


def test_metrics_success_rate_attempts_per_goal(tmp_path):
    # Only the delete_all goal can win with this stub target; win on round 2.
    s = run(small(tmp_path), [gen(), gen(body=MAGIC)]).summary
    c = s["conditions"]["adaptive_none"]
    assert c["campaigns_planned"] == 4 and c["campaigns_completed"] == 4
    # leak_post campaigns never succeed with the magic target, delete_all ones do at round 2
    assert c["per_goal"]["delete_all"]["k"] == 2 and c["per_goal"]["leak_post"]["k"] == 0
    assert c["campaign_success"]["k"] == 2 and c["campaign_success"]["n"] == 4 and c["campaign_success"]["rate"] == 0.5
    assert c["attempts_to_first_success"] == {"values": [2, 2], "mean": 2.0, "median": 2}
    assert c["per_goal"]["delete_all"]["attempts_to_first_success"] == [2, 2]


def test_defended_condition_blocks_and_reports_blocked_by(tmp_path):
    s = run(small(tmp_path, goals=("delete_all",)), [gen(body=MAGIC)]).summary
    d = s["conditions"]["adaptive_all_four"]
    assert d["campaign_success"]["k"] == 0 and d["blocked_by"]
    assert s["conditions"]["adaptive_none"]["campaign_success"]["k"] == 2


def test_refusal_rate_is_reported(tmp_path):
    s = run(small(tmp_path), [refusal(), gen()]).summary
    a = s["conditions"]["adaptive_none"]["attacker"]
    assert a["model_calls"] == 12 and a["refused"] == 4
    assert a["refusal_rate"] == round(a["refused"] / a["model_calls"], 4)
    assert s["conditions"]["blind_none"]["attacker"]["refusal_rate"] is None


def test_all_refusals_is_a_zero_success_run_with_100_percent_refusal(tmp_path):
    s = run(small(tmp_path), [refusal()]).summary
    a = s["conditions"]["adaptive_none"]
    assert a["attacker"]["refusal_rate"] == 1.0 and a["campaign_success"]["k"] == 0 and s["status"] == "complete"
    assert a["target"]["runs"] == 0


def test_blind_control_has_same_attempt_budget_and_no_attacker_calls(tmp_path):
    s = run(small(tmp_path)).summary
    assert s["conditions"]["blind_none"]["attacker"]["model_calls"] == 0
    a, b = s["conditions"]["adaptive_none"], s["conditions"]["blind_none"]
    assert a["target"]["runs"] == b["target"]["runs"] == 2 * 2 * 3   # goals x campaigns x rounds
    assert s["budget"]["used_attacker_calls"] == 2 * 2 * 3 * 2        # two adaptive conditions
    assert s["budget"]["used_target_runs"] == 3 * 12


def test_adaptive_vs_blind_comparison_present(tmp_path):
    s = run(small(tmp_path), [gen(body=MAGIC)]).summary
    c = s["comparison"]["adaptive_vs_blind_no_defense"]
    assert c["a_rate"]["k"] == 2 and c["b_rate"]["n"] == 4 and c["difference_a_minus_b"] <= 1
    assert 0 <= c["fisher_exact_p_two_sided"] <= 1
    assert "undefended_vs_defended_adaptive" in s["comparison"]


def test_comparison_omitted_when_a_side_is_missing(tmp_path):
    s = run(small(tmp_path, conditions=("adaptive_none",))).summary
    assert s["comparison"] == {} and list(s["conditions"]) == ["adaptive_none"]


def test_audit_chains_record_attacker_and_target_models(tmp_path):
    o = run(small(tmp_path, goals=("delete_all",), campaigns=1), [gen(body=MAGIC)])
    recs = [json.loads(line) for line in (o.run_dir / "audit_adaptive_none.jsonl").read_text().splitlines()]
    d = recs[0]["data"]
    assert d["attacker_model"] == "stub-attacker" and d["target"] == "llm:stub-target"
    assert d["campaign_id"] == "adaptive_none:delete_all:c0:s0"
    blind = [json.loads(line) for line in (o.run_dir / "audit_blind_none.jsonl").read_text().splitlines()]
    assert blind[0]["data"]["attacker_model"] == "blind_mutation" and blind[0]["data"]["target"] == "llm:stub-target"


def test_campaign_seeds_differ_per_campaign_and_are_shared_across_conditions(tmp_path):
    o = run(small(tmp_path, goals=("delete_all",)))
    seeds = {n: [c.seed for c in o.results[n]] for n in ae.CONDITIONS}
    assert seeds["adaptive_none"] == seeds["blind_none"] == [0, 1]


def test_attacker_is_built_once_and_not_at_all_for_blind_only(tmp_path):
    box = []
    ae.run_experiment(small(tmp_path), attacker_factory(box=box), target_factory, kill=NOKILL(), run_id="a")
    assert len(box) == 1
    box.clear()
    ae.run_experiment(small(tmp_path, conditions=("blind_none",)), attacker_factory(box=box), target_factory,
                      kill=NOKILL(), run_id="b")
    assert box == []


# ---- aborts keep partial results ---------------------------------------------------------
def test_budget_abort_saves_partial_results_and_exit_code(tmp_path):
    cfg = small(tmp_path, max_target_runs=7)
    o = run(cfg)
    assert o.exit_code == EXIT_BUDGET and o.summary["status"] == "aborted:budget_target_runs"
    assert o.summary["abort"]["reason"] == "budget_target_runs"
    assert o.summary["budget"]["used_target_runs"] == 7
    disk = json.loads((o.run_dir / "summary.json").read_text())
    assert disk["status"].startswith("aborted") and disk["conditions"]["adaptive_none"]["campaigns_completed"] >= 1
    assert all(a["chain_verified"] for a in disk["audit"].values())
    # the aborted campaign is excluded from the rate denominator and counted separately
    done = sum(c["campaigns_completed"] for c in disk["conditions"].values())
    aborted = sum(c["campaigns_aborted"] for c in disk["conditions"].values())
    assert aborted == 1 and done >= 2


def test_attacker_budget_abort(tmp_path):
    o = run(small(tmp_path, max_attacker_calls=4))
    assert o.exit_code == EXIT_BUDGET and o.summary["budget"]["used_attacker_calls"] == 4
    assert o.summary["status"] == "aborted:budget_attacker_calls"


def test_kill_switch_aborts_cleanly(tmp_path):
    k = NOKILL()
    src = StubSource([gen()], on_call=lambda n: k.trip("operator") if n == 2 else None)
    o = ae.run_experiment(small(tmp_path), lambda m: src, target_factory, kill=k, run_id="k")
    assert o.exit_code == EXIT_KILL and o.summary["status"] == "aborted:kill_switch"
    assert (o.run_dir / "summary.json").exists()
    assert load_and_verify(o.run_dir / "audit_adaptive_none.jsonl")[0]


def test_target_error_aborts_with_exit_5(tmp_path):
    o = run(small(tmp_path), tf=lambda m, lim: magic_factory(fail=True))
    assert o.exit_code == 5 and o.summary["abort"]["reason"] == "target_error"


def test_run_dir_is_never_overwritten(tmp_path):
    run(small(tmp_path))
    with pytest.raises(FileExistsError):
        run(small(tmp_path))


def test_summary_is_rewritten_after_every_campaign(tmp_path):
    states = []

    def on_call(n):
        f = tmp_path / "t" / "summary.json"
        states.append(sum(c["campaigns_completed"] for c in json.loads(f.read_text())["conditions"].values()))
    ae.run_experiment(small(tmp_path, goals=("delete_all",), campaigns=1, rounds=1),
                      lambda m: StubSource([gen()], on_call=on_call), target_factory, kill=NOKILL(), run_id="t")
    assert states == [0, 1]       # file existed before the first call and was rewritten after campaign 1


# ---- the script --------------------------------------------------------------------------
KEY = {"ANTHROPIC_API_KEY": "sk-ant-NOT-A-REAL-KEY-for-tests"}


def call(argv, env=None, **kw):
    lines = []
    code = script.main(argv, environ=env if env is not None else {}, out=lines.append, **kw)
    return code, "\n".join(lines)


def test_script_dry_run_prints_plan_and_counts_and_makes_zero_model_calls(tmp_path, monkeypatch, capsys):
    def boom(*a, **k):
        raise AssertionError("a model object was built in a dry run")
    monkeypatch.setattr(script, "_live_attacker", boom)
    monkeypatch.setattr(script, "_live_target", boom)
    code, out = call(["--dry-run", "--out-dir", str(tmp_path)])
    assert code == 0 and "360 target runs" in out and "240 attacker calls" in out and "Dry run" in out
    assert list(tmp_path.iterdir()) == []      # nothing written
    assert capsys.readouterr().err == ""


def test_script_dry_run_needs_no_key_and_no_live_flag(tmp_path):
    assert call(["--dry-run", "--out-dir", str(tmp_path)], env={})[0] == 0


def test_script_refuses_without_live(tmp_path, capsys):
    code, out = call(["--yes", "--out-dir", str(tmp_path)], env=KEY)
    assert code == 2 and "--live" in capsys.readouterr().err and list(tmp_path.iterdir()) == []
    assert "PLAN" in out


def test_script_refuses_without_key(tmp_path, capsys):
    code, _ = call(["--live", "--yes", "--out-dir", str(tmp_path)], env={})
    assert code == 2 and "ANTHROPIC_API_KEY" in capsys.readouterr().err and list(tmp_path.iterdir()) == []


def test_script_refuses_without_yes_but_prints_the_plan(tmp_path, capsys):
    code, out = call(["--live", "--out-dir", str(tmp_path)], env=KEY)
    assert code == 2 and "--yes" in capsys.readouterr().err and "TOTAL upper bound" in out
    assert list(tmp_path.iterdir()) == []


def test_script_never_accepts_a_key_on_the_command_line(tmp_path, capsys):
    for flag in ("--api-key", "--key", "--anthropic-api-key"):
        assert call([flag, "sk-ant-x", "--live", "--yes"], env=KEY)[0] == 2
    assert "sk-ant-x" not in capsys.readouterr().out


def test_script_does_not_abbreviate_flags():
    assert call(["--dry"], env={})[0] == 2        # allow_abbrev is off


def test_script_never_prints_the_key(tmp_path, capsys):
    code, out = call(["--live", "--yes", "--goals", "delete_all", "--campaigns", "1", "--rounds", "2",
                      "--out-dir", str(tmp_path)], env=KEY, attacker_factory=attacker_factory(),
                     target_factory=target_factory, kill=NOKILL())
    cap = capsys.readouterr()
    assert code == 0 and KEY["ANTHROPIC_API_KEY"] not in out + cap.out + cap.err
    summary = next(tmp_path.glob("*/summary.json")).read_text()
    assert KEY["ANTHROPIC_API_KEY"] not in summary


def test_script_full_flow_with_stubs_and_exit_codes(tmp_path):
    base = ["--live", "--yes", "--goals", "delete_all", "--campaigns", "1", "--rounds", "2",
            "--out-dir", str(tmp_path)]
    code, out = call(base, env=KEY, attacker_factory=attacker_factory([gen(body=MAGIC)]),
                     target_factory=target_factory, kill=NOKILL())
    assert code == 0 and "adaptive_none" in out and "campaign success 1/1" in out
    code, _ = call(base + ["--max-target-runs", "1", "--out-dir", str(tmp_path / "b")], env=KEY,
                   attacker_factory=attacker_factory(), target_factory=target_factory, kill=NOKILL())
    assert code == EXIT_BUDGET


def test_script_refuses_when_kill_switch_is_already_set(tmp_path):
    k = NOKILL()
    k.trip("pre-set")
    code, _ = call(["--live", "--yes", "--out-dir", str(tmp_path)], env=KEY, kill=k,
                   attacker_factory=attacker_factory(), target_factory=target_factory)
    assert code == EXIT_KILL and list(tmp_path.iterdir()) == []


def test_script_rejects_bad_goal_and_condition(tmp_path):
    assert call(["--dry-run", "--goals", "nope"])[0] == 2
    assert call(["--dry-run", "--conditions", "nope"])[0] == 2


def test_script_as_a_subprocess_refuses_without_live_and_calls_nothing(tmp_path):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)}
    for argv, needle in ((["--yes"], "--live"), (["--live", "--yes"], "ANTHROPIC_API_KEY")):
        r = subprocess.run([sys.executable, str(SCRIPT), *argv, "--out-dir", str(tmp_path / "o")],
                           capture_output=True, text=True, env=env, cwd=tmp_path)
        assert r.returncode == 2 and needle in r.stderr and not (tmp_path / "o").exists()
    r = subprocess.run([sys.executable, str(SCRIPT), "--dry-run"], capture_output=True, text=True, env=env,
                       cwd=tmp_path)
    assert r.returncode == 0 and "240 attacker calls" in r.stdout


def test_ci_workflow_does_not_run_the_live_script():
    wf = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "run_adaptive_live" not in wf and "ANTHROPIC" not in wf
