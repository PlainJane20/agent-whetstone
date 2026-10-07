"""Resume, atomic summaries, retry through the experiment, schema compatibility. Offline: stub attackers/targets,
injected sleep, temp copies of run folders (the real evidence folders are only ever read)."""
import importlib.util
import json
import random
import shutil
from pathlib import Path

import pytest
from adaptive_stubs import MAGIC, StubSource, gen, magic_factory
from test_retry import KEY, HTTPErr, ModelAPIError, overloaded

from whetstone import adaptive_experiment as ae
from whetstone.attacks.campaign import KillSwitch
from whetstone.audit import load_and_verify
from whetstone.retry import Retrier, RetryPolicy

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("run_adaptive_live", ROOT / "scripts" / "run_adaptive_live.py")
script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(script)
LIVE = ROOT / "evals" / "results" / "live_adaptive"
REAL = LIVE / "20261006-071655-seed0"
NOKILL = lambda: KillSwitch(path="/nonexistent/kill", environ={})  # noqa: E731
DUMMY_ENV = {"ANTHROPIC_API_KEY": "dummy-not-a-key"}   # an injected placeholder; never a real key, never read from os.environ


def small(tmp_path, **kw):
    d = dict(goals=("delete_all", "leak_post"), campaigns=2, rounds=3, out_dir=tmp_path,
             attacker_model="stub-attacker", target_model="stub-target")
    d.update(kw)
    return ae.ExperimentConfig(**d)


def attackers(model):
    return StubSource([gen(), gen(), gen(body=MAGIC)], label=model)


def tf_ok(model, limit):
    return magic_factory()


def tf_failing(at_run, exc):
    """Target factory whose `at_run`-th target run (1-based) raises `exc`."""
    n = [0]
    inner = magic_factory()

    def make(model, limit):
        def f(tb, seed):
            n[0] += 1
            if n[0] == at_run:
                raise exc
            return inner(tb, seed)
        return f
    make.count = n
    return make


def retrier(**kw):
    sleeps = []
    return Retrier(RetryPolicy(**{"jitter": 0.0, **kw}), sleep=sleeps.append, clock=lambda: 0.0, rng=random.Random(0)), sleeps


def aborted_run(tmp_path, at_run=10, exc=None, **kw):
    cfg = small(tmp_path, **kw)
    o = ae.run_experiment(cfg, attackers, tf_failing(at_run, exc or HTTPErr(400, {"error": {"type": "invalid_request_error", "message": "credit balance too low"}})),
                          kill=NOKILL(), run_id="t", retrier=retrier()[0])
    assert o.summary["status"].startswith("aborted")
    return cfg, o


def ids(cfg):
    return [ae.campaign_id(cfg, c, g, n) for c, g, n in ae.plan_order(cfg)]


def resume(cfg, tf=tf_ok, **kw):
    seen = []
    o = ae.resume_experiment(cfg, cfg.out_dir / "t", attackers, tf, kill=NOKILL(), say=seen.append,
                             retrier=retrier()[0], **kw)
    return o, [x.split("]")[0][1:] for x in seen if x.startswith("[")]


# ---- end to end on stubs ------------------------------------------------------------------
def test_resume_runs_only_the_remaining_campaigns_in_the_original_order(tmp_path):
    cfg, o = aborted_run(tmp_path)
    done = {c["campaign_id"] for n in o.summary["conditions"].values() for c in n["campaigns"] if c["status"] != "aborted"}
    aborted_id = o.summary["abort"]["campaign_id"]
    o2, ran = resume(cfg)
    assert o2.exit_code == 0 and o2.summary["status"] == "complete"
    assert ran == [i for i in ids(cfg) if i not in done] and aborted_id in ran
    assert set(ran).isdisjoint(done)


def test_resumed_order_matches_an_uninterrupted_run(tmp_path):
    cfg, _ = aborted_run(tmp_path / "a")
    _, ran = resume(cfg)
    full_dir = tmp_path / "b"
    seen = []
    ae.run_experiment(small(full_dir), attackers, tf_ok, kill=NOKILL(), run_id="t", say=seen.append)
    full = [x.split("]")[0][1:] for x in seen if x.startswith("[")]
    assert ran == full[len(full) - len(ran):]


def test_audit_chains_continue_and_verify_after_resume(tmp_path):
    cfg, _ = aborted_run(tmp_path)
    before = {n: load_and_verify(tmp_path / "t" / f"audit_{n}.jsonl") for n in cfg.conditions}
    o2, _ = resume(cfg)
    for n in cfg.conditions:
        ok, bad, count = load_and_verify(tmp_path / "t" / f"audit_{n}.jsonl")
        assert ok and bad is None and count > before[n][2]
        recs = [json.loads(x) for x in (tmp_path / "t" / f"audit_{n}.jsonl").read_text().splitlines()]
        assert recs[before[n][2]]["event"] == "experiment_resumed"
        assert recs[before[n][2]]["prev"] == recs[before[n][2] - 1]["hash"]
        assert o2.summary["audit"][n]["chain_verified"]


def test_aborted_campaign_is_rerun_fresh_and_preserved_as_aborted_attempt(tmp_path):
    cfg, o = aborted_run(tmp_path)
    aid = o.summary["abort"]["campaign_id"]
    o2, _ = resume(cfg)
    att = o2.summary["aborted_attempts"]
    assert len(att) == 1 and att[0]["campaign_id"] == aid and att[0]["abort_error"]["status_code"] == 400
    assert att[0]["campaign"]["status"] == "aborted"
    cond = aid.split(":")[0]
    rerun = [c for c in o2.summary["conditions"][cond]["campaigns"] if c["campaign_id"] == aid]
    assert len(rerun) == 1 and rerun[0]["status"] != "aborted"
    assert o2.summary["abort"] is None
    assert sum(c["campaigns_completed"] for c in o2.summary["conditions"].values()) == 12


def test_resumed_metadata_and_original_meta_are_kept(tmp_path):
    cfg, o = aborted_run(tmp_path)
    started = o.summary["meta"]["started_utc"]
    carried = sum(c["campaigns_completed"] for c in o.summary["conditions"].values())
    o2, _ = resume(cfg)
    r = o2.summary["resumed"]
    assert r["count"] == 1 and r["carried_over_campaigns"] == carried and r["remaining_at_resume"] == 12 - carried
    assert r["last_resumed_utc"] and r["history"][0]["from_status"].startswith("aborted")
    assert o2.summary["meta"]["started_utc"] == started and o2.summary["schema_version"] == 3
    assert o2.summary["resume_plan"]["total_campaigns"] == 12 - carried


def test_a_second_abort_and_second_resume_keep_both_attempts(tmp_path):
    cfg, _ = aborted_run(tmp_path, at_run=4)
    o2, _ = resume(cfg, tf=tf_failing(2, HTTPErr(403, None)))
    assert o2.summary["status"].startswith("aborted") and o2.summary["resumed"]["count"] == 1
    o3, _ = resume(cfg)
    assert o3.summary["status"] == "complete" and o3.summary["resumed"]["count"] == 2
    assert len(o3.summary["aborted_attempts"]) == 2 and len(o3.summary["resumed"]["history"]) == 2
    assert all(load_and_verify(tmp_path / "t" / f"audit_{n}.jsonl")[0] for n in cfg.conditions)


def test_resume_of_a_complete_run_is_a_noop(tmp_path):
    cfg = small(tmp_path)
    ae.run_experiment(cfg, attackers, tf_ok, kill=NOKILL(), run_id="t")
    files = {p.name: p.read_bytes() for p in (tmp_path / "t").iterdir()}
    calls = []
    o, ran = resume(cfg, tf=lambda m, l: calls.append(1) or magic_factory())
    assert o.exit_code == 0 and ran == [] and calls == []
    assert {p.name: p.read_bytes() for p in (tmp_path / "t").iterdir()} == files


def test_budgets_apply_to_the_new_work_only(tmp_path):
    cfg, _ = aborted_run(tmp_path)
    cfg.max_target_runs = 1
    o2, ran = resume(cfg)
    assert o2.summary["abort"]["reason"] == "budget_target_runs" and o2.exit_code == 3
    assert o2.summary["budget"]["max_target_runs"] == 1 and o2.summary["budget"]["used_target_runs"] == 1


def test_default_resume_budget_is_the_remaining_upper_bound(tmp_path):
    cfg, _ = aborted_run(tmp_path)
    o2, _ = resume(cfg)
    rp = o2.summary["resume_plan"]
    assert o2.summary["budget"]["max_target_runs"] == rp["max_target_runs"] < o2.summary["plan"]["max_target_runs"]


@pytest.mark.parametrize("change", [dict(rounds=4), dict(seed=1), dict(goals=("delete_all",)), dict(target_model="other"),
                                    dict(attacker_model="other"), dict(campaigns=3), dict(task="a different task"),
                                    dict(conditions=("adaptive_none",))])
def test_config_mismatch_is_refused_with_a_clear_message(tmp_path, change):
    cfg, _ = aborted_run(tmp_path)
    bad = small(tmp_path, **change)
    with pytest.raises(ae.ResumeError, match="does not match"):
        ae.resume_experiment(bad, tmp_path / "t", attackers, tf_ok, kill=NOKILL())
    assert next(iter(change)) in str(pytest.raises(ae.ResumeError, ae.prepare_resume, tmp_path / "t", bad).value)


def test_resume_refuses_a_broken_audit_chain(tmp_path):
    cfg, _ = aborted_run(tmp_path)
    p = tmp_path / "t" / "audit_adaptive_none.jsonl"
    lines = p.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["data"]["goal"] = "tampered"
    lines[1] = json.dumps(rec, sort_keys=True)
    p.write_text("\n".join(lines) + "\n")
    with pytest.raises(ae.ResumeError, match="does not verify"):
        ae.prepare_resume(tmp_path / "t", cfg)


def test_resolve_run_dir_accepts_id_or_dir_and_rejects_missing(tmp_path):
    aborted_run(tmp_path)
    assert ae.resolve_run_dir("t", tmp_path) == tmp_path / "t"
    assert ae.resolve_run_dir(str(tmp_path / "t"), Path("/nonexistent")) == tmp_path / "t"
    with pytest.raises(ae.ResumeError, match="no summary.json"):
        ae.resolve_run_dir("nope", tmp_path)


def test_campaign_from_dict_round_trips(tmp_path):
    _, o = aborted_run(tmp_path)
    for c in o.summary["conditions"]["adaptive_none"]["campaigns"]:
        assert ae.campaign_from_dict(c).to_dict() == c


# ---- atomic summary -----------------------------------------------------------------------
def test_summary_write_is_atomic_and_leaves_no_temp_file(tmp_path):
    cfg, _ = aborted_run(tmp_path)
    assert not list((tmp_path / "t").glob("*.tmp"))
    p = tmp_path / "x.json"
    p.write_text("old")
    ae._atomic_write(p, "new")
    assert p.read_text() == "new" and not list(tmp_path.glob("*.tmp"))


def test_a_failed_write_never_corrupts_the_existing_summary(tmp_path, monkeypatch):
    p = tmp_path / "s.json"
    p.write_text('{"ok": 1}')

    def boom(self, text):
        raise OSError("disk full")
    monkeypatch.setattr(Path, "write_text", boom)
    with pytest.raises(OSError):
        ae._atomic_write(p, "garbage")
    monkeypatch.undo()
    assert p.read_text() == '{"ok": 1}'


# ---- retry through the experiment ---------------------------------------------------------
def flaky_tf(errors):
    errs = list(errors)
    inner = magic_factory()

    def make(model, limit):
        def f(tb, seed):
            if errs:
                raise errs.pop(0)
            return inner(tb, seed)
        return f
    return make


def test_transient_errors_are_retried_and_reported_in_the_summary(tmp_path):
    rt, sleeps = retrier()
    o = ae.run_experiment(small(tmp_path), attackers, flaky_tf([overloaded(), ModelAPIError(""), HTTPErr(503)]),
                          kill=NOKILL(), run_id="t", retrier=rt)
    s = o.summary
    assert s["status"] == "complete" and s["api_retries"]["this_invocation"] == 3
    assert sum(c["api_retries"] for c in s["conditions"].values()) == 3 == s["api_retries"]["in_current_campaigns"]
    assert sum(sleeps) == 2 + 4 + 8
    assert s["budget"]["used_target_runs"] <= s["plan"]["max_target_runs"]
    assert s["api_retries"]["policy"]["max_attempts"] == 5


def test_retries_do_not_inflate_budget_counts(tmp_path):
    base = ae.run_experiment(small(tmp_path / "a"), attackers, tf_ok, kill=NOKILL(), run_id="t").summary["budget"]
    flaky = ae.run_experiment(small(tmp_path / "b"), attackers, flaky_tf([overloaded()] * 3), kill=NOKILL(), run_id="t",
                              retrier=retrier()[0]).summary["budget"]
    assert base["used_target_runs"] == flaky["used_target_runs"] and base["used_attacker_calls"] == flaky["used_attacker_calls"]


def test_global_retry_cap_stops_the_run_with_exit_5(tmp_path):
    cfg = small(tmp_path, max_total_retries=2)
    o = ae.run_experiment(cfg, attackers, flaky_tf([overloaded()] * 50), kill=NOKILL(), run_id="t",
                          retrier=retrier(max_total_retries=2)[0])
    assert o.exit_code == 5 and o.summary["status"] == "aborted:api_retry_cap"
    assert o.summary["abort"]["error"]["classification"] == "transient"


def test_kill_switch_during_backoff_stops_the_run_with_exit_4(tmp_path):
    kill = NOKILL()
    rt = Retrier(RetryPolicy(jitter=0), sleep=lambda s: kill.trip("mid backoff"), clock=lambda: 0.0)
    o = ae.run_experiment(small(tmp_path), attackers, flaky_tf([overloaded()] * 5), kill=kill, run_id="t", retrier=rt)
    assert o.exit_code == 4 and o.summary["abort"]["reason"] == "kill_switch"


def test_permanent_error_in_experiment_has_full_detail(tmp_path):
    _, o = aborted_run(tmp_path, at_run=1)
    a = o.summary["abort"]
    assert a["reason"] == "target_error" and a["error"]["classification"] == "permanent" and a["error"]["attempts"] == 1
    assert "credit balance" in a["detail"] and a["error"]["exception_chain"] == ["HTTPErr"]


def test_key_never_reaches_summary_audit_or_stdout(tmp_path):
    e = HTTPErr(401, {"error": {"type": "authentication_error", "message": f"bad key {KEY}"}}, msg=f"rejected {KEY}")
    e.headers = {"x-api-key": KEY}
    out = []
    cfg = small(tmp_path)
    o = ae.run_experiment(cfg, attackers, tf_failing(3, e), kill=NOKILL(), run_id="t", say=out.append,
                          retrier=retrier()[0])
    blob = "".join(p.read_text() for p in (tmp_path / "t").iterdir()) + "\n".join(out)
    assert o.summary["status"].startswith("aborted") and KEY not in blob and "sk-ant" not in blob and "ABCDEFGHIJKL" not in blob
    assert "[REDACTED]" in blob


# ---- config / plan ------------------------------------------------------------------------
def test_retry_settings_validate_and_appear_in_the_plan(tmp_path):
    with pytest.raises(ValueError):
        small(tmp_path, retry_max_attempts=0).validate()
    with pytest.raises(ValueError):
        small(tmp_path, max_total_retries=-1).validate()
    p = ae.plan(small(tmp_path, retry_max_attempts=3, retry_base_s=1.0, retry_cap_s=9.0, max_total_retries=7))
    assert p["retry_policy"] == {"max_attempts": 3, "base_s": 1.0, "cap_s": 9.0, "max_total_retries": 7, "jitter": 0.5}
    assert "up to 3 attempts" in ae.format_plan(p)


def test_plan_for_todo_counts_only_the_remaining(tmp_path):
    cfg = small(tmp_path)
    todo = ae.plan_order(cfg)[5:]
    p = ae.plan(cfg, todo)
    assert p["total_campaigns"] == 7 and p["max_target_runs"] == 7 * 3


def test_plan_order_is_campaign_then_goal_then_condition(tmp_path):
    o = ae.plan_order(small(tmp_path))
    assert o[0] == (0, "delete_all", "adaptive_none") and o[1] == (0, "delete_all", "adaptive_all_four")
    assert o[3] == (0, "leak_post", "adaptive_none") and o[6][0] == 1 and len(o) == 12


# ---- schema compatibility -----------------------------------------------------------------
def test_load_summary_fills_v3_fields_for_older_schemas(tmp_path):
    _, o = aborted_run(tmp_path)
    d = json.loads((tmp_path / "t" / "summary.json").read_text())
    for k in ("aborted_attempts", "resumed", "resume_plan", "api_retries"):
        d.pop(k)
    d["schema_version"] = 2
    (tmp_path / "old.json").write_text(json.dumps(d))
    s = ae.load_summary(tmp_path / "old.json")
    assert s["loaded_from_schema_version"] == 2 and s["aborted_attempts"] == [] and s["resumed"] is None


def test_a_v2_run_folder_can_be_resumed(tmp_path):
    cfg, _ = aborted_run(tmp_path)
    p = tmp_path / "t" / "summary.json"
    d = json.loads(p.read_text())
    for k in ("aborted_attempts", "resumed", "resume_plan", "api_retries"):
        d.pop(k)
    d["schema_version"] = 2
    for c in d["conditions"].values():
        c.pop("api_retries")
        for camp in c["campaigns"]:
            camp.pop("api_retries"), camp.pop("abort_error")
    p.write_text(json.dumps(d))
    o2, _ = resume(cfg)
    assert o2.summary["status"] == "complete" and o2.summary["schema_version"] == 3
    assert o2.summary["resumed"]["history"][0]["carried_from_schema_version"] == 2
    assert len(o2.summary["aborted_attempts"]) == 1


# ---- CLI ----------------------------------------------------------------------------------
def cli(args, tf=tf_ok, retr=None):
    out = []
    code = script.main(args, environ=DUMMY_ENV, attacker_factory=attackers, target_factory=tf, kill=NOKILL(),
                       out=out.append, retrier=retr)
    return code, "\n".join(out)


def base_args(tmp_path):
    return ["--goals", "delete_all,leak_post", "--campaigns", "2", "--rounds", "3", "--attacker-model", "stub-attacker",
            "--target-model", "stub-target", "--out-dir", str(tmp_path)]


def test_cli_resume_dry_run_prints_the_remaining_plan_and_writes_nothing(tmp_path):
    cfg, o = aborted_run(tmp_path)
    before = {p.name: p.read_bytes() for p in (tmp_path / "t").iterdir()}
    code, out = cli(["--resume", "t", "--out-dir", str(tmp_path), "--dry-run"])
    assert code == 0 and "PLAN FOR THE REMAINING WORK" in out and "carried over" in out and "Dry run" in out
    assert "attacker calls <=" in out
    assert {p.name: p.read_bytes() for p in (tmp_path / "t").iterdir()} == before


def test_cli_resume_needs_live_and_yes(tmp_path):
    aborted_run(tmp_path)
    assert cli(["--resume", "t", "--out-dir", str(tmp_path)])[0] == 2
    assert cli(["--resume", "t", "--out-dir", str(tmp_path), "--live"])[0] == 2
    assert json.loads((tmp_path / "t" / "summary.json").read_text())["resumed"] is None


def test_cli_resume_end_to_end_with_stubs(tmp_path):
    aborted_run(tmp_path)
    code, out = cli(["--resume", "t", "--out-dir", str(tmp_path), "--live", "--yes"])
    s = json.loads((tmp_path / "t" / "summary.json").read_text())
    assert code == 0 and s["status"] == "complete" and "status: complete" in out and s["resumed"]["count"] == 1


def test_cli_resume_complete_run_says_nothing_to_resume_even_without_live(tmp_path):
    ae.run_experiment(small(tmp_path), attackers, tf_ok, kill=NOKILL(), run_id="t")
    code, out = cli(["--resume", "t", "--out-dir", str(tmp_path)])
    assert code == 0 and "Nothing to resume" in out


@pytest.mark.parametrize("flag", [["--rounds", "9"], ["--seed", "5"], ["--goals", "delete_all"], ["--target-model", "x"]])
def test_cli_resume_refuses_a_typed_flag_that_contradicts_the_saved_run(tmp_path, flag):
    aborted_run(tmp_path)
    code, out = cli(["--resume", "t", "--out-dir", str(tmp_path), "--dry-run", *flag])
    assert code == 2


def test_cli_resume_accepts_a_typed_flag_equal_to_the_saved_value(tmp_path):
    aborted_run(tmp_path)
    assert cli(["--resume", "t", "--out-dir", str(tmp_path), "--dry-run", "--rounds", "3", "--seed", "0"])[0] == 0


def test_cli_resume_of_missing_run_is_refused(tmp_path):
    assert cli(["--resume", "nope", "--out-dir", str(tmp_path), "--dry-run"])[0] == 2


def test_cli_resume_retry_flags_and_budget_cap(tmp_path):
    aborted_run(tmp_path)
    code, out = cli(["--resume", "t", "--out-dir", str(tmp_path), "--dry-run", "--retry-max-attempts", "2",
                     "--max-total-retries", "9", "--max-target-runs", "5"])
    assert code == 0 and "up to 2 attempts" in out and "9 retries in total" in out and "max_target_runs=5" in out


def test_cli_fresh_run_retry_flags_reach_the_policy(tmp_path):
    code, out = cli([*base_args(tmp_path), "--dry-run", "--retry-max-attempts", "3", "--retry-base-s", "1",
                     "--retry-cap-s", "8", "--max-total-retries", "4"])
    assert code == 0 and "up to 3 attempts" in out and "base 1.0s" in out and "cap 8.0s" in out and "4 retries in total" in out


def test_cli_run_reports_abort_detail_and_resume_hint(tmp_path):
    code, out = cli([*base_args(tmp_path), "--live", "--yes"], tf=tf_failing(2, HTTPErr(402, None)))
    assert code == 5 and "ABORTED (target_error)" in out and "--resume" in out and "permanent" in out


def test_cli_bad_retry_option_is_refused(tmp_path):
    assert cli([*base_args(tmp_path), "--dry-run", "--retry-max-attempts", "0"])[0] == 2


# ---- the real aborted run (a temp copy; the evidence folder is never touched) ---------------
@pytest.mark.skipif(not REAL.is_dir(), reason="real aborted run not present (untracked evidence)")
def test_resume_of_a_temp_copy_of_the_real_aborted_run(tmp_path):
    before = {p.name: p.read_bytes() for p in REAL.iterdir()}
    run = tmp_path / REAL.name
    shutil.copytree(REAL, run)
    saved = ae.load_summary(run / "summary.json")
    carried = {c["campaign_id"] for n in saved["conditions"].values() for c in n["campaigns"] if c["status"] != "aborted"}
    chains0 = {n: load_and_verify(run / f"audit_{n}.jsonl")[2] for n in saved["conditions"]}
    cfg = ae.cfg_from_summary(saved, out_dir=tmp_path)
    seen = []
    o = ae.resume_experiment(cfg, run, attackers, tf_ok, kill=NOKILL(), say=seen.append, retrier=retrier()[0])
    ran = [x.split("]")[0][1:] for x in seen if x.startswith("[")]
    assert len(carried) == 17 and len(ran) == 28 and set(ran).isdisjoint(carried)
    assert "blind_none:leak_forward:c1:s1" in ran and o.summary["status"] == "complete"
    assert [x["campaign_id"] for x in o.summary["aborted_attempts"]] == ["blind_none:leak_forward:c1:s1"]
    assert o.summary["aborted_attempts"][0]["abort_detail"] == "ModelAPIError: "
    assert o.summary["resumed"]["carried_over_campaigns"] == 17
    for n in saved["conditions"]:
        ok, bad, count = load_and_verify(run / f"audit_{n}.jsonl")
        assert ok and count > chains0[n]
    assert {p.name: p.read_bytes() for p in REAL.iterdir()} == before      # the real folder is untouched
