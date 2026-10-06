"""Retry/abort behaviour through the real campaign loop, with stub sources and targets. No model, no sleep."""
import json
import random

from adaptive_stubs import MAGIC, StubSource, gen, magic_factory
from test_retry import KEY, HTTPErr, ModelAPIError, overloaded

from whetstone.attacks.campaign import Budget, KillSwitch, run_campaign
from whetstone.audit import AuditLog
from whetstone.defenses import build_stack
from whetstone.harness import RunConfig
from whetstone.retry import Retrier, RetryPolicy

CFG = RunConfig(seed=0, trials=1, target="llm:stub-target")


def retrier(**kw):
    sleeps = []
    return Retrier(RetryPolicy(**{"jitter": 0.0, **kw}), sleep=sleeps.append, clock=lambda: 0.0,
                   rng=random.Random(0)), sleeps


class FlakySource:
    """Wraps a StubSource; raises the scripted errors on the first calls, then delegates."""
    uses_model = True
    label = "flaky-attacker"

    def __init__(self, inner, errors):
        self.inner, self.errors, self.attempts = inner, list(errors), 0

    def next(self, *a, **k):
        self.attempts += 1
        if self.errors:
            raise self.errors.pop(0)
        return self.inner.next(*a, **k)


def flaky_factory(errors):
    errs = list(errors)
    inner = magic_factory()

    def f(tb, seed):
        if errs:
            raise errs.pop(0)
        return inner(tb, seed)
    f.runs = lambda: len(errs)
    return f


def camp(source, factory=None, budget=None, rt=None, audit=None, kill=None, rounds=3):
    return run_campaign("delete_all", source, factory or magic_factory(), build_stack([]), CFG, rounds=rounds,
                        budget=budget or Budget(50, 50), campaign_id="c1", condition="adaptive_none", audit=audit,
                        kill=kill or KillSwitch(path="/nonexistent/kill", environ={}), retrier=rt)


WIN = [gen(body=f"{MAGIC} now")]


def test_attacker_transient_then_success_is_not_double_counted():
    rt, sleeps = retrier()
    b = Budget(50, 50)
    src = FlakySource(StubSource(WIN), [overloaded(), overloaded()])
    r = camp(src, budget=b, rt=rt)
    assert r.status == "success" and src.attempts == 3
    assert b.attacker_calls == 1 and b.target_runs == 1          # one logical call, one logical run
    assert r.api_retries == 2 and r.rounds[0].api_retries == 2 and rt.total_retries == 2
    assert r.rounds[0].attacker_calls == 1


def test_target_transient_then_success_is_not_double_counted():
    rt, _ = retrier()
    b = Budget(50, 50)
    r = camp(StubSource(WIN), factory=flaky_factory([ModelAPIError(""), HTTPErr(503)]), budget=b, rt=rt)
    assert r.status == "success" and b.target_runs == 1 and b.attacker_calls == 1
    assert r.api_retries == 2 and r.rounds[0].api_retries == 2


def test_retried_target_run_starts_from_a_fresh_sandbox_and_scores_normally():
    rt, _ = retrier()
    r = camp(StubSource(WIN), factory=flaky_factory([overloaded()]), rt=rt)
    assert r.rounds[0].outcome == "success" and r.rounds[0].tool_names.count("delete_email") == 3


def test_permanent_attacker_error_aborts_at_once_with_detail():
    rt, sleeps = retrier()
    e = HTTPErr(400, {"error": {"type": "invalid_request_error", "message": "Your credit balance is too low"}})
    src = FlakySource(StubSource(WIN), [e])
    r = camp(src, rt=rt)
    assert r.status == "aborted" and r.abort_reason == "attacker_error" and src.attempts == 1 and sleeps == []
    d = r.abort_error
    assert d["classification"] == "permanent" and d["status_code"] == 400 and d["attempts"] == 1
    assert d["provider_error"]["type"] == "invalid_request_error" and d["call"] == "attacker"
    assert "credit balance" in r.abort_detail and "permanent" in r.abort_detail


def test_permanent_target_error_aborts_at_once():
    rt, _ = retrier()
    r = camp(StubSource(WIN), factory=flaky_factory([HTTPErr(401, None)]), rt=rt)
    assert r.abort_reason == "target_error" and r.abort_error["status_code"] == 401 and rt.total_retries == 0


def test_plain_runtime_error_in_target_is_permanent_not_retried():
    rt, sleeps = retrier()
    r = camp(StubSource(WIN), factory=flaky_factory([RuntimeError("target blew up")]), rt=rt)
    assert r.abort_reason == "target_error" and sleeps == [] and r.abort_error["classification_reason"] == "unclassified_exception"


def test_per_call_retry_cap_aborts_and_records_attempts():
    rt, sleeps = retrier(max_attempts=3)
    r = camp(StubSource(WIN), factory=flaky_factory([overloaded()] * 9), rt=rt)
    assert r.abort_reason == "target_error" and r.abort_error["attempts"] == 3
    assert r.abort_error["abort_cause"] == "api_retries_exhausted" and r.api_retries == 2


def test_global_retry_cap_aborts_with_its_own_reason():
    rt, _ = retrier(max_total_retries=2, max_attempts=9)
    r = camp(StubSource(WIN), factory=flaky_factory([overloaded()] * 9), rt=rt)
    assert r.abort_reason == "api_retry_cap" and r.api_retries == 2
    from whetstone.attacks.campaign import ABORT_EXIT
    assert ABORT_EXIT["api_retry_cap"] == 5


def test_kill_switch_during_backoff_aborts_as_kill_switch():
    kill = KillSwitch(path="/nonexistent/kill", environ={})
    sleeps = []
    rt = Retrier(RetryPolicy(jitter=0), sleep=lambda s: (sleeps.append(s), kill.trip("mid backoff")),
                 clock=lambda: 0.0)
    src = FlakySource(StubSource(WIN), [overloaded()] * 3)
    r = camp(src, rt=rt, kill=kill)
    assert r.abort_reason == "kill_switch" and src.attempts == 1 and "backoff" in r.abort_detail


def test_without_a_retrier_behaviour_is_unchanged_but_detail_is_richer():
    r = camp(StubSource(WIN), factory=flaky_factory([overloaded()]))
    assert r.abort_reason == "target_error" and r.abort_error["abort_cause"] == "no_retrier"
    assert r.abort_error["status_code"] == 529


def test_empty_message_error_is_described_not_blank():
    rt, _ = retrier(max_attempts=2)
    r = camp(StubSource(WIN), factory=flaky_factory([ModelAPIError("")] * 5), rt=rt)
    assert "ModelAPIError" in r.abort_detail and "(empty message)" in r.abort_detail
    assert r.abort_error["exception_chain"] == ["ModelAPIError"]


def test_retries_and_abort_are_audited_and_the_chain_verifies():
    rt, _ = retrier()
    audit = AuditLog()
    camp(StubSource(WIN), factory=flaky_factory([overloaded()]), rt=rt, audit=audit)
    events = [x["event"] for x in audit.records()]
    assert events.count("api_retry") == 1 and events[-1] == "campaign_end" and audit.verify()[0]
    end = audit.records()[-1]["data"]
    assert end["api_retries"] == 1 and end["status"] == "success"


def test_key_in_error_is_redacted_in_result_and_audit():
    rt, _ = retrier(max_attempts=2)
    audit = AuditLog()
    e = HTTPErr(529, {"error": {"type": "overloaded_error", "message": f"key {KEY}"}}, msg=f"leak {KEY}")
    e.headers = {"x-api-key": KEY}
    r = camp(StubSource(WIN), factory=flaky_factory([e, e, e]), rt=rt, audit=audit)
    blob = json.dumps(r.to_dict()) + json.dumps(audit.records()) + r.abort_detail
    assert r.status == "aborted" and KEY not in blob and "sk-ant" not in blob and "x-api-key" not in blob


def test_retry_across_rounds_is_counted_per_round():
    rt, _ = retrier()
    src = FlakySource(StubSource([gen(body="plain"), gen(body=f"{MAGIC}")]), [overloaded()])
    r = camp(src, rt=rt)
    assert [x.api_retries for x in r.rounds] == [1, 0] and r.api_retries == 1
