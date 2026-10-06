"""Backoff, classification and error-detail extraction. Fake exceptions imitate the SDK shapes; no model, no sleep."""
import json
import random

import pytest

from whetstone.attacks.campaign import KillSwitch
from whetstone.retry import (CallFailed, Retrier, RetryPolicy, classify, clip_redacted, describe_error,
                             error_headline, exception_chain, provider_error, redact, status_code_of)

NOKILL = KillSwitch(path="/nonexistent/kill", environ={})
KEY = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-abc"


class HTTPErr(Exception):
    """Shape of pydantic-ai ModelHTTPError / anthropic APIStatusError."""
    def __init__(self, status_code, body=None, msg=""):
        super().__init__(msg or f"status_code: {status_code}, body: {body}")
        self.status_code, self.body = status_code, body


class ModelAPIError(Exception):           # same class name as pydantic-ai's, no status
    pass


class RespErr(Exception):
    """httpx-style: status lives on .response."""
    def __init__(self, status):
        super().__init__("boom")
        self.response = type("R", (), {"status_code": status})()


def overloaded():
    return HTTPErr(529, {"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}})


def make(**kw):
    sleeps = []
    pol = RetryPolicy(**{"jitter": 0.0, **kw})
    return Retrier(pol, sleep=sleeps.append, clock=lambda: 0.0, rng=random.Random(0)), sleeps


def flaky(errors, result="ok"):
    errs = list(errors)
    calls = []

    def fn():
        calls.append(1)
        if errs:
            raise errs.pop(0)
        return result
    fn.calls = calls
    return fn


# ---- classification -----------------------------------------------------------------------
@pytest.mark.parametrize("status", [408, 429, 500, 502, 503, 504, 529])
def test_transient_statuses(status):
    assert classify(HTTPErr(status))[0] == "transient"


@pytest.mark.parametrize("status", [400, 401, 403, 404, 413, 422])
def test_permanent_statuses(status):
    assert classify(HTTPErr(status))[0] == "permanent"


def test_credit_balance_400_is_permanent_even_though_it_says_overloaded_nowhere():
    e = HTTPErr(400, {"type": "error", "error": {"type": "invalid_request_error",
                                                 "message": "Your credit balance is too low"}})
    assert classify(e) == ("permanent", "http_400")


def test_status_on_response_attribute_is_found():
    assert status_code_of(RespErr(503)) == 503 and classify(RespErr(401))[0] == "permanent"


def test_bare_model_api_error_without_status_is_transient():
    assert classify(ModelAPIError(""))[0] == "transient"


@pytest.mark.parametrize("exc", [TimeoutError("t"), ConnectionError("c"), ConnectionResetError("r"),
                                 type("ReadTimeout", (Exception,), {})("x"), type("APIConnectionError", (Exception,), {})("x")])
def test_timeouts_and_connection_errors_are_transient(exc):
    assert classify(exc)[0] == "transient"


def test_unclassified_exception_is_permanent():
    assert classify(RuntimeError("target blew up")) == ("permanent", "unclassified_exception")
    assert classify(ValueError("bad"))[0] == "permanent"


def test_provider_type_without_status_is_transient():
    e = Exception("stream error")
    e.body = {"error": {"type": "overloaded_error"}}
    assert classify(e) == ("transient", "provider_overloaded_error")


def test_status_found_through_cause_chain():
    try:
        try:
            raise HTTPErr(529)
        except HTTPErr as inner:
            raise ModelAPIError("wrapped") from inner
    except ModelAPIError as outer:
        assert status_code_of(outer) == 529 and classify(outer)[0] == "transient"


# ---- error detail -------------------------------------------------------------------------
def test_chain_lists_causes_and_contexts_and_is_cycle_safe():
    try:
        try:
            raise OSError("socket")
        except OSError:
            raise ModelAPIError("outer")          # implicit __context__
    except ModelAPIError as e:
        assert [type(x).__name__ for x in exception_chain(e)] == ["ModelAPIError", "OSError"]
    a, b = RuntimeError("a"), RuntimeError("b")
    a.__cause__, b.__cause__ = b, a
    assert len(exception_chain(a)) == 2


def test_describe_error_fields_for_a_nested_http_error():
    inner = HTTPErr(529, {"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}})
    outer = ModelAPIError("")
    outer.__cause__ = inner
    d = describe_error(outer, attempts=3)
    assert d["exception_chain"] == ["ModelAPIError", "HTTPErr"] and d["status_code"] == 529
    assert d["provider_error"]["type"] == "overloaded_error"
    assert d["classification"] == "transient" and d["attempts"] == 3
    assert d["message"] == ""


def test_describe_error_uses_body_when_message_is_empty():
    e = HTTPErr(400, {"error": {"type": "invalid_request_error", "message": "credit balance too low"}}, msg=" ")
    d = describe_error(e)
    assert "credit balance too low" in d["message"] and d["provider_error"]["type"] == "invalid_request_error"


def test_empty_message_headline_says_so():
    h = error_headline(describe_error(ModelAPIError("")))
    assert "(empty message)" in h and "no http status" in h and "transient" in h


def test_provider_code_is_extracted():
    e = HTTPErr(429, {"error": {"type": "rate_limit_error", "code": "rl_1"}})
    assert provider_error(e) == {"type": "rate_limit_error", "code": "rl_1"}


@pytest.mark.parametrize("raw", [KEY, "apikey_Zm9vYmFy123", "x-api-key: " + KEY, "Authorization: Bearer abcdefgh12345678",
                                 "sk-" + "a" * 30, "ANTHROPIC_API_KEY=" + KEY])
def test_redaction_removes_key_like_strings(raw):
    out = redact(f"failed with {raw} then more")
    assert KEY not in out and "ABCDEFGHIJ" not in out and "abcdefgh12345678" not in out
    assert "[REDACTED]" in out and "then more" in out


def test_clip_is_at_most_300_and_redacts_before_clipping():
    text = "x" * 285 + KEY
    out = clip_redacted(text)
    assert len(out) <= 300 and "sk-ant" not in out and "ABCDEF" not in out


def test_describe_error_redacts_message_and_body_and_never_includes_headers():
    e = HTTPErr(401, {"error": {"type": "authentication_error", "message": f"invalid key {KEY}"}},
                msg=f"status_code: 401 key {KEY}")
    e.headers = {"x-api-key": KEY, "authorization": "Bearer " + KEY}
    e.request = {"headers": {"x-api-key": KEY}}
    blob = json.dumps(describe_error(e)) + error_headline(describe_error(e))
    assert KEY not in blob and "ABCDEFGHIJKL" not in blob and "headers" not in blob and "[REDACTED]" in blob


def test_message_is_clipped():
    d = describe_error(RuntimeError("y" * 5000))
    assert len(d["message"]) <= 300 and len(d["body"] or "") <= 300


# ---- the retrier --------------------------------------------------------------------------
def test_backoff_schedule_is_exponential_and_capped_without_real_sleep():
    r, sleeps = make(max_attempts=8, base_s=2, cap_s=20, max_total_retries=50)
    fn = flaky([overloaded()] * 6)
    assert r.call(fn) == "ok"
    assert [e["delay_s"] for e in r.events] == [2, 4, 8, 16, 20, 20]
    assert sum(sleeps) == 70 and max(sleeps) <= 5.0


def test_jitter_only_shortens_and_never_exceeds_the_exponential_value():
    r = Retrier(RetryPolicy(jitter=0.5), sleep=lambda s: None, rng=random.Random(1))
    for attempt in range(1, 9):
        d = r.delay(attempt)
        exp = min(60, 2 * 2 ** (attempt - 1))
        assert exp * 0.5 <= d <= exp


def test_retry_after_header_is_honoured_up_to_the_cap():
    e = overloaded()
    e.retry_after = 30.0
    r, sleeps = make(base_s=2, cap_s=60)
    r.call(flaky([e]))
    assert [e["delay_s"] for e in r.events] == [30.0] and sum(sleeps) == 30.0
    e2 = overloaded()
    e2.retry_after = 999.0
    r2, s2 = make(cap_s=60)
    r2.call(flaky([e2]))
    assert [e["delay_s"] for e in r2.events] == [60.0] and sum(s2) == 60.0


def test_long_backoff_is_slept_in_slices_that_sum_to_the_delay():
    r, sleeps = make(base_s=12, cap_s=60)
    r.call(flaky([overloaded()]))
    assert sleeps == [5.0, 5.0, 2.0]


def test_transient_then_success_returns_the_value_and_counts_one_retry():
    r, sleeps = make()
    fn = flaky([overloaded()], result=42)
    assert r.call(fn) == 42 and len(fn.calls) == 2 and r.total_retries == 1 and sleeps == [2]


def test_success_first_try_never_sleeps():
    r, sleeps = make()
    assert r.call(flaky([])) == "ok" and sleeps == [] and r.total_retries == 0


def test_permanent_error_aborts_immediately_without_sleep():
    r, sleeps = make()
    fn = flaky([HTTPErr(400, {"error": {"type": "invalid_request_error", "message": "credit balance is too low"}})])
    with pytest.raises(CallFailed) as ei:
        r.call(fn)
    f = ei.value
    assert f.reason == "api_permanent" and len(fn.calls) == 1 and sleeps == [] and r.total_retries == 0
    assert f.info["classification"] == "permanent" and f.info["status_code"] == 400 and f.info["attempts"] == 1


def test_per_call_attempt_cap_gives_up_with_attempt_count():
    r, sleeps = make(max_attempts=3)
    fn = flaky([overloaded()] * 10)
    with pytest.raises(CallFailed) as ei:
        r.call(fn)
    assert ei.value.reason == "api_retries_exhausted" and len(fn.calls) == 3 and sleeps == [2, 4]
    assert ei.value.info["attempts"] == 3 and ei.value.info["classification"] == "transient"


def test_max_attempts_one_means_no_retry():
    r, sleeps = make(max_attempts=1)
    with pytest.raises(CallFailed):
        r.call(flaky([overloaded()]))
    assert sleeps == []


def test_global_retry_cap_spans_logical_calls():
    r, sleeps = make(max_attempts=5, max_total_retries=3)
    r.call(flaky([overloaded()] * 2))
    with pytest.raises(CallFailed) as ei:
        r.call(flaky([overloaded()] * 4))
    assert ei.value.reason == "api_retry_cap" and r.total_retries == 3 and len(sleeps) == 3


def test_zero_global_cap_forbids_any_retry():
    r, sleeps = make(max_total_retries=0)
    with pytest.raises(CallFailed) as ei:
        r.call(flaky([overloaded()]))
    assert ei.value.reason == "api_retry_cap" and sleeps == []


def test_kill_switch_set_before_a_retry_stops_without_sleeping():
    r, sleeps = make()
    kill = KillSwitch(path="/nonexistent/kill", environ={})
    kill.trip("stop now")
    with pytest.raises(CallFailed) as ei:
        r.call(flaky([overloaded()]), kill=kill)
    assert ei.value.reason == "kill_switch" and sleeps == []


def test_kill_switch_during_backoff_stops_before_the_next_attempt():
    kill = KillSwitch(path="/nonexistent/kill", environ={})
    sleeps = []

    def sleep(s):
        sleeps.append(s)
        kill.trip("tripped while waiting")
    r = Retrier(RetryPolicy(jitter=0, base_s=30), sleep=sleep, clock=lambda: 0.0)
    fn = flaky([overloaded()] * 3)
    with pytest.raises(CallFailed) as ei:
        r.call(fn, kill=kill)
    assert ei.value.reason == "kill_switch" and len(fn.calls) == 1 and sleeps == [5.0]
    assert "during backoff" in ei.value.detail


def test_on_retry_callback_gets_each_event_with_redacted_error():
    r, _ = make()
    seen = []
    r.call(flaky([HTTPErr(503, msg=f"key {KEY}")]), label="target", on_retry=seen.append)
    assert len(seen) == 1 and seen[0]["label"] == "target" and KEY not in json.dumps(seen)


def test_clock_is_used_for_elapsed_time():
    t = iter([0.0, 7.5])
    r = Retrier(RetryPolicy(max_attempts=1), sleep=lambda s: None, clock=lambda: next(t))
    with pytest.raises(CallFailed) as ei:
        r.call(flaky([overloaded()]))
    assert ei.value.info["elapsed_s"] == 7.5


def test_policy_validation():
    for bad in (dict(max_attempts=0), dict(base_s=-1), dict(cap_s=-1), dict(max_total_retries=-1), dict(jitter=2)):
        with pytest.raises(ValueError):
            RetryPolicy(**bad).validate()
    RetryPolicy().validate()


def test_real_pydantic_ai_exceptions_classify_when_installed():
    exc = pytest.importorskip("pydantic_ai.exceptions")
    assert classify(exc.ModelHTTPError(529, "m", {"error": {"type": "overloaded_error"}}))[0] == "transient"
    assert classify(exc.ModelHTTPError(400, "m", {"error": {"type": "invalid_request_error"}}))[0] == "permanent"
    assert classify(exc.ModelHTTPError(401, "m", None))[0] == "permanent"
    assert classify(exc.ModelAPIError("m", ""))[0] == "transient"
    d = describe_error(exc.ModelHTTPError(429, "m", {"error": {"type": "rate_limit_error"}}))
    assert d["status_code"] == 429 and d["provider_error"]["type"] == "rate_limit_error"
