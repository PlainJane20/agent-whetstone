"""Retry with backoff and rich, key-safe error detail for live model calls.

STATUS: offline-tested only (fake exceptions that imitate the SDK shapes). How the real pydantic-ai /
anthropic SDKs surface the status code for each error type was NOT verified against live failures.

Why this exists: the first full adaptive run aborted after 17 of 45 campaigns on one ModelAPIError with an
empty message. A transient failure (overload, rate limit, dropped connection) must not kill hours of work,
and a permanent one (bad request, no credit, bad key) must stop at once with a record that says which it was.

Classification (looks at the whole __cause__/__context__ chain, duck-typed so this module needs no SDK):
  * HTTP status found anywhere in the chain: 408, 429, any 5xx -> transient; every other 4xx -> permanent.
  * no status: provider error type overloaded_error / rate_limit_error / api_error -> transient;
    timeouts, connection errors and a bare ModelAPIError (pydantic-ai wraps connection failures in one) -> transient.
  * anything else (a bug, a guardrail, a usage limit) -> permanent. Unknown means stop, not loop.

The key is never written: messages and bodies are clipped to 300 chars and redacted, headers are never read
except Retry-After (a number), and request objects are never serialised.
"""
from __future__ import annotations

import random
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_BASE_S = 2.0
DEFAULT_CAP_S = 60.0
DEFAULT_MAX_TOTAL_RETRIES = 100
DEFAULT_JITTER = 0.5            # a delay is exp * (1 - jitter * U[0,1)): never above the exponential value
SLEEP_CHUNK_S = 5.0             # sleep in slices so the kill switch is honoured during a long backoff
CLIP = 300

TRANSIENT_STATUS = frozenset({408, 429, 500, 502, 503, 504, 529})
TRANSIENT_BODY_TYPES = frozenset({"overloaded_error", "rate_limit_error", "api_error", "timeout_error"})
TRANSIENT_NAMES = ("timeout", "connecterror", "connectionerror", "connectionreset", "remoteprotocolerror",
                   "readerror", "writeerror", "networkerror", "apiconnectionerror", "overloaded",
                   "modelapierror", "brokenpipe", "incompleteread", "eoferror")

_REDACT = [
    re.compile(r"sk-ant-[A-Za-z0-9_\-]+", re.I),
    re.compile(r"apikey_[A-Za-z0-9_\-]+", re.I),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"(x-api-key|api[-_ ]?key|authorization)(['\"]?\s*[:=]\s*['\"]?)(bearer\s+)?[^\s'\",}]+", re.I),
    re.compile(r"\bbearer\s+[A-Za-z0-9._\-]{8,}", re.I),
]


def redact(text: str) -> str:
    """Strip anything that looks like an API key or an auth header value."""
    out = str(text)
    out = _REDACT[0].sub("[REDACTED]", out)
    out = _REDACT[1].sub("[REDACTED]", out)
    out = _REDACT[2].sub("[REDACTED]", out)
    out = _REDACT[3].sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", out)
    out = _REDACT[4].sub("[REDACTED]", out)
    return out


def clip_redacted(text: Any, n: int = CLIP) -> str:
    """Redact first, then clip, so a key cut in half by the clip cannot survive."""
    s = redact(str(text)).replace("\n", " ")
    return s if len(s) <= n else s[: n - 3] + "..."


def exception_chain(exc: BaseException, limit: int = 8) -> list[BaseException]:
    chain: list[BaseException] = []
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen and len(chain) < limit:
        chain.append(cur)
        seen.add(id(cur))
        cur = cur.__cause__ or (None if cur.__suppress_context__ else cur.__context__)
    return chain


def _int(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def status_code_of(exc: BaseException) -> int | None:
    for e in exception_chain(exc):
        s = _int(getattr(e, "status_code", None))
        if s is None:
            s = _int(getattr(getattr(e, "response", None), "status_code", None))
        if s is not None:
            return s
    return None


def _body_of(e: BaseException) -> Any:
    return getattr(e, "body", None)


def provider_error(exc: BaseException) -> dict:
    """Provider error type / code when the chain exposes them (Anthropic bodies look like
    {"type": "error", "error": {"type": "overloaded_error", "message": "..."}})."""
    typ = code = None
    for e in exception_chain(exc):
        body = _body_of(e)
        if isinstance(body, dict):
            inner = body.get("error") if isinstance(body.get("error"), dict) else body
            t = inner.get("type") if isinstance(inner, dict) else None
            if isinstance(t, str) and t != "error":
                typ = typ or t
            c = inner.get("code") if isinstance(inner, dict) else None
            if isinstance(c, (str, int)):
                code = code if code is not None else c
        c2 = getattr(e, "code", None)
        if isinstance(c2, (str, int)) and not isinstance(c2, bool):
            code = code if code is not None else c2
    return {"type": clip_redacted(typ, 80) if typ else None, "code": clip_redacted(code, 80) if code is not None else None}


def _retry_after(exc: BaseException) -> float | None:
    for e in exception_chain(exc):
        v = getattr(e, "retry_after", None)
        if isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0:
            return float(v)
    return None


def classify(exc: BaseException) -> tuple[str, str]:
    """Return ("transient" | "permanent", reason)."""
    status = status_code_of(exc)
    if status is not None:
        if status in TRANSIENT_STATUS or status >= 500:
            return "transient", f"http_{status}"
        return "permanent", f"http_{status}"
    ptype = provider_error(exc)["type"]
    if ptype in TRANSIENT_BODY_TYPES:
        return "transient", f"provider_{ptype}"
    chain = exception_chain(exc)
    for e in chain:
        if isinstance(e, (TimeoutError, ConnectionError)):
            return "transient", "timeout_or_connection_error"
    for e in chain:
        name = type(e).__name__.lower()
        if any(k in name for k in TRANSIENT_NAMES):
            return "transient", f"class_{type(e).__name__}"
    if "overloaded" in str(exc).lower():
        return "transient", "message_overloaded"
    return "permanent", "unclassified_exception"


def describe_error(exc: BaseException, *, attempts: int = 1, classification: str | None = None,
                   reason: str | None = None) -> dict:
    """The abort / retry detail. Key-safe by construction: only class names, an int status, provider type/code
    strings and a clipped, redacted message or body are included."""
    if classification is None:
        classification, reason = classify(exc)
    chain = exception_chain(exc)
    msg = str(exc)
    body = _body_of(exc)
    if not msg.strip() and body is not None:
        msg = str(body)
    return {"exception_chain": [type(e).__name__ for e in chain],
            "status_code": status_code_of(exc),
            "provider_error": provider_error(exc),
            "message": clip_redacted(msg) if msg.strip() else "",
            "body": clip_redacted(body) if body is not None else None,
            "classification": classification, "classification_reason": reason,
            "attempts": attempts}


def error_headline(info: dict) -> str:
    """One-line abort_detail from describe_error output (kept compatible with the old 'Type: message')."""
    first = info["exception_chain"][0]
    bits = [f"status={info['status_code']}" if info["status_code"] is not None else "no http status",
            info["classification"], f"{info['attempts']} attempt(s)"]
    pe = info["provider_error"]
    if pe.get("type"):
        bits.append(f"provider_type={pe['type']}")
    msg = info["message"] or "(empty message)"
    return clip_redacted(f"{first}: {msg} [{'; '.join(bits)}]", 400)


class CallFailed(Exception):
    """A logical call gave up. `reason`: api_permanent | api_retries_exhausted | api_retry_cap | kill_switch."""

    def __init__(self, reason: str, info: dict, detail: str = "") -> None:
        super().__init__(detail or reason)
        self.reason, self.info, self.detail = reason, info, detail


@dataclass
class RetryPolicy:
    max_attempts: int = DEFAULT_MAX_ATTEMPTS        # per logical call, the first try included
    base_s: float = DEFAULT_BASE_S
    cap_s: float = DEFAULT_CAP_S
    max_total_retries: int = DEFAULT_MAX_TOTAL_RETRIES   # across the whole invocation
    jitter: float = DEFAULT_JITTER

    def validate(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("retry max attempts must be at least 1")
        if self.base_s < 0 or self.cap_s < 0:
            raise ValueError("retry base and cap seconds cannot be negative")
        if self.max_total_retries < 0:
            raise ValueError("max total retries cannot be negative")
        if not 0 <= self.jitter <= 1:
            raise ValueError("jitter must be within [0, 1]")

    def to_dict(self) -> dict:
        return {"max_attempts": self.max_attempts, "base_s": self.base_s, "cap_s": self.cap_s,
                "max_total_retries": self.max_total_retries, "jitter": self.jitter}


@dataclass
class Retrier:
    """Runs a callable, retrying transient failures. One instance per invocation: `total_retries` is the
    global counter that the cap applies to. `sleep`, `clock` and `rng` are injectable so tests never wait."""
    policy: RetryPolicy = field(default_factory=RetryPolicy)
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic
    rng: random.Random = field(default_factory=random.Random)
    total_retries: int = 0
    events: list[dict] = field(default_factory=list)       # every retry: attempt, delay, error summary

    def delay(self, attempt: int, retry_after: float | None = None) -> float:
        """Backoff before retry number `attempt` (1-based): base * 2^(attempt-1), jittered down, capped."""
        p = self.policy
        exp = min(p.cap_s, p.base_s * (2 ** (attempt - 1)))
        d = exp * (1 - p.jitter * self.rng.random())
        if retry_after is not None:
            d = max(d, retry_after)
        return min(p.cap_s, d)

    def call(self, fn: Callable[[], Any], *, label: str = "", kill=None,
             on_retry: Callable[[dict], None] | None = None) -> Any:
        p = self.policy
        attempt = 0
        t0 = self.clock()
        while True:
            attempt += 1
            try:
                return fn()
            except CallFailed:
                raise
            except Exception as exc:                     # noqa: BLE001 - classified below
                kind, why = classify(exc)
                info = describe_error(exc, attempts=attempt, classification=kind, reason=why)
                info["elapsed_s"] = round(self.clock() - t0, 3)
                if kind == "permanent":
                    raise CallFailed("api_permanent", info, "permanent API error, not retried") from exc
                if attempt >= p.max_attempts:
                    raise CallFailed("api_retries_exhausted", info,
                                     f"transient error persisted through {attempt} attempt(s)") from exc
                if self.total_retries >= p.max_total_retries:
                    raise CallFailed("api_retry_cap", info,
                                     f"global cap of {p.max_total_retries} transient retries reached") from exc
                if kill is not None and kill.reason():
                    raise CallFailed("kill_switch", info, f"kill switch set before retry: {kill.reason()}") from exc
                self.total_retries += 1
                delay = self.delay(attempt, _retry_after(exc))
                ev = {"label": label, "attempt": attempt, "next_attempt": attempt + 1,
                      "delay_s": round(delay, 3), "error": {k: info[k] for k in
                      ("exception_chain", "status_code", "provider_error", "message", "classification_reason")}}
                self.events.append(ev)
                if on_retry:
                    on_retry(ev)
                left = delay
                while left > 0:
                    step = min(left, SLEEP_CHUNK_S)
                    self.sleep(step)
                    left -= step
                    if kill is not None and kill.reason():
                        info["attempts"] = attempt
                        raise CallFailed("kill_switch", info,
                                         f"kill switch set during backoff: {kill.reason()}") from exc
