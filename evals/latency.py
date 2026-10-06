"""(e) Defense latency p50/p95, in-process, single thread, after warm-up.

Caveats: these are pure-Python regex and string operations on short synthetic emails, on one
machine. They exclude any model call, network, or real mail volume. A real deployment's latency
is dominated by the model, not by these checks.
"""
from __future__ import annotations

import time

from whetstone.attacks import base_corpus
from whetstone.defenses import (EgressFilter, InputScreen, Spotlighting, ToolPolicy, build_stack)
from whetstone.harness import RunConfig, gullible_factory, run_attack

from .common import meta, pct, save

CAVEATS = [
    "In-process, single thread, warm caches, after a warm-up. No network, no model call.",
    "Inputs are short synthetic emails; real mail is longer and the screen scales with length.",
    "'run_attack_*' includes the simulated target and the sandbox; it says nothing about a real LLM.",
    "Numbers come from one machine; the JSON records which.",
]


def _time(fn, n: int, inputs: list) -> dict:
    for i in range(min(50, n)):
        fn(inputs[i % len(inputs)])
    xs = []
    for i in range(n):
        x = inputs[i % len(inputs)]
        t = time.perf_counter()
        fn(x)
        xs.append((time.perf_counter() - t) * 1000)
    xs.sort()
    return {"n": n, "p50_ms": round(pct(xs, .5), 4), "p95_ms": round(pct(xs, .95), 4),
            "p99_ms": round(pct(xs, .99), 4), "max_ms": round(xs[-1], 4)}


def run() -> dict:
    attacks = base_corpus()
    texts = [a.untrusted_text() for a in attacks]
    screen, spot, egress, policy = InputScreen(), Spotlighting(), EgressFilter(), ToolPolicy()
    outs = ["Summary of 9 unread emails: Sprint 14 planning; Badge reader maintenance; Weekly data digest."] * 8
    calls = [("forward_email", {"to": "x@corp.example", "body": "hi", "email_id": "m1"}),
             ("post_message", {"channel": "#team-updates", "text": "Inbox summary: 9 unread emails."})]
    stack = build_stack(["all"])
    f = gullible_factory()
    cfg_n = RunConfig(seed=0, trials=1)
    cfg_a = RunConfig(seed=0, trials=1)
    none = build_stack([])

    def full_defense(text):
        p = stack.prepare(text)
        for name, args in calls:
            stack.guard(name, dict(args))
        stack.finalize_output(outs[0])
        return p

    return {"meta": meta(), "caveats": CAVEATS,
            "input_screen_scan": _time(screen.scan, 2000, texts),
            "spotlight_wrap": _time(spot.wrap, 2000, texts),
            "egress_filter_output": _time(egress.filter_output, 2000, outs),
            "tool_policy_check": _time(lambda c: policy.check(*c), 5000, calls),
            "all_defenses_per_run (prepare + 2 guards + finalize)": _time(full_defense, 2000, texts),
            "run_attack_no_defense": _time(lambda a: run_attack(a, 0, none, f, cfg_n), 550, attacks),
            "run_attack_all_four": _time(lambda a: run_attack(a, 0, stack, f, cfg_a), 550, attacks)}


def main() -> int:
    out = run()
    save("latency", out)
    print("[latency] p50 / p95 ms")
    for k, v in out.items():
        if isinstance(v, dict) and "p50_ms" in v:
            print(f"    {k:55s} n={v['n']:5d}  {v['p50_ms']:.4f} / {v['p95_ms']:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
