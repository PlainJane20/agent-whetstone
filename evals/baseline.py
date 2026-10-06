"""(a) Baseline attack success rate with no defense, overall and per technique and goal,
plus (d) canary leak rate. Target: the SIMULATED GullibleTarget."""
from __future__ import annotations

from whetstone.attacks import base_corpus
from whetstone.defenses import build_stack
from whetstone.harness import RunConfig, gullible_factory, run_corpus, summarize
from whetstone.targets import DEFAULT_PROFILE

from .common import SEED, TRIALS, meta, rate, save


def canary_leak(results) -> dict:
    leaked = [r for r in results if {"canary_in_outbound", "canary_in_output"} & set(r.violations)]
    return rate(len(leaked), len(results))


def run() -> dict:
    cfg = RunConfig(seed=SEED, trials=TRIALS)
    attacks = base_corpus()
    results = run_corpus(attacks, build_stack([]), gullible_factory(), cfg)
    s = summarize(results)
    for grp in ("by_technique", "by_goal"):
        for v in s[grp].values():
            v["ci95"] = rate(v["successes"], v["n"])["ci95"]
    return {"meta": meta(), "target": "GullibleTarget (SIMULATED, author-set susceptibility profile)",
            "profile": DEFAULT_PROFILE.describe(), "attacks": len(attacks), "trials": TRIALS,
            "overall": rate(s["successes"], s["n"]), "target_attempted": rate(s["attempted"], s["n"]),
            "canary_leak_rate": canary_leak(results),
            "by_technique": s["by_technique"], "by_goal": s["by_goal"]}


def main() -> int:
    out = run()
    save("baseline", out)
    o = out["overall"]
    print(f"[baseline] ASR {o['k']}/{o['n']} = {o['rate']:.1%}  CI95 {o['ci95']}  "
          f"canary leak {out['canary_leak_rate']['rate']:.1%}")
    for k, v in out["by_technique"].items():
        print(f"    {k:24s} {v['successes']:3d}/{v['n']:3d}  {v['asr']:.0%}")
    # gate: the simulation must not be vacuous
    return 0 if 0.2 < o["rate"] < 0.9 else 1


if __name__ == "__main__":
    raise SystemExit(main())
