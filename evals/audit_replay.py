"""Audit chain and replay check: run a sample of attacks with the audit log on, verify the hash
chain, replay every record and confirm the outcome is identical, then tamper with one record and
confirm verification fails at exactly that record. The chain is written to
evals/results/audit_sample.jsonl so it can be verified with `python -m whetstone report`."""
from __future__ import annotations

import json

from whetstone.attacks import FAMILIES, build_attack
from whetstone.audit import AuditLog, verify_records
from whetstone.defenses import build_stack
from whetstone.harness import RunConfig, gullible_factory, replay, run_corpus
from whetstone.models import GOALS

from .common import RESULTS, SEED, meta, save


def run() -> dict:
    path = RESULTS / "audit_sample.jsonl"
    RESULTS.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    log = AuditLog(path)
    attacks = [build_attack(t, GOALS[i % len(GOALS)]) for i, t in enumerate(FAMILIES)]
    stack = build_stack(["spotlight", "egress_filter", "tool_policy"])
    cfg = RunConfig(seed=SEED, trials=2)
    run_corpus(attacks, stack, gullible_factory(), cfg, log)
    recs = log.records()
    ok, bad = verify_records(recs)
    matches = [replay(r)[0] for r in recs if r["event"] == "attack_attempt"]
    tampered = json.loads(json.dumps(recs))
    tampered[3]["data"]["outcome"]["success"] = not tampered[3]["data"]["outcome"]["success"]
    t_ok, t_bad = verify_records(tampered)
    return {"meta": meta(), "records": len(recs), "head_hash": log.head(), "chain_verifies": ok,
            "replayed": len(matches), "replay_identical": sum(matches),
            "tamper_detected": (not t_ok), "tamper_first_bad_index": t_bad,
            "file": "evals/results/audit_sample.jsonl"}


def main() -> int:
    out = run()
    save("audit_replay", out)
    print(f"[audit] {out['records']} records, chain ok={out['chain_verifies']}, replay identical "
          f"{out['replay_identical']}/{out['replayed']}, tamper detected={out['tamper_detected']} "
          f"at record {out['tamper_first_bad_index']}")
    good = (out["chain_verifies"] and out["replay_identical"] == out["replayed"]
            and out["tamper_detected"] and out["tamper_first_bad_index"] == 3)
    return 0 if good else 1


if __name__ == "__main__":
    raise SystemExit(main())
