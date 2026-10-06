"""(c) RuleProposer with a TRAIN/TEST split BY TECHNIQUE FAMILY.

Three folds over the 11 families (family i goes to fold i % 3). For each fold: learn rules from
the attacks that beat an undefended target in the TRAIN families, then measure the screen on the
HELD-OUT families it never saw. Benign data is split too: train n-grams from 36 messages, bound
false positives on 18 validation messages, report FPR on 18 untouched test messages.

Three experiments (same folds, same benign split):
  E1 standard      learned n-grams may include the attacker's address and channel (an IOC).
  E2 ioc_masked    addresses and channels are masked, so rules must be about instruction wording.
  E3 unseen_wording  as E2, but train families use goal paraphrases 0 and 1 and the held-out
                   families use paraphrase 2 only, so held-out goal wording is new.

Caveat that matters: goals are paraphrased from small shared pools (3 per goal), so unrelated
families can share goal wording. Any generalisation measured here may come from that shared
wording rather than from anything the proposer learned about a technique. The JSON lists which
proposed rules fire on held-out attacks so this can be inspected.
"""
from __future__ import annotations

import re

from dataclasses import replace

from whetstone.attacks import FAMILIES, base_corpus, build_attack
from whetstone.models import GOALS
from whetstone.benign import split_benign
from whetstone.defenses import ProposerConfig, RuleProposer, RuleSet, build_stack, default_ruleset
from whetstone.defenses.proposer import _matches
from whetstone.harness import RunConfig, benign_rates, gullible_factory, run_corpus

from .common import SEED, TRIALS, meta, rate, save


def _asr(attacks, stack, cfg, f):
    res = run_corpus(attacks, stack, f, cfg)
    return rate(sum(r.success for r in res), len(res))


def _para_corpus(fams, para):
    return [replace(build_attack(t, g, para=p), id=f"{t}/{g}#p{p}") for t in fams for g in GOALS for p in para]


def run_experiment(mask: bool, unseen_wording: bool) -> dict:
    cfg = RunConfig(seed=SEED, trials=TRIALS)
    f = gullible_factory()
    attacks = base_corpus() if not unseen_wording else _para_corpus(FAMILIES, (0, 1, 2))
    none = run_corpus(attacks, build_stack([]), f, cfg)
    won = {r.attack.id for r in none if r.success}
    tr_b, va_b, te_b = split_benign(SEED)
    train_txt, val_txt = [e.render() for e in tr_b], [e.render() for e in va_b]
    empty = RuleSet(0, (), "empty seed set")
    folds, pooled = [], {"none": [0, 0], "proposed_only": [0, 0], "default": [0, 0], "default_plus_proposed": [0, 0]}
    for k in range(3):
        test_f = [x for i, x in enumerate(FAMILIES) if i % 3 == k]
        train_f = [x for x in FAMILIES if x not in test_f]
        if unseen_wording:
            train_a = [a for a in attacks if a.technique in train_f and not a.id.endswith("#p2")]
            test_a = [a for a in attacks if a.technique in test_f and a.id.endswith("#p2")]
        else:
            train_a = [a for a in attacks if a.technique in train_f]
            test_a = [a for a in attacks if a.technique in test_f]
        wins = [a for a in train_a if a.id in won]
        prop = RuleProposer(ProposerConfig(mask_iocs=mask)).propose(wins, train_txt, val_txt, empty)
        both = default_ruleset().extend(list(prop.ruleset.rules), "default + proposed")
        stacks = {"none": build_stack([]), "proposed_only": build_stack(["input_screen"], ruleset=prop.ruleset),
                  "default": build_stack(["input_screen"]), "default_plus_proposed": build_stack(["input_screen"], ruleset=both)}
        held, seen, fpr = {}, {}, {}
        for name, st in stacks.items():
            held[name] = _asr(test_a, st, cfg, f)
            seen[name] = _asr(train_a, st, cfg, f)
            fpr[name] = benign_rates(te_b, st, f, cfg) if name != "none" else None
            pooled[name][0] += held[name]["k"]
            pooled[name][1] += held[name]["n"]
        firing = []
        for r in prop.ruleset.rules:
            hits = sorted({a.technique for a in test_a if _matches(r.pattern, " \n ".join(e.body for e in a.emails))})
            firing.append({"rule": r.name, "support_in_train": r.support, "fires_on_heldout_families": hits})
        def red(name):
            b = held["none"]["rate"]
            return round(1 - held[name]["rate"] / b, 4) if b else 0.0
        folds.append({
            "fold": k, "train_families": train_f, "test_families": test_f,
            "train_winning_attacks": len(wins), "rules_proposed": len(prop.ruleset.rules),
            "candidates": prop.candidates, "rejected_by_validation": len(prop.rejected),
            "uncovered_train_wins": prop.uncovered,
            "heldout_asr": held, "train_family_asr": seen,
            "heldout_asr_reduction": {n: red(n) for n in ("proposed_only", "default", "default_plus_proposed")},
            "benign_test_fpr": {n: (rate(v["task_disrupted"], v["n"]) if v else None) for n, v in fpr.items()},
            "proposed_rules": firing,
        })
    pooled_out = {n: rate(v[0], v[1]) for n, v in pooled.items()}
    b = pooled_out["none"]["rate"]
    reductions = {n: round(1 - pooled_out[n]["rate"] / b, 4) for n in ("proposed_only", "default", "default_plus_proposed")}
    # benign test FPR pooled is identical per fold (same 18 messages, different rule sets), so report per fold
    return {"mask_iocs": mask, "unseen_wording": unseen_wording, "benign_split": {"train": len(tr_b), "validation": len(va_b), "test": len(te_b)},
            "folds": folds, "pooled_heldout_asr": pooled_out, "pooled_heldout_asr_reduction": reductions,
            }


def run() -> dict:
    return {"meta": meta(),
            "reading": ("proposed_only = screen using ONLY learned rules. A reduction near 0 on held-out "
                        "families means the learned rules did not generalise; a large reduction may reflect "
                        "shared wording or a shared address across families rather than technique-level learning."),
            "E1_standard": run_experiment(False, False),
            "E2_ioc_masked": run_experiment(True, False),
            "E3_unseen_wording_ioc_masked": run_experiment(True, True)}


def main() -> int:
    out = run()
    save("generalisation", out)
    for key in ("E1_standard", "E2_ioc_masked", "E3_unseen_wording_ioc_masked"):
        e = out[key]
        p = e["pooled_heldout_asr"]
        print(f"[generalisation {key}] pooled held-out ASR: " + "  ".join(f"{k} {v['rate']:.1%}" for k, v in p.items()))
        print("    reduction vs none: " + "  ".join(f"{k} {v:.0%}" for k, v in e["pooled_heldout_asr_reduction"].items()))
        for fd in e["folds"]:
            fp = fd["benign_test_fpr"]["proposed_only"]
            print(f"    fold {fd['fold']}: rules {fd['rules_proposed']}  held-out ASR none {fd['heldout_asr']['none']['rate']:.0%}"
                  f" -> proposed-only {fd['heldout_asr']['proposed_only']['rate']:.0%}  benign-test FPR {fp['rate']:.0%}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
