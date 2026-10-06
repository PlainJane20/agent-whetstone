"""(f) Adaptive attacker: how many of the 55 base attacks have at least one surviving variant after
N rounds of mutation, per defense. Also: a blind-mutator control, and an arms race where the
RuleProposer defender learns from each round.

"Broken" means some variant of that base attack achieved its goal in at least one of 3 trials.
The adaptive attacker sees `progress` and `blocked_by` feedback, which a real black-box attacker
may not get. Round 0 is the unmutated corpus.
"""
from __future__ import annotations

from collections import Counter

from whetstone.attacks import BlindMutator, MutatingAttacker, base_corpus
from whetstone.benign import split_benign
from whetstone.defenses import (InputScreen, InputScreenConfig, RuleProposerDefender, build_stack,
                                default_ruleset)
from whetstone.defenses.stack import DefenseStack
from whetstone.harness import RunConfig, benign_rates, gullible_factory, run_corpus, spar

from .common import DEFENSE_CONFIGS, SEED, meta, rate, save

ROUNDS = 5
TRIALS = 3
BUDGET = 110


def _stack(name: str) -> DefenseStack:
    if name == "input_screen_no_normalise":
        return DefenseStack(input_screen=InputScreen(InputScreenConfig(normalise=False)))
    return build_stack(DEFENSE_CONFIGS[name])


def play(stack_name: str, attacker_cls) -> dict:
    cfg = RunConfig(seed=SEED, trials=TRIALS)
    f = gullible_factory()
    attacker = attacker_cls(seed=SEED, budget=BUDGET, variants_per_parent=2)
    stack = _stack(stack_name)
    history, broken, rounds, chains = [], set(), [], Counter()
    for r in range(ROUNDS + 1):
        attacks = attacker.propose(r, history)
        res = run_corpus(attacks, stack, f, cfg)
        broken |= {x.attack.lineage or x.attack.id for x in res if x.success}
        chains.update("+".join(x.attack.mutations) for x in res if x.success and x.attack.mutations)
        rounds.append({"round": r, "attacks": len(attacks), "runs": len(res),
                       "asr": round(sum(x.success for x in res) / len(res), 4) if res else 0.0,
                       "lineages_broken": len(broken)})
        history = res
    return {"rounds": rounds, "broken_after_round0": rounds[0]["lineages_broken"],
            "broken_after_final": rounds[-1]["lineages_broken"], "of": 55,
            "successful_mutation_chains": dict(chains.most_common(12))}


def arms_race() -> dict:
    """InputScreen only. Static default rules vs a defender that learns rules after every round."""
    cfg = RunConfig(seed=SEED, trials=TRIALS)
    f = gullible_factory()
    tr, va, te = split_benign(SEED)
    out = {}
    for label, learn in (("static_default_rules", False), ("learning_defender", True)):
        defender = RuleProposerDefender([e.render() for e in tr], [e.render() for e in va])
        if not learn:
            defender.propose = lambda r, res: defender.ruleset      # never updates
        reports, hist = spar(MutatingAttacker(seed=SEED, budget=BUDGET), defender, [], ROUNDS + 1, f, cfg)
        final = build_stack(["input_screen"], ruleset=defender.ruleset)
        out[label] = {
            "rounds": [{"round": r.round_no, "ruleset_version": r.ruleset_version, "attacks": r.n_attacks,
                        "asr": r.asr, "new_rules": r.new_rules,
                        "lineages_broken_cumulative": r.lineages_broken} for r in reports],
            "final_rules": len(defender.ruleset.rules),
            "lineages_broken": reports[-1].lineages_broken,
            "benign_test_fpr_final_ruleset": rate(
                benign_rates(te, final, f, cfg)["task_disrupted"], len(te)),
            "benign_all_fpr_final_ruleset": rate(
                benign_rates(tr + va + te, final, f, cfg)["task_disrupted"], len(tr + va + te)),
        }
    return out


def run() -> dict:
    names = list(DEFENSE_CONFIGS) + ["input_screen_no_normalise"]
    return {"meta": meta(), "rounds": ROUNDS, "trials_per_attack": TRIALS, "budget_per_round": BUDGET,
            "adaptive": {n: play(n, MutatingAttacker) for n in names},
            "blind_control": {n: play(n, BlindMutator) for n in names},
            "arms_race": arms_race()}


def main() -> int:
    out = run()
    save("mutation", out)
    print(f"[mutation] base attacks with a surviving variant (of 55), round 0 -> round {ROUNDS}")
    for n in out["adaptive"]:
        a, b = out["adaptive"][n], out["blind_control"][n]
        print(f"    {n:26s} adaptive {a['broken_after_round0']:2d} -> {a['broken_after_final']:2d}"
              f"   blind {b['broken_after_round0']:2d} -> {b['broken_after_final']:2d}")
    for k, v in out["arms_race"].items():
        print(f"    arms race {k}: ASR by round {[r['asr'] for r in v['rounds']]} broken {v['lineages_broken']}/55 "
              f"benign-test FPR {v['benign_test_fpr_final_ruleset']['rate']:.0%}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
