# Competency map

Each entry names the code or test that demonstrates it. Nothing here is claimed without evidence in the repository, and the sandbox is simulated. The default target is a simulation of a gullible agent, not an LLM; one real model (Claude Haiku 4.5) was also run once, by hand, and is reported separately.

## Adversarial evaluation design

**Behavior:** Build an attack corpus and an adaptive attacker so that "defended" has to survive more than the cases the author first thought of.

**Evidence:**
- 11 technique families x 5 goals with three paraphrases per goal; `attacks/corpus.py`, `tests/test_attacks.py`.
- 14 seeded, deterministic mutators; `test_mutation_is_deterministic_for_a_seed`.
- Adaptive attacker with progress feedback, plus a blind control; `attacks/attackers.py`, `evals/mutation.py`.
- LLM-driven adaptive attacker with per-round feedback, a campaign loop, a blind-mutation control with the same attempt budget and a fixed metric set (campaign success, attempts to first success, refusal rate, adaptive versus blind); `attacks/llm_attacker.py`, `attacks/campaign.py`, `adaptive_experiment.py`, `tests/test_campaign.py`. **Built and tested offline with stubs only; never run live.**
- Parser sanity: with every probability at 1, all 55 attacks succeed; `test_fully_gullible_target_is_fooled_by_every_goal_of_each_family`.

## Measurement discipline

**Behavior:** Report what a number measures, with its denominator, its interval and its bias.

**Evidence:**
- Paired target seeds across defenses; `test_spotlighting_only_ever_removes_successes`.
- False positives reported next to every defense, on routine and hard benign mail separately; `evals/defenses.py`.
- Train/test split by technique family, three folds, three experiments (standard, indicator-masked, unseen wording), unflattering result reported; `evals/generalisation.py`.
- Wilson intervals; authorship bias and latency caveats stored in the JSON; `evals/common.py`.
- Exact (Clopper-Pearson) and Fisher intervals and tests with no scipy; `stats.py`, `tests/test_stats.py`.
- Baseline gate: ASR must stay in a non-vacuous range; `evals/baseline.py`, `test_baseline_is_not_vacuous`.

## Deterministic oracles

**Behavior:** Decide success with code that can be tested, not a model that can be argued with.

**Evidence:**
- Canary detection in plain and re-encoded forms, forbidden call, external recipient, mass deletion; `oracles.py`, `tests/test_oracles.py`.
- 12 known-bad and 11 known-good scripted cases, with a negative control that breaks an oracle; `evals/oracle_sanity.py`, `test_oracle_sanity_can_fail`.
- Design rule: [ADR 001](adr/001-deterministic-oracles-not-llm-judges.md).

## Defense in depth

**Behavior:** Compose guardrails with different blind spots and show which goals each one cannot see.

**Evidence:**
- Input screen with normalisation, decoding and per-message scanning; `defenses/input_screen.py`, `tests/test_defenses.py`.
- Spotlighting with random delimiters, and a fixed-delimiter mode that is shown to be spoofable; `test_fixed_delimiter_is_spoofable_but_random_is_not`.
- Egress filter and tool policy with per-goal results in the README; `defenses/egress.py`, `defenses/tool_policy.py`.
- Ablation: normalisation off; `evals/mutation.py`.

## Learning from failures, with bounded false positives

**Behavior:** Turn successful attacks into candidate rules without poisoning benign traffic.

**Evidence:**
- Deterministic n-gram synthesis, benign-train filter, held-out validation, versioned output; `defenses/proposer.py`, `tests/test_proposer.py`.
- Header fields excluded so a fixed sender cannot become the "feature"; `test_header_fields_are_not_used_as_features`.
- Indicator masking so rules are about instructions; `test_masked_rules_cover_an_address_the_training_set_never_saw`.
- Arms race against the mutating attacker; `evals/mutation.py`.

## Safe use of a dual-use capability

**Behavior:** Bound what a model-written attack can contain and what a run can spend, and say what the bounds do not cover.

**Evidence:**
- Deterministic validator (reserved domains, key-like strings, canary marker, phone and IP, real organisations, length, technique set), checked against the 55 author-written attacks so it is not over-strict; `attacks/guardrails.py`, `tests/test_guardrails.py`.
- Refusal is a recorded outcome, not an error or something to route around; `test_refusals_are_recorded_not_errors_and_skip_the_target`.
- Hard call budgets, kill switch, clean abort with partial results; the live script refuses without `--live`, `--yes` and an environment key, never takes a key on the command line, and CI never calls it; `tests/test_campaign.py`, `tests/test_adaptive_experiment.py`.
- Real provider requests switched off for the whole test suite; `tests/conftest.py`.
- Dual-use note with the validators' limits: [THREAT_MODEL.md](THREAT_MODEL.md). All offline; none of it observed with a real model.

## Secure agent design

**Behavior:** Put enforcement between the agent and its tools, not in the prompt.

**Evidence:**
- `ToolBox` guard in front of every tool call; blocked calls never reach the ledger; `targets/base.py`, `test_blocked_call_never_reaches_the_ledger_but_counts_as_attempted`.
- Append-only effects ledger with frozen entries; `tests/test_sandbox.py`.
- Confirmation required for external forwarding and deletes; recipient-domain check is suffix-safe; `tests/test_defenses.py`.

## Auditability and observability

**Behavior:** Make every attack attempt reviewable and replayable.

**Evidence:**
- Hash-chained audit log, tamper detection at the exact record, replay with identical outcome; `audit.py`, `tests/test_audit.py`, `evals/audit_replay.py` (22/22 identical).
- OpenTelemetry spans for attack run, target step, defense check, oracle, defender round with technique, goal, blocked_by and success; `tests/test_tracing.py`. No-op by default; only `opentelemetry-api` is a runtime dependency.

## Honest scoping

**Behavior:** Say what was built, what was run, and what was not.

**Evidence:**
- Environment labelled SIMULATED in every eval output; target described as a simulation in the README, the module docstring and the JSON caveat.
- `LLMTarget` unit-tested with TestModel and run live once against Claude Haiku 4.5 (0/165 undefended, 0/165 defended, 3/72 benign false positives; `evals/results/live/`); a null result reported as a null result, with an exact upper bound and the limits of that bound; `LLMDefender` still raises `NotImplementedError`, and `LLMAttacker` is built and offline-tested only, not run live; `--target llm` needs `--live` and an environment key; `tests/test_llm_target.py`, `tests/test_cli.py`.
- Live-run hygiene: audit records carry the real target label (a hardcoded `gullible` label was found and fixed, `test_harness_target_label.py`), replay refuses non-simulated records, and positive controls show the live pipeline can register a success (`evals/live_positive_control.py`, not run in CI; the 2026-10-05 control was an equivalent ad-hoc run).
- [THREAT_MODEL.md](THREAT_MODEL.md) lists what the defenses do not stop.

## Not demonstrated

- A real LLM as an attacker (built, offline-tested with stubs only, never run) or defender (not built). A real LLM as a target is demonstrated for one model, one task and 3 trials only.
- Any real mailbox, chat service or agent product (inbox-marshal and slack-daily-brief are not tested here).
- An MCP server for the sandbox tools; a second target scenario.
- Whether any simulated-target finding transfers to real models: the one comparison available says it did not (50.5% simulated vs 0% measured on Haiku 4.5).
