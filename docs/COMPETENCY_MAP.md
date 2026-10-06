# Competency map

Each entry names the code or test that demonstrates it. Nothing here is claimed without evidence in the repository, and the environment is simulated. The target is a simulation of a gullible agent, not an LLM.

## Adversarial evaluation design

**Behavior:** Build an attack corpus and an adaptive attacker so that "defended" has to survive more than the cases the author first thought of.

**Evidence:**
- 11 technique families x 5 goals with three paraphrases per goal; `attacks/corpus.py`, `tests/test_attacks.py`.
- 14 seeded, deterministic mutators; `test_mutation_is_deterministic_for_a_seed`.
- Adaptive attacker with progress feedback, plus a blind control; `attacks/attackers.py`, `evals/mutation.py`.
- Parser sanity: with every probability at 1, all 55 attacks succeed; `test_fully_gullible_target_is_fooled_by_every_goal_of_each_family`.

## Measurement discipline

**Behavior:** Report what a number measures, with its denominator, its interval and its bias.

**Evidence:**
- Paired target seeds across defenses; `test_spotlighting_only_ever_removes_successes`.
- False positives reported next to every defense, on routine and hard benign mail separately; `evals/defenses.py`.
- Train/test split by technique family, three folds, three experiments (standard, indicator-masked, unseen wording), unflattering result reported; `evals/generalisation.py`.
- Wilson intervals; authorship bias and latency caveats stored in the JSON; `evals/common.py`.
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
- `LLMTarget` built and tested only with TestModel; `LLMAttacker` and `LLMDefender` raise `NotImplementedError`; `--target llm` needs `--live` and an environment key; `tests/test_llm_target.py`, `tests/test_cli.py`.
- [THREAT_MODEL.md](THREAT_MODEL.md) lists what the defenses do not stop.

## Not demonstrated

- Any real LLM, as a target, an attacker or a defender.
- Any real mailbox, chat service or agent product (inbox-marshal and slack-daily-brief are not tested here).
- An MCP server for the sandbox tools; a second target scenario.
- Whether any finding transfers from the simulated target to real models.
