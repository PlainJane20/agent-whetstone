# Threat model

Whetstone is a **defensive evaluation harness**. This document states what it attacks (only its own sandbox), what the defenses it tests do and do not stop, and where a simulation stops being evidence. The sandbox is simulated, and the default target is a simulation; one real model (Claude Haiku 4.5) has also been run against it once, by hand (results in the README and `evals/results/live/`). Every statement below about real deployments is a limit, not a result.

## Scope and misuse boundaries

- **In scope:** attacks against this project's own simulated sandbox: a synthetic inbox of benign emails, fake tools, and fake canary strings (`CANARY-` plus 12 hex characters, unique per seed, with no value outside the sandbox).
- **Payloads are generic and benign by construction:** they ask an assistant to make a fake tool call, post to a fake channel, or reveal a fake string. Destinations are reserved `.example` names. There is no malware, no real credential, no real service and no exploit code in the repository.
- **Do not point any of this at a system you do not own.** The attack templates are simple, but the discipline matters: use them against your own agents, in your own sandbox, with fake data. The live-model path (`LLMTarget.live`, `--target llm --live`) exists for that purpose, requires your own key from the environment, and was run once, by hand, on 2026-10-05 against Claude Haiku 4.5 (never in tests or CI).
- **No data from any employer or real person** is used. Every email, sender and domain is synthetic.
- **Out of scope:** attacking third-party agents, products or services; testing against real mailboxes; anything that exfiltrates real data.

## Assets and actors

- **Asset under test:** an agent's behaviour when the content it reads is hostile (the sandbox's mailbox, notes, and tools).
- **Attacker** (scripted or mutating, offline; or a model, `LLMAttacker`, built and offline-tested only, never run live): untrusted, controls the text of one or two emails, nothing else. The model attacker is told the goals, the target's tool names and its task text; that is a white-box-ish assumption, not a black-box one.
- **Target:** untrusted by design. Two targets have been run: a **simulation** of a gullible agent (every offline number) and, once, a real model (Claude Haiku 4.5) driving the fake tools.
- **Defenses:** trusted code (screen, spotlighting, egress filter, tool policy) running in-process.
- **Oracles and ledger:** trusted code; the ledger is append-only by API and its entries are frozen.

## What the harness protects, and how

| Property | Mechanism | Evidence |
|---|---|---|
| Attacks cannot reach real systems | The package imports no network client (the optional pydantic-ai import in `LLMTarget` and `LLMAttacker` is never called here); the sandbox tools are in-memory; importing the sandbox, harness, oracles, defenses and campaign loop loads no HTTP client | `test_no_network_modules_used_by_the_package`, `test_sandbox_path_imports_no_http_client`, `tests/test_sandbox.py` |
| A generated attack carries nothing real into the sandbox | Deterministic validator before every use: reserved test domains only, no key-like strings, no phone numbers or IPs, no named real organisations, no `CANARY-` marker, length cap, fixed technique set | `tests/test_guardrails.py` (offline; a deny-list, see the dual-use section) |
| The attacker cannot judge or fake its own success | Success is only the oracle's verdict; the attacker never sees a hidden field; its text cannot contain the canary | `test_oracle_decides_not_the_attacker_rationale`, `test_feedback_has_no_hidden_fields_end_to_end` |
| An adaptive run cannot spend without bound | Per-invocation `max_target_runs` and `max_attacker_calls`, a per-run request cap, a kill switch, clean abort with partial results; the live script refuses without `--live`, `--yes` and an environment key | `tests/test_campaign.py`, `tests/test_adaptive_experiment.py` (call counts, not money) |
| A success claim is not the target's say-so | A deterministic oracle reads executed effects and delivered text | `tests/test_oracles.py`, `test_oracle_decides_success_not_the_target` |
| The oracle can fail in both directions | 23 known-bad and known-good cases; a negative control breaks an oracle on purpose | `evals/oracle_sanity.py`, `test_oracle_sanity_can_fail` |
| A blocked action leaves no effect | Guard runs before the sandbox executes; the ledger only records executed calls | `test_blocked_call_never_reaches_the_ledger_but_counts_as_attempted` |
| Comparisons across defenses are paired | The target's random draw depends on the content with any spotlight envelope removed | `test_spotlighting_only_ever_removes_successes` |
| A defense cannot learn the benign set it is scored on | Proposer trains on benign-train, validates on a held-out validation set, FPR is reported on a third split | `evals/generalisation.py` |
| Runs are tamper-evident and replayable | Hash-chained audit with full attack, defense config and seeds per record | `tests/test_audit.py`, `evals/audit_replay.py` |

## What the defenses do NOT stop

1. **Novel attacks.** A screen is a set of patterns. The held-out evaluation shows learned rules cut held-out ASR by only 26 to 37%, and mostly by recognising what is being requested, not the technique.
2. **A smarter adaptive attacker.** An LLM attacker is built (offline-tested only, never run), so how a model adapts against these defenses is unmeasured. The mutation eval breaks the input screen with Greek lookalike letters and synonyms, and the egress filter with reversed or hex-encoded secrets. A real adversary can try far more than 14 mutators. The attacker here is also weak (no better than blind mutation).
3. **Deterministic filters in general.** Every deterministic filter can be bypassed by an input it was not written for. They raise cost and catch the known; they are not a boundary.
4. **Discussing an attack versus carrying one.** All 3 benign false positives are security writing that quotes an injection phrase, a tool-call syntax or a delimiter tag. Pattern screens cannot separate the two.
5. **Leaks to an allowed destination.** The tool policy allows a post to the team channel; only the egress filter catches a secret in it, and only in the encodings it checks.
6. **Spotlighting on a real model.** Its measured benefit is by construction of the simulated target. Against Haiku 4.5 the undefended rate was already 0/165, so no benefit could be observed; whether it helps any model that is actually fooled is not measured.
7. **Semantic harm inside a permitted action.** A legitimate-looking forward to an allowed internal recipient is allowed, whatever the content.
8. **Confidentiality of the notes themselves.** The agent may read private notes. Nothing here stops reading, only some forms of leaving.
9. **Tampering by someone with file access.** Anyone who can rewrite the whole audit file can rebuild a consistent chain; the head hash is not anchored elsewhere.
10. **Most of real LLM behaviour.** One model, one task prompt and 3 trials were measured: Haiku 4.5 resisted all 165 author-written attacks, undefended and defended (0/165 bounds the rate below about 2.2% for that corpus, task and model only). Other models, stronger, indirect or adaptive attacks and other tasks are not measured. The gullible target is a model of gullibility I wrote, and its 50.5% overstated this model's vulnerability.
11. **Anything the defenses might add against a model that is already robust.** They screened out 76% of attacks before Haiku saw them but cost 3/72 (4.2%) benign false positives, with no measurable gain against this model.

## Dual use: the LLM attacker

`LLMAttacker` asks a model to write prompt-injection emails. That is dual-use capability, so the boundaries are written down. **Status: built, offline-tested only, not run live; nothing below was observed with a real model.**

- **Why generated attacks are confined to the sandbox.** The only thing the attacker produces is the text of one email, planted in a synthetic inbox that a target reads through in-memory fake tools. There is no network path, no real mailbox and no real secret to reach; the "secrets" are fake `CANARY-` strings that the attacker is never given and the validator forbids it to write. The goals are a fixed set of five that the oracles can check.
- **What the validators do NOT guarantee.** They are regexes, an allow-list of reserved test domains and a deny-list of organisation names. They are not a content-safety classifier. A model can phrase a harmful instruction without any listed token; the deny-list of real organisations is short and will miss names; entropy and prefix rules will miss novel key formats and will occasionally reject benign text; encoded content is only checked for base64 and hex that decode to printable text. A draft that passes is "free of the listed real-world markers", not "safe". The real protection is the sandbox, not the validator.
- **The prompt is not a control.** It states that the test is authorised and the data is fake; that helps a model decide, and it is not enforcement.
- **Refusal behaviour.** If the model declines (plain text, no structured output, content-filter stop), the round is recorded as `attacker_refused`, the refusal rate is reported, and nothing tries to get around it: no retry prompt, no rephrased request, no second model. A high refusal rate is a result about the attacker model, not a bug to engineer away. How a real model will behave here is unmeasured.
- **Misuse boundaries.** Use it only against this sandbox, with your own key from the environment and a provider spend limit. Do not repoint the generated emails, the campaign loop or the prompts at a mailbox, product or person you do not own, and do not add real destinations, real credentials or real service names to the sandbox to "make it realistic". The guards bound calls, not money, and not what a model may write.
- **Audit and privacy.** Each round's full attack text is stored in the audit log and the results JSON on purpose (a run must be reviewable). It is never put in OpenTelemetry span attributes.
- **A strong attacker would change this document.** If a live run ever shows the model producing material that is harmful outside the sandbox, that finding belongs here and the feature should be narrowed, not hidden.

## Limits of the simulation

- **Live runs are not simulated, but their tools are.** The real model drove fake in-memory tools over a short synthetic inbox; live behaviour is nondeterministic and live latency was not measured.
- **Compliance probabilities are author-set guesses** (per technique, per goal, per spotlight). They are documented in `SusceptibilityProfile` and recorded in `evals/results/baseline.json`.
- **The target's parser and the attack templates were written together.** With every probability set to 1, all 55 base attacks succeed (this is how I checked the parser reaches every attack); that shows the parser matches the templates, not that a real model would parse them.
- **Corpus authorship bias.** Attacks, benign mail, default rules and the profile come from one author. The default screen was written knowing the corpus, so its 8.7% ASR is optimistic.
- **Small benign set.** 72 messages, 18 in the test split.
- **Shared goal wording** across families (3 paraphrases per goal) can inflate cross-family generalisation; E3 in the generalisation eval reduces but does not remove it.
- **Latency** is in-process on one machine and excludes any model call.
