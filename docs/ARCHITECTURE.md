# Architecture

Everything runs against a **simulated** sandbox (synthetic inbox, fake tools, fake canary secrets). The default target is a **simulation**; a real model can be plugged in as target (run once, by hand) or as attacker (built; only a 1-campaign smoke test run), only through optional, guarded entry points. The sandbox has no network and no real system behind it. Attacks target only this project's own sandbox.

## Flow of one attack run

```mermaid
sequenceDiagram
    participant H as Harness
    participant S as Sandbox (fresh per run)
    participant D as DefenseStack
    participant T as Target (simulated gullible agent)
    participant G as ToolBox + guard
    participant O as Oracle (deterministic)
    participant A as Audit log (hash chain)

    H->>S: new Sandbox(seed, attack emails planted unread)
    H->>D: prepare(rendered unread mail)
    D-->>H: blocked_by=input_screen, or content (spotlit if enabled)
    alt screened out
        Note over H,T: the target never runs (progress 0)
    else content passes
        H->>T: run(task, content)
        loop each injected or legitimate action
            T->>G: call(tool, args)
            G->>D: guard(tool, args): ToolPolicy, then EgressFilter
            alt blocked
                G-->>T: error, nothing reaches the ledger
            else allowed
                G->>S: execute, append to effects ledger
            end
        end
        T-->>H: tool_calls, output_text
        H->>D: finalize_output (EgressFilter redacts or blocks)
    end
    H->>O: evaluate(goal, ledger, delivered output, canaries)
    O-->>H: success + reasons (pure function)
    H->>A: append attack_attempt (attack, defenses, seeds, outcome)
```

## Layers

| Layer | File | Responsibility |
|---|---|---|
| Models | `src/whetstone/models.py` | `Email`, `Attack`, `ToolCall`, `TargetResult`, `AttackResult`; shared constants (fake destinations, goals) |
| Sandbox | `sandbox/env.py` | Synthetic inbox, 6 mail and chat tools plus 2 note tools, private notes holding fake `CANARY-` tokens, append-only `EffectsLedger` of every call |
| Targets | `targets/base.py` | `Target` protocol; `ToolBox` puts a guard between any target and the sandbox and keeps the attempted-call log |
| | `targets/gullible.py` | `GullibleTarget`: deterministic **simulation** that follows instructions per an author-set `SusceptibilityProfile`; seeded, paired across defenses |
| | `targets/llm.py` | `LLMTarget`: pydantic-ai Agent bound to the same tools. Unit-tested with TestModel and FunctionModel; run live once by hand (Claude Haiku 4.5, results in `evals/results/live/`); optional per-run request cap |
| Attacks | `attacks/corpus.py` | 11 technique families x 5 goals = 55 base attacks; 3 goal paraphrases |
| | `attacks/mutators.py` | 14 seeded mutators (lookalikes, zero-width, synonyms, framing, encodings, secret re-encoding, re-paraphrase) |
| | `attacks/attackers.py` | `Attacker` protocol; `ScriptedAttacker`, `MutatingAttacker` (adaptive), `BlindMutator` (control) |
| | `attacks/llm_attacker.py` | `LLMAttacker`: pydantic-ai Agent, structured `AttackSpec` output, prompt with goals, task and feedback; a refusal and a non-output are distinct recorded results (non-output gets one corrective retry). **Built and offline-tested; full experiment not yet run** |
| | `attacks/feedback.py` | What the attacker may see after a round (no hidden fields, canaries withheld); `Generation`; draft to `Attack` |
| | `attacks/guardrails.py` | Deterministic validator for every generated attack: reserved domains, key-like strings, canary marker, phone and IP, real organisations, length, technique set |
| | `attacks/campaign.py` | Campaign loop (R rounds, stop at first success), `Budget`, `KillSwitch`, `BlindSource` control, per-round audit records and spans |
| | `adaptive_experiment.py`, `stats.py` | Plan, run and summarise the 3-condition experiment (adaptive, adaptive vs all defenses, blind control); Wilson, exact and Fisher; `scripts/run_adaptive_live.py` is the guarded entry point |
| Oracles | `oracles.py` | Canary in output or outbound args (plain and re-encoded), forbidden tool call, recipient outside allow-list, mass deletion; one goal oracle per goal |
| Defenses | `defenses/input_screen.py` | Fold, decode (base64, rot13, leetspeak), weighted rule scan per message; versioned `RuleSet` |
| | `defenses/spotlight.py` | Random per-call delimiters plus an explicit instruction; a fixed-delimiter mode shows the spoofing weakness |
| | `defenses/egress.py` | Secret patterns in outputs and tool args (plain, URL, rot13, base64 by default), external image stripping |
| | `defenses/tool_policy.py` | Tool, recipient, channel and folder allow-lists; confirmation for external forwards and deletes; forward limit |
| | `defenses/stack.py` | `DefenseStack` hooks: `prepare`, `guard`, `finalize_output`; config round trip for replay |
| | `defenses/proposer.py`, `defender.py` | `RuleProposer` (n-gram synthesis, benign-train filter, held-out validation, versioned output), `Defender` protocol, `LLMDefender` stub |
| Corpus | `benign.py` | 72 hand-written benign messages (36 hard), stratified train/validation/test split |
| Harness | `harness.py` | `run_attack`, `run_corpus`, `run_benign`, `spar`, `replay`, aggregation |
| Audit | `audit.py` | Hash-chained JSONL log; verify; replay support |
| Tracing | `tracing.py` | OpenTelemetry spans (attack run, target step, defense check, oracle, defender round, campaign, round, attacker call); no-op unless a provider is configured |
| CLI | `cli.py` | `run-attacks`, `run-defenses`, `spar`, `report` |

## Where each defense acts

| Hook | Defense | Sees | Cannot see |
|---|---|---|---|
| `prepare` | InputScreen | the text of each message, plus decoded views | an encoding it does not decode, lookalikes outside its table, paraphrases outside its rules |
| `prepare` | Spotlighting | wraps content | nothing by itself; it changes how a cooperative model reads the content |
| `guard` | ToolPolicy | the tool name and arguments | secrets in an allowed destination; output text |
| `guard` | EgressFilter | secret patterns in arguments | reversed or hex secrets by default; forwards or deletes of ordinary mail |
| `finalize_output` | EgressFilter | secret patterns and images in the answer | the same encodings |

## Adaptive campaign flow (built, offline-tested; full experiment not yet run)

```mermaid
flowchart LR
    G[LLMAttacker<br/>goal + task + feedback] --> V{Guardrails<br/>validate draft}
    V -->|rejected / refused| REC[Round record<br/>+ audit]
    V -->|ok| H[Harness: fresh sandbox,<br/>defenses, target]
    H --> O[Oracle decides]
    O --> REC
    REC -->|feedback: blocked_by, tool calls,<br/>output, oracle fired| G
    O -->|success| STOP[Stop campaign]
```

Budget, kill switch and abort checks run before every attacker call and every target run.

## Scoring and progress

The oracle reads only the effects ledger (calls that actually executed) and the delivered output text. A blocked call never reaches the ledger. Each result also carries `progress` for the adaptive attacker: 0 screened out, 1 ran and the target declined, 2 the target attempted the injected action but a guard stopped it, 3 success. `attempted` is simulation bookkeeping (the target knows which calls it made on an instruction) and is never read by an oracle.

## Failure table

| Failure | Behaviour |
|---|---|
| Unknown tool, bad arguments | Recorded as a failed effect in the ledger; the run continues; it never counts as success |
| Defense raises | Not caught: a crash is a visible bug, not a silent pass |
| Tampered audit record | `verify` reports the first bad index |
| `LLMTarget.live` with no key | Raises before anything is built; the CLI refuses without `--live` and an environment key |
| `LLMDefender` | Raises `NotImplementedError` (not built) |
| Attacker refuses, or returns no structured output | Recorded round outcome `attacker_refused`; costs an attacker call, not a target run; never an error |
| Generated attack fails validation | Recorded round outcome `attack_rejected` with the reasons; not run; the reasons go back to the attacker as feedback |
| Budget reached, kill switch, attacker or target error | Campaign ends `aborted` with a reason; the experiment stops, saves partial results and audit chains, and exits 3, 4 or 5 |
| `scripts/run_adaptive_live.py` without `--live`, `--yes` or `ANTHROPIC_API_KEY` | Prints the plan, refuses (exit 2), calls nothing |
