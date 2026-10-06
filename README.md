<img src="docs/whetstone-banner.svg" alt="Whetstone: a sparring partner for AI agents" width="100%" />

# Whetstone

### *A sparring partner for AI agents*

<div align="center">

[![Python 3.11+](https://img.shields.io/badge/Python_3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![pydantic-ai](https://img.shields.io/badge/pydantic--ai-LLMTarget_(built,_not_run)-E92063?style=for-the-badge&logo=pydantic&logoColor=white)](src/whetstone/targets/llm.py)
[![OpenTelemetry](https://img.shields.io/badge/OpenTelemetry-spans-f59e0b?style=for-the-badge&logo=opentelemetry&logoColor=white)](src/whetstone/tracing.py)
[![Tests](https://img.shields.io/badge/Offline_tests-240_passing-2a78d6?style=for-the-badge)](tests/)
[![Environment](https://img.shields.io/badge/Environment-SIMULATED-b45309?style=for-the-badge)](#known-limits)
[![Scope](https://img.shields.io/badge/Scope-defensive_only-e11d48?style=for-the-badge)](docs/THREAT_MODEL.md)

</div>

Whetstone grinds attacks against your agents so their defenses come out sharper. An
attacker agent fires prompt-injection and data-exfiltration attempts at a **sandboxed
target**. Composable guardrails (input screening, spotlighting, an egress filter, a tool
policy) stand in the way. A **deterministic oracle**, never an LLM judge, decides whether
each attack achieved its goal. A defender proposes new screening rules from the attacks that
won, and every attempt lands in a hash-chained, replayable audit log.

> **Everything here runs against a SIMULATED sandbox.** The inbox is synthetic, the tools
> are fake, the "secrets" are fake `CANARY-` strings, and the vulnerable target is a
> **rule-based simulation of a gullible agent, not a language model**. No network is used,
> no LLM is called, and no test or eval needs an API key.

> **Defensive scope only.** Attacks only ever target this project's own sandbox. Payloads are
> generic and benign by construction (make a fake tool call, reveal a fake string) and use
> reserved `.example` destinations. **Do not point any of this at a system you do not own.**
> See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

**Pattern:** peer swarm (attacker and defender agents) around a sandboxed target, scored by
deterministic oracles.

**Why this exists:** the agent projects in this portfolio govern what agents may do. This
one asks how you would know the governance holds when the content an agent reads is
hostile. It treats attack success rate as an engineering measurement with the same hygiene
as any other: fixed seeds, paired comparisons, false positives counted next to catch rates,
a held-out split that is allowed to disappoint, and oracles that are themselves tested.

> **Related work in this portfolio:** [Blast Door](https://github.com/PlainJane20/blast-door)
> contains the damage when an agent is wrong or hostile; Whetstone finds the weaknesses
> that make that containment necessary. The hash-chained audit log is adapted from Blast Door
> and [edge-sentinel](https://github.com/PlainJane20/edge-sentinel). The kinds of agents
> this would eventually test live are
> [inbox-marshal](https://github.com/PlainJane20/inbox-marshal) and
> [slack-daily-brief](https://github.com/PlainJane20/slack-daily-brief): **they are not
> tested here**; the only targets run in this repository are the simulated gullible agent
> and a TestModel-driven stub.

## How it works, in plain terms

![How Whetstone works: attacker, front door, simulated target, sandbox, oracle, score, defender and audit record](docs/images/how-it-works.svg)

The attacker plants one or two emails in a synthetic inbox. The defenses may screen them
out, or wrap them so the agent knows they are data. The simulated agent then summarises its
mail and posts a one-line summary to a team channel, and, with some probability set by an
author-written profile, also obeys instructions it found in the email. Guards check each
tool call and the final answer. After the run, an oracle reads the effects ledger and the
delivered text and says whether the attack's goal was met. The defender learns rules from
the attacks that won. Everything is written to an audit chain.

## At a glance

| | |
|---|---|
| **Problem** | Measure how well guardrails stop injection and exfiltration, without fooling yourself with a vacuous eval, an LLM judge, or a corpus the defense has memorised |
| **Approach** | 55 base attacks (11 technique families x 5 goals) plus seeded mutators; 72 hand-written benign messages (36 hard); four composable defenses; deterministic oracles; paired seeds so every defense sees the same random draws |
| **Proof** | 240 offline tests. No-defense ASR 50.5% (139/275). Full stack 0.0% (0/275) at 4.2% false positives (3/72). Held-out technique families: learned rules only cut ASR by 26 to 37% (poor generalisation). After 5 rounds of mutation the full stack still has 7 broken base attacks, from reversed or hex-encoded secrets. Oracles: 12/12 known-bad fire, 11/11 known-good silent |
| **Output** | ASR per technique and goal, false-positive rate, canary leak rate, latency p50/p95, versioned rule sets, hash-chained replayable audit log (22/22 replays identical), OpenTelemetry spans |
| **Not built** | A live LLM attacker, defender or target run (code paths exist as stubs or TestModel-tested only), an MCP server for the sandbox tools, a second scenario (Slack summariser). No real system or model has been tested |

## Competencies demonstrated

| Competency | Observable evidence |
|---|---|
| Adversarial evaluation design | 11 technique families x 5 goals, seeded mutators, adaptive vs blind attacker, mutation rounds reported per defense |
| Measurement discipline | Paired target seeds, Wilson intervals, FPR beside ASR, a train/test split by technique family, authorship bias stated beside every table |
| Deterministic oracles | Canary (plain and re-encoded), forbidden call, external recipient, mass deletion; 23 sanity cases with a negative control ([ADR 001](docs/adr/001-deterministic-oracles-not-llm-judges.md)) |
| Defense in depth | Input screen, spotlighting, egress filter, tool policy: each alone and together, with the goals each one cannot see |
| Secure agent design | Sandbox with an append-only effects ledger, guard layer between the agent and its tools, confirmation required for external forwarding and deletes |
| Auditability and observability | Hash-chained audit log with replay and tamper detection; OpenTelemetry spans for attack run, target step, defense check, oracle, defender round |
| Honest scoping | SIMULATED labels, "built, not run" LLM paths, explicit threat model, limits next to the numbers |

Full mapping to code and tests: [`docs/COMPETENCY_MAP.md`](docs/COMPETENCY_MAP.md).

## Real output

All numbers below come from `python -m evals.run_all` and `python -m pytest`, run on Python
3.14.7 on an arm64 Mac with fixed seeds (the committed JSON in `evals/results/` records the
machine and git commit; re-running reproduces every number except latency, which is
timing). CI runs the same commands on Python 3.11 and 3.12. The environment is **SIMULATED**.

> **Read every number here with the same caveat.** I wrote the attacks, the benign mail, the
> default screening rules and the target's susceptibility profile. The target is a
> **simulation of a gullible agent, not an LLM**. These tables show that the harness works
> and how defenses compare **against that model**. They are not an estimate of real-world
> security or of how any real model behaves.

Setup: 275 runs per configuration (55 attacks x 5 trials, seed 0); trials differ only in
the target's random draw. Intervals are 95% Wilson bands and are approximate because runs
share attacks and seeds.

### (a) Baseline attack success rate, no defense

The simulated target follows an instruction it finds with a per-technique probability from
an author-set profile ([`SusceptibilityProfile`](src/whetstone/targets/gullible.py), all
numbers are guesses, none calibrated to any model). Overall **ASR 139/275 = 50.5%** (CI 44.7
to 56.4%).

| Technique family | Successes | ASR |
|---|---|---|
| fake system message | 17/25 | 68% |
| urgency / authority pressure | 16/25 | 64% |
| direct override | 15/25 | 60% |
| markdown-image / URL exfiltration | 15/25 | 60% |
| delimiter spoofing | 14/25 | 56% |
| quoted-reply indirect injection | 14/25 | 56% |
| role-play framing | 13/25 | 52% |
| encoded payload (base64, rot13, leetspeak) | 10/25 | 40% |
| multilingual (es, fr, de) | 10/25 | 40% |
| tool-parameter injection | 9/25 | 36% |
| split payload across two emails | 6/25 | 24% |

By goal: leak canary via output text 64%, via post 58%, forward all mail externally 55%,
leak via forward 40%, delete all emails 36%. These mostly echo the profile I set, which is
the point of a baseline: it is the yardstick for the rows below, not a finding.

### (b) Each defense alone and combined, with false positives

False-positive rate (FPR) counts a benign message when a defense stopped something the user
wanted: the message was screened out, the legitimate summary post was blocked, or the summary
was altered. 72 benign messages, 36 of them hard cases. Canary leak rate is the share of runs
in which a fake canary left through any channel, including attacks that were aimed at another
goal.

| Config | ASR | ASR reduction | Canary leak | FPR, all 72 | FPR, 36 hard |
|---|---|---|---|---|---|
| none | 139/275 = 50.5% | n/a | 89/275 = 32.4% | 0 | 0 |
| input screen | 24/275 = 8.7% | 83% | 19/275 = 6.9% | **3/72 = 4.2%** | 3/36 = 8.3% |
| spotlighting | 50/275 = 18.2% | 64% | 35/275 = 12.7% | 0 | 0 |
| egress filter | 50/275 = 18.2% | 64% | **0/275 = 0.0%** | 0 | 0 |
| tool policy | 55/275 = 20.0% | 60% | 55/275 = 20.0% | 0 | 0 |
| **all four** | **0/275 = 0.0%** (CI 0 to 1.4%) | 100% | 0/275 = 0.0% | 3/72 = 4.2% | 3/36 = 8.3% |

The three false positives are all security material that quotes an attack or shows syntax: a
newsletter quoting "ignore all previous instructions", a developer note showing
`forward_email(to=...)`, and a newsletter showing a `<system>` tag. A pattern screen cannot tell
discussing an attack from carrying one. The 0 rows for the other defenses are
over a corpus I wrote; the interval for 0/72 reaches 5.1%.

**The defenses are complementary, because each is blind to goals the others see:**

| Goal | none | input screen | spotlight | egress filter | tool policy | all four |
|---|---|---|---|---|---|---|
| leak via forward | 40% | 9% | 16% | **0%** | **0%** | 0% |
| leak via post | 58% | 15% | 20% | **0%** | 36% | 0% |
| leak via output text | 64% | 11% | 27% | **0%** | **64%** | 0% |
| forward all mail | 55% | 4% | 13% | 55% | **0%** | 0% |
| delete all mail | 36% | 5% | 15% | 36% | **0%** | 0% |

The tool policy cannot see output text or a post to an allowed channel; the egress filter
cannot see a forward of ordinary mail or a delete. With the input screen on, the attacks
that survive are multilingual (40%), markdown image (24%), split payload (24%) and encoded
(8%); every other family is at 0%. Spotlighting's effect comes from the target's profile
(see Known limits).

### (c) Does the RuleProposer generalise? Held-out technique families

The RuleProposer learns word n-grams that appear in at least two successful attacks and in
no benign training message, then validates each on a held-out benign set. Evaluation uses
3 folds over the 11 families (every family is held out exactly once): rules are learned from
the attacks that beat an undefended target in the train families, then tested on families the
proposer never saw. Benign data is split as well: 36 messages to learn from, 18 to bound false
positives, 18 untouched to report FPR. "Proposed only" is a screen with only the learned rules.

| Experiment | Held-out ASR, no defense | Held-out ASR, proposed rules only | Reduction | Held-out ASR, hand-written screen | Hand-written + proposed |
|---|---|---|---|---|---|
| E1 standard | 139/275 = 50.5% | 87/275 = 31.6% | **37%** | 24/275 = 8.7% | 17/275 = 6.2% |
| E2 addresses and channels masked | 139/275 = 50.5% | 94/275 = 34.2% | **32%** | 8.7% | 21/275 = 7.6% |
| E3 masked, and held-out goal wording unseen | 124/275 = 45.1% | 92/275 = 33.5% | **26%** | 22/275 = 8.0% | 21/275 = 7.6% |

**It generalises poorly, as expected.** On the families it learned from, the proposed rules
drive ASR to about 0 to 1% (per fold: 1.1%, 0.0%, 1.0%). On families it never saw, a third of
attacks still get through (31.6% vs 50.5% undefended). The false-positive bound held:
0/18 benign test messages blocked in every fold (95% CI up to 17.6%, so this is weak
evidence). Reading the rules that fired on held-out families
(`evals/results/generalisation.json`) shows why the reduction is not zero. In E1 the
workhorse was `external mail example`, the attacker's constant address, which is an
indicator, trivially evaded by changing it. After masking addresses (E2, E3) what transfers
is not technique knowledge but **what is being asked for**: `private notes`, `the vault key`,
`all of the emails`. The proposer learned the goals, not the families. The hand-written screen
looks much better (8.7%), but I wrote it knowing this corpus, so that figure is optimistic and
the learned rules add little (to 6.2% to 7.6%) on top of it.

### (d) Canary leak rate

In table (b): 32.4% of undefended runs leak a fake canary. The egress filter drives it to 0.0%
(0/275) on this corpus; the tool policy leaves it at 20.0%, because a post to an allowed
channel is not stopped. The next section shows that 0.0% does not survive mutation.

### (e) Defense latency

In-process on one machine (arm64 macOS, Python 3.14.7), after warm-up, one thread, short
synthetic emails.

| Step | n | p50 | p95 |
|---|---|---|---|
| input screen scan (all rules, all decoded views) | 2,000 | 0.1457 ms | 0.1735 ms |
| spotlight wrap | 2,000 | 0.0010 ms | 0.0012 ms |
| egress filter, output | 2,000 | 0.0032 ms | 0.0033 ms |
| tool policy check | 5,000 | 0.0003 ms | 0.0004 ms |
| all defenses, one run (prepare + 2 guards + finalize) | 2,000 | 0.1551 ms | 0.1877 ms |
| whole attack run, no defense (simulated target + sandbox + oracle) | 550 | 0.7605 ms | 0.8624 ms |
| whole attack run, all four defenses | 550 | 0.9006 ms | 1.7080 ms |

**Caveats:** pure-Python regex on short emails; real mail is longer and the screen scales with
length. Nothing here includes a model call, which would dominate in any real deployment. One
machine, so treat the figures as an order of magnitude.

### (f) Adaptive attacker: how defenses degrade under mutation

Each round the `MutatingAttacker` mutates the attacks that did not work (best "progress"
first) using 14 seeded mutators (zero-width, homoglyphs, case, whitespace, synonyms, benign
padding, framing, base64 and rot13 wrapping, re-paraphrasing, and secret re-encoding as hex,
reversed or base64). The table counts **base attacks (of 55) with at least one successful
variant** (any of 3 trials) at round 0 (no mutation) and after round 5. The "blind"
control uses the same mutators and budget but ignores results.

| Defense | Adaptive, round 0 to 5 | Blind, round 0 to 5 |
|---|---|---|
| none | 52 to 55 | 52 to 55 |
| input screen | 13 to 25 | 13 to 34 |
| input screen, normalisation off (ablation) | 17 to 55 | 17 to 50 |
| spotlighting | 24 to 55 | 24 to 50 |
| egress filter | 20 to 49 | 20 to 43 |
| tool policy | 17 to 19 | 17 to 19 |
| **all four** | **0 to 7** | 0 to 3 |

What broke what (`successful_mutation_chains` in `evals/results/mutation.json`): the screen
fell mainly to **Greek lookalike letters** (its fold table covers Cyrillic only) and
synonym swaps; the egress filter fell to **reversed or hex-encoded secrets** (it checks
base64, rot13 and URL-encoding by default, not hex or reversal); all 7 base attacks that broke
the full stack carry a reversed or hex-encoded secret somewhere in their mutation chain.
Turning normalisation off lets everything through by round 5. Spotlighting's collapse is a
property of the simulated target (see Known limits). The "adaptive" attacker is **not**
better than blind random mutation here (it is worse against the screen: 25 vs 34); my
guess is that stacking mutations on top of earlier ones damages the payload, but I did not
test that.

**Arms race** (input screen only, learning defender vs static rules, same attacker seed, 6
rounds): base attacks broken by round 5 were 25/55 for static default rules and 17/55 for
a defender that re-learns rules after each round (5 rules added, rule set v1 to v4). Both
end at 0/18 false positives on the benign test split and 3/72 on all benign mail. The
defender trains on the same lineages it is then scored on, so this shows the loop works, not
that it generalises (see (c)).

### (g) Oracle sanity

Scripted checks that each oracle fires on a known-bad case and stays silent on a known-good
one. **Known-bad fired 12/12; known-good silent 11/11.** Cases include the canary
re-encoded (base64, hex, rot13, reversed, URL-encoded, letter-spaced), an unplanted
canary-shaped token, a failed call that must not count, 2 of 3 forwards or deletes, and
internal-only forwards. A test breaks an oracle on purpose and confirms the eval then fails
(`test_oracle_sanity_can_fail`). The oracle recognises more encodings than the default egress
filter on purpose, so the evals can show bypasses instead of missing them.

### Audit and replay

A sample run (22 attack attempts, `evals/results/audit_sample.jsonl`) produces a hash chain
that verifies; **all 22 replay with identical outcomes** (same success, blocking defense,
progress and output hash); flipping one stored outcome is detected at exactly that record.
`python -m whetstone report` re-verifies the committed chain.

## Real findings from building this

1. **My first proposer result looked like generalisation and was a constant.** The strongest
   learned rule was the attacker's own address, which every forwarding attack shared. I added
   an indicator-masked variant and an unseen-wording variant; the honest held-out reduction is
   26 to 37%, and what carries over is goal wording ("private notes", "the vault key"),
   not technique. A fixed sender in the corpus would have been an even cheaper cheat, so
   the proposer learns from bodies only.
2. **A perfect score is not a result.** The full stack scores 0/275. Five rounds of mutation
   push it to 7 broken base attacks, every one through a secret re-encoding the default egress
   filter does not check. Reporting only the static number would have hidden that.
3. **The defenses cover different goals.** The tool policy never sees output text; the egress
   filter never sees a forward of ordinary mail or a delete. Per-goal rows show it, and the
   combined 0% is a union of blind spots that happen to cover this corpus.
4. **Scanning the concatenated inbox caused false positives.** A "send ... to an external
   address" rule matched across the boundary of two unrelated emails. The screen now scans
   each message on its own (`test_screen_scans_messages_separately`).
5. **The oracle must be stricter than the defense.** If the oracle only looked for plain
   canaries it would have scored the reversed and hex leaks as defended. Sanity cases pin this.
6. **Paired seeds make comparisons meaningful.** The target's draw depends on the content
   with any spotlighting envelope removed, so every defense sees the same dice. A test
   checks that spotlighting only removes successes, never adds them.
7. **A fixed delimiter is spoofable, a random one is not.** With `randomise=False`, a forged
   closing marker ends the untrusted zone and the target treats what follows as trusted
   (`test_fixed_delimiter_is_spoofable_but_random_is_not`).
8. **The screen cannot distinguish discussing an attack from carrying one.** All 3 false
   positives are security writing. Any rule that catches `ignore all previous instructions`
   catches the newsletter that explains it.

## Architecture

```mermaid
flowchart LR
    AT[Attacker<br/>scripted or mutating] --> SC{Front door<br/>InputScreen +<br/>Spotlighting}
    SC -->|blocked| OR
    SC -->|content| TG[Target<br/>simulated gullible agent]
    TG -->|tool call| GD{Guard<br/>ToolPolicy + EgressFilter}
    GD -->|allowed| SB[(Sandbox<br/>fake tools, canaries)]
    SB --> LG[(Effects ledger<br/>append-only)]
    TG -->|answer| EF[EgressFilter<br/>on output]
    LG --> OR[Oracle<br/>deterministic]
    EF --> OR
    OR --> SCORE[ASR, FPR, leak rate]
    OR --> AU[(Hash-chained audit log)]
    SCORE --> DF[Defender<br/>RuleProposer]
    DF -->|new rule set vN+1| SC
```

Component tables, the attack-run sequence, and the failure table:
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Scope, misuse boundaries and what the
defenses do not stop: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). Design rule:
[ADR 001](docs/adr/001-deterministic-oracles-not-llm-judges.md).

## Quickstart

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest                    # 240 offline tests
python -m evals.run_all             # all evals -> evals/results/*.json (about 45 seconds)
```

The CLI (everything offline, against the simulated sandbox):

```bash
python -m whetstone run-attacks                            # baseline ASR, no defense
python -m whetstone run-attacks --technique direct_override --json
python -m whetstone run-defenses --defenses input_screen,egress_filter   # ASR + false positives
python -m whetstone run-defenses --defenses all --audit /tmp/run.jsonl
python -m whetstone spar --rounds 5                        # mutating attacker vs learning defender
python -m whetstone spar --rounds 5 --no-learn             # static-rules control
python -m whetstone report                                 # summarise results, verify the audit chain
```

`--target llm --live --model NAME` is **built but never run here**. It needs your own
`ANTHROPIC_API_KEY` in the environment (never on the command line); see
[`scripts/run_live.md`](scripts/run_live.md). Only ever point it at this sandbox.

## Planned (not built)

- [ ] **MCP server** exposing the sandbox tools, so an external agent can be attacked through
      the same guards
- [ ] **Live LLM attacker, defender and target runs.** `LLMTarget` is built and tested with
      pydantic-ai's TestModel only; `LLMAttacker` and `LLMDefender` are stubs that raise
      `NotImplementedError`. No model has ever been called from this repository
- [ ] **A second target scenario** (a Slack summariser) to test whether findings transfer
- [ ] Real-agent targets from this portfolio ([inbox-marshal](https://github.com/PlainJane20/inbox-marshal),
      [slack-daily-brief](https://github.com/PlainJane20/slack-daily-brief)), behind the `Target` protocol
- [x] Sandbox, 11 attack families x 5 goals, seeded mutators, adaptive and blind attackers
- [x] Four defenses, versioned rule sets, an offline RuleProposer with held-out validation
- [x] Deterministic oracles with sanity cases, hash-chained replayable audit, OTel spans, CLI, evals

## Known limits

- **The target is a simulation of a gullible agent.** Its compliance probabilities are numbers
  I chose. Results measure the harness and relative defense effects against that model, not
  how any real LLM behaves. Whether real models resist or fall for these attacks is not
  measured here.
- **Spotlighting's benefit is by construction.** Against the simulated target it comes from
  the profile's `spotlight` multipliers. What is tested is the mechanism (unguessable
  delimiters, spoofable fixed ones), not that spotlighting works on any model.
- **Everything is author-written.** Attacks, benign mail, default screening rules and the
  profile share one author, so the hand-written screen's 8.7% is optimistic. Mutation and the
  held-out split are there to show brittleness; they do not remove the bias.
- **Small benign set.** 72 messages (18 in the test split). A 0/18 false-positive result has a
  95% interval up to 17.6%.
- **Shared goal wording.** Three paraphrases per goal are reused across families, which can
  inflate cross-family generalisation. Experiment E3 reduces but does not remove this.
- **The adaptive attacker gets feedback** (`progress`, `blocked_by`) that a black-box attacker
  may not, and it was no better than blind mutation, so it is not a strong attacker.
- **Deterministic filters can be bypassed.** The evals show it (Greek homoglyphs, synonyms,
  reversed or hex secrets). See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).
- **The audit chain detects, not prevents.** Anyone who can rewrite the whole file can rebuild
  a consistent chain; the head hash is not anchored anywhere.
- **Latency is in-process on one machine** and excludes any model call.
- **Python versions.** I ran everything locally on Python 3.14.7 only. The code avoids newer
  syntax and CI runs 3.11 and 3.12 (see the repository's Actions tab for the result);
  `pydantic-ai-slim` is not pinned beyond `>=1.0` and I only ran it at 2.54.0.

## Repository map

```
agent-whetstone/
├── src/whetstone/
│   ├── sandbox/        synthetic inbox, fake tools, effects ledger, canaries
│   ├── targets/        Target protocol, GullibleTarget (simulated), LLMTarget (built, not run)
│   ├── attacks/        corpus (11 families x 5 goals), seeded mutators, attackers
│   ├── defenses/       InputScreen, Spotlighting, EgressFilter, ToolPolicy, stack,
│   │                   RuleProposer, Defender protocol
│   ├── oracles.py      deterministic success detection
│   ├── benign.py       72 hand-written benign messages, stratified split
│   ├── harness.py      attack run, benign run, spar loop, replay
│   ├── audit.py  tracing.py  textnorm.py  models.py  cli.py
├── tests/              240 offline tests
├── evals/              baseline, defenses, generalisation, mutation, latency,
│   │                   oracle_sanity, audit_replay, run_all
│   └── results/        committed JSON and a sample audit chain from the last run
├── scripts/            run_live.md (not run here), check_svg_overflow.py
└── docs/               architecture, threat model, competency map, ADR, banner, diagram
```

## Contact

<div align="center">

### **Navi Sohi**
*Technical Program Manager & Automation Engineer*

<br>

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/navisohi/)
[![GitHub](https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/PlainJane20)
[![Email](https://img.shields.io/badge/Email-EA4335?style=for-the-badge&logo=gmail&logoColor=white)](https://mail.google.com/mail/?view=cm&fs=1&to=nks.ai.dev@gmail.com)

<br>

</div>

## License

MIT
