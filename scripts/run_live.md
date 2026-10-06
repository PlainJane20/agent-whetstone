# Running the LLM target live (BUILT, NOT RUN)

**Status:** `LLMTarget` (`src/whetstone/targets/llm.py`) is a pydantic-ai Agent bound to the sandbox tools. It is unit-tested with pydantic-ai's `TestModel` and a `FunctionModel` stub only. **It has never been run against a live model in this repository, and no result in the README or in `evals/results/` comes from it.** The instructions below are untested.

**Scope:** defensive only. Point it at this project's own simulated sandbox, with synthetic data and fake canary secrets. Do not point it at a system you do not own.

## Prerequisites

```bash
pip install -e ".[llm]"            # pydantic-ai-slim[anthropic]
export ANTHROPIC_API_KEY=...       # your own key, environment only, never on a command line or in a file
```

The key is read from `ANTHROPIC_API_KEY` and nowhere else. The CLI refuses to run `--target llm` without `--live` and without the variable.

## CLI

```bash
python -m whetstone run-attacks --target llm --live --model <model-name> \
    --technique direct_override --trials 1
python -m whetstone run-defenses --target llm --live --model <model-name> --defenses all \
    --technique direct_override --trials 1 --audit /tmp/live.jsonl
```

`--model` is the model name as pydantic-ai expects it after the `anthropic:` prefix. Start with one family and one trial: each run makes real API calls and costs money.

## Python

```python
from whetstone.sandbox import Sandbox
from whetstone.targets import LLMTarget, ToolBox
from whetstone.defenses import build_stack

stack = build_stack(["all"])
tools = ToolBox(Sandbox(0), stack.guard)
target = LLMTarget.live(tools, "<model-name>")
```

## What to expect, and what to be careful about

- Results will differ from the simulated target, which is the point. The simulated profile is a guess.
- The oracles, guards, audit log and tracing all work the same way, because they sit outside the target.
- `attempted` is not available for a live model (the target cannot report which calls were "on instruction"); the harness falls back to "a guard blocked an injected call". `progress` is therefore less informative.
- Live runs are not deterministic. Record the model name, the date and the number of trials next to any result you publish, and do not mix them with the simulated numbers.
- Do not paste live transcripts that contain anything other than this sandbox's synthetic data.
