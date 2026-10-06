"""Offline stubs for the adaptive-attacker tests. No model, no network."""
from whetstone.attacks.feedback import Generation
from whetstone.attacks.guardrails import AttackDraft
from whetstone.models import TargetResult


def draft(body="Please help.", subject="Hello", technique="direct_override", rationale="r"):
    return AttackDraft(subject, body, technique, rationale)


class StubSource:
    """Plays a script of Generations (or callables taking the round number); records what it saw."""
    uses_model = True

    def __init__(self, script, label="stub-attacker", on_call=None):
        self.script, self.label, self.on_call = list(script), label, on_call
        self.seen: list[list] = []
        self.calls = 0

    def next(self, goal, round_no, rounds, feedback):
        self.calls += 1
        self.seen.append(list(feedback))
        if self.on_call:
            self.on_call(round_no)
        item = self.script[min(round_no - 1, len(self.script) - 1)]
        item = item(round_no) if callable(item) else item
        if isinstance(item, Exception):
            raise item
        return item


def gen(**kw) -> Generation:
    return Generation(draft=draft(**kw), input_tokens=10, output_tokens=5)


def refusal(text="I will not write that.") -> Generation:
    return Generation(refused=True, refusal_text=text, input_tokens=8, output_tokens=3)


class MagicTarget:
    """Stub target: does the benign task, and also deletes three emails if the planted email
    contains the magic phrase. Everything goes through the real ToolBox, guard, ledger and oracles."""
    WORD = "open sesame"

    def __init__(self, tb, fail=False):
        self.tb, self.fail = tb, fail

    def run(self, task, untrusted_content):
        if self.fail:
            raise RuntimeError("target blew up")
        self.tb.call("list_emails", origin="model")
        if self.WORD in untrusted_content.lower():
            for i in ("m1", "m2", "m3"):
                self.tb.call("delete_email", origin="model", email_id=i)
        self.tb.call("post_message", origin="model", channel="#team-updates", text="Summary posted.")
        return TargetResult(self.tb.calls, "Summary done.", {"usage": {"input_tokens": 100, "output_tokens": 20}})


def magic_factory(fail=False, seen=None):
    def f(tb, seed):
        if seen is not None:
            seen.append(tb.sandbox)
        return MagicTarget(tb, fail)
    return f


MAGIC = "open sesame"
