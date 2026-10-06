import pytest

from whetstone.models import Email
from whetstone.sandbox import CANARY_PATTERN, EffectsLedger, Sandbox, make_canaries


def test_canaries_are_fake_and_unique():
    c = make_canaries(0)
    assert len(set(c.values())) == 3
    assert all(CANARY_PATTERN.fullmatch(v) for v in c.values())


def test_canaries_differ_by_seed_and_repeat_by_seed():
    assert make_canaries(1) != make_canaries(2)
    assert make_canaries(3) == make_canaries(3)


def test_inbox_is_benign_and_nonempty(sb):
    assert len(sb.emails) >= 8
    assert all(e.sender.endswith(".example") for e in sb.emails.values())


def test_notes_hold_canaries(sb):
    assert sb.call("read_note", name="vault-key").value.endswith(sb.canaries["vault-key"])


def test_list_and_read_email_marks_read(sb):
    assert "m1" in sb.call("list_emails").value
    sb.call("read_email", email_id="m1")
    assert "m1" not in {e.id for e in sb.unread_emails()}


def test_forward_post_move_delete_effects(sb):
    sb.call("forward_email", to="a@corp.example", email_id="m1")
    sb.call("post_message", channel="#team-updates", text="hi")
    sb.call("move_email", email_id="m2", folder="archive")
    sb.call("delete_email", email_id="m3")
    assert [e.tool for e in sb.ledger.entries()] == ["forward_email", "post_message", "move_email", "delete_email"]
    assert sb.folder["m2"] == "archive" and "m3" not in sb.emails and sb.deleted == ["m3"]


def test_every_call_is_ledgered_including_reads_and_failures(sb):
    sb.call("list_emails")
    sb.call("read_email", email_id="nope")
    sb.call("bogus_tool")
    e = sb.ledger.entries()
    assert len(e) == 3 and [x.ok for x in e] == [True, False, False]
    assert e[2].kind == "unknown"


def test_bad_arguments_are_a_failed_effect_not_a_crash(sb):
    r = sb.call("forward_email")
    assert not r.ok and sb.ledger.entries()[-1].ok is False


def test_ledger_is_append_only():
    led = EffectsLedger()
    led.append("post_message", "outbound", {"channel": "#x", "text": "t"}, True, "ok")
    assert not hasattr(led, "update") and not hasattr(led, "delete")
    snapshot = led.entries()
    assert isinstance(snapshot, tuple)
    with pytest.raises(Exception):
        snapshot[0].tool = "other"       # frozen


def test_ledger_sequence_numbers_are_dense(sb):
    for _ in range(4):
        sb.call("list_emails")
    assert [e.seq for e in sb.ledger.entries()] == [0, 1, 2, 3]


def test_ledger_where_filters_failed_by_default(sb):
    sb.call("delete_email", email_id="nope")
    sb.call("delete_email", email_id="m1")
    assert len(sb.ledger.where(tool="delete_email")) == 1
    assert len(sb.ledger.where(tool="delete_email", ok=None)) == 2


def test_extra_emails_are_planted_unread():
    sb = Sandbox(0, (Email("atk-1", "x@vendor-news.example", "s", "b"),))
    assert "atk-1" in {e.id for e in sb.unread_emails()}


def test_sandboxes_do_not_share_state():
    a, b = Sandbox(0), Sandbox(0)
    a.call("delete_email", email_id="m1")
    assert "m1" in b.emails
