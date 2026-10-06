"""Hash-chained append-only audit log of every attack attempt (adapted from blast-door).

Each record stores the SHA-256 of the previous record, so editing, deleting or reordering a
record breaks verification at that point. It is a JSONL file (or in memory when no path is
given). Every `attack_attempt` record carries the full attack, the defense configuration, the
seeds and the outcome, so a run can be replayed and compared (see harness.replay).

This detects tampering; it does not prevent it. Whoever can rewrite the whole file can
rebuild a consistent chain. Anchoring the head hash elsewhere is not built.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

GENESIS = "0" * 64


def _digest(prev: str, body: dict) -> str:
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev + payload).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self._records: list[dict] = []
        if self.path and self.path.exists():
            self._records = [json.loads(line) for line in self.path.read_text().splitlines() if line]

    def append(self, event: str, data: dict) -> dict:
        prev = self._records[-1]["hash"] if self._records else GENESIS
        body = {"seq": len(self._records), "event": event, "data": json.loads(json.dumps(data, default=str))}
        rec = {**body, "prev": prev, "hash": _digest(prev, body)}
        self._records.append(rec)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a") as f:
                f.write(json.dumps(rec, sort_keys=True) + "\n")
        return rec

    def records(self) -> list[dict]:
        return list(self._records)

    def head(self) -> str:
        return self._records[-1]["hash"] if self._records else GENESIS

    def verify(self) -> tuple[bool, int | None]:
        """Return (ok, index of first bad record)."""
        return verify_records(self._records)


def verify_records(records: list[dict]) -> tuple[bool, int | None]:
    prev = GENESIS
    for i, rec in enumerate(records):
        body = {k: rec[k] for k in ("seq", "event", "data")}
        if rec.get("seq") != i or rec.get("prev") != prev or rec.get("hash") != _digest(prev, body):
            return False, i
        prev = rec["hash"]
    return True, None


def load_and_verify(path: str | Path) -> tuple[bool, int | None, int]:
    recs = [json.loads(line) for line in Path(path).read_text().splitlines() if line]
    ok, bad = verify_records(recs)
    return ok, bad, len(recs)
