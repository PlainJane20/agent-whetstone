"""Text normalisation and decoding helpers shared by the screen, the target and the oracles.

Two homoglyph tables exist on purpose. The InputScreen folds a SMALL table
(common Cyrillic lookalikes). The simulated gullible target reads through a
BIGGER one, the way a language model reads through most lookalike text. The gap
is a real, measurable weakness of deterministic screens, not an accident.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata

_INVISIBLE = dict.fromkeys(map(ord, "​‌‍‎‏⁠⁢⁣﻿­"), None)

HOMOGLYPHS_BASIC = {  # Cyrillic lookalikes only
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
}
HOMOGLYPHS_EXTENDED = {
    **HOMOGLYPHS_BASIC,
    "ο": "o", "ε": "e", "ι": "i", "ν": "v", "κ": "k", "ρ": "p", "α": "a", "τ": "t", "υ": "u",
    "ѕ": "s", "ј": "j", "ԁ": "d", "һ": "h", "ӏ": "l", "ꓲ": "l",
}
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a",
                       "$": "s", "!": "i"})
_B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])")
_WS = re.compile(r"\s+")


def strip_invisible(s: str) -> str:
    return s.translate(_INVISIBLE)


def fold(s: str, *, extended: bool = False) -> str:
    """NFKC, drop zero-width characters, fold lookalikes, lowercase, collapse whitespace."""
    s = unicodedata.normalize("NFKC", s)
    s = strip_invisible(s)
    table = HOMOGLYPHS_EXTENDED if extended else HOMOGLYPHS_BASIC
    s = "".join(table.get(ch, ch) for ch in s)
    return _WS.sub(" ", s.casefold()).strip()


def deleet(s: str) -> str:
    """Undo leetspeak word by word, leaving addresses and channel names (tokens with @ or #) alone."""
    return " ".join(w if ("@" in w or "#" in w) else w.translate(_LEET) for w in s.split(" "))


def rot13(s: str) -> str:
    return codecs.encode(s, "rot_13")


def b64_encode(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(1 for c in b if c in (9, 10, 13) or 32 <= c < 127) / len(b)


def b64_segments(s: str, min_len: int = 16) -> list[str]:
    """Decode every base64-looking token that decodes to mostly printable ASCII."""
    out = []
    for m in _B64.finditer(s):
        tok = m.group(0)
        if len(tok) < min_len:
            continue
        try:
            raw = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        if _printable_ratio(raw) >= 0.9:
            out.append(raw.decode("ascii", "ignore"))
    return out


def views(s: str, *, decode: bool = True, depth: int = 2) -> list[tuple[str, str]]:
    """Named views of `s` for rule scanning: folded, de-leeted, rot13, base64-decoded."""
    base = fold(s)
    out = [("plain", base), ("deleet", fold(deleet(base)))]
    if decode:
        out.append(("rot13", fold(rot13(s))))
        frontier = [s]
        for d in range(depth):
            nxt = []
            for text in frontier:
                for seg in b64_segments(text):
                    out.append((f"base64@{d + 1}", fold(seg)))
                    out.append((f"base64+rot13@{d + 1}", fold(rot13(seg))))
                    nxt.append(seg)
            frontier = nxt
    return out
