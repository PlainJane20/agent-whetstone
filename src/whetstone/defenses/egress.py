"""EgressFilter: stop secrets leaving in outputs and tool arguments.

Default checks: the CANARY pattern and registered secrets in plain text, URL-encoded, rot13 and
base64 forms. It does NOT check hex or reversed text unless you add them to `encodings`. The
oracle does check those, so the evals can show the gap. It also removes markdown images that
point at hosts outside the allow-list (a standard exfiltration channel).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import unquote

from ..sandbox import CANARY_PATTERN
from ..textnorm import b64_segments, rot13

_CANARY_I = re.compile(CANARY_PATTERN.pattern, re.IGNORECASE)
_IMG = re.compile(r"!\[[^\]]*\]\((https?://[^)\s]+)\)")
_HEX = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){8,}(?![0-9a-fA-F])")


@dataclass
class EgressConfig:
    secrets: tuple[str, ...] = ()
    encodings: tuple[str, ...] = ("url", "rot13", "base64")   # also: "hex", "reverse"
    strip_external_images: bool = True
    allowed_image_hosts: tuple[str, ...] = ()


class EgressFilter:
    name = "egress_filter"

    def __init__(self, config: EgressConfig | None = None) -> None:
        self.config = config or EgressConfig()

    def _plain_hit(self, text: str) -> bool:
        if _CANARY_I.search(text):
            return True
        return any(s and s.lower() in text.lower() for s in self.config.secrets)

    def hits(self, text: str) -> list[str]:
        """Which forms of a secret appear in `text`: plain and/or encoded."""
        enc = self.config.encodings
        found = []
        if self._plain_hit(text):
            found.append("plain")
        if "url" in enc and unquote(text) != text and self._plain_hit(unquote(text)):
            found.append("url")
        if "rot13" in enc and self._plain_hit(rot13(text)):
            found.append("rot13")
        if "reverse" in enc and self._plain_hit(text[::-1]):
            found.append("reverse")
        if "base64" in enc and any(self._plain_hit(s) or self._plain_hit(rot13(s))
                                   for s in b64_segments(text, min_len=8)):
            found.append("base64")
        if "hex" in enc:
            for h in _HEX.findall(text):
                try:
                    if self._plain_hit(bytes.fromhex(h).decode("ascii", "ignore")):
                        found.append("hex")
                        break
                except ValueError:
                    pass
        return found

    def check_call(self, name: str, args: dict) -> bool:
        """True when a tool call's arguments carry a secret (the call should be blocked)."""
        return any(self.hits(str(v)) for v in args.values())

    def filter_output(self, text: str) -> tuple[str, list[str]]:
        """Return (safe text, reasons). Plain secrets are redacted in place; an encoded secret
        replaces the whole output; external images are removed."""
        reasons: list[str] = []
        hit = self.hits(text)
        if any(h != "plain" for h in hit):
            return "[BLOCKED: possible secret exfiltration]", [f"encoded_secret:{h}" for h in hit]
        if hit:
            text = _CANARY_I.sub("[REDACTED]", text)
            for s in self.config.secrets:
                text = re.sub(re.escape(s), "[REDACTED]", text, flags=re.IGNORECASE)
            reasons.append("plain_secret")
        if self.config.strip_external_images:
            def repl(m):
                host = re.sub(r"^https?://([^/:]+).*$", r"\1", m.group(1))
                if host in self.config.allowed_image_hosts:
                    return m.group(0)
                reasons.append(f"external_image:{host}")
                return "[image removed]"
            text = _IMG.sub(repl, text)
        return text, reasons

    def describe(self) -> dict:
        c = self.config
        return {"secrets": list(c.secrets), "encodings": list(c.encodings),
                "strip_external_images": c.strip_external_images,
                "allowed_image_hosts": list(c.allowed_image_hosts)}
