"""DLP-style redaction.

Before any keystroke buffer is committed to disk, we run it through a set of
regex detectors and replace matches with structured placeholders like
`[REDACTED:CREDIT_CARD]`. This keeps logs analytically useful (you can still
see WHERE a card number was typed and HOW LONG it was) without persisting the
secret itself.

Patterns covered:
    - Credit card numbers (Luhn-validated to suppress false positives)
    - US Social Security Numbers (XXX-XX-XXXX)
    - Indian PAN (5 letters + 4 digits + 1 letter)
    - Indian Aadhaar (12 digits with optional spaces)
    - Generic JWTs (xxx.yyy.zzz base64url)
    - AWS access keys (AKIA[0-9A-Z]{16})
    - Generic high-entropy 32+ char hex tokens
    - Email addresses (light redaction — domain preserved)

The list is intentionally conservative. Adding more patterns is the kind of
extension a security engineer would do in their first week.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# --- Patterns ---------------------------------------------------------------

_CC_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PAN_RE = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
_AADHAAR_RE = re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")
_AWS_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_HEX_TOKEN_RE = re.compile(r"\b[a-fA-F0-9]{32,}\b")
_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")


def _luhn_ok(s: str) -> bool:
    digits = [int(c) for c in s if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


@dataclass
class RedactionReport:
    text: str
    counts: dict[str, int]

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def redact(text: str) -> RedactionReport:
    counts: dict[str, int] = {}

    def _sub(pattern: re.Pattern, label: str, s: str, *, validator=None) -> str:
        def repl(m: re.Match) -> str:
            if validator and not validator(m.group(0)):
                return m.group(0)
            counts[label] = counts.get(label, 0) + 1
            return f"[REDACTED:{label}]"
        return pattern.sub(repl, s)

    s = text
    s = _sub(_CC_RE, "CREDIT_CARD", s, validator=_luhn_ok)
    s = _sub(_SSN_RE, "SSN", s)
    s = _sub(_PAN_RE, "PAN_IN", s)
    s = _sub(_AADHAAR_RE, "AADHAAR_IN", s)
    s = _sub(_JWT_RE, "JWT", s)
    s = _sub(_AWS_RE, "AWS_ACCESS_KEY", s)
    s = _sub(_HEX_TOKEN_RE, "HEX_TOKEN", s)
    # Emails: preserve domain for triage utility
    def _email_repl(m: re.Match) -> str:
        counts["EMAIL"] = counts.get("EMAIL", 0) + 1
        return f"[REDACTED:EMAIL@{m.group(2)}]"
    s = _EMAIL_RE.sub(_email_repl, s)

    return RedactionReport(text=s, counts=counts)
