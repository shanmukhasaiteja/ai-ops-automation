"""Webhook authentication and PII / secret redaction.

Alert text is attacker-influenced and frequently contains things that must never
reach a third-party LLM or a database: emails, passwords, API keys, card numbers.
"""
from __future__ import annotations

import hashlib
import hmac
import re


def sign(secret: bytes, body: bytes) -> str:
    return "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()


def verify_signature(secret: bytes, body: bytes, header: str | None) -> bool:
    """Constant-time check of an 'sha256=<hex>' HMAC header."""
    if not header or not header.startswith("sha256="):
        return False
    return hmac.compare_digest(sign(secret, body), header)


def _luhn_ok(digits: str) -> bool:
    total, flip = 0, False
    for ch in reversed(digits):
        n = int(ch)
        if flip:
            n = n * 2 - 9 if n * 2 > 9 else n * 2
        total += n
        flip = not flip
    return total % 10 == 0


_CARD = re.compile(r"\b(?:\d[ -]?){13,16}\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SIMPLE = (
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), "[EMAIL]"),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[AWS_KEY]"),
    ("token", re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}"
        r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"), "[TOKEN]"),
    ("secret", re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token)\s*[=:]\s*\S+"), r"\1=[REDACTED]"),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]"),
)


def redact(text: str, ips: bool = False) -> tuple[str, list[str]]:
    """Return the text with sensitive values masked, and which kinds were found."""
    found: set[str] = set()
    for kind, pattern, replacement in _SIMPLE:
        text, n = pattern.subn(replacement, text)
        if n:
            found.add(kind)

    def mask_card(match: re.Match) -> str:
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 16 and _luhn_ok(digits):
            found.add("card")
            return "[CARD]"
        return match.group(0)

    text = _CARD.sub(mask_card, text)
    if ips:
        text, n = _IPV4.subn("[IP]", text)
        if n:
            found.add("ip")
    return text, sorted(found)
