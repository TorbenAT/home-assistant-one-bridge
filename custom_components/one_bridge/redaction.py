"""Central secret redaction for API errors, audit records and test output."""

from __future__ import annotations

import re
from typing import Any

from .const import SENSITIVE_KEY_FRAGMENTS

_SECRET_PATTERNS = (
    # Block-shaped secrets first so line-oriented patterns cannot mangle them.
    re.compile(
        r"(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
        r"(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)"
    ),
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(
        r"(?i)\b(access_token|api_key|client_secret|password|refresh_token|"
        r"supervisor_token|token)\b(\s*[:=]\s*)([^\s,;]+)"
    ),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bA[KS]IA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)(https?://[^:/\s]+:)[^@\s]+(@)"),
    re.compile(
        r"(?im)^([ +-]?\s*[A-Za-z0-9_-]*(?:password|secret|token|api[_-]?key|encryption[_-]?key)[A-Za-z0-9_-]*\s*:\s*)([^\r\n#]+)"
    ),
)

_REDACT_SUBSTITUTIONS = (
    ("<redacted-private-key>", 0),
    (r"\1 <redacted>", 1),
    (r"\1\2<redacted>", 2),
    ("<redacted>", 3),
    ("<redacted>", 4),
    ("<redacted>", 5),
    (r"\1<redacted>\2", 6),
    (r"\1<redacted>", 7),
)


def redact_text(value: str) -> str:
    """Remove common inline secret forms from untrusted text."""
    result = value
    for replacement, index in _REDACT_SUBSTITUTIONS:
        result = _SECRET_PATTERNS[index].sub(replacement, result)
    return result


def redact(value: Any, *, key_name: str = "", depth: int = 0) -> Any:
    """Recursively redact secret-bearing keys and inline string values."""
    if any(fragment in key_name.casefold() for fragment in SENSITIVE_KEY_FRAGMENTS):
        return "<redacted>"
    if depth > 8:
        return "<max-depth>"
    if isinstance(value, dict):
        return {
            str(key): redact(item, key_name=str(key), depth=depth + 1)
            for key, item in list(value.items())[:250]
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
        result = [redact(item, depth=depth + 1) for item in items[:250]]
        # Mark dropped elements so a trimmed list cannot read as complete.
        if len(items) > 250:
            result.append("<truncated>")
        return result
    if isinstance(value, str):
        text = redact_text(value)
        return text[:4_000] + "…" if len(text) > 4_000 else text
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_text(str(value))
