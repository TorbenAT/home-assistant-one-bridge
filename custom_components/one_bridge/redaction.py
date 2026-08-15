"""Central secret redaction for API errors, audit records and test output."""

from __future__ import annotations

import re
from typing import Any

from .const import SENSITIVE_KEY_FRAGMENTS

_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(
        r"(?i)\b(access_token|api_key|client_secret|password|refresh_token|"
        r"supervisor_token|token)\b(\s*[:=]\s*)([^\s,;]+)"
    ),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"(?i)(https?://[^:/\s]+:)[^@\s]+(@)"),
    re.compile(
        r"(?im)^([ +-]?\s*[A-Za-z0-9_-]*(?:password|secret|token|api[_-]?key|encryption[_-]?key)[A-Za-z0-9_-]*\s*:\s*)([^\r\n#]+)"
    ),
)


def redact_text(value: str) -> str:
    """Remove common inline secret forms from untrusted text."""
    result = value
    result = _SECRET_PATTERNS[0].sub(r"\1 <redacted>", result)
    result = _SECRET_PATTERNS[1].sub(r"\1\2<redacted>", result)
    result = _SECRET_PATTERNS[2].sub("<redacted>", result)
    result = _SECRET_PATTERNS[3].sub(r"\1<redacted>\2", result)
    result = _SECRET_PATTERNS[4].sub(r"\1<redacted>", result)
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
        return [redact(item, depth=depth + 1) for item in list(value)[:250]]
    if isinstance(value, str):
        text = redact_text(value)
        return text[:4_000] + "…" if len(text) > 4_000 else text
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_text(str(value))
