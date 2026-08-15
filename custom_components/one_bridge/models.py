"""Shared models and deterministic helpers for One Bridge v2."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Mapping
import uuid


class SuiteBridgeError(Exception):
    """A controlled API error."""

    def __init__(
        self,
        code: str,
        message: str,
        status: int = 400,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.details = details or {}


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def json_safe(value: Any, *, depth: int = 0) -> Any:
    if depth > 12:
        return "<max-depth>"
    if value is None or isinstance(value, (bool, int, float, str)):
        if isinstance(value, str) and len(value) > 20_000:
            return value[:20_000] + "…"
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 1_000:
                result["<truncated>"] = True
                break
            result[str(key)] = json_safe(item, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple, set, frozenset)):
        return [json_safe(item, depth=depth + 1) for item in list(value)[:2_000]]
    if hasattr(value, "dict_repr"):
        return json_safe(value.dict_repr, depth=depth + 1)
    return str(value)


def canonical_json(value: Any) -> str:
    return json.dumps(
        json_safe(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def pretty_json(value: Any) -> str:
    return json.dumps(json_safe(value), ensure_ascii=False, indent=2, sort_keys=True)


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(slots=True)
class PreparedMutation:
    prepare_id: str
    user_id: str
    refresh_token_id: str
    operation: str
    created_monotonic: float
    expires_monotonic: float
    expires_at: str
    digest: str
    normalized_change: dict[str, Any]
    material: dict[str, Any]
    risk: str
    confirmation_phrase: str | None = None
    consumed: bool = False
    in_flight: bool = False
    lock: Any = field(default=None, repr=False)
