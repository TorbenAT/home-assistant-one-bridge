"""Exact replay protection for consequential One Bridge apply calls."""
from __future__ import annotations

import asyncio
from copy import deepcopy
from typing import Any

from .models import SuiteBridgeError


class IdempotencyStore:
    """Bounded in-memory exact replay cache for consequential apply calls."""

    def __init__(self, maximum: int = 1000) -> None:
        self.maximum = maximum
        self._entries: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    async def begin(self, key: str, fingerprint: str) -> tuple[bool, dict[str, Any] | None]:
        async with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self._entries[key] = {"fingerprint": fingerprint, "in_flight": True, "result": None}
                while len(self._entries) > self.maximum:
                    self._entries.pop(next(iter(self._entries)))
                return True, None
            if entry["fingerprint"] != fingerprint:
                raise SuiteBridgeError(
                    "IDEMPOTENCY_KEY_REUSED",
                    "idempotency_key er allerede brugt til et andet apply-kald.",
                    409,
                )
            if entry["in_flight"]:
                raise SuiteBridgeError(
                    "IDEMPOTENCY_IN_PROGRESS",
                    "Et apply-kald med denne idempotency_key udføres allerede.",
                    409,
                )
            return False, deepcopy(entry["result"])

    async def finish(self, key: str, fingerprint: str, result: dict[str, Any]) -> None:
        async with self._lock:
            entry = self._entries.get(key)
            if entry is None or entry["fingerprint"] != fingerprint:
                return
            entry["in_flight"] = False
            entry["result"] = deepcopy(result)

    async def abort(self, key: str, fingerprint: str) -> None:
        async with self._lock:
            entry = self._entries.get(key)
            if entry is not None and entry["fingerprint"] == fingerprint and entry["in_flight"]:
                self._entries.pop(key, None)
