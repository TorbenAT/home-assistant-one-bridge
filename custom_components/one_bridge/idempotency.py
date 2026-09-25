"""Exact replay protection for consequential One Bridge apply calls.

This is the single, tested IdempotencyStore implementation shared by the
private integration and the public HACS artifact. scripts/build-release.sh
ships this file verbatim into the artifact via copytree rather than
synthesizing a separate (stale) copy that could reintroduce in-flight
eviction.
"""
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

    async def begin(
        self, key: str, fingerprint: str
    ) -> tuple[bool, dict[str, Any] | None]:
        async with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                # In-flight mutations must never be evicted: dropping one
                # would let a retry execute the same mutation twice. Evict
                # only completed FIFO entries; fail safely under full
                # in-flight pressure instead.
                if len(self._entries) >= self.maximum:
                    evictable = [
                        existing_key
                        for existing_key, existing in self._entries.items()
                        if not existing["in_flight"]
                    ]
                    if not evictable:
                        raise SuiteBridgeError(
                            "IDEMPOTENCY_BUSY",
                            "For mange samtidige apply-kald; prøv igen senere.",
                            503,
                        )
                    self._entries.pop(evictable[0], None)
                self._entries[key] = {
                    "fingerprint": fingerprint,
                    "in_flight": True,
                    "result": None,
                }
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

    async def finish(
        self, key: str, fingerprint: str, result: dict[str, Any]
    ) -> None:
        async with self._lock:
            entry = self._entries.get(key)
            if entry is None or entry["fingerprint"] != fingerprint:
                return
            entry["in_flight"] = False
            entry["result"] = deepcopy(result)

    async def abort(self, key: str, fingerprint: str) -> None:
        async with self._lock:
            entry = self._entries.get(key)
            if (
                entry is not None
                and entry["fingerprint"] == fingerprint
                and entry["in_flight"]
            ):
                self._entries.pop(key, None)
