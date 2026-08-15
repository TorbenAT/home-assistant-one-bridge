"""Short-lived, one-time prepared mutations."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import time
from typing import Any

from .const import PREPARE_TTL_SECONDS
from .models import PreparedMutation, SuiteBridgeError, digest_json, new_id


class PreparedMutationStore:
    def __init__(
        self,
        *,
        ttl_seconds: int = PREPARE_TTL_SECONDS,
        clock: Any = time.monotonic,
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self._clock = clock
        self._items: dict[str, PreparedMutation] = {}
        self._lock = asyncio.Lock()

    async def create(
        self,
        *,
        user_id: str,
        refresh_token_id: str,
        operation: str,
        normalized_change: dict[str, Any],
        material: dict[str, Any],
        risk: str,
        confirmation_phrase: str | None = None,
    ) -> PreparedMutation:
        now = self._clock()
        expires_at = (
            datetime.now(timezone.utc) + timedelta(seconds=self.ttl_seconds)
        ).isoformat().replace("+00:00", "Z")
        prepare_id = new_id("mut")
        digest = digest_json(
            {
                "prepare_id": prepare_id,
                "user_id": user_id,
                "refresh_token_id": refresh_token_id,
                "operation": operation,
                "normalized_change": normalized_change,
                "risk": risk,
                "confirmation_phrase": confirmation_phrase,
                "expires_at": expires_at,
            }
        )
        item = PreparedMutation(
            prepare_id=prepare_id,
            user_id=user_id,
            refresh_token_id=refresh_token_id,
            operation=operation,
            created_monotonic=now,
            expires_monotonic=now + self.ttl_seconds,
            expires_at=expires_at,
            digest=digest,
            normalized_change=normalized_change,
            material=material,
            risk=risk,
            confirmation_phrase=confirmation_phrase,
            lock=asyncio.Lock(),
        )
        async with self._lock:
            self._prune_locked(now)
            self._items[prepare_id] = item
        return item

    async def begin_apply(
        self,
        *,
        prepare_id: str,
        digest: str,
        user_id: str,
        refresh_token_id: str,
        confirmed: bool,
        confirmation_text: str | None,
    ) -> PreparedMutation:
        if confirmed is not True:
            raise SuiteBridgeError(
                "CONFIRMATION_REQUIRED",
                "Mutationen kræver confirmed=true efter brugerens godkendelse.",
                409,
            )
        async with self._lock:
            now = self._clock()
            item = self._items.get(prepare_id)
            if item is not None and now >= item.expires_monotonic:
                self._items.pop(prepare_id, None)
                raise SuiteBridgeError(
                    "PREPARE_EXPIRED", "Prepared mutation er udløbet.", 409
                )
            self._prune_locked(now)
            item = self._items.get(prepare_id)
        if item is None:
            raise SuiteBridgeError(
                "PREPARE_NOT_FOUND",
                "Prepared mutation findes ikke eller er udløbet.",
                409,
            )
        async with item.lock:
            if item.consumed:
                raise SuiteBridgeError(
                    "PREPARE_ALREADY_USED", "Prepared mutation er allerede anvendt.", 409
                )
            if item.in_flight:
                raise SuiteBridgeError(
                    "PREPARE_IN_PROGRESS", "Prepared mutation udføres allerede.", 409
                )
            if self._clock() >= item.expires_monotonic:
                raise SuiteBridgeError("PREPARE_EXPIRED", "Prepared mutation er udløbet.", 409)
            if item.user_id != user_id or item.refresh_token_id != refresh_token_id:
                raise SuiteBridgeError(
                    "PREPARE_SESSION_MISMATCH",
                    "Prepared mutation tilhører en anden OAuth-session.",
                    403,
                )
            if item.digest != digest:
                raise SuiteBridgeError(
                    "PREPARE_DIGEST_MISMATCH",
                    "request_digest matcher ikke prepared mutation.",
                    409,
                )
            if item.confirmation_phrase is not None and (
                confirmation_text != item.confirmation_phrase
            ):
                raise SuiteBridgeError(
                    "EXACT_CONFIRMATION_REQUIRED",
                    f"Kræver præcis bekræftelsestekst: {item.confirmation_phrase}",
                    409,
                )
            item.in_flight = True
            return item

    async def finish(self, prepare_id: str, *, consume: bool) -> None:
        async with self._lock:
            item = self._items.get(prepare_id)
        if item is None:
            return
        async with item.lock:
            item.in_flight = False
            if consume:
                item.consumed = True

    async def status(
        self,
        *,
        prepare_id: str,
        user_id: str,
        refresh_token_id: str,
    ) -> dict[str, Any]:
        async with self._lock:
            now = self._clock()
            item = self._items.get(prepare_id)
            if item is not None and now >= item.expires_monotonic:
                self._items.pop(prepare_id, None)
                return {"found": False, "state": "expired", "prepare_id": prepare_id}
            self._prune_locked(now)
            item = self._items.get(prepare_id)
        if item is None:
            return {"found": False, "state": "not_found", "prepare_id": prepare_id}
        async with item.lock:
            if item.user_id != user_id or item.refresh_token_id != refresh_token_id:
                raise SuiteBridgeError(
                    "PREPARE_SESSION_MISMATCH",
                    "Prepared mutation tilhører en anden OAuth-session.",
                    403,
                )
            state = "consumed" if item.consumed else ("in_progress" if item.in_flight else "prepared")
            return {
                "found": True,
                "state": state,
                "prepare_id": item.prepare_id,
                "operation": item.operation,
                "risk": item.risk,
                "expires_at": item.expires_at,
            }

    def _prune_locked(self, now: float) -> None:
        stale = [
            key
            for key, item in self._items.items()
            if item.expires_monotonic <= now
            or (item.consumed and now - item.created_monotonic > self.ttl_seconds)
        ]
        for key in stale:
            self._items.pop(key, None)
