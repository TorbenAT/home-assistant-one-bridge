"""Hash-chained, bounded audit log for One Bridge v2."""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from homeassistant.components import persistent_notification
from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .const import AUDIT_MAX_ENTRIES, AUDIT_STORE_KEY, AUDIT_STORE_VERSION
from .models import canonical_json, new_id, utc_now_iso
from .redaction import redact

_LOGGER = logging.getLogger(__name__)

class AuditLog:
    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass
        self._store: Store[dict[str, Any]] = Store(
            hass, AUDIT_STORE_VERSION, AUDIT_STORE_KEY
        )
        self._entries: list[dict[str, Any]] = []
        self._last_hash = "0" * 64

    async def async_load(self) -> None:
        data = await self._store.async_load()
        if isinstance(data, dict) and isinstance(data.get("entries"), list):
            self._entries = data["entries"][-AUDIT_MAX_ENTRIES:]
            if self._entries:
                self._last_hash = str(
                    self._entries[-1].get("audit_hash", self._last_hash)
                )

    async def append(self, entry: dict[str, Any]) -> dict[str, Any]:
        item = {
            "audit_id": new_id("audit2"),
            "timestamp": utc_now_iso(),
            **redact(entry),
            "previous_hash": self._last_hash,
        }
        item["audit_hash"] = hashlib.sha256(
            canonical_json(item).encode("utf-8")
        ).hexdigest()
        self._last_hash = item["audit_hash"]
        self._entries.append(item)
        self._entries = self._entries[-AUDIT_MAX_ENTRIES:]
        try:
            await self._store.async_save({"entries": self._entries})
        except Exception:
            _LOGGER.exception("Kunne ikke gemme One Bridge auditloggen")
        self.hass.bus.async_fire("one_bridge_audit", item)
        if item.get("result") == "executed":
            persistent_notification.async_create(
                self.hass,
                (
                    f"Operation: {item.get('operation', 'ukendt')}\n"
                    f"Tid: {item.get('timestamp')}\n"
                    f"Audit-id: {item.get('audit_id')}\n"
                    f"Resultat: executed"
                ),
                title="One Bridge ændring",
                notification_id="gpt_suite_bridge_last_change",
            )
        return item

    def find_latest(
        self,
        *,
        prepare_id: str = "",
        request_id: str = "",
        idempotency_key: str = "",
    ) -> dict[str, Any] | None:
        selectors = {
            "prepare_id": prepare_id.strip(),
            "request_id": request_id.strip(),
            "idempotency_key": idempotency_key.strip(),
        }
        for item in reversed(self._entries):
            if all(
                not value or str(item.get(key, "")) == value
                for key, value in selectors.items()
            ):
                return dict(item)
        return None

    def summary(self, limit: int = 20) -> dict[str, Any]:
        limit = min(max(int(limit), 1), 100)
        return {
            "count": len(self._entries),
            "last_hash": self._last_hash,
            "entries": self._entries[-limit:],
        }
