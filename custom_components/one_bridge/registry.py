"""Safe registry discovery and bounded metadata updates."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers import (
    area_registry as ar,
    device_registry as dr,
    entity_registry as er,
    floor_registry as fr,
    label_registry as lr,
)

from .audit import AuditLog
from .backup import BackupManager
from .config import BridgeConfig
from .models import SuiteBridgeError, digest_json, json_safe, pretty_json
from .prepared import PreparedMutationStore


def _entry_dict(entry: Any) -> dict[str, Any]:
    for attr in ("extended_dict", "dict_repr"):
        value = getattr(entry, attr, None)
        if isinstance(value, dict):
            return json_safe(value)
    if hasattr(entry, "as_dict"):
        value = entry.as_dict()
        if isinstance(value, dict):
            return json_safe(value)
    return json_safe(vars(entry)) if hasattr(entry, "__dict__") else {"value": str(entry)}


class RegistryManager:
    ENTITY_UPDATE_FIELDS = frozenset({"name", "icon", "area_id", "labels"})
    DEVICE_UPDATE_FIELDS = frozenset({"name_by_user", "area_id", "labels"})

    def __init__(
        self,
        hass: HomeAssistant,
        config: BridgeConfig,
        prepared: PreparedMutationStore,
        backups: BackupManager,
        audit: AuditLog,
    ) -> None:
        self.hass = hass
        self.config = config
        self.prepared = prepared
        self.backups = backups
        self.audit = audit

    def _snapshot(self) -> dict[str, list[dict[str, Any]]]:
        entity_registry = er.async_get(self.hass)
        device_registry = dr.async_get(self.hass)
        area_registry = ar.async_get(self.hass)
        floor_registry = fr.async_get(self.hass)
        label_registry = lr.async_get(self.hass)
        config_entries = []
        for entry in self.hass.config_entries.async_entries():
            config_entries.append(
                {
                    "entry_id": entry.entry_id,
                    "domain": entry.domain,
                    "title": entry.title,
                    "state": str(entry.state),
                    "disabled_by": str(entry.disabled_by) if entry.disabled_by else None,
                    "source": entry.source,
                    "supports_unload": entry.supports_unload,
                    "supports_reconfigure": getattr(entry, "supports_reconfigure", False),
                }
            )
        return {
            "entities": [_entry_dict(item) for item in entity_registry.entities.values()],
            "devices": [_entry_dict(item) for item in device_registry.devices.values()],
            "areas": [_entry_dict(item) for item in area_registry.areas.values()],
            "floors": [_entry_dict(item) for item in floor_registry.floors.values()],
            "labels": [_entry_dict(item) for item in label_registry.labels.values()],
            "config_entries": config_entries,
        }

    def search(self, payload: dict[str, Any]) -> dict[str, Any]:
        kind = str(payload.get("kind", "all")).strip().lower()
        allowed = {"all", "entities", "devices", "areas", "floors", "labels", "config_entries"}
        if kind not in allowed:
            raise SuiteBridgeError("INVALID_REGISTRY_KIND", f"kind skal være en af: {', '.join(sorted(allowed))}.")
        query = str(payload.get("query", "")).casefold().strip()
        limit = min(max(int(payload.get("limit", 100)), 1), 250)
        snapshot = self._snapshot()
        selected = snapshot if kind == "all" else {kind: snapshot[kind]}
        results: dict[str, list[dict[str, Any]]] = {}
        for key, items in selected.items():
            filtered = []
            for item in items:
                if query and query not in pretty_json(item).casefold():
                    continue
                filtered.append(item)
                if len(filtered) >= limit:
                    break
            results[key] = filtered
        return {
            "query": query,
            "kind": kind,
            "results": results,
            "write_policy": {
                "entities": sorted(self.ENTITY_UPDATE_FIELDS),
                "devices": sorted(self.DEVICE_UPDATE_FIELDS),
                "entity_id_change": False,
                "delete": False,
            },
        }

    def _validate_area_and_labels(self, changes: dict[str, Any]) -> None:
        if "area_id" in changes and changes["area_id"] is not None:
            if ar.async_get(self.hass).async_get_area(str(changes["area_id"])) is None:
                raise SuiteBridgeError("AREA_NOT_FOUND", "Det angivne area_id findes ikke.", 404)
        if "labels" in changes:
            if not isinstance(changes["labels"], list):
                raise SuiteBridgeError("INVALID_LABELS", "labels skal være en liste.")
            registry = lr.async_get(self.hass)
            missing = [
                str(label_id)
                for label_id in changes["labels"]
                if registry.async_get_label(str(label_id)) is None
            ]
            if missing:
                raise SuiteBridgeError(
                    "LABEL_NOT_FOUND",
                    f"Disse label-id'er findes ikke: {', '.join(missing)}",
                    404,
                )

    async def prepare_change(
        self,
        payload: dict[str, Any],
        *,
        user_id: str,
        refresh_token_id: str,
    ) -> dict[str, Any]:
        kind = str(payload.get("kind", "")).strip().lower()
        object_id = str(payload.get("object_id", "")).strip()
        changes = payload.get("changes")
        expected = str(payload.get("expected_sha256", "")).lower()
        if kind not in {"entity", "device"} or not object_id or not isinstance(changes, dict):
            raise SuiteBridgeError(
                "INVALID_REGISTRY_CHANGE",
                "kind (entity/device), object_id og changes er obligatoriske.",
            )
        if len(expected) != 64:
            raise SuiteBridgeError("EXPECTED_SHA256_REQUIRED", "expected_sha256 er obligatorisk.", 409)
        allowed = self.ENTITY_UPDATE_FIELDS if kind == "entity" else self.DEVICE_UPDATE_FIELDS
        unknown = set(changes) - allowed
        if unknown:
            raise SuiteBridgeError(
                "REGISTRY_FIELD_DENIED",
                f"Felterne er ikke tilladt: {', '.join(sorted(unknown))}",
                403,
            )
        normalized = deepcopy(changes)
        if "labels" in normalized:
            normalized["labels"] = sorted({str(v) for v in normalized["labels"]})
        for text_field in ("name", "icon", "name_by_user", "area_id"):
            if text_field in normalized and normalized[text_field] is not None:
                normalized[text_field] = str(normalized[text_field]).strip() or None
        self._validate_area_and_labels(normalized)

        if kind == "entity":
            entry = er.async_get(self.hass).async_get(object_id)
        else:
            entry = dr.async_get(self.hass).async_get(object_id)
        if entry is None:
            raise SuiteBridgeError("REGISTRY_OBJECT_NOT_FOUND", "Registry-objektet findes ikke.", 404)
        before = _entry_dict(entry)
        before_sha = digest_json(before)
        if before_sha != expected:
            raise SuiteBridgeError("REGISTRY_OBJECT_CHANGED", "Registry-objektets SHA-256 matcher ikke.", 409)
        after = deepcopy(before)
        after.update(normalized)
        item = await self.prepared.create(
            user_id=user_id,
            refresh_token_id=refresh_token_id,
            operation=f"registry.{kind}.update",
            normalized_change={
                "kind": kind,
                "object_id": object_id,
                "changes": normalized,
                "before_sha256": before_sha,
                "projected_after_sha256": digest_json(after),
                "before": before,
                "projected_after": after,
            },
            material={
                "kind": kind,
                "object_id": object_id,
                "changes": normalized,
                "before": before,
                "before_sha256": before_sha,
            },
            risk="normal",
        )
        return {
            "prepare_id": item.prepare_id,
            "request_digest": item.digest,
            "expires_at": item.expires_at,
            "risk": item.risk,
            "normalized_change": item.normalized_change,
        }

    async def apply(self, item, *, user_id: str) -> dict[str, Any]:
        material = item.material
        kind = material["kind"]
        object_id = material["object_id"]
        changes = material["changes"]
        if kind == "entity":
            registry = er.async_get(self.hass)
            current_entry = registry.async_get(object_id)
        else:
            registry = dr.async_get(self.hass)
            current_entry = registry.async_get(object_id)
        if current_entry is None:
            raise SuiteBridgeError("REGISTRY_OBJECT_NOT_FOUND", "Registry-objektet findes ikke.", 404)
        current = _entry_dict(current_entry)
        if digest_json(current) != material["before_sha256"]:
            raise SuiteBridgeError(
                "REGISTRY_OBJECT_CHANGED",
                "Registry-objektet er ændret efter prepare.",
                409,
            )
        backup = await self.backups.create(
            "registry",
            f"{kind}-{object_id}",
            operation=item.operation,
            installation_id=self.config.installation_id,
            data=current,
            source_sha256=material["before_sha256"],
        )
        kwargs = dict(changes)
        if "labels" in kwargs:
            kwargs["labels"] = set(kwargs["labels"])
        if kind == "entity":
            updated = registry.async_update_entity(object_id, **kwargs)
        else:
            updated = registry.async_update_device(object_id, **kwargs)
        after = _entry_dict(updated)
        audit = await self.audit.append(
            {
                "operation": item.operation,
                "user_id": user_id,
                "prepare_id": item.prepare_id,
                "kind": kind,
                "object_id": object_id,
                "changes": changes,
                "before_sha256": material["before_sha256"],
                "after_sha256": digest_json(after),
                "backup_id": backup["backup_id"],
                "result": "executed",
            }
        )
        return {
            "executed": True,
            "operation": item.operation,
            "kind": kind,
            "object_id": object_id,
            "after": after,
            "after_sha256": digest_json(after),
            "backup": backup,
            "verification": {"matched": True},
            "audit_id": audit["audit_id"],
        }
