"""Safe Lovelace discovery, patching and rollback without raw .storage access."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from homeassistant.components.lovelace.const import DOMAIN as LOVELACE_DOMAIN
from homeassistant.components.lovelace.const import LOVELACE_DATA, MODE_STORAGE
from homeassistant.core import HomeAssistant

from .audit import AuditLog
from .backup import BackupManager
from .config import BridgeConfig
from .json_patch import (
    apply_patch,
    entity_references,
    unified_diff,
    validate_dashboard_config,
)
from .models import SuiteBridgeError, digest_json, json_safe
from .prepared import PreparedMutationStore
from .ws_client import async_ws_command


class LovelaceManager:
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

    def _dashboard(self, url_path: str | None):
        data = self.hass.data.get(LOVELACE_DATA)
        if data is None:
            raise SuiteBridgeError(
                "LOVELACE_NOT_READY", "Lovelace er ikke indlæst.", 503
            )
        dashboards = data.dashboards
        normalized = None if url_path in {None, "", LOVELACE_DOMAIN} else url_path
        dashboard = (
            dashboards.get(LOVELACE_DOMAIN) or dashboards.get(None)
            if normalized is None
            else dashboards.get(normalized)
        )
        if dashboard is None:
            raise SuiteBridgeError(
                "DASHBOARD_NOT_FOUND",
                f"Dashboardet {url_path or LOVELACE_DOMAIN} blev ikke fundet.",
                404,
            )
        return dashboard, normalized

    async def list_dashboards(
        self, refresh_token_id: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        del payload
        try:
            storage_dashboards = await async_ws_command(
                self.hass,
                refresh_token_id,
                {"type": "lovelace/dashboards/list"},
            )
        except SuiteBridgeError:
            storage_dashboards = []
        result: list[dict[str, Any]] = []
        data = self.hass.data.get(LOVELACE_DATA)
        if data is None:
            raise SuiteBridgeError("LOVELACE_NOT_READY", "Lovelace er ikke indlæst.", 503)
        for key, dashboard in data.dashboards.items():
            metadata = dict(dashboard.config or {})
            url_path = dashboard.url_path
            try:
                info = await dashboard.async_get_info()
            except Exception as err:
                info = {"error": f"{type(err).__name__}: {err}"}
            result.append(
                {
                    "url_path": url_path or LOVELACE_DOMAIN,
                    "storage_key": key,
                    "mode": dashboard.mode,
                    "metadata": json_safe(metadata),
                    "info": json_safe(info),
                    "writable": dashboard.mode == MODE_STORAGE,
                }
            )
        result.sort(key=lambda item: str(item["url_path"]))
        return {
            "dashboards": result,
            "storage_dashboards": json_safe(storage_dashboards),
            "raw_storage_access": False,
        }

    async def get_dashboard(self, payload: dict[str, Any]) -> dict[str, Any]:
        url_path = payload.get("url_path")
        if url_path is not None and not isinstance(url_path, str):
            raise SuiteBridgeError("INVALID_URL_PATH", "url_path skal være tekst.")
        dashboard, normalized = self._dashboard(url_path)
        try:
            config = await dashboard.async_load(bool(payload.get("force", False)))
        except Exception as err:
            raise SuiteBridgeError(
                "DASHBOARD_LOAD_FAILED",
                f"Dashboardet kunne ikke læses: {type(err).__name__}: {err}",
                400,
            ) from err
        safe = json_safe(config)
        return {
            "url_path": normalized or LOVELACE_DOMAIN,
            "mode": dashboard.mode,
            "writable": dashboard.mode == MODE_STORAGE,
            "sha256": digest_json(config),
            "config": safe,
            "entity_references": entity_references(config),
        }

    async def list_resources(
        self, refresh_token_id: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        del payload
        result = await async_ws_command(
            self.hass, refresh_token_id, {"type": "lovelace/resources"}
        )
        return {
            "resources": json_safe(result or []),
            "write_policy": "read_only",
        }

    async def prepare_patch(
        self,
        payload: dict[str, Any],
        *,
        user_id: str,
        refresh_token_id: str,
    ) -> dict[str, Any]:
        url_path = payload.get("url_path")
        if url_path is not None and not isinstance(url_path, str):
            raise SuiteBridgeError("INVALID_URL_PATH", "url_path skal være tekst.")
        expected = str(payload.get("expected_sha256", "")).lower()
        if len(expected) != 64:
            raise SuiteBridgeError(
                "EXPECTED_SHA256_REQUIRED",
                "expected_sha256 med 64 hextegn er obligatorisk.",
                409,
            )
        patch = payload.get("patch")
        dashboard, normalized = self._dashboard(url_path)
        if dashboard.mode != MODE_STORAGE:
            raise SuiteBridgeError(
                "DASHBOARD_READ_ONLY",
                "Kun storage-baserede dashboards kan ændres gennem Bridge.",
                403,
            )
        before = await dashboard.async_load(False)
        before_sha = digest_json(before)
        if before_sha != expected:
            raise SuiteBridgeError(
                "DASHBOARD_CHANGED",
                "Dashboardets SHA-256 matcher ikke; læs det igen.",
                409,
            )
        after = apply_patch(before, patch)
        warnings = validate_dashboard_config(after)
        diff = unified_diff(before, after)
        risk = "high" if warnings else "normal"
        item = await self.prepared.create(
            user_id=user_id,
            refresh_token_id=refresh_token_id,
            operation="lovelace.patch",
            normalized_change={
                "url_path": normalized or LOVELACE_DOMAIN,
                "expected_sha256": before_sha,
                "after_sha256": digest_json(after),
                "patch": patch,
                "diff": diff,
                "warnings": warnings,
            },
            material={
                "url_path": normalized,
                "before": deepcopy(before),
                "after": after,
                "before_sha256": before_sha,
            },
            risk=risk,
        )
        audit = await self.audit.append(
            {
                "operation": "lovelace.patch.prepare",
                "user_id": user_id,
                "prepare_id": item.prepare_id,
                "dashboard": normalized or LOVELACE_DOMAIN,
                "before_sha256": before_sha,
                "after_sha256": digest_json(after),
                "result": "prepared",
                "warnings": warnings,
            }
        )
        return {
            "prepare_id": item.prepare_id,
            "request_digest": item.digest,
            "expires_at": item.expires_at,
            "risk": risk,
            "normalized_change": item.normalized_change,
            "audit_id": audit["audit_id"],
        }

    async def prepare_rollback(
        self,
        payload: dict[str, Any],
        *,
        user_id: str,
        refresh_token_id: str,
    ) -> dict[str, Any]:
        backup_id = str(payload.get("backup_id", "")).strip()
        expected = str(payload.get("expected_sha256", "")).lower()
        if not backup_id or len(expected) != 64:
            raise SuiteBridgeError(
                "ROLLBACK_INPUT_REQUIRED",
                "backup_id og dashboardets aktuelle expected_sha256 er obligatoriske.",
            )
        backup = await self.backups.read(backup_id)
        if backup.get("category") != "lovelace":
            raise SuiteBridgeError("BACKUP_TYPE_MISMATCH", "Backuppen er ikke et Lovelace-backup.")
        url_path = None if backup.get("name") == LOVELACE_DOMAIN else backup.get("name")
        dashboard, normalized = self._dashboard(url_path)
        if dashboard.mode != MODE_STORAGE:
            raise SuiteBridgeError("DASHBOARD_READ_ONLY", "Dashboardet er ikke storage-baseret.", 403)
        before = await dashboard.async_load(False)
        before_sha = digest_json(before)
        if before_sha != expected:
            raise SuiteBridgeError("DASHBOARD_CHANGED", "Dashboardet er ændret siden læsning.", 409)
        after = backup.get("data")
        validate_dashboard_config(after)
        phrase = f"BEKRÆFT DASHBOARD ROLLBACK {normalized or LOVELACE_DOMAIN}"
        item = await self.prepared.create(
            user_id=user_id,
            refresh_token_id=refresh_token_id,
            operation="lovelace.rollback",
            normalized_change={
                "url_path": normalized or LOVELACE_DOMAIN,
                "backup_id": backup_id,
                "expected_sha256": before_sha,
                "after_sha256": digest_json(after),
                "diff": unified_diff(before, after),
                "confirmation_phrase": phrase,
            },
            material={
                "url_path": normalized,
                "before": deepcopy(before),
                "after": deepcopy(after),
                "before_sha256": before_sha,
                "backup_id": backup_id,
            },
            risk="critical",
            confirmation_phrase=phrase,
        )
        return {
            "prepare_id": item.prepare_id,
            "request_digest": item.digest,
            "expires_at": item.expires_at,
            "risk": "critical",
            "normalized_change": item.normalized_change,
        }

    async def prepare_metadata(
        self,
        refresh_token_id: str,
        payload: dict[str, Any],
        *,
        user_id: str,
    ) -> dict[str, Any]:
        action = str(payload.get("action", "")).strip().lower()
        if action not in {"create", "update", "delete", "clone"}:
            raise SuiteBridgeError(
                "INVALID_DASHBOARD_ACTION",
                "action skal være create, update, delete eller clone.",
            )
        dashboards = await async_ws_command(
            self.hass, refresh_token_id, {"type": "lovelace/dashboards/list"}
        )
        dashboards = [dict(item) for item in (dashboards or []) if isinstance(item, dict)]
        collection_sha = digest_json(dashboards)
        metadata = payload.get("metadata", {})
        if not isinstance(metadata, dict):
            raise SuiteBridgeError("INVALID_DASHBOARD_METADATA", "metadata skal være et objekt.")
        allowed_fields = {
            "title", "url_path", "icon", "show_in_sidebar", "require_admin", "mode"
        }
        unknown = set(metadata) - allowed_fields
        if unknown:
            raise SuiteBridgeError(
                "DASHBOARD_METADATA_FIELD_DENIED",
                f"Felterne er ikke tilladt: {', '.join(sorted(unknown))}",
                403,
            )
        normalized = deepcopy(metadata)
        for field in ("title", "url_path", "icon", "mode"):
            if field in normalized and normalized[field] is not None:
                normalized[field] = str(normalized[field]).strip()
        dashboard_id = str(payload.get("dashboard_id", "")).strip()
        current = None
        for row in dashboards:
            if str(row.get("id", "")) == dashboard_id:
                current = row
                break

        if action in {"create", "clone"}:
            if not normalized.get("title") or not normalized.get("url_path"):
                raise SuiteBridgeError(
                    "DASHBOARD_METADATA_REQUIRED",
                    "title og url_path er obligatoriske.",
                )
            if any(row.get("url_path") == normalized["url_path"] for row in dashboards):
                raise SuiteBridgeError("DASHBOARD_EXISTS", "url_path findes allerede.", 409)
            source_config = None
            if action == "clone":
                source_url = payload.get("source_url_path")
                source_dashboard, _ = self._dashboard(source_url)
                source_config = await source_dashboard.async_load(False)
                validate_dashboard_config(source_config)
            before_sha = collection_sha
            risk = "high" if action == "clone" else "normal"
            phrase = None
        else:
            if current is None:
                raise SuiteBridgeError("DASHBOARD_NOT_FOUND", "dashboard_id blev ikke fundet.", 404)
            expected = str(payload.get("expected_sha256", "")).lower()
            before_sha = digest_json(current)
            if expected != before_sha:
                raise SuiteBridgeError(
                    "DASHBOARD_METADATA_CHANGED",
                    "Dashboardmetadataens expected_sha256 matcher ikke.",
                    409,
                )
            source_config = None
            if action == "update":
                projected = {**current, **normalized}
                normalized = {
                    key: value
                    for key, value in projected.items()
                    if key in allowed_fields
                }
                risk = "normal"
                phrase = None
            else:
                risk = "critical"
                phrase = f"BEKRÆFT SLET DASHBOARD {current.get('url_path')}"
        normalized_change = {
            "action": action,
            "dashboard_id": dashboard_id or None,
            "metadata": normalized,
            "before_sha256": before_sha,
            "current": json_safe(current),
            "confirmation_phrase": phrase,
        }
        item = await self.prepared.create(
            user_id=user_id,
            refresh_token_id=refresh_token_id,
            operation=f"lovelace.metadata.{action}",
            normalized_change=normalized_change,
            material={
                "action": action,
                "dashboard_id": dashboard_id,
                "metadata": normalized,
                "current": current,
                "before_sha256": before_sha,
                "source_config": source_config,
            },
            risk=risk,
            confirmation_phrase=phrase,
        )
        return {
            "prepare_id": item.prepare_id,
            "request_digest": item.digest,
            "expires_at": item.expires_at,
            "risk": risk,
            "normalized_change": normalized_change,
        }

    async def apply_metadata(
        self,
        item,
        *,
        user_id: str,
        refresh_token_id: str,
    ) -> dict[str, Any]:
        material = item.material
        action = material["action"]
        dashboards = await async_ws_command(
            self.hass, refresh_token_id, {"type": "lovelace/dashboards/list"}
        )
        dashboards = [dict(row) for row in (dashboards or []) if isinstance(row, dict)]
        current = next(
            (
                row
                for row in dashboards
                if str(row.get("id", "")) == material.get("dashboard_id")
            ),
            None,
        )
        backup = None
        if action in {"create", "clone"}:
            if digest_json(dashboards) != material["before_sha256"]:
                raise SuiteBridgeError(
                    "DASHBOARD_COLLECTION_CHANGED",
                    "Dashboardlisten er ændret efter prepare.",
                    409,
                )
            result = await async_ws_command(
                self.hass,
                refresh_token_id,
                {"type": "lovelace/dashboards/create", **material["metadata"]},
            )
            dashboard_id = str(result.get("id", ""))
            if action == "clone":
                new_dashboard, _ = self._dashboard(material["metadata"]["url_path"])
                await new_dashboard.async_save(deepcopy(material["source_config"]))
        elif action == "update":
            if current is None or digest_json(current) != material["before_sha256"]:
                raise SuiteBridgeError(
                    "DASHBOARD_METADATA_CHANGED",
                    "Dashboardmetadata er ændret efter prepare.",
                    409,
                )
            backup = await self.backups.create(
                "lovelace_metadata",
                str(current.get("url_path") or material["dashboard_id"]),
                operation=item.operation,
                installation_id=self.config.installation_id,
                data=current,
                source_sha256=material["before_sha256"],
            )
            result = await async_ws_command(
                self.hass,
                refresh_token_id,
                {
                    "type": "lovelace/dashboards/update",
                    "dashboard_id": material["dashboard_id"],
                    **material["metadata"],
                },
            )
            dashboard_id = material["dashboard_id"]
        else:
            if current is None or digest_json(current) != material["before_sha256"]:
                raise SuiteBridgeError(
                    "DASHBOARD_METADATA_CHANGED",
                    "Dashboardmetadata er ændret efter prepare.",
                    409,
                )
            dashboard, _ = self._dashboard(current.get("url_path"))
            try:
                config = await dashboard.async_load(False)
            except Exception:
                config = None
            backup = await self.backups.create(
                "lovelace_deleted",
                str(current.get("url_path") or material["dashboard_id"]),
                operation=item.operation,
                installation_id=self.config.installation_id,
                data={"metadata": current, "config": config},
                source_sha256=material["before_sha256"],
            )
            await async_ws_command(
                self.hass,
                refresh_token_id,
                {
                    "type": "lovelace/dashboards/delete",
                    "dashboard_id": material["dashboard_id"],
                },
            )
            result = None
            dashboard_id = material["dashboard_id"]

        after_list = await async_ws_command(
            self.hass, refresh_token_id, {"type": "lovelace/dashboards/list"}
        )
        after_rows = [dict(row) for row in (after_list or []) if isinstance(row, dict)]
        exists = any(str(row.get("id", "")) == dashboard_id for row in after_rows)
        if (action == "delete" and exists) or (action != "delete" and not exists):
            raise SuiteBridgeError(
                "DASHBOARD_METADATA_VERIFY_FAILED",
                "Dashboardmetadata kunne ikke efterverificeres.",
                500,
            )
        audit = await self.audit.append(
            {
                "operation": item.operation,
                "user_id": user_id,
                "prepare_id": item.prepare_id,
                "dashboard_id": dashboard_id,
                "metadata": material["metadata"],
                "backup_id": backup["backup_id"] if backup else None,
                "result": "executed",
            }
        )
        return {
            "executed": True,
            "operation": item.operation,
            "dashboard_id": dashboard_id,
            "result": json_safe(result),
            "backup": backup,
            "verification": {"matched": True},
            "audit_id": audit["audit_id"],
        }

    async def apply(self, item, *, user_id: str) -> dict[str, Any]:
        material = item.material
        dashboard, normalized = self._dashboard(material["url_path"])
        current = await dashboard.async_load(False)
        current_sha = digest_json(current)
        if current_sha != material["before_sha256"]:
            raise SuiteBridgeError(
                "DASHBOARD_CHANGED",
                "Dashboardet er ændret efter prepare; opret en ny mutation.",
                409,
            )
        backup = await self.backups.create(
            "lovelace",
            normalized or LOVELACE_DOMAIN,
            operation=item.operation,
            installation_id=self.config.installation_id,
            data=current,
            source_sha256=current_sha,
        )
        try:
            await dashboard.async_save(deepcopy(material["after"]))
        except Exception as err:
            raise SuiteBridgeError(
                "DASHBOARD_SAVE_FAILED",
                f"Dashboardet kunne ikke gemmes: {type(err).__name__}: {err}",
                500,
            ) from err
        verified = await dashboard.async_load(True)
        after_sha = digest_json(verified)
        expected_after = digest_json(material["after"])
        if after_sha != expected_after:
            raise SuiteBridgeError(
                "DASHBOARD_VERIFY_FAILED",
                "Dashboardet blev gemt, men efterverifikationen matcher ikke.",
                500,
            )
        audit = await self.audit.append(
            {
                "operation": item.operation,
                "user_id": user_id,
                "prepare_id": item.prepare_id,
                "dashboard": normalized or LOVELACE_DOMAIN,
                "before_sha256": current_sha,
                "after_sha256": after_sha,
                "backup_id": backup["backup_id"],
                "result": "executed",
            }
        )
        return {
            "executed": True,
            "operation": item.operation,
            "url_path": normalized or LOVELACE_DOMAIN,
            "before_sha256": current_sha,
            "after_sha256": after_sha,
            "backup": backup,
            "verification": {"matched": True, "sha256": after_sha},
            "audit_id": audit["audit_id"],
        }
