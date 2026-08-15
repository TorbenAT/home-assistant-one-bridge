"""Safe storage-helper discovery and CRUD via Home Assistant's own WebSocket API."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from homeassistant.core import HomeAssistant

from .audit import AuditLog
from .backup import BackupManager
from .config import BridgeConfig
from .const import (
    HELPER_DOMAINS,
    HELPER_FIELDS,
    MAX_HELPER_REFERENCE_FILES,
)
from .models import SuiteBridgeError, digest_json, json_safe
from .prepared import PreparedMutationStore
from .ws_client import async_ws_command


class HelperManager:
    def __init__(
        self,
        hass: HomeAssistant,
        config: BridgeConfig,
        prepared: PreparedMutationStore,
        backups: BackupManager,
        audit: AuditLog,
        lovelace,
    ) -> None:
        self.hass = hass
        self.config = config
        self.prepared = prepared
        self.backups = backups
        self.audit = audit
        self.lovelace = lovelace

    @staticmethod
    def _id_key(domain: str) -> str:
        return f"{domain}_id"

    @staticmethod
    def _validate_domain(domain: str) -> str:
        normalized = str(domain).strip().lower()
        if normalized not in HELPER_DOMAINS:
            raise SuiteBridgeError(
                "HELPER_DOMAIN_DENIED",
                f"Tilladte helper-domæner: {', '.join(HELPER_DOMAINS)}.",
                403,
            )
        return normalized

    async def _list_domain(
        self, refresh_token_id: str, domain: str
    ) -> list[dict[str, Any]]:
        result = await async_ws_command(
            self.hass, refresh_token_id, {"type": f"{domain}/list"}
        )
        return [dict(item) for item in (result or []) if isinstance(item, dict)]

    async def list_helpers(
        self, refresh_token_id: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        requested = payload.get("domains", list(HELPER_DOMAINS))
        if isinstance(requested, str):
            requested = [requested]
        if not isinstance(requested, list):
            raise SuiteBridgeError("INVALID_HELPER_DOMAINS", "domains skal være tekst eller liste.")
        domains = [self._validate_domain(item) for item in requested]
        query = str(payload.get("query", "")).casefold().strip()
        result: dict[str, list[dict[str, Any]]] = {}
        for domain in domains:
            items = await self._list_domain(refresh_token_id, domain)
            enriched = []
            id_key = self._id_key(domain)
            for item in items:
                helper_id = item.get("id") or item.get(id_key)
                entity_id = f"{domain}.{helper_id}" if helper_id else None
                state = self.hass.states.get(entity_id) if entity_id else None
                row = {
                    "domain": domain,
                    "helper_id": helper_id,
                    "entity_id": entity_id,
                    "definition": json_safe(item),
                    "definition_sha256": digest_json(item),
                    "state": state.state if state else None,
                    "attributes": json_safe(state.attributes) if state else {},
                }
                if query and query not in str(row).casefold():
                    continue
                enriched.append(row)
            result[domain] = enriched
        return {
            "helpers": result,
            "write_policy": {
                domain: sorted(HELPER_FIELDS[domain]) for domain in domains
            },
        }

    def _normalize_definition(
        self, domain: str, definition: dict[str, Any], *, require_name: bool
    ) -> dict[str, Any]:
        if not isinstance(definition, dict):
            raise SuiteBridgeError("INVALID_HELPER_DEFINITION", "definition skal være et objekt.")
        unknown = set(definition) - HELPER_FIELDS[domain]
        if unknown:
            raise SuiteBridgeError(
                "HELPER_FIELD_DENIED",
                f"Felterne er ikke tilladt for {domain}: {', '.join(sorted(unknown))}",
                403,
            )
        normalized = deepcopy(definition)
        if require_name and not str(normalized.get("name", "")).strip():
            raise SuiteBridgeError("HELPER_NAME_REQUIRED", "Helperens name er obligatorisk.")
        for field in ("name", "icon", "mode", "pattern", "unit_of_measurement", "initial", "duration"):
            if field in normalized and normalized[field] is not None:
                normalized[field] = str(normalized[field]).strip()
        if "options" in normalized:
            if not isinstance(normalized["options"], list) or not normalized["options"]:
                raise SuiteBridgeError("HELPER_OPTIONS_REQUIRED", "options skal være en ikke-tom liste.")
            normalized["options"] = [str(value) for value in normalized["options"]]
        for weekday in (
            "monday", "tuesday", "wednesday", "thursday",
            "friday", "saturday", "sunday",
        ):
            if weekday in normalized and not isinstance(normalized[weekday], list):
                raise SuiteBridgeError(
                    "INVALID_SCHEDULE",
                    f"{weekday} skal være en liste af tidsblokke.",
                )
        if domain == "input_datetime" and not (
            normalized.get("has_date") or normalized.get("has_time")
        ):
            raise SuiteBridgeError(
                "INPUT_DATETIME_MODE_REQUIRED",
                "input_datetime kræver has_date eller has_time.",
            )
        if domain == "input_number" and "min" in normalized and "max" in normalized:
            if float(normalized["min"]) >= float(normalized["max"]):
                raise SuiteBridgeError("INVALID_NUMBER_RANGE", "max skal være større end min.")
        return normalized

    async def _find_item(
        self, refresh_token_id: str, domain: str, helper_id: str
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        items = await self._list_domain(refresh_token_id, domain)
        id_key = self._id_key(domain)
        for item in items:
            if str(item.get("id") or item.get(id_key)) == helper_id:
                return item, items
        raise SuiteBridgeError(
            "HELPER_NOT_FOUND", f"{domain}.{helper_id} blev ikke fundet.", 404
        )

    def _scan_file_references(self, entity_id: str) -> list[dict[str, Any]]:
        config_root = Path(self.hass.config.config_dir)
        allowed_roots = [
            config_root / "automations.yaml",
            config_root / "scripts.yaml",
            config_root / "scenes.yaml",
            config_root / "packages",
            config_root / "integrationer",
            config_root / "prompts",
            config_root / "appdaemon" / "apps",
        ]
        matches: list[dict[str, Any]] = []
        scanned = 0
        for root in allowed_roots:
            candidates = [root] if root.is_file() else root.rglob("*") if root.is_dir() else []
            for path in candidates:
                if scanned >= MAX_HELPER_REFERENCE_FILES:
                    return matches + [{"truncated": True}]
                if path.is_symlink() or not path.is_file() or path.suffix.lower() not in {
                    ".yaml", ".yml", ".json", ".md", ".py"
                }:
                    continue
                if path.name == "secrets.yaml" or ".storage" in path.parts or ".git" in path.parts:
                    continue
                try:
                    resolved = path.resolve(strict=True)
                    if config_root.resolve(strict=True) not in resolved.parents:
                        continue
                    if resolved.stat().st_size > 1_000_000:
                        continue
                except OSError:
                    continue
                scanned += 1
                try:
                    text = resolved.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    continue
                if entity_id not in text:
                    continue
                for line_no, line in enumerate(text.splitlines(), 1):
                    if entity_id in line:
                        matches.append(
                            {
                                "source": "file",
                                "path": str(path.relative_to(config_root)),
                                "line": line_no,
                                "text": line.strip()[:300],
                            }
                        )
                        if len(matches) >= 200:
                            return matches + [{"truncated": True}]
        return matches

    async def references(self, entity_id: str) -> dict[str, Any]:
        if "." not in entity_id:
            raise SuiteBridgeError("INVALID_ENTITY_ID", "entity_id er ugyldigt.")
        file_matches = await self.hass.async_add_executor_job(
            self._scan_file_references, entity_id
        )
        dashboard_matches: list[dict[str, Any]] = []
        data = self.hass.data.get("lovelace")
        if data is not None:
            for dashboard in data.dashboards.values():
                try:
                    config = await dashboard.async_load(False)
                except Exception:
                    continue
                stack: list[tuple[str, Any]] = [("", config)]
                while stack:
                    path, value = stack.pop()
                    if isinstance(value, dict):
                        stack.extend((f"{path}/{key}", child) for key, child in value.items())
                    elif isinstance(value, list):
                        stack.extend((f"{path}/{index}", child) for index, child in enumerate(value))
                    elif value == entity_id:
                        dashboard_matches.append(
                            {
                                "source": "lovelace",
                                "url_path": dashboard.url_path or "lovelace",
                                "path": path or "/",
                            }
                        )
        return {
            "entity_id": entity_id,
            "references": file_matches + dashboard_matches,
            "count": len(file_matches) + len(dashboard_matches),
        }

    async def prepare_change(
        self,
        refresh_token_id: str,
        payload: dict[str, Any],
        *,
        user_id: str,
    ) -> dict[str, Any]:
        action = str(payload.get("action", "")).strip().lower()
        domain = self._validate_domain(payload.get("domain", ""))
        helper_id = str(payload.get("helper_id", "")).strip()
        definition = payload.get("definition", {})
        if action not in {"create", "update", "delete"}:
            raise SuiteBridgeError("INVALID_HELPER_ACTION", "action skal være create, update eller delete.")

        if action == "create":
            normalized = self._normalize_definition(domain, definition, require_name=True)
            items = await self._list_domain(refresh_token_id, domain)
            before_sha = digest_json(items)
            material = {
                "action": action,
                "domain": domain,
                "definition": normalized,
                "collection_sha256": before_sha,
            }
            normalized_change = {
                "action": action,
                "domain": domain,
                "definition": normalized,
                "collection_sha256": before_sha,
            }
            risk = "normal"
            phrase = None
        else:
            if not helper_id:
                raise SuiteBridgeError("HELPER_ID_REQUIRED", "helper_id er obligatorisk.")
            current, items = await self._find_item(refresh_token_id, domain, helper_id)
            current_sha = digest_json(current)
            expected = str(payload.get("expected_sha256", "")).lower()
            if expected != current_sha:
                raise SuiteBridgeError(
                    "HELPER_CHANGED",
                    "Helperens expected_sha256 matcher ikke den aktuelle definition.",
                    409,
                )
            if action == "update":
                merged = {
                    key: value
                    for key, value in current.items()
                    if key in HELPER_FIELDS[domain]
                }
                merged.update(definition if isinstance(definition, dict) else {})
                normalized = self._normalize_definition(domain, merged, require_name=True)
                references = None
                risk = "normal"
                phrase = None
            else:
                normalized = {}
                references = await self.references(f"{domain}.{helper_id}")
                risk = "critical"
                phrase = f"BEKRÆFT SLET HELPER {domain}.{helper_id}"
            material = {
                "action": action,
                "domain": domain,
                "helper_id": helper_id,
                "definition": normalized,
                "before": current,
                "before_sha256": current_sha,
                "references": references,
            }
            normalized_change = {
                "action": action,
                "domain": domain,
                "helper_id": helper_id,
                "before_sha256": current_sha,
                "before": json_safe(current),
                "after": json_safe(normalized) if action == "update" else None,
                "references": references,
                "confirmation_phrase": phrase,
            }

        item = await self.prepared.create(
            user_id=user_id,
            refresh_token_id=refresh_token_id,
            operation=f"helper.{action}",
            normalized_change=normalized_change,
            material=material,
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

    async def apply(self, item, *, user_id: str, refresh_token_id: str) -> dict[str, Any]:
        material = item.material
        action = material["action"]
        domain = material["domain"]
        id_key = self._id_key(domain)

        if action == "create":
            current_items = await self._list_domain(refresh_token_id, domain)
            if digest_json(current_items) != material["collection_sha256"]:
                raise SuiteBridgeError(
                    "HELPER_COLLECTION_CHANGED",
                    "Helper-samlingen er ændret efter prepare.",
                    409,
                )
            command = {"type": f"{domain}/create", **material["definition"]}
            result = await async_ws_command(self.hass, refresh_token_id, command)
            helper_id = str(result.get("id") or result.get(id_key))
            backup = None
        else:
            helper_id = material["helper_id"]
            current, _ = await self._find_item(refresh_token_id, domain, helper_id)
            if digest_json(current) != material["before_sha256"]:
                raise SuiteBridgeError("HELPER_CHANGED", "Helperen er ændret efter prepare.", 409)
            backup = await self.backups.create(
                "helpers",
                f"{domain}-{helper_id}",
                operation=item.operation,
                installation_id=self.config.installation_id,
                data=current,
                source_sha256=material["before_sha256"],
            )
            if action == "update":
                command = {
                    "type": f"{domain}/update",
                    id_key: helper_id,
                    **material["definition"],
                }
                result = await async_ws_command(self.hass, refresh_token_id, command)
            else:
                command = {"type": f"{domain}/delete", id_key: helper_id}
                await async_ws_command(self.hass, refresh_token_id, command)
                result = None

        verification_items = await self._list_domain(refresh_token_id, domain)
        matching = [
            row
            for row in verification_items
            if str(row.get("id") or row.get(id_key)) == helper_id
        ]
        matched = (not matching) if action == "delete" else bool(matching)
        if not matched:
            raise SuiteBridgeError(
                "HELPER_VERIFY_FAILED",
                "Helperændringen kunne ikke efterverificeres.",
                500,
            )
        after = matching[0] if matching else None
        audit = await self.audit.append(
            {
                "operation": item.operation,
                "user_id": user_id,
                "prepare_id": item.prepare_id,
                "domain": domain,
                "helper_id": helper_id,
                "before_sha256": material.get("before_sha256"),
                "after_sha256": digest_json(after) if after is not None else None,
                "backup_id": backup["backup_id"] if backup else None,
                "result": "executed",
            }
        )
        return {
            "executed": True,
            "operation": item.operation,
            "entity_id": f"{domain}.{helper_id}",
            "definition": json_safe(after),
            "definition_sha256": digest_json(after) if after is not None else None,
            "backup": backup,
            "verification": {"matched": True},
            "audit_id": audit["audit_id"],
        }
