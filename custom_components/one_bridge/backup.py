"""Purpose-bound backup storage outside .storage."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from typing import Any

from homeassistant.core import HomeAssistant

from .const import BACKUP_RELATIVE, MAX_BACKUPS
from .models import SuiteBridgeError, digest_json

_SAFE = re.compile(r"[^a-zA-Z0-9_.-]+")


class BackupManager:
    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass
        self.root = Path(hass.config.path(BACKUP_RELATIVE))

    @staticmethod
    def _safe(value: str) -> str:
        cleaned = _SAFE.sub("_", value).strip("._")
        return cleaned[:80] or "default"

    def _write(self, category: str, name: str, payload: dict[str, Any]) -> Path:
        directory = self.root / self._safe(category)
        directory.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        path = directory / f"{stamp}-{self._safe(name)}.json"
        temp = path.with_suffix(".tmp")
        data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        temp.write_text(data, encoding="utf-8")
        os.chmod(temp, 0o600)
        os.replace(temp, path)
        return path

    async def create(
        self,
        category: str,
        name: str,
        *,
        operation: str,
        installation_id: str,
        data: Any,
        source_sha256: str,
    ) -> dict[str, Any]:
        envelope = {
            "schema_version": 1,
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "category": category,
            "name": name,
            "operation": operation,
            "installation_id": installation_id,
            "source_sha256": source_sha256,
            "data_sha256": digest_json(data),
            "data": data,
        }
        path = await self.hass.async_add_executor_job(
            self._write, category, name, envelope
        )
        return {
            "backup_id": str(path.relative_to(self.root)),
            "path": str(path),
            "sha256": digest_json(envelope),
        }

    def _list(self, category: str | None) -> list[dict[str, Any]]:
        directory = self.root / self._safe(category) if category else self.root
        if not directory.exists():
            return []
        results = []
        for path in sorted(directory.rglob("*.json"), reverse=True)[:MAX_BACKUPS]:
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            results.append(
                {
                    "backup_id": str(path.relative_to(self.root)),
                    "created_at": raw.get("created_at"),
                    "category": raw.get("category"),
                    "name": raw.get("name"),
                    "operation": raw.get("operation"),
                    "source_sha256": raw.get("source_sha256"),
                    "data_sha256": raw.get("data_sha256"),
                    "size": path.stat().st_size,
                }
            )
        return results

    async def list(self, category: str | None = None) -> list[dict[str, Any]]:
        return await self.hass.async_add_executor_job(self._list, category)

    def _read(self, backup_id: str) -> dict[str, Any]:
        try:
            candidate = (self.root / backup_id).resolve(strict=True)
        except (FileNotFoundError, OSError) as err:
            raise SuiteBridgeError(
                "BACKUP_NOT_FOUND", "Backuppen blev ikke fundet.", 404
            ) from err
        root = self.root.resolve(strict=False)
        if candidate != root and root not in candidate.parents:
            raise SuiteBridgeError("BACKUP_PATH_DENIED", "Backup-ID ligger uden for backup-roden.", 403)
        if candidate.suffix != ".json" or not candidate.is_file():
            raise SuiteBridgeError("BACKUP_NOT_FOUND", "Backuppen blev ikke fundet.", 404)
        try:
            raw = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as err:
            raise SuiteBridgeError("BACKUP_INVALID", f"Backuppen kunne ikke læses: {err}") from err
        if not isinstance(raw, dict) or "data" not in raw:
            raise SuiteBridgeError("BACKUP_INVALID", "Backupformatet er ugyldigt.")
        return raw

    async def read(self, backup_id: str) -> dict[str, Any]:
        return await self.hass.async_add_executor_job(self._read, backup_id)
