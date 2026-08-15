"""Read-only deployment and Git status for the fixed Bridge repository."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from homeassistant.core import HomeAssistant

from .config import BridgeConfig
from .models import SuiteBridgeError


_REMOTE_RE = re.compile(r"^\s*url\s*=\s*(.+?)\s*$", re.MULTILINE)


class DeploymentManager:
    def __init__(
        self,
        hass: HomeAssistant,
        config: BridgeConfig,
        expected_remote_suffix: str | None = None,
        repo_relative: str | None = None,
        deployment_marker_relative: str | None = None,
    ) -> None:
        self.hass = hass
        self.config = config
        self.expected_remote_suffix = expected_remote_suffix
        self.repo_relative = repo_relative
        self.deployment_marker_relative = deployment_marker_relative

    def _repo_root(self) -> Path | None:
        if not self.repo_relative:
            return None
        return Path(self.hass.config.path(self.repo_relative))

    @staticmethod
    def _read_text(path: Path, limit: int = 100_000) -> str | None:
        try:
            if not path.is_file() or path.stat().st_size > limit:
                return None
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    def _resolve_head(self, git_dir: Path) -> tuple[str | None, str | None]:
        head = self._read_text(git_dir / "HEAD", 1_000)
        if not head:
            return None, None
        head = head.strip()
        if head.startswith("ref: "):
            ref = head[5:]
            direct = self._read_text(git_dir / ref, 1_000)
            if direct:
                return ref.removeprefix("refs/heads/"), direct.strip()
            packed = self._read_text(git_dir / "packed-refs")
            if packed:
                for line in packed.splitlines():
                    if line.startswith("#") or line.startswith("^"):
                        continue
                    try:
                        commit, packed_ref = line.split(" ", 1)
                    except ValueError:
                        continue
                    if packed_ref == ref:
                        return ref.removeprefix("refs/heads/"), commit
            return ref.removeprefix("refs/heads/"), None
        return None, head

    def _tags(self, git_dir: Path) -> list[dict[str, str]]:
        tags: dict[str, str] = {}
        refs = git_dir / "refs" / "tags"
        if refs.is_dir():
            for path in refs.rglob("*"):
                if not path.is_file():
                    continue
                value = self._read_text(path, 1_000)
                if value:
                    tags[str(path.relative_to(refs))] = value.strip()
        packed = self._read_text(git_dir / "packed-refs")
        if packed:
            for line in packed.splitlines():
                if line.startswith("#") or line.startswith("^") or " refs/tags/" not in line:
                    continue
                commit, ref = line.split(" ", 1)
                tags.setdefault(ref.removeprefix("refs/tags/"), commit)
        return [
            {"tag": tag, "commit": commit}
            for tag, commit in sorted(tags.items(), reverse=True)[:100]
        ]

    def _status(self) -> dict[str, Any]:
        repo = self._repo_root()
        if repo is None:
            return {
                "available": False,
                "role": self.config.role,
                "repo": None,
                "error": "Git-repository er ikke konfigureret.",
            }
        git_dir = repo / ".git"
        if not git_dir.is_dir():
            return {
                "available": False,
                "role": self.config.role,
                "repo": str(repo),
                "error": "Git-repository blev ikke fundet.",
            }
        branch, commit = self._resolve_head(git_dir)
        config_text = self._read_text(git_dir / "config") or ""
        remote_match = _REMOTE_RE.search(config_text)
        remote = remote_match.group(1) if remote_match else None
        remote_valid = (
            None
            if not self.expected_remote_suffix
            else bool(remote and remote.endswith(self.expected_remote_suffix))
        )
        version = self._read_text(repo / "VERSION", 1_000)
        deployment = None
        if self.deployment_marker_relative:
            deployment = self._read_text(
                Path(self.hass.config.path(self.deployment_marker_relative))
            )
        script_root = repo / "scripts"
        role_commands = (
            {
                "prepare": f"sh {script_root / 'git-source.sh'} prepare vX.Y.Z",
                "push_review": f"sh {script_root / 'git-source.sh'} push \"<beskrivelse>\" \"BEKRÆFT PUSH REVIEW-BRANCH\"",
                "release": f"sh {script_root / 'git-source.sh'} release vX.Y.Z \"BEKRÆFT RELEASE TIL MAIN\"",
                "stage": f"sh {script_root / 'git-source.sh'} stage vX.Y.Z \"BEKRÆFT STAGE FRA GIT\"",
            }
            if self.config.role == "source"
            else {
                "stage_update": f"sh {script_root / 'git-target.sh'} stage vX.Y.Z \"BEKRÆFT TARGET STAGE FRA GIT\"",
                "activate": f"sh {script_root / 'git-target.sh'} activate \"BEKRÆFT AKTIVER BRIDGE SUITE\"",
            }
        )
        return {
            "available": True,
            "role": self.config.role,
            "repo": str(repo),
            "branch": branch,
            "commit": commit,
            "remote": remote,
            "remote_valid": remote_valid,
            "version": version.strip() if version else None,
            "tags": self._tags(git_dir),
            "last_deployment": deployment,
            "commands": role_commands,
            "mutation_api": (
                "allowlisted prepare/apply commit; push remains unavailable"
                if self.config.role == "source"
                else "unavailable for this Bridge role"
            ),
        }

    async def status(self, payload: dict[str, Any]) -> dict[str, Any]:
        del payload
        return await self.hass.async_add_executor_job(self._status)
