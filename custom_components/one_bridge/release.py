"""Git-backed staged worker releases with atomic activation and rollback."""

from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import dataclass
import fnmatch
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import tarfile
from typing import Any, Awaitable, Callable
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen
import uuid
import zipfile

from .models import PreparedMutation, SuiteBridgeError, utc_now_iso
from .prepared import PreparedMutationStore
from .redaction import redact
from .worker_loader import WorkerLoader

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_SAFE_VERSION_RE = re.compile(r"[^A-Za-z0-9._-]+")
_GITHUB_REPO_RE = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/"
    r"(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    data = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as err:
        raise SuiteBridgeError(
            "RELEASE_STATE_INVALID",
            f"Release-state kunne ikke læses: {path.name}",
            500,
        ) from err
    if not isinstance(value, dict):
        raise SuiteBridgeError(
            "RELEASE_STATE_INVALID",
            f"Release-state er ikke et objekt: {path.name}",
            500,
        )
    return value


def _normalized_repository(value: str) -> str:
    match = _GITHUB_REPO_RE.fullmatch(value.strip())
    if match is None:
        raise SuiteBridgeError(
            "RELEASE_REPOSITORY_DENIED",
            "Kun en allowlistet HTTPS GitHub-repository-URL er tilladt.",
            403,
        )
    return (
        f"https://github.com/{match.group('owner')}/{match.group('repo')}"
    )


@dataclass(frozen=True, slots=True)
class RepositoryPolicy:
    url: str
    allowed_refs: tuple[str, ...]
    allow_branch_head: bool
    require_clean_manifest: bool

    @property
    def git_remote_suffix(self) -> str:
        return f"{self.url.removeprefix('https://github.com/')}.git"


@dataclass(frozen=True, slots=True)
class ReleasePolicy:
    enabled: bool
    repositories: tuple[RepositoryPolicy, ...]
    installation_root: Path
    active_pointer: Path
    git_repo_relative: str | None
    local_mirror_root: Path | None
    deployment_marker_relative: str | None
    max_download_bytes: int
    prepare_ttl_seconds: int
    fetch_timeout_seconds: int
    test_timeout_seconds: int
    required_commands: tuple[str, ...]
    bootstrap_paths_denied: tuple[str, ...]
    worker_path: str
    error: str | None = None

    @classmethod
    def disabled(cls, error: str) -> "ReleasePolicy":
        return cls(
            enabled=False,
            repositories=(),
            installation_root=Path("/config/one_bridge"),
            active_pointer=Path("/config/one_bridge/active.json"),
            git_repo_relative=None,
            local_mirror_root=None,
            deployment_marker_relative=None,
            max_download_bytes=25_000_000,
            prepare_ttl_seconds=1800,
            fetch_timeout_seconds=60,
            test_timeout_seconds=300,
            required_commands=(),
            bootstrap_paths_denied=(),
            worker_path="worker",
            error=error,
        )

    @classmethod
    def from_mapping(cls, raw: Any) -> "ReleasePolicy":
        if not isinstance(raw, dict):
            raise ValueError("Release policy skal være et JSON-objekt.")
        repositories_raw = raw.get("repositories")
        if not isinstance(repositories_raw, list) or not repositories_raw:
            raise ValueError("Release policy mangler repositories.")
        repositories: list[RepositoryPolicy] = []
        for item in repositories_raw:
            if not isinstance(item, dict):
                raise ValueError("Repository policy skal være et objekt.")
            url = _normalized_repository(str(item.get("url", "")))
            refs = item.get("allowed_refs")
            if (
                not isinstance(refs, list)
                or not refs
                or any(not isinstance(ref, str) or not ref for ref in refs)
            ):
                raise ValueError(f"{url} mangler allowed_refs.")
            repositories.append(
                RepositoryPolicy(
                    url=url,
                    allowed_refs=tuple(refs),
                    allow_branch_head=bool(item.get("allow_branch_head", False)),
                    require_clean_manifest=bool(
                        item.get("require_clean_manifest", True)
                    ),
                )
            )
        root = Path(str(raw.get("installation_root", "")))
        active = Path(str(raw.get("active_pointer", "")))
        if not root.is_absolute() or root == Path(root.anchor):
            raise ValueError("installation_root skal være en sikker absolut mappe.")
        if not active.is_absolute() or active.parent.resolve() != root.resolve():
            raise ValueError("active_pointer skal ligge direkte i installation_root.")
        git_repo_relative_raw = raw.get("git_repo_relative")
        git_repo_relative = None if git_repo_relative_raw is None else str(git_repo_relative_raw).strip("/")
        if git_repo_relative and (
            Path(git_repo_relative).is_absolute()
            or ".." in Path(git_repo_relative).parts
            or "\\" in git_repo_relative
        ):
            raise ValueError("git_repo_relative er ugyldig.")
        deployment_marker_raw = raw.get("deployment_marker_relative")
        deployment_marker_relative = None if deployment_marker_raw is None else str(deployment_marker_raw).strip("/")
        if deployment_marker_relative and (
            Path(deployment_marker_relative).is_absolute()
            or ".." in Path(deployment_marker_relative).parts
            or "\\" in deployment_marker_relative
        ):
            raise ValueError("deployment_marker_relative er ugyldig.")
        local_mirror_raw = raw.get("local_mirror_root")
        local_mirror_root = None if local_mirror_raw is None else Path(str(local_mirror_raw))
        if local_mirror_root is not None and (
            not local_mirror_root.is_absolute()
            or local_mirror_root == Path(local_mirror_root.anchor)
        ):
            raise ValueError("local_mirror_root skal være en sikker absolut mappe.")
        worker_path = str(raw.get("worker_path", "worker")).strip("/")
        worker_parts = Path(worker_path).parts
        if (
            not worker_path
            or Path(worker_path).is_absolute()
            or ".." in worker_parts
            or "\\" in worker_path
        ):
            raise ValueError("worker_path er ugyldig.")
        required = raw.get("required_commands")
        if not isinstance(required, list) or not required:
            raise ValueError("required_commands skal indeholde mindst én testkommando.")
        denied = raw.get("bootstrap_paths_denied")
        if not isinstance(denied, list) or not denied:
            raise ValueError("bootstrap_paths_denied må ikke være tom.")

        def bounded_int(name: str, minimum: int, maximum: int) -> int:
            value = raw.get(name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not minimum <= value <= maximum
            ):
                raise ValueError(f"{name} er uden for det tilladte interval.")
            return value

        return cls(
            enabled=bool(raw.get("enabled", False)),
            repositories=tuple(repositories),
            installation_root=root,
            active_pointer=active,
            git_repo_relative=git_repo_relative,
            local_mirror_root=local_mirror_root,
            deployment_marker_relative=deployment_marker_relative,
            max_download_bytes=bounded_int(
                "max_download_bytes", 1024, 500_000_000
            ),
            prepare_ttl_seconds=bounded_int(
                "prepare_ttl_seconds", 30, 86_400
            ),
            fetch_timeout_seconds=bounded_int(
                "fetch_timeout_seconds", 1, 600
            ),
            test_timeout_seconds=bounded_int(
                "test_timeout_seconds", 1, 3600
            ),
            required_commands=tuple(str(item) for item in required),
            bootstrap_paths_denied=tuple(str(item) for item in denied),
            worker_path=worker_path,
        )

    @classmethod
    def from_path(cls, path: Path) -> "ReleasePolicy":
        if not path.is_file():
            return cls.disabled(f"Release policy mangler: {path}")
        try:
            text = path.read_text(encoding="utf-8")
            lines = [
                line
                for line in text.splitlines()
                if not line.lstrip().startswith("#")
            ]
            return cls.from_mapping(json.loads("\n".join(lines)))
        except (OSError, json.JSONDecodeError, ValueError, SuiteBridgeError) as err:
            return cls.disabled(f"Release policy er ugyldig: {err}")

    def authorize(self, repository: str, ref: str) -> RepositoryPolicy:
        if not self.enabled:
            raise SuiteBridgeError(
                "RELEASE_POLICY_DISABLED",
                self.error or "Git-release er lokalt deaktiveret.",
                403,
            )
        normalized = _normalized_repository(repository)
        selected = next(
            (item for item in self.repositories if item.url == normalized), None
        )
        if selected is None:
            raise SuiteBridgeError(
                "RELEASE_REPOSITORY_DENIED",
                "Repository er ikke allowlistet.",
                403,
            )
        candidates = {ref}
        if ref.startswith("v"):
            candidates.add(f"refs/tags/{ref}")
        allowed = any(
            fnmatch.fnmatchcase(candidate, pattern)
            for pattern in selected.allowed_refs
            for candidate in candidates
        )
        if ref == "next" and not selected.allow_branch_head:
            allowed = False
        if not allowed:
            raise SuiteBridgeError(
                "RELEASE_REF_DENIED",
                "Git-ref er ikke allowlistet.",
                403,
            )
        if ref not in {"next"} and not (
            ref.startswith("refs/tags/v")
            or ref.startswith("v")
            or ref.startswith("refs/heads/")
            or _COMMIT_RE.fullmatch(ref)
        ):
            raise SuiteBridgeError(
                "RELEASE_REF_DENIED",
                "Kun next, allowlistede brancher, konkrete commits eller v-tags er tilladt.",
                403,
            )
        return selected


@dataclass(frozen=True, slots=True)
class SourceMaterial:
    root: Path
    commit: str
    repository: str
    ref: str
    downloaded_bytes: int


class GitHubReleaseSource:
    """Resolve and download only allowlisted github.com repository archives."""

    def __init__(self, local_mirror_root: Path | None = None) -> None:
        self.local_mirror_root = local_mirror_root

    @staticmethod
    def _coordinates(repository: str) -> tuple[str, str]:
        match = _GITHUB_REPO_RE.fullmatch(repository)
        if match is None:
            raise SuiteBridgeError(
                "RELEASE_REPOSITORY_DENIED", "Repository-URL er ugyldig.", 403
            )
        return match.group("owner"), match.group("repo")

    @staticmethod
    def _get_json(url: str, timeout: int, limit: int) -> dict[str, Any]:
        request = Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "home-assistant-one-bridge-release/0.9.1",
            },
        )
        with urlopen(request, timeout=timeout) as response:
            data = response.read(limit + 1)
        if len(data) > limit:
            raise SuiteBridgeError(
                "RELEASE_METADATA_TOO_LARGE",
                "GitHub metadata overskred størrelsesgrænsen.",
                403,
            )
        try:
            value = json.loads(data)
        except (json.JSONDecodeError, UnicodeDecodeError) as err:
            raise SuiteBridgeError(
                "RELEASE_RESOLVE_FAILED", "GitHub returnerede ugyldig metadata.", 502
            ) from err
        if not isinstance(value, dict):
            raise SuiteBridgeError(
                "RELEASE_RESOLVE_FAILED", "GitHub metadata havde forkert type.", 502
            )
        return value

    def _local_mirrors(self) -> tuple[Path, ...]:
        """Return policy-configured HA-local mirrors when available."""
        if self.local_mirror_root is None:
            return ()
        mirrors = [self.local_mirror_root / "repo"]
        mirrors.extend(sorted(self.local_mirror_root.glob("staging-*")))
        return tuple(path for path in mirrors if path.is_dir())

    def _resolve_local(self, ref: str) -> str | None:
        candidates = [ref]
        if ref == "next":
            candidates.insert(0, "refs/remotes/origin/next")
        if ref.startswith("refs/heads/"):
            candidates.append("HEAD")
        for mirror in self._local_mirrors():
            for candidate in candidates:
                try:
                    completed = subprocess.run(
                        ["git", "-c", "safe.directory=*", "-C", str(mirror), "rev-parse", f"{candidate}^{{commit}}"],
                        text=True,
                        capture_output=True,
                        check=True,
                        timeout=15,
                    )
                except (OSError, subprocess.SubprocessError):
                    continue
                commit = completed.stdout.strip().lower()
                if _COMMIT_RE.fullmatch(commit):
                    return commit
        return None

    def _materialize_local(
        self,
        repository: str,
        ref: str,
        commit: str,
        destination: Path,
        max_bytes: int,
    ) -> SourceMaterial | None:
        mirror = None
        for candidate in self._local_mirrors():
            try:
                subprocess.run(
                    ["git", "-c", "safe.directory=*", "-C", str(candidate), "cat-file", "-e", f"{commit}^{{commit}}"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=True,
                    timeout=15,
                )
                mirror = candidate
                break
            except (OSError, subprocess.SubprocessError):
                continue
        if mirror is None:
            return None
        archive = destination / "source.tar"
        try:
            with archive.open("wb") as handle:
                subprocess.run(
                    ["git", "-c", "safe.directory=*", "-C", str(mirror), "archive", "--format=tar", commit],
                    stdout=handle, stderr=subprocess.PIPE, check=True, timeout=60,
                )
            downloaded = archive.stat().st_size
            if downloaded > max_bytes:
                raise SuiteBridgeError("RELEASE_ARTIFACT_TOO_LARGE", "Release artifact overskred størrelsesgrænsen.", 403)
            extract_root = destination / "source" / "repository"
            extract_root.mkdir(parents=True)
            expanded = 0
            with tarfile.open(archive, "r") as package:
                for item in package.getmembers():
                    expanded += item.size
                    if expanded > max_bytes or item.issym() or item.islnk():
                        raise SuiteBridgeError("RELEASE_ARTIFACT_INVALID", "Release artifact indeholder en usikker fil.", 403)
                    target = (extract_root / item.name).resolve()
                    if target != extract_root.resolve() and extract_root.resolve() not in target.parents:
                        raise SuiteBridgeError("RELEASE_ARTIFACT_INVALID", "Release artifact indeholder en usikker sti.", 403)
                package.extractall(extract_root)
        except SuiteBridgeError:
            raise
        except (OSError, subprocess.SubprocessError, tarfile.TarError) as err:
            return None
        return SourceMaterial(root=extract_root, commit=commit, repository=repository, ref=ref, downloaded_bytes=downloaded)

    def resolve(
        self, repository: str, ref: str, *, timeout: int
    ) -> str:
        owner, repo = self._coordinates(repository)
        url = (
            f"https://api.github.com/repos/{quote(owner)}/{quote(repo)}/commits/"
            f"{quote(ref, safe='')}"
        )
        try:
            value = self._get_json(url, timeout, 1_000_000)
        except SuiteBridgeError:
            local = self._resolve_local(ref)
            if local:
                return local
            raise
        except Exception as err:
            local = self._resolve_local(ref)
            if local:
                return local
            raise SuiteBridgeError(
                "RELEASE_RESOLVE_FAILED",
                f"Git-ref kunne ikke resolves: {type(err).__name__}",
                502,
            ) from err
        commit = str(value.get("sha", "")).lower()
        if not _COMMIT_RE.fullmatch(commit):
            local = self._resolve_local(ref)
            if local:
                return local
            raise SuiteBridgeError(
                "RELEASE_RESOLVE_FAILED",
                "Git-ref blev ikke resolved til en konkret commit-SHA.",
                502,
            )
        return commit

    def materialize(
        self,
        repository: str,
        ref: str,
        destination: Path,
        *,
        timeout: int,
        max_bytes: int,
    ) -> SourceMaterial:
        commit = self.resolve(repository, ref, timeout=timeout)
        owner, repo = self._coordinates(repository)
        archive_url = (
            f"https://api.github.com/repos/{quote(owner)}/{quote(repo)}/zipball/"
            f"{commit}"
        )
        request = Request(
            archive_url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "gpt-suite-bridge-release/2.1",
            },
        )
        archive = destination / "source.zip"
        downloaded = 0
        try:
            with urlopen(request, timeout=timeout) as response, archive.open("wb") as out:
                while True:
                    chunk = response.read(min(1024 * 1024, max_bytes + 1))
                    if not chunk:
                        break
                    downloaded += len(chunk)
                    if downloaded > max_bytes:
                        raise SuiteBridgeError(
                            "RELEASE_ARTIFACT_TOO_LARGE",
                            "Release artifact overskred størrelsesgrænsen.",
                            403,
                        )
                    out.write(chunk)
        except SuiteBridgeError:
            raise
        except Exception as err:
            local = self._materialize_local(repository, ref, commit, destination, max_bytes)
            if local is not None:
                return local
            raise SuiteBridgeError(
                "RELEASE_FETCH_FAILED",
                f"Release artifact kunne ikke hentes: {type(err).__name__}",
                502,
            ) from err

        extract_root = destination / "source"
        extract_root.mkdir()
        expanded = 0
        try:
            with zipfile.ZipFile(archive) as package:
                for item in package.infolist():
                    expanded += item.file_size
                    if expanded > max_bytes:
                        raise SuiteBridgeError(
                            "RELEASE_ARTIFACT_TOO_LARGE",
                            "Udpakket release overskred størrelsesgrænsen.",
                            403,
                        )
                    mode = item.external_attr >> 16
                    if stat.S_ISLNK(mode):
                        raise SuiteBridgeError(
                            "RELEASE_ARTIFACT_INVALID",
                            "Links er ikke tilladt i release artifacts.",
                            403,
                        )
                    target = (extract_root / item.filename).resolve()
                    if (
                        target != extract_root.resolve()
                        and extract_root.resolve() not in target.parents
                    ):
                        raise SuiteBridgeError(
                            "RELEASE_ARTIFACT_INVALID",
                            "Release artifact indeholder en usikker sti.",
                            403,
                        )
                package.extractall(extract_root)
        except SuiteBridgeError:
            raise
        except (OSError, zipfile.BadZipFile) as err:
            raise SuiteBridgeError(
                "RELEASE_ARTIFACT_INVALID",
                "Release artifact er ikke en gyldig ZIP-fil.",
                403,
            ) from err
        roots = [path for path in extract_root.iterdir() if path.is_dir()]
        if len(roots) != 1:
            raise SuiteBridgeError(
                "RELEASE_ARTIFACT_INVALID",
                "Release artifact skal have præcis én repository-root.",
                403,
            )
        return SourceMaterial(
            root=roots[0],
            commit=commit,
            repository=repository,
            ref=ref,
            downloaded_bytes=downloaded,
        )


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


class ReleaseManager:
    """Prepare and apply a worker release while the bootstrap remains untouched."""

    def __init__(
        self,
        policy: ReleasePolicy,
        prepared: PreparedMutationStore,
        *,
        audit: Any = None,
        loader: WorkerLoader | None = None,
        source: Any = None,
        run_blocking: Callable[..., Awaitable[Any]] | None = None,
    ) -> None:
        self.policy = policy
        self.prepared = prepared
        self.audit = audit
        self.loader = loader or WorkerLoader()
        self.source = source or GitHubReleaseSource(policy.local_mirror_root)
        self.run_blocking = run_blocking
        self.idempotency = IdempotencyStore()
        self.apply_count = 0

    @property
    def releases_root(self) -> Path:
        return self.policy.installation_root / "releases"

    @property
    def state_path(self) -> Path:
        return self.policy.installation_root / "release-state.json"

    async def _blocking(self, function: Callable[..., Any], *args: Any) -> Any:
        if self.run_blocking is not None:
            return await self.run_blocking(function, *args)
        return await asyncio.to_thread(function, *args)

    async def _audit(self, entry: dict[str, Any]) -> None:
        if self.audit is not None:
            await self.audit.append(redact(entry))

    def _active(self) -> dict[str, Any] | None:
        return _read_json(self.policy.active_pointer)

    def status(self) -> dict[str, Any]:
        state = _read_json(self.state_path) or {}
        active = self._active()
        return {
            "enabled": self.policy.enabled,
            "policy_error": self.policy.error,
            "installation_root": str(self.policy.installation_root),
            "active": active,
            "active_worker_version": (active or {}).get("worker_version"),
            "active_commit": (active or {}).get("commit"),
            "previous_good": state.get("previous_good"),
            "staged": state.get("staged"),
            "last_smoke_test": state.get("last_smoke_test"),
            "rollback": state.get("rollback"),
        }

    @staticmethod
    def _tree_size(root: Path) -> int:
        total = 0
        for path in root.rglob("*"):
            if path.is_symlink():
                raise SuiteBridgeError(
                    "RELEASE_ARTIFACT_INVALID",
                    "Links er ikke tilladt i release-kilden.",
                    403,
                )
            if path.is_file():
                total += path.stat().st_size
        return total

    def _expand_command(self, command: str, root: Path) -> list[str]:
        try:
            tokens = shlex.split(command, posix=True)
        except ValueError as err:
            raise SuiteBridgeError(
                "RELEASE_TEST_POLICY_INVALID",
                "En obligatorisk testkommando er ugyldig.",
                500,
            ) from err
        if not tokens:
            raise SuiteBridgeError(
                "RELEASE_TEST_POLICY_INVALID", "Tom testkommando er ikke tilladt.", 500
            )
        executable = tokens[0]
        if executable in {"python", "python3"}:
            tokens[0] = sys.executable
        elif executable not in {"bash", "sh"}:
            raise SuiteBridgeError(
                "RELEASE_TEST_POLICY_INVALID",
                f"Ikke-allowlistet testprogram: {executable}",
                500,
            )
        expanded = [tokens[0]]
        for token in tokens[1:]:
            if any(character in token for character in "*?["):
                matches = sorted(root.glob(token))
                if not matches:
                    raise SuiteBridgeError(
                        "RELEASE_TEST_POLICY_INVALID",
                        f"Testkommandoens glob matchede ingen filer: {token}",
                        500,
                    )
                for match in matches:
                    resolved = match.resolve()
                    if root.resolve() not in resolved.parents:
                        raise SuiteBridgeError(
                            "RELEASE_TEST_POLICY_INVALID",
                            "Testkommando forsøgte at forlade release-root.",
                            500,
                        )
                    expanded.append(str(resolved))
            else:
                expanded.append(token)
        return expanded

    def _run_tests(self, root: Path) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        for command in self.policy.required_commands:
            arguments = self._expand_command(command, root)
            try:
                completed = subprocess.run(
                    arguments,
                    cwd=root,
                    env=environment,
                    text=True,
                    capture_output=True,
                    timeout=self.policy.test_timeout_seconds,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as err:
                raise SuiteBridgeError(
                    "RELEASE_TEST_FAILED",
                    f"Obligatorisk test kunne ikke køres: {type(err).__name__}",
                    409,
                ) from err
            result = {
                "command": command,
                "returncode": completed.returncode,
                "stdout": redact(completed.stdout[-4_000:]),
                "stderr": redact(completed.stderr[-4_000:]),
            }
            results.append(result)
            if completed.returncode != 0:
                raise SuiteBridgeError(
                    "RELEASE_TEST_FAILED",
                    f"Obligatorisk test fejlede: {command}",
                    409,
                    details={"test": result},
                )
        return results

    def _prepare_blocking(
        self, repository: str, ref: str, expected_active: str | None
    ) -> dict[str, Any]:
        self.policy.installation_root.mkdir(parents=True, exist_ok=True)
        self.releases_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix=".prepare-", dir=self.policy.installation_root
        ) as temporary_text:
            temporary = Path(temporary_text)
            try:
                material: SourceMaterial = self.source.materialize(
                    repository,
                    ref,
                    temporary,
                    timeout=self.policy.fetch_timeout_seconds,
                    max_bytes=self.policy.max_download_bytes,
                )
            except SuiteBridgeError:
                raise
            except Exception as err:
                raise SuiteBridgeError(
                    "RELEASE_FETCH_FAILED",
                    f"Release-kilden fejlede: {type(err).__name__}",
                    502,
                ) from err
            if not _COMMIT_RE.fullmatch(material.commit):
                raise SuiteBridgeError(
                    "RELEASE_RESOLVE_FAILED",
                    "Release-kilden returnerede ikke en konkret commit-SHA.",
                    502,
                )
            release_root = material.root.resolve()
            if self._tree_size(release_root) > self.policy.max_download_bytes:
                raise SuiteBridgeError(
                    "RELEASE_ARTIFACT_TOO_LARGE",
                    "Udpakket release overskred størrelsesgrænsen.",
                    403,
                )
            tests = self._run_tests(release_root)
            worker_source = (release_root / self.policy.worker_path).resolve()
            if (
                release_root not in worker_source.parents
                or not worker_source.is_dir()
                or worker_source.is_symlink()
            ):
                raise SuiteBridgeError(
                    "WORKER_SOURCE_MISSING",
                    f"Release mangler worker_path {self.policy.worker_path}.",
                    409,
                )
            for path in worker_source.rglob("*"):
                relative = path.resolve().relative_to(release_root).as_posix()
                if any(
                    fnmatch.fnmatchcase(relative, pattern)
                    for pattern in self.policy.bootstrap_paths_denied
                ):
                    raise SuiteBridgeError(
                        "BOOTSTRAP_PATH_DENIED",
                        f"Worker artifact indeholder en beskyttet sti: {relative}",
                        403,
                    )
            incoming = self.releases_root / f".incoming-{uuid.uuid4().hex}"
            shutil.copytree(worker_source, incoming)
            manifest = self.loader.verify(incoming)
            load_test = self.loader.load_test(incoming)
            safe_version = _SAFE_VERSION_RE.sub("-", manifest["worker_version"])
            release_id = f"{material.commit}-{safe_version}"
            slot = self.releases_root / release_id
            if slot.exists():
                existing = _read_json(slot / "release.json")
                if existing is None or existing.get("commit") != material.commit:
                    raise SuiteBridgeError(
                        "RELEASE_SLOT_CONFLICT",
                        "Et eksisterende worker-slot matcher ikke releasen.",
                        409,
                    )
                shutil.rmtree(incoming)
                load_test = self.loader.load_test(slot)
            else:
                metadata = {
                    "release_id": release_id,
                    "repository": repository,
                    "ref": ref,
                    "commit": material.commit,
                    "worker_version": manifest["worker_version"],
                    "staged_at": utc_now_iso(),
                }
                _atomic_json(incoming / "release.json", metadata)
                os.replace(incoming, slot)
            return {
                "release_id": release_id,
                "repository": repository,
                "ref": ref,
                "commit": material.commit,
                "worker_version": manifest["worker_version"],
                "slot": str(slot),
                "expected_active_commit": expected_active,
                "downloaded_bytes": material.downloaded_bytes,
                "tests": tests,
                "worker_load_test": load_test,
            }

    async def prepare(
        self,
        arguments: dict[str, Any],
        *,
        user_id: str,
        refresh_token_id: str,
    ) -> dict[str, Any]:
        repository = _normalized_repository(str(arguments["repository"]))
        ref = str(arguments["ref"])
        self.policy.authorize(repository, ref)
        active = self._active()
        active_commit = (active or {}).get("commit")
        expected = arguments.get("expected_active_commit")
        if expected is not None and expected != active_commit:
            raise SuiteBridgeError(
                "ACTIVE_RELEASE_CHANGED",
                "Aktiv worker matcher ikke expected_active_commit.",
                409,
            )
        staged = await self._blocking(
            self._prepare_blocking, repository, ref, active_commit
        )
        item = await self.prepared.create(
            user_id=user_id,
            refresh_token_id=refresh_token_id,
            operation="release.apply",
            normalized_change={
                "repository": repository,
                "ref": ref,
                "commit": staged["commit"],
                "expected_active_commit": active_commit,
            },
            material=staged,
            risk="critical",
        )
        state = _read_json(self.state_path) or {}
        state.update(
            {
                "staged": {
                    "release_id": staged["release_id"],
                    "commit": staged["commit"],
                    "worker_version": staged["worker_version"],
                    "prepare_id": item.prepare_id,
                    "expires_at": item.expires_at,
                },
                "updated_at": utc_now_iso(),
            }
        )
        await self._blocking(_atomic_json, self.state_path, state)
        await self._audit(
            {
                "operation": "release.prepare",
                "user_id": user_id,
                "repository": repository,
                "ref": ref,
                "commit": staged["commit"],
                "prepare_id": item.prepare_id,
                "result": "prepared",
            }
        )
        return {
            **staged,
            "prepare_id": item.prepare_id,
            "digest": item.digest,
            "expires_at": item.expires_at,
            "active_unchanged": self._active() == active,
        }

    def _restore_pointer(self, previous: dict[str, Any] | None) -> None:
        if previous is None:
            try:
                self.policy.active_pointer.unlink()
            except FileNotFoundError:
                pass
        else:
            _atomic_json(self.policy.active_pointer, previous)

    def _apply_blocking(self, item: PreparedMutation) -> dict[str, Any]:
        material = item.material
        slot = Path(str(material["slot"])).resolve()
        releases = self.releases_root.resolve()
        if releases not in slot.parents or not slot.is_dir():
            raise SuiteBridgeError(
                "RELEASE_SLOT_INVALID", "Prepared worker-slot er ikke længere gyldigt.", 409
            )
        previous = self._active()
        previous_commit = (previous or {}).get("commit")
        if previous_commit != material.get("expected_active_commit"):
            raise SuiteBridgeError(
                "ACTIVE_RELEASE_CHANGED",
                "Aktiv worker har ændret sig siden prepare.",
                409,
            )
        pointer = {
            "release_id": material["release_id"],
            "commit": material["commit"],
            "worker_version": material["worker_version"],
            "slot": str(slot),
            "activated_at": utc_now_iso(),
        }
        _atomic_json(self.policy.active_pointer, pointer)
        self.apply_count += 1
        try:
            _, _, verification = self.loader.load(
                slot,
                context={"release": pointer},
                activate=True,
            )
        except Exception as activation_error:
            self._restore_pointer(previous)
            rollback_load: dict[str, Any] | None = None
            rollback_error: str | None = None
            if previous is not None and previous.get("slot"):
                try:
                    _, _, rollback_load = self.loader.load(
                        Path(str(previous["slot"])),
                        context={"release": previous, "rollback": True},
                        activate=True,
                    )
                except Exception as err:
                    rollback_error = type(err).__name__
            else:
                self.loader.active_worker = None
                self.loader.active_release = None
            rollback = {
                "performed": True,
                "restored_commit": previous_commit,
                "trigger": type(activation_error).__name__,
                "worker_reload": rollback_load,
                "worker_reload_error": rollback_error,
                "at": utc_now_iso(),
            }
            state = _read_json(self.state_path) or {}
            state.update(
                {
                    "last_smoke_test": {
                        "ok": False,
                        "commit": material["commit"],
                        "error": type(activation_error).__name__,
                        "at": utc_now_iso(),
                    },
                    "rollback": rollback,
                    "staged": None,
                    "updated_at": utc_now_iso(),
                }
            )
            _atomic_json(self.state_path, state)
            return {
                "activated": False,
                "active": previous,
                "attempted": pointer,
                "verification": {"ok": False},
                "rollback": rollback,
            }
        state = _read_json(self.state_path) or {}
        state.update(
            {
                "previous_good": previous,
                "staged": None,
                "last_smoke_test": {
                    "ok": True,
                    "commit": material["commit"],
                    "details": verification,
                    "at": utc_now_iso(),
                },
                "rollback": None,
                "updated_at": utc_now_iso(),
            }
        )
        _atomic_json(self.state_path, state)
        return {
            "activated": True,
            "active": pointer,
            "previous_good": previous,
            "verification": {"ok": True, **verification},
            "rollback": None,
        }

    async def apply(
        self,
        arguments: dict[str, Any],
        *,
        user_id: str,
        refresh_token_id: str,
    ) -> dict[str, Any]:
        prepare_id = str(arguments.get("prepare_id", "")).strip()
        expected_digest = str(arguments.get("expected_digest", "")).strip()
        idempotency_key = str(arguments.get("idempotency_key", "")).strip()
        if not prepare_id:
            raise SuiteBridgeError(
                "PREPARE_ID_REQUIRED", "prepare_id er obligatorisk.", 409
            )
        fingerprint = json.dumps(
            {
                "prepare_id": prepare_id,
                "expected_digest": expected_digest,
                "user_id": user_id,
                "refresh_token_id": refresh_token_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        execute, cached = await self.idempotency.begin(
            idempotency_key, fingerprint
        )
        if not execute:
            return {**(cached or {}), "idempotent_replay": True}
        try:
            item = await self.prepared.begin_apply(
                prepare_id=prepare_id,
                digest=expected_digest,
                user_id=user_id,
                refresh_token_id=refresh_token_id,
                confirmed=arguments.get("confirmed") is True,
                confirmation_text=None,
            )
            if item.operation != "release.apply":
                raise SuiteBridgeError(
                    "PREPARE_OPERATION_MISMATCH",
                    "prepare_id tilhører ikke release.apply.",
                    409,
                )
            result = await self._blocking(self._apply_blocking, item)
            await self.prepared.finish(prepare_id, consume=True)
            await self.idempotency.finish(idempotency_key, fingerprint, result)
            await self._audit(
                {
                    "operation": "release.apply",
                    "user_id": user_id,
                    "prepare_id": prepare_id,
                    "commit": item.material.get("commit"),
                    "result": "executed" if result["activated"] else "rolled_back",
                    "rollback": result.get("rollback"),
                }
            )
            return result
        except Exception:
            await self.idempotency.abort(idempotency_key, fingerprint)
            raise
