"""Strict, extensible Git, preview and bootstrap maintenance areas."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any

from .models import SuiteBridgeError


_COMMIT_MESSAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .,:;()/_-]{7,159}$")
_HEX_RE = re.compile(r"^[0-9a-f]{40}$")
_PREVIEW_VERSION_RE = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$")
_PUBLIC_COMMIT_RE = re.compile(r"^Commit: ([0-9a-f]{40})$", re.MULTILINE)
_STATE_LINE_RE = re.compile(r"^([A-Z_]+)='([^'\n]*)'$")
_SENSITIVE_PATH = re.compile(r"(^|/)(?:\.storage|secrets?\.ya?ml|.*(?:token|secret|credential|private[_-]?key).*)$", re.IGNORECASE)
_SENSITIVE_TEXT = re.compile(r"(?i)(?:access_token|api_key|client_secret|password|private_key|refresh_token)\s*[:=]")
_PREVIEW_SECRET_TEXT = re.compile(
    rb"-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----|"
    rb"github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}"
)
_PREVIEW_SCRIPT_RELATIVE = "scripts/build-release.sh"
_PREVIEW_PUBLIC_REPO_SSH = "git@github.com:TorbenAT/home-assistant-one-bridge.git"
_PREVIEW_KEY_RELATIVE = "gpt-ha-bridge-suite/private/github/home-assistant-one-bridge_ed25519"
_PREVIEW_KNOWN_HOSTS_RELATIVE = "gpt-ha-bridge-suite/private/github/known_hosts"
_SOURCE_PRIVATE_REMOTE_PREFIX = "ssh://git@ssh.github.com:443/"
_SOURCE_KEY_PATH = Path("/share/homeassistantbridge-source/keys/source_ed25519")
_SOURCE_KNOWN_HOSTS_RELATIVE = "gpt-ha-bridge-suite/private/github/known_hosts"
_RELEASE_CANDIDATE_REF = "refs/heads/next"
_PUBLIC_MAIN_REF = "refs/heads/main"
_BOOTSTRAP_INSTALL_RELATIVE = "install.sh"
_BOOTSTRAP_ACTIVATE_RELATIVE = "activate.sh"
_BOOTSTRAP_PENDING_RELATIVE = "gpt-ha-bridge-suite/PENDING_BOOTSTRAP.env"
_BOOTSTRAP_LAST_RELATIVE = "gpt-ha-bridge-suite/LAST_BOOTSTRAP.env"
_BOOTSTRAP_BACKUP_RELATIVE = "gpt-ha-bridge-backups"
_BOOTSTRAP_CONFIRMATION = "BEKRÆFT AKTIVER ONE BRIDGE BOOTSTRAP"


@dataclass(frozen=True, slots=True)
class GitCommitArea:
    """One explicit repository area; extension is a new static entry."""

    name: str
    relative_repo: str
    allowed_branches: tuple[str, ...]
    allowed_paths: tuple[str, ...]
    expected_remote_suffix: str
    source_push_ssh: bool = False
    precommit_script: str | None = None


def default_git_commit_areas(
    expected_remote_suffix: str | None,
    relative_repo: str | None,
) -> dict[str, GitCommitArea]:
    if not expected_remote_suffix or not relative_repo:
        return {}
    return {
        "bridge": GitCommitArea(
            name="bridge",
            relative_repo=relative_repo,
            allowed_branches=("main",),
            allowed_paths=(
                "AGENTS.md", "CHANGELOG.md", "CURRENT_STATE.md", "README-DK.md", "SOURCE-HA.md", "VERSION",
                ".github/workflows/validate.yml",
                "activate.sh", "install.sh", "rollback.sh",
                "bridge_contract", "custom_components/one_bridge",
                "gpt-manual", "scripts", "tests", "worker",
            ),
            expected_remote_suffix=expected_remote_suffix,
            source_push_ssh=True,
            precommit_script="scripts/check-full.sh",
        )
    }


class GitCommitManager:
    """Inspect, commit, preview-publish and bootstrap one registered Git area."""

    def __init__(self, config_root: Path, areas: dict[str, GitCommitArea] | None = None) -> None:
        self.config_root = config_root.resolve()
        self.areas = areas if areas is not None else {}

    def _area(self, name: str) -> GitCommitArea:
        area = self.areas.get(name)
        if area is None:
            raise SuiteBridgeError("GIT_AREA_DENIED", "Git-omradet er ikke tilladt.", 403)
        return area

    def _repo(self, area: GitCommitArea) -> Path:
        repo = (self.config_root / area.relative_repo).resolve()
        if self.config_root not in repo.parents or not (repo / ".git").is_dir():
            raise SuiteBridgeError("GIT_REPOSITORY_UNAVAILABLE", "Det tilladte Git-repository findes ikke.", 503)
        return repo

    @staticmethod
    def _run(repo: Path, arguments: list[str], *, text: bool = True) -> str | bytes:
        environment = os.environ.copy()
        environment.update({"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"})
        try:
            completed = subprocess.run(
                ["git", "-C", str(repo), *arguments], check=False,
                capture_output=True, timeout=20, env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as err:
            raise SuiteBridgeError("GIT_COMMAND_FAILED", "Git-handlingen kunne ikke udfores.", 503) from err
        if completed.returncode != 0:
            raise SuiteBridgeError("GIT_COMMAND_FAILED", "Git-handlingen blev afvist.", 409)
        return completed.stdout.decode("utf-8", errors="replace") if text else completed.stdout

    def _run_source_remote(self, repo: Path, arguments: list[str]) -> str:
        remote = str(self._run(repo, ["config", "--get", "remote.origin.url"])).strip()
        if not remote.startswith(_SOURCE_PRIVATE_REMOTE_PREFIX):
            return str(self._run(repo, arguments))
        known_hosts = (self.config_root / _SOURCE_KNOWN_HOSTS_RELATIVE).resolve()
        if self.config_root not in known_hosts.parents or not known_hosts.is_file():
            raise SuiteBridgeError("GIT_SOURCE_AUTH_UNAVAILABLE", "Private source known_hosts mangler.", 503)
        if not _SOURCE_KEY_PATH.is_file():
            raise SuiteBridgeError("GIT_SOURCE_AUTH_UNAVAILABLE", "Private source deploy-key mangler.", 503)
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_SSH_COMMAND": (
                    f"ssh -F /dev/null -i {_SOURCE_KEY_PATH} -o BatchMode=yes "
                    f"-o IdentitiesOnly=yes -o UserKnownHostsFile={known_hosts} "
                    "-o StrictHostKeyChecking=yes -o HostKeyAlias=github.com"
                ),
            }
        )
        try:
            completed = subprocess.run(
                ["git", "-C", str(repo), *arguments],
                check=False,
                capture_output=True,
                timeout=30,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as err:
            raise SuiteBridgeError("GIT_SOURCE_AUTH_FAILED", "Private source Git-handling kunne ikke udfores.", 503) from err
        if completed.returncode != 0:
            raise SuiteBridgeError("GIT_SOURCE_AUTH_FAILED", "Private source Git-handling blev afvist.", 409)
        return completed.stdout.decode("utf-8", errors="replace")

    def _public_environment(self) -> dict[str, str]:
        key_file = (self.config_root / _PREVIEW_KEY_RELATIVE).resolve()
        known_hosts = (self.config_root / _PREVIEW_KNOWN_HOSTS_RELATIVE).resolve()
        if self.config_root not in key_file.parents or self.config_root not in known_hosts.parents:
            raise SuiteBridgeError("GIT_PUBLIC_AUTH_UNAVAILABLE", "Public Git auth-stien er ugyldig.", 500)
        if not key_file.is_file() or not known_hosts.is_file():
            raise SuiteBridgeError("GIT_PUBLIC_AUTH_UNAVAILABLE", "Public deploy-key eller known_hosts mangler.", 503)
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_SSH_COMMAND": (
                    f"ssh -i {key_file} -o IdentitiesOnly=yes "
                    f"-o UserKnownHostsFile={known_hosts} -o StrictHostKeyChecking=yes"
                ),
            }
        )
        return environment

    def _run_public_git(self, arguments: list[str], *, timeout: int = 60) -> str:
        try:
            completed = subprocess.run(
                ["git", *arguments], check=False, capture_output=True,
                timeout=timeout, env=self._public_environment(),
            )
        except (OSError, subprocess.TimeoutExpired) as err:
            raise SuiteBridgeError("GIT_PUBLIC_COMMAND_FAILED", "Public Git-handlingen kunne ikke udfores.", 503) from err
        if completed.returncode != 0:
            raise SuiteBridgeError("GIT_PUBLIC_COMMAND_FAILED", "Public Git-handlingen blev afvist.", 409)
        return completed.stdout.decode("utf-8", errors="replace")

    def _public_status_from_clone(self, clone: Path) -> dict[str, Any]:
        branch = str(self._run(clone, ["branch", "--show-current"])).strip()
        if branch != "main":
            raise SuiteBridgeError("GIT_PUBLIC_BRANCH_DENIED", "Public repository er ikke paa main.", 409)
        head = str(self._run(clone, ["rev-parse", "HEAD"])).strip()
        roots = [item for item in str(self._run(clone, ["rev-list", "--max-parents=0", "HEAD"])).splitlines() if item]
        if len(roots) != 1 or not _HEX_RE.fullmatch(roots[0]):
            raise SuiteBridgeError("GIT_PUBLIC_ROOT_INVALID", "Public repository har ikke én entydig root commit.", 409)
        root = roots[0]
        root_files = [item for item in str(self._run(clone, ["ls-tree", "--name-only", root])).splitlines() if item]
        try:
            commit_count = int(str(self._run(clone, ["rev-list", "--count", "HEAD"])).strip())
        except ValueError as err:
            raise SuiteBridgeError("GIT_PUBLIC_HISTORY_INVALID", "Public commit count er ugyldig.", 409) from err
        commits: list[dict[str, str]] = []
        for line in str(self._run(clone, ["log", "-20", "--format=%H%x09%s"])).splitlines():
            fields = line.split("\t", 1)
            if len(fields) == 2 and _HEX_RE.fullmatch(fields[0]):
                commits.append({"commit": fields[0], "summary": fields[1][:160]})
        tags = sorted(item for item in str(self._run(clone, ["tag", "--list"])).splitlines() if item)
        return {
            "repository": "TorbenAT/home-assistant-one-bridge",
            "branch": branch,
            "head": head,
            "root_commit": root,
            "root_files": root_files,
            "commit_count": commit_count,
            "recent_commits": commits,
            "tags": tags,
        }

    def public_status(self) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="one-bridge-public-status-") as tmp:
            clone = Path(tmp) / "repo"
            self._run_public_git(["clone", "--quiet", _PREVIEW_PUBLIC_REPO_SSH, str(clone)], timeout=90)
            return self._public_status_from_clone(clone)

    @staticmethod
    def _allowed(path: str, area: GitCommitArea) -> bool:
        normalized = path.replace("\\", "/")
        while normalized.startswith("./"):
            normalized = normalized[2:]
        normalized = normalized.lstrip("/")
        return any(normalized == item or normalized.startswith(item + "/") for item in area.allowed_paths)

    @staticmethod
    def _porcelain(raw: str) -> list[dict[str, str]]:
        entries: list[dict[str, str]] = []
        for record in raw.split("\0"):
            if not record or len(record) < 4:
                continue
            if record[0] in {"R", "C"} or record[1] in {"R", "C"}:
                raise SuiteBridgeError(
                    "GIT_RENAME_COPY_DENIED",
                    "Git rename- og copy-aendringer maa ikke committes via Bridge.",
                    409,
                )
            entries.append({"index": record[0], "worktree": record[1], "path": record[3:].replace("\\", "/")})
        return entries

    def _identity(self, area: GitCommitArea) -> tuple[Path, str, str]:
        repo = self._repo(area)
        branch = str(self._run(repo, ["branch", "--show-current"])).strip()
        if branch not in area.allowed_branches:
            raise SuiteBridgeError("GIT_BRANCH_DENIED", "Den aktuelle Git-branch er ikke tilladt.", 409)
        head = str(self._run(repo, ["rev-parse", "HEAD"])).strip()
        if not _HEX_RE.fullmatch(head):
            raise SuiteBridgeError("GIT_HEAD_INVALID", "Git HEAD er ugyldig.", 409)
        remote = str(self._run(repo, ["config", "--get", "remote.origin.url"])).strip()
        if not remote.endswith(area.expected_remote_suffix):
            raise SuiteBridgeError("GIT_REMOTE_DENIED", "Git-origin matcher ikke det tilladte repository.", 409)
        return repo, branch, head

    def _clean_identity(
        self,
        area: GitCommitArea,
        *,
        code: str = "GIT_SOURCE_DIRTY",
        message: str = "Handlingen kraever et rent source-repository.",
    ) -> tuple[Path, str, str]:
        repo, branch, head = self._identity(area)
        status = str(self._run(repo, ["status", "--porcelain=v1", "--untracked-files=all"])).strip()
        if status:
            raise SuiteBridgeError(code, message, 409)
        return repo, branch, head

    def _snapshot(self, area: GitCommitArea) -> dict[str, Any]:
        repo, branch, head = self._identity(area)
        entries = self._porcelain(str(self._run(repo, ["status", "--porcelain=v1", "-z", "--untracked-files=all"])))
        if not entries:
            raise SuiteBridgeError("GIT_NOTHING_TO_COMMIT", "Der er ingen aendringer at committe.", 409)
        if any(not self._allowed(entry["path"], area) for entry in entries):
            raise SuiteBridgeError("GIT_AREA_DIRTY_OUTSIDE", "Der er Git-aendringer uden for den valgte allowlist.", 409)
        for entry in entries:
            if _SENSITIVE_PATH.search(entry["path"]):
                raise SuiteBridgeError("GIT_SENSITIVE_PATH_DENIED", "Folsomme filer maa ikke committes via Bridge.", 403)
        paths = [entry["path"] for entry in entries]
        diff = self._run(repo, ["diff", "--no-ext-diff", "--binary", "HEAD", "--", *paths], text=False)
        assert isinstance(diff, bytes)
        if len(diff) > 200_000:
            raise SuiteBridgeError("GIT_DIFF_TOO_LARGE", "Git-diffen er for stor til Bridge-commit.", 413)
        if _SENSITIVE_TEXT.search(diff.decode("utf-8", errors="replace")):
            raise SuiteBridgeError("GIT_SENSITIVE_CONTENT_DENIED", "Diffen indeholder et folsomt felt.", 403)
        status_sha256 = sha256("\n".join(f"{entry['index']}{entry['worktree']} {entry['path']}" for entry in entries).encode("utf-8")).hexdigest()
        return {"area": area.name, "branch": branch, "head": head, "entries": entries, "paths": paths, "status_sha256": status_sha256, "diff_sha256": sha256(diff).hexdigest()}

    @staticmethod
    def _script(repo: Path, relative: str, code: str) -> tuple[Path, str]:
        script = (repo / relative).resolve()
        if repo not in script.parents or not script.is_file():
            raise SuiteBridgeError(code, "Det faste maintenance-script findes ikke.", 503)
        return script, sha256(script.read_bytes()).hexdigest()

    @staticmethod
    def _read_state(path: Path, required: set[str], missing_code: str) -> dict[str, str]:
        if not path.is_file():
            raise SuiteBridgeError(missing_code, "Bootstrap-state blev ikke fundet.", 409)
        result: dict[str, str] = {}
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            match = _STATE_LINE_RE.fullmatch(raw_line)
            if match is None:
                raise SuiteBridgeError("BOOTSTRAP_STATE_INVALID", "Bootstrap-state har ugyldigt format.", 409)
            result[match.group(1)] = match.group(2)
        if not required <= result.keys():
            raise SuiteBridgeError("BOOTSTRAP_STATE_INVALID", "Bootstrap-state mangler obligatoriske felter.", 409)
        return result

    def _preview_secret_scan(self, repo: Path, area: GitCommitArea) -> None:
        raw = str(self._run(repo, ["ls-files", "-z", "--", *area.allowed_paths]))
        for relative in (item for item in raw.split("\0") if item):
            if not self._allowed(relative, area) or _SENSITIVE_PATH.search(relative):
                raise SuiteBridgeError("GIT_PREVIEW_SECRET_SCAN_FAILED", "Preview-kilden indeholder en folsom filsti.", 403)
            path = (repo / relative).resolve()
            if repo not in path.parents or not path.is_file():
                raise SuiteBridgeError("GIT_PREVIEW_SECRET_SCAN_FAILED", "Preview-kilden kunne ikke valideres.", 409)
            data = path.read_bytes()
            if _PREVIEW_SECRET_TEXT.search(data):
                raise SuiteBridgeError("GIT_PREVIEW_SECRET_SCAN_FAILED", "Preview-kilden indeholder et muligt secret-token eller en privat noegle.", 403)

    def _preview_snapshot(self, area: GitCommitArea, version: str) -> dict[str, Any]:
        if not _PREVIEW_VERSION_RE.fullmatch(version):
            raise SuiteBridgeError("GIT_PREVIEW_VERSION_INVALID", "Preview-versionen er ugyldig.", 422)
        repo, branch, head = self._clean_identity(
            area,
            code="GIT_PREVIEW_SOURCE_DIRTY",
            message="Preview-publicering kraever et rent source-repository.",
        )
        _, script_sha256 = self._script(repo, _PREVIEW_SCRIPT_RELATIVE, "GIT_PREVIEW_SCRIPT_MISSING")
        self._preview_secret_scan(repo, area)
        return {
            "area": area.name,
            "branch": branch,
            "head": head,
            "version": version,
            "script": _PREVIEW_SCRIPT_RELATIVE,
            "script_sha256": script_sha256,
        }

    def _verify_public_commit(self, public_commit: str) -> list[str]:
        key_file = (self.config_root / _PREVIEW_KEY_RELATIVE).resolve()
        known_hosts = (self.config_root / _PREVIEW_KNOWN_HOSTS_RELATIVE).resolve()
        if self.config_root not in key_file.parents or self.config_root not in known_hosts.parents:
            raise SuiteBridgeError("GIT_PREVIEW_VERIFY_FAILED", "Preview-verifikationsstien er ugyldig.", 500)
        if not key_file.is_file() or not known_hosts.is_file():
            raise SuiteBridgeError("GIT_PREVIEW_VERIFY_FAILED", "Preview deploy-key eller known_hosts mangler.", 503)
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_SSH_COMMAND": f"ssh -i {key_file} -o IdentitiesOnly=yes -o UserKnownHostsFile={known_hosts} -o StrictHostKeyChecking=yes",
            }
        )
        try:
            completed = subprocess.run(
                ["git", "ls-remote", _PREVIEW_PUBLIC_REPO_SSH, "refs/heads/*"],
                check=False,
                capture_output=True,
                timeout=30,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as err:
            raise SuiteBridgeError("GIT_PREVIEW_VERIFY_FAILED", "Public preview-remote kunne ikke laeses.", 503) from err
        if completed.returncode != 0:
            raise SuiteBridgeError("GIT_PREVIEW_VERIFY_FAILED", "Public preview-remote afviste verifikationen.", 502)
        refs: list[str] = []
        for line in completed.stdout.decode("utf-8", errors="replace").splitlines():
            fields = line.split("\t", 1)
            if len(fields) == 2 and fields[0] == public_commit and fields[1].startswith("refs/heads/"):
                refs.append(fields[1])
        if not refs:
            raise SuiteBridgeError("GIT_PREVIEW_VERIFY_FAILED", "Public preview-commit blev ikke fundet paa en remote branch.", 502)
        return sorted(refs)

    def _bootstrap_snapshot(self, expected_source_commit: str) -> dict[str, Any]:
        if not _HEX_RE.fullmatch(expected_source_commit):
            raise SuiteBridgeError("BOOTSTRAP_COMMIT_INVALID", "Bootstrap source commit skal vaere en fuld SHA.", 422)
        area = self._area("bridge")
        repo, branch, head = self._clean_identity(
            area,
            code="BOOTSTRAP_SOURCE_DIRTY",
            message="Bootstrap maintenance kraever et rent source-repository.",
        )
        if head != expected_source_commit:
            raise SuiteBridgeError("BOOTSTRAP_SOURCE_CHANGED", "Source HEAD matcher ikke den forventede bootstrap-commit.", 409)
        version_path = (repo / "VERSION").resolve()
        version = version_path.read_text(encoding="utf-8").strip()
        if not _PREVIEW_VERSION_RE.fullmatch(version):
            raise SuiteBridgeError("BOOTSTRAP_VERSION_INVALID", "VERSION er ikke en gyldig semver-version.", 409)
        _, install_sha256 = self._script(repo, _BOOTSTRAP_INSTALL_RELATIVE, "BOOTSTRAP_INSTALL_SCRIPT_MISSING")
        _, activate_sha256 = self._script(repo, _BOOTSTRAP_ACTIVATE_RELATIVE, "BOOTSTRAP_ACTIVATE_SCRIPT_MISSING")
        return {
            "area": area.name,
            "branch": branch,
            "head": head,
            "version": version,
            "install_script": _BOOTSTRAP_INSTALL_RELATIVE,
            "install_sha256": install_sha256,
            "activate_script": _BOOTSTRAP_ACTIVATE_RELATIVE,
            "activate_sha256": activate_sha256,
        }

    def status(self, area_name: str) -> dict[str, Any]:
        return {"available": True, **self._snapshot(self._area(area_name))}

    def _precommit_validate(self, area: GitCommitArea, before: dict[str, Any]) -> dict[str, Any]:
        if area.precommit_script is None:
            return {"required": False}
        repo = self._repo(area)
        script, script_sha256 = self._script(repo, area.precommit_script, "GIT_PRECOMMIT_SCRIPT_MISSING")
        environment = os.environ.copy()
        environment.update({"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"})
        try:
            completed = subprocess.run(
                ["/bin/bash", str(script)], cwd=repo, check=False,
                capture_output=True, timeout=300, env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as err:
            raise SuiteBridgeError(
                "GIT_PRECOMMIT_VALIDATION_FAILED",
                "Pre-commit valideringen fik ikke et afsluttende svar.",
                503,
            ) from err
        if completed.returncode != 0:
            raise SuiteBridgeError(
                "GIT_PRECOMMIT_VALIDATION_FAILED",
                "Pre-commit check-full afviste working tree.",
                409,
            )
        after = self._snapshot(area)
        if any(after[key] != before[key] for key in ("head", "status_sha256", "diff_sha256")):
            raise SuiteBridgeError(
                "GIT_PRECOMMIT_STATE_CHANGED",
                "Working tree aendrede sig under pre-commit valideringen.",
                409,
            )
        return {
            "required": True,
            "result": "passed",
            "script": area.precommit_script,
            "script_sha256": script_sha256,
        }

    def prepare(self, area_name: str, summary: str) -> dict[str, Any]:
        if not _COMMIT_MESSAGE_RE.fullmatch(summary):
            raise SuiteBridgeError("GIT_COMMIT_MESSAGE_INVALID", "Commit-beskeden er ugyldig.", 422)
        area = self._area(area_name)
        snapshot = self._snapshot(area)
        validation = self._precommit_validate(area, snapshot)
        return {**snapshot, "summary": summary, "validation": validation}

    def commit(self, material: dict[str, Any]) -> dict[str, Any]:
        area = self._area(str(material.get("area") or ""))
        current = self._snapshot(area)
        if any(current[key] != material.get(key) for key in ("head", "status_sha256", "diff_sha256")):
            raise SuiteBridgeError("GIT_STATE_CHANGED", "Git-omradet er aendret efter prepare.", 409)
        summary = str(material.get("summary") or "")
        if not _COMMIT_MESSAGE_RE.fullmatch(summary):
            raise SuiteBridgeError("GIT_COMMIT_MESSAGE_INVALID", "Commit-beskeden er ugyldig.", 422)
        repo = self._repo(area)
        self._run(repo, ["diff", "--check", "--", *current["paths"]])
        self._run(repo, ["add", "--all", "--", *current["paths"]])
        self._run(repo, ["commit", "-m", summary, "--", *current["paths"]])
        commit = str(self._run(repo, ["rev-parse", "HEAD"])).strip()
        return {"committed": True, "area": area.name, "branch": current["branch"], "previous_commit": current["head"], "commit": commit, "paths": current["paths"], "push": "not_performed"}

    def prepare_source_push(self, expected_source_commit: str) -> dict[str, Any]:
        """Bind a private source push to clean bridge main HEAD and origin/main."""
        if not _HEX_RE.fullmatch(expected_source_commit):
            raise SuiteBridgeError("GIT_PUSH_COMMIT_INVALID", "Source push commit skal vaere en fuld SHA.", 422)
        area = self._area("bridge")
        repo, branch, head = self._clean_identity(
            area,
            code="GIT_PUSH_SOURCE_DIRTY",
            message="Private source push kraever et rent source-repository.",
        )
        if branch != "main" or head != expected_source_commit:
            raise SuiteBridgeError("GIT_PUSH_SOURCE_CHANGED", "Source HEAD matcher ikke den forventede main-commit.", 409)
        remote = str(self._run(repo, ["config", "--get", "remote.origin.url"])).strip()
        if area.source_push_ssh and remote != _SOURCE_PRIVATE_REMOTE_PREFIX + area.expected_remote_suffix:
            raise SuiteBridgeError("GIT_PUSH_REMOTE_DENIED", "Private source origin matcher ikke den faste SSH remote.", 409)
        raw = self._run_source_remote(repo, ["ls-remote", "origin", "refs/heads/main"]).strip()
        fields = raw.split()
        if len(fields) != 2 or fields[1] != "refs/heads/main" or not _HEX_RE.fullmatch(fields[0]):
            raise SuiteBridgeError("GIT_PUSH_REMOTE_INVALID", "origin/main kunne ikke verificeres.", 502)
        return {
            "area": area.name,
            "branch": branch,
            "head": head,
            "remote": "origin",
            "remote_ref": "refs/heads/main",
            "remote_before": fields[0],
            "force": False,
        }

    def push_source(self, material: dict[str, Any]) -> dict[str, Any]:
        """Push only prepared clean bridge main HEAD to fixed origin/main without force."""
        expected = str(material.get("head") or "")
        current = self.prepare_source_push(expected)
        keys = ("area", "branch", "head", "remote", "remote_ref", "remote_before", "force")
        if any(current[key] != material.get(key) for key in keys):
            raise SuiteBridgeError("GIT_PUSH_STATE_CHANGED", "Source eller remote aendrede sig efter prepare.", 409)
        repo = self._repo(self._area("bridge"))
        self._run_source_remote(repo, ["push", "origin", "HEAD:refs/heads/main"])
        raw = self._run_source_remote(repo, ["ls-remote", "origin", "refs/heads/main"]).strip()
        fields = raw.split()
        if len(fields) != 2 or fields[0] != expected or fields[1] != "refs/heads/main":
            raise SuiteBridgeError("GIT_PUSH_VERIFY_FAILED", "Private origin/main matcher ikke source HEAD efter push.", 502)
        return {
            "pushed": True,
            "area": "bridge",
            "branch": "main",
            "commit": expected,
            "remote": "origin",
            "remote_ref": "refs/heads/main",
            "remote_before": current["remote_before"],
            "remote_after": fields[0],
            "verified_push": True,
            "force": False,
        }

    def prepare_release_candidate(self, expected_source_commit: str) -> dict[str, Any]:
        """Bind clean private main HEAD to the fixed release-candidate ref origin/next."""
        if not _HEX_RE.fullmatch(expected_source_commit):
            raise SuiteBridgeError("GIT_RC_COMMIT_INVALID", "Release-candidate commit skal vaere en fuld SHA.", 422)
        area = self._area("bridge")
        repo, branch, head = self._clean_identity(
            area, code="GIT_RC_SOURCE_DIRTY",
            message="Release-candidate publicering kraever et rent source-repository.",
        )
        if branch != "main" or head != expected_source_commit:
            raise SuiteBridgeError("GIT_RC_SOURCE_CHANGED", "Source HEAD matcher ikke den forventede main-commit.", 409)
        remote = str(self._run(repo, ["config", "--get", "remote.origin.url"])).strip()
        if area.source_push_ssh and remote != _SOURCE_PRIVATE_REMOTE_PREFIX + area.expected_remote_suffix:
            raise SuiteBridgeError("GIT_RC_REMOTE_DENIED", "Private source origin matcher ikke den faste SSH remote.", 409)
        raw = self._run_source_remote(repo, ["ls-remote", "origin", _RELEASE_CANDIDATE_REF]).strip()
        remote_before: str | None = None
        if raw:
            fields = raw.split()
            if len(fields) != 2 or fields[1] != _RELEASE_CANDIDATE_REF or not _HEX_RE.fullmatch(fields[0]):
                raise SuiteBridgeError("GIT_RC_REMOTE_INVALID", "origin/next kunne ikke verificeres.", 502)
            remote_before = fields[0]
        return {
            "area": area.name,
            "branch": branch,
            "head": head,
            "remote": "origin",
            "remote_ref": _RELEASE_CANDIDATE_REF,
            "remote_before": remote_before,
            "force": False,
        }

    def publish_release_candidate(self, material: dict[str, Any]) -> dict[str, Any]:
        """Push only prepared clean main HEAD to fixed origin/next without force."""
        expected = str(material.get("head") or "")
        current = self.prepare_release_candidate(expected)
        keys = ("area", "branch", "head", "remote", "remote_ref", "remote_before", "force")
        if any(current[key] != material.get(key) for key in keys):
            raise SuiteBridgeError("GIT_RC_STATE_CHANGED", "Source eller origin/next aendrede sig efter prepare.", 409)
        repo = self._repo(self._area("bridge"))
        self._run_source_remote(repo, ["push", "origin", f"HEAD:{_RELEASE_CANDIDATE_REF}"])
        raw = self._run_source_remote(repo, ["ls-remote", "origin", _RELEASE_CANDIDATE_REF]).strip()
        fields = raw.split()
        if len(fields) != 2 or fields[0] != expected or fields[1] != _RELEASE_CANDIDATE_REF:
            raise SuiteBridgeError("GIT_RC_VERIFY_FAILED", "Private origin/next matcher ikke source HEAD efter push.", 502)
        self._run(repo, ["update-ref", "refs/remotes/origin/next", expected])
        if str(self._run(repo, ["rev-parse", "refs/remotes/origin/next"])).strip() != expected:
            raise SuiteBridgeError("GIT_RC_VERIFY_FAILED", "Lokal origin/next tracking-ref kunne ikke verificeres.", 502)
        return {
            "published": True,
            "area": "bridge",
            "branch": "main",
            "commit": expected,
            "remote": "origin",
            "remote_ref": _RELEASE_CANDIDATE_REF,
            "remote_before": current["remote_before"],
            "remote_after": fields[0],
            "verified_push": True,
            "force": False,
        }

    def prepare_preview(self, version: str) -> dict[str, Any]:
        """Bind a HACS preview publication to the clean bridge source HEAD and script SHA."""
        return self._preview_snapshot(self._area("bridge"), version)

    def publish_preview(self, material: dict[str, Any]) -> dict[str, Any]:
        """Run only the fixed public preview publisher and verify the pushed SHA remotely."""
        version = str(material.get("version") or "")
        if str(material.get("area") or "") != "bridge":
            raise SuiteBridgeError("GIT_AREA_DENIED", "Git-omradet er ikke tilladt.", 403)
        area = self._area("bridge")
        current = self._preview_snapshot(area, version)
        if any(current[key] != material.get(key) for key in ("branch", "head", "version", "script", "script_sha256")):
            raise SuiteBridgeError("GIT_STATE_CHANGED", "Git-omradet er aendret efter prepare.", 409)
        repo = self._repo(area)
        script = repo / _PREVIEW_SCRIPT_RELATIVE
        environment = os.environ.copy()
        environment.update({"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"})
        try:
            completed = subprocess.run(
                [str(script), "--publish-hacs-preview", version],
                cwd=repo,
                input=b"PUBLISH\n",
                check=False,
                capture_output=True,
                timeout=600,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as err:
            raise SuiteBridgeError("GIT_PREVIEW_PUBLISH_FAILED", "Preview-publiceringen kunne ikke udfores.", 503) from err
        output = completed.stdout.decode("utf-8", errors="replace")
        if completed.returncode != 0:
            raise SuiteBridgeError("GIT_PREVIEW_PUBLISH_FAILED", "Det faste preview-buildscript blev afvist.", 409)
        public_match = _PUBLIC_COMMIT_RE.search(output)
        if public_match is None:
            raise SuiteBridgeError("GIT_PREVIEW_VERIFY_FAILED", "Publisheren returnerede ikke en public commit-SHA.", 502)
        public_commit = public_match.group(1)
        remote_refs = self._verify_public_commit(public_commit)
        after = self._preview_snapshot(area, version)
        if after["head"] != current["head"] or after["script_sha256"] != current["script_sha256"]:
            raise SuiteBridgeError("GIT_STATE_CHANGED", "Source HEAD eller publisher-script aendrede sig under preview-publicering.", 409)
        return {
            "published": True,
            "repository": "TorbenAT/home-assistant-one-bridge",
            "version": version,
            "source_commit": current["head"],
            "publisher_sha256": current["script_sha256"],
            "public_commit": public_commit,
            "remote_refs": remote_refs,
            "verified_push": True,
            "final_release": False,
            "tag_created": False,
        }

    def prepare_public_cleanup(self, version: str, expected_source_commit: str) -> dict[str, Any]:
        """Bind a one-time public history cleanup to current source and public main HEAD."""
        if not _HEX_RE.fullmatch(expected_source_commit):
            raise SuiteBridgeError("GIT_PUBLIC_CLEANUP_SOURCE_INVALID", "Public cleanup source commit skal vaere en fuld SHA.", 422)
        snapshot = self._preview_snapshot(self._area("bridge"), version)
        if snapshot["head"] != expected_source_commit:
            raise SuiteBridgeError("GIT_PUBLIC_CLEANUP_SOURCE_CHANGED", "Source HEAD matcher ikke den forventede cleanup-commit.", 409)
        public = self.public_status()
        if public["root_files"] != ["LICENSE"]:
            raise SuiteBridgeError("GIT_PUBLIC_CLEANUP_ROOT_DENIED", "Public root commit er ikke den forventede LICENSE-only commit.", 409)
        if public["tags"]:
            raise SuiteBridgeError("GIT_PUBLIC_CLEANUP_TAGGED", "Public cleanup maa kun ske foer foerste tag.", 409)
        if public["commit_count"] < 2:
            raise SuiteBridgeError("GIT_PUBLIC_CLEANUP_NOT_NEEDED", "Public historikken har ikke preview-commits at rydde op i.", 409)
        return {
            **snapshot,
            "public_head": public["head"],
            "public_root": public["root_commit"],
            "public_commit_count": public["commit_count"],
            "public_recent_commits": public["recent_commits"],
            "public_tags": public["tags"],
            "target_commit_count": 2,
            "force_with_lease": True,
            "tag_created": False,
        }

    def cleanup_public(self, material: dict[str, Any]) -> dict[str, Any]:
        """Rewrite public main to root LICENSE + one current snapshot commit using force-with-lease."""
        version = str(material.get("version") or "")
        expected_source = str(material.get("head") or "")
        current = self.prepare_public_cleanup(version, expected_source)
        keys = (
            "head", "version", "script_sha256", "public_head", "public_root",
            "public_commit_count", "public_tags", "target_commit_count", "force_with_lease",
        )
        if any(current[key] != material.get(key) for key in keys):
            raise SuiteBridgeError("GIT_PUBLIC_CLEANUP_STATE_CHANGED", "Source eller public historik aendrede sig efter prepare.", 409)
        source_repo = self._repo(self._area("bridge"))
        check_script = source_repo / "scripts" / "check-full.sh"
        try:
            checked = subprocess.run(
                ["/bin/bash", str(check_script)], cwd=source_repo, check=False,
                capture_output=True, timeout=600, env=os.environ.copy(),
            )
        except (OSError, subprocess.TimeoutExpired) as err:
            raise SuiteBridgeError("GIT_PUBLIC_CLEANUP_TEST_FAILED", "check-full kunne ikke afsluttes foer cleanup.", 503) from err
        if checked.returncode != 0:
            raise SuiteBridgeError("GIT_PUBLIC_CLEANUP_TEST_FAILED", "check-full afviste source foer public cleanup.", 409)
        publisher = source_repo / _PREVIEW_SCRIPT_RELATIVE
        with tempfile.TemporaryDirectory(prefix="one-bridge-public-cleanup-") as tmp:
            root = Path(tmp)
            clone = root / "repo"
            snapshot_dir = root / "snapshot"
            self._run_public_git(["clone", "--quiet", _PREVIEW_PUBLIC_REPO_SSH, str(clone)], timeout=90)
            before = self._public_status_from_clone(clone)
            if before["head"] != current["public_head"] or before["root_commit"] != current["public_root"] or before["tags"]:
                raise SuiteBridgeError("GIT_PUBLIC_CLEANUP_STATE_CHANGED", "Public repository aendrede sig foer cleanup.", 409)
            environment = os.environ.copy()
            environment["LICENSE_FILE"] = str(clone / "LICENSE")
            try:
                built = subprocess.run(
                    [str(publisher), "--hacs-snapshot", version, str(snapshot_dir)],
                    cwd=source_repo, check=False, capture_output=True, timeout=300, env=environment,
                )
            except (OSError, subprocess.TimeoutExpired) as err:
                raise SuiteBridgeError("GIT_PUBLIC_CLEANUP_BUILD_FAILED", "Public snapshot kunne ikke bygges.", 503) from err
            if built.returncode != 0 or not (snapshot_dir / "PUBLIC_SNAPSHOT.json").is_file():
                raise SuiteBridgeError("GIT_PUBLIC_CLEANUP_BUILD_FAILED", "Public snapshot validation fejlede.", 409)
            self._run(clone, ["reset", "--hard", current["public_root"]])
            shutil.copytree(snapshot_dir, clone, dirs_exist_ok=True)
            self._run(clone, ["diff", "--check"])
            self._run(clone, ["add", "-A"])
            self._run(clone, ["diff", "--cached", "--check"])
            author_name = str(self._run(clone, ["log", "-1", "--format=%an", current["public_root"]])).strip()
            author_email = str(self._run(clone, ["log", "-1", "--format=%ae", current["public_root"]])).strip()
            self._run(clone, ["config", "user.name", author_name])
            self._run(clone, ["config", "user.email", author_email])
            self._run(clone, ["commit", "-m", f"Publish One Bridge {version}"])
            new_commit = str(self._run(clone, ["rev-parse", "HEAD"])).strip()
            if int(str(self._run(clone, ["rev-list", "--count", "HEAD"])).strip()) != 2:
                raise SuiteBridgeError("GIT_PUBLIC_CLEANUP_VERIFY_FAILED", "Renset public historik har ikke præcis 2 commits.", 409)
            self._run_public_git(
                ["-C", str(clone), "push", f"--force-with-lease={_PUBLIC_MAIN_REF}:{current['public_head']}", "origin", f"HEAD:{_PUBLIC_MAIN_REF}"],
                timeout=120,
            )
            remote_raw = self._run_public_git(["ls-remote", _PREVIEW_PUBLIC_REPO_SSH, _PUBLIC_MAIN_REF]).strip()
            fields = remote_raw.split()
            if len(fields) != 2 or fields[0] != new_commit or fields[1] != _PUBLIC_MAIN_REF:
                raise SuiteBridgeError("GIT_PUBLIC_CLEANUP_VERIFY_FAILED", "Public main matcher ikke den rensede commit efter rewrite.", 502)
            if self._run_public_git(["ls-remote", "--tags", _PREVIEW_PUBLIC_REPO_SSH]).strip():
                raise SuiteBridgeError("GIT_PUBLIC_CLEANUP_VERIFY_FAILED", "Et public tag opstod under cleanup.", 502)
            return {
                "cleaned": True,
                "repository": "TorbenAT/home-assistant-one-bridge",
                "version": version,
                "source_commit": expected_source,
                "public_before": current["public_head"],
                "public_after": new_commit,
                "root_commit": current["public_root"],
                "commit_count_before": current["public_commit_count"],
                "commit_count_after": 2,
                "force_with_lease": True,
                "verified_push": True,
                "tags": [],
            }

    def prepare_public_tag(self, version: str, expected_public_commit: str) -> dict[str, Any]:
        """Bind the first final version tag to the verified cleaned public main commit."""
        if not _PREVIEW_VERSION_RE.fullmatch(version):
            raise SuiteBridgeError("GIT_PUBLIC_TAG_VERSION_INVALID", "Public tag-versionen er ugyldig.", 422)
        if not _HEX_RE.fullmatch(expected_public_commit):
            raise SuiteBridgeError("GIT_PUBLIC_TAG_COMMIT_INVALID", "Public tag commit skal vaere en fuld SHA.", 422)
        public = self.public_status()
        if public["head"] != expected_public_commit:
            raise SuiteBridgeError("GIT_PUBLIC_TAG_HEAD_CHANGED", "Public main matcher ikke den forventede tag-commit.", 409)
        if public["root_files"] != ["LICENSE"] or public["commit_count"] != 2:
            raise SuiteBridgeError("GIT_PUBLIC_TAG_HISTORY_DIRTY", "Public historikken er ikke renset til root + én release-commit.", 409)
        tag = f"v{version}"
        if tag in public["tags"]:
            raise SuiteBridgeError("GIT_PUBLIC_TAG_EXISTS", "Det endelige public tag findes allerede.", 409)
        return {
            "repository": public["repository"],
            "version": version,
            "tag": tag,
            "public_commit": expected_public_commit,
            "root_commit": public["root_commit"],
            "commit_count": public["commit_count"],
            "tags_before": public["tags"],
            "force": False,
        }

    def create_public_tag(self, material: dict[str, Any]) -> dict[str, Any]:
        """Create one new lightweight v<version> tag; never move or delete tags."""
        version = str(material.get("version") or "")
        expected = str(material.get("public_commit") or "")
        current = self.prepare_public_tag(version, expected)
        keys = ("repository", "version", "tag", "public_commit", "root_commit", "commit_count", "tags_before", "force")
        if any(current[key] != material.get(key) for key in keys):
            raise SuiteBridgeError("GIT_PUBLIC_TAG_STATE_CHANGED", "Public state aendrede sig efter tag-prepare.", 409)
        with tempfile.TemporaryDirectory(prefix="one-bridge-public-tag-") as tmp:
            clone = Path(tmp) / "repo"
            self._run_public_git(["clone", "--quiet", _PREVIEW_PUBLIC_REPO_SSH, str(clone)], timeout=90)
            self._run(clone, ["tag", current["tag"], expected])
            self._run_public_git(["-C", str(clone), "push", "origin", f"refs/tags/{current['tag']}:refs/tags/{current['tag']}"], timeout=90)
        raw = self._run_public_git(["ls-remote", _PREVIEW_PUBLIC_REPO_SSH, f"refs/tags/{current['tag']}"]).strip()
        fields = raw.split()
        if len(fields) != 2 or fields[0] != expected or fields[1] != f"refs/tags/{current['tag']}":
            raise SuiteBridgeError("GIT_PUBLIC_TAG_VERIFY_FAILED", "Public tag matcher ikke den forventede commit.", 502)
        return {
            "tag_created": True,
            "repository": current["repository"],
            "version": version,
            "tag": current["tag"],
            "public_commit": expected,
            "verified": True,
            "force": False,
            "github_release_created": False,
        }

    def bootstrap_status(self) -> dict[str, Any]:
        """Return redacted bootstrap source/pending/last state without mutation."""
        area = self._area("bridge")
        repo, branch, head = self._identity(area)
        version = (repo / "VERSION").read_text(encoding="utf-8").strip()
        result: dict[str, Any] = {
            "source_commit": head,
            "version": version,
            "branch": branch,
            "pending": None,
            "last": None,
        }
        pending_path = (self.config_root / _BOOTSTRAP_PENDING_RELATIVE).resolve()
        if pending_path.is_file():
            state = self._read_state(
                pending_path,
                {"BACKUP_DIR", "RELEASE_COMMIT", "PACKAGE_VERSION", "STAGED_AT"},
                "BOOTSTRAP_PENDING_NOT_FOUND",
            )
            result["pending"] = {
                "release_commit": state["RELEASE_COMMIT"],
                "package_version": state["PACKAGE_VERSION"],
                "staged_at": state["STAGED_AT"],
                "sha256": sha256(pending_path.read_bytes()).hexdigest(),
            }
        last_path = (self.config_root / _BOOTSTRAP_LAST_RELATIVE).resolve()
        if last_path.is_file():
            state = self._read_state(
                last_path,
                {"BACKUP_DIR", "RELEASE_COMMIT", "PACKAGE_VERSION", "ACTIVATED_AT"},
                "BOOTSTRAP_LAST_NOT_FOUND",
            )
            result["last"] = {
                "release_commit": state["RELEASE_COMMIT"],
                "package_version": state["PACKAGE_VERSION"],
                "activated_at": state["ACTIVATED_AT"],
                "sha256": sha256(last_path.read_bytes()).hexdigest(),
            }
        return result

    def prepare_bootstrap_stage(self, expected_source_commit: str) -> dict[str, Any]:
        """Bind bootstrap staging to a clean source commit and fixed scripts."""
        return self._bootstrap_snapshot(expected_source_commit)

    def stage_bootstrap(self, material: dict[str, Any]) -> dict[str, Any]:
        """Run only install.sh for the prepared source commit; never restart HA."""
        expected = str(material.get("head") or "")
        current = self._bootstrap_snapshot(expected)
        keys = (
            "area", "branch", "head", "version", "install_script",
            "install_sha256", "activate_script", "activate_sha256",
        )
        if any(current[key] != material.get(key) for key in keys):
            raise SuiteBridgeError("BOOTSTRAP_SOURCE_CHANGED", "Bootstrap-source eller maintenance-script aendrede sig efter prepare.", 409)
        repo = self._repo(self._area("bridge"))
        script = repo / _BOOTSTRAP_INSTALL_RELATIVE
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_OPTIONAL_LOCKS": "0",
                "CONFIG_DIR": str(self.config_root),
                "BACKUP_BASE": str(self.config_root / _BOOTSTRAP_BACKUP_RELATIVE),
                "RELEASE_COMMIT": expected,
            }
        )
        try:
            completed = subprocess.run(
                ["/bin/bash", str(script)], cwd=repo, check=False, capture_output=True,
                timeout=900, env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as err:
            raise SuiteBridgeError("BOOTSTRAP_STAGE_FAILED", "Bootstrap staging kunne ikke udfores.", 503) from err
        output = completed.stdout.decode("utf-8", errors="replace")
        if completed.returncode != 0 or "PASS: One Bridge bootstrap staged; no restart performed" not in output:
            raise SuiteBridgeError("BOOTSTRAP_STAGE_FAILED", "Det faste bootstrap install-script blev afvist.", 409)
        if "config_check=passed" in output:
            config_check = True
        elif "config_check=deferred" in output:
            config_check = False
        else:
            raise SuiteBridgeError("BOOTSTRAP_STAGE_VERIFY_FAILED", "Bootstrap-scriptet returnerede ikke config-check status.", 409)
        pending_path = (self.config_root / _BOOTSTRAP_PENDING_RELATIVE).resolve()
        state = self._read_state(
            pending_path,
            {"BACKUP_DIR", "RELEASE_COMMIT", "PACKAGE_VERSION", "STAGED_AT"},
            "BOOTSTRAP_PENDING_NOT_FOUND",
        )
        if state["RELEASE_COMMIT"] != expected or state["PACKAGE_VERSION"] != current["version"]:
            raise SuiteBridgeError("BOOTSTRAP_STAGE_VERIFY_FAILED", "Pending bootstrap-state matcher ikke den prepared source.", 409)
        backup_path = Path(state["BACKUP_DIR"]).resolve()
        backup_root = (self.config_root / _BOOTSTRAP_BACKUP_RELATIVE).resolve()
        if backup_root != backup_path and backup_root not in backup_path.parents:
            raise SuiteBridgeError("BOOTSTRAP_STAGE_VERIFY_FAILED", "Bootstrap-backup ligger uden for den faste backup-root.", 409)
        source_component = repo / "custom_components" / "one_bridge"
        installed_component = self.config_root / "custom_components" / "one_bridge"
        for relative in ("const.py", "engine.py", "operations.v2.yaml"):
            source_sha = sha256((source_component / relative).read_bytes()).hexdigest()
            installed_sha = sha256((installed_component / relative).read_bytes()).hexdigest()
            if source_sha != installed_sha:
                raise SuiteBridgeError("BOOTSTRAP_STAGE_VERIFY_FAILED", f"Installeret {relative} matcher ikke source.", 409)
        return {
            "staged": True,
            "source_commit": expected,
            "version": current["version"],
            "backup_dir": str(backup_path),
            "config_check": config_check,
            "config_check_required_before_restart": not config_check,
            "restart_performed": False,
            "pending_sha256": sha256(pending_path.read_bytes()).hexdigest(),
        }

    def prepare_bootstrap_finalize(
        self, expected_source_commit: str, loaded_version: str
    ) -> dict[str, Any]:
        """Bind bookkeeping finalization to a verified post-restart runtime."""
        current = self._bootstrap_snapshot(expected_source_commit)
        if loaded_version != current["version"]:
            raise SuiteBridgeError(
                "BOOTSTRAP_NOT_LOADED",
                "Den indlaeste bootstrap-version matcher ikke den staged version.",
                409,
            )
        pending_path = (self.config_root / _BOOTSTRAP_PENDING_RELATIVE).resolve()
        state = self._read_state(
            pending_path,
            {"BACKUP_DIR", "RELEASE_COMMIT", "PACKAGE_VERSION", "STAGED_AT"},
            "BOOTSTRAP_PENDING_NOT_FOUND",
        )
        if (
            state["RELEASE_COMMIT"] != expected_source_commit
            or state["PACKAGE_VERSION"] != current["version"]
        ):
            raise SuiteBridgeError(
                "BOOTSTRAP_PENDING_CHANGED",
                "Pending bootstrap matcher ikke den forventede source commit/version.",
                409,
            )
        repo = self._repo(self._area("bridge"))
        source_component = repo / "custom_components" / "one_bridge"
        installed_component = self.config_root / "custom_components" / "one_bridge"
        for relative in ("const.py", "engine.py", "git_commit.py", "operations.v2.yaml"):
            source_sha = sha256((source_component / relative).read_bytes()).hexdigest()
            installed_sha = sha256((installed_component / relative).read_bytes()).hexdigest()
            if source_sha != installed_sha:
                raise SuiteBridgeError(
                    "BOOTSTRAP_NOT_LOADED",
                    f"Installeret {relative} matcher ikke den staged source.",
                    409,
                )
        return {
            **current,
            "loaded_version": loaded_version,
            "pending_sha256": sha256(pending_path.read_bytes()).hexdigest(),
            "staged_at": state["STAGED_AT"],
            "backup_dir": state["BACKUP_DIR"],
        }

    def finalize_bootstrap(
        self, material: dict[str, Any], loaded_version: str
    ) -> dict[str, Any]:
        """Finalize state after restart; this method never restarts Home Assistant."""
        expected = str(material.get("head") or "")
        current = self.prepare_bootstrap_finalize(expected, loaded_version)
        keys = (
            "area",
            "branch",
            "head",
            "version",
            "install_sha256",
            "activate_sha256",
            "loaded_version",
            "pending_sha256",
        )
        if any(current[key] != material.get(key) for key in keys):
            raise SuiteBridgeError(
                "BOOTSTRAP_PENDING_CHANGED",
                "Bootstrap finalize-state aendrede sig efter prepare.",
                409,
            )
        pending_path = (self.config_root / _BOOTSTRAP_PENDING_RELATIVE).resolve()
        last_path = (self.config_root / _BOOTSTRAP_LAST_RELATIVE).resolve()
        activated_at = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        document = (
            f"BACKUP_DIR='{current['backup_dir']}'\n"
            f"RELEASE_COMMIT='{expected}'\n"
            f"PACKAGE_VERSION='{current['version']}'\n"
            f"ACTIVATED_AT='{activated_at}'\n"
        )
        tmp = last_path.with_name(last_path.name + ".tmp")
        tmp.write_text(document, encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, last_path)
        pending_path.unlink()
        state = self._read_state(
            last_path,
            {"BACKUP_DIR", "RELEASE_COMMIT", "PACKAGE_VERSION", "ACTIVATED_AT"},
            "BOOTSTRAP_FINALIZE_VERIFY_FAILED",
        )
        if (
            state["RELEASE_COMMIT"] != expected
            or state["PACKAGE_VERSION"] != current["version"]
            or pending_path.exists()
        ):
            raise SuiteBridgeError(
                "BOOTSTRAP_FINALIZE_VERIFY_FAILED",
                "Bootstrap-state kunne ikke efterverificeres.",
                409,
            )
        return {
            "finalized": True,
            "source_commit": expected,
            "version": current["version"],
            "loaded_version": loaded_version,
            "restart_performed": False,
            "last_bootstrap_sha256": sha256(last_path.read_bytes()).hexdigest(),
        }
