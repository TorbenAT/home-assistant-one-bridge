"""Load and verify versioned worker slots without modifying bootstrap code."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any, Callable
import uuid

from .models import SuiteBridgeError

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MANIFEST_FIELDS = frozenset(
    {"schema_version", "worker_version", "entrypoint", "sha256"}
)


def _inside(root: Path, candidate: Path) -> bool:
    resolved_root = root.resolve()
    resolved = candidate.resolve()
    return resolved == resolved_root or resolved_root in resolved.parents


class WorkerLoader:
    """Verify, import, health-check and smoke-test one worker release."""

    def __init__(
        self,
        *,
        smoke_hook: Callable[[Any, dict[str, Any]], Any] | None = None,
    ) -> None:
        self.smoke_hook = smoke_hook
        self.active_worker: Any = None
        self.active_release: dict[str, Any] | None = None

    def _manifest(self, slot: Path) -> dict[str, Any]:
        path = slot / "manifest.json"
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as err:
            raise SuiteBridgeError(
                "WORKER_MANIFEST_INVALID",
                "Worker-manifest kunne ikke læses.",
                500,
            ) from err
        if not isinstance(raw, dict) or set(raw) != _MANIFEST_FIELDS:
            raise SuiteBridgeError(
                "WORKER_MANIFEST_INVALID",
                "Worker-manifest har ugyldige eller ekstra felter.",
                500,
            )
        if raw.get("schema_version") != 1:
            raise SuiteBridgeError(
                "WORKER_MANIFEST_INVALID",
                "Worker-manifestets schema_version understøttes ikke.",
                500,
            )
        if not isinstance(raw.get("worker_version"), str) or not raw["worker_version"]:
            raise SuiteBridgeError(
                "WORKER_MANIFEST_INVALID", "worker_version mangler.", 500
            )
        entrypoint = raw.get("entrypoint")
        if (
            not isinstance(entrypoint, str)
            or "/" in entrypoint
            or "\\" in entrypoint
            or not entrypoint.endswith(".py")
        ):
            raise SuiteBridgeError(
                "WORKER_MANIFEST_INVALID", "Worker-entrypoint er ugyldigt.", 500
            )
        checksums = raw.get("sha256")
        if not isinstance(checksums, dict) or not checksums:
            raise SuiteBridgeError(
                "WORKER_MANIFEST_INVALID", "Worker-checksums mangler.", 500
            )
        return raw

    def verify(self, slot: Path) -> dict[str, Any]:
        slot = slot.resolve()
        if not slot.is_dir() or slot.is_symlink():
            raise SuiteBridgeError(
                "WORKER_SLOT_INVALID", "Worker-slot findes ikke eller er et link.", 500
            )
        manifest = self._manifest(slot)
        checksums = manifest["sha256"]
        for relative, expected in checksums.items():
            if (
                not isinstance(relative, str)
                or not relative
                or not isinstance(expected, str)
                or not _SHA256_RE.fullmatch(expected)
            ):
                raise SuiteBridgeError(
                    "WORKER_MANIFEST_INVALID", "Worker-checksum er ugyldig.", 500
                )
            candidate = slot / relative
            if (
                not _inside(slot, candidate)
                or candidate.is_symlink()
                or not candidate.is_file()
            ):
                raise SuiteBridgeError(
                    "WORKER_FILE_INVALID",
                    f"Worker-fil mangler eller er usikker: {relative}",
                    500,
                )
            actual = hashlib.sha256(candidate.read_bytes()).hexdigest()
            if actual != expected:
                raise SuiteBridgeError(
                    "WORKER_DIGEST_MISMATCH",
                    f"Worker-fil matcher ikke manifestet: {relative}",
                    500,
                )
        if manifest["entrypoint"] not in checksums:
            raise SuiteBridgeError(
                "WORKER_MANIFEST_INVALID",
                "Worker-entrypoint er ikke dækket af manifestets checksums.",
                500,
            )
        return manifest

    def load(
        self,
        slot: Path,
        *,
        context: dict[str, Any] | None = None,
        activate: bool = False,
    ) -> tuple[Any, dict[str, Any], dict[str, Any]]:
        manifest = self.verify(slot)
        entrypoint = slot.resolve() / manifest["entrypoint"]
        module_name = f"_gpt_suite_worker_{uuid.uuid4().hex}"
        spec = importlib.util.spec_from_file_location(module_name, entrypoint)
        if spec is None or spec.loader is None:
            raise SuiteBridgeError(
                "WORKER_LOAD_FAILED", "Worker-entrypoint kunne ikke indlæses.", 500
            )
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
            factory = getattr(module, "load_worker", None)
            if not callable(factory):
                raise SuiteBridgeError(
                    "WORKER_LOAD_FAILED", "Worker mangler load_worker().", 500
                )
            worker = factory(dict(context or {}))
            if hasattr(worker, "__await__"):
                raise SuiteBridgeError(
                    "WORKER_LOAD_FAILED",
                    "Worker-load skal være synkron og deterministisk.",
                    500,
                )
            health_method = getattr(worker, "health", None)
            if not callable(health_method):
                raise SuiteBridgeError(
                    "WORKER_LOAD_FAILED", "Worker mangler health().", 500
                )
            health = health_method()
            if not isinstance(health, dict) or health.get("ok") is not True:
                raise SuiteBridgeError(
                    "WORKER_HEALTH_FAILED", "Worker health-check fejlede.", 500
                )
            smoke_method = getattr(worker, "smoke_test", None)
            smoke = smoke_method() if callable(smoke_method) else {"ok": True}
            if smoke is False or (
                isinstance(smoke, dict) and smoke.get("ok") is not True
            ):
                raise SuiteBridgeError(
                    "WORKER_SMOKE_FAILED", "Worker smoke test fejlede.", 500
                )
            if self.smoke_hook is not None:
                hooked = self.smoke_hook(worker, manifest)
                if hooked is False or (
                    isinstance(hooked, dict) and hooked.get("ok") is not True
                ):
                    raise SuiteBridgeError(
                        "WORKER_SMOKE_FAILED",
                        "Bridge smoke test fejlede.",
                        500,
                    )
            verification = {
                "load": "passed",
                "health": health,
                "smoke": smoke,
            }
            if activate:
                self.active_worker = worker
                self.active_release = {
                    "slot": str(slot.resolve()),
                    "worker_version": manifest["worker_version"],
                }
            return worker, manifest, verification
        except SuiteBridgeError:
            raise
        except Exception as err:
            raise SuiteBridgeError(
                "WORKER_LOAD_FAILED",
                f"Worker-load fejlede: {type(err).__name__}",
                500,
            ) from err
        finally:
            sys.modules.pop(module_name, None)

    def load_test(self, slot: Path) -> dict[str, Any]:
        _, manifest, verification = self.load(
            slot, context={"load_test": True}, activate=False
        )
        return {
            "worker_version": manifest["worker_version"],
            **verification,
        }
