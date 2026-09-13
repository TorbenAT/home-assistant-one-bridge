"""Shared models and deterministic helpers for One Bridge v2."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
from typing import Any, Collection, Mapping
import uuid

_SLUG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")

# Service domains that must never be invoked through the Bridge, neither via a
# single service.call nor as an action inside a sequence.call.
BLOCKED_SERVICE_DOMAINS = frozenset({"shell_command", "python_script", "rest_command", "notify"})

# Supervisor resources and actions allowed by the authoritative operation
# contract. This is the single matrix: prepare and apply both enforce it via
# supervisor_endpoint, and bridge_contract/operations.v2.yaml documents the
# same combinations in supervisor.action valid_combinations.
SUPERVISOR_RESOURCES = frozenset({"app", "backup", "update"})
SUPERVISOR_ACTIONS = frozenset(
    {"install", "update", "backup", "restore", "start", "stop", "restart"}
)


def validate_slug(value: Any, *, code: str, message: str) -> str:
    """Validate a Supervisor add-on/app slug or similar resource identifier.

    Slugs are interpolated into Supervisor API endpoints, so anything outside
    the official slug alphabet (including path separators and ``..``) is
    rejected before it can reach endpoint construction.
    """
    slug = str(value or "").strip()
    if ".." in slug or not _SLUG_PATTERN.fullmatch(slug):
        raise SuiteBridgeError(code, message, 422)
    return slug


def sequence_action_call(action: Any) -> tuple[str, str]:
    """Parse one sequence action into a (domain, service) call pair.

    Shared by prepare and apply so the blocked-domain deny-list cannot be
    bypassed by crafting actions that only one of the two stages inspects.
    """
    if not isinstance(action, dict):
        raise SuiteBridgeError("INVALID_SEQUENCE_ACTION", "Sekvens-handlingen skal være et objekt.", 400)
    domain = action.get("domain")
    service = action.get("service")
    if not service and isinstance(action.get("action"), str) and "." in action["action"]:
        domain, service = action["action"].split(".", 1)
    domain, service = str(domain or "").strip(), str(service or "").strip()
    if not domain or not service:
        raise SuiteBridgeError("INVALID_SEQUENCE_ACTION", "Sekvens-handlingen mangler domain/service.", 400)
    if domain in BLOCKED_SERVICE_DOMAINS:
        raise SuiteBridgeError("SERVICE_DENIED", "Denne service-type er ikke tilladt via Bridge.", 403)
    return domain, service


def supervisor_endpoint(resource: Any, target: Any, action: str) -> str:
    """Build the Supervisor API endpoint for a prepared supervisor action.

    Validates resource, target slug and fallback action before any string is
    interpolated into the endpoint path.
    """
    resource = str(resource or "").strip()
    if resource not in SUPERVISOR_RESOURCES:
        raise SuiteBridgeError("SUPERVISOR_RESOURCE_DENIED", "Ukendt Supervisor-ressource.", 403)
    if str(action or "").strip() not in SUPERVISOR_ACTIONS:
        raise SuiteBridgeError("SUPERVISOR_ACTION_DENIED", "Ukendt Supervisor-handling.", 403)
    if resource == "app":
        if not str(target or "").strip():
            raise SuiteBridgeError("SUPERVISOR_TARGET_REQUIRED", "App-handlinger kræver target.", 400)
        slug = validate_slug(
            target,
            code="SUPERVISOR_TARGET_INVALID",
            message="App-handlinger kræver et gyldigt app-slug.",
        )
        return f"/addons/{slug}/{action}"
    raw_target = str(target or "").strip()
    if raw_target:
        slug = validate_slug(
            raw_target,
            code="SUPERVISOR_TARGET_INVALID",
            message="Supervisor-target skal være et gyldigt slug.",
        )
        return f"/{resource}s/{slug}"
    fallback = validate_slug(
        action,
        code="SUPERVISOR_TARGET_INVALID",
        message="Supervisor-handlingen mangler et gyldigt target.",
    )
    return f"/{resource}s/{fallback}"


class SuiteBridgeError(Exception):
    """A controlled API error."""

    def __init__(
        self,
        code: str,
        message: str,
        status: int = 400,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.details = details or {}


def enforce_capability_policy(
    *,
    capabilities: Collection[str],
    role: str,
    read_only_lockdown: bool,
    capability: str,
    mutation: bool,
) -> None:
    """Enforce the authoritative server-side capability boundary."""
    if capability not in capabilities:
        raise SuiteBridgeError(
            "CAPABILITY_DENIED",
            f"Rollen {role} tillader ikke capability {capability}.",
            403,
        )

    if mutation and read_only_lockdown:
        raise SuiteBridgeError(
            "READ_ONLY_LOCKDOWN",
            "Bridge er lokalt låst i read-only mode.",
            423,
        )


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def json_safe(value: Any, *, depth: int = 0, truncate: bool = True) -> Any:
    # truncate=False keeps every element: digests must never hash a
    # lossy-truncated view, or two different inputs can collide to one sha256.
    if depth > 12:
        if truncate:
            return "<max-depth>"
        raise SuiteBridgeError(
            "DIGEST_INPUT_TOO_DEEP", "Input til digest er for dybt.", 422
        )
    if value is None or isinstance(value, (bool, int, float, str)):
        if truncate and isinstance(value, str) and len(value) > 20_000:
            return value[:20_000] + "…"
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if truncate and index >= 1_000:
                result["<truncated>"] = True
                break
            result[str(key)] = json_safe(item, depth=depth + 1, truncate=truncate)
        return result
    if isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
        if truncate:
            items = items[:2_000]
        return [json_safe(item, depth=depth + 1, truncate=truncate) for item in items]
    if hasattr(value, "dict_repr"):
        return json_safe(value.dict_repr, depth=depth + 1, truncate=truncate)
    return str(value)


def canonical_json(value: Any, *, truncate: bool = True) -> str:
    return json.dumps(
        json_safe(value, truncate=truncate),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def pretty_json(value: Any) -> str:
    return json.dumps(json_safe(value), ensure_ascii=False, indent=2, sort_keys=True)


def digest_json(value: Any) -> str:
    # Full-fidelity canonical form: truncated views would let inputs that
    # differ only past a truncation boundary share one digest.
    return hashlib.sha256(
        canonical_json(value, truncate=False).encode("utf-8")
    ).hexdigest()


@dataclass(slots=True)
class PreparedMutation:
    prepare_id: str
    user_id: str
    refresh_token_id: str
    operation: str
    created_monotonic: float
    expires_monotonic: float
    expires_at: str
    digest: str
    normalized_change: dict[str, Any]
    material: dict[str, Any]
    risk: str
    confirmation_phrase: str | None = None
    consumed: bool = False
    in_flight: bool = False
    lock: Any = field(default=None, repr=False)
