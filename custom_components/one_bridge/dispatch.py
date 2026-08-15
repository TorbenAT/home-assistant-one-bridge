"""Strict public envelopes and server-side operation catalog."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re
from typing import Any, Mapping

from .const import BOOTSTRAP_VERSION
from .models import SuiteBridgeError

_OPERATION_RE = re.compile(r"^[a-z][a-z0-9_.-]+$")
_DISPATCH_FIELDS = frozenset(
    {"mode", "operation", "arguments", "request_id", "timeout_seconds"}
)
_APPLY_FIELDS = frozenset(
    {"operation", "arguments", "request_id", "timeout_seconds"}
)


def _error(
    code: str,
    message: str,
    *,
    status: int = 400,
    field: str | None = None,
) -> SuiteBridgeError:
    details = {"field": field} if field else None
    return SuiteBridgeError(code, message, status, details=details)


def _validate_common(payload: Any, allowed: frozenset[str]) -> None:
    if not isinstance(payload, dict):
        raise _error("INVALID_ENVELOPE", "Request body skal være et JSON-objekt.")
    extra = sorted(set(payload) - allowed)
    if extra:
        raise _error(
            "EXTRA_ENVELOPE_FIELD",
            f"Ukendt top-level felt: {extra[0]}",
            field=extra[0],
        )
    operation = payload.get("operation")
    if not isinstance(operation, str) or not _OPERATION_RE.fullmatch(operation):
        raise _error(
            "INVALID_OPERATION_NAME",
            "operation skal være et gyldigt katalognavn.",
            field="operation",
        )
    arguments = payload.get("arguments")
    if not isinstance(arguments, dict):
        raise _error(
            "INVALID_ARGUMENTS",
            "arguments skal være et JSON-objekt.",
            field="arguments",
        )
    request_id = payload.get("request_id")
    if request_id is not None and (
        not isinstance(request_id, str) or not 8 <= len(request_id) <= 100
    ):
        raise _error(
            "INVALID_REQUEST_ID",
            "request_id skal være tekst på 8-100 tegn.",
            field="request_id",
        )
    timeout = payload.get("timeout_seconds")
    if timeout is not None and (
        isinstance(timeout, bool)
        or not isinstance(timeout, int)
        or not 1 <= timeout <= 180
    ):
        raise _error(
            "INVALID_TIMEOUT",
            "timeout_seconds skal være et heltal mellem 1 og 180.",
            field="timeout_seconds",
        )


def validate_dispatch_envelope(payload: Any) -> dict[str, Any]:
    """Validate a read/prepare envelope, defaulting omitted arguments to {}."""
    if not isinstance(payload, dict):
        _validate_common(payload, _DISPATCH_FIELDS)
    normalized = dict(payload)
    normalized.setdefault("arguments", {})
    _validate_common(normalized, _DISPATCH_FIELDS)
    mode = normalized.get("mode")
    if mode not in {"read", "prepare"}:
        raise _error(
            "INVALID_DISPATCH_MODE",
            "dispatch tillader kun mode read eller prepare.",
            field="mode",
        )
    if not {"mode", "operation"}.issubset(normalized):
        missing = sorted({"mode", "operation"} - set(normalized))[0]
        raise _error(
            "MISSING_ENVELOPE_FIELD",
            f"Obligatorisk top-level felt mangler: {missing}",
            field=missing,
        )
    return normalized


def validate_apply_envelope(payload: Any) -> dict[str, Any]:
    """Validate the consequential apply envelope without free change data."""
    _validate_common(payload, _APPLY_FIELDS)
    if not {"operation", "arguments"}.issubset(payload):
        missing = sorted({"operation", "arguments"} - set(payload))[0]
        raise _error(
            "MISSING_ENVELOPE_FIELD",
            f"Obligatorisk top-level felt mangler: {missing}",
            field=missing,
        )
    if payload.get("operation") not in {"change.apply", "release.apply"}:
        raise _error(
            "INVALID_APPLY_OPERATION",
            "apply tillader kun change.apply eller release.apply.",
            field="operation",
        )
    return dict(payload)


def _type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "null":
        return value is None
    return False


def validate_schema(value: Any, schema: Mapping[str, Any], *, field: str) -> None:
    """Validate the JSON-Schema subset used by the operation catalog."""
    expected = schema.get("type")
    if isinstance(expected, str) and not _type_matches(value, expected):
        raise _error(
            "INVALID_ARGUMENT_TYPE",
            f"{field} har forkert type; forventede {expected}.",
            status=422,
            field=field,
        )
    if "enum" in schema and value not in schema["enum"]:
        raise _error(
            "INVALID_ARGUMENT_VALUE",
            f"{field} har en værdi uden for allowlisten.",
            status=422,
            field=field,
        )
    if "const" in schema and value != schema["const"]:
        raise _error(
            "INVALID_ARGUMENT_VALUE",
            f"{field} skal være {schema['const']!r}.",
            status=422,
            field=field,
        )
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        required = set(schema.get("required", []))
        missing = sorted(required - set(value))
        if missing:
            path = f"{field}.{missing[0]}"
            if field == "arguments" and missing[0] == "prepare_id":
                raise _error(
                    "PREPARE_ID_REQUIRED",
                    "prepare_id er obligatorisk.",
                    status=409,
                    field=path,
                )
            raise _error(
                "MISSING_OPERATION_ARGUMENT",
                f"Obligatorisk argument mangler: {missing[0]}",
                status=422,
                field=path,
            )
        if schema.get("additionalProperties") is False:
            extra = sorted(set(value) - set(properties))
            if extra:
                path = f"{field}.{extra[0]}"
                raise _error(
                    "EXTRA_OPERATION_ARGUMENT",
                    f"Ukendt operation-argument: {extra[0]}",
                    field=path,
                )
        for key, item in value.items():
            child = properties.get(key)
            if isinstance(child, dict):
                validate_schema(item, child, field=f"{field}.{key}")
    elif isinstance(value, list):
        minimum = schema.get("minItems")
        maximum = schema.get("maxItems")
        if isinstance(minimum, int) and len(value) < minimum:
            raise _error(
                "INVALID_ARGUMENT_LENGTH",
                f"{field} indeholder for få elementer.",
                status=422,
                field=field,
            )
        if isinstance(maximum, int) and len(value) > maximum:
            raise _error(
                "INVALID_ARGUMENT_LENGTH",
                f"{field} indeholder for mange elementer.",
                status=422,
                field=field,
            )
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                validate_schema(item, item_schema, field=f"{field}[{index}]")
    elif isinstance(value, str):
        minimum = schema.get("minLength")
        maximum = schema.get("maxLength")
        pattern = schema.get("pattern")
        if isinstance(minimum, int) and len(value) < minimum:
            raise _error(
                "INVALID_ARGUMENT_LENGTH",
                f"{field} er for kort.",
                status=422,
                field=field,
            )
        if isinstance(maximum, int) and len(value) > maximum:
            raise _error(
                "INVALID_ARGUMENT_LENGTH",
                f"{field} er for lang.",
                status=422,
                field=field,
            )
        if isinstance(pattern, str) and re.fullmatch(pattern, value) is None:
            raise _error(
                "INVALID_ARGUMENT_FORMAT",
                f"{field} matcher ikke det krævede format.",
                status=422,
                field=field,
            )
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, (int, float)) and value < minimum:
            raise _error(
                "INVALID_ARGUMENT_RANGE",
                f"{field} er mindre end minimum.",
                status=422,
                field=field,
            )
        if isinstance(maximum, (int, float)) and value > maximum:
            raise _error(
                "INVALID_ARGUMENT_RANGE",
                f"{field} er større end maksimum.",
                status=422,
                field=field,
            )


class OperationCatalog:
    """Immutable lookup of allowlisted operation contracts."""

    def __init__(self, document: Mapping[str, Any]) -> None:
        operations = document.get("operations")
        if not isinstance(operations, list) or not operations:
            raise ValueError("Operation catalog mangler operations.")
        self.schema_version = str(document.get("schema_version", "unknown"))
        self.catalog_version = int(document.get("catalog_version", 0))
        self.public_routes = deepcopy(document.get("public_routes", {}))
        self._operations: dict[str, dict[str, Any]] = {}
        for raw in operations:
            if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
                raise ValueError("Operation catalog indeholder en ugyldig operation.")
            name = raw["name"]
            if name in self._operations:
                raise ValueError(f"Dubleret operation: {name}")
            arguments = raw.get("arguments")
            if (
                not isinstance(arguments, dict)
                or arguments.get("type") != "object"
                or arguments.get("additionalProperties") is not False
            ):
                raise ValueError(f"Operation {name} har ikke et strict arguments-schema.")
            self._operations[name] = deepcopy(raw)

    @classmethod
    def from_path(cls, path: Path) -> "OperationCatalog":
        text = path.read_text(encoding="utf-8")
        json_text = "\n".join(
            line for line in text.splitlines()
            if not line.lstrip().startswith("#")
        )
        return cls(json.loads(json_text))

    def resolve(
        self, operation: str, mode: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        item = self._operations.get(operation)
        if item is None:
            raise _error(
                "UNKNOWN_OPERATION",
                f"Ukendt operation: {operation}",
                field="operation",
            )
        if item.get("mode") != mode:
            raise _error(
                "OPERATION_MODE_MISMATCH",
                f"{operation} kræver mode {item.get('mode')}.",
                field="mode",
            )
        validate_schema(arguments, item["arguments"], field="arguments")
        return deepcopy(item)

    def list(
        self,
        *,
        operation: str | None = None,
        mode: str | None = None,
        compact: bool = False,
    ) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for name in sorted(self._operations):
            item = self._operations[name]
            if operation is not None and name != operation:
                continue
            if mode is not None and item.get("mode") != mode:
                continue
            if compact:
                result.append(
                    {
                        "name": name,
                        "mode": item.get("mode"),
                        "risk": item.get("risk"),
                        "description": item.get("description"),
                    }
                )
            else:
                result.append(deepcopy(item))
        return result

    @property
    def names(self) -> frozenset[str]:
        return frozenset(self._operations)


class SystemOperations:
    """Pure handlers for the bootstrap-owned system operations."""

    def __init__(
        self,
        catalog: OperationCatalog,
        release_status: Any,
        implemented_operations: frozenset[str],
    ) -> None:
        self.catalog = catalog
        self.release_status = release_status
        self.implemented_operations = implemented_operations

    def status(self, base_status: Mapping[str, Any]) -> dict[str, Any]:
        release = self.release_status()
        return {
            **dict(base_status),
            "bootstrap_version": BOOTSTRAP_VERSION,
            "catalog_version": self.catalog.catalog_version,
            "worker_version": release.get("active_worker_version"),
            "worker_commit": release.get("active_commit"),
            "release": release,
        }

    def catalog_result(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        operations = self.catalog.list(
            operation=arguments.get("operation"),
            mode=arguments.get("mode"),
            compact=bool(arguments.get("compact", False)),
        )
        for item in operations:
            item["implemented"] = item["name"] in self.implemented_operations
        return {
            "schema_version": self.catalog.schema_version,
            "catalog_version": self.catalog.catalog_version,
            "operations": operations,
        }

    def capabilities(self) -> dict[str, Any]:
        release = self.release_status()
        return {
            "bootstrap_version": BOOTSTRAP_VERSION,
            "protocol_version": self.catalog.schema_version,
            "catalog_version": self.catalog.catalog_version,
            "implemented_operations": sorted(self.implemented_operations),
            "catalog_operations": len(self.catalog.names),
            "release_enabled": release["enabled"],
            "worker_version": release.get("active_worker_version"),
            "worker_commit": release.get("active_commit"),
        }
