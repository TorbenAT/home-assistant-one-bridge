"""Dependency-free RFC 6902 JSON Patch with Bridge safety checks."""

from __future__ import annotations

from copy import deepcopy
import difflib
import json
import re
from typing import Any

from .const import MAX_JSON_BYTES, MAX_PATCH_OPERATIONS, SENSITIVE_KEY_FRAGMENTS
from .models import SuiteBridgeError, pretty_json

_ENTITY_RE = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")


def _tokens(pointer: str) -> list[str]:
    if pointer == "":
        return []
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise SuiteBridgeError("INVALID_JSON_POINTER", f"Ugyldig JSON Pointer: {pointer!r}")
    return [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]


def _index(token: str, length: int, *, allow_end: bool = False) -> int:
    if token == "-" and allow_end:
        return length
    try:
        value = int(token)
    except ValueError as err:
        raise SuiteBridgeError("INVALID_ARRAY_INDEX", f"Ugyldigt array-indeks: {token}") from err
    maximum = length if allow_end else length - 1
    if value < 0 or value > maximum:
        raise SuiteBridgeError("ARRAY_INDEX_OUT_OF_RANGE", f"Array-indeks uden for interval: {token}")
    return value


def _parent(document: Any, tokens: list[str]) -> tuple[Any, str]:
    if not tokens:
        raise SuiteBridgeError(
            "ROOT_PATCH_DENIED",
            "Hele dashboardroden må ikke erstattes direkte; brug rollback-flowet.",
        )
    current = document
    for token in tokens[:-1]:
        if isinstance(current, dict):
            if token not in current:
                raise SuiteBridgeError("PATCH_PATH_NOT_FOUND", f"Stien findes ikke: {token}")
            current = current[token]
        elif isinstance(current, list):
            current = current[_index(token, len(current))]
        else:
            raise SuiteBridgeError("PATCH_PATH_NOT_CONTAINER", "Patch-stien rammer en scalar.")
    return current, tokens[-1]


def _get(document: Any, tokens: list[str]) -> Any:
    current = document
    for token in tokens:
        if isinstance(current, dict):
            if token not in current:
                raise SuiteBridgeError("PATCH_PATH_NOT_FOUND", f"Stien findes ikke: {token}")
            current = current[token]
        elif isinstance(current, list):
            current = current[_index(token, len(current))]
        else:
            raise SuiteBridgeError("PATCH_PATH_NOT_CONTAINER", "Patch-stien rammer en scalar.")
    return current


def _remove(document: Any, tokens: list[str]) -> Any:
    parent, token = _parent(document, tokens)
    if isinstance(parent, dict):
        if token not in parent:
            raise SuiteBridgeError("PATCH_PATH_NOT_FOUND", f"Stien findes ikke: {token}")
        return parent.pop(token)
    if isinstance(parent, list):
        return parent.pop(_index(token, len(parent)))
    raise SuiteBridgeError("PATCH_PATH_NOT_CONTAINER", "Patch-stien rammer en scalar.")


def _add(document: Any, tokens: list[str], value: Any) -> None:
    parent, token = _parent(document, tokens)
    if isinstance(parent, dict):
        parent[token] = value
        return
    if isinstance(parent, list):
        parent.insert(_index(token, len(parent), allow_end=True), value)
        return
    raise SuiteBridgeError("PATCH_PATH_NOT_CONTAINER", "Patch-stien rammer en scalar.")


def _replace(document: Any, tokens: list[str], value: Any) -> None:
    parent, token = _parent(document, tokens)
    if isinstance(parent, dict):
        if token not in parent:
            raise SuiteBridgeError("PATCH_PATH_NOT_FOUND", f"Stien findes ikke: {token}")
        parent[token] = value
        return
    if isinstance(parent, list):
        parent[_index(token, len(parent))] = value
        return
    raise SuiteBridgeError("PATCH_PATH_NOT_CONTAINER", "Patch-stien rammer en scalar.")


def _scan_sensitive(value: Any, *, key: str = "", depth: int = 0) -> None:
    if depth > 30:
        raise SuiteBridgeError("JSON_TOO_DEEP", "Dashboardkonfigurationen er for dyb.")
    if any(fragment in key.casefold() for fragment in SENSITIVE_KEY_FRAGMENTS):
        raise SuiteBridgeError(
            "SENSITIVE_FIELD_DENIED",
            f"Følsomt felt må ikke indføres i dashboardet: {key}",
            403,
        )
    if isinstance(value, dict):
        for child_key, child in value.items():
            _scan_sensitive(child, key=str(child_key), depth=depth + 1)
    elif isinstance(value, list):
        for child in value:
            _scan_sensitive(child, depth=depth + 1)


def validate_dashboard_config(config: Any) -> list[str]:
    if not isinstance(config, dict):
        raise SuiteBridgeError("INVALID_DASHBOARD", "Dashboardkonfigurationen skal være et objekt.")
    if "views" in config and not isinstance(config["views"], list):
        raise SuiteBridgeError("INVALID_DASHBOARD", "views skal være en liste.")
    encoded = json.dumps(config, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_JSON_BYTES:
        raise SuiteBridgeError(
            "DASHBOARD_TOO_LARGE",
            f"Dashboardet må højst fylde {MAX_JSON_BYTES} bytes.",
            413,
        )
    _scan_sensitive(config)
    warnings: list[str] = []
    flattened = encoded.decode("utf-8", errors="ignore")
    if '"visible"' in flattened or '"users"' in flattened:
        warnings.append("Ændringen berører muligvis dashboardets bruger-/synlighedsfiltre.")
    if "http://" in flattened or "https://" in flattened:
        warnings.append("Dashboardet indeholder eksterne URL-referencer; kontrollér dem manuelt.")
    return warnings


def apply_patch(document: Any, operations: list[dict[str, Any]]) -> Any:
    if not isinstance(operations, list) or not operations:
        raise SuiteBridgeError("PATCH_REQUIRED", "patch skal være en ikke-tom liste.")
    if len(operations) > MAX_PATCH_OPERATIONS:
        raise SuiteBridgeError(
            "TOO_MANY_PATCH_OPERATIONS",
            f"Der må højst være {MAX_PATCH_OPERATIONS} patch-operationer.",
        )
    result = deepcopy(document)
    for index, raw in enumerate(operations):
        if not isinstance(raw, dict):
            raise SuiteBridgeError("INVALID_PATCH", f"Patch-operation {index} er ikke et objekt.")
        op = str(raw.get("op", "")).lower()
        path = raw.get("path")
        if not isinstance(path, str) or len(path) > 500:
            raise SuiteBridgeError("INVALID_PATCH_PATH", f"Ugyldig path i operation {index}.")
        tokens = _tokens(path)
        if op == "add":
            _add(result, tokens, deepcopy(raw.get("value")))
        elif op == "replace":
            if "value" not in raw:
                raise SuiteBridgeError("PATCH_VALUE_REQUIRED", f"value mangler i operation {index}.")
            _replace(result, tokens, deepcopy(raw["value"]))
        elif op == "remove":
            _remove(result, tokens)
        elif op == "copy":
            from_path = raw.get("from")
            if not isinstance(from_path, str):
                raise SuiteBridgeError("PATCH_FROM_REQUIRED", f"from mangler i operation {index}.")
            _add(result, tokens, deepcopy(_get(result, _tokens(from_path))))
        elif op == "move":
            from_path = raw.get("from")
            if not isinstance(from_path, str):
                raise SuiteBridgeError("PATCH_FROM_REQUIRED", f"from mangler i operation {index}.")
            value = _remove(result, _tokens(from_path))
            _add(result, tokens, value)
        elif op == "test":
            if _get(result, tokens) != raw.get("value"):
                raise SuiteBridgeError("PATCH_TEST_FAILED", f"test fejlede i operation {index}.", 409)
        else:
            raise SuiteBridgeError("PATCH_OPERATION_DENIED", f"Ukendt patch-operation: {op}")
    validate_dashboard_config(result)
    return result


def unified_diff(before: Any, after: Any, *, max_chars: int = 60_000) -> str:
    lines = difflib.unified_diff(
        pretty_json(before).splitlines(),
        pretty_json(after).splitlines(),
        fromfile="before.json",
        tofile="after.json",
        lineterm="",
    )
    text = "\n".join(lines)
    if len(text) > max_chars:
        return text[:max_chars] + "\n... diff truncated ..."
    return text


def entity_references(value: Any, *, path: str = "") -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            found.extend(entity_references(child, path=f"{path}/{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(entity_references(child, path=f"{path}/{index}"))
    elif isinstance(value, str) and _ENTITY_RE.match(value):
        found.append({"entity_id": value, "path": path or "/"})
    return found
