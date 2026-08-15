"""Strict, bounded file operations used by the v2 dispatch worker."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
from typing import Any

from .models import SuiteBridgeError
from .redaction import redact_text

MAX_FILE_BYTES = 512 * 1024
_CONTROL = set(chr(i) for i in range(32)) | {chr(127)}
VALIDATION_PROFILES = frozenset({"yaml", "home_assistant_yaml", "esphome_yaml"})


def _roots(hass: Any) -> dict[str, Path]:
    config = Path(hass.config.path()).resolve()
    return {
        "config": config,
        "addon_configs": Path("/addon_configs").resolve(),
        "appdaemon": (config / "appdaemon").resolve(),
        "share": Path("/share").resolve(),
    }


def _validate_relative(path: Any, *, allow_empty: bool = False) -> str:
    if not isinstance(path, str) or (not path and not allow_empty) or "\x00" in path:
        raise SuiteBridgeError("INVALID_FILE_PATH", "path skal være en ikke-tom relativ tekststi.", 400)
    if any(ch in _CONTROL for ch in path):
        raise SuiteBridgeError("INVALID_FILE_PATH", "path må ikke indeholde kontroltegn.", 400)
    if Path(path).is_absolute() or path.startswith(("/", "\\")):
        raise SuiteBridgeError("FILE_PATH_DENIED", "Absolutte stier er ikke tilladt.", 403)
    parts = Path(path).parts
    if ".." in parts:
        raise SuiteBridgeError("FILE_PATH_DENIED", "Path traversal er ikke tilladt.", 403)
    return path.replace("\\", "/")


def resolve_path(hass: Any, root_name: Any, relative: Any, *, write: bool = False, allow_empty: bool = False) -> tuple[str, Path, Path]:
    if root_name not in _roots(hass):
        raise SuiteBridgeError("UNKNOWN_FILE_ROOT", "Ukendt fil-root.", 400)
    rel = _validate_relative(relative, allow_empty=allow_empty)
    root = _roots(hass)[root_name]
    candidate = (root / rel).resolve(strict=False)
    if candidate != root and root not in candidate.parents:
        raise SuiteBridgeError("FILE_PATH_DENIED", "Stien ligger uden for den valgte root.", 403)
    denied = {"secrets.yaml", ".storage", "keys", ".local", "secrets.yml"}
    if any(part in denied or part.startswith(".oauth") for part in candidate.relative_to(root).parts):
        raise SuiteBridgeError("FILE_PATH_DENIED", "Følsomme filer og mapper er ikke tilgængelige.", 403)
    # Refuse symlink/reparse escapes in every existing component.
    current = root
    for part in candidate.relative_to(root).parts:
        current = current / part
        if current.exists() and current.is_symlink():
            raise SuiteBridgeError("FILE_PATH_DENIED", "Symlink-stier er ikke tilladt.", 403)
    if write and root_name not in {"config", "addon_configs", "appdaemon", "share"}:
        raise SuiteBridgeError("READ_ONLY_ROOT", "Den valgte root er skrivebeskyttet.", 403)
    return root_name, root, candidate


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_bytes(path: Path) -> bytes:
    try:
        data = path.read_bytes()
    except FileNotFoundError as err:
        raise SuiteBridgeError("FILE_NOT_FOUND", "Filen blev ikke fundet.", 404) from err
    except OSError as err:
        raise SuiteBridgeError("FILE_READ_FAILED", "Filen kunne ikke læses.", 500) from err
    if len(data) > MAX_FILE_BYTES:
        raise SuiteBridgeError("FILE_TOO_LARGE", f"Filen overskrider grænsen på {MAX_FILE_BYTES} bytes.", 413)
    return data


def _decode(data: bytes) -> tuple[str, str]:
    if b"\x00" in data:
        raise SuiteBridgeError("BINARY_FILE_UNSUPPORTED", "Binære filer understøttes ikke.", 415)
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError as err:
        raise SuiteBridgeError("BINARY_FILE_UNSUPPORTED", "Filen er ikke gyldig UTF-8.", 415) from err


def _load_yaml_syntax(text: str) -> Any:
    """Validate YAML syntax without resolving Home Assistant/ESPHome tags.

    Config files legitimately contain local tags such as ``!secret`` and
    ``!include``.  ``yaml.safe_load`` rejects those tags even though their YAML
    syntax is valid, which previously made a harmless ESPHome edit impossible
    to prepare through the Bridge.  Keep SafeLoader's safe constructors, but
    represent unknown local tags as plain values solely for syntax validation.
    """
    import yaml  # type: ignore

    class _SyntaxOnlyLoader(yaml.SafeLoader):
        pass

    def _unknown_tag(loader: Any, tag_suffix: str, node: Any) -> Any:
        del tag_suffix
        if isinstance(node, yaml.ScalarNode):
            return loader.construct_scalar(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node)
        raise yaml.YAMLError("Unsupported YAML node")

    _SyntaxOnlyLoader.add_multi_constructor("!", _unknown_tag)
    return yaml.load(text, Loader=_SyntaxOnlyLoader)


def _validate_automation_structure(document: Any, path: Path) -> None:
    """Catch unsafe automation shapes that plain YAML parsing cannot see."""
    if path.name not in {"automations.yaml", "automations.yml"}:
        return
    if not isinstance(document, list):
        raise SuiteBridgeError("INVALID_HA_AUTOMATION_STRUCTURE", "automations.yaml skal være en YAML-liste.", 422)

    def walk(value: Any, location: str) -> None:
        if isinstance(value, dict):
            choose = value.get("choose")
            if choose is not None:
                if not isinstance(choose, list):
                    raise SuiteBridgeError("INVALID_HA_AUTOMATION_STRUCTURE", f"{location}.choose skal være en liste.", 422)
                for index, option in enumerate(choose):
                    option_location = f"{location}.choose[{index}]"
                    if not isinstance(option, dict) or "conditions" not in option or "sequence" not in option:
                        raise SuiteBridgeError("INVALID_HA_AUTOMATION_STRUCTURE", f"{option_location} skal indeholde conditions og sequence.", 422)
                    if not isinstance(option["sequence"], list):
                        raise SuiteBridgeError("INVALID_HA_AUTOMATION_STRUCTURE", f"{option_location}.sequence skal være en liste.", 422)
            for key, child in value.items():
                walk(child, f"{location}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{location}[{index}]")

    walk(document, "automations")


def validate_content(text: str, path: Path, profile: Any = None) -> dict[str, Any]:
    """Validate only allowlisted YAML profiles; never resolve local secrets."""
    selected = str(profile or "yaml").lower()
    if selected not in VALIDATION_PROFILES:
        raise SuiteBridgeError("INVALID_VALIDATION_PROFILE", "validation_profile er ikke allowlistet.", 422)
    try:
        document = _load_yaml_syntax(text)
    except ImportError as err:
        raise SuiteBridgeError("YAML_VALIDATOR_UNAVAILABLE", "YAML-validatoren er ikke tilgængelig; ændringen kan ikke forberedes sikkert.", 503) from err
    except Exception as err:
        raise SuiteBridgeError("INVALID_YAML", "Indholdet er ikke gyldig YAML.", 422) from err
    if selected == "home_assistant_yaml":
        _validate_automation_structure(document, path)
    return {
        "ok": True,
        "profile": selected,
        "engine": "syntax_only",
        "limitations": (
            ["ESPHome-tags valideres syntaktisk; ESPHome CLI-build/upload er et separat prepare/apply-flow."]
            if selected == "esphome_yaml"
            else []
        ),
    }


def _validation_for(path: Path, text: str, profile: Any) -> dict[str, Any]:
    selected = profile
    if selected is None and path.suffix.lower() in {".yaml", ".yml"}:
        selected = "yaml"
    if selected is None:
        return {"ok": True, "profile": None, "engine": "not_applicable", "limitations": []}
    return validate_content(text, path, selected)


def read_file(hass: Any, arguments: dict[str, Any]) -> dict[str, Any]:
    root_name, root, path = resolve_path(hass, arguments.get("root"), arguments.get("path"))
    data = _read_bytes(path)
    text, encoding = _decode(data)
    lines = text.splitlines(keepends=True)
    start = arguments.get("start_line")
    end = arguments.get("end_line")
    if start is not None or end is not None:
        first = max(1, int(start or 1))
        last = min(len(lines), int(end or len(lines)))
        text = "".join(lines[first - 1:last])
    return {
        "root": root_name,
        "path": str(path.relative_to(root)).replace("\\", "/"),
        "size": len(data),
        "encoding": encoding,
        "sha256": _sha(data),
        "content": redact_text(text),
        "truncated": False,
        "mtime": path.stat().st_mtime,
    }


def list_files(hass: Any, arguments: dict[str, Any]) -> dict[str, Any]:
    root_name, root, base = resolve_path(hass, arguments.get("root"), arguments.get("path") or "", allow_empty=True)
    recursive = bool(arguments.get("recursive", False))
    limit = min(int(arguments.get("limit", 100)), 500)
    paths = base.rglob("*") if recursive else base.glob("*")
    items = []
    for candidate in sorted(paths):
        if len(items) >= limit:
            break
        if candidate.is_symlink() or not candidate.is_file():
            continue
        try:
            relative = str(candidate.relative_to(root)).replace("\\", "/")
            size = candidate.stat().st_size
        except OSError:
            continue
        items.append({"path": relative, "size": size, "sha256": _sha(candidate.read_bytes()) if size <= MAX_FILE_BYTES else None})
    return {"root": root_name, "path": str(base.relative_to(root)).replace("\\", "/"), "files": items, "count": len(items), "truncated": len(items) >= limit}


def search_files(hass: Any, arguments: dict[str, Any]) -> dict[str, Any]:
    roots = arguments.get("roots") or ["config"]
    query = arguments.get("query")
    if not isinstance(query, str) or not query:
        raise SuiteBridgeError("MISSING_OPERATION_ARGUMENT", "query er obligatorisk.", 422)
    glob = arguments.get("glob") or "*"
    limit = min(int(arguments.get("limit", 50)), 200)
    matches: list[dict[str, Any]] = []
    for root_name in roots:
        _, root, base = resolve_path(hass, root_name, "", allow_empty=True)
        for path in base.rglob(glob):
            if len(matches) >= limit:
                break
            if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_FILE_BYTES:
                continue
            try:
                text, _ = _decode(path.read_bytes())
            except SuiteBridgeError:
                continue
            for line_no, line in enumerate(text.splitlines(), 1):
                if query.casefold() in line.casefold():
                    matches.append({"root": root_name, "path": str(path.relative_to(root)).replace("\\", "/"), "line": line_no, "text": redact_text(line[:500])})
                    break
        if len(matches) >= limit:
            break
    return {"matches": matches, "count": len(matches), "truncated": len(matches) >= limit}


def prepare_file(hass: Any, arguments: dict[str, Any]) -> dict[str, Any]:
    import difflib
    root_name, root, path = resolve_path(hass, arguments.get("root"), arguments.get("path"), write=True)
    new_content = arguments.get("new_content")
    if not isinstance(new_content, str) or len(new_content.encode()) > MAX_FILE_BYTES:
        raise SuiteBridgeError("INVALID_FILE_CONTENT", "new_content skal være begrænset UTF-8 tekst.", 400)
    before = _read_bytes(path)
    before_text, _ = _decode(before)
    expected = arguments.get("expected_sha256")
    if expected != _sha(before):
        raise SuiteBridgeError("STALE_FILE_HASH", "Filen har ændret sig siden læsning.", 409)
    after = new_content.encode("utf-8")
    validation = _validation_for(path, new_content, arguments.get("validation_profile"))
    diff = "".join(difflib.unified_diff(before_text.splitlines(True), new_content.splitlines(True), fromfile=str(path), tofile=str(path)))
    return {"root": root_name, "path": str(path.relative_to(root)).replace("\\", "/"), "before_sha256": _sha(before), "after_sha256": _sha(after), "diff": redact_text(diff[:60000]), "validation": validation, "new_content": new_content}


def prepare_file_patch(hass: Any, arguments: dict[str, Any]) -> dict[str, Any]:
    """Prepare bounded, exact line replacements without returning a whole file.

    ``expected_sha256`` protects the complete file against concurrent changes.
    Each patch additionally has to match the exact original line range, so a
    line number can never by itself select unrelated content.
    """
    import difflib

    root_name, root, path = resolve_path(
        hass, arguments.get("root"), arguments.get("path"), write=True
    )
    before = _read_bytes(path)
    before_text, _ = _decode(before)
    expected = arguments.get("expected_sha256")
    if expected != _sha(before):
        raise SuiteBridgeError("STALE_FILE_HASH", "Filen har ændret sig siden læsning.", 409)

    patches = arguments.get("patches")
    if not isinstance(patches, list) or not 1 <= len(patches) <= 20:
        raise SuiteBridgeError("INVALID_FILE_PATCHES", "patches skal indeholde 1-20 ændringer.", 400)

    lines = before_text.splitlines(keepends=True)
    checked: list[tuple[int, int, str, dict[str, Any]]] = []
    for index, patch in enumerate(patches, 1):
        if not isinstance(patch, dict):
            raise SuiteBridgeError("INVALID_FILE_PATCH", f"Patch {index} skal være et objekt.", 400)
        start, end = patch.get("start_line"), patch.get("end_line")
        old_content, new_content = patch.get("old_content"), patch.get("new_content")
        if (
            isinstance(start, bool)
            or isinstance(end, bool)
            or not isinstance(start, int)
            or not isinstance(end, int)
            or start < 1
            or end < start
            or end > len(lines)
        ):
            raise SuiteBridgeError("INVALID_FILE_PATCH_RANGE", f"Patch {index} har et ugyldigt linjeområde.", 400)
        if not isinstance(old_content, str) or not isinstance(new_content, str):
            raise SuiteBridgeError("INVALID_FILE_PATCH", f"Patch {index} skal have tekst i old_content og new_content.", 400)
        actual = "".join(lines[start - 1:end])
        if actual != old_content:
            raise SuiteBridgeError("FILE_PATCH_MISMATCH", f"Patch {index} matcher ikke filens aktuelle indhold.", 409)
        checked.append((start, end, new_content, {"start_line": start, "end_line": end, "matched": True}))

    previous_end = 0
    for start, end, _, _ in sorted(checked):
        if start <= previous_end:
            raise SuiteBridgeError("OVERLAPPING_FILE_PATCHES", "Patch-linjeområder må ikke overlappe.", 400)
        previous_end = end

    after_lines = list(lines)
    for start, end, new_content, _ in sorted(checked, reverse=True):
        after_lines[start - 1:end] = new_content.splitlines(keepends=True)
    new_content = "".join(after_lines)
    after = new_content.encode("utf-8")
    if len(after) > MAX_FILE_BYTES:
        raise SuiteBridgeError("INVALID_FILE_CONTENT", "Resultatet overskrider filgrænsen.", 400)

    validation = _validation_for(path, new_content, arguments.get("validation_profile"))

    diff = "".join(
        difflib.unified_diff(
            before_text.splitlines(True), new_content.splitlines(True),
            fromfile=str(path), tofile=str(path),
        )
    )
    return {
        "root": root_name,
        "path": str(path.relative_to(root)).replace("\\", "/"),
        "before_sha256": _sha(before),
        "after_sha256": _sha(after),
        "patches": [meta for _, _, _, meta in checked],
        "diff": redact_text(diff[:60000]),
        "validation": validation,
        "new_content": new_content,
    }


def validate_file(hass: Any, arguments: dict[str, Any]) -> dict[str, Any]:
    root_name, root, path = resolve_path(hass, arguments.get("root"), arguments.get("path"))
    data = _read_bytes(path)
    text, _ = _decode(data)
    validation = validate_content(text, path, arguments["validation_profile"])
    return {
        "target": {"root": root_name, "path": str(path.relative_to(root)).replace("\\", "/")},
        "sha256": _sha(data),
        "validation": validation,
    }


def apply_file(hass: Any, item: Any, backups: Any) -> dict[str, Any]:
    material = item.material
    _, root, path = resolve_path(hass, material["root"], material["path"], write=True)
    current = _read_bytes(path)
    if _sha(current) != material["before_sha256"]:
        raise SuiteBridgeError("STALE_FILE_HASH", "Filen ændrede sig efter prepare.", 409)
    temp = path.with_name(path.name + ".gpt-bridge.tmp")
    try:
        temp.write_bytes(material["new_content"].encode("utf-8"))
        os.chmod(temp, stat.S_IMODE(path.stat().st_mode))
        os.replace(temp, path)
        final = _read_bytes(path)
        if _sha(final) != material["after_sha256"]:
            raise SuiteBridgeError("POST_WRITE_HASH_MISMATCH", "Efter-hash matcher ikke prepare-resultatet.", 500)
    finally:
        if temp.exists():
            temp.unlink(missing_ok=True)
    return {"root": material["root"], "path": material["path"], "sha256": _sha(final)}
