"""Home Assistant-backed read operations for the strict v2 dispatch route."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from .models import SuiteBridgeError
from .redaction import redact_text
from .ws_client import async_ws_command


def _limit(value: Any, default: int = 100, maximum: int = 250) -> int:
    try:
        return min(max(int(value or default), 1), maximum)
    except (TypeError, ValueError) as err:
        raise SuiteBridgeError("INVALID_ARGUMENT_TYPE", "limit skal være et heltal.", 400) from err


async def audit_search(audit: Any, arguments: dict[str, Any]) -> dict[str, Any]:
    result = audit.summary(_limit(arguments.get("limit"), 20, 100))
    operation = arguments.get("operation")
    if operation:
        result["entries"] = [item for item in result["entries"] if item.get("operation") == operation]
    request_id = arguments.get("request_id")
    if request_id:
        result["entries"] = [item for item in result["entries"] if item.get("request_id") == request_id]
    return result


async def history(hass: Any, auth_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
    try:
        result = await async_ws_command(hass, auth_id, {"type": "history/history_during_period", "start_time": arguments["start"], "end_time": arguments["end"], "entity_ids": arguments["entity_ids"], "minimal_response": bool(arguments.get("minimal", False)), "no_attributes": bool(arguments.get("minimal", False)), "significant_changes_only": False})
    except SuiteBridgeError as err:
        return {"states": {}, "entity_ids": arguments["entity_ids"], "available": False, "error": {"code": err.code, "message": redact_text(err.message)}}
    limit, offset = _limit(arguments.get("limit"), 100, 250), int(arguments.get("offset", 0) or 0)
    if isinstance(result, dict):
        states = {key: (value[offset:offset + limit] if isinstance(value, list) else []) for key, value in result.items()}
        count = sum(len(value) for value in states.values())
        has_more = any(isinstance(value, list) and len(value) > offset + limit for value in result.values())
    else:
        entries = list(result or [])
        states, count, has_more = entries[offset:offset + limit], len(entries[offset:offset + limit]), len(entries) > offset + limit
    return {"states": states, "entity_ids": arguments["entity_ids"], "available": True, "count": count, "offset": offset, "limit": limit, "has_more": has_more}


async def statistics(hass: Any, auth_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
    command = {"type": "recorder/statistics_during_period", "start_time": arguments["start"], "statistic_ids": arguments["statistic_ids"], "period": arguments.get("period", "hour")}
    try:
        result = await async_ws_command(hass, auth_id, command)
    except SuiteBridgeError as err:
        return {"statistics": {}, "available": False, "upstream_error": err.code}
    return {"statistics": result or {}, "available": True}


async def logbook(hass: Any, auth_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
    entity_ids = arguments.get("entity_ids")
    try:
        result = await async_ws_command(hass, auth_id, {"type": "logbook/entries", "start_time": arguments["start"], "end_time": arguments["end"], "entity_ids": entity_ids, "limit": _limit(arguments.get("limit"), 100, 250)})
    except SuiteBridgeError as err:
        return {"entries": [], "count": 0, "entity_ids": entity_ids or [], "available": False, "error": {"code": err.code, "message": redact_text(err.message)}}
    entries = list(result or [])
    limit, offset = _limit(arguments.get("limit"), 100, 250), int(arguments.get("offset", 0) or 0)
    return {"entries": entries[offset:offset + limit], "count": len(entries[offset:offset + limit]), "entity_ids": entity_ids or [], "available": True, "offset": offset, "limit": limit, "has_more": len(entries) > offset + limit}


async def template_render(hass: Any, auth_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
    try:
        result = await async_ws_command(hass, auth_id, {"type": "render_template", "template": arguments["template"]})
    except SuiteBridgeError as err:
        return {"rendered": None, "available": False, "upstream_error": err.code}
    return {"rendered": result, "available": True}


async def calendar_events(hass: Any, auth_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
    del auth_id
    entity_ids = list(arguments["entity_ids"])
    invalid = [entity_id for entity_id in entity_ids if not str(entity_id).startswith("calendar.")]
    if invalid:
        raise SuiteBridgeError(
            "INVALID_CALENDAR_ENTITY",
            "Alle entity_ids skal være calendar-entiteter.",
            400,
        )
    service_data = {
        "start_date_time": arguments["start"],
        "end_date_time": arguments["end"],
    }
    response = await hass.services.async_call(
        "calendar",
        "get_events",
        service_data,
        target={"entity_id": entity_ids},
        blocking=True,
        return_response=True,
    )
    calendars = response or {}
    count = 0
    if isinstance(calendars, dict):
        for value in calendars.values():
            if isinstance(value, dict) and isinstance(value.get("events"), list):
                count += len(value["events"])
    return {
        "calendars": calendars,
        "entity_ids": entity_ids,
        "start": arguments["start"],
        "end": arguments["end"],
        "count": count,
        "available": True,
    }


async def services_list(hass: Any, auth_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
    del auth_id
    services = hass.services.async_services()
    domain = arguments.get("domain")
    query = str(arguments.get("query") or "").casefold()
    result: dict[str, list[str]] = {}
    for name, methods in services.items():
        if domain and name != domain:
            continue
        selected = sorted(str(method) for method in methods if not query or query in str(method).casefold())
        if selected:
            result[str(name)] = selected
    if arguments.get("compact"):
        return {"domains": sorted(result), "services": sum((list(v) for v in result.values()), [])}
    return {"services": result}


async def target_resolve(hass: Any, auth_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
    del auth_id
    target = arguments.get("target") or {}
    if not isinstance(target, dict):
        raise SuiteBridgeError("INVALID_TARGET", "target skal være et objekt.", 400)
    allowed = set(arguments.get("allowed_domains") or [])
    ids: list[str] = []
    ids.extend(target.get("entity_id", []) if isinstance(target.get("entity_id"), list) else ([target["entity_id"]] if target.get("entity_id") else []))
    if target.get("area_id") or target.get("device_id"):
        # Registry expansion is intentionally conservative; entity_id is always explicit.
        ids = ids or []
    entities = []
    for entity_id in ids:
        state = hass.states.get(entity_id)
        if state is None:
            continue
        if allowed and state.domain not in allowed:
            continue
        entities.append(entity_id)
    return {"entity_ids": entities, "count": len(entities), "unresolved": [x for x in ids if x not in entities]}


def _registry_for(hass: Any, registry: str) -> Any:
    from homeassistant.helpers import area_registry, device_registry, entity_registry, floor_registry, label_registry
    factories = {"entity": entity_registry.async_get, "device": device_registry.async_get, "area": area_registry.async_get, "floor": floor_registry.async_get, "label": label_registry.async_get}
    if registry not in factories:
        raise SuiteBridgeError("INVALID_REGISTRY", "Ukendt registry.", 400)
    return factories[registry](hass)


def _registry_item(item: Any) -> dict[str, Any]:
    for attr in ("extended_dict", "dict_repr"):
        try:
            value = getattr(item, attr, None)
        except Exception:
            continue
        if callable(value):
            try:
                value = value()
            except Exception:
                continue
        if isinstance(value, dict):
            return dict(value)
    try:
        as_dict = getattr(item, "as_dict", None)
        if callable(as_dict):
            value = as_dict()
            if isinstance(value, dict):
                return dict(value)
    except Exception:
        pass
    try:
        return {key: value for key, value in vars(item).items() if not key.startswith("_")}
    except (TypeError, AttributeError):
        try:
            item_id = getattr(item, "id", "")
        except Exception:
            item_id = ""
        return {"id": str(item_id)}


async def registry_list(hass: Any, auth_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
    del auth_id
    registry = _registry_for(hass, arguments["registry"])
    query = str(arguments.get("query") or "").casefold()
    entries = []
    try:
        items = registry.async_items()
    except Exception:
        items = ()
    if isinstance(items, dict):
        items = items.values()
    for item in items:
        data = _registry_item(item)
        if query and query not in str(data).casefold():
            continue
        entries.append(data)
        if len(entries) >= _limit(arguments.get("limit"), 100, 250):
            break
    return {"registry": arguments["registry"], "items": entries, "count": len(entries)}


async def registry_get(hass: Any, auth_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
    del auth_id
    registry = _registry_for(hass, arguments["registry"])
    item = registry.async_get(arguments["id"])
    if item is None:
        raise SuiteBridgeError("REGISTRY_ITEM_NOT_FOUND", "Registry-elementet blev ikke fundet.", 404)
    return {"registry": arguments["registry"], "item": _registry_item(item)}


async def config_entries_list(hass: Any, auth_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
    del auth_id
    entries = []
    for entry in hass.config_entries.async_entries(domain=arguments.get("domain")):
        if arguments.get("state") and entry.state.value != arguments["state"]:
            continue
        entries.append({"entry_id": entry.entry_id, "domain": entry.domain, "title": entry.title, "state": entry.state.value, "disabled_by": entry.disabled_by.value if entry.disabled_by else None})
        if len(entries) >= _limit(arguments.get("limit"), 100, 250):
            break
    return {"entries": entries, "count": len(entries)}


async def config_entries_get(hass: Any, auth_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
    del auth_id
    entry = hass.config_entries.async_get_entry(arguments["entry_id"])
    if entry is None:
        raise SuiteBridgeError("CONFIG_ENTRY_NOT_FOUND", "Config entry blev ikke fundet.", 404)
    return {"entry_id": entry.entry_id, "domain": entry.domain, "title": entry.title, "state": entry.state.value, "data_keys": sorted(entry.data), "options_keys": sorted(entry.options)}


async def automation_traces(hass: Any, auth_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
    try:
        result = await async_ws_command(hass, auth_id, {"type": "trace/list", "domain": "automation", "item_id": arguments["entity_id"].split(".", 1)[-1], "limit": _limit(arguments.get("limit"), 25, 100)})
    except SuiteBridgeError as err:
        return {"traces": [], "available": False, "upstream_error": err.code}
    return {"traces": result or [], "available": True}


async def dashboard_list(hass: Any, auth_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
    try:
        return {"dashboards": await async_ws_command(hass, auth_id, {"type": "lovelace/dashboards/list"})}
    except SuiteBridgeError as err:
        return {"dashboards": [], "available": False, "upstream_error": err.code}


async def dashboard_get(hass: Any, auth_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
    try:
        return {"config": await async_ws_command(hass, auth_id, {"type": "lovelace/config", "url_path": arguments.get("url_path")})}
    except SuiteBridgeError as err:
        return {"config": None, "available": False, "upstream_error": err.code}


async def logs_get(hass: Any, auth_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
    lines = _limit(arguments.get("lines"), 100, 500)
    source = arguments["source"]
    contains = arguments.get("contains")
    if source == "core":
        path = hass.config.path("home-assistant.log")
        def read_tail() -> list[str]:
            with open(path, "rb") as handle:
                handle.seek(0, 2)
                size = handle.tell()
                handle.seek(max(0, size - 1_000_000))
                return handle.read().decode("utf-8", errors="replace").splitlines()
        try:
            selected = await hass.async_add_executor_job(read_tail)
        except OSError as err:
            return {"lines": [], "count": 0, "source": source, "available": False, "error": {"code": "LOG_READ_FAILED", "message": redact_text(str(err))}}
    else:
        endpoint = {"supervisor": "/supervisor/logs", "host": "/host/logs"}.get(source)
        if source == "app":
            slug = str(arguments.get("app_slug") or "").strip()
            if not slug:
                raise SuiteBridgeError("APP_SLUG_REQUIRED", "app_slug er obligatorisk for app-logs.", 422)
            endpoint = f"/addons/{slug}/logs"
        try:
            result = await async_ws_command(hass, auth_id, {"type": "supervisor/api", "endpoint": endpoint, "method": "get"})
            selected = str(result.get("data", result) if isinstance(result, dict) else result).splitlines()
        except SuiteBridgeError as err:
            return {"lines": [], "count": 0, "source": source, "available": False, "error": {"code": err.code, "message": redact_text(err.message)}}
    if contains:
        selected = [line for line in selected if str(contains).casefold() in line.casefold()]
    selected = [redact_text(line) for line in selected[-lines:]]
    return {"lines": selected, "count": len(selected), "source": source, "available": True}


async def supervisor_info(hass: Any, auth_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
    sections = arguments.get("sections") or []
    try:
        result = await async_ws_command(hass, auth_id, {"type": "supervisor/api", "endpoint": "/supervisor/info", "method": "get"})
    except SuiteBridgeError as err:
        return {"sections": {}, "available": False, "upstream_error": err.code}
    return {"sections": result if not sections else {key: result.get(key) for key in sections if isinstance(result, dict) and key in result}}


async def apps_list(hass: Any, auth_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
    try:
        result = await async_ws_command(hass, auth_id, {"type": "supervisor/api", "endpoint": "/store/addons", "method": "get"})
    except SuiteBridgeError as err:
        return {"apps": [], "include_config": bool(arguments.get("include_config")), "available": False, "upstream_error": err.code}
    return {"apps": result or [], "include_config": bool(arguments.get("include_config"))}


async def backups_list(hass: Any, auth_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
    try:
        result = await async_ws_command(hass, auth_id, {"type": "supervisor/api", "endpoint": "/backups", "method": "get"})
    except SuiteBridgeError as err:
        return {"backups": [], "available": False, "upstream_error": err.code}
    return {"backups": (result or {}).get("backups", result or [])[:_limit(arguments.get("limit"), 100, 250)] if isinstance(result, dict) else result}


async def updates_list(hass: Any, auth_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
    try:
        result = await async_ws_command(hass, auth_id, {"type": "supervisor/api", "endpoint": "/core/info", "method": "get"})
    except SuiteBridgeError as err:
        return {"updates": {}, "available": False, "upstream_error": err.code}
    return {"updates": result or {}}
