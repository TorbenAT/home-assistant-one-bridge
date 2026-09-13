"""Read-only Home Assistant entity discovery and state access."""

from __future__ import annotations

from typing import Any

from .models import SuiteBridgeError, json_safe


def _registry_metadata(hass: Any, entity_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        from homeassistant.helpers import device_registry as dr
        from homeassistant.helpers import entity_registry as er

        entity = er.async_get(hass).async_get(entity_id)
        if entity is None:
            return {}, {}
        entity_data = json_safe(vars(entity)) if hasattr(entity, "__dict__") else {}
        device = dr.async_get(hass).async_get(getattr(entity, "device_id", None))
        device_data = json_safe(vars(device)) if device is not None and hasattr(device, "__dict__") else {}
        return entity_data, device_data
    except Exception:
        return {}, {}


def _record(hass: Any, entity_id: str, *, include_attributes: bool = True) -> dict[str, Any] | None:
    state = hass.states.get(entity_id)
    if state is None:
        return None
    attrs = dict(getattr(state, "attributes", {}) or {})
    entity_data, device_data = _registry_metadata(hass, entity_id)
    return {
        "entity_id": entity_id,
        "state": str(getattr(state, "state", "unknown")),
        "attributes": json_safe(attrs) if include_attributes else {},
        "friendly_name": attrs.get("friendly_name") or entity_data.get("name") or entity_data.get("original_name"),
        "unit_of_measurement": attrs.get("unit_of_measurement"),
        "device_class": attrs.get("device_class"),
        "last_changed": getattr(state, "last_changed", None).isoformat() if getattr(state, "last_changed", None) else None,
        "last_updated": getattr(state, "last_updated", None).isoformat() if getattr(state, "last_updated", None) else None,
        "device_name": device_data.get("name_by_user") or device_data.get("name"),
    }


def search_entities(hass: Any, arguments: dict[str, Any]) -> dict[str, Any]:
    query = str(arguments["query"]).casefold().strip()
    domains = {str(value).casefold().strip() for value in arguments.get("domains", [])}
    limit = int(arguments.get("limit", 50))
    matches: list[dict[str, Any]] = []
    for state in hass.states.async_all():
        entity_id = str(state.entity_id)
        domain = entity_id.split(".", 1)[0].casefold()
        if domains and domain not in domains:
            continue
        record = _record(hass, entity_id, include_attributes=False)
        if record is None:
            continue
        haystack = " ".join(
            str(record.get(key) or "")
            for key in ("entity_id", "friendly_name", "device_name", "device_class", "unit_of_measurement")
        ).casefold()
        tokens = [token for token in query.split() if token]
        score = sum(2 if token in haystack else 0 for token in tokens)
        if query in haystack:
            score += 3
        if score == 0:
            continue
        record["domain"] = domain
        record["score"] = score
        matches.append(record)
    matches.sort(key=lambda item: (-int(item["score"]), str(item["entity_id"])))
    return {"query": query, "matches": matches[:limit], "count": min(len(matches), limit)}


def get_states(hass: Any, arguments: dict[str, Any]) -> dict[str, Any]:
    records = []
    for entity_id in arguments["entity_ids"]:
        record = _record(hass, str(entity_id), include_attributes=bool(arguments.get("include_attributes", True)))
        if record is None:
            raise SuiteBridgeError("ENTITY_NOT_FOUND", f"Entity findes ikke: {entity_id}", 404, details={"entity_id": entity_id})
        records.append(record)
    return {"states": records, "count": len(records)}
