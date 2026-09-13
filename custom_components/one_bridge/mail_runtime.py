"""Runtime wiring for the bounded One Bridge mail surface.

Mail is activated after the core engine has validated its normal operation
catalog. The same catalog object is then extended with a separately validated,
typed mail contract and the engine's implemented-operation registry is updated.
"""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
from typing import Any

from .const import DOMAIN
from .dispatch import OperationCatalog, validate_dispatch_envelope
from .mail_ops import (
    apply_mail_send,
    mail_accounts,
    mail_folders,
    mail_get,
    mail_search,
    prepare_mail_send,
)
from .models import SuiteBridgeError, enforce_capability_policy, json_safe

_MAIL_SERVICE = "mail_send_prepared"
_MAIL_OPERATIONS = frozenset(
    {
        "mail.accounts",
        "mail.folders",
        "mail.search",
        "mail.get",
        "change.prepare.mail_send",
    }
)


def _load_mail_contract() -> OperationCatalog:
    path = Path(__file__).with_name("mail_operations.v2.json")
    document = json.loads(path.read_text(encoding="utf-8"))
    return OperationCatalog(document)


def _extend_catalog(catalog: OperationCatalog) -> None:
    extension = _load_mail_contract()
    overlap = catalog.names & extension.names
    if overlap:
        raise RuntimeError(f"Mail operation catalog collision: {sorted(overlap)}")
    for name, contract in extension._operations.items():
        catalog._operations[name] = deepcopy(contract)


def activate_mail_feature(hass: Any, catalog: OperationCatalog, engine: Any) -> None:
    """Activate typed mail operations on one initialized bridge engine."""

    _extend_catalog(catalog)
    engine_cls = type(engine)
    engine_module = sys.modules[engine_cls.__module__]
    engine_module.DISPATCH_OPERATION_HANDLERS = frozenset(
        set(engine_module.DISPATCH_OPERATION_HANDLERS) | set(_MAIL_OPERATIONS)
    )
    engine_module.IMPLEMENTED_OPERATIONS = frozenset(
        set(engine_module.DISPATCH_OPERATION_HANDLERS)
        | set(engine_module.APPLY_OPERATION_HANDLERS)
    )
    engine.implemented_operations = engine_module.IMPLEMENTED_OPERATIONS
    engine.system_operations.implemented_operations = engine_module.IMPLEMENTED_OPERATIONS
    engine._mail_apply_results = {}

    if not getattr(engine_cls, "_one_bridge_mail_patch_installed", False):
        _patch_engine_class(engine_cls, engine_module)

    if not hass.services.has_service(DOMAIN, _MAIL_SERVICE):
        _register_internal_send_service(engine)


def _patch_engine_class(engine_cls: type[Any], engine_module: Any) -> None:
    original_dispatch = engine_cls._dispatch_request
    original_apply_request = engine_cls._apply_request
    original_success_outcome = engine_module._success_outcome

    def patched_success_outcome(result: dict[str, Any], operation: str) -> str:
        if (
            operation == "service.call"
            and result.get("domain") == DOMAIN
            and result.get("service") == _MAIL_SERVICE
        ):
            return engine_module.OUTCOME_APPLIED_VERIFIED
        return original_success_outcome(result, operation)

    engine_module._success_outcome = patched_success_outcome

    async def patched_dispatch(self: Any, payload: dict[str, Any], auth: Any) -> dict[str, Any]:
        envelope = validate_dispatch_envelope(payload)
        operation = envelope["operation"]
        if operation not in _MAIL_OPERATIONS:
            return await original_dispatch(self, payload, auth)

        mode = envelope["mode"]
        arguments = envelope["arguments"]
        contract = self.catalog.resolve(operation, mode, arguments)
        required_capability = str(contract.get("capability"))
        enforce_capability_policy(
            capabilities=self.config.capabilities,
            role=self.config.role,
            read_only_lockdown=self.config.read_only_lockdown,
            capability=required_capability,
            mutation=mode == "prepare",
        )

        if operation == "mail.accounts":
            result = mail_accounts(self.hass)
        elif operation == "mail.folders":
            result = await mail_folders(self.hass, arguments)
        elif operation == "mail.search":
            result = await mail_search(self.hass, arguments)
        elif operation == "mail.get":
            result = await mail_get(self.hass, arguments)
        elif operation == "change.prepare.mail_send":
            result = await _prepare_mail_send(self, arguments, auth, envelope)
        else:
            raise RuntimeError(f"Mail handler registry drift: {operation}")

        return {
            "request_id": envelope.get("request_id"),
            "operation": operation,
            "mode": mode,
            "result": result,
        }

    async def patched_apply_request(self: Any, payload: dict[str, Any], auth: Any) -> dict[str, Any]:
        response = await original_apply_request(self, payload, auth)
        try:
            prepare_id = str(payload.get("arguments", {}).get("prepare_id") or "")
            mail_result = self._mail_apply_results.get(prepare_id)
            result = response.get("result")
            if mail_result is not None and isinstance(result, dict):
                result["mail"] = json_safe(mail_result)
                result["verified"] = bool(mail_result.get("verified"))
                if mail_result.get("verified"):
                    result["outcome"] = engine_module.OUTCOME_APPLIED_VERIFIED
        except Exception:
            # Enrichment never changes the already-recorded apply outcome.
            pass
        return response

    engine_cls._dispatch_request = patched_dispatch
    engine_cls._apply_request = patched_apply_request
    engine_cls._one_bridge_mail_patch_installed = True


async def _prepare_mail_send(
    engine: Any,
    arguments: dict[str, Any],
    auth: Any,
    envelope: dict[str, Any],
) -> dict[str, Any]:
    mail_material, normalized = await prepare_mail_send(engine.hass, arguments)
    service_material = {
        "domain": DOMAIN,
        "service": _MAIL_SERVICE,
        "target": {},
        "data": {"mime_sha256": mail_material["mime_sha256"]},
        "expected": {"entity_ids": [], "not_states": []},
        "verify": False,
        "_mail": mail_material,
    }
    item = await engine.prepared.create(
        user_id=auth.user_id,
        refresh_token_id=auth.refresh_token_id,
        operation="service.call",
        normalized_change=normalized,
        material=service_material,
        risk="high",
    )
    service_material["data"]["prepare_id"] = item.prepare_id
    await engine.audit.append(
        {
            **auth.audit_metadata(
                capability="mail:write",
                operation="change.prepare.mail_send",
                request_id=envelope.get("request_id"),
            ),
            "prepare_id": item.prepare_id,
            "result": "prepared",
            "mail_from": normalized["from"],
            "mail_to": normalized["to"],
            "mail_cc": normalized["cc"],
            "mail_subject": normalized["subject"],
            "message_id": normalized["message_id"],
            "mime_sha256": normalized["mime_sha256"],
        }
    )
    return engine._prepared_response(item)


def _register_internal_send_service(engine: Any) -> None:
    async def async_mail_send(call: Any) -> None:
        prepare_id = str(call.data.get("prepare_id") or "").strip()
        mime_sha256 = str(call.data.get("mime_sha256") or "").strip()
        item = engine.prepared._items.get(prepare_id)
        if (
            item is None
            or not item.in_flight
            or item.operation != "service.call"
            or item.material.get("domain") != DOMAIN
            or item.material.get("service") != _MAIL_SERVICE
        ):
            raise SuiteBridgeError(
                "MAIL_PREPARE_NOT_ACTIVE",
                "Mailafsendelse kræver et aktivt, server-genereret change.apply.",
                409,
            )
        mail_material = item.material.get("_mail")
        if not isinstance(mail_material, dict):
            raise SuiteBridgeError(
                "MAIL_PREPARE_INVALID",
                "Den preparerede mail mangler server-side materiale.",
                409,
            )
        if str(mail_material.get("mime_sha256") or "") != mime_sha256:
            raise SuiteBridgeError(
                "MAIL_MIME_CHANGED",
                "MIME-hashen matcher ikke den preparerede mail.",
                409,
                details={"outcome": "not_applied"},
            )
        result = await apply_mail_send(engine.hass, mail_material)
        engine._mail_apply_results[prepare_id] = result
        while len(engine._mail_apply_results) > 200:
            engine._mail_apply_results.pop(next(iter(engine._mail_apply_results)))
        if not result.get("verified"):
            raise SuiteBridgeError(
                "MAIL_SEND_INCOMPLETE",
                "Mailen blev helt eller delvist sendt, men afsendelsen kunne ikke verificeres som sent_and_saved.",
                409,
                details={
                    "outcome": "applied_unverified",
                    "verification": json_safe(result),
                },
            )

    engine.hass.services.async_register(DOMAIN, _MAIL_SERVICE, async_mail_send)
