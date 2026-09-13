"""One Bridge for Home Assistant."""
from __future__ import annotations

import html
import json
import logging
from pathlib import Path
from typing import Any

from aiohttp import web
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType

from .audit import AuditLog
from .auth import BridgeAuthorizer, OAuthClientMetadataView, OAuthRevokeProxyView, OAuthTokenProxyView
from .config import async_load_config
from .const import API_VERSION, DOMAIN, PREPARE_TTL_SECONDS, PRIVATE_CONFIG_RELATIVE
from .dispatch import OperationCatalog
from .engine import SuiteBridgeEngine
from .models import digest_json
from .prepared import PreparedMutationStore
from .views import (
    ApplyView,
    BackupListView,
    BackupReadView,
    DashboardGetView,
    DashboardListView,
    DashboardMetadataPrepareView,
    DashboardPatchPrepareView,
    DashboardRollbackPrepareView,
    DeploymentStatusView,
    DispatchView as _BaseDispatchView,
    GPTInstructionsView as _BaseGPTInstructionsView,
    GPTSetupView as _BaseGPTSetupView,
    HelperChangePrepareView,
    HelperListView,
    HelperReferencesView,
    MutationApplyView,
    OpenAPIView as _BaseOpenAPIView,
    PrivacyPolicyView,
    RegistryChangePrepareView,
    RegistrySearchView,
    ResourceListView,
    SuiteAuditView,
    SuiteStatusView,
    _allowed_operation_contracts,
    _openapi_document,
    build_gpt_instructions,
)

_LOGGER = logging.getLogger(__name__)
CONFIG_SCHEMA = cv.empty_config_schema(DOMAIN)


def _merge_argument_schema(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    """Return a broad GPT-facing schema while server contracts remain strict."""
    if existing == incoming:
        return dict(existing)
    if "oneOf" in existing:
        variants = list(existing["oneOf"])
        if incoming not in variants:
            variants.append(dict(incoming))
        return {"oneOf": variants}
    existing_type = existing.get("type")
    incoming_type = incoming.get("type")
    if existing_type and existing_type == incoming_type:
        if existing_type == "array":
            return {"type": "array", "items": {}}
        if existing_type == "object":
            return {"type": "object", "additionalProperties": True}
        return {"type": existing_type}
    return {"oneOf": [dict(existing), dict(incoming)]}


def _dispatch_arguments_schema(engine: SuiteBridgeEngine) -> dict[str, Any]:
    """Expose all capability-filtered dispatch argument names to GPT Actions."""
    properties: dict[str, dict[str, Any]] = {}
    contracts = sorted(
        (
            item
            for item in _allowed_operation_contracts(engine)
            if item.get("mode") in {"read", "prepare"}
        ),
        key=lambda item: str(item.get("name", "")),
    )
    for contract in contracts:
        argument_schema = contract.get("arguments") or {}
        raw_properties = argument_schema.get("properties") or {}
        if not isinstance(raw_properties, dict):
            continue
        for name, raw_schema in raw_properties.items():
            if not isinstance(name, str) or not isinstance(raw_schema, dict):
                continue
            schema = dict(raw_schema)
            if name in properties:
                properties[name] = _merge_argument_schema(properties[name], schema)
            else:
                properties[name] = schema
    return {
        "type": "object",
        "properties": {name: properties[name] for name in sorted(properties)},
        "additionalProperties": False,
    }


def _public_openapi_document(engine: SuiteBridgeEngine) -> tuple[dict[str, Any], str]:
    """Return the final public OpenAPI document and its self-excluding fingerprint."""
    document = _openapi_document(engine)
    schemas = document["components"]["schemas"]
    schemas["DispatchArguments"] = _dispatch_arguments_schema(engine)
    schemas["DispatchRequest"]["properties"]["arguments"] = {
        "$ref": "#/components/schemas/DispatchArguments"
    }
    metadata = document["x-one-bridge"]
    metadata.pop("schema_sha256", None)
    fingerprint = digest_json(document)
    metadata["schema_sha256"] = fingerprint
    return document, fingerprint


def _public_gpt_instructions(engine: SuiteBridgeEngine) -> tuple[str, str]:
    """Return GPT instructions carrying the final public OpenAPI fingerprint."""
    _, fingerprint = _public_openapi_document(engine)
    lines = build_gpt_instructions(engine).splitlines()
    text = "\n".join(
        f"Schema fingerprint: {fingerprint}"
        if line.startswith("Schema fingerprint: ")
        else line
        for line in lines
    ) + "\n"
    return text, fingerprint


class OpenAPIView(_BaseOpenAPIView):
    """Generated OpenAPI with explicit dispatch argument properties for GPT Actions."""

    async def get(self, request: web.Request) -> web.Response:
        del request
        document, fingerprint = _public_openapi_document(self._engine)
        return web.Response(
            text=json.dumps(document, indent=2) + "\n",
            content_type="application/yaml",
            headers={
                "Cache-Control": "no-store",
                "X-One-Bridge-Schema": fingerprint,
            },
        )


class GPTInstructionsView(_BaseGPTInstructionsView):
    """Generated GPT instructions matching the final public OpenAPI fingerprint."""

    async def get(self, request: web.Request) -> web.Response:
        del request
        text, fingerprint = _public_gpt_instructions(self._engine)
        return web.Response(
            text=text,
            content_type="text/plain",
            headers={
                "Cache-Control": "no-store",
                "X-One-Bridge-Schema": fingerprint,
            },
        )


def _deployment_visible(engine: SuiteBridgeEngine) -> bool:
    return any(
        capability.startswith("deployment:")
        for capability in engine.config.capabilities
    )


def _filter_public_system_result(
    engine: SuiteBridgeEngine, operation: str, result: Any
) -> Any:
    if not isinstance(result, dict):
        return result
    filtered = dict(result)
    if operation == "system.status":
        filtered["api_version"] = API_VERSION
    if operation == "system.capabilities":
        allowed_operations = sorted(
            str(item["name"])
            for item in _allowed_operation_contracts(engine)
            if item.get("name")
        )
        filtered["implemented_operations"] = allowed_operations
        filtered["catalog_operations"] = len(allowed_operations)
    if not _deployment_visible(engine):
        if operation == "system.status":
            for key in ("release", "worker_version", "worker_commit"):
                filtered.pop(key, None)
        elif operation == "system.capabilities":
            for key in ("release_enabled", "worker_version", "worker_commit"):
                filtered.pop(key, None)
    return filtered


class DispatchView(_BaseDispatchView):
    """Public dispatch response with API-version and capability-aware status."""

    async def post(self, request: web.Request) -> web.Response:
        response = await super().post(request)
        if response.status != 200 or not response.body:
            return response
        try:
            payload = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return response
        operation = payload.get("operation")
        if operation not in {"system.status", "system.capabilities"}:
            return response
        payload["result"] = _filter_public_system_result(
            self._engine, str(operation), payload.get("result")
        )
        return web.json_response(
            payload,
            status=response.status,
            headers={"Cache-Control": "no-store"},
        )


class GPTSetupView(_BaseGPTSetupView):
    """Copy-friendly GPT setup page without exposing the client secret."""

    async def get(self, request: web.Request) -> web.Response:
        del request
        config = self._engine.config
        base = config.public_base_url.rstrip("/")
        public_instructions, _ = _public_gpt_instructions(self._engine)
        values = [
            ("client-id", "Client ID", config.oauth_client_id),
            ("authorization-url", "Authorization URL", f"{base}/auth/authorize"),
            ("token-url", "Token URL", f"{base}/api/one_bridge/v1/oauth/token"),
            ("scope", "Scope", "homeassistant"),
            ("schema-url", "Schema URL", f"{base}/api/one_bridge/v1/openapi.yaml"),
            ("instructions-url", "Instructions URL", f"{base}/api/one_bridge/v1/instructions.txt"),
            ("privacy-url", "Privacy Policy URL", f"{base}/api/one_bridge/v1/privacy"),
            ("gpt-instructions", "GPT Instructions", public_instructions.rstrip()),
        ]
        oauth_bundle = "\n".join(
            f"{label}: {value}" for _, label, value in values[:4]
        )
        diagnostic_bundle = "\n\n".join(
            f"{label}: {value}" for _, label, value in values
        )
        cards = []
        for key, label, value in values:
            cards.append(
                '<section><h2>'
                + html.escape(label)
                + '</h2><pre id="value-'
                + key
                + '">'
                + html.escape(value)
                + '</pre><button type="button" data-copy="value-'
                + key
                + '">Copy</button></section>'
            )
        document = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>One Bridge GPT setup</title>
<style>body{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;line-height:1.45}section{border:1px solid #8885;border-radius:.6rem;padding:1rem;margin:1rem 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0001;padding:.75rem;border-radius:.4rem}button{padding:.55rem .8rem;cursor:pointer;margin:.2rem .35rem .2rem 0}.note{padding:.8rem;border-left:4px solid #888;background:#8881}</style></head><body>
<h1>One Bridge GPT setup</h1>
<p class="note"><strong>Client Secret is intentionally not shown here.</strong> Use the secret shown once during initial setup or secret rotation.</p>
<p><button type="button" data-copy="oauth-bundle">Copy OAuth configuration</button><button type="button" data-copy="value-gpt-instructions">Copy GPT Instructions</button><button type="button" data-copy="diagnostic-bundle">Copy diagnostic bundle</button></p>
<p class="note">The diagnostic bundle is intended for troubleshooting or documentation. It contains no Client Secret, but it does contain installation URLs and the current non-secret GPT configuration.</p>
<pre id="oauth-bundle" hidden>""" + html.escape(oauth_bundle) + """</pre>
<pre id="diagnostic-bundle" hidden>""" + html.escape(diagnostic_bundle) + """</pre>
""" + "".join(cards) + """
<script>document.addEventListener('click',async(e)=>{const b=e.target.closest('[data-copy]');if(!b)return;const n=document.getElementById(b.dataset.copy);if(!n)return;await navigator.clipboard.writeText(n.textContent);const old=b.textContent;b.textContent='Copied';setTimeout(()=>b.textContent=old,1200);});</script>
</body></html>"""
        return web.Response(
            text=document,
            content_type="text/html",
            headers={
                "Cache-Control": "no-store",
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'",
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
            },
        )


async def _async_initialize(hass: HomeAssistant) -> bool:
    existing = hass.data.get(DOMAIN)
    if isinstance(existing, dict) and existing.get("engine") is not None:
        return True
    bridge_config = await async_load_config(hass)
    authorizer = BridgeAuthorizer(hass, bridge_config)
    audit = AuditLog(hass)
    await audit.async_load()
    catalog = await hass.async_add_executor_job(
        OperationCatalog.from_path,
        Path(__file__).with_name("operations.v2.yaml"),
    )
    prepared = PreparedMutationStore(ttl_seconds=PREPARE_TTL_SECONDS)
    engine = SuiteBridgeEngine(
        hass, bridge_config, authorizer, audit, prepared, catalog
    )
    oauth_client_view = OAuthClientMetadataView(bridge_config)
    oauth_token_view = OAuthTokenProxyView(hass, bridge_config)
    oauth_revoke_view = OAuthRevokeProxyView(hass, bridge_config)
    hass.data[DOMAIN] = {
        "config": bridge_config,
        "authorizer": authorizer,
        "audit": audit,
        "prepared": prepared,
        "engine": engine,
        "oauth_views": (
            oauth_client_view,
            oauth_token_view,
            oauth_revoke_view,
        ),
    }
    for oauth_view in (oauth_client_view, oauth_token_view, oauth_revoke_view):
        hass.http.register_view(oauth_view)
    hass.http.register_view(OpenAPIView(engine))
    hass.http.register_view(GPTInstructionsView(engine))
    hass.http.register_view(GPTSetupView(engine))
    hass.http.register_view(PrivacyPolicyView())
    for view_cls in (
        DispatchView,
        ApplyView,
        SuiteStatusView,
        SuiteAuditView,
        DashboardListView,
        DashboardGetView,
        ResourceListView,
        DashboardPatchPrepareView,
        DashboardMetadataPrepareView,
        DashboardRollbackPrepareView,
        RegistrySearchView,
        RegistryChangePrepareView,
        HelperListView,
        HelperReferencesView,
        HelperChangePrepareView,
        BackupListView,
        BackupReadView,
        MutationApplyView,
        DeploymentStatusView,
    ):
        hass.http.register_view(view_cls(engine, authorizer))
    if bridge_config.enabled:
        _LOGGER.info(
            "One Bridge ready; installation=%s; role=%s",
            bridge_config.installation_id,
            bridge_config.role,
        )
    else:
        _LOGGER.warning(
            "One Bridge er installeret, men ikke aktiveret: %s",
            bridge_config.error,
        )
    return True


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    private_config = Path(hass.config.path(PRIVATE_CONFIG_RELATIVE))
    if DOMAIN not in config and not private_config.exists():
        return True
    return await _async_initialize(hass)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    del entry
    return await _async_initialize(hass)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    del hass, entry
    return False
