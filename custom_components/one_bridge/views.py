"""OAuth-bound HTTP views for One Bridge v2."""

from __future__ import annotations

from http import HTTPStatus
import html
import json
import logging
from typing import Any

from aiohttp import web

from homeassistant.components.http import HomeAssistantView

from .auth import BridgeAuthorizer
from .const import BOOTSTRAP_VERSION, MAX_REQUEST_BYTES, PROTOCOL_VERSION
from .engine import SuiteBridgeEngine
from .models import SuiteBridgeError, digest_json, new_id
from .redaction import redact

_LOGGER = logging.getLogger(__name__)


def _envelope(
    request_id: str,
    *,
    data: Any = None,
    error: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "ok": error is None,
        "protocol": PROTOCOL_VERSION,
        "request_id": request_id,
        "data": data if error is None else None,
        "error": error,
    }


def _error(request_id: str, err: SuiteBridgeError) -> web.Response:
    error = {
        "code": err.code,
        "message": redact(err.message),
        **redact(err.details),
    }
    return web.json_response(
        _envelope(
            request_id,
            error=error,
        ),
        status=err.status,
        headers={"Cache-Control": "no-store"},
    )


async def _read_json(request: web.Request, request_id: str) -> dict[str, Any]:
    raw = await request.read()
    if len(raw) > MAX_REQUEST_BYTES:
        raise SuiteBridgeError(
            "REQUEST_TOO_LARGE",
            f"Forespørgslen må højst fylde {MAX_REQUEST_BYTES} bytes.",
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
        )
    try:
        payload = json.loads(raw or b"{}")
    except (json.JSONDecodeError, UnicodeDecodeError) as err:
        raise SuiteBridgeError("INVALID_JSON", "Request body er ikke gyldig JSON.") from err
    if not isinstance(payload, dict):
        raise SuiteBridgeError("INVALID_REQUEST", "Request body skal være et JSON-objekt.")
    return payload


def _public_envelope(
    request_id: str,
    *,
    operation: str,
    mode: str,
    worker_version: str | None = None,
    result: Any = None,
    error: dict[str, Any] | None = None,
) -> dict[str, Any]:
    prepare = None
    verification = None
    rollback = None
    if isinstance(result, dict):
        if "prepare_id" in result:
            prepare = {
                "prepare_id": result.get("prepare_id"),
                "digest": result.get("digest"),
                "expires_at": result.get("expires_at"),
                "summary": (
                    f"Worker {result.get('worker_version')} ved commit "
                    f"{result.get('commit')} er staget."
                ),
                "diff": {
                    "from_commit": result.get("expected_active_commit"),
                    "to_commit": result.get("commit"),
                },
            }
        verification = result.get("verification")
        rollback = result.get("rollback")
    return {
        "ok": error is None,
        "request_id": request_id,
        "protocol_version": str(PROTOCOL_VERSION),
        "bootstrap_version": BOOTSTRAP_VERSION,
        "worker_version": worker_version,
        "operation": operation,
        "mode": mode,
        "result": result if error is None else None,
        "prepare": prepare,
        "verification": verification,
        "rollback": rollback,
        "error": error,
    }


def _allowed_operation_contracts(engine: SuiteBridgeEngine) -> list[dict[str, Any]]:
    return [
        item
        for item in engine.catalog.list(compact=False)
        if item.get("capability") in engine.config.capabilities
        and item.get("name") in engine.implemented_operations
        and (not engine.config.read_only_lockdown or item.get("mode") == "read")
    ]


def _schema_fingerprint(engine: SuiteBridgeEngine) -> str:
    config = engine.config
    return digest_json(
        {
            "role": config.role,
            "permission_preset": config.permission_preset,
            "capabilities": sorted(config.capabilities),
            "read_only_lockdown": config.read_only_lockdown,
            "public_base_url": config.public_base_url,
        }
    )


def build_gpt_instructions(engine: SuiteBridgeEngine) -> str:
    config = engine.config
    writable = "mutation:apply" in config.capabilities and not config.read_only_lockdown
    lines = [
        "You administer this Home Assistant installation through One Bridge.",
        "",
        "Stable Action surface:",
        "- Use dispatchHomeAssistantBridge for read and prepare operations.",
    ]
    if writable:
        lines.append("- Use applyHomeAssistantBridgeChange only for a previously prepared change after explicit user confirmation.")
    else:
        lines.append("- This installation is read-only. Do not attempt prepare or apply operations.")
    lines.extend([
        "",
        f"Installation role: {config.role}",
        f"Permission preset: {config.permission_preset}",
        "Allowed capabilities: " + ", ".join(sorted(config.capabilities)),
        "",
        "Rules:",
        "- Read first. Prefer targeted reads over broad state, log, file or registry dumps.",
        "- The server-side operation catalog is authoritative. Use system.catalog when an operation name or arguments are unknown.",
        "- Never invent operations, modes or fields, and never try to bypass a server rejection.",
        "- Only use operations returned by system.catalog; the catalog is filtered to this installation's allowed capabilities.",
        "- For change.prepare.file_patch, use the latest file sha256 and exact old_content. Line numbers are location hints; the server may safely relocate a patch only when old_content occurs exactly once.",
        "- On FILE_PATCH_MISMATCH, INVALID_FILE_PATCH_RANGE or FILE_PATCH_AMBIGUOUS, re-read the smallest relevant file region and retry from the current sha256. Do not guess a new range or switch to a less strict write path.",
        "- On RATE_LIMITED, respect retry_after_seconds and do not create a duplicate prepare. Reuse the still-valid prepare_id and digest after cooldown; an apply retry uses a fresh idempotency key.",
        "- If an apply response is lost or transport fails, use system.apply.status before deciding whether any retry is safe.",
    ])
    if writable:
        lines.extend([
            "- Every mutation must be prepared first. Inspect the target, before-state, requested change, diff, validation, risk, prepare_id, digest and expiry.",
            "- Apply only with change.apply or release.apply, using the exact server-issued prepare_id and digest, confirmed=true and a fresh idempotency key.",
            "- Do not alter the payload between prepare and apply.",
            "- For destructive or operationally critical changes, state the consequence clearly before apply.",
            "- After apply, verify the server-reported after-state, verification, errors and any rollback before claiming success.",
        ])
    lines.extend([
        "- Never expose OAuth secrets, bearer tokens, refresh tokens, passwords, private keys or other credentials.",
        "- Do not attempt arbitrary shell, generic HTTP/WebSocket proxying or direct .storage writes.",
        "- On errors, report request_id, error code, what was rejected and the next concrete action.",
        "",
        f"Schema URL: {config.public_base_url}/api/one_bridge/v1/openapi.yaml",
        f"Instructions URL: {config.public_base_url}/api/one_bridge/v1/instructions.txt",
        f"Setup URL: {config.public_base_url}/api/one_bridge/v1/setup",
        f"Privacy Policy URL: {config.public_base_url}/api/one_bridge/v1/privacy",
        f"Schema fingerprint: {_schema_fingerprint(engine)}",
    ])
    return "\n".join(lines) + "\n"


def _openapi_document(engine: SuiteBridgeEngine) -> dict[str, Any]:
    config = engine.config
    contracts = _allowed_operation_contracts(engine)
    dispatch_names = sorted(
        item["name"] for item in contracts if item.get("mode") in {"read", "prepare"}
    )
    dispatch_modes = sorted(
        {str(item.get("mode")) for item in contracts if item.get("mode") in {"read", "prepare"}}
    )
    apply_names = sorted(item["name"] for item in contracts if item.get("mode") == "apply")
    paths: dict[str, Any] = {
        "/api/one_bridge/v1/dispatch": {
            "post": {
                "operationId": "dispatchHomeAssistantBridge",
                "summary": "Run an allowed read or prepare operation",
                "description": "Operation names and arguments are validated server-side against the current capability-filtered catalog. Use system.catalog when unsure.",
                "x-openai-isConsequential": False,
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/DispatchRequest"}}},
                },
                "responses": {"200": {"description": "Bridge response", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/BridgeEnvelope"}}}}},
            }
        }
    }
    if apply_names and not config.read_only_lockdown:
        paths["/api/one_bridge/v1/apply"] = {
            "post": {
                "operationId": "applyHomeAssistantBridgeChange",
                "summary": "Apply a confirmed, previously prepared change",
                "description": "Apply accepts only a valid server-issued prepare_id and expected_digest with confirmed=true and a fresh idempotency key.",
                "x-openai-isConsequential": True,
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ApplyRequest"}}},
                },
                "responses": {"200": {"description": "Apply response", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/BridgeEnvelope"}}}}},
            }
        }
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "One Bridge",
            "version": BOOTSTRAP_VERSION,
            "description": "Generated GPT Action schema for this One Bridge installation. The operation enum is filtered to the capabilities currently allowed by Home Assistant.",
        },
        "servers": [{"url": config.public_base_url}],
        "externalDocs": {"description": "Generated GPT instructions", "url": f"{config.public_base_url}/api/one_bridge/v1/instructions.txt"},
        "x-one-bridge": {
            "role": config.role,
            "permission_preset": config.permission_preset,
            "capabilities": sorted(config.capabilities),
            "read_only_lockdown": config.read_only_lockdown,
            "schema_sha256": _schema_fingerprint(engine),
        },
        "paths": paths,
        "components": {
            "schemas": {
                "DispatchRequest": {
                    "type": "object",
                    "properties": {
                        "mode": {"type": "string", "enum": dispatch_modes},
                        "operation": {"type": "string", "enum": dispatch_names},
                        "arguments": {"type": "object", "additionalProperties": True},
                        "request_id": {"type": "string", "minLength": 8, "maxLength": 100},
                        "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 40, "default": 30},
                    },
                    "required": ["mode", "operation"],
                    "additionalProperties": False,
                },
                "ApplyRequest": {
                    "type": "object",
                    "properties": {
                        "operation": {"type": "string", "enum": apply_names},
                        "arguments": {"$ref": "#/components/schemas/ApplyArguments"},
                        "request_id": {"type": "string", "minLength": 8, "maxLength": 100},
                        "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 40, "default": 40},
                    },
                    "required": ["operation", "arguments"],
                    "additionalProperties": False,
                },
                "ApplyArguments": {
                    "type": "object",
                    "properties": {
                        "prepare_id": {"type": "string", "minLength": 8, "maxLength": 200},
                        "expected_digest": {"type": "string", "minLength": 32, "maxLength": 128},
                        "confirmed": {"type": "boolean", "const": True},
                        "idempotency_key": {"type": "string", "minLength": 8, "maxLength": 200},
                    },
                    "required": ["prepare_id", "expected_digest", "confirmed", "idempotency_key"],
                    "additionalProperties": False,
                },
                "BridgeEnvelope": {
                    "type": "object",
                    "properties": {
                        "ok": {"type": "boolean"},
                        "request_id": {"type": "string"},
                        "protocol_version": {"type": "string"},
                        "bootstrap_version": {"type": "string"},
                        "worker_version": {},
                        "operation": {"type": "string"},
                        "mode": {"type": "string"},
                        "result": {},
                        "prepare": {},
                        "verification": {},
                        "rollback": {},
                        "error": {},
                    },
                    "required": [
                        "ok",
                        "request_id",
                        "protocol_version",
                        "bootstrap_version",
                        "worker_version",
                        "operation",
                        "mode",
                        "result",
                        "prepare",
                        "verification",
                        "rollback",
                        "error",
                    ],
                    "additionalProperties": False,
                },
            }
        },
    }


class OpenAPIView(HomeAssistantView):
    url = "/api/one_bridge/v1/openapi.yaml"
    name = "api:one_bridge:v1:openapi"
    requires_auth = False

    def __init__(self, engine: SuiteBridgeEngine) -> None:
        self._engine = engine

    async def get(self, request: web.Request) -> web.Response:
        del request
        return web.Response(
            text=json.dumps(_openapi_document(self._engine), indent=2) + "\n",
            content_type="application/yaml",
            headers={"Cache-Control": "no-store", "X-One-Bridge-Schema": _schema_fingerprint(self._engine)},
        )


class GPTInstructionsView(HomeAssistantView):
    url = "/api/one_bridge/v1/instructions.txt"
    name = "api:one_bridge:v1:instructions"
    requires_auth = False

    def __init__(self, engine: SuiteBridgeEngine) -> None:
        self._engine = engine

    async def get(self, request: web.Request) -> web.Response:
        del request
        return web.Response(
            text=build_gpt_instructions(self._engine),
            content_type="text/plain",
            headers={"Cache-Control": "no-store", "X-One-Bridge-Schema": _schema_fingerprint(self._engine)},
        )


class GPTSetupView(HomeAssistantView):
    url = "/api/one_bridge/v1/setup"
    name = "api:one_bridge:v1:setup"
    requires_auth = False

    def __init__(self, engine: SuiteBridgeEngine) -> None:
        self._engine = engine

    async def get(self, request: web.Request) -> web.Response:
        del request
        config = self._engine.config
        base = config.public_base_url.rstrip("/")
        values = [
            ("Client ID", config.oauth_client_id),
            ("Authorization URL", f"{base}/auth/authorize"),
            ("Token URL", f"{base}/api/one_bridge/v1/oauth/token"),
            ("Scope", "homeassistant"),
            ("Schema URL", f"{base}/api/one_bridge/v1/openapi.yaml"),
            ("Instructions URL", f"{base}/api/one_bridge/v1/instructions.txt"),
            ("Privacy Policy URL", f"{base}/api/one_bridge/v1/privacy"),
            ("GPT Instructions", build_gpt_instructions(self._engine).rstrip()),
        ]
        cards = []
        for index, (label, value) in enumerate(values):
            cards.append(
                '<section><h2>'
                + html.escape(label)
                + '</h2><pre id="value-'
                + str(index)
                + '">'
                + html.escape(value)
                + '</pre><button type="button" data-copy="value-'
                + str(index)
                + '">Copy</button></section>'
            )
        bundle = "\n\n".join(f"{label}: {value}" for label, value in values)
        document = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>One Bridge GPT setup</title>
<style>body{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;line-height:1.45}section{border:1px solid #8885;border-radius:.6rem;padding:1rem;margin:1rem 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0001;padding:.75rem;border-radius:.4rem}button{padding:.55rem .8rem;cursor:pointer}.note{padding:.8rem;border-left:4px solid #888;background:#8881}</style></head><body>
<h1>One Bridge GPT setup</h1>
<p class="note"><strong>Client Secret is intentionally not shown here.</strong> Use the secret shown once during initial setup or secret rotation.</p>
<button type="button" data-copy="bundle">Copy all non-secret setup values</button>
<pre id="bundle" hidden>""" + html.escape(bundle) + """</pre>
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


class PrivacyPolicyView(HomeAssistantView):
    url = "/api/one_bridge/v1/privacy"
    name = "api:one_bridge:v1:privacy"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        del request
        document = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>One Bridge Privacy Policy</title></head><body style="font-family:system-ui,sans-serif;max-width:800px;margin:2rem auto;padding:0 1rem;line-height:1.5">
<h1>One Bridge Privacy Policy</h1>
<p><strong>Last updated:</strong> 2026-08-14</p>
<p>One Bridge is a self-hosted Home Assistant custom integration. Requests from a configured ChatGPT GPT Action are processed by the user's own Home Assistant instance according to the capabilities and security settings selected by that Home Assistant administrator.</p>
<h2>Data processed</h2><p>One Bridge processes the Action request, Home Assistant identity and authorization information, and the Home Assistant data needed to perform the allowed operation. OAuth credentials and tokens are handled locally by the Home Assistant installation.</p>
<h2>Data sharing</h2><p>One Bridge does not operate a hosted data collection service and does not sell user data. Data is exchanged with OpenAI/ChatGPT only when the user configures and invokes the GPT Action, and otherwise remains subject to the user's own Home Assistant environment and integrations.</p>
<h2>Storage and control</h2><p>Configuration, audit information and any persistent credentials created by Home Assistant are controlled by the Home Assistant administrator. The administrator can disable or remove One Bridge and revoke its OAuth access from Home Assistant.</p>
<h2>Security</h2><p>Operations are capability-filtered server-side. Mutations use a prepare/apply flow, and One Bridge does not expose arbitrary shell, generic HTTP proxying, WebSocket proxying or direct Home Assistant .storage writes through the GPT Action surface.</p>
<h2>Contact</h2><p>Questions and issues can be reported at <a href="https://github.com/TorbenAT/home-assistant-one-bridge/issues">the One Bridge issue tracker</a>.</p>
</body></html>"""
        return web.Response(
            text=document,
            content_type="text/html",
            headers={
                "Cache-Control": "no-store",
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'",
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
            },
        )


class _PublicBridgeView(HomeAssistantView):
    engine_method: str
    capability: str
    mutation = False

    def __init__(
        self, engine: SuiteBridgeEngine, authorizer: BridgeAuthorizer
    ) -> None:
        self._engine = engine
        self._authorizer = authorizer

    async def post(self, request: web.Request) -> web.Response:
        request_id = new_id("bridge2")
        operation = ""
        mode = "apply" if self.mutation else ""
        try:
            payload = await _read_json(request, request_id)
            if (
                isinstance(payload.get("request_id"), str)
                and 8 <= len(payload["request_id"]) <= 100
            ):
                request_id = payload["request_id"]
            operation = (
                payload.get("operation")
                if isinstance(payload.get("operation"), str)
                else ""
            )
            if not self.mutation and isinstance(payload.get("mode"), str):
                mode = payload["mode"]
            auth = self._authorizer.authorize(
                request,
                self.capability,
                mutation=self.mutation or mode == "prepare",
                require_bound_client=True,
            )
            method = getattr(self._engine, self.engine_method)
            outcome = await method(payload, auth)
            request_id = outcome.get("request_id") or request_id
            operation = outcome["operation"]
            mode = outcome["mode"]
            result = outcome["result"]
            release_status = self._engine.release.status()
            return self.json(
                _public_envelope(
                    request_id,
                    operation=operation,
                    mode=mode,
                    worker_version=release_status.get("active_worker_version"),
                    result=result,
                ),
                headers={"Cache-Control": "no-store"},
            )
        except SuiteBridgeError as err:
            return web.json_response(
                _public_envelope(
                    request_id,
                    operation=operation,
                    mode=mode or ("apply" if self.mutation else "read"),
                    error={
                        "code": err.code,
                        "message": redact(err.message),
                        "retryable": err.status >= 500,
                        **redact(err.details),
                    },
                ),
                status=err.status,
                headers={"Cache-Control": "no-store"},
            )
        except Exception:
            _LOGGER.exception(
                "Uventet One Bridge dispatch-fejl; request_id=%s",
                request_id,
            )
            return web.json_response(
                _public_envelope(
                    request_id,
                    operation=operation,
                    mode=mode or ("apply" if self.mutation else "read"),
                    error={
                        "code": "INTERNAL_ERROR",
                        "message": (
                            "En intern Bridge-fejl opstod. Se Home Assistant-loggen "
                            "med request-id."
                        ),
                        "retryable": True,
                    },
                ),
                status=500,
                headers={"Cache-Control": "no-store"},
            )


class DispatchView(_PublicBridgeView):
    url = "/api/one_bridge/v1/dispatch"
    name = "api:one_bridge:v1:dispatch"
    engine_method = "dispatch_request"
    capability = "status:read"


class ApplyView(_PublicBridgeView):
    url = "/api/one_bridge/v1/apply"
    name = "api:one_bridge:v1:apply"
    engine_method = "apply_request"
    capability = "mutation:apply"
    mutation = True


class _PostView(HomeAssistantView):
    engine_method: str
    capability: str
    mutation = False

    def __init__(
        self, engine: SuiteBridgeEngine, authorizer: BridgeAuthorizer
    ) -> None:
        self._engine = engine
        self._authorizer = authorizer

    async def post(self, request: web.Request) -> web.Response:
        request_id = new_id("suite2")
        try:
            auth = self._authorizer.authorize(
                request,
                self.capability,
                mutation=self.mutation,
                require_bound_client=True,
            )
            payload = await _read_json(request, request_id)
            method = getattr(self._engine, self.engine_method)
            result = method(payload, auth)
            if hasattr(result, "__await__"):
                result = await result
        except SuiteBridgeError as err:
            return _error(request_id, err)
        except Exception:
            _LOGGER.exception("Uventet One Bridge-fejl; request_id=%s", request_id)
            return _error(
                request_id,
                SuiteBridgeError(
                    "INTERNAL_ERROR",
                    "En intern Suite Bridge-fejl opstod. Se Home Assistant-loggen med request-id.",
                    500,
                ),
            )
        return self.json(
            _envelope(request_id, data=result),
            headers={"Cache-Control": "no-store"},
        )


class SuiteStatusView(_PostView):
    url = "/api/one_bridge/v1/status"
    name = "api:one_bridge:v1:status"
    engine_method = "status"
    capability = "status:read"


class SuiteAuditView(_PostView):
    url = "/api/one_bridge/v1/audit"
    name = "api:one_bridge:v1:audit"
    engine_method = "audit_summary"
    capability = "audit:read"


class DashboardListView(_PostView):
    url = "/api/one_bridge/v1/lovelace/dashboards/list"
    name = "api:one_bridge:v1:lovelace:dashboards:list"
    engine_method = "list_dashboards"
    capability = "lovelace:read"


class DashboardGetView(_PostView):
    url = "/api/one_bridge/v1/lovelace/dashboards/get"
    name = "api:one_bridge:v1:lovelace:dashboards:get"
    engine_method = "get_dashboard"
    capability = "lovelace:read"


class ResourceListView(_PostView):
    url = "/api/one_bridge/v1/lovelace/resources/list"
    name = "api:one_bridge:v1:lovelace:resources:list"
    engine_method = "list_resources"
    capability = "lovelace:read"


class DashboardPatchPrepareView(_PostView):
    url = "/api/one_bridge/v1/lovelace/changes/prepare"
    name = "api:one_bridge:v1:lovelace:changes:prepare"
    engine_method = "prepare_lovelace_patch"
    capability = "lovelace:write"
    mutation = True


class DashboardMetadataPrepareView(_PostView):
    url = "/api/one_bridge/v1/lovelace/metadata/prepare"
    name = "api:one_bridge:v1:lovelace:metadata:prepare"
    engine_method = "prepare_lovelace_metadata"
    capability = "lovelace:write"
    mutation = True


class DashboardRollbackPrepareView(_PostView):
    url = "/api/one_bridge/v1/lovelace/rollback/prepare"
    name = "api:one_bridge:v1:lovelace:rollback:prepare"
    engine_method = "prepare_lovelace_rollback"
    capability = "lovelace:write"
    mutation = True


class RegistrySearchView(_PostView):
    url = "/api/one_bridge/v1/registry/search"
    name = "api:one_bridge:v1:registry:search"
    engine_method = "search_registry"
    capability = "registry:read"


class RegistryChangePrepareView(_PostView):
    url = "/api/one_bridge/v1/registry/changes/prepare"
    name = "api:one_bridge:v1:registry:changes:prepare"
    engine_method = "prepare_registry_change"
    capability = "registry:write"
    mutation = True


class HelperListView(_PostView):
    url = "/api/one_bridge/v1/helpers/list"
    name = "api:one_bridge:v1:helpers:list"
    engine_method = "list_helpers"
    capability = "helpers:read"


class HelperReferencesView(_PostView):
    url = "/api/one_bridge/v1/helpers/references"
    name = "api:one_bridge:v1:helpers:references"
    engine_method = "helper_references"
    capability = "helpers:read"


class HelperChangePrepareView(_PostView):
    url = "/api/one_bridge/v1/helpers/changes/prepare"
    name = "api:one_bridge:v1:helpers:changes:prepare"
    engine_method = "prepare_helper_change"
    capability = "helpers:write"
    mutation = True


class BackupListView(_PostView):
    url = "/api/one_bridge/v1/backups/list"
    name = "api:one_bridge:v1:backups:list"
    engine_method = "list_backups"
    capability = "backup:read"


class BackupReadView(_PostView):
    url = "/api/one_bridge/v1/backups/read"
    name = "api:one_bridge:v1:backups:read"
    engine_method = "read_backup"
    capability = "backup:read"


class MutationApplyView(_PostView):
    url = "/api/one_bridge/v1/mutations/apply"
    name = "api:one_bridge:v1:mutations:apply"
    engine_method = "apply_mutation"
    capability = "mutation:apply"
    mutation = True


class DeploymentStatusView(_PostView):
    url = "/api/one_bridge/v1/deployment/status"
    name = "api:one_bridge:v1:deployment:status"
    engine_method = "deployment_status"
    capability = "deployment:read"
