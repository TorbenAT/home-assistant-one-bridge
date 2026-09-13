"""Exact OAuth-client and HA-user binding for One Bridge v2."""

from __future__ import annotations

import base64
from collections import defaultdict, deque
from dataclasses import dataclass
from hashlib import sha256
from html import escape
from http import HTTPStatus
import hmac
import json
import logging
import math
import time
from typing import Any
from urllib.parse import urlparse

from aiohttp import web

from homeassistant.components import persistent_notification
from homeassistant.components.http import HomeAssistantView
from homeassistant.components.http.const import (
    KEY_HASS_REFRESH_TOKEN_ID,
    KEY_HASS_USER,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .config import BridgeConfig
from .const import (
    API_APPLY_RATE_MAX,
    API_PREPARE_RATE_MAX,
    API_RATE_WINDOW_SECONDS,
    API_READ_RATE_MAX,
    DOMAIN,
    TOKEN_RATE_MAX_FAILURES,
    TOKEN_RATE_WINDOW_SECONDS,
)
from .models import SuiteBridgeError, enforce_capability_policy


_LOGGER = logging.getLogger(__name__)


def _local_auth_token_endpoint(hass: HomeAssistant) -> tuple[str, bool]:
    """Resolve this instance's own /auth/token endpoint for the token proxy.

    The upstream URL always comes from Home Assistant's own configuration
    (helpers.network), never from request headers such as Host or
    X-Forwarded-*. Loopback HTTP is trusted by construction; HTTPS keeps
    certificate verification on unless the operator explicitly opted out via
    internal_ws_verify_ssl — the same documented escape hatch the WS client
    uses.
    """
    data = hass.data.get(DOMAIN) or {}
    bridge_config = data.get("config") if isinstance(data, dict) else None
    verify_ssl = bool(getattr(bridge_config, "internal_ws_verify_ssl", True))
    try:
        from homeassistant.helpers import network as ha_network

        base_url = ha_network.get_url(
            hass,
            allow_internal=True,
            allow_external=False,
            allow_cloud=False,
            allow_ip=True,
        )
    except Exception:  # noqa: BLE001 - NoURLAvailableError and stub environments
        base_url = "http://127.0.0.1:8123"
    parsed = urlparse(str(base_url))
    scheme = parsed.scheme if parsed.scheme in {"http", "https"} else "http"
    netloc = parsed.netloc or "127.0.0.1:8123"
    return f"{scheme}://{netloc}/auth/token", verify_ssl
_PKCE_ALLOWED_CHARACTERS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-._~"
)


def _valid_pkce_code_verifier(code_verifier: str) -> bool:
    """Validate the RFC 7636 verifier syntax without retaining its value."""
    return 43 <= len(code_verifier) <= 128 and all(
        char in _PKCE_ALLOWED_CHARACTERS for char in code_verifier
    )


@dataclass(frozen=True, slots=True)
class BridgeAuthContext:
    user_id: str
    refresh_token_id: str
    client_id: str
    remote_ip: str
    role: str
    installation_id: str
    capability: str
    oauth_bound: bool

    def audit_metadata(
        self, *, capability: str, operation: str, request_id: str | None
    ) -> dict[str, str]:
        """Return the credential-free metadata required for mutation audit."""
        metadata = {
            "user_id": self.user_id,
            "client_id": self.client_id,
            "capability": capability,
            "operation": operation,
            "remote_ip": self.remote_ip,
        }
        if request_id:
            metadata["request_id"] = request_id
        return metadata


class BridgeAuthorizer:
    def __init__(self, hass: HomeAssistant, config: BridgeConfig) -> None:
        self.hass = hass
        self.config = config
        self._api_calls: dict[str, deque[float]] = defaultdict(deque)

    def _check_api_rate(
        self,
        refresh_token_id: str,
        capability: str,
        *,
        mutation: bool,
    ) -> None:
        now = time.monotonic()
        if capability == "mutation:apply":
            bucket = "apply"
            maximum = API_APPLY_RATE_MAX
        elif mutation:
            bucket = "prepare"
            maximum = API_PREPARE_RATE_MAX
        else:
            bucket = "read"
            maximum = API_READ_RATE_MAX
        key = f"{refresh_token_id}:{bucket}"
        queue = self._api_calls[key]
        while queue and now - queue[0] > API_RATE_WINDOW_SECONDS:
            queue.popleft()
        if len(queue) >= maximum:
            retry_after_seconds = max(
                1,
                math.ceil(API_RATE_WINDOW_SECONDS - (now - queue[0])),
            )
            raise SuiteBridgeError(
                "RATE_LIMITED",
                f"For mange {bucket}-kald; prøv igen efter cooldown.",
                HTTPStatus.TOO_MANY_REQUESTS,
                details={
                    "bucket": bucket,
                    "limit": maximum,
                    "window_seconds": API_RATE_WINDOW_SECONDS,
                    "retry_after_seconds": retry_after_seconds,
                    "recovery": "Genbrug et gyldigt prepare-resultat; lav ikke en dublet-prepare alene på grund af rate limit.",
                },
            )
        queue.append(now)

    def _base_checks(
        self,
        request: web.Request,
        capability: str,
        *,
        mutation: bool,
    ) -> tuple[Any, str]:
        config = self.config
        user = request.get(KEY_HASS_USER)
        refresh_token_id = request.get(KEY_HASS_REFRESH_TOKEN_ID)
        if user is None or not refresh_token_id:
            raise SuiteBridgeError(
                "OAUTH_REQUIRED",
                "Kaldet kræver et Home Assistant OAuth-token.",
                HTTPStatus.UNAUTHORIZED,
            )
        if not user.is_active:
            raise SuiteBridgeError("USER_INACTIVE", "HA-brugeren er deaktiveret.", 403)
        if config.allowed_user_ids and user.id not in config.allowed_user_ids:
            raise SuiteBridgeError(
                "USER_NOT_ALLOWED",
                "HA-brugeren er ikke på Bridge-allowlisten.",
                HTTPStatus.FORBIDDEN,
            )
        if config.require_owner and not user.is_owner:
            raise SuiteBridgeError(
                "OWNER_REQUIRED",
                "Bridge-konfigurationen kræver Home Assistant-ejeren.",
                HTTPStatus.FORBIDDEN,
            )
        if config.require_admin and not user.is_admin:
            raise SuiteBridgeError(
                "ADMIN_REQUIRED",
                "Bridge-konfigurationen kræver en administrator.",
                HTTPStatus.FORBIDDEN,
            )
        enforce_capability_policy(
            capabilities=config.capabilities,
            role=config.role,
            read_only_lockdown=config.read_only_lockdown,
            capability=capability,
            mutation=mutation,
        )
        self._check_api_rate(
            refresh_token_id, capability, mutation=mutation
        )
        return user, refresh_token_id

    def authorize_prebody(self, request: web.Request) -> None:
        """Identity gate for dispatch endpoints, run before the body is read.

        Performs only body-independent checks (bridge enabled, HA user present,
        active and allowlisted). Capability policy and rate limiting stay in
        authorize so unauthenticated traffic cannot cost parse resources while
        authenticated requests keep their exact per-mode semantics.
        """
        config = self.config
        if not config.enabled:
            raise SuiteBridgeError(
                "BRIDGE_NOT_CONFIGURED",
                config.error or "Bridge v2 er ikke aktiveret.",
                HTTPStatus.SERVICE_UNAVAILABLE,
            )
        user = request.get(KEY_HASS_USER)
        refresh_token_id = request.get(KEY_HASS_REFRESH_TOKEN_ID)
        del refresh_token_id
        if user is None:
            raise SuiteBridgeError(
                "OAUTH_REQUIRED",
                "Kaldet kræver et Home Assistant OAuth-token.",
                HTTPStatus.UNAUTHORIZED,
            )
        if not user.is_active:
            raise SuiteBridgeError("USER_INACTIVE", "HA-brugeren er deaktiveret.", 403)
        if config.allowed_user_ids and user.id not in config.allowed_user_ids:
            raise SuiteBridgeError(
                "USER_NOT_ALLOWED",
                "HA-brugeren er ikke på Bridge-allowlisten.",
                HTTPStatus.FORBIDDEN,
            )
        if config.require_owner and not user.is_owner:
            raise SuiteBridgeError(
                "OWNER_REQUIRED",
                "Bridge-konfigurationen kræver Home Assistant-ejeren.",
                HTTPStatus.FORBIDDEN,
            )
        if config.require_admin and not user.is_admin:
            raise SuiteBridgeError(
                "ADMIN_REQUIRED",
                "Bridge-konfigurationen kræver en administrator.",
                HTTPStatus.FORBIDDEN,
            )

    def authorize(
        self,
        request: web.Request,
        capability: str,
        *,
        mutation: bool = False,
        require_bound_client: bool = True,
    ) -> BridgeAuthContext:
        config = self.config
        if not config.enabled:
            raise SuiteBridgeError(
                "BRIDGE_NOT_CONFIGURED",
                config.error or "Bridge v2 er ikke aktiveret.",
                HTTPStatus.SERVICE_UNAVAILABLE,
            )
        user, refresh_token_id = self._base_checks(
            request, capability, mutation=mutation
        )
        refresh_token = self.hass.auth.async_get_refresh_token(refresh_token_id)
        if refresh_token is None:
            raise SuiteBridgeError(
                "OAUTH_SESSION_NOT_FOUND",
                "OAuth-sessionen findes ikke længere.",
                HTTPStatus.UNAUTHORIZED,
            )
        oauth_bound = refresh_token.client_id == config.oauth_client_id
        if require_bound_client and not oauth_bound:
            raise SuiteBridgeError(
                "OAUTH_CLIENT_MISMATCH",
                "Tokenet er ikke udstedt til denne GPT-klient.",
                HTTPStatus.FORBIDDEN,
            )
        return BridgeAuthContext(
            user_id=user.id,
            refresh_token_id=refresh_token_id,
            client_id=refresh_token.client_id or "",
            remote_ip=request.remote or "unknown",
            role=config.role,
            installation_id=config.installation_id,
            capability=capability,
            oauth_bound=oauth_bound,
        )

    def authorize_legacy_route(
        self,
        request: web.Request,
        capability: str,
        *,
        mutation: bool = False,
    ) -> BridgeAuthContext:
        """Protect v1/v3 routes while allowing an explicit migration window."""
        config = self.config
        if not config.enabled:
            # The suite has not been configured yet. Existing authenticated admin
            # routes keep working until the local v2 config is created.
            user = request.get(KEY_HASS_USER)
            refresh_token_id = request.get(KEY_HASS_REFRESH_TOKEN_ID)
            if user is None or not refresh_token_id or not user.is_admin:
                raise SuiteBridgeError("ADMIN_REQUIRED", "Administrator kræves.", 403)
            return BridgeAuthContext(
                user_id=user.id,
                refresh_token_id=refresh_token_id,
                client_id="",
                remote_ip=request.remote or "unknown",
                role="migration",
                installation_id="unconfigured",
                capability=capability,
                oauth_bound=False,
            )
        return self.authorize(
            request,
            capability,
            mutation=mutation,
            require_bound_client=config.enforce_oauth_client,
        )


def _log_safe(value: Any) -> str:
    """Strip control characters so request data cannot forge log lines."""
    return "".join(ch for ch in str(value or "") if ch.isprintable())


class OAuthClientMetadataView(HomeAssistantView):
    """IndieAuth client-id page used by Home Assistant OAuth."""

    url = "/api/one_bridge/v1/oauth/client"
    name = "api:one_bridge:v1:oauth:client"
    requires_auth = False

    def __init__(self, config: BridgeConfig) -> None:
        self._config = config

    async def get(self, request: web.Request) -> web.Response:
        del request
        links = "\n".join(
            f'<link rel="redirect_uri" href="{escape(uri, quote=True)}">'
            for uri in self._config.allowed_redirect_uris
        )
        body = (
            "<!doctype html><html><head><meta charset=\"utf-8\">"
            "<meta name=\"robots\" content=\"noindex,nofollow\">"
            f"{links}<title>One Bridge OAuth client</title></head>"
            "<body><h1>One Bridge OAuth client</h1>"
            "<p>Denne side registrerer kun de tilladte ChatGPT callback-adresser.</p>"
            "</body></html>"
        )
        return web.Response(
            text=body,
            content_type="text/html",
            headers={
                "Cache-Control": "no-store",
                "Content-Security-Policy": "default-src 'none'; style-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
            },
        )


class _FailureLimiter:
    def __init__(self) -> None:
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    def blocked(self, key: str) -> bool:
        now = time.monotonic()
        queue = self._failures[key]
        while queue and now - queue[0] > TOKEN_RATE_WINDOW_SECONDS:
            queue.popleft()
        return len(queue) >= TOKEN_RATE_MAX_FAILURES

    def failed(self, key: str) -> None:
        self._failures[key].append(time.monotonic())

    def succeeded(self, key: str) -> None:
        self._failures.pop(key, None)


def _refresh_token_allowed(config: BridgeConfig, refresh_token: Any) -> bool:
    """Check that a refresh token belongs to this Bridge's OAuth client and users."""
    user = refresh_token.user
    return bool(
        refresh_token.client_id == config.oauth_client_id
        and user.is_active
        and (not config.require_owner or user.is_owner)
        and (not config.require_admin or user.is_admin)
        and (
            not config.allowed_user_ids
            or user.id in config.allowed_user_ids
        )
    )


def _extract_client_credentials(request: web.Request, data: dict[str, str]) -> tuple[str, str]:
    client_id = data.get("client_id", "")
    client_secret = data.get("client_secret", "")
    header = request.headers.get("Authorization", "")
    if header.startswith("Basic "):
        try:
            decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
            basic_id, basic_secret = decoded.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            return "", ""
        if client_id and client_id != basic_id:
            return "", ""
        client_id, client_secret = basic_id, basic_secret
    return client_id, client_secret


class OAuthTokenProxyView(HomeAssistantView):
    """Validate a per-HA client secret, then delegate to HA's native token issuer."""

    url = "/api/one_bridge/v1/oauth/token"
    name = "api:one_bridge:v1:oauth:token"
    requires_auth = False
    # OAuth token exchange is server-to-server; never enable browser CORS here.
    cors_allowed = False

    def __init__(self, hass: HomeAssistant, config: BridgeConfig) -> None:
        self._hass = hass
        self._config = config
        self._limiter = _FailureLimiter()

    def _refresh_token_allowed(self, refresh_token: Any) -> bool:
        return _refresh_token_allowed(self._config, refresh_token)

    def _reject_native_refresh_token(self, token: str) -> None:
        refresh_token = self._hass.auth.async_get_refresh_token_by_token(token)
        if refresh_token is not None:
            self._hass.auth.async_remove_refresh_token(refresh_token)

    async def post(self, request: web.Request) -> web.Response:
        remote = request.remote or "unknown"
        if self._limiter.blocked(remote):
            return web.json_response(
                {"error": "temporarily_unavailable"},
                status=HTTPStatus.TOO_MANY_REQUESTS,
                headers={"Cache-Control": "no-store"},
            )
        if not self._config.enabled:
            return web.json_response(
                {"error": "server_error", "error_description": "Bridge er ikke konfigureret."},
                status=HTTPStatus.SERVICE_UNAVAILABLE,
                headers={"Cache-Control": "no-store"},
            )
        try:
            post = await request.post()
            data = {str(key): str(value) for key, value in post.items()}
        except Exception:
            self._limiter.failed(remote)
            return web.json_response({"error": "invalid_request"}, status=400)

        client_id, client_secret = _extract_client_credentials(request, data)
        supplied_hash = sha256(client_secret.encode("utf-8")).hexdigest()
        if (
            client_id != self._config.oauth_client_id
            or not hmac.compare_digest(supplied_hash, self._config.client_secret_sha256)
        ):
            self._limiter.failed(remote)
            return web.json_response(
                {"error": "invalid_client"},
                status=HTTPStatus.UNAUTHORIZED,
                headers={
                    "Cache-Control": "no-store",
                    "WWW-Authenticate": 'Basic realm="One Bridge OAuth"',
                },
            )

        grant_type = data.get("grant_type")
        if grant_type not in {"authorization_code", "refresh_token"}:
            self._limiter.failed(remote)
            return web.json_response(
                {"error": "unsupported_grant_type"},
                status=HTTPStatus.BAD_REQUEST,
                headers={"Cache-Control": "no-store"},
            )

        forwarded: dict[str, str] = {
            "grant_type": grant_type,
            "client_id": self._config.oauth_client_id,
        }
        supplied_refresh_token = ""
        if grant_type == "authorization_code":
            code = data.get("code", "")
            redirect_uri = data.get("redirect_uri", "")
            if not code or not redirect_uri:
                self._limiter.failed(remote)
                return web.json_response({"error": "invalid_request"}, status=400)
            if redirect_uri not in self._config.allowed_redirect_uris:
                self._limiter.failed(remote)
                return web.json_response(
                    {"error": "invalid_request", "error_description": "redirect_uri er ikke registreret."},
                    status=HTTPStatus.BAD_REQUEST,
                    headers={"Cache-Control": "no-store"},
                )
            forwarded["code"] = code
            # Preserve GPT's exact callback URI for HA's authorization-code
            # validation. Never reconstruct or hardcode a GPT callback here.
            forwarded["redirect_uri"] = redirect_uri
            code_verifier = data.get("code_verifier", "")
            if code_verifier:
                if not _valid_pkce_code_verifier(code_verifier):
                    self._limiter.failed(remote)
                    return web.json_response(
                        {
                            "error": "invalid_request",
                            "error_description": "Ugyldig PKCE code_verifier.",
                        },
                        status=HTTPStatus.BAD_REQUEST,
                        headers={"Cache-Control": "no-store"},
                    )
                forwarded["code_verifier"] = code_verifier
        else:
            supplied_refresh_token = data.get("refresh_token", "")
            if not supplied_refresh_token:
                self._limiter.failed(remote)
                return web.json_response({"error": "invalid_request"}, status=400)
            model = self._hass.auth.async_get_refresh_token_by_token(
                supplied_refresh_token
            )
            if model is None or not self._refresh_token_allowed(model):
                self._limiter.failed(remote)
                return web.json_response(
                    {"error": "invalid_grant"},
                    status=HTTPStatus.UNAUTHORIZED,
                    headers={"Cache-Control": "no-store"},
                )
            forwarded["refresh_token"] = supplied_refresh_token

        session = async_get_clientsession(self._hass)
        token_url, verify_ssl = _local_auth_token_endpoint(self._hass)
        try:
            async with session.post(
                token_url,
                data=forwarded,
                timeout=30,
                ssl=verify_ssl,
            ) as response:
                body = await response.read()
                status = response.status
                content_type = response.headers.get(
                    "Content-Type", "application/json"
                ).split(";", 1)[0]
        except Exception as err:
            _LOGGER.warning(
                "OAuth token upstream network failure: grant_type=%s redirect_uri=%s "
                "client_id_match=%s upstream_status=%s upstream_error=%s exception_type=%s",
                _log_safe(grant_type),
                _log_safe(data.get("redirect_uri", "")),
                client_id == self._config.oauth_client_id,
                "network_error",
                "",
                type(err).__name__,
            )
            return web.json_response(
                {"error": "server_error"},
                status=HTTPStatus.BAD_GATEWAY,
                headers={"Cache-Control": "no-store"},
            )

        if 200 <= status < 300:
            if grant_type == "authorization_code":
                try:
                    native_payload = json.loads(body)
                    raw_refresh = str(native_payload.get("refresh_token", ""))
                except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
                    raw_refresh = ""
                model = (
                    self._hass.auth.async_get_refresh_token_by_token(raw_refresh)
                    if raw_refresh
                    else None
                )
                if model is None or not self._refresh_token_allowed(model):
                    if raw_refresh:
                        self._reject_native_refresh_token(raw_refresh)
                    self._limiter.failed(remote)
                    return web.json_response(
                        {
                            "error": "access_denied",
                            "error_description": "HA-brugeren eller OAuth-klienten er ikke tilladt.",
                        },
                        status=HTTPStatus.FORBIDDEN,
                        headers={"Cache-Control": "no-store"},
                    )
                if self._config.persistent_refresh_token:
                    self._hass.auth.async_set_expiry(
                        model, enable_expiry=False
                    )
                event_data = {
                    "installation_id": self._config.installation_id,
                    "user_id": model.user.id,
                    "client_id": model.client_id,
                    "persistent_refresh_token": self._config.persistent_refresh_token,
                }
                self._hass.bus.async_fire(
                    "gpt_suite_bridge_oauth_authorized", event_data
                )
                persistent_notification.async_create(
                    self._hass,
                    (
                        "En ny GPT Bridge OAuth-forbindelse er godkendt.\n"
                        f"Installation: {self._config.installation_id}\n"
                        f"HA-bruger: {model.user.name or model.user.id}\n"
                        "Forbindelsen kan tilbagekaldes fra brugerens sikkerhedsside."
                    ),
                    title="One Bridge OAuth",
                    notification_id="gpt_suite_bridge_oauth_authorized",
                )
            self._limiter.succeeded(remote)
        else:
            self._limiter.failed(remote)
            upstream_error = ""
            oauth_body: dict[str, Any] | None = None
            if content_type == "application/json":
                try:
                    parsed = json.loads(body)
                    if isinstance(parsed, dict):
                        oauth_body = parsed
                        upstream_error = str(parsed.get("error", ""))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    oauth_body = None
            _LOGGER.warning(
                "OAuth token upstream response: grant_type=%s redirect_uri=%s "
                "client_id_match=%s upstream_status=%s upstream_error=%s exception_type=%s",
                _log_safe(grant_type),
                _log_safe(data.get("redirect_uri", "")),
                client_id == self._config.oauth_client_id,
                status,
                _log_safe(upstream_error),
                "",
            )
            if status == HTTPStatus.BAD_REQUEST and upstream_error in {
                "invalid_grant",
                "invalid_code",
                "invalid_request",
            } and oauth_body is not None:
                return web.json_response(
                    oauth_body,
                    status=HTTPStatus.BAD_REQUEST,
                    headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
                )
            if status >= 500:
                return web.json_response(
                    {"error": "server_error"},
                    status=HTTPStatus.BAD_GATEWAY,
                    headers={"Cache-Control": "no-store"},
                )
        return web.Response(
            body=body,
            status=status,
            content_type=content_type,
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )



class OAuthRevokeProxyView(HomeAssistantView):
    """Revoke a native HA refresh token with the same client authentication."""

    url = "/api/one_bridge/v1/oauth/revoke"
    name = "api:one_bridge:v1:oauth:revoke"
    requires_auth = False
    # Revocation is a server-to-server OAuth endpoint; browser CORS is unnecessary.
    cors_allowed = False

    def __init__(self, hass: HomeAssistant, config: BridgeConfig) -> None:
        self._hass = hass
        self._config = config
        self._limiter = _FailureLimiter()

    async def post(self, request: web.Request) -> web.Response:
        remote = request.remote or "unknown"
        if self._limiter.blocked(remote):
            return web.Response(
                status=HTTPStatus.TOO_MANY_REQUESTS,
                headers={"Cache-Control": "no-store"},
            )
        if not self._config.enabled:
            return web.Response(
                status=HTTPStatus.SERVICE_UNAVAILABLE,
                headers={"Cache-Control": "no-store"},
            )
        post = await request.post()
        data = {str(key): str(value) for key, value in post.items()}
        client_id, client_secret = _extract_client_credentials(request, data)
        supplied_hash = sha256(client_secret.encode("utf-8")).hexdigest()
        if (
            client_id != self._config.oauth_client_id
            or not hmac.compare_digest(supplied_hash, self._config.client_secret_sha256)
        ):
            self._limiter.failed(remote)
            return web.Response(status=HTTPStatus.UNAUTHORIZED)
        token = data.get("token", "")
        # Only revoke tokens that belong to this Bridge's OAuth client and
        # allowed users; never forward arbitrary tokens to Home Assistant.
        model = (
            self._hass.auth.async_get_refresh_token_by_token(token)
            if token
            else None
        )
        if model is None or not _refresh_token_allowed(self._config, model):
            self._limiter.failed(remote)
            return web.Response(status=HTTPStatus.UNAUTHORIZED)
        session = async_get_clientsession(self._hass)
        try:
            async with session.post(
                "http://127.0.0.1:8123/auth/revoke",
                data={"token": token},
                timeout=15,
            ) as response:
                await response.read()
        except Exception:
            self._limiter.failed(remote)
            return web.Response(status=HTTPStatus.BAD_GATEWAY)
        self._limiter.succeeded(remote)
        return web.Response(status=HTTPStatus.OK)
