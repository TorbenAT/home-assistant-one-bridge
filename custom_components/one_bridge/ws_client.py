"""Small internal WebSocket client for official Home Assistant CRUD commands."""

from __future__ import annotations

import asyncio
from contextvars import ContextVar
from typing import Any
from urllib.parse import urlparse

from aiohttp import WSMsgType

from homeassistant.core import HomeAssistant
from homeassistant.helpers import network
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import DOMAIN
from .models import SuiteBridgeError


INTERNAL_WS_MAX_MSG_SIZE = 512 * 1024

# Per-request WS budget. The dispatch/apply envelope accepts timeout_seconds
# from the client; the engine binds it here (request-scoped, concurrency-safe
# via contextvars) instead of silently ignoring the documented field. The hard
# ceiling keeps a slow upstream from holding bridge workers forever.
_WS_COMMAND_TIMEOUT: "ContextVar[int]" = ContextVar("one_bridge_ws_command_timeout", default=25)
_WS_COMMAND_TIMEOUT_CEILING = 185


def command_timeout_token(seconds: Any):
    """Bind this request's WS budget in seconds; reset the token when done."""
    try:
        value = int(seconds)
    except (TypeError, ValueError):
        value = 25
    return _WS_COMMAND_TIMEOUT.set(max(1, min(value, _WS_COMMAND_TIMEOUT_CEILING)))


def reset_command_timeout(token) -> None:
    _WS_COMMAND_TIMEOUT.reset(token)


def resolve_internal_ws_transport(hass: HomeAssistant) -> tuple[str, bool]:
    """Resolve configured or automatically detected local Home Assistant WS transport."""
    data = hass.data.get(DOMAIN) or {}
    bridge_config = data.get("config") if isinstance(data, dict) else None
    configured_url = str(getattr(bridge_config, "internal_ws_url", "") or "").strip()
    # Secure by default: certificate verification is required unless the
    # operator explicitly opted out in the integration configuration.
    verify_ssl = bool(getattr(bridge_config, "internal_ws_verify_ssl", True))
    if configured_url:
        return configured_url, verify_ssl

    try:
        base_url = network.get_url(
            hass,
            allow_internal=True,
            allow_external=False,
            allow_cloud=False,
            allow_ip=True,
        )
    except network.NoURLAvailableError:
        base_url = "http://127.0.0.1:8123"

    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise SuiteBridgeError(
            "INTERNAL_WS_URL_INVALID",
            "Home Assistants interne URL kunne ikke omsættes til WebSocket.",
            500,
        )
    scheme = "wss" if parsed.scheme == "https" else "ws"
    return f"{scheme}://{parsed.netloc}/api/websocket", verify_ssl


async def async_ws_command(
    hass: HomeAssistant,
    refresh_token_id: str,
    command: dict[str, Any],
) -> Any:
    refresh_token = hass.auth.async_get_refresh_token(refresh_token_id)
    if refresh_token is None:
        raise SuiteBridgeError("OAUTH_SESSION_NOT_FOUND", "OAuth-sessionen findes ikke.", 401)
    access_token = hass.auth.async_create_access_token(refresh_token, "127.0.0.1")
    session = async_get_clientsession(hass)
    try:
        async with asyncio.timeout(_WS_COMMAND_TIMEOUT.get()):
            ws_url, verify_ssl = resolve_internal_ws_transport(hass)
            async with session.ws_connect(
                ws_url,
                max_msg_size=INTERNAL_WS_MAX_MSG_SIZE,
                heartbeat=10,
                ssl=verify_ssl,
            ) as ws:
                first = await ws.receive_json()
                if first.get("type") != "auth_required":
                    raise SuiteBridgeError("INTERNAL_WS_PROTOCOL", "Forventede auth_required.")
                await ws.send_json({"type": "auth", "access_token": access_token})
                auth = await ws.receive_json()
                if auth.get("type") != "auth_ok":
                    raise SuiteBridgeError("INTERNAL_WS_AUTH", "Intern WebSocket-auth fejlede.", 403)
                message = {"id": 1, **command}
                await ws.send_json(message)
                while True:
                    reply = await ws.receive()
                    if reply.type in {WSMsgType.CLOSED, WSMsgType.CLOSE, WSMsgType.ERROR}:
                        raise SuiteBridgeError("INTERNAL_WS_CLOSED", "Intern WebSocket lukkede uventet.")
                    if reply.type != WSMsgType.TEXT:
                        continue
                    payload = reply.json()
                    if payload.get("id") != 1 or payload.get("type") != "result":
                        continue
                    if not payload.get("success"):
                        error = payload.get("error") or {}
                        raise SuiteBridgeError(
                            "HOME_ASSISTANT_WS_ERROR",
                            f"{error.get('code', 'unknown')}: {error.get('message', 'Ukendt fejl')}",
                            400,
                        )
                    return payload.get("result")
    except TimeoutError as err:
        raise SuiteBridgeError("INTERNAL_WS_TIMEOUT", "Intern Home Assistant WebSocket timed out.", 504) from err
    except SuiteBridgeError:
        raise
    except Exception as err:
        raise SuiteBridgeError(
            "INTERNAL_WS_FAILED",
            f"Intern Home Assistant WebSocket fejlede: {type(err).__name__}: {err}",
            500,
        ) from err
