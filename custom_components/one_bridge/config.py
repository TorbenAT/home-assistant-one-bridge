"""Local, non-Git role and OAuth-client configuration."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from homeassistant.core import HomeAssistant

from .const import DEFAULT_PERMISSION_PRESET, PERMISSION_PRESETS, PRIVATE_CONFIG_RELATIVE, ROLE_CAPABILITIES
from .models import digest_json


@dataclass(frozen=True, slots=True)
class BridgeConfig:
    enabled: bool
    installation_id: str
    role: str
    permission_preset: str
    allowed_capabilities: frozenset[str]
    public_base_url: str
    oauth_client_id: str
    client_secret_sha256: str
    allowed_redirect_uris: tuple[str, ...]
    allowed_user_ids: frozenset[str]
    require_owner: bool
    require_admin: bool
    enforce_oauth_client: bool
    persistent_refresh_token: bool
    read_only_lockdown: bool
    internal_ws_url: str
    internal_ws_verify_ssl: bool
    config_sha256: str
    error: str | None = None

    @property
    def capabilities(self) -> frozenset[str]:
        role_capabilities = ROLE_CAPABILITIES.get(self.role, frozenset())
        return frozenset(role_capabilities & self.allowed_capabilities)


def _disabled(error: str) -> BridgeConfig:
    return BridgeConfig(
        enabled=False,
        installation_id="unconfigured",
        role="target",
        permission_preset="minimal",
        allowed_capabilities=frozenset(),
        public_base_url="",
        oauth_client_id="",
        client_secret_sha256="",
        allowed_redirect_uris=(),
        allowed_user_ids=frozenset(),
        require_owner=True,
        require_admin=True,
        enforce_oauth_client=False,
        persistent_refresh_token=True,
        read_only_lockdown=True,
        internal_ws_url="",
        internal_ws_verify_ssl=False,
        config_sha256=digest_json({"error": error}),
        error=error,
    )


def _https_url(value: Any, field: str) -> str:
    text = str(value or "").strip().rstrip("/")
    parsed = urlparse(text)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError(f"{field} skal være en offentlig https-URL uden credentials.")
    return text


def _public_base_url(value: Any) -> str:
    raw = str(value or "").strip()
    parsed = urlparse(raw)
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("public_base_url skal være en ren https-origin uden path, query eller fragment.")
    return _https_url(raw, "public_base_url")


def resolve_allowed_capabilities(
    role: str,
    preset: str | None,
    selected: Any = None,
) -> tuple[str, frozenset[str]]:
    role_capabilities = ROLE_CAPABILITIES.get(role)
    if role_capabilities is None:
        raise ValueError("role skal være source eller target.")
    normalized_preset = str(preset or DEFAULT_PERMISSION_PRESET).strip().lower()
    if normalized_preset == "advanced":
        allowed = set(role_capabilities)
    elif normalized_preset == "custom":
        if not isinstance(selected, (list, tuple, set, frozenset)):
            raise ValueError("allowed_capabilities skal være en liste ved custom permissions.")
        requested = {str(value).strip() for value in selected if str(value).strip()}
        unknown = requested - set(role_capabilities)
        if unknown:
            raise ValueError(f"Ukendte eller rolle-forbudte capabilities: {', '.join(sorted(unknown))}.")
        allowed = requested
    elif normalized_preset in PERMISSION_PRESETS:
        allowed = set(PERMISSION_PRESETS[normalized_preset] & role_capabilities)
    else:
        raise ValueError("permission_preset er ugyldig.")
    allowed.add("status:read")
    has_mutation_source = any(
        capability.endswith(":write")
        or capability in {"deployment:source", "deployment:target", "git:commit"}
        for capability in allowed
    )
    if has_mutation_source:
        allowed.add("mutation:apply")
    else:
        allowed.discard("mutation:apply")
    return normalized_preset, frozenset(allowed & role_capabilities)


def _internal_ws_url(value: Any) -> str:
    text = str(value or "").strip().rstrip("/")
    if not text:
        return ""
    parsed = urlparse(text)
    if parsed.scheme not in {"ws", "wss"}:
        raise ValueError("internal_ws_url skal bruge ws:// eller wss://.")
    if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("internal_ws_url skal pege på loopback.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("internal_ws_url må ikke indeholde credentials, query eller fragment.")
    if parsed.path != "/api/websocket":
        raise ValueError("internal_ws_url skal ende på /api/websocket.")
    return text


def _load_file(path: Path) -> BridgeConfig:
    if not path.exists():
        return _disabled(f"Konfiguration mangler: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as err:
        return _disabled(f"Konfigurationen kunne ikke læses: {err}")
    try:
        if not isinstance(raw, dict):
            raise ValueError("Konfigurationen skal være et JSON-objekt.")
        role = str(raw.get("role", "")).strip().lower()
        if role not in ROLE_CAPABILITIES:
            raise ValueError("role skal være source eller target.")
        if "permission_preset" not in raw and "allowed_capabilities" not in raw:
            permission_preset, allowed_capabilities = "advanced", frozenset(ROLE_CAPABILITIES[role])
        else:
            permission_preset, allowed_capabilities = resolve_allowed_capabilities(
                role,
                raw.get("permission_preset"),
                raw.get("allowed_capabilities"),
            )
        base_url = _public_base_url(raw.get("public_base_url"))
        expected_client = f"{base_url}/api/one_bridge/v1/oauth/client"
        client_id = _https_url(raw.get("oauth_client_id", expected_client), "oauth_client_id")
        if client_id != expected_client:
            raise ValueError("oauth_client_id skal pege på denne installations OAuth-client-side.")

        secret_hash = str(raw.get("client_secret_sha256", "")).strip().lower()
        if len(secret_hash) != 64 or any(ch not in "0123456789abcdef" for ch in secret_hash):
            raise ValueError("client_secret_sha256 skal være en SHA-256-værdi på 64 hextegn.")

        redirects_raw = raw.get("allowed_redirect_uris", [])
        if not isinstance(redirects_raw, list):
            raise ValueError("allowed_redirect_uris skal være en liste.")
        redirects: list[str] = []
        for value in redirects_raw:
            raw_redirect = str(value or "").strip()
            redirect = _https_url(raw_redirect, "redirect_uri")
            parsed = urlparse(redirect)
            parts = parsed.path.split("/")
            if redirect != raw_redirect or parsed.hostname not in {"chat.openai.com", "chatgpt.com"}:
                raise ValueError("Kun officielle ChatGPT callback-URL'er er tilladt.")
            if parsed.params or parsed.query or parsed.fragment or len(parts) != 5 or parts[1] != "aip" or not parts[2] or parts[3:] != ["oauth", "callback"]:
                raise ValueError("Callback-stien har et uventet format.")
            redirects.append(redirect)

        users_raw = raw.get("allowed_user_ids", [])
        if not isinstance(users_raw, list):
            raise ValueError("allowed_user_ids skal være en liste.")
        installation_id = str(raw.get("installation_id", "")).strip()
        if not installation_id or len(installation_id) > 80:
            raise ValueError("installation_id mangler eller er for lang.")

        normalized = {
            "enabled": bool(raw.get("enabled", True)),
            "installation_id": installation_id,
            "role": role,
            "permission_preset": permission_preset,
            "allowed_capabilities": sorted(allowed_capabilities),
            "public_base_url": base_url,
            "oauth_client_id": client_id,
            "client_secret_sha256": secret_hash,
            "allowed_redirect_uris": sorted(set(redirects)),
            "allowed_user_ids": sorted(
                {str(v).strip() for v in users_raw if str(v).strip()}
            ),
            "require_owner": bool(raw.get("require_owner", True)),
            "require_admin": bool(raw.get("require_admin", True)),
            "enforce_oauth_client": bool(raw.get("enforce_oauth_client", False)),
            "persistent_refresh_token": bool(raw.get("persistent_refresh_token", True)),
            "read_only_lockdown": bool(raw.get("read_only_lockdown", False)),
            "internal_ws_url": _internal_ws_url(raw.get("internal_ws_url", "")),
            "internal_ws_verify_ssl": bool(raw.get("internal_ws_verify_ssl", False)),
        }
        return BridgeConfig(
            enabled=normalized["enabled"],
            installation_id=installation_id,
            role=role,
            permission_preset=permission_preset,
            allowed_capabilities=allowed_capabilities,
            public_base_url=base_url,
            oauth_client_id=client_id,
            client_secret_sha256=secret_hash,
            allowed_redirect_uris=tuple(normalized["allowed_redirect_uris"]),
            allowed_user_ids=frozenset(normalized["allowed_user_ids"]),
            require_owner=normalized["require_owner"],
            require_admin=normalized["require_admin"],
            enforce_oauth_client=normalized["enforce_oauth_client"],
            persistent_refresh_token=normalized["persistent_refresh_token"],
            read_only_lockdown=normalized["read_only_lockdown"],
            internal_ws_url=normalized["internal_ws_url"],
            internal_ws_verify_ssl=normalized["internal_ws_verify_ssl"],
            config_sha256=digest_json(normalized),
        )
    except ValueError as err:
        return _disabled(str(err))


async def async_load_config(hass: HomeAssistant) -> BridgeConfig:
    path = Path(hass.config.path(PRIVATE_CONFIG_RELATIVE))
    return await hass.async_add_executor_job(_load_file, path)
