"""Config flow for One Bridge."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
from typing import Any
from urllib.parse import urlparse

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import network
from homeassistant.helpers.selector import SelectSelector, SelectSelectorConfig, SelectSelectorMode

from .config import BridgeConfig, async_load_config, resolve_allowed_capabilities
from .const import DEFAULT_PERMISSION_PRESET, DOMAIN, PRIVATE_CONFIG_RELATIVE, ROLE_CAPABILITIES


def _https(value: Any, field: str) -> str:
    text = str(value or "").strip().rstrip("/")
    parsed = urlparse(text)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError(field)
    return text


def _public_base_url(value: Any) -> str:
    raw = str(value or "").strip()
    parsed = urlparse(raw)
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("public_base_url")
    return _https(raw, "public_base_url")


def _suggest_public_base_url(hass: HomeAssistant) -> str | None:
    try:
        return _public_base_url(
            network.get_url(
                hass,
                allow_internal=False,
                allow_external=True,
                allow_cloud=True,
                require_ssl=True,
                prefer_external=True,
            )
        )
    except (network.NoURLAvailableError, ValueError):
        return None


def _callback(value: Any) -> str:
    raw = str(value or "").strip()
    text = _https(raw, "callback")
    parsed = urlparse(text)
    parts = parsed.path.split("/")
    if (
        text != raw
        or parsed.hostname not in {"chat.openai.com", "chatgpt.com"}
        or parsed.params
        or parsed.query
        or parsed.fragment
        or len(parts) != 5
        or parts[1] != "aip"
        or not parts[2]
        or parts[3:] != ["oauth", "callback"]
    ):
        raise ValueError("callback")
    return text


def _internal_ws(value: Any) -> str:
    text = str(value or "").strip().rstrip("/")
    if not text:
        return ""
    parsed = urlparse(text)
    if (
        parsed.scheme not in {"ws", "wss"}
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path != "/api/websocket"
    ):
        raise ValueError("internal_ws")
    return text


def _write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _read(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    loaded = json.loads(path.read_text(encoding="utf-8"))
    return loaded if isinstance(loaded, dict) else {}


def _preset_selector() -> SelectSelector:
    return SelectSelector(
        SelectSelectorConfig(
            options=["minimal", "home_control", "read_only", "advanced", "custom"],
            translation_key="permission_preset",
            mode=SelectSelectorMode.DROPDOWN,
        )
    )


_ALL_CAPABILITIES = frozenset().union(*ROLE_CAPABILITIES.values())
_CAPABILITY_OPTION_TO_VALUE = {
    capability.replace(":", "_"): capability for capability in _ALL_CAPABILITIES
}
if len(_CAPABILITY_OPTION_TO_VALUE) != len(_ALL_CAPABILITIES):
    raise RuntimeError("Capability option aliases are not unique.")


def _capability_option(capability: str) -> str:
    return capability.replace(":", "_")


def _capability_values(options: Any) -> list[str]:
    if not isinstance(options, (list, tuple, set, frozenset)):
        raise ValueError("allowed_capabilities skal være en liste.")
    try:
        return [_CAPABILITY_OPTION_TO_VALUE[str(option)] for option in options]
    except KeyError as exc:
        raise ValueError("Ukendt capability-option.") from exc


def _capability_selector(role: str) -> SelectSelector:
    return SelectSelector(
        SelectSelectorConfig(
            options=sorted(_capability_option(value) for value in ROLE_CAPABILITIES[role]),
            translation_key="capability",
            multiple=True,
            mode=SelectSelectorMode.DROPDOWN,
        )
    )


def _raw_capabilities(raw: dict[str, Any]) -> list[str]:
    role = str(raw.get("role", "target")).strip().lower()
    if "permission_preset" not in raw and "allowed_capabilities" not in raw:
        return sorted(ROLE_CAPABILITIES.get(role, frozenset()))
    _, allowed = resolve_allowed_capabilities(
        role,
        raw.get("permission_preset"),
        raw.get("allowed_capabilities"),
    )
    return sorted(allowed)


def _gpt_instructions(raw: dict[str, Any]) -> str:
    base = str(raw.get("public_base_url", "")).rstrip("/")
    role = str(raw.get("role", "target"))
    preset = str(raw.get("permission_preset", "advanced"))
    capabilities = _raw_capabilities(raw)
    writable = "mutation:apply" in capabilities and not bool(raw.get("read_only_lockdown", False))
    lines = [
        "You administer this Home Assistant installation through One Bridge.",
        "Use dispatchHomeAssistantBridge for read and prepare operations.",
    ]
    if writable:
        lines.append("Use applyHomeAssistantBridgeChange only for a previously prepared change after explicit user confirmation.")
    else:
        lines.append("This installation is read-only. Do not attempt prepare or apply operations.")
    lines.extend(
        [
            f"Installation role: {role}.",
            f"Permission preset: {preset}.",
            "Allowed capabilities: " + ", ".join(capabilities) + ".",
            "Read first and prefer targeted reads.",
            "Use system.catalog whenever an operation name or its arguments are unknown; the catalog is server-filtered to allowed capabilities.",
            "Never invent operations, modes or fields, and never bypass a server rejection.",
        ]
    )
    if writable:
        lines.extend(
            [
                "Every mutation must be prepared first. Inspect target, before-state, requested change, diff, validation, risk, prepare_id, digest and expiry.",
                "Apply only with change.apply or release.apply using the exact prepare_id and digest, confirmed=true and a fresh idempotency key.",
                "Do not change the payload between prepare and apply. Verify after-state, verification and rollback before claiming success.",
            ]
        )
    lines.extend(
        [
            "Never expose OAuth secrets, bearer tokens, refresh tokens, passwords, private keys or other credentials.",
            "Do not attempt arbitrary shell, generic HTTP/WebSocket proxying or direct .storage writes.",
            "On errors, report request_id, error code, what was rejected and the next concrete action.",
            f"Schema URL: {base}/api/one_bridge/v1/openapi.yaml",
            f"Instructions URL: {base}/api/one_bridge/v1/instructions.txt",
            f"Setup URL: {base}/api/one_bridge/v1/setup",
            f"Privacy Policy URL: {base}/api/one_bridge/v1/privacy",
        ]
    )
    return "\n".join(lines)


def _setup_placeholders(raw: dict[str, Any], client_secret: str | None) -> dict[str, str]:
    base = str(raw.get("public_base_url", "")).rstrip("/")
    callbacks = raw.get("allowed_redirect_uris") or []
    callback_url = str(callbacks[0]) if callbacks else "Not configured yet — add the callback shown by the GPT editor in One Bridge Options."
    return {
        "client_id": str(raw.get("oauth_client_id", "")),
        "client_secret": client_secret or "Existing secret unchanged; it cannot be read back.",
        "authorization_url": f"{base}/auth/authorize",
        "token_url": f"{base}/api/one_bridge/v1/oauth/token",
        "scope": "homeassistant",
        "callback_url": callback_url,
        "schema_url": f"{base}/api/one_bridge/v1/openapi.yaml",
        "instructions_url": f"{base}/api/one_bridge/v1/instructions.txt",
        "setup_url": f"{base}/api/one_bridge/v1/setup",
        "privacy_url": f"{base}/api/one_bridge/v1/privacy",
        "permission_preset": str(raw.get("permission_preset", "advanced")),
        "capabilities": ", ".join(_raw_capabilities(raw)),
        "gpt_instructions": _gpt_instructions(raw),
    }


def _apply_runtime_config(hass: HomeAssistant, config: BridgeConfig) -> None:
    runtime = hass.data.get(DOMAIN)
    if not isinstance(runtime, dict):
        return
    runtime["config"] = config
    authorizer = runtime.get("authorizer")
    if authorizer is not None:
        authorizer.config = config
    engine = runtime.get("engine")
    if engine is not None:
        engine.config = config
        engine.authorizer.config = config
        for attr in ("lovelace", "registry", "helpers", "deployment"):
            manager = getattr(engine, attr, None)
            if manager is not None and hasattr(manager, "config"):
                manager.config = config
    for view in runtime.get("oauth_views", ()):
        if hasattr(view, "_config"):
            view._config = config


class OneBridgeConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._pending: dict[str, Any] | None = None
        self._secret: str | None = None

    async def async_step_user(self, user_input=None):
        errors = {}
        if user_input is not None:
            try:
                role = str(user_input["role"]).strip().lower()
                if role not in {"source", "target"}:
                    raise ValueError("role")
                base = _public_base_url(user_input["public_base_url"])
                secret = secrets.token_urlsafe(48)
                self._pending = {
                    "enabled": True,
                    "installation_id": f"{role}-{hashlib.sha256(base.encode()).hexdigest()[:12]}",
                    "role": role,
                    "public_base_url": base,
                    "oauth_client_id": f"{base}/api/one_bridge/v1/oauth/client",
                    "client_secret_sha256": hashlib.sha256(secret.encode()).hexdigest(),
                    "allowed_redirect_uris": [],
                    "allowed_user_ids": [],
                    "require_owner": bool(user_input.get("require_owner", False)),
                    "require_admin": bool(user_input.get("require_admin", True)),
                    "enforce_oauth_client": False,
                    "persistent_refresh_token": True,
                    "read_only_lockdown": False,
                    "internal_ws_url": "",
                    "internal_ws_verify_ssl": False,
                }
                self._secret = secret
                await self.async_set_unique_id("one_bridge")
                self._abort_if_unique_id_configured()
                return await self.async_step_permissions()
            except (KeyError, ValueError):
                errors["base"] = "invalid_configuration"
        suggested_public_base_url = _suggest_public_base_url(self.hass)
        public_base_url_key = (
            vol.Required("public_base_url", default=suggested_public_base_url)
            if suggested_public_base_url
            else vol.Required("public_base_url")
        )
        schema = vol.Schema(
            {
                vol.Required("role", default="target"): vol.In(["target"]),
                public_base_url_key: str,
                vol.Required("require_admin", default=True): bool,
                vol.Required("require_owner", default=False): bool,
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def async_step_permissions(self, user_input=None):
        if self._pending is None:
            return self.async_abort(reason="missing_pending_configuration")
        errors = {}
        if user_input is not None:
            try:
                preset = str(user_input["permission_preset"])
                if preset == "custom":
                    self._pending["permission_preset"] = "custom"
                    return await self.async_step_capabilities()
                normalized, allowed = resolve_allowed_capabilities(self._pending["role"], preset)
                self._pending["permission_preset"] = normalized
                self._pending["allowed_capabilities"] = sorted(allowed)
                return await self.async_step_credentials()
            except (KeyError, ValueError):
                errors["base"] = "invalid_permissions"
        schema = vol.Schema(
            {vol.Required("permission_preset", default=DEFAULT_PERMISSION_PRESET): _preset_selector()}
        )
        return self.async_show_form(step_id="permissions", data_schema=schema, errors=errors)

    async def async_step_capabilities(self, user_input=None):
        if self._pending is None:
            return self.async_abort(reason="missing_pending_configuration")
        role = str(self._pending["role"])
        errors = {}
        default = ["status:read", "control:read", "control:write", "mutation:apply"]
        default = [
            _capability_option(value)
            for value in default
            if value in ROLE_CAPABILITIES[role]
        ]
        if user_input is not None:
            try:
                normalized, allowed = resolve_allowed_capabilities(
                    role,
                    "custom",
                    _capability_values(user_input.get("allowed_capabilities", [])),
                )
                self._pending["permission_preset"] = normalized
                self._pending["allowed_capabilities"] = sorted(allowed)
                return await self.async_step_credentials()
            except ValueError:
                errors["base"] = "invalid_permissions"
        schema = vol.Schema(
            {vol.Required("allowed_capabilities", default=default): _capability_selector(role)}
        )
        return self.async_show_form(step_id="capabilities", data_schema=schema, errors=errors)

    async def async_step_credentials(self, user_input=None):
        if self._pending is None or self._secret is None:
            return self.async_abort(reason="missing_pending_configuration")
        errors = {}
        if user_input is not None:
            if bool(user_input.get("confirm")):
                path = Path(self.hass.config.path(PRIVATE_CONFIG_RELATIVE))
                await self.hass.async_add_executor_job(_write, path, dict(self._pending))
                return self.async_create_entry(
                    title=f"One Bridge ({self._pending['role']})",
                    data={
                        "installation_id": self._pending["installation_id"],
                        "role": self._pending["role"],
                        "public_base_url": self._pending["public_base_url"],
                        "callback_url": (self._pending.get("allowed_redirect_uris") or [""])[0],
                        "permission_preset": self._pending["permission_preset"],
                    },
                )
            errors["base"] = "secret_not_confirmed"
        return self.async_show_form(
            step_id="credentials",
            data_schema=vol.Schema({vol.Required("confirm", default=False): bool}),
            errors=errors,
            description_placeholders=_setup_placeholders(self._pending, self._secret),
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return OneBridgeOptionsFlow()


class OneBridgeOptionsFlow(config_entries.OptionsFlow):
    async def _stage_and_show_setup(
        self,
        previous: dict[str, Any],
        updated: dict[str, Any],
        rotate_secret: bool,
    ):
        candidate = dict(updated)
        new_secret = None
        if rotate_secret:
            new_secret = secrets.token_urlsafe(48)
            candidate["client_secret_sha256"] = hashlib.sha256(new_secret.encode()).hexdigest()
        self._previous_raw = dict(previous)
        self._setup_raw = candidate
        self._new_secret = new_secret
        return await self.async_step_setup()

    async def async_step_init(self, user_input=None):
        path = Path(self.hass.config.path(PRIVATE_CONFIG_RELATIVE))
        raw = await self.hass.async_add_executor_job(_read, path)
        if not raw:
            return self.async_abort(reason="missing_pending_configuration")
        role = str(raw.get("role", "target")).strip().lower()
        current_preset = str(raw.get("permission_preset", "advanced"))
        errors = {}
        if user_input is not None:
            try:
                updated = dict(raw)
                updated.update(
                    {
                        "require_admin": bool(user_input.get("require_admin", True)),
                        "require_owner": bool(user_input.get("require_owner", False)),
                        "persistent_refresh_token": bool(user_input.get("persistent_refresh_token", True)),
                        "read_only_lockdown": bool(user_input.get("read_only_lockdown", False)),
                        "internal_ws_url": _internal_ws(user_input.get("internal_ws_url", "")),
                        "internal_ws_verify_ssl": bool(user_input.get("internal_ws_verify_ssl", False)),
                    }
                )
                callback_value = str(user_input.get("callback_url", "")).strip()
                updated["allowed_redirect_uris"] = [_callback(callback_value)] if callback_value else []
                preset = str(user_input.get("permission_preset", current_preset))
                rotate_secret = bool(user_input.get("rotate_client_secret", False))
                if preset == "custom":
                    updated["permission_preset"] = "custom"
                    self._pending_options = updated
                    self._previous_raw = dict(raw)
                    self._rotate_secret = rotate_secret
                    return await self.async_step_capabilities()
                normalized, allowed = resolve_allowed_capabilities(role, preset)
                updated["permission_preset"] = normalized
                updated["allowed_capabilities"] = sorted(allowed)
                if not rotate_secret:
                    previous_without_callback = {
                        key: value
                        for key, value in raw.items()
                        if key != "allowed_redirect_uris"
                    }
                    updated_without_callback = {
                        key: value
                        for key, value in updated.items()
                        if key != "allowed_redirect_uris"
                    }
                    if previous_without_callback == updated_without_callback:
                        path = Path(self.hass.config.path(PRIVATE_CONFIG_RELATIVE))
                        await self.hass.async_add_executor_job(_write, path, updated)
                        config = await async_load_config(self.hass)
                        if not config.enabled:
                            await self.hass.async_add_executor_job(_write, path, raw)
                            return self.async_abort(reason="invalid_saved_configuration")
                        _apply_runtime_config(self.hass, config)
                        return self.async_create_entry(
                            title="",
                            data={
                                "callback_url": (updated.get("allowed_redirect_uris") or [""])[0],
                            },
                        )
                return await self._stage_and_show_setup(raw, updated, rotate_secret)
            except ValueError:
                errors["base"] = "invalid_options"
        callbacks = raw.get("allowed_redirect_uris") or [""]
        schema = vol.Schema(
            {
                vol.Optional("callback_url", default=str(callbacks[0])): str,
                vol.Required("permission_preset", default=current_preset): _preset_selector(),
                vol.Required("require_admin", default=bool(raw.get("require_admin", True))): bool,
                vol.Required("require_owner", default=bool(raw.get("require_owner", False))): bool,
                vol.Required("persistent_refresh_token", default=bool(raw.get("persistent_refresh_token", True))): bool,
                vol.Required("read_only_lockdown", default=bool(raw.get("read_only_lockdown", False))): bool,
                vol.Required("rotate_client_secret", default=False): bool,
                vol.Optional("internal_ws_url", default=str(raw.get("internal_ws_url", "") or "")): str,
                vol.Required("internal_ws_verify_ssl", default=bool(raw.get("internal_ws_verify_ssl", False))): bool,
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema, errors=errors)

    async def async_step_capabilities(self, user_input=None):
        pending = getattr(self, "_pending_options", None)
        if not isinstance(pending, dict):
            return self.async_abort(reason="missing_pending_configuration")
        role = str(pending.get("role", "target"))
        errors = {}
        default = [_capability_option(value) for value in _raw_capabilities(pending)]
        if user_input is not None:
            try:
                normalized, allowed = resolve_allowed_capabilities(
                    role,
                    "custom",
                    _capability_values(user_input.get("allowed_capabilities", [])),
                )
                pending["permission_preset"] = normalized
                pending["allowed_capabilities"] = sorted(allowed)
                previous = getattr(self, "_previous_raw", None)
                if not isinstance(previous, dict):
                    return self.async_abort(reason="missing_pending_configuration")
                return await self._stage_and_show_setup(
                    previous, pending, bool(getattr(self, "_rotate_secret", False))
                )
            except ValueError:
                errors["base"] = "invalid_permissions"
        schema = vol.Schema(
            {vol.Required("allowed_capabilities", default=default): _capability_selector(role)}
        )
        return self.async_show_form(step_id="capabilities", data_schema=schema, errors=errors)

    async def async_step_setup(self, user_input=None):
        raw = getattr(self, "_setup_raw", None)
        if not isinstance(raw, dict):
            return self.async_abort(reason="missing_pending_configuration")
        errors = {}
        if user_input is not None:
            if bool(user_input.get("confirm")):
                previous = getattr(self, "_previous_raw", None)
                if not isinstance(previous, dict):
                    return self.async_abort(reason="missing_pending_configuration")
                path = Path(self.hass.config.path(PRIVATE_CONFIG_RELATIVE))
                await self.hass.async_add_executor_job(_write, path, raw)
                config = await async_load_config(self.hass)
                if not config.enabled:
                    await self.hass.async_add_executor_job(_write, path, previous)
                    return self.async_abort(reason="invalid_saved_configuration")
                _apply_runtime_config(self.hass, config)
                return self.async_create_entry(
                    title="",
                    data={
                        "permission_preset": raw.get("permission_preset"),
                        "callback_url": (raw.get("allowed_redirect_uris") or [""])[0],
                        "read_only_lockdown": bool(raw.get("read_only_lockdown", False)),
                    },
                )
            errors["base"] = "setup_not_confirmed"
        return self.async_show_form(
            step_id="setup",
            data_schema=vol.Schema({vol.Required("confirm", default=False): bool}),
            errors=errors,
            description_placeholders=_setup_placeholders(
                raw, getattr(self, "_new_secret", None)
            ),
        )
