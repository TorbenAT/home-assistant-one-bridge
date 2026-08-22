"""Constants for One Bridge API v2."""

from __future__ import annotations

DOMAIN = "one_bridge"
API_VERSION = 1
PROTOCOL_VERSION = 2
BOOTSTRAP_VERSION = "0.9.2"
CATALOG_VERSION = 2

PRIVATE_CONFIG_RELATIVE = "one-bridge/private/bridge-v1.json"
BACKUP_RELATIVE = "one_bridge_backups"
AUDIT_STORE_KEY = "one_bridge.audit"
AUDIT_STORE_VERSION = 1
AUDIT_MAX_ENTRIES = 1000

PREPARE_TTL_SECONDS = 300
MAX_REQUEST_BYTES = 1_000_000
MAX_PATCH_OPERATIONS = 100
MAX_JSON_BYTES = 2_000_000
MAX_RESULTS = 250
MAX_BACKUPS = 500
MAX_HELPER_REFERENCE_FILES = 500
TOKEN_RATE_WINDOW_SECONDS = 300
TOKEN_RATE_MAX_FAILURES = 12
API_RATE_WINDOW_SECONDS = 60
API_READ_RATE_MAX = 60
API_PREPARE_RATE_MAX = 10
API_APPLY_RATE_MAX = 5

SENSITIVE_KEY_FRAGMENTS = (
    "access_token",
    "api_key",
    "authorization",
    "bearer",
    "client_secret",
    "credential",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "token",
)

HELPER_DOMAINS = (
    "input_boolean",
    "input_number",
    "input_datetime",
    "input_select",
    "input_text",
    "counter",
    "timer",
    "schedule",
)

COMMON_CAPABILITIES = {
    "status:read",
    "audit:read",
    "files:read",
    "files:write",
    "control:read",
    "control:write",
    "lovelace:read",
    "lovelace:write",
    "registry:read",
    "registry:write",
    "helpers:read",
    "helpers:write",
    "backup:read",
    "backup:write",
    "deployment:read",
    "mutation:apply",
}

ROLE_CAPABILITIES = {
    "target": frozenset(COMMON_CAPABILITIES | {"deployment:target"}),
}

PERMISSION_PRESETS = {
    "minimal": frozenset({"status:read", "control:read"}),
    "home_control": frozenset({"status:read", "control:read", "control:write", "mutation:apply"}),
    "read_only": frozenset(capability for capability in COMMON_CAPABILITIES if capability.endswith(":read")),
    "advanced": frozenset(COMMON_CAPABILITIES),
}
DEFAULT_PERMISSION_PRESET = "home_control"

CAPABILITY_LABELS = {
    "status:read": "Bridge status and operation catalog",
    "audit:read": "Audit log",
    "files:read": "Files - read",
    "files:write": "Files - prepare changes",
    "control:read": "Home Assistant states, history and configuration - read",
    "control:write": "Home Assistant services and configuration - prepare changes",
    "lovelace:read": "Dashboards - read",
    "lovelace:write": "Dashboards - prepare changes",
    "registry:read": "Registries - read",
    "registry:write": "Registries - prepare changes",
    "helpers:read": "Helpers - read",
    "helpers:write": "Helpers - prepare changes",
    "backup:read": "Backups - read",
    "backup:write": "Backups - prepare changes",
    "deployment:read": "Supervisor, updates and deployment - read",
    "deployment:target": "Target deployment preparation",
    "mutation:apply": "Apply confirmed prepared changes",
}

HELPER_FIELDS = {
    "input_boolean": frozenset({"name", "icon", "initial"}),
    "input_number": frozenset(
        {"name", "icon", "initial", "min", "max", "step", "mode", "unit_of_measurement"}
    ),
    "input_datetime": frozenset(
        {"name", "icon", "initial", "has_date", "has_time"}
    ),
    "input_select": frozenset({"name", "icon", "initial", "options"}),
    "input_text": frozenset(
        {"name", "icon", "initial", "min", "max", "mode", "pattern"}
    ),
    "counter": frozenset(
        {"name", "icon", "initial", "step", "minimum", "maximum", "restore"}
    ),
    "timer": frozenset({"name", "icon", "duration", "restore"}),
    "schedule": frozenset(
        {"name", "icon", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}
    ),
}
