#!/usr/bin/env python3
import json
from pathlib import Path
import sys

root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
domain = "one_bridge"
suite = root / "custom_components" / domain
assert sorted(path.name for path in (root / "custom_components").iterdir() if path.is_dir()) == [domain]
manifest = json.loads((suite / "manifest.json").read_text(encoding="utf-8"))
metadata = json.loads((root / "PUBLIC_SNAPSHOT.json").read_text(encoding="utf-8"))
hacs = json.loads((root / "hacs.json").read_text(encoding="utf-8"))
assert manifest["domain"] == domain
assert manifest["name"] == "One Bridge"
assert manifest["config_flow"] is True
assert manifest["single_config_entry"] is True
assert manifest["integration_type"] == "service"
assert list(manifest) == [
    "domain",
    "name",
    "after_dependencies",
    "codeowners",
    "config_flow",
    "dependencies",
    "documentation",
    "integration_type",
    "iot_class",
    "issue_tracker",
    "single_config_entry",
    "version",
]
assert manifest["version"] == metadata["version"]
assert metadata["version"].startswith("0.")
const_source = (suite / "const.py").read_text(encoding="utf-8")
assert f'BOOTSTRAP_VERSION = "{metadata["version"]}"' in const_source
assert 'DOMAIN = "one_bridge"' in const_source
assert 'API_VERSION = 1' in const_source
assert 'PRIVATE_CONFIG_RELATIVE = "one-bridge/private/bridge-v1.json"' in const_source
assert 'AUDIT_STORE_KEY = "one_bridge.audit"' in const_source
assert 'BACKUP_RELATIVE = "one_bridge_backups"' in const_source
assert '"source": frozenset' not in const_source
assert '"deployment:source"' not in const_source
assert '"git:commit"' not in const_source
assert '"target": frozenset(COMMON_CAPABILITIES | {"deployment:target"})' in const_source
assert manifest["documentation"] == "https://github.com/TorbenAT/home-assistant-one-bridge"
assert manifest["issue_tracker"] == "https://github.com/TorbenAT/home-assistant-one-bridge/issues"
assert hacs["name"] == "One Bridge"
assert hacs["homeassistant"] == "2026.8.0"
assert (root / "README.md").is_file()
assert (root / "LICENSE").is_file()
assert (suite / "brand" / "icon.png").stat().st_size > 100
strings = json.loads((suite / "strings.json").read_text(encoding="utf-8"))
assert "permissions" in strings["config"]["step"]
assert "capabilities" in strings["config"]["step"]
assert "setup" in strings["options"]["step"]
assert "home_control" in strings["selector"]["permission_preset"]["options"]
capability_options = strings["selector"]["capability"]["options"]
assert "status_read" in capability_options
assert "mutation_apply" in capability_options
assert all(":" not in option for option in capability_options)
assert (suite / "translations" / "en.json").is_file()
assert (suite / "translations" / "da.json").is_file()
config_flow_source = (suite / "config_flow.py").read_text(encoding="utf-8")
assert 'vol.In(["target"])' in config_flow_source
assert 'vol.In(["target", "source"])' not in config_flow_source
views_source = (suite / "views.py").read_text(encoding="utf-8")
init_source = (suite / "__init__.py").read_text(encoding="utf-8")
assert "async_step_permissions" in config_flow_source
assert "async_step_capabilities" in config_flow_source
assert "rotate_client_secret" in config_flow_source
assert 'vol.Required("callback_url"' not in config_flow_source
assert 'vol.Optional("callback_url"' in config_flow_source
assert "_stage_and_show_setup" in config_flow_source
assert "/api/one_bridge/v1/openapi.yaml" in views_source
assert "/api/one_bridge/v1/instructions.txt" in views_source
assert "/api/one_bridge/v1/dispatch" in views_source
assert "/api/one_bridge/v1/apply" in views_source
assert "api:one_bridge:v1" in views_source
legacy_domain = "gpt_" + "suite_bridge_api"
legacy_api_prefix = "/api/gpt_" + "suite_bridge/v2"
assert legacy_domain not in init_source
assert legacy_api_prefix not in views_source
assert "dispatchHomeAssistantBridge" in views_source
assert "applyHomeAssistantBridgeChange" in views_source
assert views_source.count('"x-openai-isConsequential": False') == 1
assert views_source.count('"x-openai-isConsequential": True') == 1
assert '"maximum": 120' not in views_source
assert '"maximum": 180' not in views_source
assert '"schema_sha256"' in views_source
assert "config.config_sha256" not in views_source
assert "OpenAPIView(engine)" in init_source
assert "GPTInstructionsView(engine)" in init_source
assert not list(suite.rglob("__pycache__"))
assert not list(suite.rglob("*.pyc"))
for source_only_name in ("git_commit.py", "release.py", "worker_loader.py"):
    assert not (suite / source_only_name).exists(), source_only_name
catalog = json.loads((suite / "operations.v2.yaml").read_text(encoding="utf-8"))
assert all(
    item.get("capability") not in {"deployment:source", "git:commit"}
    for item in catalog["operations"]
)
installed_text = "
".join(
    path.read_text(encoding="utf-8", errors="replace")
    for path in suite.rglob("*")
    if path.is_file() and path.suffix.lower() in {".py", ".json", ".yaml", ".yml", ".md", ".txt"}
)
for marker in (
    "deployment:source",
    "git:commit",
    "release.prepare",
    "release.apply",
    "bootstrap.status",
    "git.preview.publish",
    "change.prepare.git_commit",
    "ReleaseManager",
    "GitCommitManager",
    "WorkerLoader",
):
    assert marker not in installed_text, marker
print("OK: public HACS layout and onboarding surface")
