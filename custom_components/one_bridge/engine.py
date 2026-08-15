"""Orchestration for One Bridge v2."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
from typing import Any

from homeassistant.core import HomeAssistant

from .audit import AuditLog
from .auth import BridgeAuthContext, BridgeAuthorizer
from .backup import BackupManager
from .config import BridgeConfig
from .const import BOOTSTRAP_VERSION
from .deployment import DeploymentManager
from .entity import get_states, search_entities
from .file_ops import apply_file, list_files, prepare_file, prepare_file_patch, read_file, resolve_path, search_files, validate_file
from .operations import (
    apps_list,
    audit_search,
    automation_traces,
    backups_list,
    calendar_events,
    config_entries_get,
    config_entries_list,
    dashboard_get,
    dashboard_list,
    history,
    logbook,
    logs_get,
    registry_get,
    registry_list,
    services_list,
    statistics,
    supervisor_info,
    target_resolve,
    template_render,
    updates_list,
)
from .dispatch import (
    OperationCatalog,
    SystemOperations,
    validate_apply_envelope,
    validate_dispatch_envelope,
)
from .helpers import HelperManager
from .git_commit import GitCommitManager, default_git_commit_areas
from .lovelace import LovelaceManager
from .models import SuiteBridgeError
from .models import digest_json, json_safe
from .prepared import PreparedMutationStore
from .release import IdempotencyStore, ReleaseManager, ReleasePolicy
from .registry import RegistryManager

DISPATCH_OPERATION_HANDLERS = frozenset(
    {
        "system.status",
        "system.catalog",
        "system.capabilities",
        "system.apply.status",
        "system.prepare.status",
        "system.audit.search",
        "ha.entity.search",
        "ha.state.get",
        "ha.calendar.events",
        "ha.history.get",
        "ha.statistics.get",
        "ha.logbook.get",
        "ha.template.render",
        "ha.services.list",
        "ha.target.resolve",
        "ha.registry.list",
        "ha.registry.get",
        "ha.config_entries.list",
        "ha.config_entries.get",
        "ha.automation.traces",
        "ha.dashboard.list",
        "ha.dashboard.get",
        "ha.logs.get",
        "ha.supervisor.info",
        "ha.apps.list",
        "ha.backups.list",
        "ha.updates.list",
        "files.list",
        "files.read",
        "files.search",
        "files.diff",
        "release.status",
        "bootstrap.status",
        "bootstrap.stage",
        "bootstrap.finalize",
        "git.area.status",
        "git.source.push",
        "git.release_candidate.publish",
        "git.public.status",
        "git.public.cleanup",
        "git.public.tag",
        "git.preview.publish",
        "change.prepare.service",
        "change.prepare.sequence",
        "change.prepare.file",
        "change.prepare.file_patch",
        "esphome.config.validate",
        "esphome.device.status",
        "esphome.logs.get",
        "change.prepare.registry",
        "change.prepare.dashboard",
        "change.prepare.config_entry",
        "change.prepare.supervisor",
        "change.prepare.core",
        "change.prepare.git_commit",
        "release.prepare",
    }
)
APPLY_OPERATION_HANDLERS = frozenset({"change.apply", "release.apply"})
IMPLEMENTED_OPERATIONS = DISPATCH_OPERATION_HANDLERS | APPLY_OPERATION_HANDLERS


class SuiteBridgeEngine:
    def __init__(
        self,
        hass: HomeAssistant,
        config: BridgeConfig,
        authorizer: BridgeAuthorizer,
        audit: AuditLog,
        prepared: PreparedMutationStore,
        release_policy: ReleasePolicy,
    ) -> None:
        self.hass = hass
        self.config = config
        self.authorizer = authorizer
        self.audit = audit
        self.prepared = prepared
        self.backups = BackupManager(hass)
        self.lovelace = LovelaceManager(
            hass, config, prepared, self.backups, audit
        )
        self.registry = RegistryManager(
            hass, config, prepared, self.backups, audit
        )
        self.helpers = HelperManager(
            hass, config, prepared, self.backups, audit, self.lovelace
        )
        repository_policy = release_policy.repositories[0] if release_policy.enabled and release_policy.repositories else None
        expected_remote_suffix = repository_policy.git_remote_suffix if repository_policy else None
        repo_relative = release_policy.git_repo_relative if release_policy.enabled else None
        deployment_marker_relative = release_policy.deployment_marker_relative if release_policy.enabled else None
        self.deployment = DeploymentManager(
            hass,
            config,
            expected_remote_suffix,
            repo_relative,
            deployment_marker_relative,
        )
        self.git_commits = GitCommitManager(
            Path(hass.config.path()),
            default_git_commit_areas(expected_remote_suffix, repo_relative),
        )
        self.catalog = OperationCatalog.from_path(
            Path(__file__).with_name("operations.v2.yaml")
        )
        self.release = ReleaseManager(
            release_policy,
            prepared,
            audit=audit,
            run_blocking=hass.async_add_executor_job,
        )
        self.change_idempotency = IdempotencyStore()
        self.implemented_operations = IMPLEMENTED_OPERATIONS
        if self.catalog.names != self.implemented_operations:
            missing = sorted(self.catalog.names - self.implemented_operations)
            extra = sorted(self.implemented_operations - self.catalog.names)
            raise RuntimeError(
                f"Operation handler registry drift; missing={missing}; extra={extra}"
            )
        self.system_operations = SystemOperations(
            self.catalog, self.release.status, self.implemented_operations
        )

    def status(self, payload: dict[str, Any], auth: BridgeAuthContext) -> dict[str, Any]:
        del payload
        return {
            "api_version": 2,
            "protocol": 2,
            "enabled": self.config.enabled,
            "installation_id": self.config.installation_id,
            "role": self.config.role,
            "oauth_bound": auth.oauth_bound,
            "oauth_client_id": self.config.oauth_client_id,
            "oauth_enforcement": self.config.enforce_oauth_client,
            "persistent_refresh_token": self.config.persistent_refresh_token,
            "read_only_lockdown": self.config.read_only_lockdown,
            "internal_ws_mode": "custom" if self.config.internal_ws_url else "auto",
            "internal_ws_url": self.config.internal_ws_url or None,
            "internal_ws_verify_ssl": self.config.internal_ws_verify_ssl,
            "config_sha256": self.config.config_sha256,
            "capabilities": sorted(self.config.capabilities),
            "raw_storage_access": False,
            "git_mutation_api": "git:commit" in self.config.capabilities,
        }

    def _system_status(self, auth: BridgeAuthContext) -> dict[str, Any]:
        return self.system_operations.status(self.status({}, auth))

    def _system_catalog(self, arguments: dict[str, Any]) -> dict[str, Any]:
        items = self.catalog.list(
            operation=arguments.get("operation"),
            mode=arguments.get("mode"),
            compact=False,
        )
        items = [
            item
            for item in items
            if item.get("capability") in self.config.capabilities
            and (not self.config.read_only_lockdown or item.get("mode") == "read")
        ]
        for item in items:
            item["implemented"] = item["name"] in self.implemented_operations
        if bool(arguments.get("compact", False)):
            items = [
                {
                    "name": item["name"],
                    "mode": item.get("mode"),
                    "risk": item.get("risk"),
                    "description": item.get("description"),
                    "implemented": item.get("implemented", False),
                }
                for item in items
            ]
        return {
            "schema_version": self.catalog.schema_version,
            "catalog_version": self.catalog.catalog_version,
            "permission_preset": self.config.permission_preset,
            "capabilities": sorted(self.config.capabilities),
            "read_only_lockdown": self.config.read_only_lockdown,
            "operations": items,
        }

    def _system_capabilities(self) -> dict[str, Any]:
        result = self.system_operations.capabilities()
        result["permission_preset"] = self.config.permission_preset
        result["allowed_capabilities"] = sorted(self.config.capabilities)
        result["read_only_lockdown"] = self.config.read_only_lockdown
        return result

    def _system_apply_status(self, arguments: dict[str, Any]) -> dict[str, Any]:
        prepare_id = str(arguments.get("prepare_id", "")).strip()
        request_id = str(arguments.get("request_id", "")).strip()
        idempotency_key = str(arguments.get("idempotency_key", "")).strip()
        if not any((prepare_id, request_id, idempotency_key)):
            raise SuiteBridgeError(
                "APPLY_STATUS_SELECTOR_REQUIRED",
                "Angiv prepare_id, request_id eller idempotency_key.",
                422,
            )
        item = self.audit.find_latest(
            prepare_id=prepare_id,
            request_id=request_id,
            idempotency_key=idempotency_key,
        )
        selector = {
            key: value
            for key, value in {
                "prepare_id": prepare_id,
                "request_id": request_id,
                "idempotency_key": idempotency_key,
            }.items()
            if value
        }
        if item is None:
            return {"found": False, "selector": selector}
        allowed = (
            "audit_id",
            "timestamp",
            "operation",
            "prepare_id",
            "request_id",
            "idempotency_key",
            "result",
            "details",
            "error",
            "message",
        )
        receipt = {key: item[key] for key in allowed if key in item}
        return {
            "found": True,
            "selector": selector,
            "status": item.get("result"),
            "receipt": receipt,
        }

    async def _system_prepare_status(
        self, arguments: dict[str, Any], auth: BridgeAuthContext
    ) -> dict[str, Any]:
        return await self.prepared.status(
            prepare_id=str(arguments["prepare_id"]).strip(),
            user_id=auth.user_id,
            refresh_token_id=auth.refresh_token_id,
        )

    async def dispatch_request(
        self, payload: dict[str, Any], auth: BridgeAuthContext
    ) -> dict[str, Any]:
        envelope = validate_dispatch_envelope(payload)
        operation = envelope["operation"]
        mode = envelope["mode"]
        arguments = envelope["arguments"]
        contract = self.catalog.resolve(operation, mode, arguments)
        required_capability = contract.get("capability")
        if required_capability not in self.config.capabilities:
            raise SuiteBridgeError(
                "CAPABILITY_DENIED",
                f"Rollen {self.config.role} tillader ikke capability "
                f"{required_capability}.",
                403,
            )
        if operation == "system.status":
            result = self._system_status(auth)
        elif operation == "system.catalog":
            result = self._system_catalog(arguments)
        elif operation == "system.capabilities":
            result = self._system_capabilities()
        elif operation == "system.apply.status":
            result = self._system_apply_status(arguments)
        elif operation == "system.prepare.status":
            result = await self._system_prepare_status(arguments, auth)
        elif operation == "release.status":
            result = self.release.status()
        elif operation == "bootstrap.status":
            result = await self.hass.async_add_executor_job(
                self.git_commits.bootstrap_status
            )
        elif operation == "bootstrap.stage":
            result = await self._prepare_bootstrap_stage(arguments, auth)
        elif operation == "bootstrap.finalize":
            result = await self._prepare_bootstrap_finalize(arguments, auth)
        elif operation == "git.area.status":
            result = await self.hass.async_add_executor_job(
                self.git_commits.status, arguments["area"]
            )
        elif operation == "git.source.push":
            result = await self._prepare_git_source_push(arguments, auth)
        elif operation == "git.release_candidate.publish":
            result = await self._prepare_git_release_candidate(arguments, auth)
        elif operation == "git.public.status":
            result = await self.hass.async_add_executor_job(self.git_commits.public_status)
        elif operation == "git.public.cleanup":
            result = await self._prepare_git_public_cleanup(arguments, auth)
        elif operation == "git.public.tag":
            result = await self._prepare_git_public_tag(arguments, auth)
        elif operation == "git.preview.publish":
            result = await self._prepare_git_preview(arguments, auth)
        elif operation == "release.prepare":
            result = await self.release.prepare(
                arguments,
                user_id=auth.user_id,
                refresh_token_id=auth.refresh_token_id,
            )
        elif operation == "ha.entity.search":
            result = search_entities(self.hass, arguments)
        elif operation == "ha.calendar.events":
            result = await calendar_events(self.hass, auth.refresh_token_id, arguments)
        elif operation == "ha.state.get":
            result = get_states(self.hass, arguments)
        elif operation == "system.audit.search":
            result = await audit_search(self.audit, arguments)
        elif operation == "ha.history.get":
            result = await history(self.hass, auth.refresh_token_id, arguments)
        elif operation == "ha.statistics.get":
            result = await statistics(self.hass, auth.refresh_token_id, arguments)
        elif operation == "ha.logbook.get":
            result = await logbook(self.hass, auth.refresh_token_id, arguments)
        elif operation == "ha.template.render":
            result = await template_render(self.hass, auth.refresh_token_id, arguments)
        elif operation == "ha.services.list":
            result = await services_list(self.hass, auth.refresh_token_id, arguments)
        elif operation == "ha.target.resolve":
            result = await target_resolve(self.hass, auth.refresh_token_id, arguments)
        elif operation == "ha.registry.list":
            result = await registry_list(self.hass, auth.refresh_token_id, arguments)
        elif operation == "ha.registry.get":
            result = await registry_get(self.hass, auth.refresh_token_id, arguments)
        elif operation == "ha.config_entries.list":
            result = await config_entries_list(self.hass, auth.refresh_token_id, arguments)
        elif operation == "ha.config_entries.get":
            result = await config_entries_get(self.hass, auth.refresh_token_id, arguments)
        elif operation == "ha.automation.traces":
            result = await automation_traces(self.hass, auth.refresh_token_id, arguments)
        elif operation == "ha.dashboard.list":
            result = await self.lovelace.list_dashboards(auth.refresh_token_id, arguments)
        elif operation == "ha.dashboard.get":
            result = await self.lovelace.get_dashboard(arguments)
        elif operation == "ha.logs.get":
            result = await logs_get(self.hass, auth.refresh_token_id, arguments)
        elif operation == "ha.supervisor.info":
            result = await supervisor_info(self.hass, auth.refresh_token_id, arguments)
        elif operation == "ha.apps.list":
            result = await apps_list(self.hass, auth.refresh_token_id, arguments)
        elif operation == "ha.backups.list":
            result = await backups_list(self.hass, auth.refresh_token_id, arguments)
        elif operation == "ha.updates.list":
            result = await updates_list(self.hass, auth.refresh_token_id, arguments)
        elif operation == "files.list":
            result = await self.hass.async_add_executor_job(list_files, self.hass, arguments)
        elif operation == "files.read":
            result = await self.hass.async_add_executor_job(read_file, self.hass, arguments)
        elif operation == "files.search":
            result = await self.hass.async_add_executor_job(search_files, self.hass, arguments)
        elif operation == "files.diff":
            result = await self.hass.async_add_executor_job(prepare_file, self.hass, arguments)
            result.pop("new_content", None)
        elif operation == "change.prepare.file":
            result = await self._prepare_file(arguments, auth)
        elif operation == "change.prepare.file_patch":
            result = await self._prepare_file_patch(arguments, auth)
        elif operation == "esphome.config.validate":
            result = await self.hass.async_add_executor_job(validate_file, self.hass, {**arguments, "validation_profile": "esphome_yaml"})
        elif operation == "esphome.device.status":
            states = get_states(self.hass, {"entity_ids": arguments["entity_ids"], "include_attributes": bool(arguments.get("include_attributes", False))})
            unavailable = [item["entity_id"] for item in states["states"] if item["state"] in {"unavailable", "unknown"}]
            result = {**states, "available": not unavailable, "unavailable_entities": unavailable}
        elif operation == "esphome.logs.get":
            result = await logs_get(self.hass, auth.refresh_token_id, {"source": "core", "contains": arguments["device"], "lines": arguments.get("lines", 100)})
            result["device"] = arguments["device"]
        elif operation == "change.prepare.service":
            result = await self._prepare_service(arguments, auth)
        elif operation == "change.prepare.sequence":
            result = await self._prepare_sequence(arguments, auth)
        elif operation == "change.prepare.registry":
            result = await self._prepare_registry(arguments, auth)
        elif operation == "change.prepare.dashboard":
            result = await self._prepare_dashboard(arguments, auth)
        elif operation == "change.prepare.config_entry":
            result = await self._prepare_config_entry(arguments, auth)
        elif operation == "change.prepare.supervisor":
            result = await self._prepare_supervisor(arguments, auth)
        elif operation == "change.prepare.core":
            result = await self._prepare_core(arguments, auth)
        elif operation == "change.prepare.git_commit":
            result = await self._prepare_git_commit(arguments, auth)
        else:
            raise RuntimeError(
                f"Operation handler registry drift for dispatch: {operation}"
            )
        return {
            "request_id": envelope.get("request_id"),
            "operation": operation,
            "mode": mode,
            "result": result,
        }

    @staticmethod
    def _prepared_response(item: Any) -> dict[str, Any]:
        result = {
            "prepare_id": item.prepare_id,
            "request_digest": item.digest,
            "digest": item.digest,
            "expires_at": item.expires_at,
            "risk": item.risk,
            "normalized_change": json_safe(item.normalized_change),
        }
        if item.operation == "file.update":
            material = item.material
            result.update({
                "target": {"root": material["root"], "path": material["path"]},
                "before": {"sha256": material["before_sha256"]},
                "after": {"sha256": material["after_sha256"]},
                "patch_ranges": material.get("patches", []),
                "diff": material.get("diff", ""),
                "validation": material.get("validation", {"ok": True, "profile": None}),
            })
        return result

    async def _prepare_file(self, arguments: dict[str, Any], auth: BridgeAuthContext) -> dict[str, Any]:
        material = await self.hass.async_add_executor_job(prepare_file, self.hass, arguments)
        item = await self.prepared.create(
            user_id=auth.user_id, refresh_token_id=auth.refresh_token_id,
            operation="file.update", normalized_change={k: v for k, v in material.items() if k != "new_content"},
            material=material, risk="normal",
        )
        await self.audit.append({"operation": "change.prepare.file", "user_id": auth.user_id, "prepare_id": item.prepare_id, "root": material["root"], "path": material["path"], "before_sha256": material["before_sha256"], "after_sha256": material["after_sha256"], "result": "prepared"})
        return self._prepared_response(item)

    async def _prepare_file_patch(self, arguments: dict[str, Any], auth: BridgeAuthContext) -> dict[str, Any]:
        material = await self.hass.async_add_executor_job(prepare_file_patch, self.hass, arguments)
        item = await self.prepared.create(
            user_id=auth.user_id, refresh_token_id=auth.refresh_token_id,
            operation="file.update", normalized_change={k: v for k, v in material.items() if k != "new_content"},
            material=material, risk="normal",
        )
        await self.audit.append({"operation": "change.prepare.file_patch", "user_id": auth.user_id, "prepare_id": item.prepare_id, "root": material["root"], "path": material["path"], "before_sha256": material["before_sha256"], "after_sha256": material["after_sha256"], "result": "prepared"})
        return self._prepared_response(item)

    async def _prepare_service(self, arguments: dict[str, Any], auth: BridgeAuthContext) -> dict[str, Any]:
        domain, service = str(arguments["domain"]).strip(), str(arguments["service"]).strip()
        if domain in {"shell_command", "python_script", "rest_command", "notify"}:
            raise SuiteBridgeError("SERVICE_DENIED", "Denne service-type er ikke tilladt via Bridge.", 403)
        if not self.hass.services.has_service(domain, service):
            raise SuiteBridgeError("SERVICE_NOT_FOUND", "Servicen findes ikke.", 404)
        expected = arguments.get("expected") or {}
        if not isinstance(expected, dict):
            raise SuiteBridgeError("INVALID_SERVICE_VERIFICATION", "expected skal være et objekt.", 422)
        entity_ids = expected.get("entity_ids", [])
        not_states = expected.get("not_states", ["unavailable"])
        if not isinstance(entity_ids, list) or not all(isinstance(value, str) and value for value in entity_ids):
            raise SuiteBridgeError("INVALID_SERVICE_VERIFICATION", "expected.entity_ids skal være en liste af entity_id'er.", 422)
        if not isinstance(not_states, list) or not all(isinstance(value, str) for value in not_states):
            raise SuiteBridgeError("INVALID_SERVICE_VERIFICATION", "expected.not_states skal være en tekstliste.", 422)
        material = {"domain": domain, "service": service, "target": arguments.get("target") or {}, "data": arguments.get("data") or {}, "expected": {"entity_ids": entity_ids, "not_states": not_states}, "verify": bool(arguments.get("verify", True))}
        item = await self.prepared.create(user_id=auth.user_id, refresh_token_id=auth.refresh_token_id, operation="service.call", normalized_change={k: json_safe(v) for k, v in material.items() if k != "data"}, material=material, risk="normal")
        return self._prepared_response(item)

    async def _prepare_sequence(self, arguments: dict[str, Any], auth: BridgeAuthContext) -> dict[str, Any]:
        actions = arguments["actions"]
        if not isinstance(actions, list) or not actions or len(actions) > 25 or not all(isinstance(a, dict) for a in actions):
            raise SuiteBridgeError("INVALID_SEQUENCE", "actions skal være 1-25 objekter.", 400)
        material = {"actions": json_safe(actions), "stop_on_error": bool(arguments.get("stop_on_error", True)), "verify_each": bool(arguments.get("verify_each", False))}
        item = await self.prepared.create(user_id=auth.user_id, refresh_token_id=auth.refresh_token_id, operation="sequence.call", normalized_change=material, material=material, risk="high")
        return self._prepared_response(item)

    async def _prepare_registry(self, arguments: dict[str, Any], auth: BridgeAuthContext) -> dict[str, Any]:
        registry = arguments["registry"]
        if registry not in {"entity", "device"}:
            raise SuiteBridgeError("REGISTRY_WRITE_DENIED", "Kun entity- og device-registry kan ændres.", 403)
        payload = {"kind": registry, "object_id": arguments["id"], "changes": arguments["changes"], "expected_sha256": arguments.get("expected_version") or ""}
        return await self.prepare_registry_change(payload, auth)

    async def _prepare_dashboard(self, arguments: dict[str, Any], auth: BridgeAuthContext) -> dict[str, Any]:
        dashboard, normalized = self.lovelace._dashboard(arguments.get("url_path"))
        before = await dashboard.async_load(False)
        before_sha = digest_json(before)
        if before_sha != arguments["expected_sha256"]:
            raise SuiteBridgeError("DASHBOARD_CHANGED", "Dashboardets SHA-256 matcher ikke.", 409)
        material = {"url_path": normalized, "before": before, "after": arguments["config"], "before_sha256": before_sha}
        item = await self.prepared.create(user_id=auth.user_id, refresh_token_id=auth.refresh_token_id, operation="dashboard.replace", normalized_change={"url_path": normalized, "before_sha256": before_sha, "after_sha256": digest_json(arguments["config"])}, material=material, risk="high")
        return self._prepared_response(item)

    async def _prepare_config_entry(self, arguments: dict[str, Any], auth: BridgeAuthContext) -> dict[str, Any]:
        entry = self.hass.config_entries.async_get_entry(arguments["entry_id"])
        if entry is None:
            raise SuiteBridgeError("CONFIG_ENTRY_NOT_FOUND", "Config entry blev ikke fundet.", 404)
        action = arguments["action"]
        if action in {"reauth", "reconfigure"}:
            raise SuiteBridgeError("CONFIG_ENTRY_ACTION_UNSUPPORTED", "Denne handling kræver en interaktiv HA-flow.", 409)
        material = {"entry_id": entry.entry_id, "action": action, "options": arguments.get("options") or {}, "before_state": entry.state.value, "before_options": dict(entry.options)}
        item = await self.prepared.create(user_id=auth.user_id, refresh_token_id=auth.refresh_token_id, operation="config_entry.update", normalized_change=material, material=material, risk="high")
        return self._prepared_response(item)

    async def _prepare_supervisor(self, arguments: dict[str, Any], auth: BridgeAuthContext) -> dict[str, Any]:
        if arguments["action"] not in {"install", "update", "backup", "restore", "start", "stop", "restart"}:
            raise SuiteBridgeError("SUPERVISOR_ACTION_DENIED", "Ukendt Supervisor-handling.", 403)
        material = json_safe(arguments)
        item = await self.prepared.create(user_id=auth.user_id, refresh_token_id=auth.refresh_token_id, operation="supervisor.action", normalized_change=material, material=material, risk="critical")
        return self._prepared_response(item)

    async def _prepare_core(self, arguments: dict[str, Any], auth: BridgeAuthContext) -> dict[str, Any]:
        action = arguments["action"]
        material = {"action": action, "scope": arguments.get("scope")}
        risk = "normal" if action == "check_config" else ("high" if action == "reload" else "critical")
        item = await self.prepared.create(user_id=auth.user_id, refresh_token_id=auth.refresh_token_id, operation="core.action", normalized_change=material, material=material, risk=risk)
        return self._prepared_response(item)

    async def _prepare_git_commit(self, arguments: dict[str, Any], auth: BridgeAuthContext) -> dict[str, Any]:
        material = await self.hass.async_add_executor_job(
            self.git_commits.prepare, arguments["area"], arguments["summary"]
        )
        item = await self.prepared.create(
            user_id=auth.user_id,
            refresh_token_id=auth.refresh_token_id,
            operation="git.commit",
            normalized_change={
                "area": material["area"],
                "branch": material["branch"],
                "head": material["head"],
                "summary": material["summary"],
                "paths": material["paths"],
                "diff_sha256": material["diff_sha256"],
            },
            material=material,
            risk="high",
        )
        await self.audit.append({
            "operation": "change.prepare.git_commit",
            "user_id": auth.user_id,
            "prepare_id": item.prepare_id,
            "area": material["area"],
            "head": material["head"],
            "paths": material["paths"],
            "result": "prepared",
        })
        return self._prepared_response(item)

    async def _prepare_git_source_push(
        self, arguments: dict[str, Any], auth: BridgeAuthContext
    ) -> dict[str, Any]:
        material = await self.hass.async_add_executor_job(
            self.git_commits.prepare_source_push,
            arguments["expected_source_commit"],
        )
        item = await self.prepared.create(
            user_id=auth.user_id,
            refresh_token_id=auth.refresh_token_id,
            operation="git.source.push",
            normalized_change={
                "area": material["area"],
                "branch": material["branch"],
                "source_commit": material["head"],
                "remote": material["remote"],
                "remote_ref": material["remote_ref"],
                "remote_before": material["remote_before"],
                "force": False,
            },
            material=material,
            risk="high",
        )
        await self.audit.append(
            {
                "operation": "git.source.push",
                "user_id": auth.user_id,
                "prepare_id": item.prepare_id,
                "source_commit": material["head"],
                "remote_before": material["remote_before"],
                "result": "prepared",
            }
        )
        return self._prepared_response(item)

    async def _prepare_git_release_candidate(
        self, arguments: dict[str, Any], auth: BridgeAuthContext
    ) -> dict[str, Any]:
        material = await self.hass.async_add_executor_job(
            self.git_commits.prepare_release_candidate,
            arguments["expected_source_commit"],
        )
        item = await self.prepared.create(
            user_id=auth.user_id,
            refresh_token_id=auth.refresh_token_id,
            operation="git.release_candidate.publish",
            normalized_change={
                "area": material["area"],
                "branch": material["branch"],
                "source_commit": material["head"],
                "remote": material["remote"],
                "remote_ref": material["remote_ref"],
                "remote_before": material["remote_before"],
                "force": False,
            },
            material=material,
            risk="high",
        )
        await self.audit.append({
            "operation": "git.release_candidate.publish",
            "user_id": auth.user_id,
            "prepare_id": item.prepare_id,
            "source_commit": material["head"],
            "remote_before": material["remote_before"],
            "result": "prepared",
        })
        return self._prepared_response(item)

    async def _prepare_git_public_cleanup(
        self, arguments: dict[str, Any], auth: BridgeAuthContext
    ) -> dict[str, Any]:
        material = await self.hass.async_add_executor_job(
            self.git_commits.prepare_public_cleanup,
            arguments["version"],
            arguments["expected_source_commit"],
        )
        item = await self.prepared.create(
            user_id=auth.user_id,
            refresh_token_id=auth.refresh_token_id,
            operation="git.public.cleanup",
            normalized_change={
                "repository": "TorbenAT/home-assistant-one-bridge",
                "source_commit": material["head"],
                "version": material["version"],
                "public_head": material["public_head"],
                "public_root": material["public_root"],
                "commit_count_before": material["public_commit_count"],
                "commit_count_after": material["target_commit_count"],
                "recent_commits": material["public_recent_commits"],
                "tags_before": material["public_tags"],
                "force_with_lease": True,
                "tag_created": False,
            },
            material=material,
            risk="high",
        )
        await self.audit.append({
            "operation": "git.public.cleanup",
            "user_id": auth.user_id,
            "prepare_id": item.prepare_id,
            "source_commit": material["head"],
            "public_head": material["public_head"],
            "commit_count_before": material["public_commit_count"],
            "result": "prepared",
        })
        return self._prepared_response(item)

    async def _prepare_git_public_tag(
        self, arguments: dict[str, Any], auth: BridgeAuthContext
    ) -> dict[str, Any]:
        material = await self.hass.async_add_executor_job(
            self.git_commits.prepare_public_tag,
            arguments["version"],
            arguments["expected_public_commit"],
        )
        item = await self.prepared.create(
            user_id=auth.user_id,
            refresh_token_id=auth.refresh_token_id,
            operation="git.public.tag",
            normalized_change={
                "repository": material["repository"],
                "version": material["version"],
                "tag": material["tag"],
                "public_commit": material["public_commit"],
                "commit_count": material["commit_count"],
                "tags_before": material["tags_before"],
                "force": False,
                "final_tag": True,
            },
            material=material,
            risk="high",
        )
        await self.audit.append({
            "operation": "git.public.tag",
            "user_id": auth.user_id,
            "prepare_id": item.prepare_id,
            "tag": material["tag"],
            "public_commit": material["public_commit"],
            "result": "prepared",
        })
        return self._prepared_response(item)

    async def _prepare_git_preview(self, arguments: dict[str, Any], auth: BridgeAuthContext) -> dict[str, Any]:
        material = await self.hass.async_add_executor_job(
            self.git_commits.prepare_preview, arguments["version"]
        )
        item = await self.prepared.create(
            user_id=auth.user_id,
            refresh_token_id=auth.refresh_token_id,
            operation="git.preview.publish",
            normalized_change={
                "repository": "TorbenAT/home-assistant-one-bridge",
                "area": material["area"],
                "branch": material["branch"],
                "source_commit": material["head"],
                "version": material["version"],
                "publisher_sha256": material["script_sha256"],
                "final_release": False,
                "tag_created": False,
            },
            material=material,
            risk="high",
        )
        await self.audit.append(
            {
                "operation": "git.preview.publish",
                "user_id": auth.user_id,
                "prepare_id": item.prepare_id,
                "source_commit": material["head"],
                "version": material["version"],
                "publisher_sha256": material["script_sha256"],
                "result": "prepared",
            }
        )
        return self._prepared_response(item)

    async def _prepare_bootstrap_stage(
        self, arguments: dict[str, Any], auth: BridgeAuthContext
    ) -> dict[str, Any]:
        material = await self.hass.async_add_executor_job(
            self.git_commits.prepare_bootstrap_stage,
            arguments["expected_source_commit"],
        )
        item = await self.prepared.create(
            user_id=auth.user_id,
            refresh_token_id=auth.refresh_token_id,
            operation="bootstrap.stage",
            normalized_change={
                "source_commit": material["head"],
                "version": material["version"],
                "install_sha256": material["install_sha256"],
                "activate_sha256": material["activate_sha256"],
                "restart_performed": False,
            },
            material=material,
            risk="high",
        )
        await self.audit.append(
            {
                "operation": "bootstrap.stage",
                "user_id": auth.user_id,
                "prepare_id": item.prepare_id,
                "source_commit": material["head"],
                "version": material["version"],
                "result": "prepared",
            }
        )
        return self._prepared_response(item)

    async def _prepare_bootstrap_finalize(
        self, arguments: dict[str, Any], auth: BridgeAuthContext
    ) -> dict[str, Any]:
        material = await self.hass.async_add_executor_job(
            self.git_commits.prepare_bootstrap_finalize,
            arguments["expected_source_commit"],
            BOOTSTRAP_VERSION,
        )
        item = await self.prepared.create(
            user_id=auth.user_id,
            refresh_token_id=auth.refresh_token_id,
            operation="bootstrap.finalize",
            normalized_change={
                "source_commit": material["head"],
                "version": material["version"],
                "loaded_version": material["loaded_version"],
                "pending_sha256": material["pending_sha256"],
                "restart_performed": False,
            },
            material=material,
            risk="high",
        )
        await self.audit.append(
            {
                "operation": "bootstrap.finalize",
                "user_id": auth.user_id,
                "prepare_id": item.prepare_id,
                "source_commit": material["head"],
                "version": material["version"],
                "result": "prepared",
            }
        )
        return self._prepared_response(item)

    async def apply_request(
        self, payload: dict[str, Any], auth: BridgeAuthContext
    ) -> dict[str, Any]:
        envelope = validate_apply_envelope(payload)
        operation = envelope["operation"]
        arguments = envelope["arguments"]
        contract = self.catalog.resolve(operation, "apply", arguments)
        required_capability = contract.get("capability")
        if required_capability not in self.config.capabilities:
            raise SuiteBridgeError(
                "CAPABILITY_DENIED",
                f"Rollen {self.config.role} tillader ikke capability "
                f"{required_capability}.",
                403,
            )
        if operation == "release.apply":
            result = await self.release.apply(
                arguments,
                user_id=auth.user_id,
                refresh_token_id=auth.refresh_token_id,
            )
        elif operation == "change.apply":
            key = arguments["idempotency_key"]
            fingerprint = json.dumps(
                {
                    "arguments": arguments,
                    "user_id": auth.user_id,
                    "refresh_token_id": auth.refresh_token_id,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            receipt_base = {
                "operation": "change.apply.receipt",
                "request_id": envelope.get("request_id"),
                "idempotency_key": key,
                "prepare_id": arguments["prepare_id"],
            }
            await self.audit.append({**receipt_base, "result": "received"})
            execute, cached = await self.change_idempotency.begin(key, fingerprint)
            if execute:
                await self.audit.append({**receipt_base, "result": "started"})
                try:
                    result = await self.apply_mutation(
                        {
                            "prepare_id": arguments["prepare_id"],
                            "request_digest": arguments["expected_digest"],
                            "confirmed": arguments["confirmed"],
                        },
                        auth,
                    )
                except Exception as err:
                    await self.change_idempotency.abort(key, fingerprint)
                    await self.audit.append(
                        {
                            "operation": "change.apply.receipt",
                            "request_id": envelope.get("request_id"),
                            "idempotency_key": key,
                            "prepare_id": arguments["prepare_id"],
                            "result": "failed_or_unknown_outcome",
                            "error": type(err).__name__,
                            "message": str(err),
                        }
                    )
                    raise
                await self.change_idempotency.finish(key, fingerprint, result)
                await self.audit.append(
                    {
                        "operation": "change.apply.receipt",
                        "request_id": envelope.get("request_id"),
                        "idempotency_key": key,
                        "prepare_id": arguments["prepare_id"],
                        "result": "completed",
                        "details": json_safe(result),
                    }
                )
            else:
                result = {**(cached or {}), "idempotent_replay": True}
                await self.audit.append(
                    {**receipt_base, "result": "replayed", "details": json_safe(result)}
                )
        else:
            raise RuntimeError(
                f"Operation handler registry drift for apply: {operation}"
            )
        return {
            "request_id": envelope.get("request_id"),
            "operation": operation,
            "mode": "apply",
            "result": result,
        }

    def audit_summary(self, payload: dict[str, Any], auth: BridgeAuthContext) -> dict[str, Any]:
        del auth
        return self.audit.summary(int(payload.get("limit", 20)))

    async def list_dashboards(
        self, payload: dict[str, Any], auth: BridgeAuthContext
    ) -> dict[str, Any]:
        return await self.lovelace.list_dashboards(auth.refresh_token_id, payload)

    async def get_dashboard(
        self, payload: dict[str, Any], auth: BridgeAuthContext
    ) -> dict[str, Any]:
        del auth
        return await self.lovelace.get_dashboard(payload)

    async def list_resources(
        self, payload: dict[str, Any], auth: BridgeAuthContext
    ) -> dict[str, Any]:
        return await self.lovelace.list_resources(auth.refresh_token_id, payload)

    async def prepare_lovelace_patch(
        self, payload: dict[str, Any], auth: BridgeAuthContext
    ) -> dict[str, Any]:
        return await self.lovelace.prepare_patch(
            payload,
            user_id=auth.user_id,
            refresh_token_id=auth.refresh_token_id,
        )

    async def prepare_lovelace_metadata(
        self, payload: dict[str, Any], auth: BridgeAuthContext
    ) -> dict[str, Any]:
        return await self.lovelace.prepare_metadata(
            auth.refresh_token_id,
            payload,
            user_id=auth.user_id,
        )

    async def prepare_lovelace_rollback(
        self, payload: dict[str, Any], auth: BridgeAuthContext
    ) -> dict[str, Any]:
        return await self.lovelace.prepare_rollback(
            payload,
            user_id=auth.user_id,
            refresh_token_id=auth.refresh_token_id,
        )

    def search_registry(
        self, payload: dict[str, Any], auth: BridgeAuthContext
    ) -> dict[str, Any]:
        del auth
        return self.registry.search(payload)

    async def prepare_registry_change(
        self, payload: dict[str, Any], auth: BridgeAuthContext
    ) -> dict[str, Any]:
        return await self.registry.prepare_change(
            payload,
            user_id=auth.user_id,
            refresh_token_id=auth.refresh_token_id,
        )

    async def list_helpers(
        self, payload: dict[str, Any], auth: BridgeAuthContext
    ) -> dict[str, Any]:
        return await self.helpers.list_helpers(auth.refresh_token_id, payload)

    async def helper_references(
        self, payload: dict[str, Any], auth: BridgeAuthContext
    ) -> dict[str, Any]:
        del auth
        return await self.helpers.references(str(payload.get("entity_id", "")))

    async def prepare_helper_change(
        self, payload: dict[str, Any], auth: BridgeAuthContext
    ) -> dict[str, Any]:
        return await self.helpers.prepare_change(
            auth.refresh_token_id,
            payload,
            user_id=auth.user_id,
        )

    async def list_backups(
        self, payload: dict[str, Any], auth: BridgeAuthContext
    ) -> dict[str, Any]:
        del auth
        category = payload.get("category")
        if category is not None and not isinstance(category, str):
            raise SuiteBridgeError("INVALID_BACKUP_CATEGORY", "category skal være tekst.")
        return {"backups": await self.backups.list(category)}

    async def read_backup(
        self, payload: dict[str, Any], auth: BridgeAuthContext
    ) -> dict[str, Any]:
        del auth
        backup_id = str(payload.get("backup_id", "")).strip()
        if not backup_id:
            raise SuiteBridgeError("BACKUP_ID_REQUIRED", "backup_id er obligatorisk.")
        return await self.backups.read(backup_id)

    async def deployment_status(
        self, payload: dict[str, Any], auth: BridgeAuthContext
    ) -> dict[str, Any]:
        del auth
        return await self.deployment.status(payload)

    async def apply_mutation(
        self, payload: dict[str, Any], auth: BridgeAuthContext
    ) -> dict[str, Any]:
        prepare_id = str(payload.get("prepare_id", "")).strip()
        digest = str(payload.get("request_digest", "")).strip()
        item = await self.prepared.begin_apply(
            prepare_id=prepare_id,
            digest=digest,
            user_id=auth.user_id,
            refresh_token_id=auth.refresh_token_id,
            confirmed=payload.get("confirmed") is True,
            confirmation_text=payload.get("confirmation_text"),
        )
        try:
            if item.operation in {"lovelace.patch", "lovelace.rollback"}:
                result = await self.lovelace.apply(item, user_id=auth.user_id)
            elif item.operation.startswith("lovelace.metadata."):
                result = await self.lovelace.apply_metadata(
                    item,
                    user_id=auth.user_id,
                    refresh_token_id=auth.refresh_token_id,
                )
            elif item.operation.startswith("registry."):
                result = await self.registry.apply(item, user_id=auth.user_id)
            elif item.operation.startswith("helper."):
                result = await self.helpers.apply(
                    item,
                    user_id=auth.user_id,
                    refresh_token_id=auth.refresh_token_id,
                )
            elif item.operation == "file.update":
                _, _, before_path = resolve_path(self.hass, item.material["root"], item.material["path"], write=True)
                before_bytes = before_path.read_bytes()
                before_mode = before_path.stat().st_mode
                backup = await self.backups.create(
                    "files",
                    item.material["path"],
                    operation=item.operation,
                    installation_id=self.config.installation_id,
                    data={"root": item.material["root"], "path": item.material["path"], "content": before_path.read_text(encoding="utf-8")},
                    source_sha256=item.material["before_sha256"],
                )
                try:
                    result = await self.hass.async_add_executor_job(apply_file, self.hass, item, self.backups)
                except Exception:
                    rollback_tmp = before_path.with_name(before_path.name + ".gpt-bridge-rollback.tmp")
                    rollback_tmp.write_bytes(before_bytes)
                    os.chmod(rollback_tmp, before_mode)
                    os.replace(rollback_tmp, before_path)
                    raise
                result["backup"] = backup
                result.update({
                    "verified": result["sha256"] == item.material["after_sha256"],
                    "before": {"sha256": item.material["before_sha256"]},
                    "after": {"sha256": item.material["after_sha256"]},
                    "validation": item.material.get("validation", {"ok": True, "profile": None}),
                })
            elif item.operation == "service.call":
                material = item.material
                await self.hass.services.async_call(
                    material["domain"], material["service"],
                    service_data=material["data"], target=material["target"], blocking=True,
                )
                result = {"executed": True, "domain": material["domain"], "service": material["service"]}
                if material["verify"] and material["expected"]["entity_ids"]:
                    rejected = set(material["expected"]["not_states"])
                    states = []
                    for entity_id in material["expected"]["entity_ids"]:
                        state = self.hass.states.get(entity_id)
                        value = None if state is None else state.state
                        states.append({"entity_id": entity_id, "state": value})
                    failed = [entry["entity_id"] for entry in states if entry["state"] is None or entry["state"] in rejected]
                    result["verification"] = {"verified": not failed, "states": states, "failed_entities": failed}
                    if failed:
                        raise SuiteBridgeError("POST_APPLY_VERIFICATION_FAILED", "Servicen blev kørt, men de forventede entities bestod ikke efterverifikation.", 409, details=result["verification"])
            elif item.operation == "sequence.call":
                results = []
                for action in item.material["actions"]:
                    domain = action.get("domain")
                    service = action.get("service")
                    if not service and isinstance(action.get("action"), str) and "." in action["action"]:
                        domain, service = action["action"].split(".", 1)
                    if not domain or not service:
                        raise SuiteBridgeError("INVALID_SEQUENCE_ACTION", "Sekvens-handlingen mangler domain/service.", 400)
                    await self.hass.services.async_call(domain, service, service_data=action.get("data") or {}, target=action.get("target") or {}, blocking=True)
                    results.append({"domain": domain, "service": service, "ok": True})
                result = {"executed": True, "results": results}
            elif item.operation == "dashboard.replace":
                dashboard, _ = self.lovelace._dashboard(item.material.get("url_path"))
                current = await dashboard.async_load(False)
                if digest_json(current) != item.material["before_sha256"]:
                    raise SuiteBridgeError("DASHBOARD_CHANGED", "Dashboardet er ændret efter prepare.", 409)
                await dashboard.async_save(item.material["after"])
                result = {"executed": True, "sha256": digest_json(item.material["after"])}
            elif item.operation == "config_entry.update":
                from homeassistant.config_entries import ConfigEntryState, ConfigEntryDisabler
                entry = self.hass.config_entries.async_get_entry(item.material["entry_id"])
                if entry is None:
                    raise SuiteBridgeError("CONFIG_ENTRY_NOT_FOUND", "Config entry blev ikke fundet.", 404)
                action = item.material["action"]
                if action == "reload":
                    result = {"reloaded": await self.hass.config_entries.async_reload(entry.entry_id)}
                elif action == "enable":
                    await self.hass.config_entries.async_set_disabled_by(entry.entry_id, None)
                    result = {"enabled": True}
                elif action == "disable":
                    await self.hass.config_entries.async_set_disabled_by(entry.entry_id, ConfigEntryDisabler.USER)
                    result = {"disabled": True}
                else:
                    self.hass.config_entries.async_update_entry(entry, options=item.material["options"])
                    result = {"options_updated": True}
            elif item.operation == "core.action":
                action = item.material["action"]
                if action == "check_config":
                    await self.hass.services.async_call("homeassistant", "check_config", blocking=True)
                    result = {"checked": True, "valid": True}
                elif action == "reload":
                    await self.hass.services.async_call("homeassistant", "reload_core_config", blocking=True)
                    result = {"executed": True, "action": action, "service": "reload_core_config"}
                else:
                    await self.hass.services.async_call("homeassistant", action, blocking=True)
                    result = {"executed": True, "action": action}
                await self.audit.append(
                    {
                        "operation": item.operation,
                        "user_id": auth.user_id,
                        "prepare_id": prepare_id,
                        "result": "executed",
                        "details": json_safe(result),
                    }
                )
            elif item.operation == "supervisor.action":
                from .ws_client import async_ws_command
                resource, action = item.material["resource"], item.material["action"]
                if resource == "app":
                    target = item.material.get("target")
                    if not target:
                        raise SuiteBridgeError("SUPERVISOR_TARGET_REQUIRED", "App-handlinger kræver target.", 400)
                    endpoint = f"/addons/{target}/{action}"
                else:
                    endpoint = f"/{resource}s/{item.material.get('target') or action}"
                result = await async_ws_command(self.hass, auth.refresh_token_id, {"type": "supervisor/api", "endpoint": endpoint, "method": "post", "data": item.material.get("options") or {}})
            elif item.operation == "git.commit":
                result = await self.hass.async_add_executor_job(
                    self.git_commits.commit, item.material
                )
            elif item.operation == "git.source.push":
                result = await self.hass.async_add_executor_job(
                    self.git_commits.push_source, item.material
                )
                await self.audit.append(
                    {
                        "operation": item.operation,
                        "user_id": auth.user_id,
                        "prepare_id": prepare_id,
                        "result": "pushed",
                        "details": json_safe(result),
                    }
                )
            elif item.operation == "git.release_candidate.publish":
                result = await self.hass.async_add_executor_job(
                    self.git_commits.publish_release_candidate, item.material
                )
                await self.audit.append({
                    "operation": item.operation,
                    "user_id": auth.user_id,
                    "prepare_id": prepare_id,
                    "result": "published",
                    "details": json_safe(result),
                })
            elif item.operation == "git.public.cleanup":
                result = await self.hass.async_add_executor_job(
                    self.git_commits.cleanup_public, item.material
                )
                await self.audit.append({
                    "operation": item.operation,
                    "user_id": auth.user_id,
                    "prepare_id": prepare_id,
                    "result": "cleaned",
                    "details": json_safe(result),
                })
            elif item.operation == "git.public.tag":
                result = await self.hass.async_add_executor_job(
                    self.git_commits.create_public_tag, item.material
                )
                await self.audit.append({
                    "operation": item.operation,
                    "user_id": auth.user_id,
                    "prepare_id": prepare_id,
                    "result": "tagged",
                    "details": json_safe(result),
                })
            elif item.operation == "git.preview.publish":
                result = await self.hass.async_add_executor_job(
                    self.git_commits.publish_preview, item.material
                )
                await self.audit.append(
                    {
                        "operation": item.operation,
                        "user_id": auth.user_id,
                        "prepare_id": prepare_id,
                        "result": "published",
                        "details": json_safe(result),
                    }
                )
            elif item.operation == "bootstrap.stage":
                result = await self.hass.async_add_executor_job(
                    self.git_commits.stage_bootstrap, item.material
                )
                await self.audit.append(
                    {
                        "operation": item.operation,
                        "user_id": auth.user_id,
                        "prepare_id": prepare_id,
                        "result": "staged",
                        "details": json_safe(result),
                    }
                )
            elif item.operation == "bootstrap.finalize":
                result = await self.hass.async_add_executor_job(
                    self.git_commits.finalize_bootstrap,
                    item.material,
                    BOOTSTRAP_VERSION,
                )
                await self.audit.append(
                    {
                        "operation": item.operation,
                        "user_id": auth.user_id,
                        "prepare_id": prepare_id,
                        "result": "finalized",
                        "details": json_safe(result),
                    }
                )
            else:
                raise SuiteBridgeError(
                    "UNKNOWN_PREPARED_OPERATION",
                    f"Ukendt prepared operation: {item.operation}",
                    400,
                )
        except Exception as err:
            await self.prepared.finish(prepare_id, consume=True)
            await self.audit.append(
                {
                    "operation": item.operation,
                    "user_id": auth.user_id,
                    "prepare_id": prepare_id,
                    "result": "failed_or_unknown_outcome",
                    "error": type(err).__name__,
                    "message": str(err),
                }
            )
            raise
        await self.prepared.finish(prepare_id, consume=True)
        return result
