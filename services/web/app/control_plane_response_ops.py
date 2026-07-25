from __future__ import annotations

from collections import Counter
from datetime import timedelta
from email.message import EmailMessage
import hashlib
import json
import shutil
import smtplib
import subprocess
import time
from typing import Any

try:
    from . import enterprise_control_plane as core
except ImportError:  # pragma: no cover - local test fallback
    import enterprise_control_plane as core  # type: ignore[no-redef]
try:
    from .response_workflow_runtime import (
        approval_is_expired,
        approval_ready,
        build_approval_state,
        build_execution_linkage,
        build_response_policy_packs,
        infer_policy_pack_id,
        normalize_action_linkage,
        normalize_response_approval,
        record_approval,
        record_rejection,
    )
except ImportError:  # pragma: no cover - local test fallback
    from response_workflow_runtime import (  # type: ignore[no-redef]
        approval_is_expired,
        approval_ready,
        build_approval_state,
        build_execution_linkage,
        build_response_policy_packs,
        infer_policy_pack_id,
        normalize_action_linkage,
        normalize_response_approval,
        record_approval,
        record_rejection,
    )

CONTROL_PLANE_SCHEMA_VERSION = core.CONTROL_PLANE_SCHEMA_VERSION
_collection = core._collection
_find_by_id = core._find_by_id
_json_clone = core._json_clone
_new_id = core._new_id
_now = core._now
_now_iso = core._now_iso
_parse_ts = core._parse_ts
_safe_slug = core._safe_slug
_save_collection = core._save_collection
_sample_records = core._sample_records
_resolve_config_value = core._resolve_config_value
_resolve_required_secrets = core._resolve_required_secrets
_resolve_runtime_object = core._resolve_runtime_object
_resolve_secret_value = core._resolve_secret_value
_safe_timeout_seconds = core._safe_timeout_seconds
_http_request = core._http_request
_decode_http_payload = core._decode_http_payload
_coerce_message_text = core._coerce_message_text
_normalize_connector_secret_requirements = core._normalize_connector_secret_requirements
_merge_seed_rows = core._merge_seed_rows
append_audit_event = core.append_audit_event
_default_response_actions = core._default_response_actions
_default_response_executions = core._default_response_executions

RESPONSE_SUCCESS_STATUSES = {"dry_run", "accepted", "approved", "executed"}
RESPONSE_RETRYABLE_STATUSES = {"error", "failed", "blocked", "partial_failure"}


def _is_nonproduction_response_action(action: dict[str, Any]) -> bool:
    action_id = str(action.get("id") or "").strip().lower()
    title = str(action.get("title") or "").strip().lower()
    policy_pack_id = str(action.get("policy_pack_id") or "").strip().lower()
    playbook_class = str(action.get("playbook_class") or "").strip().lower()
    governance_tier = str(action.get("governance_tier") or "").strip().lower()
    if action_id.startswith(("smoke-", "test-", "qa-")):
        return True
    if title.startswith(("smoke ", "test ", "qa ")):
        return True
    if policy_pack_id.startswith(("smoke", "test", "qa")):
        return True
    if playbook_class in {"smoke", "test", "qa"}:
        return True
    return governance_tier in {"smoke", "test", "qa"}


def _production_response_actions(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [dict(item) for item in actions if not _is_nonproduction_response_action(dict(item or {}))]


def _normalize_principal_context(actor: str, principal_context: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = dict(principal_context or {})
    return {
        "actor": str(payload.get("actor") or actor or "system"),
        "role": str(payload.get("role") or "").strip().lower(),
        "principal_type": str(payload.get("principal_type") or "user").strip().lower() or "user",
        "auth_mechanism": str(payload.get("auth_mechanism") or "").strip().lower(),
        "break_glass": bool(payload.get("break_glass", False)),
    }


def _dangerous_action_has_linkage(linkage: dict[str, Any]) -> bool:
    for key in ("case_id", "alert_id", "incident_id", "detection_id", "finding_key", "report_id", "trigger_id"):
        if str(linkage.get(key) or "").strip():
            return True
    return False


def _enforce_execute_governance(
    action: dict[str, Any],
    runtime_payload: dict[str, Any],
    *,
    dry_run: bool,
    approval_config: dict[str, Any],
    linkage: dict[str, Any],
    principal: dict[str, Any],
) -> None:
    dangerous = bool(action.get("dangerous", False))
    trigger_kind = str(linkage.get("trigger_kind") or "manual").strip().lower() or "manual"
    if dangerous and not _dangerous_action_has_linkage(linkage) and not bool(principal.get("break_glass")):
        raise ValueError("Dangerous actions require linkage to detection, case, finding, or report unless break-glass is active")
    allowed_trigger_kinds = [str(item).strip().lower() for item in (approval_config.get("allowed_trigger_kinds") or action.get("trigger_kinds") or []) if str(item).strip()]
    if allowed_trigger_kinds and trigger_kind not in allowed_trigger_kinds and not bool(principal.get("break_glass")):
        raise ValueError(f"Trigger kind {trigger_kind!r} is not allowed for this action")
    if not dry_run and str(principal.get("principal_type") or "user") == "service_account":
        if dangerous or bool(approval_config.get("required")):
            raise ValueError("Service accounts cannot execute dangerous or approval-gated response actions")
    if not dry_run and bool(principal.get("break_glass")) and not str(runtime_payload.get("break_glass_reason") or runtime_payload.get("approval_note") or runtime_payload.get("request_note") or "").strip():
        raise ValueError("Break-glass executions require an explicit reason")


def _default_response_dlq() -> list[dict[str, Any]]:
    if hasattr(core, "_default_response_dlq"):
        return core._default_response_dlq()
    return []


def _default_response_idempotency() -> list[dict[str, Any]]:
    if hasattr(core, "_default_response_idempotency"):
        return core._default_response_idempotency()
    return []


def _default_response_ledger() -> list[dict[str, Any]]:
    if hasattr(core, "_default_response_ledger"):
        return core._default_response_ledger()
    return []


def _clean_runtime_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {str(key): value for key, value in payload.items() if not str(key).startswith("_")}


def _int_or_default(value: Any, default: int, *, minimum: int = 1, maximum: int = 5000) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = int(default)
    return max(minimum, min(maximum, parsed))


def _normalize_vuln_asset_seed(raw_assets: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_assets, list):
        return []
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(raw_assets, start=1):
        if not isinstance(item, dict):
            continue
        hostname = str(item.get("hostname") or "").strip().lower()
        ip = str(item.get("ip") or "").strip()
        asset_id = str(item.get("asset_id") or "").strip() or _safe_slug(hostname or ip or f"asset-{index}", default=f"asset-{index}")
        tags_value = item.get("tags") or []
        if isinstance(tags_value, str):
            tags = tags_value
        else:
            tags = ",".join(str(tag).strip() for tag in tags_value if str(tag).strip())
        normalized.append(
            {
                "asset_id": asset_id,
                "asset_type": str(item.get("asset_type") or "server").strip() or "server",
                "hostname": hostname,
                "ip": ip,
                "owner": str(item.get("owner") or "platform").strip(),
                "criticality": str(item.get("criticality") or "high").strip().lower() or "high",
                "environment": str(item.get("environment") or "prod").strip().lower() or "prod",
                "business_service": str(item.get("business_service") or "siem").strip(),
                "os_family": str(item.get("os_family") or "linux").strip().lower() or "linux",
                "expected_ports": str(item.get("expected_ports") or "").strip(),
                "tags": tags,
                "notes": str(item.get("notes") or "Managed by SOAR vulnerability enrollment task").strip(),
                "vuln_enabled": bool(item.get("vuln_enabled", True)),
                "vuln_profile": str(item.get("vuln_profile") or "network-basic").strip().lower() or "network-basic",
            }
        )
    return normalized


def _upsert_vuln_asset_seeds(raw_assets: Any) -> list[dict[str, Any]]:
    assets = _normalize_vuln_asset_seed(raw_assets)
    if not assets:
        return []
    try:
        from .asset_catalog_runtime import save_cmdb_asset
    except ImportError:  # pragma: no cover - local test fallback
        from asset_catalog_runtime import save_cmdb_asset  # type: ignore[no-redef]
    saved: list[dict[str, Any]] = []
    for item in assets:
        saved.append(
            save_cmdb_asset(
                asset_id=str(item.get("asset_id") or ""),
                asset_type=str(item.get("asset_type") or "server"),
                hostname=str(item.get("hostname") or ""),
                ip=str(item.get("ip") or ""),
                owner=str(item.get("owner") or ""),
                criticality=str(item.get("criticality") or "high"),
                environment=str(item.get("environment") or "prod"),
                business_service=str(item.get("business_service") or ""),
                os_family=str(item.get("os_family") or "linux"),
                expected_ports=str(item.get("expected_ports") or ""),
                tags=str(item.get("tags") or ""),
                notes=str(item.get("notes") or ""),
                vuln_enabled=bool(item.get("vuln_enabled", True)),
                vuln_profile=str(item.get("vuln_profile") or "network-basic"),
            )
        )
    return saved


def _default_openvas_fleet_assets() -> list[dict[str, Any]]:
    return [
        {
            "asset_id": "siem-vm1",
            "hostname": "siem-ingest",
            "ip": "10.20.10.104",
            "asset_type": "server",
            "owner": "platform",
            "criticality": "high",
            "environment": "prod",
            "business_service": "siem-ingest",
            "os_family": "linux",
            "expected_ports": "443,514,1514,5514,6514,9092",
            "tags": ["siem", "vm1", "ingest", "vuln"],
            "vuln_enabled": True,
            "vuln_profile": "network-basic",
        },
        {
            "asset_id": "siem-vm2",
            "hostname": "siem-processing",
            "ip": "10.20.10.105",
            "asset_type": "server",
            "owner": "platform",
            "criticality": "high",
            "environment": "prod",
            "business_service": "siem-processing",
            "os_family": "linux",
            "expected_ports": "22,9092",
            "tags": ["siem", "vm2", "processing", "kafka", "vuln"],
            "vuln_enabled": True,
            "vuln_profile": "network-basic",
        },
        {
            "asset_id": "siem-vm3",
            "hostname": "siem-storage",
            "ip": "10.20.10.106",
            "asset_type": "server",
            "owner": "platform",
            "criticality": "critical",
            "environment": "prod",
            "business_service": "siem-storage",
            "os_family": "linux",
            "expected_ports": "22,8123,9000,9092,27017,5432",
            "tags": ["siem", "vm3", "storage", "clickhouse", "vuln"],
            "vuln_enabled": True,
            "vuln_profile": "network-basic",
        },
        {
            "asset_id": "siem-vm4",
            "hostname": "siem-web",
            "ip": "10.20.10.107",
            "asset_type": "server",
            "owner": "platform",
            "criticality": "high",
            "environment": "prod",
            "business_service": "siem-web",
            "os_family": "linux",
            "expected_ports": "22,443,9092",
            "tags": ["siem", "vm4", "web", "control-plane", "vuln"],
            "vuln_enabled": True,
            "vuln_profile": "network-basic",
        },
        {
            "asset_id": "siem-vm5",
            "hostname": "siem-transport",
            "ip": "10.20.10.108",
            "asset_type": "server",
            "owner": "platform",
            "criticality": "high",
            "environment": "prod",
            "business_service": "siem-transport",
            "os_family": "linux",
            "expected_ports": "22,9092",
            "tags": ["siem", "vm5", "transport", "kafka", "vuln"],
            "vuln_enabled": True,
            "vuln_profile": "network-basic",
        },
    ]


def _default_openvas_response_actions() -> list[dict[str, Any]]:
    now = _now_iso()
    return [
        {
            "id": "greenbone-fleet-enrollment",
            "type": "response_action",
            "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
            "kind": "chain",
            "title": "Greenbone / OpenVAS fleet enrollment",
            "description": "Enable VM1-VM5 for vulnerability coverage and synchronize them into Greenbone schedules.",
            "enabled": True,
            "dangerous": False,
            "approval_required": False,
            "updated_ts": now,
            "health": {"last_execution_ts": "", "last_status": "never", "total_executions": 0},
            "target": {},
            "message_template": "Enroll the full SIEM fleet into scheduled vulnerability scanning.",
            "owners": ["exposure-management", "platform-engineering"],
            "trigger_kinds": ["manual", "report"],
            "default_linkage": {"trigger_kind": "report"},
            "playbook_class": "enrichment",
            "governance_tier": "operator",
            "evidence_contract": ["asset_id", "hostname", "ip", "scan_profile"],
            "rollback_contract": ["asset_id", "vuln_enabled"],
            "compliance_controls": ["PCI-DSS-11", "CIS-Continuous-Vuln-Management"],
            "secret_requirements": [],
            "steps": [
                {
                    "id": "seed-fleet-assets",
                    "title": "Enable fleet assets for vulnerability coverage",
                    "kind": "vuln_sync",
                    "enabled": True,
                    "continue_on_error": False,
                    "target": {"limit": 500, "assets": _default_openvas_fleet_assets()},
                    "message_template": "Register the full SIEM fleet in vulnerability coverage and refresh scanner targets.",
                    "secret_requirements": [],
                }
            ],
        },
        {
            "id": "greenbone-import-and-escalate",
            "type": "response_action",
            "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
            "kind": "chain",
            "title": "Greenbone / OpenVAS import and escalation",
            "description": "Import newly completed Greenbone reports and promote critical findings into cases and risk signals.",
            "enabled": True,
            "dangerous": False,
            "approval_required": False,
            "updated_ts": now,
            "health": {"last_execution_ts": "", "last_status": "never", "total_executions": 0},
            "target": {},
            "message_template": "Import scanner results and escalate critical exposure.",
            "owners": ["exposure-management", "soc-ops"],
            "trigger_kinds": ["report", "incident", "manual"],
            "default_linkage": {"trigger_kind": "report"},
            "playbook_class": "investigation",
            "governance_tier": "system",
            "evidence_contract": ["report_id", "asset_id", "severity", "cves"],
            "rollback_contract": ["finding_id", "case_id"],
            "compliance_controls": ["PCI-DSS-11", "NIST-RA.5"],
            "secret_requirements": [],
            "steps": [
                {
                    "id": "import-greenbone-reports",
                    "title": "Import Greenbone reports",
                    "kind": "vuln_import",
                    "enabled": True,
                    "continue_on_error": False,
                    "target": {"limit": 50},
                    "message_template": "Import the newest completed Greenbone reports into structured vulnerability tables.",
                    "secret_requirements": [],
                },
                {
                    "id": "apply-vulnerability-policies",
                    "title": "Apply critical vulnerability policies",
                    "kind": "vuln_policy_apply",
                    "enabled": True,
                    "continue_on_error": False,
                    "target": {"days": 30, "limit": 50},
                    "message_template": "Create or update cases and risk signals for critical vulnerability findings.",
                    "secret_requirements": [],
                },
            ],
        },
    ]


def _default_ansible_response_actions() -> list[dict[str, Any]]:
    now = _now_iso()
    inventory = "/opt/siem/soar/ansible/inventory.ini"
    return [
        {
            "id": "ansible-host-triage",
            "type": "response_action",
            "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
            "kind": "ansible_playbook",
            "title": "Ansible host triage",
            "description": "Collect services, disk, memory, journal and network context from a selected SIEM or pilot node.",
            "enabled": True,
            "dangerous": False,
            "approval_required": False,
            "updated_ts": now,
            "health": {"last_execution_ts": "", "last_status": "never", "total_executions": 0},
            "target": {"inventory": inventory, "playbook": "/opt/siem/soar/ansible/collect_triage.yml", "limit": "siem_web", "check_mode": False, "timeout_ms": 180000},
            "message_template": "Collect Ansible triage evidence for {{asset_id}}.",
            "owners": ["platform-engineering", "soc-ops"],
            "trigger_kinds": ["manual", "incident", "case"],
            "default_linkage": {"trigger_kind": "manual", "asset_id": "siem-web"},
            "playbook_class": "evidence",
            "governance_tier": "operator",
            "evidence_contract": ["asset_id", "host_name", "journal", "services", "disk"],
            "rollback_contract": [],
            "compliance_controls": ["NIST-DE.CM", "SOC2-CC7"],
            "preconditions": ["target-host-selected", "ssh-reachability-confirmed"],
            "integration_targets": ["ansible", "linux-hosts"],
            "operator_notes": "Use as the first SOAR action when the analyst needs a machine view from the SIEM UI.",
            "rollback_notes": "Read-only collection; no rollback is required.",
            "secret_requirements": [],
        },
        {
            "id": "ansible-restart-service",
            "type": "response_action",
            "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
            "kind": "ansible_playbook",
            "title": "Ansible controlled service restart",
            "description": "Restart an approved systemd service on a selected node and collect pre/post status.",
            "enabled": True,
            "dangerous": True,
            "approval_required": True,
            "updated_ts": now,
            "health": {"last_execution_ts": "", "last_status": "never", "total_executions": 0},
            "target": {
                "inventory": inventory,
                "playbook": "/opt/siem/soar/ansible/restart_service.yml",
                "limit": "siem_web",
                "check_mode": False,
                "timeout_ms": 180000,
                "extra_vars": {"service_name": "siem-web.service"},
            },
            "message_template": "Restart {{service_name}} on {{asset_id}} after approval.",
            "owners": ["platform-engineering"],
            "trigger_kinds": ["manual", "incident", "case"],
            "default_linkage": {"trigger_kind": "case", "asset_id": "siem-web"},
            "playbook_class": "remediation",
            "governance_tier": "high-risk",
            "evidence_contract": ["asset_id", "service_name", "case_id"],
            "rollback_contract": ["pre_status", "post_status", "journal_tail"],
            "compliance_controls": ["NIST-RS.MI", "SOC2-CC7"],
            "preconditions": ["case_linked", "service_name_allowlisted", "approval_chain_satisfied"],
            "integration_targets": ["ansible", "systemd"],
            "operator_notes": "Use only for allowlisted services and a scoped host limit.",
            "rollback_notes": "Use the collected pre/post status and journal tail to revert or escalate manually.",
            "secret_requirements": [],
        },
        {
            "id": "ansible-quarantine-host",
            "type": "response_action",
            "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
            "kind": "ansible_playbook",
            "title": "Ansible host quarantine",
            "description": "Apply a scoped Linux firewall quarantine profile and preserve rollback evidence.",
            "enabled": True,
            "dangerous": True,
            "approval_required": True,
            "updated_ts": now,
            "health": {"last_execution_ts": "", "last_status": "never", "total_executions": 0},
            "target": {"inventory": inventory, "playbook": "/opt/siem/soar/ansible/quarantine_host.yml", "limit": "pilot_web", "check_mode": True, "timeout_ms": 180000},
            "message_template": "Quarantine {{asset_id}} with Ansible after analyst approval.",
            "owners": ["soc-ops", "platform-engineering"],
            "trigger_kinds": ["incident", "case"],
            "default_linkage": {"trigger_kind": "case", "asset_id": "pilot-web-01"},
            "playbook_class": "containment",
            "governance_tier": "high-risk",
            "evidence_contract": ["asset_id", "case_id", "actor_ip", "approval_ticket"],
            "rollback_contract": ["iptables_backup", "connectivity_check", "case_note"],
            "compliance_controls": ["NIST-RS.MI", "SOC2-CC7"],
            "preconditions": ["case_linked", "target_confirmed", "approval_chain_satisfied"],
            "integration_targets": ["ansible", "linux-firewall"],
            "operator_notes": "Default target is pilot-web and check_mode is enabled until an operator explicitly disables it.",
            "rollback_notes": "Restore from the captured firewall backup and document the reversal in the linked case.",
            "secret_requirements": [],
        },
        {
            "id": "greenbone-targeted-rescan",
            "type": "response_action",
            "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
            "kind": "vuln_scan_start",
            "title": "Greenbone targeted rescan",
            "description": "Start existing Greenbone tasks only for explicitly selected, current CMDB asset bindings.",
            "enabled": True,
            "dangerous": False,
            "approval_required": False,
            "updated_ts": now,
            "health": {"last_execution_ts": "", "last_status": "never", "total_executions": 0},
            "target": {"asset_ids": [], "limit": 25},
            "message_template": "Start a targeted Greenbone rescan for approved asset IDs.",
            "owners": ["exposure-management", "soc-ops"],
            "trigger_kinds": ["manual", "case", "vulnerability_finding"],
            "default_linkage": {"trigger_kind": "case"},
            "playbook_class": "validation",
            "governance_tier": "operator",
            "evidence_contract": ["asset_id", "task_id", "report_id"],
            "rollback_contract": [],
            "compliance_controls": ["PCI-DSS-11", "NIST-RA.5"],
            "preconditions": ["asset-scan-enabled", "current-cmdb-binding", "scanner-connectivity-confirmed"],
            "integration_targets": ["greenbone", "cmdb"],
            "operator_notes": "Stale scanner bindings are rejected. Synchronize targets before retrying.",
            "rollback_notes": "The action starts a read-only scan and does not modify the target.",
            "secret_requirements": [],
        },
        {
            "id": "ansible-vuln-safe-validation",
            "type": "response_action",
            "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
            "kind": "ansible_playbook",
            "title": "Vulnerability safe validation",
            "description": "Collect package, service and socket evidence without exploiting or changing the target.",
            "enabled": True,
            "dangerous": False,
            "approval_required": False,
            "updated_ts": now,
            "health": {"last_execution_ts": "", "last_status": "never", "total_executions": 0},
            "target": {
                "inventory": inventory,
                "playbook": "/opt/siem/soar/ansible/vuln_validate.yml",
                "limit": "pilot_web",
                "check_mode": False,
                "timeout_ms": 180000,
                "extra_vars": {"vuln_case_id": "", "vuln_package": "", "vuln_service": "", "vuln_port": 0},
            },
            "message_template": "Validate vulnerability evidence for {{asset_id}} without intrusive checks.",
            "owners": ["exposure-management", "soc-ops"],
            "trigger_kinds": ["manual", "case", "vulnerability_finding"],
            "default_linkage": {"trigger_kind": "case"},
            "playbook_class": "evidence",
            "governance_tier": "operator",
            "evidence_contract": ["asset_id", "case_id", "package_version", "service_state", "listening_socket"],
            "rollback_contract": [],
            "compliance_controls": ["PCI-DSS-11", "NIST-RA.5"],
            "preconditions": ["case_linked", "target-host-selected", "ssh-reachability-confirmed"],
            "integration_targets": ["ansible", "linux-hosts", "greenbone"],
            "operator_notes": "No exploit modules or arbitrary scanner-provided commands are accepted.",
            "rollback_notes": "Read-only validation; no rollback is required.",
            "secret_requirements": [],
        },
        {
            "id": "ansible-vuln-package-remediation",
            "type": "response_action",
            "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
            "kind": "ansible_playbook",
            "title": "Approved vulnerability package remediation",
            "description": "Update one allowlisted Linux package with two-person approval, check mode by default and captured evidence.",
            "enabled": True,
            "dangerous": True,
            "approval_required": True,
            "approval": {
                "required": True,
                "mode": "two_man",
                "min_approvers": 2,
                "required_roles": ["soc-manager", "platform-engineering"],
                "justification_required": True,
                "expires_minutes": 30,
                "role_separation_required": True,
            },
            "updated_ts": now,
            "health": {"last_execution_ts": "", "last_status": "never", "total_executions": 0},
            "target": {
                "inventory": inventory,
                "playbook": "/opt/siem/soar/ansible/vuln_patch_package.yml",
                "limit": "pilot_web",
                "check_mode": True,
                "diff": True,
                "timeout_ms": 600000,
                "extra_vars": {
                    "vuln_case_id": "",
                    "vuln_approval_ticket": "",
                    "vuln_package": "",
                    "vuln_allowed_packages": [],
                },
            },
            "message_template": "Update {{vuln_package}} on {{asset_id}} after two-person approval.",
            "owners": ["platform-engineering", "soc-manager"],
            "trigger_kinds": ["case", "vulnerability_finding"],
            "default_linkage": {"trigger_kind": "case"},
            "playbook_class": "remediation",
            "governance_tier": "high-risk",
            "evidence_contract": ["asset_id", "case_id", "approval_ticket", "package_before", "package_after"],
            "rollback_contract": ["previous_package_version", "package_manager_history", "service_health"],
            "compliance_controls": ["NIST-RA.5", "NIST-RS.MI", "SOC2-CC7"],
            "preconditions": ["case_linked", "package_allowlisted", "rollback-plan-recorded", "approval_chain_satisfied"],
            "integration_targets": ["ansible", "linux-package-manager", "greenbone"],
            "operator_notes": "The default execution remains check mode. A scoped operator payload must explicitly disable it after approval.",
            "rollback_notes": "Restore the previous package version, then run safe validation and a targeted rescan.",
            "secret_requirements": [],
        },
        {
            "id": "ansible-openvas-refresh",
            "type": "response_action",
            "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
            "kind": "chain",
            "title": "Ansible OpenVAS refresh and import",
            "description": "Trigger scanner-side housekeeping through Ansible, then import Greenbone reports into SIEM.",
            "enabled": True,
            "dangerous": False,
            "approval_required": False,
            "updated_ts": now,
            "health": {"last_execution_ts": "", "last_status": "never", "total_executions": 0},
            "target": {},
            "message_template": "Refresh OpenVAS scanner context and import reports.",
            "owners": ["exposure-management", "platform-engineering"],
            "trigger_kinds": ["manual", "report"],
            "default_linkage": {"trigger_kind": "report"},
            "playbook_class": "orchestration",
            "governance_tier": "operator",
            "evidence_contract": ["scanner_host", "report_id", "import_result"],
            "rollback_contract": [],
            "compliance_controls": ["PCI-DSS-11", "NIST-RA.5"],
            "preconditions": ["scanner-reachable", "import-credentials-configured"],
            "integration_targets": ["ansible", "greenbone", "siem-import"],
            "operator_notes": "Use when OpenVAS reports need a controlled refresh before the SIEM import step.",
            "rollback_notes": "No destructive scanner action is performed by default.",
            "secret_requirements": [],
            "steps": [
                {
                    "id": "scanner-refresh",
                    "title": "Refresh scanner host",
                    "kind": "ansible_playbook",
                    "enabled": True,
                    "continue_on_error": False,
                    "target": {"inventory": inventory, "playbook": "/opt/siem/soar/ansible/openvas_refresh.yml", "limit": "vuln_mgr", "check_mode": False, "timeout_ms": 180000},
                    "message_template": "Refresh Greenbone scanner host context.",
                    "secret_requirements": [],
                },
                {
                    "id": "import-greenbone-reports",
                    "title": "Import Greenbone reports",
                    "kind": "vuln_import",
                    "enabled": True,
                    "continue_on_error": False,
                    "target": {"limit": 50},
                    "message_template": "Import the newest completed Greenbone reports into SIEM.",
                    "secret_requirements": [],
                },
            ],
        },
    ]


def _merged_default_response_actions() -> list[dict[str, Any]]:
    rows = [dict(item) for item in _default_response_actions()]
    existing_ids = {str(item.get("id") or "") for item in rows}
    for item in [*_default_openvas_response_actions(), *_default_ansible_response_actions()]:
        if str(item.get("id") or "") not in existing_ids:
            rows.append(dict(item))
    return rows


def _normalize_response_steps(items: list[dict[str, Any]] | None, *, existing: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    raw_steps = list(items or existing or [])
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(raw_steps, start=1):
        if not isinstance(item, dict):
            continue
        step_id = _safe_slug(str(item.get("id") or item.get("title") or f"step-{index}"), default=f"step-{index}")
        normalized.append(
            {
                "id": step_id,
                "title": str(item.get("title") or step_id),
                "kind": str(item.get("kind") or "webhook").strip().lower() or "webhook",
                "enabled": bool(item.get("enabled", True)),
                "continue_on_error": bool(item.get("continue_on_error", False)),
                "target": _resolve_runtime_object(item.get("target") or {}),
                "message_template": str(item.get("message_template") or ""),
                "secret_requirements": _normalize_connector_secret_requirements(item.get("secret_requirements") or []),
            }
        )
    return normalized


def _single_step_from_action(action: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": "primary",
        "title": str(action.get("title") or action.get("id") or "primary"),
        "kind": str(action.get("kind") or "webhook").strip().lower() or "webhook",
        "enabled": True,
        "continue_on_error": False,
        "target": dict(_resolve_runtime_object(action.get("target") or {})),
        "message_template": str(action.get("message_template") or ""),
        "secret_requirements": _normalize_connector_secret_requirements(action.get("secret_requirements") or []),
    }


def _action_steps(action: dict[str, Any]) -> list[dict[str, Any]]:
    steps = [dict(item) for item in (action.get("steps") or []) if isinstance(item, dict) and bool(item.get("enabled", True))]
    return steps or [_single_step_from_action(action)]


def _build_step_action(action: dict[str, Any], step: dict[str, Any]) -> dict[str, Any]:
    return {
        **dict(action),
        "kind": str(step.get("kind") or action.get("kind") or "webhook"),
        "target": dict(step.get("target") or action.get("target") or {}),
        "message_template": str(step.get("message_template") or action.get("message_template") or ""),
        "secret_requirements": list(step.get("secret_requirements") or action.get("secret_requirements") or []),
        "title": str(step.get("title") or action.get("title") or step.get("id") or action.get("id") or "action"),
    }


def _normalize_response_action_governance(action: dict[str, Any]) -> dict[str, Any]:
    current = dict(action)
    kind = str(current.get("kind") or "workflow").strip().lower() or "workflow"
    current["playbook_class"] = str(current.get("playbook_class") or kind or "workflow").strip().lower() or "workflow"
    current["governance_tier"] = str(current.get("governance_tier") or ("high-risk" if bool(current.get("dangerous")) else "operator")).strip().lower() or "operator"
    current["evidence_contract"] = [str(value).strip() for value in (current.get("evidence_contract") or []) if str(value).strip()]
    current["rollback_contract"] = [str(value).strip() for value in (current.get("rollback_contract") or []) if str(value).strip()]
    current["compliance_controls"] = [str(value).strip() for value in (current.get("compliance_controls") or []) if str(value).strip()]
    default_preconditions = {
        "telegram": ["incident-context-present", "operator-channel-approved"],
        "webhook": ["payload-contract-validated", "destination-endpoint-approved"],
        "approval_gate": ["approval-chain-satisfied", "rollback-path-defined"],
        "chain": ["steps-validated", "rollback-path-defined"],
        "vuln_sync": ["target-scope-approved", "scanner-connectivity-confirmed"],
        "vuln_scan_start": ["asset-scan-enabled", "current-cmdb-binding", "scanner-connectivity-confirmed"],
        "ansible_playbook": ["target-host-selected", "ssh-reachability-confirmed", "playbook-reviewed"],
    }.get(kind, ["linked-case-present"])
    default_targets = {
        "telegram": ["telegram"],
        "webhook": ["ticketing", "webhook"],
        "approval_gate": ["identity-provider", "access-governance"],
        "chain": ["workflow-engine"],
        "vuln_sync": ["vulnerability-manager"],
        "vuln_scan_start": ["greenbone", "cmdb"],
        "ansible_playbook": ["ansible", "linux-hosts"],
    }.get(kind, ["control-plane"])
    current["preconditions"] = [str(value).strip() for value in (current.get("preconditions") or []) if str(value).strip()] or default_preconditions
    current["integration_targets"] = [str(value).strip() for value in (current.get("integration_targets") or []) if str(value).strip()] or default_targets
    current["operator_notes"] = str(
        current.get("operator_notes")
        or {
            "telegram": "Use for analyst-visible notifications and escalation fan-out.",
            "webhook": "Use when the receiving system is ready to accept governed incident payloads.",
            "approval_gate": "Use only with a linked case and explicit approval record.",
            "chain": "Validate every step and downstream dependency before live execution.",
            "vuln_sync": "Use for scoped vulnerability synchronization and coverage workflows.",
            "vuln_scan_start": "Start only tasks with current CMDB bindings; stale bindings are rejected.",
            "ansible_playbook": "Use a scoped inventory limit and prefer dry-run before changing machine state.",
        }.get(kind, "")
    ).strip()
    current["rollback_notes"] = str(
        current.get("rollback_notes")
        or {
            "telegram": "Notifications are immutable; publish a corrective update if needed.",
            "webhook": "Reverse or close the downstream ticket/work item if payload mapping was incorrect.",
            "approval_gate": "Restore prior target state and document the reversal in the case timeline.",
            "chain": "Rollback every completed step in reverse order using linked evidence.",
            "vuln_sync": "Remove unintended targets from the scanner scope and record the resync plan.",
            "vuln_scan_start": "Cancel the task in Greenbone if needed; the target itself is not changed.",
            "ansible_playbook": "Use playbook evidence and the linked case to run the documented rollback step.",
        }.get(kind, "")
    ).strip()
    return current


def _merge_response_action_seed(seed: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    merged = _json_clone(seed)
    merged.update(_json_clone(current))
    merged["target"] = {
        **dict(seed.get("target") or {}),
        **dict(current.get("target") or {}),
    }
    merged["health"] = {
        **dict(seed.get("health") or {}),
        **dict(current.get("health") or {}),
    }
    merged["approval"] = {
        **dict(seed.get("approval") or {}),
        **dict(current.get("approval") or {}),
    }
    merged["default_linkage"] = {
        **dict(seed.get("default_linkage") or {}),
        **dict(current.get("default_linkage") or {}),
    }
    merged["steps"] = list(current.get("steps") or seed.get("steps") or [])
    if not list(merged.get("secret_requirements") or []):
        merged["secret_requirements"] = list(seed.get("secret_requirements") or [])
    for list_field in ("owners", "trigger_kinds", "evidence_contract", "rollback_contract", "compliance_controls", "preconditions", "integration_targets"):
        merged[list_field] = [str(value).strip() for value in (merged.get(list_field) or []) if str(value).strip()]
        if not merged[list_field]:
            merged[list_field] = [str(value).strip() for value in (seed.get(list_field) or []) if str(value).strip()]
    for text_field in ("operator_notes", "rollback_notes"):
        merged[text_field] = str(merged.get(text_field) or seed.get(text_field) or "").strip()
    return merged


def _run_response_sequence(
    action: dict[str, Any],
    runtime_payload: dict[str, Any],
    *,
    actor: str,
    dry_run: bool,
) -> dict[str, Any]:
    steps = _action_steps(action)
    resume_from_step = max(0, int(runtime_payload.get("_response_resume_from_step") or runtime_payload.get("resume_from_step") or 0))
    step_results: list[dict[str, Any]] = []
    failed_step: dict[str, Any] | None = None
    for index, step in enumerate(steps):
        if index < resume_from_step:
            step_results.append(
                {
                    "step_id": str(step.get("id") or f"step-{index + 1}"),
                    "index": index,
                    "status": "skipped",
                    "message": "Skipped because execution resumed from a later step",
                    "details": {"resume_skip": True},
                    "attempts_total": 0,
                }
            )
            continue
        step_action = _build_step_action(action, step)
        max_attempts, backoff_ms = _resolve_retry_policy(step_action)
        step_status = "accepted"
        step_message = ""
        step_details: dict[str, Any] = {}
        step_attempts = 0
        step_error = ""
        try:
            for attempt in range(1, max_attempts + 1):
                step_attempts = attempt
                executed = _run_response_executor(step_action, runtime_payload, dry_run=dry_run)
                step_status = str(executed.get("status") or ("dry_run" if dry_run else "accepted"))
                step_message = str(executed.get("message") or "")
                step_details = dict(executed.get("details") or {})
                step_error = str(step_details.get("error") or "")
                if step_status not in RESPONSE_RETRYABLE_STATUSES:
                    break
                if attempt < max_attempts and backoff_ms > 0:
                    time.sleep(backoff_ms / 1000.0)
        except Exception as exc:  # noqa: BLE001
            step_status = "error"
            step_message = str(exc)
            step_details = {"executor": str(step_action.get("kind") or "action"), "error": str(exc)}
            step_error = str(exc)
            step_attempts = max(step_attempts, 1)
        step_result = {
            "step_id": str(step.get("id") or f"step-{index + 1}"),
            "index": index,
            "title": str(step.get("title") or step_action.get("title") or step.get("id") or f"step-{index + 1}"),
            "status": step_status,
            "message": step_message,
            "details": step_details,
            "attempts_total": int(step_attempts or 1),
            "continue_on_error": bool(step.get("continue_on_error", False)),
        }
        step_results.append(step_result)
        append_audit_event(
            actor=actor,
            action="response_action.step_executed",
            object_type="response_action_step",
            object_id=str(step_result["step_id"]),
            summary=str(step_result["title"]),
            details={
                "action_id": str(action.get("id") or ""),
                "status": step_status,
                "attempts_total": int(step_result["attempts_total"]),
                "dry_run": bool(dry_run),
            },
        )
        if step_status in RESPONSE_RETRYABLE_STATUSES:
            failed_step = {
                **step_result,
                "error": step_error,
                "resume_from_step": index,
            }
            if not bool(step.get("continue_on_error", False)):
                break
    successful_steps = [item for item in step_results if str(item.get("status") or "") in RESPONSE_SUCCESS_STATUSES]
    failed_steps = [item for item in step_results if str(item.get("status") or "") in RESPONSE_RETRYABLE_STATUSES]
    if dry_run:
        status = "dry_run"
    elif not failed_steps:
        status = "executed"
    elif successful_steps:
        status = "partial_failure"
    else:
        status = str(failed_steps[0].get("status") or "error")
    failed_index = int(failed_step.get("resume_from_step")) if failed_step else None
    details = {
        "executor": "sequence" if len(steps) > 1 else str(action.get("kind") or "action"),
        "steps": step_results,
        "sequence_total": len(steps),
        "sequence_completed": len(successful_steps),
        "sequence_failed": len(failed_steps),
        "resume_from_step": failed_index,
        "resume_payload": {"_response_resume_from_step": failed_index} if failed_index is not None else {},
        "error": str((failed_step or {}).get("error") or ""),
    }
    if dry_run:
        message = f"Validated {len(steps)} response step(s)"
    elif failed_steps:
        message = f"Executed {len(successful_steps)} of {len(steps)} response step(s)"
    else:
        message = f"Executed {len(steps)} response step(s)"
    return {"status": status, "message": message, "details": details}


def list_response_actions() -> list[dict[str, Any]]:
    default_rows = _merged_default_response_actions()
    rows = _merge_seed_rows(_collection("response_actions", _merged_default_response_actions), default_rows)
    original_rows = _json_clone(rows)
    seed_by_id = {str(item.get("id") or ""): item for item in default_rows}
    normalized_rows: list[dict[str, Any]] = []
    for item in rows:
        item_id = str(item.get("id") or "")
        current = _merge_response_action_seed(seed_by_id[item_id], item) if item_id in seed_by_id else dict(item)
        dangerous = bool(current.get("dangerous", False))
        approval_required = bool(current.get("approval_required", False))
        current["approval"] = normalize_response_approval(current.get("approval") or {}, required=approval_required, dangerous=dangerous)
        current["approval_required"] = bool(current.get("approval", {}).get("required", approval_required))
        current["policy_pack_id"] = infer_policy_pack_id(current)
        current["default_linkage"] = normalize_action_linkage(current.get("default_linkage") or {})
        current["trigger_kinds"] = [str(value).strip().lower() for value in (current.get("trigger_kinds") or []) if str(value).strip()]
        current["owners"] = [str(value).strip() for value in (current.get("owners") or []) if str(value).strip()]
        current = _normalize_response_action_governance(current)
        normalized_rows.append(current)
    rows = normalized_rows
    if rows != original_rows:
        _save_collection("response_actions", rows)
    rows.sort(key=lambda item: str(item.get("title") or item.get("id") or ""))
    return _json_clone(rows)


def save_response_action(payload: dict[str, Any]) -> dict[str, Any]:
    rows = list_response_actions()
    action_id = _safe_slug(str(payload.get("id") or payload.get("title") or ""), default=_new_id("action"))
    existing = _find_by_id(rows, action_id)
    target = _resolve_runtime_object(payload.get("target") or (existing.get("target") if existing else {}))
    steps = _normalize_response_steps(payload.get("steps"), existing=list(existing.get("steps") or []) if existing else None)
    resolved_kind = str(payload.get("kind") or (existing.get("kind") if existing else ("chain" if steps else "webhook")) or ("chain" if steps else "webhook"))
    approval_required = bool(payload.get("approval_required", existing.get("approval_required", False) if existing else False))
    dangerous = bool(payload.get("dangerous", existing.get("dangerous", False) if existing else False))
    approval = normalize_response_approval(
        payload.get("approval") or (existing.get("approval") if existing else {}),
        required=approval_required,
        dangerous=dangerous,
    )
    trigger_kinds = [
        str(item).strip().lower()
        for item in (payload.get("trigger_kinds") or (existing.get("trigger_kinds") if existing else []) or [])
        if str(item).strip()
    ]
    if trigger_kinds and not list(approval.get("allowed_trigger_kinds") or []):
        approval["allowed_trigger_kinds"] = list(trigger_kinds)
    policy_pack_id = infer_policy_pack_id(
        {
            "policy_pack_id": payload.get("policy_pack_id") or (existing.get("policy_pack_id") if existing else ""),
            "title": payload.get("title") or (existing.get("title") if existing else ""),
            "description": payload.get("description") or (existing.get("description") if existing else ""),
            "kind": resolved_kind,
            "steps": steps,
        }
    )
    item = {
        "id": action_id,
        "type": "response_action",
        "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
        "kind": resolved_kind.strip().lower() or ("chain" if steps else "webhook"),
        "title": str(payload.get("title") or action_id),
        "description": str(payload.get("description") or ""),
        "enabled": bool(payload.get("enabled", existing.get("enabled", True) if existing else True)),
        "dangerous": dangerous,
        "approval_required": bool(approval.get("required")),
        "approval": approval,
        "updated_ts": _now_iso(),
        "health": dict(existing.get("health") if existing else {"last_execution_ts": "", "last_status": "never", "total_executions": 0}),
        "target": target,
        "steps": steps,
        "message_template": str(payload.get("message_template") or (existing.get("message_template") if existing else "") or ""),
        "policy_pack_id": policy_pack_id,
        "template_id": str(payload.get("template_id") or (existing.get("template_id") if existing else "") or ""),
        "trigger_kinds": trigger_kinds,
        "owners": [str(item).strip() for item in (payload.get("owners") or (existing.get("owners") if existing else []) or []) if str(item).strip()],
        "default_linkage": normalize_action_linkage(payload.get("default_linkage") or (existing.get("default_linkage") if existing else {})),
        "playbook_class": str(payload.get("playbook_class") or (existing.get("playbook_class") if existing else resolved_kind) or resolved_kind).strip().lower() or resolved_kind.strip().lower() or "workflow",
        "governance_tier": str(payload.get("governance_tier") or (existing.get("governance_tier") if existing else ("high-risk" if dangerous else "operator")) or ("high-risk" if dangerous else "operator")).strip().lower(),
        "evidence_contract": [str(entry).strip() for entry in (payload.get("evidence_contract") or (existing.get("evidence_contract") if existing else []) or []) if str(entry).strip()],
        "rollback_contract": [str(entry).strip() for entry in (payload.get("rollback_contract") or (existing.get("rollback_contract") if existing else []) or []) if str(entry).strip()],
        "compliance_controls": [str(entry).strip() for entry in (payload.get("compliance_controls") or (existing.get("compliance_controls") if existing else []) or []) if str(entry).strip()],
        "preconditions": [str(entry).strip() for entry in (payload.get("preconditions") or (existing.get("preconditions") if existing else []) or []) if str(entry).strip()],
        "integration_targets": [str(entry).strip() for entry in (payload.get("integration_targets") or (existing.get("integration_targets") if existing else []) or []) if str(entry).strip()],
        "operator_notes": str(payload.get("operator_notes") or (existing.get("operator_notes") if existing else "") or ""),
        "rollback_notes": str(payload.get("rollback_notes") or (existing.get("rollback_notes") if existing else "") or ""),
        "secret_requirements": _normalize_connector_secret_requirements(
            payload.get("secret_requirements") or (existing.get("secret_requirements") if existing else [])
        ),
    }
    rows = [row for row in rows if str(row.get("id") or "") != action_id]
    rows.append(item)
    _save_collection("response_actions", rows)
    append_audit_event(
        actor=str(payload.get("_audit_actor") or "system"),
        action="response_action.saved",
        object_type="response_action",
        object_id=item["id"],
        summary=item["title"],
        details={
            "kind": item["kind"],
            "approval_required": item["approval_required"],
            "approval_mode": str(item.get("approval", {}).get("mode") or ""),
            "enabled": item["enabled"],
            "policy_pack_id": policy_pack_id,
            "playbook_class": item["playbook_class"],
            "governance_tier": item["governance_tier"],
            "retry_attempts": int(target.get("retry_attempts") or 1),
            "steps_total": len(steps),
            "integration_targets": len(item["integration_targets"]),
            "preconditions": len(item["preconditions"]),
        },
    )
    return _json_clone(item)


def list_response_executions(*, action_id: str = "", limit: int = 100) -> list[dict[str, Any]]:
    rows = _collection("response_executions", _default_response_executions)
    safe_action_id = str(action_id or "").strip()
    if safe_action_id:
        rows = [item for item in rows if str(item.get("action_id") or "") == safe_action_id]
    rows.sort(key=lambda item: _parse_ts(str(item.get("created_ts") or "")), reverse=True)
    return _json_clone(rows[: max(1, min(500, int(limit or 100)))])


def list_response_dlq(limit: int = 100) -> list[dict[str, Any]]:
    rows = _collection("response_dlq", _default_response_dlq)
    rows.sort(key=lambda item: _parse_ts(str(item.get("created_ts") or "")), reverse=True)
    return _json_clone(rows[: max(1, min(500, int(limit or 100)))])


def list_response_ledger(limit: int = 100) -> list[dict[str, Any]]:
    rows = _collection("response_ledger", _default_response_ledger)
    rows.sort(key=lambda item: _parse_ts(str(item.get("created_ts") or "")), reverse=True)
    return _json_clone(rows[: max(1, min(1000, int(limit or 100)))])


def _save_response_action_rows(rows: list[dict[str, Any]], updated: dict[str, Any]) -> None:
    _save_collection("response_actions", [updated if str(item.get("id") or "") == str(updated.get("id") or "") else item for item in rows])


def _save_response_execution_rows(rows: list[dict[str, Any]], updated: dict[str, Any]) -> None:
    _save_collection("response_executions", [updated if str(item.get("id") or "") == str(updated.get("id") or "") else item for item in rows])


def _save_response_dlq_rows(rows: list[dict[str, Any]], updated: dict[str, Any] | None = None) -> None:
    payload = rows if updated is None else [updated if str(item.get("id") or "") == str(updated.get("id") or "") else item for item in rows]
    _save_collection("response_dlq", payload)


def _record_response_ledger(
    *,
    action: dict[str, Any] | None,
    execution: dict[str, Any] | None,
    actor: str,
    stage: str,
    status: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    rows = _collection("response_ledger", _default_response_ledger)
    entry = {
        "id": _new_id("rled"),
        "type": "response_ledger",
        "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
        "created_ts": _now_iso(),
        "actor": str(actor or "system"),
        "stage": str(stage or "execution"),
        "status": str(status or "unknown"),
        "action_id": str((action or {}).get("id") or (execution or {}).get("action_id") or ""),
        "execution_id": str((execution or {}).get("id") or ""),
        "approval": _json_clone((execution or {}).get("approval") or {}),
        "linkage": _json_clone((execution or {}).get("linkage") or {}),
        "details": _json_clone(details or {}),
    }
    rows.append(entry)
    rows = sorted(rows, key=lambda item: _parse_ts(str(item.get("created_ts") or "")), reverse=True)[:1000]
    _save_collection("response_ledger", rows)
    return entry


def _update_action_health(action: dict[str, Any], *, status: str, details: dict[str, Any] | None = None, increment_total: bool = True) -> dict[str, Any]:
    health = dict(action.get("health") or {})
    health["last_execution_ts"] = _now_iso()
    health["last_status"] = str(status or "unknown")
    if increment_total:
        health["total_executions"] = int(health.get("total_executions") or 0) + 1
    if details and details.get("latency_ms") is not None:
        health["last_latency_ms"] = float(details.get("latency_ms") or 0)
    if details and details.get("error"):
        health["last_error"] = str(details.get("error"))
    elif status in RESPONSE_SUCCESS_STATUSES:
        health.pop("last_error", None)
    action["health"] = health
    action["updated_ts"] = _now_iso()
    return action


def _resolve_retry_policy(action: dict[str, Any]) -> tuple[int, int]:
    target = dict(_resolve_runtime_object(action.get("target") or {}))
    max_attempts = max(1, min(5, int(target.get("retry_attempts") or 1)))
    backoff_ms = max(0, min(5000, int(target.get("retry_backoff_ms") or 0)))
    return max_attempts, backoff_ms


def _idempotency_key(action_id: str, payload: dict[str, Any], *, dry_run: bool) -> str:
    explicit = str(payload.get("idempotency_key") or payload.get("_idempotency_key") or "").strip()
    if explicit:
        return explicit
    payload_repr = repr(_json_clone(_clean_runtime_payload(payload)))
    digest = hashlib.sha256(payload_repr.encode("utf-8")).hexdigest()
    return f"{action_id}:{'dry' if dry_run else 'live'}:{digest}"


def _remember_idempotency(action_id: str, idempotency_key: str, execution_id: str) -> None:
    rows = _collection("response_idempotency", _default_response_idempotency)
    rows = [
        item
        for item in rows
        if not (
            str(item.get("action_id") or "") == str(action_id)
            and str(item.get("idempotency_key") or "") == str(idempotency_key)
        )
    ]
    rows.append(
        {
            "id": _new_id("idem"),
            "type": "response_idempotency",
            "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
            "action_id": str(action_id),
            "idempotency_key": str(idempotency_key),
            "execution_id": str(execution_id),
            "created_ts": _now_iso(),
        }
    )
    rows = sorted(rows, key=lambda item: _parse_ts(str(item.get("created_ts") or "")), reverse=True)[:2000]
    _save_collection("response_idempotency", rows)


def _lookup_idempotent_execution(action_id: str, idempotency_key: str) -> dict[str, Any] | None:
    rows = _collection("response_idempotency", _default_response_idempotency)
    match = next(
        (
            item
            for item in rows
            if str(item.get("action_id") or "") == str(action_id)
            and str(item.get("idempotency_key") or "") == str(idempotency_key)
        ),
        None,
    )
    if match is None:
        return None
    execution_id = str(match.get("execution_id") or "")
    return _find_by_id(_collection("response_executions", _default_response_executions), execution_id)


def _record_response_dlq(action: dict[str, Any], execution: dict[str, Any], *, actor: str) -> dict[str, Any]:
    rows = _collection("response_dlq", _default_response_dlq)
    details = dict(execution.get("details") or {})
    entry = {
        "id": _new_id("rdlq"),
        "type": "response_dlq",
        "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
        "action_id": str(action.get("id") or ""),
        "execution_id": str(execution.get("id") or ""),
        "created_ts": _now_iso(),
        "actor": actor,
        "status": str(execution.get("status") or "error"),
        "error": str(execution.get("error") or execution.get("message") or ""),
        "payload": _json_clone(execution.get("payload") or {}),
        "linkage": _json_clone(execution.get("linkage") or {}),
        "approval": _json_clone(execution.get("approval") or {}),
        "attempts": int(execution.get("attempts_total") or 1),
        "resume_from_step": details.get("resume_from_step"),
        "resume_payload": _json_clone(details.get("resume_payload") or {}),
    }
    rows.append(entry)
    rows = sorted(rows, key=lambda item: _parse_ts(str(item.get("created_ts") or "")), reverse=True)[:500]
    _save_response_dlq_rows(rows)
    return entry


def _execute_webhook_action(action: dict[str, Any], payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    target = dict(_resolve_runtime_object(action.get("target") or {}))
    url = str(_resolve_config_value(target, "url", "") or "").strip()
    if not url:
        raise ValueError("Webhook action requires target.url or target.url_env")
    method = str(_resolve_config_value(target, "method", "POST") or "POST").upper()
    headers = {str(key): str(value) for key, value in dict(_resolve_config_value(target, "headers", {}) or {}).items()}
    message = _coerce_message_text(action, _clean_runtime_payload(payload))
    secret_value = str(
        payload.get("_resolved_secrets", {}).get("SIEM_WEBHOOK_SHARED_SECRET")
        or _resolve_secret_value("SIEM_WEBHOOK_SHARED_SECRET")[0]
        or ""
    ).strip()
    if secret_value:
        headers.setdefault("x-rdegon-webhook-secret", secret_value)
    body = payload.get("body")
    if body is None:
        body = {
            "action_id": action.get("id"),
            "title": action.get("title"),
            "kind": action.get("kind"),
            "message": message,
            "linkage": _clean_runtime_payload(payload).get("linkage") or {},
            "payload": _clean_runtime_payload(payload),
        }
    if dry_run:
        return {"status": "dry_run", "message": f"Validated webhook target {url}", "details": {"executor": "webhook", "url": url, "method": method}}
    response = _http_request(
        url=url,
        method=method,
        headers=headers,
        body=body,
        timeout_seconds=_safe_timeout_seconds(_resolve_config_value(target, "timeout_ms", 10000)),
        verify_tls=bool(target.get("verify_tls", True)),
    )
    http_status = int(response.get("http_status") or 0)
    status = "executed" if 200 <= http_status < 300 else "error"
    return {
        "status": status,
        "message": f"Webhook action delivered to {url}",
        "details": {
            "executor": "webhook",
            "url": url,
            "method": method,
            "http_status": http_status,
            "latency_ms": float(response.get("latency_ms") or 0),
            "response": _sample_records(_decode_http_payload(response.get("body", b""), str(response.get("content_type") or ""))),
            "error": str(response.get("error") or ""),
        },
    }


def _execute_telegram_action(action: dict[str, Any], payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    target = dict(_resolve_runtime_object(action.get("target") or {}))
    api_base_url = str(_resolve_config_value(target, "api_base_url", "https://api.telegram.org") or "https://api.telegram.org").rstrip("/")
    bot_token = str(
        payload.get("_resolved_secrets", {}).get("SIEM_TELEGRAM_BOT_TOKEN")
        or _resolve_secret_value("SIEM_TELEGRAM_BOT_TOKEN")[0]
        or _resolve_config_value(target, "token", "")
        or ""
    ).strip()
    chat_id = str(_resolve_config_value(target, "chat_id", "") or "").strip()
    if not bot_token:
        raise ValueError("Telegram action requires a bot token")
    if not chat_id:
        raise ValueError("Telegram action requires target.chat_id or target.chat_id_env")
    message = _coerce_message_text(action, _clean_runtime_payload(payload))
    if dry_run:
        return {"status": "dry_run", "message": f"Validated Telegram action for chat {chat_id}", "details": {"executor": "telegram", "chat_id": chat_id}}
    response = _http_request(
        url=f"{api_base_url}/bot{bot_token}/sendMessage",
        method="POST",
        headers={"Accept": "application/json"},
        body={"chat_id": chat_id, "text": message},
        timeout_seconds=_safe_timeout_seconds(_resolve_config_value(target, "timeout_ms", 10000)),
        verify_tls=bool(target.get("verify_tls", True)),
    )
    http_status = int(response.get("http_status") or 0)
    status = "executed" if 200 <= http_status < 300 else "error"
    return {
        "status": status,
        "message": f"Telegram message sent to chat {chat_id}",
        "details": {
            "executor": "telegram",
            "chat_id": chat_id,
            "http_status": http_status,
            "latency_ms": float(response.get("latency_ms") or 0),
            "response": _sample_records(_decode_http_payload(response.get("body", b""), str(response.get("content_type") or ""))),
            "error": str(response.get("error") or ""),
        },
    }


def _execute_email_action(action: dict[str, Any], payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    target = dict(_resolve_runtime_object(action.get("target") or {}))
    host = str(_resolve_config_value(target, "smtp_host", "") or "").strip()
    if not host:
        raise ValueError("Email action requires target.smtp_host")
    sender = str(_resolve_config_value(target, "from", "") or "").strip()
    recipients_value = _resolve_config_value(target, "recipients", target.get("to") or [])
    if isinstance(recipients_value, str):
        recipients = [item.strip() for item in recipients_value.split(",") if item.strip()]
    else:
        recipients = [str(item).strip() for item in (recipients_value or []) if str(item).strip()]
    if not sender or not recipients:
        raise ValueError("Email action requires sender and recipients")
    subject = str(payload.get("subject") or action.get("title") or "Rdegon SIEM notification")
    message_text = _coerce_message_text(action, _clean_runtime_payload(payload))
    if dry_run:
        return {"status": "dry_run", "message": f"Validated email action for {len(recipients)} recipient(s)", "details": {"executor": "email", "smtp_host": host, "recipients": recipients}}
    started = time.perf_counter()
    email_message = EmailMessage()
    email_message["Subject"] = subject
    email_message["From"] = sender
    email_message["To"] = ", ".join(recipients)
    email_message.set_content(message_text)
    port = int(_resolve_config_value(target, "smtp_port", 587) or 587)
    username = str(_resolve_config_value(target, "smtp_user", "") or "").strip()
    password = str(_resolve_config_value(target, "smtp_password", "") or _resolve_secret_value("SIEM_SMTP_PASSWORD")[0] or "").strip()
    use_ssl = bool(target.get("use_ssl", False))
    use_tls = bool(target.get("use_tls", not use_ssl))
    if use_ssl:
        with smtplib.SMTP_SSL(host, port, timeout=_safe_timeout_seconds(_resolve_config_value(target, "timeout_ms", 10000))) as server:
            if username and password:
                server.login(username, password)
            server.send_message(email_message)
    else:
        with smtplib.SMTP(host, port, timeout=_safe_timeout_seconds(_resolve_config_value(target, "timeout_ms", 10000))) as server:
            if use_tls:
                server.starttls()
            if username and password:
                server.login(username, password)
            server.send_message(email_message)
    latency_ms = round((time.perf_counter() - started) * 1000.0, 1)
    return {"status": "executed", "message": f"Email sent to {len(recipients)} recipient(s)", "details": {"executor": "email", "smtp_host": host, "recipients": recipients, "latency_ms": latency_ms}}


def _execute_runtime_doc_action(action: dict[str, Any], payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    try:
        from .deps_runtime_docs_ops import save_runtime_doc
    except ImportError:  # pragma: no cover - local test fallback
        from deps_runtime_docs_ops import save_runtime_doc  # type: ignore[no-redef]
    target = dict(_resolve_runtime_object(action.get("target") or {}))
    name = str(_resolve_config_value(target, "name", payload.get("name") or action.get("id") or "response-action.md") or "").strip()
    if not name:
        raise ValueError("runtime_doc action requires target.name")
    content = str(payload.get("content") or _coerce_message_text(action, _clean_runtime_payload(payload))).strip()
    if dry_run:
        return {"status": "dry_run", "message": f"Validated runtime doc write for {name}", "details": {"executor": "runtime_doc", "name": name}}
    saved = save_runtime_doc(name, content)
    return {"status": "executed", "message": f"Runtime doc updated: {name}", "details": {"executor": "runtime_doc", "name": name, "saved": saved}}


def _execute_case_comment_action(action: dict[str, Any], payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    try:
        from .control_plane_case_ops import append_case_comment
    except ImportError:  # pragma: no cover - local test fallback
        from control_plane_case_ops import append_case_comment  # type: ignore[no-redef]
    target = dict(_resolve_runtime_object(action.get("target") or {}))
    linkage = dict(payload.get("linkage") or {})
    case_id = str(_resolve_config_value(target, "case_id", linkage.get("case_id") or payload.get("case_id") or "") or "").strip()
    if not case_id:
        raise ValueError("case_comment action requires target.case_id")
    body = str(payload.get("body") or _coerce_message_text(action, _clean_runtime_payload(payload))).strip()
    if not body:
        raise ValueError("case_comment action requires a message body")
    if dry_run:
        return {"status": "dry_run", "message": f"Validated case comment for {case_id}", "details": {"executor": "case_comment", "case_id": case_id}}
    case_item = append_case_comment(case_id, body=body, author=str(payload.get("author") or "response-action"))
    return {"status": "executed", "message": f"Case comment added to {case_id}", "details": {"executor": "case_comment", "case_id": case_id, "comments_total": len(case_item.get("comments") or [])}}


def _execute_slack_webhook_action(action: dict[str, Any], payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    target = dict(_resolve_runtime_object(action.get("target") or {}))
    url = str(_resolve_config_value(target, "url", "") or "").strip()
    if not url:
        raise ValueError("slack_webhook action requires target.url")
    body = {
        "text": str(payload.get("text") or _coerce_message_text(action, _clean_runtime_payload(payload))).strip(),
        "blocks": payload.get("blocks") if isinstance(payload.get("blocks"), list) else None,
    }
    if body["blocks"] is None:
        body.pop("blocks")
    if dry_run:
        return {"status": "dry_run", "message": f"Validated Slack webhook target {url}", "details": {"executor": "slack_webhook", "url": url}}
    response = _http_request(
        url=url,
        method="POST",
        headers={"Accept": "application/json"},
        body=body,
        timeout_seconds=_safe_timeout_seconds(_resolve_config_value(target, "timeout_ms", 10000)),
        verify_tls=bool(target.get("verify_tls", True)),
    )
    http_status = int(response.get("http_status") or 0)
    status = "executed" if 200 <= http_status < 300 else "error"
    return {
        "status": status,
        "message": "Slack webhook dispatched",
        "details": {"executor": "slack_webhook", "url": url, "http_status": http_status, "latency_ms": float(response.get("latency_ms") or 0), "error": str(response.get("error") or "")},
    }


def _ansible_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value or "").strip()
    if not text:
        return []
    return [item.strip() for item in text.split(",") if item.strip()]


def _build_ansible_command(target: dict[str, Any], payload: dict[str, Any]) -> list[str]:
    binary = str(_resolve_config_value(target, "binary", payload.get("ansible_binary") or "ansible-playbook") or "ansible-playbook").strip()
    inventory = str(_resolve_config_value(target, "inventory", payload.get("inventory") or "") or "").strip()
    playbook = str(_resolve_config_value(target, "playbook", payload.get("playbook") or "") or "").strip()
    url = str(_resolve_config_value(target, "url", "") or "").strip()
    if not playbook and url.startswith("ansible://"):
        playbook = url[len("ansible://") :].strip("/")
    if not playbook:
        raise ValueError("ansible_playbook action requires target.playbook")
    command = [binary]
    if inventory:
        command.extend(["-i", inventory])
    command.append(playbook)
    limit = str(_resolve_config_value(target, "limit", payload.get("limit") or "") or "").strip()
    if limit:
        command.extend(["--limit", limit])
    tags = _ansible_list(_resolve_config_value(target, "tags", payload.get("tags") or ""))
    if tags:
        command.extend(["--tags", ",".join(tags)])
    skip_tags = _ansible_list(_resolve_config_value(target, "skip_tags", payload.get("skip_tags") or ""))
    if skip_tags:
        command.extend(["--skip-tags", ",".join(skip_tags)])
    if bool(_resolve_config_value(target, "check_mode", payload.get("check_mode") if "check_mode" in payload else False)):
        command.append("--check")
    if bool(_resolve_config_value(target, "diff", payload.get("diff") if "diff" in payload else False)):
        command.append("--diff")
    extra_vars = payload.get("extra_vars") if "extra_vars" in payload else target.get("extra_vars")
    if isinstance(extra_vars, dict) and extra_vars:
        command.extend(["--extra-vars", json.dumps(extra_vars, ensure_ascii=False)])
    elif isinstance(extra_vars, str) and extra_vars.strip():
        command.extend(["--extra-vars", extra_vars.strip()])
    return command


def _execute_ansible_playbook_action(action: dict[str, Any], payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    target = dict(_resolve_runtime_object(action.get("target") or {}))
    command = _build_ansible_command(target, payload)
    command_preview = subprocess.list2cmdline(command)
    if dry_run:
        return {
            "status": "dry_run",
            "message": f"Validated Ansible playbook: {command[-1]}",
            "details": {"executor": "ansible_playbook", "command": command, "command_preview": command_preview},
        }
    resolved_binary = shutil.which(command[0])
    if not resolved_binary:
        raise ValueError(f"ansible-playbook binary is not available: {command[0]}")
    command[0] = resolved_binary
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=_safe_timeout_seconds(_resolve_config_value(target, "timeout_ms", 120000), default_ms=120000),
    )
    latency_ms = round((time.perf_counter() - started) * 1000.0, 1)
    stdout_tail = "\n".join(str(completed.stdout or "").splitlines()[-80:])
    stderr_tail = "\n".join(str(completed.stderr or "").splitlines()[-80:])
    status = "executed" if completed.returncode == 0 else "error"
    return {
        "status": status,
        "message": f"Ansible playbook finished with rc={completed.returncode}",
        "details": {
            "executor": "ansible_playbook",
            "command": command,
            "command_preview": command_preview,
            "returncode": completed.returncode,
            "latency_ms": latency_ms,
            "stdout_tail": stdout_tail,
            "stderr_tail": stderr_tail,
            "error": stderr_tail if completed.returncode else "",
        },
    }


def _execute_vuln_sync_action(action: dict[str, Any], payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    try:
        from .vulnerability_query_runtime import sync_vulnerability_targets
    except ImportError:  # pragma: no cover - local test fallback
        from vulnerability_query_runtime import sync_vulnerability_targets  # type: ignore[no-redef]
    target = dict(_resolve_runtime_object(action.get("target") or {}))
    asset_seeds = _clean_runtime_payload(payload).get("assets")
    if not asset_seeds:
        asset_seeds = target.get("assets") or []
    normalized_assets = _normalize_vuln_asset_seed(asset_seeds)
    limit = _int_or_default(_resolve_config_value(target, "limit", payload.get("limit") or 500), 500)
    if dry_run:
        return {
            "status": "dry_run",
            "message": f"Validated vulnerability target sync for {len(normalized_assets)} seeded asset(s)",
            "details": {"executor": "vuln_sync", "limit": limit, "asset_seed_total": len(normalized_assets), "assets": normalized_assets},
        }
    saved_assets = _upsert_vuln_asset_seeds(normalized_assets)
    result = dict(sync_vulnerability_targets(limit=max(limit, len(saved_assets) or 1)))
    status = "executed" if str(result.get("status") or "ok").lower() != "error" else "error"
    return {
        "status": status,
        "message": f"Synchronized vulnerability targets for {len(saved_assets)} seeded asset(s)",
        "details": {
            "executor": "vuln_sync",
            "limit": limit,
            "asset_seed_total": len(normalized_assets),
            "seeded_assets": saved_assets,
            "sync": result,
            "error": str(result.get("error") or ""),
        },
    }


def _execute_vuln_import_action(action: dict[str, Any], payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    try:
        from .vulnerability_query_runtime import import_greenbone_reports
    except ImportError:  # pragma: no cover - local test fallback
        from vulnerability_query_runtime import import_greenbone_reports  # type: ignore[no-redef]
    target = dict(_resolve_runtime_object(action.get("target") or {}))
    limit = _int_or_default(_resolve_config_value(target, "limit", payload.get("limit") or 20), 20, maximum=500)
    if dry_run:
        return {
            "status": "dry_run",
            "message": f"Validated Greenbone report import for up to {limit} report(s)",
            "details": {"executor": "vuln_import", "limit": limit},
        }
    result = dict(import_greenbone_reports(limit=limit))
    status = "executed" if str(result.get("status") or "ok").lower() != "error" else "error"
    imported_total = int(result.get("imported") or result.get("processed") or result.get("saved") or 0)
    return {
        "status": status,
        "message": f"Imported {imported_total} Greenbone report(s)",
        "details": {"executor": "vuln_import", "limit": limit, "result": result, "error": str(result.get("error") or "")},
    }


def _execute_vuln_scan_start_action(action: dict[str, Any], payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    try:
        from .vulnerability_query_runtime import start_vulnerability_scans
    except ImportError:  # pragma: no cover - local test fallback
        from vulnerability_query_runtime import start_vulnerability_scans  # type: ignore[no-redef]
    target = dict(_resolve_runtime_object(action.get("target") or {}))
    raw_asset_ids = payload.get("asset_ids") if "asset_ids" in payload else target.get("asset_ids")
    if isinstance(raw_asset_ids, str):
        asset_ids = [item.strip() for item in raw_asset_ids.split(",") if item.strip()]
    elif isinstance(raw_asset_ids, (list, tuple, set)):
        asset_ids = [str(item).strip() for item in raw_asset_ids if str(item).strip()]
    else:
        asset_ids = []
    if not asset_ids:
        raise ValueError("vuln_scan_start action requires at least one asset_id")
    limit = _int_or_default(_resolve_config_value(target, "limit", payload.get("limit") or 25), 25, maximum=100)
    if dry_run:
        return {
            "status": "dry_run",
            "message": f"Validated targeted Greenbone rescan for {len(asset_ids)} asset(s)",
            "details": {"executor": "vuln_scan_start", "asset_ids": asset_ids, "limit": limit},
        }
    result = dict(start_vulnerability_scans(asset_ids=asset_ids, limit=limit))
    status = "executed" if str(result.get("status") or "ok").lower() not in {"error", "degraded"} else "error"
    return {
        "status": status,
        "message": f"Started {int(result.get('started') or 0)} targeted Greenbone scan(s)",
        "details": {
            "executor": "vuln_scan_start",
            "asset_ids": asset_ids,
            "limit": limit,
            "result": result,
            "error": "" if status == "executed" else "One or more scan tasks failed",
        },
    }


def _execute_vuln_policy_apply_action(action: dict[str, Any], payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    try:
        from .vuln_maturity_runtime import apply_vulnerability_incident_policies
    except ImportError:  # pragma: no cover - local test fallback
        from vuln_maturity_runtime import apply_vulnerability_incident_policies  # type: ignore[no-redef]
    target = dict(_resolve_runtime_object(action.get("target") or {}))
    days = _int_or_default(_resolve_config_value(target, "days", payload.get("days") or 30), 30, maximum=365)
    limit = _int_or_default(_resolve_config_value(target, "limit", payload.get("limit") or 50), 50, maximum=500)
    actor = str(payload.get("actor") or payload.get("initiated_by") or "response-action").strip() or "response-action"
    if dry_run:
        return {
            "status": "dry_run",
            "message": f"Validated vulnerability incident policy application for {days} day(s)",
            "details": {"executor": "vuln_policy_apply", "days": days, "limit": limit, "actor": actor},
        }
    result = dict(apply_vulnerability_incident_policies(actor=actor, days=days, limit=limit))
    return {
        "status": "executed",
        "message": f"Applied vulnerability policies: created {int(result.get('created') or 0)} case(s)",
        "details": {"executor": "vuln_policy_apply", "days": days, "limit": limit, "actor": actor, "result": result},
    }


def _run_response_executor(action: dict[str, Any], payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    kind = str(action.get("kind") or "webhook").strip().lower()
    if kind == "webhook":
        return _execute_webhook_action(action, payload, dry_run=dry_run)
    if kind == "telegram":
        return _execute_telegram_action(action, payload, dry_run=dry_run)
    if kind == "email":
        return _execute_email_action(action, payload, dry_run=dry_run)
    if kind == "vuln_sync":
        return _execute_vuln_sync_action(action, payload, dry_run=dry_run)
    if kind == "vuln_import":
        return _execute_vuln_import_action(action, payload, dry_run=dry_run)
    if kind == "vuln_scan_start":
        return _execute_vuln_scan_start_action(action, payload, dry_run=dry_run)
    if kind == "vuln_policy_apply":
        return _execute_vuln_policy_apply_action(action, payload, dry_run=dry_run)
    if kind == "runtime_doc":
        return _execute_runtime_doc_action(action, payload, dry_run=dry_run)
    if kind == "case_comment":
        return _execute_case_comment_action(action, payload, dry_run=dry_run)
    if kind == "slack_webhook":
        return _execute_slack_webhook_action(action, payload, dry_run=dry_run)
    if kind == "ansible_playbook":
        return _execute_ansible_playbook_action(action, payload, dry_run=dry_run)
    if kind == "approval_gate":
        return {"status": "dry_run" if dry_run else "approved", "message": "Approval gate satisfied", "details": {"executor": "approval_gate"}}
    raise ValueError(f"Response executor is not implemented for kind={kind}")


def execute_response_action(
    action_id: str,
    *,
    actor: str = "system",
    payload: dict[str, Any] | None = None,
    dry_run: bool = True,
    principal_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    actions = list_response_actions()
    action = _find_by_id(actions, action_id)
    if action is None:
        raise ValueError(f"Response action not found: {action_id}")
    if not action.get("enabled", True):
        raise ValueError(f"Response action is disabled: {action_id}")
    secrets, missing = _resolve_required_secrets(action.get("secret_requirements") or [])
    if missing and not dry_run:
        labels = ", ".join(item["label"] for item in missing)
        raise ValueError(f"Missing required secrets: {labels}")
    runtime_payload = dict(payload or {})
    principal = _normalize_principal_context(actor, principal_context)
    approval_config = normalize_response_approval(
        action.get("approval") or {},
        required=bool(action.get("approval_required", False)),
        dangerous=bool(action.get("dangerous", False)),
    )
    linkage = build_execution_linkage(action, runtime_payload)
    _enforce_execute_governance(
        action,
        runtime_payload,
        dry_run=dry_run,
        approval_config=approval_config,
        linkage=linkage,
        principal=principal,
    )
    if linkage:
        runtime_payload["linkage"] = linkage
    if secrets:
        runtime_payload.setdefault("_resolved_secrets", secrets)
    idem_key = _idempotency_key(action_id, runtime_payload, dry_run=dry_run)
    existing = _lookup_idempotent_execution(action_id, idem_key)
    if existing is not None and str(existing.get("status") or "") in RESPONSE_SUCCESS_STATUSES:
        _record_response_ledger(
            action=action,
            execution=existing,
            actor=actor,
            stage="idempotent_reuse",
            status=str(existing.get("status") or "reused"),
            details={"idempotency_key": idem_key},
        )
        return {"execution": _json_clone(existing), "action": _json_clone(action), "reused": True}

    execution_status = "dry_run" if dry_run else "awaiting_approval" if approval_config.get("required") else "accepted"
    details: dict[str, Any] = {}
    message = ""
    error = ""
    attempts_total = 0
    approval_state = build_approval_state(
        approval_config,
        actor=actor,
        note=str(runtime_payload.get("approval_note") or runtime_payload.get("request_note") or ""),
    )
    try:
        if dry_run:
            executed = _run_response_sequence(action, runtime_payload, actor=actor, dry_run=True)
            execution_status = str(executed.get("status") or "dry_run")
            details = dict(executed.get("details") or {})
            message = str(executed.get("message") or "")
            attempts_total = 1
        elif approval_config.get("required"):
            preview = _run_response_sequence(action, runtime_payload, actor=actor, dry_run=True)
            details = dict(preview.get("details") or {})
            details["approval_progress"] = str(approval_state.get("approval_progress") or "")
            message = str(preview.get("message") or "Awaiting approval")
            attempts_total = 1
        else:
            executed = _run_response_sequence(action, runtime_payload, actor=actor, dry_run=False)
            execution_status = str(executed.get("status") or "accepted")
            details = dict(executed.get("details") or {})
            message = str(executed.get("message") or "")
            error = str(details.get("error") or "")
            attempts_total = max(
                1,
                max((int(item.get("attempts_total") or 0) for item in details.get("steps") or []), default=0),
            )
    except Exception as exc:  # noqa: BLE001
        execution_status = "error"
        error = str(exc)
        message = str(exc)
        details = {"executor": str(action.get("kind") or "action"), "error": str(exc)}
        attempts_total = max(attempts_total, 1)

    execution = {
        "id": _new_id("exec"),
        "type": "response_execution",
        "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
        "action_id": action_id,
        "kind": action.get("kind", "webhook"),
        "status": execution_status,
        "created_ts": _now_iso(),
        "actor": actor,
        "dry_run": bool(dry_run),
        "payload": _json_clone(_clean_runtime_payload(runtime_payload)),
        "approval_required": bool(approval_config.get("required", False)),
        "approval": approval_state,
        "linkage": linkage,
        "policy_pack_id": str(action.get("policy_pack_id") or ""),
        "idempotency_key": idem_key,
        "attempts_total": int(attempts_total or 1),
        "message": message,
        "details": details,
        "error": error,
        "principal_context": principal,
    }
    rows = _collection("response_executions", _default_response_executions)
    rows.append(execution)
    rows = sorted(rows, key=lambda item: _parse_ts(str(item.get("created_ts") or "")), reverse=True)[:500]
    _save_collection("response_executions", rows)

    _update_action_health(action, status=execution_status, details=details, increment_total=True)
    _save_response_action_rows(actions, action)
    _remember_idempotency(action_id, idem_key, str(execution.get("id") or ""))
    _record_response_ledger(
        action=action,
        execution=execution,
        actor=actor,
        stage="dry_run" if dry_run else "approval_requested" if approval_config.get("required") else "executed",
        status=execution_status,
        details={
            "attempts_total": int(execution.get("attempts_total") or 1),
            "policy_pack_id": str(action.get("policy_pack_id") or ""),
            "approval_progress": str(approval_state.get("approval_progress") or ""),
        },
    )
    dlq_entry = None
    if execution_status in RESPONSE_RETRYABLE_STATUSES and not dry_run and not approval_config.get("required"):
        dlq_entry = _record_response_dlq(action, execution, actor=actor)
        _record_response_ledger(
            action=action,
            execution=execution,
            actor=actor,
            stage="dlq_recorded",
            status=execution_status,
            details={"dlq_id": str(dlq_entry.get("id") or "")},
        )
    append_audit_event(
        actor=actor,
        action="response_action.executed",
        object_type="response_execution",
        object_id=execution["id"],
        summary=action.get("title") or action_id,
        details={
            "action_id": action_id,
            "status": execution_status,
            "dry_run": bool(dry_run),
            "approval_required": bool(approval_config.get("required", False)),
            "attempts_total": int(execution.get("attempts_total") or 1),
            "policy_pack_id": str(action.get("policy_pack_id") or ""),
            "trigger_kind": str(linkage.get("trigger_kind") or ""),
            "case_id": str(linkage.get("case_id") or ""),
            "dlq_id": str(dlq_entry.get("id") or "") if dlq_entry else "",
            "steps_total": int(details.get("sequence_total") or 0),
            "resume_from_step": details.get("resume_from_step"),
            "principal_type": str(principal.get("principal_type") or "user"),
            "auth_mechanism": str(principal.get("auth_mechanism") or ""),
            "break_glass": bool(principal.get("break_glass", False)),
        },
    )
    return {"execution": _json_clone(execution), "action": _json_clone(action), "dlq": _json_clone(dlq_entry) if dlq_entry else None}


def approve_response_execution(
    execution_id: str,
    *,
    actor: str = "system",
    note: str = "",
    actor_role: str = "",
    principal_type: str = "user",
    break_glass: bool = False,
) -> dict[str, Any]:
    rows = _collection("response_executions", _default_response_executions)
    item = _find_by_id(rows, execution_id)
    if item is None:
        raise ValueError(f"Execution not found: {execution_id}")
    if str(item.get("status") or "") not in {"awaiting_approval"}:
        raise ValueError("Execution is not awaiting approval")
    actions = list_response_actions()
    action = _find_by_id(actions, str(item.get("action_id") or ""))
    if action is None:
        raise ValueError(f"Response action not found: {item.get('action_id')}")
    approval_config = normalize_response_approval(
        action.get("approval") or item.get("approval") or {},
        required=bool(action.get("approval_required", item.get("approval_required", False))),
        dangerous=bool(action.get("dangerous", False)),
    )
    approval_state = dict(item.get("approval") or build_approval_state(approval_config, actor=str(item.get("actor") or "system")))
    if approval_is_expired(approval_state):
        item["status"] = "expired"
        item["error"] = "Approval window expired"
        item["approval"] = approval_state
        _save_response_execution_rows(rows, item)
        _record_response_ledger(
            action=action,
            execution=item,
            actor=actor,
            stage="approval_expired",
            status="expired",
            details={"action_id": item.get("action_id")},
        )
        raise ValueError("Approval window expired")
    if str(principal_type or "user").strip().lower() == "service_account":
        raise ValueError("Service accounts cannot approve response executions")
    if break_glass:
        raise ValueError("Break-glass principals cannot approve response executions")
    if bool(approval_state.get("justification_required")) and not str(note or "").strip():
        raise ValueError("Approval note is required")
    approval_state = record_approval(
        approval_state,
        actor=actor,
        note=note,
        actor_role=actor_role,
        principal_type=principal_type,
        break_glass=break_glass,
    )
    item["approval"] = approval_state
    item["approved_by"] = actor
    item["approved_ts"] = _now_iso()
    if not approval_ready(approval_state):
        item["message"] = f"Approval recorded ({approval_state.get('approval_progress')})"
        _save_response_execution_rows(rows, item)
        _record_response_ledger(
            action=action,
            execution=item,
            actor=actor,
            stage="approval_recorded",
            status=str(item.get("status") or "awaiting_approval"),
            details={"approval_progress": str(approval_state.get("approval_progress") or "")},
        )
        append_audit_event(
            actor=actor,
            action="response_execution.approved",
            object_type="response_execution",
            object_id=execution_id,
            summary=item.get("message") or execution_id,
            details={
                "status": item.get("status"),
                "action_id": item.get("action_id"),
                "approval_progress": str(approval_state.get("approval_progress") or ""),
            },
        )
        return _json_clone(item)
    runtime_payload = dict(item.get("payload") or {})
    secrets, missing = _resolve_required_secrets(action.get("secret_requirements") or [])
    if missing:
        labels = ", ".join(secret["label"] for secret in missing)
        item["status"] = "error"
        item["error"] = f"Missing required secrets: {labels}"
        _save_response_execution_rows(rows, item)
        _update_action_health(action, status="error", details={"error": item["error"]}, increment_total=False)
        _save_response_action_rows(actions, action)
        _record_response_ledger(
            action=action,
            execution=item,
            actor=actor,
            stage="approval_failed",
            status="error",
            details={"error": item["error"]},
        )
        append_audit_event(
            actor=actor,
            action="response_execution.approved",
            object_type="response_execution",
            object_id=execution_id,
            summary=item.get("message") or execution_id,
            details={"status": item["status"], "error": item["error"], "action_id": item.get("action_id")},
        )
        _record_response_dlq(action, item, actor=actor)
        return _json_clone(item)
    if secrets:
        runtime_payload["_resolved_secrets"] = secrets
    try:
        executed = _run_response_sequence(action, runtime_payload, actor=actor, dry_run=False)
        item["status"] = str(executed.get("status") or "approved")
        item["message"] = str(executed.get("message") or item.get("message") or "")
        item["details"] = dict(executed.get("details") or {})
        item["error"] = str(item["details"].get("error") or "")
    except Exception as exc:  # noqa: BLE001
        item["status"] = "error"
        item["message"] = str(exc)
        item["details"] = {"executor": str(action.get("kind") or "action"), "error": str(exc)}
        item["error"] = str(exc)
    item["approved_by"] = actor
    item["approved_ts"] = _now_iso()
    item["executed_ts"] = _now_iso()
    _save_response_execution_rows(rows, item)
    _update_action_health(action, status=str(item.get("status") or "approved"), details=dict(item.get("details") or {}), increment_total=False)
    _save_response_action_rows(actions, action)
    _record_response_ledger(
        action=action,
        execution=item,
        actor=actor,
        stage="approved_execution",
        status=str(item.get("status") or "approved"),
        details={"approval_progress": str(item.get("approval", {}).get("approval_progress") or "")},
    )
    append_audit_event(
        actor=actor,
        action="response_execution.approved",
        object_type="response_execution",
        object_id=execution_id,
        summary=item.get("message") or execution_id,
        details={"status": item["status"], "action_id": item.get("action_id")},
    )
    if str(item.get("status") or "") in RESPONSE_RETRYABLE_STATUSES:
        _record_response_dlq(action, item, actor=actor)
    return _json_clone(item)


def reject_response_execution(
    execution_id: str,
    *,
    actor: str = "system",
    reason: str = "",
    principal_type: str = "user",
    break_glass: bool = False,
) -> dict[str, Any]:
    rows = _collection("response_executions", _default_response_executions)
    item = _find_by_id(rows, execution_id)
    if item is None:
        raise ValueError(f"Execution not found: {execution_id}")
    if str(item.get("status") or "") != "awaiting_approval":
        raise ValueError("Execution is not awaiting approval")
    if not str(reason or "").strip():
        raise ValueError("Rejection reason is required")
    if str(principal_type or "user").strip().lower() == "service_account":
        raise ValueError("Service accounts cannot reject response executions")
    if break_glass:
        raise ValueError("Break-glass principals cannot reject response executions")
    actions = list_response_actions()
    action = _find_by_id(actions, str(item.get("action_id") or ""))
    if action is None:
        raise ValueError(f"Response action not found: {item.get('action_id')}")
    approval_config = normalize_response_approval(
        action.get("approval") or item.get("approval") or {},
        required=bool(action.get("approval_required", item.get("approval_required", False))),
        dangerous=bool(action.get("dangerous", False)),
    )
    approval_state = dict(item.get("approval") or build_approval_state(approval_config, actor=str(item.get("actor") or "system")))
    item["approval"] = record_rejection(approval_state, actor=actor, reason=reason)
    item["status"] = "rejected"
    item["error"] = str(reason)
    item["message"] = f"Rejected by {actor}: {reason}"
    item["rejected_by"] = actor
    item["rejected_ts"] = _now_iso()
    _save_response_execution_rows(rows, item)
    _record_response_ledger(
        action=action,
        execution=item,
        actor=actor,
        stage="rejected",
        status="rejected",
        details={"reason": reason},
    )
    append_audit_event(
        actor=actor,
        action="response_execution.rejected",
        object_type="response_execution",
        object_id=execution_id,
        summary=item.get("message") or execution_id,
        details={"action_id": item.get("action_id"), "reason": reason},
    )
    return _json_clone(item)


def retry_response_execution(execution_id: str, *, actor: str = "system") -> dict[str, Any]:
    item = _find_by_id(_collection("response_executions", _default_response_executions), execution_id)
    if item is None:
        raise ValueError(f"Execution not found: {execution_id}")
    if str(item.get("status") or "") not in RESPONSE_RETRYABLE_STATUSES:
        raise ValueError("Execution is not retryable")
    retry_payload = dict(item.get("payload") or {})
    details = dict(item.get("details") or {})
    resume_payload = dict(details.get("resume_payload") or {})
    retry_payload.update(resume_payload)
    _record_response_ledger(
        action={"id": str(item.get("action_id") or "")},
        execution=item,
        actor=actor,
        stage="retry_requested",
        status=str(item.get("status") or "unknown"),
        details={"resume_from_step": details.get("resume_from_step")},
    )
    return execute_response_action(
        str(item.get("action_id") or ""),
        actor=actor,
        payload=retry_payload,
        dry_run=bool(item.get("dry_run", False)),
    )


def replay_response_dlq(dlq_id: str, *, actor: str = "system") -> dict[str, Any]:
    rows = _collection("response_dlq", _default_response_dlq)
    entry = _find_by_id(rows, dlq_id)
    if entry is None:
        raise ValueError(f"Response DLQ entry not found: {dlq_id}")
    replay_payload = dict(entry.get("payload") or {})
    replay_payload.update(dict(entry.get("resume_payload") or {}))
    result = execute_response_action(
        str(entry.get("action_id") or ""),
        actor=actor,
        payload=replay_payload,
        dry_run=False,
    )
    entry["replayed_ts"] = _now_iso()
    entry["replayed_by"] = actor
    _save_response_dlq_rows(rows, entry)
    _record_response_ledger(
        action={"id": str(entry.get("action_id") or "")},
        execution=result.get("execution") if isinstance(result, dict) else None,
        actor=actor,
        stage="dlq_replayed",
        status=str((result.get("execution") or {}).get("status") if isinstance(result, dict) else "unknown"),
        details={"dlq_id": dlq_id, "source_execution_id": str(entry.get("execution_id") or "")},
    )
    append_audit_event(
        actor=actor,
        action="response_dlq.replayed",
        object_type="response_dlq",
        object_id=dlq_id,
        summary=str(entry.get("action_id") or dlq_id),
        details={"execution_id": str(entry.get("execution_id") or "")},
    )
    return result


def get_response_overview() -> dict[str, Any]:
    actions = list_response_actions()
    production_actions = _production_response_actions(actions)
    production_action_ids = {str(item.get("id") or "") for item in production_actions if str(item.get("id") or "").strip()}
    executions = [
        item
        for item in list_response_executions(limit=120)
        if not production_action_ids or not str(item.get("action_id") or "").strip() or str(item.get("action_id") or "") in production_action_ids
    ]
    dlq = list_response_dlq(limit=120)
    ledger = list_response_ledger(limit=120)
    status_counts = Counter(str(item.get("status") or "unknown") for item in executions)
    approval_queue = [item for item in executions if str(item.get("status") or "") == "awaiting_approval"]
    return {
        "actions": actions,
        "executions": executions[:20],
        "dlq": dlq[:20],
        "ledger": ledger[:30],
        "policy_packs": build_response_policy_packs(production_actions),
        "approval_queue": approval_queue[:20],
        "metrics": {
            "total_actions": len(production_actions),
            "catalog_total_actions": len(actions),
            "ignored_nonprod_actions": max(0, len(actions) - len(production_actions)),
            "enabled_actions": sum(1 for item in production_actions if item.get("enabled", True)),
            "pending_approvals": len(approval_queue),
            "runs_24h": sum(1 for item in executions if _parse_ts(str(item.get("created_ts") or "")) >= _now() - timedelta(hours=24)),
            "dlq_items": len(dlq),
            "linked_executions": sum(1 for item in executions if bool(item.get("linkage"))),
        },
        "breakdowns": {"execution_status": [{"label": label, "count": count} for label, count in status_counts.most_common()]},
    }


def get_response_analytics(*, limit: int = 200) -> dict[str, Any]:
    catalog_actions = list_response_actions()
    actions = _production_response_actions(catalog_actions)
    production_action_ids = {str(item.get("id") or "") for item in actions if str(item.get("id") or "").strip()}
    executions = [
        item
        for item in list_response_executions(limit=limit)
        if not production_action_ids or not str(item.get("action_id") or "").strip() or str(item.get("action_id") or "") in production_action_ids
    ]
    dlq = list_response_dlq(limit=limit)
    ledger = [
        item
        for item in list_response_ledger(limit=limit)
        if not production_action_ids or not str(item.get("action_id") or "").strip() or str(item.get("action_id") or "") in production_action_ids
    ]
    latencies = sorted(
        float(item.get("details", {}).get("latency_ms") or 0)
        for item in executions
        if isinstance(item.get("details"), dict) and item.get("details", {}).get("latency_ms") is not None
    )
    p95_latency = latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))] if latencies else 0.0
    kind_counts = Counter(str(item.get("kind") or "unknown") for item in actions)
    execution_status_counts = Counter(str(item.get("status") or "unknown") for item in executions)
    trigger_kind_counts = Counter(str((item.get("linkage") or {}).get("trigger_kind") or "manual") for item in executions)
    policy_pack_counts = Counter(str(item.get("policy_pack_id") or "unassigned") for item in actions)
    approval_mode_counts = Counter(str((item.get("approval") or {}).get("mode") or "single") for item in actions if bool((item.get("approval") or {}).get("required")))
    playbook_class_counts = Counter(str(item.get("playbook_class") or "workflow") for item in actions)
    step_status_counts = Counter(
        str(step.get("status") or "unknown")
        for item in executions
        for step in (dict(item.get("details") or {}).get("steps") or [])
        if isinstance(step, dict)
    )
    actions_total = len(actions)
    owned_actions = sum(1 for item in actions if list(item.get("owners") or []))
    evidence_contract_actions = sum(1 for item in actions if list(item.get("evidence_contract") or []))
    rollback_ready_actions = sum(1 for item in actions if list(item.get("rollback_contract") or []))
    compliance_ready_actions = sum(1 for item in actions if list(item.get("compliance_controls") or []))
    precondition_actions = sum(1 for item in actions if list(item.get("preconditions") or []))
    integration_target_actions = sum(1 for item in actions if list(item.get("integration_targets") or []))
    governed_actions = sum(1 for item in actions if list(item.get("owners") or []) and list(item.get("evidence_contract") or []) and list(item.get("compliance_controls") or []))
    compliance_catalog = {
        "SOC2": lambda control: control.startswith("SOC2"),
        "ISO27001": lambda control: control.startswith("ISO27001"),
        "NIST": lambda control: control.startswith("NIST"),
        "PCI-DSS": lambda control: control.startswith("PCI"),
    }
    compliance_families = []
    for family, matcher in compliance_catalog.items():
        covered = sum(1 for item in actions if any(matcher(str(control)) for control in (item.get("compliance_controls") or [])))
        compliance_families.append(
            {
                "family": family,
                "covered_actions": covered,
                "coverage_pct": round((covered / actions_total) * 100.0, 1) if actions_total else 0.0,
            }
        )
    return {
        "metrics": {
            "actions_total": actions_total,
            "catalog_actions_total": len(catalog_actions),
            "ignored_nonprod_actions": max(0, len(catalog_actions) - actions_total),
            "executions_total": len(executions),
            "dlq_total": len(dlq),
            "pending_approvals": sum(1 for item in executions if str(item.get("status") or "") == "awaiting_approval"),
            "partial_failures": sum(1 for item in executions if str(item.get("status") or "") == "partial_failure"),
            "linked_executions": sum(1 for item in executions if bool(item.get("linkage"))),
            "two_man_actions": sum(1 for item in actions if int((item.get("approval") or {}).get("min_approvers") or 0) >= 2),
            "success_rate": round((sum(1 for item in executions if str(item.get("status") or "") in RESPONSE_SUCCESS_STATUSES) / len(executions)) * 100.0, 1) if executions else 0.0,
            "p95_latency_ms": round(float(p95_latency), 1),
            "governed_actions": governed_actions,
            "owner_coverage_pct": round((owned_actions / actions_total) * 100.0, 1) if actions_total else 0.0,
            "evidence_contract_pct": round((evidence_contract_actions / actions_total) * 100.0, 1) if actions_total else 0.0,
            "rollback_ready_pct": round((rollback_ready_actions / actions_total) * 100.0, 1) if actions_total else 0.0,
            "compliance_coverage_pct": round((compliance_ready_actions / actions_total) * 100.0, 1) if actions_total else 0.0,
            "precondition_coverage_pct": round((precondition_actions / actions_total) * 100.0, 1) if actions_total else 0.0,
            "integration_target_pct": round((integration_target_actions / actions_total) * 100.0, 1) if actions_total else 0.0,
        },
        "breakdowns": {
            "action_kinds": [{"label": label, "count": count} for label, count in kind_counts.most_common()],
            "execution_status": [{"label": label, "count": count} for label, count in execution_status_counts.most_common()],
            "step_status": [{"label": label, "count": count} for label, count in step_status_counts.most_common()],
            "trigger_kinds": [{"label": label, "count": count} for label, count in trigger_kind_counts.most_common()],
            "policy_packs": [{"label": label, "count": count} for label, count in policy_pack_counts.most_common()],
            "approval_modes": [{"label": label, "count": count} for label, count in approval_mode_counts.most_common()],
            "playbook_classes": [{"label": label, "count": count} for label, count in playbook_class_counts.most_common()],
        },
        "recent_executions": executions[:20],
        "recent_dlq": dlq[:20],
        "recent_ledger": ledger[:25],
        "policy_packs": build_response_policy_packs(actions),
        "governance": {
            "owner_coverage_pct": round((owned_actions / actions_total) * 100.0, 1) if actions_total else 0.0,
            "evidence_contract_pct": round((evidence_contract_actions / actions_total) * 100.0, 1) if actions_total else 0.0,
            "rollback_ready_pct": round((rollback_ready_actions / actions_total) * 100.0, 1) if actions_total else 0.0,
            "compliance_coverage_pct": round((compliance_ready_actions / actions_total) * 100.0, 1) if actions_total else 0.0,
            "precondition_coverage_pct": round((precondition_actions / actions_total) * 100.0, 1) if actions_total else 0.0,
            "integration_target_pct": round((integration_target_actions / actions_total) * 100.0, 1) if actions_total else 0.0,
            "governed_actions": governed_actions,
            "next_actions": [
                "Increase owner coverage for manual actions.",
                "Bind missing evidence contracts to operator playbooks.",
                "Map remaining actions to compliance control families.",
            ],
        },
        "compliance": {
            "families": compliance_families,
            "actions_with_controls": compliance_ready_actions,
        },
        "playbook_library": [
            {
                "id": str(item.get("id") or ""),
                "title": str(item.get("title") or item.get("id") or ""),
                "policy_pack_id": str(item.get("policy_pack_id") or ""),
                "playbook_class": str(item.get("playbook_class") or "workflow"),
                "governance_tier": str(item.get("governance_tier") or "operator"),
                "approval_mode": str((item.get("approval") or {}).get("mode") or "none"),
                "compliance_controls": list(item.get("compliance_controls") or []),
                "preconditions": list(item.get("preconditions") or []),
                "integration_targets": list(item.get("integration_targets") or []),
                "operator_notes": str(item.get("operator_notes") or ""),
                "rollback_notes": str(item.get("rollback_notes") or ""),
            }
            for item in actions[:50]
        ],
    }


def delete_response_action(action_id: str, *, actor: str = "system") -> dict[str, Any]:
    safe_action_id = str(action_id or "").strip()
    if not safe_action_id:
        raise ValueError("Response action id is required")
    seed_ids = {str(item.get("id") or "") for item in _merged_default_response_actions()}
    if safe_action_id in seed_ids:
        raise ValueError("Built-in response actions cannot be deleted")
    rows = list_response_actions()
    existing = _find_by_id(rows, safe_action_id)
    if existing is None:
        raise ValueError(f"Response action not found: {safe_action_id}")
    _save_collection(
        "response_actions",
        [item for item in rows if str(item.get("id") or "") != safe_action_id],
    )
    _save_collection(
        "response_executions",
        [item for item in _collection("response_executions", _default_response_executions) if str(item.get("action_id") or "") != safe_action_id],
    )
    _save_collection(
        "response_dlq",
        [item for item in _collection("response_dlq", _default_response_dlq) if str(item.get("action_id") or "") != safe_action_id],
    )
    _save_collection(
        "response_ledger",
        [item for item in _collection("response_ledger", _default_response_ledger) if str(item.get("action_id") or "") != safe_action_id],
    )
    _save_collection(
        "response_idempotency",
        [item for item in _collection("response_idempotency", _default_response_idempotency) if str(item.get("action_id") or "") != safe_action_id],
    )
    append_audit_event(
        actor=str(actor or "system"),
        action="response_action.deleted",
        object_type="response_action",
        object_id=safe_action_id,
        summary=str(existing.get("title") or safe_action_id),
        details={"kind": str(existing.get("kind") or ""), "policy_pack_id": str(existing.get("policy_pack_id") or "")},
    )
    return {"status": "deleted", "id": safe_action_id}
