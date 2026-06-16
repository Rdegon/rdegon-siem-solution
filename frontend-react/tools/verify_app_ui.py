from __future__ import annotations

import argparse
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from playwright.async_api import Page, Route, async_playwright


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_DIR = ROOT / ".artifacts" / "browser"


BOOTSTRAP = {
    "user": {
        "username": "operator",
        "role": "admin",
        "permissions": [
            "auth:view",
            "response:view",
            "health:view",
            "sources:view",
            "assets:view",
            "events:view",
            "incidents:view",
            "vuln:view",
            "builders:view",
            "docs:view",
        ],
        "principal_type": "user",
        "service_account_id": "",
        "auth_mechanism": "oidc",
        "issuer": "http://vm4-keycloak.test/realms/siem",
        "groups": ["siem-admins", "soc-core"],
        "break_glass": False,
        "session_expires_ts": "2026-03-27T06:00:00Z",
    },
    "ui_lang": "en",
    "theme": "dark",
    "labels": {},
}


def runtime_blob(**values: Any) -> dict[str, Any]:
    return values


def dashboard_registry() -> dict[str, Any]:
    return {
        "dashboards": [
            {
                "id": "soc-overview",
                "title": "SOC Overview",
                "description": "Primary operating surface",
                "layout": [
                    {"widget": "kpis", "span": 2},
                    {"widget": "timelines"},
                    {"widget": "severity_breakdown"},
                ],
            }
        ]
    }


def dashboard_summary() -> dict[str, Any]:
    return {
        "timeline_window": {
            "window": "24h",
            "bucket_minutes": 60,
            "from_ts": "2026-03-26T00:00:00Z",
            "to_ts": "2026-03-27T00:00:00Z",
        },
        "metrics": {
            "events_1h": 12840,
            "open_incidents_24h": 7,
            "ti_hits_24h": 12,
            "active_sources_24h": 28,
        },
        "timeline": [
            {"bucket": "2026-03-26T21:00:00Z", "count": 3120},
            {"bucket": "2026-03-26T22:00:00Z", "count": 4020},
            {"bucket": "2026-03-26T23:00:00Z", "count": 5700},
        ],
        "alert_timeline": [
            {"bucket": "2026-03-26T21:00:00Z", "count": 8},
            {"bucket": "2026-03-26T22:00:00Z", "count": 11},
            {"bucket": "2026-03-26T23:00:00Z", "count": 14},
        ],
        "severity_breakdown": [
            {"label": "critical", "count": 4},
            {"label": "high", "count": 11},
            {"label": "medium", "count": 26},
            {"label": "low", "count": 38},
        ],
        "alert_severity_breakdown": [
            {"label": "critical", "count": 2},
            {"label": "high", "count": 6},
            {"label": "medium", "count": 10},
        ],
        "alert_status_breakdown": [
            {"label": "new", "count": 6},
            {"label": "triaged", "count": 7},
            {"label": "contained", "count": 5},
        ],
        "recent_alerts": [
            {"id": "al-1", "rule_name": "Kerberos abuse", "severity": "critical", "source_name": "dc-01", "created_ts": "2026-03-26T23:43:00Z"},
            {"id": "al-2", "rule_name": "North-south beacon", "severity": "high", "source_name": "vpn-gw", "created_ts": "2026-03-26T23:45:00Z"},
        ],
        "top_sources": [
            {"source_name": "dc-01", "event_count": 5820},
            {"source_name": "edge-fw-01", "event_count": 4410},
            {"source_name": "vuln-mgr-01", "event_count": 2012},
        ],
        "collectors": [{"collector_name": "collector-a", "healthy": True, "source_count": 12}],
        "geo_sources": {"items": [{"country": "Germany", "country_code": "DE", "events": 81, "domain": "scanner.example", "ip": "203.0.113.5", "last_seen": "2026-03-26T23:20:00Z"}]},
        "geo_vpn_destinations": {"items": [{"country": "Netherlands", "country_code": "NL", "visits": 32, "domain": "updates.vendor", "ip": "198.51.100.19", "last_seen": "2026-03-26T23:10:00Z"}]},
        "dashboard_cards": [],
    }


def events_response() -> dict[str, Any]:
    rows = [
        {
            "event_id": "evt-1001",
            "ts": "2026-03-26T23:54:00Z",
            "log_source": "dc-01",
            "collector_profile": "windows-security-http",
            "severity": "high",
            "category": "auth",
            "subcategory": "kerberos",
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.11",
            "dst_port": 88,
            "user_name": "svc_backup",
            "target_user": "krbtgt",
            "asset_id": "asset-dc-01",
            "device_product": "windows-event-log",
            "process_name": "lsass.exe",
            "ti_indicator": "golden-ticket",
            "message": "Subject:\nAccount name: svc_backup\nAccount domain: CORP\nService:\nService name: krbtgt\nClient address: 192.168.1.10",
            "normalized_json": {
                "host_name": "dc-01",
                "collector_profile": "windows-security-http",
                "severity": "high",
                "user_name": "svc_backup",
                "asset_id": "asset-dc-01",
                "message": "Kerberos service ticket requested for admin account",
                "process_name": "lsass.exe",
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.11",
                "dst_port": 88,
            },
        },
        {
            "event_id": "evt-1002",
            "ts": "2026-03-26T23:57:00Z",
            "log_source": "edge-fw-01",
            "collector_profile": "network-syslog-http",
            "severity": "medium",
            "category": "network",
            "subcategory": "egress",
            "src_ip": "192.168.1.117",
            "dst_ip": "198.51.100.7",
            "dst_port": 443,
            "user_name": "host-17",
            "asset_id": "asset-ws-17",
            "device_product": "cisco-ios",
            "message": "Connection:\nDestination IP: 198.51.100.7\nDestination port: 443\nASN: 64510",
            "normalized_json": {
                "host_name": "edge-fw-01",
                "collector_profile": "network-syslog-http",
                "severity": "medium",
                "message": "Outbound session to rare ASN",
                "src_ip": "192.168.1.117",
                "dst_ip": "198.51.100.7",
                "dst_port": 443,
            },
        },
    ]
    return {
        "rows": rows,
        "row_count": len(rows),
        "total_count": len(rows),
        "page": 1,
        "total_pages": 1,
        "offset": 0,
        "elapsed_ms": 34,
        "from_ts": "2026-03-26T00:00:00Z",
        "to_ts": "2026-03-27T00:00:00Z",
        "base_sql": "SELECT ts, log_source, severity, category, src_ip, dst_ip, user_name, message FROM events_view ORDER BY ts DESC LIMIT 100",
        "severity_stats": [
            {"label": "high", "count": 1},
            {"label": "medium", "count": 1},
        ],
        "histogram": [
            {"bucket": "2026-03-26T22:00:00Z", "count": 18},
            {"bucket": "2026-03-26T23:00:00Z", "count": 24},
        ],
    }


def incidents_response() -> dict[str, Any]:
    items = [
        {
            "agg_id": "agg-1",
            "title": "Kerberos abuse on dc-01",
            "severity": "critical",
            "severity_agg": "critical",
            "status": "open",
            "assignee": "analyst-1",
            "ts_first": "2026-03-26T22:41:00Z",
            "ts_last": "2026-03-26T23:41:00Z",
            "source_summary": "dc-01",
            "entity_key": "host:dc-01",
            "raw_hits_total": 3,
            "summary": "Potential ticket forgery and privileged abuse.",
            "context": {
                "source_name": "dc-01",
                "asset_id": "asset-dc-01",
                "user_name": "svc_backup",
                "ti_hits": 1,
            },
            "samples": [
                {"event_id": "evt-1001", "message": "Kerberos service ticket requested", "source_name": "dc-01"},
            ],
        },
        {
            "agg_id": "agg-2",
            "title": "Rare beacon from host-17",
            "severity": "high",
            "severity_agg": "high",
            "status": "investigating",
            "assignee": "analyst-2",
            "ts_first": "2026-03-26T21:15:00Z",
            "ts_last": "2026-03-26T23:00:00Z",
            "source_summary": "edge-fw-01",
            "entity_key": "host:ws-17",
            "raw_hits_total": 2,
            "summary": "Outbound session to suspicious ASN.",
            "context": {
                "source_name": "edge-fw-01",
                "asset_id": "asset-ws-17",
                "dst_ip": "198.51.100.7",
            },
            "samples": [
                {"event_id": "evt-1002", "message": "Outbound session to rare ASN", "source_name": "edge-fw-01"},
            ],
        },
    ]
    return {
        "view": "agg",
        "scope": "main",
        "items": items,
        "metrics": {
            "agg_total": len(items),
            "agg_open": 2,
            "raw_total": 5,
            "critical_raw": 1,
        },
        "status_transitions": {
            "new": ["open", "investigating", "closed"],
            "open": ["investigating", "contained", "closed"],
            "investigating": ["contained", "closed"],
            "contained": ["closed"],
            "closed": [],
        },
    }


def incident_detail(record_id: str) -> dict[str, Any]:
    items = {item["agg_id"]: item for item in incidents_response()["items"]}
    selected = items.get(record_id, next(iter(items.values())))
    return {
        "view": "agg",
        "item": {
            **selected,
            "summary": "Readable summary rendered for investigation.",
            "freshest_sample": {"event_id": "evt-1001", "source_name": "dc-01", "message": "Kerberos service ticket requested"},
        },
        "history": [{"changed_ts": "2026-03-26T23:20:00Z", "changed_by": "analyst-1", "previous_status": "new", "next_status": "open", "note": "Assigned"}],
        "status_transitions": incidents_response()["status_transitions"],
    }


def sources_inventory() -> dict[str, Any]:
    items = [
        {
            "source_name": "dc-01",
            "source_type": "windows",
            "status": "active",
            "collector_name": "collector-a",
            "products": ["windows event log"],
            "services": ["ad"],
            "categories": ["auth", "process"],
            "auth_events": 5520,
            "audit_events": 2110,
            "notable_events": 12,
            "last_seen": "2026-03-26T23:59:00Z",
        },
        {
            "source_name": "vuln-mgr-01",
            "source_type": "greenbone",
            "status": "warning",
            "collector_name": "collector-b",
            "products": ["greenbone"],
            "services": ["scanner"],
            "categories": ["vulnerability"],
            "auth_events": 0,
            "audit_events": 0,
            "notable_events": 3,
            "last_seen": "2026-03-26T23:52:00Z",
        },
    ]
    return {"items": items, "metrics": {"active": 1, "warning": 1}}


def integrations_catalog() -> dict[str, Any]:
    return {
        "items": [
            {"id": "windows-agent", "family": "source", "group": "endpoint", "mode": "push", "title": "Windows native agent", "description": "Signed package for Windows onboarding.", "block_type": "source", "protocols": ["https"], "stage": "ingest"},
            {"id": "ssh-config-push", "family": "source", "group": "network", "mode": "runtime", "title": "SSH config push", "description": "Dry-run and execute config push for supported vendors.", "block_type": "rest_pull", "protocols": ["ssh"], "stage": "ingest"},
            {"id": "greenbone", "family": "source", "group": "vulnerability", "mode": "pull", "title": "Greenbone", "description": "Structured import from the vulnerability manager.", "block_type": "rest_pull", "protocols": ["https"], "stage": "ingest"},
            {"id": "webhook-source", "family": "source", "group": "general", "mode": "runtime", "title": "Webhook source", "description": "Inbound webhook collector template.", "block_type": "webhook_source", "protocols": ["https"], "stage": "ingest"},
            {"id": "telegram-action", "family": "action", "group": "notification", "mode": "runtime", "title": "Telegram action", "description": "Outbound analyst notification template.", "block_type": "telegram_output", "protocols": ["https"], "stage": "publish"},
        ]
    }


def asset_catalog() -> dict[str, Any]:
    return {
        "detection_rules": [{"id": "rule-1", "title": "Kerberos abuse"}],
        "normalizers": [{"id": "norm-1", "title": "Windows auth normalizer"}],
        "active_lists": [{"id": "list-1", "title": "Rare ASN watchlist"}],
        "threat_intel": [{"id": "ti-1", "title": "Malicious ASN feed"}],
    }


def builder_drafts() -> dict[str, Any]:
    return {
        "items": [
            {
                "id": "draft-1",
                "title": "Kerberos lateral movement detector",
                "description": "Graph for Windows auth, TI lookup and incident promotion.",
                "kind": "detection",
                "status": "ready",
                "version": 3,
                "updated_ts": "2026-03-26T23:40:00Z",
                "published_ts": "2026-03-26T23:10:00Z",
                "blocks": [
                    {"id": "b-1", "type": "source", "stage": "ingest", "label": "Windows auth stream", "config": {"links_to": ["b-2"]}},
                    {"id": "b-2", "type": "normalizer", "stage": "parse", "label": "Auth normalizer", "config": {"links_to": ["b-3"]}},
                    {"id": "b-3", "type": "ti_lookup", "stage": "enrich", "label": "Reputation lookup", "config": {"links_to": ["b-4"]}},
                    {"id": "b-4", "type": "detection", "stage": "detect", "label": "Kerberos anomaly", "config": {"links_to": ["b-5"]}},
                    {"id": "b-5", "type": "incident", "stage": "incident", "label": "Incident projection", "config": {"links_to": ["b-6"]}},
                    {"id": "b-6", "type": "publish", "stage": "publish", "label": "Runtime publish", "config": {"links_to": []}},
                ],
                "history": [
                    {"ts": "2026-03-26T23:10:00Z", "action": "published", "version": 2, "status": "published"},
                    {"ts": "2026-03-26T23:40:00Z", "action": "edited", "version": 3, "status": "ready"},
                ],
            }
        ]
    }


def source_discovery() -> dict[str, Any]:
    items = [
        {
            "id": "cand-win-01",
            "hostname": "ws-17",
            "ip": "192.168.1.117",
            "platform": "windows",
            "vendor": "microsoft",
            "connected": False,
            "candidate_type": "windows_native_agent",
            "recommended_action": "Deploy native package",
            "windows_package": {"name": "windows-agent-ws-17.zip", "size": 14321},
            "binding_target": "asset-ws-17",
            "binding_override": None,
            "dry_run": {"commands": ["install-service", "set-api-endpoint"]},
            "artifact_manifest": [{"name": "windows-agent-ws-17.zip", "kind": "package"}],
            "last_job_id": "job-1",
        },
        {
            "id": "cand-net-01",
            "hostname": "edge-sw-01",
            "ip": "192.168.1.40",
            "platform": "network",
            "vendor": "cisco_ios",
            "connected": False,
            "candidate_type": "network_ssh_push",
            "recommended_action": "Dry-run config push",
            "binding_target": "asset-edge-sw-01",
            "binding_override": {"id": "ovr-1", "target": "asset-edge-sw-01", "note": "Matched via inventory alias"},
            "dry_run": {"commands": ["show running-config", "push telemetry config"]},
            "artifact_manifest": [{"name": "edge-sw-01.cfg", "kind": "network-config"}],
            "last_job_id": "job-2",
        },
    ]
    jobs = [
        {"id": "job-1", "status": "prepared", "kind": "windows_package", "started_ts": "2026-03-26T23:20:00Z", "transcript": ["package staged"], "artifacts": [{"name": "windows-agent-ws-17.zip"}]},
        {"id": "job-2", "status": "dry_run", "kind": "network_push", "started_ts": "2026-03-26T23:22:00Z", "transcript": ["connection ok", "config diff ready"], "artifacts": [{"name": "edge-sw-01.cfg"}]},
    ]
    return {
        "items": items,
        "jobs": jobs,
        "metrics": {
            "total": 2,
            "connected": 0,
            "pending": 2,
            "windows_packages": 1,
            "network_candidates": 1,
            "binding_overrides_total": 1,
            "binding_overrides_applied": 1,
            "unmanaged_without_override": 1,
        },
    }


def vuln_runtime() -> dict[str, Any]:
    return {
        "healthy": True,
        "structured_reports": 42,
        "latest_report_ts": "2026-03-26T23:18:00Z",
        "ready_for_incident_policies": True,
    }


def vuln_maturity() -> dict[str, Any]:
    return {
        "healthy": True,
        "ready_for_incident_policies": True,
        "critical_open": 3,
        "unmapped_targets_total": 2,
        "binding_overrides_total": 1,
        "binding_overrides_active": 1,
        "critical_queue": [
            {"finding_id": "finding-1", "asset_name": "dc-01", "severity": "critical", "title": "SMB Signing Disabled"},
            {"finding_id": "finding-2", "asset_name": "vpn-gw", "severity": "critical", "title": "CVE-2026-1122"},
        ],
        "unmapped_targets": [
            {"finding_id": "finding-3", "target": "ws-17.corp.local", "hostname": "ws-17", "ip": "192.168.1.117", "severity": "high", "suggested_asset_id": "asset-ws-17"},
            {"finding_id": "finding-4", "target": "edge-sw-01", "hostname": "edge-sw-01", "ip": "192.168.1.40", "severity": "medium", "suggested_asset_id": "asset-edge-sw-01"},
        ],
        "quick_actions": [{"id": "apply-policies", "label": "Apply policies"}],
    }


def vuln_overview() -> dict[str, Any]:
    return {
        "summary": {"open_findings": 18, "critical_open": 3, "reports": 42},
        "critical_queue": [
            {"finding_id": "finding-1", "asset_name": "dc-01", "severity": "critical", "title": "SMB Signing Disabled"},
            {"finding_id": "finding-2", "asset_name": "vpn-gw", "severity": "critical", "title": "CVE-2026-1122"},
        ],
        "top_exposure": [{"label": "dc-01", "count": 6}, {"label": "vpn-gw", "count": 4}],
        "reports": [{"report_id": "rep-1", "title": "Nightly scanner sync", "created_ts": "2026-03-26T23:18:00Z"}],
    }


def auth_governance() -> dict[str, Any]:
    return {
        "vault": runtime_blob(healthy=True, ready=True),
        "break_glass": runtime_blob(metrics=runtime_blob(active=0), items=[]),
        "secrets": runtime_blob(
            summary=runtime_blob(vault_backed=14, required_missing=0),
            items=[
                runtime_blob(name="jwt-signing", ref="vault://kv/siem/jwt", required=True, resolved=True),
                runtime_blob(name="smtp", ref="vault://kv/siem/smtp", required=False, resolved=True),
            ],
        ),
    }


def auth_providers() -> dict[str, Any]:
    return {
        "items": [
            {"id": "oidc-enterprise", "title": "Enterprise SSO", "issuer": "http://vm4-keycloak.test/realms/siem", "kind": "oidc", "enabled": True, "healthy": True, "issues": []},
            {"id": "break-glass", "title": "Break-glass", "issuer": "", "kind": "local", "enabled": True, "healthy": True, "issues": []},
        ]
    }


def auth_permissions() -> dict[str, Any]:
    bundles = [
        {"id": "admin", "title": "Admin", "permissions": ["auth:view", "auth:write", "response:view"]},
        {"id": "analyst", "title": "Analyst", "permissions": ["events:view", "incidents:view", "vuln:view"]},
    ]
    return {"permission_bundles": bundles, "permission_categories": [{"id": "core", "title": "Core"}]}


def local_users() -> dict[str, Any]:
    return {
        "items": [{"username": "recovery-admin", "role": "admin", "enabled": True, "permission_bundles": ["admin"]}],
        "permission_bundles": auth_permissions()["permission_bundles"],
        "permission_categories": auth_permissions()["permission_categories"],
        "metrics": {"active": 1},
    }


def local_user_detail(username: str) -> dict[str, Any]:
    return {"item": {"username": username, "role": "admin", "enabled": True, "permission_bundles": ["admin"]}}


def break_glass() -> dict[str, Any]:
    return {"items": [], "metrics": {"active": 0}}


def service_accounts() -> dict[str, Any]:
    return {
        "items": [
            {"id": "svc-greenbone", "name": "Greenbone bridge", "description": "Structured vulnerability sync", "enabled": True, "permission_bundles": ["admin"]},
            {"id": "svc-netpush", "name": "Network push", "description": "SSH onboarding automation", "enabled": True, "permission_bundles": ["admin"]},
        ],
        "permission_bundles": auth_permissions()["permission_bundles"],
        "permission_categories": auth_permissions()["permission_categories"],
        "metrics": {"active_tokens": 2, "tokens_expiring_14d": 0},
    }


def service_account_detail(service_account_id: str) -> dict[str, Any]:
    return {
        "item": {"id": service_account_id, "name": service_account_id, "description": "Machine identity", "enabled": True, "permission_bundles": ["admin"]},
        "tokens": [{"id": "tok-1", "title": "active", "expires_ts": "2026-06-01T00:00:00Z", "active": True}],
    }


def keycloak_status() -> dict[str, Any]:
    return {
        "healthy": True,
        "admin_ready": True,
        "base_url": "http://vm4-keycloak.test",
        "realm": "siem",
        "inventory": {"users": 18, "groups": 5, "roles": 4, "clients": 6},
    }


def keycloak_users(search: str = "") -> dict[str, Any]:
    items = [
        {
            "id": "u-1",
            "username": "alice",
            "email": "alice@example.test",
            "first_name": "Alice",
            "last_name": "Warden",
            "enabled": True,
            "email_verified": True,
            "created_ts": "2026-03-01T00:00:00Z",
            "groups": [{"id": "g-1", "name": "siem-admins"}],
            "roles": [{"name": "siem-admin"}],
        },
        {
            "id": "u-2",
            "username": "bob",
            "email": "bob@example.test",
            "first_name": "Bob",
            "last_name": "Hunter",
            "enabled": False,
            "email_verified": False,
            "created_ts": "2026-03-03T00:00:00Z",
            "groups": [{"id": "g-2", "name": "soc-core"}],
            "roles": [{"name": "siem-analyst"}],
        },
    ]
    if search:
        lowered = search.lower()
        items = [item for item in items if lowered in item["username"].lower() or lowered in item["email"].lower()]
    return {"items": items, "total": len(items), "returned": len(items)}


def keycloak_user_detail(user_id: str) -> dict[str, Any]:
    item = keycloak_users()["items"][0 if user_id == "u-1" else 1]
    item = {**item, "sessions": [{"id": "sess-1", "ip_address": "192.168.1.44", "started_ts": "2026-03-26T22:00:00Z"}]}
    return {"item": item}


def keycloak_groups() -> dict[str, Any]:
    return {"items": [{"id": "g-1", "name": "siem-admins", "path": "/siem-admins", "sub_group_count": 0}, {"id": "g-2", "name": "soc-core", "path": "/soc-core", "sub_group_count": 0}]}


def keycloak_roles() -> dict[str, Any]:
    return {"items": [{"name": "siem-admin", "description": "Full admin"}, {"name": "siem-analyst", "description": "Analyst role"}]}


def keycloak_clients() -> dict[str, Any]:
    return {"items": [{"id": "c-1", "client_id": "siem-web", "name": "SIEM Web", "enabled": True, "service_accounts_enabled": False, "public_client": False}, {"id": "c-2", "client_id": "siem-keycloak-admin", "name": "Admin automation", "enabled": True, "service_accounts_enabled": True, "public_client": False}]}


def keycloak_client_detail(client_id: str) -> dict[str, Any]:
    item = next((item for item in keycloak_clients()["items"] if item["client_id"] == client_id or item["id"] == client_id), keycloak_clients()["items"][0])
    detail = {**item, "description": "Managed by SIEM control center", "redirect_uris": ["http://localhost:4174/app/*"], "web_origins": ["http://localhost:4174"], "root_url": "http://localhost:4174/app", "base_url": "/app"}
    return {"item": detail}


def certification_health() -> dict[str, Any]:
    return {"healthy": True, "latest_certified_ceiling_eps": 79, "budgets": {"ingest_p95_ms": 22000}}


def platform_status() -> dict[str, Any]:
    return {"clickhouse_ok": True, "clickhouse_runtime": {"healthy": True}}


def asset_binding_overrides() -> dict[str, Any]:
    return {
        "items": [
            {"id": "ovr-1", "scope": "vulnerability", "target": "asset-edge-sw-01", "hostname": "edge-sw-01", "ip": "192.168.1.40", "enabled": True, "note": "Matched via inventory alias"}
        ]
    }


def event_saved_searches() -> dict[str, Any]:
    return {"items": []}


def response_actions() -> dict[str, Any]:
    return {"items": [], "policies": [], "summary": {}}


def route_json(path: str, query: dict[str, list[str]]) -> dict[str, Any]:
    if path == "/api/ui/bootstrap":
        return BOOTSTRAP
    if path == "/api/platform/status":
        return platform_status()
    if path == "/api/dashboards":
        return dashboard_registry()
    if path == "/api/dashboard/summary":
        return dashboard_summary()
    if path == "/api/events/query":
        return events_response()
    if path == "/api/search/saved":
        return event_saved_searches()
    if path == "/api/incidents":
        return incidents_response()
    if path.startswith("/api/incidents/"):
        return incident_detail(path.rsplit("/", 1)[-1])
    if path == "/api/assets/catalog":
        return asset_catalog()
    if path == "/api/sources":
        return sources_inventory()
    if path == "/api/sources/discovery":
        return source_discovery()
    if path == "/api/integrations/catalog":
        return integrations_catalog()
    if path == "/api/builders/drafts":
        return builder_drafts()
    if path == "/api/vuln/overview":
        return vuln_overview()
    if path == "/api/vuln/runtime":
        return vuln_runtime()
    if path == "/api/vuln/maturity":
        return vuln_maturity()
    if path == "/api/auth/governance":
        return auth_governance()
    if path == "/api/auth/providers":
        return auth_providers()
    if path == "/api/auth/permissions":
        return auth_permissions()
    if path == "/api/auth/users":
        return local_users()
    if path.startswith("/api/auth/users/"):
        return local_user_detail(path.rsplit("/", 1)[-1])
    if path == "/api/auth/break-glass":
        return break_glass()
    if path == "/api/auth/service-accounts":
        return service_accounts()
    if path.startswith("/api/auth/service-accounts/"):
        return service_account_detail(path.split("/")[4])
    if path == "/api/auth/keycloak/status":
        return keycloak_status()
    if path == "/api/auth/keycloak/users":
        return keycloak_users((query.get("search") or [""])[0])
    if path.startswith("/api/auth/keycloak/users/"):
        return keycloak_user_detail(path.split("/")[5])
    if path == "/api/auth/keycloak/groups":
        return keycloak_groups()
    if path == "/api/auth/keycloak/roles":
        return keycloak_roles()
    if path == "/api/auth/keycloak/clients":
        return keycloak_clients()
    if path.startswith("/api/auth/keycloak/clients/"):
        return keycloak_client_detail(path.split("/")[5])
    if path == "/api/health/certification":
        return certification_health()
    if path == "/api/assets/binding-overrides":
        return asset_binding_overrides()
    if path == "/api/response/actions":
        return response_actions()
    if path.startswith("/api/geo/"):
        return {"items": []}
    if path == "/api/docs/index":
        return {"items": []}
    return {}


async def handle_route(route: Route) -> None:
    parsed = urlparse(route.request.url)
    path = parsed.path
    query = parse_qs(parsed.query)
    if path.startswith("/api/"):
        payload = route_json(path, query)
        status = 200
        method = route.request.method
        if method in {"POST", "DELETE"} and path.startswith("/api/"):
            body = {"ok": True, **payload}
            if path.endswith("/secret/rotate"):
                body = {"client_id": "siem-keycloak-admin", "secret": "rotated-secret-value"}
            await route.fulfill(status=status, content_type="application/json", body=json.dumps(body))
            return
        await route.fulfill(status=status, content_type="application/json", body=json.dumps(payload))
        return
    await route.continue_()


async def verify_shell_toggle(page: Page) -> None:
    shell_toggle = page.get_by_role("button", name="Hide").first
    await shell_toggle.wait_for()
    await shell_toggle.click()
    await page.get_by_role("button", name="Show").first.wait_for()
    await page.get_by_role("button", name="Show").first.click()
    await page.get_by_role("button", name="Hide").first.wait_for()


async def login_break_glass(page: Page, base_url: str, username: str, password: str, reason: str) -> None:
    await page.goto(f"{base_url}/auth/login", wait_until="networkidle")
    await page.get_by_label("Username").fill(username)
    await page.get_by_label("Password").fill(password)
    await page.locator("#break_glass_reason").fill(reason)
    await page.get_by_role("button", name="Open break-glass session").click()
    await page.wait_for_url(lambda url: "/app" in str(url), wait_until="networkidle")


async def login_oidc(page: Page, base_url: str, username: str, password: str) -> None:
    await page.goto(f"{base_url}/auth/oidc/start", wait_until="domcontentloaded")
    await page.wait_for_url(
        lambda url: ":8081" in str(url) or "/realms/" in str(url) or "openid-connect" in str(url),
        wait_until="domcontentloaded",
    )
    await page.wait_for_selector("#username")
    await page.locator("#username").fill(username)
    await page.locator("#password").fill(password)
    await page.locator("#kc-login").click()
    await page.wait_for_url(lambda url: "/app" in str(url), wait_until="networkidle")


async def verify(
    base_url: str,
    *,
    live: bool = False,
    username: str = "",
    password: str = "",
    break_glass_reason: str = "",
    auth_mode: str = "break-glass",
) -> None:
    artifact_dir = ARTIFACT_DIR / ("live-audit" if live else "mock-audit")
    artifact_dir.mkdir(parents=True, exist_ok=True)
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        page = await browser.new_page(viewport={"width": 1600, "height": 1100}, ignore_https_errors=live)
        page_errors: list[str] = []
        page_404s: list[str] = []
        completed_checks: list[dict[str, str]] = []

        page.on("pageerror", lambda error: page_errors.append(str(error)))
        page.on("console", lambda message: page_errors.append(message.text) if message.type == "error" else None)
        page.on("response", lambda response: page_404s.append(response.url) if response.status == 404 else None)
        if not live:
            await page.route("**/*", handle_route)
        else:
            if not username or not password:
                raise AssertionError("live mode requires username and password")
            if auth_mode == "oidc":
                await login_oidc(page, base_url, username, password)
            else:
                await login_break_glass(page, base_url, username, password, break_glass_reason or "Live UI audit")
            await page.screenshot(path=str(artifact_dir / "login-success.png"), full_page=True)

        checks = [
            ("/app/", "overview", "Operating lane"),
            ("/app/events", "events", "Result set"),
            ("/app/incidents", "incidents", "Incident queue"),
            ("/app/sources?view=discovery", "sources", "LAN discovery and onboarding"),
            ("/app/vuln", "vuln", "Unmapped target queue"),
            ("/app/builders", "builders", "Content-plane block editor"),
            ("/app/access?tab=keycloak-users", "access-users", "Keycloak users"),
            ("/app/access?tab=keycloak-clients", "access-clients", "Clients"),
        ]
        if live:
            checks.extend(
                [
                    ("/app/entities", "entities", "Entity register"),
                    ("/app/assets", "assets", "Asset investigation model"),
                    ("/app/threat-intel", "threat-intel", "Indicator catalog"),
                ]
            )

        for path, slug, marker in checks:
            await page.goto(f"{base_url}{path}", wait_until="networkidle")
            if path == "/app/":
                await verify_shell_toggle(page)
            if path == "/app/events":
                event_rows = page.locator("table[aria-label='Event result set'] tbody tr").filter(has_not=page.locator(".react-table-spacer"))
                if await event_rows.count():
                    await event_rows.first.click()
                    await page.get_by_text("Event details").wait_for()
            if path == "/app/incidents":
                incident_rows = page.locator("table.react-table tbody tr")
                if await incident_rows.count():
                    await incident_rows.first.click()
                    await page.get_by_text("Incident details").wait_for()
            if path == "/app/entities":
                entity_buttons = page.locator(".react-card.react-card-button")
                if await entity_buttons.count():
                    await entity_buttons.first.click()
                    await page.get_by_text("Entity profile").wait_for()
            if path == "/app/assets":
                asset_rows = page.locator("table.react-table tbody tr")
                if await asset_rows.count():
                    await asset_rows.first.click()
                    await page.get_by_text("Asset investigation model").wait_for()
            if path == "/app/threat-intel":
                intel_rows = page.locator("table.react-table tbody tr")
                if await intel_rows.count():
                    action = intel_rows.first.locator("button.react-inline-action").first
                    if await action.count():
                        await action.click()
                        await page.get_by_text("Threat-intel entries").wait_for()
            await page.screenshot(path=str(artifact_dir / f"{slug}.png"), full_page=True)
            await page.locator("body").wait_for()
            body = await page.text_content("body")
            if body is None or marker not in body:
                raise AssertionError(f"Expected marker '{marker}' on {path}")
            if "React shell runtime error" in body or "Unable to bootstrap UI" in body:
                raise AssertionError(f"Bootstrap failure on {path}")
            completed_checks.append({"path": path, "artifact": f"{slug}.png", "marker": marker})

        favicon_href = await page.evaluate(
            """() => document.querySelector('link[rel="icon"]')?.getAttribute('href') || ''"""
        )
        if "/favicon." not in str(favicon_href):
            raise AssertionError("favicon is not wired into /app shell")

        if page_errors:
            filtered = [item for item in page_errors if "favicon" not in item.lower()]
            if filtered:
                raise AssertionError(f"Browser errors detected: {filtered[:5]} 404s={page_404s[:10]}")
        if page_404s:
            raise AssertionError(f"404 resources detected: {page_404s[:10]}")

        results = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "mode": "live" if live else "mock",
            "base_url": base_url,
            "checks": completed_checks,
            "console_errors": page_errors,
            "resource_404s": page_404s,
            "artifact_dir": str(artifact_dir),
        }
        (artifact_dir / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")

        await browser.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify built /app shell with Playwright and mocked API responses.")
    parser.add_argument("--base-url", default="http://127.0.0.1:4174")
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--username", default="")
    parser.add_argument("--password", default="")
    parser.add_argument("--break-glass-reason", default="Live UI audit")
    parser.add_argument("--auth-mode", choices=["break-glass", "oidc"], default="break-glass")
    args = parser.parse_args()
    asyncio.run(
        verify(
            args.base_url,
            live=args.live,
            username=args.username,
            password=args.password,
            break_glass_reason=args.break_glass_reason,
            auth_mode=args.auth_mode,
        )
    )


if __name__ == "__main__":
    main()
