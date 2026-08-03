from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any

from .content_store import load_list, save_list
from .control_plane_governance_runtime import append_audit_event
from .tenant_scope_runtime import validate_tenant_scope_header

RESOURCE_KINDS = {
    "collector",
    "correlator",
    "storage",
    "agent",
    "proxy",
    "correlationRule",
    "aggregationRule",
    "normalizer",
    "filter",
    "connector",
    "destination",
    "enrichmentRule",
    "activeList",
    "dictionary",
    "contextTable",
    "search",
    "secret",
    "segmentationRule",
    "emailTemplate",
    "eventRouter",
    "responseRule",
}
RESOURCE_FILE = Path(os.getenv("SIEM_RESOURCE_CATALOG_FILE", "/opt/siem/runtime-docs/platform_resources.json"))
RUNTIME_RESOURCE_FILE = Path(
    os.getenv("SIEM_RESOURCE_RUNTIME_FILE", "/opt/siem/runtime-docs/platform_resource_runtime.json")
)
_RESOURCE_ID_PATTERN = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}")
RESOURCE_MUTATION_LOCK = RLock()


def _deps():
    from . import deps

    return deps


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _slug(value: str) -> str:
    result = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")
    return result[:96]


def _stored_resources() -> list[dict[str, Any]]:
    RESOURCE_FILE.parent.mkdir(parents=True, exist_ok=True)
    return load_list("platform_resources", RESOURCE_FILE, [])


def _save_resources(rows: list[dict[str, Any]]) -> None:
    save_list("platform_resources", RESOURCE_FILE, rows)


def _runtime_registry() -> list[dict[str, Any]]:
    RUNTIME_RESOURCE_FILE.parent.mkdir(parents=True, exist_ok=True)
    return load_list("platform_resource_runtime", RUNTIME_RESOURCE_FILE, [])


def _save_runtime_registry(rows: list[dict[str, Any]]) -> None:
    save_list("platform_resource_runtime", RUNTIME_RESOURCE_FILE, rows)


_INLINE_SECRET_KEYS = {
    "password",
    "passwd",
    "token",
    "auth_token",
    "bearer_token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "client_secret",
    "credential",
    "credentials",
    "passphrase",
    "ssh_key",
    "privatekey",
    "private_key",
    "secret",
    "authorization",
    "cookie",
}


def _sanitize_config(value: Any, *, key: str = "") -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for child_key, child_value in value.items():
            normalized = str(child_key).strip().lower()
            if normalized in _INLINE_SECRET_KEYS and normalized not in {"secret_ref"}:
                continue
            result[str(child_key)] = _sanitize_config(child_value, key=normalized)
        return result
    if isinstance(value, list):
        return [_sanitize_config(item, key=key) for item in value]
    return value


def _inline_secret_paths(value: Any, *, prefix: str = "config") -> list[str]:
    paths: list[str] = []
    if isinstance(value, dict):
        for child_key, child_value in value.items():
            normalized = str(child_key).strip().lower()
            path = f"{prefix}.{child_key}"
            if normalized in _INLINE_SECRET_KEYS and child_value not in (None, "", False):
                paths.append(path)
            paths.extend(_inline_secret_paths(child_value, prefix=path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            paths.extend(_inline_secret_paths(item, prefix=f"{prefix}[{index}]"))
    return paths


def _runtime_resources() -> tuple[list[dict[str, Any]], list[str]]:
    deps = _deps()
    resources: list[dict[str, Any]] = []
    issues: list[str] = []
    try:
        for item in deps.fetch_collector_inventory(hours=24):
            collector_id = str(item.get("collector_id") or item.get("id") or item.get("name") or "").strip()
            resources.append(
                {
                    "id": f"runtime-collector-{collector_id}",
                    "name": str(item.get("name") or collector_id),
                    "kind": "collector",
                    "status": "active" if str(item.get("status") or "") in {"active", "ready"} else str(item.get("status") or "degraded"),
                    "version": 1,
                    "origin": "sentinel-runtime",
                    "tenant_id": "main",
                    "updated_ts": str(item.get("last_seen") or ""),
                    "description": str(item.get("role") or ""),
                    "config": {
                        "collector_profile": collector_id,
                        "protocols": list(item.get("protocols") or []),
                        "source_types": list(item.get("source_types") or []),
                        "sources_count": int(item.get("sources_count") or 0),
                        "events": int(item.get("events") or 0),
                    },
                    "bindings": {},
                    "read_only": True,
                }
            )
    except Exception as exc:  # noqa: BLE001
        issues.append(f"collectors:{exc}")
    try:
        for item in deps.fetch_normalizer_rules(limit=5000):
            resources.append(
                {
                    "id": f"runtime-normalizer-{int(item.get('id') or 0)}",
                    "name": f"{item.get('source_type') or 'generic'} normalizer #{int(item.get('id') or 0)}",
                    "kind": "normalizer",
                    "status": "active" if bool(item.get("enabled")) else "disabled",
                    "version": 1,
                    "origin": "sentinel-runtime",
                    "tenant_id": "main",
                    "updated_ts": "",
                    "description": str(item.get("event_matcher") or ""),
                    "config": dict(item),
                    "bindings": {},
                    "read_only": True,
                }
            )
    except Exception as exc:  # noqa: BLE001
        issues.append(f"normalizers:{exc}")
    try:
        for item in deps.get_ch_client().query(
            """
            SELECT id, name, description, priority, expr, action, tags, enabled, updated_ts
            FROM siem.filter_rules
            ORDER BY priority, id
            LIMIT 5000
            """
        ).named_results():
            resources.append(
                {
                    "id": f"runtime-filter-{int(item.get('id') or 0)}",
                    "name": str(item.get("name") or f"Filter #{item.get('id')}"),
                    "kind": "filter",
                    "status": "active" if bool(item.get("enabled")) else "disabled",
                    "version": 1,
                    "origin": "sentinel-runtime",
                    "tenant_id": "main",
                    "updated_ts": str(item.get("updated_ts") or ""),
                    "description": str(item.get("description") or ""),
                    "config": dict(item),
                    "bindings": {},
                    "read_only": True,
                }
            )
    except Exception as exc:  # noqa: BLE001
        issues.append(f"filters:{exc}")
    try:
        for item in deps.get_ch_client().query(
            """
            SELECT id, name, description, enabled, severity, pattern, window_s, threshold, expr, entity_field
            FROM siem.correlation_rules_stream
            ORDER BY id
            LIMIT 10000
            """
        ).named_results():
            resources.append(
                {
                    "id": f"runtime-correlation-rule-{int(item.get('id') or 0)}",
                    "name": str(item.get("name") or f"Rule #{item.get('id')}"),
                    "kind": "correlationRule",
                    "status": "active" if bool(item.get("enabled")) else "disabled",
                    "version": 1,
                    "origin": "sentinel-runtime",
                    "tenant_id": "main",
                    "updated_ts": "",
                    "description": str(item.get("description") or ""),
                    "config": dict(item),
                    "bindings": {},
                    "read_only": True,
                }
            )
    except Exception as exc:  # noqa: BLE001
        issues.append(f"correlation_rules:{exc}")
    try:
        from .control_plane_connector_ops import list_connector_definitions

        for item in list_connector_definitions():
            connector_id = str(item.get("id") or "").strip()
            resources.append(
                {
                    "id": f"runtime-connector-{connector_id}",
                    "name": str(item.get("name") or item.get("title") or connector_id),
                    "kind": "connector",
                    "status": str(item.get("status") or ("active" if item.get("enabled", True) else "disabled")),
                    "version": int(item.get("version") or 1),
                    "origin": "sentinel-runtime",
                    "tenant_id": "main",
                    "updated_ts": str(item.get("updated_ts") or ""),
                    "description": str(item.get("description") or ""),
                    "config": dict(item),
                    "bindings": {},
                    "read_only": True,
                }
            )
    except Exception as exc:  # noqa: BLE001
        issues.append(f"connectors:{exc}")
    resources.extend(
        [
            {
                "id": "runtime-correlator-stream",
                "name": "Stream correlation",
                "kind": "correlator",
                "status": "active",
                "version": 1,
                "origin": "sentinel-runtime",
                "tenant_id": "main",
                "updated_ts": "",
                "description": "Kafka/Redis streaming correlation workers",
                "config": {"engine": "stream", "rule_table": "siem.correlation_rules_stream"},
                "bindings": {"correlation_rules": [item["id"] for item in resources if item.get("kind") == "correlationRule" and item.get("status") == "active"]},
                "read_only": True,
            },
            {
                "id": "runtime-correlator-batch",
                "name": "Batch correlation",
                "kind": "correlator",
                "status": "active",
                "version": 1,
                "origin": "sentinel-runtime",
                "tenant_id": "main",
                "updated_ts": "",
                "description": "Scheduled ClickHouse batch correlation",
                "config": {"engine": "batch", "rule_table": "siem.correlation_rules_batch"},
                "bindings": {},
                "read_only": True,
            },
        ]
    )
    return resources, issues


def list_resources(*, kind: str = "", include_runtime: bool = True) -> dict[str, Any]:
    if kind and kind not in RESOURCE_KINDS:
        raise ValueError(f"Unsupported resource kind: {kind}")
    stored = [dict(item) for item in _stored_resources() if isinstance(item, dict)]
    runtime, issues = _runtime_resources() if include_runtime else ([], [])
    items = runtime + stored
    if kind:
        items = [item for item in items if str(item.get("kind") or "") == kind]
    items.sort(key=lambda item: (str(item.get("kind") or ""), 0 if str(item.get("status") or "") == "active" else 1, str(item.get("name") or "").lower()))
    summary: dict[str, int] = {}
    for item in items:
        key = str(item.get("kind") or "unknown")
        summary[key] = summary.get(key, 0) + 1
    return {"items": items, "total": len(items), "summary": summary, "issues": issues, "generated_ts": _now_iso()}


def get_resource(resource_id: str) -> dict[str, Any]:
    safe_id = str(resource_id or "").strip()
    for item in list_resources().get("items") or []:
        if str(item.get("id") or "") == safe_id:
            return dict(item)
    raise ValueError(f"Resource not found: {safe_id}")


def _save_resource(payload: dict[str, Any], *, actor: str) -> dict[str, Any]:
    kind = str(payload.get("kind") or "").strip()
    name = str(payload.get("name") or "").strip()
    if kind not in RESOURCE_KINDS:
        raise ValueError(f"Unsupported resource kind: {kind}")
    if not name:
        raise ValueError("Resource name is required")
    inline_secrets = _inline_secret_paths(dict(payload.get("config") or {}))
    if inline_secrets:
        raise ValueError(f"Inline secrets are forbidden; use secret_ref: {', '.join(inline_secrets[:5])}")
    tenant_ids = validate_tenant_scope_header(str(payload.get("tenant_id") or "main"))
    if len(tenant_ids) != 1:
        raise ValueError("Exactly one tenant is required")
    tenant_id = tenant_ids[0]
    rows = _stored_resources()
    requested_id = str(payload.get("id") or "").strip()
    if requested_id and not _RESOURCE_ID_PATTERN.fullmatch(requested_id):
        raise ValueError("Resource id contains unsupported characters")
    resource_id = requested_id if requested_id and not requested_id.startswith("runtime-") else f"{kind.lower()}-{_slug(name)}"
    existing = next((item for item in rows if str(item.get("id") or "") == resource_id), None)
    if existing and str(existing.get("kind") or "") != kind:
        raise ValueError("A managed resource kind cannot be changed")
    if existing and str(existing.get("tenant_id") or "main") != tenant_id:
        raise ValueError("A managed resource cannot be moved between tenants")
    if existing and payload.get("expected_revision") is not None:
        expected_revision = int(payload.get("expected_revision") or 0)
        current_revision = int(existing.get("revision") or existing.get("version") or 0)
        if expected_revision != current_revision:
            raise ValueError(
                f"Resource changed concurrently: expected revision {expected_revision}, current revision {current_revision}"
            )
    now = _now_iso()
    history = [dict(item) for item in list((existing or {}).get("history") or []) if isinstance(item, dict)]
    version = max(1, int((existing or {}).get("version") or 0) + 1)
    revision = max(1, int((existing or {}).get("revision") or (existing or {}).get("version") or 0) + 1)
    history.insert(0, {"ts": now, "actor": actor, "action": "save", "version": version})
    item = {
        "id": resource_id,
        "name": name,
        "kind": kind,
        "description": str(payload.get("description") or "").strip(),
        "status": "draft",
        "version": version,
        "revision": revision,
        "origin": "sentinel-managed",
        "tenant_id": tenant_id,
        "updated_ts": now,
        "published_ts": str((existing or {}).get("published_ts") or ""),
        "config": _sanitize_config(dict(payload.get("config") or {})),
        "bindings": dict(payload.get("bindings") or {}),
        "history": history[:25],
        "read_only": False,
    }
    from .resource_lifecycle_runtime import record_resource_version

    record_resource_version(item, actor=actor, action="save")
    rows = [row for row in rows if str(row.get("id") or "") != resource_id]
    rows.append(item)
    _save_resources(rows)
    append_audit_event(
        actor=actor,
        action="resource.saved",
        object_type="platform_resource",
        object_id=resource_id,
        summary=f"Saved managed {kind} resource {resource_id} as version {version}",
        details={"tenant_id": tenant_id, "version": version, "revision": revision, "status": "draft"},
    )
    return item


def save_resource(payload: dict[str, Any], *, actor: str) -> dict[str, Any]:
    with RESOURCE_MUTATION_LOCK:
        return _save_resource(payload, actor=actor)


def validate_resource_payload(payload: dict[str, Any]) -> dict[str, Any]:
    kind = str(payload.get("kind") or "").strip()
    name = str(payload.get("name") or "").strip()
    config = dict(payload.get("config") or {})
    bindings = dict(payload.get("bindings") or {})
    errors: list[str] = []
    warnings: list[str] = []
    if kind not in RESOURCE_KINDS:
        errors.append(f"Unsupported resource kind: {kind}")
    if not name:
        errors.append("name is required")
    inline_secrets = _inline_secret_paths(config)
    if inline_secrets:
        errors.append(f"Inline secrets are forbidden; use secret_ref: {', '.join(inline_secrets[:5])}")
    if kind == "collector":
        if str(config.get("transport") or "") not in {"http", "syslog_tcp", "syslog_udp", "kafka"}:
            errors.append("collector transport must be http, syslog_tcp, syslog_udp or kafka")
        if not str(config.get("collector_profile") or "").strip():
            errors.append("collector_profile is required")
    elif kind == "correlator":
        if str(config.get("engine") or "") not in {"stream", "batch"}:
            errors.append("correlator engine must be stream or batch")
        if not list(bindings.get("correlation_rules") or []):
            warnings.append("No correlation rules are bound")
    elif kind == "correlationRule":
        if int(config.get("rule_id") or 0) <= 0:
            errors.append("rule_id must be a positive integer")
        if not str(config.get("expr") or "").strip() and not str(config.get("sigma_yaml") or "").strip():
            errors.append("expr or sigma_yaml is required")
        if int(config.get("threshold") or 0) <= 0:
            errors.append("threshold must be positive")
        if int(config.get("window_s") or 0) < 60:
            errors.append("window_s must be at least 60")
    elif kind == "normalizer":
        if not str(config.get("source_type") or "").strip():
            errors.append("source_type is required")
        if not str(config.get("event_matcher") or "").strip():
            errors.append("event_matcher is required")
        if not isinstance(config.get("uem_mapping"), (dict, str)):
            errors.append("uem_mapping must be an object or JSON string")
    elif kind == "filter":
        if not str(config.get("expr") or "").strip():
            errors.append("expr is required")
        if str(config.get("action") or "") not in {"drop", "tag", "pass"}:
            errors.append("filter action must be drop, tag or pass")
    elif kind == "activeList":
        if str(config.get("list_kind") or "watch") not in {"watch", "allow", "deny"}:
            errors.append("active list kind must be watch, allow or deny")
        if int(config.get("ttl_seconds") or 0) < 0:
            errors.append("active list ttl_seconds cannot be negative")
        key_fields = config.get("key_fields") or []
        if not isinstance(key_fields, list) or not [item for item in key_fields if str(item).strip()]:
            errors.append("active list key_fields requires at least one key field")
    elif kind == "storage":
        if str(config.get("engine") or "clickhouse") not in {"clickhouse", "s3", "minio", "filesystem"}:
            errors.append("storage engine must be clickhouse, s3, minio or filesystem")
        if not str(config.get("endpoint") or config.get("path") or "").strip():
            errors.append("storage endpoint or path is required")
    elif kind == "aggregationRule":
        if not str(config.get("expr") or "").strip():
            errors.append("aggregation rule expr is required")
        if int(config.get("window_s") or 0) <= 0:
            errors.append("aggregation rule window_s must be positive")
        if not list(config.get("group_by") or []):
            errors.append("aggregation rule group_by requires at least one field")
    elif kind in {"dictionary", "contextTable"}:
        if not list(config.get("key_fields") or []):
            errors.append(f"{kind} key_fields requires at least one field")
        if not str(config.get("source") or config.get("endpoint") or "manual").strip():
            errors.append(f"{kind} source is required")
    elif kind == "connector":
        if not str(config.get("block_type") or config.get("protocol") or "").strip():
            errors.append("connector block_type or protocol is required")
        if not str(config.get("endpoint") or config.get("operation") or "").strip():
            errors.append("connector endpoint or operation is required")
    elif kind == "destination":
        if str(config.get("protocol") or "") not in {"kafka", "clickhouse", "webhook", "syslog_tcp", "syslog_udp", "s3", "minio"}:
            errors.append("destination protocol is unsupported")
        if not str(config.get("endpoint") or config.get("topic") or "").strip():
            errors.append("destination endpoint or topic is required")
    elif kind == "enrichmentRule":
        if not str(config.get("expr") or "").strip():
            errors.append("enrichment rule expr is required")
        if not dict(config.get("set_fields") or {}) and not str(config.get("lookup") or "").strip():
            errors.append("enrichment rule requires set_fields or lookup")
    elif kind == "responseRule":
        if not str(config.get("action_id") or config.get("kind") or "").strip():
            errors.append("response rule action_id or kind is required")
        if not str(config.get("trigger") or "").strip():
            errors.append("response rule trigger is required")
    elif kind == "search":
        if not str(config.get("query") or "").strip():
            errors.append("search query is required")
    elif kind == "agent":
        if str(config.get("platform") or "") not in {"linux", "windows", "container", "network"}:
            errors.append("agent platform must be linux, windows, container or network")
        if not str(config.get("collector_profile") or "").strip():
            errors.append("agent collector_profile is required")
    elif kind == "proxy":
        if not str(config.get("listen") or "").strip() or not str(config.get("upstream") or "").strip():
            errors.append("proxy listen and upstream are required")
    elif kind == "secret":
        if not str(config.get("secret_ref") or "").strip():
            errors.append("secret_ref is required")
    elif kind == "segmentationRule":
        if not str(config.get("expr") or "").strip():
            errors.append("segmentation rule expr is required")
        if not str(config.get("tenant_id") or config.get("segment") or "").strip():
            errors.append("segmentation rule tenant_id or segment is required")
    elif kind == "emailTemplate":
        if not str(config.get("subject") or "").strip() or not str(config.get("body") or "").strip():
            errors.append("email template subject and body are required")
    elif kind == "eventRouter":
        if not str(config.get("expr") or "").strip():
            errors.append("event router expr is required")
        if not list(bindings.get("destinations") or []):
            errors.append("event router requires at least one destination binding")
    return {"valid": not errors, "errors": errors, "warnings": warnings}


def validate_resource(resource_id: str) -> dict[str, Any]:
    resource = get_resource(resource_id)
    validation = validate_resource_payload(resource)
    return {**validation, "resource_id": resource_id, "kind": resource.get("kind")}


def _publish_filter(resource: dict[str, Any]) -> dict[str, Any]:
    deps = _deps()
    config = dict(resource.get("config") or {})
    rule_id = int(config.get("rule_id") or 0)
    deps.get_ch_client().command(
        """
        CREATE TABLE IF NOT EXISTS siem.filter_rules
        (
            id UInt32,
            name String,
            description String,
            priority UInt32,
            expr String,
            action LowCardinality(String),
            tags Array(String),
            enabled UInt8,
            created_ts DateTime DEFAULT now(),
            updated_ts DateTime DEFAULT now()
        )
        ENGINE = MergeTree
        ORDER BY (priority, id)
        """
    )
    if rule_id <= 0:
        row = deps.get_ch_client().query("SELECT max(id) AS id FROM siem.filter_rules").named_results()
        rule_id = int(next(iter(row), {}).get("id") or 3000) + 1
    deps.get_ch_client().command(f"ALTER TABLE siem.filter_rules DELETE WHERE id = {rule_id}", settings={"mutations_sync": 1})
    deps.get_ch_client().insert(
        "siem.filter_rules",
        [[
            rule_id,
            str(resource.get("name") or ""),
            str(resource.get("description") or ""),
            max(1, int(config.get("priority") or 100)),
            str(config.get("expr") or ""),
            str(config.get("action") or "tag"),
            [str(item) for item in list(config.get("tags") or [])],
            1,
        ]],
        column_names=["id", "name", "description", "priority", "expr", "action", "tags", "enabled"],
    )
    return {"table": "siem.filter_rules", "rule_id": rule_id}


def _publish_correlation_rule(resource: dict[str, Any], *, actor: str) -> dict[str, Any]:
    from .correlation_pack_runtime import publish_correlation_pack, save_correlation_pack

    config = dict(resource.get("config") or {})
    rule_id = int(config.get("rule_id") or 0)
    pack_id = f"managed-{resource.get('id')}"
    save_correlation_pack(
        {
            "pack_id": pack_id,
            "title": str(resource.get("name") or ""),
            "version": str(resource.get("version") or 1),
            "status": "active",
            "owner": actor,
            "notes": ["Published from Sentinel resource workspace"],
            "stream_rules": [
                {
                    "id": rule_id,
                    "title": str(resource.get("name") or ""),
                    "severity": str(config.get("severity") or "medium"),
                    "window_s": int(config.get("window_s") or 300),
                    "threshold": int(config.get("threshold") or 1),
                    "entity_field": str(config.get("entity_field") or "host.name"),
                    "suppression_key": str(config.get("suppression_key") or config.get("entity_field") or "host.name"),
                    "status": "active",
                    "operator_action": str(resource.get("description") or ""),
                    "sigma_yaml": str(config.get("sigma_yaml") or ""),
                    "expr": str(config.get("expr") or ""),
                }
            ],
            "batch_rules": [],
        },
        actor=actor,
    )
    return publish_correlation_pack(pack_id)


def _publish_connector(resource: dict[str, Any], *, actor: str) -> dict[str, Any]:
    from .control_plane_connector_ops import save_connector_definition

    config = dict(resource.get("config") or {})
    endpoint = str(config.get("endpoint") or "").strip()
    runtime = dict(config.get("runtime") or {})
    if endpoint:
        request = dict(runtime.get("request") or {})
        request.setdefault("url", endpoint)
        runtime["request"] = request
    runtime.setdefault("operation", str(config.get("operation") or "collect"))
    saved = save_connector_definition(
        {
            "id": str(resource.get("id") or ""),
            "title": str(resource.get("name") or ""),
            "description": str(resource.get("description") or ""),
            "family": str(config.get("family") or "source"),
            "block_type": str(config.get("block_type") or config.get("protocol") or "custom_connector"),
            "stage": str(config.get("stage") or "ingest"),
            "group": str(config.get("group") or "managed"),
            "source_family": str(config.get("source_family") or "custom_api"),
            "protocols": list(config.get("protocols") or ([config.get("protocol")] if config.get("protocol") else [])),
            "mode": str(config.get("mode") or "push"),
            "enabled": True,
            "status": "ready",
            "runtime": runtime,
            "mappings": dict(config.get("mappings") or {}),
            "secret_requirements": list(config.get("secret_requirements") or []),
            "_audit_actor": actor,
        }
    )
    return {
        "state": "applied",
        "applied": True,
        "runtime": "connector_control_plane",
        "runtime_id": str(saved.get("id") or ""),
        "status": str(saved.get("status") or "ready"),
    }


def _publish_response_rule(resource: dict[str, Any], *, actor: str) -> dict[str, Any]:
    from .control_plane_response_ops import save_response_action

    config = dict(resource.get("config") or {})
    trigger = str(config.get("trigger") or "manual").strip().lower()
    saved = save_response_action(
        {
            "id": str(config.get("action_id") or resource.get("id") or ""),
            "title": str(resource.get("name") or ""),
            "description": str(resource.get("description") or ""),
            "kind": str(config.get("kind") or "webhook"),
            "enabled": True,
            "dangerous": bool(config.get("dangerous", False)),
            "approval_required": bool(config.get("approval_required", config.get("dangerous", False))),
            "target": dict(config.get("target") or {}),
            "steps": list(config.get("steps") or []),
            "trigger_kinds": [trigger],
            "owners": [actor],
            "secret_requirements": list(config.get("secret_requirements") or []),
            "_audit_actor": actor,
        }
    )
    return {
        "state": "applied",
        "applied": True,
        "runtime": "response_control_plane",
        "runtime_id": str(saved.get("id") or ""),
        "approval_required": bool(saved.get("approval_required")),
    }


def _publish_runtime_descriptor(resource: dict[str, Any], *, actor: str) -> dict[str, Any]:
    """Register resource contracts without claiming that an absent worker applied them."""
    now = _now_iso()
    resource_id = str(resource.get("id") or "")
    descriptor = {
        "id": resource_id,
        "kind": str(resource.get("kind") or ""),
        "name": str(resource.get("name") or ""),
        "version": int(resource.get("version") or 1),
        "tenant_id": str(resource.get("tenant_id") or "main"),
        "config": _sanitize_config(dict(resource.get("config") or {})),
        "bindings": dict(resource.get("bindings") or {}),
        "state": "registered",
        "applied": False,
        "issue": "No executable runtime adapter is registered for this resource kind",
        "actor": actor,
        "updated_ts": now,
    }
    rows = [item for item in _runtime_registry() if str(item.get("id") or "") != resource_id]
    rows.append(descriptor)
    _save_runtime_registry(rows)
    return {
        "state": descriptor["state"],
        "applied": descriptor["applied"],
        "runtime": "resource_registry",
        "runtime_id": resource_id,
        "issue": descriptor["issue"],
    }


def _collector_endpoint() -> str:
    return str(
        os.getenv("SIEM_PUBLIC_INGEST_BASE_URL")
        or os.getenv("SIEM_INGEST_BASE_URL")
        or "https://192.168.3.102:8443"
    ).rstrip("/")


def build_collector_deployment(resource_id: str) -> dict[str, Any]:
    resource = get_resource(resource_id)
    if str(resource.get("kind") or "") != "collector":
        raise ValueError("Deployment commands are available only for collector resources")
    config = dict(resource.get("config") or {})
    profile = re.sub(r"[^a-zA-Z0-9_.-]+", "-", str(config.get("collector_profile") or "").strip()).strip("-")
    if not profile:
        raise ValueError("collector_profile is required")
    base_url = _collector_endpoint()
    syslog_host = str(os.getenv("SIEM_PUBLIC_INGEST_FORWARD_HOST") or "192.168.3.102").strip()
    syslog_port = max(1, min(65535, int(os.getenv("SIEM_INGEST_FORWARD_PORT") or 1514)))
    transport = str(config.get("transport") or "http")
    linux_config = (
        "*.* action(type=\"omfwd\" "
        f"target=\"{syslog_host}\" port=\"{syslog_port}\" protocol=\"tcp\" "
        "template=\"RSYSLOG_SyslogProtocol23Format\" action.resumeRetryCount=\"-1\" "
        f"queue.type=\"linkedList\" queue.filename=\"sentinel-{profile}\")"
    )
    linux_commands = [
        "sudo install -d -m 0755 /etc/rsyslog.d",
        "sudo tee /etc/rsyslog.d/90-rdegon-sentinel.conf >/dev/null <<'EOF'\n" + linux_config + "\nEOF",
        "sudo rsyslogd -N1 && sudo systemctl restart rsyslog",
        f"logger -t sentinel-onboarding 'collector={profile} onboarding verification'",
    ]
    http_example = (
        f"curl --fail-with-body -X POST '{base_url}/ingest/http' "
        "-H 'Content-Type: application/json' -H 'X-SIEM-Shared-Secret: <secret>' "
        f"--data '{{\"collector\":\"{profile}\",\"collector_profile\":\"{profile}\","
        "\"source\":\"<hostname>\",\"message\":\"application onboarding verification\"}}'"
    )
    docker_daemon = json.dumps(
        {
            "log-driver": "syslog",
            "log-opts": {
                "syslog-address": f"tcp://{syslog_host}:{syslog_port}",
                "tag": "{{.Name}}/{{.ID}}",
            },
        },
        ensure_ascii=False,
        indent=2,
    )
    return {
        "resource_id": resource_id,
        "collector_profile": profile,
        "transport": transport,
        "ingest_base_url": base_url,
        "variants": [
            {
                "id": "linux",
                "title": "Linux host / VM / LXC",
                "description": "OS journals through persistent TCP syslog with disk-backed retry queue.",
                "commands": linux_commands,
                "verification": f"Search events by collector_profile={profile} and source hostname.",
            },
            {
                "id": "windows",
                "title": "Windows host",
                "description": "Generate the signed native-agent package from Discovery and install it elevated.",
                "commands": [
                    "Open Discovery, select the Windows host and choose Prepare onboarding",
                    "Download the generated Windows native-agent package",
                    "Run install-native-agent.cmd <shared-secret> from an elevated terminal",
                ],
                "verification": "Run get-windows-event-agent-status.ps1 -Detailed, then search Windows events by hostname.",
            },
            {
                "id": "container",
                "title": "Docker / container host",
                "description": "Forward container stdout/stderr with the Docker syslog driver.",
                "commands": [
                    "sudo tee /etc/docker/daemon.json >/dev/null <<'EOF'\n" + docker_daemon + "\nEOF",
                    "sudo systemctl restart docker",
                ],
                "verification": "Start a test container that writes one log line and search it by container name.",
            },
            {
                "id": "application",
                "title": "Application / webhook",
                "description": "Send structured application audit records through the production HTTP ingest endpoint.",
                "commands": [http_example],
                "verification": f"Search events by collector_profile={profile}.",
            },
        ],
    }


def _publish_resource(resource_id: str, *, actor: str) -> dict[str, Any]:
    resource = get_resource(resource_id)
    if bool(resource.get("read_only")):
        raise ValueError("Runtime-discovered resources are read-only; duplicate one to create a managed version")
    validation = validate_resource_payload(resource)
    if not validation["valid"]:
        raise ValueError("; ".join(validation["errors"]))
    kind = str(resource.get("kind") or "")
    config = dict(resource.get("config") or {})
    activation: dict[str, Any]
    if kind == "normalizer":
        activation = _deps().save_normalizer_rule(
            rule_id=int(config.get("rule_id") or 0) or None,
            priority=max(1, int(config.get("priority") or 100)),
            source_type=str(config.get("source_type") or ""),
            event_matcher=str(config.get("event_matcher") or ""),
            uem_mapping=config.get("uem_mapping") or {},
            enabled=True,
        )
        activation["table"] = "siem.normalizer_rules"
        activation.update({"state": "applied", "applied": True})
    elif kind == "filter":
        activation = _publish_filter(resource)
        activation.update({"state": "applied", "applied": True})
    elif kind == "correlationRule":
        activation = _publish_correlation_rule(resource, actor=actor)
        activation.update({"state": "applied", "applied": True})
    elif kind == "collector":
        profile = str(config.get("collector_profile") or "")
        activation = {
            "state": "applied",
            "applied": True,
            "collector_profile": profile,
            "transport": str(config.get("transport") or ""),
            "ingest_contract": {
                "http_endpoint": "/ingest/http",
                "required_fields": {"collector_profile": profile, "collector": profile},
            },
        }
    elif kind == "activeList":
        _deps().ensure_active_list_support()
        activation = {
            "state": "applied",
            "applied": True,
            "table": str(getattr(_deps(), "ACTIVE_LIST_TABLE", "siem.active_list_items")),
            "list_name": str(resource.get("name") or ""),
            "list_kind": str(config.get("list_kind") or "watch"),
            "key_fields": [str(item) for item in list(config.get("key_fields") or []) if str(item).strip()],
            "context_fields": [str(item) for item in list(config.get("context_fields") or []) if str(item).strip()],
            "ttl_seconds": max(0, int(config.get("ttl_seconds") or 0)),
            "runtime": "correlation and enrichment",
        }
    elif kind == "correlator":
        activation = {
            "state": "registered",
            "applied": False,
            "engine": str(config.get("engine") or ""),
            "rule_ids": list(dict(resource.get("bindings") or {}).get("correlation_rules") or []),
            "issue": "Bind this definition to a managed correlation service instance before activation",
        }
    elif kind == "connector":
        activation = _publish_connector(resource, actor=actor)
    elif kind == "responseRule":
        activation = _publish_response_rule(resource, actor=actor)
    else:
        activation = _publish_runtime_descriptor(resource, actor=actor)
    rows = _stored_resources()
    now = _now_iso()
    published = dict(resource)
    published["status"] = "active" if bool(activation.get("applied")) else "registered"
    published["published_ts"] = now
    published["updated_ts"] = now
    published["revision"] = max(1, int(resource.get("revision") or resource.get("version") or 0) + 1)
    published["activation"] = activation
    history = [dict(item) for item in list(published.get("history") or []) if isinstance(item, dict)]
    history.insert(0, {"ts": now, "actor": actor, "action": "publish", "version": int(published.get("version") or 1)})
    published["history"] = history[:25]
    rows = [published if str(item.get("id") or "") == resource_id else item for item in rows]
    _save_resources(rows)
    append_audit_event(
        actor=actor,
        action="resource.published" if bool(activation.get("applied")) else "resource.registered",
        object_type="platform_resource",
        object_id=resource_id,
        summary=(
            f"Published managed resource {resource_id}"
            if bool(activation.get("applied"))
            else f"Registered managed resource {resource_id}; runtime adapter has not applied it"
        ),
        details={
            "tenant_id": str(published.get("tenant_id") or "main"),
            "version": int(published.get("version") or 0),
            "revision": int(published.get("revision") or 0),
            "state": str(activation.get("state") or ""),
            "applied": bool(activation.get("applied")),
        },
    )
    return {
        "status": "published" if bool(activation.get("applied")) else "registered",
        "resource": published,
        "activation": activation,
        "validation": validation,
    }


def publish_resource(resource_id: str, *, actor: str) -> dict[str, Any]:
    with RESOURCE_MUTATION_LOCK:
        return _publish_resource(resource_id, actor=actor)
