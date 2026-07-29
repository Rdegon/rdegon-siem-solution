
from __future__ import annotations

from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from datetime import datetime, timedelta
from functools import lru_cache
import hashlib
import html
import ipaddress
import io
import json
import os
from pathlib import Path
import re
import socket
from time import perf_counter, time
from typing import Any, Dict, List
from urllib.parse import quote
from urllib.request import urlopen

import clickhouse_connect
import yaml

try:
    import markdown as markdown_lib
except ImportError:  # pragma: no cover - optional dependency during local editing
    markdown_lib = None

from .config import CONFIG
from .content_store import (
    content_store_backend,
    content_store_status,
    delete_text_document,
    import_content_list,
    import_content_text_documents,
    list_content_collection,
    load_list,
    load_text_document,
    record_content_store_migration,
    save_list,
    save_text_document,
)
from .inventory_catalog import (
    COLLECTOR_CATALOG,
    COMMON_SERVICE_PORTS,
    CORE_PLATFORM_SOURCES,
    SOURCE_ALIAS_OVERRIDES,
    SOURCE_FRESHNESS_THRESHOLDS,
    canonicalize_core_ip,
)
from .clickhouse_runtime import clickhouse_failover_status, clickhouse_replication_snapshot, get_clickhouse_client
try:
    from .transport_health_runtime import build_shadow_transport_status, transport_health_snapshot
except ImportError:  # pragma: no cover - local test fallback
    from transport_health_runtime import build_shadow_transport_status, transport_health_snapshot  # type: ignore[no-redef]
try:
    from .stream_state_runtime import stream_state_runtime_status
except ImportError:  # pragma: no cover - local test fallback
    from stream_state_runtime import stream_state_runtime_status  # type: ignore[no-redef]
try:
    from .proxmox_fleet_runtime import list_proxmox_fleet_inventory
except ImportError:  # pragma: no cover - local test fallback
    from proxmox_fleet_runtime import list_proxmox_fleet_inventory  # type: ignore[no-redef]
try:
    from .runtime_humanization import canonicalize_source_name, humanize_principal, humanize_source_name, humanize_technical_value
except ImportError:  # pragma: no cover - local test fallback
    from runtime_humanization import canonicalize_source_name, humanize_principal, humanize_source_name, humanize_technical_value  # type: ignore[no-redef]
try:
    from .operational_filters import NON_OPERATIONAL_MARKERS, is_non_operational_record
except ImportError:  # pragma: no cover - local test fallback
    from operational_filters import NON_OPERATIONAL_MARKERS, is_non_operational_record  # type: ignore[no-redef]


EVENT_ROW_LIMIT_DEFAULT = 100
EVENT_ROW_LIMIT_MAX = 1000
try:
    SOURCE_INVENTORY_CACHE_TTL_SECONDS = max(5, min(300, int(os.getenv("SIEM_SOURCE_INVENTORY_CACHE_TTL_SECONDS", "45") or "45")))
except ValueError:
    SOURCE_INVENTORY_CACHE_TTL_SECONDS = 45
_SOURCE_INVENTORY_CACHE: Dict[tuple[int, int], tuple[float, List[Dict[str, Any]]]] = {}
EVENT_WINDOWS = {
    '15m': "now() - INTERVAL 15 MINUTE",
    '1h': "now() - INTERVAL 1 HOUR",
    '6h': "now() - INTERVAL 6 HOUR",
    '24h': "now() - INTERVAL 24 HOUR",
    '72h': "now() - INTERVAL 72 HOUR",
    '7d': "now() - INTERVAL 7 DAY",
    '30d': "now() - INTERVAL 30 DAY",
    'all': None,
}
EVENT_STORAGE_TABLES = {
    'hot': 'siem.events',
    'cold': 'siem.events_cold',
}
EVENT_BASE_SELECT_SQL = """
    SELECT
        ts,
        event_id,
        event_code,
        category,
        subcategory,
        event_action,
        event_outcome,
        if(src_ip = 0, '', IPv4NumToString(src_ip)) AS src_ip,
        if(dst_ip = 0, '', IPv4NumToString(dst_ip)) AS dst_ip,
        src_port,
        dst_port,
        device_vendor,
        device_product,
        log_source,
        host_name,
        extract(normalized_json, '"collector":"([^"]*)"') AS observer_collector,
        extract(normalized_json, '"profile":"([^"]*)"') AS collector_profile,
        extract(normalized_json, '"dataset":"([^"]*)"') AS event_dataset,
        extract(normalized_json, '"listener_port":"?([0-9]+)"?') AS collector_port,
        asset_id,
        asset_owner,
        asset_criticality,
        asset_environment,
        asset_service,
        user_name,
        target_user,
        process_name,
        process_executable,
        process_command,
        ti_indicator,
        ti_indicator_type,
        ti_provider,
        ti_severity,
        lower(severity) AS severity,
        message,
        normalized_json,
        tags
""".strip()
EVENT_VIEW_COLUMNS = [
    'ts',
    'event_id',
    'event_code',
    'category',
    'subcategory',
    'event_action',
    'event_outcome',
    'src_ip',
    'dst_ip',
    'src_port',
    'dst_port',
    'device_vendor',
    'device_product',
    'log_source',
    'host_name',
    'observer_collector',
    'collector_profile',
    'event_dataset',
    'collector_port',
    'asset_id',
    'asset_owner',
    'asset_criticality',
    'asset_environment',
    'asset_service',
    'user_name',
    'target_user',
    'process_name',
    'process_executable',
    'process_command',
    'ti_indicator',
    'ti_indicator_type',
    'ti_provider',
    'ti_severity',
    'severity',
    'message',
    'normalized_json',
    'tags',
]
ALLOWED_EVENT_FIELDS = set(EVENT_VIEW_COLUMNS)
FORBIDDEN_SQL_RE = re.compile(
    r"\b(insert|update|delete|drop|alter|create|truncate|optimize|attach|detach|rename|grant|revoke|kill|system|use|set)\b",
    re.IGNORECASE,
)
COMMENT_SQL_RE = re.compile(r"(--|/\*|\*/)")
FULL_SQL_RE = re.compile(r"^\s*(select|with)\b", re.IGNORECASE)
LIMIT_RE = re.compile(r"\blimit\s+(\d+)\b", re.IGNORECASE)
EVENT_VIEW_FROM_RE = re.compile(r"\b(from|join)\s+events_view\b", re.IGNORECASE)
EVENT_TABLE_FROM_RE = re.compile(r"\b(from|join)\s+siem\.events\b", re.IGNORECASE)
SIGMA_CONDITION_TOKEN_RE = re.compile(r"\(|\)|\b(?:and|or|not)\b|[A-Za-z0-9_*]+", re.IGNORECASE)
DETECTION_RULE_TABLE = "siem.detection_rule_catalog"
ACTIVE_LIST_TABLE = "siem.active_list_items"
ALERT_HISTORY_TABLE = "siem.alert_history"
EVENTS_COLD_TABLE = "siem.events_cold"
CMDB_ASSET_TABLE = "siem.cmdb_assets"
THREAT_INTEL_TABLE = "siem.threat_intel_iocs"
STREAM_CORR_RUNTIME_TABLE = "siem.stream_corr_runtime_status"
SHADOW_EVENTS_TABLE = "siem.events_shadow"
RUNTIME_DOCS_DIR = Path("/opt/siem/runtime-docs")
RUNTIME_DASHBOARDS_FILE = RUNTIME_DOCS_DIR / "dashboards.json"
RUNTIME_DASHBOARD_SUMMARY_CACHE_FILE = RUNTIME_DOCS_DIR / "dashboard_summary_cache.json"
RUNTIME_GEOIP_CACHE_FILE = RUNTIME_DOCS_DIR / "geoip_cache.json"
RUNTIME_DNS_CACHE_FILE = RUNTIME_DOCS_DIR / "dns_cache.json"
RUNTIME_BUILDER_DRAFTS_FILE = RUNTIME_DOCS_DIR / "builder_drafts.json"
GEO_ACTIVITY_FALLBACK_WINDOWS = (72, 168)
PROTECTED_PUBLIC_IPS = tuple(
    ip.strip()
    for ip in (os.environ.get("SIEM_PROTECTED_PUBLIC_IPS") or "45.89.111.208,176.108.250.215").split(",")
    if ip.strip()
)
VPN_DESTINATION_CAPTURE_RE = re.compile(
    r"accepted\s+(?:(?:tcp|udp):)?(?://)?(?P<host>\[[^\]]+\]|[^/\s:\]]+)(?::\d+)?",
    re.IGNORECASE,
)
_ALERT_METRICS_CACHE: tuple[float, Dict[str, Any]] | None = None
_DASHBOARD_METRICS_CACHE: tuple[float, Dict[str, Any]] | None = None
_DASHBOARD_SNAPSHOT_CACHE: dict[str, tuple[float, Dict[str, Any]]] = {}
_INCIDENT_DETAIL_CACHE: dict[str, tuple[float, Dict[str, Any]]] = {}
_ALERTS_AGG_CACHE: dict[str, tuple[float, List[Dict[str, Any]]]] = {}
_ALERT_HISTORY_CACHE: dict[str, tuple[float, List[Dict[str, Any]]]] = {}
_INCIDENT_WORKFLOW_READY = False
INCIDENT_STATUS_TRANSITIONS = {
    "new": {"triaged", "assigned", "in_progress", "escalated", "suppressed", "resolved", "closed", "false_positive"},
    "open": {"triaged", "assigned", "in_progress", "escalated", "suppressed", "resolved", "closed", "false_positive"},
    "triaged": {"assigned", "in_progress", "escalated", "suppressed", "resolved", "closed", "false_positive"},
    "assigned": {"in_progress", "escalated", "suppressed", "resolved", "closed", "false_positive"},
    "in_progress": {"assigned", "escalated", "suppressed", "resolved", "closed", "false_positive"},
    "escalated": {"assigned", "in_progress", "suppressed", "resolved", "closed", "false_positive"},
    "suppressed": {"reopened", "in_progress", "closed"},
    "resolved": {"reopened", "closed"},
    "closed": {"reopened"},
    "false_positive": {"reopened"},
    "reopened": {"assigned", "in_progress", "escalated", "suppressed", "resolved", "closed", "false_positive"},
}

DEFAULT_DASHBOARDS: List[Dict[str, Any]] = [
    {
        "id": "security-overview",
        "title": "Security Overview / Обзор безопасности",
        "description": "Default SOC posture view with incidents, event volume, source activity and targeted ports.",
        "widgets": [
            "kpis",
            "severity_breakdown",
            "timelines",
            "geo_sources",
            "geo_vpn_destinations",
            "threat_intel",
            "sources",
            "ports",
            "categories",
            "incidents_preview",
            "incident_queue",
        ],
        "built_in": True,
    },
    {
        "id": "collector-health",
        "title": "Collector Health / Коллекторы",
        "description": "Collector-oriented view focused on source activity, port targeting and category mix.",
        "widgets": [
            "kpis",
            "timelines",
            "geo_sources",
            "threat_intel",
            "sources",
            "ports",
            "vpn_sites",
            "categories",
        ],
        "built_in": True,
    },
    {
        "id": "incident-operations",
        "title": "Incident Operations / Операции SOC",
        "description": "Queue-centric dashboard for analysts with severity breakdown and richer incident previews.",
        "widgets": [
            "kpis",
            "severity_breakdown",
            "incidents_preview",
            "incident_queue",
        ],
        "built_in": True,
    },
]

WIDGET_CATALOG: List[Dict[str, Any]] = [
    {
        "id": "kpis",
        "title": "KPI cards",
        "description": "Core event, incident, TI and source counters.",
        "default_span": 2,
    },
    {
        "id": "severity_breakdown",
        "title": "Severity breakdown",
        "description": "Events, alerts and status distribution widgets.",
        "default_span": 2,
    },
    {
        "id": "timelines",
        "title": "Event and alert timelines",
        "description": "Interactive time-series for events and alerts.",
        "default_span": 2,
    },
    {
        "id": "geo_sources",
        "title": "Attack geography",
        "description": "GeoIP country and map view for external source IPs.",
        "default_span": 2,
    },
    {
        "id": "geo_vpn_destinations",
        "title": "VPN destination map",
        "description": "Geo view of destinations observed behind the VPN egress.",
        "default_span": 2,
    },
    {
        "id": "threat_intel",
        "title": "Threat intelligence",
        "description": "IOC matches, malicious IPs, provider mix and reputation-driven context.",
        "default_span": 2,
    },
    {
        "id": "sources",
        "title": "Top sources",
        "description": "Most active monitored sources in the selected window.",
        "default_span": 1,
    },
    {
        "id": "ports",
        "title": "Targeted ports",
        "description": "Service and probe activity grouped by target port.",
        "default_span": 1,
    },
    {
        "id": "vpn_sites",
        "title": "VPN top visited sites",
        "description": "Domains most frequently accessed behind the VPN.",
        "default_span": 1,
    },
    {
        "id": "categories",
        "title": "Top categories",
        "description": "Normalized category mix for the recent telemetry stream.",
        "default_span": 1,
    },
    {
        "id": "incidents_preview",
        "title": "Recent incidents",
        "description": "Fresh incident queue preview with pivots into incidents.",
        "default_span": 1,
    },
    {
        "id": "incident_queue",
        "title": "Incident queue",
        "description": "Analyst-facing queue widget with current open incidents.",
        "default_span": 2,
    },
]

DEFAULT_BUILDER_DRAFTS: List[Dict[str, Any]] = [
    {
        "id": "linux-auth-detection",
        "title": "Linux auth detection",
        "description": "Collector -> normalizer -> active-list -> detection -> incident pipeline.",
        "kind": "detection",
        "status": "draft",
        "version": 1,
        "updated_ts": "",
        "published_ts": "",
        "history": [],
        "blocks": [
            {"id": "source-1", "type": "source", "stage": "ingest", "label": "Linux Auth Collector", "config": {"profile": "linux-auth"}},
            {"id": "normalize-1", "type": "normalizer", "stage": "parse", "label": "Linux auth normalizer", "config": {"category": "authentication"}},
            {"id": "lookup-1", "type": "active_list", "stage": "enrich", "label": "Denylist lookup", "config": {"list": "denylist"}},
            {"id": "rule-1", "type": "detection", "stage": "detect", "label": "SSH failure burst", "config": {"threshold": 5, "window_s": 300}},
            {"id": "incident-1", "type": "incident", "stage": "incident", "label": "Queue incident", "config": {"severity": "high"}},
            {"id": "publish-1", "type": "publish", "stage": "publish", "label": "Publish runtime", "config": {"target": "stream-correlation"}},
        ],
    },
]

_GEO_COUNTRY_CACHE: Dict[tuple[str, int, int, str], tuple[float, Dict[str, Any]]] = {}

DEFAULT_BUILDER_STAGE_BY_TYPE: Dict[str, str] = {
    "source": "ingest",
    "normalizer": "parse",
    "active_list": "enrich",
    "ti_lookup": "enrich",
    "filter": "enrich",
    "detection": "detect",
    "incident": "incident",
    "publish": "publish",
}
BUILDER_REQUIRED_BLOCKS: Dict[str, List[str]] = {
    "detection": ["source", "detection"],
    "normalizer": ["source", "normalizer"],
    "active-list": ["active_list"],
    "threat-intel": ["ti_lookup"],
}


def _now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _normalize_builder_block(item: Dict[str, Any], index: int = 0) -> Dict[str, Any]:
    block_type = str(item.get("type", "") or "transform").strip().lower()
    block_id = _safe_doc_name(str(item.get("id", "") or f"{block_type}-{index + 1}"))
    return {
        "id": block_id,
        "type": block_type,
        "stage": str(item.get("stage", "") or DEFAULT_BUILDER_STAGE_BY_TYPE.get(block_type, "publish")),
        "label": str(item.get("label", "") or block_id),
        "config": dict(item.get("config") or {}),
    }


def _compile_builder_runtime(draft: Dict[str, Any]) -> Dict[str, Any]:
    blocks = [_normalize_builder_block(item, index) for index, item in enumerate(draft.get("blocks") or [])]
    stage_order = ["ingest", "parse", "enrich", "detect", "incident", "publish"]
    ordered_blocks = sorted(blocks, key=lambda item: (stage_order.index(item["stage"]) if item["stage"] in stage_order else 999, item["id"]))
    return {
        "kind": str(draft.get("kind") or "generic"),
        "stages": stage_order,
        "pipeline": [
            {
                "id": item["id"],
                "type": item["type"],
                "stage": item["stage"],
                "label": item["label"],
                "config": item["config"],
            }
            for item in ordered_blocks
        ],
        "graph": {
            "nodes": [
                {
                    "id": item["id"],
                    "label": item["label"],
                    "type": item["type"],
                    "stage": item["stage"],
                }
                for item in ordered_blocks
            ],
            "edges": [
                {
                    "id": f"edge-{ordered_blocks[index]['id']}-{ordered_blocks[index + 1]['id']}",
                    "source": ordered_blocks[index]["id"],
                    "target": ordered_blocks[index + 1]["id"],
                }
                for index in range(len(ordered_blocks) - 1)
            ],
        },
        "summary": " -> ".join(f"[{item['stage']}] {item['label']}" for item in ordered_blocks),
    }


def validate_builder_draft_payload(
    title: str,
    description: str,
    kind: str,
    blocks: List[Dict[str, Any]],
) -> Dict[str, Any]:
    clean_title = str(title or "").strip()
    normalized_blocks = [_normalize_builder_block(item, index) for index, item in enumerate(blocks or []) if isinstance(item, dict)]
    errors: List[str] = []
    warnings: List[str] = []
    if not clean_title:
        errors.append("Draft title is required.")
    if not normalized_blocks:
        errors.append("At least one block must be present.")
    seen_ids: set[str] = set()
    duplicate_ids: set[str] = set()
    for block in normalized_blocks:
        if block["id"] in seen_ids:
            duplicate_ids.add(block["id"])
        seen_ids.add(block["id"])
    if duplicate_ids:
        errors.append(f"Duplicate block ids detected: {', '.join(sorted(duplicate_ids))}")
    if normalized_blocks and normalized_blocks[0]["type"] != "source":
        warnings.append("Pipeline should usually start with a source block.")
    safe_kind = str(kind or "generic").strip().lower()
    required_types = BUILDER_REQUIRED_BLOCKS.get(safe_kind, [])
    block_types = {block["type"] for block in normalized_blocks}
    missing_types = [item for item in required_types if item not in block_types]
    if missing_types:
        errors.append(f"Missing required blocks for {safe_kind}: {', '.join(missing_types)}")
    if "publish" not in block_types:
        warnings.append("No publish block present. The draft can be tested but should include a publish block before runtime promotion.")
    compiled = _compile_builder_runtime(
        {
            "title": clean_title,
            "description": str(description or "").strip(),
            "kind": safe_kind or "generic",
            "blocks": normalized_blocks,
        }
    )
    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "normalized_blocks": normalized_blocks,
        "compiled": compiled,
    }


def _event_select_sql(table_name: str) -> str:
    return f"{EVENT_BASE_SELECT_SQL}\n    FROM {table_name}"


def _event_view_sql(storage: str = 'hot') -> str:
    if str(os.getenv("SIEM_EVENT_VIEW_ENSURE_SCHEMA_ON_READ", "") or "").strip().lower() in {"1", "true", "yes", "on"}:
        try:
            ensure_event_enrichment_support()
        except Exception:
            # Read paths must not fail because one worker timed out on best-effort
            # ADD COLUMN IF NOT EXISTS checks. Deployment/retention jobs own schema
            # drift remediation; queries should continue against the existing schema.
            pass
    if storage == 'all':
        ensure_cold_storage_support()
        return f"{_event_select_sql('siem.events')} UNION ALL {_event_select_sql(EVENTS_COLD_TABLE)}"
    table_name = EVENT_STORAGE_TABLES.get(storage, 'siem.events')
    if storage == 'cold':
        ensure_cold_storage_support()
    return _event_select_sql(table_name)


def _event_source_label_expr(alias: str = "source_name") -> str:
    return f"if(host_name != '' AND host_name != '-', host_name, log_source) AS {alias}"


def _event_source_group_expr() -> str:
    return "if(host_name != '' AND host_name != '-', host_name, log_source)"


def _event_summary_expr() -> str:
    return (
        "if(category != '', "
        "concat(category, if(subcategory != '', concat(' / ', subcategory), '')), "
        "if(device_product != '', device_product, 'uncategorized'))"
    )


def _alert_source_group_expr() -> str:
    return (
        "if(source != '' AND source != 'stream', source, "
        "if(JSONExtractString(context_json, 'source') != '', JSONExtractString(context_json, 'source'), "
        "if(JSONExtractString(context_json, 'host_name') != '', JSONExtractString(context_json, 'host_name'), "
        "if(entity_key != '', entity_key, 'unknown'))))"
    )


NON_OPERATIONAL_DASHBOARD_TOKENS = NON_OPERATIONAL_MARKERS
SQL_NON_OPERATIONAL_DASHBOARD_TOKENS = (
    "smoke",
    "synthetic",
    "benchmark",
    "collector-bench",
    "bench-syslog",
    "eps-bench",
    "e2e",
    "assignment-full",
    "full-batch-e2e",
    "full-stream-e2e",
    "validation",
    "generic-http",
    "127.0.0.1",
    "::1",
    "{'ip':",
    "vm1-debug",
    "unit-test",
    "ci-test",
    "test-ioc",
    "example-ioc",
    "pytest",
    "playwright",
    "203.0.113.",
    "198.51.100.",
    "192.0.2.",
)


def _contains_non_operational_token(value: Any) -> bool:
    return is_non_operational_record(value)


def _is_non_operational_alert_row(row: Dict[str, Any]) -> bool:
    return is_non_operational_record(row)


def _sql_not_contains_any(expr: str, tokens: tuple[str, ...]) -> str:
    return " AND ".join(f"positionCaseInsensitiveUTF8({expr}, {_sql_quote(token)}) = 0" for token in tokens)


def _combine_sql_filters(*filters: str) -> str:
    active = [f"({str(item).strip()})" for item in filters if str(item or "").strip() and str(item).strip() != "1"]
    return " AND ".join(active) if active else "1"


def _event_operational_filter_sql() -> str:
    haystack = (
        "concat("
        "toString(log_source), ' ', toString(host_name), ' ', "
        "toString(tags)"
        ")"
    )
    return _sql_not_contains_any(haystack, SQL_NON_OPERATIONAL_DASHBOARD_TOKENS)


def _clone_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [dict(row) for row in rows]


def _alert_raw_operational_filter_sql() -> str:
    haystack = "concat(toString(rule_name), ' ', toString(source), ' ', toString(context_json), ' ', toString(entity_key), ' ', toString(status), ' ', toString(assignee))"
    return _sql_not_contains_any(haystack, NON_OPERATIONAL_DASHBOARD_TOKENS)


def _alert_agg_operational_filter_sql() -> str:
    haystack = (
        "concat("
        "toString(rule_name), ' ', toString(entity_key), ' ', "
        "toString(group_key_json), ' ', toString(samples_json), ' ', "
        "toString(status), ' ', toString(assignee)"
        ")"
    )
    return _sql_not_contains_any(haystack, NON_OPERATIONAL_DASHBOARD_TOKENS)


@lru_cache(maxsize=1)
def ensure_event_enrichment_support() -> bool:
    required_columns = {
        "event_code": "String DEFAULT ''",
        "asset_id": "String DEFAULT ''",
        "asset_owner": "String DEFAULT ''",
        "asset_criticality": "String DEFAULT ''",
        "asset_environment": "String DEFAULT ''",
        "asset_service": "String DEFAULT ''",
        "ti_indicator": "String DEFAULT ''",
        "ti_indicator_type": "String DEFAULT ''",
        "ti_provider": "String DEFAULT ''",
        "ti_severity": "String DEFAULT ''",
    }
    client = get_ch_client()
    for table in ("siem.events", EVENTS_COLD_TABLE):
        exists = client.query(f"EXISTS TABLE {table}").result_rows
        if not exists or not exists[0][0]:
            continue
        database, table_name = table.split(".", 1)
        existing_rows = client.query(
            """
            SELECT name
            FROM system.columns
            WHERE database = %(database)s
              AND table = %(table)s
            """,
            parameters={"database": database, "table": table_name},
        ).result_rows
        existing = {str(row[0]) for row in existing_rows if row}
        missing = [
            f"ADD COLUMN IF NOT EXISTS {name} {definition}"
            for name, definition in required_columns.items()
            if name not in existing
        ]
        if missing:
            client.command(f"ALTER TABLE {table} " + ", ".join(missing))
    return True


@lru_cache(maxsize=1)
def ensure_cmdb_ti_support() -> bool:
    client = get_ch_client()
    rows = client.query(
        """
        SELECT name
        FROM system.tables
        WHERE database = 'siem'
          AND name IN ('cmdb_assets', 'threat_intel_indicators')
        """
    ).result_rows
    existing = {str(row[0]) for row in rows if row}
    if CMDB_ASSET_TABLE.rsplit(".", 1)[-1] not in existing:
        client.command(
            f"""
        CREATE TABLE IF NOT EXISTS {CMDB_ASSET_TABLE}
        (
            asset_id String,
            asset_type LowCardinality(String) DEFAULT 'server',
            hostname String DEFAULT '',
            ip String DEFAULT '',
            owner String DEFAULT '',
            criticality LowCardinality(String) DEFAULT 'medium',
            environment LowCardinality(String) DEFAULT 'prod',
            business_service String DEFAULT '',
            os_family LowCardinality(String) DEFAULT '',
            expected_ports String DEFAULT '',
            tags String DEFAULT '',
            notes String DEFAULT '',
            enabled UInt8 DEFAULT 1,
            updated_ts DateTime DEFAULT now()
        )
        ENGINE = ReplacingMergeTree(updated_ts)
        ORDER BY asset_id
        """
        )
    if THREAT_INTEL_TABLE.rsplit(".", 1)[-1] not in existing:
        client.command(
            f"""
        CREATE TABLE IF NOT EXISTS {THREAT_INTEL_TABLE}
        (
            indicator_type LowCardinality(String),
            indicator String,
            provider String DEFAULT '',
            severity LowCardinality(String) DEFAULT 'medium',
            confidence UInt8 DEFAULT 50,
            description String DEFAULT '',
            tags String DEFAULT '',
            enabled UInt8 DEFAULT 1,
            expires_ts Nullable(DateTime),
            updated_ts DateTime DEFAULT now()
        )
        ENGINE = MergeTree
        ORDER BY (indicator_type, indicator, provider)
        """
        )
    return True


def get_ch_client() -> clickhouse_connect.driver.Client:
    return get_clickhouse_client()


def ch_ping() -> bool:
    try:
        get_ch_client().command("SELECT 1")
        return True
    except Exception:
        return False


def _clickhouse_status_snapshot() -> dict[str, Any]:
    try:
        runtime = dict(clickhouse_failover_status())
    except Exception as exc:  # noqa: BLE001
        runtime = {
            "healthy": False,
            "configured_hosts": [],
            "healthy_endpoints": [],
            "failed_endpoints": [{"error": f"{type(exc).__name__}:{exc}"}],
            "active_endpoint": None,
            "replica_hosts_total": 0,
        }
    if "healthy" not in runtime:
        runtime["healthy"] = False
    runtime["clickhouse_ok"] = bool(runtime.get("healthy"))
    return runtime


def _fmt(value: Any) -> Any:
    if value is None:
        return ""
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(value, (list, tuple)):
        return [_fmt(item) for item in value]
    if isinstance(value, dict):
        return {key: _fmt(item) for key, item in value.items()}
    return value


def _iso_from_epoch(value: float) -> str:
    if float(value or 0) <= 0:
        return ""
    return datetime.utcfromtimestamp(float(value)).strftime("%Y-%m-%d %H:%M:%S")


def _parse_fmt_ts(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _freshness_state(last_seen: str, source_type: str = "") -> str:
    ts = _parse_fmt_ts(last_seen)
    if ts is None:
        return "unknown"
    age_minutes = max(0, int((datetime.utcnow() - ts).total_seconds() // 60))
    active_cutoff, delayed_cutoff = SOURCE_FRESHNESS_THRESHOLDS.get(
        source_type or "default",
        SOURCE_FRESHNESS_THRESHOLDS["default"],
    )
    if age_minutes <= active_cutoff:
        return "active"
    if age_minutes <= delayed_cutoff:
        return "delayed"
    return "stale"


def _guess_source_type(source_name: str, products: List[str], categories: List[str]) -> str:
    blob = " ".join([source_name] + products + categories).lower()
    if source_name in CORE_PLATFORM_SOURCES or source_name.lower().startswith("siem-"):
        return "Platform"
    if (
        any(part.startswith("windows.") for part in products)
        or any("windows_event" in part.lower() for part in products)
        or source_name.upper().startswith(("DESKTOP-", "WIN-", "WINDOWS-"))
        or "sysmon" in blob
        or "powershell" in blob
        or "eventlog" in blob
    ):
        return "Windows"
    if "cisco" in blob or "asa" in blob or "ios" in blob:
        return "Cisco"
    if "nextcloud" in blob:
        return "Nextcloud"
    if "openvas" in blob or "greenbone" in blob or "vuln" in blob or "scanner" in blob:
        return "Vulnerability scanner"
    if source_name.lower() == "pve" or "proxmox" in blob or "pveproxy" in blob or "pvedaemon" in blob or "pvestatd" in blob or "pve-cluster" in blob:
        return "Proxmox"
    if "bsdrp" in blob or "freebsd" in blob or "opnsense" in blob or "pfsense" in blob:
        return "BSDRP"
    if "wireguard" in blob or "openvpn" in blob or "xray" in blob or "vpn" in blob:
        return "VPN"
    if "linux." in blob or "auditd" in blob or "sshd" in blob or "sudo" in blob or "systemd" in blob:
        return "Linux"
    return "Application"


def _guess_collector_id(source_type: str) -> str:
    mapping = {
        "Windows": "windows-event-http",
        "Cisco": "network-syslog",
        "Linux": "linux-syslog-audit",
        "VPN": "linux-syslog-audit",
        "BSDRP": "app-json-syslog",
        "Nextcloud": "app-json-syslog",
        "Proxmox": "app-json-syslog",
        "Vulnerability scanner": "vulnerability-import",
        "Application": "app-json-syslog",
    }
    return mapping.get(source_type, "app-json-syslog")


def _json_loads_safe(value: Any) -> Any:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        # Some legacy batch alerts contain numeric JSON values with a stray
        # quote before a comma, for example: "host_count":11","failures":14.
        repaired = re.sub(r"(:\s*-?\d+(?:\.\d+)?)\"\s*([,}])", r"\1\2", text)
        repaired = re.sub(r"(:\s*(?:true|false|null))\"\s*([,}])", r"\1\2", repaired, flags=re.IGNORECASE)
        if repaired != text:
            try:
                return json.loads(repaired)
            except Exception:
                return None
        return None


def _alert_effective_source(source: Any, context_json: Any) -> str:
    safe_source = str(source or "").strip()
    if safe_source and safe_source != "stream":
        return safe_source
    context = _json_loads_safe(context_json)
    if isinstance(context, dict):
        for key in ("source", "host_name"):
            candidate = str(context.get(key) or "").strip()
            if candidate:
                return candidate
    return safe_source or "unknown"


def _alert_effective_source_sql(alias: str = "effective_source") -> str:
    return f"if(source != '' AND source != 'stream', source, '') AS {alias}"


def _incident_key_expr() -> str:
    source_expr = "if(source != '' AND source != 'stream', source, '')"
    return f"if(entity_key != '', entity_key, {source_expr})"


def _incident_key_sql(alias: str = "incident_key") -> str:
    return f"{_incident_key_expr()} AS {alias}"


def _incident_key_from_alert(row: Dict[str, Any]) -> str:
    entity_key = str(row.get("entity_key") or "").strip()
    if entity_key:
        return entity_key
    source = _alert_effective_source(row.get("source"), row.get("context_json"))
    if source and source != "unknown":
        return source
    return f"rule:{row.get('rule_id', 'unknown')}"


def _context_value(context: Any, *keys: str) -> str:
    if not isinstance(context, dict):
        return ""
    for key in keys:
        if key in context:
            candidate = _context_scalar(context.get(key))
            if candidate:
                return candidate
        value = context
        for part in key.split("."):
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(part)
        candidate = str(value or "").strip()
        if candidate:
            return candidate
    return ""


def _context_scalar(value: Any) -> str:
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(item).strip() for item in value if str(item or "").strip())
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False)
    return str(value or "").strip()


def _split_context_values(values: List[Any]) -> List[str]:
    expanded: List[str] = []
    for value in values:
        if isinstance(value, (list, tuple, set)):
            expanded.extend(str(item or "").strip() for item in value)
            continue
        text = str(value or "").strip()
        if not text:
            continue
        if "," in text:
            expanded.extend(part.strip() for part in text.split(","))
        else:
            expanded.append(text)
    return _unique_texts(expanded)


def _unique_texts(values: List[str]) -> List[str]:
    items: List[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        items.append(text)
    return items


def _extract_ip_candidates(value: Any) -> List[str]:
    text = str(value or "").strip()
    if not text:
        return []
    matches = re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", text)
    resolved: List[str] = []
    for match in matches:
        try:
            resolved.append(str(ipaddress.ip_address(match)))
        except ValueError:
            continue
    return _unique_texts(resolved)


def _is_ip_literal(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value or "").strip())
        return True
    except ValueError:
        return False


def _is_observed_cmdb_autocreate_candidate(*, asset_name: str, host_name: str, ip_value: str) -> bool:
    identity = str(host_name or asset_name or "").strip()
    if not identity:
        return False
    if identity.lower() in {"localhost", "127.0.0.1", "::1"}:
        return False
    if _is_ip_literal(identity):
        return False
    if not any(char.isalpha() for char in identity):
        return False
    return not is_non_operational_record({"source_name": identity, "hostname": host_name, "ip": ip_value})


def _incident_actor_ips(context: Any, *, row: Dict[str, Any] | None = None) -> List[str]:
    candidates: List[str] = []
    for key in (
        "source_ip",
        "src_ip",
        "source.ip",
        "attacker_ip",
        "context.source_ip",
        "normalized.source.ip",
        "network.src_ip",
        "client.ip",
        "client_ip",
        "source.address",
        "winlog.event_data.IpAddress",
        "winlog.event_data.SourceAddress",
    ):
        value = _context_value(context, key)
        if value:
            candidates.append(value)
    if row:
        for key in ("entity_key",):
            value = str(row.get(key) or "").strip()
            if value:
                candidates.append(value)
    resolved: List[str] = []
    for value in candidates:
        resolved.extend(_extract_ip_candidates(value))
    return _unique_texts(resolved)


def _incident_campaign(row: Dict[str, Any], context: Any) -> str:
    rule_id = int(row.get("rule_id") or 0)
    rule_name = str(row.get("rule_name") or "").lower()
    event_type = _context_value(context, "event_type", "event.type", "subcategory").lower()
    if rule_id == 4003 or "port probe" in rule_name or "brute force" in rule_name:
        return "network_intrusion"
    if rule_id == 4004 or "privileged execution" in rule_name or "sudo" in rule_name:
        return "privilege_escalation"
    if rule_id == 4005 or "threat intel" in rule_name or _context_value(context, "ti_indicator"):
        return "threat_intel"
    if "windows_" in event_type or "windows" in rule_name:
        return "windows_activity"
    if "ssh" in rule_name or event_type.startswith("ssh_") or "authentication" in rule_name:
        return "authentication"
    if "recon" in rule_name or "system_recon" in event_type:
        return "reconnaissance"
    return event_type or "generic"


def _incident_scope_key_from_alert(row: Dict[str, Any]) -> str:
    context = row.get("context") or _json_loads_safe(row.get("context_json"))
    source = _alert_effective_source(row.get("source"), row.get("context_json"))
    asset_id = _context_value(context, "asset_id", "enrichment.cmdb.asset_id")
    if not asset_id:
        asset_id = source if source and source != "unknown" else ""
    actor_ips = _incident_actor_ips(context, row=row)
    actor = actor_ips[0] if actor_ips else ""
    ti_indicator = _context_value(context, "ti_indicator", "ioc", "indicator")
    campaign = _incident_campaign(row, context)
    if ti_indicator and asset_id:
        return f"asset:{asset_id}|ti:{ti_indicator}|campaign:{campaign}"
    if actor and asset_id:
        return f"asset:{asset_id}|actor:{actor}|campaign:{campaign}"
    if asset_id:
        return f"asset:{asset_id}|campaign:{campaign}"
    if actor and source and source != "unknown":
        return f"source:{source}|actor:{actor}|campaign:{campaign}"
    if source and source != "unknown":
        return f"source:{source}|campaign:{campaign}"
    return _incident_key_from_alert(row)


def _severity_rank(level: str) -> int:
    order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}
    return order.get(str(level or "").lower(), 0)


def _incident_status_value(rows: List[Dict[str, Any]]) -> str:
    statuses = {str(row.get("status") or "new").lower() for row in rows}
    priority = ["in_progress", "assigned", "triaged", "reopened", "open", "new", "closed", "false_positive"]
    for candidate in priority:
        if candidate in statuses:
            return candidate
    return "new"


def _incident_assignee_value(rows: List[Dict[str, Any]]) -> str:
    ranked = sorted(rows, key=lambda row: str(row.get("updated_ts") or row.get("ts_last") or row.get("ts") or ""), reverse=True)
    for row in ranked:
        assignee = str(row.get("assignee") or "").strip()
        if assignee:
            return assignee
    return ""


def _incident_hosts(samples: List[Dict[str, Any]], sources: List[str], assets: List[str], entity_keys: List[str]) -> List[str]:
    host_candidates: List[str] = []
    for value in [*sources, *assets]:
        text = str(value or "").strip()
        if text:
            host_candidates.append(text)
    known_hosts = {str(item or "").strip().lower() for item in host_candidates if str(item or "").strip()}
    for value in entity_keys:
        text = str(value or "").strip()
        if not text:
            continue
        if "|" in text:
            lead = canonicalize_source_name(text.split("|", 1)[0])
            if str(lead or "").strip().lower() in known_hosts:
                continue
        host_candidates.append(text)
    for sample in samples:
        for key in (
            "host_name",
            "source",
            "log_source",
            "observer_collector",
            "enrichment.cmdb.asset_id",
            "asset_id",
            "destination.host.name",
            "destination.hostname",
        ):
            text = _context_value(sample, key)
            if text:
                host_candidates.append(text)
    resolved: List[str] = []
    seen: set[str] = set()
    for value in host_candidates:
        canonical = canonicalize_source_name(value)
        candidate = str(canonical or value or "").strip()
        if not candidate or candidate.lower() == "unknown":
            continue
        dedupe_key = candidate.lower()
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        resolved.append(candidate)
    return resolved


def _incident_host_labels(hosts: List[str]) -> List[str]:
    labels: List[str] = []
    for host in hosts:
        label = humanize_source_name(host, lang="ru", technical_suffix=True) or humanize_technical_value(host, lang="ru") or str(host)
        safe_label = str(label or "").strip()
        if safe_label and safe_label not in labels:
            labels.append(safe_label)
    return labels


def _scalar(query: str) -> Any:
    result = get_ch_client().query(query)
    if not result.result_rows:
        return 0
    return result.result_rows[0][0]


def _clean_datetime_input(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"Invalid datetime value: {text}") from None
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _event_time_filter(window: str, from_ts: str = "", to_ts: str = "") -> str:
    clauses: List[str] = []
    safe_from = _clean_datetime_input(from_ts)
    safe_to = _clean_datetime_input(to_ts)
    if safe_from:
        clauses.append(f"ts >= parseDateTimeBestEffort({_sql_quote(safe_from)})")
    if safe_to:
        clauses.append(f"ts <= parseDateTimeBestEffort({_sql_quote(safe_to)})")
    if clauses:
        return " AND ".join(clauses)
    expr = EVENT_WINDOWS.get(window, EVENT_WINDOWS['24h'])
    if expr is None:
        return "1"
    return f"ts >= {expr}"


def _time_filter(column: str, *, window: str = "24h", from_ts: str = "", to_ts: str = "", hours: int | None = None) -> str:
    clauses: List[str] = []
    safe_from = _clean_datetime_input(from_ts)
    safe_to = _clean_datetime_input(to_ts)
    if safe_from:
        clauses.append(f"{column} >= parseDateTimeBestEffort({_sql_quote(safe_from)})")
    if safe_to:
        clauses.append(f"{column} <= parseDateTimeBestEffort({_sql_quote(safe_to)})")
    if clauses:
        return " AND ".join(clauses)
    if hours is not None:
        return f"{column} >= now() - INTERVAL {max(1, int(hours))} HOUR"
    expr = EVENT_WINDOWS.get(window, EVENT_WINDOWS["24h"])
    if expr is None:
        return "1"
    return f"{column} >= {expr}"


def _sql_quote(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'"


def _search_expr_for_token(token: str) -> str:
    quoted = _sql_quote(token)
    haystack = (
        "concat(toString(ts), ' ', toString(event_id), ' ', toString(event_code), ' ', category, ' ', subcategory, ' ', "
        "event_action, ' ', event_outcome, ' ', "
        "src_ip, ' ', dst_ip, ' ', toString(src_port), ' ', toString(dst_port), ' ', "
        "device_vendor, ' ', device_product, ' ', log_source, ' ', host_name, ' ', observer_collector, ' ', collector_profile, ' ', event_dataset, ' ', collector_port, ' ', "
        "asset_id, ' ', asset_owner, ' ', asset_criticality, ' ', asset_environment, ' ', asset_service, ' ', "
        "user_name, ' ', "
        "target_user, ' ', process_name, ' ', process_executable, ' ', process_command, ' ', "
        "ti_indicator, ' ', ti_indicator_type, ' ', ti_provider, ' ', ti_severity, ' ', "
        "severity, ' ', message, ' ', normalized_json, ' ', tags)"
    )
    return f"positionCaseInsensitiveUTF8({haystack}, {quoted}) > 0"


def _field_expr(field: str, expected: str) -> str:
    if field not in ALLOWED_EVENT_FIELDS:
        return _search_expr_for_token(f"{field}:{expected}")
    quoted = _sql_quote(expected)
    return f"positionCaseInsensitiveUTF8(toString({field}), {quoted}) > 0"


def _build_token_query(raw_query: str) -> str:
    expressions: List[str] = []
    for token in raw_query.split():
        if not token:
            continue
        if ':' in token and not token.startswith('http'):
            field, expected = token.split(':', 1)
            expressions.append(_field_expr(field.strip(), expected.strip()))
            continue
        expressions.append(_search_expr_for_token(token))
    return ' AND '.join(expressions) if expressions else '1'


def _looks_like_expression(raw_query: str) -> bool:
    lower = raw_query.lower()
    markers = ['=', '!=', '>=', '<=', '<', '>', ' like ', ' ilike ', ' and ', ' or ', ' in ', ' not ', ' match(', '(', ')', "'", ' between ']
    return any(marker in lower for marker in markers)


def _validate_read_only_sql(raw_query: str) -> str:
    query = raw_query.strip().rstrip(';')
    if not query:
        raise ValueError('Query is empty')
    if COMMENT_SQL_RE.search(query):
        raise ValueError('Comments are not allowed in the query editor')
    if ';' in query:
        raise ValueError('Only a single statement is allowed')
    if FORBIDDEN_SQL_RE.search(query):
        raise ValueError('Only read-only SELECT/WITH queries are allowed')
    return query


def _resolve_select_query(raw_query: str, storage: str) -> str:
    query = _validate_read_only_sql(raw_query)
    view_sql = _event_view_sql(storage)
    if 'events_view' in query.lower():
        resolved = EVENT_VIEW_FROM_RE.sub(rf"\1 ({view_sql}) AS events_view", query)
    else:
        resolved = EVENT_TABLE_FROM_RE.sub(rf"\1 ({view_sql}) AS events_view", query)
    if ' from ' not in resolved.lower():
        raise ValueError('SELECT query must include a FROM clause')
    if resolved == query and 'events_view' not in query.lower() and 'siem.events' not in query.lower():
        raise ValueError("Read-only SELECT must query from events_view or siem.events")
    return resolved


def _build_events_base_sql(
    query_text: str,
    window: str,
    storage: str = 'hot',
    from_ts: str = "",
    to_ts: str = "",
    *,
    include_operational_filter: bool = True,
) -> str:
    storage = storage if storage in {'hot', 'cold', 'all'} else 'hot'
    query_text = (query_text or '').strip()
    time_filter = _event_time_filter(window, from_ts=from_ts, to_ts=to_ts)
    if not query_text:
        expression = '1'
    elif FULL_SQL_RE.match(query_text):
        resolved = _resolve_select_query(query_text, storage)
        if time_filter == "1":
            return resolved
        return (
            "SELECT *\n"
            f"FROM ({resolved}) AS ranged_events\n"
            f"WHERE {time_filter}"
        )
    elif _looks_like_expression(query_text):
        expression = _validate_read_only_sql(query_text)
    else:
        expression = _build_token_query(query_text)
    filters = [time_filter]
    if include_operational_filter:
        filters.append(_event_operational_filter_sql())

    return (
        f"SELECT\n"
        f"    ts,\n"
        f"    event_id,\n"
        f"    event_code,\n"
        f"    category,\n"
        f"    subcategory,\n"
        f"    event_action,\n"
        f"    event_outcome,\n"
        f"    src_ip,\n"
        f"    dst_ip,\n"
        f"    src_port,\n"
        f"    dst_port,\n"
        f"    device_vendor,\n"
        f"    device_product,\n"
        f"    log_source,\n"
        f"    host_name,\n"
        f"    observer_collector,\n"
        f"    collector_profile,\n"
        f"    event_dataset,\n"
        f"    collector_port,\n"
        f"    asset_id,\n"
        f"    asset_owner,\n"
        f"    asset_criticality,\n"
        f"    asset_environment,\n"
        f"    asset_service,\n"
        f"    user_name,\n"
        f"    target_user,\n"
        f"    process_name,\n"
        f"    process_executable,\n"
        f"    process_command,\n"
        f"    ti_indicator,\n"
        f"    ti_indicator_type,\n"
        f"    ti_provider,\n"
        f"    ti_severity,\n"
        f"    severity,\n"
        f"    message,\n"
        f"    normalized_json,\n"
        f"    tags\n"
        f"FROM ({_event_view_sql(storage)}) AS events_view\n"
        f"WHERE {_combine_sql_filters(*filters)}\n"
        f"  AND ({expression})\n"
        f"ORDER BY ts DESC\n"
    )


def _filter_non_operational_event_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [row for row in rows if not is_non_operational_record(row)]


def _paginate_sql(sql: str, limit: int, offset: int) -> str:
    return (
        f"SELECT *\n"
        f"FROM ({sql}) AS page_view\n"
        f"LIMIT {limit}\n"
        f"OFFSET {offset}"
    )


def _event_normalized_blob(row: Dict[str, Any]) -> Dict[str, Any]:
    value = row.get("normalized_json")
    if isinstance(value, dict):
        return dict(value)
    text = str(value or "").strip()
    if not text or not text.startswith("{"):
        return {}
    try:
        payload = json.loads(text)
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _nested_lookup(payload: Dict[str, Any], *keys: str) -> str:
    for key in keys:
        safe_key = str(key or "").strip()
        if not safe_key:
            continue
        if safe_key in payload and str(payload.get(safe_key) or "").strip():
            return str(payload.get(safe_key) or "").strip()
        current: Any = payload
        matched = True
        for part in safe_key.split("."):
            if not isinstance(current, dict) or part not in current:
                matched = False
                break
            current = current.get(part)
        if matched and str(current or "").strip():
            return str(current or "").strip()
    return ""


def _fleet_inventory_indexes() -> Dict[str, Dict[str, Dict[str, Any]]]:
    try:
        items = list((list_proxmox_fleet_inventory(limit=5000) or {}).get("items") or [])
    except Exception:
        items = []
    by_name: Dict[str, Dict[str, Any]] = {}
    by_ip: Dict[str, Dict[str, Any]] = {}
    by_source: Dict[str, Dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip().lower()
        ip_value = str(item.get("ip") or "").strip()
        source_name = str(item.get("source_name") or "").strip().lower()
        if name:
            by_name[name] = item
        if ip_value:
            by_ip[ip_value] = item
        if source_name:
            by_source[source_name] = item
    return {"by_name": by_name, "by_ip": by_ip, "by_source": by_source}


def _event_fleet_asset(row: Dict[str, Any], payload: Dict[str, Any], indexes: Dict[str, Dict[str, Dict[str, Any]]]) -> Dict[str, Any]:
    host_name = str(row.get("host_name") or "").strip().lower()
    log_source = str(row.get("log_source") or "").strip().lower()
    asset_id = str(row.get("asset_id") or "").strip().lower()
    src_ip = str(row.get("src_ip") or "").strip()
    dst_ip = str(row.get("dst_ip") or "").strip()
    candidates = [
        indexes["by_name"].get(host_name),
        indexes["by_name"].get(asset_id),
        indexes["by_source"].get(log_source),
        indexes["by_source"].get(host_name),
        indexes["by_ip"].get(src_ip),
        indexes["by_ip"].get(dst_ip),
    ]
    for item in candidates:
        if isinstance(item, dict):
            return item
    return {}


def _event_scanner_family(row: Dict[str, Any], payload: Dict[str, Any]) -> str:
    scanner_family = _nested_lookup(payload, "scanner.family", "scanner_family", "scanner", "report.scanner_family")
    if scanner_family:
        return scanner_family
    source = " ".join([
        str(row.get("log_source") or ""),
        str(row.get("device_product") or ""),
        str(row.get("message") or ""),
    ]).lower()
    if "greenbone" in source or "openvas" in source:
        return "greenbone"
    if "nmap" in source:
        return "nmap"
    return ""


def _event_source_family(row: Dict[str, Any], payload: Dict[str, Any]) -> str:
    explicit = _nested_lookup(payload, "source.family", "source_family", "event.provider", "observer.collector")
    if explicit:
        return explicit
    source = str(row.get("log_source") or "").lower()
    if "openclaw" in source:
        return "openclaw"
    if "gitea" in source:
        return "gitea"
    if "navidrome" in source:
        return "navidrome"
    return source


def _enrich_event_row(row: Dict[str, Any], indexes: Dict[str, Dict[str, Dict[str, Any]]]) -> Dict[str, Any]:
    payload = _event_normalized_blob(row)
    asset = _event_fleet_asset(row, payload, indexes)
    app_family = _nested_lookup(payload, "app.family", "app_family")
    if not app_family:
        source_blob = " ".join([str(row.get("log_source") or ""), str(row.get("message") or ""), str(row.get("device_product") or "")]).lower()
        if "gitea" in source_blob:
            app_family = "gitea"
        elif "navidrome" in source_blob:
            app_family = "navidrome"
        elif "openclaw" in source_blob:
            app_family = "openclaw"
    dns_query_name = _nested_lookup(payload, "dns.question.name", "dns.query.name", "dns_query_name", "query")
    destination_host = _nested_lookup(payload, "destination.host.name", "destination.hostname", "network.destination.host", "resolved_host")
    destination_ip = _nested_lookup(payload, "destination.ip", "network.destination.ip") or str(row.get("dst_ip") or "").strip()
    destination_port = _nested_lookup(payload, "destination.port", "network.destination.port") or str(row.get("dst_port") or "").strip()
    keycloak_principal = _nested_lookup(payload, "keycloak.principal", "principal.username", "auth.user", "user.email")
    route_family = _nested_lookup(payload, "route.family", "http.route.family", "request.route")
    return {
        **row,
        "asset_name": str(asset.get("name") or row.get("host_name") or row.get("asset_id") or ""),
        "asset_label": humanize_source_name(asset.get("name") or row.get("host_name") or row.get("asset_id"), lang="ru", technical_suffix=True),
        "asset_role": str(asset.get("role") or ""),
        "business_service": str(asset.get("business_service") or row.get("asset_service") or ""),
        "criticality": str(asset.get("criticality") or row.get("asset_criticality") or ""),
        "fleet_state": str(asset.get("fleet_state") or asset.get("state") or ""),
        "scanner_family": _event_scanner_family(row, payload),
        "source_family": _event_source_family(row, payload),
        "source_label": humanize_source_name(row.get("log_source") or row.get("host_name") or row.get("src_ip"), lang="ru", technical_suffix=True),
        "dns_query_name": dns_query_name,
        "destination_host": destination_host,
        "destination_label": humanize_source_name(destination_host or destination_ip, lang="ru", technical_suffix=True),
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "app_family": app_family,
        "route_family": route_family,
        "keycloak_principal": keycloak_principal,
        "principal_label": humanize_principal(keycloak_principal or row.get("user_name") or row.get("target_user")),
        "event_label": humanize_technical_value(payload.get("event.type") or row.get("event_code") or row.get("subcategory") or row.get("category"), lang="ru"),
    }


def _rows_from_query(sql: str, *, settings: Dict[str, Any] | None = None) -> Dict[str, Any]:
    result = get_ch_client().query(sql, settings=settings or None)
    columns = [str(name) for name in result.column_names]
    rows: List[Dict[str, Any]] = []
    indexes = _fleet_inventory_indexes()
    for raw_row in result.result_rows:
        row = {columns[index]: _fmt(value) for index, value in enumerate(raw_row)}
        rows.append(_enrich_event_row(row, indexes))
    return {'columns': columns, 'rows': rows}


def _parse_ts(value: Any) -> datetime | None:
    text = str(value or '').strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace(' ', 'T'))
    except ValueError:
        return None


def _bucket_rows(rows: List[Dict[str, Any]], bucket_minutes: int = 15) -> List[Dict[str, Any]]:
    buckets: Dict[str, int] = defaultdict(int)
    for row in rows:
        dt = _parse_ts(row.get('ts'))
        if not dt:
            continue
        minute = (dt.minute // bucket_minutes) * bucket_minutes
        bucket = dt.replace(minute=minute, second=0, microsecond=0).strftime('%Y-%m-%d %H:%M:%S')
        buckets[bucket] += 1
    return [{'bucket': key, 'count': buckets[key]} for key in sorted(buckets)]


def _severity_stats(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    order = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
    counts = Counter(str(row.get('severity') or 'unknown').lower() for row in rows)
    return [{'label': name, 'count': counts.get(name, 0)} for name in order if counts.get(name, 0)]


def _source_stats(rows: List[Dict[str, Any]], limit: int = 8) -> List[Dict[str, Any]]:
    counts = Counter(str(row.get('log_source') or 'unknown') for row in rows)
    return [{'label': key, 'count': value} for key, value in counts.most_common(limit)]


def _time_bucket_minutes(window: str, from_ts: str = "", to_ts: str = "") -> int:
    safe_from = _clean_datetime_input(from_ts) if from_ts else ""
    safe_to = _clean_datetime_input(to_ts) if to_ts else ""
    if safe_from and safe_to:
        try:
            start_dt = datetime.fromisoformat(safe_from.replace(" ", "T"))
            end_dt = datetime.fromisoformat(safe_to.replace(" ", "T"))
            span_minutes = max(1, int((end_dt - start_dt).total_seconds() // 60))
            if span_minutes <= 360:
                return 15
            if span_minutes <= 24 * 60:
                return 60
            if span_minutes <= 7 * 24 * 60:
                return 180
            return 720
        except ValueError:
            pass
    return {
        "15m": 5,
        "1h": 10,
        "6h": 30,
        "24h": 60,
        "72h": 180,
        "7d": 360,
        "all": 720,
    }.get(window, 60)


def _severity_stats_query(base_sql: str) -> List[Dict[str, Any]]:
    query = (
        "SELECT lower(severity) AS label, count() AS count "
        f"FROM ({base_sql}) AS stats_view "
        "GROUP BY label "
        "ORDER BY count DESC, label ASC"
    )
    return [
        {
            "label": str(row["label"] or "unknown"),
            "count": int(row["count"] or 0),
        }
        for row in get_ch_client().query(query).named_results()
    ]


def _histogram_query(base_sql: str, bucket_minutes: int) -> List[Dict[str, Any]]:
    safe_minutes = max(1, int(bucket_minutes))
    query = f"""
        SELECT
            toStartOfInterval(ts, toIntervalMinute({safe_minutes})) AS bucket,
            count() AS count
        FROM ({base_sql}) AS stats_view
        GROUP BY bucket
        ORDER BY bucket ASC
    """
    return [
        {
            "bucket": _fmt(row["bucket"]),
            "count": int(row["count"] or 0),
        }
        for row in get_ch_client().query(query).named_results()
    ]


def _source_stats_query(base_sql: str, limit: int = 8) -> List[Dict[str, Any]]:
    query = f"""
        SELECT log_source, count() AS count
        FROM ({base_sql}) AS stats_view
        GROUP BY log_source
        ORDER BY count DESC, log_source ASC
        LIMIT {int(limit)}
    """
    return [
        {
            "label": str(row["log_source"] or "unknown"),
            "count": int(row["count"] or 0),
        }
        for row in get_ch_client().query(query).named_results()
    ]


def _host_stats_query(base_sql: str, limit: int = 16) -> List[Dict[str, Any]]:
    query = f"""
        SELECT
            multiIf(
                length(ifNull(host_name, '')) > 0, ifNull(host_name, ''),
                length(ifNull(asset_id, '')) > 0, ifNull(asset_id, ''),
                length(ifNull(log_source, '')) > 0, ifNull(log_source, ''),
                'unknown'
            ) AS label,
            anyLast(log_source) AS sample_log_source,
            anyLast(asset_id) AS sample_asset_id,
            anyLast(collector_profile) AS sample_collector,
            count() AS count,
            countIf(lower(severity) IN ('critical', 'high')) AS notable,
            max(ts) AS last_seen,
            uniqExact(category) AS categories
        FROM ({base_sql}) AS stats_view
        GROUP BY label
        ORDER BY count DESC, label ASC
        LIMIT {int(limit)}
    """
    return [
        {
            "label": str(row["label"] or "unknown"),
            "count": int(row["count"] or 0),
            "notable": int(row["notable"] or 0),
            "last_seen": _fmt(row["last_seen"]),
            "log_source": str(row["sample_log_source"] or ""),
            "asset_id": str(row["sample_asset_id"] or ""),
            "collector": str(row["sample_collector"] or ""),
            "categories": int(row["categories"] or 0),
        }
        for row in get_ch_client().query(query).named_results()
    ]


def execute_event_query(
    query_text: str,
    window: str = '24h',
    limit: int = EVENT_ROW_LIMIT_DEFAULT,
    storage: str = 'hot',
    offset: int = 0,
    from_ts: str = "",
    to_ts: str = "",
    include_facets: bool = False,
    include_count: bool = False,
) -> Dict[str, Any]:
    started_at = perf_counter()
    limit = max(1, min(int(limit or EVENT_ROW_LIMIT_DEFAULT), EVENT_ROW_LIMIT_MAX))
    offset = max(0, int(offset or 0))
    base_sql = _build_events_base_sql(
        query_text=query_text,
        window=window,
        storage=storage,
        from_ts=from_ts,
        to_ts=to_ts,
        include_operational_filter=False,
    )
    filtered_base_sql = _build_events_base_sql(
        query_text=query_text,
        window=window,
        storage=storage,
        from_ts=from_ts,
        to_ts=to_ts,
        include_operational_filter=True,
    )
    probe_limit = min(EVENT_ROW_LIMIT_MAX, max(limit + 1, (limit * 5) + 1))
    sql = _paginate_sql(base_sql, limit=probe_limit, offset=offset)
    result = _rows_from_query(sql)
    filtered_rows = _filter_non_operational_event_rows(result['rows'])
    rows = filtered_rows[:limit]
    has_next_page = len(filtered_rows) > limit or len(result['rows']) >= probe_limit
    if include_count:
        total_count = int(_scalar(f"SELECT count() FROM ({filtered_base_sql}) AS count_view"))
        total_count_is_estimate = False
    else:
        total_count = offset + len(rows) + (1 if has_next_page else 0)
        total_count_is_estimate = True
    total_pages = max(1, (total_count + limit - 1) // limit) if total_count else 1
    current_page = min(total_pages, (offset // limit) + 1) if total_count else 1
    bucket_minutes = _time_bucket_minutes(window, from_ts=from_ts, to_ts=to_ts)
    first_row = offset + 1 if rows else 0
    last_row = offset + len(rows)
    payload: Dict[str, Any] = {
        'sql': sql,
        'base_sql': base_sql,
        'storage': storage,
        'columns': result['columns'],
        'rows': rows,
        'row_count': len(rows),
        'total_count': total_count,
        'total_count_is_estimate': total_count_is_estimate,
        'limit': limit,
        'offset': offset,
        'page': current_page,
        'total_pages': total_pages,
        'has_prev_page': current_page > 1,
        'has_next_page': has_next_page if total_count_is_estimate else offset + len(rows) < total_count,
        'first_row': first_row,
        'last_row': last_row,
        'from_ts': _clean_datetime_input(from_ts) if from_ts else "",
        'to_ts': _clean_datetime_input(to_ts) if to_ts else "",
        'elapsed_ms': int((perf_counter() - started_at) * 1000),
    }
    if include_facets:
        payload.update(
            {
                'histogram': _histogram_query(filtered_base_sql, bucket_minutes=bucket_minutes),
                'severity_stats': _severity_stats_query(filtered_base_sql),
                'source_stats': _source_stats_query(filtered_base_sql),
                'host_stats': _host_stats_query(filtered_base_sql),
            }
        )
    return payload


def execute_event_facets_query(
    query_text: str,
    window: str = '24h',
    storage: str = 'hot',
    from_ts: str = "",
    to_ts: str = "",
) -> Dict[str, Any]:
    started_at = perf_counter()
    base_sql = _build_events_base_sql(
        query_text=query_text,
        window=window,
        storage=storage,
        from_ts=from_ts,
        to_ts=to_ts,
        include_operational_filter=True,
    )
    bucket_minutes = _time_bucket_minutes(window, from_ts=from_ts, to_ts=to_ts)
    return {
        'base_sql': base_sql,
        'storage': storage,
        'from_ts': _clean_datetime_input(from_ts) if from_ts else "",
        'to_ts': _clean_datetime_input(to_ts) if to_ts else "",
        'histogram': _histogram_query(base_sql, bucket_minutes=bucket_minutes),
        'severity_stats': _severity_stats_query(base_sql),
        'source_stats': _source_stats_query(base_sql),
        'host_stats': _host_stats_query(base_sql),
        'elapsed_ms': int((perf_counter() - started_at) * 1000),
    }


def _as_unique_text_list(value: Any, *, fallback: str = "") -> List[str]:
    if isinstance(value, list):
        return _unique_texts(str(item) for item in value if str(item or "").strip())
    if isinstance(value, tuple):
        return _unique_texts(str(item) for item in value if str(item or "").strip())
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return [fallback] if fallback else []
        parsed = _json_loads_safe(stripped)
        if isinstance(parsed, list):
            return _unique_texts(str(item) for item in parsed if str(item or "").strip())
        return _unique_texts(part.strip() for part in stripped.split(",") if part.strip())
    return [fallback] if fallback else []


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return int(default)


def _stable_materialized_incident_key(row: Dict[str, Any], group_key: Dict[str, Any]) -> str:
    explicit = str(group_key.get("incident_key") or group_key.get("agg_id") or "").strip()
    if explicit:
        return explicit
    entity_key = str(row.get("entity_key") or group_key.get("entity_key") or "").strip().lower()
    rule_id = str(group_key.get("primary_rule_id") or row.get("rule_id") or "").strip()
    rule_name = str(group_key.get("primary_rule") or row.get("rule_name") or "").strip().lower()
    severity = str(row.get("severity_agg") or "").strip().lower()
    basis = "|".join(part for part in (entity_key, rule_id, rule_name, severity) if part)
    if not basis:
        basis = str(row.get("agg_id") or row.get("record_id") or "").strip()
    digest = hashlib.sha1(basis.encode("utf-8", errors="ignore")).hexdigest()[:20]
    return f"agg:{digest}" if digest else ""


def fetch_alerts_agg(limit: int = 200, *, window: str = "24h", from_ts: str = "", to_ts: str = "") -> List[Dict[str, Any]]:
    time_filter = _time_filter("ts_last", window=window, from_ts=from_ts, to_ts=to_ts)
    safe_limit = max(10, min(int(limit or 200), 5000))
    cache_key = json.dumps(["alerts_agg_table_v1", safe_limit, window, from_ts, to_ts], ensure_ascii=False, sort_keys=True)
    now_ts = time()
    cached = _ALERTS_AGG_CACHE.get(cache_key)
    if cached and now_ts - cached[0] < 60:
        return [dict(row) for row in cached[1]]

    query = f"""
        SELECT
            ts_last AS ts,
            agg_id,
            rule_id,
            rule_name,
            lower(severity_agg) AS severity_agg,
            ts_first,
            ts_last,
            count_alerts,
            unique_entities,
            entity_key,
            group_key_json,
            samples_json,
            status,
            assignee,
            updated_ts
        FROM siem.alerts_agg
        WHERE {time_filter}
        ORDER BY ts_last DESC
        LIMIT {safe_limit}
    """
    try:
        table_rows = list(get_ch_client().query(query).named_results())
    except Exception:
        return _fetch_alerts_agg_from_raw_scan(limit=safe_limit, window=window, from_ts=from_ts, to_ts=to_ts)

    if table_rows and "alert_id" in table_rows[0] and "agg_id" not in table_rows[0]:
        return _fetch_alerts_agg_from_raw_scan(limit=safe_limit, window=window, from_ts=from_ts, to_ts=to_ts)

    incidents: List[Dict[str, Any]] = []
    for row in table_rows:
        group_key = _json_loads_safe(row.get("group_key_json"))
        if not isinstance(group_key, dict):
            group_key = {}
        samples = _json_loads_safe(row.get("samples_json"))
        if isinstance(samples, dict):
            samples = [samples]
        elif not isinstance(samples, list):
            samples = []
        samples = [sample for sample in samples if isinstance(sample, dict)]

        entity_key = str(row.get("entity_key") or group_key.get("entity_key") or "").strip()
        storage_agg_id = str(row.get("agg_id") or "").strip()
        agg_id = _stable_materialized_incident_key(row, group_key) or entity_key or storage_agg_id
        rule_names = _as_unique_text_list(group_key.get("rule_names"), fallback=str(row.get("rule_name") or ""))
        sources = _as_unique_text_list(group_key.get("sources"))
        assets = _as_unique_text_list(group_key.get("assets"))
        actors = _as_unique_text_list(group_key.get("actors"))
        iocs = _as_unique_text_list(group_key.get("iocs"))
        campaigns = _as_unique_text_list(group_key.get("campaigns"))
        entity_keys = _as_unique_text_list(group_key.get("entity_keys"), fallback=entity_key)
        hosts = _as_unique_text_list(group_key.get("hosts"))
        if not hosts:
            hosts = _incident_hosts(samples, sources, assets, entity_keys)
        host_labels = _incident_host_labels(hosts)
        severity_agg = str(row.get("severity_agg") or "info").lower()
        count_alerts = _safe_int(row.get("count_alerts"), 1)
        total_hits = _safe_int(
            group_key.get("total_hits")
            or group_key.get("raw_hits_total")
            or group_key.get("hits")
            or count_alerts,
            count_alerts,
        )
        primary_rule = str(group_key.get("primary_rule") or row.get("rule_name") or (rule_names[0] if rule_names else agg_id))
        primary_rule_id = _safe_int(group_key.get("primary_rule_id") or row.get("rule_id"), 0)
        incident = {
            "ts": _fmt(row.get("ts")),
            "agg_id": agg_id,
            "record_id": agg_id,
            "storage_agg_id": storage_agg_id,
            "rule_id": primary_rule_id,
            "rule_name": primary_rule,
            "title": primary_rule or agg_id,
            "severity_agg": severity_agg,
            "ts_first": _fmt(row.get("ts_first")),
            "ts_last": _fmt(row.get("ts_last")),
            "count_alerts": count_alerts,
            "count_events": total_hits,
            "unique_entities": max(1, _safe_int(row.get("unique_entities"), len(entity_keys) or 1)),
            "entity_key": entity_key or agg_id,
            "group_key_json": str(row.get("group_key_json") or ""),
            "samples_json": str(row.get("samples_json") or ""),
            "group_key": group_key,
            "samples": samples,
            "status": str(row.get("status") or "new").lower(),
            "assignee": str(row.get("assignee") or ""),
            "updated_ts": _fmt(row.get("updated_ts")),
            "sources": sources,
            "source_summary": ", ".join((actors or sources or host_labels or [entity_key or agg_id])[:4]),
            "hosts": hosts,
            "host_labels": host_labels,
            "host_summary": ", ".join(host_labels[:4]),
            "raw_alerts_total": count_alerts,
            "raw_hits_total": total_hits,
            "alert_ids": _as_unique_text_list(group_key.get("alert_ids")),
            "cluster": {
                "sources": sources,
                "assets": assets,
                "hosts": hosts,
                "host_labels": host_labels,
                "actors": actors,
                "iocs": iocs,
                "campaigns": campaigns,
                "rule_names": rule_names,
                "raw_alerts": count_alerts,
                "total_hits": total_hits,
                "cluster_first": _fmt(row.get("ts_first")),
                "cluster_last": _fmt(row.get("ts_last")),
            },
        }
        incidents.append(incident)

    _ALERTS_AGG_CACHE[cache_key] = (now_ts, incidents)
    if len(_ALERTS_AGG_CACHE) > 32:
        oldest_key = min(_ALERTS_AGG_CACHE, key=lambda key: _ALERTS_AGG_CACHE[key][0])
        _ALERTS_AGG_CACHE.pop(oldest_key, None)
    return [dict(row) for row in incidents]


def _fetch_alerts_agg_from_raw_scan(limit: int = 200, *, window: str = "24h", from_ts: str = "", to_ts: str = "") -> List[Dict[str, Any]]:
    time_filter = _time_filter("ts_last", window=window, from_ts=from_ts, to_ts=to_ts)
    operational_filter = _alert_raw_operational_filter_sql()
    # Aggregation happens in Python because the incident grouping model depends on enriched
    # alert context. Pull a sufficiently deep raw-alert slice first; otherwise a bursty rule
    # can collapse the visible queue to ~10 groups even when the UI requests hundreds.
    safe_limit = max(10, min(int(limit or 200), 5000))
    cache_key = json.dumps([safe_limit, window, from_ts, to_ts], ensure_ascii=False, sort_keys=True)
    now_ts = time()
    cached = _ALERTS_AGG_CACHE.get(cache_key)
    if cached and now_ts - cached[0] < 60:
        return [dict(row) for row in cached[1]]
    raw_scan_limit = max(1000, min(12000, safe_limit * 12))
    query = f"""
        SELECT
            ts,
            alert_id,
            rule_id,
            rule_name,
            lower(severity) AS severity,
            ts_first,
            ts_last,
            window_s,
            entity_key,
            hits,
            context_json,
            source,
            status,
            assignee,
            updated_ts
        FROM siem.alerts_raw
        WHERE {_combine_sql_filters(time_filter, operational_filter)}
        ORDER BY ts_last DESC
        LIMIT {raw_scan_limit}
    """
    raw_rows = [
        {
            "ts": _fmt(row["ts"]),
            "alert_id": str(row["alert_id"]),
            "rule_id": int(row["rule_id"]),
            "rule_name": str(row["rule_name"]),
            "severity": str(row["severity"]).lower(),
            "ts_first": _fmt(row["ts_first"]),
            "ts_last": _fmt(row["ts_last"]),
            "window_s": int(row["window_s"]),
            "entity_key": str(row["entity_key"] or ""),
            "hits": int(row["hits"]),
            "context_json": row["context_json"],
            "context": _json_loads_safe(row["context_json"]),
            "source": _alert_effective_source(row["source"], row["context_json"]),
            "status": str(row["status"]).lower(),
            "assignee": str(row.get("assignee", "") or ""),
            "updated_ts": _fmt(row.get("updated_ts")),
        }
        for row in get_ch_client().query(query).named_results()
    ]
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in raw_rows:
        grouped[_incident_scope_key_from_alert(row)].append(row)

    incidents: List[Dict[str, Any]] = []
    for incident_key, items in grouped.items():
        sorted_items = sorted(
            items,
            key=lambda row: (
                str(row.get("ts_last") or ""),
                _severity_rank(str(row.get("severity") or "")),
                int(row.get("hits") or 0),
            ),
            reverse=True,
        )
        latest = sorted_items[0]
        rule_names = list(dict.fromkeys(str(row.get("rule_name") or "") for row in sorted_items if str(row.get("rule_name") or "").strip()))
        sources = list(dict.fromkeys(str(row.get("source") or "") for row in sorted_items if str(row.get("source") or "").strip()))
        samples = [row.get("context") or _json_loads_safe(row.get("context_json")) for row in sorted_items[:5]]
        samples = [sample for sample in samples if sample]
        assets = list(
            dict.fromkeys(
                _context_value(sample, "asset_id", "enrichment.cmdb.asset_id")
                for sample in samples
                if _context_value(sample, "asset_id", "enrichment.cmdb.asset_id")
            )
        )
        actors = _unique_texts(
            [
                ip
                for row in sorted_items
                for ip in _incident_actor_ips(row.get("context") or _json_loads_safe(row.get("context_json")), row=row)
            ]
        )
        iocs = list(
            dict.fromkeys(
                _context_value(sample, "ti_indicator", "ioc", "indicator")
                for sample in samples
                if _context_value(sample, "ti_indicator", "ioc", "indicator")
            )
        )
        campaigns = list(dict.fromkeys(_incident_campaign(row, row.get("context")) for row in sorted_items))
        severity_agg = max((str(row.get("severity") or "info").lower() for row in sorted_items), key=_severity_rank, default="info")
        ts_first = min((str(row.get("ts_first") or "") for row in sorted_items), default="")
        ts_last = max((str(row.get("ts_last") or "") for row in sorted_items), default="")
        total_hits = sum(int(row.get("hits") or 0) for row in sorted_items)
        entity_keys = list(dict.fromkeys(str(row.get("entity_key") or "") for row in sorted_items if str(row.get("entity_key") or "").strip()))
        hosts = _incident_hosts(samples, sources, assets, entity_keys)
        host_labels = _incident_host_labels(hosts)
        group_key = {
            "incident_key": incident_key,
            "entity_key": entity_keys[0] if entity_keys else incident_key,
            "sources": sources,
            "assets": assets,
            "actors": actors,
            "iocs": iocs,
            "campaigns": campaigns,
            "rule_names": rule_names,
            "primary_rule": str(latest.get("rule_name") or ""),
            "primary_rule_id": int(latest.get("rule_id") or 0),
        }
        incident = {
            "ts": latest["ts"],
            "agg_id": incident_key,
            "record_id": incident_key,
            "rule_id": int(latest["rule_id"]),
            "rule_name": str(latest["rule_name"]),
            "title": str(latest["rule_name"] or incident_key),
            "severity_agg": severity_agg,
            "ts_first": ts_first,
            "ts_last": ts_last,
            "count_alerts": len(sorted_items),
            "count_events": total_hits,
            "unique_entities": max(1, len(entity_keys)),
            "entity_key": entity_keys[0] if entity_keys else incident_key,
            "group_key_json": json.dumps(group_key, ensure_ascii=False),
            "samples_json": json.dumps(samples, ensure_ascii=False),
            "group_key": group_key,
            "samples": samples,
            "status": _incident_status_value(sorted_items),
            "assignee": _incident_assignee_value(sorted_items),
            "updated_ts": max((str(row.get("updated_ts") or row.get("ts_last") or "") for row in sorted_items), default=""),
            "sources": sources,
            "source_summary": ", ".join((actors or sources)[:4]),
            "hosts": hosts,
            "host_labels": host_labels,
            "host_summary": ", ".join(host_labels[:4]),
            "raw_alerts_total": len(sorted_items),
            "raw_hits_total": total_hits,
            "alert_ids": [str(row.get("alert_id") or "") for row in sorted_items if str(row.get("alert_id") or "").strip()],
            "cluster": {
                "sources": sources,
                "assets": assets,
                "hosts": hosts,
                "host_labels": host_labels,
                "actors": actors,
                "iocs": iocs,
                "campaigns": campaigns,
                "rule_names": rule_names,
                "raw_alerts": len(sorted_items),
                "total_hits": total_hits,
                "cluster_first": ts_first,
                "cluster_last": ts_last,
            },
        }
        incidents.append(incident)

    incidents.sort(key=lambda row: str(row.get("ts_last") or ""), reverse=True)
    result = incidents[:safe_limit]
    _ALERTS_AGG_CACHE[cache_key] = (now_ts, result)
    if len(_ALERTS_AGG_CACHE) > 32:
        oldest_key = min(_ALERTS_AGG_CACHE, key=lambda key: _ALERTS_AGG_CACHE[key][0])
        _ALERTS_AGG_CACHE.pop(oldest_key, None)
    return [dict(row) for row in result]


def _match_alert_ids_for_incident_scope(
    incident_key: str,
    *,
    window: str = "24h",
    from_ts: str = "",
    to_ts: str = "",
    limit: int = 5000,
) -> List[str]:
    safe_key = str(incident_key or "").strip()
    if not safe_key:
        return []
    safe_limit = max(10, min(int(limit or 500), 1000))
    raw_scan_limit = max(1000, min(12000, safe_limit * 12))
    time_filter = _time_filter("ts_last", window=window, from_ts=from_ts, to_ts=to_ts)
    operational_filter = _alert_raw_operational_filter_sql()
    query = f"""
        SELECT
            ts,
            alert_id,
            rule_id,
            rule_name,
            lower(severity) AS severity,
            ts_first,
            ts_last,
            window_s,
            entity_key,
            hits,
            context_json,
            source,
            status,
            assignee,
            updated_ts
        FROM siem.alerts_raw
        WHERE {_combine_sql_filters(time_filter, operational_filter)}
        ORDER BY ts_last DESC
        LIMIT {raw_scan_limit}
    """
    matched: List[str] = []
    for row in get_ch_client().query(query).named_results():
        normalized = {
            "ts": _fmt(row["ts"]),
            "alert_id": str(row["alert_id"]),
            "rule_id": int(row["rule_id"]),
            "rule_name": str(row["rule_name"]),
            "severity": str(row["severity"]).lower(),
            "ts_first": _fmt(row["ts_first"]),
            "ts_last": _fmt(row["ts_last"]),
            "window_s": int(row["window_s"]),
            "entity_key": str(row["entity_key"] or ""),
            "hits": int(row["hits"]),
            "context_json": row["context_json"],
            "context": _json_loads_safe(row["context_json"]),
            "source": _alert_effective_source(row["source"], row["context_json"]),
            "status": str(row["status"]).lower(),
            "assignee": str(row.get("assignee", "") or ""),
            "updated_ts": _fmt(row.get("updated_ts")),
        }
        if _incident_scope_key_from_alert(normalized) == safe_key:
            matched.append(str(normalized["alert_id"]))
    return matched


def _incident_materialized_alert_time_filter(selected: Dict[str, Any]) -> str:
    ts_first = _clean_datetime_input(str(selected.get("ts_first") or ""))
    ts_last = _clean_datetime_input(str(selected.get("ts_last") or selected.get("ts") or ""))
    if ts_first and ts_last:
        return (
            f"ts_last >= parseDateTimeBestEffort({_sql_quote(ts_first)}) - INTERVAL 2 HOUR "
            f"AND ts_first <= parseDateTimeBestEffort({_sql_quote(ts_last)}) + INTERVAL 2 HOUR"
        )
    return _time_filter("ts_last", window="30d")


def _match_alert_ids_for_materialized_incident(selected: Dict[str, Any], *, limit: int = 5000) -> List[str]:
    group_key = selected.get("group_key")
    if not isinstance(group_key, dict):
        group_key = _json_loads_safe(selected.get("group_key_json"))
    if not isinstance(group_key, dict):
        group_key = {}
    explicit_alert_ids = _as_unique_text_list(selected.get("alert_ids"))
    if not explicit_alert_ids:
        explicit_alert_ids = _as_unique_text_list(group_key.get("alert_ids"))
    if explicit_alert_ids:
        query = f"""
            SELECT alert_id
            FROM siem.alerts_raw
            WHERE toString(alert_id) IN (
                {", ".join(_sql_quote(alert_id) for alert_id in explicit_alert_ids)}
            )
            LIMIT {max(1, min(int(limit or 5000), 5000))}
        """
        matched_alert_ids = [
            str(row["alert_id"])
            for row in get_ch_client().query(query).named_results()
            if str(row.get("alert_id") or "").strip()
        ]
        if matched_alert_ids:
            return matched_alert_ids

    entity_key = str(selected.get("entity_key") or "").strip()
    rule_id = _safe_int(selected.get("rule_id"), 0)
    rule_name = str(selected.get("rule_name") or selected.get("title") or "").strip()
    if not entity_key or (rule_id <= 0 and not rule_name):
        return []
    filters = [
        _incident_materialized_alert_time_filter(selected),
        f"toString(entity_key) = {_sql_quote(entity_key)}",
    ]
    if rule_id > 0:
        filters.append(f"toInt64(rule_id) = {rule_id}")
    elif rule_name:
        filters.append(f"toString(rule_name) = {_sql_quote(rule_name)}")
    query = f"""
        SELECT alert_id
        FROM siem.alerts_raw
        WHERE {_combine_sql_filters(*filters)}
        ORDER BY ts_last DESC
        LIMIT {max(1, min(int(limit or 5000), 5000))}
    """
    return [str(row["alert_id"]) for row in get_ch_client().query(query).named_results() if str(row.get("alert_id") or "").strip()]


def fetch_alerts_raw(limit: int = 200, *, window: str = "24h", from_ts: str = "", to_ts: str = "") -> List[Dict[str, Any]]:
    time_filter = _time_filter("ts_last", window=window, from_ts=from_ts, to_ts=to_ts)
    operational_filter = _alert_raw_operational_filter_sql()
    query = f"""
        SELECT
            ts,
            alert_id,
            rule_id,
            rule_name,
            lower(severity) AS severity,
            ts_first,
            ts_last,
            window_s,
            entity_key,
            hits,
            context_json,
            source,
            status,
            assignee,
            updated_ts
        FROM siem.alerts_raw
        WHERE {_combine_sql_filters(time_filter, operational_filter)}
        ORDER BY ts_last DESC
        LIMIT {int(limit)}
    """
    rows: List[Dict[str, Any]] = []
    for row in get_ch_client().query(query).named_results():
        rows.append(
            {
                'ts': _fmt(row['ts']),
                'alert_id': str(row['alert_id']),
                'rule_id': row['rule_id'],
                'rule_name': row['rule_name'],
                'severity': str(row['severity']).lower(),
                'ts_first': _fmt(row['ts_first']),
                'ts_last': _fmt(row['ts_last']),
                'window_s': int(row['window_s']),
                'entity_key': row['entity_key'],
                'hits': int(row['hits']),
                'context_json': row['context_json'],
                'context': _json_loads_safe(row['context_json']),
                'source': _alert_effective_source(row['source'], row['context_json']),
                'status': str(row['status']).lower(),
                'assignee': row.get('assignee', ''),
                'updated_ts': _fmt(row.get('updated_ts')),
            }
        )
    if not rows:
        return rows
    cluster_rows = get_ch_client().query(
        f"""
        SELECT
            entity_key,
            groupUniqArray(8)(if(source != 'stream', source, '')) AS sources,
            groupUniqArray(8)(rule_name) AS rule_names,
            count() AS raw_alerts,
            sum(hits) AS total_hits,
            min(ts_first) AS cluster_first,
            max(ts_last) AS cluster_last
        FROM siem.alerts_raw
        WHERE entity_key != ''
          AND {_combine_sql_filters(time_filter, operational_filter)}
        GROUP BY entity_key
        """
    ).named_results()
    cluster_index = {
        str(row["entity_key"]): {
            "sources": [str(item) for item in row["sources"] if str(item or "").strip()],
            "rule_names": [str(item) for item in row["rule_names"] if str(item or "").strip()],
            "raw_alerts": int(row["raw_alerts"]),
            "total_hits": int(row["total_hits"]),
            "cluster_first": _fmt(row["cluster_first"]),
            "cluster_last": _fmt(row["cluster_last"]),
        }
        for row in cluster_rows
    }
    for row in rows:
        row["cluster"] = cluster_index.get(str(row["entity_key"] or ""), {})
    return rows


def _incident_terminal_status_requires_note(status: str) -> bool:
    return str(status or "").strip().lower() in {"closed", "false_positive", "resolved", "suppressed"}


def _incident_selected_record(view: str, record_id: str, *, window: str = "24h", from_ts: str = "", to_ts: str = "") -> Dict[str, Any] | None:
    safe_view = "raw" if view == "raw" else "agg"
    windows = [(window or "24h", from_ts, to_ts), ("7d", "", ""), ("30d", "", ""), ("all", "", "")]
    key_name = "alert_id" if safe_view == "raw" else "agg_id"

    def _match(rows: List[Dict[str, Any]]) -> Dict[str, Any] | None:
        selected = next((row for row in rows if str(row.get(key_name) or "") == str(record_id)), None)
        if selected is None and safe_view == "agg":
            selected = next(
                (
                    row
                    for row in rows
                    if str(row.get("record_id") or "") == str(record_id)
                    or str(row.get("storage_agg_id") or "") == str(record_id)
                    or str(row.get("entity_key") or "") == str(record_id)
                    or str((row.get("group_key") or {}).get("incident_key") or "") == str(record_id)
                ),
                None,
            )
        return selected

    for next_window, next_from, next_to in windows:
        for row_limit in (200, 500, 2000, 5000):
            try:
                rows = (
                    fetch_alerts_raw(limit=row_limit, window=next_window, from_ts=next_from, to_ts=next_to)
                    if safe_view == "raw"
                    else fetch_alerts_agg(limit=row_limit, window=next_window, from_ts=next_from, to_ts=next_to)
                )
            except Exception:
                continue
            selected = _match(rows)
            if selected is not None:
                return selected
            if len(rows) < row_limit:
                break
        if safe_view == "agg":
            try:
                selected = _match(
                    _fetch_alerts_agg_from_raw_scan(
                        limit=5000,
                        window=next_window,
                        from_ts=next_from,
                        to_ts=next_to,
                    )
                )
            except Exception:
                selected = None
            if selected is not None:
                return selected
    return None


def _incident_raw_alert_rows(selected: Dict[str, Any], view: str, limit: int = 500) -> List[Dict[str, Any]]:
    if view == "raw":
        alert_id = str(selected.get("alert_id") or "").strip()
        alert_ids = [alert_id] if alert_id else []
    else:
        alert_ids = [str(item or "").strip() for item in selected.get("alert_ids", []) if str(item or "").strip()]
    if not alert_ids and view != "raw":
        alert_ids = _match_alert_ids_for_materialized_incident(selected, limit=limit)
    if not alert_ids:
        incident_key = str(selected.get("agg_id") or selected.get("record_id") or "").strip()
        alert_ids = _match_alert_ids_for_incident_scope(incident_key, window="30d", limit=limit) if incident_key else []
    if not alert_ids:
        return []
    values = ", ".join(_sql_quote(alert_id) for alert_id in alert_ids[: max(1, min(int(limit or 500), 1000))])
    operational_filter = _alert_raw_operational_filter_sql()
    query = f"""
        SELECT
            ts,
            alert_id,
            rule_id,
            rule_name,
            lower(severity) AS severity,
            ts_first,
            ts_last,
            window_s,
            entity_key,
            hits,
            context_json,
            source,
            status,
            assignee,
            updated_ts
        FROM siem.alerts_raw
        WHERE toString(alert_id) IN ({values})
          AND {operational_filter}
        ORDER BY ts_last DESC
        LIMIT {max(1, min(int(limit or 500), 1000))}
    """
    rows: List[Dict[str, Any]] = []
    for row in get_ch_client().query(query).named_results():
        context = _json_loads_safe(row["context_json"])
        rows.append(
            {
                "ts": _fmt(row["ts"]),
                "alert_id": str(row["alert_id"]),
                "rule_id": int(row["rule_id"]),
                "rule_name": str(row["rule_name"] or ""),
                "severity": str(row["severity"] or "info").lower(),
                "ts_first": _fmt(row["ts_first"]),
                "ts_last": _fmt(row["ts_last"]),
                "window_s": int(row["window_s"] or 0),
                "entity": str(row["entity_key"] or ""),
                "entity_key": str(row["entity_key"] or ""),
                "group_key": str(row["entity_key"] or ""),
                "source_event_count": int(row["hits"] or 0),
                "hits": int(row["hits"] or 0),
                "status": str(row["status"] or "new").lower(),
                "source": _alert_effective_source(row["source"], row["context_json"]),
                "dedup_key": f"{int(row['rule_id'])}:{str(row['entity_key'] or '')}",
                "assignee": str(row.get("assignee") or ""),
                "updated_ts": _fmt(row.get("updated_ts")),
                "context": context if isinstance(context, dict) else {},
                "context_json": str(row["context_json"] or ""),
            }
        )
    return rows


MITRE_TACTIC_NAMES = {
    "attack.reconnaissance": "Reconnaissance",
    "attack.resource_development": "Resource Development",
    "attack.initial_access": "Initial Access",
    "attack.execution": "Execution",
    "attack.persistence": "Persistence",
    "attack.privilege_escalation": "Privilege Escalation",
    "attack.defense_evasion": "Defense Evasion",
    "attack.credential_access": "Credential Access",
    "attack.discovery": "Discovery",
    "attack.lateral_movement": "Lateral Movement",
    "attack.collection": "Collection",
    "attack.command_and_control": "Command and Control",
    "attack.exfiltration": "Exfiltration",
    "attack.impact": "Impact",
}


def _mitre_from_tags(tags_value: Any) -> Dict[str, Any]:
    tags = [item.strip().lower() for item in str(tags_value or "").split(",") if item.strip()]
    tactics: List[str] = []
    techniques: List[str] = []
    for tag in tags:
        if tag in MITRE_TACTIC_NAMES:
            tactics.append(MITRE_TACTIC_NAMES[tag])
            continue
        technique = re.search(r"attack\.(t\d{4}(?:\.\d{3})?)", tag)
        if technique:
            techniques.append(technique.group(1).upper())
    return {
        "mitre_tactics": _unique_texts(tactics),
        "mitre_techniques": _unique_texts(techniques),
        "mitre_tactic": ", ".join(_unique_texts(tactics)),
        "mitre_technique": ", ".join(_unique_texts(techniques)),
    }


MITRE_RULE_TEXT_HINTS = (
    (("encoded powershell", "powershell", "script", "cmd.exe", "shell"), "Execution", "T1059"),
    (("wmi", "wmic"), "Execution", "T1047"),
    (("lolbin", "rundll32", "regsvr32", "mshta"), "Defense Evasion", "T1218"),
    (("defender", "protection disabled", "security tool", "tamper"), "Defense Evasion", "T1562"),
    (("brute", "password spray", "failed login", "login failure", "invalid user"), "Credential Access", "T1110"),
    (("root ssh", "explicit credential", "special privilege", "privilege", "sudo"), "Privilege Escalation", "T1548"),
    (("user added", "admin group", "account created", "new user"), "Persistence", "T1098"),
    (("port scan", "probe", "scan burst", "recon"), "Discovery", "T1046"),
    (("dns", "doh", "dot", "destination", "sni", "c2"), "Command and Control", "T1071"),
    (("ioc", "indicator", "threat intel", "denylist"), "Command and Control", "T1071"),
    (("sqli", "xss", "web-", "sql injection", "remote code execution"), "Initial Access", "T1190"),
    (("pve", "proxmox", "reboot", "reset", "shutdown"), "Impact", "T1529"),
    (("ld preload", "setuid", "capability modified"), "Privilege Escalation", "T1548"),
)


def _mitre_from_rule_text(*values: Any) -> Dict[str, Any]:
    text = " ".join(str(value or "") for value in values).lower()
    tactics: List[str] = []
    techniques: List[str] = []
    for tokens, tactic, technique in MITRE_RULE_TEXT_HINTS:
        if any(token in text for token in tokens):
            tactics.append(tactic)
            techniques.append(technique)
    return {
        "mitre_tactics": _unique_texts(tactics),
        "mitre_techniques": _unique_texts(techniques),
        "mitre_tactic": ", ".join(_unique_texts(tactics)),
        "mitre_technique": ", ".join(_unique_texts(techniques)),
    }


def _incident_rule_catalog_index(rule_ids: List[int]) -> Dict[int, Dict[str, Any]]:
    ids = sorted({int(rule_id) for rule_id in rule_ids if int(rule_id or 0) > 0})
    if not ids:
        return {}
    id_list = ", ".join(str(rule_id) for rule_id in ids[:100])
    query = f"""
        SELECT
            id,
            title,
            sigma_id,
            status,
            level,
            source_format,
            logsource_product,
            logsource_service,
            logsource_category,
            sigma_yaml,
            expr,
            entity_field,
            window_s,
            threshold,
            verification_query,
            tags,
            description,
            enabled,
            author,
            updated_ts
        FROM {DETECTION_RULE_TABLE}
        WHERE id IN ({id_list})
        ORDER BY id
    """
    try:
        result = get_ch_client().query(query).named_results()
    except Exception:
        return {}
    index: Dict[int, Dict[str, Any]] = {}
    for row in result:
        mitre = _mitre_from_tags(row.get("tags"))
        if not mitre.get("mitre_tactic") and not mitre.get("mitre_technique"):
            mitre = _mitre_from_rule_text(
                row.get("title"),
                row.get("description"),
                row.get("tags"),
                row.get("logsource_product"),
                row.get("logsource_service"),
                row.get("logsource_category"),
            )
        index[int(row["id"])] = {
            "rule_id": int(row["id"]),
            "rule_name": str(row.get("title") or ""),
            "catalog_status": str(row.get("status") or ""),
            "severity": str(row.get("level") or "info").lower(),
            "enabled": bool(row.get("enabled")),
            "created_by": str(row.get("author") or "catalog"),
            "updated_at": _fmt(row.get("updated_ts")),
            "description": str(row.get("description") or ""),
            "logic_summary": str(row.get("expr") or row.get("verification_query") or row.get("sigma_yaml") or ""),
            "window_s": int(row.get("window_s") or 0),
            "threshold": int(row.get("threshold") or 0),
            "group_by": str(row.get("entity_field") or ""),
            "source_format": str(row.get("source_format") or ""),
            "logsource_product": str(row.get("logsource_product") or ""),
            "logsource_service": str(row.get("logsource_service") or ""),
            "logsource_category": str(row.get("logsource_category") or ""),
            "source_category": " / ".join(
                item
                for item in (
                    str(row.get("logsource_product") or ""),
                    str(row.get("logsource_service") or ""),
                    str(row.get("logsource_category") or ""),
                )
                if item
            ),
            "sigma_id": str(row.get("sigma_id") or ""),
            "tags": str(row.get("tags") or ""),
            "verification_query": str(row.get("verification_query") or ""),
            **mitre,
        }
    return index


def _merge_rule_catalog_metadata(runtime_row: Dict[str, Any], catalog_row: Dict[str, Any] | None) -> Dict[str, Any]:
    if not catalog_row:
        return runtime_row
    merged = dict(runtime_row)
    for key, value in catalog_row.items():
        if key in {"rule_id"}:
            continue
        if key in {"enabled"}:
            merged[key] = value
            continue
        if key in {"mitre_tactics", "mitre_techniques"}:
            merged[key] = value
            continue
        if str(value or "").strip() and not str(merged.get(key) or "").strip():
            merged[key] = value
    for key in (
        "source_format",
        "logsource_product",
        "logsource_service",
        "logsource_category",
        "source_category",
        "sigma_id",
        "tags",
        "verification_query",
        "catalog_status",
        "mitre_tactic",
        "mitre_technique",
    ):
        if str(catalog_row.get(key) or "").strip():
            merged[key] = catalog_row[key]
    if str(catalog_row.get("description") or "").strip():
        merged["description"] = catalog_row["description"]
    return merged


def _incident_rule_rows(rule_ids: List[int]) -> List[Dict[str, Any]]:
    ids = sorted({int(rule_id) for rule_id in rule_ids if int(rule_id or 0) > 0})
    if not ids:
        return []
    id_list = ", ".join(str(rule_id) for rule_id in ids[:100])
    rows: List[Dict[str, Any]] = []
    catalog = _incident_rule_catalog_index(ids)
    stream_query = f"""
        SELECT
            id,
            name,
            description,
            enabled,
            severity,
            pattern,
            window_s,
            threshold,
            expr,
            entity_field,
            updated_ts
        FROM siem.correlation_rules_stream
        WHERE id IN ({id_list})
        ORDER BY id
    """
    for row in get_ch_client().query(stream_query).named_results():
        rule_id = int(row["id"])
        rows.append(
            _merge_rule_catalog_metadata(
                {
                "rule_id": rule_id,
                "rule_name": str(row["name"] or ""),
                "rule_type": "stream correlation",
                "rule_version": "runtime",
                "severity": str(row["severity"] or "info").lower(),
                "confidence": 80,
                "enabled": bool(row["enabled"]),
                "created_by": "runtime",
                "updated_at": _fmt(row["updated_ts"]),
                "description": str(row["description"] or ""),
                "logic_summary": str(row["expr"] or row["pattern"] or ""),
                "mitre_tactic": "",
                "mitre_technique": "",
                "window_s": int(row["window_s"] or 0),
                "threshold": int(row["threshold"] or 0),
                "group_by": str(row["entity_field"] or ""),
                "suppression_window": "",
                },
                catalog.get(rule_id),
            )
        )
    batch_query = f"""
        SELECT
            id,
            name,
            description,
            enabled,
            severity,
            window_s,
            sql_template,
            updated_ts
        FROM siem.correlation_rules_batch
        WHERE id IN ({id_list})
        ORDER BY id
    """
    for row in get_ch_client().query(batch_query).named_results():
        rule_id = int(row["id"])
        if any(item["rule_id"] == rule_id for item in rows):
            continue
        rows.append(
            _merge_rule_catalog_metadata(
                {
                "rule_id": rule_id,
                "rule_name": str(row["name"] or ""),
                "rule_type": "batch correlation",
                "rule_version": "runtime",
                "severity": str(row["severity"] or "info").lower(),
                "confidence": 75,
                "enabled": bool(row["enabled"]),
                "created_by": "runtime",
                "updated_at": _fmt(row["updated_ts"]),
                "description": str(row["description"] or ""),
                "logic_summary": str(row["sql_template"] or ""),
                "mitre_tactic": "",
                "mitre_technique": "",
                "window_s": int(row["window_s"] or 0),
                "threshold": 1,
                "group_by": "",
                "suppression_window": "",
                },
                catalog.get(rule_id),
            )
        )
    existing_ids = {int(row.get("rule_id") or 0) for row in rows}
    for rule_id, catalog_row in catalog.items():
        if rule_id in existing_ids:
            continue
        rows.append(
            {
                **catalog_row,
                "rule_type": "catalog rule",
                "rule_version": "catalog",
                "confidence": 70,
                "suppression_window": "",
            }
        )
    for row in rows:
        if not str(row.get("mitre_tactic") or "").strip() and not str(row.get("mitre_technique") or "").strip():
            inferred_mitre = _mitre_from_rule_text(
                row.get("rule_name"),
                row.get("description"),
                row.get("tags"),
                row.get("source_category"),
                row.get("logic_summary"),
            )
            row.update({key: value for key, value in inferred_mitre.items() if value})
    rows.sort(key=lambda item: int(item.get("rule_id") or 0))
    return rows


def _incident_context_values(contexts: List[Dict[str, Any]], *keys: str) -> List[str]:
    values: List[str] = []
    for context in contexts:
        for key in keys:
            value = _context_value(context, key)
            if value:
                values.append(value)
    return _split_context_values(values)


def _incident_event_candidates(selected: Dict[str, Any], raw_alerts: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    contexts = [row.get("context") for row in raw_alerts if isinstance(row.get("context"), dict)]
    samples = [item for item in selected.get("samples", []) if isinstance(item, dict)]
    contexts.extend(samples)
    group_key = selected.get("group_key") if isinstance(selected.get("group_key"), dict) else {}
    hosts = _split_context_values(
        [
            *[str(item or "") for item in selected.get("hosts", [])],
            *[str(item or "") for item in selected.get("sources", [])],
            *[str(item or "") for item in group_key.get("sources", [])],
            *[str(item or "") for item in group_key.get("assets", [])],
            str(selected.get("entity_key") or ""),
            *_incident_context_values(contexts, "host_name", "host.name", "source", "log_source", "hosts", "asset_id", "enrichment.cmdb.asset_id"),
        ]
    )
    users = _incident_context_values(contexts, "user_name", "user.name", "target_user", "user.target.name")
    ips = _split_context_values(
        [
            *[str(item or "") for item in group_key.get("actors", [])],
            *[ip for context in contexts for ip in _incident_actor_ips(context)],
            *_incident_context_values(contexts, "src_ip", "source_ip", "source.ip", "dst_ip", "destination_ip", "destination.ip"),
        ]
    )
    categories = _incident_context_values(contexts, "category", "event.category", "event_type", "event.type", "subcategory")
    return {
        "hosts": [item for item in hosts if item and not item.startswith("asset:") and "|" not in item][:24],
        "users": users[:24],
        "ips": ips[:24],
        "categories": categories[:24],
    }


def _incident_time_bounds(selected: Dict[str, Any], raw_alerts: List[Dict[str, Any]]) -> tuple[str, str]:
    starts = [str(selected.get("ts_first") or selected.get("ts") or "").strip()]
    ends = [str(selected.get("ts_last") or selected.get("ts") or "").strip()]
    for row in raw_alerts:
        starts.append(str(row.get("ts_first") or row.get("ts") or "").strip())
        ends.append(str(row.get("ts_last") or row.get("ts") or "").strip())
    starts = [item for item in starts if item]
    ends = [item for item in ends if item]
    return (min(starts) if starts else "", max(ends) if ends else "")


def _incident_event_select_sql(*, include_normalized_json: bool = False) -> str:
    # The incident card needs concise SOC evidence. Keep the column visible for
    # shared noise filters, but avoid pulling the large blob unless command
    # evidence explicitly needs it.
    normalized_column = "normalized_json" if include_normalized_json else "'' AS normalized_json"
    return """
        SELECT
            ts,
            event_id,
            event_code,
            category,
            subcategory,
            event_action,
            event_outcome,
            if(src_ip = 0, '', IPv4NumToString(src_ip)) AS src_ip,
            if(dst_ip = 0, '', IPv4NumToString(dst_ip)) AS dst_ip,
            src_port,
            dst_port,
            device_vendor,
            device_product,
            log_source,
            host_name,
            asset_id,
            user_name,
            target_user,
            process_name,
            process_executable,
            process_command,
            asset_service,
            lower(severity) AS severity,
            message,
            tags,
            {normalized_column}
        FROM siem.events
    """.format(normalized_column=normalized_column).strip()


INCIDENT_DETAIL_QUERY_SETTINGS = {
    "max_execution_time": 6,
    "max_threads": 2,
}


INCIDENT_EVIDENCE_RADIUS_MINUTES = 45


def _incident_evidence_time_clause(start_ts: str, end_ts: str) -> str:
    if not start_ts or not end_ts:
        return "ts >= now() - INTERVAL 24 HOUR"
    safe_start = _clean_datetime_input(start_ts)
    safe_end = _clean_datetime_input(end_ts)
    start_dt = _parse_ts(safe_start)
    end_dt = _parse_ts(safe_end)
    if start_dt is None or end_dt is None:
        return "ts >= now() - INTERVAL 24 HOUR"
    if end_dt < start_dt:
        start_dt, end_dt = end_dt, start_dt
        safe_start, safe_end = safe_end, safe_start
    radius = INCIDENT_EVIDENCE_RADIUS_MINUTES
    if end_dt - start_dt <= timedelta(minutes=radius * 2):
        return (
            f"ts >= parseDateTimeBestEffort({_sql_quote(safe_start)}) - INTERVAL {radius} MINUTE "
            f"AND ts <= parseDateTimeBestEffort({_sql_quote(safe_end)}) + INTERVAL {radius} MINUTE"
        )
    return (
        "("
        f"(ts >= parseDateTimeBestEffort({_sql_quote(safe_start)}) - INTERVAL {radius} MINUTE "
        f"AND ts <= parseDateTimeBestEffort({_sql_quote(safe_start)}) + INTERVAL {radius} MINUTE) "
        "OR "
        f"(ts >= parseDateTimeBestEffort({_sql_quote(safe_end)}) - INTERVAL {radius} MINUTE "
        f"AND ts <= parseDateTimeBestEffort({_sql_quote(safe_end)}) + INTERVAL {radius} MINUTE)"
        ")"
    )


def _incident_should_run_command_priority_query(
    selected: Dict[str, Any],
    raw_alerts: List[Dict[str, Any]],
    candidates: Dict[str, List[str]],
) -> bool:
    contexts = [
        row.get("context")
        for row in raw_alerts
        if isinstance(row.get("context"), dict)
    ]
    text_parts: List[str] = [
        str(selected.get("rule_name") or ""),
        str(selected.get("title") or ""),
        str(selected.get("source_summary") or ""),
        str(selected.get("entity_key") or ""),
        " ".join(candidates.get("categories") or []),
    ]
    for context in contexts[:8]:
        text_parts.extend(
            str(context.get(key) or "")
            for key in (
                "category",
                "event.category",
                "event_type",
                "event.type",
                "event_action",
                "process_name",
                "process_command",
                "description",
            )
        )
    signal = " ".join(text_parts).lower()
    return any(
        token in signal
        for token in (
            "command",
            "cmd",
            "powershell",
            "pwsh",
            "wmi",
            "wmic",
            "script",
            "process",
            "execution",
            "exec",
            "sudo",
            "systemd unit modified",
            "scheduled task",
            "task scheduler",
            "lolbin",
            "defender",
            "tamper",
            "temporary paths",
            "/tmp",
            "kernel or sysctl",
        )
    )


def _incident_related_events(selected: Dict[str, Any], raw_alerts: List[Dict[str, Any]], limit: int = 200) -> Dict[str, Any]:
    candidates = _incident_event_candidates(selected, raw_alerts)
    start_ts, end_ts = _incident_time_bounds(selected, raw_alerts)
    safe_limit = max(1, min(int(limit or 200), 500))
    time_clause = _incident_evidence_time_clause(start_ts, end_ts)
    entity_clauses: List[str] = []
    category_clauses: List[str] = []
    for value in candidates["hosts"]:
        quoted = _sql_quote(value)
        entity_clauses.append(
            f"(host_name = {quoted} OR asset_id = {quoted} OR log_source = {quoted})"
        )
    for value in candidates["users"]:
        quoted = _sql_quote(value)
        entity_clauses.append(f"(user_name = {quoted} OR target_user = {quoted})")
    for value in candidates["ips"]:
        quoted = _sql_quote(value)
        entity_clauses.append(f"(src_ip = {quoted} OR dst_ip = {quoted})")
    for value in candidates["categories"][:8]:
        quoted = _sql_quote(value)
        category_clauses.append(f"(category = {quoted} OR subcategory = {quoted} OR event_action = {quoted})")
    if entity_clauses and category_clauses:
        where_scope = f"(({' OR '.join(entity_clauses)}) AND ({' OR '.join(category_clauses)}))"
    elif entity_clauses:
        where_scope = " OR ".join(entity_clauses)
    elif category_clauses:
        where_scope = " OR ".join(category_clauses)
    else:
        where_scope = "1"
    event_sql = _incident_event_select_sql()
    operational_filter = _event_operational_filter_sql()
    evidence_errors: List[str] = []
    command_terms = (
        "positionCaseInsensitiveUTF8(concat(message, ' ', process_name, ' ', process_executable, ' ', process_command), 'powershell') > 0 "
        "OR positionCaseInsensitiveUTF8(concat(message, ' ', process_name, ' ', process_executable, ' ', process_command), 'cmd.exe') > 0 "
        "OR positionCaseInsensitiveUTF8(concat(message, ' ', process_name, ' ', process_executable, ' ', process_command), 'wmi') > 0 "
        "OR positionCaseInsensitiveUTF8(concat(message, ' ', process_name, ' ', process_executable, ' ', process_command), 'Task Scheduler') > 0 "
        "OR positionCaseInsensitiveUTF8(concat(message, ' ', process_name, ' ', process_executable, ' ', process_command), 'HostApplication=') > 0 "
        "OR positionCaseInsensitiveUTF8(concat(message, ' ', process_name, ' ', process_executable, ' ', process_command), 'CommandLine=') > 0 "
        "OR positionCaseInsensitiveUTF8(concat(message, ' ', process_name, ' ', process_executable, ' ', process_command), 'sudo') > 0 "
        "OR positionCaseInsensitiveUTF8(concat(message, ' ', process_name, ' ', process_executable, ' ', process_command), 'execve') > 0"
    )
    prioritize_commands = _incident_should_run_command_priority_query(selected, raw_alerts, candidates)
    order_clause = f"({command_terms}) DESC, ts DESC" if prioritize_commands else "ts DESC"
    base_sql = f"""
        SELECT *
        FROM ({event_sql}) AS incident_events
        WHERE {_combine_sql_filters(time_clause, operational_filter)}
          AND ({where_scope})
        ORDER BY {order_clause}
        LIMIT {safe_limit}
    """
    try:
        result = _rows_from_query(base_sql, settings=INCIDENT_DETAIL_QUERY_SETTINGS)
    except Exception as exc:  # noqa: BLE001
        result = {"columns": [], "rows": []}
        evidence_errors.append(f"related events query failed: {type(exc).__name__}: {str(exc)[:240]}")
    merged_rows: List[Dict[str, Any]] = []
    seen_event_ids: set[str] = set()
    for row in result["rows"]:
        event_id = str(row.get("event_id") or f"{row.get('ts')}:{row.get('message')}")
        if event_id in seen_event_ids:
            continue
        seen_event_ids.add(event_id)
        merged_rows.append(row)
    for row in merged_rows:
        for field in ("message", "process_command", "normalized_json"):
            if field in row:
                row[field] = _mask_sensitive_text(row.get(field))
    return {
        "rows": merged_rows[:safe_limit],
        "columns": result["columns"],
        "limit": safe_limit,
        "row_count": len(merged_rows),
        "query_scope": candidates,
        "time_bounds": {"from": start_ts, "to": end_ts},
        "sql": base_sql,
        "partial": bool(evidence_errors),
        "errors": evidence_errors[:4],
    }


COMMAND_PATTERNS = (
    re.compile(r"HostApplication=(?P<cmd>.+?)(?:\r?\n|\t[A-Z][A-Za-z]+=|$)", re.IGNORECASE | re.DOTALL),
    re.compile(r"CommandLine=(?P<cmd>.+?)(?:\r?\n|\t[A-Z][A-Za-z]+=|$)", re.IGNORECASE | re.DOTALL),
    re.compile(r'action\s+"(?P<cmd>[^"]+\.(?:exe|ps1|bat|cmd))"', re.IGNORECASE),
    re.compile(r'instance\s+"(?P<cmd>[^"]+\.(?:exe|ps1|bat|cmd))"', re.IGNORECASE),
)


SENSITIVE_COMMAND_PATTERNS = (
    re.compile(r"(?P<prefix>[-/]{1,2}(?:SharedSecret|Password|Pass|Token|ApiKey|APIKey|Secret|Key)\s+)(?P<value>[^ \t\r\n;]+)", re.IGNORECASE),
    re.compile(r"(?P<prefix>\b(?:shared_secret|sharedsecret|password|passwd|token|api_key|apikey|secret|client_secret)\b\s*[:=]\s*)(?P<value>[^ \t\r\n,;\"']+)", re.IGNORECASE),
)


def _mask_sensitive_text(value: Any) -> str:
    text = str(value or "")
    if not text:
        return ""
    masked = text
    for pattern in SENSITIVE_COMMAND_PATTERNS:
        masked = pattern.sub(lambda match: f"{match.group('prefix')}[REDACTED]", masked)
    return masked


def _incident_command_from_event(row: Dict[str, Any]) -> str:
    for key in ("process_command", "process.command_line", "process.command"):
        value = str(row.get(key) or "").strip()
        if value:
            normalized = _mask_sensitive_text(value)[:4000]
            if re.fullmatch(r'(?:[A-Za-z]:\\[^"\r\n]+\\)?(?:powershell|pwsh|cmd|wscript|cscript|rundll32|wmic|schtasks|mshta|regsvr32)(?:\.exe)?', normalized.strip(), re.IGNORECASE):
                return ""
            return normalized
    payload = _event_normalized_blob(row)
    value = _nested_lookup(payload, "process.command_line", "process.command", "process.commandLine")
    if value:
        normalized = _mask_sensitive_text(value)[:4000]
        if re.fullmatch(r'(?:[A-Za-z]:\\[^"\r\n]+\\)?(?:powershell|pwsh|cmd|wscript|cscript|rundll32|wmic|schtasks|mshta|regsvr32)(?:\.exe)?', normalized.strip(), re.IGNORECASE):
            return ""
        return normalized
    message = str(row.get("message") or "")
    for pattern in COMMAND_PATTERNS:
        match = pattern.search(message)
        if match:
            normalized = _mask_sensitive_text(re.sub(r"\s+", " ", match.group("cmd")).strip())[:4000]
            if re.fullmatch(r'(?:[A-Za-z]:\\[^"\r\n]+\\)?(?:powershell|pwsh|cmd|wscript|cscript|rundll32|wmic|schtasks|mshta|regsvr32)(?:\.exe)?', normalized.strip(), re.IGNORECASE):
                return ""
            return normalized
    # Do not treat generic process lifecycle messages as executed commands.
    # Without an explicit command-line field this turns evidence into noise
    # such as "Process terminated: Image: powershell.exe".
    command_like = re.search(
        r"(^|\s)(?:powershell|pwsh|cmd|wscript|cscript|rundll32|wmic|schtasks|mshta|regsvr32)(?:\.exe)?\s+[-/]",
        message,
        re.IGNORECASE,
    )
    if command_like:
        return _mask_sensitive_text(message.strip())[:4000]
    return ""


def _incident_command_evidence(events: List[Dict[str, Any]], limit: int = 20) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for event in events:
        command = _incident_command_from_event(event)
        if not command:
            continue
        dedupe = f"{event.get('ts')}|{event.get('host_name')}|{command}".lower()
        if dedupe in seen:
            continue
        seen.add(dedupe)
        rows.append(
            {
                "ts": event.get("ts"),
                "event_id": event.get("event_id"),
                "host_name": event.get("host_name"),
                "user_name": event.get("user_name") or event.get("target_user"),
                "process_name": event.get("process_name") or event.get("device_product"),
                "process_executable": event.get("process_executable"),
                "process_command": command,
                "log_source": event.get("log_source"),
                "message": str(event.get("message") or "")[:1000],
            }
        )
        if len(rows) >= limit:
            break
    return rows


def _incident_entity_summary(selected: Dict[str, Any], raw_alerts: List[Dict[str, Any]], events: List[Dict[str, Any]]) -> Dict[str, Any]:
    contexts = [row.get("context") for row in raw_alerts if isinstance(row.get("context"), dict)]
    group_key = selected.get("group_key") if isinstance(selected.get("group_key"), dict) else {}
    users = _split_context_values(
        [
            *_incident_context_values(contexts, "user_name", "user.name", "target_user", "user.target.name"),
            *[str(row.get("user_name") or "") for row in events],
            *[str(row.get("target_user") or "") for row in events],
        ]
    )
    hosts = _split_context_values(
        [
            *[str(item or "") for item in selected.get("hosts", [])],
            *[str(item or "") for item in selected.get("sources", [])],
            *[str(item or "") for item in group_key.get("assets", [])],
            *[str(item or "") for item in group_key.get("sources", [])],
            *_incident_context_values(contexts, "host_name", "host.name", "source", "log_source", "hosts", "asset_id", "enrichment.cmdb.asset_id"),
            *[str(row.get("host_name") or "") for row in events],
            *[str(row.get("asset_id") or "") for row in events],
            *[str(row.get("log_source") or "") for row in events],
        ]
    )
    ips = _split_context_values(
        [
            *[str(item or "") for item in group_key.get("actors", [])],
            *_incident_context_values(contexts, "source_ip", "src_ip", "source.ip", "destination_ip", "dst_ip", "destination.ip"),
            *[ip for context in contexts for ip in _incident_actor_ips(context)],
            *[str(row.get("src_ip") or "") for row in events],
            *[str(row.get("dst_ip") or "") for row in events],
        ]
    )
    processes = _split_context_values(
        [
            *_incident_context_values(contexts, "process_name", "process.name", "process_executable", "process.executable"),
            *[str(row.get("process_name") or "") for row in events],
            *[str(row.get("process_executable") or "") for row in events],
        ]
    )
    sources = _split_context_values([*[str(item or "") for item in selected.get("sources", [])], *_incident_context_values(contexts, "source", "log_source"), *[str(row.get("log_source") or "") for row in events]])
    ports = _split_context_values([*_incident_context_values(contexts, "src_port", "source.port", "dst_port", "destination.port"), *[str(row.get("src_port") or "") for row in events], *[str(row.get("dst_port") or "") for row in events]])
    rules = _unique_texts([str(row.get("rule_name") or "") for row in raw_alerts])
    return {
        "users": [{"user.name": item} for item in users if item],
        "hosts": [{"host.name": item} for item in hosts if item and item != "0"],
        "ips": [{"ip": item, "is_internal": _is_internal_ip(item), "is_public": not _is_internal_ip(item)} for item in ips if item and item != "0"],
        "processes": [{"process.name": item} for item in processes if item],
        "ports": [{"port": item} for item in ports if item and item != "0"],
        "sources": [{"log.source": item} for item in sources if item],
        "rules": [{"rule.name": item} for item in rules if item],
    }


def _is_internal_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(str(value)).is_private
    except ValueError:
        return False


def _incident_risk(selected: Dict[str, Any], entities: Dict[str, Any]) -> Dict[str, Any]:
    severity = str(selected.get("severity_agg") or selected.get("severity") or "info").lower()
    severity_score = {"critical": 95, "high": 80, "medium": 55, "low": 30, "info": 10}.get(severity, 20)
    high_value_entity = bool(entities.get("hosts") or entities.get("users"))
    external_ip = any(not item.get("is_internal") for item in entities.get("ips", []))
    risk_score = min(100, severity_score + (8 if high_value_entity else 0) + (7 if external_ip else 0))
    return {
        "severity": severity,
        "severity_score": severity_score,
        "confidence": 85 if selected.get("raw_hits_total") or selected.get("count_events") else 70,
        "risk_score": risk_score,
        "impact": "High" if risk_score >= 80 else "Medium" if risk_score >= 55 else "Low",
        "urgency": "Immediate" if severity == "critical" or risk_score >= 90 else "High" if risk_score >= 80 else "Normal",
        "priority": "P1" if severity == "critical" else "P2" if risk_score >= 80 else "P3" if risk_score >= 55 else "P4",
        "escalation_reason": "High-risk entity or high severity incident" if risk_score >= 80 else "",
        "warning": "High risk. Priority incident handling is required." if risk_score >= 80 else "",
    }


def _incident_recommendations(
    selected: Dict[str, Any],
    commands: List[Dict[str, Any]],
    entities: Dict[str, Any],
    rules: List[Dict[str, Any]] | None = None,
) -> List[str]:
    rule_name = str(selected.get("rule_name") or "").lower()
    category_text = " ".join(str(item.get("rule.name") or "") for item in entities.get("rules", [])).lower()
    rule_text = " ".join(
        " ".join(
            str(rule.get(key) or "")
            for key in ("rule_name", "description", "tags", "source_category", "logsource_product", "logsource_service", "mitre_tactic", "mitre_technique")
        )
        for rule in (rules or [])
    ).lower()
    recommendations = [
        "Validate whether the activity belongs to an approved administrative or collector workflow.",
        "Review the related raw alerts and events in chronological order before closing the incident.",
        "Check the affected host and user context against expected asset ownership and business role.",
    ]
    if commands or "powershell" in category_text or "wmi" in rule_name or "process" in rule_name:
        recommendations.extend(
            [
                "Review every captured process command line, parent context and account that executed it.",
                "For unexpected PowerShell/WMI activity, collect a host snapshot and verify running processes, scheduled tasks and persistence points.",
                "If the command is not authorized, isolate the host or block the account before enrichment/eradication steps.",
            ]
        )
    if "brute" in rule_name or "login" in rule_name or "auth" in rule_name:
        recommendations.extend(
            [
                "Check failed and successful authentication sequence for the same account and source IP.",
                "Reset credentials or disable the account if the source cannot be confirmed as legitimate.",
            ]
        )
    if any(token in f"{rule_name} {category_text} {rule_text}" for token in ("ssh", "login", "auth", "credential", "t1078", "t1110")):
        recommendations.extend(
            [
                "Pivot by user, source IP and destination host to determine whether the activity is isolated or distributed.",
                "Compare the source address with approved administration networks and VPN ranges.",
            ]
        )
    if any(token in f"{rule_name} {category_text} {rule_text}" for token in ("network", "dns", "port scan", "suricata", "doh", "dot", "destination")):
        recommendations.extend(
            [
                "Review source and destination IP addresses, ports, DNS names and whether the traffic matches allowed network policy.",
                "If the destination is external or reputation is unknown, pivot to recent events for the same destination.",
            ]
        )
    if any(token in f"{rule_name} {category_text} {rule_text}" for token in ("pve", "proxmox", "service", "standby", "writer", "pipeline")):
        recommendations.extend(
            [
                "Check the affected platform service status and recent administrative changes on the corresponding node.",
                "Validate whether the event came from planned maintenance before suppressing or closing it.",
            ]
        )
    if "defender" in rule_name or "evasion" in rule_name:
        recommendations.append("Verify whether protection settings were weakened and restore the expected Defender policy if needed.")
    for rule in rules or []:
        description = str(rule.get("description") or "").strip()
        if description and len(description) >= 24:
            recommendations.append(description)
    return _unique_texts(recommendations)[:10]


def _incident_summary(
    selected: Dict[str, Any],
    raw_alerts: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    commands: List[Dict[str, Any]],
    risk: Dict[str, Any],
    rules: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    rule_name = str(selected.get("rule_name") or selected.get("title") or "Incident")
    entity = str(selected.get("entity_key") or selected.get("agg_id") or "not defined")
    event_count = int(selected.get("count_events") or selected.get("raw_hits_total") or sum(int(row.get("hits") or 0) for row in raw_alerts))
    alert_count = int(selected.get("count_alerts") or len(raw_alerts))
    time_range = f"{selected.get('ts_first') or selected.get('ts') or ''} - {selected.get('ts_last') or selected.get('ts') or ''}"
    rule_meta = (rules or [{}])[0] if rules else {}
    rule_description = str(rule_meta.get("description") or _context_value((raw_alerts[0].get("context") if raw_alerts else {}) or {}, "description") or "").strip()
    rule_logic = str(rule_meta.get("logic_summary") or "").strip()
    mitre_tactic = str(rule_meta.get("mitre_tactic") or "").strip()
    mitre_technique = str(rule_meta.get("mitre_technique") or "").strip()
    source_category = str(rule_meta.get("source_category") or _context_value((raw_alerts[0].get("context") if raw_alerts else {}) or {}, "category", "event_type") or "").strip()
    indicators = [
        f"{alert_count} raw alerts",
        f"{event_count} source events",
        f"{len(events)} related events loaded",
        f"{len(commands)} command lines extracted",
    ]
    if source_category:
        indicators.append(f"source category: {source_category}")
    if rule_logic:
        indicators.append(f"logic: {rule_logic[:180]}")
    return {
        "description": rule_description or f"{rule_name} was triggered for {entity}. The incident contains {alert_count} raw alerts and {event_count} source events.",
        "trigger_reason": (
            f"Rule '{rule_name}' matched with threshold {display_threshold} in {display_window} and grouping by {display_group}."
            if (display_threshold := str(rule_meta.get("threshold") or "").strip())
            and (display_window := str(rule_meta.get("window_s") or "").strip())
            and (display_group := str(rule_meta.get("group_by") or "").strip())
            else f"Correlation threshold/logic for rule '{rule_name}' matched grouped activity for the main entity."
        ),
        "key_indicators": indicators,
        "main_entity": entity,
        "unique_entities": int(selected.get("unique_entities") or 1),
        "time_range": time_range,
        "mitre_tactic": mitre_tactic or ("Execution" if commands else "Not mapped"),
        "mitre_technique": mitre_technique or ("Command and Scripting Interpreter" if commands else "Not mapped"),
        "business_risk": "Possible unauthorized execution or account/host compromise." if risk.get("risk_score", 0) >= 80 else "Requires validation against expected operational activity.",
        "recommended_primary_action": "Review extracted commands and validate whether they are authorized." if commands else "Review raw alerts and related events.",
        "source_category": source_category or "Not defined",
    }


def _incident_timeline(raw_alerts: List[Dict[str, Any]], events: List[Dict[str, Any]], limit: int = 120) -> List[Dict[str, Any]]:
    timeline: List[Dict[str, Any]] = []
    for event in events:
        timeline.append(
            {
                "ts": event.get("ts"),
                "type": event.get("subcategory") or event.get("category") or "event",
                "source": event.get("log_source") or event.get("host_name"),
                "description": str(event.get("message") or "")[:500],
                "entity": event.get("host_name") or event.get("user_name") or event.get("src_ip"),
                "severity": event.get("severity"),
                "rule_id": "",
                "event_id": event.get("event_id"),
            }
        )
    for alert in raw_alerts:
        timeline.append(
            {
                "ts": alert.get("ts_last") or alert.get("ts"),
                "type": "correlation_triggered",
                "source": alert.get("source"),
                "description": alert.get("rule_name"),
                "entity": alert.get("entity_key"),
                "severity": alert.get("severity"),
                "rule_id": alert.get("rule_id"),
                "event_id": alert.get("alert_id"),
            }
        )
    timeline.sort(key=lambda item: str(item.get("ts") or ""))
    return timeline[-max(1, min(int(limit or 120), 500)):]


def _slim_incident_alert(row: Dict[str, Any]) -> Dict[str, Any]:
    context = row.get("context") if isinstance(row.get("context"), dict) else {}
    return {
        "ts": row.get("ts"),
        "alert_id": row.get("alert_id"),
        "rule_id": row.get("rule_id"),
        "rule_name": row.get("rule_name"),
        "severity": row.get("severity"),
        "ts_first": row.get("ts_first"),
        "ts_last": row.get("ts_last"),
        "window_s": row.get("window_s"),
        "entity": row.get("entity") or row.get("entity_key"),
        "entity_key": row.get("entity_key"),
        "group_key": row.get("group_key"),
        "source_event_count": row.get("source_event_count") or row.get("hits"),
        "hits": row.get("hits"),
        "status": row.get("status"),
        "source": row.get("source"),
        "dedup_key": row.get("dedup_key"),
        "assignee": row.get("assignee"),
        "updated_ts": row.get("updated_ts"),
        "context": {
            key: context.get(key)
            for key in (
                "source",
                "host_name",
                "category",
                "event_type",
                "event_action",
                "user_name",
                "target_user",
                "process_name",
                "process_command",
                "description",
            )
            if context.get(key) not in (None, "")
        },
    }


def _slim_incident_event(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "ts": row.get("ts"),
        "event_id": row.get("event_id"),
        "event_code": row.get("event_code"),
        "category": row.get("category"),
        "subcategory": row.get("subcategory"),
        "event_action": row.get("event_action"),
        "event_outcome": row.get("event_outcome"),
        "src_ip": row.get("src_ip"),
        "dst_ip": row.get("dst_ip"),
        "src_port": row.get("src_port"),
        "dst_port": row.get("dst_port"),
        "log_source": row.get("log_source"),
        "host_name": row.get("host_name"),
        "user_name": row.get("user_name"),
        "target_user": row.get("target_user"),
        "process_name": row.get("process_name"),
        "process_executable": row.get("process_executable"),
        "process_command": _mask_sensitive_text(row.get("process_command"))[:1200],
        "severity": row.get("severity"),
        "message": _mask_sensitive_text(row.get("message"))[:1200],
    }


def fetch_incident_detail_bundle(
    view: str,
    record_id: str,
    *,
    window: str = "24h",
    from_ts: str = "",
    to_ts: str = "",
    event_limit: int = 80,
    alert_limit: int = 120,
    include_evidence: bool = True,
) -> Dict[str, Any]:
    safe_view = "raw" if view == "raw" else "agg"
    safe_event_limit = max(1, min(int(event_limit or 80), 250))
    safe_alert_limit = max(1, min(int(alert_limit or 120), 300))
    cache_key = json.dumps(
        [
            safe_view,
            record_id,
            window,
            from_ts,
            to_ts,
            safe_event_limit,
            safe_alert_limit,
            bool(include_evidence),
        ],
        ensure_ascii=False,
        sort_keys=True,
    )
    now_ts = time()
    cached = _INCIDENT_DETAIL_CACHE.get(cache_key)
    if cached and now_ts - cached[0] < 300:
        return dict(cached[1])
    selected = _incident_selected_record(safe_view, record_id, window=window, from_ts=from_ts, to_ts=to_ts)
    if not selected:
        raise ValueError(f"Incident not found: {record_id}")
    raw_alerts = _incident_raw_alert_rows(selected, safe_view, limit=safe_alert_limit)
    related_events_bundle = (
        _incident_related_events(selected, raw_alerts, limit=safe_event_limit)
        if include_evidence
        else {
            "rows": [],
            "row_count": _safe_int(selected.get("count_events"), 0)
            or _safe_int(selected.get("raw_hits_total"), 0),
            "limit": safe_event_limit,
            "query_scope": {},
            "partial": True,
            "errors": ["Evidence is loading asynchronously."],
            "sql": "",
        }
    )
    related_events = related_events_bundle["rows"]
    rules = _incident_rule_rows([int(row.get("rule_id") or 0) for row in raw_alerts] or [int(selected.get("rule_id") or 0)])
    commands = _incident_command_evidence(related_events)
    entities = _incident_entity_summary(selected, raw_alerts, related_events)
    risk = _incident_risk(selected, entities)
    summary = _incident_summary(selected, raw_alerts, related_events, commands, risk, rules)
    timeline = _incident_timeline(raw_alerts, related_events)
    source_ips = _unique_texts([str(row.get("src_ip") or "") for row in related_events if str(row.get("src_ip") or "") not in {"", "0"}])
    destination_ips = _unique_texts([str(row.get("dst_ip") or "") for row in related_events if str(row.get("dst_ip") or "") not in {"", "0"}])
    destination_ports = _unique_texts([str(row.get("dst_port") or "") for row in related_events if str(row.get("dst_port") or "") not in {"", "0"}])
    log_sources = _unique_texts([str(row.get("log_source") or "") for row in related_events if str(row.get("log_source") or "").strip()])
    auth_events = [
        row
        for row in related_events
        if any(
            token in f"{row.get('category')} {row.get('subcategory')} {row.get('event_action')} {row.get('message')}".lower()
            for token in ("auth", "login", "logon", "ssh", "credential", "failed password", "accepted password")
        )
    ]
    process_events = [
        {
            "ts": row.get("ts"),
            "event_id": row.get("event_id"),
            "host_name": row.get("host_name"),
            "user_name": row.get("user_name") or row.get("target_user"),
            "process_name": row.get("process_name"),
            "process_executable": row.get("process_executable"),
            "process_command": _incident_command_from_event(row) or row.get("process_command") or "",
            "message": str(row.get("message") or "")[:1000],
        }
        for row in related_events
        if str(row.get("process_name") or row.get("process_executable") or row.get("process_command") or "").strip()
    ][:50]
    network_context = {
        "source_ips": source_ips,
        "destination_ips": destination_ips,
        "destination_ports": destination_ports,
        "log_sources": log_sources,
        "unique_source_ip_count": len(source_ips),
        "unique_destination_ip_count": len(destination_ips),
        "unique_destination_port_count": len(destination_ports),
        "external_source_ip_count": sum(1 for ip in source_ips if not _is_internal_ip(ip)),
        "external_destination_ip_count": sum(1 for ip in destination_ips if not _is_internal_ip(ip)),
        "ips": entities.get("ips", []),
    }
    authentication_context = {
        "failed_login_count": sum(1 for row in auth_events if "fail" in f"{row.get('event_outcome')} {row.get('message')}".lower() or "invalid" in f"{row.get('message')}".lower()),
        "successful_login_count": sum(1 for row in auth_events if "success" in f"{row.get('event_outcome')} {row.get('message')}".lower() or "accepted" in f"{row.get('message')}".lower()),
        "unique_source_ip_count": network_context["unique_source_ip_count"],
        "unique_host_count": len(entities.get("hosts", [])),
        "users": entities.get("users", []),
        "hosts": entities.get("hosts", []),
        "auth_event_count": len(auth_events),
        "first_auth_event": min((str(row.get("ts") or "") for row in auth_events), default=""),
        "last_auth_event": max((str(row.get("ts") or "") for row in auth_events), default=""),
    }
    process_context = {
        "commands": commands,
        "processes": entities.get("processes", []),
        "process_events": process_events,
        "process_event_count": len(process_events),
    }
    history = fetch_alert_history(safe_view, record_id)
    selected_payload = dict(selected)
    selected_payload.pop("samples_json", None)
    selected_alert_ids = [str(item) for item in selected_payload.pop("alert_ids", []) if str(item).strip()]
    if selected_alert_ids:
        selected_payload["alert_ids_sample"] = selected_alert_ids[:20]
        selected_payload["alert_ids_total"] = len(selected_alert_ids)
    slim_raw_alerts = [_slim_incident_alert(row) for row in raw_alerts]
    slim_related_events = [_slim_incident_event(row) for row in related_events]
    raw_alert_total = max(
        len(raw_alerts),
        _safe_int(selected.get("count_alerts"), 0),
        _safe_int(selected.get("raw_alerts"), 0),
    )
    payload = {
        "view": safe_view,
        "evidence_state": "loaded" if include_evidence else "deferred",
        "item": selected_payload,
        "incident": selected_payload,
        "summary": summary,
        "risk": risk,
        "entities": entities,
        "rules": rules,
        "timeline_preview": timeline[-10:],
        "timeline": timeline,
        "raw_alerts": {
            "items": slim_raw_alerts[: max(1, min(safe_alert_limit, 500))],
            "total": raw_alert_total,
            "limit": safe_alert_limit,
            "offset": 0,
        },
        "related_events": {
            "items": slim_related_events,
            "total": related_events_bundle["row_count"],
            "limit": related_events_bundle["limit"],
            "offset": 0,
            "query_scope": related_events_bundle["query_scope"],
            "partial": bool(related_events_bundle.get("partial")),
            "errors": related_events_bundle.get("errors", []),
        },
        "command_evidence": commands,
        "network_context": network_context,
        "authentication_context": authentication_context,
        "process_context": process_context,
        "recommendations": _incident_recommendations(selected, commands, entities, rules),
        "comments": [],
        "audit_log": history,
        "technical_debug": {
            "agg_id": selected.get("agg_id"),
            "rule_id": selected.get("rule_id"),
            "group_key_json": selected.get("group_key_json"),
            "samples": selected.get("samples"),
            "correlator_instance": "stream/batch runtime",
            "pipeline_stage": "alerts_raw -> alerts_agg -> incident detail bundle",
            "normalizer_id": "",
            "filter_rule_id": "",
            "created_at": selected.get("ts_first") or selected.get("ts"),
            "updated_at": selected.get("updated_ts") or selected.get("ts_last"),
            "raw_query": str(related_events_bundle["sql"] or "")[:4000],
            "evidence_partial": bool(related_events_bundle.get("partial")),
            "evidence_deferred": not include_evidence,
            "evidence_errors": related_events_bundle.get("errors", []),
        },
        "json_view": {
            "incident": selected_payload,
            "alerts_raw": slim_raw_alerts[:50],
            "events": slim_related_events[:50],
            "group_key_json": selected.get("group_key_json"),
            "samples": selected.get("samples"),
            "rule_metadata": rules,
        },
        "permissions": {
            "can_view": True,
            "can_view_raw_events": True,
            "can_view_debug": True,
            "can_change_status": True,
            "can_comment": True,
        },
        "history": history,
        "status_transitions": {key: sorted(values) for key, values in INCIDENT_STATUS_TRANSITIONS.items()},
    }
    _INCIDENT_DETAIL_CACHE[cache_key] = (now_ts, payload)
    if len(_INCIDENT_DETAIL_CACHE) > 32:
        oldest_key = min(_INCIDENT_DETAIL_CACHE, key=lambda key: _INCIDENT_DETAIL_CACHE[key][0])
        _INCIDENT_DETAIL_CACHE.pop(oldest_key, None)
    return dict(payload)


def _sanitize_bucket_minutes(bucket_minutes: int) -> int:
    allowed = (5, 10, 15, 30, 60, 120, 180, 360, 720)
    safe_value = max(5, int(bucket_minutes or 60))
    return min(allowed, key=lambda item: abs(item - safe_value))


def fetch_events_timeseries(hours: int = 24, bucket_minutes: int = 30, *, from_ts: str = "", to_ts: str = "") -> List[Dict[str, Any]]:
    safe_bucket_minutes = _sanitize_bucket_minutes(bucket_minutes)
    time_filter = _time_filter("ts", hours=hours, from_ts=from_ts, to_ts=to_ts)
    operational_filter = _event_operational_filter_sql()
    query = f"""
        SELECT
            toStartOfInterval(ts, INTERVAL {safe_bucket_minutes} minute) AS bucket,
            count() AS cnt
        FROM siem.events
        WHERE {_combine_sql_filters(time_filter, operational_filter)}
        GROUP BY bucket
        ORDER BY bucket ASC
    """
    rows: List[Dict[str, Any]] = []
    result = get_ch_client().query(query)
    for bucket, cnt in result.result_rows:
        bucket_start = _fmt(bucket)
        bucket_end = _fmt(bucket + timedelta(minutes=safe_bucket_minutes)) if hasattr(bucket, "strftime") else bucket_start
        rows.append(
            {
                'bucket': bucket_start,
                'bucket_start': bucket_start,
                'bucket_end': bucket_end,
                'bucket_minutes': safe_bucket_minutes,
                'cnt': int(cnt),
            }
        )
    return rows


def fetch_alert_timeseries(hours: int = 24, bucket_minutes: int = 60, *, from_ts: str = "", to_ts: str = "") -> List[Dict[str, Any]]:
    safe_bucket_minutes = _sanitize_bucket_minutes(bucket_minutes)
    time_filter = _time_filter("ts_last", hours=hours, from_ts=from_ts, to_ts=to_ts)
    operational_filter = _alert_raw_operational_filter_sql()
    query = f"""
        SELECT
            toStartOfInterval(ts_last, INTERVAL {safe_bucket_minutes} minute) AS bucket,
            count() AS cnt
        FROM siem.alerts_raw
        WHERE {_combine_sql_filters(time_filter, operational_filter)}
        GROUP BY bucket
        ORDER BY bucket ASC
    """
    rows: List[Dict[str, Any]] = []
    result = get_ch_client().query(query)
    for bucket, cnt in result.result_rows:
        bucket_start = _fmt(bucket)
        bucket_end = _fmt(bucket + timedelta(minutes=safe_bucket_minutes)) if hasattr(bucket, "strftime") else bucket_start
        rows.append(
            {
                'bucket': bucket_start,
                'bucket_start': bucket_start,
                'bucket_end': bucket_end,
                'bucket_minutes': safe_bucket_minutes,
                'cnt': int(cnt),
            }
        )
    return rows


def fetch_severity_breakdown(hours: int = 24, *, from_ts: str = "", to_ts: str = "") -> List[Dict[str, Any]]:
    time_filter = _time_filter("ts", hours=hours, from_ts=from_ts, to_ts=to_ts)
    operational_filter = _event_operational_filter_sql()
    query = f"""
        SELECT
            lower(severity) AS severity,
            count() AS cnt,
            arraySlice(topK(4)({_event_source_group_expr()}), 1, 4) AS top_sources,
            arraySlice(topK(4)({_event_summary_expr()}), 1, 4) AS top_events
        FROM siem.events
        WHERE {_combine_sql_filters(time_filter, operational_filter)}
        GROUP BY severity
        ORDER BY cnt DESC
    """
    rows: List[Dict[str, Any]] = []
    for row in get_ch_client().query(query).named_results():
        rows.append(
            {
                "severity": str(row.get("severity") or "unknown"),
                "cnt": int(row.get("cnt") or 0),
                "top_sources": [str(item) for item in (row.get("top_sources") or []) if str(item or "").strip()],
                "top_events": [str(item) for item in (row.get("top_events") or []) if str(item or "").strip()],
            }
        )
    return rows


def fetch_alert_severity_breakdown(hours: int = 24, *, from_ts: str = "", to_ts: str = "") -> List[Dict[str, Any]]:
    time_filter = _time_filter("ts", hours=hours, from_ts=from_ts, to_ts=to_ts)
    operational_filter = _alert_raw_operational_filter_sql()
    query = f"""
        SELECT
            lower(severity) AS severity,
            count() AS cnt,
            arraySlice(topK(4)({_alert_source_group_expr()}), 1, 4) AS top_sources,
            arraySlice(topK(4)(rule_name), 1, 4) AS top_events
        FROM siem.alerts_raw
        WHERE {_combine_sql_filters(time_filter, operational_filter)}
        GROUP BY severity
        ORDER BY cnt DESC
    """
    rows: List[Dict[str, Any]] = []
    for row in get_ch_client().query(query).named_results():
        rows.append(
            {
                "severity": str(row.get("severity") or "unknown"),
                "cnt": int(row.get("cnt") or 0),
                "top_sources": [str(item) for item in (row.get("top_sources") or []) if str(item or "").strip()],
                "top_events": [str(item) for item in (row.get("top_events") or []) if str(item or "").strip()],
            }
        )
    return rows


def fetch_alert_status_breakdown(hours: int = 24, *, from_ts: str = "", to_ts: str = "") -> List[Dict[str, Any]]:
    time_filter = _time_filter("ts", hours=hours, from_ts=from_ts, to_ts=to_ts)
    operational_filter = _alert_raw_operational_filter_sql()
    query = f"""
        SELECT
            lower(status) AS status,
            count() AS cnt,
            arraySlice(topK(4)({_alert_source_group_expr()}), 1, 4) AS top_sources,
            arraySlice(topK(4)(rule_name), 1, 4) AS top_events
        FROM siem.alerts_raw
        WHERE {_combine_sql_filters(time_filter, operational_filter)}
        GROUP BY status
        ORDER BY cnt DESC
    """
    rows: List[Dict[str, Any]] = []
    for row in get_ch_client().query(query).named_results():
        rows.append(
            {
                "status": str(row.get("status") or "unknown"),
                "cnt": int(row.get("cnt") or 0),
                "top_sources": [str(item) for item in (row.get("top_sources") or []) if str(item or "").strip()],
                "top_events": [str(item) for item in (row.get("top_events") or []) if str(item or "").strip()],
            }
        )
    return rows


def fetch_top_sources(limit: int = 8, hours: int = 24, *, from_ts: str = "", to_ts: str = "") -> List[Dict[str, Any]]:
    time_filter = _time_filter("ts", hours=hours, from_ts=from_ts, to_ts=to_ts)
    operational_filter = _event_operational_filter_sql()
    query = f"""
        SELECT
            {_event_source_label_expr('log_source')},
            count() AS events,
            max(ts) AS last_seen
        FROM siem.events
        WHERE {_combine_sql_filters(time_filter, operational_filter)}
        GROUP BY log_source
        ORDER BY events DESC
        LIMIT {max(int(limit) * 8, 64)}
    """
    host_index, ip_index = _cmdb_asset_indexes()
    grouped: Dict[str, Dict[str, Any]] = {}
    for row in get_ch_client().query(query).named_results():
        raw_name = str(row['log_source'] or '').strip() or 'unknown'
        canonical_name, _cmdb = _canonical_source_name(raw_name, host_index, ip_index)
        if _contains_non_operational_token(raw_name) or _contains_non_operational_token(canonical_name):
            continue
        entry = grouped.setdefault(
            canonical_name,
            {
                'log_source': canonical_name,
                'events': 0,
                'last_seen': '',
                '_last_seen_dt': None,
            },
        )
        entry['events'] += int(row['events'] or 0)
        last_seen = _fmt(row['last_seen'])
        last_seen_dt = _parse_fmt_ts(last_seen)
        if last_seen_dt and (entry['_last_seen_dt'] is None or last_seen_dt > entry['_last_seen_dt']):
            entry['_last_seen_dt'] = last_seen_dt
            entry['last_seen'] = last_seen
    rows = list(grouped.values())
    rows.sort(key=lambda item: (-int(item['events']), str(item['log_source'])))
    for row in rows:
        row.pop('_last_seen_dt', None)
    return rows[: int(limit)]


def fetch_top_target_ports(limit: int = 8, hours: int = 24, *, from_ts: str = "", to_ts: str = "") -> List[Dict[str, Any]]:
    # This widget is an overview cue, not a forensic report. Capping the live
    # scan prevents a 7-day dashboard refresh from blocking the whole page.
    effective_hours = min(max(int(hours or 24), 1), 24) if not (from_ts or to_ts) else max(int(hours or 24), 1)
    time_filter = _time_filter("ts", hours=effective_hours, from_ts=from_ts, to_ts=to_ts)
    operational_filter = _event_operational_filter_sql()
    query = f"""
        SELECT
            port_value,
            count() AS attempts,
            uniqCombined64(if(source_ip_text != '', source_ip_text, 'unknown')) AS unique_sources,
            max(ts) AS last_seen,
            countIf(category = 'authentication') AS auth_attempts,
            countIf(subcategory = 'linux_firewall_blocked') AS firewall_hits,
            arrayStringConcat(groupUniqArray(5)(if(source_ip_text != '', source_ip_text, 'unknown')), ',') AS source_sample
        FROM
        (
            SELECT
                ts,
                category,
                subcategory,
                device_product,
                if(src_ip = 0, '', IPv4NumToString(src_ip)) AS source_ip_text,
                if(
                    dst_port = 0
                    AND (
                        device_product = 'linux.sshd'
                        OR subcategory IN ('ssh_login_success', 'ssh_login_failure', 'ssh_invalid_user', 'linux_root_ssh_login')
                    ),
                    22,
                    dst_port
                ) AS port_value
            FROM siem.events
            WHERE {_combine_sql_filters(time_filter, operational_filter)}
              AND (
                    subcategory = 'linux_firewall_blocked'
                    OR device_product = 'linux.sshd'
                    OR subcategory IN ('ssh_login_success', 'ssh_login_failure', 'ssh_invalid_user', 'linux_root_ssh_login', 'audit_user_login_failure', 'audit_user_err')
              )
        )
        WHERE port_value > 0
        GROUP BY port_value
        ORDER BY attempts DESC
        LIMIT {int(limit)}
    """
    rows: List[Dict[str, Any]] = []
    for row in get_ch_client().query(query).named_results():
        port_value = int(row["port_value"] or 0)
        auth_attempts = int(row["auth_attempts"] or 0)
        firewall_hits = int(row["firewall_hits"] or 0)
        signal = "password spray / auth probing" if auth_attempts else "network scan / blocked probe" if firewall_hits else "service connection attempts"
        rows.append(
            {
                "dst_port": port_value,
                "service": COMMON_SERVICE_PORTS.get(port_value, "custom"),
                "attempts": int(row["attempts"] or 0),
                "unique_sources": int(row["unique_sources"] or 0),
                "last_seen": _fmt(row["last_seen"]),
                "signal": signal,
                "source_sample": [part for part in str(row["source_sample"] or "").split(",") if part],
            }
        )
    return rows


def fetch_top_vpn_sites(limit: int = 8, hours: int = 24, *, from_ts: str = "", to_ts: str = "") -> List[Dict[str, Any]]:
    time_filter = _time_filter("ts", hours=hours, from_ts=from_ts, to_ts=to_ts)
    operational_filter = _event_operational_filter_sql()
    query = f"""
        SELECT
            ts,
            message,
            if(src_ip = 0, '', IPv4NumToString(src_ip)) AS client_ip,
            extract(message, 'email:\\s*([^,\\s]+)') AS client_id
        FROM siem.events
        WHERE {_combine_sql_filters(time_filter, operational_filter)}
          AND (
              device_product = 'vpn.xray'
              OR subcategory = 'vpn_proxy_access'
              OR positionCaseInsensitiveUTF8(message, 'accepted tcp:') > 0
              OR positionCaseInsensitiveUTF8(message, 'accepted udp:') > 0
              OR positionCaseInsensitiveUTF8(message, 'accepted //') > 0
          )
        ORDER BY ts DESC
        LIMIT {max(int(limit) * 800, 8000)}
    """
    aggregated: Dict[str, Dict[str, Any]] = {}
    try:
        for row in get_ch_client().query(query).named_results():
            domain = _extract_vpn_destination_host(str(row.get("message") or ""))
            if not domain or domain == "127.0.0.1":
                continue
            item = aggregated.setdefault(
                domain,
                {
                    "domain": domain,
                    "client_id": "",
                    "visits": 0,
                    "client_ips": set(),
                    "last_seen_raw": None,
                },
            )
            item["visits"] += 1
            client_ip = str(row.get("client_ip") or "").strip()
            if client_ip:
                item["client_ips"].add(client_ip)
            client_id = str(row.get("client_id") or "").strip()
            if client_id and not item["client_id"]:
                item["client_id"] = client_id
            row_ts = row.get("ts")
            if item["last_seen_raw"] is None or (row_ts is not None and row_ts > item["last_seen_raw"]):
                item["last_seen_raw"] = row_ts
    except Exception:
        return []
    rows = [
        {
            "domain": str(item["domain"] or ""),
            "client_id": str(item["client_id"] or ""),
            "visits": int(item["visits"] or 0),
            "unique_clients": len(item["client_ips"]),
            "last_seen": _fmt(item["last_seen_raw"]),
        }
        for item in aggregated.values()
    ]
    rows.sort(key=lambda item: (-int(item["visits"] or 0), str(item["domain"] or "")))
    return rows[: int(limit)]


def fetch_top_categories(limit: int = 8, hours: int = 24, *, from_ts: str = "", to_ts: str = "") -> List[Dict[str, Any]]:
    time_filter = _time_filter("ts", hours=hours, from_ts=from_ts, to_ts=to_ts)
    operational_filter = _event_operational_filter_sql()
    query = f"""
        SELECT category, count() AS events
        FROM siem.events
        WHERE {_combine_sql_filters(time_filter, operational_filter)}
        GROUP BY category
        ORDER BY events DESC
        LIMIT {int(limit)}
    """
    rows: List[Dict[str, Any]] = []
    for category, events in get_ch_client().query(query).result_rows:
        rows.append({'category': str(category or 'unknown'), 'events': int(events)})
    return rows


def fetch_dashboard_metrics() -> Dict[str, Any]:
    global _DASHBOARD_METRICS_CACHE
    now_ts = time()
    if _DASHBOARD_METRICS_CACHE and now_ts - _DASHBOARD_METRICS_CACHE[0] < 30:
        return dict(_DASHBOARD_METRICS_CACHE[1])
    event_source_expr = "if(host_name != '' AND host_name != '-', host_name, log_source)"
    event_operational_filter = _event_operational_filter_sql()
    alert_operational_filter = _alert_agg_operational_filter_sql()
    event_query = f"""
        SELECT
            count() AS events_24h,
            countIf(ts >= now() - INTERVAL 1 HOUR) AS events_1h,
            countIf(ts >= now() - INTERVAL 24 HOUR AND lower(severity) = 'critical') AS critical_events_24h,
            countDistinctIf({event_source_expr}, {event_source_expr} != '') AS active_sources_24h,
            countIf(ts >= now() - INTERVAL 24 HOUR AND (device_product = 'linux.auditd' OR category = 'auditd' OR positionCaseInsensitiveUTF8(tags, 'linux-audit') > 0)) AS audit_events_24h,
            countIf(ts >= now() - INTERVAL 24 HOUR AND ti_indicator != '') AS ti_hits_24h,
            countDistinctIf(asset_id, ts >= now() - INTERVAL 24 HOUR AND lower(asset_criticality) IN ('high', 'critical') AND asset_id != '') AS critical_assets_observed_24h
        FROM siem.events
        WHERE {_combine_sql_filters("ts >= now() - INTERVAL 24 HOUR", event_operational_filter)}
    """
    alert_query = f"""
        SELECT
            countIf(lower(status) NOT IN ('closed', 'false_positive')) AS open_incidents_24h,
            countIf(lower(status) = 'new') AS new_alerts_24h
        FROM siem.alerts_agg
        WHERE {_combine_sql_filters("ts_last >= now() - INTERVAL 24 HOUR", alert_operational_filter)}
    """
    event_row = next(iter(get_ch_client().query(event_query).named_results()), {})
    alert_row = next(iter(get_ch_client().query(alert_query).named_results()), {})
    result = {
        "events_24h": int(event_row.get("events_24h") or 0),
        "events_1h": int(event_row.get("events_1h") or 0),
        "open_incidents_24h": int(alert_row.get("open_incidents_24h") or 0),
        "new_alerts_24h": int(alert_row.get("new_alerts_24h") or 0),
        "critical_events_24h": int(event_row.get("critical_events_24h") or 0),
        "active_sources_24h": int(event_row.get("active_sources_24h") or 0),
        "audit_events_24h": int(event_row.get("audit_events_24h") or 0),
        "ti_hits_24h": int(event_row.get("ti_hits_24h") or 0),
        "critical_assets_observed_24h": int(event_row.get("critical_assets_observed_24h") or 0),
    }
    _DASHBOARD_METRICS_CACHE = (now_ts, result)
    return dict(result)


def fetch_alert_metrics() -> Dict[str, Any]:
    global _ALERT_METRICS_CACHE
    now_ts = time()
    if _ALERT_METRICS_CACHE and now_ts - _ALERT_METRICS_CACHE[0] < 15:
        return dict(_ALERT_METRICS_CACHE[1])
    operational_filter = _alert_raw_operational_filter_sql()
    metrics_query = f"""
        SELECT
            uniqExact(concat(toString(rule_id), ':', ifNull(entity_key, ''), ':', ifNull(source, ''))) AS agg_total,
            uniqExactIf(concat(toString(rule_id), ':', ifNull(entity_key, ''), ':', ifNull(source, '')), lower(status) NOT IN ('closed', 'false_positive')) AS agg_open,
            count() AS raw_total,
            countIf(lower(severity) = 'critical') AS critical_raw,
            countIf(lower(status) = 'new') AS new_raw
        FROM siem.alerts_raw
        WHERE {operational_filter}
    """
    row = next(iter(get_ch_client().query(metrics_query).named_results()), {})
    result = {
        'agg_total': int(row.get('agg_total') or 0),
        'agg_open': int(row.get('agg_open') or 0),
        'raw_total': int(row.get('raw_total') or 0),
        'critical_raw': int(row.get('critical_raw') or 0),
        'new_raw': int(row.get('new_raw') or 0),
    }
    _ALERT_METRICS_CACHE = (now_ts, result)
    return dict(result)


def fetch_recent_alerts(limit: int = 10, *, from_ts: str = "", to_ts: str = "") -> List[Dict[str, Any]]:
    safe_limit = max(1, min(int(limit or 10), 60))
    time_filter = _time_filter("ts_last", window="24h", from_ts=from_ts, to_ts=to_ts)
    operational_filter = _alert_agg_operational_filter_sql()
    query = f"""
        SELECT
            ts,
            toString(agg_id) AS agg_id,
            rule_id,
            rule_name,
            lower(severity_agg) AS severity,
            ts_first,
            ts_last,
            count_alerts,
            unique_entities,
            entity_key,
            status,
            assignee,
            updated_ts
        FROM siem.alerts_agg
        WHERE {_combine_sql_filters(time_filter, operational_filter)}
        ORDER BY ts_last DESC
        LIMIT {safe_limit}
    """
    rows: List[Dict[str, Any]] = []
    for row in get_ch_client().query(query).named_results():
        entity = str(row["entity_key"] or "")
        item = {
            "ts": _fmt(row["ts"]),
            "alert_id": str(row["agg_id"]),
            "agg_id": str(row["agg_id"]),
            "record_id": str(row["agg_id"]),
            "rule_id": int(row["rule_id"]),
            "rule_name": str(row["rule_name"] or ""),
            "title": str(row["rule_name"] or ""),
            "severity": str(row["severity"] or "info").lower(),
            "severity_agg": str(row["severity"] or "info").lower(),
            "ts_first": _fmt(row["ts_first"]),
            "ts_last": _fmt(row["ts_last"]),
            "count_alerts": int(row["count_alerts"] or 0),
            "count_events": int(row["count_alerts"] or 0),
            "unique_entities": int(row["unique_entities"] or 0),
            "entity_key": entity,
            "source": entity,
            "source_summary": entity,
            "host_summary": entity,
            "status": str(row["status"] or "new").lower(),
            "assignee": str(row.get("assignee") or ""),
            "updated_ts": _fmt(row.get("updated_ts")),
        }
        if not _is_non_operational_alert_row(item):
            rows.append(item)
    return rows


def fetch_vulnerability_reports(limit: int = 100, days: int = 14) -> List[Dict[str, Any]]:
    operational_filter = _event_operational_filter_sql()
    query = f"""
        SELECT
            event_code AS report_id,
            min(ts) AS ts_first,
            max(ts) AS ts_last,
            countIf((event_action = 'finding') OR (positionCaseInsensitiveUTF8(message, 'Open service ') = 1)) AS findings_total,
            countDistinctIf(dst_ip, ((event_action = 'finding') OR (positionCaseInsensitiveUTF8(message, 'Open service ') = 1)) AND dst_ip != 0) AS target_count,
            countDistinctIf(dst_port, ((event_action = 'finding') OR (positionCaseInsensitiveUTF8(message, 'Open service ') = 1)) AND dst_port > 0) AS unique_ports,
            countIf((((lower(severity) IN ('critical', 'high')) OR (dst_port IN (23, 3389, 5900, 8728))) AND ((event_action = 'finding') OR (positionCaseInsensitiveUTF8(message, 'Open service ') = 1)))) AS notable_findings,
            maxIf(message, (event_action = 'summary') OR (positionCaseInsensitiveUTF8(message, 'Nmap scan ') = 1)) AS summary_message,
            anyLast(log_source) AS scanner_source,
            groupUniqArrayIf(8)(if(dst_ip = 0, '', IPv4NumToString(dst_ip)), ((event_action = 'finding') OR (positionCaseInsensitiveUTF8(message, 'Open service ') = 1)) AND dst_ip != 0) AS targets,
            groupUniqArrayIf(10)(toString(dst_port), ((event_action = 'finding') OR (positionCaseInsensitiveUTF8(message, 'Open service ') = 1)) AND dst_port > 0) AS ports
        FROM siem.events
        WHERE {_combine_sql_filters(f"ts >= now() - INTERVAL {int(days)} DAY", operational_filter)}
          AND event_code != ''
          AND (
              category = 'vulnerability'
              OR device_product = 'nmap'
              OR positionCaseInsensitiveUTF8(event_code, 'nmap-') = 1
          )
        GROUP BY report_id
        ORDER BY ts_last DESC
        LIMIT {int(limit)}
    """
    rows: List[Dict[str, Any]] = []
    for row in get_ch_client().query(query).named_results():
        rows.append(
            {
                "report_id": str(row["report_id"] or ""),
                "ts_first": _fmt(row["ts_first"]),
                "ts_last": _fmt(row["ts_last"]),
                "findings_total": int(row["findings_total"] or 0),
                "target_count": int(row["target_count"] or 0),
                "unique_ports": int(row["unique_ports"] or 0),
                "notable_findings": int(row["notable_findings"] or 0),
                "summary_message": str(row["summary_message"] or ""),
                "scanner_source": str(row["scanner_source"] or "nmap"),
                "targets": [str(item) for item in (row["targets"] or []) if str(item or "").strip()],
                "ports": [str(item) for item in (row["ports"] or []) if str(item or "").strip()],
                "artifact_link": f"/api/reports/{str(row['report_id'] or '')}/artifact",
            }
        )
    return rows


def fetch_vulnerability_report_details(report_id: str, limit: int = 200) -> Dict[str, Any]:
    safe_id = (report_id or "").strip()
    if not safe_id:
        raise ValueError("report_id is required")
    operational_filter = _event_operational_filter_sql()
    query = f"""
        SELECT
            ts,
            log_source,
            host_name,
            if(dst_ip = 0, '', IPv4NumToString(dst_ip)) AS dst_ip,
            dst_port,
            severity,
            event_action,
            process_name,
            process_command,
            message,
            tags
        FROM siem.events
        WHERE event_code = {_sql_quote(safe_id)}
          AND {operational_filter}
          AND (
              category = 'vulnerability'
              OR device_product = 'nmap'
              OR positionCaseInsensitiveUTF8(event_code, 'nmap-') = 1
          )
        ORDER BY ts DESC
        LIMIT {int(limit)}
    """
    findings: List[Dict[str, Any]] = []
    summary_message = ""
    scanner_source = ""
    for row in get_ch_client().query(query).named_results():
        event_action = str(row["event_action"] or "")
        if event_action == "summary" and not summary_message:
            summary_message = str(row["message"] or "")
            scanner_source = str(row["log_source"] or row["host_name"] or "")
            continue
        findings.append(
            {
                "ts": _fmt(row["ts"]),
                "source": str(row["log_source"] or row["host_name"] or ""),
                "dst_ip": str(row["dst_ip"] or ""),
                "dst_port": int(row["dst_port"] or 0),
                "severity": str(row["severity"] or "info").lower(),
                "event_action": event_action or "finding",
                "process_name": str(row["process_name"] or ""),
                "process_command": str(row["process_command"] or ""),
                "message": str(row["message"] or ""),
                "tags": [part for part in str(row["tags"] or "").split(",") if part],
            }
        )
    target_count = len({item["dst_ip"] for item in findings if item["dst_ip"]})
    port_count = len({item["dst_port"] for item in findings if item["dst_port"]})
    cves: List[str] = []
    for item in findings:
        for match in re.findall(r"CVE-\d{4}-\d{4,7}", str(item.get("message") or ""), flags=re.IGNORECASE):
            safe_match = match.upper()
            if safe_match not in cves:
                cves.append(safe_match)
    return {
        "report_id": safe_id,
        "summary_message": summary_message,
        "scanner_source": scanner_source or "nmap",
        "finding_count": len(findings),
        "target_count": target_count,
        "port_count": port_count,
        "cves": cves,
        "targets": sorted({item["dst_ip"] for item in findings if item["dst_ip"]}),
        "ports": sorted({str(item["dst_port"]) for item in findings if item["dst_port"]}),
        "artifact_link": f"/api/reports/{safe_id}/artifact",
        "findings": findings,
    }


def _vulnerability_filter_clause(days: int = 30) -> str:
    scope_filter = (
        "category = 'vulnerability' "
        "OR device_product = 'nmap' "
        "OR positionCaseInsensitiveUTF8(event_code, 'nmap-') = 1"
    )
    return _combine_sql_filters(
        f"ts >= now() - INTERVAL {int(days)} DAY",
        _event_operational_filter_sql(),
        f"({scope_filter})",
    )


def fetch_vulnerability_inventory(days: int = 30, limit: int = 25) -> Dict[str, Any]:
    where_clause = _vulnerability_filter_clause(days)
    target_expr = (
        "if(match(toString(dst_ip), '^[0-9]+$') AND toString(dst_ip) != '0', "
        "IPv4NumToString(toUInt32(toString(dst_ip))), "
        "if(toString(dst_ip) != '' AND toString(dst_ip) != '0', toString(dst_ip), if(host_name != '', host_name, log_source)))"
    )
    hosts_query = f"""
        SELECT
            {target_expr} AS target,
            count() AS findings,
            countDistinctIf(dst_port, dst_port > 0) AS open_ports,
            max(ts) AS last_seen,
            groupUniqArray(6)(if(process_name != '', process_name, if(device_product != '', device_product, 'unknown'))) AS services
        FROM siem.events
        WHERE {where_clause}
          AND ((event_action = 'finding') OR (positionCaseInsensitiveUTF8(message, 'open service ') > 0))
          AND target != ''
        GROUP BY target
        ORDER BY findings DESC, last_seen DESC
        LIMIT {int(limit)}
    """
    services_query = f"""
        SELECT
            lower(if(process_name != '', process_name, if(device_product != '', device_product, 'unknown'))) AS service,
            count() AS findings,
            countDistinct({target_expr}) AS hosts,
            max(ts) AS last_seen,
            groupUniqArray(6)(toString(dst_port)) AS ports
        FROM siem.events
        WHERE {where_clause}
          AND ((event_action = 'finding') OR (positionCaseInsensitiveUTF8(message, 'open service ') > 0))
          AND service != ''
        GROUP BY service
        ORDER BY findings DESC, last_seen DESC
        LIMIT {int(limit)}
    """
    cves_query = f"""
        SELECT
            upper(arrayJoin(extractAll(message, 'CVE-\\\\d{{4}}-\\\\d{{4,7}}'))) AS cve,
            count() AS findings,
            max(ts) AS last_seen,
            groupUniqArray(6)({target_expr}) AS hosts
        FROM siem.events
        WHERE {where_clause}
          AND positionCaseInsensitiveUTF8(message, 'CVE-') > 0
        GROUP BY cve
        HAVING cve != ''
        ORDER BY findings DESC, last_seen DESC
        LIMIT {int(limit)}
    """
    summary_query = f"""
        SELECT
            countIf((event_action = 'finding') OR (positionCaseInsensitiveUTF8(message, 'open service ') > 0)) AS findings,
            countDistinctIf({target_expr}, ((event_action = 'finding') OR (positionCaseInsensitiveUTF8(message, 'open service ') > 0))) AS targets,
            countDistinctIf(dst_port, ((event_action = 'finding') OR (positionCaseInsensitiveUTF8(message, 'open service ') > 0)) AND dst_port > 0) AS ports,
            countDistinctIf(event_code, event_code != '') AS reports
        FROM siem.events
        WHERE {where_clause}
    """

    hosts = [
        {
            "target": str(row["target"] or ""),
            "findings": int(row["findings"] or 0),
            "open_ports": int(row["open_ports"] or 0),
            "last_seen": _fmt(row["last_seen"]),
            "services": [str(item) for item in (row["services"] or []) if str(item or "").strip()],
        }
        for row in get_ch_client().query(hosts_query).named_results()
    ]
    services = [
        {
            "service": str(row["service"] or "unknown"),
            "findings": int(row["findings"] or 0),
            "hosts": int(row["hosts"] or 0),
            "last_seen": _fmt(row["last_seen"]),
            "ports": [str(item) for item in (row["ports"] or []) if str(item or "").strip() and str(item) != "0"],
        }
        for row in get_ch_client().query(services_query).named_results()
    ]
    cves = [
        {
            "cve": str(row["cve"] or ""),
            "findings": int(row["findings"] or 0),
            "last_seen": _fmt(row["last_seen"]),
            "hosts": [str(item) for item in (row["hosts"] or []) if str(item or "").strip()],
        }
        for row in get_ch_client().query(cves_query).named_results()
    ]
    summary_row = next(iter(get_ch_client().query(summary_query).named_results()), None) or {}
    return {
        "summary": {
            "findings": int(summary_row.get("findings") or 0),
            "targets": int(summary_row.get("targets") or 0),
            "ports": int(summary_row.get("ports") or 0),
            "reports": int(summary_row.get("reports") or 0),
        },
        "hosts": hosts,
        "services": services,
        "cves": cves,
    }


def search_vulnerability_findings(query_text: str = "", days: int = 30, limit: int = 120) -> Dict[str, Any]:
    token = str(query_text or "").strip()
    where_clause = _vulnerability_filter_clause(days)
    target_expr = (
        "if(match(toString(dst_ip), '^[0-9]+$') AND toString(dst_ip) != '0', "
        "IPv4NumToString(toUInt32(toString(dst_ip))), "
        "if(toString(dst_ip) != '' AND toString(dst_ip) != '0', toString(dst_ip), ''))"
    )
    search_clause = "1"
    if token:
        quoted = _sql_quote(token)
        search_clause = (
            f"("
            f"positionCaseInsensitiveUTF8(message, {quoted}) > 0 "
            f"OR positionCaseInsensitiveUTF8(log_source, {quoted}) > 0 "
            f"OR positionCaseInsensitiveUTF8(host_name, {quoted}) > 0 "
            f"OR positionCaseInsensitiveUTF8(process_name, {quoted}) > 0 "
            f"OR positionCaseInsensitiveUTF8(process_command, {quoted}) > 0 "
            f"OR positionCaseInsensitiveUTF8({target_expr}, {quoted}) > 0 "
            f"OR positionCaseInsensitiveUTF8(toString(dst_port), {quoted}) > 0 "
            f"OR positionCaseInsensitiveUTF8(event_code, {quoted}) > 0"
            f")"
        )
    sql = f"""
        SELECT
            ts,
            event_code AS report_id,
            log_source,
            host_name,
            {target_expr} AS dst_ip,
            dst_port,
            lower(severity) AS severity,
            if(process_name != '', process_name, if(device_product != '', device_product, 'unknown')) AS service,
            message
        FROM siem.events
        WHERE {where_clause}
          AND ((event_action = 'finding') OR (positionCaseInsensitiveUTF8(message, 'open service ') > 0))
          AND ({search_clause})
        ORDER BY ts DESC
        LIMIT {int(limit)}
    """
    rows = []
    for row in get_ch_client().query(sql).named_results():
        message = str(row["message"] or "")
        cves = []
        for match in re.findall(r"CVE-\d{4}-\d{4,7}", message, flags=re.IGNORECASE):
            normalized = match.upper()
            if normalized not in cves:
                cves.append(normalized)
        rows.append(
            {
                "ts": _fmt(row["ts"]),
                "report_id": str(row["report_id"] or ""),
                "source": str(row["log_source"] or ""),
                "host_name": str(row["host_name"] or ""),
                "dst_ip": str(row["dst_ip"] or ""),
                "dst_port": int(row["dst_port"] or 0),
                "severity": str(row["severity"] or "info"),
                "service": str(row["service"] or "unknown"),
                "message": message,
                "cves": cves,
            }
        )
    return {
        "query": token,
        "row_count": len(rows),
        "items": rows,
    }


def _vulnerability_search_clause(token: str, target_expr: str, service_expr: str) -> str:
    safe_token = str(token or "").strip()
    if not safe_token:
        return "1"
    quoted = _sql_quote(safe_token)
    return (
        f"("
        f"positionCaseInsensitiveUTF8(message, {quoted}) > 0 "
        f"OR positionCaseInsensitiveUTF8(log_source, {quoted}) > 0 "
        f"OR positionCaseInsensitiveUTF8(host_name, {quoted}) > 0 "
        f"OR positionCaseInsensitiveUTF8({target_expr}, {quoted}) > 0 "
        f"OR positionCaseInsensitiveUTF8({service_expr}, {quoted}) > 0 "
        f"OR positionCaseInsensitiveUTF8(toString(dst_port), {quoted}) > 0 "
        f"OR positionCaseInsensitiveUTF8(event_code, {quoted}) > 0"
        f")"
    )


def fetch_vulnerability_hosts(query_text: str = "", days: int = 30, limit: int = 120) -> Dict[str, Any]:
    where_clause = _vulnerability_filter_clause(days)
    target_expr = (
        "if(match(toString(dst_ip), '^[0-9]+$') AND toString(dst_ip) != '0', "
        "IPv4NumToString(toUInt32(toString(dst_ip))), "
        "if(toString(dst_ip) != '' AND toString(dst_ip) != '0', toString(dst_ip), if(host_name != '', host_name, log_source)))"
    )
    service_expr = "lower(if(process_name != '', process_name, if(device_product != '', device_product, 'unknown')))"
    sql = f"""
        SELECT
            {target_expr} AS target,
            count() AS findings,
            countDistinctIf(dst_port, dst_port > 0) AS open_ports,
            countDistinctIf(event_code, event_code != '') AS reports,
            max(ts) AS last_seen,
            groupUniqArray(8)({service_expr}) AS services,
            groupUniqArray(8)(toString(dst_port)) AS ports
        FROM siem.events
        WHERE {where_clause}
          AND ((event_action = 'finding') OR (positionCaseInsensitiveUTF8(message, 'open service ') > 0))
          AND ({_vulnerability_search_clause(query_text, target_expr, service_expr)})
          AND target != ''
        GROUP BY target
        ORDER BY findings DESC, last_seen DESC
        LIMIT {int(limit)}
    """
    rows = [
        {
            "target": str(row["target"] or ""),
            "findings": int(row["findings"] or 0),
            "open_ports": int(row["open_ports"] or 0),
            "reports": int(row["reports"] or 0),
            "last_seen": _fmt(row["last_seen"]),
            "services": [str(item) for item in (row["services"] or []) if str(item or "").strip()],
            "ports": [str(item) for item in (row["ports"] or []) if str(item or "").strip() and str(item) != "0"],
        }
        for row in get_ch_client().query(sql).named_results()
    ]
    return {"query": str(query_text or "").strip(), "row_count": len(rows), "items": rows}


def fetch_vulnerability_software(query_text: str = "", days: int = 30, limit: int = 120) -> Dict[str, Any]:
    where_clause = _vulnerability_filter_clause(days)
    target_expr = (
        "if(match(toString(dst_ip), '^[0-9]+$') AND toString(dst_ip) != '0', "
        "IPv4NumToString(toUInt32(toString(dst_ip))), "
        "if(toString(dst_ip) != '' AND toString(dst_ip) != '0', toString(dst_ip), if(host_name != '', host_name, log_source)))"
    )
    service_expr = "lower(if(process_name != '', process_name, if(device_product != '', device_product, 'unknown')))"
    sql = f"""
        SELECT
            {service_expr} AS service,
            count() AS findings,
            countDistinct({target_expr}) AS hosts,
            countDistinctIf(event_code, event_code != '') AS reports,
            max(ts) AS last_seen,
            groupUniqArray(8)({target_expr}) AS host_samples,
            groupUniqArray(8)(toString(dst_port)) AS ports
        FROM siem.events
        WHERE {where_clause}
          AND ((event_action = 'finding') OR (positionCaseInsensitiveUTF8(message, 'open service ') > 0))
          AND ({_vulnerability_search_clause(query_text, target_expr, service_expr)})
          AND service != ''
        GROUP BY service
        ORDER BY findings DESC, last_seen DESC
        LIMIT {int(limit)}
    """
    rows = [
        {
            "service": str(row["service"] or "unknown"),
            "findings": int(row["findings"] or 0),
            "hosts": int(row["hosts"] or 0),
            "reports": int(row["reports"] or 0),
            "last_seen": _fmt(row["last_seen"]),
            "host_samples": [str(item) for item in (row["host_samples"] or []) if str(item or "").strip()],
            "ports": [str(item) for item in (row["ports"] or []) if str(item or "").strip() and str(item) != "0"],
        }
        for row in get_ch_client().query(sql).named_results()
    ]
    return {"query": str(query_text or "").strip(), "row_count": len(rows), "items": rows}


def fetch_vulnerability_cves(query_text: str = "", days: int = 30, limit: int = 120) -> Dict[str, Any]:
    where_clause = _vulnerability_filter_clause(days)
    target_expr = (
        "if(match(toString(dst_ip), '^[0-9]+$') AND toString(dst_ip) != '0', "
        "IPv4NumToString(toUInt32(toString(dst_ip))), "
        "if(toString(dst_ip) != '' AND toString(dst_ip) != '0', toString(dst_ip), if(host_name != '', host_name, log_source)))"
    )
    service_expr = "lower(if(process_name != '', process_name, if(device_product != '', device_product, 'unknown')))"
    safe_token = str(query_text or "").strip()
    search_clause = "1"
    if safe_token:
        quoted = _sql_quote(safe_token)
        search_clause = (
            f"("
            f"positionCaseInsensitiveUTF8(message, {quoted}) > 0 "
            f"OR positionCaseInsensitiveUTF8({target_expr}, {quoted}) > 0 "
            f"OR positionCaseInsensitiveUTF8({service_expr}, {quoted}) > 0 "
            f"OR positionCaseInsensitiveUTF8(event_code, {quoted}) > 0"
            f")"
        )
    sql = f"""
        SELECT
            upper(arrayJoin(extractAll(message, 'CVE-\\\\d{{4}}-\\\\d{{4,7}}'))) AS cve,
            count() AS findings,
            countDistinct({target_expr}) AS hosts,
            countDistinctIf(event_code, event_code != '') AS reports,
            max(ts) AS last_seen,
            groupUniqArray(8)({target_expr}) AS host_samples,
            groupUniqArray(8)({service_expr}) AS services
        FROM siem.events
        WHERE {where_clause}
          AND positionCaseInsensitiveUTF8(message, 'CVE-') > 0
          AND ({search_clause})
        GROUP BY cve
        HAVING cve != ''
        ORDER BY findings DESC, last_seen DESC
        LIMIT {int(limit)}
    """
    rows = [
        {
            "cve": str(row["cve"] or ""),
            "findings": int(row["findings"] or 0),
            "hosts": int(row["hosts"] or 0),
            "reports": int(row["reports"] or 0),
            "last_seen": _fmt(row["last_seen"]),
            "host_samples": [str(item) for item in (row["host_samples"] or []) if str(item or "").strip()],
            "services": [str(item) for item in (row["services"] or []) if str(item or "").strip()],
        }
        for row in get_ch_client().query(sql).named_results()
    ]
    return {"query": safe_token, "row_count": len(rows), "items": rows}


def _cmdb_asset_indexes() -> tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    host_index: Dict[str, Dict[str, Any]] = {}
    ip_index: Dict[str, Dict[str, Any]] = {}
    for item in fetch_cmdb_assets(limit=1000):
        hostname = str(item.get("hostname") or "").strip().lower()
        ip_value = str(item.get("ip") or "").strip()
        if hostname:
            host_index[hostname] = item
        if ip_value:
            ip_index[ip_value] = item
    return host_index, ip_index


def _canonical_source_name(
    source_name: str,
    host_index: Dict[str, Dict[str, Any]],
    ip_index: Dict[str, Dict[str, Any]],
) -> tuple[str, Dict[str, Any] | None]:
    raw_name = str(source_name or "").strip() or "unknown"
    override = SOURCE_ALIAS_OVERRIDES.get(raw_name)
    if override:
        cmdb = host_index.get(override.lower()) or ip_index.get(raw_name)
        return override, cmdb
    cmdb = host_index.get(raw_name.lower()) or ip_index.get(raw_name)
    if cmdb:
        hostname = str(cmdb.get("hostname") or "").strip()
        if hostname:
            return hostname, cmdb
    if "." in raw_name:
        short_name = raw_name.split(".", 1)[0].strip().lower()
        if short_name and short_name in host_index:
            cmdb = host_index[short_name]
            hostname = str(cmdb.get("hostname") or "").strip()
            if hostname:
                return hostname, cmdb
    return raw_name, cmdb


def fetch_assets(limit: int = 50, hours: int = 24) -> List[Dict[str, Any]]:
    ensure_cmdb_ti_support()
    operational_filter = _event_operational_filter_sql()
    query = f"""
        SELECT
            {_event_source_label_expr('log_source')},
            count() AS events,
            max(ts) AS last_seen,
            countIf(lower(severity) IN ('critical', 'high')) AS notable_events,
            groupUniqArray(4)(category) AS categories,
            groupUniqArray(4)(device_product) AS products,
            countIf(message LIKE '%auditd:%') AS audit_events
        FROM siem.events
        WHERE {_combine_sql_filters(f"ts >= now() - INTERVAL {int(hours)} HOUR", operational_filter)}
        GROUP BY log_source
        ORDER BY events DESC
        LIMIT {int(limit)}
    """
    host_index, ip_index = _cmdb_asset_indexes()
    grouped: Dict[str, Dict[str, Any]] = {}
    for row in get_ch_client().query(query).named_results():
        raw_name = str(row['log_source'] or 'unknown').strip() or 'unknown'
        asset_name, cmdb = _canonical_source_name(raw_name, host_index, ip_index)
        entry = grouped.setdefault(
            asset_name,
            {
                'asset': asset_name,
                'events': 0,
                'last_seen': '',
                '_last_seen_dt': None,
                'notable_events': 0,
                'audit_events': 0,
                'categories': set(),
                'products': set(),
                'aliases': set(),
                'cmdb_asset_id': '',
                'cmdb_owner': '',
                'cmdb_criticality': '',
                'cmdb_environment': '',
                'cmdb_service': '',
                'cmdb_tags': [],
                'cmdb_expected_ports': [],
            },
        )
        last_seen = _fmt(row['last_seen'])
        last_seen_dt = _parse_fmt_ts(last_seen)
        if last_seen_dt and (entry['_last_seen_dt'] is None or last_seen_dt > entry['_last_seen_dt']):
            entry['_last_seen_dt'] = last_seen_dt
            entry['last_seen'] = last_seen
        entry['events'] += int(row['events'] or 0)
        entry['notable_events'] += int(row['notable_events'] or 0)
        entry['audit_events'] += int(row['audit_events'] or 0)
        entry['categories'].update(str(item) for item in row['categories'] if str(item or '').strip())
        entry['products'].update(str(item) for item in row['products'] if str(item or '').strip())
        if raw_name and raw_name != asset_name:
            entry['aliases'].add(raw_name)
        if cmdb and not entry['cmdb_asset_id']:
            entry['cmdb_asset_id'] = str((cmdb or {}).get('asset_id') or '')
            entry['cmdb_owner'] = str((cmdb or {}).get('owner') or '')
            entry['cmdb_criticality'] = str((cmdb or {}).get('criticality') or '')
            entry['cmdb_environment'] = str((cmdb or {}).get('environment') or '')
            entry['cmdb_service'] = str((cmdb or {}).get('business_service') or '')
            entry['cmdb_tags'] = list((cmdb or {}).get('tags') or [])
            entry['cmdb_expected_ports'] = list((cmdb or {}).get('expected_ports') or [])
    rows: List[Dict[str, Any]] = []
    for entry in grouped.values():
        rows.append(
            {
                'asset': entry['asset'],
                'events': int(entry['events']),
                'last_seen': entry['last_seen'],
                'notable_events': int(entry['notable_events']),
                'audit_events': int(entry['audit_events']),
                'categories': sorted(entry['categories']),
                'products': sorted(entry['products']),
                'aliases': sorted(entry['aliases']),
                'cmdb_asset_id': entry['cmdb_asset_id'],
                'cmdb_owner': entry['cmdb_owner'],
                'cmdb_criticality': entry['cmdb_criticality'],
                'cmdb_environment': entry['cmdb_environment'],
                'cmdb_service': entry['cmdb_service'],
                'cmdb_tags': list(entry['cmdb_tags']),
                'cmdb_expected_ports': list(entry['cmdb_expected_ports']),
            }
        )
    rows.sort(key=lambda item: (-int(item['events']), str(item['asset'])))
    return rows


def fetch_source_inventory(limit: int = 200, hours: int = 24) -> List[Dict[str, Any]]:
    safe_limit = max(1, min(int(limit or 200), 1000))
    safe_hours = max(1, min(int(hours or 24), 720))
    cache_key = (safe_limit, safe_hours)
    cached = _SOURCE_INVENTORY_CACHE.get(cache_key)
    now_ts = time()
    if cached and now_ts - cached[0] <= SOURCE_INVENTORY_CACHE_TTL_SECONDS:
        return _clone_rows(cached[1])
    ensure_cmdb_ti_support()
    operational_filter = _event_operational_filter_sql()
    query = f"""
        SELECT
            source_name,
            count() AS events,
            max(ts) AS last_seen,
            countIf(lower(severity) IN ('critical', 'high')) AS notable_events,
            countIf(category = 'authentication') AS auth_events,
            countIf(ti_indicator != '') AS ti_hits,
            countIf(device_product = 'linux.auditd' OR message LIKE '%auditd:%') AS audit_events,
            groupUniqArray(6)(category) AS categories,
            groupUniqArray(6)(device_product) AS products,
            groupUniqArray(4)(asset_environment) AS environments,
            groupUniqArray(4)(asset_service) AS services,
            groupUniqArrayIf(8)(IPv4NumToString(src_ip), src_ip != 0) AS observed_src_ips,
            groupUniqArrayIf(8)(IPv4NumToString(dst_ip), dst_ip != 0) AS observed_dst_ips
        FROM
        (
            SELECT
                ts,
                src_ip,
                dst_ip,
                severity,
                category,
                device_product,
                ti_indicator,
                message,
                asset_environment,
                asset_service,
                {_event_source_label_expr('source_name')}
            FROM siem.events
            WHERE {_combine_sql_filters(f"ts >= now() - INTERVAL {safe_hours} HOUR", operational_filter)}
        )
        WHERE source_name != ''
        GROUP BY source_name
        ORDER BY events DESC
        LIMIT {safe_limit}
    """
    host_index, ip_index = _cmdb_asset_indexes()
    grouped: Dict[str, Dict[str, Any]] = {}
    for row in get_ch_client().query(query).named_results():
        source_name = str(row["source_name"] or "").strip() or "unknown"
        products = [str(item) for item in row["products"]]
        categories = [str(item) for item in row["categories"]]
        source_name, cmdb = _canonical_source_name(source_name, host_index, ip_index)
        entry = grouped.setdefault(
            source_name,
            {
                "source_name": source_name,
                "events": 0,
                "notable_events": 0,
                "auth_events": 0,
                "ti_hits": 0,
                "audit_events": 0,
                "categories": set(),
                "products": set(),
                "environments": set(),
                "services": set(),
                "observed_ips": set(),
                "source_ips": set(),
                "aliases": set(),
                "_last_seen_dt": None,
                "last_seen": "",
                "cmdb_asset_id": "",
                "cmdb_ip": "",
                "cmdb_owner": "",
                "cmdb_criticality": "",
                "cmdb_environment": "",
                "cmdb_service": "",
            },
        )
        last_seen = _fmt(row["last_seen"])
        last_seen_dt = _parse_fmt_ts(last_seen)
        if last_seen_dt and (entry["_last_seen_dt"] is None or last_seen_dt > entry["_last_seen_dt"]):
            entry["_last_seen_dt"] = last_seen_dt
            entry["last_seen"] = last_seen
        entry["events"] += int(row["events"] or 0)
        entry["notable_events"] += int(row["notable_events"] or 0)
        entry["auth_events"] += int(row["auth_events"] or 0)
        entry["ti_hits"] += int(row["ti_hits"] or 0)
        entry["audit_events"] += int(row["audit_events"] or 0)
        entry["categories"].update(item for item in categories if item)
        entry["products"].update(item for item in products if item)
        entry["environments"].update(str(item) for item in row["environments"] if str(item or "").strip())
        entry["services"].update(str(item) for item in row["services"] if str(item or "").strip())
        entry["observed_ips"].update(
            canonicalize_core_ip(item) for item in row["observed_src_ips"] if str(item or "").strip()
        )
        entry["observed_ips"].update(
            canonicalize_core_ip(item) for item in row["observed_dst_ips"] if str(item or "").strip()
        )
        raw_row_name = str(row["source_name"] or "").strip()
        entry["source_ips"].update(canonicalize_core_ip(item) for item in _extract_ip_candidates(raw_row_name))
        if raw_row_name and raw_row_name != source_name:
            entry["aliases"].add(raw_row_name)
        if cmdb and not entry["cmdb_asset_id"]:
            entry["cmdb_asset_id"] = str((cmdb or {}).get("asset_id") or "")
            entry["cmdb_ip"] = str((cmdb or {}).get("ip") or "")
            entry["source_ips"].update(
                canonicalize_core_ip(item) for item in _extract_ip_candidates(entry["cmdb_ip"])
            )
            entry["cmdb_owner"] = str((cmdb or {}).get("owner") or "")
            entry["cmdb_criticality"] = str((cmdb or {}).get("criticality") or "")
            entry["cmdb_environment"] = str((cmdb or {}).get("environment") or "")
            entry["cmdb_service"] = str((cmdb or {}).get("business_service") or "")
    rows: List[Dict[str, Any]] = []
    for entry in grouped.values():
        products = sorted(entry["products"])
        categories = sorted(entry["categories"])
        source_type = _guess_source_type(entry["source_name"], products, categories)
        collector_id = _guess_collector_id(source_type)
        rows.append(
            {
                "source_name": entry["source_name"],
                "source_type": source_type,
                "collector_id": collector_id,
                "collector_name": COLLECTOR_CATALOG.get(collector_id, {}).get("name", collector_id),
                "events": int(entry["events"] or 0),
                "last_seen": entry["last_seen"],
                "status": _freshness_state(entry["last_seen"], source_type),
                "notable_events": int(entry["notable_events"] or 0),
                "auth_events": int(entry["auth_events"] or 0),
                "ti_hits": int(entry["ti_hits"] or 0),
                "audit_events": int(entry["audit_events"] or 0),
                "categories": categories,
                "products": products,
                "environments": sorted(entry["environments"]),
                "services": sorted(entry["services"]),
                "aliases": sorted(entry["aliases"]),
                "source_ips": _unique_texts(sorted(entry["source_ips"])),
                "observed_ips": _unique_texts(sorted(entry["observed_ips"])),
                "cmdb_asset_id": entry["cmdb_asset_id"],
                "cmdb_ip": entry["cmdb_ip"],
                "cmdb_owner": entry["cmdb_owner"],
                "cmdb_criticality": entry["cmdb_criticality"],
                "cmdb_environment": entry["cmdb_environment"],
                "cmdb_service": entry["cmdb_service"],
            }
        )
    rows.sort(key=lambda item: (-int(item["events"]), str(item["source_name"])))
    rows = rows[:safe_limit]
    _SOURCE_INVENTORY_CACHE[cache_key] = (now_ts, _clone_rows(rows))
    if len(_SOURCE_INVENTORY_CACHE) > 24:
        oldest_key = min(_SOURCE_INVENTORY_CACHE, key=lambda key: _SOURCE_INVENTORY_CACHE[key][0])
        _SOURCE_INVENTORY_CACHE.pop(oldest_key, None)
    return _clone_rows(rows)


def fetch_collector_inventory(hours: int = 24) -> List[Dict[str, Any]]:
    sources = fetch_source_inventory(limit=500, hours=hours)
    grouped: Dict[str, Dict[str, Any]] = {key: dict(value) for key, value in COLLECTOR_CATALOG.items()}
    for collector_id, collector in grouped.items():
        collector["sources_count"] = 0
        collector["events"] = 0
        collector["last_seen"] = ""
        collector["status"] = collector.get("status", "ready")
        collector["covered_sources"] = []
        collector["source_statuses"] = []
    for source in sources:
        collector = grouped.get(source["collector_id"])
        if not collector:
            continue
        collector["sources_count"] += 1
        collector["events"] += int(source["events"] or 0)
        collector["covered_sources"].append(source["source_name"])
        collector["source_statuses"].append(str(source["status"] or "unknown"))
        current_last = _parse_fmt_ts(str(collector["last_seen"] or ""))
        source_last = _parse_fmt_ts(str(source["last_seen"] or ""))
        if source_last and (current_last is None or source_last > current_last):
            collector["last_seen"] = str(source["last_seen"] or "")
    rows: List[Dict[str, Any]] = []
    for collector_id, collector in grouped.items():
        last_seen = str(collector.get("last_seen") or "")
        status = collector.get("status", "ready")
        if collector.get("sources_count", 0) > 0:
            source_statuses = set(collector.get("source_statuses") or [])
            if "active" in source_statuses:
                status = "active"
            elif "delayed" in source_statuses:
                status = "delayed"
            elif "stale" in source_statuses:
                status = "stale"
            else:
                status = _freshness_state(last_seen, "Platform")
        rows.append(
            {
                "collector_id": collector_id,
                "name": str(collector.get("name") or collector_id),
                "node": str(collector.get("node") or ""),
                "role": str(collector.get("role") or ""),
                "protocols": list(collector.get("protocols") or []),
                "source_types": list(collector.get("source_types") or []),
                "sources_count": int(collector.get("sources_count") or 0),
                "events": int(collector.get("events") or 0),
                "last_seen": last_seen,
                "status": status,
                "covered_sources": sorted(set(str(item) for item in collector.get("covered_sources") or []))[:12],
            }
        )
    rows.sort(key=lambda item: (0 if item["status"] == "active" else 1 if item["status"] == "ready" else 2, -item["events"], item["name"]))
    return rows


def fetch_normalizer_rules(limit: int = 100) -> List[Dict[str, Any]]:
    query = f"""
        SELECT
            id,
            priority,
            source_type,
            event_matcher,
            uem_mapping,
            enabled
        FROM siem.normalizer_rules
        ORDER BY priority ASC, id ASC
        LIMIT {int(limit)}
    """
    rows: List[Dict[str, Any]] = []
    for row in get_ch_client().query(query).named_results():
        rows.append(
            {
                'id': int(row['id']),
                'priority': int(row['priority']),
                'source_type': str(row['source_type'] or ''),
                'event_matcher': str(row['event_matcher'] or ''),
                'uem_mapping': str(row['uem_mapping'] or '{}'),
                'enabled': bool(row.get('enabled', 1)),
            }
        )
    return rows


def ensure_normalizer_rule_support() -> None:
    get_ch_client().command(
        """
        CREATE TABLE IF NOT EXISTS siem.normalizer_rules
        (
            id UInt32,
            priority UInt32,
            source_type String,
            event_matcher String,
            uem_mapping String,
            enabled UInt8 DEFAULT 1,
            updated_ts DateTime DEFAULT now()
        )
        ENGINE = MergeTree
        ORDER BY (priority, id)
        """
    )


def save_normalizer_rule(
    *,
    rule_id: int | None = None,
    priority: int,
    source_type: str,
    event_matcher: str,
    uem_mapping: dict[str, Any] | str,
    enabled: bool = True,
) -> dict[str, Any]:
    ensure_normalizer_rule_support()
    safe_rule_id = int(rule_id or max((int(item.get("id") or 0) for item in fetch_normalizer_rules(limit=5000)), default=0) + 1)
    safe_mapping = uem_mapping if isinstance(uem_mapping, str) else json.dumps(dict(uem_mapping or {}), ensure_ascii=False)
    get_ch_client().command(f"ALTER TABLE siem.normalizer_rules DELETE WHERE id = {safe_rule_id}")
    get_ch_client().insert(
        "siem.normalizer_rules",
        [[
            safe_rule_id,
            max(1, int(priority or 1)),
            str(source_type or "").strip(),
            str(event_matcher or "").strip(),
            str(safe_mapping or "{}"),
            1 if enabled else 0,
        ]],
        column_names=["id", "priority", "source_type", "event_matcher", "uem_mapping", "enabled"],
    )
    return {
        "id": safe_rule_id,
        "priority": max(1, int(priority or 1)),
        "source_type": str(source_type or "").strip(),
        "event_matcher": str(event_matcher or "").strip(),
        "uem_mapping": str(safe_mapping or "{}"),
        "enabled": bool(enabled),
    }


def fetch_resource_overview() -> Dict[str, Any]:
    ensure_detection_support_tables()
    ensure_incident_workflow_support()
    ensure_active_list_support()
    ensure_cold_storage_support()
    ensure_cmdb_ti_support()
    clickhouse_status = _clickhouse_status_snapshot()
    return {
        'clickhouse_ok': bool(clickhouse_status.get("healthy")),
        'clickhouse_runtime': clickhouse_status,
        'events_total': int(_scalar("SELECT count() FROM siem.events")) + int(_scalar(f"SELECT count() FROM {EVENTS_COLD_TABLE}")),
        'events_hot_total': int(_scalar("SELECT count() FROM siem.events")),
        'events_cold_total': int(_scalar(f"SELECT count() FROM {EVENTS_COLD_TABLE}")),
        'alerts_raw_total': int(_scalar("SELECT count() FROM siem.alerts_raw")),
        'alerts_agg_total': int(_scalar("SELECT count() FROM siem.alerts_agg")),
        'normalizer_rules': int(_scalar("SELECT count() FROM siem.normalizer_rules WHERE enabled = 1")),
        'filter_rules': int(_scalar("SELECT count() FROM siem.filter_rules WHERE enabled = 1")),
        'stream_rules': int(_scalar("SELECT count() FROM siem.correlation_rules_stream WHERE enabled = 1")),
        'detection_rules': int(_scalar(f"SELECT count() FROM {DETECTION_RULE_TABLE}")),
        'active_list_items': int(_scalar(f"SELECT count() FROM {ACTIVE_LIST_TABLE}")),
        'cmdb_assets': int(
            _scalar(
                f"""
                SELECT count()
                FROM
                (
                    SELECT asset_id, enabled
                    FROM {CMDB_ASSET_TABLE}
                    ORDER BY updated_ts DESC
                    LIMIT 1 BY asset_id
                )
                WHERE enabled = 1
                """
            )
        ),
        'threat_iocs': int(_scalar(f"SELECT count() FROM {THREAT_INTEL_TABLE} WHERE enabled = 1")),
        'incident_history_rows': int(_scalar(f"SELECT count() FROM {ALERT_HISTORY_TABLE}")),
        'last_event_ts': _fmt(_scalar("SELECT max(ts) FROM siem.events")),
        'hot_retention_hours': int(CONFIG.hot_retention_hours),
        'cold_retention_days': int(CONFIG.cold_retention_days),
    }


def fetch_platform_status() -> Dict[str, Any]:
    content_status = content_storage_status()
    stream_corr_status = fetch_stream_correlation_runtime_status()
    shadow_transport_status = fetch_transport_shadow_status()
    storage_memory_status = fetch_clickhouse_memory_status()
    transport_snapshot = transport_health_snapshot()
    clickhouse_status = _clickhouse_status_snapshot()
    clickhouse_ok = bool(clickhouse_status.get("healthy"))
    if not clickhouse_ok:
        return {
            "clickhouse_ok": False,
            "clickhouse_runtime": clickhouse_status,
            "last_event_ts": "",
            "events_5m": 0,
            "alerts_24h": 0,
            "content_store": str(content_status.get("backend") or content_store_backend()),
            "content_store_backend": str(content_status.get("backend") or content_store_backend()),
            "content_store_healthy": bool(content_status.get("healthy", False)),
            "content_store_status": content_status,
            "transport_backend": str(stream_corr_status.get("transport_backend") or transport_snapshot.get("backend") or "kafka"),
            "stream_state_backend": str(stream_corr_status.get("state_backend") or stream_state_runtime_status().get("backend") or "sqlite"),
            "stream_correlation": stream_corr_status,
            "transport_shadow_status": shadow_transport_status,
            "storage_memory": storage_memory_status,
        }
    return {
        "clickhouse_ok": True,
        "clickhouse_runtime": clickhouse_status,
        "last_event_ts": _fmt(_scalar("SELECT max(ts) FROM siem.events")),
        "events_5m": int(_scalar("SELECT count() FROM siem.events WHERE ts >= now() - INTERVAL 5 MINUTE")),
        "alerts_24h": int(_scalar("SELECT count() FROM siem.alerts_raw WHERE ts >= now() - INTERVAL 24 HOUR")),
        "content_store": str(content_status.get("backend") or content_store_backend()),
        "content_store_backend": str(content_status.get("backend") or content_store_backend()),
        "content_store_healthy": bool(content_status.get("healthy", False)),
        "content_store_status": content_status,
        "transport_backend": str(stream_corr_status.get("transport_backend") or transport_snapshot.get("backend") or "kafka"),
        "stream_state_backend": str(stream_corr_status.get("state_backend") or stream_state_runtime_status().get("backend") or "sqlite"),
        "stream_correlation": stream_corr_status,
        "transport_shadow_status": shadow_transport_status,
        "storage_memory": storage_memory_status,
    }


def _format_bytes_short(value: Any) -> str:
    size = float(max(int(value or 0), 0))
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    unit = units[0]
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            break
        size /= 1024.0
    return f"{size:.2f} {unit}"


def _build_clickhouse_memory_status(
    async_metrics: Dict[str, Any],
    runtime_metrics: Dict[str, Any],
    server_settings: Dict[str, Any],
) -> Dict[str, Any]:
    resident_bytes = int(async_metrics.get("MemoryResident") or 0)
    allocated_bytes = int(async_metrics.get("jemalloc.allocated") or 0)
    active_bytes = int(async_metrics.get("jemalloc.active") or 0)
    mark_cache_bytes = int(async_metrics.get("MarkCacheBytes") or 0)
    uncompressed_cache_bytes = int(async_metrics.get("UncompressedCacheBytes") or 0)
    mapped_file_bytes = int(async_metrics.get("MMappedFileBytes") or 0)
    max_server_memory_usage = int(server_settings.get("max_server_memory_usage") or 0)
    max_server_memory_ratio = float(server_settings.get("max_server_memory_usage_to_ram_ratio") or 0.0)
    configured_mark_cache_size = int(server_settings.get("mark_cache_size") or 0)
    configured_uncompressed_cache_size = int(server_settings.get("uncompressed_cache_size") or 0)
    configured_mmap_cache_size = int(server_settings.get("mmap_cache_size") or 0)
    memory_tracking = int(runtime_metrics.get("MemoryTracking") or 0)
    merge_tasks = int(runtime_metrics.get("Merge") or 0)
    background_pool_tasks = int(runtime_metrics.get("BackgroundPoolTask") or 0)
    merges_memory_tracking = int(runtime_metrics.get("MergesMutationsMemoryTracking") or 0)
    pressure_ratio = 0.0
    if max_server_memory_usage > 0:
        pressure_ratio = max(resident_bytes, memory_tracking) / max_server_memory_usage
    if pressure_ratio >= 0.85:
        pressure = "critical"
    elif pressure_ratio >= 0.7:
        pressure = "high"
    elif pressure_ratio >= 0.5:
        pressure = "elevated"
    else:
        pressure = "healthy"
    return {
        "available": True,
        "pressure": pressure,
        "pressure_ratio": round(pressure_ratio, 4),
        "resident_bytes": resident_bytes,
        "resident_human": _format_bytes_short(resident_bytes),
        "allocated_bytes": allocated_bytes,
        "allocated_human": _format_bytes_short(allocated_bytes),
        "active_bytes": active_bytes,
        "active_human": _format_bytes_short(active_bytes),
        "memory_tracking_bytes": memory_tracking,
        "memory_tracking_human": _format_bytes_short(memory_tracking),
        "mark_cache_bytes": mark_cache_bytes,
        "mark_cache_human": _format_bytes_short(mark_cache_bytes),
        "uncompressed_cache_bytes": uncompressed_cache_bytes,
        "uncompressed_cache_human": _format_bytes_short(uncompressed_cache_bytes),
        "mapped_file_bytes": mapped_file_bytes,
        "mapped_file_human": _format_bytes_short(mapped_file_bytes),
        "configured_mark_cache_size_bytes": configured_mark_cache_size,
        "configured_mark_cache_size_human": _format_bytes_short(configured_mark_cache_size),
        "configured_uncompressed_cache_size_bytes": configured_uncompressed_cache_size,
        "configured_uncompressed_cache_size_human": _format_bytes_short(configured_uncompressed_cache_size),
        "configured_mmap_cache_size": configured_mmap_cache_size,
        "max_server_memory_usage_bytes": max_server_memory_usage,
        "max_server_memory_usage_human": _format_bytes_short(max_server_memory_usage),
        "max_server_memory_usage_to_ram_ratio": max_server_memory_ratio,
        "merge_tasks": merge_tasks,
        "background_pool_tasks": background_pool_tasks,
        "merges_memory_tracking_bytes": merges_memory_tracking,
        "merges_memory_tracking_human": _format_bytes_short(merges_memory_tracking),
    }


def fetch_clickhouse_memory_status() -> Dict[str, Any]:
    try:
        async_query = """
            SELECT metric, value
            FROM system.asynchronous_metrics
            WHERE metric IN (
                'MemoryResident',
                'jemalloc.allocated',
                'jemalloc.active',
                'MarkCacheBytes',
                'UncompressedCacheBytes',
                'MMappedFileBytes'
            )
        """
        runtime_query = """
            SELECT name, value
            FROM system.metrics
            WHERE name IN (
                'MemoryTracking',
                'Merge',
                'BackgroundPoolTask',
                'MergesMutationsMemoryTracking'
            )
        """
        settings_query = """
            SELECT name, value
            FROM system.server_settings
            WHERE name IN (
                'max_server_memory_usage',
                'max_server_memory_usage_to_ram_ratio',
                'mark_cache_size',
                'uncompressed_cache_size',
                'mmap_cache_size'
            )
        """
        async_metrics = {
            str(row.get("metric") or ""): int(row.get("value") or 0)
            for row in get_ch_client().query(async_query).named_results()
            if str(row.get("metric") or "")
        }
        runtime_metrics = {
            str(row.get("name") or ""): int(row.get("value") or 0)
            for row in get_ch_client().query(runtime_query).named_results()
            if str(row.get("name") or "")
        }
        server_settings = {
            str(row.get("name") or ""): row.get("value")
            for row in get_ch_client().query(settings_query).named_results()
            if str(row.get("name") or "")
        }
    except Exception:
        return {"available": False, "status": "unavailable", "pressure": "unknown"}
    return _build_clickhouse_memory_status(async_metrics, runtime_metrics, server_settings)


def fetch_stream_correlation_runtime_status() -> Dict[str, Any]:
    transport_snapshot = transport_health_snapshot()
    state_runtime = stream_state_runtime_status()

    def _fallback(status: str) -> Dict[str, Any]:
        transport_backend_name = str(transport_snapshot.get("backend") or "kafka")
        state_backend_name = str(state_runtime.get("backend") or "sqlite")
        return {
            "available": False,
            "status": status,
            "instance_name": "siem-stream-corr",
            "transport_backend": transport_backend_name,
            "state_backend": state_backend_name,
            "mode": str(os.getenv("SIEM_STREAM_CORR_TIME_MODE", "event") or "event").strip().lower(),
            "shadow_compare": str(os.getenv("SIEM_STREAM_CORR_SHADOW_COMPARE", "false") or "false").strip().lower() in {"1", "true", "yes", "on"},
            "watermark_epoch": 0.0,
            "watermark_ts": "",
            "watermark_lag_sec": int(str(os.getenv("SIEM_STREAM_CORR_WATERMARK_LAG_SEC", "300") or "300")),
            "allowed_lateness_sec": int(str(os.getenv("SIEM_STREAM_CORR_ALLOWED_LATENESS_SEC", "600") or "600")),
            "max_event_epoch_seen": 0.0,
            "max_event_ts": "",
            "last_event_epoch": 0.0,
            "last_event_ts": "",
            "late_events_total": 0,
            "timestamp_fallback_total": 0,
            "shadow_compare_mismatches_total": 0,
            "last_mismatch_ts": "",
            "last_batch_events": 0,
            "last_batch_alerts": 0,
            "observed_ts": "",
        }

    try:
        query = f"""
            SELECT
                observed_ts,
                instance_name,
                transport_backend,
                state_backend,
                mode,
                shadow_compare,
                watermark_epoch,
                watermark_lag_sec,
                allowed_lateness_sec,
                max_event_epoch_seen,
                last_event_epoch,
                late_events_total,
                timestamp_fallback_total,
                shadow_compare_mismatches_total,
                last_mismatch_ts,
                last_batch_events,
                last_batch_alerts
            FROM {STREAM_CORR_RUNTIME_TABLE}
            PREWHERE observed_ts >= now() - INTERVAL 15 MINUTE
            ORDER BY observed_ts DESC
            LIMIT 1
        """
        row = get_ch_client().query(query).first_row
    except Exception:
        return _fallback("unavailable")
    if not row:
        return _fallback("pending")
    observed_ts = row[0]
    instance_name = str(row[1] or "siem-stream-corr")
    desired_transport = transport_health_snapshot()
    state_runtime = stream_state_runtime_status()
    transport_backend_name = str(row[2] or desired_transport.get("backend") or "kafka")
    state_backend = str(row[3] or state_runtime.get("backend") or "sqlite")
    mode = str(row[4] or "processing")
    shadow_compare = bool(row[5])
    watermark_epoch = float(row[6] or 0.0)
    watermark_lag_sec = int(row[7] or 0)
    allowed_lateness_sec = int(row[8] or 0)
    max_event_epoch_seen = float(row[9] or 0.0)
    last_event_epoch = float(row[10] or 0.0)
    late_events_total = int(row[11] or 0)
    timestamp_fallback_total = int(row[12] or 0)
    shadow_compare_mismatches_total = int(row[13] or 0)
    last_mismatch_ts = _fmt(row[14]) if row[14] else ""
    last_batch_events = int(row[15] or 0)
    last_batch_alerts = int(row[16] or 0)
    return {
        "available": True,
        "status": "active",
        "instance_name": instance_name,
        "transport_backend": transport_backend_name,
        "state_backend": state_backend,
        "mode": mode,
        "shadow_compare": shadow_compare,
        "watermark_epoch": watermark_epoch,
        "watermark_ts": _iso_from_epoch(watermark_epoch) if watermark_epoch else "",
        "watermark_lag_sec": watermark_lag_sec,
        "allowed_lateness_sec": allowed_lateness_sec,
        "max_event_epoch_seen": max_event_epoch_seen,
        "max_event_ts": _iso_from_epoch(max_event_epoch_seen) if max_event_epoch_seen else "",
        "last_event_epoch": last_event_epoch,
        "last_event_ts": _iso_from_epoch(last_event_epoch) if last_event_epoch else "",
        "late_events_total": late_events_total,
        "timestamp_fallback_total": timestamp_fallback_total,
        "shadow_compare_mismatches_total": shadow_compare_mismatches_total,
        "last_mismatch_ts": last_mismatch_ts,
        "last_batch_events": last_batch_events,
        "last_batch_alerts": last_batch_alerts,
        "observed_ts": _fmt(observed_ts),
    }


def fetch_transport_shadow_status() -> Dict[str, Any]:
    replication = clickhouse_replication_snapshot()
    nodes = [
        dict(item)
        for item in (replication.get("nodes") or [])
        if isinstance(item, dict) and bool(item.get("healthy", True))
    ]
    if nodes:
        cluster_main_events_5m = max(int(item.get("events_5m") or 0) for item in nodes)
        cluster_main_events_15m = max(int(item.get("events_15m") or 0) for item in nodes)
        shadow_nodes = [item for item in nodes if bool(item.get("shadow_table_exists"))]
        if shadow_nodes:
            freshest = max(
                shadow_nodes,
                key=lambda item: (
                    int(item.get("shadow_latest_event_epoch") or 0),
                    int(item.get("shadow_events_15m") or 0),
                    int(item.get("shadow_events_5m") or 0),
                ),
            )
            payload = build_shadow_transport_status(
                shadow_table_exists=True,
                main_events_5m=int(freshest.get("events_5m") or cluster_main_events_5m),
                main_events_15m=int(freshest.get("events_15m") or cluster_main_events_15m),
                shadow_events_5m=int(freshest.get("shadow_events_5m") or 0),
                shadow_events_15m=int(freshest.get("shadow_events_15m") or 0),
                shadow_last_event_ts=_iso_from_epoch(int(freshest.get("shadow_latest_event_epoch") or 0))
                if int(freshest.get("shadow_latest_event_epoch") or 0) > 0
                else "",
            )
            payload["shadow_source_endpoint"] = {
                "host": str(freshest.get("host") or ""),
                "port": int(freshest.get("port") or 0),
            }
            shadow_query_error = str(freshest.get("shadow_query_error") or "").strip()
            if shadow_query_error:
                payload.setdefault("query_warnings", []).append(shadow_query_error)
            return payload
        return build_shadow_transport_status(
            shadow_table_exists=False,
            main_events_5m=cluster_main_events_5m,
            main_events_15m=cluster_main_events_15m,
            shadow_events_5m=0,
            shadow_events_15m=0,
            shadow_last_event_ts="",
        )
    try:
        shadow_table_exists = int(_scalar(f"EXISTS TABLE {SHADOW_EVENTS_TABLE}")) == 1
    except Exception:
        return {
            "available": False,
            "healthy": False,
            "status": "unavailable",
            "issues": ["Kafka shadow transport runtime is unavailable"],
        }

    if not shadow_table_exists:
        return build_shadow_transport_status(
            shadow_table_exists=False,
            main_events_5m=int(_scalar("SELECT count() FROM siem.events WHERE ts >= now() - INTERVAL 5 MINUTE")),
            main_events_15m=int(_scalar("SELECT count() FROM siem.events WHERE ts >= now() - INTERVAL 15 MINUTE")),
            shadow_events_5m=0,
            shadow_events_15m=0,
            shadow_last_event_ts="",
        )

    try:
        main_events_5m = int(_scalar("SELECT count() FROM siem.events WHERE ts >= now() - INTERVAL 5 MINUTE"))
        main_events_15m = int(_scalar("SELECT count() FROM siem.events WHERE ts >= now() - INTERVAL 15 MINUTE"))
        shadow_events_5m = int(_scalar(f"SELECT count() FROM {SHADOW_EVENTS_TABLE} WHERE ts >= now() - INTERVAL 5 MINUTE"))
        shadow_events_15m = int(_scalar(f"SELECT count() FROM {SHADOW_EVENTS_TABLE} WHERE ts >= now() - INTERVAL 15 MINUTE"))
        shadow_last_event_ts = _fmt(_scalar(f"SELECT max(ts) FROM {SHADOW_EVENTS_TABLE}"))
    except Exception:
        return {
            "available": False,
            "healthy": False,
            "status": "unavailable",
            "issues": ["Kafka shadow transport metrics query failed"],
            "shadow_table_exists": True,
        }

    return build_shadow_transport_status(
        shadow_table_exists=True,
        main_events_5m=main_events_5m,
        main_events_15m=main_events_15m,
        shadow_events_5m=shadow_events_5m,
        shadow_events_15m=shadow_events_15m,
        shadow_last_event_ts=shadow_last_event_ts,
    )


def _load_geoip_cache() -> Dict[str, Any]:
    payload = _load_runtime_json_file(RUNTIME_GEOIP_CACHE_FILE, {})
    return payload if isinstance(payload, dict) else {}


def _load_dns_cache() -> Dict[str, Any]:
    payload = _load_runtime_json_file(RUNTIME_DNS_CACHE_FILE, {})
    return payload if isinstance(payload, dict) else {}


def _save_geoip_cache(cache: Dict[str, Any]) -> None:
    _save_runtime_json_file(RUNTIME_GEOIP_CACHE_FILE, cache)


def _save_dns_cache(cache: Dict[str, Any]) -> None:
    _save_runtime_json_file(RUNTIME_DNS_CACHE_FILE, cache)


def _is_public_ip(ip_text: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(str(ip_text or "").strip())
    except ValueError:
        return False
    return not (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
        or ip_obj.is_link_local
    )


def _geo_lookup(ip_text: str, *, allow_network: bool = True) -> Dict[str, Any]:
    ip_value = str(ip_text or "").strip()
    if not ip_value:
        return {}
    cache = _load_geoip_cache()
    cached = cache.get(ip_value)
    if isinstance(cached, dict):
        cached_country = str(cached.get("country") or "").strip()
        cached_code = str(cached.get("country_code") or "").strip()
        if cached_country and cached_country.lower() != "unknown" and cached_code:
            return dict(cached)
    result: Dict[str, Any] = {
        "ip": ip_value,
        "country": "Unknown",
        "country_code": "",
        "city": "",
        "lat": None,
        "lon": None,
        "org": "",
    }
    if _is_public_ip(ip_value) and allow_network:
        try:
            with urlopen(f"https://ipwho.is/{quote(ip_value)}", timeout=4) as response:  # noqa: S310 - controlled lookup
                payload = json.loads(response.read().decode("utf-8", errors="ignore"))
            if isinstance(payload, dict) and payload.get("success") is not False:
                connection = payload.get("connection") or {}
                result.update(
                    {
                        "country": str(payload.get("country") or "Unknown"),
                        "country_code": str(payload.get("country_code") or "").upper(),
                        "city": str(payload.get("city") or ""),
                        "lat": payload.get("latitude"),
                        "lon": payload.get("longitude"),
                        "org": str(connection.get("isp") or connection.get("org") or ""),
                    }
                )
        except Exception:
            pass
    elif not _is_public_ip(ip_value):
        result.update({"country": "Private / LAN", "country_code": "LAN"})
    if result["country_code"] or str(result["country"]).strip().lower() == "private / lan":
        cache[ip_value] = result
        _save_geoip_cache(cache)
    elif ip_value in cache:
        cache.pop(ip_value, None)
        _save_geoip_cache(cache)
    return dict(result)


def _normalize_country_name(value: str) -> str:
    raw = str(value or "").strip().lower()
    aliases = {
        "russian federation": "russia",
        "russia": "russia",
        "united states": "united states of america",
        "usa": "united states of america",
        "u.s.a.": "united states of america",
        "uk": "united kingdom",
        "u.k.": "united kingdom",
        "czechia": "czech republic",
        "korea, republic of": "south korea",
    }
    return aliases.get(raw, raw)


def _normalize_vpn_destination_host(value: str) -> str:
    host = str(value or "").strip().lower()
    if not host:
        return ""
    if "://" in host:
        host = host.split("://", 1)[1]
    while host.startswith("//"):
        host = host[2:]
    host = host.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].strip().strip("\"'`(){}<>.,;")
    if host.startswith("[") and "]" in host:
        host = host[1 : host.index("]")]
    elif host.count(":") == 1:
        left, right = host.rsplit(":", 1)
        if right.isdigit():
            host = left
    host = host.strip().strip("\"'`()[]{}<>.,;")
    if not host:
        return ""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if "." not in host:
        return ""
    if not re.fullmatch(r"[a-z0-9._-]+", host):
        return ""
    return host.rstrip(".")


def _extract_vpn_destination_host(message: str) -> str:
    text = str(message or "").strip()
    if not text:
        return ""
    match = VPN_DESTINATION_CAPTURE_RE.search(text)
    if match:
        host = _normalize_vpn_destination_host(match.group("host"))
        if host:
            return host
    for candidate in re.findall(r"(?:(?:tcp|udp):)?//([^\s/\]]+)", text, flags=re.IGNORECASE):
        host = _normalize_vpn_destination_host(candidate)
        if host:
            return host
    return ""


def _resolve_hostname_ip(hostname: str, *, allow_network: bool = True) -> str:
    host = str(hostname or "").strip().lower()
    if not host:
        return ""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    cache = _load_dns_cache()
    cached = str(cache.get(host) or "").strip()
    if cached:
        return cached
    if host in cache:
        cache.pop(host, None)
        _save_dns_cache(cache)
    resolved = ""
    if allow_network:
        try:
            for row in socket.getaddrinfo(host, 443, family=socket.AF_INET, type=socket.SOCK_STREAM):
                candidate = str(row[4][0] or "").strip()
                if candidate:
                    resolved = candidate
                    break
        except Exception:
            resolved = ""
    if resolved:
        cache[host] = resolved
        _save_dns_cache(cache)
    return resolved


def _ip_reputation(ip_text: str) -> Dict[str, Any]:
    ip_value = str(ip_text or "").strip()
    if not ip_value:
        return {"label": "unknown", "sources": []}
    quoted = _sql_quote(ip_value)
    query = f"""
        SELECT
            countIf(indicator_type IN ('ip', 'ipv4') AND indicator = {quoted} AND enabled = 1) AS ti_hits,
            countIf(value_type IN ('ip', 'ipv4') AND value = {quoted} AND enabled = 1 AND list_kind = 'deny') AS deny_hits,
            countIf(value_type IN ('ip', 'ipv4') AND value = {quoted} AND enabled = 1 AND list_kind IN ('watch', 'allow')) AS watch_hits
        FROM
        (
            SELECT indicator_type, indicator, enabled, '' AS value_type, '' AS value, '' AS list_kind FROM {THREAT_INTEL_TABLE}
            UNION ALL
            SELECT '' AS indicator_type, '' AS indicator, enabled, value_type, value, list_kind FROM {ACTIVE_LIST_TABLE}
        )
    """
    try:
        row = next(iter(get_ch_client().query(query).named_results()), None) or {}
    except Exception:
        row = {}
    deny_hits = int(row.get("deny_hits") or 0)
    ti_hits = int(row.get("ti_hits") or 0)
    watch_hits = int(row.get("watch_hits") or 0)
    sources = []
    if deny_hits:
        sources.append("active-list deny")
    if ti_hits:
        sources.append("threat intel")
    if watch_hits:
        sources.append("watchlist")
    if deny_hits or ti_hits:
        label = "malicious"
    elif watch_hits:
        label = "watch"
    else:
        label = "unknown"
    return {"label": label, "sources": sources}


def fetch_geo_ip_detail(ip_text: str, hours: int = 72) -> Dict[str, Any]:
    safe_ip = str(ip_text or "").strip()
    if not safe_ip:
        raise ValueError("ip is required")
    try:
        ip_num = int(ipaddress.ip_address(safe_ip))
    except ValueError as exc:
        raise ValueError(f"invalid ip: {safe_ip}") from exc

    geo = _geo_lookup(safe_ip)
    reputation = _ip_reputation(safe_ip)
    quoted_ip = _sql_quote(safe_ip)
    event_operational_filter = _event_operational_filter_sql()
    incident_operational_filter = _alert_agg_operational_filter_sql()
    summary_sql = f"""
        SELECT
            count() AS events,
            countIf(lower(severity) IN ('critical', 'high')) AS notable_events,
            countIf(category = 'authentication') AS auth_events,
            countIf(ti_indicator != '') AS ti_events,
            max(ts) AS last_seen,
            groupUniqArray(8)(log_source) AS log_sources,
            groupUniqArray(8)(category) AS categories,
            groupUniqArray(10)(if(dst_port > 0, toString(dst_port), '')) AS dst_ports,
            countIf(src_ip = {ip_num}) AS as_source,
            countIf(dst_ip = {ip_num}) AS as_destination
        FROM siem.events
        WHERE ts >= now() - INTERVAL {int(hours)} HOUR
          AND {event_operational_filter}
          AND (src_ip = {ip_num} OR dst_ip = {ip_num})
    """
    event_sample_sql = f"""
        SELECT
            ts,
            log_source,
            category,
            subcategory,
            lower(severity) AS severity,
            if(src_ip = 0, '', IPv4NumToString(src_ip)) AS src_ip_text,
            if(dst_ip = 0, '', IPv4NumToString(dst_ip)) AS dst_ip_text,
            dst_port,
            message
        FROM siem.events
        WHERE ts >= now() - INTERVAL {int(hours)} HOUR
          AND {event_operational_filter}
          AND (src_ip = {ip_num} OR dst_ip = {ip_num})
        ORDER BY ts DESC
        LIMIT 20
    """
    incident_sql = f"""
        SELECT
            agg_id,
            rule_id,
            rule_name,
            status,
            severity_agg,
            ts_last,
            count_alerts AS alert_count,
            entity_key,
            group_key_json,
            samples_json
        FROM siem.alerts_agg
        WHERE {incident_operational_filter}
          AND (
              positionCaseInsensitiveUTF8(entity_key, {quoted_ip}) > 0
              OR positionCaseInsensitiveUTF8(group_key_json, {quoted_ip}) > 0
              OR positionCaseInsensitiveUTF8(samples_json, {quoted_ip}) > 0
          )
        ORDER BY ts_last DESC
        LIMIT 10
    """
    active_list_sql = f"""
        SELECT
            list_name,
            list_kind,
            value_type,
            value,
            label,
            tags,
            updated_ts
        FROM {ACTIVE_LIST_TABLE}
        WHERE enabled = 1
          AND value_type IN ('ip', 'ipv4')
          AND value = {quoted_ip}
        ORDER BY updated_ts DESC
        LIMIT 20
    """
    ti_sql = f"""
        SELECT
            indicator_type,
            indicator,
            provider,
            severity,
            confidence,
            description,
            tags,
            expires_ts,
            updated_ts
        FROM {THREAT_INTEL_TABLE}
        WHERE enabled = 1
          AND indicator_type IN ('ip', 'ipv4')
          AND indicator = {quoted_ip}
        ORDER BY updated_ts DESC
        LIMIT 20
    """
    summary_row = next(iter(get_ch_client().query(summary_sql).named_results()), None) or {}
    recent_events = [
        {
            "ts": _fmt(row.get("ts")),
            "log_source": str(row.get("log_source") or ""),
            "category": str(row.get("category") or ""),
            "subcategory": str(row.get("subcategory") or ""),
            "severity": str(row.get("severity") or "info"),
            "src_ip": str(row.get("src_ip_text") or ""),
            "dst_ip": str(row.get("dst_ip_text") or ""),
            "dst_port": int(row.get("dst_port") or 0),
            "message": str(row.get("message") or ""),
        }
        for row in get_ch_client().query(event_sample_sql).named_results()
    ]
    incidents = [
        {
            "agg_id": str(row.get("agg_id") or ""),
            "rule_id": int(row.get("rule_id") or 0),
            "rule_name": str(row.get("rule_name") or ""),
            "status": str(row.get("status") or "new"),
            "severity": str(row.get("severity_agg") or "info"),
            "last_seen": _fmt(row.get("ts_last")),
            "alert_count": int(row.get("alert_count") or 0),
            "source_summary": str(row.get("group_key_json") or ""),
            "entity_summary": str(row.get("entity_key") or ""),
            "samples_json": str(row.get("samples_json") or ""),
        }
        for row in get_ch_client().query(incident_sql).named_results()
    ]
    ti_entries = [
        {
            "indicator_type": str(row.get("indicator_type") or ""),
            "indicator": str(row.get("indicator") or ""),
            "provider": str(row.get("provider") or ""),
            "severity": str(row.get("severity") or ""),
            "confidence": int(row.get("confidence") or 0),
            "description": str(row.get("description") or ""),
            "tags": [part for part in str(row.get("tags") or "").split(",") if part],
            "expires_ts": _fmt(row.get("expires_ts")),
            "updated_ts": _fmt(row.get("updated_ts")),
        }
        for row in get_ch_client().query(ti_sql).named_results()
    ]
    active_list_hits = [
        {
            "list_name": str(row.get("list_name") or ""),
            "list_kind": str(row.get("list_kind") or ""),
            "value_type": str(row.get("value_type") or ""),
            "value": str(row.get("value") or ""),
            "label": str(row.get("label") or ""),
            "tags": [part for part in str(row.get("tags") or "").split(",") if part],
            "updated_ts": _fmt(row.get("updated_ts")),
        }
        for row in get_ch_client().query(active_list_sql).named_results()
    ]
    return {
        "ip": safe_ip,
        "geo": geo,
        "reputation": reputation,
        "summary": {
            "events": int(summary_row.get("events") or 0),
            "notable_events": int(summary_row.get("notable_events") or 0),
            "auth_events": int(summary_row.get("auth_events") or 0),
            "ti_events": int(summary_row.get("ti_events") or 0),
            "as_source": int(summary_row.get("as_source") or 0),
            "as_destination": int(summary_row.get("as_destination") or 0),
            "last_seen": _fmt(summary_row.get("last_seen")),
            "log_sources": [str(item) for item in (summary_row.get("log_sources") or []) if str(item or "").strip()],
            "categories": [str(item) for item in (summary_row.get("categories") or []) if str(item or "").strip()],
            "dst_ports": [str(item) for item in (summary_row.get("dst_ports") or []) if str(item or "").strip()],
        },
        "recent_events": recent_events,
        "incidents": incidents,
        "threat_intel": ti_entries,
        "active_lists": active_list_hits,
    }


def _fetch_geo_source_activity_window(
    hours: int = 24,
    limit: int = 20,
    *,
    from_ts: str = "",
    to_ts: str = "",
    allow_network: bool = True,
) -> Dict[str, Any]:
    time_filter = _time_filter("ts", hours=hours, from_ts=from_ts, to_ts=to_ts)
    operational_filter = _event_operational_filter_sql()
    protected_sources_sql = ", ".join(_sql_quote(ip) for ip in PROTECTED_PUBLIC_IPS)
    protected_source_filter = (
        f"AND source_ip NOT IN ({protected_sources_sql})"
        if protected_sources_sql
        else ""
    )
    query = f"""
        SELECT
            source_ip,
            count() AS events,
            max(ts) AS last_seen,
            countIf(lower(severity) IN ('critical', 'high')) AS notable_events,
            countIf(category = 'authentication') AS auth_events,
            countIf(ti_indicator != '') AS ti_hits,
            arrayStringConcat(groupUniqArray(4)(if(dst_port > 0, toString(dst_port), '')), ',') AS target_ports,
            arrayStringConcat(groupUniqArray(6)(target_ip), ',') AS target_ips,
            arrayStringConcat(groupUniqArray(6)(log_source), ',') AS log_sources
        FROM
        (
            SELECT
                ts,
                severity,
                category,
                subcategory,
                log_source,
                device_product,
                ti_indicator,
                dst_port,
                if(
                    extract(message, 'SRC=([0-9]{{1,3}}(?:\\.[0-9]{{1,3}}){{3}})') != '',
                    extract(message, 'SRC=([0-9]{{1,3}}(?:\\.[0-9]{{1,3}}){{3}})'),
                    if(src_ip = 0, '', IPv4NumToString(src_ip))
                ) AS source_ip,
                if(
                    extract(message, 'DST=([0-9]{{1,3}}(?:\\.[0-9]{{1,3}}){{3}})') != '',
                    extract(message, 'DST=([0-9]{{1,3}}(?:\\.[0-9]{{1,3}}){{3}})'),
                    if(dst_ip = 0, '', IPv4NumToString(dst_ip))
                ) AS target_ip
            FROM siem.events
            WHERE {_combine_sql_filters(time_filter, operational_filter)}
              AND (
                  lower(category) IN ('authentication', 'network')
                  OR lower(subcategory) IN (
                      'linux_kernel_event',
                      'linux_firewall_blocked',
                      'ssh_login_failure',
                      'ssh_invalid_user',
                      'audit_user_login_failure',
                      'audit_user_err'
                  )
                  OR lower(log_source) IN ('linux_kernel_event', 'linux_firewall_blocked')
                  OR lower(device_product) IN ('linux.sshd', 'linux.kernel')
                  OR position(message, 'SRC=') > 0
              )
        )
        WHERE source_ip != ''
          {protected_source_filter}
          AND (target_ip = '' OR source_ip != target_ip)
        GROUP BY source_ip
        ORDER BY events DESC
        LIMIT {max(int(limit) * 8, 120)}
    """
    items: List[Dict[str, Any]] = []
    country_index: Dict[str, Dict[str, Any]] = {}
    for row in get_ch_client().query(query).named_results():
        ip_value = str(row["source_ip"] or "").strip()
        if not _is_public_ip(ip_value):
            continue
        geo = _geo_lookup(ip_value, allow_network=allow_network)
        reputation = _ip_reputation(ip_value)
        item = {
            "ip": ip_value,
            "country": str(geo.get("country") or "Unknown"),
            "country_code": str(geo.get("country_code") or ""),
            "city": str(geo.get("city") or ""),
            "lat": geo.get("lat"),
            "lon": geo.get("lon"),
            "org": str(geo.get("org") or ""),
            "events": int(row["events"] or 0),
            "last_seen": _fmt(row["last_seen"]),
            "notable_events": int(row["notable_events"] or 0),
            "auth_events": int(row["auth_events"] or 0),
            "ti_hits": int(row["ti_hits"] or 0),
            "target_ports": str(row["target_ports"] or ""),
            "target_ips": str(row.get("target_ips") or ""),
            "log_sources": str(row.get("log_sources") or ""),
            "reputation": reputation["label"],
            "reputation_sources": list(reputation["sources"]),
        }
        items.append(item)
        country_key = item["country"] or "Unknown"
        summary = country_index.setdefault(
            _normalize_country_name(country_key),
            {
                "country": country_key,
                "country_code": item["country_code"],
                "events": 0,
                "ips": 0,
            },
        )
        summary["events"] += item["events"]
        summary["ips"] += 1
        if len(items) >= int(limit):
            break
    countries = sorted(country_index.values(), key=lambda item: (-int(item["events"]), item["country"]))
    return {
        "items": items,
        "countries": countries[: max(8, int(limit))],
        "summary": {
            "countries": len(countries),
            "ips": len(items),
            "events": sum(int(item["events"]) for item in items),
        },
    }


def fetch_geo_source_activity(
    hours: int = 24,
    limit: int = 20,
    *,
    from_ts: str = "",
    to_ts: str = "",
    allow_network: bool = True,
) -> Dict[str, Any]:
    requested_hours = max(1, int(hours))
    observed_hours = requested_hours
    payload = _fetch_geo_source_activity_window(
        hours=requested_hours,
        limit=limit,
        from_ts=from_ts,
        to_ts=to_ts,
        allow_network=allow_network,
    )
    if not from_ts and not to_ts and not payload.get("items"):
        for candidate_hours in GEO_ACTIVITY_FALLBACK_WINDOWS:
            if candidate_hours <= observed_hours:
                continue
            payload = _fetch_geo_source_activity_window(
                hours=candidate_hours,
                limit=limit,
                from_ts=from_ts,
                to_ts=to_ts,
                allow_network=allow_network,
            )
            observed_hours = candidate_hours
            if payload.get("items"):
                break
    summary = dict(payload.get("summary") or {})
    summary["requested_window_hours"] = requested_hours
    summary["observed_window_hours"] = observed_hours
    summary["fallback_applied"] = observed_hours != requested_hours
    payload["summary"] = summary
    return payload


def _fetch_geo_vpn_destinations_window(
    hours: int = 24,
    limit: int = 20,
    *,
    from_ts: str = "",
    to_ts: str = "",
    allow_network: bool = True,
) -> Dict[str, Any]:
    items: List[Dict[str, Any]] = []
    country_index: Dict[str, Dict[str, Any]] = {}
    for row in fetch_top_vpn_sites(limit=max(limit, 12), hours=hours, from_ts=from_ts, to_ts=to_ts):
        domain = str(row.get("domain") or "").strip().lower()
        if not domain:
            continue
        resolved_ip = _resolve_hostname_ip(domain, allow_network=allow_network)
        if not resolved_ip:
            continue
        geo = _geo_lookup(resolved_ip, allow_network=allow_network)
        item = {
            "domain": domain,
            "ip": resolved_ip,
            "country": str(geo.get("country") or "Unknown"),
            "country_code": str(geo.get("country_code") or ""),
            "city": str(geo.get("city") or ""),
            "lat": geo.get("lat"),
            "lon": geo.get("lon"),
            "org": str(geo.get("org") or ""),
            "visits": int(row.get("visits") or 0),
            "client_id": str(row.get("client_id") or ""),
            "last_seen": str(row.get("last_seen") or ""),
        }
        items.append(item)
        country_key = item["country"] or "Unknown"
        summary = country_index.setdefault(
            _normalize_country_name(country_key),
            {
                "country": country_key,
                "country_code": item["country_code"],
                "visits": 0,
                "destinations": 0,
            },
        )
        summary["visits"] += item["visits"]
        summary["destinations"] += 1
    countries = sorted(country_index.values(), key=lambda item: (-int(item["visits"]), item["country"]))
    return {
        "items": items[: int(limit)],
        "countries": countries[: max(8, int(limit))],
        "summary": {
            "countries": len(countries),
            "destinations": len(items),
            "visits": sum(int(item["visits"]) for item in items),
        },
    }


def fetch_geo_vpn_destinations(
    hours: int = 24,
    limit: int = 20,
    *,
    from_ts: str = "",
    to_ts: str = "",
    allow_network: bool = True,
) -> Dict[str, Any]:
    requested_hours = max(1, int(hours))
    observed_hours = requested_hours
    payload = _fetch_geo_vpn_destinations_window(
        hours=requested_hours,
        limit=limit,
        from_ts=from_ts,
        to_ts=to_ts,
        allow_network=allow_network,
    )
    if not from_ts and not to_ts and not payload.get("items"):
        for candidate_hours in GEO_ACTIVITY_FALLBACK_WINDOWS:
            if candidate_hours <= observed_hours:
                continue
            payload = _fetch_geo_vpn_destinations_window(
                hours=candidate_hours,
                limit=limit,
                from_ts=from_ts,
                to_ts=to_ts,
                allow_network=allow_network,
            )
            observed_hours = candidate_hours
            if payload.get("items"):
                break
    summary = dict(payload.get("summary") or {})
    summary["requested_window_hours"] = requested_hours
    summary["observed_window_hours"] = observed_hours
    summary["fallback_applied"] = observed_hours != requested_hours
    payload["summary"] = summary
    return payload


def _dashboard_geo_payload(
    fetcher,
    *,
    hours: int,
    limit: int,
    from_ts: str = "",
    to_ts: str = "",
) -> Dict[str, Any]:
    payload = fetcher(hours=hours, limit=limit, from_ts=from_ts, to_ts=to_ts, allow_network=False)
    items = list(payload.get("items") or [])
    mappable_points = sum(
        1
        for item in items
        if item.get("country_code") and item.get("lat") is not None and item.get("lon") is not None
    )
    needs_hydration = any(
        (item.get("ip") or item.get("domain"))
        and (not item.get("country_code") or item.get("lat") is None or item.get("lon") is None)
        for item in items
    )
    if items and needs_hydration:
        hydrated = fetcher(hours=hours, limit=limit, from_ts=from_ts, to_ts=to_ts, allow_network=True)
        hydrated_items = list(hydrated.get("items") or [])
        hydrated_mappable_points = sum(
            1
            for item in hydrated_items
            if item.get("country_code") and item.get("lat") is not None and item.get("lon") is not None
        )
        if hydrated_items and hydrated_mappable_points >= mappable_points:
            return hydrated
    has_mappable_points = any(
        item.get("country_code") and item.get("lat") is not None and item.get("lon") is not None for item in items
    )
    if items and not has_mappable_points:
        hydrated = fetcher(hours=hours, limit=limit, from_ts=from_ts, to_ts=to_ts, allow_network=True)
        if hydrated.get("items"):
            return hydrated
    return payload


def _is_nonproduction_ti_entry(entry: Dict[str, Any]) -> bool:
    haystack = " ".join(
        [
            str(entry.get("indicator") or ""),
            str(entry.get("provider") or ""),
            str(entry.get("description") or ""),
            " ".join(str(item) for item in (entry.get("tags") or [])),
        ]
    ).lower()
    return any(token in haystack for token in ("smoke-test", "smoke_test", "smoke:", "test-ioc", "example-ioc", "203.0.113."))


def _protected_target_hit(target_ips: Any) -> bool:
    tokens = {str(item).strip() for item in str(target_ips or "").split(",") if str(item).strip()}
    return bool(tokens & set(PROTECTED_PUBLIC_IPS))


def fetch_geo_country_detail(country: str, hours: int = 24, limit: int = 60, kind: str = "source") -> Dict[str, Any]:
    safe_kind = "vpn" if str(kind or "").strip().lower() == "vpn" else "source"
    country_name = str(country or "").strip()
    if not country_name:
        raise ValueError("Country is required")
    cache_key = (country_name.lower(), int(hours), int(limit), safe_kind)
    cached = _GEO_COUNTRY_CACHE.get(cache_key)
    now_ts = time()
    if cached and now_ts - cached[0] < 300:
        return cached[1]
    normalized_target = _normalize_country_name(country_name)
    if safe_kind == "vpn":
        rows = fetch_geo_vpn_destinations(hours=hours, limit=max(int(limit) * 6, 120)).get("items", [])
        items = [
            {
                "label": str(row.get("domain") or row.get("ip") or ""),
                "ip": str(row.get("ip") or ""),
                "org": str(row.get("org") or "n/a"),
                "events": int(row.get("visits") or 0),
                "last_seen": str(row.get("last_seen") or ""),
                "country": str(row.get("country") or "Unknown"),
                "country_code": str(row.get("country_code") or ""),
                "client_id": str(row.get("client_id") or ""),
            }
            for row in rows
            if _normalize_country_name(str(row.get("country") or "")) == normalized_target
        ]
    else:
        rows = fetch_geo_source_activity(hours=hours, limit=max(int(limit) * 8, 180)).get("items", [])
        items = [
            {
                "label": str(row.get("ip") or ""),
                "ip": str(row.get("ip") or ""),
                "org": str(row.get("org") or "n/a"),
                "events": int(row.get("events") or 0),
                "last_seen": str(row.get("last_seen") or ""),
                "country": str(row.get("country") or "Unknown"),
                "country_code": str(row.get("country_code") or ""),
                "reputation": str(row.get("reputation") or ""),
                "reputation_sources": list(row.get("reputation_sources") or []),
                "target_ports": str(row.get("target_ports") or ""),
                "target_ips": str(row.get("target_ips") or ""),
                "log_sources": str(row.get("log_sources") or ""),
            }
            for row in rows
            if _normalize_country_name(str(row.get("country") or "")) == normalized_target
        ]
    items.sort(key=lambda item: (-int(item.get("events") or 0), str(item.get("label") or "")))
    trimmed = items[: int(limit)]
    payload = {
        "kind": safe_kind,
        "country": country_name,
        "summary": {
            "items": len(trimmed),
            "events": sum(int(item.get("events") or 0) for item in trimmed),
            "organizations": len({str(item.get("org") or "n/a") for item in trimmed}),
        },
        "items": trimmed,
    }
    _GEO_COUNTRY_CACHE[cache_key] = (now_ts, payload)
    return payload


def fetch_threat_intel_overview(
    limit: int = 20,
    hours: int = 24,
    *,
    from_ts: str = "",
    to_ts: str = "",
    allow_network: bool = False,
) -> Dict[str, Any]:
    catalog_entries = fetch_threat_intel_entries(limit=max(int(limit) * 8, 160))
    ignored_nonprod = [entry for entry in catalog_entries if _is_nonproduction_ti_entry(entry)]
    entries = [entry for entry in catalog_entries if not _is_nonproduction_ti_entry(entry)]
    provider_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    indicator_type_counts: Counter[str] = Counter()
    for entry in entries:
        provider_counts[str(entry.get("provider") or "unknown")] += 1
        severity_counts[str(entry.get("severity") or "unknown")] += 1
        indicator_type_counts[str(entry.get("indicator_type") or "unknown")] += 1

    time_filter = _time_filter("ts", hours=hours, from_ts=from_ts, to_ts=to_ts)
    operational_filter = _event_operational_filter_sql()
    recent_match_sql = f"""
        SELECT
            ti_indicator,
            anyLast(ti_indicator_type) AS indicator_type,
            anyLast(ti_provider) AS provider,
            anyLast(ti_severity) AS severity,
            count() AS events,
            max(ts) AS last_seen,
            groupUniqArray(5)(log_source) AS log_sources,
            anyLast(if(src_ip = 0, '', IPv4NumToString(src_ip))) AS sample_ip
        FROM siem.events
        WHERE {_combine_sql_filters(time_filter, operational_filter)}
          AND ti_indicator != ''
        GROUP BY ti_indicator
        ORDER BY events DESC, last_seen DESC
        LIMIT {int(limit)}
    """
    match_rows = []
    for row in get_ch_client().query(recent_match_sql).named_results():
        sample_ip = str(row.get("sample_ip") or "").strip()
        geo = _geo_lookup(sample_ip, allow_network=allow_network) if sample_ip else {}
        reputation = _ip_reputation(sample_ip) if sample_ip else {"label": "unknown", "sources": []}
        match_rows.append(
            {
                "indicator": str(row.get("ti_indicator") or ""),
                "indicator_type": str(row.get("indicator_type") or ""),
                "provider": str(row.get("provider") or ""),
                "severity": str(row.get("severity") or "medium"),
                "events": int(row.get("events") or 0),
                "last_seen": _fmt(row.get("last_seen")),
                "log_sources": [str(item) for item in (row.get("log_sources") or []) if str(item or "").strip()],
                "sample_ip": sample_ip,
                "geo": geo,
                "reputation": reputation,
            }
        )

    malicious_sources = [
        item
        for item in fetch_geo_source_activity(
            hours=hours,
            limit=max(limit * 2, 24),
            from_ts=from_ts,
            to_ts=to_ts,
            allow_network=allow_network,
        ).get("items", [])
        if str(item.get("reputation") or "unknown") != "unknown"
        or int(item.get("ti_hits") or 0) > 0
        or _protected_target_hit(item.get("target_ips"))
        or int(item.get("auth_events") or 0) > 0
    ]
    for item in malicious_sources:
        if str(item.get("reputation") or "unknown") == "unknown" and _protected_target_hit(item.get("target_ips")):
            item["reputation"] = "protected-target-activity"
            item["reputation_sources"] = sorted(set(list(item.get("reputation_sources") or []) + ["protected public IP"]))
    countries: Counter[str] = Counter()
    for item in malicious_sources:
        countries[str(item.get("country") or "Unknown")] += int(item.get("events") or 0)

    return {
        "summary": {
            "indicators": len(entries),
            "providers": len(provider_counts),
            "matches_24h": sum(int(item.get("events") or 0) for item in match_rows),
            "malicious_ips": len(malicious_sources),
            "ignored_nonprod_indicators": len(ignored_nonprod),
            "protected_target_sources": sum(1 for item in malicious_sources if _protected_target_hit(item.get("target_ips"))),
        },
        "providers": [{"provider": name, "count": count} for name, count in provider_counts.most_common(8)],
        "severity": [{"label": name, "count": count} for name, count in severity_counts.most_common(8)],
        "indicator_types": [{"label": name, "count": count} for name, count in indicator_type_counts.most_common(8)],
        "recent_matches": match_rows,
        "malicious_sources": malicious_sources[: int(limit)],
        "observed_sources": malicious_sources[: int(limit)],
        "countries": [{"country": name, "events": count} for name, count in countries.most_common(8)],
        "entries": entries[: max(int(limit), 20)],
        "ignored_nonprod_entries": ignored_nonprod[:20],
    }


def fetch_dashboard_snapshot(
    *,
    window: str = "24h",
    from_ts: str = "",
    to_ts: str = "",
    bucket_minutes: int = 60,
    recent_limit: int = 10,
) -> Dict[str, Any]:
    cache_key = json.dumps(
        [window, from_ts, to_ts, int(bucket_minutes), int(recent_limit)],
        ensure_ascii=False,
        sort_keys=True,
    )
    now_ts = time()
    cached = _DASHBOARD_SNAPSHOT_CACHE.get(cache_key)
    if cached and now_ts - cached[0] < 300:
        return dict(cached[1])
    try:
        cache_payload = json.loads(RUNTIME_DASHBOARD_SUMMARY_CACHE_FILE.read_text(encoding="utf-8"))
        file_cached = dict(cache_payload.get(cache_key) or {})
        file_cached_ts = float(file_cached.get("ts") or 0)
        file_cached_payload = file_cached.get("payload")
        if isinstance(file_cached_payload, dict) and now_ts - file_cached_ts < 300:
            _DASHBOARD_SNAPSHOT_CACHE[cache_key] = (file_cached_ts, file_cached_payload)
            return dict(file_cached_payload)
    except Exception:
        pass
    safe_bucket_minutes = _sanitize_bucket_minutes(bucket_minutes)
    safe_window = window if window in EVENT_WINDOWS else "24h"
    effective_hours = {
        "15m": 1,
        "1h": 1,
        "6h": 6,
        "24h": 24,
        "72h": 72,
        "7d": 24 * 7,
        "all": 24 * 30,
    }.get(safe_window, 24)
    dashboard_tasks = {
        "metrics": lambda: fetch_dashboard_metrics(),
        "timeline": lambda: fetch_events_timeseries(hours=effective_hours, bucket_minutes=safe_bucket_minutes, from_ts=from_ts, to_ts=to_ts),
        "alert_timeline": lambda: fetch_alert_timeseries(hours=effective_hours, bucket_minutes=safe_bucket_minutes, from_ts=from_ts, to_ts=to_ts),
        "severity_breakdown": lambda: fetch_severity_breakdown(hours=effective_hours, from_ts=from_ts, to_ts=to_ts),
        "alert_severity_breakdown": lambda: fetch_alert_severity_breakdown(hours=effective_hours, from_ts=from_ts, to_ts=to_ts),
        "alert_status_breakdown": lambda: fetch_alert_status_breakdown(hours=effective_hours, from_ts=from_ts, to_ts=to_ts),
        "top_sources": lambda: fetch_top_sources(limit=8, hours=effective_hours, from_ts=from_ts, to_ts=to_ts),
        "top_target_ports": lambda: fetch_top_target_ports(limit=10, hours=effective_hours, from_ts=from_ts, to_ts=to_ts),
        "top_vpn_sites": lambda: fetch_top_vpn_sites(limit=10, hours=effective_hours, from_ts=from_ts, to_ts=to_ts),
        "geo_sources": lambda: _dashboard_geo_payload(
            fetch_geo_source_activity,
            hours=effective_hours,
            limit=16,
            from_ts=from_ts,
            to_ts=to_ts,
        ),
        "geo_vpn_destinations": lambda: _dashboard_geo_payload(
            fetch_geo_vpn_destinations,
            hours=effective_hours,
            limit=12,
            from_ts=from_ts,
            to_ts=to_ts,
        ),
        "threat_intel": lambda: fetch_threat_intel_overview(
            limit=12,
            hours=effective_hours,
            from_ts=from_ts,
            to_ts=to_ts,
            allow_network=False,
        ),
        "top_categories": lambda: fetch_top_categories(limit=8, hours=effective_hours, from_ts=from_ts, to_ts=to_ts),
        "recent_alerts": lambda: fetch_recent_alerts(limit=max(5, min(int(recent_limit), 60)), from_ts=from_ts, to_ts=to_ts),
        "platform_status": lambda: fetch_platform_status(),
    }
    payload: Dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=min(4, len(dashboard_tasks)), thread_name_prefix="dashboard") as executor:
        futures = {executor.submit(task): name for name, task in dashboard_tasks.items()}
        for future in as_completed(futures):
            payload[futures[future]] = future.result()
    payload.update({
        "timeline_window": {
            "window": safe_window,
            "from_ts": _clean_datetime_input(from_ts) if from_ts else "",
            "to_ts": _clean_datetime_input(to_ts) if to_ts else "",
            "bucket_minutes": safe_bucket_minutes,
            "recent_limit": max(5, min(int(recent_limit), 60)),
        },
    })
    _DASHBOARD_SNAPSHOT_CACHE[cache_key] = (now_ts, payload)
    if len(_DASHBOARD_SNAPSHOT_CACHE) > 32:
        oldest_key = min(_DASHBOARD_SNAPSHOT_CACHE, key=lambda key: _DASHBOARD_SNAPSHOT_CACHE[key][0])
        _DASHBOARD_SNAPSHOT_CACHE.pop(oldest_key, None)
    try:
        RUNTIME_DOCS_DIR.mkdir(parents=True, exist_ok=True)
        cache_payload = {}
        if RUNTIME_DASHBOARD_SUMMARY_CACHE_FILE.exists():
            cache_payload = json.loads(RUNTIME_DASHBOARD_SUMMARY_CACHE_FILE.read_text(encoding="utf-8"))
            if not isinstance(cache_payload, dict):
                cache_payload = {}
        cache_payload[cache_key] = {"ts": now_ts, "payload": payload}
        for key, item in list(cache_payload.items()):
            item_ts = float(item.get("ts") or 0) if isinstance(item, dict) else 0
            if now_ts - item_ts > 900:
                cache_payload.pop(key, None)
        tmp_path = RUNTIME_DASHBOARD_SUMMARY_CACHE_FILE.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(cache_payload, ensure_ascii=False), encoding="utf-8")
        tmp_path.replace(RUNTIME_DASHBOARD_SUMMARY_CACHE_FILE)
    except Exception:
        pass
    return dict(payload)


def _ensure_runtime_docs_dir() -> Path:
    RUNTIME_DOCS_DIR.mkdir(parents=True, exist_ok=True)
    return RUNTIME_DOCS_DIR


def _safe_doc_name(name: str) -> str:
    candidate = re.sub(r"[^A-Za-z0-9._-]+", "_", (name or "").strip())
    if not candidate:
        raise ValueError("Document name is required")
    return candidate


def _flatten_toc_tokens(tokens: List[Dict[str, Any]], level: int = 1) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for token in tokens or []:
        rows.append(
            {
                "id": str(token.get("id") or ""),
                "name": str(token.get("name") or ""),
                "level": int(token.get("level") or level),
            }
        )
        children = token.get("children") or []
        if children:
            rows.extend(_flatten_toc_tokens(children, level + 1))
    return rows


def _render_runtime_doc_content(content: str) -> Dict[str, Any]:
    text = content or ""
    if markdown_lib is None:
        return {
            "content_html": "<pre>" + html.escape(text) + "</pre>",
            "toc": [],
        }
    md = markdown_lib.Markdown(
        extensions=[
            "extra",
            "tables",
            "toc",
            "sane_lists",
            "nl2br",
        ]
    )
    rendered = md.convert(text)
    toc_tokens = getattr(md, "toc_tokens", []) or []
    return {
        "content_html": rendered,
        "toc": _flatten_toc_tokens(toc_tokens),
    }


def list_runtime_docs() -> List[Dict[str, Any]]:
    doc_dir = _ensure_runtime_docs_dir()
    docs_index: Dict[str, Dict[str, Any]] = {}
    backend = content_store_backend()
    stored_docs = list_content_collection("docs_pages") or []
    for item in stored_docs:
        if not isinstance(item, dict):
            continue
        name = _safe_doc_name(str(item.get("name") or item.get("id") or "").strip())
        if not name:
            continue
        content = str(item.get("content") or "")
        docs_index[name] = {
            "name": name,
            "size": len(content.encode("utf-8")),
            "updated_ts": str(item.get("updated_ts") or ""),
            "storage": backend,
        }
    for item in sorted(doc_dir.iterdir(), key=lambda path: (path.is_file() is False, path.name.lower())):
        if not item.is_file():
            continue
        existing = docs_index.get(item.name, {})
        docs_index[item.name] = {
            "name": item.name,
            "size": int(existing.get("size") or item.stat().st_size),
            "updated_ts": str(existing.get("updated_ts") or _fmt(datetime.fromtimestamp(item.stat().st_mtime))),
            "storage": backend,
        }
    return list(docs_index.values())


def load_runtime_doc(name: str) -> Dict[str, Any]:
    doc_dir = _ensure_runtime_docs_dir()
    safe_name = _safe_doc_name(name)
    path = doc_dir / safe_name
    payload = load_text_document("docs_pages", safe_name, path)
    if payload is None:
        raise FileNotFoundError(safe_name)
    content = str(payload.get("content") or "")
    rendered = _render_runtime_doc_content(content)
    updated_ts = payload.get("updated_ts") or (_fmt(datetime.fromtimestamp(path.stat().st_mtime)) if path.exists() else "")
    return {
        "name": safe_name,
        "content": content,
        "content_html": rendered["content_html"],
        "toc": rendered["toc"],
        "size": len(content.encode("utf-8")),
        "updated_ts": updated_ts,
    }


def save_runtime_doc(name: str, content: str) -> Dict[str, Any]:
    doc_dir = _ensure_runtime_docs_dir()
    safe_name = _safe_doc_name(name)
    path = doc_dir / safe_name
    save_text_document(
        "docs_pages",
        safe_name,
        path,
        {
            "name": safe_name,
            "content": content or "",
            "updated_ts": _fmt(datetime.utcnow()),
        },
    )
    return load_runtime_doc(safe_name)


def save_runtime_doc_file(filename: str, payload: bytes) -> Dict[str, Any]:
    doc_dir = _ensure_runtime_docs_dir()
    safe_name = _safe_doc_name(filename)
    path = doc_dir / safe_name
    path.write_bytes(payload or b"")
    save_text_document(
        "docs_pages",
        safe_name,
        path,
        {
            "name": safe_name,
            "content": path.read_text(encoding="utf-8", errors="ignore"),
            "updated_ts": _fmt(datetime.utcnow()),
        },
    )
    return load_runtime_doc(safe_name)


def delete_runtime_doc(name: str) -> None:
    doc_dir = _ensure_runtime_docs_dir()
    safe_name = _safe_doc_name(name)
    path = doc_dir / safe_name
    delete_text_document("docs_pages", safe_name, path)


def migrate_content_store() -> Dict[str, Any]:
    from .content_runtime import migrate_content_store as migrate_content_store_impl

    return migrate_content_store_impl()


def content_storage_status() -> Dict[str, Any]:
    from .content_runtime import content_storage_status as content_storage_status_impl

    return content_storage_status_impl()


def _load_runtime_json_file(path: Path, default: Any) -> Any:
    _ensure_runtime_docs_dir()
    if not path.exists():
        path.write_text(json.dumps(default, ensure_ascii=False, indent=2), encoding="utf-8")
        return json.loads(json.dumps(default))
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        path.write_text(json.dumps(default, ensure_ascii=False, indent=2), encoding="utf-8")
        return json.loads(json.dumps(default))


def _save_runtime_json_file(path: Path, payload: Any) -> None:
    _ensure_runtime_docs_dir()
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _widget_catalog_index() -> Dict[str, Dict[str, Any]]:
    return {str(item["id"]): dict(item) for item in WIDGET_CATALOG}


def _default_dashboard_layout(widgets: List[str]) -> List[Dict[str, Any]]:
    catalog = _widget_catalog_index()
    layout = []
    for widget_id in widgets:
        spec = catalog.get(str(widget_id))
        if not spec:
            continue
        layout.append(
            {
                "widget": str(widget_id),
                "span": int(spec.get("default_span") or 1),
            }
        )
    return layout


def _coerce_dashboard_layout(raw_layout: Any, widgets: List[str]) -> List[Dict[str, Any]]:
    catalog = _widget_catalog_index()
    widget_set = {str(item) for item in widgets}
    layout: List[Dict[str, Any]] = []
    if isinstance(raw_layout, list):
        for item in raw_layout:
            if not isinstance(item, dict):
                continue
            widget_id = str(item.get("widget") or "").strip()
            if widget_id not in widget_set or widget_id not in catalog:
                continue
            span = 2 if int(item.get("span") or 1) >= 2 else 1
            if widget_id not in {row["widget"] for row in layout}:
                layout.append({"widget": widget_id, "span": span})
    for widget_id in widgets:
        if widget_id not in {row["widget"] for row in layout}:
            spec = catalog.get(widget_id) or {}
            layout.append({"widget": widget_id, "span": int(spec.get("default_span") or 1)})
    return layout


def _load_dashboard_registry() -> List[Dict[str, Any]]:
    payload = load_list("dashboard_instances", RUNTIME_DASHBOARDS_FILE, DEFAULT_DASHBOARDS)
    default_index = {}
    for item in DEFAULT_DASHBOARDS:
        widgets = [str(widget) for widget in item.get("widgets", []) if str(widget).strip()]
        default_index[str(item["id"])] = {
            "id": str(item["id"]),
            "title": str(item["title"]),
            "description": str(item.get("description") or ""),
            "widgets": widgets,
            "layout": _default_dashboard_layout(widgets),
            "built_in": bool(item.get("built_in", False)),
        }
    dashboards: List[Dict[str, Any]] = []
    if isinstance(payload, list):
        for item in payload:
            if not isinstance(item, dict):
                continue
            widgets = item.get("widgets") or []
            if not isinstance(widgets, list):
                widgets = []
            clean_widgets = [str(widget) for widget in widgets if str(widget).strip()]
            dashboard_id = _safe_doc_name(str(item.get("id", "") or ""))
            if bool(item.get("built_in", False)) and dashboard_id in default_index:
                base = dict(default_index[dashboard_id])
                dashboards.append(base)
                continue
            dashboards.append(
                {
                    "id": dashboard_id,
                    "title": str(item.get("title", "") or "").strip() or "Dashboard",
                    "description": str(item.get("description", "") or "").strip(),
                    "widgets": clean_widgets,
                    "layout": _coerce_dashboard_layout(item.get("layout"), clean_widgets),
                    "built_in": bool(item.get("built_in", False)),
                }
            )
    if not dashboards:
        dashboards = list(default_index.values())
    return dashboards


def list_dashboards() -> List[Dict[str, Any]]:
    return _load_dashboard_registry()


def describe_dashboard_widgets() -> List[Dict[str, Any]]:
    return [dict(item) for item in WIDGET_CATALOG]


def save_dashboard_definition(
    title: str,
    description: str,
    widgets: List[str],
    layout: List[Dict[str, Any]] | None = None,
    dashboard_id: str = "",
) -> Dict[str, Any]:
    dashboards = _load_dashboard_registry()
    clean_title = str(title or "").strip()
    if not clean_title:
        raise ValueError("Dashboard title is required")
    resolved_dashboard_id = _safe_doc_name(str(dashboard_id or "").strip()) or _safe_doc_name(clean_title.lower())
    allowed_widgets = {item["id"] for item in WIDGET_CATALOG}
    widget_list = []
    for item in widgets:
        widget_id = str(item).strip()
        if widget_id and widget_id in allowed_widgets and widget_id not in widget_list:
            widget_list.append(widget_id)
    if not widget_list:
        raise ValueError("At least one widget must be selected")
    item = {
        "id": resolved_dashboard_id,
        "title": clean_title,
        "description": str(description or "").strip(),
        "widgets": widget_list,
        "layout": _coerce_dashboard_layout(layout or [], widget_list),
        "built_in": False,
    }
    dashboards = [row for row in dashboards if row["id"] != resolved_dashboard_id]
    dashboards.append(item)
    save_list("dashboard_instances", RUNTIME_DASHBOARDS_FILE, dashboards)
    return item


def delete_dashboard_definition(dashboard_id: str) -> None:
    safe_id = _safe_doc_name(dashboard_id)
    dashboards = [row for row in _load_dashboard_registry() if not (row["id"] == safe_id and not row.get("built_in"))]
    save_list("dashboard_instances", RUNTIME_DASHBOARDS_FILE, dashboards)


def list_builder_drafts() -> List[Dict[str, Any]]:
    payload = load_list("builder_drafts", RUNTIME_BUILDER_DRAFTS_FILE, DEFAULT_BUILDER_DRAFTS)
    drafts: List[Dict[str, Any]] = []
    if isinstance(payload, list):
        for item in payload:
            if not isinstance(item, dict):
                continue
            blocks = item.get("blocks") or []
            if not isinstance(blocks, list):
                blocks = []
            history = item.get("history") or []
            if not isinstance(history, list):
                history = []
            drafts.append(
                {
                    "id": _safe_doc_name(str(item.get("id", "") or "")),
                    "title": str(item.get("title", "") or "").strip() or "Draft",
                    "description": str(item.get("description", "") or "").strip(),
                    "kind": str(item.get("kind", "") or "generic"),
                    "status": str(item.get("status", "") or "draft"),
                    "version": max(1, int(item.get("version") or 1)),
                    "updated_ts": str(item.get("updated_ts", "") or ""),
                    "published_ts": str(item.get("published_ts", "") or ""),
                    "history": [dict(entry) for entry in history if isinstance(entry, dict)][:12],
                    "blocks": [_normalize_builder_block(dict(block), index) for index, block in enumerate(blocks) if isinstance(block, dict)],
                }
            )
    if not drafts:
        drafts = [dict(item) for item in DEFAULT_BUILDER_DRAFTS]
    return drafts


def save_builder_draft(
    title: str,
    description: str,
    kind: str,
    blocks: List[Dict[str, Any]],
    draft_id: str = "",
    status: str = "draft",
) -> Dict[str, Any]:
    clean_title = str(title or "").strip()
    if not clean_title:
        raise ValueError("Draft title is required")
    validation = validate_builder_draft_payload(clean_title, description, kind, blocks)
    clean_blocks = validation["normalized_blocks"]
    if validation["errors"]:
        raise ValueError("; ".join(validation["errors"]))
    existing_drafts = list_builder_drafts()
    safe_id = _safe_doc_name(str(draft_id or clean_title.lower()))
    existing = next((row for row in existing_drafts if row["id"] == safe_id), None)
    version = max(1, int((existing or {}).get("version") or 0) + 1)
    now = _now_iso()
    history = [dict(entry) for entry in ((existing or {}).get("history") or []) if isinstance(entry, dict)]
    history.insert(
        0,
        {
            "ts": now,
            "action": "save",
            "version": version,
            "status": str(status or (existing or {}).get("status") or "draft"),
        },
    )
    draft = {
        "id": safe_id,
        "title": clean_title,
        "description": str(description or "").strip(),
        "kind": str(kind or "generic").strip() or "generic",
        "status": str(status or (existing or {}).get("status") or "draft"),
        "version": version,
        "updated_ts": now,
        "published_ts": str((existing or {}).get("published_ts") or ""),
        "history": history[:12],
        "blocks": clean_blocks,
    }
    drafts = [row for row in existing_drafts if row["id"] != draft["id"]]
    drafts.append(draft)
    save_list("builder_drafts", RUNTIME_BUILDER_DRAFTS_FILE, drafts)
    return draft


def delete_builder_draft(draft_id: str) -> None:
    safe_id = _safe_doc_name(draft_id)
    drafts = [row for row in list_builder_drafts() if row["id"] != safe_id]
    save_list("builder_drafts", RUNTIME_BUILDER_DRAFTS_FILE, drafts)


def test_builder_draft_payload(
    title: str,
    description: str,
    kind: str,
    blocks: List[Dict[str, Any]],
) -> Dict[str, Any]:
    validation = validate_builder_draft_payload(title, description, kind, blocks)
    tests: List[Dict[str, Any]] = []
    if validation["valid"]:
        for block in validation["normalized_blocks"]:
            if block["type"] != "detection":
                continue
            rule_id = str(block.get("config", {}).get("rule_id") or "").strip()
            if rule_id.isdigit():
                tests.append(test_detection_rule(int(rule_id)))
                continue
            tests.append(
                {
                    "block_id": block["id"],
                    "title": block["label"],
                    "threshold": int(block.get("config", {}).get("threshold") or 1),
                    "window_s": int(block.get("config", {}).get("window_s") or 300),
                    "entity_field": str(block.get("config", {}).get("entity_field") or "log_source"),
                    "result": "Synthetic validation only: detection block has no linked runtime rule_id yet.",
                }
            )
    return {
        "valid": validation["valid"],
        "errors": validation["errors"],
        "warnings": validation["warnings"],
        "compiled": validation["compiled"],
        "tests": tests,
    }


def publish_builder_draft(draft_id: str) -> Dict[str, Any]:
    safe_id = _safe_doc_name(draft_id)
    drafts = list_builder_drafts()
    draft = next((row for row in drafts if row["id"] == safe_id), None)
    if draft is None:
        raise ValueError("Builder draft not found")
    validation = validate_builder_draft_payload(draft["title"], draft["description"], draft["kind"], draft["blocks"])
    if validation["errors"]:
        raise ValueError("; ".join(validation["errors"]))
    now = _now_iso()
    published = dict(draft)
    published["status"] = "published"
    published["version"] = max(1, int(draft.get("version") or 1) + 1)
    published["updated_ts"] = now
    published["published_ts"] = now
    history = [dict(entry) for entry in (draft.get("history") or []) if isinstance(entry, dict)]
    history.insert(
        0,
        {
            "ts": now,
            "action": "publish",
            "version": published["version"],
            "status": "published",
        },
    )
    published["history"] = history[:12]
    remaining = [row for row in drafts if row["id"] != safe_id]
    remaining.append(published)
    save_list("builder_drafts", RUNTIME_BUILDER_DRAFTS_FILE, remaining)
    return {
        "id": published["id"],
        "status": published["status"],
        "version": published["version"],
        "published_ts": published["published_ts"],
        "compiled": validation["compiled"],
    }


def ensure_cold_storage_support() -> None:
    ensure_event_enrichment_support()
    get_ch_client().command(
        f"""
        CREATE TABLE IF NOT EXISTS {EVENTS_COLD_TABLE}
        (
            ts DateTime,
            event_id String,
            event_code String DEFAULT '',
            category String,
            subcategory String,
            event_action String DEFAULT '',
            event_outcome String DEFAULT '',
            src_ip UInt32,
            dst_ip UInt32,
            src_port UInt16,
            dst_port UInt16,
            device_vendor String,
            device_product String,
            log_source String,
            host_name String DEFAULT '',
            asset_id String DEFAULT '',
            asset_owner String DEFAULT '',
            asset_criticality String DEFAULT '',
            asset_environment String DEFAULT '',
            asset_service String DEFAULT '',
            user_name String DEFAULT '',
            target_user String DEFAULT '',
            process_name String DEFAULT '',
            process_executable String DEFAULT '',
            process_command String DEFAULT '',
            ti_indicator String DEFAULT '',
            ti_indicator_type String DEFAULT '',
            ti_provider String DEFAULT '',
            ti_severity String DEFAULT '',
            severity String,
            message String,
            normalized_json String DEFAULT '',
            tags String
        )
        ENGINE = MergeTree
        ORDER BY (ts, log_source, event_id)
        """
    )


def ensure_incident_workflow_support() -> None:
    global _INCIDENT_WORKFLOW_READY
    if _INCIDENT_WORKFLOW_READY:
        return
    for table in ("siem.alerts_raw", "siem.alerts_agg"):
        get_ch_client().command(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS assignee String DEFAULT ''")
        get_ch_client().command(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS updated_ts DateTime DEFAULT now()")
    get_ch_client().command(
        f"""
        CREATE TABLE IF NOT EXISTS {ALERT_HISTORY_TABLE}
        (
            changed_ts DateTime DEFAULT now(),
            view LowCardinality(String),
            record_id String,
            rule_id UInt32,
            previous_status LowCardinality(String),
            next_status LowCardinality(String),
            previous_assignee String,
            next_assignee String,
            changed_by String,
            note String
        )
        ENGINE = MergeTree
        ORDER BY (view, record_id, changed_ts)
        """
    )
    _INCIDENT_WORKFLOW_READY = True


def ensure_active_list_support() -> None:
    get_ch_client().command(
        f"""
        CREATE TABLE IF NOT EXISTS {ACTIVE_LIST_TABLE}
        (
            list_name LowCardinality(String),
            list_kind LowCardinality(String) DEFAULT 'watch',
            value String,
            value_type LowCardinality(String),
            label String,
            tags String,
            enabled UInt8,
            updated_ts DateTime DEFAULT now()
        )
        ENGINE = MergeTree
        ORDER BY (list_name, value)
        """
    )
    get_ch_client().command(f"ALTER TABLE {ACTIVE_LIST_TABLE} ADD COLUMN IF NOT EXISTS list_kind LowCardinality(String) DEFAULT 'watch'")


def fetch_active_list_items(limit: int = 200) -> List[Dict[str, Any]]:
    ensure_active_list_support()
    query = f"""
        SELECT
            list_name,
            list_kind,
            value_type,
            value,
            label,
            tags,
            enabled,
            updated_ts
        FROM {ACTIVE_LIST_TABLE}
        ORDER BY updated_ts DESC, list_name, value
        LIMIT {int(limit)}
    """
    return [
        {
            "list_name": row["list_name"],
            "list_kind": row.get("list_kind", "watch"),
            "item_type": row["value_type"],
            "item_value": row["value"],
            "item_label": row["label"],
            "tags": [part for part in str(row["tags"] or "").split(",") if part],
            "enabled": bool(row["enabled"]),
            "updated_ts": _fmt(row["updated_ts"]),
        }
        for row in get_ch_client().query(query).named_results()
    ]


def save_active_list_item(
    *,
    list_name: str,
    list_kind: str,
    item_type: str,
    item_value: str,
    item_label: str = "",
    tags: str = "",
) -> Dict[str, Any]:
    ensure_active_list_support()
    safe_list_name = (list_name or "").strip()
    safe_list_kind = (list_kind or "watch").strip().lower()
    safe_item_type = (item_type or "").strip().lower()
    safe_item_value = (item_value or "").strip()
    safe_item_label = (item_label or "").strip()
    safe_tags = ",".join(part.strip() for part in str(tags or "").split(",") if part.strip())
    if safe_list_kind not in {"watch", "allow", "deny"}:
        raise ValueError("Active list kind must be watch, allow or deny")
    if not safe_list_name or not safe_item_type or not safe_item_value:
        raise ValueError("Active list name, item type and item value are required")
    get_ch_client().command(
        f"""
        ALTER TABLE {ACTIVE_LIST_TABLE}
        DELETE WHERE
            list_name = {_sql_quote(safe_list_name)}
            AND list_kind = {_sql_quote(safe_list_kind)}
            AND value_type = {_sql_quote(safe_item_type)}
            AND value = {_sql_quote(safe_item_value)}
        """
    )
    get_ch_client().insert(
        ACTIVE_LIST_TABLE,
        [[safe_list_name, safe_list_kind, safe_item_value, safe_item_type, safe_item_label, safe_tags, 1]],
        column_names=["list_name", "list_kind", "value", "value_type", "label", "tags", "enabled"],
    )
    return {
        "list_name": safe_list_name,
        "list_kind": safe_list_kind,
        "item_type": safe_item_type,
        "item_value": safe_item_value,
        "item_label": safe_item_label,
        "tags": safe_tags,
    }


def _normalize_csv(value: str) -> str:
    return ",".join(part.strip() for part in str(value or "").split(",") if part.strip())


def fetch_cmdb_assets(limit: int = 200) -> List[Dict[str, Any]]:
    ensure_cmdb_ti_support()
    query = f"""
        SELECT
            asset_id,
            asset_type,
            hostname,
            ip,
            owner,
            criticality,
            environment,
            business_service,
            os_family,
            expected_ports,
            tags,
            notes,
            enabled,
            updated_ts
        FROM {CMDB_ASSET_TABLE}
        ORDER BY updated_ts DESC, asset_id
        LIMIT 1 BY asset_id
        LIMIT {int(limit)}
    """
    rows: List[Dict[str, Any]] = []
    for row in get_ch_client().query(query).named_results():
        rows.append(
            {
                "asset_id": str(row["asset_id"] or ""),
                "asset_type": str(row["asset_type"] or ""),
                "hostname": str(row["hostname"] or ""),
                "ip": str(row["ip"] or ""),
                "owner": str(row["owner"] or ""),
                "criticality": str(row["criticality"] or ""),
                "environment": str(row["environment"] or ""),
                "business_service": str(row["business_service"] or ""),
                "os_family": str(row["os_family"] or ""),
                "expected_ports": [part for part in str(row["expected_ports"] or "").split(",") if part],
                "tags": [part for part in str(row["tags"] or "").split(",") if part],
                "notes": str(row["notes"] or ""),
                "enabled": bool(row["enabled"]),
                "updated_ts": _fmt(row["updated_ts"]),
            }
        )
    return rows


def save_cmdb_asset(
    *,
    asset_id: str,
    asset_type: str,
    hostname: str,
    ip: str,
    owner: str,
    criticality: str,
    environment: str,
    business_service: str,
    os_family: str,
    expected_ports: str,
    tags: str,
    notes: str,
) -> Dict[str, Any]:
    ensure_cmdb_ti_support()
    safe_asset_id = (asset_id or "").strip()
    safe_asset_type = (asset_type or "server").strip().lower()
    safe_hostname = (hostname or "").strip().lower()
    safe_ip = (ip or "").strip()
    safe_owner = (owner or "").strip()
    safe_criticality = (criticality or "medium").strip().lower()
    safe_environment = (environment or "prod").strip().lower()
    safe_business_service = (business_service or "").strip()
    safe_os_family = (os_family or "").strip().lower()
    safe_expected_ports = _normalize_csv(expected_ports)
    safe_tags = _normalize_csv(tags)
    safe_notes = (notes or "").strip()
    if not safe_asset_id:
        raise ValueError("asset_id is required")
    if safe_criticality not in {"low", "medium", "high", "critical"}:
        raise ValueError("criticality must be low, medium, high or critical")
    get_ch_client().insert(
        CMDB_ASSET_TABLE,
        [[
            safe_asset_id,
            safe_asset_type,
            safe_hostname,
            safe_ip,
            safe_owner,
            safe_criticality,
            safe_environment,
            safe_business_service,
            safe_os_family,
            safe_expected_ports,
            safe_tags,
            safe_notes,
            1,
        ]],
        column_names=[
            "asset_id",
            "asset_type",
            "hostname",
            "ip",
            "owner",
            "criticality",
            "environment",
            "business_service",
            "os_family",
            "expected_ports",
            "tags",
            "notes",
            "enabled",
        ],
    )
    return {
        "asset_id": safe_asset_id,
        "hostname": safe_hostname,
        "ip": safe_ip,
        "criticality": safe_criticality,
        "environment": safe_environment,
    }


def fetch_threat_intel_entries(limit: int = 200) -> List[Dict[str, Any]]:
    ensure_cmdb_ti_support()
    query = f"""
        SELECT
            indicator_type,
            indicator,
            provider,
            severity,
            confidence,
            description,
            tags,
            enabled,
            expires_ts,
            updated_ts
        FROM {THREAT_INTEL_TABLE}
        ORDER BY updated_ts DESC, indicator_type, indicator
        LIMIT {int(limit)}
    """
    rows: List[Dict[str, Any]] = []
    for row in get_ch_client().query(query).named_results():
        rows.append(
            {
                "indicator_type": str(row["indicator_type"] or ""),
                "indicator": str(row["indicator"] or ""),
                "provider": str(row["provider"] or ""),
                "severity": str(row["severity"] or ""),
                "confidence": int(row["confidence"] or 0),
                "description": str(row["description"] or ""),
                "tags": [part for part in str(row["tags"] or "").split(",") if part],
                "enabled": bool(row["enabled"]),
                "expires_ts": _fmt(row["expires_ts"]),
                "updated_ts": _fmt(row["updated_ts"]),
            }
        )
    return rows


def save_threat_intel_indicator(
    *,
    indicator_type: str,
    indicator: str,
    provider: str,
    severity: str,
    confidence: int,
    description: str,
    tags: str,
) -> Dict[str, Any]:
    ensure_cmdb_ti_support()
    safe_indicator_type = (indicator_type or "").strip().lower()
    safe_indicator = (indicator or "").strip().lower()
    safe_provider = (provider or "").strip()
    safe_severity = (severity or "medium").strip().lower()
    safe_confidence = max(0, min(100, int(confidence or 0)))
    safe_description = (description or "").strip()
    safe_tags = _normalize_csv(tags)
    if safe_indicator_type not in {"ip", "host", "user", "process", "raw"}:
        raise ValueError("indicator_type must be ip, host, user, process or raw")
    if not safe_indicator:
        raise ValueError("indicator is required")
    get_ch_client().command(
        f"""
        ALTER TABLE {THREAT_INTEL_TABLE}
        DELETE WHERE
            indicator_type = {_sql_quote(safe_indicator_type)}
            AND indicator = {_sql_quote(safe_indicator)}
            AND provider = {_sql_quote(safe_provider)}
        """
    )
    get_ch_client().insert(
        THREAT_INTEL_TABLE,
        [[safe_indicator_type, safe_indicator, safe_provider, safe_severity, safe_confidence, safe_description, safe_tags, 1]],
        column_names=["indicator_type", "indicator", "provider", "severity", "confidence", "description", "tags", "enabled"],
    )
    return {
        "indicator_type": safe_indicator_type,
        "indicator": safe_indicator,
        "provider": safe_provider,
        "severity": safe_severity,
        "confidence": safe_confidence,
    }


def _parse_import_records(payload: str) -> List[Dict[str, Any]]:
    text = str(payload or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except Exception:
        data = None
    if isinstance(data, dict):
        if isinstance(data.get("items"), list):
            return [dict(item) for item in data["items"] if isinstance(item, dict)]
        return [data]
    if isinstance(data, list):
        return [dict(item) for item in data if isinstance(item, dict)]
    reader = csv.DictReader(io.StringIO(text))
    rows: List[Dict[str, Any]] = []
    for row in reader:
        if any(str(value or "").strip() for value in row.values()):
            rows.append({str(key or "").strip(): str(value or "").strip() for key, value in row.items()})
    return rows


def import_cmdb_assets(payload: str) -> Dict[str, Any]:
    records = _parse_import_records(payload)
    if not records:
        raise ValueError("No CMDB records found in JSON/CSV payload")
    saved = 0
    for row in records:
        asset_id = str(row.get("asset_id") or row.get("id") or "").strip()
        hostname = str(row.get("hostname") or row.get("host") or row.get("name") or "").strip()
        ip = str(row.get("ip") or row.get("address") or "").strip()
        if not asset_id:
            if hostname:
                asset_id = f"asset-{re.sub(r'[^a-z0-9]+', '-', hostname.lower()).strip('-')}"
            elif ip:
                asset_id = f"asset-{ip.replace('.', '-')}"
        if not asset_id:
            continue
        save_cmdb_asset(
            asset_id=asset_id,
            asset_type=str(row.get("asset_type") or row.get("type") or "server"),
            hostname=hostname,
            ip=ip,
            owner=str(row.get("owner") or ""),
            criticality=str(row.get("criticality") or "medium"),
            environment=str(row.get("environment") or "prod"),
            business_service=str(row.get("business_service") or row.get("service") or ""),
            os_family=str(row.get("os_family") or row.get("os") or ""),
            expected_ports=str(row.get("expected_ports") or row.get("ports") or ""),
            tags=str(row.get("tags") or ""),
            notes=str(row.get("notes") or row.get("description") or ""),
        )
        saved += 1
    return {"saved": saved, "parsed": len(records)}


def import_threat_intel_entries(payload: str) -> Dict[str, Any]:
    records = _parse_import_records(payload)
    if not records:
        raise ValueError("No threat intel records found in JSON/CSV payload")
    saved = 0
    for row in records:
        indicator = str(row.get("indicator") or row.get("value") or row.get("ioc") or "").strip()
        if not indicator:
            continue
        save_threat_intel_indicator(
            indicator_type=str(row.get("indicator_type") or row.get("type") or "raw"),
            indicator=indicator,
            provider=str(row.get("provider") or row.get("feed") or "import"),
            severity=str(row.get("severity") or "medium"),
            confidence=int(str(row.get("confidence") or 50)),
            description=str(row.get("description") or row.get("notes") or ""),
            tags=str(row.get("tags") or row.get("labels") or ""),
        )
        saved += 1
    return {"saved": saved, "parsed": len(records)}


def sync_observed_assets_to_cmdb(hours: int = 72, limit: int = 200) -> Dict[str, Any]:
    ensure_cmdb_ti_support()
    operational_filter = _event_operational_filter_sql()
    observed_query = f"""
        SELECT
            asset_name,
            any(host_name) AS host_name,
            any(log_source) AS log_source,
            any(src_ip_text) AS src_ip_text,
            any(device_product) AS device_product,
            max(ts) AS last_seen
        FROM
        (
            SELECT
                if(host_name != '' AND host_name != '-', host_name, log_source) AS asset_name,
                host_name,
                log_source,
                if(src_ip = 0, '', IPv4NumToString(src_ip)) AS src_ip_text,
                device_product,
                ts
            FROM siem.events
            WHERE {_combine_sql_filters(f"ts >= now() - INTERVAL {int(hours)} HOUR", operational_filter)}
        )
        WHERE asset_name != ''
        GROUP BY asset_name
        ORDER BY last_seen DESC
        LIMIT {int(limit)}
    """
    existing = fetch_cmdb_assets(limit=5000)
    known = {item["asset_id"] for item in existing} | {item["hostname"] for item in existing if item["hostname"]} | {item["ip"] for item in existing if item["ip"]}
    created = 0
    for row in get_ch_client().query(observed_query).named_results():
        asset_name = str(row["asset_name"] or "").strip()
        host_name = str(row["host_name"] or "").strip()
        ip_value = str(row["src_ip_text"] or "").strip()
        if not _is_observed_cmdb_autocreate_candidate(asset_name=asset_name, host_name=host_name, ip_value=ip_value):
            continue
        if asset_name in known or host_name in known or ip_value in known:
            continue
        seed = host_name or asset_name or ip_value
        if not seed:
            continue
        asset_id = f"asset-{re.sub(r'[^a-z0-9]+', '-', seed.lower()).strip('-')}"
        save_cmdb_asset(
            asset_id=asset_id,
            asset_type="server",
            hostname=host_name or asset_name,
            ip=ip_value,
            owner="soc-discovered",
            criticality="medium",
            environment="unknown",
            business_service="Observed asset",
            os_family="windows" if str(row["device_product"] or "").startswith("windows.") else "linux",
            expected_ports="",
            tags="auto-discovered,telemetry",
            notes=f"Auto-created from observed events during the last {int(hours)} hours.",
        )
        created += 1
        known.add(asset_id)
    return {"created": created, "hours": int(hours), "limit": int(limit)}


def archive_events_to_cold(older_than_hours: int) -> Dict[str, Any]:
    ensure_cold_storage_support()
    safe_hours = max(1, int(older_than_hours))
    threshold = f"now() - INTERVAL {safe_hours} HOUR"
    moved_rows = int(
        _scalar(
            f"""
            SELECT count()
            FROM siem.events
            WHERE ts < {threshold}
            """
        )
    )
    if moved_rows <= 0:
        return {
            "moved_rows": 0,
            "older_than_hours": safe_hours,
            "status": "no-op",
        }
    get_ch_client().command(
        f"""
        INSERT INTO {EVENTS_COLD_TABLE}
        (
            ts,
            event_id,
            category,
            subcategory,
            event_action,
            event_outcome,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            device_vendor,
            device_product,
            log_source,
            host_name,
            user_name,
            target_user,
            process_name,
            process_executable,
            process_command,
            severity,
            message,
            normalized_json,
            tags,
            event_code,
            asset_id,
            asset_owner,
            asset_criticality,
            asset_environment,
            asset_service,
            ti_indicator,
            ti_indicator_type,
            ti_provider,
            ti_severity
        )
        SELECT
            ts,
            event_id,
            category,
            subcategory,
            event_action,
            event_outcome,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            device_vendor,
            device_product,
            log_source,
            host_name,
            user_name,
            target_user,
            process_name,
            process_executable,
            process_command,
            severity,
            message,
            normalized_json,
            tags,
            event_code,
            asset_id,
            asset_owner,
            asset_criticality,
            asset_environment,
            asset_service,
            ti_indicator,
            ti_indicator_type,
            ti_provider,
            ti_severity
        FROM siem.events
        WHERE ts < {threshold}
        """
    )
    get_ch_client().command(
        f"""
        ALTER TABLE siem.events
        DELETE WHERE ts < {threshold}
        """
    )
    return {
        "moved_rows": moved_rows,
        "older_than_hours": safe_hours,
        "status": "archived",
    }


def enforce_event_retention(older_than_hours: int, cold_retention_days: int) -> Dict[str, Any]:
    ensure_cold_storage_support()
    safe_hours = max(1, int(older_than_hours))
    safe_days = max(1, int(cold_retention_days))
    archive_result = archive_events_to_cold(safe_hours)
    client = get_ch_client()

    cold_threshold = f"now() - INTERVAL {safe_days} DAY"
    cold_deleted = int(
        _scalar(
            f"""
            SELECT count()
            FROM {EVENTS_COLD_TABLE}
            WHERE ts < {cold_threshold}
            """
        )
    )
    if cold_deleted > 0:
        client.command(
            f"""
            ALTER TABLE {EVENTS_COLD_TABLE}
            DELETE WHERE ts < {cold_threshold}
            """
        )

    shadow_deleted = 0
    try:
        shadow_threshold = f"now() - INTERVAL {safe_hours} HOUR"
        shadow_deleted = int(
            _scalar(
                f"""
                SELECT count()
                FROM siem.events_shadow
                WHERE ts < {shadow_threshold}
                """
            )
        )
        if shadow_deleted > 0:
            client.command(
                f"""
                ALTER TABLE siem.events_shadow
                DELETE WHERE ts < {shadow_threshold}
                """
            )
    except Exception:
        shadow_deleted = 0

    return {
        "hot_retention_hours": safe_hours,
        "cold_retention_days": safe_days,
        "archive": archive_result,
        "cold_deleted_rows": cold_deleted,
        "shadow_deleted_rows": shadow_deleted,
        "status": "completed",
    }


def fetch_alert_history(view: str, record_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    safe_limit = max(1, min(int(limit or 50), 200))
    cache_key = json.dumps([view, record_id, safe_limit], ensure_ascii=False, sort_keys=True)
    now_ts = time()
    cached = _ALERT_HISTORY_CACHE.get(cache_key)
    if cached and now_ts - cached[0] < 60:
        return [dict(row) for row in cached[1]]
    query = f"""
        SELECT
            changed_ts,
            view,
            record_id,
            rule_id,
            previous_status,
            next_status,
            previous_assignee,
            next_assignee,
            changed_by,
            note
        FROM {ALERT_HISTORY_TABLE}
        WHERE view = {_sql_quote(view)}
          AND record_id = {_sql_quote(record_id)}
        ORDER BY changed_ts DESC
        LIMIT {safe_limit}
    """
    rows = [
        {
            "changed_ts": _fmt(row["changed_ts"]),
            "view": row["view"],
            "record_id": row["record_id"],
            "rule_id": int(row["rule_id"]),
            "previous_status": row["previous_status"],
            "next_status": row["next_status"],
            "previous_assignee": row["previous_assignee"],
            "next_assignee": row["next_assignee"],
            "changed_by": row["changed_by"],
            "note": row["note"],
        }
        for row in get_ch_client().query(query).named_results()
    ]
    _ALERT_HISTORY_CACHE[cache_key] = (now_ts, rows)
    if len(_ALERT_HISTORY_CACHE) > 64:
        oldest_key = min(_ALERT_HISTORY_CACHE, key=lambda key: _ALERT_HISTORY_CACHE[key][0])
        _ALERT_HISTORY_CACHE.pop(oldest_key, None)
    return [dict(row) for row in rows]


def update_alert_assignment(
    view: str,
    record_id: str,
    *,
    status: str,
    assignee: str,
    changed_by: str,
    note: str = "",
) -> Dict[str, Any]:
    ensure_incident_workflow_support()
    client = get_ch_client()
    next_status = (status or "new").strip().lower()
    next_assignee = (assignee or "").strip()
    if _incident_terminal_status_requires_note(next_status) and not str(note or "").strip():
        raise ValueError("A comment is required when closing, resolving, suppressing or marking an incident as false positive")
    safe_status = _sql_quote(next_status)
    safe_assignee = _sql_quote(next_assignee)
    safe_id = _sql_quote(record_id)
    selector = ""
    if view == "raw":
        target = "siem.alerts_raw"
        selector = f"toString(alert_id) = {safe_id}"
        current_query = f"""
            SELECT rule_id, lower(status) AS status, assignee
            FROM {target}
            WHERE {selector}
            LIMIT 1
        """
        result = client.query(current_query).result_rows
        if not result:
            raise ValueError("Alert or incident not found")
        rule_id, current_status, current_assignee = result[0]
        current_status = str(current_status or "new").lower()
        current_assignee = str(current_assignee or "")
    else:
        target = "siem.alerts_raw"
        incidents = fetch_alerts_agg(limit=5000)
        selected_incident = next((row for row in incidents if str(row.get("agg_id") or "") == str(record_id)), None)
        if not selected_incident:
            selected_incident = next(
                (
                    row
                    for row in incidents
                    if str(row.get("entity_key") or "") == str(record_id)
                    or str((row.get("group_key") or {}).get("incident_key") or "") == str(record_id)
                ),
                None,
            )
        if not selected_incident:
            raise ValueError("Alert or incident not found")
        rule_id = int(selected_incident["rule_id"])
        current_status = str(selected_incident.get("status") or "new").lower()
        current_assignee = str(selected_incident.get("assignee") or "")
        incident_key = str(selected_incident.get("agg_id") or selected_incident.get("record_id") or record_id).strip()
        if not incident_key:
            raise ValueError("Alert or incident not found")
        matched_alert_ids = _match_alert_ids_for_materialized_incident(selected_incident, limit=5000)
        if not matched_alert_ids:
            matched_alert_ids = _match_alert_ids_for_incident_scope(incident_key, window="30d", limit=5000)
        if not matched_alert_ids:
            raise ValueError("No raw alerts matched the selected incident")
        selector = "toString(alert_id) IN ({values})".format(
            values=", ".join(_sql_quote(alert_id) for alert_id in matched_alert_ids)
        )
    if next_status == current_status and next_assignee != current_assignee:
        if next_assignee and current_status in {"new", "open", "triaged", "reopened"}:
            next_status = "assigned"
            safe_status = _sql_quote(next_status)
        elif not next_assignee and current_status == "assigned":
            next_status = "triaged"
            safe_status = _sql_quote(next_status)
    if next_status != current_status:
        allowed = INCIDENT_STATUS_TRANSITIONS.get(current_status, set())
        if next_status not in allowed:
            raise ValueError(f"Invalid transition: {current_status} -> {next_status}")
    client.command(
        f"""
        ALTER TABLE {target}
        UPDATE
            status = {safe_status},
            assignee = {safe_assignee},
            updated_ts = now()
        WHERE {selector}
        SETTINGS mutations_sync = 2
        """
    )
    expected_updates = 1 if view == "raw" else len(matched_alert_ids)
    verification_rows = client.query(
        f"""
        SELECT count()
        FROM {target}
        WHERE {selector}
          AND lower(status) = {safe_status}
          AND assignee = {safe_assignee}
        """
    ).result_rows
    verified_updates = int(verification_rows[0][0]) if verification_rows and verification_rows[0] else 0
    if verified_updates != expected_updates:
        raise RuntimeError(
            f"Incident assignment update was not fully applied: expected {expected_updates}, verified {verified_updates}"
        )
    client.insert(
        ALERT_HISTORY_TABLE,
        [[
            view,
            str(record_id),
            int(rule_id),
            current_status,
            next_status,
            current_assignee,
            next_assignee,
            (changed_by or "web").strip() or "web",
            (note or "").strip(),
        ]],
        column_names=[
            "view",
            "record_id",
            "rule_id",
            "previous_status",
            "next_status",
            "previous_assignee",
            "next_assignee",
            "changed_by",
            "note",
        ],
    )
    _ALERT_HISTORY_CACHE.clear()
    _ALERTS_AGG_CACHE.clear()
    _INCIDENT_DETAIL_CACHE.clear()
    return {"view": view, "record_id": record_id, "status": next_status, "assignee": next_assignee}


DEFAULT_SIGMA_RULES = [
    {
        "id": 1001,
        "title": "Linux SSH Brute Force Burst",
        "level": "high",
        "window_s": 300,
        "threshold": 5,
        "entity_field": "source.ip",
        "yaml": """
title: Linux SSH Brute Force Burst
id: sigma-linux-ssh-bruteforce-burst
status: experimental
logsource:
  product: linux
  service: sshd
detection:
  selection:
    event.provider: linux.sshd
    event.type: ssh_login_failure
  condition: selection
level: high
tags:
  - attack.credential_access
  - attack.t1110
""".strip(),
    },
    {
        "id": 1002,
        "title": "Linux Audit USER_LOGIN Failures",
        "level": "medium",
        "window_s": 300,
        "threshold": 3,
        "entity_field": "source.ip",
        "yaml": """
title: Linux Audit USER_LOGIN Failures
id: sigma-linux-audit-user-login-failure
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: audit_user_login_failure
  condition: selection
level: medium
tags:
  - attack.credential_access
  - attack.t1078
""".strip(),
    },
    {
        "id": 1003,
        "title": "Linux Sudo To Root",
        "level": "medium",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "user.name",
        "yaml": """
title: Linux Sudo To Root
id: sigma-linux-sudo-to-root
status: experimental
logsource:
  product: linux
  service: sudo
detection:
  selection:
    event.provider: linux.sudo
    event.type: sudo_command
    user.target.name: root
  condition: selection
level: medium
tags:
  - attack.privilege_escalation
  - attack.t1548
""".strip(),
    },
    {
        "id": 1004,
        "title": "Linux Exec As Root Burst",
        "level": "high",
        "window_s": 600,
        "threshold": 3,
        "entity_field": "log_source",
        "yaml": """
title: Linux Exec As Root Burst
id: sigma-linux-exec-as-root-burst
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: audit_exec_as_root
  condition: selection
level: high
tags:
  - attack.privilege_escalation
  - attack.execution
""".strip(),
    },
    {
        "id": 1005,
        "title": "Linux Root SSH Login Success",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "source.ip",
        "yaml": """
title: Linux Root SSH Login Success
id: sigma-linux-root-ssh-login-success
status: experimental
logsource:
  product: linux
  service: sshd
detection:
  selection:
    event.provider: linux.sshd
    event.type: ssh_login_success
    user.name: root
  condition: selection
level: high
tags:
  - attack.initial_access
  - attack.t1078
""".strip(),
    },
    {
        "id": 1006,
        "title": "Linux Suspicious Download Utility",
        "level": "medium",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Suspicious Download Utility
id: sigma-linux-suspicious-download-utility
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection_curl:
    event.provider: linux.auditd
    event.type: audit_execve
    process.command_line|contains: curl
  selection_wget:
    event.provider: linux.auditd
    event.type: audit_execve
    process.command_line|contains: wget
  condition: 1 of selection_*
level: medium
tags:
  - attack.command_and_control
  - attack.t1105
""".strip(),
    },
    {
        "id": 1007,
        "title": "Linux Netcat Execution",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Netcat Execution
id: sigma-linux-netcat-execution
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection_nc_bin:
    event.provider: linux.auditd
    event.type: audit_execve
    process.name: nc
  selection_ncat_bin:
    event.provider: linux.auditd
    event.type: audit_execve
    process.name: ncat
  condition: 1 of selection_*
level: high
tags:
  - attack.command_and_control
  - attack.t1095
""".strip(),
    },
    {
        "id": 1008,
        "title": "Linux Sudo Root Session Opened",
        "level": "medium",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "user.target.name",
        "yaml": """
title: Linux Sudo Root Session Opened
id: sigma-linux-sudo-root-session-opened
status: experimental
logsource:
  product: linux
  service: sudo
detection:
  selection:
    event.provider: linux.sudo
    event.type: sudo_session_opened
    user.target.name: root
  condition: selection
level: medium
tags:
  - attack.privilege_escalation
  - attack.t1548
""".strip(),
    },
    {
        "id": 1009,
        "title": "Linux Authorized Keys Modified",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Authorized Keys Modified
id: sigma-linux-authorized-keys-modified
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_authorized_keys_modified
  condition: selection
level: high
tags:
  - attack.persistence
  - attack.t1098
""".strip(),
    },
    {
        "id": 1010,
        "title": "Linux Cron Modified",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Cron Modified
id: sigma-linux-cron-modified
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_cron_modified
  condition: selection
level: high
tags:
  - attack.persistence
  - attack.t1053.003
""".strip(),
    },
    {
        "id": 1011,
        "title": "Linux Passwd Or Shadow Access",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Passwd Or Shadow Access
id: sigma-linux-passwd-shadow-access
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_passwd_shadow_access
  condition: selection
level: high
tags:
  - attack.credential_access
  - attack.t1003
""".strip(),
    },
    {
        "id": 1012,
        "title": "Linux User Added To Admin Group",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "user.target.name",
        "yaml": """
title: Linux User Added To Admin Group
id: sigma-linux-user-added-to-admin-group
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_user_added_to_admin_group
  condition: selection
level: high
tags:
  - attack.privilege_escalation
  - attack.t1098
""".strip(),
    },
    {
        "id": 1013,
        "title": "Linux Execution From Tmp",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Execution From Tmp
id: sigma-linux-exec-from-tmp
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_exec_from_tmp
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059
""".strip(),
    },
    {
        "id": 1014,
        "title": "Linux Reverse Shell Possible",
        "level": "critical",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Reverse Shell Possible
id: sigma-linux-reverse-shell-possible
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_reverse_shell_possible
  condition: selection
level: critical
tags:
  - attack.command_and_control
  - attack.t1059
""".strip(),
    },
    {
        "id": 1015,
        "title": "Linux Firewall Disabled",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Firewall Disabled
id: sigma-linux-firewall-disabled
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_firewall_disabled
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1562
""".strip(),
    },
    {
        "id": 1016,
        "title": "Linux Audit Rules Cleared",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Audit Rules Cleared
id: sigma-linux-audit-rules-cleared
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_audit_rules_cleared
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1562
""".strip(),
    },
    {
        "id": 1017,
        "title": "Linux Audit Config Changed",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Audit Config Changed
id: sigma-linux-audit-config-changed
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_audit_config_changed
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1562
""".strip(),
    },
    {
        "id": 1018,
        "title": "Linux User Created",
        "level": "medium",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "user.target.name",
        "yaml": """
title: Linux User Created
id: sigma-linux-user-created
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_user_created
  condition: selection
level: medium
tags:
  - attack.persistence
  - attack.t1136
""".strip(),
    },
    {
        "id": 1019,
        "title": "Linux User Deleted",
        "level": "medium",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "user.target.name",
        "yaml": """
title: Linux User Deleted
id: sigma-linux-user-deleted
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_user_deleted
  condition: selection
level: medium
tags:
  - attack.defense_evasion
  - attack.t1531
""".strip(),
    },
    {
        "id": 1020,
        "title": "Linux Password Changed",
        "level": "medium",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "user.target.name",
        "yaml": """
title: Linux Password Changed
id: sigma-linux-password-changed
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_password_changed
  condition: selection
level: medium
tags:
  - attack.credential_access
  - attack.t1098
""".strip(),
    },
    {
        "id": 1021,
        "title": "Linux LD Preload Modified",
        "level": "critical",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux LD Preload Modified
id: sigma-linux-ld-preload-modified
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_ld_preload_modified
  condition: selection
level: critical
tags:
  - attack.persistence
  - attack.t1574
""".strip(),
    },
    {
        "id": 1022,
        "title": "Denylist Entity Observed",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Denylist Entity Observed
id: sigma-denylist-entity-observed
status: experimental
logsource:
  product: linux
  service: enriched
detection:
  selection:
    keywords:
      - 'denylist:'
  condition: selection
level: high
tags:
    - enrichment.denylist
    - attack.resource_development
""".strip(),
    },
    {
        "id": 1023,
        "title": "Linux Sudoers Modified",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Sudoers Modified
id: sigma-linux-sudoers-modified
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_sudoers_modified
  condition: selection
level: high
tags:
  - attack.privilege_escalation
  - attack.t1548
""".strip(),
    },
    {
        "id": 1024,
        "title": "Linux Systemd Unit Modified",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Systemd Unit Modified
id: sigma-linux-systemd-unit-modified
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_systemd_unit_modified
  condition: selection
level: high
tags:
  - attack.persistence
  - attack.t1543
""".strip(),
    },
    {
        "id": 1025,
        "title": "Linux Systemd Service Disabled",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Systemd Service Disabled
id: sigma-linux-systemd-service-disabled
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_systemd_service_disabled
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1562
""".strip(),
    },
    {
        "id": 1026,
        "title": "Linux Packet Capture Utility",
        "level": "medium",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Packet Capture Utility
id: sigma-linux-packet-capture-utility
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_packet_capture
  condition: selection
level: medium
tags:
  - attack.discovery
  - attack.t1040
""".strip(),
    },
    {
        "id": 1027,
        "title": "Linux Setuid Bit Modified",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "process.executable",
        "yaml": """
title: Linux Setuid Bit Modified
id: sigma-linux-setuid-bit-modified
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_setuid_bit_modified
  condition: selection
level: high
tags:
  - attack.privilege_escalation
  - attack.t1548
""".strip(),
    },
    {
        "id": 1028,
        "title": "Linux File Capability Modified",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "process.executable",
        "yaml": """
title: Linux File Capability Modified
id: sigma-linux-file-capability-modified
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_file_capability_modified
  condition: selection
level: high
tags:
  - attack.privilege_escalation
  - attack.t1548
""".strip(),
    },
    {
        "id": 1029,
        "title": "Linux System Recon Burst",
        "level": "medium",
        "window_s": 300,
        "threshold": 3,
        "entity_field": "log_source",
        "yaml": """
title: Linux System Recon Burst
id: sigma-linux-system-recon-burst
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_system_recon
  condition: selection
level: medium
tags:
  - attack.discovery
  - attack.t1082
""".strip(),
    },
    {
        "id": 1030,
        "title": "Windows Logon Failure Burst",
        "level": "high",
        "window_s": 300,
        "threshold": 5,
        "entity_field": "source.ip",
        "yaml": """
title: Windows Logon Failure Burst
id: sigma-windows-logon-failure-burst
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    event.provider: windows.security
    event.type: windows_logon_failure
  condition: selection
level: high
tags:
  - attack.credential_access
  - attack.t1110
""".strip(),
    },
    {
        "id": 1031,
        "title": "Windows Audit Log Cleared",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Windows Audit Log Cleared
id: sigma-windows-audit-log-cleared
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    event.provider: windows.security
    event.type: windows_audit_log_cleared
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1070
""".strip(),
    },
    {
        "id": 1032,
        "title": "Windows Privileged Group Membership Changed",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "user.target.name",
        "yaml": """
title: Windows Privileged Group Membership Changed
id: sigma-windows-privileged-group-membership-changed
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    event.provider: windows.security
    event.type: windows_user_added_to_privileged_group
  condition: selection
level: high
tags:
  - attack.persistence
  - attack.t1098
""".strip(),
    },
    {
        "id": 1033,
        "title": "Windows Suspicious PowerShell Encoded Command",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Windows Suspicious PowerShell Encoded Command
id: sigma-windows-powershell-encoded-command
status: experimental
logsource:
  product: windows
  service: powershell
detection:
  selection:
    event.provider: windows.powershell
    event.type: windows_powershell_encoded_command
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001
""".strip(),
    },
    {
        "id": 1034,
        "title": "Windows Service Installed",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Windows Service Installed
id: sigma-windows-service-installed
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    event.provider: windows.security
    event.type: windows_service_installed
  condition: selection
level: high
tags:
  - attack.persistence
  - attack.t1543
""".strip(),
    },
    {
        "id": 1035,
        "title": "Windows User Created",
        "level": "medium",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "user.target.name",
        "yaml": """
title: Windows User Created
id: sigma-windows-user-created
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    event.provider: windows.security
    event.type: windows_user_created
  condition: selection
level: medium
tags:
  - attack.persistence
  - attack.t1136
""".strip(),
    },
]

DEFAULT_SIGMA_RETIRED_DUPLICATE_IDS = {
    1001,
    1002,
    1003,
    1004,
    1005,
    1006,
    1007,
    1008,
    1009,
    1010,
    1011,
    1012,
    1013,
    1014,
    1015,
    1016,
    1017,
    1018,
    1019,
    1020,
    1021,
    1023,
    1024,
    1025,
    1026,
    1027,
    1028,
    1029,
    1030,
    1031,
    1032,
    1033,
    1034,
    1035,
}


def ensure_detection_support_tables() -> None:
    get_ch_client().command(
        f"""
        CREATE TABLE IF NOT EXISTS {DETECTION_RULE_TABLE}
        (
            id UInt32,
            title String,
            sigma_id String,
            status LowCardinality(String),
            level LowCardinality(String),
            source_format LowCardinality(String),
            logsource_product String,
            logsource_service String,
            logsource_category String,
            sigma_yaml String,
            expr String,
            entity_field String,
            window_s UInt32,
            threshold UInt32,
            verification_query String,
            tags String,
            description String,
            enabled UInt8,
            author String,
            created_ts DateTime DEFAULT now(),
            updated_ts DateTime DEFAULT now()
        )
        ENGINE = MergeTree
        ORDER BY (id)
        """
    )
    _seed_default_sigma_rules()


def _map_sigma_field(field_name: str, *, target: str = "stream") -> tuple[str, str]:
    parts = field_name.split("|")
    field = parts[0].strip()
    modifier = parts[1].strip().lower() if len(parts) > 1 else "eq"
    field_key = field.lower()
    if target == "events":
        field_map = {
            "message": ("message", "contains"),
            "event.original": ("message", "contains"),
            "event.code": ("event_code", "eq"),
            "winlog.event_id": ("event_code", "eq"),
            "event.provider": ("device_product", "eq"),
            "event.category": ("category", "eq"),
            "event.type": ("subcategory", "eq"),
            "event.action": ("event_action", "eq"),
            "event.outcome": ("event_outcome", "eq"),
            "logsource": ("log_source", "eq"),
            "log_source": ("log_source", "eq"),
            "severity": ("severity", "eq"),
            "sourceip": ("src_ip", "eq"),
            "source.ip": ("src_ip", "eq"),
            "source.port": ("src_port", "eq"),
            "clientaddress": ("src_ip", "eq"),
            "ipaddress": ("src_ip", "eq"),
            "destination.port": ("dst_port", "eq"),
            "destport": ("dst_port", "eq"),
            "host": ("log_source", "eq"),
            "host.name": ("host_name", "eq"),
            "asset.id": ("asset_id", "eq"),
            "asset.owner": ("asset_owner", "contains"),
            "asset.criticality": ("asset_criticality", "eq"),
            "asset.environment": ("asset_environment", "eq"),
            "asset.service": ("asset_service", "contains"),
            "threat.indicator": ("ti_indicator", "contains"),
            "threat.provider": ("ti_provider", "contains"),
            "threat.severity": ("ti_severity", "eq"),
            "user": ("user_name", "contains"),
            "username": ("user_name", "contains"),
            "accountname": ("user_name", "contains"),
            "user.name": ("user_name", "contains"),
            "targetuser": ("target_user", "contains"),
            "targetusername": ("target_user", "contains"),
            "user.target.name": ("target_user", "contains"),
            "commandline": ("process_command", "contains"),
            "process.command_line": ("process_command", "contains"),
            "image": ("process_executable", "contains"),
            "process.executable": ("process_executable", "contains"),
            "process.name": ("process_name", "contains"),
        }
        normalized, default_modifier = field_map.get(field_key, ("message", "contains"))
        effective_modifier = modifier if modifier != "eq" else default_modifier
    else:
        field_map = {
            "message": "event.original",
            "event.original": "event.original",
            "event.code": "event.code",
            "winlog.event_id": "event.code",
            "event.provider": "event.provider",
            "event.category": "event.category",
            "event.type": "event.type",
            "event.action": "event.action",
            "event.outcome": "event.outcome",
            "source.port": "source.port",
            "destination.port": "destination.port",
            "commandline": "process.command_line",
            "process.command_line": "process.command_line",
            "image": "process.executable",
            "process.executable": "process.executable",
            "user": "user.name",
            "username": "user.name",
            "accountname": "user.name",
            "user.name": "user.name",
            "targetuser": "user.target.name",
            "targetusername": "user.target.name",
            "user.target.name": "user.target.name",
            "sourceip": "source.ip",
            "source.ip": "source.ip",
            "clientaddress": "source.ip",
            "ipaddress": "source.ip",
            "host": "host.name",
            "host.name": "host.name",
        }
        normalized = field_map.get(field_key, field)
        effective_modifier = modifier
    op_map = {
        "eq": "==",
        "contains": "icontains",
        "startswith": "startswith",
        "endswith": "endswith",
    }
    return normalized, op_map.get(effective_modifier, "==")


def _stream_expr(field: str, op: str, value: Any) -> str:
    escaped = str(value).replace("\\", "\\\\").replace("'", "\\'")
    return f"{field} {op} '{escaped}'"


def _verification_expr(field: str, op: str, value: Any) -> str:
    escaped = str(value).replace("\\", "\\\\").replace("'", "''")
    haystack = f"toString({field})"
    if op == "==":
        return f"{haystack} = '{escaped}'"
    if op == "!=":
        return f"{haystack} != '{escaped}'"
    if op == "icontains":
        return f"positionCaseInsensitiveUTF8({haystack}, '{escaped}') > 0"
    if op == "startswith":
        return f"positionCaseInsensitiveUTF8({haystack}, '{escaped}') = 1"
    if op == "endswith":
        return f"endsWith(lowerUTF8({haystack}), lowerUTF8('{escaped}'))"
    return f"positionCaseInsensitiveUTF8({haystack}, '{escaped}') > 0"


def _selection_to_expr(selection: Dict[str, Any], *, target: str) -> str:
    chunks: List[str] = []
    for raw_field, raw_value in selection.items():
        if raw_field == "keywords":
            values = raw_value if isinstance(raw_value, list) else [raw_value]
            builder = _stream_expr if target == "stream" else _verification_expr
            keyword_field = "event.original" if target == "stream" else "message"
            keyword_exprs = [builder(keyword_field, "icontains", item) for item in values]
            chunks.append("(" + " or ".join(keyword_exprs) + ")")
            continue
        field, op = _map_sigma_field(raw_field, target=target)
        values = raw_value if isinstance(raw_value, list) else [raw_value]
        builder = _stream_expr if target == "stream" else _verification_expr
        exprs = [builder(field, op, item) for item in values]
        chunks.append("(" + " or ".join(exprs) + ")" if len(exprs) > 1 else exprs[0])
    fallback = "event.provider != 'unknown'" if target == "stream" else "device_product != ''"
    return " and ".join(chunks) if chunks else fallback


def _compile_sigma_condition(condition: str, selections: Dict[str, str]) -> str:
    compact = " ".join(condition.strip().split())
    special = re.fullmatch(r"(1|all) of ([A-Za-z0-9_*]+)", compact, flags=re.IGNORECASE)
    if special:
        mode, pattern = special.groups()
        prefix = pattern[:-1] if pattern.endswith("*") else pattern
        matched = [expr for key, expr in selections.items() if key.startswith(prefix)]
        if not matched:
            raise ValueError("Sigma condition does not match any selection blocks")
        joiner = " or " if mode.lower() == "1" else " and "
        return "(" + joiner.join(matched) + ")"

    tokens = SIGMA_CONDITION_TOKEN_RE.findall(compact)
    pos = 0

    def parse_primary() -> str:
        nonlocal pos
        token = tokens[pos]
        lowered = token.lower()
        if token == "(":
            pos += 1
            inner = parse_or()
            if pos >= len(tokens) or tokens[pos] != ")":
                raise ValueError("Unclosed Sigma condition group")
            pos += 1
            return f"({inner})"
        if lowered == "not":
            raise ValueError("Sigma 'not' conditions are not supported in the current converter")
        if token not in selections:
            raise ValueError(f"Unsupported Sigma condition token: {token}")
        pos += 1
        return f"({selections[token]})"

    def parse_and() -> str:
        nonlocal pos
        left = parse_primary()
        while pos < len(tokens) and tokens[pos].lower() == "and":
            pos += 1
            left = f"({left} and {parse_primary()})"
        return left

    def parse_or() -> str:
        nonlocal pos
        left = parse_and()
        while pos < len(tokens) and tokens[pos].lower() == "or":
            pos += 1
            left = f"({left} or {parse_and()})"
        return left

    compiled = parse_or()
    if pos != len(tokens):
        raise ValueError("Unexpected tokens in Sigma condition")
    return compiled


def convert_sigma_to_stream_rule(
    sigma_yaml: str,
    *,
    threshold: int,
    window_s: int,
    entity_field: str,
    rule_id: int | None = None,
) -> Dict[str, Any]:
    document = yaml.safe_load(sigma_yaml) or {}
    if not isinstance(document, dict):
        raise ValueError("Sigma payload must be a YAML object")
    detection = document.get("detection")
    if not isinstance(detection, dict):
        raise ValueError("Sigma rule must contain detection")
    condition = str(detection.get("condition", "")).strip()
    if not condition:
        raise ValueError("Sigma detection.condition is required")

    selection_exprs: Dict[str, str] = {}
    verification_exprs: Dict[str, str] = {}
    for key, value in detection.items():
        if key == "condition":
            continue
        if not isinstance(value, dict):
            raise ValueError(f"Sigma selection '{key}' must be an object")
        selection_exprs[key] = _selection_to_expr(value, target="stream")
        verification_exprs[key] = _selection_to_expr(value, target="events")

    expr = _compile_sigma_condition(condition, selection_exprs)
    verification_query = _compile_sigma_condition(condition, verification_exprs)
    expr = f"({expr}) and not tags icontains 'allowlist:'"
    verification_query = f"({verification_query}) AND positionCaseInsensitiveUTF8(toString(tags), 'allowlist:') = 0"
    level = str(document.get("level", "medium") or "medium").lower()
    logsource = document.get("logsource") or {}
    if not isinstance(logsource, dict):
        logsource = {}
    title = str(document.get("title", "Untitled Sigma rule") or "Untitled Sigma rule").strip()
    description = str(document.get("description", "") or "").strip()
    sigma_id = str(document.get("id", "") or "").strip()
    tags = document.get("tags") or []
    if not isinstance(tags, list):
        tags = [str(tags)]
    return {
        "id": int(rule_id) if rule_id is not None else 0,
        "title": title,
        "sigma_id": sigma_id,
        "status": str(document.get("status", "custom") or "custom"),
        "level": level,
        "source_format": "sigma",
        "logsource_product": str(logsource.get("product", "") or ""),
        "logsource_service": str(logsource.get("service", "") or ""),
        "logsource_category": str(logsource.get("category", "") or ""),
        "sigma_yaml": sigma_yaml.strip(),
        "expr": expr,
        "entity_field": entity_field,
        "window_s": int(window_s),
        "threshold": int(threshold),
        "verification_query": verification_query,
        "tags": ",".join(str(tag) for tag in tags),
        "description": description,
        "enabled": 1,
        "author": "web",
    }


def _next_detection_rule_id() -> int:
    current_catalog = int(_scalar(f"SELECT max(id) FROM {DETECTION_RULE_TABLE}"))
    current_stream = int(_scalar("SELECT max(id) FROM siem.correlation_rules_stream"))
    return max(current_catalog, current_stream, 1999) + 1


def _seed_default_sigma_rules() -> None:
    desired_rules = [
        convert_sigma_to_stream_rule(
            item["yaml"],
            threshold=item["threshold"],
            window_s=item["window_s"],
            entity_field=item["entity_field"],
            rule_id=item["id"],
        )
        for item in DEFAULT_SIGMA_RULES
        if int(item["id"]) not in DEFAULT_SIGMA_RETIRED_DUPLICATE_IDS
    ]
    if not desired_rules:
        return
    desired_ids = sorted({int(rule["id"]) for rule in desired_rules})
    catalog_ids = _query_existing_rule_ids(DETECTION_RULE_TABLE, desired_ids)
    stream_ids = _query_existing_rule_ids("siem.correlation_rules_stream", desired_ids)

    catalog_missing = [rule for rule in desired_rules if int(rule["id"]) not in catalog_ids]
    if catalog_missing:
        _insert_detection_rule_rows(catalog_missing, sync_stream=False)

    for rule in desired_rules:
        if int(rule["id"]) not in stream_ids:
            _insert_stream_rule(rule, replace_existing=False)


def _query_existing_rule_ids(table_name: str, rule_ids: List[int]) -> set[int]:
    ids = sorted({int(rule_id) for rule_id in rule_ids if int(rule_id or 0) > 0})
    if not ids:
        return set()
    id_list = ", ".join(str(rule_id) for rule_id in ids)
    try:
        result = get_ch_client().query(f"SELECT id FROM {table_name} WHERE id IN ({id_list})")
    except Exception:
        return set()
    return {int(row[0]) for row in getattr(result, "result_rows", []) if row}


def _insert_detection_rule_rows(rules: List[Dict[str, Any]], *, sync_stream: bool) -> None:
    rows = [
        [
            int(rule["id"]),
            rule["title"],
            rule["sigma_id"],
            rule["status"],
            rule["level"],
            rule["source_format"],
            rule["logsource_product"],
            rule["logsource_service"],
            rule["logsource_category"],
            rule["sigma_yaml"],
            rule["expr"],
            rule["entity_field"],
            int(rule["window_s"]),
            int(rule["threshold"]),
            rule["verification_query"],
            rule["tags"],
            rule["description"],
            int(rule["enabled"]),
            rule["author"],
        ]
        for rule in rules
    ]
    get_ch_client().insert(
        DETECTION_RULE_TABLE,
        rows,
        column_names=[
            "id",
            "title",
            "sigma_id",
            "status",
            "level",
            "source_format",
            "logsource_product",
            "logsource_service",
            "logsource_category",
            "sigma_yaml",
            "expr",
            "entity_field",
            "window_s",
            "threshold",
            "verification_query",
            "tags",
            "description",
            "enabled",
            "author",
        ],
    )
    if sync_stream:
        for rule in rules:
            _insert_stream_rule(rule)


def _insert_stream_rule(rule: Dict[str, Any], *, replace_existing: bool = True) -> None:
    if replace_existing:
        get_ch_client().command(f"ALTER TABLE siem.correlation_rules_stream DELETE WHERE id = {int(rule['id'])}")
    get_ch_client().insert(
        "siem.correlation_rules_stream",
        [[
            int(rule["id"]),
            rule["title"],
            rule["description"] or f"Sigma-derived rule for {rule['title']}",
            1,
            rule["level"],
            "threshold",
            int(rule["window_s"]),
            int(rule["threshold"]),
            rule["expr"],
            rule["entity_field"],
        ]],
        column_names=[
            "id",
            "name",
            "description",
            "enabled",
            "severity",
            "pattern",
            "window_s",
            "threshold",
            "expr",
            "entity_field",
        ],
    )


def save_sigma_rule(
    sigma_yaml: str,
    *,
    threshold: int,
    window_s: int,
    entity_field: str,
    author: str = "web",
) -> Dict[str, Any]:
    ensure_detection_support_tables()
    rule = convert_sigma_to_stream_rule(
        sigma_yaml,
        threshold=threshold,
        window_s=window_s,
        entity_field=entity_field,
        rule_id=_next_detection_rule_id(),
    )
    rule["author"] = author
    _insert_detection_rule_rows([rule], sync_stream=True)
    return rule


def _count_rule_matches(query_text: str, window: str = "24h") -> int:
    expression = _validate_read_only_sql(str(query_text or "").strip())
    operational_filter = _event_operational_filter_sql()
    result = get_ch_client().query(
        f"""
        SELECT count() AS cnt
        FROM ({_event_view_sql('all')}) AS events_view
        WHERE {_combine_sql_filters(_event_time_filter(window), operational_filter)}
          AND ({expression})
        """
    )
    return int(result.result_rows[0][0]) if result.result_rows else 0


def fetch_detection_rules(limit: int = 100) -> List[Dict[str, Any]]:
    ensure_detection_support_tables()
    query = f"""
        SELECT
            id,
            title,
            sigma_id,
            status,
            level,
            source_format,
            logsource_product,
            logsource_service,
            logsource_category,
            expr,
            entity_field,
            window_s,
            threshold,
            verification_query,
            tags,
            description,
            enabled,
            author,
            created_ts,
            updated_ts
        FROM {DETECTION_RULE_TABLE}
        ORDER BY updated_ts DESC, id DESC
        LIMIT {int(limit)}
    """
    rules: List[Dict[str, Any]] = []
    operational_filter = _alert_raw_operational_filter_sql()
    alert_rows = get_ch_client().query(
        f"""
        SELECT rule_id, count() AS hits, max(ts_last) AS last_alert
        FROM siem.alerts_raw
        WHERE {operational_filter}
        GROUP BY rule_id
        """
    ).result_rows
    alert_index = {int(rule_id): {"hits": int(hits), "last_alert": _fmt(last_alert)} for rule_id, hits, last_alert in alert_rows}
    for row in get_ch_client().query(query).named_results():
        verification_query = str(row["verification_query"] or "")
        match_hits_24h = _count_rule_matches(verification_query, window="24h") if verification_query else 0
        record = {
            "id": int(row["id"]),
            "title": row["title"],
            "sigma_id": row["sigma_id"],
            "status": row["status"],
            "level": str(row["level"]).lower(),
            "source_format": row["source_format"],
            "logsource_product": row["logsource_product"],
            "logsource_service": row["logsource_service"],
            "logsource_category": row["logsource_category"],
            "expr": row["expr"],
            "entity_field": row["entity_field"],
            "window_s": int(row["window_s"]),
            "threshold": int(row["threshold"]),
            "verification_query": verification_query,
            "tags": [part for part in str(row["tags"] or "").split(",") if part],
            "description": row["description"],
            "enabled": bool(row["enabled"]),
            "author": row["author"],
            "created_ts": _fmt(row["created_ts"]),
            "updated_ts": _fmt(row["updated_ts"]),
            "match_hits_24h": match_hits_24h,
            "alert_hits_total": alert_index.get(int(row["id"]), {}).get("hits", 0),
            "last_alert_ts": alert_index.get(int(row["id"]), {}).get("last_alert", ""),
            "events_link": f"/events?q={quote(verification_query)}" if verification_query else "/events",
        }
        rules.append(record)
    return rules


def test_detection_rule(rule_id: int) -> Dict[str, Any]:
    ensure_detection_support_tables()
    result = get_ch_client().query(
        f"""
        SELECT id, title, verification_query
        FROM {DETECTION_RULE_TABLE}
        WHERE id = {int(rule_id)}
        LIMIT 1
        """
    )
    if not result.result_rows:
        raise ValueError("Rule not found")
    _, title, verification_query = result.result_rows[0]
    hits = _count_rule_matches(str(verification_query or ""), window="24h")
    last_alert = _scalar(
        f"SELECT max(ts_last) FROM siem.alerts_raw "
        f"WHERE rule_id = {int(rule_id)} AND {_alert_raw_operational_filter_sql()}"
    )
    return {
        "rule_id": int(rule_id),
        "title": title,
        "verification_query": verification_query,
        "hits_24h": hits,
        "last_alert_ts": _fmt(last_alert),
        "events_link": f"/events?q={quote(str(verification_query or ''))}",
    }


def fetch_asset_categories() -> List[Dict[str, Any]]:
    ensure_detection_support_tables()
    ensure_active_list_support()
    ensure_cmdb_ti_support()
    return [
        {
            "name": "Devices",
            "count": int(
                _scalar(
                    "SELECT countDistinct(if(host_name != '' AND host_name != '-', host_name, log_source)) "
                    f"FROM siem.events WHERE {_combine_sql_filters('ts >= now() - INTERVAL 24 HOUR', _event_operational_filter_sql())}"
                )
            ),
            "description": "Observed hosts and sources active during the last 24 hours.",
        },
        {
            "name": "CMDB Assets",
            "count": int(
                _scalar(
                    f"""
                    SELECT count()
                    FROM
                    (
                        SELECT asset_id, enabled
                        FROM {CMDB_ASSET_TABLE}
                        ORDER BY updated_ts DESC
                        LIMIT 1 BY asset_id
                    )
                    WHERE enabled = 1
                    """
                )
            ),
            "description": "Asset registry with owners, criticality, environment and expected services.",
        },
        {
            "name": "Detection Rules",
            "count": int(_scalar(f"SELECT count() FROM {DETECTION_RULE_TABLE}")),
            "description": "Rules stored in the web-side catalog and synchronized to stream correlation.",
        },
        {
            "name": "Sigma Rules",
            "count": int(_scalar(f"SELECT count() FROM {DETECTION_RULE_TABLE} WHERE lower(source_format) = 'sigma'")),
            "description": "Sigma-oriented rules converted into the SIEM stream rule DSL.",
        },
        {
            "name": "Normalizers",
            "count": int(_scalar("SELECT count() FROM siem.normalizer_rules WHERE enabled = 1")),
            "description": "Enabled normalizer rules plus built-in Linux parsing logic.",
        },
        {
            "name": "Active Lists",
            "count": int(_scalar(f"SELECT count() FROM {ACTIVE_LIST_TABLE}")),
            "description": "Stateful watchlists for enrichment, allow/deny inventory and entity lookups.",
        },
        {
            "name": "Threat Feeds",
            "count": int(_scalar(f"SELECT count() FROM {THREAT_INTEL_TABLE} WHERE enabled = 1")),
            "description": "Threat intel indicators used to enrich events and drive high-priority detections.",
        },
        {
            "name": "Windows Content",
            "count": int(_scalar(f"SELECT count() FROM {DETECTION_RULE_TABLE} WHERE lower(logsource_product) = 'windows'")),
            "description": "Windows normalization and Sigma-backed detection foundations for Security and Sysmon telemetry.",
        },
    ]


_fetch_vulnerability_reports_raw = fetch_vulnerability_reports
_fetch_vulnerability_report_details_raw = fetch_vulnerability_report_details
_fetch_vulnerability_inventory_raw = fetch_vulnerability_inventory
_search_vulnerability_findings_raw = search_vulnerability_findings
_fetch_vulnerability_hosts_raw = fetch_vulnerability_hosts
_fetch_vulnerability_software_raw = fetch_vulnerability_software
_fetch_vulnerability_cves_raw = fetch_vulnerability_cves
_fetch_source_inventory_raw = fetch_source_inventory
_fetch_collector_inventory_raw = fetch_collector_inventory
_fetch_resource_overview_raw = fetch_resource_overview
_fetch_platform_status_raw = fetch_platform_status
_fetch_transport_shadow_status_raw = fetch_transport_shadow_status
_list_runtime_docs_raw = list_runtime_docs
_load_runtime_doc_raw = load_runtime_doc
_save_runtime_doc_raw = save_runtime_doc
_save_runtime_doc_file_raw = save_runtime_doc_file
_delete_runtime_doc_raw = delete_runtime_doc
_list_dashboards_raw = list_dashboards
_describe_dashboard_widgets_raw = describe_dashboard_widgets
_save_dashboard_definition_raw = save_dashboard_definition
_delete_dashboard_definition_raw = delete_dashboard_definition
_list_builder_drafts_raw = list_builder_drafts
_save_builder_draft_raw = save_builder_draft
_delete_builder_draft_raw = delete_builder_draft
_validate_builder_draft_payload_raw = validate_builder_draft_payload
_test_builder_draft_payload_raw = test_builder_draft_payload
_publish_builder_draft_raw = publish_builder_draft


def _vuln_store():
    try:
        from . import vuln_store as vuln_store_module
    except ImportError:  # pragma: no cover - local test fallback
        import vuln_store as vuln_store_module  # type: ignore[no-redef]

    return vuln_store_module


def ensure_vulnerability_support() -> bool:
    return bool(_vuln_store().ensure_vulnerability_support())


def sync_vulnerability_targets(limit: int = 500) -> Dict[str, Any]:
    return _vuln_store().sync_vulnerability_targets(limit=limit)


def import_greenbone_reports(limit: int = 20) -> Dict[str, Any]:
    return _vuln_store().import_greenbone_reports(limit=limit)


def start_vulnerability_scans(asset_ids: List[str], limit: int = 25) -> Dict[str, Any]:
    return _vuln_store().start_vulnerability_scans(asset_ids=asset_ids, limit=limit)


def get_report_artifact_path(report_id: str) -> str:
    try:
        return str(_vuln_store().get_report_artifact_path(report_id))
    except Exception:
        return ""


def _prefer_structured_vulnerability(days: int) -> bool:
    try:
        store = _vuln_store()
        store.ensure_vulnerability_support()
        return bool(store.has_structured_vulnerability_data(days=max(1, int(days))))
    except Exception:
        return False


def fetch_vulnerability_reports(limit: int = 100, days: int = 14) -> List[Dict[str, Any]]:
    if _prefer_structured_vulnerability(days):
        return _vuln_store().fetch_vulnerability_reports(limit=limit, days=days)
    return _fetch_vulnerability_reports_raw(limit=limit, days=days)


def fetch_vulnerability_report_details(report_id: str, limit: int = 200) -> Dict[str, Any]:
    if _prefer_structured_vulnerability(days=30):
        try:
            return _vuln_store().fetch_vulnerability_report_details(report_id, limit=limit)
        except ValueError:
            pass
    return _fetch_vulnerability_report_details_raw(report_id, limit=limit)


def fetch_vulnerability_inventory(days: int = 30, limit: int = 25) -> Dict[str, Any]:
    if _prefer_structured_vulnerability(days):
        return _vuln_store().fetch_vulnerability_inventory(days=days, limit=limit)
    return _fetch_vulnerability_inventory_raw(days=days, limit=limit)


def search_vulnerability_findings(query_text: str = "", days: int = 30, limit: int = 120) -> Dict[str, Any]:
    if _prefer_structured_vulnerability(days):
        return _vuln_store().search_vulnerability_findings(query_text=query_text, days=days, limit=limit)
    return _search_vulnerability_findings_raw(query_text=query_text, days=days, limit=limit)


def fetch_vulnerability_hosts(query_text: str = "", days: int = 30, limit: int = 120) -> Dict[str, Any]:
    if _prefer_structured_vulnerability(days):
        return _vuln_store().fetch_vulnerability_hosts(query_text=query_text, days=days, limit=limit)
    return _fetch_vulnerability_hosts_raw(query_text=query_text, days=days, limit=limit)


def fetch_vulnerability_software(query_text: str = "", days: int = 30, limit: int = 120) -> Dict[str, Any]:
    if _prefer_structured_vulnerability(days):
        return _vuln_store().fetch_vulnerability_software(query_text=query_text, days=days, limit=limit)
    return _fetch_vulnerability_software_raw(query_text=query_text, days=days, limit=limit)


def fetch_vulnerability_cves(query_text: str = "", days: int = 30, limit: int = 120) -> Dict[str, Any]:
    if _prefer_structured_vulnerability(days):
        return _vuln_store().fetch_vulnerability_cves(query_text=query_text, days=days, limit=limit)
    return _fetch_vulnerability_cves_raw(query_text=query_text, days=days, limit=limit)


def _platform_ops():
    try:
        from . import deps_platform_ops as platform_module
    except ImportError:  # pragma: no cover - local test fallback
        import deps_platform_ops as platform_module  # type: ignore[no-redef]

    return platform_module


def _runtime_docs_ops():
    try:
        from . import deps_runtime_docs_ops as runtime_docs_module
    except ImportError:  # pragma: no cover - local test fallback
        import deps_runtime_docs_ops as runtime_docs_module  # type: ignore[no-redef]

    return runtime_docs_module


def fetch_source_inventory(limit: int = 200, hours: int = 24) -> List[Dict[str, Any]]:
    return _platform_ops().fetch_source_inventory(limit=limit, hours=hours)


def fetch_collector_inventory(hours: int = 24) -> List[Dict[str, Any]]:
    return _platform_ops().fetch_collector_inventory(hours=hours)


def fetch_resource_overview() -> Dict[str, Any]:
    return _platform_ops().fetch_resource_overview()


def fetch_platform_status() -> Dict[str, Any]:
    return _platform_ops().fetch_platform_status()


def fetch_transport_shadow_status() -> Dict[str, Any]:
    return _platform_ops().fetch_transport_shadow_status()


def list_runtime_docs() -> List[Dict[str, Any]]:
    return _runtime_docs_ops().list_runtime_docs()


def load_runtime_doc(name: str) -> Dict[str, Any]:
    return _runtime_docs_ops().load_runtime_doc(name)


def save_runtime_doc(name: str, content: str) -> Dict[str, Any]:
    return _runtime_docs_ops().save_runtime_doc(name, content)


def save_runtime_doc_file(filename: str, payload: bytes) -> Dict[str, Any]:
    return _runtime_docs_ops().save_runtime_doc_file(filename, payload)


def delete_runtime_doc(name: str) -> None:
    _runtime_docs_ops().delete_runtime_doc(name)


def list_dashboards() -> List[Dict[str, Any]]:
    return _runtime_docs_ops().list_dashboards()


def describe_dashboard_widgets() -> List[Dict[str, Any]]:
    return _runtime_docs_ops().describe_dashboard_widgets()


def save_dashboard_definition(
    title: str,
    description: str,
    widgets: List[str],
    layout: List[Dict[str, Any]] | None = None,
    dashboard_id: str = "",
) -> Dict[str, Any]:
    return _runtime_docs_ops().save_dashboard_definition(
        title=title,
        description=description,
        widgets=widgets,
        layout=layout,
        dashboard_id=dashboard_id,
    )


def delete_dashboard_definition(dashboard_id: str) -> None:
    _runtime_docs_ops().delete_dashboard_definition(dashboard_id)


def list_builder_drafts() -> List[Dict[str, Any]]:
    return _runtime_docs_ops().list_builder_drafts()


def save_builder_draft(
    title: str,
    description: str,
    kind: str,
    blocks: List[Dict[str, Any]],
    draft_id: str = "",
    status: str = "draft",
) -> Dict[str, Any]:
    return _runtime_docs_ops().save_builder_draft(
        title=title,
        description=description,
        kind=kind,
        blocks=blocks,
        draft_id=draft_id,
        status=status,
    )


def delete_builder_draft(draft_id: str) -> None:
    _runtime_docs_ops().delete_builder_draft(draft_id)


def validate_builder_draft_payload(
    title: str,
    description: str,
    kind: str,
    blocks: List[Dict[str, Any]],
) -> Dict[str, Any]:
    return _runtime_docs_ops().validate_builder_draft_payload(title, description, kind, blocks)


def test_builder_draft_payload(
    title: str,
    description: str,
    kind: str,
    blocks: List[Dict[str, Any]],
) -> Dict[str, Any]:
    return _runtime_docs_ops().test_builder_draft_payload(title, description, kind, blocks)


def publish_builder_draft(draft_id: str) -> Dict[str, Any]:
    return _runtime_docs_ops().publish_builder_draft(draft_id)
