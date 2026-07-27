from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import re
from threading import RLock
from time import monotonic
from typing import Any
from uuid import UUID

from .clickhouse_runtime import get_clickhouse_client


@dataclass(frozen=True)
class SecurityService:
    service_id: str
    title: str
    product: str
    host_name: str
    address: str
    placement: str
    role: str
    asset_group: str
    expected_products: tuple[str, ...]
    capabilities: tuple[str, ...]


SECURITY_SERVICES: tuple[SecurityService, ...] = (
    SecurityService(
        "ndr",
        "Network Detection",
        "Zeek 8.2.1",
        "soc-ndr-01",
        "10.20.10.127",
        "VM127",
        "NDR",
        "sec",
        ("zeek", "host.metrics"),
        ("network sessions", "DNS and TLS telemetry", "protocol anomalies", "network evidence"),
    ),
    SecurityService(
        "dfir",
        "Endpoint DFIR",
        "Velociraptor 0.77.1",
        "soc-dfir-01",
        "10.20.10.128",
        "CT128",
        "DFIR",
        "sec",
        ("velociraptor", "host.metrics"),
        ("endpoint collections", "hunts", "artifact results", "triage evidence"),
    ),
    SecurityService(
        "analysis",
        "Malware Analysis",
        "ClamAV, YARA and static analysis toolchain",
        "soc-analysis-01",
        "10.20.30.129",
        "CT129",
        "Static analysis",
        "lab",
        ("malware-analysis", "clamav", "yara", "host.metrics"),
        ("file verdicts", "hash extraction", "YARA matches", "static evidence"),
    ),
    SecurityService(
        "threat-intel",
        "Threat Intelligence",
        "MISP",
        "soc-ti-01",
        "10.20.10.131",
        "VM131",
        "TIP",
        "sec",
        ("misp", "host.metrics"),
        ("indicator lifecycle", "feed ingestion", "IOC export", "event-side sightings"),
    ),
    SecurityService(
        "pki",
        "Internal PKI",
        "step-ca",
        "soc-pki-01",
        "10.20.10.132",
        "CT132",
        "PKI",
        "sec",
        ("step-ca", "host.metrics"),
        ("certificate authority health", "service identity", "certificate issuance telemetry"),
    ),
    SecurityService(
        "evidence",
        "Evidence Storage",
        "MinIO",
        "soc-evidence-01",
        "10.20.10.133",
        "CT133",
        "Evidence store",
        "sec",
        ("minio", "host.metrics"),
        ("immutable evidence objects", "retention", "collection bundles", "chain-of-custody storage"),
    ),
)

_SERVICE_INDEX = {item.service_id: item for item in SECURITY_SERVICES}
_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_CACHE_LOCK = RLock()
_CACHE_TTL_SECONDS = 30.0
_QUERY_SETTINGS = {"max_execution_time": 6, "max_threads": 2}
_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|token|api[_-]?key|secret|client_secret)\b(\s*[:=]\s*)([^\s,;]+)"
)


def _sql_quote(value: str) -> str:
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def _format(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    return value


def _redact(value: Any, limit: int = 800) -> str:
    text = str(value or "")
    return _SECRET_RE.sub(lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]", text)[:limit]


def _service_payload(service: SecurityService) -> dict[str, Any]:
    payload = asdict(service)
    payload["expected_products"] = list(service.expected_products)
    payload["capabilities"] = list(service.capabilities)
    payload["pivots"] = {
        "events": f"/events?q={service.host_name}",
        "incidents": f"/incidents?q={service.host_name}",
        "host_runtime": f"/host-runtime?host={service.host_name}",
        "sources": f"/sources?q={service.host_name}",
    }
    return payload


def _summary_rows(
    client: Any,
    services: tuple[SecurityService, ...] = SECURITY_SERVICES,
) -> dict[str, dict[str, Any]]:
    hosts = ", ".join(_sql_quote(item.host_name) for item in services)
    query = f"""
        SELECT
            if(host_name IN ({hosts}), host_name, log_source) AS service_host,
            countIf(ts >= now() - INTERVAL 15 MINUTE) AS events_15m,
            count() AS events_1h,
            max(ts) AS latest_event,
            groupUniqArray(16)(device_product) AS products,
            groupUniqArray(24)(subcategory) AS signal_types
        FROM siem.events
        WHERE ts >= now() - INTERVAL 1 HOUR
          AND (host_name IN ({hosts}) OR log_source IN ({hosts}))
        GROUP BY service_host
    """
    return {
        str(row["service_host"]): {
            "events_15m": int(row.get("events_15m") or 0),
            "events_1h": int(row.get("events_1h") or 0),
            "latest_event": _format(row.get("latest_event")),
            "products": sorted(str(value) for value in row.get("products") or [] if str(value or "").strip()),
            "signal_types": sorted(str(value) for value in row.get("signal_types") or [] if str(value or "").strip()),
        }
        for row in client.query(query, settings=_QUERY_SETTINGS).named_results()
    }


def list_security_services(*, client: Any | None = None) -> dict[str, Any]:
    cache_key = "catalog"
    now = monotonic()
    if client is None:
        with _CACHE_LOCK:
            cached = _CACHE.get(cache_key)
        if cached and now - cached[0] < _CACHE_TTL_SECONDS:
            return deepcopy(cached[1])
    runtime_client = client or get_clickhouse_client()
    summaries = _summary_rows(runtime_client)
    items: list[dict[str, Any]] = []
    for service in SECURITY_SERVICES:
        summary = summaries.get(service.host_name, {})
        events_15m = int(summary.get("events_15m") or 0)
        items.append(
            {
                **_service_payload(service),
                **summary,
                "telemetry_state": "healthy" if events_15m > 0 else "stale",
            }
        )
    payload = {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "healthy": sum(1 for item in items if item["telemetry_state"] == "healthy"),
        "total": len(items),
        "items": items,
    }
    if client is None:
        with _CACHE_LOCK:
            _CACHE[cache_key] = (now, payload)
    return deepcopy(payload)


def _detail_payload(service: SecurityService, client: Any) -> dict[str, Any]:
    host = _sql_quote(service.host_name)
    breakdown_query = f"""
        SELECT
            device_product,
            category,
            subcategory,
            lower(severity) AS severity,
            count() AS event_count,
            max(ts) AS latest_event
        FROM siem.events
        WHERE ts >= now() - INTERVAL 1 HOUR
          AND (host_name = {host} OR log_source = {host})
        GROUP BY device_product, category, subcategory, severity
        ORDER BY event_count DESC
        LIMIT 50
    """
    recent_query = f"""
        SELECT
            ts,
            event_id,
            category,
            subcategory,
            event_action,
            event_outcome,
            lower(severity) AS severity,
            device_product,
            log_source,
            host_name,
            if(src_ip = 0, '', IPv4NumToString(src_ip)) AS src_ip,
            if(dst_ip = 0, '', IPv4NumToString(dst_ip)) AS dst_ip,
            src_port,
            dst_port,
            user_name,
            process_name,
            rule_name,
            file_sha256,
            evidence_id,
            substring(message, 1, 800) AS message
        FROM siem.events
        WHERE ts >= now() - INTERVAL 1 HOUR
          AND (host_name = {host} OR log_source = {host})
        ORDER BY ts DESC
        LIMIT 50
    """
    alerts_query = f"""
        SELECT
            ts_last,
            alert_id,
            rule_id,
            rule_name,
            lower(severity) AS severity,
            hits,
            entity_key,
            status,
            source
        FROM siem.alerts_raw
        WHERE ts_last >= now() - INTERVAL 7 DAY
          AND (source = {host} OR positionCaseInsensitiveUTF8(context_json, {host}) > 0)
          AND positionCaseInsensitiveUTF8(context_json, 'benchmark') = 0
          AND positionCaseInsensitiveUTF8(context_json, 'synthetic') = 0
          AND positionCaseInsensitiveUTF8(context_json, 'e2e') = 0
        ORDER BY ts_last DESC
        LIMIT 50
    """
    breakdown = [
        {key: _format(value) for key, value in dict(row).items()}
        for row in client.query(breakdown_query, settings=_QUERY_SETTINGS).named_results()
    ]
    recent_events = []
    for source_row in client.query(recent_query, settings=_QUERY_SETTINGS).named_results():
        row = {key: _format(value) for key, value in dict(source_row).items()}
        row["message"] = _redact(row.get("message"))
        recent_events.append(row)
    recent_alerts = [
        {key: _format(value) for key, value in dict(row).items()}
        for row in client.query(alerts_query, settings=_QUERY_SETTINGS).named_results()
    ]
    summary = _summary_rows(client, (service,)).get(service.host_name, {})
    events_15m = int(summary.get("events_15m") or 0)
    return {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "service": _service_payload(service),
        "telemetry": {
            **summary,
            "state": "healthy" if events_15m > 0 else "stale",
            "alerts_7d_returned": len(recent_alerts),
        },
        "signal_breakdown": breakdown,
        "recent_events": recent_events,
        "recent_alerts": recent_alerts,
    }


def get_security_service(service_id: str, *, client: Any | None = None) -> dict[str, Any]:
    normalized_id = str(service_id or "").strip().lower()
    service = _SERVICE_INDEX.get(normalized_id)
    if service is None:
        raise KeyError(normalized_id)
    now = monotonic()
    cache_key = f"detail:{normalized_id}"
    if client is None:
        with _CACHE_LOCK:
            cached = _CACHE.get(cache_key)
        if cached and now - cached[0] < _CACHE_TTL_SECONDS:
            return deepcopy(cached[1])
    payload = _detail_payload(service, client or get_clickhouse_client())
    if client is None:
        with _CACHE_LOCK:
            _CACHE[cache_key] = (now, payload)
    return deepcopy(payload)


def clear_security_services_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()
