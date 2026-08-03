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
        "Zeek 8.2.1 and Arkime 6.3.1",
        "soc-ndr-01",
        "10.20.10.127",
        "VM127",
        "NDR",
        "sec",
        ("zeek", "arkime", "host.metrics"),
        (
            "network sessions",
            "DNS and TLS telemetry",
            "protocol anomalies",
            "packet capture",
            "network evidence",
        ),
    ),
    SecurityService(
        "ngfw",
        "Network Firewall",
        "OPNsense",
        "opnsense-edge-01",
        "192.168.3.103",
        "VM103",
        "NGFW and router",
        "mgmt",
        ("opnsense", "host.metrics"),
        (
            "inter-zone routing",
            "stateful firewall",
            "source NAT",
            "DNS resolver",
            "VPN-aware policy",
        ),
    ),
    SecurityService(
        "ips",
        "Network IPS",
        "Suricata on OPNsense and edge",
        "opnsense-edge-01",
        "192.168.3.103",
        "VM103 / VM102",
        "IDS and IPS",
        "mgmt",
        ("suricata", "linux.suricata", "host.metrics"),
        (
            "multi-segment inspection",
            "signature alerts",
            "flow telemetry",
            "DNS and TLS inspection",
        ),
    ),
    SecurityService(
        "vpn",
        "Remote Access VPN",
        "WireGuard on OPNsense",
        "opnsense-edge-01",
        "192.168.3.103",
        "VM103",
        "Remote access gateway",
        "mgmt",
        ("wireguard", "opnsense", "host.metrics"),
        (
            "remote access tunnels",
            "peer activity",
            "VPN-aware firewall policy",
            "connection telemetry",
        ),
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
        "vulnerability",
        "Vulnerability Management",
        "Greenbone Community Edition and OpenVAS",
        "vuln-mgr-01",
        "10.20.30.122",
        "VM122",
        "Vulnerability management",
        "lab",
        ("openvas.finding", "nmap", "host.metrics"),
        (
            "asset discovery",
            "authenticated scanning",
            "finding lifecycle",
            "remediation validation",
        ),
    ),
    SecurityService(
        "runtime",
        "Container Runtime Security",
        "Falco 0.44.1",
        "gamepanel-01",
        "10.20.20.130",
        "VM130",
        "Runtime protection",
        "servers_games",
        ("falco", "host.metrics"),
        (
            "container runtime detection",
            "process telemetry",
            "workload triage",
            "SIEM correlation",
        ),
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
SERVICE_WORKSPACES: dict[str, list[dict[str, Any]]] = {
    "ndr": [
        {"label": "Arkime sessions", "href": "http://192.168.3.102:8005/", "external": True, "kind": "native", "description": "Packet sessions and bounded PCAP evidence."},
        {"label": "Network events", "href": "/events?q=soc-ndr-01", "kind": "siem", "description": "Normalized Zeek and Arkime telemetry."},
        {"label": "Telemetry topology", "href": "/topology", "kind": "siem", "description": "Source-to-collector event path."},
    ],
    "ngfw": [
        {"label": "OPNsense console", "href": "https://192.168.3.103/", "external": True, "kind": "native", "description": "Native router and firewall console."},
        {"label": "Firewall events", "href": "/events?q=opnsense-edge-01", "kind": "siem", "description": "Normalized firewall decisions and audit events."},
    ],
    "ips": [
        {"label": "OPNsense console", "href": "https://192.168.3.103/", "external": True, "kind": "native", "description": "Native Suricata policy and diagnostics."},
        {"label": "IPS events", "href": "/events?q=suricata", "kind": "siem", "description": "Normalized alerts, flows, DNS and TLS evidence."},
    ],
    "vpn": [
        {"label": "OPNsense console", "href": "https://192.168.3.103/", "external": True, "kind": "native", "description": "Native WireGuard peers, tunnels and gateway diagnostics."},
        {"label": "VPN events", "href": "/events?q=wireguard", "kind": "siem", "description": "Normalized tunnel, peer and firewall telemetry."},
        {"label": "Access governance", "href": "/access", "kind": "siem", "description": "Identity, service accounts and remote-access permissions."},
    ],
    "dfir": [
        {"label": "Velociraptor console", "href": "https://192.168.3.102:8889/app/index.html", "external": True, "kind": "native", "description": "Endpoint hunts and artifact collections."},
        {"label": "Cases", "href": "/cases", "kind": "siem", "description": "Investigation case files and evidence."},
        {"label": "Response", "href": "/response", "kind": "siem", "description": "Approved response workflows."},
    ],
    "analysis": [
        {"label": "Analysis events", "href": "/events?q=soc-analysis-01", "kind": "siem", "description": "ClamAV, YARA and static-analysis verdicts."},
        {"label": "Cases", "href": "/cases", "kind": "siem", "description": "Attach verdicts and hashes to investigations."},
    ],
    "vulnerability": [
        {"label": "Vulnerability workspace", "href": "/vuln", "kind": "siem", "description": "Targets, scans, findings and remediation validation."},
        {"label": "Greenbone console", "href": "http://192.168.3.102:9392/", "external": True, "kind": "native", "description": "Native scanner task and report console."},
    ],
    "runtime": [
        {"label": "Host runtime", "href": "/host-runtime?host=gamepanel-01", "kind": "siem", "description": "Workload health and host operations."},
        {"label": "Falco events", "href": "/events?q=falco", "kind": "siem", "description": "Runtime security detections."},
        {"label": "Response", "href": "/response", "kind": "siem", "description": "Approved containment workflows."},
    ],
    "threat-intel": [
        {"label": "Threat intelligence", "href": "/threat-intel", "kind": "siem", "description": "Indicators, sightings, expiry and confidence."},
        {"label": "MISP console", "href": "https://192.168.3.102:8444/", "external": True, "kind": "native", "description": "Native event, feed and IOC management."},
    ],
    "pki": [
        {"label": "Access governance", "href": "/access", "kind": "siem", "description": "Service identities and access lifecycle."},
        {"label": "PKI events", "href": "/events?q=soc-pki-01", "kind": "siem", "description": "step-ca issuance and audit telemetry."},
    ],
    "evidence": [
        {"label": "Evidence cases", "href": "/cases", "kind": "siem", "description": "Case-linked evidence and custody trail."},
        {"label": "MinIO console", "href": "https://192.168.3.102:9001/", "external": True, "kind": "native", "description": "Native object storage console."},
    ],
}
SERVICE_INTEGRATION_MODES = {
    "ngfw": "managed_control",
    "ips": "managed_control",
    "vpn": "managed_control",
}
_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_CACHE_LOCK = RLock()
_CACHE_TTL_SECONDS = 30.0
_QUERY_SETTINGS = {"max_execution_time": 6, "max_threads": 2}
_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|token|api[_-]?key|secret|client_secret)\b(\s*[:=]\s*)([^\s,;]+)"
)
_HOST_MONITORING_PRODUCTS = {"host.metrics"}
_CONTROL_STATES = {"unavailable", "read-only", "managed"}
_OPNSENSE_OPERATIONS: dict[str, tuple[str, ...]] = {
    "ngfw": ("create", "update", "toggle", "delete"),
    "ips": ("toggle_rule", "toggle_ruleset", "reload", "update"),
}


def _error_text(exc: Exception) -> str:
    return _redact(str(exc), limit=300) or exc.__class__.__name__


def _opnsense_adapter_snapshot() -> dict[str, Any]:
    adapter = "services.web.app.opnsense_control_runtime"
    try:
        from .opnsense_control_runtime import load_opnsense_config

        config = load_opnsense_config()
    except Exception as exc:  # noqa: BLE001 - adapter discovery must not break telemetry
        return {
            "adapter": adapter,
            "state": "unavailable",
            "reason": f"OPNsense adapter discovery failed: {_error_text(exc)}",
        }
    if not config.configured:
        return {
            "adapter": adapter,
            "state": "unavailable",
            "reason": "OPNsense control credentials are not configured",
        }
    return {
        "adapter": adapter,
        "state": "managed",
        "reason": "OPNsense control adapter and credentials are configured",
        "auth_mode": config.auth_mode,
    }


def _remote_access_adapter_snapshot() -> dict[str, Any]:
    adapter = "services.web.app.remote_access_runtime"
    try:
        from .remote_access_runtime import remote_access_state

        state = remote_access_state()
    except Exception as exc:  # noqa: BLE001 - adapter discovery must not break telemetry
        return {
            "adapter": adapter,
            "state": "unavailable",
            "reason": f"Remote-access adapter discovery failed: {_error_text(exc)}",
            "providers": {},
        }
    providers = {
        str(item.get("provider") or "").strip().lower(): dict(item)
        for item in state.get("controllers") or []
        if isinstance(item, dict) and str(item.get("provider") or "").strip()
    }
    managed = [name for name, item in providers.items() if bool(item.get("configured"))]
    return {
        "adapter": adapter,
        "state": "managed" if managed else "unavailable",
        "reason": (
            f"Managed profile issuance is configured for: {', '.join(sorted(managed))}"
            if managed
            else "No remote-access profile controller is configured"
        ),
        "providers": providers,
    }


def _adapter_inventory() -> dict[str, dict[str, Any]]:
    opnsense = _opnsense_adapter_snapshot()
    return {
        "ngfw": deepcopy(opnsense),
        "ips": deepcopy(opnsense),
        "vpn": _remote_access_adapter_snapshot(),
    }


def _action(
    action_id: str,
    label: str,
    *,
    state: str,
    adapter: str,
    operation: str,
    href: str,
    method: str = "GET",
    reason: str = "",
    provider: str = "",
) -> dict[str, Any]:
    normalized_state = state if state in _CONTROL_STATES else "unavailable"
    payload = {
        "id": action_id,
        "label": label,
        "state": normalized_state,
        "available": normalized_state != "unavailable",
        "managed": normalized_state == "managed",
        "adapter": adapter,
        "operation": operation,
        "href": href,
        "method": method,
    }
    if reason:
        payload["reason"] = reason
    if provider:
        payload["provider"] = provider
    return payload


def _control_contract(
    service: SecurityService,
    adapter_inventory: dict[str, dict[str, Any]],
    *,
    telemetry_state: str = "fresh",
    incidents_state: str = "fresh",
) -> dict[str, Any]:
    telemetry_adapter = "services.web.app.clickhouse_runtime.get_clickhouse_client"
    telemetry_available = telemetry_state != "error"
    incidents_available = incidents_state != "error"
    actions = [
        _action(
            "telemetry.view",
            "View telemetry",
            state="read-only" if telemetry_available else "unavailable",
            adapter=telemetry_adapter,
            operation="query siem.events",
            href=f"/events?q={service.host_name}",
            reason="" if telemetry_available else "ClickHouse event telemetry is unavailable",
        ),
        _action(
            "incidents.view",
            "View incidents",
            state="read-only" if incidents_available else "unavailable",
            adapter=telemetry_adapter,
            operation="query siem.alerts_raw",
            href=f"/incidents?q={service.host_name}",
            reason="" if incidents_available else "ClickHouse alert telemetry is unavailable",
        ),
    ]
    adapter = adapter_inventory.get(service.service_id)
    if service.service_id in _OPNSENSE_OPERATIONS:
        adapter = adapter or {
            "adapter": "services.web.app.opnsense_control_runtime",
            "state": "unavailable",
            "reason": "OPNsense adapter was not discovered",
        }
        for operation in _OPNSENSE_OPERATIONS[service.service_id]:
            actions.append(
                _action(
                    f"{service.service_id}.{operation}",
                    operation.replace("_", " ").title(),
                    state=str(adapter.get("state") or "unavailable"),
                    adapter=str(adapter.get("adapter") or ""),
                    operation=operation,
                    href=(
                        f"/api/security-services/ngfw/firewall/{operation}"
                        if service.service_id == "ngfw"
                        else f"/api/security-services/ips/{operation}"
                    ),
                    method="POST",
                    reason=str(adapter.get("reason") or ""),
                )
            )
    elif service.service_id == "vpn":
        adapter = adapter or {
            "adapter": "services.web.app.remote_access_runtime",
            "state": "unavailable",
            "reason": "Remote-access adapter was not discovered",
            "providers": {},
        }
        providers = dict(adapter.get("providers") or {})
        actions.append(
            _action(
                "vpn.profiles.list",
                "List profiles",
                state="read-only",
                adapter=str(adapter.get("adapter") or ""),
                operation="remote_access_state",
                href="/api/security-services/vpn/remote-access",
            )
        )
        for provider in ("openvpn", "vless"):
            provider_state = dict(providers.get(provider) or {})
            configured = bool(provider_state.get("configured"))
            reason = (
                f"{provider} profile controller is configured"
                if configured
                else f"{provider} profile controller is not configured"
            )
            actions.append(
                _action(
                    f"vpn.{provider}.create",
                    f"Create {provider} profile",
                    state="managed" if configured else "unavailable",
                    adapter=str(adapter.get("adapter") or ""),
                    operation="create_remote_access_profile",
                    href="/api/security-services/vpn/remote-access",
                    method="POST",
                    reason=reason,
                    provider=provider,
                )
            )
        openvpn = dict(providers.get("openvpn") or {})
        revoke_managed = bool(openvpn.get("configured") and openvpn.get("local_controller"))
        actions.append(
            _action(
                "vpn.openvpn.revoke",
                "Revoke OpenVPN profile",
                state="managed" if revoke_managed else "unavailable",
                adapter=str(adapter.get("adapter") or ""),
                operation="delete_remote_access_profile",
                href="/api/security-services/vpn/remote-access/{profile_id}",
                method="DELETE",
                reason=(
                    "The local OpenVPN controller supports CA revocation"
                    if revoke_managed
                    else "CA-backed OpenVPN revocation is not available"
                ),
                provider="openvpn",
            )
        )

    write_actions = [item for item in actions if item["method"] != "GET"]
    if any(item["state"] == "managed" for item in write_actions):
        control_state = "managed"
    elif write_actions:
        control_state = "unavailable"
    elif any(item["available"] for item in actions):
        control_state = "read-only"
    else:
        control_state = "unavailable"
    return {
        "control_state": control_state,
        "actions": actions,
        "available_actions": [item["id"] for item in actions if item["available"]],
        "adapter": deepcopy(adapter) if adapter else None,
    }


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


def _service_payload(
    service: SecurityService,
    *,
    adapter_inventory: dict[str, dict[str, Any]] | None = None,
    telemetry_state: str = "fresh",
    incidents_state: str = "fresh",
) -> dict[str, Any]:
    payload = asdict(service)
    payload["expected_products"] = list(service.expected_products)
    payload["capabilities"] = list(service.capabilities)
    payload["pivots"] = {
        "events": f"/events?q={service.host_name}",
        "incidents": f"/incidents?q={service.host_name}",
        "host_runtime": f"/host-runtime?host={service.host_name}",
        "sources": f"/sources?q={service.host_name}",
    }
    control = _control_contract(
        service,
        adapter_inventory or {},
        telemetry_state=telemetry_state,
        incidents_state=incidents_state,
    )
    payload["integration_mode"] = (
        SERVICE_INTEGRATION_MODES.get(service.service_id, "telemetry_and_pivot")
        if control["control_state"] == "managed"
        else "telemetry_and_pivot"
    )
    payload.update(control)
    payload["workspaces"] = deepcopy(SERVICE_WORKSPACES.get(service.service_id) or [])
    payload["native_console_route"] = (
        "direct"
        if service.service_id in {"ngfw", "ips"}
        else "10.20.0.0/16 via 192.168.3.103"
    )
    return payload


def _normalized_product(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", ".", str(value or "").strip().lower()).strip(".")


def _product_matches(expected: str, observed: str) -> bool:
    expected_name = _normalized_product(expected)
    observed_name = _normalized_product(observed)
    if not expected_name or not observed_name:
        return False
    return (
        expected_name == observed_name
        or observed_name.endswith(f".{expected_name}")
        or expected_name.endswith(f".{observed_name}")
    )


def _integration_health(
    service: SecurityService,
    summary: dict[str, Any],
    *,
    metrics_state: str = "fresh",
) -> dict[str, Any]:
    observed = [
        str(value)
        for value in summary.get("products") or []
        if _normalized_product(value) not in _HOST_MONITORING_PRODUCTS
    ]
    expected = [
        value
        for value in service.expected_products
        if _normalized_product(value) not in _HOST_MONITORING_PRODUCTS
    ]
    matched = [
        expected_product
        for expected_product in expected
        if any(_product_matches(expected_product, observed_product) for observed_product in observed)
    ]
    missing = [value for value in expected if value not in matched]
    events_15m = int(summary.get("events_15m") or 0)
    events_24h = int(summary.get("events_24h") or 0)
    monitoring_seen = any(
        _normalized_product(value) in _HOST_MONITORING_PRODUCTS
        for value in summary.get("products") or []
    )
    if metrics_state == "error":
        state = "degraded"
        telemetry_state = "error"
    elif matched and events_15m > 0:
        state = "healthy"
        telemetry_state = state
    elif matched and events_24h > 0:
        state = "quiet"
        telemetry_state = state
    elif events_15m > 0 or monitoring_seen:
        state = "degraded"
        telemetry_state = state
    else:
        state = "stale"
        telemetry_state = state
    return {
        "integration_state": state,
        "telemetry_state": telemetry_state,
        "host_telemetry_state": (
            "error"
            if metrics_state == "error"
            else "healthy"
            if events_15m > 0 and monitoring_seen
            else "quiet"
            if monitoring_seen
            else "stale"
        ),
        "matched_products": matched,
        "missing_products": missing,
        "product_coverage": round(len(matched) / len(expected), 3) if expected else 1.0,
    }


def _empty_summary() -> dict[str, Any]:
    return {
        "events_15m": 0,
        "events_1h": 0,
        "events_24h": 0,
        "latest_event": None,
        "products": [],
        "signal_types": [],
    }


def _metrics_contract(
    summary: dict[str, Any],
    *,
    query_error: str = "",
) -> dict[str, Any]:
    if query_error:
        state = "error"
    elif int(summary.get("events_15m") or 0) > 0:
        state = "fresh"
    else:
        state = "stale"
    payload = {
        "state": state,
        "source": "clickhouse:siem.events",
        "window": "24h",
        "latest_event": summary.get("latest_event"),
        "observed": bool(int(summary.get("events_24h") or 0)),
    }
    if query_error:
        payload["error"] = query_error
    return payload


def _query_rows(client: Any, query: str) -> tuple[list[dict[str, Any]], str]:
    try:
        return [dict(row) for row in client.query(query, settings=_QUERY_SETTINGS).named_results()], ""
    except Exception as exc:  # noqa: BLE001 - partial datasets remain useful to operators
        return [], _error_text(exc)


def _summary_rows(
    client: Any,
    services: tuple[SecurityService, ...] = SECURITY_SERVICES,
) -> dict[str, dict[str, Any]]:
    hosts = ", ".join(_sql_quote(item.host_name) for item in services)
    query = f"""
        SELECT
            if(host_name IN ({hosts}), host_name, log_source) AS service_host,
            countIf(ts >= now() - INTERVAL 15 MINUTE) AS events_15m,
            countIf(ts >= now() - INTERVAL 1 HOUR) AS events_1h,
            count() AS events_24h,
            max(ts) AS latest_event,
            groupUniqArray(128)(device_product) AS products,
            groupUniqArray(128)(subcategory) AS signal_types
        FROM siem.events
        WHERE ts >= now() - INTERVAL 24 HOUR
          AND (host_name IN ({hosts}) OR log_source IN ({hosts}))
        GROUP BY service_host
    """
    return {
        str(row["service_host"]): {
            "events_15m": int(row.get("events_15m") or 0),
            "events_1h": int(row.get("events_1h") or 0),
            "events_24h": int(row.get("events_24h") or 0),
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
    summary_error = ""
    try:
        summaries = _summary_rows(runtime_client)
    except Exception as exc:  # noqa: BLE001 - return explicit error state, not a fake empty success
        summaries = {}
        summary_error = _error_text(exc)
    adapter_inventory = _adapter_inventory()
    items: list[dict[str, Any]] = []
    for service in SECURITY_SERVICES:
        summary = {**_empty_summary(), **summaries.get(service.host_name, {})}
        metrics = _metrics_contract(summary, query_error=summary_error)
        health = _integration_health(service, summary, metrics_state=metrics["state"])
        items.append(
            {
                **_service_payload(
                    service,
                    adapter_inventory=adapter_inventory,
                    telemetry_state=metrics["state"],
                    incidents_state=metrics["state"],
                ),
                **summary,
                **health,
                "metrics_state": metrics["state"],
                "metrics": metrics,
            }
        )
    payload = {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "data_state": "error" if summary_error else ("fresh" if any(item["metrics_state"] == "fresh" for item in items) else "stale"),
        "healthy": sum(1 for item in items if item["integration_state"] == "healthy"),
        "quiet": sum(1 for item in items if item["integration_state"] == "quiet"),
        "degraded": sum(1 for item in items if item["integration_state"] == "degraded"),
        "stale": sum(1 for item in items if item["integration_state"] == "stale"),
        "error": sum(1 for item in items if item["metrics_state"] == "error"),
        "total": len(items),
        "items": items,
    }
    if summary_error:
        payload["data_error"] = summary_error
    if client is None and not summary_error:
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
    breakdown_rows, breakdown_error = _query_rows(client, breakdown_query)
    breakdown = [
        {key: _format(value) for key, value in row.items()}
        for row in breakdown_rows
    ]
    recent_rows, recent_error = _query_rows(client, recent_query)
    recent_events = []
    for source_row in recent_rows:
        row = {key: _format(value) for key, value in source_row.items()}
        row["message"] = _redact(row.get("message"))
        recent_events.append(row)
    alert_rows, alerts_error = _query_rows(client, alerts_query)
    recent_alerts = [
        {key: _format(value) for key, value in row.items()}
        for row in alert_rows
    ]
    summary_error = ""
    try:
        summary = {**_empty_summary(), **_summary_rows(client, (service,)).get(service.host_name, {})}
    except Exception as exc:  # noqa: BLE001
        summary = _empty_summary()
        summary_error = _error_text(exc)
    metrics = _metrics_contract(summary, query_error=summary_error)
    health = _integration_health(service, summary, metrics_state=metrics["state"])
    datasets = {
        "summary": {"state": metrics["state"], **({"error": summary_error} if summary_error else {})},
        "signal_breakdown": {"state": "error" if breakdown_error else metrics["state"], **({"error": breakdown_error} if breakdown_error else {})},
        "recent_events": {"state": "error" if recent_error else metrics["state"], **({"error": recent_error} if recent_error else {})},
        "recent_alerts": {"state": "error" if alerts_error else "fresh", **({"error": alerts_error} if alerts_error else {})},
    }
    detail_error = any(value["state"] == "error" for value in datasets.values())
    adapter_inventory = _adapter_inventory()
    return {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "data_state": "error" if detail_error else metrics["state"],
        "service": _service_payload(
            service,
            adapter_inventory=adapter_inventory,
            telemetry_state=metrics["state"],
            incidents_state="error" if alerts_error else "fresh",
        ),
        "telemetry": {
            **summary,
            **health,
            "state": health["integration_state"],
            "metrics_state": metrics["state"],
            "metrics": metrics,
            "alerts_7d_returned": len(recent_alerts),
        },
        "datasets": datasets,
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
    if client is None and payload.get("data_state") != "error":
        with _CACHE_LOCK:
            _CACHE[cache_key] = (now, payload)
    return deepcopy(payload)


def clear_security_services_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()
