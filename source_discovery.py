from __future__ import annotations

import ipaddress
import json
import os
import queue
import shlex
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from .enterprise_control_plane import control_plane_collection_path, load_control_plane_rows, save_control_plane_rows
except ImportError:  # pragma: no cover - local test fallback
    from enterprise_control_plane import control_plane_collection_path, load_control_plane_rows, save_control_plane_rows  # type: ignore[no-redef]
try:
    from .inventory_catalog import SOURCE_ALIAS_OVERRIDES
except ImportError:  # pragma: no cover - local test fallback
    from inventory_catalog import SOURCE_ALIAS_OVERRIDES  # type: ignore[no-redef]
try:
    from .source_onboarding_runtime import (
        build_network_onboarding_plan,
        build_windows_native_package,
        build_windows_native_package_spec,
        execute_network_cli_push,
    )
except ImportError:  # pragma: no cover - local test fallback
    from source_onboarding_runtime import (  # type: ignore[no-redef]
        build_network_onboarding_plan,
        build_windows_native_package,
        build_windows_native_package_spec,
        execute_network_cli_push,
    )
try:
    from .asset_binding_overrides import list_binding_overrides
except ImportError:  # pragma: no cover - local test fallback
    from asset_binding_overrides import list_binding_overrides  # type: ignore[no-redef]
try:
    from .asset_catalog_runtime import fetch_source_inventory
except ImportError:  # pragma: no cover - local test fallback
    try:
        from asset_catalog_runtime import fetch_source_inventory  # type: ignore[no-redef]
    except ImportError:  # pragma: no cover - tests without runtime DB
        fetch_source_inventory = None  # type: ignore[assignment]

DISCOVERY_CANDIDATES_COLLECTION = "source_discovery_candidates"
DISCOVERY_JOBS_COLLECTION = "source_discovery_jobs"
DEFAULT_DISCOVERY_CIDRS = "192.168.1.0/24,10.20.10.0/24,10.20.20.0/24,10.20.30.0/24"
DEFAULT_SCAN_PORTS = (22, 80, 135, 139, 161, 389, 443, 445, 514, 1514, 3389, 5985, 5986, 8006, 8080, 8443)
CONNECTED_SOURCE_CACHE_TTL_SECONDS = 30.0
PORT_HINTS = {
    22: "ssh",
    80: "http",
    135: "rpc",
    139: "netbios",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    514: "syslog",
    1514: "syslog-tcp",
    3389: "rdp",
    5985: "winrm-http",
    5986: "winrm-https",
    8006: "proxmox",
    8080: "http-alt",
    8443: "https-alt",
}
SUPPORTED_AUTO_METHODS = {"linux_rsyslog_ssh", "windows_onboarding_package", "network_cli_ssh"}
DEFAULT_TELEMETRY_SELECTION = {
    "linux": ["syslog", "linux_auth", "auditd", "process_runtime"],
    "windows": ["windows_event", "powershell", "defender", "sysmon"],
    "network": ["network_syslog", "netflow", "config_backup"],
    "application": ["app_json", "http_access", "api_audit"],
    "unknown": ["syslog", "service_probe"],
}

_CONNECTED_SOURCE_CACHE: list[dict[str, Any]] = []
_CONNECTED_SOURCE_CACHE_TS = 0.0


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _now_iso() -> str:
    return _now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _string(value: Any) -> str:
    return str(value or "").strip()


def _normalize_token(value: Any) -> str:
    return "".join(ch.lower() for ch in str(value or "").strip() if ch.isalnum())


def _normalize_telemetry_selection(value: Any, os_family: str = "unknown") -> list[str]:
    if isinstance(value, str):
        raw_items = [item.strip() for item in value.split(",")]
    elif isinstance(value, list):
        raw_items = [str(item or "").strip() for item in value]
    else:
        raw_items = []
    normalized = [
        item.lower().replace("-", "_").replace(" ", "_")
        for item in raw_items
        if item and len(item) <= 64
    ]
    if not normalized:
        normalized = DEFAULT_TELEMETRY_SELECTION.get(str(os_family or "unknown").lower(), DEFAULT_TELEMETRY_SELECTION["unknown"])
    return list(dict.fromkeys(normalized))


def _load_rows(name: str) -> list[dict[str, Any]]:
    rows = load_control_plane_rows(name, list)
    return rows if isinstance(rows, list) else []


def _save_rows(name: str, rows: list[dict[str, Any]]) -> None:
    save_control_plane_rows(name, rows)


def _reverse_dns(ip_text: str, timeout_seconds: float = 0.35) -> str:
    result_queue: queue.Queue[str] = queue.Queue(maxsize=1)

    def lookup() -> None:
        try:
            hostname = socket.gethostbyaddr(ip_text)[0]
        except Exception:  # noqa: BLE001
            hostname = ""
        try:
            result_queue.put_nowait(str(hostname or "").strip())
        except queue.Full:
            return

    thread = threading.Thread(target=lookup, daemon=True)
    thread.start()
    thread.join(max(0.05, min(float(timeout_seconds or 0.35), 1.0)))
    if thread.is_alive():
        return ""
    try:
        return result_queue.get_nowait()
    except queue.Empty:
        return ""


def _http_probe(ip_text: str, port: int, timeout_seconds: float) -> dict[str, Any]:
    scheme = "https" if port in {443, 8443, 8006} else "http"
    context = None
    if scheme == "https":
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    request = urllib.request.Request(
        f"{scheme}://{ip_text}:{port}/",
        method="GET",
        headers={"User-Agent": "Rdegon-Discovery/1.0", "Accept": "*/*"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds, context=context) as response:
            body = response.read(256).decode("utf-8", errors="replace")
            headers = dict(response.headers.items())
    except Exception:  # noqa: BLE001
        return {}
    title = ""
    lower_body = body.lower()
    if "<title>" in lower_body and "</title>" in lower_body:
        start = lower_body.index("<title>") + len("<title>")
        end = lower_body.index("</title>", start)
        title = body[start:end].strip()
    return {
        "scheme": scheme,
        "status_code": int(getattr(response, "status", 200) or 200),
        "server": str(headers.get("Server") or headers.get("server") or "").strip(),
        "title": title,
    }


def _probe_port(ip_text: str, port: int, timeout_seconds: float) -> dict[str, Any] | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_seconds)
    try:
        result = sock.connect_ex((ip_text, int(port)))
        if result != 0:
            return None
        probe: dict[str, Any] = {"port": int(port), "service": PORT_HINTS.get(int(port), "tcp")}
        if int(port) == 22:
            try:
                banner = sock.recv(256).decode("utf-8", errors="replace").strip()
            except Exception:  # noqa: BLE001
                banner = ""
            if banner:
                probe["banner"] = banner
        elif int(port) in {80, 443, 8006, 8080, 8443} or int(port) not in {135, 139, 161, 389, 445, 514, 1514, 3389, 5985, 5986}:
            probe.update(_http_probe(ip_text, int(port), timeout_seconds))
        return probe
    finally:
        sock.close()


def _recommended_onboarding(os_family: str, probable_role: str, open_ports: list[dict[str, Any]]) -> dict[str, Any]:
    port_set = {int(item.get("port") or 0) for item in open_ports}
    if probable_role == "proxmox":
        return {
            "collector_profile": "linux-syslog-audit",
            "integration_template": "rest-pull",
            "auto_monitoring_method": "linux_rsyslog_ssh",
            "auto_monitoring_supported": True,
            "title": "Linux syslog forwarding over SSH",
        }
    if os_family == "windows":
        return {
            "collector_profile": "windows-event-http",
            "integration_template": "webhook-source",
            "auto_monitoring_method": "windows_onboarding_package",
            "auto_monitoring_supported": True,
            "title": "Windows native agent package",
        }
    if os_family == "network":
        network_ssh_ready = 22 in port_set
        return {
            "collector_profile": "network-syslog",
            "integration_template": "webhook-source",
            "auto_monitoring_method": "network_cli_ssh" if network_ssh_ready else "network_syslog_snippet",
            "auto_monitoring_supported": network_ssh_ready,
            "title": "Network syslog CLI automation" if network_ssh_ready else "Network syslog forwarding snippet",
        }
    if os_family == "linux" or 22 in port_set:
        return {
            "collector_profile": "linux-syslog-audit",
            "integration_template": "rest-pull",
            "auto_monitoring_method": "linux_rsyslog_ssh",
            "auto_monitoring_supported": True,
            "title": "Linux syslog forwarding over SSH",
        }
    return {
        "collector_profile": "app-json-syslog",
        "integration_template": "webhook-source",
        "auto_monitoring_method": "manual_investigation",
        "auto_monitoring_supported": False,
        "title": "Manual investigation and connector fit",
    }


def _classify_candidate(ip_text: str, hostname: str, open_ports: list[dict[str, Any]]) -> dict[str, Any]:
    port_set = {int(item.get("port") or 0) for item in open_ports}
    evidence = " ".join(
        [
            str(hostname or ""),
            *(str(item.get("banner") or "") for item in open_ports),
            *(str(item.get("server") or "") for item in open_ports),
            *(str(item.get("title") or "") for item in open_ports),
        ]
    ).lower()
    probable_role = "workstation"
    os_family = "unknown"
    source_family = "candidate_host"
    confidence = 0.45
    if 8006 in port_set or "pveproxy" in evidence or "proxmox" in evidence:
        os_family = "linux"
        probable_role = "proxmox"
        source_family = "proxmox_host"
        confidence = 0.98
    elif 445 in port_set or 3389 in port_set or 5985 in port_set or 5986 in port_set or "microsoft" in evidence:
        os_family = "windows"
        probable_role = "windows-endpoint"
        source_family = "windows_endpoint"
        confidence = 0.93
    elif 161 in port_set or (514 in port_set and 22 not in port_set and 445 not in port_set):
        os_family = "network"
        probable_role = "network-device"
        source_family = "network_device"
        confidence = 0.81
    elif 22 in port_set:
        os_family = "linux"
        probable_role = "linux-host"
        source_family = "linux_host"
        confidence = 0.88
    elif 80 in port_set or 443 in port_set or 8080 in port_set or 8443 in port_set:
        os_family = "application"
        probable_role = "web-application"
        source_family = "application_service"
        confidence = 0.67
    recommendation = _recommended_onboarding(os_family, probable_role, open_ports)
    return {
        "os_family": os_family,
        "probable_role": probable_role,
        "source_family": source_family,
        "confidence": confidence,
        "recommendation": recommendation,
    }


def _connected_markers(connected_sources: list[dict[str, Any]] | None) -> set[str]:
    markers: set[str] = set()
    for item in connected_sources or []:
        source_values: list[Any] = [
            item.get("source_name"),
            item.get("source"),
            item.get("log_source"),
            item.get("ip"),
            item.get("source_ip"),
            item.get("hostname"),
            item.get("host_name"),
            item.get("asset"),
            item.get("asset_id"),
            item.get("display_label"),
            item.get("label"),
            item.get("connected_source"),
            item.get("public_ip"),
            *(item.get("aliases") or []),
        ]
        for value in source_values:
            text = str(value or "").strip()
            if not text:
                continue
            markers.add(text.lower())
            markers.add(_normalize_token(text))
            alias = str(SOURCE_ALIAS_OVERRIDES.get(text) or "").strip()
            if alias:
                markers.add(alias.lower())
                markers.add(_normalize_token(alias))
            try:
                ip_obj = ipaddress.ip_address(text)
            except ValueError:
                continue
            markers.add(_normalize_token(str(ip_obj)))
    return markers


def _load_connected_source_inventory(timeout_seconds: float | None = None) -> list[dict[str, Any]]:
    global _CONNECTED_SOURCE_CACHE, _CONNECTED_SOURCE_CACHE_TS
    now = time.monotonic()
    if _CONNECTED_SOURCE_CACHE and now - _CONNECTED_SOURCE_CACHE_TS <= CONNECTED_SOURCE_CACHE_TTL_SECONDS:
        return [dict(item) for item in _CONNECTED_SOURCE_CACHE]
    if fetch_source_inventory is None:
        return []
    timeout_budget = 0.0 if timeout_seconds is None else max(0.05, float(timeout_seconds or 0.0))

    def load() -> list[dict[str, Any]]:
        rows = fetch_source_inventory(limit=500, hours=168)  # type: ignore[misc]
        if not isinstance(rows, list):
            return []
        return [dict(item) for item in rows if isinstance(item, dict)]

    if timeout_budget <= 0:
        try:
            rows = load()
        except Exception:  # noqa: BLE001
            return [dict(item) for item in _CONNECTED_SOURCE_CACHE]
        _CONNECTED_SOURCE_CACHE = [dict(item) for item in rows]
        _CONNECTED_SOURCE_CACHE_TS = time.monotonic()
        return rows

    result_queue: queue.Queue[list[dict[str, Any]]] = queue.Queue(maxsize=1)

    def loader() -> None:
        try:
            rows = load()
        except Exception:  # noqa: BLE001
            rows = []
        try:
            result_queue.put_nowait(rows)
        except queue.Full:
            return

    thread = threading.Thread(target=loader, daemon=True)
    thread.start()
    thread.join(timeout_budget)
    if thread.is_alive():
        return [dict(item) for item in _CONNECTED_SOURCE_CACHE]
    try:
        rows = result_queue.get_nowait()
    except queue.Empty:
        return [dict(item) for item in _CONNECTED_SOURCE_CACHE]
    _CONNECTED_SOURCE_CACHE = [dict(item) for item in rows]
    _CONNECTED_SOURCE_CACHE_TS = time.monotonic()
    return rows


def _candidate_override_match(candidate: dict[str, Any], overrides: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not overrides:
        return None
    candidate_tokens = {
        _string(candidate.get("id")).lower(),
        _string(candidate.get("ip")).lower(),
        _string(candidate.get("hostname")).lower(),
    }
    candidate_tokens.update({_normalize_token(item) for item in list(candidate_tokens) if item})
    for service in candidate.get("open_ports") or []:
        candidate_tokens.add(_string(service.get("service")).lower())
    candidate_tokens = {item for item in candidate_tokens if item}
    for override in overrides:
        if not bool(override.get("enabled", True)):
            continue
        scope = _string(override.get("scope") or "all").lower() or "all"
        if scope not in {"all", "source_discovery", "sources"}:
            continue
        override_tokens = {
            _string(override.get("id")).lower(),
            _string(override.get("target")).lower(),
            _string(override.get("asset_id")).lower(),
            _string(override.get("hostname")).lower(),
            _string(override.get("ip")).lower(),
        }
        override_tokens.update(_string(item).lower() for item in (override.get("aliases") or []) if _string(item))
        override_tokens = {item for item in override_tokens if item}
        override_tokens.update({_normalize_token(item) for item in list(override_tokens) if item})
        if candidate_tokens & override_tokens:
            return {
                "id": _string(override.get("id")),
                "target": _string(override.get("target")),
                "asset_id": _string(override.get("asset_id")),
                "scope": scope,
                "hostname": _string(override.get("hostname")),
                "ip": _string(override.get("ip")),
                "note": _string(override.get("note")),
                "enabled": bool(override.get("enabled", True)),
            }
    return None


def _candidate_alias(ip_text: str, hostname: str) -> str:
    alias = str(SOURCE_ALIAS_OVERRIDES.get(str(ip_text or "").strip()) or "").strip()
    if alias:
        return alias
    return str(hostname or "").strip()


def _candidate_connected(ip_text: str, hostname: str, connected_tokens: set[str]) -> tuple[bool, str]:
    alias = _candidate_alias(ip_text, hostname)
    connected = any(
        token and token in connected_tokens
        for token in (
            str(ip_text or "").strip().lower(),
            str(hostname or "").strip().lower(),
            str(alias or "").strip().lower(),
            _normalize_token(ip_text),
            _normalize_token(hostname),
            _normalize_token(alias),
        )
    )
    return connected, alias


def _reconcile_candidate_connection(candidate: dict[str, Any], connected_tokens: set[str]) -> tuple[dict[str, Any], bool]:
    row = dict(candidate)
    connected, alias = _candidate_connected(str(row.get("ip") or ""), str(row.get("hostname") or ""), connected_tokens)
    if not connected:
        return row, False
    changed = not bool(row.get("connected")) or str(row.get("monitoring_status") or "") != "connected"
    row["connected"] = True
    row["status"] = "connected"
    row["monitoring_status"] = "connected"
    row["connected_source"] = alias or str(row.get("connected_source") or "")
    row["updated_ts"] = row.get("updated_ts") or _now_iso()
    return row, changed


def _parse_discovery_networks(cidr_text: str) -> list[ipaddress._BaseNetwork]:
    raw = str(cidr_text or DEFAULT_DISCOVERY_CIDRS).strip() or DEFAULT_DISCOVERY_CIDRS
    networks: list[ipaddress._BaseNetwork] = []
    for token in raw.split(","):
        candidate = str(token or "").strip()
        if not candidate:
            continue
        networks.append(ipaddress.ip_network(candidate, strict=False))
    return networks or [ipaddress.ip_network(DEFAULT_DISCOVERY_CIDRS.split(",", 1)[0], strict=False)]


def _scan_host(ip_text: str, ports: tuple[int, ...], timeout_seconds: float, connected_tokens: set[str]) -> dict[str, Any] | None:
    open_ports: list[dict[str, Any]] = []
    for port in ports:
        probe = _probe_port(ip_text, int(port), timeout_seconds)
        if probe:
            open_ports.append(probe)
    if not open_ports:
        return None
    hostname = _reverse_dns(ip_text, timeout_seconds=timeout_seconds)
    classification = _classify_candidate(ip_text, hostname, open_ports)
    connected, alias = _candidate_connected(ip_text, hostname, connected_tokens)
    last_seen = _now_iso()
    status = "connected" if connected else "candidate"
    monitoring_status = "connected" if connected else "candidate"
    return {
        "id": f"candidate-{ip_text.replace('.', '-')}",
        "ip": ip_text,
        "hostname": hostname,
        "status": status,
        "monitoring_status": monitoring_status,
        "connected": connected,
        "connected_source": alias if connected else "",
        "last_seen_ts": last_seen,
        "discovered_ts": last_seen,
        "open_ports": open_ports,
        "port_summary": ", ".join(f"{item['port']}/{item.get('service', 'tcp')}" for item in open_ports),
        **classification,
    }


def _merge_candidate(existing: dict[str, Any] | None, fresh: dict[str, Any]) -> dict[str, Any]:
    row = dict(existing or {})
    row.update(fresh)
    row["first_seen_ts"] = str(existing.get("first_seen_ts") if existing else fresh.get("discovered_ts") or _now_iso())
    row["last_job_id"] = str(row.get("last_job_id") or (existing or {}).get("last_job_id") or "")
    if fresh.get("connected"):
        row["connected_source"] = str(fresh.get("connected_source") or row.get("connected_source") or "")
        row["monitoring_status"] = "connected"
    else:
        row["connected_source"] = str((existing or {}).get("connected_source") or "")
        if str(row.get("last_job_id") or "").strip():
            row["monitoring_status"] = str((existing or {}).get("monitoring_status") or row.get("monitoring_status") or "prepared")
    row["auto_monitoring_ready"] = bool(row.get("recommendation", {}).get("auto_monitoring_supported"))
    return row


def _supersede_jobs_for_connected_candidate(candidate: dict[str, Any], jobs: list[dict[str, Any]], *, actor: str) -> bool:
    if not bool(candidate.get("connected")):
        return False
    candidate_id = str(candidate.get("id") or "").strip()
    if not candidate_id:
        return False
    touched = False
    for job in jobs:
        if str(job.get("candidate_id") or "").strip() != candidate_id:
            continue
        if str(job.get("status") or "").strip() not in {"prepared", "dry_run", "pending", "manual_required"}:
            continue
        job["status"] = "superseded"
        job["updated_ts"] = _now_iso()
        job["superseded_reason"] = "candidate_connected"
        job["superseded_by"] = str(actor or "system")
        touched = True
    return touched


def list_source_discovery_candidates(
    limit: int = 200,
    *,
    connected_sources: list[dict[str, Any]] | None = None,
    inventory_timeout_seconds: float | None = 2.0,
) -> dict[str, Any]:
    raw_rows = _load_rows(DISCOVERY_CANDIDATES_COLLECTION)
    if connected_sources is None:
        connected_sources = _load_connected_source_inventory(timeout_seconds=inventory_timeout_seconds)
    connected_tokens = _connected_markers(connected_sources)
    jobs = sorted(_load_rows(DISCOVERY_JOBS_COLLECTION), key=lambda item: str(item.get("updated_ts") or ""), reverse=True)
    rows: list[dict[str, Any]] = []
    rows_changed = False
    jobs_changed = False
    for item in raw_rows:
        reconciled, changed = _reconcile_candidate_connection(item, connected_tokens)
        rows.append(reconciled)
        rows_changed = rows_changed or changed
        if changed:
            jobs_changed = _supersede_jobs_for_connected_candidate(reconciled, jobs, actor="inventory-reconcile") or jobs_changed
    if rows_changed:
        _save_rows(DISCOVERY_CANDIDATES_COLLECTION, rows)
    if jobs_changed:
        _save_rows(DISCOVERY_JOBS_COLLECTION, jobs)
    rows = sorted(
        rows,
        key=lambda item: (
            1 if bool(item.get("connected")) else 0,
            str(item.get("last_seen_ts") or ""),
            str(item.get("ip") or ""),
        ),
        reverse=True,
    )
    overrides = list_binding_overrides(scope="source_discovery", include_disabled=False, limit=500)
    enriched_rows: list[dict[str, Any]] = []
    overridden_total = 0
    for item in rows:
        enriched = dict(item)
        match = _candidate_override_match(enriched, overrides)
        if match is not None:
            enriched["binding_override"] = match
            enriched["binding_override_id"] = _string(match.get("id"))
            enriched["binding_target"] = _string(match.get("target")) or _string(match.get("asset_id"))
            overridden_total += 1
        else:
            enriched["binding_override"] = None
            enriched["binding_override_id"] = ""
            enriched["binding_target"] = _string(enriched.get("hostname")) or _string(enriched.get("ip"))
        enriched_rows.append(enriched)
    items = enriched_rows[: max(1, min(int(limit), 500))]
    connected_total = sum(1 for item in rows if bool(item.get("connected")))
    auto_ready = sum(1 for item in rows if bool(item.get("auto_monitoring_ready")) and not bool(item.get("connected")))
    last_scan_ts = max((str(item.get("last_seen_ts") or "") for item in rows), default="")
    return {
        "items": items,
        "jobs": jobs[:50],
        "metrics": {
            "total": len(rows),
            "connected": connected_total,
            "unmanaged": max(0, len(rows) - connected_total),
            "auto_ready": auto_ready,
            "binding_overrides_total": len(overrides),
            "binding_overrides_applied": overridden_total,
            "unmanaged_without_override": sum(
                1 for item in enriched_rows if not bool(item.get("connected")) and not bool(item.get("binding_override_id"))
            ),
            "prepared": sum(1 for item in rows if str(item.get("monitoring_status") or "") == "prepared"),
            "applied": sum(1 for item in rows if str(item.get("monitoring_status") or "") == "applied"),
            "last_scan_ts": last_scan_ts,
        },
    }


def scan_source_candidates(
    cidr: str = DEFAULT_DISCOVERY_CIDRS,
    *,
    connected_sources: list[dict[str, Any]] | None = None,
    ports: list[int] | tuple[int, ...] | None = None,
    timeout_seconds: float = 0.35,
    max_hosts: int = 256,
    actor: str = "system",
) -> dict[str, Any]:
    networks = _parse_discovery_networks(cidr)
    hosts: list[str] = []
    for network in networks:
        for host in network.hosts():
            hosts.append(str(host))
    hosts = list(dict.fromkeys(hosts))
    if len(hosts) > max_hosts:
        hosts = hosts[:max_hosts]
    scan_ports = tuple(sorted({int(port) for port in (ports or DEFAULT_SCAN_PORTS) if int(port) > 0})) or DEFAULT_SCAN_PORTS
    if connected_sources is None:
        connected_sources = _load_connected_source_inventory(
            timeout_seconds=max(0.2, min(float(timeout_seconds or 0.35) * 2.0, 2.0))
        )
    connected_tokens = _connected_markers(connected_sources)
    existing_rows = {str(item.get("ip") or ""): item for item in _load_rows(DISCOVERY_CANDIDATES_COLLECTION)}
    jobs = _load_rows(DISCOVERY_JOBS_COLLECTION)
    merged_rows = dict(existing_rows)
    discovered: list[dict[str, Any]] = []
    jobs_changed = False
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=min(48, max(4, len(hosts)))) as executor:
        futures = {
            executor.submit(_scan_host, host, scan_ports, max(0.1, min(float(timeout_seconds), 2.0)), connected_tokens): host
            for host in hosts
        }
        for future in as_completed(futures):
            row = future.result()
            if not row:
                continue
            merged = _merge_candidate(existing_rows.get(str(row.get("ip") or "")), row)
            merged_rows[str(merged.get("ip") or "")] = merged
            discovered.append(merged)
            jobs_changed = _supersede_jobs_for_connected_candidate(merged, jobs, actor=str(actor or "system")) or jobs_changed
    _save_rows(DISCOVERY_CANDIDATES_COLLECTION, list(merged_rows.values()))
    if jobs_changed:
        _save_rows(DISCOVERY_JOBS_COLLECTION, jobs)
    duration_seconds = round(time.perf_counter() - start, 2)
    payload = list_source_discovery_candidates(connected_sources=connected_sources)
    payload["scan"] = {
        "cidr": ",".join(str(network) for network in networks),
        "hosts_scanned": len(hosts),
        "ports": list(scan_ports),
        "duration_seconds": duration_seconds,
        "actor": str(actor or "system"),
        "discovered": len(discovered),
        "discovered_unmanaged": sum(1 for item in discovered if not bool(item.get("connected"))),
    }
    return payload


def _linux_rsyslog_config() -> str:
    ingest_host = str(os.getenv("SIEM_INGEST_FORWARD_HOST", "192.168.1.35") or "192.168.1.35").strip()
    ingest_port = max(1, min(65535, _safe_int(os.getenv("SIEM_INGEST_FORWARD_PORT", "1514"), 1514)))
    return (
        "*.* action(type=\"omfwd\" "
        f"target=\"{ingest_host}\" port=\"{ingest_port}\" protocol=\"tcp\" "
        "template=\"RSYSLOG_SyslogProtocol23Format\" action.resumeRetryCount=\"-1\" "
        "queue.type=\"linkedList\" queue.filename=\"rdegon-fwd\")"
    )


def _control_plane_dir() -> Path:
    return control_plane_collection_path(DISCOVERY_CANDIDATES_COLLECTION).parent


def _repo_root() -> Path:
    current = Path(__file__).resolve().parent
    for candidate in (current, *current.parents):
        if (candidate / "deploy" / "windows-agent").exists() and (candidate / "ops").exists():
            return candidate
    return current


def _windows_package_root() -> Path:
    root = _control_plane_dir() / "generated" / "windows-onboarding"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _public_ingest_base_url() -> str:
    return str(os.getenv("SIEM_INGEST_BASE_URL", "https://192.168.1.35") or "https://192.168.1.35").rstrip("/")


def _shared_secret_required() -> bool:
    return bool(
        str(os.getenv("SIEM_INGEST_API_SHARED_SECRET", "").strip() or os.getenv("SIEM_WEBHOOK_SHARED_SECRET", "").strip())
    )


def _windows_package_spec(candidate: dict[str, Any] | None = None, job: dict[str, Any] | None = None) -> dict[str, Any]:
    return build_windows_native_package_spec(
        dict(candidate or {}),
        dict(job or {}),
        base_url=_public_ingest_base_url(),
        shared_secret_required=_shared_secret_required(),
    )


def _windows_package_dir(job_id: str) -> Path:
    return _windows_package_root() / str(job_id or "windows-package").strip()


def _windows_package_zip_path(job_id: str) -> Path:
    package_dir = _windows_package_dir(job_id)
    return package_dir.parent / f"{package_dir.name}.zip"


def _windows_install_cmd(spec: dict[str, Any]) -> str:
    shared_secret_required = bool(spec.get("shared_secret_required"))
    secret_hint = (
        "if \"%SHAREDSECRET%\"==\"\" (\n"
        "    echo Shared secret is required. Pass it as the first argument.\n"
        "    exit /b 2\n"
        ")\n"
        if shared_secret_required
        else ""
    )
    return (
        "@echo off\n"
        "setlocal\n\n"
        "set \"ROOT=%~dp0\"\n"
        "set \"INSTALL=%ROOT%install-windows-event-agent.ps1\"\n"
        "set \"SHAREDSECRET=%~1\"\n"
        f"set \"BASEURL={str(spec.get('base_url') or _public_ingest_base_url()).strip()}\"\n\n"
        "if not exist \"%INSTALL%\" (\n"
        "    echo Native install script not found: %INSTALL%\n"
        "    exit /b 1\n"
        ")\n\n"
        f"{secret_hint}"
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"%INSTALL%\" -BaseUrl \"%BASEURL%\" -SharedSecret \"%SHAREDSECRET%\" -StartAfterInstall\n"
        "endlocal\n"
    )


def _windows_package_readme(candidate: dict[str, Any], job: dict[str, Any], spec: dict[str, Any]) -> str:
    hostname = str(candidate.get("hostname") or candidate.get("ip") or "windows-endpoint").strip()
    return (
        f"# Windows Native Agent Package for {hostname}\n\n"
        "This package was generated by the discovery plane to stage a managed Windows service rollout.\n\n"
        "## Recommended path\n\n"
        "Use the native Windows Event Agent as the primary rollout path. The legacy PowerShell collector remains a fallback only.\n\n"
        "## What the package does\n\n"
        "- prepares a host-specific Windows agent profile\n"
        "- stages native install, package, and status scripts from the repo\n"
        "- aligns the endpoint with the current HTTPS ingest routing\n"
        "- keeps VPN route alignment scripts next to the installer assets\n\n"
        "## Install\n\n"
        "1. Copy the package directory to the target Windows machine.\n"
        "2. Build or provide the release bundle using `package-windows-event-agent.ps1`.\n"
        "3. Run `install-native-agent.cmd <shared-secret>` from an elevated shell.\n"
        "4. Confirm the service is healthy with `get-windows-event-agent-status.ps1 -Detailed`.\n\n"
        "## Notes\n\n"
        f"- Base URL: `{spec.get('base_url')}`\n"
        f"- Delivery mode: `{spec.get('delivery_mode')}`\n"
        f"- Shared secret required: `{'yes' if bool(spec.get('shared_secret_required')) else 'no'}`\n"
        f"- Discovery job: `{job.get('id')}`\n"
        "- Sysmon remains optional and should follow the endpoint profile.\n"
        "- If the endpoint cannot reach the base URL directly, deploy one of the packaged VPN route profiles first.\n\n"
        "## Included files\n\n"
        "- `windows-agent-profile.local.json`\n"
        "- `install-native-agent.cmd`\n"
        "- `install-windows-event-agent.ps1`\n"
        "- `package-windows-event-agent.ps1`\n"
        "- `get-windows-event-agent-status.ps1`\n"
        "- `build-openvpn-route-profile.ps1`\n"
        "- `package-manifest.json`\n"
    )


def _windows_package_options_doc() -> str:
    return (
        "# Windows Collector Options\n\n"
        "## Recommended now\n\n"
        "- Native Windows Event Agent: primary enterprise rollout path.\n"
        "- Legacy PowerShell collector: fallback for emergency or non-admin onboarding.\n\n"
        "## Optional later\n\n"
        "- Fluent Bit once a long-term schema adapter is introduced.\n"
        "- Windows Event Forwarding for domain-centric fan-in.\n"
    )


def _generate_windows_onboarding_package(job: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    return build_windows_native_package(
        candidate,
        job,
        repo_root=_repo_root(),
        output_root=_windows_package_root(),
        base_url=_public_ingest_base_url(),
        shared_secret_required=_shared_secret_required(),
    )


def _prepare_job_payload(candidate: dict[str, Any], actor: str, requested_telemetry: list[str] | None = None) -> dict[str, Any]:
    recommendation = dict(candidate.get("recommendation") or {})
    method = str(recommendation.get("auto_monitoring_method") or "manual_investigation")
    telemetry_selection = _normalize_telemetry_selection(requested_telemetry, str(candidate.get("os_family") or "unknown"))
    base = {
        "id": _new_id("onboard"),
        "candidate_id": str(candidate.get("id") or ""),
        "ip": str(candidate.get("ip") or ""),
        "hostname": str(candidate.get("hostname") or ""),
        "created_ts": _now_iso(),
        "updated_ts": _now_iso(),
        "created_by": str(actor or "system"),
        "method": method,
        "collector_profile": str(recommendation.get("collector_profile") or ""),
        "integration_template": str(recommendation.get("integration_template") or ""),
        "status": "prepared",
        "dry_run_supported": True,
        "execution_supported": method in SUPPORTED_AUTO_METHODS,
        "credential_requirements": [],
        "config_preview": "",
        "command_preview": [],
        "summary": "",
        "requested_telemetry": telemetry_selection,
        "telemetry_selection": telemetry_selection,
    }
    if method == "linux_rsyslog_ssh":
        base["credential_requirements"] = [
            {"id": "username", "label": "SSH username", "required": True},
            {"id": "password", "label": "SSH password", "required": True},
            {"id": "sudo_password", "label": "sudo password", "required": False},
            {"id": "port", "label": "SSH port", "required": False},
        ]
        base["config_preview"] = _linux_rsyslog_config()
        base["command_preview"] = [
            "upload /etc/rsyslog.d/90-rdegon-siem.conf",
            "restart rsyslog",
            "verify TCP forwarding to 192.168.1.35:1514",
        ]
        base["command_preview"].append(f"enable telemetry profiles: {', '.join(telemetry_selection)}")
        base["summary"] = "Prepare Linux syslog forwarding over SSH"
        return base
    if method == "windows_onboarding_package":
        package_spec = _windows_package_spec(candidate, base)
        base["credential_requirements"] = []
        base["config_preview"] = json.dumps(package_spec, ensure_ascii=False, indent=2)
        base["command_preview"] = [
            "generate native Windows agent staging package",
            "copy package to the Windows host",
            "build or provide the native release bundle",
            "run install-native-agent.cmd on the endpoint",
        ]
        base["command_preview"].append(f"enable telemetry profiles: {', '.join(telemetry_selection)}")
        base["summary"] = "Generate Windows native-agent onboarding package"
        base["package_spec"] = package_spec
        return base
    if method == "network_cli_ssh":
        plan = build_network_onboarding_plan(candidate, ingest_host="192.168.1.35", ingest_port=1514)
        base["credential_requirements"] = list(plan.get("credential_requirements") or [])
        base["config_preview"] = str(plan.get("config_preview") or "")
        base["command_preview"] = list(plan.get("command_preview") or [])
        base["command_preview"].append(f"enable telemetry profiles: {', '.join(telemetry_selection)}")
        base["summary"] = f"Push {plan.get('vendor')} syslog configuration over SSH"
        base["network_vendor"] = str(plan.get("vendor") or "")
        base["network_commands"] = list(plan.get("commands") or [])
        return base
    if method == "network_syslog_snippet":
        plan = build_network_onboarding_plan(candidate, ingest_host="192.168.1.35", ingest_port=1514)
        base["config_preview"] = str(plan.get("config_preview") or "logging host 192.168.1.35 transport tcp port 1514")
        base["command_preview"] = [
            "apply the generated CLI snippet manually",
            "point device syslog to 192.168.1.35:1514/tcp",
        ]
        base["command_preview"].append(f"enable telemetry profiles: {', '.join(telemetry_selection)}")
        base["summary"] = "Prepare manual network syslog forwarding snippet"
        return base
    base["command_preview"] = ["investigate host role", "choose connector template", "prepare manual onboarding", f"enable telemetry profiles: {', '.join(telemetry_selection)}"]
    base["summary"] = "Manual investigation required"
    return base


def prepare_source_onboarding(candidate_id: str, *, actor: str = "system", requested_telemetry: Any = None) -> dict[str, Any]:
    candidates = _load_rows(DISCOVERY_CANDIDATES_COLLECTION)
    candidate = next((item for item in candidates if str(item.get("id") or "") == str(candidate_id or "").strip()), None)
    if not candidate:
        raise ValueError(f"Candidate not found: {candidate_id}")
    if bool(candidate.get("connected")):
        raise ValueError(f"Candidate is already connected: {candidate_id}")
    jobs = _load_rows(DISCOVERY_JOBS_COLLECTION)
    job = _prepare_job_payload(candidate, actor, _normalize_telemetry_selection(requested_telemetry, str(candidate.get("os_family") or "unknown")))
    jobs.insert(0, job)
    _save_rows(DISCOVERY_JOBS_COLLECTION, jobs)
    for item in candidates:
        if str(item.get("id") or "") == str(candidate_id or "").strip():
            item["last_job_id"] = job["id"]
            item["monitoring_status"] = "prepared"
            item["updated_ts"] = _now_iso()
            break
    _save_rows(DISCOVERY_CANDIDATES_COLLECTION, candidates)
    return {"candidate": candidate, "job": job, "jobs_total": len(jobs)}


def _execute_linux_job(ip_text: str, credentials: dict[str, Any]) -> dict[str, Any]:
    try:
        import paramiko  # type: ignore[import-not-found]
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("paramiko_not_available") from exc
    username = str(credentials.get("username") or "").strip()
    password = str(credentials.get("password") or "")
    sudo_password = str(credentials.get("sudo_password") or password)
    port = max(1, min(65535, _safe_int(credentials.get("port"), 22)))
    if not username or not password:
        raise RuntimeError("linux_ssh_credentials_required")
    config_payload = _linux_rsyslog_config()
    quoted_sudo_password = shlex.quote(sudo_password)
    remote_script = f"""
set -e
TMP_FILE="$(mktemp)"
cat >"$TMP_FILE" <<'EOF'
{config_payload}
EOF
if command -v sudo >/dev/null 2>&1; then
  printf '%s\\n' {quoted_sudo_password} | sudo -S install -m 0644 "$TMP_FILE" /etc/rsyslog.d/90-rdegon-siem.conf
  printf '%s\\n' {quoted_sudo_password} | sudo -S systemctl restart rsyslog || printf '%s\\n' {quoted_sudo_password} | sudo -S service rsyslog restart
else
  install -m 0644 "$TMP_FILE" /etc/rsyslog.d/90-rdegon-siem.conf
  systemctl restart rsyslog || service rsyslog restart
fi
rm -f "$TMP_FILE"
"""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        ip_text,
        port=port,
        username=username,
        password=password,
        timeout=20,
        auth_timeout=20,
        banner_timeout=20,
        look_for_keys=False,
        allow_agent=False,
    )
    try:
        _, stdout, stderr = client.exec_command(remote_script)
        output = stdout.read().decode("utf-8", errors="replace")
        error = stderr.read().decode("utf-8", errors="replace")
        code = stdout.channel.recv_exit_status()
    finally:
        client.close()
    if code != 0:
        raise RuntimeError(f"linux_onboarding_failed: {error or output or code}")
    return {"status": "executed", "stdout": output, "stderr": error}


def _execute_network_job(job: dict[str, Any], credentials: dict[str, Any]) -> dict[str, Any]:
    vendor = str(job.get("network_vendor") or "cisco_ios").strip() or "cisco_ios"
    commands = [str(item) for item in (job.get("network_commands") or []) if str(item).strip()]
    if not commands:
        plan = build_network_onboarding_plan(
            {"hostname": job.get("hostname"), "open_ports": [{"port": int(credentials.get("port") or 22)}]},
            ingest_host="192.168.1.35",
            ingest_port=1514,
        )
        commands = [str(item) for item in (plan.get("commands") or []) if str(item).strip()]
        vendor = str(plan.get("vendor") or vendor)
    result = execute_network_cli_push(str(job.get("ip") or ""), vendor=vendor, commands=commands, credentials=credentials)
    result["commands"] = commands
    return result


def execute_source_onboarding(
    job_id: str,
    *,
    actor: str = "system",
    credentials: dict[str, Any] | None = None,
    dry_run: bool = True,
) -> dict[str, Any]:
    jobs = _load_rows(DISCOVERY_JOBS_COLLECTION)
    job = next((item for item in jobs if str(item.get("id") or "") == str(job_id or "").strip()), None)
    if not job:
        raise ValueError(f"Onboarding job not found: {job_id}")
    candidates = _load_rows(DISCOVERY_CANDIDATES_COLLECTION)
    candidate = next((item for item in candidates if str(item.get("id") or "") == str(job.get("candidate_id") or "")), None)
    telemetry_selection = _normalize_telemetry_selection(
        (credentials or {}).get("telemetry_selection") or (credentials or {}).get("requested_telemetry") or job.get("requested_telemetry"),
        str((candidate or {}).get("os_family") or "unknown"),
    )
    execution = {
        "job_id": str(job.get("id") or ""),
        "candidate_id": str(job.get("candidate_id") or ""),
        "actor": str(actor or "system"),
        "dry_run": bool(dry_run),
        "ts": _now_iso(),
        "status": "dry_run" if dry_run else "pending",
        "requested_telemetry": telemetry_selection,
        "telemetry_selection": telemetry_selection,
    }
    method = str(job.get("method") or "")
    if dry_run:
        execution["summary"] = str(job.get("summary") or "Preview only")
        if method == "windows_onboarding_package":
            execution["package_spec"] = dict(job.get("package_spec") or {})
        elif method == "network_cli_ssh":
            execution["network_vendor"] = str(job.get("network_vendor") or "")
            execution["commands"] = list(job.get("network_commands") or [])
    elif method == "linux_rsyslog_ssh":
        execution.update(_execute_linux_job(str(job.get("ip") or ""), credentials or {}))
        execution["status"] = "executed"
    elif method == "windows_onboarding_package":
        if not candidate:
            raise ValueError(f"Candidate not found for onboarding job: {job_id}")
        execution["artifacts"] = _generate_windows_onboarding_package(job, candidate)
        execution["status"] = "package_generated"
        execution["summary"] = "Windows native-agent package generated"
    elif method == "network_cli_ssh":
        execution.update(_execute_network_job(job, credentials or {}))
        execution["status"] = "executed"
        execution["summary"] = f"Network syslog automation applied via {execution.get('network_vendor') or job.get('network_vendor') or 'ssh'}"
    else:
        execution["status"] = "manual_required"
        execution["summary"] = "This onboarding path currently requires operator confirmation and credentials outside the UI."
    job["updated_ts"] = _now_iso()
    job["status"] = str(execution.get("status") or job.get("status") or "prepared")
    job["last_execution"] = execution
    _save_rows(DISCOVERY_JOBS_COLLECTION, jobs)

    for item in candidates:
        if str(item.get("id") or "") == str(job.get("candidate_id") or ""):
            item["last_job_id"] = str(job.get("id") or "")
            item["updated_ts"] = _now_iso()
            if job["status"] == "executed":
                item["monitoring_status"] = "applied"
            elif job["status"] == "package_generated":
                item["monitoring_status"] = "package_ready"
            elif job["status"] == "dry_run":
                item["monitoring_status"] = "prepared"
            break
    _save_rows(DISCOVERY_CANDIDATES_COLLECTION, candidates)
    return {"job": job, "execution": execution}
