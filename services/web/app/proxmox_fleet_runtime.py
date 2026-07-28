from __future__ import annotations

import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

try:
    from .enterprise_control_plane import load_control_plane_rows, save_control_plane_rows
except ImportError:  # pragma: no cover - local test fallback
    from enterprise_control_plane import load_control_plane_rows, save_control_plane_rows  # type: ignore[no-redef]

try:
    from .inventory_catalog import SOURCE_ALIAS_OVERRIDES
except ImportError:  # pragma: no cover - local test fallback
    from inventory_catalog import SOURCE_ALIAS_OVERRIDES  # type: ignore[no-redef]


PROXMOX_FLEET_COLLECTION = "proxmox_fleet_inventory"
PROXMOX_FLEET_SYNC_COLLECTION = "proxmox_fleet_sync_state"
_RUNNING_STATES = {"running"}
_DEFAULT_PROXMOX_PORT = 8006
_DEFAULT_FLEET_CACHE_TTL_SECONDS = 300
_IGNORED_VMIDS = {"109"}

_GUEST_HINTS: dict[str, dict[str, Any]] = {
    "100": {
        "name": "minecraft-01",
        "ip": "10.20.20.100",
        "guest_type": "lxc",
        "os_family": "linux",
        "role": "minecraft",
        "business_service": "Minecraft game server",
        "criticality": "medium",
        "tags": ["proxmox-fleet", "game", "minecraft"],
        "source_name": "minecraft-01",
        "monitoring_enabled": True,
    },
    "101": {
        "name": "win-test",
        "ip": "",
        "guest_type": "qemu",
        "os_family": "windows",
        "role": "disposable-windows",
        "business_service": "Reserved disposable Windows guest",
        "criticality": "low",
        "tags": ["proxmox-fleet", "windows", "disposable", "planned-offline"],
        "monitoring_enabled": False,
    },
    "102": {
        "name": "lab-edge-01",
        "ip": "192.168.3.102",
        "guest_type": "qemu",
        "os_family": "linux",
        "role": "edge-router",
        "business_service": "Linux edge router, firewall and DNS",
        "criticality": "medium",
        "tags": ["proxmox-fleet", "edge-appliance", "router", "dns", "ngfw"],
        "source_name": "lab-edge-01",
        "monitoring_enabled": True,
    },
    "103": {
        "name": "opnsense-edge-01",
        "ip": "192.168.3.103",
        "guest_type": "qemu",
        "os_family": "bsd",
        "role": "ngfw",
        "business_service": "OPNsense routing, NGFW, DNS and inline IPS",
        "criticality": "critical",
        "tags": ["proxmox-fleet", "network", "opnsense", "ngfw", "ids", "ips"],
        "source_name": "10.20.10.254",
        "monitoring_enabled": False,
    },
    "104": {
        "name": "siem-ingest",
        "ip": "10.20.10.104",
        "guest_type": "qemu",
        "os_family": "linux",
        "role": "ingest",
        "business_service": "SIEM ingest edge",
        "criticality": "high",
        "tags": ["proxmox-fleet", "siem-core", "ingest"],
        "source_name": "siem-ingest",
        "monitoring_enabled": True,
    },
    "105": {
        "name": "siem-processing",
        "ip": "10.20.10.105",
        "guest_type": "qemu",
        "os_family": "linux",
        "role": "processing",
        "business_service": "SIEM processing plane",
        "criticality": "high",
        "tags": ["proxmox-fleet", "siem-core", "processing"],
        "source_name": "siem-processing",
        "monitoring_enabled": True,
    },
    "106": {
        "name": "siem-storage",
        "ip": "10.20.10.106",
        "guest_type": "qemu",
        "os_family": "linux",
        "role": "storage",
        "business_service": "SIEM storage and correlation",
        "criticality": "high",
        "tags": ["proxmox-fleet", "siem-core", "storage"],
        "source_name": "siem-storage",
        "monitoring_enabled": True,
    },
    "107": {
        "name": "siem-web",
        "ip": "10.20.10.107",
        "guest_type": "qemu",
        "os_family": "linux",
        "role": "control-plane",
        "business_service": "SIEM control plane",
        "criticality": "high",
        "tags": ["proxmox-fleet", "siem-core", "control-plane"],
        "source_name": "siem-web",
        "monitoring_enabled": True,
    },
    "108": {
        "name": "siem-transport",
        "ip": "10.20.10.108",
        "guest_type": "qemu",
        "os_family": "linux",
        "role": "transport",
        "business_service": "SIEM transport plane",
        "criticality": "high",
        "tags": ["proxmox-fleet", "siem-core", "transport"],
        "source_name": "siem-transport",
        "monitoring_enabled": True,
    },
    "111": {
        "name": "WIN-RTX-test",
        "ip": "192.168.3.81",
        "guest_type": "qemu",
        "os_family": "windows",
        "role": "workstation",
        "business_service": "Windows telemetry test workstation",
        "criticality": "medium",
        "tags": ["proxmox-fleet", "windows", "endpoint"],
    },
    "120": {
        "name": "nextcloud-siem",
        "ip": "10.20.20.120",
        "guest_type": "lxc",
        "os_family": "linux",
        "role": "business-app",
        "business_service": "Nextcloud collaboration and storage",
        "criticality": "high",
        "tags": ["proxmox-fleet", "nextcloud", "collaboration"],
        "source_name": "nextcloud-siem",
        "monitoring_enabled": True,
    },
    "121": {
        "name": "navidrome-01",
        "ip": "10.20.20.121",
        "guest_type": "lxc",
        "os_family": "linux",
        "role": "media-node",
        "business_service": "Navidrome media node",
        "criticality": "medium",
        "tags": ["proxmox-fleet", "media", "navidrome-target"],
        "source_name": "navidrome-01",
        "monitoring_enabled": True,
    },
    "122": {
        "name": "vuln-mgr-01",
        "ip": "10.20.30.122",
        "guest_type": "qemu",
        "os_family": "linux",
        "role": "vulnerability-manager",
        "business_service": "Vulnerability manager",
        "criticality": "high",
        "tags": ["proxmox-fleet", "greenbone", "scanner-control"],
        "source_name": "vuln-mgr-01",
        "monitoring_enabled": True,
    },
    "123": {
        "name": "pilot-web-01",
        "ip": "10.20.30.123",
        "guest_type": "qemu",
        "os_family": "linux",
        "role": "pilot-web",
        "business_service": "Pilot collaboration web service",
        "criticality": "medium",
        "tags": ["proxmox-fleet", "pilot", "gitea-target"],
        "source_name": "pilot-web-01",
        "monitoring_enabled": True,
    },
    "124": {
        "name": "pilot-db-01",
        "ip": "10.20.30.124",
        "guest_type": "qemu",
        "os_family": "linux",
        "role": "pilot-db",
        "business_service": "Pilot data service",
        "criticality": "medium",
        "tags": ["proxmox-fleet", "pilot", "postgresql-target"],
        "source_name": "pilot-db-01",
        "monitoring_enabled": True,
    },
    "125": {
        "name": "pilot-cache-01",
        "ip": "10.20.30.125",
        "guest_type": "qemu",
        "os_family": "linux",
        "role": "pilot-cache",
        "business_service": "Pilot cache service",
        "criticality": "medium",
        "tags": ["proxmox-fleet", "pilot", "valkey-target"],
        "source_name": "pilot-cache-01",
        "monitoring_enabled": True,
    },
    "126": {
        "name": "openclaw-gateway",
        "ip": "10.20.30.126",
        "guest_type": "qemu",
        "os_family": "linux",
        "role": "openclaw-gateway",
        "business_service": "OpenClaw egress gateway",
        "criticality": "high",
        "tags": ["proxmox-fleet", "openclaw", "gateway"],
        "source_name": "openclaw-gateway",
        "monitoring_enabled": False,
    },
    "127": {
        "name": "soc-ndr-01",
        "ip": "10.20.10.127",
        "guest_type": "qemu",
        "os_family": "linux",
        "role": "ndr",
        "business_service": "Zeek and Arkime network detection",
        "criticality": "high",
        "tags": ["proxmox-fleet", "security", "ndr", "zeek", "arkime"],
        "source_name": "soc-ndr-01",
        "monitoring_enabled": True,
    },
    "128": {
        "name": "soc-dfir-01",
        "ip": "10.20.10.128",
        "guest_type": "lxc",
        "os_family": "linux",
        "role": "dfir",
        "business_service": "Velociraptor DFIR and endpoint visibility",
        "criticality": "high",
        "tags": ["proxmox-fleet", "security", "dfir", "velociraptor"],
        "source_name": "soc-dfir-01",
        "monitoring_enabled": True,
    },
    "129": {
        "name": "soc-analysis-01",
        "ip": "10.20.30.129",
        "guest_type": "lxc",
        "os_family": "linux",
        "role": "malware-analysis",
        "business_service": "Static malware analysis",
        "criticality": "high",
        "tags": ["proxmox-fleet", "security", "malware-analysis", "static-analysis"],
        "source_name": "soc-analysis-01",
        "monitoring_enabled": True,
    },
    "130": {
        "name": "gamepanel-01",
        "ip": "10.20.20.130",
        "guest_type": "qemu",
        "os_family": "linux",
        "role": "game-panel",
        "business_service": "Pterodactyl, Wings and Falco runtime",
        "criticality": "high",
        "tags": ["proxmox-fleet", "game", "pterodactyl", "wings", "falco"],
        "source_name": "gamepanel-01",
        "monitoring_enabled": True,
    },
    "131": {
        "name": "soc-ti-01",
        "ip": "10.20.10.131",
        "guest_type": "qemu",
        "os_family": "linux",
        "role": "threat-intelligence",
        "business_service": "MISP threat intelligence",
        "criticality": "high",
        "tags": ["proxmox-fleet", "security", "threat-intelligence", "misp"],
        "source_name": "soc-ti-01",
        "monitoring_enabled": True,
    },
    "132": {
        "name": "soc-pki-01",
        "ip": "10.20.10.132",
        "guest_type": "lxc",
        "os_family": "linux",
        "role": "pki",
        "business_service": "SOC internal PKI",
        "criticality": "high",
        "tags": ["proxmox-fleet", "security", "pki", "step-ca"],
        "source_name": "soc-pki-01",
        "monitoring_enabled": True,
    },
    "133": {
        "name": "soc-evidence-01",
        "ip": "10.20.10.133",
        "guest_type": "lxc",
        "os_family": "linux",
        "role": "evidence-storage",
        "business_service": "MinIO evidence object storage",
        "criticality": "critical",
        "tags": ["proxmox-fleet", "security", "evidence", "minio"],
        "source_name": "soc-evidence-01",
        "monitoring_enabled": True,
    },
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _fleet_cache_is_stale(sync_state: dict[str, Any]) -> bool:
    timestamp = _string(sync_state.get("updated_ts"))
    if not timestamp:
        return True
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return True
    ttl_seconds = max(
        60,
        _safe_int(
            os.getenv("SIEM_PROXMOX_FLEET_CACHE_TTL_SECONDS"),
            _DEFAULT_FLEET_CACHE_TTL_SECONDS,
        ),
    )
    return (_now() - parsed.astimezone(timezone.utc)).total_seconds() > ttl_seconds


def _string(value: Any) -> str:
    return str(value or "").strip()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalize_token(value: Any) -> str:
    return "".join(ch.lower() for ch in _string(value) if ch.isalnum())


def _safe_slug(value: Any, *, default: str = "") -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", _string(value).lower()).strip("-")
    return slug or default


def _load_rows(name: str) -> list[dict[str, Any]]:
    rows = load_control_plane_rows(name, list)
    return rows if isinstance(rows, list) else []


def _save_rows(name: str, rows: list[dict[str, Any]]) -> None:
    save_control_plane_rows(name, rows)


def _proxmox_user() -> str:
    username = _string(os.getenv("SIEM_PROXMOX_USER"))
    if username and "@" not in username:
        return f"{username}@pam"
    return username


def _proxmox_base_url() -> str:
    host = _string(os.getenv("SIEM_PROXMOX_HOST"))
    port = _safe_int(os.getenv("SIEM_PROXMOX_PORT"), _DEFAULT_PROXMOX_PORT)
    if not host:
        return ""
    if host.startswith("http://") or host.startswith("https://"):
        return host.rstrip("/")
    return f"https://{host}:{port}"


def proxmox_is_configured() -> bool:
    return bool(_proxmox_base_url() and _proxmox_user() and _string(os.getenv("SIEM_PROXMOX_PASSWORD")))


def _ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _proxmox_auth_headers() -> dict[str, str]:
    if not proxmox_is_configured():
        raise RuntimeError("Proxmox integration is not configured")
    base_url = _proxmox_base_url()
    payload = urllib.parse.urlencode(
        {
            "username": _proxmox_user(),
            "password": _string(os.getenv("SIEM_PROXMOX_PASSWORD")),
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url}/api2/json/access/ticket",
        method="POST",
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(request, timeout=20, context=_ssl_context()) as response:
        body = json.loads(response.read().decode("utf-8", errors="replace"))
    data = dict(body.get("data") or {})
    ticket = _string(data.get("ticket"))
    csrf = _string(data.get("CSRFPreventionToken"))
    if not ticket:
        raise RuntimeError("Proxmox auth ticket is empty")
    headers = {"Cookie": f"PVEAuthCookie={ticket}"}
    if csrf:
        headers["CSRFPreventionToken"] = csrf
    return headers


def _proxmox_request(path: str) -> dict[str, Any]:
    base_url = _proxmox_base_url()
    headers = _proxmox_auth_headers()
    request = urllib.request.Request(
        f"{base_url}/api2/json/{path.lstrip('/')}",
        method="GET",
        headers=headers,
    )
    with urllib.request.urlopen(request, timeout=20, context=_ssl_context()) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def _hint_by_vmid(vmid: str, name: str) -> dict[str, Any]:
    direct = dict(_GUEST_HINTS.get(vmid) or {})
    if direct:
        return direct
    name_token = _normalize_token(name)
    for hint in _GUEST_HINTS.values():
        if _normalize_token(hint.get("name")) == name_token:
            return dict(hint)
    return {}


def _guess_os_family(name: str, hint: dict[str, Any], guest_type: str) -> str:
    if _string(hint.get("os_family")):
        return _string(hint.get("os_family"))
    token = _normalize_token(name)
    if token.startswith("win"):
        return "windows"
    if "bsd" in token:
        return "bsd"
    if "router" in token or "firewall" in token:
        return "network"
    if guest_type in {"qemu", "lxc"}:
        return "linux"
    return "unknown"


def _guess_role(name: str, hint: dict[str, Any]) -> str:
    if _string(hint.get("role")):
        return _string(hint.get("role"))
    token = _normalize_token(name)
    if "nextcloud" in token:
        return "business-app"
    if "openclaw" in token:
        return "openclaw-gateway"
    if "pilotweb" in token:
        return "pilot-web"
    if "pilotdb" in token:
        return "pilot-db"
    if "pilotcache" in token:
        return "pilot-cache"
    if "vulnmgr" in token or "greenbone" in token:
        return "vulnerability-manager"
    return "guest"


def _guest_state(*, running: bool, connected: bool, ip_text: str, os_family: str) -> str:
    if not running:
        return "offline"
    if connected:
        return "connected"
    if ip_text and os_family in {"linux", "windows"}:
        return "onboardable"
    if ip_text:
        return "scan-only"
    if os_family == "unknown":
        return "unsupported"
    return "inventory-only"


def _connected_markers(connected_sources: list[dict[str, Any]] | None) -> set[str]:
    markers: set[str] = set()
    for item in connected_sources or []:
        values = [item.get("source_name"), item.get("cmdb_asset_id"), *(item.get("aliases") or [])]
        for value in values:
            text = _string(value)
            if not text:
                continue
            markers.add(text.lower())
            markers.add(_normalize_token(text))
    return markers


def _last_seen_map() -> dict[str, str]:
    try:
        from .host_runtime_runtime import fetch_host_runtime_last_seen_map
    except ImportError:  # pragma: no cover - local test fallback
        try:
            from host_runtime_runtime import fetch_host_runtime_last_seen_map  # type: ignore[no-redef]
        except Exception:  # noqa: BLE001
            return {}
    try:
        return dict(fetch_host_runtime_last_seen_map(hours=72))
    except Exception:  # noqa: BLE001
        return {}


def _fetch_connected_sources() -> list[dict[str, Any]]:
    try:
        from .asset_catalog_runtime import fetch_source_inventory
    except ImportError:  # pragma: no cover - local test fallback
        try:
            from asset_catalog_runtime import fetch_source_inventory  # type: ignore[no-redef]
        except Exception:  # noqa: BLE001
            return []
    try:
        return list(fetch_source_inventory(limit=2000, hours=24 * 14))
    except Exception:  # noqa: BLE001
        return []


def _cmdb_assets() -> list[dict[str, Any]]:
    try:
        from .vuln_store import fetch_cmdb_assets
    except ImportError:  # pragma: no cover - local test fallback
        try:
            from vuln_store import fetch_cmdb_assets  # type: ignore[no-redef]
        except Exception:  # noqa: BLE001
            return []
    try:
        return list(fetch_cmdb_assets(limit=5000))
    except Exception:  # noqa: BLE001
        return []


def _cmdb_index() -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for asset in _cmdb_assets():
        for key in (asset.get("asset_id"), asset.get("hostname"), asset.get("ip")):
            token = _normalize_token(key)
            if token and token not in index:
                index[token] = dict(asset)
    return index


def _known_ip(hint: dict[str, Any], guest_name: str) -> str:
    ip_text = _string(hint.get("ip"))
    if ip_text:
        return ip_text
    alias = SOURCE_ALIAS_OVERRIDES.get(_string(guest_name))
    return _string(alias)


def _resolve_qemu_ips(node: str, vmid: str) -> list[str]:
    try:
        payload = _proxmox_request(f"nodes/{urllib.parse.quote(node)}/qemu/{urllib.parse.quote(vmid)}/agent/network-get-interfaces")
    except Exception:  # noqa: BLE001
        return []
    result = []
    for item in payload.get("data") or []:
        if not isinstance(item, dict):
            continue
        for address in item.get("ip-addresses") or []:
            if not isinstance(address, dict):
                continue
            ip_text = _string(address.get("ip-address"))
            if not ip_text or ip_text.startswith("127.") or ip_text == "::1":
                continue
            if ip_text.startswith("fe80:"):
                continue
            result.append(ip_text)
    deduped: list[str] = []
    for ip_text in result:
        if ip_text not in deduped:
            deduped.append(ip_text)
    return deduped


def _asset_id_for_item(item: dict[str, Any], cmdb_index: dict[str, dict[str, Any]]) -> str:
    for key in (item.get("name"), item.get("ip"), item.get("hostname"), item.get("source_name")):
        match = cmdb_index.get(_normalize_token(key))
        if match and _string(match.get("asset_id")):
            return _string(match.get("asset_id"))
    return f"asset-{_safe_slug(item.get('name') or item.get('vmid'), default='guest')}"


def _summaries(items: list[dict[str, Any]]) -> dict[str, Any]:
    state_counts: dict[str, int] = {}
    os_counts: dict[str, int] = {}
    connected = 0
    reachable = 0
    running = 0
    scannable = 0
    for item in items:
        state = _string(item.get("state") or "unknown")
        os_family = _string(item.get("os_family") or "unknown")
        state_counts[state] = state_counts.get(state, 0) + 1
        os_counts[os_family] = os_counts.get(os_family, 0) + 1
        if bool(item.get("connected")):
            connected += 1
        if bool(item.get("running")):
            running += 1
        if bool(item.get("reachable")):
            reachable += 1
        if bool(item.get("vuln_scannable")):
            scannable += 1
    flattened_state_counts = {
        _safe_slug(state, default="unknown").replace("-", "_"): count
        for state, count in state_counts.items()
    }
    return {
        "total": len(items),
        "running": running,
        "connected": connected,
        "reachable": reachable,
        "vuln_scannable": scannable,
        **flattened_state_counts,
        "state_counts": state_counts,
        "os_counts": os_counts,
    }


def sync_proxmox_fleet_inventory(*, actor: str = "system", connected_sources: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    if not proxmox_is_configured():
        raise RuntimeError("Proxmox integration is not configured")
    resources_payload = _proxmox_request("cluster/resources?type=vm")
    resource_rows = [row for row in (resources_payload.get("data") or []) if isinstance(row, dict)]
    markers = _connected_markers(connected_sources if connected_sources is not None else _fetch_connected_sources())
    last_seen_map = _last_seen_map()
    cmdb_index = _cmdb_index()
    items: list[dict[str, Any]] = []
    now_iso = _now_iso()
    for row in resource_rows:
        guest_type = _string(row.get("type") or "")
        if guest_type not in {"qemu", "lxc"}:
            continue
        vmid = _string(row.get("vmid"))
        if vmid in _IGNORED_VMIDS:
            continue
        name = _string(row.get("name")) or _string(row.get("id")) or f"{guest_type}-{vmid}"
        node = _string(row.get("node") or "pve")
        hint = _hint_by_vmid(vmid, name)
        running = _string(row.get("status")).lower() in _RUNNING_STATES
        ip_candidates = []
        hint_ip = _string(hint.get("ip"))
        if hint_ip:
            ip_candidates.append(hint_ip)
        if running and guest_type == "qemu":
            ip_candidates.extend(_resolve_qemu_ips(node, vmid))
        ip_text = next((candidate for candidate in ip_candidates if _string(candidate)), "")
        guest_name = _string(hint.get("name")) or name
        os_family = _guess_os_family(guest_name, hint, guest_type)
        source_name = _string(hint.get("source_name")) or SOURCE_ALIAS_OVERRIDES.get(ip_text, guest_name) or guest_name
        connected = False
        for candidate in (source_name, guest_name, ip_text, vmid):
            text = _string(candidate)
            if not text:
                continue
            if text.lower() in markers or _normalize_token(text) in markers:
                connected = True
                break
        role = _guess_role(guest_name, hint)
        state = _guest_state(running=running, connected=connected, ip_text=ip_text, os_family=os_family)
        reachable = bool(running and ip_text)
        item = {
            "id": f"proxmox-{vmid}",
            "vmid": vmid,
            "node": node,
            "guest_type": guest_type,
            "name": guest_name,
            "hostname": guest_name,
            "source_name": source_name,
            "ip": ip_text,
            "running": running,
            "state": state,
            "connected": connected,
            "reachable": reachable,
            "monitoring_supported": os_family in {"linux", "windows"},
            "vuln_scannable": reachable,
            "host_runtime_enabled": bool(hint.get("monitoring_enabled", os_family == "linux" and guest_type in {"qemu", "lxc"})),
            "os_family": os_family,
            "role": role,
            "business_service": _string(hint.get("business_service")) or guest_name,
            "criticality": _string(hint.get("criticality")) or "medium",
            "tags": sorted({*[_string(item) for item in (hint.get("tags") or []) if _string(item)], f"os:{os_family}", f"role:{role}"}),
            "last_seen_ts": _string(last_seen_map.get(source_name) or last_seen_map.get(guest_name) or ""),
            "max_memory_bytes": _safe_int(row.get("maxmem")),
            "used_memory_bytes": _safe_int(row.get("mem")),
            "cpu": float(row.get("cpu") or 0.0),
            "uptime_seconds": _safe_int(row.get("uptime")),
            "asset_id": "",
            "updated_ts": now_iso,
        }
        item["asset_id"] = _asset_id_for_item(item, cmdb_index)
        items.append(item)
    items.sort(key=lambda current: (_string(current.get("state")) != "connected", _string(current.get("state")), _string(current.get("name")).lower()))
    _save_rows(PROXMOX_FLEET_COLLECTION, items)
    _save_rows(
        PROXMOX_FLEET_SYNC_COLLECTION,
        [
            {
                "updated_ts": now_iso,
                "actor": actor,
                "count": len(items),
            }
        ],
    )
    return {
        "generated_ts": now_iso,
        "items": items,
        "metrics": _summaries(items),
        "sync": {"actor": actor, "updated_ts": now_iso, "count": len(items)},
    }


def list_proxmox_fleet_inventory(*, limit: int = 500) -> dict[str, Any]:
    items = [dict(item) for item in _load_rows(PROXMOX_FLEET_COLLECTION)]
    sync_rows = _load_rows(PROXMOX_FLEET_SYNC_COLLECTION)
    sync_state = dict(sync_rows[0]) if sync_rows else {}
    if proxmox_is_configured() and (not items or _fleet_cache_is_stale(sync_state)):
        try:
            return sync_proxmox_fleet_inventory(actor="auto-sync")
        except Exception:
            if not items:
                raise
    trimmed = items[: max(1, min(int(limit or 500), 5000))]
    return {
        "generated_ts": _now_iso(),
        "items": trimmed,
        "metrics": _summaries(items),
        "sync": sync_state,
    }


def sync_proxmox_fleet_to_cmdb(*, actor: str = "system") -> dict[str, Any]:
    try:
        from .vuln_store import fetch_cmdb_assets, save_cmdb_assets
    except ImportError:  # pragma: no cover - local test fallback
        from vuln_store import fetch_cmdb_assets, save_cmdb_assets  # type: ignore[no-redef]

    payload = list_proxmox_fleet_inventory(limit=5000)
    items = list(payload.get("items") or [])
    existing_assets = list(fetch_cmdb_assets(limit=5000))
    existing_index: dict[str, dict[str, Any]] = {}
    for asset in existing_assets:
        for key in (asset.get("asset_id"), asset.get("hostname"), asset.get("ip")):
            token = _normalize_token(key)
            if token and token not in existing_index:
                existing_index[token] = dict(asset)
    created = 0
    updated = 0
    normalized_items: list[dict[str, Any]] = []
    cmdb_versions: list[dict[str, Any]] = []
    for item in items:
        if _string(item.get("state")) == "unsupported":
            normalized_items.append(dict(item))
            continue
        existing = (
            existing_index.get(_normalize_token(item.get("asset_id")))
            or existing_index.get(_normalize_token(item.get("ip")))
            or existing_index.get(_normalize_token(item.get("name")))
            or {}
        )
        asset_id = _string(existing.get("asset_id")) or _string(item.get("asset_id")) or f"asset-{_safe_slug(item.get('name'), default='guest')}"
        if existing:
            updated += 1
        else:
            created += 1
        tags = {
            *[_string(tag) for tag in (existing.get("tags") or []) if _string(tag)],
            *[_string(tag) for tag in (item.get("tags") or []) if _string(tag)],
            "proxmox-fleet",
        }
        cmdb_versions.append(
            {
                "asset_id": asset_id,
                "asset_type": _string(existing.get("asset_type"))
                or (
                    "container"
                    if _string(item.get("guest_type")) == "lxc"
                    else "server"
                ),
                "hostname": _string(item.get("hostname"))
                or _string(existing.get("hostname")),
                "ip": _string(item.get("ip")) or _string(existing.get("ip")),
                "owner": _string(existing.get("owner")) or "soc-fleet",
                "criticality": _string(existing.get("criticality"))
                or _string(item.get("criticality"))
                or "medium",
                "environment": _string(existing.get("environment")) or "lab",
                "business_service": _string(existing.get("business_service"))
                or _string(item.get("business_service"))
                or _string(item.get("name")),
                "os_family": _string(existing.get("os_family"))
                or _string(item.get("os_family"))
                or "linux",
                "expected_ports": ",".join(str(port) for port in []),
                "tags": ",".join(sorted(tags)),
                "notes": _string(existing.get("notes"))
                or f"Managed by Proxmox fleet sync ({actor}).",
                "vuln_enabled": bool(item.get("vuln_scannable")),
                "vuln_profile": "network-basic",
            }
        )
        updated_item = dict(item)
        updated_item["asset_id"] = asset_id
        normalized_items.append(updated_item)
    if cmdb_versions:
        save_cmdb_assets(cmdb_versions)
    if normalized_items:
        _save_rows(PROXMOX_FLEET_COLLECTION, normalized_items)
    return {
        "status": "ok",
        "created": created,
        "updated": updated,
        "total": len(normalized_items),
    }


def build_proxmox_fleet_vuln_coverage(*, days: int = 30, reports: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    try:
        from .vuln_store import fetch_vulnerability_reports
    except ImportError:  # pragma: no cover - local test fallback
        try:
            from vuln_store import fetch_vulnerability_reports  # type: ignore[no-redef]
        except Exception:  # noqa: BLE001
            fetch_vulnerability_reports = None  # type: ignore[assignment]

    payload = list_proxmox_fleet_inventory(limit=5000)
    items = list(payload.get("items") or [])
    reports = list(reports) if reports is not None else (
        list(fetch_vulnerability_reports(limit=1000, days=max(1, int(days)))) if fetch_vulnerability_reports else []
    )
    scanned_markers: set[str] = set()
    last_finished_at = ""
    for report in reports:
        for candidate in (
            report.get("asset_id"),
            report.get("hostname"),
            report.get("ip"),
            *(report.get("targets") or []),
        ):
            token = _normalize_token(candidate)
            if token:
                scanned_markers.add(token)
        finished_at = _string(report.get("ts_last") or report.get("finished_at"))
        if finished_at and finished_at > last_finished_at:
            last_finished_at = finished_at
    recently_scanned = 0
    unresolved = 0
    offline = 0
    reachable = 0
    scannable = 0
    for item in items:
        state = _string(item.get("state"))
        if state == "offline":
            offline += 1
        if bool(item.get("reachable")):
            reachable += 1
        elif not _string(item.get("ip")):
            unresolved += 1
        if bool(item.get("vuln_scannable")):
            scannable += 1
        for candidate in (item.get("asset_id"), item.get("ip"), item.get("name"), item.get("hostname")):
            if _normalize_token(candidate) in scanned_markers:
                recently_scanned += 1
                break
    return {
        "total_guests": len(items),
        "reachable_guests": reachable,
        "scannable_guests": scannable,
        "recently_scanned_guests": recently_scanned,
        "offline_guests": offline,
        "unresolved_guests": unresolved,
        "last_successful_import": last_finished_at,
    }


def host_runtime_targets_from_fleet() -> list[dict[str, Any]]:
    payload = list_proxmox_fleet_inventory(limit=5000)
    items = []
    for item in payload.get("items") or []:
        if item.get("monitoring_supported") is False:
            continue
        if not bool(item.get("host_runtime_enabled")):
            continue
        if _string(item.get("state")) in {"offline", "unsupported", "inventory-only"}:
            continue
        if not _string(item.get("ip")):
            continue
        items.append(
            {
                "host_name": _string(item.get("source_name") or item.get("name")),
                "host_role": _string(item.get("role") or item.get("os_family") or "generic"),
                "host_ip": _string(item.get("ip")),
            }
        )
    return items
