from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any


PROTECTED_PUBLIC_IPS = tuple(
    ip.strip()
    for ip in (os.environ.get("SIEM_PROTECTED_PUBLIC_IPS") or "45.89.111.208,176.108.250.215").split(",")
    if ip.strip()
)

PUBLIC_IP_PROFILES: dict[str, dict[str, str]] = {
    "176.108.250.215": {
        "hostname": "vpn-host-khanov",
        "display_label": "vpn-host-khanov",
        "source_kind": "vpn_host",
        "entity_role": "vpn-public-edge",
        "source_type_label": "VPN host",
        "topology_lane": "edge",
    },
    "45.89.111.208": {
        "hostname": "vpn-public-edge-45",
        "display_label": "vpn-public-edge-45",
        "source_kind": "vpn_host",
        "entity_role": "vpn-public-edge",
        "source_type_label": "VPN host",
        "topology_lane": "edge",
    },
}

SOURCE_IDENTITY_OVERRIDES: dict[str, dict[str, str]] = {
    "pve": {
        "hostname": "pve",
        "ip": "192.168.1.28",
        "source_kind": "proxmox_host",
        "entity_role": "proxmox-hypervisor",
        "source_type_label": "Proxmox host",
        "topology_lane": "inventory",
    },
    "opnsense-edge-01": {
        "hostname": "opnsense-edge-01",
        "ip": "192.168.1.102",
        "source_kind": "virtual_router",
        "entity_role": "edge-router",
        "source_type_label": "Virtual router",
        "topology_lane": "inventory",
    },
    "lab-edge-01": {
        "hostname": "lab-edge-01",
        "source_kind": "virtual_router",
        "entity_role": "edge-router",
        "source_type_label": "Virtual router",
        "topology_lane": "inventory",
    },
    "vpn-host-khanov": {
        "hostname": "vpn-host-khanov",
        "ip": "176.108.250.215",
        "source_kind": "vpn_host",
        "entity_role": "vpn-host",
        "source_type_label": "VPN host",
        "topology_lane": "edge",
    },
}

SOURCE_KIND_LABELS: dict[str, str] = {
    "proxmox_host": "Proxmox host",
    "proxmox_guest": "Proxmox VM/CT",
    "virtual_router": "Virtual router",
    "vpn_host": "VPN host",
    "vpn_gateway": "VPN gateway",
    "siem_core": "SIEM core host",
    "collector": "Collector",
    "workstation": "Workstation",
    "business_app": "Business app",
    "vulnerability_manager": "Vulnerability manager",
    "network_device": "Network device",
    "external_ip": "External IP",
    "telemetry_source": "Telemetry source",
    "host": "Host",
}


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _slug(value: Any, default: str = "node") -> str:
    text = str(value or "").strip().lower()
    cleaned = "".join(ch if ch.isalnum() else "-" for ch in text).strip("-")
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return cleaned or default


def _text(value: Any) -> str:
    return str(value or "").strip()


def _is_ip_text(value: Any) -> bool:
    text = _text(value)
    if not text:
        return False
    try:
        ip_address(text.split("/", 1)[0])
    except ValueError:
        return False
    return True


def _hostname_from_ip(ip_text: Any, *, prefix: str = "host") -> str:
    text = _text(ip_text)
    if not text:
        return ""
    return f"{prefix}-{re.sub(r'[^0-9a-fA-F]+', '-', text).strip('-').lower()}"


def _identity_token(value: Any) -> str:
    text = _text(value).lower()
    if not text:
        return ""
    if _is_ip_text(text):
        return text
    return re.sub(r"[^a-z0-9.:-]+", "-", text).strip("-")


def _identity_tokens(*values: Any) -> list[str]:
    result: list[str] = []
    for value in values:
        if isinstance(value, (list, tuple, set)):
            nested = _identity_tokens(*value)
            for token in nested:
                if token not in result:
                    result.append(token)
            continue
        token = _identity_token(value)
        if token and len(token) > 1 and token not in {"n-a", "unknown", "candidate", "host", "source"} and token not in result:
            result.append(token)
        slug = _slug(value, "")
        if slug and slug not in result:
            result.append(slug)
    return result


def _kind_label(source_kind: Any) -> str:
    kind = _identity_token(source_kind).replace("-", "_")
    return SOURCE_KIND_LABELS.get(kind, SOURCE_KIND_LABELS["host"])


def _infer_source_kind(record: dict[str, Any], *, fallback: str = "host") -> str:
    explicit = _identity_token(record.get("source_kind") or record.get("host_kind") or record.get("kind")).replace("-", "_")
    if explicit:
        return explicit
    text = " ".join(
        _text(record.get(key)).lower()
        for key in (
            "source_name",
            "name",
            "hostname",
            "label",
            "role",
            "entity_role",
            "source_type",
            "source_family",
            "probable_role",
            "os_family",
            "guest_type",
            "business_service",
        )
    )
    tags = record.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    text = f"{text} {' '.join(_text(item).lower() for item in tags)}"
    if re.search(r"\bpve\b", text) or "proxmox-hypervisor" in text or "hypervisor" in text:
        return "proxmox_host"
    if "opnsense" in text or "edge-router" in text or "router" in text or "firewall" in text or "ngfw" in text:
        return "virtual_router"
    if "vpn" in text or "wireguard" in text or "openvpn" in text:
        return "vpn_host"
    if "siem-" in text or any(token in text for token in (" ingest", " processing", " storage", " transport", "control-plane", "siem-core")):
        return "siem_core"
    if "collector" in text or "syslog" in text:
        return "collector"
    if "windows" in text or "workstation" in text or "desktop" in text:
        return "workstation"
    if "vulnerability" in text or "greenbone" in text or "scanner" in text:
        return "vulnerability_manager"
    if any(token in text for token in ("nextcloud", "navidrome", "pilot-", "business-app", "media-node", "db", "cache")):
        return "business_app"
    if any(token in text for token in ("switch", "appliance", "network")):
        return "network_device"
    return fallback


def _public_ip_profile(ip_text: str) -> dict[str, str]:
    profile = dict(PUBLIC_IP_PROFILES.get(ip_text) or {})
    if not profile:
        profile = {
            "hostname": _hostname_from_ip(ip_text, prefix="protected-edge"),
            "display_label": _hostname_from_ip(ip_text, prefix="protected-edge"),
            "source_kind": "vpn_host",
            "entity_role": "protected-public-edge",
            "source_type_label": "Protected public IP",
            "topology_lane": "edge",
        }
    profile["ip"] = ip_text
    profile.setdefault("source_type_label", _kind_label(profile.get("source_kind")))
    profile.setdefault("display_label", profile.get("hostname") or ip_text)
    profile.setdefault("identity_tokens", ",".join(_identity_tokens(ip_text, profile.get("hostname"), profile.get("display_label"))))
    return profile


def _identity_profile_from_record(record: dict[str, Any], *, default_hostname_prefix: str = "host") -> dict[str, Any]:
    ip_text = _text(record.get("ip") or record.get("host_ip") or record.get("management_ip"))
    raw_hostname = _text(record.get("hostname") or record.get("host_name") or record.get("name") or record.get("source_name") or record.get("label"))
    hostname = raw_hostname if raw_hostname and not _is_ip_text(raw_hostname) else _hostname_from_ip(ip_text, prefix=default_hostname_prefix)
    if not hostname:
        hostname = _text(record.get("id") or record.get("vmid") or "")
    source_kind = _infer_source_kind(record)
    source_type_label = _text(record.get("source_type_label")) or _kind_label(source_kind)
    entity_role = _text(record.get("entity_role") or record.get("role") or record.get("probable_role") or record.get("source_family"))
    return {
        "hostname": hostname,
        "display_label": _text(record.get("display_label") or hostname or ip_text),
        "ip": ip_text,
        "source_kind": source_kind,
        "source_type_label": source_type_label,
        "entity_role": entity_role,
        "topology_lane": _text(record.get("topology_lane") or ""),
        "identity_tokens": ",".join(
            _identity_tokens(
                ip_text,
                hostname,
                record.get("source_name"),
                record.get("name"),
                record.get("label"),
                record.get("id"),
                record.get("vmid"),
                record.get("connected_source"),
            )
        ),
    }


def _build_identity_index(fleet_rows: list[dict[str, Any]], candidate_rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}

    def add_profile(record: dict[str, Any], *, profile: dict[str, Any] | None = None, overwrite: bool = False) -> None:
        resolved = profile or _identity_profile_from_record(record)
        tokens = _identity_tokens(
            record.get("source_name"),
            record.get("name"),
            record.get("hostname"),
            record.get("host_name"),
            record.get("ip"),
            record.get("id"),
            record.get("vmid"),
            record.get("connected_source"),
            resolved.get("hostname"),
            resolved.get("display_label"),
            resolved.get("ip"),
        )
        for token in tokens:
            if overwrite or token not in index:
                index[token] = dict(resolved)

    for source_name, profile in SOURCE_IDENTITY_OVERRIDES.items():
        add_profile({"source_name": source_name, **profile}, profile=profile, overwrite=True)
    for public_ip, profile in PUBLIC_IP_PROFILES.items():
        add_profile({"ip": public_ip, **profile}, profile={**profile, "ip": public_ip}, overwrite=True)
    for guest in fleet_rows:
        profile = _identity_profile_from_record(guest)
        profile["platform_kind"] = "proxmox_guest"
        if profile.get("source_kind") == "host":
            profile["source_kind"] = "proxmox_guest"
            profile["source_type_label"] = _kind_label("proxmox_guest")
        elif profile.get("source_kind") not in {"proxmox_host", "virtual_router", "vpn_host", "siem_core"}:
            profile.setdefault("source_type_label", _kind_label(profile.get("source_kind")))
        if not profile.get("topology_lane"):
            profile["topology_lane"] = "inventory"
        add_profile(guest, profile=profile)
    for candidate in candidate_rows:
        add_profile(candidate, profile=_identity_profile_from_record(candidate))
    return index


def _resolve_identity(record: dict[str, Any], identity_index: dict[str, dict[str, Any]], *, default_hostname_prefix: str = "host") -> dict[str, Any]:
    tokens = _identity_tokens(
        record.get("source_name"),
        record.get("name"),
        record.get("hostname"),
        record.get("host_name"),
        record.get("label"),
        record.get("ip"),
        record.get("id"),
        record.get("connected_source"),
    )
    matched: dict[str, Any] = {}
    for token in tokens:
        if token in identity_index:
            matched = dict(identity_index[token])
            break
    resolved = _identity_profile_from_record({**matched, **record}, default_hostname_prefix=default_hostname_prefix)
    for key, value in matched.items():
        if value and not resolved.get(key):
            resolved[key] = value
    if not resolved.get("source_type_label"):
        resolved["source_type_label"] = _kind_label(resolved.get("source_kind"))
    if not resolved.get("display_label"):
        resolved["display_label"] = resolved.get("hostname") or resolved.get("ip") or _text(record.get("source_name") or record.get("label"))
    resolved["identity_tokens"] = ",".join(_identity_tokens(tokens, resolved.get("hostname"), resolved.get("display_label"), resolved.get("ip")))
    return resolved


def _number(value: Any, default: int = 0) -> int:
    try:
        return int(float(value or 0))
    except (TypeError, ValueError):
        return default


def _csv_tokens(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [part.strip() for part in str(value or "").split(",") if part.strip()]


def _node(node_id: str, node_type: str, label: str, *, x: float, y: float, **extra: Any) -> dict[str, Any]:
    payload = {
        "id": node_id,
        "type": node_type,
        "label": label,
        "x": round(float(x), 2),
        "y": round(float(y), 2),
    }
    payload.update({key: value for key, value in extra.items() if value is not None})
    return payload


def _edge(edge_id: str, source: str, target: str, edge_type: str, **extra: Any) -> dict[str, Any]:
    payload = {"id": edge_id, "source": source, "target": target, "type": edge_type}
    payload.update({key: value for key, value in extra.items() if value is not None})
    return payload


def _profile_keys(profile: dict[str, Any]) -> set[str]:
    values = {
        str(profile.get("host_id") or "").strip(),
        str(profile.get("ip") or "").strip(),
        str(profile.get("hostname") or "").strip().lower(),
        str(profile.get("host_label") or "").strip().lower(),
    }
    return {value for value in values if value}


def _node_keys(node: dict[str, Any]) -> set[str]:
    values = {
        str(node.get("id") or "").strip(),
        str(node.get("ip") or "").strip(),
        str(node.get("label") or "").strip().lower(),
    }
    return {value for value in values if value}


def _profile_summary(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "profile_id": str(profile.get("profile_id") or ""),
        "protocol": str(profile.get("protocol") or ""),
        "port": profile.get("port"),
        "username": str(profile.get("username") or ""),
        "auth_method": str(profile.get("auth_method") or ""),
        "credential_label": str(profile.get("credential_label") or ""),
        "secret_status": str(profile.get("secret_status") or ""),
        "enabled": bool(profile.get("enabled", True)),
    }


def _host_access_node_key(node: dict[str, Any]) -> str:
    for key in ("ip", "hostname", "display_label", "label", "id"):
        value = _identity_token(node.get(key))
        if value:
            return value
    return ""


def _spread(index: int, total: int, *, top: float = 14.0, bottom: float = 86.0) -> float:
    if total <= 1:
        return (top + bottom) / 2.0
    return top + ((bottom - top) * (index / max(1, total - 1)))


def _load_sources(hours: int, limit: int) -> list[dict[str, Any]]:
    try:
        from .asset_catalog_runtime import fetch_source_inventory
    except ImportError:  # pragma: no cover - local test fallback
        from asset_catalog_runtime import fetch_source_inventory  # type: ignore[no-redef]

    return list(fetch_source_inventory(hours=hours, limit=limit))


def _load_collectors(hours: int) -> list[dict[str, Any]]:
    try:
        from .asset_catalog_runtime import fetch_collector_inventory
    except ImportError:  # pragma: no cover - local test fallback
        from asset_catalog_runtime import fetch_collector_inventory  # type: ignore[no-redef]

    return list(fetch_collector_inventory(hours=hours))


def _load_geo_sources(hours: int, limit: int) -> list[dict[str, Any]]:
    try:
        from .asset_catalog_runtime import fetch_geo_source_activity
    except ImportError:  # pragma: no cover - local test fallback
        from asset_catalog_runtime import fetch_geo_source_activity  # type: ignore[no-redef]

    return list((fetch_geo_source_activity(hours=hours, limit=limit) or {}).get("items") or [])


def _load_discovery(limit: int) -> dict[str, Any]:
    try:
        from .source_discovery import list_source_discovery_candidates
    except ImportError:  # pragma: no cover - local test fallback
        from source_discovery import list_source_discovery_candidates  # type: ignore[no-redef]

    return dict(list_source_discovery_candidates(limit=limit))


def _load_fleet(limit: int) -> dict[str, Any]:
    try:
        from .proxmox_fleet_runtime import list_proxmox_fleet_inventory
    except ImportError:  # pragma: no cover - local test fallback
        from proxmox_fleet_runtime import list_proxmox_fleet_inventory  # type: ignore[no-redef]

    return dict(list_proxmox_fleet_inventory(limit=limit))


def _load_host_access_profiles(limit: int) -> list[dict[str, Any]]:
    try:
        from .host_access_runtime import list_host_access_profiles
    except ImportError:  # pragma: no cover - local test fallback
        from host_access_runtime import list_host_access_profiles  # type: ignore[no-redef]

    return list((list_host_access_profiles(limit=limit) or {}).get("items") or [])


def _compact_ports(rows: list[dict[str, Any]], *, limit: int = 8) -> list[str]:
    ports: list[str] = []
    for row in rows:
        for token in _csv_tokens(row.get("target_ports") or row.get("port_summary")):
            if token and token not in ports:
                ports.append(token)
            if len(ports) >= limit:
                return ports
    return ports


def _event_sum(rows: list[dict[str, Any]]) -> int:
    return sum(_number(row.get("events")) for row in rows)


def _packet_flow(
    flow_id: str,
    order: int,
    title: str,
    source: str,
    target: str,
    *,
    protocols: list[str],
    ports: list[str] | None = None,
    events: int = 0,
    nodes: int = 0,
    source_layer: str = "",
    target_layer: str = "",
    description: str = "",
) -> dict[str, Any]:
    return {
        "id": flow_id,
        "order": order,
        "title": title,
        "from": source,
        "to": target,
        "protocols": protocols,
        "ports": ports or [],
        "events": events,
        "nodes": nodes,
        "source_layer": source_layer,
        "target_layer": target_layer,
        "description": description,
    }


def _build_packet_flows(
    *,
    geo_sources: list[dict[str, Any]],
    source_rows: list[dict[str, Any]],
    collector_rows: list[dict[str, Any]],
    candidate_rows: list[dict[str, Any]],
    fleet_rows: list[dict[str, Any]],
    protected_targets: set[str],
) -> list[dict[str, Any]]:
    unmanaged = [item for item in candidate_rows if not bool(item.get("connected"))]
    connected_fleet = [item for item in fleet_rows if bool(item.get("connected"))]
    source_events = _event_sum(source_rows)
    collector_events = _event_sum(collector_rows)
    attack_events = _event_sum(geo_sources)
    return [
        _packet_flow(
            "packet-flow-external-edge",
            1,
            "Internet traffic to protected edge",
            "External IP / Internet actor",
            "VPN or public edge",
            protocols=["tcp", "udp", "icmp"],
            ports=_compact_ports(geo_sources),
            events=attack_events,
            nodes=len(geo_sources),
            source_layer="external",
            target_layer="edge",
            description="Inbound packets first appear as external GeoIP/TI observations and are bound to protected public IPs such as VPN/public edge addresses.",
        ),
        _packet_flow(
            "packet-flow-edge-host",
            2,
            "Edge forwarding to internal hosts",
            "VPN / virtual router",
            "LAN host or Proxmox guest",
            protocols=["vpn", "nat", "lan"],
            ports=["22", "80", "443", "3389", "5985", "8006"],
            events=len(protected_targets),
            nodes=len(fleet_rows) + len(candidate_rows),
            source_layer="edge",
            target_layer="inventory",
            description="After edge termination or NAT, traffic resolves into internal host identities: Proxmox guests, routers, VPN hosts and discovered assets.",
        ),
        _packet_flow(
            "packet-flow-discovery",
            3,
            "Discovery probing and candidate staging",
            "Discovery scanner",
            "Unconnected asset queue",
            protocols=["tcp-connect", "reverse-dns", "service-probe"],
            ports=["22", "80", "135", "445", "514", "3389", "5985", "8006"],
            events=len(unmanaged),
            nodes=len(unmanaged),
            source_layer="inventory",
            target_layer="source",
            description="Network scanning probes open services, infers hostname/role/platform and stores unmanaged nodes as onboarding candidates.",
        ),
        _packet_flow(
            "packet-flow-host-collector",
            4,
            "Telemetry emission to collectors",
            "Host / network source",
            "Collector profile",
            protocols=["syslog", "windows-agent", "auditd", "powershell", "api-pull"],
            ports=["514", "1514", "443", "5985", "5986"],
            events=source_events,
            nodes=len(source_rows) + len(connected_fleet),
            source_layer="source",
            target_layer="collector",
            description="Managed hosts send logs through syslog, Windows agent, API or collector bindings before ingestion.",
        ),
        _packet_flow(
            "packet-flow-collector-ingest",
            5,
            "Collector delivery to SIEM ingest",
            "Collectors",
            "Ingest API",
            protocols=["https", "json", "syslog-forward"],
            ports=["443", "8123"],
            events=max(collector_events, source_events),
            nodes=len(collector_rows),
            source_layer="collector",
            target_layer="core",
            description="Collectors normalize transport details and deliver accepted event batches into the SIEM ingest surface.",
        ),
        _packet_flow(
            "packet-flow-ingest-processing",
            6,
            "Stream transport and correlation",
            "Ingest / transport",
            "Processing and correlation",
            protocols=["kafka", "internal-http", "rules-engine"],
            events=source_events,
            nodes=3,
            source_layer="core",
            target_layer="core",
            description="Events move through transport into parser, normalizer, filter, enrichment and correlation stages.",
        ),
        _packet_flow(
            "packet-flow-storage-web-soar",
            7,
            "Storage, analyst query and SOAR action",
            "ClickHouse storage",
            "Web UI / SOAR",
            protocols=["clickhouse-native", "https", "soar-action"],
            ports=["8123", "443", "22", "3389"],
            events=source_events,
            nodes=2,
            source_layer="core",
            target_layer="core",
            description="Processed events are retained in hot/cold storage, queried by UI dashboards and used by SOAR/IRP actions through host access profiles.",
        ),
    ]


def build_network_topology(*, hours: int = 24, limit: int = 240) -> dict[str, Any]:
    issues: list[str] = []
    safe_hours = max(1, int(hours or 24))
    safe_limit = max(20, min(int(limit or 240), 600))

    try:
        sources = _load_sources(safe_hours, safe_limit)
    except Exception as exc:  # noqa: BLE001
        sources = []
        issues.append(f"sources:{type(exc).__name__}:{exc}")
    try:
        collectors = _load_collectors(safe_hours)
    except Exception as exc:  # noqa: BLE001
        collectors = []
        issues.append(f"collectors:{type(exc).__name__}:{exc}")
    try:
        geo_sources = _load_geo_sources(safe_hours, 18)
    except Exception as exc:  # noqa: BLE001
        geo_sources = []
        issues.append(f"geo:{type(exc).__name__}:{exc}")
    try:
        discovery = _load_discovery(safe_limit)
    except Exception as exc:  # noqa: BLE001
        discovery = {"items": [], "jobs": [], "metrics": {}}
        issues.append(f"discovery:{type(exc).__name__}:{exc}")
    try:
        fleet = _load_fleet(safe_limit)
    except Exception as exc:  # noqa: BLE001
        fleet = {"items": [], "metrics": {}}
        issues.append(f"fleet:{type(exc).__name__}:{exc}")
    try:
        host_access_profiles = _load_host_access_profiles(safe_limit)
    except Exception as exc:  # noqa: BLE001
        host_access_profiles = []
        issues.append(f"host_access:{type(exc).__name__}:{exc}")

    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    nodes["internet"] = _node("internet", "zone", "Internet", x=5, y=50, status="observed")

    public_targets = set(PROTECTED_PUBLIC_IPS)
    for index, ip_text in enumerate(sorted(public_targets)):
        node_id = f"public:{ip_text}"
        profile = _public_ip_profile(ip_text)
        nodes[node_id] = _node(
            node_id,
            "protected_public_ip",
            str(profile.get("display_label") or profile.get("hostname") or ip_text),
            x=20,
            y=_spread(index, max(1, len(public_targets)), top=36, bottom=64),
            status="protected",
            role=str(profile.get("entity_role") or "public edge"),
            ip=ip_text,
            hostname=str(profile.get("hostname") or ""),
            display_label=str(profile.get("display_label") or profile.get("hostname") or ip_text),
            source_kind=str(profile.get("source_kind") or "vpn_host"),
            source_type_label=str(profile.get("source_type_label") or "Protected public IP"),
            entity_role=str(profile.get("entity_role") or "protected-public-edge"),
            topology_lane=str(profile.get("topology_lane") or "edge"),
            identity_tokens=str(profile.get("identity_tokens") or ""),
            protected_ip=True,
        )

    core_layout = [
        ("core:ingest", "Ingest", 70, 26, "active"),
        ("core:transport", "Transport", 82, 26, "active"),
        ("core:processing", "Processing", 82, 55, "active"),
        ("core:storage", "Storage", 94, 40, "active"),
        ("core:web", "Web UI / API", 94, 16, "active"),
        ("core:soar", "SOAR", 94, 73, "active"),
    ]
    for node_id, label, x, y, status in core_layout:
        nodes[node_id] = _node(node_id, "core_service", label, x=x, y=y, status=status)
    edges.extend(
        [
            _edge("core-ingest-transport", "core:ingest", "core:transport", "pipeline", label="events"),
            _edge("core-transport-processing", "core:transport", "core:processing", "pipeline", label="stream"),
            _edge("core-processing-storage", "core:processing", "core:storage", "pipeline", label="writes"),
            _edge("core-storage-web", "core:storage", "core:web", "query", label="analytics"),
            _edge("core-processing-soar", "core:processing", "core:soar", "response", label="alerts"),
        ]
    )

    collector_rows = collectors[:12]
    if not collector_rows:
        collector_rows = [{"collector_id": "collector-default", "name": "Default collector", "status": "unknown"}]
    for index, collector in enumerate(collector_rows):
        collector_id = str(collector.get("collector_id") or collector.get("name") or f"collector-{index}")
        node_id = f"collector:{_slug(collector_id, f'collector-{index}')}"
        nodes[node_id] = _node(
            node_id,
            "collector",
            str(collector.get("name") or collector_id),
            x=55,
            y=_spread(index, len(collector_rows), top=16, bottom=84),
            status=str(collector.get("status") or "unknown"),
            role=str(collector.get("role") or ""),
            events=_number(collector.get("events")),
            sources_count=_number(collector.get("sources_count")),
            protocols=list(collector.get("protocols") or []),
            href=f"/app/collectors?focus={collector_id}",
        )
        edges.append(_edge(f"{node_id}->ingest", node_id, "core:ingest", "ingest", events=_number(collector.get("events"))))

    collector_lookup = {
        str(item.get("collector_id") or "").strip(): f"collector:{_slug(item.get('collector_id') or item.get('name'))}"
        for item in collector_rows
    }
    candidate_rows = list(discovery.get("items") or [])[:18]
    fleet_rows = list(fleet.get("items") or [])[:22]
    identity_index = _build_identity_index(fleet_rows, candidate_rows)

    source_rows = sources[:26]
    for index, source in enumerate(source_rows):
        source_name = str(source.get("source_name") or f"source-{index}")
        node_id = f"source:{_slug(source_name, f'source-{index}')}"
        status = str(source.get("status") or "unknown")
        identity = _resolve_identity({**source, "source_name": source_name}, identity_index, default_hostname_prefix="source")
        source_kind = str(identity.get("source_kind") or "telemetry_source")
        source_type_label = str(identity.get("source_type_label") or _kind_label(source_kind))
        display_label = str(identity.get("display_label") or source_name)
        nodes[node_id] = _node(
            node_id,
            "source",
            display_label,
            x=38,
            y=_spread(index, max(1, len(source_rows)), top=12, bottom=88),
            status=status,
            role=str(source.get("source_type") or identity.get("entity_role") or source_type_label),
            source_name=source_name,
            hostname=str(identity.get("hostname") or display_label),
            display_label=display_label,
            ip=str(identity.get("ip") or ""),
            source_kind=source_kind,
            source_type_label=source_type_label,
            entity_role=str(identity.get("entity_role") or ""),
            platform_kind=str(identity.get("platform_kind") or ""),
            topology_lane=str(identity.get("topology_lane") or ""),
            identity_tokens=str(identity.get("identity_tokens") or ""),
            events=_number(source.get("events")),
            ti_hits=_number(source.get("ti_hits")),
            notable_events=_number(source.get("notable_events")),
            products=list(source.get("products") or []),
            categories=list(source.get("categories") or []),
            last_seen=str(source.get("last_seen") or ""),
            href=f"/app/sources?focus={source_name}",
        )
        collector_id = str(source.get("collector_id") or "").strip()
        target = collector_lookup.get(collector_id) or "core:ingest"
        edges.append(
            _edge(
                f"{node_id}->{target}",
                node_id,
                target,
                "source_binding",
                status=status,
                events=_number(source.get("events")),
            )
        )

    for index, attacker in enumerate(geo_sources[:16]):
        ip_text = str(attacker.get("ip") or "").strip()
        if not ip_text:
            continue
        node_id = f"external:{_slug(ip_text, f'external-{index}')}"
        hostname = str(attacker.get("hostname") or attacker.get("domain") or _hostname_from_ip(ip_text, prefix="external") or ip_text)
        nodes[node_id] = _node(
            node_id,
            "external_ip",
            hostname,
            x=5,
            y=_spread(index, min(len(geo_sources), 16), top=10, bottom=90),
            status=str(attacker.get("reputation") or "observed"),
            role="internet actor",
            ip=ip_text,
            hostname=hostname,
            display_label=hostname,
            source_kind="external_ip",
            source_type_label="External IP",
            entity_role="internet-actor",
            topology_lane="external",
            country=str(attacker.get("country") or "Unknown"),
            org=str(attacker.get("org") or ""),
            events=_number(attacker.get("events")),
            target_ports=str(attacker.get("target_ports") or ""),
            href=f"/app/dashboards?ip={ip_text}",
        )
        targets = [target for target in _csv_tokens(attacker.get("target_ips")) if target in public_targets]
        if not targets:
            edges.append(_edge(f"{node_id}->internet", node_id, "internet", "external_observation", events=_number(attacker.get("events"))))
        for target_ip in targets:
            target_id = f"public:{target_ip}"
            edges.append(
                _edge(
                    f"{node_id}->{target_id}",
                    node_id,
                    target_id,
                    "attack_observation",
                    events=_number(attacker.get("events")),
                    label=str(attacker.get("target_ports") or ""),
                )
            )

    unmanaged_candidates = [item for item in candidate_rows if not bool(item.get("connected"))]
    for index, candidate in enumerate(candidate_rows):
        ip_text = str(candidate.get("ip") or "")
        node_id = f"candidate:{_slug(candidate.get('id') or ip_text, f'candidate-{index}')}"
        status = "connected" if bool(candidate.get("connected")) else str(candidate.get("monitoring_status") or candidate.get("status") or "candidate")
        identity = _resolve_identity(candidate, identity_index, default_hostname_prefix="host")
        nodes[node_id] = _node(
            node_id,
            "discovery_candidate",
            str(identity.get("display_label") or candidate.get("hostname") or ip_text or candidate.get("id") or "candidate"),
            x=25,
            y=_spread(index, max(1, len(candidate_rows)), top=12, bottom=88),
            status=status,
            role=str(candidate.get("probable_role") or candidate.get("source_family") or identity.get("entity_role") or ""),
            ip=ip_text or str(identity.get("ip") or ""),
            hostname=str(identity.get("hostname") or ""),
            display_label=str(identity.get("display_label") or ""),
            source_kind=str(identity.get("source_kind") or "host"),
            source_type_label=str(identity.get("source_type_label") or "Host"),
            entity_role=str(identity.get("entity_role") or ""),
            topology_lane=str(identity.get("topology_lane") or "inventory"),
            identity_tokens=str(identity.get("identity_tokens") or ""),
            confidence=candidate.get("confidence"),
            port_summary=str(candidate.get("port_summary") or ""),
            href=f"/app/assets?view=unconnected&q={ip_text}",
        )
        if bool(candidate.get("connected")) and str(candidate.get("connected_source") or ""):
            source_id = f"source:{_slug(candidate.get('connected_source'))}"
            if source_id in nodes:
                edges.append(_edge(f"{node_id}->{source_id}", node_id, source_id, "discovery_binding", status="connected"))
        else:
            edges.append(_edge(f"{node_id}->core:ingest", node_id, "core:ingest", "needs_onboarding", status=status))

    for index, guest in enumerate(fleet_rows):
        name = str(guest.get("name") or guest.get("hostname") or guest.get("vmid") or f"guest-{index}")
        ip_text = str(guest.get("ip") or "")
        node_id = f"fleet:{_slug(guest.get('id') or name, f'fleet-{index}')}"
        status = "connected" if bool(guest.get("connected")) else str(guest.get("state") or "inventory")
        identity = _resolve_identity({**guest, "name": name}, identity_index, default_hostname_prefix="host")
        nodes[node_id] = _node(
            node_id,
            "proxmox_guest",
            str(identity.get("display_label") or name),
            x=25,
            y=_spread(index, max(1, len(fleet_rows)), top=12, bottom=88),
            status=status,
            role=str(guest.get("role") or guest.get("os_family") or guest.get("guest_type") or identity.get("entity_role") or ""),
            ip=ip_text or str(identity.get("ip") or ""),
            hostname=str(identity.get("hostname") or name),
            display_label=str(identity.get("display_label") or name),
            source_kind=str(identity.get("source_kind") or "proxmox_guest"),
            source_type_label=str(identity.get("source_type_label") or "Proxmox VM/CT"),
            entity_role=str(identity.get("entity_role") or ""),
            platform_kind=str(identity.get("platform_kind") or "proxmox_guest"),
            topology_lane=str(identity.get("topology_lane") or "inventory"),
            identity_tokens=str(identity.get("identity_tokens") or ""),
            host_runtime_enabled=bool(guest.get("host_runtime_enabled")),
            vuln_scannable=bool(guest.get("vuln_scannable")),
            href=f"/app/sources?view=fleet&q={ip_text or name}",
        )
        if bool(guest.get("connected")):
            source_name = str(guest.get("source_name") or guest.get("hostname") or name)
            source_id = f"source:{_slug(source_name)}"
            if source_id in nodes:
                edges.append(_edge(f"{node_id}->{source_id}", node_id, source_id, "fleet_source_binding", status="connected"))
        elif bool(guest.get("reachable")) or bool(guest.get("monitoring_supported")):
            edges.append(_edge(f"{node_id}->core:ingest", node_id, "core:ingest", "needs_onboarding", status=status))

    profile_index: dict[str, list[dict[str, Any]]] = {}
    for profile in host_access_profiles:
        for key in _profile_keys(profile):
            profile_index.setdefault(key, []).append(profile)
    for node in nodes.values():
        matches: dict[str, dict[str, Any]] = {}
        for key in _node_keys(node):
            for profile in profile_index.get(key, []):
                profile_id = str(profile.get("profile_id") or "")
                if profile_id:
                    matches[profile_id] = profile
        matched_profiles = list(matches.values())
        if matched_profiles:
            node["access_profile_count"] = len(matched_profiles)
            node["access_status"] = "configured" if any(str(item.get("secret_status") or "") in {"configured", "reference"} for item in matched_profiles) else "metadata-only"
            node["access_profiles"] = [_profile_summary(item) for item in matched_profiles[:4]]

    attention = [
        {
            "kind": "discovery",
            "id": str(item.get("id") or ""),
            "label": str(item.get("hostname") or item.get("ip") or item.get("id") or ""),
            "ip": str(item.get("ip") or ""),
            "reason": str(item.get("recommendation", {}).get("title") or item.get("monitoring_status") or "candidate"),
            "href": f"/app/assets?view=unconnected&q={item.get('ip') or item.get('hostname') or ''}",
        }
        for item in unmanaged_candidates[:12]
    ]
    attention.extend(
        {
            "kind": "fleet",
            "id": str(item.get("id") or item.get("vmid") or ""),
            "label": str(item.get("name") or item.get("hostname") or item.get("vmid") or ""),
            "ip": str(item.get("ip") or ""),
            "reason": "reachable guest without telemetry",
            "href": f"/app/sources?view=fleet&q={item.get('ip') or item.get('name') or ''}",
        }
        for item in fleet_rows
        if not bool(item.get("connected")) and (bool(item.get("reachable")) or bool(item.get("monitoring_supported")))
    )

    metrics = {
        "nodes": len(nodes),
        "edges": len(edges),
        "monitored_sources": len(source_rows),
        "active_sources": sum(1 for item in source_rows if str(item.get("status") or "") == "active"),
        "stale_sources": sum(1 for item in source_rows if str(item.get("status") or "") in {"stale", "delayed"}),
        "collectors": len(collector_rows),
        "external_attack_sources": len([node for node in nodes.values() if node.get("type") == "external_ip"]),
        "protected_target_hits": sum(1 for edge_item in edges if edge_item.get("type") == "attack_observation"),
        "discovery_candidates": len(candidate_rows),
        "unmanaged_candidates": len(unmanaged_candidates),
        "fleet_guests": len(fleet_rows),
        "fleet_unconnected": sum(1 for item in fleet_rows if not bool(item.get("connected"))),
        "host_access_profiles": len(host_access_profiles),
        "hosts_with_access_profiles": len(
            {
                _host_access_node_key(node)
                for node in nodes.values()
                if int(node.get("access_profile_count") or 0) > 0 and _host_access_node_key(node)
            }
        ),
    }
    packet_flows = _build_packet_flows(
        geo_sources=geo_sources[:16],
        source_rows=source_rows,
        collector_rows=collector_rows,
        candidate_rows=candidate_rows,
        fleet_rows=fleet_rows,
        protected_targets=public_targets,
    )

    return {
        "generated_ts": _now_iso(),
        "window_hours": safe_hours,
        "protected_public_ips": list(PROTECTED_PUBLIC_IPS),
        "metrics": metrics,
        "layers": [
            {"id": "external", "title": "External activity", "count": metrics["external_attack_sources"]},
            {"id": "inventory", "title": "Fleet and discovery", "count": len(candidate_rows) + len(fleet_rows)},
            {"id": "sources", "title": "Telemetry sources", "count": len(source_rows)},
            {"id": "collectors", "title": "Collectors", "count": len(collector_rows)},
            {"id": "core", "title": "SIEM core", "count": 6},
        ],
        "nodes": list(nodes.values()),
        "edges": edges,
        "packet_flows": packet_flows,
        "host_access_profiles": host_access_profiles[:safe_limit],
        "attention": attention[:20],
        "issues": issues,
    }
