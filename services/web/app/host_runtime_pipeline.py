from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_STALE_AFTER_SECONDS = 420
SERVICE_FLAP_WINDOW_SECONDS = 1800
SERVICE_FLAP_THRESHOLD = 3
DEFAULT_STATE_PATH = "/var/lib/siem-host-runtime/state.json"
DEFAULT_WATCHED_SERVICES: dict[str, list[str]] = {
    "ingest": ["siem-ingest", "nginx"],
    "processing": ["siem-normalizer", "siem-normalizer@2", "siem-filter", "siem-filter@2"],
    "storage": ["clickhouse-server", "siem-writer", "siem-writer@2", "siem-stream-corr", "siem-batch-corr", "siem-alert-agg"],
    "control-plane": ["siem-web", "nginx", "openvpn-client@home-gateway", "siem-jump-tunnels"],
    "transport": ["siem-kafka", "siem-normalizer@1", "siem-normalizer@2", "siem-filter@1", "siem-filter@2"],
}
HOST_ROLE_ALIASES = {
    "siem-ingest": "ingest",
    "siem-processing": "processing",
    "siem-storage": "storage",
    "siem-web": "control-plane",
    "siem-transport": "transport",
}
DEFAULT_THRESHOLDS: dict[str, float] = {
    "cpu_pct_high": 90.0,
    "memory_pct_high": 90.0,
    "disk_pct_high": 90.0,
    "load_ratio_high": 1.5,
    "swap_pct_high": 20.0,
    "inode_pct_high": 90.0,
    "storage_memory_pct_high": 85.0,
    "storage_disk_pct_high": 85.0,
    "control_plane_memory_pct_high": 80.0,
    "control_plane_cpu_pct_high": 85.0,
    "control_plane_load_ratio_high": 1.2,
}
LOAD_PRESSURE_RELEVANT_ROLES = {"control-plane", "storage", "processing", "ingest", "transport"}
DEFAULT_EVENT_POLICY: dict[str, dict[str, Any]] = {
    "host_cpu_pressure": {"suppression_seconds": 600, "escalate_after": 3},
    "host_memory_pressure": {"suppression_seconds": 600, "escalate_after": 2},
    "host_disk_pressure": {"suppression_seconds": 1800, "escalate_after": 2},
    "host_load_pressure": {"suppression_seconds": 600, "escalate_after": 3},
    "host_swap_pressure": {"suppression_seconds": 900, "escalate_after": 2},
    "host_inode_pressure": {"suppression_seconds": 1800, "escalate_after": 2},
    "host_storage_pressure": {"suppression_seconds": 900, "escalate_after": 2},
    "host_control_plane_pressure": {"suppression_seconds": 900, "escalate_after": 2},
    "host_service_flapping": {"suppression_seconds": 900, "escalate_after": 2},
    "host_telemetry_stale": {"suppression_seconds": 1800, "escalate_after": 1},
}
SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _memory_cache_bytes(meminfo: dict[str, int]) -> int:
    cached = max(meminfo.get("Cached", 0), 0)
    buffers = max(meminfo.get("Buffers", 0), 0)
    reclaimable = max(meminfo.get("SReclaimable", 0), 0)
    shmem = max(meminfo.get("Shmem", 0), 0)
    return max(cached + buffers + reclaimable - shmem, 0)


def _memory_pressure_status(metrics: dict[str, Any], host_role: str, rules: dict[str, float] | None = None) -> str:
    active_rules = {**DEFAULT_THRESHOLDS, **dict(rules or {})}
    used_pct = _safe_float(metrics.get("memory_used_pct"))
    available_pct = _safe_float(metrics.get("memory_available_pct"))
    swap_pct = _safe_float(metrics.get("swap_used_pct"))
    available_bytes = _safe_float(metrics.get("memory_available_bytes"))
    storage_mode = str(host_role or "").strip().lower() == "storage"

    if available_pct <= 0 and available_bytes <= 0:
        if used_pct >= active_rules["memory_pct_high"] and swap_pct >= max(active_rules["swap_pct_high"] - 5.0, 5.0):
            return "critical"
        if used_pct >= active_rules["memory_pct_high"]:
            return "high"
        if used_pct >= max(active_rules["memory_pct_high"] - 5.0, 75.0):
            return "warning"
        return "healthy"

    critical_available_pct = 4.0 if storage_mode else 6.0
    warning_available_pct = 12.0 if storage_mode else 15.0
    swap_high_pct = max(active_rules["swap_pct_high"], 20.0)
    swap_critical_pct = max(swap_high_pct + 10.0, 30.0)
    if available_pct <= critical_available_pct:
        return "critical"
    if swap_pct >= swap_critical_pct and (available_pct <= warning_available_pct or used_pct >= active_rules["memory_pct_high"]):
        return "critical"
    if available_pct <= warning_available_pct:
        return "high"
    if swap_pct >= swap_high_pct and (available_pct <= warning_available_pct + 5.0 or used_pct >= max(active_rules["memory_pct_high"] - 5.0, 75.0)):
        return "high"
    if used_pct >= active_rules["memory_pct_high"] and available_pct > warning_available_pct and swap_pct < 5.0:
        return "cache-heavy"
    return "healthy"


def _severity_rank(value: str) -> int:
    safe = str(value or "info").strip().lower()
    return SEVERITY_ORDER.index(safe) if safe in SEVERITY_ORDER else 0


def _escalate_severity(value: str, *, steps: int = 1) -> str:
    index = min(len(SEVERITY_ORDER) - 1, _severity_rank(value) + max(0, int(steps)))
    return SEVERITY_ORDER[index]


def _normalize_policy(policy: dict[str, Any] | None) -> dict[str, Any]:
    raw = dict(policy or {})
    overrides = {}
    for key, value in dict(raw.get("event_overrides") or {}).items():
        if not isinstance(value, dict):
            continue
        overrides[str(key)] = {
            "suppression_seconds": max(0, _safe_int(value.get("suppression_seconds"), 0)),
            "escalate_after": max(1, _safe_int(value.get("escalate_after"), 1)),
            "severity": str(value.get("severity") or "").strip().lower(),
        }
    return {"event_overrides": {**DEFAULT_EVENT_POLICY, **overrides}}


def _event_policy(policy: dict[str, Any], event_type: str) -> dict[str, Any]:
    return dict((policy.get("event_overrides") or {}).get(str(event_type or ""), {}))


def _event_fingerprint(event: dict[str, Any]) -> str:
    details = dict(event.get("details") or {})
    service = str(details.get("service") or "").strip().lower()
    return "|".join(
        [
            str(event.get("host.name") or "").strip().lower(),
            str(event.get("event.type") or "").strip().lower(),
            service,
        ]
    )


def _apply_event_policy(events: list[dict[str, Any]], state: dict[str, Any], *, policy: dict[str, Any], now_epoch: float) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    suppression_state = state.setdefault("suppression", {})
    counters = state.setdefault("event_counters", {})
    published: list[dict[str, Any]] = []
    for event in events:
        event_type = str(event.get("event.type") or "").strip()
        policy_item = _event_policy(policy, event_type)
        fingerprint = _event_fingerprint(event)
        suppression_seconds = max(0, _safe_int(policy_item.get("suppression_seconds"), 0))
        last_emitted_epoch = _safe_float(dict(suppression_state.get(fingerprint) or {}).get("last_emitted_epoch"), 0.0)
        if suppression_seconds and last_emitted_epoch and (now_epoch - last_emitted_epoch) < suppression_seconds:
            continue
        counter = dict(counters.get(fingerprint) or {})
        recent_epochs = [float(item) for item in list(counter.get("epochs") or []) if now_epoch - float(item) <= max(suppression_seconds, 1800)]
        recent_epochs.append(now_epoch)
        counters[fingerprint] = {"epochs": recent_epochs}
        severity_override = str(policy_item.get("severity") or "").strip().lower()
        if severity_override in SEVERITY_ORDER:
            event["severity"] = severity_override
        escalate_after = max(1, _safe_int(policy_item.get("escalate_after"), 1))
        if len(recent_epochs) >= escalate_after:
            event["severity"] = _escalate_severity(str(event.get("severity") or "medium"), steps=1)
            details = dict(event.get("details") or {})
            details["escalated"] = True
            details["escalation_hits"] = len(recent_epochs)
            event["details"] = details
        suppression_state[fingerprint] = {"last_emitted_epoch": now_epoch, "last_event_type": event_type}
        published.append(event)
    return published, state


def _load_meminfo(text: str) -> dict[str, int]:
    payload: dict[str, int] = {}
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        key, raw_value = line.split(":", 1)
        value = raw_value.strip().split()[0] if raw_value.strip() else "0"
        payload[key.strip()] = _safe_int(value, 0) * 1024
    return payload


def _cpu_times() -> tuple[int, int]:
    raw = Path("/proc/stat").read_text(encoding="utf-8", errors="replace").splitlines()[0]
    parts = raw.split()
    values = [_safe_int(item, 0) for item in parts[1:]]
    idle = values[3] + values[4] if len(values) > 4 else values[3]
    total = sum(values)
    return total, idle


def _cpu_usage_percent(sample_seconds: float = 0.15) -> float:
    total_1, idle_1 = _cpu_times()
    time.sleep(max(0.05, min(sample_seconds, 0.5)))
    total_2, idle_2 = _cpu_times()
    total_delta = max(total_2 - total_1, 1)
    idle_delta = max(idle_2 - idle_1, 0)
    busy_delta = max(total_delta - idle_delta, 0)
    return round((busy_delta / total_delta) * 100.0, 1)


def _detect_primary_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return str(sock.getsockname()[0] or "")
    except OSError:
        return ""


def _service_status(service_name: str) -> dict[str, Any]:
    command = ["systemctl", "show", service_name, "--property=ActiveState,SubState,Result", "--no-page"]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    payload = {"name": str(service_name), "active_state": "unknown", "sub_state": "", "result": "", "status": "unknown"}
    if completed.returncode != 0:
        payload["status"] = "not-found"
        return payload
    for raw_line in str(completed.stdout or "").splitlines():
        if "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key == "ActiveState":
            payload["active_state"] = value.lower()
        elif key == "SubState":
            payload["sub_state"] = value.lower()
        elif key == "Result":
            payload["result"] = value.lower()
    active_state = str(payload.get("active_state") or "").lower()
    payload["status"] = "active" if active_state == "active" else active_state or "unknown"
    return payload


def _service_transition_counts_as_flap(previous_status: str, current_status: str) -> bool:
    stable_statuses = {"active", "inactive"}
    previous = str(previous_status or "").strip().lower()
    current = str(current_status or "").strip().lower()
    if not previous or previous == current:
        return False
    return previous not in stable_statuses or current not in stable_statuses


def normalize_host_role(host_name: str, requested_role: str = "") -> str:
    safe_role = str(requested_role or "").strip().lower()
    if safe_role:
        return safe_role
    return HOST_ROLE_ALIASES.get(str(host_name or "").strip().lower(), "generic")


def resolve_watched_services(host_role: str, raw_services: list[str] | str | None = None) -> list[str]:
    if isinstance(raw_services, str):
        values = [item.strip() for item in raw_services.split(",") if item.strip()]
        if values:
            return values
    if isinstance(raw_services, list):
        values = [str(item).strip() for item in raw_services if str(item).strip()]
        if values:
            return values
    return list(DEFAULT_WATCHED_SERVICES.get(str(host_role or "").strip().lower(), []))


def collect_local_snapshot(*, host_name: str = "", host_role: str = "", watched_services: list[str] | None = None) -> dict[str, Any]:
    resolved_host = str(host_name or socket.gethostname() or "").strip()
    resolved_role = normalize_host_role(resolved_host, host_role)
    services = resolve_watched_services(resolved_role, watched_services)
    meminfo = _load_meminfo(Path("/proc/meminfo").read_text(encoding="utf-8", errors="replace"))
    total_memory = max(meminfo.get("MemTotal", 0), 1)
    available_memory = max(meminfo.get("MemAvailable", 0), 0)
    cache_memory = _memory_cache_bytes(meminfo)
    used_memory = max(total_memory - available_memory, 0)
    swap_total = max(meminfo.get("SwapTotal", 0), 0)
    swap_free = max(meminfo.get("SwapFree", 0), 0)
    swap_used = max(swap_total - swap_free, 0)
    disk_usage = shutil.disk_usage("/")
    statvfs = os.statvfs("/")
    inode_total = int(statvfs.f_files or 0)
    inode_free = int(statvfs.f_ffree or 0)
    inode_used = max(inode_total - inode_free, 0)
    cpu_count = max(int(os.cpu_count() or 1), 1)
    load1, load5, load15 = os.getloadavg()
    service_rows = [_service_status(name) for name in services]
    failed_services = [item for item in service_rows if str(item.get("status") or "") not in {"active", "inactive"}]
    primary_ip = _detect_primary_ip()
    snapshot = {
        "generated_ts": _now_iso(),
        "host_name": resolved_host,
        "host_role": resolved_role,
        "primary_ip": primary_ip,
        "metrics": {
            "cpu_pct": _cpu_usage_percent(),
            "cpu_count": cpu_count,
            "memory_total_bytes": total_memory,
            "memory_available_bytes": available_memory,
            "memory_available_pct": round((available_memory / total_memory) * 100.0, 1),
            "memory_cache_bytes": cache_memory,
            "memory_cache_pct": round((cache_memory / total_memory) * 100.0, 1),
            "memory_used_bytes": used_memory,
            "memory_used_pct": round((used_memory / total_memory) * 100.0, 1),
            "swap_total_bytes": swap_total,
            "swap_used_bytes": swap_used,
            "swap_used_pct": round((swap_used / swap_total) * 100.0, 1) if swap_total else 0.0,
            "disk_total_bytes": int(disk_usage.total),
            "disk_used_bytes": int(disk_usage.used),
            "disk_free_bytes": int(disk_usage.free),
            "disk_used_pct": round((disk_usage.used / max(int(disk_usage.total), 1)) * 100.0, 1),
            "inode_total": inode_total,
            "inode_used": inode_used,
            "inode_used_pct": round((inode_used / max(inode_total, 1)) * 100.0, 1) if inode_total else 0.0,
            "load_1": round(load1, 3),
            "load_5": round(load5, 3),
            "load_15": round(load15, 3),
            "load_ratio": round(load1 / cpu_count, 3),
            "failed_services_total": len(failed_services),
        },
        "services": service_rows,
    }
    snapshot["metrics"]["memory_pressure_status"] = _memory_pressure_status(snapshot["metrics"], resolved_role)
    return snapshot


def load_state(path: str) -> dict[str, Any]:
    state_path = Path(path)
    if not state_path.exists():
        return {"hosts": {}, "services": {}, "stale": {}}
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"hosts": {}, "services": {}, "stale": {}}
    if not isinstance(payload, dict):
        return {"hosts": {}, "services": {}, "stale": {}}
    payload.setdefault("hosts", {})
    payload.setdefault("services", {})
    payload.setdefault("stale", {})
    return payload


def save_state(path: str, payload: dict[str, Any]) -> None:
    state_path = Path(path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _base_event(snapshot: dict[str, Any], *, event_type: str, severity: str, message: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    details = dict(details or {})
    host_name = str(snapshot.get("host_name") or "")
    host_role = str(snapshot.get("host_role") or "generic")
    host_ip = str(snapshot.get("primary_ip") or "")
    return {
        "ts": str(snapshot.get("generated_ts") or _now_iso()),
        "source": host_name,
        "source_type": "platform_host_runtime",
        "collector": "host_runtime_agent",
        "collector_profile": host_role,
        "ingest_profile": "host-runtime",
        "ingest_path": "/host-runtime",
        "event.dataset": "host-runtime",
        "event.provider": "host.metrics",
        "event.category": "platform_health",
        "event.type": str(event_type),
        "event.action": "observe",
        "event.outcome": "success" if severity in {"info", "low"} else "warning",
        "host.name": host_name,
        "host.role": host_role,
        "host.ip": host_ip,
        "host": {"name": host_name, "role": host_role, "ip": host_ip},
        "log_source": host_name,
        "severity": str(severity),
        "message": str(message),
        "tags": ["host-runtime", "platform-health", str(event_type)],
        "metrics": dict(snapshot.get("metrics") or {}),
        "services": list(snapshot.get("services") or []),
        "details": details,
    }


def build_snapshot_event(snapshot: dict[str, Any]) -> dict[str, Any]:
    return _base_event(
        snapshot,
        event_type="host_runtime_snapshot",
        severity="info",
        message=f"Host runtime snapshot collected for {snapshot.get('host_name')}",
        details={"heartbeat": True},
    )


def evaluate_snapshot(
    snapshot: dict[str, Any],
    state: dict[str, Any] | None = None,
    *,
    thresholds: dict[str, float] | None = None,
    policy: dict[str, Any] | None = None,
    now_epoch: float | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    active_state = json.loads(json.dumps(state or {"hosts": {}, "services": {}, "stale": {}}))
    rules = {**DEFAULT_THRESHOLDS, **dict(thresholds or {})}
    host_name = str(snapshot.get("host_name") or "")
    host_role = str(snapshot.get("host_role") or "generic")
    metrics = dict(snapshot.get("metrics") or {})
    now_value = float(now_epoch if now_epoch is not None else time.time())
    alerts: list[dict[str, Any]] = []

    cpu_pct = _safe_float(metrics.get("cpu_pct"))
    mem_pct = _safe_float(metrics.get("memory_used_pct"))
    mem_available_pct = _safe_float(metrics.get("memory_available_pct"))
    disk_pct = _safe_float(metrics.get("disk_used_pct"))
    load_ratio = _safe_float(metrics.get("load_ratio"))
    swap_pct = _safe_float(metrics.get("swap_used_pct"))
    inode_pct = _safe_float(metrics.get("inode_used_pct"))
    failed_services_total = _safe_int(metrics.get("failed_services_total"), 0)
    memory_pressure_status = str(metrics.get("memory_pressure_status") or _memory_pressure_status(metrics, host_role, rules)).strip().lower() or "healthy"
    load_ratio_high = _safe_float(rules.get("load_ratio_high"), DEFAULT_THRESHOLDS["load_ratio_high"])
    load_signal_threshold = max(rules["cpu_pct_high"] - 20.0, 70.0)
    load_is_material = (
        cpu_pct >= load_signal_threshold
        or memory_pressure_status in {"high", "critical"}
        or failed_services_total > 0
        or host_role in LOAD_PRESSURE_RELEVANT_ROLES
    )

    if cpu_pct >= rules["cpu_pct_high"]:
        alerts.append(_base_event(snapshot, event_type="host_cpu_pressure", severity="high", message=f"CPU pressure on {host_name}: {cpu_pct:.1f}%"))
    if memory_pressure_status in {"high", "critical"}:
        alerts.append(
            _base_event(
                snapshot,
                event_type="host_memory_pressure",
                severity="high" if memory_pressure_status == "critical" else "medium",
                message=f"Memory pressure on {host_name}: {mem_pct:.1f}% used, {mem_available_pct:.1f}% available",
                details={"memory_pressure_status": memory_pressure_status},
            )
        )
    if disk_pct >= rules["disk_pct_high"]:
        alerts.append(_base_event(snapshot, event_type="host_disk_pressure", severity="high", message=f"Disk pressure on {host_name}: {disk_pct:.1f}%"))
    if load_ratio >= load_ratio_high and load_is_material:
        alerts.append(
            _base_event(
                snapshot,
                event_type="host_load_pressure",
                severity="medium",
                message=f"Load pressure on {host_name}: load ratio {load_ratio:.2f}",
                details={
                    "cpu_pct": cpu_pct,
                    "memory_pressure_status": memory_pressure_status,
                    "failed_services_total": failed_services_total,
                    "host_role": host_role,
                },
            )
        )
    if swap_pct >= rules["swap_pct_high"] and memory_pressure_status in {"high", "critical"}:
        alerts.append(_base_event(snapshot, event_type="host_swap_pressure", severity="high", message=f"Swap thrash on {host_name}: {swap_pct:.1f}% used"))
    if inode_pct >= rules["inode_pct_high"]:
        alerts.append(_base_event(snapshot, event_type="host_inode_pressure", severity="medium", message=f"Inode pressure on {host_name}: {inode_pct:.1f}% used"))
    if host_role == "storage" and (memory_pressure_status in {"high", "critical"} or disk_pct >= rules["storage_disk_pct_high"]):
        alerts.append(_base_event(snapshot, event_type="host_storage_pressure", severity="high", message=f"Storage node pressure on {host_name}"))
    if host_role == "control-plane" and (
        memory_pressure_status in {"high", "critical"}
        or cpu_pct >= rules["control_plane_cpu_pct_high"]
        or load_ratio >= rules["control_plane_load_ratio_high"]
    ):
        alerts.append(_base_event(snapshot, event_type="host_control_plane_pressure", severity="medium", message=f"Control-plane pressure on {host_name}"))

    service_state = active_state.setdefault("services", {}).setdefault(host_name, {})
    for service in snapshot.get("services") or []:
        service_name = str(service.get("name") or "").strip()
        if not service_name:
            continue
        previous = dict(service_state.get(service_name) or {})
        current_status = str(service.get("status") or "unknown")
        change_epochs = [float(item) for item in (previous.get("change_epochs") or []) if _safe_float(item) > 0]
        if previous and _service_transition_counts_as_flap(str(previous.get("status") or ""), current_status):
            change_epochs.append(now_value)
        if previous and str(previous.get("status") or "") == "active" and current_status != "active":
            alerts.append(
                _base_event(
                    snapshot,
                    event_type="host_service_down",
                    severity="high",
                    message=f"Service stopped on {host_name}: {service_name} ({current_status})",
                    details={
                        "service": service_name,
                        "status": current_status,
                        "result": str(service.get("result") or ""),
                    },
                )
            )
        change_epochs = [epoch for epoch in change_epochs if now_value - epoch <= SERVICE_FLAP_WINDOW_SECONDS]
        service_state[service_name] = {"status": current_status, "change_epochs": change_epochs}
        if len(change_epochs) >= SERVICE_FLAP_THRESHOLD:
            alerts.append(
                _base_event(
                    snapshot,
                    event_type="host_service_flapping",
                    severity="medium",
                    message=f"Service flapping on {host_name}: {service_name}",
                    details={"service": service_name, "changes_window": len(change_epochs)},
                )
            )

    active_state.setdefault("hosts", {})[host_name] = {
        "last_snapshot_ts": str(snapshot.get("generated_ts") or _now_iso()),
        "host_role": host_role,
        "primary_ip": str(snapshot.get("primary_ip") or ""),
        "metrics": metrics,
    }
    active_state.setdefault("stale", {}).pop(host_name, None)
    normalized_policy = _normalize_policy(policy)
    filtered_alerts, active_state = _apply_event_policy(alerts, active_state, policy=normalized_policy, now_epoch=now_value)
    return filtered_alerts, active_state


def build_stale_events(
    *,
    expected_hosts: list[dict[str, Any]],
    last_seen: dict[str, str],
    state: dict[str, Any] | None = None,
    stale_after_seconds: int = DEFAULT_STALE_AFTER_SECONDS,
    policy: dict[str, Any] | None = None,
    now_epoch: float | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    active_state = json.loads(json.dumps(state or {"hosts": {}, "services": {}, "stale": {}}))
    stale_state = active_state.setdefault("stale", {})
    now_value = float(now_epoch if now_epoch is not None else time.time())
    events: list[dict[str, Any]] = []
    for item in expected_hosts:
        host_name = str(item.get("host_name") or "").strip()
        if not host_name:
            continue
        safe_role = normalize_host_role(host_name, str(item.get("host_role") or ""))
        last_seen_ts = str(last_seen.get(host_name) or "").strip()
        if last_seen_ts:
            try:
                last_seen_epoch = datetime.fromisoformat(last_seen_ts.replace("Z", "+00:00")).timestamp()
            except ValueError:
                last_seen_epoch = 0.0
        else:
            last_seen_epoch = 0.0
        age_seconds = int(now_value - last_seen_epoch) if last_seen_epoch else stale_after_seconds + 1
        if age_seconds <= stale_after_seconds:
            stale_state.pop(host_name, None)
            continue
        if stale_state.get(host_name):
            continue
        snapshot = {
            "generated_ts": _now_iso(),
            "host_name": host_name,
            "host_role": safe_role,
            "primary_ip": str(item.get("host_ip") or ""),
            "metrics": {"stale_age_seconds": age_seconds},
            "services": [],
        }
        events.append(
            _base_event(
                snapshot,
                event_type="host_telemetry_stale",
                severity="high",
                message=f"Telemetry stale for {host_name}: last heartbeat {age_seconds}s ago",
                details={"last_seen_ts": last_seen_ts, "stale_after_seconds": int(stale_after_seconds)},
            )
        )
        stale_state[host_name] = {"emitted_ts": snapshot["generated_ts"], "last_seen_ts": last_seen_ts}
    normalized_policy = _normalize_policy(policy)
    filtered_events, active_state = _apply_event_policy(events, active_state, policy=normalized_policy, now_epoch=now_value)
    return filtered_events, active_state
