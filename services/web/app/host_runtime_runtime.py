from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime, timezone
import ipaddress
from pathlib import Path
from typing import Any

try:
    from .clickhouse_runtime import get_clickhouse_client
except Exception:  # noqa: BLE001
    from clickhouse_runtime import get_clickhouse_client  # type: ignore[no-redef]

try:
    from .host_runtime_pipeline import (
        DEFAULT_EVENT_POLICY,
        DEFAULT_STALE_AFTER_SECONDS,
        DEFAULT_THRESHOLDS,
        HOST_ROLE_ALIASES,
    )
except Exception:  # noqa: BLE001
    from host_runtime_pipeline import (  # type: ignore[no-redef]
        DEFAULT_EVENT_POLICY,
        DEFAULT_STALE_AFTER_SECONDS,
        DEFAULT_THRESHOLDS,
        HOST_ROLE_ALIASES,
    )
try:
    from .proxmox_fleet_runtime import list_proxmox_fleet_inventory
except Exception:  # noqa: BLE001
    try:
        from proxmox_fleet_runtime import list_proxmox_fleet_inventory  # type: ignore[no-redef]
    except Exception:  # noqa: BLE001
        list_proxmox_fleet_inventory = None  # type: ignore[assignment]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _utc_now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_host_runtime_policy() -> dict[str, Any]:
    default_path = Path(__file__).resolve().parents[3] / "correlation_rule_packs" / "host_runtime_policy_v1.json"
    path = Path(str(os.getenv("SIEM_HOST_RUNTIME_POLICY_PATH") or default_path))
    configured: dict[str, Any] = {}
    load_error = ""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            configured = payload
        else:
            load_error = "policy root must be an object"
    except (OSError, json.JSONDecodeError) as exc:
        load_error = str(exc)
    overrides: dict[str, dict[str, Any]] = {
        key: dict(value)
        for key, value in DEFAULT_EVENT_POLICY.items()
    }
    for key, value in dict(configured.get("event_overrides") or {}).items():
        if isinstance(value, dict):
            overrides[str(key)] = {**overrides.get(str(key), {}), **value}
    thresholds = {
        **DEFAULT_THRESHOLDS,
        **{
            str(key): value
            for key, value in dict(configured.get("thresholds") or {}).items()
            if isinstance(value, (int, float))
        },
    }
    return {
        "version": str(configured.get("version") or "host-runtime-defaults"),
        "loaded": not bool(load_error),
        "load_error": load_error,
        "event_overrides": overrides,
        "thresholds": thresholds,
    }


def _parse_iso8601(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _stale_age_seconds(last_seen_ts: str, *, now: datetime) -> int | None:
    parsed = _parse_iso8601(last_seen_ts)
    if parsed is None:
        return None
    return max(0, int((now - parsed).total_seconds()))


def _safe_float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _nested_text(container: dict[str, Any] | None, *keys: str) -> str:
    current: Any = container or {}
    for key in keys:
        if not isinstance(current, dict):
            return ""
        current = current.get(key)
    return str(current or "").strip()


def _is_ip_text(value: Any) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _normalize_runtime_row(row: dict[str, Any]) -> dict[str, Any]:
    normalized_text = str(row.get("normalized_json") or "").strip()
    payload: dict[str, Any] = {}
    if normalized_text:
        try:
            parsed = json.loads(normalized_text)
        except json.JSONDecodeError:
            parsed = {}
        if isinstance(parsed, dict):
            payload = parsed
    host_payload = payload.get("host") if isinstance(payload.get("host"), dict) else {}
    event_payload = payload.get("event") if isinstance(payload.get("event"), dict) else {}
    source_payload = payload.get("source") if isinstance(payload.get("source"), dict) else {}
    metrics_payload = payload.get("metrics") if isinstance(payload.get("metrics"), dict) else {}
    services_payload = payload.get("services") if isinstance(payload.get("services"), list) else []

    host_name = (
        _nested_text(host_payload, "name")
        or str(payload.get("host.name") or "").strip()
        or str(row.get("host_name") or "").strip()
        or str(payload.get("host") or "").strip()
    )
    host_role = (
        _nested_text(host_payload, "role")
        or str(payload.get("host.role") or "").strip()
        or str(row.get("host_role") or "").strip()
        or HOST_ROLE_ALIASES.get(host_name.lower(), "generic")
    )
    host_ip = (
        _nested_text(host_payload, "ip")
        or str(payload.get("host.ip") or "").strip()
        or str(row.get("host_ip") or "").strip()
        or _nested_text(source_payload, "ip")
        or str(payload.get("source.ip") or "").strip()
    )
    event_type = _nested_text(event_payload, "type") or str(row.get("event_type") or "").strip() or str(payload.get("type") or "").strip()

    normalized = {
        "ts": str(row.get("ts") or ""),
        "message": str(row.get("message") or payload.get("message") or ""),
        "severity": str(row.get("severity") or ""),
        "host_name": host_name,
        "host_role": host_role,
        "host_ip": host_ip,
        "event_type": event_type,
        "metrics": dict(metrics_payload),
        "services": list(services_payload),
        "cpu_pct": _safe_float(metrics_payload.get("cpu_pct", row.get("cpu_pct"))),
        "memory_used_pct": _safe_float(metrics_payload.get("memory_used_pct", row.get("memory_used_pct"))),
        "memory_available_bytes": _safe_float(metrics_payload.get("memory_available_bytes", row.get("memory_available_bytes"))),
        "memory_available_pct": _safe_float(metrics_payload.get("memory_available_pct", row.get("memory_available_pct"))),
        "memory_cache_bytes": _safe_float(metrics_payload.get("memory_cache_bytes", row.get("memory_cache_bytes"))),
        "memory_cache_pct": _safe_float(metrics_payload.get("memory_cache_pct", row.get("memory_cache_pct"))),
        "disk_used_pct": _safe_float(metrics_payload.get("disk_used_pct", row.get("disk_used_pct"))),
        "load_ratio": _safe_float(metrics_payload.get("load_ratio", row.get("load_ratio"))),
        "swap_used_pct": _safe_float(metrics_payload.get("swap_used_pct", row.get("swap_used_pct"))),
        "memory_pressure_status": str(metrics_payload.get("memory_pressure_status", row.get("memory_pressure_status")) or ""),
        "inode_used_pct": _safe_float(metrics_payload.get("inode_used_pct", row.get("inode_used_pct"))),
        "stale_age_seconds": _safe_float(metrics_payload.get("stale_age_seconds", row.get("stale_age_seconds"))),
    }
    return normalized


def _snapshot_has_runtime_data(row: dict[str, Any]) -> bool:
    metrics = row.get("metrics")
    if isinstance(metrics, dict) and metrics:
        return True
    services = row.get("services")
    if isinstance(services, list) and services:
        return True
    return any(
        _safe_float(row.get(key)) > 0
        for key in ("cpu_pct", "memory_used_pct", "disk_used_pct", "load_ratio", "swap_used_pct", "inode_used_pct")
    )


def _merge_snapshot_payload(primary: dict[str, Any], fallback: dict[str, Any]) -> dict[str, Any]:
    merged = dict(primary)
    fallback_metrics = dict(fallback.get("metrics") or {})
    primary_metrics = dict(primary.get("metrics") or {})
    merged["metrics"] = {**fallback_metrics, **primary_metrics}
    merged["services"] = list(primary.get("services") or fallback.get("services") or [])
    for key in ("cpu_pct", "memory_used_pct", "memory_available_pct", "disk_used_pct", "load_ratio", "swap_used_pct", "inode_used_pct"):
        if _safe_float(merged.get(key)) <= 0 and _safe_float(fallback.get(key)) > 0:
            merged[key] = _safe_float(fallback.get(key))
    if not str(merged.get("memory_pressure_status") or "").strip():
        merged["memory_pressure_status"] = str(fallback.get("memory_pressure_status") or "").strip()
    return merged


def host_runtime_targets_from_env(env: dict[str, str] | None = None) -> list[dict[str, Any]]:
    env_map = env or os.environ
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    retired_targets = {
        item.strip().lower()
        for item in str(
            env_map.get("SIEM_HOST_RUNTIME_RETIRED_TARGETS", "openclaw-gateway") or ""
        ).split(",")
        if item.strip()
    }

    def add_target(item: dict[str, Any]) -> None:
        host_name = str(item.get("host_name") or item.get("name") or item.get("source_name") or "").strip()
        if not host_name:
            return
        if host_name.lower() in retired_targets:
            return
        if item.get("monitoring_supported") is False:
            return
        key = host_name.lower()
        if key in seen:
            return
        seen.add(key)
        merged.append(
            {
                "host_name": host_name,
                "host_role": str(item.get("host_role") or item.get("role") or HOST_ROLE_ALIASES.get(host_name.lower(), "generic")),
                "host_ip": str(item.get("host_ip") or item.get("ip") or ""),
            }
        )

    raw = str(env_map.get("SIEM_HOST_RUNTIME_TARGETS_JSON") or "").strip()
    if raw:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = []
        if isinstance(payload, list):
            for item in payload:
                if not isinstance(item, dict):
                    continue
                add_target(item)
    defaults = [
        {"host_name": "siem-ingest", "host_role": "ingest", "host_ip": "10.20.10.104"},
        {"host_name": "siem-processing", "host_role": "processing", "host_ip": "10.20.10.105"},
        {"host_name": "siem-storage", "host_role": "storage", "host_ip": "10.20.10.106"},
        {"host_name": "siem-web", "host_role": "control-plane", "host_ip": "10.20.10.107"},
        {"host_name": "siem-transport", "host_role": "transport", "host_ip": "10.20.10.108"},
    ]
    include_fleet = str(env_map.get("SIEM_HOST_RUNTIME_INCLUDE_FLEET", "1") or "1").strip().lower() not in {"0", "false", "no", "off"}
    for item in defaults:
        add_target(item)
    if not include_fleet or list_proxmox_fleet_inventory is None:
        return merged or defaults
    fleet_rows: list[dict[str, Any]] = []
    try:
        fleet_payload = list_proxmox_fleet_inventory(limit=200)
        fleet_rows = list(fleet_payload.get("items") or [])
    except Exception:  # noqa: BLE001
        fleet_rows = []
    for item in fleet_rows:
        state = str(item.get("state") or "").strip().lower()
        if state in {"offline", "unsupported", "inventory-only"}:
            continue
        if item.get("monitoring_supported") is False:
            continue
        if not bool(item.get("host_runtime_enabled", item.get("monitoring_enabled", False))):
            continue
        add_target(item)
    return merged


def _event_rows(hours: int = 24, limit: int = 2000) -> list[dict[str, Any]]:
    safe_hours = max(1, min(168, int(hours or 24)))
    safe_limit = max(100, min(5000, int(limit or 2000)))
    query = f"""
        SELECT
            ts,
            message,
            severity,
            normalized_json
        FROM siem.events
        WHERE ts >= now() - INTERVAL {safe_hours} HOUR
          AND category = 'platform_health'
          AND device_vendor = 'host.metrics'
          AND device_product = 'host.metrics'
        ORDER BY ts DESC
        LIMIT {safe_limit}
    """
    rows: list[dict[str, Any]] = []
    for row in get_clickhouse_client().query(query).named_results():
        rows.append(_normalize_runtime_row(row))
    return rows


def fetch_host_runtime_last_seen_map(*, hours: int = 24) -> dict[str, str]:
    rows = _event_rows(hours=hours, limit=2000)
    latest: dict[str, str] = {}
    for row in rows:
        if str(row.get("event_type") or "") != "host_runtime_snapshot":
            continue
        host_name = str(row.get("host_name") or "").strip()
        if not host_name or host_name in latest:
            continue
        latest[host_name] = str(row.get("ts") or "")
    return latest


def fetch_host_runtime_overview(*, hours: int = 24, limit: int = 50) -> dict[str, Any]:
    rows = _event_rows(hours=hours, limit=max(200, limit * 30))
    latest_snapshots: dict[str, dict[str, Any]] = {}
    latest_rich_snapshots: dict[str, dict[str, Any]] = {}
    alerts: list[dict[str, Any]] = []
    type_counts = Counter()
    for row in rows:
        event_type = str(row.get("event_type") or "")
        host_name = str(row.get("host_name") or "").strip()
        type_counts[event_type] += 1
        if event_type == "host_runtime_snapshot" and host_name:
            if host_name not in latest_snapshots:
                latest_snapshots[host_name] = row
            if _snapshot_has_runtime_data(row) and host_name not in latest_rich_snapshots:
                latest_rich_snapshots[host_name] = row
        elif event_type != "host_runtime_snapshot":
            alerts.append(row)
    for host_name, snapshot in list(latest_snapshots.items()):
        if _snapshot_has_runtime_data(snapshot):
            continue
        fallback = latest_rich_snapshots.get(host_name)
        if fallback:
            latest_snapshots[host_name] = _merge_snapshot_payload(snapshot, fallback)
    targets = host_runtime_targets_from_env()
    last_seen_map = {host: str(item.get("ts") or "") for host, item in latest_snapshots.items()}
    stale_after = max(60, min(3600, int(os.getenv("SIEM_HOST_RUNTIME_STALE_AFTER_SECONDS", str(DEFAULT_STALE_AFTER_SECONDS)) or DEFAULT_STALE_AFTER_SECONDS)))
    now = _utc_now()
    target_rows = []
    for item in targets:
        host_name = str(item.get("host_name") or "")
        last_snapshot = latest_snapshots.get(host_name)
        last_seen_ts = last_seen_map.get(host_name, "")
        stale_age = _stale_age_seconds(last_seen_ts, now=now)
        stale = stale_age is None or stale_age > stale_after
        target_rows.append(
            {
                "host_name": host_name,
                "host_role": str(item.get("host_role") or ""),
                "host_ip": str(item.get("host_ip") or ""),
                "last_seen_ts": last_seen_ts,
                "stale": stale,
                "stale_age_seconds": stale_age,
                "snapshot": dict(last_snapshot or {}),
            }
        )
    for item in target_rows:
        snapshot = dict(item.get("snapshot") or {})
        if not snapshot:
            continue
        if not str(snapshot.get("host_name") or "").strip():
            snapshot["host_name"] = str(item.get("host_name") or "")
        if not str(snapshot.get("host_role") or "").strip():
            snapshot["host_role"] = str(item.get("host_role") or "")
        if not _is_ip_text(snapshot.get("host_ip")):
            snapshot["host_ip"] = str(item.get("host_ip") or "")
        item["snapshot"] = snapshot
    stale_targets = sum(1 for item in target_rows if item["stale"])
    cache_heavy_targets = sum(
        1
        for item in target_rows
        if float(dict(item.get("snapshot") or {}).get("memory_cache_pct") or 0.0) >= 25.0
        and str(dict(item.get("snapshot") or {}).get("memory_pressure_status") or "").strip().lower() not in {"high", "critical"}
    )
    pressure_targets = sum(
        1
        for item in target_rows
        if str(dict(item.get("snapshot") or {}).get("memory_pressure_status") or "").strip().lower() in {"high", "critical"}
    )
    memory_available_values = [
        float(dict(item.get("snapshot") or {}).get("memory_available_pct") or 0.0)
        for item in target_rows
        if dict(item.get("snapshot") or {}).get("memory_available_pct") is not None
    ]
    memory_cache_values = [
        float(dict(item.get("snapshot") or {}).get("memory_cache_pct") or 0.0)
        for item in target_rows
        if dict(item.get("snapshot") or {}).get("memory_cache_pct") is not None
    ]
    latest_snapshot_ts = max((str(item.get("ts") or "") for item in latest_snapshots.values()), default="")
    issues = []
    if stale_targets:
        issues.append(f"{stale_targets} host runtime targets are stale")
    if pressure_targets:
        issues.append(f"{pressure_targets} host runtime targets report real memory pressure")
    healthy = stale_targets == 0 and bool(target_rows)
    return {
        "generated_ts": _now_iso(),
        "status": "healthy" if healthy else "degraded",
        "healthy": healthy,
        "issues": issues,
        "targets_total": len(target_rows),
        "stale_targets": stale_targets,
        "latest_snapshot_ts": latest_snapshot_ts,
        "targets": target_rows[:limit],
        "latest_snapshots": list(latest_snapshots.values())[:limit],
        "recent_alerts": alerts[:limit],
        "metrics": {
            "snapshot_events": int(type_counts.get("host_runtime_snapshot", 0)),
            "alert_events": int(sum(count for key, count in type_counts.items() if key and key != "host_runtime_snapshot")),
            "stale_targets": stale_targets,
            "cache_heavy_targets": cache_heavy_targets,
            "pressure_targets": pressure_targets,
            "targets_total": len(target_rows),
            "stale_after_seconds": stale_after,
            "avg_memory_available_pct": round(sum(memory_available_values) / len(memory_available_values), 1) if memory_available_values else 0.0,
            "avg_memory_cache_pct": round(sum(memory_cache_values) / len(memory_cache_values), 1) if memory_cache_values else 0.0,
        },
        "breakdowns": {
            "event_types": [{"label": label or "unknown", "count": count} for label, count in type_counts.most_common()],
        },
        "memory_truth": {
            "summary": "Cache-heavy Linux memory usage is expected unless pressure or swap growth is present."
            if not pressure_targets
            else "One or more targets report real memory pressure beyond normal filesystem cache growth.",
            "cache_heavy_targets": cache_heavy_targets,
            "pressure_targets": pressure_targets,
            "stale_targets": stale_targets,
            "avg_memory_available_pct": round(sum(memory_available_values) / len(memory_available_values), 1) if memory_available_values else 0.0,
            "avg_memory_cache_pct": round(sum(memory_cache_values) / len(memory_cache_values), 1) if memory_cache_values else 0.0,
        },
        "policy": load_host_runtime_policy(),
    }
