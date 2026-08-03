from __future__ import annotations

import copy
import hashlib
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

try:
    from .enterprise_control_plane import (
        append_audit_event,
        list_audit_events,
        load_control_plane_rows,
        save_control_plane_rows,
    )
    from .host_runtime_runtime import fetch_host_runtime_overview
    from .proxmox_fleet_runtime import list_proxmox_fleet_inventory
    from .proxmox_guest_ops import guest_exec, proxmox_guest_exec_configured
except ImportError:  # pragma: no cover - local test fallback
    from enterprise_control_plane import (  # type: ignore[no-redef]
        append_audit_event,
        list_audit_events,
        load_control_plane_rows,
        save_control_plane_rows,
    )
    from host_runtime_runtime import fetch_host_runtime_overview  # type: ignore[no-redef]
    from proxmox_fleet_runtime import list_proxmox_fleet_inventory  # type: ignore[no-redef]
    from proxmox_guest_ops import guest_exec, proxmox_guest_exec_configured  # type: ignore[no-redef]


ServiceAction = Literal["start", "stop", "restart", "reload"]
SERVICE_ACTIONS: tuple[ServiceAction, ...] = ("start", "stop", "restart", "reload")
IDEMPOTENCY_COLLECTION = "service_lifecycle_idempotency"
_UNIT_PATTERN = re.compile(r"^[A-Za-z0-9_.@-]+\.(?:service|timer)$")
_IDEMPOTENCY_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{8,128}$")
_IDEMPOTENCY_LOCK = threading.Lock()
_REGISTRY_CACHE_LOCK = threading.Lock()
_REGISTRY_CACHE: tuple[float, dict[str, Any]] | None = None


@dataclass(frozen=True)
class ServiceSpec:
    instance_id: str
    node: str
    vmid: int
    guest_type: str
    service_type: str
    unit: str
    title: str
    actions: tuple[ServiceAction, ...] = SERVICE_ACTIONS


def _spec(
    instance_id: str,
    node: str,
    vmid: int,
    service_type: str,
    unit: str,
    title: str,
    *,
    guest_type: str = "qemu",
    actions: tuple[ServiceAction, ...] = SERVICE_ACTIONS,
) -> ServiceSpec:
    if not _UNIT_PATTERN.fullmatch(unit):
        raise ValueError(f"Unsafe systemd unit in lifecycle allowlist: {unit}")
    return ServiceSpec(instance_id, node, vmid, guest_type, service_type, unit, title, actions)


SERVICE_SPECS: tuple[ServiceSpec, ...] = (
    _spec("collector-ingest-primary", "siem-ingest", 104, "collector", "siem-ingest.service", "HTTP/syslog ingest collector"),
    _spec("event-router-ingest", "siem-ingest", 104, "event-router", "siem-kafka.service", "Ingest Kafka router"),
    _spec("agent-ingest", "siem-ingest", 104, "agent", "siem-host-runtime-agent.timer", "Host runtime agent"),
    _spec("normalizer-primary", "siem-processing", 105, "normalizer", "siem-normalizer.service", "Normalizer primary"),
    _spec("normalizer-1", "siem-processing", 105, "normalizer", "siem-normalizer@1.service", "Normalizer worker 1"),
    _spec("normalizer-2", "siem-processing", 105, "normalizer", "siem-normalizer@2.service", "Normalizer worker 2"),
    _spec("normalizer-3", "siem-processing", 105, "normalizer", "siem-normalizer@3.service", "Normalizer worker 3"),
    _spec("filter-primary", "siem-processing", 105, "filter", "siem-filter.service", "Filter primary"),
    _spec("filter-1", "siem-processing", 105, "filter", "siem-filter@1.service", "Filter worker 1"),
    _spec("filter-2", "siem-processing", 105, "filter", "siem-filter@2.service", "Filter worker 2"),
    _spec("filter-3", "siem-processing", 105, "filter", "siem-filter@3.service", "Filter worker 3"),
    _spec("agent-processing", "siem-processing", 105, "agent", "siem-host-runtime-agent.timer", "Host runtime agent"),
    _spec("storage-clickhouse", "siem-storage", 106, "storage", "clickhouse-server.service", "ClickHouse storage"),
    _spec("writer-primary", "siem-storage", 106, "writer", "siem-writer.service", "Event writer primary"),
    _spec("writer-2", "siem-storage", 106, "writer", "siem-writer@2.service", "Event writer worker 2"),
    _spec("correlator-stream", "siem-storage", 106, "correlator", "siem-stream-corr.service", "Stream correlator"),
    _spec("alert-agg-primary", "siem-storage", 106, "alert-agg", "siem-alert-agg.service", "Alert aggregator"),
    _spec("agent-storage", "siem-storage", 106, "agent", "siem-host-runtime-agent.timer", "Host runtime agent"),
    _spec("agent-web", "siem-web", 107, "agent", "siem-host-runtime-agent.timer", "Host runtime agent"),
    _spec("event-router-transport", "siem-transport", 108, "event-router", "siem-kafka.service", "Transport Kafka router"),
    _spec("normalizer-transport-1", "siem-transport", 108, "normalizer", "siem-normalizer@1.service", "Transport normalizer 1"),
    _spec("normalizer-transport-2", "siem-transport", 108, "normalizer", "siem-normalizer@2.service", "Transport normalizer 2"),
    _spec("filter-transport-1", "siem-transport", 108, "filter", "siem-filter@1.service", "Transport filter 1"),
    _spec("filter-transport-2", "siem-transport", 108, "filter", "siem-filter@2.service", "Transport filter 2"),
    _spec("writer-standby", "siem-transport", 108, "writer", "siem-writer-standby.service", "Standby event writer"),
    _spec("agent-transport", "siem-transport", 108, "agent", "siem-host-runtime-agent.timer", "Host runtime agent"),
)
SERVICE_SPEC_BY_ID = {item.instance_id: item for item in SERVICE_SPECS}


class ServiceLifecycleError(RuntimeError):
    def __init__(self, message: str, *, code: str, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _now_iso() -> str:
    return _now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _safe_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None and str(value).strip() else None
    except (TypeError, ValueError):
        return None


def _runtime_value(metrics: dict[str, Any], names: tuple[str, ...]) -> float | None:
    for name in names:
        value = _safe_float(metrics.get(name))
        if value is not None:
            return value
    return None


def _runtime_targets() -> dict[str, dict[str, Any]]:
    try:
        hours = max(1, min(24, int(os.getenv("SIEM_SERVICE_LIFECYCLE_RUNTIME_HOURS", "2") or 2)))
        limit = max(20, min(200, int(os.getenv("SIEM_SERVICE_LIFECYCLE_RUNTIME_LIMIT", "50") or 50)))
        payload = fetch_host_runtime_overview(hours=hours, limit=limit)
    except Exception:  # noqa: BLE001
        return {}
    return {
        str(item.get("host_name") or "").strip().lower(): dict(item)
        for item in list(payload.get("targets") or [])
        if str(item.get("host_name") or "").strip()
    }


def _fleet_items() -> dict[int, dict[str, Any]]:
    try:
        payload = list_proxmox_fleet_inventory(limit=1000, refresh_if_stale=False)
    except Exception:  # noqa: BLE001
        return {}
    result: dict[int, dict[str, Any]] = {}
    for item in list(payload.get("items") or []):
        try:
            result[int(item.get("vmid"))] = dict(item)
        except (TypeError, ValueError):
            continue
    return result


def _snapshot_status(target: dict[str, Any], unit: str) -> dict[str, Any]:
    snapshot = dict(target.get("snapshot") or {})
    for service in list(snapshot.get("services") or []):
        if str(service.get("name") or "").strip() in {unit, unit.removesuffix(".service"), unit.removesuffix(".timer")}:
            active_state = str(service.get("active_state") or service.get("status") or "unknown").lower()
            return {
                "load_state": "loaded",
                "active_state": active_state,
                "sub_state": str(service.get("sub_state") or ""),
                "result": str(service.get("result") or ""),
                "source": "runtime_snapshot",
            }
    return {}


def _parse_systemd_show(output: str) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    current: dict[str, str] = {}

    def commit() -> None:
        unit = str(current.get("Id") or "").strip()
        if not unit:
            current.clear()
            return
        environment = str(current.get("Environment") or "")
        version = ""
        for token in environment.split():
            if token.startswith(("SIEM_RELEASE_VERSION=", "SIEM_BUILD_VERSION=", "APP_VERSION=")):
                version = token.split("=", 1)[1].strip('"')
                break
        records[unit] = {
            "load_state": str(current.get("LoadState") or "unknown").lower(),
            "active_state": str(current.get("ActiveState") or "unknown").lower(),
            "sub_state": str(current.get("SubState") or "").lower(),
            "result": str(current.get("Result") or "").lower(),
            "unit_file_state": str(current.get("UnitFileState") or "").lower(),
            "description": str(current.get("Description") or ""),
            "can_reload": str(current.get("CanReload") or "").lower() == "yes",
            "restarts": int(current.get("NRestarts") or 0),
            "version": version,
            "source": "systemd_live",
        }
        current.clear()

    for raw_line in str(output or "").splitlines():
        line = raw_line.strip()
        if not line:
            commit()
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            current[key] = value
    commit()
    return records


def _run_with_timeout(function, *, timeout_seconds: int):
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="service-lifecycle")
    future = executor.submit(function)
    try:
        return future.result(timeout=timeout_seconds)
    except FutureTimeoutError as exc:
        future.cancel()
        raise ServiceLifecycleError("Host control adapter timed out", code="adapter_timeout", status_code=504) from exc
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def _query_guest_units(vmid: int, guest_type: str, units: tuple[str, ...], *, timeout_seconds: int) -> dict[str, dict[str, Any]]:
    trusted_units = tuple(unit for unit in units if _UNIT_PATTERN.fullmatch(unit))
    if trusted_units != units:
        raise RuntimeError("Lifecycle allowlist contains an unsafe unit")
    property_list = "Id,LoadState,ActiveState,SubState,Result,UnitFileState,Description,CanReload,NRestarts,Environment"
    command = f"systemctl show --no-pager --property={property_list} -- {' '.join(trusted_units)}"
    output = _run_with_timeout(
        lambda: guest_exec(vmid, guest_type, command, timeout=timeout_seconds),
        timeout_seconds=timeout_seconds,
    )
    return _parse_systemd_show(str(output or ""))


def _live_statuses(fleet: dict[int, dict[str, Any]], *, timeout_seconds: int) -> tuple[dict[str, dict[str, Any]], dict[int, str]]:
    if not proxmox_guest_exec_configured():
        return {}, {spec.vmid: "Proxmox guest control adapter is not configured" for spec in SERVICE_SPECS}
    grouped: dict[tuple[int, str], list[ServiceSpec]] = {}
    errors: dict[int, str] = {}
    for spec in SERVICE_SPECS:
        fleet_item = fleet.get(spec.vmid, {})
        if fleet_item and not bool(fleet_item.get("running", False)):
            errors[spec.vmid] = "Guest is not running"
            continue
        guest_type = str(fleet_item.get("guest_type") or spec.guest_type)
        grouped.setdefault((spec.vmid, guest_type), []).append(spec)
    statuses: dict[str, dict[str, Any]] = {}
    max_workers = max(1, min(5, len(grouped)))
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="service-registry") as executor:
        futures = {
            executor.submit(_query_guest_units, vmid, guest_type, tuple(item.unit for item in specs), timeout_seconds=timeout_seconds): (vmid, specs)
            for (vmid, guest_type), specs in grouped.items()
        }
        for future, (vmid, specs) in futures.items():
            try:
                result = future.result(timeout=timeout_seconds + 1)
            except Exception as exc:  # noqa: BLE001
                errors[vmid] = str(exc)[:240]
                continue
            for spec in specs:
                if spec.unit in result:
                    statuses[spec.instance_id] = result[spec.unit]
    return statuses, errors


def _management_state(spec: ServiceSpec, status: dict[str, Any], adapter_error: str) -> tuple[str, list[str], str]:
    if adapter_error:
        return "read_only", [], adapter_error
    if str(status.get("source") or "") != "systemd_live":
        return "read_only", [], "Live systemd adapter did not return this unit"
    if str(status.get("load_state") or "") == "not-found":
        return "unavailable", [], "Systemd unit is not installed on the target"
    active = str(status.get("active_state") or "") == "active"
    capabilities: list[str] = []
    if active:
        capabilities.extend(action for action in ("stop", "restart") if action in spec.actions)
        if "reload" in spec.actions and bool(status.get("can_reload")):
            capabilities.append("reload")
    elif "start" in spec.actions:
        capabilities.append("start")
    return "managed", capabilities, ""


def _record_for_spec(
    spec: ServiceSpec,
    *,
    target: dict[str, Any],
    fleet_item: dict[str, Any],
    live_status: dict[str, Any],
    adapter_error: str,
) -> dict[str, Any]:
    snapshot = dict(target.get("snapshot") or {})
    metrics = dict(snapshot.get("metrics") or {})
    status = dict(live_status or _snapshot_status(target, spec.unit))
    management_state, capabilities, unavailable_reason = _management_state(spec, status, adapter_error)
    active_state = str(status.get("active_state") or ("offline" if fleet_item and not fleet_item.get("running") else "unknown"))
    last_seen = str(target.get("last_seen_ts") or fleet_item.get("last_seen_ts") or "")
    return {
        "instance_id": spec.instance_id,
        "title": spec.title,
        "node": spec.node,
        "node_ip": str(target.get("host_ip") or fleet_item.get("ip") or ""),
        "vmid": spec.vmid,
        "guest_type": str(fleet_item.get("guest_type") or spec.guest_type),
        "service_type": spec.service_type,
        "unit": spec.unit,
        "status": active_state,
        "active_state": active_state,
        "sub_state": str(status.get("sub_state") or ""),
        "load_state": str(status.get("load_state") or "unknown"),
        "result": str(status.get("result") or ""),
        "unit_file_state": str(status.get("unit_file_state") or ""),
        "version": str(status.get("version") or ""),
        "restarts": int(status.get("restarts") or 0),
        "eps": _runtime_value(metrics, ("eps", "events_per_second", "output_eps", "input_eps")),
        "lag": _runtime_value(metrics, ("consumer_lag", "kafka_lag", "lag", "queue_lag")),
        "last_seen_ts": last_seen,
        "stale": bool(target.get("stale", not bool(last_seen))),
        "status_source": str(status.get("source") or "inventory"),
        "management_state": management_state,
        "capabilities": capabilities,
        "unavailable_reason": unavailable_reason,
        "fleet_state": str(fleet_item.get("state") or "unknown"),
    }


def list_service_instances(*, refresh_live: bool = True, timeout_seconds: int | None = None) -> dict[str, Any]:
    global _REGISTRY_CACHE
    cache_ttl = max(1, min(60, int(os.getenv("SIEM_SERVICE_LIFECYCLE_CACHE_TTL_SEC", "15") or 15)))
    if not refresh_live:
        with _REGISTRY_CACHE_LOCK:
            cached = _REGISTRY_CACHE
            if cached and time.monotonic() - cached[0] <= cache_ttl:
                return copy.deepcopy(cached[1])
    safe_timeout = max(2, min(30, int(timeout_seconds or os.getenv("SIEM_SERVICE_LIFECYCLE_TIMEOUT_SEC", "12") or 12)))
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="service-registry-context") as executor:
        targets_future = executor.submit(_runtime_targets)
        fleet_future = executor.submit(_fleet_items)
        targets = targets_future.result()
        fleet = fleet_future.result()
    live_statuses: dict[str, dict[str, Any]] = {}
    adapter_errors: dict[int, str] = {}
    if refresh_live:
        live_statuses, adapter_errors = _live_statuses(fleet, timeout_seconds=safe_timeout)
    elif not proxmox_guest_exec_configured():
        adapter_errors = {spec.vmid: "Proxmox guest control adapter is not configured" for spec in SERVICE_SPECS}
    items = [
        _record_for_spec(
            spec,
            target=targets.get(spec.node.lower(), {}),
            fleet_item=fleet.get(spec.vmid, {}),
            live_status=live_statuses.get(spec.instance_id, {}),
            adapter_error=adapter_errors.get(spec.vmid, ""),
        )
        for spec in SERVICE_SPECS
    ]
    payload = {
        "generated_ts": _now_iso(),
        "items": items,
        "metrics": {
            "total": len(items),
            "active": sum(1 for item in items if item["active_state"] == "active"),
            "failed": sum(1 for item in items if item["active_state"] == "failed"),
            "managed": sum(1 for item in items if item["management_state"] == "managed"),
            "read_only": sum(1 for item in items if item["management_state"] == "read_only"),
            "unavailable": sum(1 for item in items if item["management_state"] == "unavailable"),
        },
        "adapter": {
            "kind": "proxmox_guest_exec",
            "configured": proxmox_guest_exec_configured(),
            "errors": [{"vmid": vmid, "error": error} for vmid, error in sorted(adapter_errors.items())],
        },
    }
    if not refresh_live:
        with _REGISTRY_CACHE_LOCK:
            _REGISTRY_CACHE = (time.monotonic(), copy.deepcopy(payload))
    return payload


def get_service_instance(instance_id: str, *, refresh_live: bool = True) -> dict[str, Any]:
    safe_id = str(instance_id or "").strip()
    if safe_id not in SERVICE_SPEC_BY_ID:
        raise ServiceLifecycleError("Managed service instance was not found", code="instance_not_found", status_code=404)
    spec = SERVICE_SPEC_BY_ID[safe_id]
    targets = _runtime_targets()
    fleet = _fleet_items()
    fleet_item = fleet.get(spec.vmid, {})
    live_status: dict[str, Any] = {}
    adapter_error = ""
    if refresh_live:
        if not proxmox_guest_exec_configured():
            adapter_error = "Proxmox guest control adapter is not configured"
        elif fleet_item and not bool(fleet_item.get("running", False)):
            adapter_error = "Guest is not running"
        else:
            try:
                guest_type = str(fleet_item.get("guest_type") or spec.guest_type)
                result = _query_guest_units(spec.vmid, guest_type, (spec.unit,), timeout_seconds=12)
                live_status = dict(result.get(spec.unit) or {})
            except Exception as exc:  # noqa: BLE001
                adapter_error = str(exc)[:240]
    elif not proxmox_guest_exec_configured():
        adapter_error = "Proxmox guest control adapter is not configured"
    item = _record_for_spec(
        spec,
        target=targets.get(spec.node.lower(), {}),
        fleet_item=fleet_item,
        live_status=live_status,
        adapter_error=adapter_error,
    )
    try:
        audit_payload = list_audit_events(object_type="siem_service_instance", limit=500)
        audit = [event for event in list(audit_payload.get("items") or []) if str(event.get("object_id") or "") == safe_id][-50:]
    except Exception:  # noqa: BLE001
        audit = []
    return {**item, "audit_trail": audit}


def _load_idempotency_rows() -> list[dict[str, Any]]:
    return list(load_control_plane_rows(IDEMPOTENCY_COLLECTION, list))


def _save_idempotency_rows(rows: list[dict[str, Any]]) -> None:
    save_control_plane_rows(IDEMPOTENCY_COLLECTION, rows[-1000:])


def _idempotency_fingerprint(instance_id: str, action: ServiceAction) -> str:
    return hashlib.sha256(f"{instance_id}:{action}".encode("utf-8")).hexdigest()


def _reserve_idempotency(key: str, instance_id: str, action: ServiceAction, actor: str) -> dict[str, Any] | None:
    if not _IDEMPOTENCY_PATTERN.fullmatch(key):
        raise ServiceLifecycleError("A valid idempotency key is required", code="invalid_idempotency_key", status_code=400)
    fingerprint = _idempotency_fingerprint(instance_id, action)
    with _IDEMPOTENCY_LOCK:
        rows = _load_idempotency_rows()
        existing = next((row for row in rows if str(row.get("key") or "") == key), None)
        if existing:
            if str(existing.get("fingerprint") or "") != fingerprint:
                raise ServiceLifecycleError("Idempotency key was already used for another operation", code="idempotency_conflict", status_code=409)
            if str(existing.get("status") or "") in {"completed", "failed"} and isinstance(existing.get("response"), dict):
                return {**dict(existing["response"]), "idempotent_replay": True}
            if str(existing.get("status") or "") == "pending":
                raise ServiceLifecycleError("An identical lifecycle action is already running", code="action_in_progress", status_code=409)
            rows = [row for row in rows if str(row.get("key") or "") != key]
        rows.append(
            {
                "key": key,
                "fingerprint": fingerprint,
                "instance_id": instance_id,
                "action": action,
                "actor": actor,
                "status": "pending",
                "created_ts": _now_iso(),
            }
        )
        _save_idempotency_rows(rows)
    return None


def _complete_idempotency(key: str, *, status: str, response: dict[str, Any]) -> None:
    with _IDEMPOTENCY_LOCK:
        rows = _load_idempotency_rows()
        for row in rows:
            if str(row.get("key") or "") == key:
                row["status"] = status
                row["response"] = dict(response)
                row["completed_ts"] = _now_iso()
                break
        _save_idempotency_rows(rows)


def _single_live_status(spec: ServiceSpec, *, timeout_seconds: int) -> dict[str, Any]:
    result = _query_guest_units(spec.vmid, spec.guest_type, (spec.unit,), timeout_seconds=timeout_seconds)
    return dict(result.get(spec.unit) or {})


def _action_command(spec: ServiceSpec, action: ServiceAction) -> str:
    if action not in spec.actions or action not in SERVICE_ACTIONS:
        raise ServiceLifecycleError("Lifecycle action is not allowlisted for this instance", code="action_not_allowed", status_code=400)
    return f"systemctl {action} -- {spec.unit}"


def execute_service_action(
    instance_id: str,
    action: ServiceAction,
    *,
    actor: str,
    idempotency_key: str,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    safe_id = str(instance_id or "").strip()
    if safe_id not in SERVICE_SPEC_BY_ID:
        raise ServiceLifecycleError("Managed service instance was not found", code="instance_not_found", status_code=404)
    if action not in SERVICE_ACTIONS:
        raise ServiceLifecycleError("Unsupported lifecycle action", code="unsupported_action", status_code=400)
    replay = _reserve_idempotency(str(idempotency_key or "").strip(), safe_id, action, actor)
    if replay is not None:
        return replay
    spec = SERVICE_SPEC_BY_ID[safe_id]
    safe_timeout = max(2, min(60, int(timeout_seconds or os.getenv("SIEM_SERVICE_LIFECYCLE_ACTION_TIMEOUT_SEC", "20") or 20)))
    before: dict[str, Any] = {}
    response: dict[str, Any]
    try:
        if not proxmox_guest_exec_configured():
            raise ServiceLifecycleError("Proxmox guest control adapter is not configured", code="adapter_unavailable", status_code=503)
        fleet = _fleet_items().get(spec.vmid, {})
        if fleet and not bool(fleet.get("running", False)):
            raise ServiceLifecycleError("Target guest is not running", code="target_offline", status_code=409)
        before = _single_live_status(spec, timeout_seconds=safe_timeout)
        state, capabilities, reason = _management_state(spec, before, "")
        if state != "managed" or action not in capabilities:
            raise ServiceLifecycleError(reason or "Lifecycle action is unavailable", code="action_unavailable", status_code=409)
        append_audit_event(
            actor=actor,
            action=f"siem_service.{action}.requested",
            object_type="siem_service_instance",
            object_id=safe_id,
            summary=f"Requested {action} for {spec.title} on {spec.node}",
            details={
                "unit": spec.unit,
                "node": spec.node,
                "vmid": spec.vmid,
                "before": {"active_state": before.get("active_state"), "sub_state": before.get("sub_state")},
                "idempotency_hash": hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()[:16],
            },
        )
        command = _action_command(spec, action)
        _run_with_timeout(
            lambda: guest_exec(spec.vmid, spec.guest_type, command, timeout=safe_timeout),
            timeout_seconds=safe_timeout,
        )
        expected = "inactive" if action == "stop" else "active"
        after: dict[str, Any] = {}
        for _ in range(5):
            after = _single_live_status(spec, timeout_seconds=safe_timeout)
            if str(after.get("active_state") or "") == expected:
                break
            time.sleep(0.5)
        verified = str(after.get("active_state") or "") == expected
        if not verified:
            raise ServiceLifecycleError(
                f"Post-action verification failed: expected {expected}, got {after.get('active_state') or 'unknown'}",
                code="verification_failed",
                status_code=502,
            )
        response = {
            "instance_id": safe_id,
            "action": action,
            "status": "completed",
            "verified": True,
            "before": {"active_state": before.get("active_state"), "sub_state": before.get("sub_state")},
            "after": {"active_state": after.get("active_state"), "sub_state": after.get("sub_state")},
            "completed_ts": _now_iso(),
            "idempotent_replay": False,
        }
        try:
            append_audit_event(
                actor=actor,
                action=f"siem_service.{action}",
                object_type="siem_service_instance",
                object_id=safe_id,
                summary=f"{action} {spec.title} on {spec.node}",
                details={
                    "unit": spec.unit,
                    "node": spec.node,
                    "vmid": spec.vmid,
                    "verified": True,
                    "before": response["before"],
                    "after": response["after"],
                    "idempotency_hash": hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()[:16],
                },
            )
            response["audit_recorded"] = True
        except Exception:  # noqa: BLE001
            response["audit_recorded"] = False
        _complete_idempotency(idempotency_key, status="completed", response=response)
        return response
    except Exception as exc:  # noqa: BLE001
        error = exc if isinstance(exc, ServiceLifecycleError) else ServiceLifecycleError(str(exc)[:240], code="adapter_error", status_code=502)
        response = {
            "instance_id": safe_id,
            "action": action,
            "status": "failed",
            "verified": False,
            "error": str(error),
            "code": error.code,
            "completed_ts": _now_iso(),
        }
        _complete_idempotency(idempotency_key, status="failed", response=response)
        try:
            append_audit_event(
                actor=actor,
                action=f"siem_service.{action}.failed",
                object_type="siem_service_instance",
                object_id=safe_id,
                summary=f"Failed to {action} {spec.title} on {spec.node}",
                details={"unit": spec.unit, "node": spec.node, "vmid": spec.vmid, "code": error.code, "before": before},
            )
        except Exception:  # noqa: BLE001
            pass
        raise error
