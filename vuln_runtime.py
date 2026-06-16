from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any


def _greenbone_enabled() -> bool:
    return str(os.getenv("SIEM_GREENBONE_ENABLED", "0") or "0").strip().lower() in {"1", "true", "yes", "on"}


def _greenbone_text(name: str, default: str = "") -> str:
    return str(os.getenv(name, default) or default).strip()


def _greenbone_port() -> int:
    try:
        return int(_greenbone_text("SIEM_GREENBONE_PORT", "0") or "0")
    except ValueError:
        return 0


def greenbone_is_configured() -> bool:
    return bool(_greenbone_enabled() and _greenbone_text("SIEM_GREENBONE_HOST") and _greenbone_text("SIEM_GREENBONE_USERNAME"))


def vulnerability_runtime_state_path() -> Path:
    artifact_dir = Path(_greenbone_text("SIEM_GREENBONE_ARTIFACT_DIR", "/opt/siem/siem-solution/services/web/runtime-vuln/greenbone-artifacts"))
    return artifact_dir.parent / "greenbone-sync-state.json"


def vulnerability_policy_state_path() -> Path:
    artifact_dir = Path(_greenbone_text("SIEM_GREENBONE_ARTIFACT_DIR", "/opt/siem/siem-solution/services/web/runtime-vuln/greenbone-artifacts"))
    return artifact_dir.parent / "vuln-policy-apply-state.json"


def load_vulnerability_runtime_state(path: Path | None = None) -> dict[str, Any]:
    target = path or vulnerability_runtime_state_path()
    if not target.exists():
        return {}
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"status": "error", "error": f"invalid runtime state file: {target}"}
    if not isinstance(payload, dict):
        return {"status": "error", "error": f"unexpected runtime state payload: {target}"}
    return payload


def write_vulnerability_runtime_state(payload: dict[str, Any], path: Path | None = None) -> Path:
    target = path or vulnerability_runtime_state_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    serialized = dict(payload)
    serialized.setdefault("updated_at", datetime.now(timezone.utc).isoformat())
    target.write_text(json.dumps(serialized, ensure_ascii=True, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


def build_vulnerability_runtime_status(
    days: int = 14,
    *,
    reports: list[dict[str, Any]] | None = None,
    fleet_coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        from .vuln_store import fetch_vulnerability_reports
    except Exception:  # noqa: BLE001
        from vuln_store import fetch_vulnerability_reports  # type: ignore[no-redef]
    try:
        from .proxmox_fleet_runtime import build_proxmox_fleet_vuln_coverage
    except Exception:  # noqa: BLE001
        from proxmox_fleet_runtime import build_proxmox_fleet_vuln_coverage  # type: ignore[no-redef]

    state_path = vulnerability_runtime_state_path()
    policy_state_path = vulnerability_policy_state_path()
    effective_days = max(1, int(days))
    reports = list(reports) if reports is not None else fetch_vulnerability_reports(limit=120, days=effective_days)
    latest_report = reports[0] if reports else {}
    runtime_state = load_vulnerability_runtime_state(state_path)
    policy_runtime = load_vulnerability_runtime_state(policy_state_path)
    probe = dict(runtime_state.get("probe") or {})
    target_sync = dict(runtime_state.get("target_sync") or {})
    report_import = dict(runtime_state.get("report_import") or {})
    fleet_coverage = dict(fleet_coverage) if fleet_coverage is not None else build_proxmox_fleet_vuln_coverage(
        days=effective_days,
        reports=reports,
    )
    scanner_breakdown: dict[str, int] = {}
    for item in reports:
        scanner_family = str(item.get("scanner_source") or item.get("scanner_family") or "unknown").strip().lower() or "unknown"
        scanner_breakdown[scanner_family] = int(scanner_breakdown.get(scanner_family, 0) or 0) + 1
    probe_status = str(probe.get("status") or runtime_state.get("status") or ("configured" if greenbone_is_configured() else "disabled")).strip().lower() or "unknown"
    target_sync_status = str(target_sync.get("status") or ("ok" if target_sync else "idle")).strip().lower() or "idle"
    report_import_status = str(report_import.get("status") or ("ok" if report_import else "idle")).strip().lower() or "idle"
    last_error = str(
        report_import.get("error")
        or target_sync.get("error")
        or probe.get("error")
        or runtime_state.get("error")
        or ""
    ).strip()
    last_target_sync_ts = str(
        target_sync.get("finished_at")
        or target_sync.get("updated_at")
        or runtime_state.get("finished_at")
        or runtime_state.get("updated_at")
        or runtime_state.get("started_at")
        or ""
    ).strip()
    last_import_ts = str(
        report_import.get("finished_at")
        or report_import.get("updated_at")
        or runtime_state.get("finished_at")
        or runtime_state.get("updated_at")
        or runtime_state.get("started_at")
        or ""
    ).strip()
    last_successful_import_ts = str(
        latest_report.get("ts_last")
        or latest_report.get("finished_at")
        or (last_import_ts if report_import_status in {"ok", "completed", "success"} else "")
        or ""
    ).strip()
    healthy = bool(
        greenbone_is_configured()
        and probe_status in {"ok", "connected", "configured"}
        and target_sync_status not in {"error", "failed"}
        and report_import_status not in {"error", "failed"}
    )
    return {
        "greenbone": {
            "enabled": greenbone_is_configured(),
            "host": _greenbone_text("SIEM_GREENBONE_HOST"),
            "port": _greenbone_port(),
            "web_base_url": _greenbone_text("SIEM_GREENBONE_WEB_BASE_URL"),
            "artifact_dir": _greenbone_text("SIEM_GREENBONE_ARTIFACT_DIR", "/opt/siem/siem-solution/services/web/runtime-vuln/greenbone-artifacts"),
            "state_path": str(state_path),
        },
        "runtime": runtime_state,
        "probe": probe,
        "last_target_sync_ts": last_target_sync_ts,
        "last_import_ts": last_import_ts,
        "last_successful_import_ts": last_successful_import_ts,
        "last_error": last_error,
        "scanner_family_breakdown": scanner_breakdown,
        "policy_scheduler": {
            "state_path": str(policy_state_path),
            "runtime": policy_runtime,
        },
        "structured_reports": {
            "days": effective_days,
            "count": len(reports),
            "latest_report_id": str(latest_report.get("report_id") or ""),
            "latest_finished_at": str(latest_report.get("ts_last") or latest_report.get("finished_at") or ""),
        },
        "fleet_coverage": fleet_coverage,
        "healthy": healthy,
    }
