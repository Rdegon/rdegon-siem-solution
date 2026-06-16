from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Mapping

from deploy.env_file_runtime import maybe_load_runtime_env

maybe_load_runtime_env()

ROOT = Path(__file__).resolve().parents[1]
WEB_ROOT = ROOT / "services" / "web"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if WEB_ROOT.exists() and str(WEB_ROOT) not in sys.path:
    sys.path.insert(0, str(WEB_ROOT))


def _alarm_thresholds(env: Mapping[str, str] | None = None) -> dict[str, int]:
    env_map = dict(env or os.environ)
    return {
        "postgres_lag_warn_sec": int(str(env_map.get("SIEM_STORAGE_HA_POSTGRES_LAG_WARN_SEC") or "60")),
        "mongo_lag_warn_sec": int(str(env_map.get("SIEM_STORAGE_HA_MONGO_LAG_WARN_SEC") or "120")),
        "clickhouse_lag_warn_sec": int(str(env_map.get("SIEM_STORAGE_HA_CLICKHOUSE_LAG_WARN_SEC") or "300")),
    }


def build_storage_ha_drill_report(status: Mapping[str, Any], *, thresholds: Mapping[str, int] | None = None) -> dict[str, Any]:
    limits = dict(_alarm_thresholds())
    limits.update({str(key): int(value) for key, value in dict(thresholds or {}).items()})
    alarms: list[str] = []
    clickhouse = dict(status.get("clickhouse") or {})
    postgres = dict(status.get("postgres") or {})
    mongo = dict(status.get("mongo") or {})

    clickhouse_lag = clickhouse.get("replication_lag_seconds_max")
    if clickhouse.get("configured") is False or not clickhouse.get("healthy", False):
        alarms.append("clickhouse_unhealthy")
    if clickhouse_lag is not None and int(clickhouse_lag) > limits["clickhouse_lag_warn_sec"]:
        alarms.append(f"clickhouse_replication_lag>{limits['clickhouse_lag_warn_sec']}s")

    postgres_lag = dict(postgres.get("standby") or {}).get("replay_lag_seconds")
    if not postgres.get("healthy", False):
        alarms.append("postgres_primary_or_standby_unhealthy")
    if postgres_lag is not None and float(postgres_lag) > limits["postgres_lag_warn_sec"]:
        alarms.append(f"postgres_replication_lag>{limits['postgres_lag_warn_sec']}s")

    mongo_lag = mongo.get("replication_lag_seconds_max")
    if not mongo.get("healthy", False):
        alarms.append("mongo_primary_or_secondary_unhealthy")
    if mongo_lag is not None and int(mongo_lag) > limits["mongo_lag_warn_sec"]:
        alarms.append(f"mongo_replication_lag>{limits['mongo_lag_warn_sec']}s")

    failover_ready = not alarms and bool(clickhouse.get("standby_present")) and bool(postgres.get("standby")) and bool(mongo.get("secondary"))
    return {
        "healthy": not alarms,
        "failover_ready": failover_ready,
        "controlled_switchover_ready": failover_ready,
        "restore_ready": failover_ready,
        "alarms": alarms,
        "checks": {
            "clickhouse": clickhouse,
            "postgres": postgres,
            "mongo": mongo,
        },
        "runbook": [
            "Freeze writes or declare maintenance window.",
            "Promote standby or switch active endpoint.",
            "Verify health surfaces and event flow return to green.",
            "Execute restore verification before clearing the incident.",
        ],
    }


def build_live_storage_ha_status() -> dict[str, Any]:
    try:
        from app.storage_ha_runtime import build_storage_ha_status  # type: ignore[no-redef]
        from app.content_runtime import content_storage_status  # type: ignore[no-redef]
        from app.enterprise_control_plane import control_plane_storage_status  # type: ignore[no-redef]
        from app.deps import fetch_platform_status  # type: ignore[no-redef]
    except Exception:  # noqa: BLE001
        from storage_ha_runtime import build_storage_ha_status
        from content_runtime import content_storage_status
        from enterprise_control_plane import control_plane_storage_status
        from deps import fetch_platform_status

    return build_storage_ha_status(
        platform_status=fetch_platform_status(),
        control_plane_status=control_plane_storage_status(),
        content_status=content_storage_status(),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a storage HA drill report")
    parser.add_argument("--output-json", default="")
    args = parser.parse_args()
    status = build_live_storage_ha_status()
    report = build_storage_ha_drill_report(status)
    payload = json.dumps(report, ensure_ascii=False, indent=2)
    if str(args.output_json).strip():
        Path(args.output_json).write_text(payload + "\n", encoding="utf-8")
    print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
