from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def _resolve_root() -> Path:
    current = Path(__file__).resolve().parent
    if (current / "ops").exists():
        return current
    if current.name == "app":
        candidate = current.parents[2]
        if (candidate / "ops").exists():
            return candidate
    return current


ROOT = _resolve_root()
RUNTIME_DIR = ROOT / "runtime-control-plane"
DEFAULT_PROFILE_PATH = ROOT / "ops" / "production_certification_profile.json"
DEFAULT_STATUS_PATH = RUNTIME_DIR / "production_certification_status.json"


def _now_iso() -> str:
    try:
        from .enterprise_control_plane import _now_iso as local_now_iso
    except ImportError:  # pragma: no cover - local test fallback
        from enterprise_control_plane import _now_iso as local_now_iso  # type: ignore[no-redef]

    return local_now_iso()


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _default_profile() -> dict[str, Any]:
    return {
        "profile_id": "production-certification",
        "stage_ladder_eps": [100, 250, 500],
        "latency_budget_skip_initial_stages": 1,
        "delivery_ratio_min": 0.995,
        "ingest_p95_latency_ms_max": 22000,
        "kafka_lag_max": 5000,
        "post_benchmark_health_required": True,
        "destructive_drills": [
            "kafka_transport_recovery",
            "postgres_failover_readiness",
            "mongo_stepdown_readiness",
            "clickhouse_primary_standby_verification",
            "runner_plane_recovery",
        ],
    }


def certification_profile() -> dict[str, Any]:
    path = Path(str(os.getenv("SIEM_CERTIFICATION_PROFILE_PATH") or DEFAULT_PROFILE_PATH))
    payload = _read_json(path)
    if payload:
        return payload
    return _default_profile()


def _stage_latency_p95(stage: dict[str, Any]) -> float:
    return float(dict(stage.get("latency") or {}).get("p95_ms") or stage.get("p95_latency_ms") or 0.0)


def _stage_achieved_eps(stage: dict[str, Any]) -> float:
    return float(stage.get("achieved_eps") or stage.get("eps_target_total") or 0.0)


def _stage_delivery_ratio(stage: dict[str, Any]) -> float | None:
    if "delivery_ratio" not in stage:
        return None
    return float(stage.get("delivery_ratio") or 0.0)


def _stage_consumer_lag(stage: dict[str, Any]) -> int | None:
    if "largest_consumer_lag" not in stage:
        return None
    return int(stage.get("largest_consumer_lag") or 0)


def _stage_errors(stage: dict[str, Any]) -> list[str]:
    return [str(item or "").strip() for item in list(stage.get("errors") or []) if str(item or "").strip()]


def _stage_success(stage: dict[str, Any], *, delivery_ratio_min: float) -> bool:
    status = str(stage.get("status") or "success").strip().lower()
    if status not in {"success", ""}:
        return False
    if _stage_errors(stage):
        return False
    delivery_ratio = _stage_delivery_ratio(stage)
    if delivery_ratio is None:
        return True
    return delivery_ratio >= delivery_ratio_min


def evaluate_benchmark(summary: dict[str, Any], profile: dict[str, Any] | None = None) -> dict[str, Any]:
    active = dict(profile or certification_profile())
    stages = [dict(item) for item in list(summary.get("stages") or []) if isinstance(item, dict)]
    skip_initial_stages = max(0, int(active.get("latency_budget_skip_initial_stages") or 0))
    delivery_ratio_min = float(active.get("delivery_ratio_min") or 0.995)
    successful_indices = [index for index, item in enumerate(stages) if _stage_success(item, delivery_ratio_min=delivery_ratio_min)]
    post_warmup_successful = [index for index in successful_indices if index >= skip_initial_stages]
    candidate_indices = post_warmup_successful or successful_indices
    best_stage_index = max(candidate_indices, key=lambda index: _stage_achieved_eps(stages[index]), default=-1)
    if best_stage_index >= 0:
        certified_window_start = best_stage_index
        certified_window = [stages[best_stage_index]]
        budget_stages = certified_window
    else:
        certified_window_start = skip_initial_stages if len(stages) > skip_initial_stages else 0
        certified_window = stages[certified_window_start:] or stages
        budget_stages = certified_window
    best_eps = int(summary.get("best_sustained_eps") or 0)
    stage_delivery_ratios = [value for item in budget_stages if (value := _stage_delivery_ratio(item)) is not None]
    stage_lag_values = [value for item in budget_stages if (value := _stage_consumer_lag(item)) is not None]
    delivery_ratio = min(stage_delivery_ratios) if stage_delivery_ratios else float(summary.get("best_delivery_ratio") or 0.0)
    max_lag = max(stage_lag_values) if stage_lag_values else int(summary.get("max_observed_consumer_lag") or 0)
    max_latency = max((_stage_latency_p95(item) for item in budget_stages), default=0.0)
    issues: list[str] = []
    if delivery_ratio < delivery_ratio_min:
        issues.append(f"delivery_ratio<{delivery_ratio_min:.3f}")
    if max_latency > float(active.get("ingest_p95_latency_ms_max") or 22000):
        issues.append(f"ingest_p95_latency_ms>{float(active.get('ingest_p95_latency_ms_max') or 22000):.0f}")
    if max_lag > int(active.get("kafka_lag_max") or 5000):
        issues.append(f"kafka_lag>{int(active.get('kafka_lag_max') or 5000)}")
    return {
        "healthy": not issues and best_eps > 0,
        "issues": issues,
        "best_sustained_eps": best_eps,
        "best_delivery_ratio": delivery_ratio,
        "max_observed_consumer_lag": max_lag,
        "observed_ingest_p95_latency_ms": round(max_latency, 1),
        "latency_budget_skip_initial_stages": skip_initial_stages,
        "certified_window_start_stage_index": certified_window_start if stages else 0,
        "certified_window_end_stage_index": best_stage_index if best_stage_index >= 0 else max(0, len(stages) - 1),
        "certified_window_stage_targets": [int(item.get("eps_target_total") or 0) for item in certified_window],
        "stages": stages,
    }


def certification_runtime_status() -> dict[str, Any]:
    profile = certification_profile()
    payload = _read_json(Path(str(os.getenv("SIEM_CERTIFICATION_STATUS_PATH") or DEFAULT_STATUS_PATH)))
    benchmark = dict(payload.get("benchmark") or {})
    drill = dict(payload.get("drill") or {})
    health = dict(payload.get("post_benchmark_health") or {})
    benchmark_eval = evaluate_benchmark(benchmark, profile)
    drill_ok = bool(drill.get("healthy", False))
    health_ok = not bool(profile.get("post_benchmark_health_required", True)) or bool(health.get("healthy", False))
    issues = list(benchmark_eval.get("issues") or [])
    if not drill_ok:
        issues.append(str(drill.get("last_failure_reason") or "drill_unhealthy"))
    if not health_ok:
        issues.append(str(health.get("last_failure_reason") or "post_benchmark_health_unhealthy"))
    return {
        "generated_ts": _now_iso(),
        "healthy": not issues and bool(payload),
        "profile": profile,
        "budgets": {
            "delivery_ratio_min": float(profile.get("delivery_ratio_min") or 0.995),
            "latency_budget_skip_initial_stages": int(profile.get("latency_budget_skip_initial_stages") or 0),
            "ingest_p95_latency_ms_max": float(profile.get("ingest_p95_latency_ms_max") or 22000),
            "kafka_lag_max": int(profile.get("kafka_lag_max") or 5000),
            "stage_ladder_eps": list(profile.get("stage_ladder_eps") or []),
        },
        "latest_certified_ceiling_eps": int(benchmark_eval.get("best_sustained_eps") or 0),
        "latest_benchmark": benchmark_eval,
        "latest_drill": drill,
        "post_benchmark_health": health,
        "last_failure_reason": issues[0] if issues else "",
        "issues": issues,
        "last_updated_ts": str(payload.get("last_updated_ts") or ""),
    }


def save_certification_status(payload: dict[str, Any]) -> dict[str, Any]:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    prepared = {
        **dict(payload or {}),
        "last_updated_ts": _now_iso(),
    }
    DEFAULT_STATUS_PATH.write_text(json.dumps(prepared, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return prepared
