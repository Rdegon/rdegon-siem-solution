from __future__ import annotations

import ipaddress
import os
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

try:
    from .services.stream_state import stream_state_runtime_status as local_stream_state_runtime_status
except ImportError:  # pragma: no cover - local test fallback
    from services.stream_state import stream_state_runtime_status as local_stream_state_runtime_status  # type: ignore[no-redef]

try:
    from .services.transport_runtime import transport_health_snapshot as local_transport_health_snapshot
except ImportError:  # pragma: no cover - local test fallback
    from services.transport_runtime import transport_health_snapshot as local_transport_health_snapshot  # type: ignore[no-redef]

try:
    from .host_runtime_runtime import fetch_host_runtime_overview as local_host_runtime_overview
except ImportError:  # pragma: no cover - local test fallback
    from host_runtime_runtime import fetch_host_runtime_overview as local_host_runtime_overview  # type: ignore[no-redef]

try:
    from .control_plane_access_ops import list_break_glass_sessions as local_list_break_glass_sessions
except ImportError:  # pragma: no cover - local test fallback
    from control_plane_access_ops import list_break_glass_sessions as local_list_break_glass_sessions  # type: ignore[no-redef]

try:
    from .oidc_runtime import providers_inventory as local_providers_inventory, provider_status as local_provider_status
except ImportError:  # pragma: no cover - local test fallback
    from oidc_runtime import providers_inventory as local_providers_inventory, provider_status as local_provider_status  # type: ignore[no-redef]

try:
    from .secret_runtime import vault_runtime_status as local_vault_runtime_status
except ImportError:  # pragma: no cover - local test fallback
    from secret_runtime import vault_runtime_status as local_vault_runtime_status  # type: ignore[no-redef]

try:
    from .certification_runtime import certification_runtime_status as local_certification_runtime_status
except ImportError:  # pragma: no cover - local test fallback
    from certification_runtime import certification_runtime_status as local_certification_runtime_status  # type: ignore[no-redef]


def _ecp():
    try:
        from . import enterprise_control_plane as module
    except ImportError:  # pragma: no cover - local test fallback
        import enterprise_control_plane as module  # type: ignore[no-redef]

    return module


def _parse_health_ts(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    normalized = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        try:
            parsed = datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _stream_shadow_mismatch_gate(stream_corr: dict[str, Any], *, now: datetime | None = None) -> tuple[str, str]:
    shadow_mismatches = int(stream_corr.get("shadow_compare_mismatches_total") or 0)
    if shadow_mismatches <= 0:
        return "", ""
    last_mismatch = _parse_health_ts(stream_corr.get("last_mismatch_ts"))
    safe_now = now or datetime.now(timezone.utc)
    try:
        window_seconds = max(60, int(os.getenv("SIEM_STREAM_SHADOW_MISMATCH_GATE_WINDOW_SECONDS", "3600") or "3600"))
    except ValueError:
        window_seconds = 3600
    summary = f"Stream correlation shadow mismatches: {shadow_mismatches}"
    if shadow_mismatches <= 100:
        return "", summary
    if last_mismatch is None:
        return summary, ""
    age_seconds = max(0, int((safe_now - last_mismatch).total_seconds()))
    if age_seconds <= window_seconds:
        return f"{summary} since {last_mismatch.isoformat().replace('+00:00', 'Z')}", ""
    return "", f"Historical {summary}; last mismatch {last_mismatch.isoformat().replace('+00:00', 'Z')}"


def get_auth_overview() -> dict[str, Any]:
    module = _ecp()
    accounts = module.list_service_accounts()
    tokens = module.list_service_account_tokens(include_revoked=True)
    rotations = [dict(item) for item in module._collection("service_account_rotations", lambda: [])]
    break_glass_sessions = local_list_break_glass_sessions(limit=100)
    providers = local_providers_inventory()
    permission_counts = Counter(permission for item in accounts for permission in (item.get("permissions") or []))
    token_status_counts = Counter(str(item.get("status") or "unknown") for item in tokens)
    provider_health_counts = Counter("healthy" if bool(item.get("healthy")) else "degraded" for item in providers if bool(item.get("enabled", True)))
    soon_threshold = module._now() + module.timedelta(days=14)
    local_auth = {"local_users_total": 0, "local_users_hashed": 0, "local_users_plaintext": 0}
    rate_limit = {"enabled": False, "window_seconds": 0, "max_attempts": 0, "lockout_seconds": 0, "tracked_ips": 0, "blocked_ips": 0, "recent_failures": 0}
    try:
        try:
            from .security import get_auth_rate_limit_overview, get_local_auth_summary
        except ImportError:  # pragma: no cover - local test fallback
            from security import get_auth_rate_limit_overview, get_local_auth_summary  # type: ignore[no-redef]

        local_auth = get_local_auth_summary()
        rate_limit = get_auth_rate_limit_overview()
    except Exception:  # noqa: BLE001
        pass
    return {
        "items": accounts,
        "metrics": {
            "service_accounts_total": len(accounts),
            "enabled_service_accounts": sum(1 for item in accounts if item.get("enabled", True)),
            "active_tokens": sum(1 for item in tokens if str(item.get("status") or "") == "active"),
            "tokens_expiring_14d": sum(
                1
                for item in tokens
                if str(item.get("status") or "") == "active"
                and str(item.get("expires_ts") or "").strip()
                and module._parse_ts(str(item.get("expires_ts") or "")) <= soon_threshold
            ),
            "token_usage_24h": sum(
                1
                for item in tokens
                if str(item.get("last_used_ts") or "").strip() and module._parse_ts(str(item.get("last_used_ts") or "")) >= module._now() - module.timedelta(hours=24)
            ),
            **local_auth,
            "login_rate_limit_blocked_ips": int(rate_limit.get("blocked_ips") or 0),
            "login_rate_limit_recent_failures": int(rate_limit.get("recent_failures") or 0),
            "service_account_rotations_30d": sum(
                1
                for item in rotations
                if str(item.get("rotated_ts") or "").strip() and module._parse_ts(str(item.get("rotated_ts") or "")) >= module._now() - module.timedelta(days=30)
            ),
            "break_glass_sessions_total": len(break_glass_sessions),
            "break_glass_active": sum(1 for item in break_glass_sessions if bool(item.get("active"))),
            "break_glass_expired": sum(1 for item in break_glass_sessions if str(item.get("status") or "") == "expired"),
            "providers_enabled": sum(1 for item in providers if bool(item.get("enabled", True))),
            "providers_healthy": sum(1 for item in providers if bool(item.get("enabled", True)) and bool(item.get("healthy"))),
        },
        "breakdowns": {
            "token_status": [{"label": label, "count": count} for label, count in token_status_counts.most_common()],
            "permission_usage": [{"label": label, "count": count} for label, count in permission_counts.most_common()],
            "provider_health": [{"label": label, "count": count} for label, count in provider_health_counts.most_common()],
        },
        "policy": {"login_rate_limit": rate_limit},
        "providers": providers,
        "break_glass": {
            "items": break_glass_sessions[:20],
            "metrics": {
                "active": sum(1 for item in break_glass_sessions if bool(item.get("active"))),
                "expired": sum(1 for item in break_glass_sessions if str(item.get("status") or "") == "expired"),
                "revoked": sum(1 for item in break_glass_sessions if str(item.get("status") or "") == "revoked"),
            },
        },
        "rotations": {
            "items": sorted(rotations, key=lambda item: module._parse_ts(str(item.get("rotated_ts") or "")), reverse=True)[:20],
            "metrics": {
                "total": len(rotations),
                "last_rotation_ts": str(sorted(rotations, key=lambda item: module._parse_ts(str(item.get("rotated_ts") or "")), reverse=True)[0].get("rotated_ts") or "") if rotations else "",
            },
        },
    }


def get_secret_inventory() -> dict[str, Any]:
    module = _ecp()
    items: list[dict[str, Any]] = []
    for spec in module.SECRET_SPECS:
        describe_secret = getattr(module, "_describe_secret_env", None)
        if callable(describe_secret):
            details = dict(describe_secret(spec["env"]) or {})
            status = str(details.get("status") or "missing")
            source = str(details.get("source") or "missing")
        else:
            status, source = module._secret_status_for_env(spec["env"])
            details = {"status": status, "source": source}
        items.append({**spec, **details, "status": status, "source": source, "secret_ref_env": f"{spec['env']}_REF"})
    group_counts: dict[str, Counter[str]] = {}
    for item in items:
        group = str(item["group"])
        group_counts.setdefault(group, Counter())
        group_counts[group][str(item["status"])] += 1
    summary = {
        "required_missing": sum(1 for item in items if item["required"] and item["status"] == "missing"),
        "configured": sum(1 for item in items if item["status"] == "configured"),
        "references": sum(1 for item in items if item["status"] == "reference"),
        "vault_backed": sum(1 for item in items if str(item.get("reference_type") or "") == "vault"),
        "missing": sum(1 for item in items if item["status"] == "missing"),
    }
    return {
        "items": items,
        "summary": summary,
        "groups": {group: [{"label": label, "count": count} for label, count in counts.most_common()] for group, counts in group_counts.items()},
        "vault": local_vault_runtime_status(),
        "notes": [
            "Only readiness is exposed here. Secret values are never returned by the API.",
            "Use *_REF variables or vault:// style references for production deployments.",
            "Rotate credentials stored in docs or example environment files before production rollout.",
        ],
    }


def get_response_overview() -> dict[str, Any]:
    module = _ecp()
    return module.get_response_overview()


def get_auth_governance_overview() -> dict[str, Any]:
    auth = get_auth_overview()
    secrets = get_secret_inventory()
    providers = auth.get("providers") or local_providers_inventory()
    oidc = local_provider_status()
    return {
        "generated_ts": _ecp()._now_iso(),
        "providers": providers,
        "oidc": oidc,
        "vault": local_vault_runtime_status(),
        "service_accounts": {
            "items": auth.get("items") or [],
            "metrics": auth.get("metrics") or {},
            "rotations": dict(auth.get("rotations") or {}),
        },
        "break_glass": dict(auth.get("break_glass") or {}),
        "local_auth": {
            "metrics": {
                "local_users_total": int(dict(auth.get("metrics") or {}).get("local_users_total") or 0),
                "local_users_hashed": int(dict(auth.get("metrics") or {}).get("local_users_hashed") or 0),
                "local_users_plaintext": int(dict(auth.get("metrics") or {}).get("local_users_plaintext") or 0),
            },
            "policy": dict(auth.get("policy") or {}),
        },
        "secrets": secrets,
    }


def _source_is_operational(item: dict[str, Any]) -> bool:
    source_name = str(item.get("source_name") or "").strip().lower()
    categories = {str(entry or "").strip().lower() for entry in (item.get("categories") or []) if str(entry or "").strip()}
    products = {str(entry or "").strip().lower() for entry in (item.get("products") or []) if str(entry or "").strip()}
    if (
        "synthetic" in categories
        or "synthetic" in products
        or "benchmark" in categories
        or source_name.startswith("vm1-smoke")
        or source_name.startswith("eps-bench")
        or source_name.startswith("generic-http")
        or source_name.startswith("{'ip':")
        or source_name.endswith("-probe")
        or "kafka-cutover" in source_name
        or source_name == "manual"
    ):
        return False
    try:
        if source_name and ipaddress.ip_address(source_name).is_loopback:
            return False
    except ValueError:
        pass
    return True


def _is_low_signal_ingest_issue(issue: object) -> bool:
    text = str(issue or "").strip().lower()
    if text.startswith("delayed sources detected:"):
        return True
    if text.startswith("ingest dlq backlog:"):
        try:
            return int(text.split(":", 1)[1].strip()) < 5
        except (IndexError, ValueError):
            return False
    if text.startswith("outstanding dlq events:"):
        try:
            return int(text.split(":", 1)[1].strip()) < 5
        except (IndexError, ValueError):
            return False
    if text.startswith("parser errors recorded:"):
        return True
    if text.startswith("stale sources detected:") or text.startswith("stale collectors detected:"):
        try:
            return int(text.split(":", 1)[1].strip()) < 2
        except (IndexError, ValueError):
            return False
    return False


def _build_release_gates(
    *,
    content_bundles: list[dict[str, Any]],
    connector_overview: dict[str, Any],
    response_analytics: dict[str, Any],
    host_runtime: dict[str, Any],
) -> dict[str, Any]:
    bundle_items = list(content_bundles or [])
    ready_bundles = sum(1 for item in bundle_items if bool(dict(item.get("release_gate") or {}).get("ready_for_live")))
    response_metrics = dict(response_analytics.get("metrics") or {})
    response_ready = bool(
        float(response_metrics.get("owner_coverage_pct") or 0.0) >= 90.0
        and float(response_metrics.get("evidence_contract_pct") or 0.0) >= 90.0
        and float(response_metrics.get("compliance_coverage_pct") or 0.0) >= 90.0
        and float(response_metrics.get("precondition_coverage_pct") or 0.0) >= 80.0
    )
    connector_posture = dict(connector_overview.get("posture") or {})
    connector_metrics = dict(connector_overview.get("metrics") or {})
    host_metrics = dict(host_runtime.get("metrics") or {})
    memory_truth = dict(host_runtime.get("memory_truth") or {})
    return {
        "content": {
            "ready_bundles": ready_bundles,
            "total_bundles": len(bundle_items),
            "ready_pct": round((ready_bundles / len(bundle_items)) * 100.0, 1) if bundle_items else 0.0,
        },
        "connectors": {
            "ready_for_live": int(connector_metrics.get("release_gate_ready") or 0),
            "total": int(connector_metrics.get("total") or 0),
            "ready_pct": float(connector_posture.get("release_gate_ready_pct") or 0.0),
        },
        "response": {
            "ready": response_ready,
            "owner_coverage_pct": float(response_metrics.get("owner_coverage_pct") or 0.0),
            "evidence_contract_pct": float(response_metrics.get("evidence_contract_pct") or 0.0),
            "compliance_coverage_pct": float(response_metrics.get("compliance_coverage_pct") or 0.0),
            "precondition_coverage_pct": float(response_metrics.get("precondition_coverage_pct") or 0.0),
        },
        "runtime": {
            "stale_targets": int(host_metrics.get("stale_targets") or 0),
            "pressure_targets": int(host_metrics.get("pressure_targets") or 0),
            "cache_heavy_targets": int(host_metrics.get("cache_heavy_targets") or 0),
            "memory_summary": str(memory_truth.get("summary") or ""),
        },
    }


def build_health_overview(
    *,
    platform_status: dict[str, Any],
    source_inventory: list[dict[str, Any]],
    collector_inventory: list[dict[str, Any]],
    ingest_runtime: dict[str, Any] | None = None,
) -> dict[str, Any]:
    module = _ecp()
    connector_overview = module.get_connectors_overview()
    entities_overview = module.get_entities_overview()
    response_overview = module.get_response_overview()
    if hasattr(module, "get_response_analytics"):
        response_analytics = module.get_response_analytics(limit=200)
    else:
        try:
            from .control_plane_response_ops import get_response_analytics as response_analytics_impl
        except ImportError:  # pragma: no cover - local test fallback
            from control_plane_response_ops import get_response_analytics as response_analytics_impl  # type: ignore[no-redef]

        response_analytics = response_analytics_impl(limit=200)
    auth_overview = get_auth_overview()
    secret_inventory = get_secret_inventory()
    certification = local_certification_runtime_status()
    content_bundles = module.list_content_bundles()
    case_rows = module.list_cases(limit=500)
    audit_rows = module._collection("audit_events", module._default_audit_events)
    audit_chain = module.verify_audit_chain()
    storage_status = module.control_plane_storage_status()
    operational_sources = [item for item in source_inventory if _source_is_operational(dict(item or {}))]
    source_status_counts = Counter(str(item.get("status") or "unknown") for item in operational_sources)
    collector_status_counts = Counter(str(item.get("status") or item.get("health") or "unknown") for item in collector_inventory)
    case_status_counts = Counter(str(item.get("status") or "unknown") for item in case_rows)
    issues: list[str] = []
    if secret_inventory["summary"]["required_missing"]:
        issues.append(f"Missing required secrets: {secret_inventory['summary']['required_missing']}")
    if source_status_counts.get("stale", 0) >= 2:
        issues.append(f"Stale sources detected: {source_status_counts['stale']}")
    if source_status_counts.get("delayed", 0) >= 3:
        issues.append(f"Delayed sources detected: {source_status_counts['delayed']}")
    if connector_overview["metrics"]["degraded"]:
        issues.append(f"Degraded connectors: {connector_overview['metrics']['degraded']}")
    if response_overview["metrics"]["pending_approvals"]:
        issues.append(f"Pending dangerous actions: {response_overview['metrics']['pending_approvals']}")
    if not audit_chain.get("valid", False):
        issues.append("Audit chain validation failed")
    if storage_status.get("requested_backend") == "postgres" and storage_status.get("backend") != "postgres":
        issues.append("Control-plane storage is not using the requested Postgres backend")
    if str(storage_status.get("migration_status") or "") in {"blocked", "failed", "completed_with_errors"}:
        issues.append(f"Control-plane migration state: {storage_status.get('migration_status')}")
    if int(auth_overview["metrics"].get("tokens_expiring_14d") or 0):
        issues.append(f"Service-account tokens expiring soon: {int(auth_overview['metrics'].get('tokens_expiring_14d') or 0)}")
    if int(auth_overview["metrics"].get("local_users_plaintext") or 0):
        issues.append(f"Local auth still uses plaintext credentials: {int(auth_overview['metrics'].get('local_users_plaintext') or 0)}")
    active_break_glass = [
        dict(item)
        for item in list(dict(auth_overview.get("break_glass") or {}).get("items") or [])
        if bool(dict(item or {}).get("active"))
    ]
    long_lived_break_glass = [
        item
        for item in active_break_glass
        if str(item.get("expires_ts") or "").strip()
        and module._parse_ts(str(item.get("expires_ts") or "")) >= module._now() + timedelta(hours=4)
    ]
    if long_lived_break_glass:
        issues.append(f"Long-lived break-glass sessions active: {len(long_lived_break_glass)}")
    if int(auth_overview["metrics"].get("providers_healthy") or 0) < int(auth_overview["metrics"].get("providers_enabled") or 0):
        issues.append("Identity provider health is degraded")
    if not bool(dict(secret_inventory.get("vault") or {}).get("healthy", True)):
        issues.append("Vault runtime is unhealthy")
    stream_corr = platform_status.get("stream_correlation") if isinstance(platform_status, dict) else {}
    transport_shadow_status = platform_status.get("transport_shadow_status") if isinstance(platform_status, dict) else {}
    content_store_status = platform_status.get("content_store_status") if isinstance(platform_status, dict) else {}
    storage_memory_status = platform_status.get("storage_memory") if isinstance(platform_status, dict) else {}
    transport_status = (ingest_runtime or {}).get("transport") if isinstance(ingest_runtime, dict) else {}
    desired_transport = local_transport_health_snapshot()
    state_runtime = local_stream_state_runtime_status()
    transport_backend = str(
        (transport_status.get("backend") if isinstance(transport_status, dict) else "")
        or (platform_status.get("transport_backend") if isinstance(platform_status, dict) else "")
        or desired_transport.get("backend")
        or "kafka"
    )
    stream_state_backend = str(
        (stream_corr.get("state_backend") if isinstance(stream_corr, dict) else "")
        or (platform_status.get("stream_state_backend") if isinstance(platform_status, dict) else "")
        or state_runtime.get("backend")
        or "sqlite"
    )
    advisories: list[str] = []
    if isinstance(stream_corr, dict):
        mismatch_issue, mismatch_advisory = _stream_shadow_mismatch_gate(stream_corr)
        if mismatch_issue:
            issues.append(mismatch_issue)
        if mismatch_advisory:
            advisories.append(mismatch_advisory)
    if isinstance(content_store_status, dict):
        if str(content_store_status.get("requested_backend") or "") == "mongo" and str(content_store_status.get("backend") or "") != "mongo":
            issues.append("Content store is not using the requested Mongo backend")
        if not bool(content_store_status.get("healthy", True)):
            issues.append("Content store is unhealthy")
        if str(content_store_status.get("migration_status") or "") in {"pending", "failed", "blocked", "fallback"}:
            issues.append(f"Content-store migration state: {content_store_status.get('migration_status')}")
    shadow_required = transport_backend == "dual" or bool(
        dict(stream_corr or {}).get("shadow_compare")
    )
    if shadow_required and isinstance(transport_shadow_status, dict):
        if not bool(transport_shadow_status.get("healthy", True)):
            for item in transport_shadow_status.get("issues") or []:
                text = str(item or "").strip()
                if text:
                    issues.append(text)
    if isinstance(storage_memory_status, dict):
        pressure = str(storage_memory_status.get("pressure") or "")
        if pressure in {"high", "critical"}:
            issues.append(f"Storage memory pressure is {pressure}")
    if ingest_runtime:
        ingest_metrics = ingest_runtime.get("metrics") or {}
        ingest_dlq = ingest_runtime.get("dlq") or {}
        if int(ingest_dlq.get("outstanding") or 0) >= 5:
            issues.append(f"Ingest DLQ backlog: {int(ingest_dlq.get('outstanding') or 0)}")
        for item in ingest_runtime.get("issues") or []:
            text = str(item or "").strip()
            if text and not _is_low_signal_ingest_issue(text):
                issues.append(text)
    if isinstance(transport_status, dict):
        backend = str(transport_status.get("backend") or transport_backend or "kafka")
        if backend == "dual":
            issues.append("Transport cutover is still running in dual-write mode")
    try:
        host_runtime = local_host_runtime_overview(hours=6, limit=20)
    except Exception as exc:  # noqa: BLE001
        host_runtime = {"error": str(exc), "metrics": {"stale_targets": 0}}
    if int(dict(host_runtime.get("metrics") or {}).get("stale_targets") or 0):
        issues.append(f"Host telemetry stale targets: {int(dict(host_runtime.get('metrics') or {}).get('stale_targets') or 0)}")
    if not bool(certification.get("healthy", False)):
        reason = str(certification.get("last_failure_reason") or "certification_not_ready")
        issues.append(f"Certification unhealthy: {reason}")
    release_gates = _build_release_gates(
        content_bundles=content_bundles,
        connector_overview=connector_overview,
        response_analytics=response_analytics,
        host_runtime=host_runtime,
    )
    if float(dict(release_gates.get("connectors") or {}).get("ready_pct") or 0.0) < 50.0:
        issues.append("Connector release-gate coverage is below target")
    if not bool(dict(release_gates.get("response") or {}).get("ready", False)):
        issues.append("Response governance coverage is below target")
    clickhouse_runtime = {}
    if isinstance(platform_status, dict):
        clickhouse_runtime = dict(platform_status.get("clickhouse_runtime") or {})
    platform_payload = {
        **platform_status,
        "clickhouse_ok": bool(dict(platform_status or {}).get("clickhouse_ok", False) or clickhouse_runtime.get("healthy", False)),
        "clickhouse_runtime": clickhouse_runtime,
        "transport_backend": transport_backend,
        "stream_state_backend": stream_state_backend,
    }
    return {
        "generated_ts": module._now_iso(),
        "platform": platform_payload,
        "sources": {"total": len(operational_sources), "breakdown": [{"label": label, "count": count} for label, count in source_status_counts.most_common()]},
        "collectors": {"total": len(collector_inventory), "breakdown": [{"label": label, "count": count} for label, count in collector_status_counts.most_common()]},
        "connectors": connector_overview,
        "cases": {
            "items": case_rows[:20],
            "metrics": {"total": len(case_rows), "open": sum(1 for item in case_rows if str(item.get("status") or "") not in {"closed", "false_positive"})},
            "breakdown": [{"label": label, "count": count} for label, count in case_status_counts.most_common()],
        },
        "entities": entities_overview,
        "response": response_overview,
        "response_analytics": response_analytics,
        "auth": auth_overview,
        "content": {
            "bundles": content_bundles,
            "bundle_breakdown": [{"label": label, "count": count} for label, count in Counter(str(item.get("bundle_type") or "unknown") for item in content_bundles).most_common()],
        },
        "transport": {
            "ingest": transport_status or {"status": "unavailable"},
            "stream_correlation": stream_corr if isinstance(stream_corr, dict) else {"status": "unavailable"},
            "shadow": transport_shadow_status if isinstance(transport_shadow_status, dict) else {"status": "unavailable"},
        },
        "control_plane": storage_status,
        "ingest": ingest_runtime or {"status": "unavailable"},
        "host_runtime": host_runtime,
        "release_gates": release_gates,
        "certification": certification,
        "audit": {
            "chain": audit_chain,
            "events_total": len(audit_rows),
            "latest_event_ts": str(audit_rows[-1].get("ts") or "") if audit_rows else "",
            "latest_action": str(audit_rows[-1].get("action") or "") if audit_rows else "",
        },
        "secrets": secret_inventory,
        "advisories": advisories,
        "issues": issues,
    }
