from __future__ import annotations

from collections import Counter
import ipaddress
from pathlib import Path
import sys
from typing import Any

try:
    from .vuln_store import fetch_cmdb_assets
except Exception:  # noqa: BLE001
    def fetch_cmdb_assets(limit: int = 200) -> list[dict[str, Any]]:  # type: ignore[no-redef]
        return []
try:
    from .asset_catalog_runtime import fetch_source_inventory
except Exception:  # noqa: BLE001
    def fetch_source_inventory(limit: int = 200, hours: int = 24) -> list[dict[str, Any]]:  # type: ignore[no-redef]
        return []
try:
    from .vuln_asset_binding import binding_target_label, build_asset_lookup, match_finding_asset
except Exception:  # noqa: BLE001
    from vuln_asset_binding import binding_target_label, build_asset_lookup, match_finding_asset  # type: ignore[no-redef]
try:
    from .asset_binding_overrides import list_binding_overrides
except Exception:  # noqa: BLE001
    def list_binding_overrides(*, scope: str = "", include_disabled: bool = True, limit: int = 500) -> list[dict[str, Any]]:  # type: ignore[no-redef]
        return []
try:
    from .proxmox_fleet_runtime import build_proxmox_fleet_vuln_coverage
except Exception:  # noqa: BLE001
    def build_proxmox_fleet_vuln_coverage(*, days: int = 30, reports: list[dict[str, Any]] | None = None) -> dict[str, Any]:  # type: ignore[no-redef]
        return {}


AUTO_CASE_TAGS = ("vulnerability", "auto", "greenbone")
AUTO_CASE_MIN_BINDING_CONFIDENCE = 0.90


def _root_on_path() -> None:
    root = str(Path(__file__).resolve().parent)
    if root not in sys.path:
        sys.path.insert(0, root)


def _case_ops_module():
    try:
        from . import control_plane_case_ops as module
    except ImportError:  # pragma: no cover - local test fallback
        _root_on_path()
        import control_plane_case_ops as module  # type: ignore[no-redef]
    return module


def _runtime_module():
    try:
        from . import vuln_runtime as module
    except ImportError:  # pragma: no cover - local test fallback
        _root_on_path()
        import vuln_runtime as module  # type: ignore[no-redef]
    return module


def _query_module():
    try:
        from . import vulnerability_query_runtime as module
    except ImportError:  # pragma: no cover - local test fallback
        _root_on_path()
        import vulnerability_query_runtime as module  # type: ignore[no-redef]
    return module


def append_case_comment(*args: Any, **kwargs: Any) -> Any:
    return _case_ops_module().append_case_comment(*args, **kwargs)


def list_cases(*args: Any, **kwargs: Any) -> Any:
    return _case_ops_module().list_cases(*args, **kwargs)


def record_risk_signal(*args: Any, **kwargs: Any) -> Any:
    return _case_ops_module().record_risk_signal(*args, **kwargs)


def save_case(*args: Any, **kwargs: Any) -> Any:
    return _case_ops_module().save_case(*args, **kwargs)


def build_vulnerability_runtime_status(*args: Any, **kwargs: Any) -> Any:
    return _runtime_module().build_vulnerability_runtime_status(*args, **kwargs)


def fetch_vulnerability_findings(*args: Any, **kwargs: Any) -> Any:
    return _query_module().fetch_vulnerability_findings(*args, **kwargs)


def fetch_vulnerability_inventory(*args: Any, **kwargs: Any) -> Any:
    return _query_module().fetch_vulnerability_inventory(*args, **kwargs)


def fetch_vulnerability_reports(*args: Any, **kwargs: Any) -> Any:
    return _query_module().fetch_vulnerability_reports(*args, **kwargs)


def _string(value: Any) -> str:
    return str(value or "").strip()


def _severity_rank(value: str) -> int:
    normalized = _string(value).lower()
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(normalized, 0)


def _short_hostname(value: Any) -> str:
    text = _string(value).lower()
    try:
        ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        return text
    return text.split(".", 1)[0] if text else ""


def _candidate_aliases(value: Any) -> set[str]:
    text = _string(value)
    lowered = text.lower()
    short = _short_hostname(text)
    return {item for item in (text, lowered, short) if item}


def _suggest_asset_for_target(target: str, item: dict[str, Any], assets: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not target or not assets:
        return None
    candidate_aliases = set(_candidate_aliases(target))
    candidate_aliases.update(_candidate_aliases(item.get("host_name")))
    candidate_aliases.update(_candidate_aliases(item.get("dst_ip")))
    best: dict[str, Any] | None = None
    for asset in assets:
        asset_aliases = {
            _string(asset.get("asset_id")),
            _string(asset.get("hostname")),
            _short_hostname(asset.get("hostname")),
            _string(asset.get("ip")),
            *[_string(alias) for alias in (asset.get("aliases") or []) if _string(alias)],
            *[_short_hostname(alias) for alias in (asset.get("aliases") or []) if _string(alias)],
        }
        asset_aliases = {alias.lower() for alias in asset_aliases if alias}
        overlap = {alias.lower() for alias in candidate_aliases if alias.lower() in asset_aliases}
        if not overlap:
            continue
        confidence = 1.0 if _string(target).lower() in asset_aliases else 0.88
        candidate = {
            "asset_id": _string(asset.get("asset_id")),
            "hostname": _string(asset.get("hostname")),
            "ip": _string(asset.get("ip")),
            "basis": "target-heuristic",
            "confidence": round(confidence, 4),
            "matched_alias": sorted(overlap)[0],
        }
        if best is None or float(candidate["confidence"]) > float(best.get("confidence") or 0.0):
            best = candidate
    return best


def _finding_key(item: dict[str, Any]) -> str:
    parts = (
        _string(item.get("external_report_id") or item.get("report_id")),
        _string(item.get("dst_ip")),
        _string(item.get("host_name")),
        _string(item.get("service")),
        ",".join(sorted(_string(token) for token in (item.get("cves") or []) if _string(token))),
    )
    return "|".join(parts)


def _asset_match_map(assets: list[dict[str, Any]], source_inventory: list[dict[str, Any]] | None = None) -> dict[str, list[dict[str, Any]]]:
    return build_asset_lookup(assets, source_inventory)


def _finding_asset(
    item: dict[str, Any],
    asset_lookup: dict[str, list[dict[str, Any]]],
    *,
    overrides: list[dict[str, Any]] | None = None,
    assets: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    match = match_finding_asset(item, asset_lookup, overrides=overrides, assets=assets)
    return dict(match.get("asset") or {}) if match else None


def _finding_case_title(item: dict[str, Any]) -> str:
    target = _string(item.get("host_name")) or _string(item.get("dst_ip")) or "unknown-target"
    cves = [token for token in (item.get("cves") or []) if _string(token)]
    cve_label = cves[0] if cves else _string(item.get("service")) or "exposure"
    return f"Critical vulnerability exposure on {target}: {cve_label}"


def _finding_summary(item: dict[str, Any], asset: dict[str, Any] | None) -> str:
    target = _string(item.get("host_name")) or _string(item.get("dst_ip")) or "unknown target"
    severity = _string(item.get("severity") or "high")
    service = _string(item.get("service") or "unknown-service")
    cvss = float(item.get("cvss_score") or 0)
    asset_label = _string((asset or {}).get("asset_id") or (asset or {}).get("hostname") or "")
    asset_text = f" asset={asset_label};" if asset_label else ""
    return f"Scanner finding severity={severity}; cvss={cvss:.1f}; target={target}; service={service};{asset_text}"


def _existing_auto_case_keys() -> set[str]:
    keys: set[str] = set()
    for item in list_cases(limit=1000):
        if str(item.get("source") or "") != "vulnerability_policy":
            continue
        for source in item.get("source_alerts") or []:
            key = _string((source or {}).get("finding_key"))
            if key:
                keys.add(key)
    return keys


def build_vulnerability_maturity_status(*, days: int = 30, limit: int = 200) -> dict[str, Any]:
    effective_limit = max(1, min(500, limit))
    reports = fetch_vulnerability_reports(limit=effective_limit, days=days)
    findings_payload = fetch_vulnerability_findings(query_text="", days=days, limit=effective_limit)
    findings = list(findings_payload.get("items") or [])
    inventory = fetch_vulnerability_inventory(days=days, limit=50)
    assets = fetch_cmdb_assets(limit=5000)
    source_inventory = fetch_source_inventory(limit=1000, hours=24)
    overrides = list_binding_overrides(scope="vulnerability", include_disabled=False, limit=500)
    asset_lookup = _asset_match_map(assets, source_inventory)

    matched_assets = 0
    matched_report_ids: set[str] = set()
    unmatched_targets: list[str] = []
    unmatched_target_rows: dict[str, dict[str, Any]] = {}
    severity_counter: Counter[str] = Counter()
    binding_counter: Counter[str] = Counter()
    critical_candidates: list[dict[str, Any]] = []
    auto_case_keys = _existing_auto_case_keys()
    deduped_keys: set[str] = set()
    binding_confidences: list[float] = []
    for item in findings:
        severity = _string(item.get("severity") or "info").lower()
        severity_counter[severity] += 1
        asset_match = match_finding_asset(item, asset_lookup, overrides=overrides, assets=assets)
        asset = dict(asset_match.get("asset") or {}) if asset_match else None
        if asset:
            matched_assets += 1
            binding_counter[_string(asset_match.get("basis") or "matched")] += 1
            binding_confidences.append(float(asset_match.get("confidence") or 0.0))
            report_key = _string(item.get("external_report_id") or item.get("report_id"))
            if report_key:
                matched_report_ids.add(report_key)
        else:
            target = binding_target_label(item)
            if target:
                unmatched_targets.append(target)
                suggestion = _suggest_asset_for_target(target, item, assets)
                candidate_row = {
                    "finding_key": _finding_key(item),
                    "report_id": _string(item.get("report_id") or item.get("external_report_id")),
                    "target": target,
                    "hostname": _string(item.get("host_name")),
                    "ip": _string(item.get("dst_ip")),
                    "severity": severity,
                    "cvss_score": float(item.get("cvss_score") or 0.0),
                    "reason": _string(item.get("message") or item.get("summary") or item.get("status") or "Unmapped target"),
                    "suggested_asset_id": _string((suggestion or {}).get("asset_id")),
                    "suggested_hostname": _string((suggestion or {}).get("hostname")),
                    "suggested_ip": _string((suggestion or {}).get("ip")),
                    "suggested_basis": _string((suggestion or {}).get("basis")),
                    "suggested_confidence": float((suggestion or {}).get("confidence") or 0.0),
                    "matched_alias": _string((suggestion or {}).get("matched_alias")),
                }
                current = unmatched_target_rows.get(target)
                current_score = (_severity_rank(_string((current or {}).get("severity"))) * 1000) + float((current or {}).get("cvss_score") or 0.0)
                candidate_score = (_severity_rank(severity) * 1000) + float(candidate_row.get("cvss_score") or 0.0)
                if current is None or candidate_score > current_score:
                    unmatched_target_rows[target] = candidate_row
        if _severity_rank(severity) >= 4 or float(item.get("cvss_score") or 0) >= 9.0:
            finding_key = _finding_key(item)
            if not finding_key or finding_key in deduped_keys:
                continue
            deduped_keys.add(finding_key)
            critical_candidates.append(
                {
                    "finding_key": finding_key,
                    "report_id": _string(item.get("report_id")),
                    "external_report_id": _string(item.get("external_report_id")),
                    "target": _string(item.get("host_name")) or _string(item.get("dst_ip")),
                    "service": _string(item.get("service")),
                    "severity": severity,
                    "cvss_score": float(item.get("cvss_score") or 0),
                    "cves": [token for token in (item.get("cves") or []) if _string(token)],
                    "status": _string(item.get("status") or "open"),
                    "delta_state": _string(item.get("delta_state") or "new"),
                    "asset_id": _string((asset or {}).get("asset_id")),
                    "asset_current_ip": _string((asset or {}).get("ip")),
                    "target_ip": _string(item.get("dst_ip")),
                    "asset_binding_basis": _string((asset_match or {}).get("basis")),
                    "asset_binding_confidence": round(float((asset_match or {}).get("confidence") or 0.0), 4),
                    "auto_case_exists": finding_key in auto_case_keys,
                    "playbook": "critical-vulnerability-response",
                }
            )

    reports_with_assets = len(matched_report_ids) or sum(1 for item in reports if _string(item.get("asset_id")))
    coverage = round(matched_assets / len(findings), 4) if findings else 0.0
    fleet_coverage = build_proxmox_fleet_vuln_coverage(days=days, reports=reports)
    runtime_status = build_vulnerability_runtime_status(
        days=max(1, min(90, days)),
        reports=reports,
        fleet_coverage=fleet_coverage,
    )
    policy_scheduler = dict(dict(runtime_status.get("policy_scheduler") or {}).get("runtime") or {})
    policy_scheduler_ready = str(policy_scheduler.get("status") or "ok").strip().lower() == "ok"
    return {
        "runtime": runtime_status,
        "reports_total": len(reports),
        "reports_with_asset_binding": reports_with_assets,
        "findings_total": len(findings),
        "findings_with_asset_binding": matched_assets,
        "asset_binding_coverage": coverage,
        "asset_binding_breakdown": dict(sorted(binding_counter.items())),
        "asset_binding_avg_confidence": round(sum(binding_confidences) / len(binding_confidences), 4) if binding_confidences else 0.0,
        "severity_counts": dict(sorted(severity_counter.items())),
        "inventory_summary": dict(inventory.get("summary") or {}),
        "critical_candidates": critical_candidates[:100],
        "critical_candidates_total": len(critical_candidates),
        "unmapped_targets": [
            unmatched_target_rows[target]
            for target in sorted(
                unmatched_target_rows,
                key=lambda value: (
                    -_severity_rank(_string(unmatched_target_rows[value].get("severity"))),
                    -float(unmatched_target_rows[value].get("cvss_score") or 0.0),
                    value.lower(),
                ),
            )[:100]
        ],
        "unmapped_targets_total": len(set(unmatched_targets)),
        "binding_overrides_total": len(overrides),
        "binding_overrides_active": len([item for item in overrides if bool(item.get("enabled", True))]),
        "source_inventory_total": len(source_inventory),
        "fleet_coverage": fleet_coverage,
        "scheduled_workflows": [
            {"id": "greenbone-sync", "kind": "import", "schedule": "timer/service", "target": "greenbone -> structured vuln tables"},
            {"id": "vuln-incident-policy", "kind": "policy", "schedule": "timer/service", "target": "critical findings -> cases/signals"},
            {"id": "critical-vuln-response", "kind": "playbook", "schedule": "on-demand", "target": "response chains / operator workflow"},
        ],
        "playbooks": [
            {
                "id": "critical-vulnerability-response",
                "title": "Critical vulnerability response",
                "steps": [
                    "Create or update case",
                    "Record entity risk signal",
                    "Notify operator workflow",
                    "Run approved response chain",
                ],
            }
        ],
        "ready_for_incident_policies": bool(runtime_status.get("healthy", False) and policy_scheduler_ready),
    }


def apply_vulnerability_incident_policies(*, actor: str = "system", days: int = 30, limit: int = 50) -> dict[str, Any]:
    status = build_vulnerability_maturity_status(days=days, limit=max(limit * 2, 100))
    candidates = list(status.get("critical_candidates") or [])
    findings_lookup = {
        _finding_key(item): item
        for item in (fetch_vulnerability_findings(query_text="", days=days, limit=max(limit * 4, 200)).get("items") or [])
    }
    existing_keys = _existing_auto_case_keys()
    created_cases: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for candidate in candidates[: max(1, limit)]:
        finding_key = _string(candidate.get("finding_key"))
        if not finding_key:
            continue
        if finding_key in existing_keys:
            skipped.append({"finding_key": finding_key, "reason": "existing_case"})
            continue
        asset_id = _string(candidate.get("asset_id"))
        binding_confidence = float(candidate.get("asset_binding_confidence") or 0.0)
        current_ip = _string(candidate.get("asset_current_ip"))
        target_ip = _string(candidate.get("target_ip"))
        if not asset_id:
            skipped.append({"finding_key": finding_key, "reason": "unmapped_asset"})
            continue
        if binding_confidence < AUTO_CASE_MIN_BINDING_CONFIDENCE:
            skipped.append(
                {
                    "finding_key": finding_key,
                    "reason": "low_binding_confidence",
                    "confidence": binding_confidence,
                }
            )
            continue
        if current_ip and target_ip and current_ip != target_ip:
            skipped.append(
                {
                    "finding_key": finding_key,
                    "reason": "stale_scanner_target",
                    "target_ip": target_ip,
                    "current_asset_ip": current_ip,
                }
            )
            continue
        finding = dict(findings_lookup.get(finding_key) or {})
        asset = {
            "asset_id": asset_id,
            "hostname": _string(candidate.get("target")),
        }
        case_item = save_case(
            {
                "title": _finding_case_title(finding or candidate),
                "summary": _finding_summary(finding or candidate, asset if asset.get("asset_id") else None),
                "status": "new",
                "severity": "critical",
                "priority": 1,
                "source": "vulnerability_policy",
                "tags": list(AUTO_CASE_TAGS),
                "related_entities": [_string(asset.get("asset_id"))] if _string(asset.get("asset_id")) else [],
                "related_iocs": list(candidate.get("cves") or []),
                "source_alerts": [
                    {
                        "type": "vulnerability_finding",
                        "finding_key": finding_key,
                        "report_id": _string(candidate.get("report_id")),
                        "external_report_id": _string(candidate.get("external_report_id")),
                    }
                ],
            },
            actor=actor,
        )
        append_case_comment(
            case_item["id"],
            body=_string((finding or {}).get("solution") or "Validate exposure, assign owner, and track remediation."),
            author=actor,
        )
        record_risk_signal(
            {
                "entity_type": "host",
                "entity_name": _string(candidate.get("target")) or _string(asset.get("asset_id")) or "unknown-host",
                "summary": _finding_summary(finding or candidate, asset if asset.get("asset_id") else None),
                "score": 85,
                "severity": "critical",
                "source": "vulnerability_policy",
                "rule_id": "vuln-critical-exposure",
                "context": {"finding_key": finding_key, "cves": list(candidate.get("cves") or [])},
            },
            actor=actor,
        )
        created_cases.append(
            {
                "case_id": case_item["id"],
                "finding_key": finding_key,
                "title": case_item["title"],
                "asset_binding_basis": _string(candidate.get("asset_binding_basis")),
                "asset_binding_confidence": float(candidate.get("asset_binding_confidence") or 0.0),
            }
        )
        existing_keys.add(finding_key)
    return {
        "created": len(created_cases),
        "skipped": len(skipped),
        "created_cases": created_cases,
        "skipped_items": skipped[:100],
    }
