from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
from typing import Any, Callable, Iterable
from urllib.parse import urlencode
from urllib.request import Request, urlopen

try:
    from .vuln_asset_binding import build_asset_lookup, match_finding_asset
    from .vuln_store import fetch_cmdb_assets
except ImportError:  # pragma: no cover - local test fallback
    from vuln_asset_binding import build_asset_lookup, match_finding_asset  # type: ignore[no-redef]
    from vuln_store import fetch_cmdb_assets  # type: ignore[no-redef]


CISA_KEV_URLS = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
)
FIRST_EPSS_URL = "https://api.first.org/data/v1/epss"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,19}$", re.IGNORECASE)
INTELLIGENCE_SCHEMA_VERSION = 1


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None = None) -> str:
    return (value or _utcnow()).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _string(value: Any) -> str:
    return str(value or "").strip()


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _normalize_cve(value: Any) -> str:
    token = _string(value).upper()
    return token if CVE_RE.fullmatch(token) else ""


def _cache_path() -> Path:
    configured = _string(os.getenv("SIEM_VULN_INTEL_CACHE"))
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parent.parent / "runtime-vuln" / "vulnerability-intelligence.json"


def _empty_intelligence() -> dict[str, Any]:
    return {
        "schema_version": INTELLIGENCE_SCHEMA_VERSION,
        "updated_ts": "",
        "kev": {},
        "epss": {},
        "sources": {},
        "errors": [],
    }


def load_vulnerability_intelligence(path: Path | None = None) -> dict[str, Any]:
    target = path or _cache_path()
    if not target.exists():
        return _empty_intelligence()
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return _empty_intelligence()
    if not isinstance(payload, dict):
        return _empty_intelligence()
    result = _empty_intelligence()
    result.update(payload)
    result["kev"] = dict(payload.get("kev") or {})
    result["epss"] = dict(payload.get("epss") or {})
    result["sources"] = dict(payload.get("sources") or {})
    result["errors"] = list(payload.get("errors") or [])
    return result


def _save_vulnerability_intelligence(payload: dict[str, Any], path: Path | None = None) -> None:
    target = path or _cache_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(f"{target.suffix}.tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(target)


def _fetch_json(url: str, *, timeout: int = 20) -> dict[str, Any]:
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "Rdegon-SIEM-Exposure-Management/1.0",
        },
    )
    with urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed HTTPS sources
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected an object from {url}")
    return payload


def _finding_cves(findings: Iterable[dict[str, Any]]) -> list[str]:
    result: set[str] = set()
    for finding in findings:
        for value in finding.get("cves") or []:
            cve = _normalize_cve(value)
            if cve:
                result.add(cve)
    return sorted(result)


def _epss_batches(cves: list[str], max_query_chars: int = 1800) -> list[list[str]]:
    batches: list[list[str]] = []
    current: list[str] = []
    current_size = 0
    for cve in cves:
        extra = len(cve) + (1 if current else 0)
        if current and current_size + extra > max_query_chars:
            batches.append(current)
            current = []
            current_size = 0
        current.append(cve)
        current_size += len(cve) + (1 if len(current) > 1 else 0)
    if current:
        batches.append(current)
    return batches


def sync_vulnerability_intelligence(
    *,
    cves: Iterable[str] | None = None,
    days: int = 30,
    limit: int = 500,
    fetcher: Callable[[str], dict[str, Any]] | None = None,
    cache_path: Path | None = None,
) -> dict[str, Any]:
    if cves is None:
        findings = _query_module().fetch_vulnerability_findings(query_text="", days=days, limit=limit).get("items") or []
        normalized_cves = _finding_cves(findings)
    else:
        normalized_cves = sorted({_normalize_cve(item) for item in cves if _normalize_cve(item)})

    get_json = fetcher or _fetch_json
    cached = load_vulnerability_intelligence(cache_path)
    errors: list[str] = []
    kev_records: dict[str, dict[str, Any]] = {}
    kev_source = ""
    for url in CISA_KEV_URLS:
        try:
            kev_payload = get_json(url)
            for raw in kev_payload.get("vulnerabilities") or []:
                if not isinstance(raw, dict):
                    continue
                cve = _normalize_cve(raw.get("cveID"))
                if not cve:
                    continue
                kev_records[cve] = {
                    "cve": cve,
                    "vendor": _string(raw.get("vendorProject")),
                    "product": _string(raw.get("product")),
                    "name": _string(raw.get("vulnerabilityName")),
                    "date_added": _string(raw.get("dateAdded")),
                    "due_date": _string(raw.get("dueDate")),
                    "required_action": _string(raw.get("requiredAction")),
                    "known_ransomware_use": _string(raw.get("knownRansomwareCampaignUse")),
                }
            kev_source = url
            break
        except Exception as exc:  # noqa: BLE001
            errors.append(f"KEV {url}: {exc}")
    if not kev_records:
        kev_records = dict(cached.get("kev") or {})

    epss_records = dict(cached.get("epss") or {})
    epss_updated = 0
    for batch in _epss_batches(normalized_cves):
        url = f"{FIRST_EPSS_URL}?{urlencode({'cve': ','.join(batch)})}"
        try:
            payload = get_json(url)
            for raw in payload.get("data") or []:
                if not isinstance(raw, dict):
                    continue
                cve = _normalize_cve(raw.get("cve"))
                if not cve:
                    continue
                epss_records[cve] = {
                    "cve": cve,
                    "epss": round(max(0.0, min(1.0, _float(raw.get("epss")))), 6),
                    "percentile": round(max(0.0, min(1.0, _float(raw.get("percentile")))), 6),
                    "date": _string(raw.get("date")),
                }
                epss_updated += 1
        except Exception as exc:  # noqa: BLE001
            errors.append(f"EPSS batch starting {batch[0]}: {exc}")

    now = _iso()
    result = {
        "schema_version": INTELLIGENCE_SCHEMA_VERSION,
        "updated_ts": now,
        "kev": kev_records,
        "epss": epss_records,
        "sources": {
            "kev": {
                "url": kev_source or _string((cached.get("sources") or {}).get("kev", {}).get("url")),
                "updated_ts": now if kev_source else _string((cached.get("sources") or {}).get("kev", {}).get("updated_ts")),
                "records": len(kev_records),
                "stale": not bool(kev_source),
            },
            "epss": {
                "url": FIRST_EPSS_URL,
                "updated_ts": now if epss_updated or not normalized_cves else _string((cached.get("sources") or {}).get("epss", {}).get("updated_ts")),
                "records": len(epss_records),
                "requested": len(normalized_cves),
                "updated": epss_updated,
                "stale": bool(normalized_cves and epss_updated == 0),
            },
        },
        "errors": errors[-20:],
    }
    _save_vulnerability_intelligence(result, cache_path)
    return {
        "status": "ok" if not errors else ("degraded" if kev_records or epss_records else "error"),
        "updated_ts": now,
        "kev_records": len(kev_records),
        "epss_records": len(epss_records),
        "epss_requested": len(normalized_cves),
        "epss_updated": epss_updated,
        "errors": errors[-20:],
        "sources": result["sources"],
    }


def _asset_is_public(asset: dict[str, Any]) -> bool:
    tokens = {
        _string(item).lower()
        for item in [
            asset.get("environment"),
            asset.get("business_service"),
            *(asset.get("tags") or []),
        ]
        if _string(item)
    }
    return any(
        marker in token
        for token in tokens
        for marker in ("public", "internet", "edge", "dmz", "vpn", "public_services")
    )


def calculate_exposure_score(
    finding: dict[str, Any],
    *,
    epss: float = 0.0,
    kev: bool = False,
    asset: dict[str, Any] | None = None,
) -> dict[str, Any]:
    cvss = max(0.0, min(10.0, _float(finding.get("cvss_score"))))
    qod = max(0.0, min(100.0, _float(finding.get("qod"), 100.0)))
    asset = dict(asset or {})
    criticality = _string(asset.get("criticality") or "medium").lower()
    public = _asset_is_public(asset)
    score = cvss * 4.0 + max(0.0, min(1.0, epss)) * 25.0
    reasons = [f"CVSS {cvss:.1f}", f"EPSS {max(0.0, min(1.0, epss)):.3f}"]
    if kev:
        score += 25.0
        reasons.append("CISA KEV")
    if public:
        score += 6.0
        reasons.append("public exposure")
    criticality_bonus = {"critical": 7.0, "high": 4.0, "medium": 1.0}.get(criticality, 0.0)
    score += criticality_bonus
    if criticality_bonus:
        reasons.append(f"{criticality} asset")
    if qod < 50:
        score -= 10.0
        reasons.append("low QoD")
    elif qod < 70:
        score -= 4.0
        reasons.append("reduced QoD")
    score = round(max(0.0, min(100.0, score)), 1)
    band = "urgent" if score >= 80 else "high" if score >= 65 else "medium" if score >= 40 else "low"
    sla_hours = 24 if kev or score >= 90 else 72 if score >= 80 else 168 if score >= 65 else 720
    return {
        "score": score,
        "band": band,
        "sla_hours": sla_hours,
        "reasons": reasons,
        "public_exposure": public,
        "asset_criticality": criticality,
    }


def _finding_key(item: dict[str, Any]) -> str:
    parts = (
        _string(item.get("external_report_id") or item.get("report_id")),
        _string(item.get("dst_ip")),
        _string(item.get("host_name")),
        _string(item.get("service")),
        ",".join(sorted(_normalize_cve(token) for token in (item.get("cves") or []) if _normalize_cve(token))),
    )
    return "|".join(parts)


def _parse_ts(value: Any) -> datetime:
    text = _string(value)
    if text:
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc)
        except ValueError:
            pass
    return _utcnow()


def _existing_case_map() -> dict[str, dict[str, Any]]:
    cases: dict[str, dict[str, Any]] = {}
    for case_item in _case_ops_module().list_cases(limit=500):
        if _string(case_item.get("source")) not in {"vulnerability_policy", "vulnerability_exposure"}:
            continue
        for source in case_item.get("source_alerts") or []:
            key = _string((source or {}).get("finding_key"))
            if key:
                cases[key] = case_item
    return cases


def _remediation_proposal(finding: dict[str, Any], *, kev_record: dict[str, Any] | None = None) -> dict[str, Any]:
    package = _string(finding.get("package_name"))
    fixed_version = _string(finding.get("fixed_version"))
    if package and fixed_version:
        mode = "package_update"
        action = f"Update {package} to {fixed_version} or newer"
    else:
        mode = "vendor_guidance"
        action = _string((kev_record or {}).get("required_action")) or _string(finding.get("solution")) or "Apply vendor remediation and compensating controls"
    return {
        "mode": mode,
        "action": action,
        "package_name": package,
        "fixed_version": fixed_version,
        "approval_required": True,
        "validation_profile": "safe-read-only",
        "intrusive_validation_allowed": False,
    }


def build_exposure_workbench(*, days: int = 30, limit: int = 200) -> dict[str, Any]:
    effective_limit = max(1, min(500, int(limit)))
    findings = list(
        _query_module().fetch_vulnerability_findings(query_text="", days=days, limit=effective_limit).get("items") or []
    )
    assets = fetch_cmdb_assets(limit=5000)
    lookup = build_asset_lookup(assets)
    intelligence = load_vulnerability_intelligence()
    kev_records = dict(intelligence.get("kev") or {})
    epss_records = dict(intelligence.get("epss") or {})
    case_map = _existing_case_map()
    items: list[dict[str, Any]] = []
    fixed_keys: list[str] = []
    now = _utcnow()

    for finding in findings:
        finding_key = _finding_key(finding)
        if _string(finding.get("status")).lower() == "fixed":
            fixed_keys.append(finding_key)
            continue
        match = match_finding_asset(finding, lookup, assets=assets)
        asset = dict((match or {}).get("asset") or {})
        cves = sorted({_normalize_cve(token) for token in (finding.get("cves") or []) if _normalize_cve(token)})
        kev_matches = [kev_records[cve] for cve in cves if cve in kev_records]
        epss_matches = [dict(epss_records.get(cve) or {}) for cve in cves]
        epss = max((_float(item.get("epss")) for item in epss_matches), default=0.0)
        percentile = max((_float(item.get("percentile")) for item in epss_matches), default=0.0)
        risk = calculate_exposure_score(finding, epss=epss, kev=bool(kev_matches), asset=asset)
        last_seen = _parse_ts(finding.get("ts"))
        due = last_seen + timedelta(hours=int(risk["sla_hours"]))
        current_ip = _string(asset.get("ip"))
        finding_ip = _string(finding.get("dst_ip"))
        stale_target = bool(current_ip and finding_ip and current_ip != finding_ip)
        case_item = case_map.get(finding_key) or {}
        items.append(
            {
                "finding_key": finding_key,
                "report_id": _string(finding.get("report_id")),
                "asset_id": _string(asset.get("asset_id")),
                "asset_hostname": _string(asset.get("hostname")),
                "asset_owner": _string(asset.get("owner")),
                "target": _string(finding.get("host_name") or finding.get("dst_ip")),
                "target_ip": finding_ip,
                "current_asset_ip": current_ip,
                "stale_target": stale_target,
                "asset_binding_basis": _string((match or {}).get("basis")),
                "asset_binding_confidence": round(_float((match or {}).get("confidence")), 4),
                "title": _string(finding.get("title") or finding.get("message") or finding.get("service")),
                "severity": _string(finding.get("severity") or "info"),
                "cvss_score": _float(finding.get("cvss_score")),
                "qod": _float(finding.get("qod")),
                "cves": cves,
                "kev": bool(kev_matches),
                "kev_details": kev_matches[:3],
                "epss": round(epss, 6),
                "epss_percentile": round(percentile, 6),
                "priority_score": risk["score"],
                "priority_band": risk["band"],
                "priority_reasons": risk["reasons"],
                "sla_hours": risk["sla_hours"],
                "due_ts": _iso(due),
                "sla_breached": due < now,
                "case_id": _string(case_item.get("id")),
                "case_status": _string(case_item.get("status")),
                "remediation": _remediation_proposal(finding, kev_record=kev_matches[0] if kev_matches else None),
            }
        )

    items.sort(
        key=lambda item: (
            bool(item.get("stale_target")),
            -_float(item.get("priority_score")),
            _string(item.get("target")),
        )
    )
    current_targets = [item for item in items if not bool(item.get("stale_target"))]
    actionable_scope = [item for item in current_targets if _string(item.get("asset_id"))]
    return {
        "generated_ts": _iso(),
        "intelligence": {
            "updated_ts": _string(intelligence.get("updated_ts")),
            "sources": intelligence.get("sources") or {},
            "errors": intelligence.get("errors") or [],
        },
        "summary": {
            "findings": len(items),
            "actionable": len([item for item in actionable_scope if _float(item.get("priority_score")) >= 65]),
            "urgent": len([item for item in actionable_scope if _string(item.get("priority_band")) == "urgent"]),
            "kev": len([item for item in actionable_scope if bool(item.get("kev"))]),
            "epss_high": len([item for item in actionable_scope if _float(item.get("epss")) >= 0.1]),
            "sla_breached": len([item for item in actionable_scope if bool(item.get("sla_breached"))]),
            "unowned": len([item for item in actionable_scope if not _string(item.get("asset_owner"))]),
            "unmapped": len([item for item in current_targets if not _string(item.get("asset_id"))]),
            "stale_targets": len(items) - len(current_targets),
            "existing_cases": len([item for item in items if _string(item.get("case_id"))]),
            "fixed_findings": len(fixed_keys),
        },
        "items": items[:effective_limit],
        "fixed_finding_keys": fixed_keys[:effective_limit],
    }


def apply_exposure_management_policies(
    *,
    actor: str = "system",
    days: int = 30,
    limit: int = 100,
) -> dict[str, Any]:
    workbench = build_exposure_workbench(days=days, limit=max(limit * 3, 200))
    case_ops = _case_ops_module()
    created: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for item in workbench.get("items") or []:
        if len(created) >= max(1, min(500, int(limit))):
            break
        key = _string(item.get("finding_key"))
        if _float(item.get("priority_score")) < 65 and not bool(item.get("kev")):
            continue
        if bool(item.get("stale_target")):
            skipped.append({"finding_key": key, "reason": "stale_scanner_target"})
            continue
        if not _string(item.get("asset_id")):
            skipped.append({"finding_key": key, "reason": "unmapped_asset"})
            continue
        if _string(item.get("case_id")):
            skipped.append({"finding_key": key, "reason": "existing_case", "case_id": item.get("case_id")})
            continue
        priority = 1 if _string(item.get("priority_band")) == "urgent" else 2
        severity = "critical" if priority == 1 else "high"
        target = _string(item.get("asset_hostname") or item.get("target") or item.get("asset_id")) or "unknown-target"
        cve_label = ", ".join(item.get("cves") or []) or _string(item.get("title")) or "exposure"
        case_item = case_ops.save_case(
            {
                "title": f"Vulnerability remediation on {target}: {cve_label}",
                "summary": (
                    f"Risk-based exposure score={_float(item.get('priority_score')):.1f}; "
                    f"KEV={bool(item.get('kev'))}; EPSS={_float(item.get('epss')):.3f}; "
                    f"due={_string(item.get('due_ts'))}."
                ),
                "status": "new",
                "severity": severity,
                "priority": priority,
                "assignee": _string(item.get("asset_owner")),
                "source": "vulnerability_exposure",
                "tags": ["vulnerability", "exposure-management", "auto", _string(item.get("priority_band"))],
                "related_entities": [_string(item.get("asset_id"))] if _string(item.get("asset_id")) else [],
                "related_iocs": list(item.get("cves") or []),
                "source_alerts": [
                    {
                        "type": "vulnerability_finding",
                        "finding_key": key,
                        "report_id": _string(item.get("report_id")),
                        "priority_score": item.get("priority_score"),
                    }
                ],
            },
            actor=actor,
        )
        remediation = dict(item.get("remediation") or {})
        case_ops.append_case_task(
            case_item["id"],
            title=_string(remediation.get("action")) or "Apply approved remediation",
            assignee=_string(item.get("asset_owner")),
            due_ts=_string(item.get("due_ts")),
            actor=actor,
        )
        case_ops.append_case_comment(
            case_item["id"],
            body=(
                "Automatic changes are disabled. Validate with the safe-read-only profile, "
                "approve remediation, preserve rollback evidence, and run a targeted Greenbone rescan."
            ),
            author=actor,
        )
        case_ops.record_risk_signal(
            {
                "entity_type": "host",
                "entity_name": target,
                "summary": case_item["summary"],
                "score": item.get("priority_score"),
                "severity": severity,
                "source": "vulnerability_exposure",
                "rule_id": "vuln-risk-based-exposure",
                "context": {
                    "finding_key": key,
                    "case_id": case_item["id"],
                    "cves": item.get("cves") or [],
                    "kev": bool(item.get("kev")),
                    "epss": item.get("epss"),
                },
            },
            actor=actor,
        )
        created.append({"case_id": case_item["id"], "finding_key": key, "priority_score": item.get("priority_score")})
    return {
        "created": len(created),
        "skipped": len(skipped),
        "created_cases": created,
        "skipped_items": skipped[:100],
        "summary": workbench.get("summary") or {},
    }


def _query_module():
    try:
        from . import vulnerability_query_runtime as module
    except ImportError:  # pragma: no cover - local test fallback
        import vulnerability_query_runtime as module  # type: ignore[no-redef]
    return module


def _case_ops_module():
    try:
        from . import control_plane_case_ops as module
    except ImportError:  # pragma: no cover - local test fallback
        import control_plane_case_ops as module  # type: ignore[no-redef]
    return module
