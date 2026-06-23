from __future__ import annotations

from datetime import datetime
from functools import lru_cache
import json
import re
from typing import Any, Dict, List


VULN_ASSET_BINDING_TABLE = "siem.vuln_asset_bindings"
VULN_SCAN_RUN_TABLE = "siem.vuln_scan_runs"
VULN_FINDING_TABLE = "siem.vuln_findings"


def _deps():
    try:
        from . import deps as deps_module
    except ImportError:  # pragma: no cover - local test fallback
        import deps as deps_module  # type: ignore[no-redef]

    return deps_module


def _vuln_parse_ts(value: Any) -> datetime:
    deps = _deps()
    text = str(value or "").strip()
    if not text:
        return datetime.utcnow()
    parsed = deps._parse_fmt_ts(text)
    if parsed is not None:
        return parsed
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return datetime.utcnow()


def _csv_items(value: Any) -> List[str]:
    if isinstance(value, (list, tuple)):
        return [str(item or "").strip() for item in value if str(item or "").strip()]
    return [part.strip() for part in str(value or "").split(",") if part.strip()]


def _csv_dump(values: Any) -> str:
    return ",".join(_csv_items(values))


def _normalize_vuln_profile(value: str) -> str:
    candidate = str(value or "network-basic").strip().lower()
    return candidate if candidate in {"network-basic", "linux-ssh"} else "network-basic"


def _normalize_flag(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


@lru_cache(maxsize=1)
def ensure_vulnerability_support() -> bool:
    deps = _deps()
    deps.ensure_cmdb_ti_support()
    deps.get_ch_client().command(f"ALTER TABLE {deps.CMDB_ASSET_TABLE} ADD COLUMN IF NOT EXISTS vuln_enabled UInt8 DEFAULT 0")
    deps.get_ch_client().command(
        f"ALTER TABLE {deps.CMDB_ASSET_TABLE} ADD COLUMN IF NOT EXISTS vuln_profile LowCardinality(String) DEFAULT 'network-basic'"
    )
    deps.get_ch_client().command(
        f"""
        CREATE TABLE IF NOT EXISTS {VULN_ASSET_BINDING_TABLE}
        (
            asset_id String,
            scanner_family LowCardinality(String) DEFAULT 'greenbone',
            profile LowCardinality(String) DEFAULT 'network-basic',
            environment LowCardinality(String) DEFAULT 'prod',
            target_ref String DEFAULT '',
            target_id String DEFAULT '',
            target_name String DEFAULT '',
            task_id String DEFAULT '',
            task_name String DEFAULT '',
            schedule_name String DEFAULT '',
            sync_status LowCardinality(String) DEFAULT 'pending',
            sync_message String DEFAULT '',
            last_sync_ts DateTime DEFAULT now()
        )
        ENGINE = MergeTree
        ORDER BY (scanner_family, asset_id)
        """
    )
    deps.get_ch_client().command(
        f"""
        CREATE TABLE IF NOT EXISTS {VULN_SCAN_RUN_TABLE}
        (
            scan_run_id String,
            scanner_family LowCardinality(String) DEFAULT 'greenbone',
            external_report_id String DEFAULT '',
            task_id String DEFAULT '',
            task_name String DEFAULT '',
            target_id String DEFAULT '',
            target_name String DEFAULT '',
            asset_id String DEFAULT '',
            target String DEFAULT '',
            hostname String DEFAULT '',
            ip String DEFAULT '',
            environment LowCardinality(String) DEFAULT 'prod',
            profile LowCardinality(String) DEFAULT 'network-basic',
            started_at DateTime,
            finished_at DateTime,
            status LowCardinality(String) DEFAULT 'completed',
            summary_message String DEFAULT '',
            scanner_source String DEFAULT 'greenbone',
            artifact_path String DEFAULT '',
            artifact_format LowCardinality(String) DEFAULT 'xml',
            greenbone_report_url String DEFAULT '',
            asset_count UInt32 DEFAULT 0,
            finding_count UInt32 DEFAULT 0,
            unique_port_count UInt32 DEFAULT 0,
            notable_findings UInt32 DEFAULT 0,
            new_count UInt32 DEFAULT 0,
            fixed_count UInt32 DEFAULT 0,
            reopened_count UInt32 DEFAULT 0,
            targets_csv String DEFAULT '',
            ports_csv String DEFAULT '',
            cves_csv String DEFAULT '',
            severity_counts_json String DEFAULT '',
            imported_ts DateTime DEFAULT now()
        )
        ENGINE = MergeTree
        ORDER BY (finished_at, scan_run_id)
        """
    )
    deps.get_ch_client().command(
        f"""
        CREATE TABLE IF NOT EXISTS {VULN_FINDING_TABLE}
        (
            finding_id String,
            scan_run_id String,
            external_report_id String DEFAULT '',
            scanner_family LowCardinality(String) DEFAULT 'greenbone',
            asset_id String DEFAULT '',
            target String DEFAULT '',
            hostname String DEFAULT '',
            ip String DEFAULT '',
            port UInt16 DEFAULT 0,
            protocol LowCardinality(String) DEFAULT '',
            service String DEFAULT '',
            package_name String DEFAULT '',
            installed_version String DEFAULT '',
            fixed_version String DEFAULT '',
            cve String DEFAULT '',
            cvss_score Float32 DEFAULT 0,
            severity_vendor String DEFAULT '',
            severity_normalized LowCardinality(String) DEFAULT 'info',
            qod Float32 DEFAULT 0,
            solution String DEFAULT '',
            scanner_plugin_id String DEFAULT '',
            title String DEFAULT '',
            description String DEFAULT '',
            evidence String DEFAULT '',
            status LowCardinality(String) DEFAULT 'open',
            delta_state LowCardinality(String) DEFAULT 'new',
            first_seen DateTime,
            last_seen DateTime,
            task_id String DEFAULT '',
            target_id String DEFAULT '',
            artifact_path String DEFAULT '',
            report_url String DEFAULT '',
            updated_ts DateTime DEFAULT now()
        )
        ENGINE = MergeTree
        ORDER BY (last_seen, finding_id, scan_run_id)
        """
    )
    return True


def fetch_cmdb_assets(limit: int = 200) -> List[Dict[str, Any]]:
    deps = _deps()
    ensure_vulnerability_support()
    query = f"""
        SELECT
            asset_id,
            asset_type,
            hostname,
            ip,
            owner,
            criticality,
            environment,
            business_service,
            os_family,
            expected_ports,
            tags,
            notes,
            enabled,
            vuln_enabled,
            vuln_profile,
            updated_ts
        FROM {deps.CMDB_ASSET_TABLE}
        ORDER BY updated_ts DESC, asset_id
        LIMIT {int(limit)}
    """
    rows: List[Dict[str, Any]] = []
    for row in deps.get_ch_client().query(query).named_results():
        rows.append(
            {
                "asset_id": str(row["asset_id"] or ""),
                "asset_type": str(row["asset_type"] or ""),
                "hostname": str(row["hostname"] or ""),
                "ip": str(row["ip"] or ""),
                "owner": str(row["owner"] or ""),
                "criticality": str(row["criticality"] or ""),
                "environment": str(row["environment"] or ""),
                "business_service": str(row["business_service"] or ""),
                "os_family": str(row["os_family"] or ""),
                "expected_ports": _csv_items(row["expected_ports"]),
                "tags": _csv_items(row["tags"]),
                "notes": str(row["notes"] or ""),
                "enabled": bool(row["enabled"]),
                "vuln_enabled": bool(row["vuln_enabled"]),
                "vuln_profile": _normalize_vuln_profile(str(row["vuln_profile"] or "network-basic")),
                "updated_ts": deps._fmt(row["updated_ts"]),
            }
        )
    return rows


def save_cmdb_asset(
    *,
    asset_id: str,
    asset_type: str,
    hostname: str,
    ip: str,
    owner: str,
    criticality: str,
    environment: str,
    business_service: str,
    os_family: str,
    expected_ports: str,
    tags: str,
    notes: str,
    vuln_enabled: bool = False,
    vuln_profile: str = "network-basic",
) -> Dict[str, Any]:
    deps = _deps()
    ensure_vulnerability_support()
    safe_asset_id = (asset_id or "").strip()
    safe_asset_type = (asset_type or "server").strip().lower()
    safe_hostname = (hostname or "").strip().lower()
    safe_ip = (ip or "").strip()
    safe_owner = (owner or "").strip()
    safe_criticality = (criticality or "medium").strip().lower()
    safe_environment = (environment or "prod").strip().lower()
    safe_business_service = (business_service or "").strip()
    safe_os_family = (os_family or "").strip().lower()
    safe_expected_ports = deps._normalize_csv(expected_ports)
    safe_tags = deps._normalize_csv(tags)
    safe_notes = (notes or "").strip()
    safe_vuln_enabled = 1 if _normalize_flag(vuln_enabled) else 0
    safe_vuln_profile = _normalize_vuln_profile(vuln_profile)
    if not safe_asset_id:
        raise ValueError("asset_id is required")
    if safe_criticality not in {"low", "medium", "high", "critical"}:
        raise ValueError("criticality must be low, medium, high or critical")
    deps.get_ch_client().command(f"ALTER TABLE {deps.CMDB_ASSET_TABLE} DELETE WHERE asset_id = {deps._sql_quote(safe_asset_id)}")
    deps.get_ch_client().insert(
        deps.CMDB_ASSET_TABLE,
        [[
            safe_asset_id,
            safe_asset_type,
            safe_hostname,
            safe_ip,
            safe_owner,
            safe_criticality,
            safe_environment,
            safe_business_service,
            safe_os_family,
            safe_expected_ports,
            safe_tags,
            safe_notes,
            1,
            safe_vuln_enabled,
            safe_vuln_profile,
        ]],
        column_names=[
            "asset_id",
            "asset_type",
            "hostname",
            "ip",
            "owner",
            "criticality",
            "environment",
            "business_service",
            "os_family",
            "expected_ports",
            "tags",
            "notes",
            "enabled",
            "vuln_enabled",
            "vuln_profile",
        ],
    )
    return {
        "asset_id": safe_asset_id,
        "hostname": safe_hostname,
        "ip": safe_ip,
        "criticality": safe_criticality,
        "environment": safe_environment,
        "vuln_enabled": bool(safe_vuln_enabled),
        "vuln_profile": safe_vuln_profile,
    }


def import_cmdb_assets(payload: str) -> Dict[str, Any]:
    deps = _deps()
    records = deps._parse_import_records(payload)
    if not records:
        raise ValueError("No CMDB records found in JSON/CSV payload")
    saved = 0
    for row in records:
        asset_id = str(row.get("asset_id") or row.get("id") or "").strip()
        hostname = str(row.get("hostname") or row.get("host") or row.get("name") or "").strip()
        ip = str(row.get("ip") or row.get("address") or "").strip()
        if not asset_id:
            if hostname:
                asset_id = f"asset-{re.sub(r'[^a-z0-9]+', '-', hostname.lower()).strip('-')}"
            elif ip:
                asset_id = f"asset-{ip.replace('.', '-')}"
        if not asset_id:
            continue
        save_cmdb_asset(
            asset_id=asset_id,
            asset_type=str(row.get("asset_type") or row.get("type") or "server"),
            hostname=hostname,
            ip=ip,
            owner=str(row.get("owner") or ""),
            criticality=str(row.get("criticality") or "medium"),
            environment=str(row.get("environment") or "prod"),
            business_service=str(row.get("business_service") or row.get("service") or ""),
            os_family=str(row.get("os_family") or row.get("os") or ""),
            expected_ports=str(row.get("expected_ports") or row.get("ports") or ""),
            tags=str(row.get("tags") or ""),
            notes=str(row.get("notes") or row.get("description") or ""),
            vuln_enabled=_normalize_flag(
                row.get("vuln_enabled") or row.get("scan_enabled") or row.get("scanner_enabled"),
                default=False,
            ),
            vuln_profile=str(row.get("vuln_profile") or row.get("scan_profile") or "network-basic"),
        )
        saved += 1
    return {"saved": saved, "parsed": len(records)}


def sync_observed_assets_to_cmdb(hours: int = 72, limit: int = 200) -> Dict[str, Any]:
    deps = _deps()
    ensure_vulnerability_support()
    observed_query = f"""
        SELECT
            asset_name,
            any(host_name) AS host_name,
            any(log_source) AS log_source,
            any(src_ip_text) AS src_ip_text,
            any(device_product) AS device_product,
            max(ts) AS last_seen
        FROM
        (
            SELECT
                if(host_name != '' AND host_name != '-', host_name, log_source) AS asset_name,
                host_name,
                log_source,
                if(src_ip = 0, '', IPv4NumToString(src_ip)) AS src_ip_text,
                device_product,
                ts
            FROM siem.events
            WHERE ts >= now() - INTERVAL {int(hours)} HOUR
        )
        WHERE asset_name != ''
        GROUP BY asset_name
        ORDER BY last_seen DESC
        LIMIT {int(limit)}
    """
    existing = fetch_cmdb_assets(limit=5000)
    known = {item["asset_id"] for item in existing} | {item["hostname"] for item in existing if item["hostname"]} | {item["ip"] for item in existing if item["ip"]}
    created = 0
    for row in deps.get_ch_client().query(observed_query).named_results():
        asset_name = str(row["asset_name"] or "").strip()
        host_name = str(row["host_name"] or "").strip()
        ip_value = str(row["src_ip_text"] or "").strip()
        if asset_name in known or host_name in known or ip_value in known:
            continue
        seed = host_name or asset_name or ip_value
        if not seed:
            continue
        asset_id = f"asset-{re.sub(r'[^a-z0-9]+', '-', seed.lower()).strip('-')}"
        save_cmdb_asset(
            asset_id=asset_id,
            asset_type="server",
            hostname=host_name or asset_name,
            ip=ip_value,
            owner="soc-discovered",
            criticality="medium",
            environment="unknown",
            business_service="Observed asset",
            os_family="windows" if str(row["device_product"] or "").startswith("windows.") else "linux",
            expected_ports="",
            tags="auto-discovered,telemetry",
            notes=f"Auto-created from observed events during the last {int(hours)} hours.",
            vuln_enabled=False,
            vuln_profile="network-basic",
        )
        created += 1
        known.add(asset_id)
    return {"created": created, "hours": int(hours), "limit": int(limit)}


def _fetch_vuln_asset_bindings(limit: int = 5000) -> List[Dict[str, Any]]:
    deps = _deps()
    ensure_vulnerability_support()
    query = f"""
        SELECT
            asset_id,
            scanner_family,
            profile,
            environment,
            target_ref,
            target_id,
            target_name,
            task_id,
            task_name,
            schedule_name,
            sync_status,
            sync_message,
            last_sync_ts
        FROM {VULN_ASSET_BINDING_TABLE}
        ORDER BY last_sync_ts DESC, asset_id
        LIMIT {int(limit)}
    """
    items: List[Dict[str, Any]] = []
    for row in deps.get_ch_client().query(query).named_results():
        items.append(
            {
                "asset_id": str(row["asset_id"] or ""),
                "scanner_family": str(row["scanner_family"] or "greenbone"),
                "profile": str(row["profile"] or "network-basic"),
                "environment": str(row["environment"] or "prod"),
                "target_ref": str(row["target_ref"] or ""),
                "target_id": str(row["target_id"] or ""),
                "target_name": str(row["target_name"] or ""),
                "task_id": str(row["task_id"] or ""),
                "task_name": str(row["task_name"] or ""),
                "schedule_name": str(row["schedule_name"] or ""),
                "sync_status": str(row["sync_status"] or "pending"),
                "sync_message": str(row["sync_message"] or ""),
                "last_sync_ts": deps._fmt(row["last_sync_ts"]),
            }
        )
    return items


def _binding_maps() -> Dict[str, Dict[str, Dict[str, Any]]]:
    rows = _fetch_vuln_asset_bindings(limit=5000)
    return {
        "by_asset": {row["asset_id"]: row for row in rows if row["asset_id"]},
        "by_task": {row["task_id"]: row for row in rows if row["task_id"]},
        "by_target": {row["target_id"]: row for row in rows if row["target_id"]},
    }


def _upsert_vuln_asset_bindings(items: List[Dict[str, Any]]) -> None:
    deps = _deps()
    if not items:
        return
    ensure_vulnerability_support()
    for item in items:
        asset_id = str(item.get("asset_id") or "").strip()
        scanner_family = str(item.get("scanner_family") or "greenbone").strip().lower()
        if not asset_id:
            continue
        deps.get_ch_client().command(
            f"ALTER TABLE {VULN_ASSET_BINDING_TABLE} DELETE WHERE asset_id = {deps._sql_quote(asset_id)} AND scanner_family = {deps._sql_quote(scanner_family)}"
        )
        deps.get_ch_client().insert(
            VULN_ASSET_BINDING_TABLE,
            [[
                asset_id,
                scanner_family,
                _normalize_vuln_profile(str(item.get("profile") or "network-basic")),
                str(item.get("environment") or "prod"),
                str(item.get("target_ref") or ""),
                str(item.get("target_id") or ""),
                str(item.get("target_name") or ""),
                str(item.get("task_id") or ""),
                str(item.get("task_name") or ""),
                str(item.get("schedule_name") or ""),
                str(item.get("sync_status") or "pending"),
                str(item.get("sync_message") or ""),
                _vuln_parse_ts(item.get("last_sync_ts") or datetime.utcnow()),
            ]],
            column_names=[
                "asset_id",
                "scanner_family",
                "profile",
                "environment",
                "target_ref",
                "target_id",
                "target_name",
                "task_id",
                "task_name",
                "schedule_name",
                "sync_status",
                "sync_message",
                "last_sync_ts",
            ],
        )


def _cmdb_target_index() -> Dict[str, Dict[str, Any]]:
    index: Dict[str, Dict[str, Any]] = {}
    for asset in fetch_cmdb_assets(limit=5000):
        for key in (asset.get("hostname"), asset.get("ip")):
            value = str(key or "").strip().lower()
            if value and value not in index:
                index[value] = asset
    return index


def sync_vulnerability_targets(limit: int = 500) -> Dict[str, Any]:
    try:
        from .vuln_greenbone import sync_assets
    except ImportError:  # pragma: no cover - local test fallback
        from vuln_greenbone import sync_assets  # type: ignore[no-redef]
    try:
        from .proxmox_fleet_runtime import sync_proxmox_fleet_to_cmdb
    except ImportError:  # pragma: no cover - local test fallback
        from proxmox_fleet_runtime import sync_proxmox_fleet_to_cmdb  # type: ignore[no-redef]

    ensure_vulnerability_support()
    try:
        sync_proxmox_fleet_to_cmdb(actor="vuln-sync")
    except Exception:
        pass
    assets = fetch_cmdb_assets(limit=max(int(limit), 5000))
    maps = _binding_maps()
    result = sync_assets(assets, maps["by_asset"])
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    for item in result.get("items", []):
        item["last_sync_ts"] = timestamp
    _upsert_vuln_asset_bindings(result.get("items", []))
    return result


def _imported_greenbone_report_ids() -> set[str]:
    deps = _deps()
    ensure_vulnerability_support()
    rows = deps.get_ch_client().query(
        f"SELECT external_report_id FROM {VULN_SCAN_RUN_TABLE} WHERE scanner_family = 'greenbone'"
    ).result_rows
    return {str(row[0] or "").strip() for row in rows if str(row[0] or "").strip()}


def _load_previous_latest_findings(asset_id: str, task_id: str, target_id: str, target: str) -> Dict[str, Dict[str, Any]]:
    deps = _deps()
    ensure_vulnerability_support()
    clauses = []
    if asset_id:
        clauses.append(f"v.asset_id = {deps._sql_quote(asset_id)}")
    if task_id:
        clauses.append(f"v.task_id = {deps._sql_quote(task_id)}")
    if target_id:
        clauses.append(f"v.target_id = {deps._sql_quote(target_id)}")
    if target:
        clauses.append(f"lower(v.target) = lower({deps._sql_quote(target)})")
    if not clauses:
        return {}
    query = f"""
        SELECT
            finding_id,
            argMax(scan_run_id, updated_ts) AS scan_run_id,
            argMax(external_report_id, updated_ts) AS external_report_id,
            argMax(asset_id, updated_ts) AS asset_id,
            argMax(target, updated_ts) AS target,
            argMax(hostname, updated_ts) AS hostname,
            argMax(ip, updated_ts) AS ip,
            argMax(port, updated_ts) AS port,
            argMax(protocol, updated_ts) AS protocol,
            argMax(service, updated_ts) AS service,
            argMax(package_name, updated_ts) AS package_name,
            argMax(installed_version, updated_ts) AS installed_version,
            argMax(fixed_version, updated_ts) AS fixed_version,
            argMax(cve, updated_ts) AS cve,
            argMax(cvss_score, updated_ts) AS cvss_score,
            argMax(severity_vendor, updated_ts) AS severity_vendor,
            argMax(severity_normalized, updated_ts) AS severity_normalized,
            argMax(qod, updated_ts) AS qod,
            argMax(solution, updated_ts) AS solution,
            argMax(scanner_plugin_id, updated_ts) AS scanner_plugin_id,
            argMax(title, updated_ts) AS title,
            argMax(description, updated_ts) AS description,
            argMax(evidence, updated_ts) AS evidence,
            argMax(status, updated_ts) AS status,
            argMax(delta_state, updated_ts) AS delta_state,
            min(first_seen) AS first_seen,
            max(last_seen) AS last_seen,
            argMax(task_id, updated_ts) AS task_id,
            argMax(target_id, updated_ts) AS target_id,
            argMax(artifact_path, updated_ts) AS artifact_path,
            argMax(report_url, updated_ts) AS report_url,
            max(updated_ts) AS latest_updated_ts
        FROM {VULN_FINDING_TABLE} AS v
        WHERE v.scanner_family = 'greenbone'
          AND ({' OR '.join(clauses)})
        GROUP BY finding_id
    """
    rows: Dict[str, Dict[str, Any]] = {}
    for row in deps.get_ch_client().query(query).named_results():
        rows[str(row["finding_id"] or "")] = {
            "finding_id": str(row["finding_id"] or ""),
            "scan_run_id": str(row["scan_run_id"] or ""),
            "external_report_id": str(row["external_report_id"] or ""),
            "asset_id": str(row["asset_id"] or ""),
            "target": str(row["target"] or ""),
            "hostname": str(row["hostname"] or ""),
            "ip": str(row["ip"] or ""),
            "port": int(row["port"] or 0),
            "protocol": str(row["protocol"] or ""),
            "service": str(row["service"] or ""),
            "package_name": str(row["package_name"] or ""),
            "installed_version": str(row["installed_version"] or ""),
            "fixed_version": str(row["fixed_version"] or ""),
            "cve": str(row["cve"] or ""),
            "cvss_score": float(row["cvss_score"] or 0),
            "severity_vendor": str(row["severity_vendor"] or ""),
            "severity_normalized": str(row["severity_normalized"] or "info"),
            "qod": float(row["qod"] or 0),
            "solution": str(row["solution"] or ""),
            "scanner_plugin_id": str(row["scanner_plugin_id"] or ""),
            "title": str(row["title"] or ""),
            "description": str(row["description"] or ""),
            "evidence": str(row["evidence"] or ""),
            "status": str(row["status"] or "open"),
            "delta_state": str(row["delta_state"] or "new"),
            "first_seen": deps._fmt(row["first_seen"]),
            "last_seen": deps._fmt(row["last_seen"]),
            "task_id": str(row["task_id"] or ""),
            "target_id": str(row["target_id"] or ""),
            "artifact_path": str(row["artifact_path"] or ""),
            "report_url": str(row["report_url"] or ""),
            "updated_ts": deps._fmt(row["latest_updated_ts"]),
        }
    return rows


def _apply_finding_deltas(scan_run: Dict[str, Any], findings: List[Dict[str, Any]]) -> tuple[List[Dict[str, Any]], Dict[str, int]]:
    previous = _load_previous_latest_findings(
        asset_id=str(scan_run.get("asset_id") or ""),
        task_id=str(scan_run.get("task_id") or ""),
        target_id=str(scan_run.get("target_id") or ""),
        target=str(scan_run.get("target") or ""),
    )
    finished_at = str(scan_run.get("finished_at") or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
    current_ids = {str(item.get("finding_id") or "") for item in findings if str(item.get("finding_id") or "").strip()}
    new_count = 0
    reopened_count = 0
    fixed_count = 0
    rows: List[Dict[str, Any]] = []
    for item in findings:
        finding_id = str(item.get("finding_id") or "")
        prior = previous.get(finding_id)
        if prior:
            item["first_seen"] = str(prior.get("first_seen") or item.get("first_seen") or finished_at)
            prior_status = str(prior.get("status") or "open")
            if prior_status == "fixed":
                item["status"] = "reopened"
                item["delta_state"] = "reopened"
                reopened_count += 1
            elif prior_status in {"accepted_risk", "suppressed"}:
                item["status"] = prior_status
                item["delta_state"] = "unchanged"
            else:
                item["status"] = "open"
                item["delta_state"] = "unchanged"
        else:
            item["status"] = "open"
            item["delta_state"] = "new"
            new_count += 1
        item["last_seen"] = finished_at
        rows.append(item)
    for finding_id, prior in previous.items():
        if finding_id in current_ids or str(prior.get("status") or "") == "fixed":
            continue
        fixed_count += 1
        rows.append(
            {
                **prior,
                "scan_run_id": str(scan_run.get("scan_run_id") or ""),
                "external_report_id": str(scan_run.get("external_report_id") or ""),
                "status": "fixed",
                "delta_state": "fixed",
                "last_seen": finished_at,
                "artifact_path": str(scan_run.get("artifact_path") or ""),
                "report_url": str(scan_run.get("greenbone_report_url") or ""),
            }
        )
    return rows, {"new_count": new_count, "reopened_count": reopened_count, "fixed_count": fixed_count}


def _insert_scan_run(scan_run: Dict[str, Any]) -> None:
    deps = _deps()
    ensure_vulnerability_support()
    deps.get_ch_client().insert(
        VULN_SCAN_RUN_TABLE,
        [[
            str(scan_run.get("scan_run_id") or ""),
            str(scan_run.get("scanner_family") or "greenbone"),
            str(scan_run.get("external_report_id") or ""),
            str(scan_run.get("task_id") or ""),
            str(scan_run.get("task_name") or ""),
            str(scan_run.get("target_id") or ""),
            str(scan_run.get("target_name") or ""),
            str(scan_run.get("asset_id") or ""),
            str(scan_run.get("target") or ""),
            str(scan_run.get("hostname") or ""),
            str(scan_run.get("ip") or ""),
            str(scan_run.get("environment") or "prod"),
            _normalize_vuln_profile(str(scan_run.get("profile") or "network-basic")),
            _vuln_parse_ts(scan_run.get("started_at")),
            _vuln_parse_ts(scan_run.get("finished_at")),
            str(scan_run.get("status") or "completed"),
            str(scan_run.get("summary_message") or ""),
            str(scan_run.get("scanner_source") or "greenbone"),
            str(scan_run.get("artifact_path") or ""),
            str(scan_run.get("artifact_format") or "xml"),
            str(scan_run.get("greenbone_report_url") or ""),
            int(scan_run.get("asset_count") or 0),
            int(scan_run.get("finding_count") or 0),
            int(scan_run.get("unique_port_count") or 0),
            int(scan_run.get("notable_findings") or 0),
            int(scan_run.get("new_count") or 0),
            int(scan_run.get("fixed_count") or 0),
            int(scan_run.get("reopened_count") or 0),
            _csv_dump(scan_run.get("targets_csv") or scan_run.get("targets") or []),
            _csv_dump(scan_run.get("ports_csv") or scan_run.get("ports") or []),
            _csv_dump(scan_run.get("cves_csv") or scan_run.get("cves") or []),
            json.dumps(scan_run.get("severity_counts") or {}, ensure_ascii=True, sort_keys=True),
            datetime.utcnow(),
        ]],
        column_names=[
            "scan_run_id",
            "scanner_family",
            "external_report_id",
            "task_id",
            "task_name",
            "target_id",
            "target_name",
            "asset_id",
            "target",
            "hostname",
            "ip",
            "environment",
            "profile",
            "started_at",
            "finished_at",
            "status",
            "summary_message",
            "scanner_source",
            "artifact_path",
            "artifact_format",
            "greenbone_report_url",
            "asset_count",
            "finding_count",
            "unique_port_count",
            "notable_findings",
            "new_count",
            "fixed_count",
            "reopened_count",
            "targets_csv",
            "ports_csv",
            "cves_csv",
            "severity_counts_json",
            "imported_ts",
        ],
    )


def _insert_findings(rows: List[Dict[str, Any]]) -> None:
    deps = _deps()
    if not rows:
        return
    ensure_vulnerability_support()
    payload = []
    for row in rows:
        payload.append(
            [
                str(row.get("finding_id") or ""),
                str(row.get("scan_run_id") or ""),
                str(row.get("external_report_id") or ""),
                str(row.get("scanner_family") or "greenbone"),
                str(row.get("asset_id") or ""),
                str(row.get("target") or ""),
                str(row.get("hostname") or ""),
                str(row.get("ip") or ""),
                int(row.get("port") or 0),
                str(row.get("protocol") or ""),
                str(row.get("service") or ""),
                str(row.get("package_name") or ""),
                str(row.get("installed_version") or ""),
                str(row.get("fixed_version") or ""),
                str(row.get("cve") or ""),
                float(row.get("cvss_score") or 0),
                str(row.get("severity_vendor") or ""),
                str(row.get("severity_normalized") or "info"),
                float(row.get("qod") or 0),
                str(row.get("solution") or ""),
                str(row.get("scanner_plugin_id") or ""),
                str(row.get("title") or ""),
                str(row.get("description") or ""),
                str(row.get("evidence") or ""),
                str(row.get("status") or "open"),
                str(row.get("delta_state") or "new"),
                _vuln_parse_ts(row.get("first_seen")),
                _vuln_parse_ts(row.get("last_seen")),
                str(row.get("task_id") or ""),
                str(row.get("target_id") or ""),
                str(row.get("artifact_path") or ""),
                str(row.get("report_url") or ""),
                datetime.utcnow(),
            ]
        )
    deps.get_ch_client().insert(
        VULN_FINDING_TABLE,
        payload,
        column_names=[
            "finding_id",
            "scan_run_id",
            "external_report_id",
            "scanner_family",
            "asset_id",
            "target",
            "hostname",
            "ip",
            "port",
            "protocol",
            "service",
            "package_name",
            "installed_version",
            "fixed_version",
            "cve",
            "cvss_score",
            "severity_vendor",
            "severity_normalized",
            "qod",
            "solution",
            "scanner_plugin_id",
            "title",
            "description",
            "evidence",
            "status",
            "delta_state",
            "first_seen",
            "last_seen",
            "task_id",
            "target_id",
            "artifact_path",
            "report_url",
            "updated_ts",
        ],
    )


def import_greenbone_reports(limit: int = 20) -> Dict[str, Any]:
    try:
        from .vuln_greenbone import fetch_completed_reports
    except ImportError:  # pragma: no cover - local test fallback
        from vuln_greenbone import fetch_completed_reports  # type: ignore[no-redef]

    ensure_vulnerability_support()
    result = fetch_completed_reports(
        imported_report_ids=_imported_greenbone_report_ids(),
        bindings_by_task=_binding_maps()["by_task"],
        bindings_by_target=_binding_maps()["by_target"],
        asset_by_target=_cmdb_target_index(),
        limit=max(1, int(limit)),
    )
    imported_runs = []
    for bundle in result.get("imported_runs", []):
        scan_run = dict(bundle.get("scan_run") or {})
        finding_rows = [dict(item) for item in (bundle.get("findings") or [])]
        finding_rows, counters = _apply_finding_deltas(scan_run, finding_rows)
        active_rows = [row for row in finding_rows if str(row.get("status") or "") != "fixed"]
        summary_rows = active_rows or finding_rows
        scan_run["finding_count"] = len(finding_rows)
        scan_run["asset_count"] = len({row["asset_id"] for row in summary_rows if str(row.get("asset_id") or "").strip()}) or len(
            {row["target"] for row in summary_rows if str(row.get("target") or "").strip()}
        )
        scan_run["unique_port_count"] = len({int(row["port"] or 0) for row in summary_rows if int(row.get("port") or 0) > 0})
        scan_run["notable_findings"] = sum(
            1 for row in summary_rows if str(row.get("severity_normalized") or "").lower() in {"high", "critical"}
        )
        scan_run["new_count"] = counters["new_count"]
        scan_run["fixed_count"] = counters["fixed_count"]
        scan_run["reopened_count"] = counters["reopened_count"]
        scan_run["targets"] = sorted({str(row["target"] or "") for row in summary_rows if str(row.get("target") or "").strip()})
        scan_run["ports"] = sorted({str(int(row["port"])) for row in summary_rows if int(row.get("port") or 0) > 0}, key=lambda item: int(item))
        scan_run["cves"] = sorted({str(row["cve"] or "") for row in summary_rows if str(row.get("cve") or "").strip()})
        _insert_findings(finding_rows)
        _insert_scan_run(scan_run)
        imported_runs.append(
            {
                "scan_run_id": scan_run["scan_run_id"],
                "external_report_id": scan_run.get("external_report_id", ""),
                "finding_count": scan_run["finding_count"],
                "new_count": scan_run["new_count"],
                "fixed_count": scan_run["fixed_count"],
                "reopened_count": scan_run["reopened_count"],
            }
        )
    return {"status": result.get("status", "ok"), "imported": len(imported_runs), "runs": imported_runs}


def has_structured_vulnerability_data(days: int = 14) -> bool:
    deps = _deps()
    ensure_vulnerability_support()
    window_days = max(1, int(days))
    query = f"""
        SELECT
            (
                SELECT count()
                FROM {VULN_SCAN_RUN_TABLE}
                WHERE finished_at >= now() - INTERVAL {window_days} DAY
            ) AS scan_run_total,
            (
                SELECT count()
                FROM {VULN_FINDING_TABLE}
                WHERE last_seen >= now() - INTERVAL {window_days} DAY
            ) AS finding_total
    """
    row = next(iter(deps.get_ch_client().query(query).named_results()), None)
    if not row:
        return False
    return int(row.get("scan_run_total") or 0) > 0 or int(row.get("finding_total") or 0) > 0


def _vuln_latest_findings_subquery(days: int) -> str:
    ensure_vulnerability_support()
    return f"""
        SELECT
            finding_id,
            scan_run_id,
            external_report_id,
            scanner_family,
            asset_id,
            target,
            hostname,
            ip,
            port,
            protocol,
            service,
            package_name,
            installed_version,
            fixed_version,
            cve,
            cvss_score,
            severity_vendor,
            severity_normalized,
            qod,
            solution,
            scanner_plugin_id,
            title,
            description,
            evidence,
            status,
            delta_state,
            agg_first_seen AS first_seen,
            agg_last_seen AS last_seen,
            task_id,
            target_id,
            artifact_path,
            report_url,
            agg_updated_ts AS updated_ts
        FROM
        (
            SELECT
                finding_id,
                argMax(scan_run_id, updated_ts) AS scan_run_id,
                argMax(external_report_id, updated_ts) AS external_report_id,
                argMax(scanner_family, updated_ts) AS scanner_family,
                argMax(asset_id, updated_ts) AS asset_id,
                argMax(target, updated_ts) AS target,
                argMax(hostname, updated_ts) AS hostname,
                argMax(ip, updated_ts) AS ip,
                argMax(port, updated_ts) AS port,
                argMax(protocol, updated_ts) AS protocol,
                argMax(service, updated_ts) AS service,
                argMax(package_name, updated_ts) AS package_name,
                argMax(installed_version, updated_ts) AS installed_version,
                argMax(fixed_version, updated_ts) AS fixed_version,
                argMax(cve, updated_ts) AS cve,
                argMax(cvss_score, updated_ts) AS cvss_score,
                argMax(severity_vendor, updated_ts) AS severity_vendor,
                argMax(severity_normalized, updated_ts) AS severity_normalized,
                argMax(qod, updated_ts) AS qod,
                argMax(solution, updated_ts) AS solution,
                argMax(scanner_plugin_id, updated_ts) AS scanner_plugin_id,
                argMax(title, updated_ts) AS title,
                argMax(description, updated_ts) AS description,
                argMax(evidence, updated_ts) AS evidence,
                argMax(status, updated_ts) AS status,
                argMax(delta_state, updated_ts) AS delta_state,
                min(first_seen) AS agg_first_seen,
                max(last_seen) AS agg_last_seen,
                argMax(task_id, updated_ts) AS task_id,
                argMax(target_id, updated_ts) AS target_id,
                argMax(artifact_path, updated_ts) AS artifact_path,
                argMax(report_url, updated_ts) AS report_url,
                max(updated_ts) AS agg_updated_ts
            FROM {VULN_FINDING_TABLE}
            WHERE last_seen >= now() - INTERVAL {int(days)} DAY
            GROUP BY finding_id
        )
    """


def _vuln_search_clause(token: str) -> str:
    deps = _deps()
    safe_token = str(token or "").strip()
    if not safe_token:
        return "1"
    quoted = deps._sql_quote(safe_token)
    return (
        "("
        f"positionCaseInsensitiveUTF8(title, {quoted}) > 0 "
        f"OR positionCaseInsensitiveUTF8(description, {quoted}) > 0 "
        f"OR positionCaseInsensitiveUTF8(evidence, {quoted}) > 0 "
        f"OR positionCaseInsensitiveUTF8(target, {quoted}) > 0 "
        f"OR positionCaseInsensitiveUTF8(hostname, {quoted}) > 0 "
        f"OR positionCaseInsensitiveUTF8(ip, {quoted}) > 0 "
        f"OR positionCaseInsensitiveUTF8(service, {quoted}) > 0 "
        f"OR positionCaseInsensitiveUTF8(package_name, {quoted}) > 0 "
        f"OR positionCaseInsensitiveUTF8(installed_version, {quoted}) > 0 "
        f"OR positionCaseInsensitiveUTF8(fixed_version, {quoted}) > 0 "
        f"OR positionCaseInsensitiveUTF8(cve, {quoted}) > 0 "
        f"OR positionCaseInsensitiveUTF8(scan_run_id, {quoted}) > 0 "
        f"OR positionCaseInsensitiveUTF8(external_report_id, {quoted}) > 0 "
        f"OR positionCaseInsensitiveUTF8(toString(port), {quoted}) > 0"
        ")"
    )


def fetch_vulnerability_reports(limit: int = 100, days: int = 14) -> List[Dict[str, Any]]:
    deps = _deps()
    ensure_vulnerability_support()
    fetch_limit = max(int(limit) * 5, int(limit), 200)
    query = f"""
        SELECT
            scan_run_id,
            external_report_id,
            started_at,
            finished_at,
            scanner_family,
            finding_count,
            asset_count,
            unique_port_count,
            notable_findings,
            summary_message,
            scanner_source,
            artifact_path,
            greenbone_report_url,
            new_count,
            fixed_count,
            reopened_count,
            targets_csv,
            ports_csv,
            cves_csv,
            status
        FROM {VULN_SCAN_RUN_TABLE}
        WHERE finished_at >= now() - INTERVAL {int(days)} DAY
        ORDER BY finished_at DESC
        LIMIT {int(fetch_limit)}
    """
    rows: List[Dict[str, Any]] = []
    for row in deps.get_ch_client().query(query).named_results():
        report_id = str(row["scan_run_id"] or "")
        rows.append(
            {
                "report_id": report_id,
                "external_report_id": str(row["external_report_id"] or ""),
                "ts_first": deps._fmt(row["started_at"]),
                "ts_last": deps._fmt(row["finished_at"]),
                "scanner_family": str(row["scanner_family"] or "greenbone"),
                "findings_total": int(row["finding_count"] or 0),
                "target_count": int(row["asset_count"] or 0),
                "unique_ports": int(row["unique_port_count"] or 0),
                "notable_findings": int(row["notable_findings"] or 0),
                "summary_message": str(row["summary_message"] or ""),
                "scanner_source": str(row["scanner_source"] or "greenbone"),
                "targets": _csv_items(row["targets_csv"]),
                "ports": _csv_items(row["ports_csv"]),
                "cves": _csv_items(row["cves_csv"]),
                "status": str(row["status"] or "completed"),
                "new_count": int(row["new_count"] or 0),
                "fixed_count": int(row["fixed_count"] or 0),
                "reopened_count": int(row["reopened_count"] or 0),
                "artifact_path": str(row["artifact_path"] or ""),
                "artifact_link": f"/api/reports/{report_id}/artifact",
                "greenbone_report_url": str(row["greenbone_report_url"] or ""),
            }
        )
    def _scanner_priority(item: Dict[str, Any]) -> int:
        family = str(item.get("scanner_family") or item.get("scanner_source") or "").strip().lower()
        source = str(item.get("scanner_source") or "").strip().lower()
        if family in {"greenbone", "openvas"} or any(token in source for token in ("greenbone", "openvas")):
            return 0
        if family == "nmap" or "nmap" in source:
            return 2
        return 1

    rows.sort(key=lambda item: str(item.get("ts_last") or ""), reverse=True)
    rows.sort(key=_scanner_priority)
    return rows[: max(1, int(limit))]


def fetch_vulnerability_report_details(report_id: str, limit: int = 200) -> Dict[str, Any]:
    deps = _deps()
    ensure_vulnerability_support()
    safe_id = (report_id or "").strip()
    if not safe_id:
        raise ValueError("report_id is required")
    report_query = f"""
        SELECT
            scan_run_id,
            external_report_id,
            started_at,
            finished_at,
            finding_count,
            asset_count,
            unique_port_count,
            summary_message,
            scanner_source,
            artifact_path,
            greenbone_report_url,
            new_count,
            fixed_count,
            reopened_count,
            targets_csv,
            ports_csv,
            cves_csv,
            status
        FROM {VULN_SCAN_RUN_TABLE}
        WHERE scan_run_id = {deps._sql_quote(safe_id)} OR external_report_id = {deps._sql_quote(safe_id)}
        ORDER BY finished_at DESC
        LIMIT 1
    """
    report_row = next(iter(deps.get_ch_client().query(report_query).named_results()), None)
    if not report_row:
        raise ValueError("Report not found")
    resolved_scan_run_id = str(report_row["scan_run_id"] or safe_id)
    finding_query = f"""
        SELECT
            target,
            hostname,
            ip,
            port,
            service,
            package_name,
            installed_version,
            fixed_version,
            cve,
            cvss_score,
            severity_normalized,
            solution,
            title,
            description,
            evidence,
            status,
            delta_state,
            first_seen,
            last_seen,
            report_url
        FROM {VULN_FINDING_TABLE}
        WHERE scan_run_id = {deps._sql_quote(resolved_scan_run_id)}
        ORDER BY last_seen DESC
        LIMIT {max(int(limit) * 4, int(limit))}
    """
    grouped: Dict[str, Dict[str, Any]] = {}
    for row in deps.get_ch_client().query(finding_query).named_results():
        base_key = "|".join(
            [
                str(row["target"] or ""),
                str(row["hostname"] or ""),
                str(row["port"] or 0),
                str(row["service"] or ""),
                str(row["package_name"] or ""),
                str(row["title"] or ""),
                str(row["status"] or ""),
                str(row["delta_state"] or ""),
            ]
        )
        item = grouped.get(base_key)
        if item is None:
            item = {
                "ts": deps._fmt(row["last_seen"]),
                "source": str(report_row["scanner_source"] or "greenbone"),
                "target": str(row["target"] or ""),
                "host_name": str(row["hostname"] or ""),
                "dst_ip": str(row["ip"] or row["target"] or ""),
                "dst_port": int(row["port"] or 0),
                "port": int(row["port"] or 0),
                "service": str(row["service"] or row["package_name"] or ""),
                "process_name": str(row["service"] or row["package_name"] or ""),
                "installed_version": str(row["installed_version"] or ""),
                "fixed_version": str(row["fixed_version"] or ""),
                "severity": str(row["severity_normalized"] or "info"),
                "status": str(row["status"] or "open"),
                "delta_state": str(row["delta_state"] or "new"),
                "title": str(row["title"] or ""),
                "summary_message": str(row["title"] or ""),
                "message": " ".join(
                    part for part in [str(row["title"] or ""), str(row["description"] or ""), str(row["evidence"] or "")] if part
                ).strip(),
                "description": str(row["description"] or ""),
                "solution": str(row["solution"] or ""),
                "cvss_score": float(row["cvss_score"] or 0),
                "report_url": str(row["report_url"] or ""),
                "first_seen": deps._fmt(row["first_seen"]),
                "last_seen": deps._fmt(row["last_seen"]),
                "cves": [],
            }
            grouped[base_key] = item
        cve = str(row["cve"] or "").strip()
        if cve and cve not in item["cves"]:
            item["cves"].append(cve)
    findings = list(grouped.values())[: int(limit)]
    return {
        "report_id": resolved_scan_run_id,
        "external_report_id": str(report_row["external_report_id"] or ""),
        "summary_message": str(report_row["summary_message"] or ""),
        "scanner_source": str(report_row["scanner_source"] or "greenbone"),
        "status": str(report_row["status"] or "completed"),
        "artifact_path": str(report_row["artifact_path"] or ""),
        "artifact_link": f"/api/reports/{resolved_scan_run_id}/artifact",
        "greenbone_report_url": str(report_row["greenbone_report_url"] or ""),
        "finding_count": int(report_row["finding_count"] or 0),
        "target_count": int(report_row["asset_count"] or 0),
        "port_count": int(report_row["unique_port_count"] or 0),
        "new_count": int(report_row["new_count"] or 0),
        "fixed_count": int(report_row["fixed_count"] or 0),
        "reopened_count": int(report_row["reopened_count"] or 0),
        "cves": _csv_items(report_row["cves_csv"]),
        "targets": _csv_items(report_row["targets_csv"]),
        "ports": _csv_items(report_row["ports_csv"]),
        "findings": findings,
    }


def get_report_artifact_path(report_id: str) -> str:
    deps = _deps()
    ensure_vulnerability_support()
    safe_id = str(report_id or "").strip()
    if not safe_id:
        return ""
    row = next(
        iter(
            deps.get_ch_client()
            .query(
                f"""
                SELECT artifact_path
                FROM {VULN_SCAN_RUN_TABLE}
                WHERE scan_run_id = {deps._sql_quote(safe_id)} OR external_report_id = {deps._sql_quote(safe_id)}
                ORDER BY finished_at DESC
                LIMIT 1
                """
            )
            .result_rows
        ),
        None,
    )
    return str(row[0] or "") if row else ""


def fetch_vulnerability_inventory(days: int = 30, limit: int = 25) -> Dict[str, Any]:
    deps = _deps()
    latest = _vuln_latest_findings_subquery(days)
    open_filter = "status != 'fixed'"
    summary_query = f"""
        SELECT
            countIf({open_filter}) AS findings,
            countDistinctIf(if(target != '', target, if(hostname != '', hostname, ip)), {open_filter}) AS targets,
            countDistinctIf(port, {open_filter} AND port > 0) AS ports,
            countDistinctIf(scan_run_id, 1) AS reports,
            countIf(delta_state = 'new' AND {open_filter}) AS new_findings,
            countIf(delta_state = 'reopened' AND {open_filter}) AS reopened_findings,
            countIf(status = 'fixed') AS fixed_findings,
            countIf(severity_normalized = 'critical' AND {open_filter}) AS critical_findings
        FROM ({latest})
    """
    target_expr = "if(target != '', target, if(hostname != '', hostname, ip))"
    service_expr = "lower(if(package_name != '', package_name, if(service != '', service, 'unknown')))"
    hosts_query = f"""
        SELECT
            {target_expr} AS target_key,
            count() AS findings,
            countDistinctIf(port, port > 0) AS open_ports,
            max(last_seen) AS last_seen,
            groupUniqArray(6)({service_expr}) AS services
        FROM ({latest})
        WHERE {open_filter}
          AND target_key != ''
        GROUP BY target_key
        ORDER BY findings DESC, last_seen DESC
        LIMIT {int(limit)}
    """
    services_query = f"""
        SELECT
            {service_expr} AS service_key,
            count() AS findings,
            countDistinct({target_expr}) AS hosts,
            max(last_seen) AS last_seen,
            groupUniqArray(6)(toString(port)) AS ports
        FROM ({latest})
        WHERE {open_filter}
          AND service_key != ''
        GROUP BY service_key
        ORDER BY findings DESC, last_seen DESC
        LIMIT {int(limit)}
    """
    cves_query = f"""
        SELECT
            cve,
            count() AS findings,
            max(last_seen) AS last_seen,
            groupUniqArray(6)({target_expr}) AS hosts
        FROM ({latest})
        WHERE {open_filter}
          AND cve != ''
        GROUP BY cve
        ORDER BY findings DESC, last_seen DESC
        LIMIT {int(limit)}
    """
    summary = next(iter(deps.get_ch_client().query(summary_query).named_results()), None) or {}
    hosts = [
        {
            "target": str(row["target_key"] or ""),
            "findings": int(row["findings"] or 0),
            "open_ports": int(row["open_ports"] or 0),
            "last_seen": deps._fmt(row["last_seen"]),
            "services": [str(item) for item in (row["services"] or []) if str(item or "").strip()],
        }
        for row in deps.get_ch_client().query(hosts_query).named_results()
    ]
    services = [
        {
            "service": str(row["service_key"] or "unknown"),
            "findings": int(row["findings"] or 0),
            "hosts": int(row["hosts"] or 0),
            "last_seen": deps._fmt(row["last_seen"]),
            "ports": [str(item) for item in (row["ports"] or []) if str(item or "").strip() and str(item) != "0"],
        }
        for row in deps.get_ch_client().query(services_query).named_results()
    ]
    cves = [
        {
            "cve": str(row["cve"] or ""),
            "findings": int(row["findings"] or 0),
            "last_seen": deps._fmt(row["last_seen"]),
            "hosts": [str(item) for item in (row["hosts"] or []) if str(item or "").strip()],
        }
        for row in deps.get_ch_client().query(cves_query).named_results()
    ]
    return {
        "summary": {
            "findings": int(summary.get("findings") or 0),
            "targets": int(summary.get("targets") or 0),
            "ports": int(summary.get("ports") or 0),
            "reports": int(summary.get("reports") or 0),
            "new_findings": int(summary.get("new_findings") or 0),
            "reopened_findings": int(summary.get("reopened_findings") or 0),
            "fixed_findings": int(summary.get("fixed_findings") or 0),
            "critical_findings": int(summary.get("critical_findings") or 0),
        },
        "hosts": hosts,
        "services": services,
        "cves": cves,
    }


def search_vulnerability_findings(query_text: str = "", days: int = 30, limit: int = 120) -> Dict[str, Any]:
    deps = _deps()
    latest = _vuln_latest_findings_subquery(days)
    sql = f"""
        SELECT
            scan_run_id,
            external_report_id,
            target,
            hostname,
            ip,
            port,
            severity_normalized,
            status,
            delta_state,
            service,
            package_name,
            installed_version,
            fixed_version,
            cve,
            cvss_score,
            qod,
            solution,
            title,
            description,
            evidence,
            artifact_path,
            report_url,
            last_seen
        FROM ({latest})
        WHERE {_vuln_search_clause(query_text)}
        ORDER BY updated_ts DESC
        LIMIT {int(limit)}
    """
    rows = []
    for row in deps.get_ch_client().query(sql).named_results():
        message = " ".join(
            part for part in [str(row["title"] or ""), str(row["description"] or ""), str(row["evidence"] or "")] if part
        ).strip()
        report_id = str(row["scan_run_id"] or "")
        rows.append(
            {
                "ts": deps._fmt(row["last_seen"]),
                "report_id": report_id,
                "external_report_id": str(row["external_report_id"] or ""),
                "source": "greenbone",
                "host_name": str(row["hostname"] or ""),
                "dst_ip": str(row["ip"] or row["target"] or ""),
                "dst_port": int(row["port"] or 0),
                "severity": str(row["severity_normalized"] or "info"),
                "status": str(row["status"] or "open"),
                "delta_state": str(row["delta_state"] or "new"),
                "service": str(row["service"] or row["package_name"] or "unknown"),
                "package_name": str(row["package_name"] or ""),
                "installed_version": str(row["installed_version"] or ""),
                "fixed_version": str(row["fixed_version"] or ""),
                "message": message,
                "title": str(row["title"] or ""),
                "description": str(row["description"] or ""),
                "solution": str(row["solution"] or ""),
                "cvss_score": float(row["cvss_score"] or 0),
                "qod": float(row["qod"] or 0),
                "cves": [str(row["cve"] or "")] if str(row["cve"] or "").strip() else [],
                "artifact_path": str(row["artifact_path"] or ""),
                "report_url": str(row["report_url"] or ""),
                "artifact_link": f"/api/reports/{report_id}/artifact",
            }
        )
    return {"query": str(query_text or "").strip(), "row_count": len(rows), "items": rows}


def fetch_vulnerability_hosts(query_text: str = "", days: int = 30, limit: int = 120) -> Dict[str, Any]:
    deps = _deps()
    latest = _vuln_latest_findings_subquery(days)
    target_expr = "if(target != '', target, if(hostname != '', hostname, ip))"
    service_expr = "lower(if(package_name != '', package_name, if(service != '', service, 'unknown')))"
    sql = f"""
        SELECT
            {target_expr} AS target_key,
            count() AS findings,
            countDistinctIf(port, port > 0) AS open_ports,
            countDistinct(scan_run_id) AS reports,
            max(last_seen) AS last_seen,
            groupUniqArray(8)({service_expr}) AS services,
            groupUniqArray(8)(toString(port)) AS ports
        FROM ({latest})
        WHERE status != 'fixed'
          AND ({_vuln_search_clause(query_text)})
          AND target_key != ''
        GROUP BY target_key
        ORDER BY findings DESC, last_seen DESC
        LIMIT {int(limit)}
    """
    rows = [
        {
            "target": str(row["target_key"] or ""),
            "findings": int(row["findings"] or 0),
            "open_ports": int(row["open_ports"] or 0),
            "reports": int(row["reports"] or 0),
            "last_seen": deps._fmt(row["last_seen"]),
            "services": [str(item) for item in (row["services"] or []) if str(item or "").strip()],
            "ports": [str(item) for item in (row["ports"] or []) if str(item or "").strip() and str(item) != "0"],
        }
        for row in deps.get_ch_client().query(sql).named_results()
    ]
    return {"query": str(query_text or "").strip(), "row_count": len(rows), "items": rows}


def fetch_vulnerability_software(query_text: str = "", days: int = 30, limit: int = 120) -> Dict[str, Any]:
    deps = _deps()
    latest = _vuln_latest_findings_subquery(days)
    target_expr = "if(target != '', target, if(hostname != '', hostname, ip))"
    service_expr = "lower(if(package_name != '', package_name, if(service != '', service, 'unknown')))"
    sql = f"""
        SELECT
            {service_expr} AS service_key,
            count() AS findings,
            countDistinct({target_expr}) AS hosts,
            countDistinct(scan_run_id) AS reports,
            max(last_seen) AS last_seen,
            groupUniqArray(8)({target_expr}) AS host_samples,
            groupUniqArray(8)(toString(port)) AS ports
        FROM ({latest})
        WHERE status != 'fixed'
          AND ({_vuln_search_clause(query_text)})
          AND service_key != ''
        GROUP BY service_key
        ORDER BY findings DESC, last_seen DESC
        LIMIT {int(limit)}
    """
    rows = [
        {
            "service": str(row["service_key"] or "unknown"),
            "findings": int(row["findings"] or 0),
            "hosts": int(row["hosts"] or 0),
            "reports": int(row["reports"] or 0),
            "last_seen": deps._fmt(row["last_seen"]),
            "host_samples": [str(item) for item in (row["host_samples"] or []) if str(item or "").strip()],
            "ports": [str(item) for item in (row["ports"] or []) if str(item or "").strip() and str(item) != "0"],
        }
        for row in deps.get_ch_client().query(sql).named_results()
    ]
    return {"query": str(query_text or "").strip(), "row_count": len(rows), "items": rows}


def fetch_vulnerability_cves(query_text: str = "", days: int = 30, limit: int = 120) -> Dict[str, Any]:
    deps = _deps()
    latest = _vuln_latest_findings_subquery(days)
    target_expr = "if(target != '', target, if(hostname != '', hostname, ip))"
    service_expr = "lower(if(package_name != '', package_name, if(service != '', service, 'unknown')))"
    sql = f"""
        SELECT
            cve,
            count() AS findings,
            countDistinct({target_expr}) AS hosts,
            countDistinct(scan_run_id) AS reports,
            max(last_seen) AS last_seen,
            groupUniqArray(8)({target_expr}) AS host_samples,
            groupUniqArray(8)({service_expr}) AS services
        FROM ({latest})
        WHERE status != 'fixed'
          AND cve != ''
          AND ({_vuln_search_clause(query_text)})
        GROUP BY cve
        ORDER BY findings DESC, last_seen DESC
        LIMIT {int(limit)}
    """
    rows = [
        {
            "cve": str(row["cve"] or ""),
            "findings": int(row["findings"] or 0),
            "hosts": int(row["hosts"] or 0),
            "reports": int(row["reports"] or 0),
            "last_seen": deps._fmt(row["last_seen"]),
            "host_samples": [str(item) for item in (row["host_samples"] or []) if str(item or "").strip()],
            "services": [str(item) for item in (row["services"] or []) if str(item or "").strip()],
        }
        for row in deps.get_ch_client().query(sql).named_results()
    ]
    return {"query": str(query_text or "").strip(), "row_count": len(rows), "items": rows}
