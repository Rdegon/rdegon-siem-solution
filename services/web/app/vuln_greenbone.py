from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha1
from pathlib import Path
import re
import xml.etree.ElementTree as ET
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from typing import Any, Callable, Dict, Iterable, List

try:
    from .config import CONFIG
except ImportError:  # pragma: no cover - local test fallback
    from config import CONFIG  # type: ignore[no-redef]


REPORT_PORT_RE = re.compile(r"(?P<port>\d+)/(?:tcp|udp)(?:\s+\((?P<service>[^)]+)\))?", re.IGNORECASE)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

def _moscow_tz():
    try:
        return ZoneInfo("Europe/Moscow")
    except ZoneInfoNotFoundError:  # pragma: no cover - depends on host tzdata packaging
        return timezone(timedelta(hours=3), name="Europe/Moscow")


MSK = _moscow_tz()


def _import_gvm() -> tuple[Any, Any, Any]:
    try:
        from gvm.connections import TLSConnection
        from gvm.protocols.gmp import Gmp
        from gvm.transforms import EtreeTransform
    except ImportError as exc:  # pragma: no cover - optional until Greenbone is installed
        raise RuntimeError(
            "python-gvm is not installed. Add it from requirements-web.txt before enabling Greenbone sync/import."
        ) from exc
    return TLSConnection, Gmp, EtreeTransform


def greenbone_is_configured() -> bool:
    return bool(CONFIG.greenbone.enabled)


def _require_greenbone() -> None:
    if not CONFIG.greenbone.enabled:
        raise RuntimeError(
            "Greenbone integration is not configured. Set SIEM_GREENBONE_HOST, SIEM_GREENBONE_USERNAME and SIEM_GREENBONE_PASSWORD."
        )


def _safe_text(value: Any) -> str:
    return str(value or "").strip()


def _xml_text(node: ET.Element | None, path: str = "", default: str = "") -> str:
    if node is None:
        return default
    if not path:
        return _safe_text(node.text) or default
    found = node.find(path)
    if found is None:
        return default
    return _safe_text(found.text) or default


def _response_id(node: ET.Element | None) -> str:
    if node is None:
        return ""
    return _safe_text(node.get("id"))


def _resource_map(response: ET.Element, item_tag: str) -> Dict[str, Dict[str, str]]:
    items: Dict[str, Dict[str, str]] = {}
    for node in response.findall(f".//{item_tag}"):
        name = _xml_text(node, "name")
        if not name:
            continue
        items[name] = {"id": _response_id(node), "name": name}
    return items


def _task_map(response: ET.Element) -> Dict[str, Dict[str, str]]:
    items: Dict[str, Dict[str, str]] = {}
    for node in response.findall(".//task"):
        name = _xml_text(node, "name")
        if not name:
            continue
        target_node = node.find("target")
        items[name] = {
            "id": _response_id(node),
            "name": name,
            "target_id": _safe_text(target_node.get("id") if target_node is not None else ""),
        }
    return items


def _schedule_start(hour: int, minute: int) -> datetime:
    now = datetime.now(MSK).replace(second=0, microsecond=0)
    start = now.replace(hour=hour, minute=minute)
    if start <= now:
        start += timedelta(days=1)
    return start


def _ics_payload(start: datetime, rrule: str) -> str:
    utc_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    start_text = start.strftime("%Y%m%dT%H%M%S")
    return "\r\n".join(
        [
            "BEGIN:VCALENDAR",
            "VERSION:2.0",
            "PRODID:-//Rdegon SIEM//Vulnerability Manager//EN",
            "BEGIN:VEVENT",
            f"DTSTAMP:{utc_stamp}",
            f"DTSTART;TZID=Europe/Moscow:{start_text}",
            f"RRULE:{rrule}",
            "END:VEVENT",
            "END:VCALENDAR",
            "",
        ]
    )


def _connect_gmp():
    _require_greenbone()
    TLSConnection, Gmp, EtreeTransform = _import_gvm()
    cfg = CONFIG.greenbone
    connection = TLSConnection(
        hostname=cfg.host,
        port=cfg.port,
        timeout=60,
        cafile=None if cfg.insecure_tls else None,
    )
    return Gmp(connection=connection, transform=EtreeTransform())


def _with_gmp(fn: Callable[[Any], Any]) -> Any:
    cfg = CONFIG.greenbone
    with _connect_gmp() as gmp:
        gmp.authenticate(cfg.username, cfg.password)
        return fn(gmp)


def probe_greenbone() -> Dict[str, Any]:
    _require_greenbone()

    def _run(gmp: Any) -> Dict[str, Any]:
        version = ""
        if hasattr(gmp, "get_version"):
            try:
                response = gmp.get_version()
                version = _xml_text(response, "version") or _xml_text(response, ".//version")
            except Exception:  # noqa: BLE001
                version = ""
        return {
            "status": "ok",
            "authenticated": True,
            "host": _safe_text(CONFIG.greenbone.host),
            "port": int(CONFIG.greenbone.port or 0),
            "version": version,
        }

    return _with_gmp(_run)


def _ensure_schedule(gmp: Any, schedule_name: str, icalendar: str) -> str:
    schedules = _resource_map(gmp.get_schedules(), "schedule")
    existing = schedules.get(schedule_name)
    if existing:
        return existing["id"]
    response = gmp.create_schedule(
        name=schedule_name,
        icalendar=icalendar,
        timezone="Europe/Moscow",
        comment="Managed by Rdegon SIEM vulnerability sync.",
    )
    return _response_id(response)


def _resolve_scan_config_id(gmp: Any) -> str:
    wanted = _safe_text(CONFIG.greenbone.default_scan_config)
    configs = _resource_map(gmp.get_scan_configs(), "config")
    if wanted and wanted in configs:
        return configs[wanted]["id"]
    if not configs:
        raise RuntimeError("Greenbone scan configurations are unavailable")
    return next(iter(configs.values()))["id"]


def _resolve_scanner_id(gmp: Any) -> str:
    wanted = _safe_text(CONFIG.greenbone.default_scanner)
    response = gmp.get_scanners()
    scanners: List[Dict[str, str]] = []
    for node in response.findall(".//scanner"):
        scanners.append(
            {
                "id": _response_id(node),
                "name": _xml_text(node, "name"),
                "type": _xml_text(node, "type"),
            }
        )
    if wanted:
        for scanner in scanners:
            if scanner["name"] == wanted and scanner["id"]:
                return scanner["id"]
    for scanner in scanners:
        if scanner["name"] == "OpenVAS Default" and scanner["id"]:
            return scanner["id"]
    for scanner in scanners:
        if scanner["type"] == "2" and scanner["id"]:
            return scanner["id"]
    for scanner in scanners:
        if scanner["name"].lower() != "cve" and scanner["id"]:
            return scanner["id"]
    if not scanners:
        raise RuntimeError("Greenbone scanners are unavailable")
    return scanners[0]["id"]


def _resolve_port_list_id(gmp: Any) -> str:
    wanted = _safe_text(CONFIG.greenbone.default_port_list)
    port_lists = _resource_map(gmp.get_port_lists(), "port_list")
    if wanted and wanted in port_lists:
        return port_lists[wanted]["id"]
    for fallback in (
        "All TCP and Nmap top 100 UDP",
        "All IANA assigned TCP and UDP",
        "All IANA assigned TCP",
    ):
        if fallback in port_lists:
            return port_lists[fallback]["id"]
    if not port_lists:
        raise RuntimeError("Greenbone port lists are unavailable")
    return next(iter(port_lists.values()))["id"]


def _resolve_alive_test() -> str:
    return _safe_text(CONFIG.greenbone.default_alive_test) or "Consider Alive"


def _asset_target_host(asset: Dict[str, Any]) -> str:
    return _safe_text(asset.get("ip")) or _safe_text(asset.get("hostname"))


def _asset_tags(asset: Dict[str, Any]) -> set[str]:
    raw = asset.get("tags") or []
    if isinstance(raw, str):
        values = [part.strip() for part in raw.split(",")]
    else:
        values = [str(item or "").strip() for item in raw]
    return {item.lower() for item in values if item}


def _asset_schedule_name(asset: Dict[str, Any]) -> str:
    criticality = _safe_text(asset.get("criticality")).lower()
    tags = _asset_tags(asset)
    if criticality in {"high", "critical"} or tags.intersection({"edge", "internet-facing", "public", "vpn"}):
        return CONFIG.greenbone.daily_schedule_name
    return CONFIG.greenbone.weekly_schedule_name


def _asset_profile(asset: Dict[str, Any]) -> str:
    profile = _safe_text(asset.get("vuln_profile")).lower()
    return profile if profile in {"network-basic", "linux-ssh"} else "network-basic"


def _target_comment(asset: Dict[str, Any]) -> str:
    return (
        f"Managed by SIEM. asset_id={_safe_text(asset.get('asset_id'))}; "
        f"profile={_asset_profile(asset)}; environment={_safe_text(asset.get('environment')) or 'prod'}"
    )


def _task_name(asset: Dict[str, Any]) -> str:
    return f"SIEM {_safe_text(asset.get('asset_id'))} {_asset_profile(asset)}".strip()


def _target_name(asset: Dict[str, Any]) -> str:
    return f"SIEM {_safe_text(asset.get('asset_id'))} target".strip()


def _target_kwargs(asset: Dict[str, Any], *, port_list_id: str, alive_test: str) -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {
        "hosts": [_asset_target_host(asset)],
        "comment": _target_comment(asset),
        "port_list_id": port_list_id,
        "alive_test": alive_test,
    }
    if _asset_profile(asset) == "linux-ssh" and CONFIG.greenbone.ssh_credential_id:
        kwargs["ssh_credential_id"] = CONFIG.greenbone.ssh_credential_id
        kwargs["ssh_credential_port"] = 22
    return kwargs


def sync_assets(
    assets: Iterable[Dict[str, Any]],
    bindings_by_asset: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    enabled_assets = [dict(asset) for asset in assets if bool(asset.get("vuln_enabled")) and _asset_target_host(asset)]
    if not enabled_assets:
        return {"status": "no-op", "synced": 0, "failed": 0, "items": []}

    daily_ics = _ics_payload(_schedule_start(2, 0), "FREQ=DAILY;INTERVAL=1")
    weekly_ics = _ics_payload(_schedule_start(1, 0), "FREQ=WEEKLY;BYDAY=SU")

    def _run(gmp: Any) -> Dict[str, Any]:
        schedule_ids = {
            CONFIG.greenbone.daily_schedule_name: _ensure_schedule(gmp, CONFIG.greenbone.daily_schedule_name, daily_ics),
            CONFIG.greenbone.weekly_schedule_name: _ensure_schedule(gmp, CONFIG.greenbone.weekly_schedule_name, weekly_ics),
        }
        scan_config_id = _resolve_scan_config_id(gmp)
        scanner_id = _resolve_scanner_id(gmp)
        port_list_id = _resolve_port_list_id(gmp)
        alive_test = _resolve_alive_test()
        targets = _resource_map(gmp.get_targets(filter_string="rows=-1"), "target")
        tasks = _task_map(gmp.get_tasks(filter_string="rows=-1"))
        results: List[Dict[str, Any]] = []
        for asset in enabled_assets:
            asset_id = _safe_text(asset.get("asset_id"))
            target_name = _target_name(asset)
            task_name = _task_name(asset)
            schedule_name = _asset_schedule_name(asset)
            binding = bindings_by_asset.get(asset_id) or {}
            try:
                target_id = _safe_text(binding.get("target_id"))
                if target_id:
                    gmp.modify_target(
                        target_id,
                        name=target_name,
                        **_target_kwargs(asset, port_list_id=port_list_id, alive_test=alive_test),
                    )
                elif target_name in targets and targets[target_name]["id"]:
                    target_id = targets[target_name]["id"]
                    gmp.modify_target(
                        target_id,
                        **_target_kwargs(asset, port_list_id=port_list_id, alive_test=alive_test),
                    )
                else:
                    response = gmp.create_target(
                        target_name,
                        **_target_kwargs(asset, port_list_id=port_list_id, alive_test=alive_test),
                    )
                    target_id = _response_id(response)
                    if not target_id:
                        target_id = _safe_text(
                            (
                                _resource_map(
                                    gmp.get_targets(filter_string="rows=-1"),
                                    "target",
                                ).get(target_name)
                                or {}
                            ).get("id")
                        )
                if not target_id:
                    raise RuntimeError(f"Greenbone did not return a target id for {target_name}")

                task_id = _safe_text(binding.get("task_id"))
                if task_id:
                    gmp.modify_task(
                        task_id,
                        name=task_name,
                        config_id=scan_config_id,
                        target_id=target_id,
                        scanner_id=scanner_id,
                        schedule_id=schedule_ids[schedule_name],
                        schedule_periods=0,
                        comment="Managed by Rdegon SIEM vulnerability sync.",
                    )
                elif task_name in tasks and tasks[task_name]["id"]:
                    task_id = tasks[task_name]["id"]
                    gmp.modify_task(
                        task_id,
                        config_id=scan_config_id,
                        target_id=target_id,
                        scanner_id=scanner_id,
                        schedule_id=schedule_ids[schedule_name],
                        schedule_periods=0,
                        comment="Managed by Rdegon SIEM vulnerability sync.",
                    )
                else:
                    response = gmp.create_task(
                        task_name,
                        scan_config_id,
                        target_id,
                        scanner_id,
                        schedule_id=schedule_ids[schedule_name],
                        schedule_periods=0,
                        comment="Managed by Rdegon SIEM vulnerability sync.",
                    )
                    task_id = _response_id(response)
                    if not task_id:
                        task_id = _safe_text(
                            (
                                _task_map(
                                    gmp.get_tasks(filter_string="rows=-1")
                                ).get(task_name)
                                or {}
                            ).get("id")
                        )
                if not task_id:
                    raise RuntimeError(f"Greenbone did not return a task id for {task_name}")

                results.append(
                    {
                        "asset_id": asset_id,
                        "scanner_family": "greenbone",
                        "profile": _asset_profile(asset),
                        "environment": _safe_text(asset.get("environment")) or "prod",
                        "target_ref": _asset_target_host(asset),
                        "target_id": target_id,
                        "target_name": target_name,
                        "task_id": task_id,
                        "task_name": task_name,
                        "schedule_name": schedule_name,
                        "sync_status": "synced",
                        "sync_message": "",
                    }
                )
            except Exception as exc:  # noqa: BLE001
                results.append(
                    {
                        "asset_id": asset_id,
                        "scanner_family": "greenbone",
                        "profile": _asset_profile(asset),
                        "environment": _safe_text(asset.get("environment")) or "prod",
                        "target_ref": _asset_target_host(asset),
                        "target_id": _safe_text(binding.get("target_id")),
                        "target_name": target_name,
                        "task_id": _safe_text(binding.get("task_id")),
                        "task_name": task_name,
                        "schedule_name": schedule_name,
                        "sync_status": "error",
                        "sync_message": str(exc),
                    }
                )
        enabled_ids = {_safe_text(asset.get("asset_id")) for asset in enabled_assets}
        for asset_id, binding in bindings_by_asset.items():
            if asset_id in enabled_ids:
                continue
            task_id = _safe_text(binding.get("task_id"))
            try:
                if task_id and _safe_text(binding.get("sync_status")) != "retired":
                    gmp.delete_task(task_id)
                results.append(
                    {
                        "asset_id": asset_id,
                        "scanner_family": "greenbone",
                        "profile": _safe_text(binding.get("profile")) or "network-basic",
                        "environment": _safe_text(binding.get("environment")) or "prod",
                        "target_ref": _safe_text(binding.get("target_ref")),
                        "target_id": _safe_text(binding.get("target_id")),
                        "target_name": _safe_text(binding.get("target_name")),
                        "task_id": "",
                        "task_name": _safe_text(binding.get("task_name")),
                        "schedule_name": "",
                        "sync_status": "retired",
                        "sync_message": "Asset is missing, disabled, or removed from vulnerability coverage.",
                    }
                )
            except Exception as exc:  # noqa: BLE001
                results.append(
                    {
                        **binding,
                        "asset_id": asset_id,
                        "scanner_family": "greenbone",
                        "sync_status": "error",
                        "sync_message": f"Unable to retire scanner task: {exc}",
                    }
                )
        retired = sum(1 for item in results if item["sync_status"] == "retired")
        failed = sum(1 for item in results if item["sync_status"] == "error")
        return {
            "status": "ok" if failed == 0 else "degraded",
            "synced": sum(1 for item in results if item["sync_status"] == "synced"),
            "retired": retired,
            "failed": failed,
            "items": results,
        }

    return _with_gmp(_run)


def start_tasks(bindings: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    requested = [dict(item) for item in bindings if _safe_text(item.get("task_id"))]
    if not requested:
        return {"status": "no-op", "started": 0, "skipped": 0, "failed": 0, "items": []}

    def _run(gmp: Any) -> Dict[str, Any]:
        task_states: Dict[str, str] = {}
        response = gmp.get_tasks(filter_string="rows=-1")
        for node in response.findall(".//task"):
            task_id = _response_id(node)
            if task_id:
                task_states[task_id] = _xml_text(node, "status").lower()

        results: List[Dict[str, Any]] = []
        active_states = {"requested", "queued", "running", "processing", "stop requested"}
        for binding in requested:
            task_id = _safe_text(binding.get("task_id"))
            state = task_states.get(task_id, "")
            result = {
                "asset_id": _safe_text(binding.get("asset_id")),
                "task_id": task_id,
                "task_name": _safe_text(binding.get("task_name")),
                "previous_status": state,
            }
            if state in active_states:
                results.append({**result, "status": "skipped", "message": f"task already {state}"})
                continue
            try:
                started = gmp.start_task(task_id)
                results.append(
                    {
                        **result,
                        "status": "started",
                        "report_id": _response_id(started),
                        "message": "",
                    }
                )
            except Exception as exc:  # noqa: BLE001
                results.append({**result, "status": "error", "message": str(exc)})
        started_total = sum(1 for item in results if item["status"] == "started")
        skipped_total = sum(1 for item in results if item["status"] == "skipped")
        failed_total = sum(1 for item in results if item["status"] == "error")
        return {
            "status": "ok" if failed_total == 0 else "degraded",
            "started": started_total,
            "skipped": skipped_total,
            "failed": failed_total,
            "items": results,
        }

    return _with_gmp(_run)


def _find_report_node(response: ET.Element) -> ET.Element | None:
    if response.tag == "report":
        return response
    report = response.find(".//report")
    if report is not None:
        nested = report.find("report")
        return nested if nested is not None else report
    return None


def _report_nodes(response: ET.Element) -> List[ET.Element]:
    direct = list(response.findall("./report"))
    return direct or list(response.findall(".//report"))


def _parse_port(value: str) -> tuple[int, str, str]:
    text = _safe_text(value)
    if not text:
        return 0, "", ""
    match = REPORT_PORT_RE.search(text)
    if not match:
        return 0, "", ""
    return int(match.group("port") or 0), "tcp" if "/tcp" in text.lower() else "udp", _safe_text(match.group("service"))


def _severity_label(score: float) -> str:
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _join_text(node: ET.Element | None) -> str:
    if node is None:
        return ""
    parts = [part.strip() for part in node.itertext() if part and part.strip()]
    return " ".join(parts)


def _extract_cves(result: ET.Element) -> List[str]:
    values: List[str] = []
    for ref in result.findall(".//nvt/refs/ref"):
        ref_id = _safe_text(ref.get("id") or ref.text)
        ref_type = _safe_text(ref.get("type")).lower()
        if ref_type == "cve" and ref_id:
            values.append(ref_id.upper())
    text_blob = " ".join(
        [
            _xml_text(result, "name"),
            _join_text(result.find("description")),
            _join_text(result.find("nvt")),
        ]
    )
    for match in CVE_RE.findall(text_blob):
        values.append(match.upper())
    return sorted(set(values))


def _artifact_path(report_id: str) -> Path:
    root = Path(CONFIG.greenbone.artifact_dir)
    root.mkdir(parents=True, exist_ok=True)
    return root / f"{report_id}.xml"


def _report_url(report_id: str) -> str:
    base = _safe_text(CONFIG.greenbone.web_base_url).rstrip("/")
    if not base:
        return ""
    return f"{base}/reports/{report_id}"


def _report_binding(
    task_id: str,
    target_id: str,
    target_value: str,
    bindings_by_task: Dict[str, Dict[str, Any]],
    bindings_by_target: Dict[str, Dict[str, Any]],
    asset_by_target: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    if task_id and task_id in bindings_by_task:
        return bindings_by_task[task_id]
    if target_id and target_id in bindings_by_target:
        return bindings_by_target[target_id]
    return asset_by_target.get(target_value.lower(), {})


def _finding_key(parts: Iterable[str]) -> str:
    payload = "|".join(_safe_text(part).lower() for part in parts)
    return sha1(payload.encode("utf-8")).hexdigest()


def _result_findings(
    result: ET.Element,
    *,
    scan_run_id: str,
    external_report_id: str,
    task_id: str,
    target_id: str,
    binding: Dict[str, Any],
    started_at: str,
    finished_at: str,
    artifact_path: str,
    report_url: str,
) -> List[Dict[str, Any]]:
    target = _xml_text(result, "host") or _safe_text(binding.get("target_ref"))
    hostname = _xml_text(result, "hostname") or _xml_text(result, "host")
    port_text = _xml_text(result, "port")
    port, protocol, detected_service = _parse_port(port_text)
    service = detected_service or _xml_text(result, "service") or _xml_text(result, "nvt/name")
    title = _xml_text(result, "name") or _xml_text(result, "nvt/name") or service or "Greenbone finding"
    description = _join_text(result.find("description")) or _join_text(result.find("nvt/summary"))
    solution = _join_text(result.find("nvt/solution")) or _xml_text(result, "solution")
    severity_value = _xml_text(result, "severity") or _xml_text(result, "threat")
    try:
        cvss_score = float(severity_value)
    except ValueError:
        cvss_score = 0.0
    qod_value = _xml_text(result, "qod/value") or _xml_text(result, "qod")
    try:
        qod = float(qod_value)
    except ValueError:
        qod = 0.0
    nvt_node = result.find("nvt")
    plugin_id = _safe_text(nvt_node.get("oid") if nvt_node is not None else "")
    package_name = _xml_text(result, "product")
    installed_version = _xml_text(result, "version")
    fixed_version = _xml_text(result, "nvt/solution") if "fixed version" in solution.lower() else ""
    cves = _extract_cves(result) or [""]
    evidence = " ".join(
        part
        for part in [
            description,
            _join_text(result.find("nvt")),
            _join_text(result.find("notes")),
        ]
        if part
    ).strip()
    rows: List[Dict[str, Any]] = []
    for cve in cves:
        finding_id = _finding_key(
            [
                _safe_text(binding.get("asset_id")),
                "greenbone",
                plugin_id,
                cve,
                str(port),
                package_name,
                target,
            ]
        )
        rows.append(
            {
                "finding_id": finding_id,
                "scan_run_id": scan_run_id,
                "external_report_id": external_report_id,
                "scanner_family": "greenbone",
                "asset_id": _safe_text(binding.get("asset_id")),
                "target": target,
                "hostname": hostname,
                "ip": target if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", target) else "",
                "port": port,
                "protocol": protocol,
                "service": service,
                "package_name": package_name,
                "installed_version": installed_version,
                "fixed_version": fixed_version,
                "cve": cve,
                "cvss_score": cvss_score,
                "severity_vendor": severity_value or _severity_label(cvss_score),
                "severity_normalized": _severity_label(cvss_score),
                "qod": qod,
                "solution": solution,
                "scanner_plugin_id": plugin_id,
                "title": title,
                "description": description,
                "evidence": evidence,
                "status": "open",
                "delta_state": "new",
                "first_seen": started_at,
                "last_seen": finished_at,
                "task_id": task_id,
                "target_id": target_id,
                "artifact_path": artifact_path,
                "report_url": report_url,
            }
        )
    return rows


def fetch_completed_reports(
    imported_report_ids: set[str],
    bindings_by_task: Dict[str, Dict[str, Any]],
    bindings_by_target: Dict[str, Dict[str, Any]],
    asset_by_target: Dict[str, Dict[str, Any]],
    limit: int = 20,
) -> Dict[str, Any]:
    def _run(gmp: Any) -> Dict[str, Any]:
        requested_rows = min(250, max(20, max(1, int(limit)) * 5))
        reports_response = gmp.get_reports(
            filter_string=f"rows={requested_rows} sort-reverse=scan_end",
            details=False,
        )
        report_nodes = _report_nodes(reports_response)
        imported: List[Dict[str, Any]] = []
        seen_report_ids = {report_id for report_id in imported_report_ids if report_id}
        for report_node in report_nodes:
            report_id = _response_id(report_node)
            if not report_id or report_id in seen_report_ids:
                continue
            seen_report_ids.add(report_id)
            details_response = gmp.get_report(report_id, details=True, ignore_pagination=True)
            root_report = _find_report_node(details_response)
            if root_report is None:
                continue
            task_node = root_report.find("task")
            task_id = _safe_text(task_node.get("id") if task_node is not None else "")
            target_node = task_node.find("target") if task_node is not None else None
            if target_node is None:
                target_node = root_report.find("target")
            target_id = _safe_text(target_node.get("id") if target_node is not None else "")
            target_value = _xml_text(target_node, "name") or _xml_text(root_report, "host")
            binding = _report_binding(task_id, target_id, target_value, bindings_by_task, bindings_by_target, asset_by_target)
            scan_run_id = f"greenbone-{report_id}"
            started_at = _xml_text(root_report, "scan_start") or _xml_text(root_report, "creation_time")
            finished_at = _xml_text(root_report, "scan_end") or _xml_text(root_report, "modification_time")
            artifact = ET.tostring(root_report, encoding="unicode")
            artifact_path = _artifact_path(report_id)
            artifact_path.write_text(artifact, encoding="utf-8")
            findings: List[Dict[str, Any]] = []
            for result in root_report.findall(".//result"):
                findings.extend(
                    _result_findings(
                        result,
                        scan_run_id=scan_run_id,
                        external_report_id=report_id,
                        task_id=task_id,
                        target_id=target_id,
                        binding=binding,
                        started_at=started_at or finished_at,
                        finished_at=finished_at or started_at,
                        artifact_path=str(artifact_path),
                        report_url=_report_url(report_id),
                    )
                )
            severity_counts: Dict[str, int] = {}
            for row in findings:
                severity = _safe_text(row.get("severity_normalized")) or "info"
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            summary_message = f"Greenbone report {report_id} imported with {len(findings)} findings."
            imported.append(
                {
                    "scan_run": {
                        "scan_run_id": scan_run_id,
                        "scanner_family": "greenbone",
                        "external_report_id": report_id,
                        "task_id": task_id,
                        "task_name": _xml_text(task_node, "name"),
                        "target_id": target_id,
                        "target_name": _xml_text(target_node, "name") or target_value,
                        "asset_id": _safe_text(binding.get("asset_id")),
                        "target": _safe_text(binding.get("target_ref")) or target_value,
                        "hostname": _safe_text(binding.get("hostname")),
                        "ip": _safe_text(binding.get("ip")),
                        "environment": _safe_text(binding.get("environment")) or "prod",
                        "profile": _safe_text(binding.get("profile")) or "network-basic",
                        "started_at": started_at or finished_at,
                        "finished_at": finished_at or started_at,
                        "status": "completed",
                        "summary_message": summary_message,
                        "scanner_source": "greenbone",
                        "artifact_path": str(artifact_path),
                        "artifact_format": "xml",
                        "greenbone_report_url": _report_url(report_id),
                        "finding_count": len(findings),
                        "asset_count": 1 if _safe_text(binding.get("asset_id")) else len({row["target"] for row in findings if row["target"]}),
                        "severity_counts": severity_counts,
                    },
                    "findings": findings,
                }
            )
            if len(imported) >= max(1, int(limit)):
                break
        return {"status": "ok", "imported_runs": imported, "imported": len(imported)}

    return _with_gmp(_run)
