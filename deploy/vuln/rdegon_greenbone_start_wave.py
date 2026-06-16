#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys
import time
import types
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = ROOT if (ROOT / "config.py").exists() else ROOT / "services" / "web" / "app"
PACKAGE = "rdegon_greenbone_start_pkg"


def _load_module(name: str):
    if PACKAGE not in sys.modules:
        package = types.ModuleType(PACKAGE)
        package.__path__ = [str(APP_ROOT)]
        sys.modules[PACKAGE] = package
    full_name = f"{PACKAGE}.{name}"
    if full_name in sys.modules:
        return sys.modules[full_name]
    spec = importlib.util.spec_from_file_location(full_name, APP_ROOT / f"{name}.py")
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load runtime module {name} from {APP_ROOT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = module
    spec.loader.exec_module(module)
    return module


_greenbone = _load_module("vuln_greenbone")
_store = _load_module("vuln_store")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Start a Greenbone task wave for SIEM-managed fleet assets.")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--wait-seconds", type=int, default=0)
    parser.add_argument("--poll-seconds", type=int, default=30)
    parser.add_argument("--import-limit", type=int, default=50)
    return parser


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _fetch_bindings(limit: int) -> list[dict[str, Any]]:
    rows = _store._fetch_vuln_asset_bindings(limit=max(1, int(limit)))  # type: ignore[attr-defined]
    return [dict(row) for row in rows if str(row.get("sync_status") or "").strip().lower() == "synced" and str(row.get("task_id") or "").strip()]


def _task_state_map(gmp: Any) -> dict[str, dict[str, str]]:
    response = gmp.get_tasks()
    rows: dict[str, dict[str, str]] = {}
    for node in response.findall(".//task"):
        task_id = str(node.get("id") or "").strip()
        if not task_id:
            continue
        rows[task_id] = {
            "name": _greenbone._xml_text(node, "name"),  # type: ignore[attr-defined]
            "status": _greenbone._xml_text(node, "status"),  # type: ignore[attr-defined]
            "progress": _greenbone._xml_text(node, "progress"),  # type: ignore[attr-defined]
        }
    return rows


def run_wave(*, limit: int, wait_seconds: int, poll_seconds: int, import_limit: int) -> dict[str, Any]:
    if not _greenbone.greenbone_is_configured():
        raise RuntimeError("Greenbone integration is not configured on this node")
    bindings = _fetch_bindings(limit)
    result: dict[str, Any] = {
        "status": "ok",
        "started_at": _now_iso(),
        "selected": len(bindings),
        "started": 0,
        "skipped": 0,
        "failed": 0,
        "items": [],
    }

    def _run(gmp: Any) -> dict[str, Any]:
        states = _task_state_map(gmp)
        items: list[dict[str, Any]] = []
        for binding in bindings:
            task_id = str(binding.get("task_id") or "").strip()
            current = states.get(task_id) or {}
            status = str(current.get("status") or "").strip().lower()
            item = {
                "asset_id": str(binding.get("asset_id") or ""),
                "task_id": task_id,
                "task_name": str(binding.get("task_name") or current.get("name") or ""),
                "previous_status": status,
                "report_id": "",
                "result": "skipped",
                "message": "",
            }
            if status in {"requested", "queued", "running"}:
                item["message"] = f"Task already {status}"
                items.append(item)
                continue
            try:
                response = gmp.start_task(task_id)
                report_node = response.find(".//report_id")
                item["report_id"] = str((report_node.text if report_node is not None else "") or "").strip()
                item["result"] = "started"
            except Exception as exc:  # noqa: BLE001
                item["result"] = "error"
                item["message"] = str(exc)
            items.append(item)
        return {"items": items}

    wave_payload = _greenbone._with_gmp(_run)  # type: ignore[attr-defined]
    result["items"] = wave_payload["items"]
    result["started"] = sum(1 for item in result["items"] if item["result"] == "started")
    result["failed"] = sum(1 for item in result["items"] if item["result"] == "error")
    result["skipped"] = len(result["items"]) - result["started"] - result["failed"]
    if wait_seconds > 0:
        deadline = time.time() + max(0, int(wait_seconds))
        while time.time() < deadline:
            time.sleep(max(5, min(int(poll_seconds), 60)))
        result["report_import"] = _store.import_greenbone_reports(limit=max(1, int(import_limit)))
    result["finished_at"] = _now_iso()
    return result


def main() -> int:
    args = _parser().parse_args()
    payload = run_wave(
        limit=args.limit,
        wait_seconds=args.wait_seconds,
        poll_seconds=args.poll_seconds,
        import_limit=args.import_limit,
    )
    print(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
