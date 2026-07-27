from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
from typing import Any


def _query(binary: str, api_config: str, query: str, timeout: int) -> list[dict[str, Any]]:
    completed = subprocess.run(
        [
            binary,
            "--api_config",
            api_config,
            "query",
            "--format",
            "jsonl",
            query,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    rows: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        try:
            payload = json.loads(line)
        except ValueError:
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def _load_state(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"seen": {}}
    if not isinstance(payload, dict):
        return {"seen": {}}
    payload.setdefault("seen", {})
    return payload


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _timestamp_from_micros(value: Any) -> str:
    try:
        micros = int(value or 0)
    except (TypeError, ValueError):
        micros = 0
    if micros <= 0:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return datetime.fromtimestamp(micros / 1_000_000, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _flow_event(client: dict[str, Any], flow: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    client_id = str(flow.get("client_id") or client.get("client_id") or "").strip()
    flow_id = str(flow.get("session_id") or flow.get("flow_id") or "").strip()
    request = flow.get("request") if isinstance(flow.get("request"), dict) else {}
    artifacts = [
        str(item)
        for item in (flow.get("artifacts_with_results") or request.get("artifacts") or [])
        if str(item).strip()
    ]
    state = str(flow.get("state") or "UNKNOWN").strip().upper()
    identity = f"{client_id}:{flow_id}"
    event = {
        "@timestamp": _timestamp_from_micros(
            flow.get("active_time") or flow.get("start_time") or flow.get("create_time")
        ),
        "event.id": f"velociraptor-flow-{client_id}-{flow_id}",
        "event.dataset": "velociraptor.flow",
        "event.action": "collection_completed" if state == "FINISHED" else "collection_failed",
        "event.outcome": "success" if state == "FINISHED" else "failure",
        "source_type": "velociraptor",
        "client_id": client_id,
        "client.id": client_id,
        "flow_id": flow_id,
        "flow.state": state,
        "artifact": "flow_summary",
        "artifacts": artifacts,
        "hostname": str(client.get("hostname") or "").strip(),
        "os": str(client.get("system") or "").strip(),
        "collected_rows": int(flow.get("total_collected_rows") or 0),
        "uploaded_files": int(flow.get("total_uploaded_files") or 0),
        "uploaded_bytes": int(flow.get("total_uploaded_bytes") or 0),
        "severity": "info" if state == "FINISHED" else "high",
        "tags": ["telemetry:endpoint", "velociraptor:flow"],
    }
    return identity, event


def export_once(args: argparse.Namespace) -> dict[str, int]:
    state_path = Path(args.state_path)
    output_path = Path(args.output_path)
    state = _load_state(state_path)
    seen = {str(key): int(value or 0) for key, value in dict(state.get("seen") or {}).items()}
    clients = _query(
        args.binary,
        args.api_config,
        "SELECT client_id, os_info.hostname AS hostname, os_info.system AS system FROM clients()",
        args.timeout,
    )
    exported: list[dict[str, Any]] = []
    for client in clients:
        client_id = str(client.get("client_id") or "").strip()
        if not client_id:
            continue
        query = (
            "SELECT * FROM flows(client_id="
            + json.dumps(client_id)
            + f") ORDER BY create_time DESC LIMIT {int(args.flows_per_client)}"
        )
        for flow in _query(args.binary, args.api_config, query, args.timeout):
            identity, event = _flow_event(client, flow)
            if not identity or identity in seen:
                continue
            seen[identity] = int(datetime.now(timezone.utc).timestamp())
            exported.append(event)

    if exported:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("a", encoding="utf-8", newline="\n") as handle:
            for event in exported:
                handle.write(json.dumps(event, ensure_ascii=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        output_path.chmod(0o640)
    if len(seen) > args.seen_limit:
        seen = dict(sorted(seen.items(), key=lambda item: item[1], reverse=True)[: args.seen_limit])
    _atomic_json(state_path, {"seen": seen})
    return {"clients": len(clients), "flows_exported": len(exported)}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export Velociraptor flow summaries to SIEM JSONL")
    parser.add_argument("--binary", default="/usr/local/bin/velociraptor")
    parser.add_argument("--api-config", default="/etc/velociraptor/api-soc-deploy.yaml")
    parser.add_argument("--state-path", default="/var/lib/siem-velociraptor-exporter/state.json")
    parser.add_argument("--output-path", default="/var/log/siem/velociraptor-client-flows.jsonl")
    parser.add_argument("--flows-per-client", type=int, default=100)
    parser.add_argument("--seen-limit", type=int, default=100_000)
    parser.add_argument("--timeout", type=int, default=60)
    return parser


def main() -> int:
    print(json.dumps(export_once(_parser().parse_args()), ensure_ascii=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
