from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


DEFAULT_INGEST_URL = "https://10.20.10.104/ingest/json"
RETRYABLE_HTTP_CODES = {408, 425, 429, 500, 502, 503, 504}


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(os.getenv(name, str(default)) or str(default))
    except ValueError:
        parsed = default
    return max(minimum, min(maximum, parsed))


def _event_id(sensor: str, path: Path, inode: int, offset: int, payload: dict[str, Any]) -> str:
    existing = str(payload.get("event.id") or payload.get("event_id") or "").strip()
    if existing:
        return existing
    identity = f"{sensor}|{path}|{inode}|{offset}".encode("utf-8", errors="replace")
    return f"sensor-{hashlib.sha256(identity).hexdigest()[:32]}"


def _atomic_json_write(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)


def _load_state(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"files": {}}
    if not isinstance(payload, dict):
        return {"files": {}}
    payload.setdefault("files", {})
    return payload


def _append_spool(
    path: Path,
    events: Iterable[dict[str, Any]],
    max_bytes: int,
    consumed_bytes: int = 0,
) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    current_size = path.stat().st_size if path.exists() else 0
    pending_size = max(0, current_size - max(0, consumed_bytes))
    written = 0
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        for event in events:
            line = json.dumps(event, ensure_ascii=True, separators=(",", ":"), default=str) + "\n"
            encoded_size = len(line.encode("utf-8"))
            if pending_size + encoded_size > max_bytes:
                break
            handle.write(line)
            current_size += encoded_size
            pending_size += encoded_size
            written += 1
        handle.flush()
        os.fsync(handle.fileno())
    return written


def _read_spool(path: Path, limit: int, start_offset: int = 0) -> tuple[list[dict[str, Any]], int]:
    if not path.exists():
        return [], 0
    file_size = path.stat().st_size
    safe_offset = max(0, int(start_offset))
    if safe_offset > file_size:
        safe_offset = 0
    events: list[dict[str, Any]] = []
    next_offset = safe_offset
    with path.open("rb") as handle:
        handle.seek(safe_offset)
        while len(events) < limit:
            line = handle.readline()
            if not line:
                break
            next_offset = handle.tell()
            text = line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            try:
                payload = json.loads(text)
            except ValueError:
                continue
            if isinstance(payload, dict):
                events.append(payload)
    return events, next_offset


def _compact_spool(
    path: Path,
    state: dict[str, Any],
    *,
    min_consumed_bytes: int = 67_108_864,
) -> bool:
    if not path.exists():
        state["spool_offset"] = 0
        return False
    file_size = path.stat().st_size
    consumed = max(0, int(state.get("spool_offset") or 0))
    if consumed <= 0:
        return False
    if consumed >= file_size:
        with path.open("r+b") as handle:
            handle.truncate(0)
            handle.flush()
            os.fsync(handle.fileno())
        state["spool_offset"] = 0
        return True
    if consumed < min_consumed_bytes or consumed < file_size // 2:
        return False
    temp = path.with_suffix(path.suffix + ".tmp")
    with path.open("rb") as source, temp.open("wb") as target:
        source.seek(consumed)
        while True:
            chunk = source.read(4 * 1024 * 1024)
            if not chunk:
                break
            target.write(chunk)
        target.flush()
        os.fsync(target.fileno())
    os.replace(temp, path)
    state["spool_offset"] = 0
    return True


def _trivy_findings(payload: Any) -> Iterable[dict[str, Any]]:
    documents = payload if isinstance(payload, list) else [payload]
    for document in documents:
        if not isinstance(document, dict):
            continue
        artifact_name = str(document.get("ArtifactName") or document.get("RepoTags") or "").strip()
        artifact_type = str(document.get("ArtifactType") or "").strip()
        results = document.get("Results")
        if not isinstance(results, list):
            results = [document]
        for result in results:
            if not isinstance(result, dict):
                continue
            target = str(result.get("Target") or artifact_name).strip()
            result_type = str(result.get("Type") or artifact_type).strip()
            vulnerabilities = result.get("Vulnerabilities")
            if not isinstance(vulnerabilities, list):
                if result.get("VulnerabilityID"):
                    vulnerabilities = [result]
                else:
                    continue
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    continue
                finding = dict(vulnerability)
                finding.setdefault("Target", target)
                finding.setdefault("Type", result_type)
                yield finding


def _misp_attributes(payload: Any) -> Iterable[dict[str, Any]]:
    documents = payload if isinstance(payload, list) else [payload]
    for document in documents:
        if not isinstance(document, dict):
            continue
        event = document.get("Event") if isinstance(document.get("Event"), dict) else document
        attributes = event.get("Attribute") if isinstance(event, dict) else None
        if isinstance(attributes, dict):
            attributes = [attributes]
        if not isinstance(attributes, list):
            if isinstance(document.get("Attribute"), dict):
                yield document
            continue
        for attribute in attributes:
            if isinstance(attribute, dict):
                yield {"Event": event, "Attribute": attribute}


def _json_document_events(kind: str, payload: Any) -> Iterable[dict[str, Any]]:
    if kind == "trivy":
        yield from _trivy_findings(payload)
        return
    if kind == "misp":
        yield from _misp_attributes(payload)
        return
    if isinstance(payload, dict):
        yield payload
    elif isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                yield item


def _decorate(
    event: dict[str, Any],
    *,
    kind: str,
    sensor: str,
    host_name: str,
    path: Path,
    inode: int,
    offset: int,
) -> dict[str, Any]:
    decorated = dict(event)
    decorated.setdefault("event.id", _event_id(sensor, path, inode, offset, event))
    decorated.setdefault("source_type", kind)
    # Sensor payloads overload "source" with protocol/parser values (for
    # example Zeek "HTTP" or Falco "syscall"). Transport identity must always
    # remain the reporting sensor host.
    decorated["source"] = host_name or sensor
    decorated["log_source"] = host_name or sensor
    decorated.setdefault("host.name", host_name or sensor)
    decorated.setdefault("collector", f"{kind}-forwarder")
    decorated.setdefault("collector_profile", f"{kind}-json")
    decorated.setdefault("ingest_profile", f"{kind}-json")
    decorated.setdefault("observer.collector", f"{kind}-forwarder")
    decorated.setdefault("observer.profile", f"{kind}-json")
    decorated.setdefault(
        "event.ingested",
        datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )
    dataset = f"{kind}.event"
    if kind == "zeek":
        dataset = f"zeek.{path.name.lower().split('.', 1)[0]}"
    decorated.setdefault("event.dataset", dataset)
    decorated.setdefault("sensor.name", sensor)
    decorated.setdefault("sensor.file", str(path))
    decorated.setdefault("sensor.offset", str(offset))
    if kind == "velociraptor" and not decorated.get("artifact") and not decorated.get("Artifact"):
        parts = path.parts
        for marker in ("server_artifacts", "server_artifact_logs", "artifacts"):
            if marker in parts:
                marker_index = parts.index(marker)
                if marker_index + 1 < len(parts):
                    decorated["artifact"] = parts[marker_index + 1]
                break
        if "clients" in parts:
            client_index = parts.index("clients")
            if client_index + 1 < len(parts):
                decorated.setdefault("client.id", parts[client_index + 1])
        if "artifacts" in parts:
            artifact_index = parts.index("artifacts")
            if artifact_index + 2 < len(parts):
                decorated.setdefault("flow.id", parts[artifact_index + 2])
    return decorated


def _read_jsonl(
    path: Path,
    *,
    state_entry: dict[str, Any],
    kind: str,
    sensor: str,
    host_name: str,
    limit: int,
    start_position: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    stat = path.stat()
    inode = int(getattr(stat, "st_ino", 0))
    previous_inode = int(state_entry.get("inode") or 0)
    previous_offset = int(state_entry.get("offset") or 0)
    if not state_entry and start_position == "end":
        previous_offset = stat.st_size
    elif previous_inode and previous_inode != inode or stat.st_size < previous_offset:
        previous_offset = 0

    events: list[dict[str, Any]] = []
    next_offset = previous_offset
    with path.open("rb") as handle:
        handle.seek(previous_offset)
        while len(events) < limit:
            offset = handle.tell()
            line = handle.readline()
            if not line:
                break
            next_offset = handle.tell()
            text = line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            try:
                payload = json.loads(text)
            except ValueError:
                continue
            if not isinstance(payload, dict):
                continue
            events.append(
                _decorate(
                    payload,
                    kind=kind,
                    sensor=sensor,
                    host_name=host_name,
                    path=path,
                    inode=inode,
                    offset=offset,
                )
            )
    return events, {"inode": inode, "offset": next_offset, "mtime_ns": stat.st_mtime_ns}


def _read_json_document(
    path: Path,
    *,
    state_entry: dict[str, Any],
    kind: str,
    sensor: str,
    host_name: str,
    limit: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    stat = path.stat()
    inode = int(getattr(stat, "st_ino", 0))
    if (
        int(state_entry.get("inode") or 0) == inode
        and int(state_entry.get("mtime_ns") or 0) == stat.st_mtime_ns
        and int(state_entry.get("size") or -1) == stat.st_size
    ):
        return [], state_entry
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except ValueError:
        return [], state_entry
    events = [
        _decorate(
            event,
            kind=kind,
            sensor=sensor,
            host_name=host_name,
            path=path,
            inode=inode,
            offset=index,
        )
        for index, event in enumerate(_json_document_events(kind, payload))
        if index < limit
    ]
    return events, {"inode": inode, "mtime_ns": stat.st_mtime_ns, "size": stat.st_size, "offset": stat.st_size}


def _ssl_context(verify_mode: str, ca_file: str) -> ssl.SSLContext | None:
    if verify_mode == "disabled":
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    context = ssl.create_default_context(cafile=ca_file or None)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def _post(
    url: str,
    events: list[dict[str, Any]],
    *,
    timeout: int,
    tls_verify: str,
    ca_file: str,
    bearer_token: str,
) -> dict[str, Any]:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    request = urllib.request.Request(
        url,
        data=json.dumps(events, ensure_ascii=True, separators=(",", ":"), default=str).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(
        request,
        timeout=timeout,
        context=_ssl_context(tls_verify, ca_file) if url.startswith("https://") else None,
    ) as response:
        body = response.read().decode("utf-8", errors="replace")
    result = json.loads(body) if body else {}
    if not isinstance(result, dict):
        raise RuntimeError("ingest response must be a JSON object")
    accepted = int(result.get("ingested") or 0)
    rejected = int(result.get("rejected") or 0)
    if accepted != len(events) or rejected:
        raise RuntimeError(f"ingest accepted={accepted}, rejected={rejected}, expected={len(events)}")
    return result


def _expand_paths(patterns: list[str]) -> list[Path]:
    resolved: list[Path] = []
    seen: set[str] = set()
    for pattern in patterns:
        for match in sorted(glob.glob(pattern)):
            path = Path(match).resolve()
            key = str(path)
            if path.is_file() and key not in seen:
                seen.add(key)
                resolved.append(path)
    return resolved


def _collect_once(args: argparse.Namespace, state: dict[str, Any]) -> int:
    spool_path = Path(args.spool_path)
    spool_offset = max(0, int(state.get("spool_offset") or 0))
    pending_bytes = (
        max(0, spool_path.stat().st_size - spool_offset)
        if spool_path.exists()
        else 0
    )
    if pending_bytes >= args.spool_max_bytes:
        state["spool_backpressure"] = True
        return 0
    if bool(state.get("spool_backpressure")):
        if pending_bytes > args.spool_max_bytes // 2:
            return 0
        state["spool_backpressure"] = False
        _atomic_json_write(Path(args.state_path), state)
    files_state = state.setdefault("files", {})
    collected = 0
    for path in _expand_paths(args.path):
        if collected >= args.read_limit:
            break
        state_entry = files_state.get(str(path), {})
        limit = args.read_limit - collected
        try:
            if args.format == "json":
                events, next_entry = _read_json_document(
                    path,
                    state_entry=state_entry,
                    kind=args.kind,
                    sensor=args.sensor,
                    host_name=args.host_name,
                    limit=limit,
                )
            else:
                events, next_entry = _read_jsonl(
                    path,
                    state_entry=state_entry,
                    kind=args.kind,
                    sensor=args.sensor,
                    host_name=args.host_name,
                    limit=limit,
                    start_position=args.start_position,
                )
        except FileNotFoundError:
            # Log rotation can unlink a file after glob expansion.
            continue
        written = _append_spool(
            spool_path,
            events,
            args.spool_max_bytes,
            consumed_bytes=spool_offset,
        )
        if written != len(events):
            break
        files_state[str(path)] = next_entry
        _atomic_json_write(Path(args.state_path), state)
        collected += written
    return collected


def _deliver_once(args: argparse.Namespace, state: dict[str, Any]) -> int:
    spool_path = Path(args.spool_path)
    spool_offset = max(0, int(state.get("spool_offset") or 0))
    delivery_batch_size = max(
        1,
        min(
            int(args.batch_size),
            int(state.get("delivery_batch_size") or args.batch_size),
        ),
    )
    events, next_offset = _read_spool(spool_path, delivery_batch_size, start_offset=spool_offset)
    if not events:
        if next_offset > spool_offset:
            state["spool_offset"] = next_offset
        if _compact_spool(spool_path, state):
            _atomic_json_write(Path(args.state_path), state)
        elif next_offset > spool_offset:
            _atomic_json_write(Path(args.state_path), state)
        return 0
    while True:
        try:
            _post(
                args.ingest_url,
                events,
                timeout=args.timeout,
                tls_verify=args.tls_verify,
                ca_file=args.ca_file,
                bearer_token=args.bearer_token,
            )
            break
        except urllib.error.HTTPError as exc:
            if exc.code != 413 or len(events) <= 1:
                raise
            delivery_batch_size = max(1, len(events) // 2)
            state["delivery_batch_size"] = delivery_batch_size
            events, next_offset = _read_spool(
                spool_path,
                delivery_batch_size,
                start_offset=spool_offset,
            )
    state["spool_offset"] = next_offset
    _compact_spool(spool_path, state)
    _atomic_json_write(Path(args.state_path), state)
    return len(events)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Durable JSON/JSONL sensor event forwarder for SIEM HTTP ingest.")
    parser.add_argument("--kind", default=os.getenv("SIEM_SENSOR_KIND", "generic").strip().lower())
    parser.add_argument("--sensor", default=os.getenv("SIEM_SENSOR_NAME", "security-sensor").strip())
    parser.add_argument("--host-name", default=os.getenv("SIEM_SENSOR_HOSTNAME", "").strip())
    parser.add_argument("--format", choices=("jsonl", "json"), default=os.getenv("SIEM_SENSOR_FORMAT", "jsonl").strip().lower())
    parser.add_argument("--path", action="append", default=[])
    parser.add_argument("--ingest-url", default=os.getenv("SIEM_SENSOR_INGEST_URL", DEFAULT_INGEST_URL).strip())
    parser.add_argument("--state-path", default=os.getenv("SIEM_SENSOR_STATE_PATH", "").strip())
    parser.add_argument("--spool-path", default=os.getenv("SIEM_SENSOR_SPOOL_PATH", "").strip())
    parser.add_argument("--start-position", choices=("beginning", "end"), default=os.getenv("SIEM_SENSOR_START_POSITION", "end").strip().lower())
    parser.add_argument("--tls-verify", choices=("required", "disabled"), default=os.getenv("SIEM_SENSOR_TLS_VERIFY", "required").strip().lower())
    parser.add_argument("--ca-file", default=os.getenv("SIEM_SENSOR_CA_FILE", "").strip())
    parser.add_argument("--bearer-token", default=os.getenv("SIEM_SENSOR_BEARER_TOKEN", "").strip())
    parser.add_argument("--batch-size", type=int, default=_env_int("SIEM_SENSOR_BATCH_SIZE", 250, 1, 2000))
    parser.add_argument(
        "--delivery-batches",
        type=int,
        default=_env_int("SIEM_SENSOR_DELIVERY_BATCHES", 8, 1, 32),
    )
    parser.add_argument("--read-limit", type=int, default=_env_int("SIEM_SENSOR_READ_LIMIT", 2000, 1, 10000))
    parser.add_argument("--spool-max-bytes", type=int, default=_env_int("SIEM_SENSOR_SPOOL_MAX_BYTES", 536_870_912, 1_048_576, 10_737_418_240))
    parser.add_argument("--timeout", type=int, default=_env_int("SIEM_SENSOR_TIMEOUT_SECONDS", 15, 2, 120))
    parser.add_argument("--interval", type=int, default=_env_int("SIEM_SENSOR_INTERVAL_SECONDS", 2, 1, 300))
    parser.add_argument("--once", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    if not args.path:
        raw_paths = os.getenv("SIEM_SENSOR_PATHS", "").strip()
        args.path = [item.strip() for item in raw_paths.split(";") if item.strip()]
    if not args.path:
        raise SystemExit("at least one --path or SIEM_SENSOR_PATHS entry is required")
    base = Path("/var/lib/siem-security-forwarder")
    args.state_path = args.state_path or str(base / f"{args.sensor}.state.json")
    args.spool_path = args.spool_path or str(base / f"{args.sensor}.spool.jsonl")

    state_path = Path(args.state_path)
    state = _load_state(state_path)
    while True:
        collected = 0
        delivered = 0
        error = ""
        try:
            for _ in range(args.delivery_batches):
                batch_delivered = _deliver_once(args, state)
                delivered += batch_delivered
                if batch_delivered == 0:
                    break
        except urllib.error.HTTPError as exc:
            error = f"http_{exc.code}"
            if exc.code not in RETRYABLE_HTTP_CODES:
                print(json.dumps({"sensor": args.sensor, "collected": collected, "delivered": 0, "error": error}))
                return 2
        except (urllib.error.URLError, TimeoutError, OSError, RuntimeError) as exc:
            error = type(exc).__name__
        collected = _collect_once(args, state)
        if delivered == 0 and collected and not error:
            try:
                delivered = _deliver_once(args, state)
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, RuntimeError) as exc:
                error = f"http_{exc.code}" if isinstance(exc, urllib.error.HTTPError) else type(exc).__name__
        spool_size = Path(args.spool_path).stat().st_size if Path(args.spool_path).exists() else 0
        spool_bytes = max(0, spool_size - max(0, int(state.get("spool_offset") or 0)))
        print(
            json.dumps(
                {
                    "sensor": args.sensor,
                    "kind": args.kind,
                    "collected": collected,
                    "delivered": delivered,
                    "spool_bytes": spool_bytes,
                    "error": error,
                },
                ensure_ascii=True,
            ),
            flush=True,
        )
        if args.once:
            return 0 if not error else 1
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
