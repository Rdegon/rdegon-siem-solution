from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_SENSITIVE_KEYS = {
    "authorization",
    "certificate",
    "encrypted-key",
    "ott",
    "password",
    "private-key",
    "token",
}
_SENSITIVE_VALUE_RE = re.compile(
    r"(?i)\b(authorization|certificate|encrypted-key|ott|password|private-key|token)"
    r"=(?:\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*'|\S+)"
)


def _atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)
    path.chmod(0o600)


def _load_cursor(path: Path) -> str:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    if not isinstance(payload, dict):
        return ""
    return str(payload.get("cursor") or "").strip()


def _timestamp(value: Any) -> str:
    try:
        epoch = int(str(value)) / 1_000_000
    except (TypeError, ValueError):
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_logfmt(message: str) -> dict[str, str]:
    if "=" not in message:
        return {}
    try:
        parts = shlex.split(message, posix=True)
    except ValueError:
        return {}
    fields: dict[str, str] = {}
    for part in parts:
        key, separator, value = part.partition("=")
        normalized_key = key.strip()
        if not separator or not normalized_key or normalized_key.lower() in _SENSITIVE_KEYS:
            continue
        fields[normalized_key] = value
    return fields


def _redact_message(message: str) -> str:
    return _SENSITIVE_VALUE_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", message)


def journal_document(
    record: dict[str, Any],
    *,
    provider: str,
    host_name: str,
) -> dict[str, Any] | None:
    message = str(record.get("MESSAGE") or "").strip()
    if not message:
        return None
    try:
        parsed = json.loads(message)
    except (TypeError, ValueError):
        parsed = _parse_logfmt(message)
    document = dict(parsed) if isinstance(parsed, dict) else {}
    for key in tuple(document):
        if key.lower() in _SENSITIVE_KEYS:
            document.pop(key, None)
    document.setdefault("message", _redact_message(message))
    document.setdefault("@timestamp", _timestamp(record.get("__REALTIME_TIMESTAMP")))
    document.setdefault("source_type", provider)
    document.setdefault("event.provider", provider)
    document.setdefault("event.dataset", f"{provider}.audit")
    document.setdefault("host.name", host_name)
    document.setdefault("log_source", host_name)
    document.setdefault("service.name", provider)
    document.setdefault("process.pid", str(record.get("_PID") or ""))
    document.setdefault("journal.cursor", str(record.get("__CURSOR") or ""))
    return document


def export_once(
    *,
    unit: str,
    provider: str,
    host_name: str,
    state_path: Path,
    output_path: Path,
    initial_lookback: str,
) -> dict[str, int]:
    cursor = _load_cursor(state_path)
    command = ["journalctl", "-u", unit, "--no-pager", "-o", "json"]
    if cursor:
        command.extend(["--after-cursor", cursor])
    else:
        command.extend(["--since", initial_lookback])
    completed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    documents: list[dict[str, Any]] = []
    last_cursor = cursor
    for line in completed.stdout.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        candidate_cursor = str(record.get("__CURSOR") or "").strip()
        if candidate_cursor:
            last_cursor = candidate_cursor
        document = journal_document(record, provider=provider, host_name=host_name)
        if document is not None:
            documents.append(document)
    if documents:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("a", encoding="utf-8", newline="\n") as handle:
            for document in documents:
                handle.write(json.dumps(document, ensure_ascii=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        output_path.chmod(0o640)
    if last_cursor:
        _atomic_write(state_path, {"cursor": last_cursor})
    return {"records": len(documents)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Export structured journald records to JSONL.")
    parser.add_argument("--unit", required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--host-name", required=True)
    parser.add_argument("--state-path", required=True)
    parser.add_argument("--output-path", required=True)
    parser.add_argument("--initial-lookback", default="-5min")
    args = parser.parse_args()
    result = export_once(
        unit=args.unit,
        provider=args.provider,
        host_name=args.host_name,
        state_path=Path(args.state_path),
        output_path=Path(args.output_path),
        initial_lookback=args.initial_lookback,
    )
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
