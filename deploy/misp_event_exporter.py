from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable


AUTHKEY_PATTERN = re.compile(
    r"(?:new key created|Authentication key changed to):\s*([A-Za-z0-9]{40})",
    re.IGNORECASE,
)
EVENT_FIELDS = {
    "id",
    "uuid",
    "info",
    "threat_level_id",
    "analysis",
    "published",
    "timestamp",
    "date",
    "Orgc",
}
ATTRIBUTE_FIELDS = {
    "id",
    "uuid",
    "type",
    "category",
    "value",
    "to_ids",
    "timestamp",
    "deleted",
    "disable_correlation",
    "comment",
    "first_seen",
    "last_seen",
}


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)
    path.chmod(0o600)


def _load_state(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"seen": {}}
    if not isinstance(payload, dict) or not isinstance(payload.get("seen"), dict):
        return {"seen": {}}
    return payload


def _load_key(path: Path) -> str:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""
    for line in lines:
        key, separator, value = line.partition("=")
        if separator and key.strip() == "MISP_API_KEY":
            candidate = value.strip()
            if len(candidate) == 40 and candidate.isalnum():
                return candidate
    return ""


def _store_key(path: Path, key: str) -> None:
    if len(key) != 40 or not key.isalnum():
        raise ValueError("MISP returned an invalid API key")
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(f"MISP_API_KEY={key}\n", encoding="ascii")
    temp.chmod(0o600)
    os.replace(temp, path)


def _rotate_key(compose_dir: Path, key_path: Path, admin_email: str) -> str:
    requested = secrets.token_hex(20)
    command = (
        "read -r requested; cd /var/www/MISP && "
        f"./app/Console/cake user change_authkey {admin_email!r} \"$requested\""
    )
    completed = subprocess.run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "misp-core",
            "sh",
            "-lc",
            command,
        ],
        cwd=compose_dir,
        input=requested + "\n",
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
    )
    output = "\n".join((completed.stdout, completed.stderr))
    match = AUTHKEY_PATTERN.search(output)
    if completed.returncode != 0 or not match:
        raise RuntimeError("MISP API key rotation failed")
    key = match.group(1)
    _store_key(key_path, key)
    return key


def _request_events(
    endpoint: str,
    api_key: str,
    *,
    timestamp: int,
    page: int,
    limit: int,
    timeout: int,
) -> Any:
    body = json.dumps(
        {
            "returnFormat": "json",
            "published": True,
            "timestamp": str(timestamp),
            "page": page,
            "limit": limit,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Authorization": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "siem-misp-exporter/1",
        },
    )
    context = ssl._create_unverified_context()
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        return json.load(response)


def _response_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        payload = payload.get("response", payload.get("Response", payload))
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]


def _attribute_documents(items: Iterable[dict[str, Any]]) -> Iterable[tuple[str, int, dict[str, Any]]]:
    for item in items:
        event = item.get("Event") if isinstance(item.get("Event"), dict) else item
        if not isinstance(event, dict):
            continue
        attributes = event.get("Attribute")
        if isinstance(attributes, dict):
            attributes = [attributes]
        if not isinstance(attributes, list):
            continue
        event_meta = {key: value for key, value in event.items() if key in EVENT_FIELDS}
        event_id = str(event.get("uuid") or event.get("id") or "")
        for attribute in attributes:
            if not isinstance(attribute, dict):
                continue
            attribute_id = str(attribute.get("uuid") or attribute.get("id") or "")
            timestamp = int(attribute.get("timestamp") or event.get("timestamp") or 0)
            fallback = f"{attribute.get('type', '')}:{attribute.get('value', '')}"
            identity = f"{event_id}:{attribute_id or fallback}:{timestamp}"
            compact_attribute = {
                key: value for key, value in attribute.items() if key in ATTRIBUTE_FIELDS
            }
            yield identity, timestamp, {"Event": event_meta, "Attribute": compact_attribute}


def export_once(args: argparse.Namespace) -> dict[str, int]:
    state_path = Path(args.state_path)
    output_path = Path(args.output_path)
    key_path = Path(args.key_path)
    state = _load_state(state_path)
    seen = {str(key): int(value or 0) for key, value in state["seen"].items()}
    api_key = _load_key(key_path)
    cutoff = max(0, int(time.time()) - args.lookback_seconds)
    exported: list[dict[str, Any]] = []

    for attempt in range(2):
        try:
            page = 1
            while page <= args.max_pages:
                payload = _request_events(
                    args.endpoint,
                    api_key,
                    timestamp=cutoff,
                    page=page,
                    limit=args.page_size,
                    timeout=args.timeout,
                )
                items = _response_items(payload)
                for identity, timestamp, document in _attribute_documents(items):
                    if identity in seen:
                        continue
                    seen[identity] = timestamp or int(time.time())
                    exported.append(document)
                if len(items) < args.page_size:
                    break
                page += 1
            break
        except urllib.error.HTTPError as exc:
            if exc.code != 403 or attempt:
                raise
            api_key = _rotate_key(Path(args.compose_dir), key_path, args.admin_email)

    if exported:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("a", encoding="utf-8", newline="\n") as handle:
            for document in exported:
                handle.write(json.dumps(document, ensure_ascii=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        output_path.chmod(0o640)

    if len(seen) > args.seen_limit:
        newest = sorted(seen.items(), key=lambda item: item[1], reverse=True)[: args.seen_limit]
        seen = dict(newest)
    _atomic_json(state_path, {"seen": seen, "last_success": int(time.time())})
    return {"events": len(_response_items(payload)), "attributes_exported": len(exported)}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export published MISP attributes to SIEM JSONL.")
    parser.add_argument("--endpoint", default="https://127.0.0.1/events/restSearch")
    parser.add_argument("--compose-dir", default="/opt/misp-docker")
    parser.add_argument("--admin-email", default="socadmin@lab.home.arpa")
    parser.add_argument("--key-path", default="/etc/siem/misp-api.env")
    parser.add_argument("--state-path", default="/var/lib/siem-misp-exporter/state.json")
    parser.add_argument("--output-path", default="/var/log/siem/misp-events.jsonl")
    parser.add_argument("--lookback-seconds", type=int, default=2_592_000)
    parser.add_argument("--page-size", type=int, default=500)
    parser.add_argument("--max-pages", type=int, default=100)
    parser.add_argument("--seen-limit", type=int, default=100_000)
    parser.add_argument("--timeout", type=int, default=30)
    return parser


def main() -> int:
    result = export_once(_parser().parse_args())
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
