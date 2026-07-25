from __future__ import annotations

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from host_runtime_pipeline import (  # noqa: E402
    DEFAULT_STATE_PATH,
    build_snapshot_event,
    collect_local_snapshot,
    evaluate_snapshot,
    load_state,
    save_state,
)


def _ingest_url() -> str:
    return str(os.getenv("SIEM_HOST_RUNTIME_INGEST_URL", "https://10.20.10.104/ingest/json") or "https://10.20.10.104/ingest/json").strip()


def _timeout_seconds() -> float:
    try:
        value = float(os.getenv("SIEM_HOST_RUNTIME_TIMEOUT_SECONDS", "10") or "10")
    except ValueError:
        value = 10.0
    return max(2.0, min(30.0, value))


def _ssl_context():
    url = _ingest_url()
    if not url.startswith("https://"):
        return None
    mode = str(os.getenv("SIEM_HOST_RUNTIME_INGEST_TLS_VERIFY", "disabled") or "disabled").strip().lower()
    if mode in {"disabled", "off", "none"}:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    cafile = str(os.getenv("SIEM_HOST_RUNTIME_INGEST_CA_FILE", "") or "").strip() or None
    context = ssl.create_default_context(cafile=cafile)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def _post_events(events: list[dict]) -> dict:
    body = json.dumps(events, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        _ingest_url(),
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    last_error: Exception | None = None
    attempts = max(1, min(5, int(os.getenv("SIEM_HOST_RUNTIME_DELIVERY_ATTEMPTS", "4") or "4")))
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=_timeout_seconds(), context=_ssl_context()) as response:
                raw = response.read().decode("utf-8", errors="replace")
            return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code not in {429, 502, 503, 504} or attempt >= attempts:
                raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
            if attempt >= attempts:
                raise
        time.sleep(min(6.0, float(attempt)))
    if last_error is not None:
        raise last_error
    return {}


def _policy() -> dict:
    raw_path = str(os.getenv("SIEM_HOST_RUNTIME_POLICY_PATH", "") or "").strip()
    if not raw_path:
        return {}
    path = Path(raw_path)
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def main() -> int:
    state_path = str(os.getenv("SIEM_HOST_RUNTIME_STATE_PATH", DEFAULT_STATE_PATH) or DEFAULT_STATE_PATH).strip()
    snapshot = collect_local_snapshot(
        host_name=str(os.getenv("SIEM_HOST_RUNTIME_HOSTNAME", "") or "").strip(),
        host_role=str(os.getenv("SIEM_HOST_RUNTIME_ROLE", "") or "").strip(),
        watched_services=[item.strip() for item in str(os.getenv("SIEM_HOST_RUNTIME_SERVICES", "") or "").split(",") if item.strip()],
    )
    state = load_state(state_path)
    alerts, next_state = evaluate_snapshot(snapshot, state, policy=_policy())
    save_state(state_path, next_state)
    events = [build_snapshot_event(snapshot), *alerts]
    result = _post_events(events)
    print(json.dumps({"snapshot_host": snapshot["host_name"], "alerts_emitted": len(alerts), "ingest_result": result}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except urllib.error.URLError as exc:
        print(json.dumps({"error": f"unable to post host runtime events: {exc.reason}"}, ensure_ascii=False))
        raise
