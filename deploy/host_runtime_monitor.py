from __future__ import annotations

import json
import os
import ssl
import sys
import time
import textwrap
import urllib.error
import urllib.request
from pathlib import Path
import shlex

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from host_runtime_pipeline import DEFAULT_STALE_AFTER_SECONDS, build_snapshot_event, build_stale_events, evaluate_snapshot, load_state, save_state  # noqa: E402
from host_runtime_runtime import fetch_host_runtime_last_seen_map, host_runtime_targets_from_env  # noqa: E402
try:
    from proxmox_fleet_runtime import list_proxmox_fleet_inventory  # type: ignore
except Exception:  # noqa: BLE001
    list_proxmox_fleet_inventory = None  # type: ignore[assignment]
try:
    from proxmox_guest_ops import guest_exec, proxmox_guest_exec_configured  # type: ignore
except Exception:  # noqa: BLE001
    guest_exec = None  # type: ignore[assignment]
    proxmox_guest_exec_configured = lambda: False  # type: ignore[assignment]


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


def _fleet_guest_index() -> dict[str, dict]:
    if list_proxmox_fleet_inventory is None:
        return {}
    try:
        payload = list_proxmox_fleet_inventory(limit=5000)
    except Exception:  # noqa: BLE001
        return {}
    index: dict[str, dict] = {}
    for item in payload.get("items") or []:
        if not isinstance(item, dict):
            continue
        for candidate in (item.get("source_name"), item.get("name")):
            key = str(candidate or "").strip().lower()
            if key and key not in index:
                index[key] = dict(item)
    return index


def _fallback_refresh_after_seconds(stale_after_seconds: int) -> int:
    return max(60, min(max(60, stale_after_seconds - 60), stale_after_seconds // 2))


def _fallback_target_items(targets: list[dict], last_seen: dict[str, str], *, stale_after_seconds: int) -> list[dict]:
    if guest_exec is None or not proxmox_guest_exec_configured():
        return []
    fleet_index = _fleet_guest_index()
    refresh_after_seconds = _fallback_refresh_after_seconds(stale_after_seconds)
    candidates: list[dict] = []
    now_epoch = time.time()
    for target in targets:
        host_name = str(target.get("host_name") or "").strip()
        if not host_name:
            continue
        item = dict(fleet_index.get(host_name.lower()) or {})
        if not item:
            continue
        if item.get("monitoring_supported") is False:
            continue
        if not bool(item.get("host_runtime_enabled", item.get("monitoring_enabled", False))):
            continue
        if str(item.get("state") or "").strip().lower() in {"offline", "unsupported", "inventory-only"}:
            continue
        last_seen_ts = str(last_seen.get(host_name) or "").strip()
        if last_seen_ts:
            from host_runtime_runtime import _parse_iso8601  # noqa: PLC0415

            parsed = _parse_iso8601(last_seen_ts)
            if parsed is not None and int(now_epoch - parsed.timestamp()) <= refresh_after_seconds:
                continue
        candidates.append(
            {
                "host_name": host_name,
                "host_role": str(target.get("host_role") or item.get("role") or "generic"),
                "host_ip": str(target.get("host_ip") or item.get("ip") or ""),
                "vmid": int(item.get("vmid") or 0),
                "guest_type": str(item.get("guest_type") or "").strip().lower(),
            }
        )
    return [item for item in candidates if item.get("vmid") and item.get("guest_type")]


def _collect_guest_snapshot(item: dict) -> dict | None:
    if guest_exec is None:
        return None
    host_name = str(item.get("host_name") or "").strip()
    host_role = str(item.get("host_role") or "generic").strip() or "generic"
    host_ip = str(item.get("host_ip") or "").strip()
    command = textwrap.dedent(
        f"""
        set -a
        [ -f /etc/siem/host-runtime.env ] && . /etc/siem/host-runtime.env
        cd /opt/siem/siem-solution
        python3 - <<'PY'
        import json
        import os
        import sys
        from pathlib import Path
        ROOT = Path('/opt/siem/siem-solution')
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from host_runtime_pipeline import collect_local_snapshot
        services = [item.strip() for item in str(os.getenv('SIEM_HOST_RUNTIME_SERVICES', '') or '').split(',') if item.strip()]
        snapshot = collect_local_snapshot(
            host_name={host_name!r},
            host_role={host_role!r},
            watched_services=services,
        )
        if {host_ip!r} and not str(snapshot.get('primary_ip') or '').strip():
            snapshot['primary_ip'] = {host_ip!r}
        print(json.dumps(snapshot, ensure_ascii=False))
        PY
        """
    ).strip()
    try:
        output = str(guest_exec(int(item["vmid"]), str(item["guest_type"]), command, timeout=240) or "").strip()
    except Exception:
        return None
    if not output:
        return None
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        return None
    try:
        payload = json.loads(lines[-1])
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def main() -> int:
    state_path = str(os.getenv("SIEM_HOST_RUNTIME_MONITOR_STATE_PATH", "/var/lib/siem-host-runtime/monitor-state.json") or "/var/lib/siem-host-runtime/monitor-state.json").strip()
    stale_after_seconds = max(
        60,
        min(
            3600,
            int(os.getenv("SIEM_HOST_RUNTIME_STALE_AFTER_SECONDS", str(DEFAULT_STALE_AFTER_SECONDS)) or DEFAULT_STALE_AFTER_SECONDS),
        ),
    )
    targets = host_runtime_targets_from_env()
    last_seen = fetch_host_runtime_last_seen_map(hours=max(2, stale_after_seconds // 60))
    state = load_state(state_path)
    fallback_events: list[dict] = []
    fallback_hosts: list[str] = []
    for item in _fallback_target_items(targets, last_seen, stale_after_seconds=stale_after_seconds):
        snapshot = _collect_guest_snapshot(item)
        if not snapshot:
            continue
        fallback_hosts.append(str(item.get("host_name") or ""))
        alerts, state = evaluate_snapshot(snapshot, state, policy=_policy())
        fallback_events.extend([build_snapshot_event(snapshot), *alerts])
        last_seen[str(item.get("host_name") or "")] = str(snapshot.get("generated_ts") or "")
    stale_events, next_state = build_stale_events(
        expected_hosts=targets,
        last_seen=last_seen,
        state=state,
        stale_after_seconds=stale_after_seconds,
        policy=_policy(),
    )
    all_events = [*fallback_events, *stale_events]
    save_state(state_path, next_state)
    result = _post_events(all_events) if all_events else {"status": "noop", "ingested": 0}
    print(json.dumps({"targets": len(targets), "fallback_hosts": fallback_hosts, "emitted_events": len(all_events), "ingest_result": result}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except urllib.error.URLError as exc:
        print(json.dumps({"error": f"unable to post stale telemetry events: {exc.reason}"}, ensure_ascii=False))
        raise
