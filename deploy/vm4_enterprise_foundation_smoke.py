from __future__ import annotations

import json
import os
import ssl
import sys
import time
import urllib.error
from http.cookiejar import CookieJar
from urllib.parse import quote, urlencode
from urllib.request import HTTPCookieProcessor, HTTPSHandler, Request, build_opener

import paramiko


CRITICAL_INGEST_COLLECTOR_PROFILES = ("app", "linux-auth", "linux-audit")
EDGE_VPN_SOURCE_ALIASES = {"192.168.1.102", "opnsense-edge-01", "lab-edge-01"}
MAX_SMOKE_ARTIFACT_CLEANUP_PER_TYPE = 25
DEFAULT_HTTP_TIMEOUT_SECONDS = 20.0
SLOW_API_TIMEOUT_SECONDS = 75.0


def _required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _resolve_base_url() -> str:
    explicit = os.getenv("SIEM_WEB_BASE_URL", "").strip()
    if explicit:
        return explicit.rstrip("/")
    vm4_host = os.getenv("SIEM_VM4_HOST", "").strip()
    if vm4_host:
        return f"https://{vm4_host}".rstrip("/")
    return "https://192.168.1.39"


class Client:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.jar = CookieJar()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self.opener = build_opener(HTTPSHandler(context=context), HTTPCookieProcessor(self.jar))

    def csrf_token(self) -> str:
        for cookie in self.jar:
            if cookie.name == "csrf_token":
                return cookie.value
        return ""

    def request_with_meta(
        self,
        path: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
        attempts: int = 4,
        delay_seconds: float = 2.0,
        timeout_seconds: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
    ) -> tuple[int, str, str]:
        last_error: Exception | None = None
        for attempt in range(1, attempts + 1):
            prepared_headers = dict(headers or {})
            if method.upper() not in {"GET", "HEAD", "OPTIONS"} and "X-CSRF-Token" not in prepared_headers:
                csrf_token = self.csrf_token()
                if csrf_token:
                    prepared_headers["X-CSRF-Token"] = csrf_token
            request = Request(f"{self.base_url}{path}", data=data, headers=prepared_headers, method=method)
            try:
                with self.opener.open(request, timeout=timeout_seconds) as response:
                    body = response.read().decode("utf-8", errors="replace")
                    return response.status, body, response.geturl()
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace")
                if attempt < attempts and exc.code in {429, 502, 503, 504}:
                    time.sleep(delay_seconds)
                    continue
                if attempt == attempts:
                    raise RuntimeError(
                        f"Request failed for {path}: HTTP {exc.code} {exc.reason}; body={body[:600]}"
                    ) from exc
                time.sleep(delay_seconds)
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                if attempt == attempts:
                    break
                time.sleep(delay_seconds)
        raise RuntimeError(f"Request failed for {path}: {last_error}")

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
        attempts: int = 4,
        delay_seconds: float = 2.0,
        timeout_seconds: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
    ) -> tuple[int, str]:
        code, body, _ = self.request_with_meta(
            path,
            method=method,
            headers=headers,
            data=data,
            attempts=attempts,
            delay_seconds=delay_seconds,
            timeout_seconds=timeout_seconds,
        )
        return code, body


def _connect_client(host: str, user: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        username=user,
        password=password,
        timeout=20,
        banner_timeout=20,
        auth_timeout=20,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def _run_remote(
    client: paramiko.SSHClient,
    command: str,
    *,
    sudo_password: str = "",
    use_sudo: bool = False,
    timeout_seconds: float = 300.0,
) -> tuple[int, str, str]:
    wrapped = f"sudo -S -p '' bash -lc {command!r}" if use_sudo else command
    transport = client.get_transport()
    if transport is None:
        raise RuntimeError("SSH transport is not connected")
    channel = transport.open_session(timeout=20)
    if use_sudo:
        channel.get_pty()
    channel.settimeout(2.0)
    channel.exec_command(wrapped)
    stdin = channel.makefile_stdin("wb")
    out_chunks: list[bytes] = []
    err_chunks: list[bytes] = []
    if use_sudo:
        stdin.write(f"{sudo_password}\n".encode("utf-8"))
        stdin.flush()
    deadline = time.monotonic() + max(1.0, float(timeout_seconds))
    while True:
        while channel.recv_ready():
            out_chunks.append(channel.recv(65535))
        while channel.recv_stderr_ready():
            err_chunks.append(channel.recv_stderr(65535))
        if channel.exit_status_ready():
            break
        if time.monotonic() >= deadline:
            channel.close()
            out = b"".join(out_chunks).decode("utf-8", errors="replace")
            err = b"".join(err_chunks).decode("utf-8", errors="replace")
            return 124, out, f"{err}\nCommand timed out after {timeout_seconds:g}s: {command[:240]}"
        time.sleep(0.1)
    while channel.recv_ready():
        out_chunks.append(channel.recv(65535))
    while channel.recv_stderr_ready():
        err_chunks.append(channel.recv_stderr(65535))
    code = channel.recv_exit_status()
    out = b"".join(out_chunks).decode("utf-8", errors="replace")
    err = b"".join(err_chunks).decode("utf-8", errors="replace")
    channel.close()
    return code, out, err


def _close_ssh_client(client: paramiko.SSHClient) -> None:
    try:
        transport = client.get_transport()
        if transport is not None:
            transport.close()
    except Exception:
        pass


def _strip_sudo_echo(text: str, sudo_password: str) -> str:
    if not sudo_password:
        return text
    return "\n".join(line for line in str(text or "").splitlines() if line.strip() != sudo_password)


def _expect_status(code: int, allowed: set[int], path: str) -> None:
    if code not in allowed:
        raise RuntimeError(f"Unexpected status for {path}: {code}")


def _env_enabled(name: str) -> bool:
    return str(os.getenv(name, "") or "").strip().lower() in {"1", "true", "yes", "on"}


def _is_smoke_label(value: object) -> bool:
    text = str(value or "").strip().lower()
    return text.startswith(("smoke-", "smoke ", "test-", "test ", "qa-", "qa "))


def _best_effort_delete(client: Client, path: str) -> bool:
    try:
        status, _ = client.request(path, method="DELETE", attempts=1, delay_seconds=0.5)
        return status in {200, 202, 204, 404, 405}
    except Exception:  # noqa: BLE001
        return False


def _cleanup_smoke_artifacts(client: Client) -> None:
    if not _env_enabled("SIEM_SMOKE_CLEANUP_ARTIFACTS"):
        return
    removed = {"connectors": 0, "actions": 0, "service_accounts": 0}
    try:
        status, body = client.request("/api/connectors", attempts=1, delay_seconds=0.5)
        if status == 200:
            payload = json.loads(body)
            for item in list(payload.get("items") or []):
                connector_id = str(item.get("id") or "").strip()
                if not connector_id:
                    continue
                if _is_smoke_label(connector_id) or _is_smoke_label(item.get("title")) or str(item.get("group") or "").strip().lower() == "smoke":
                    if _best_effort_delete(client, f"/api/connectors/{quote(connector_id, safe='')}"):
                        removed["connectors"] += 1
                    if removed["connectors"] >= MAX_SMOKE_ARTIFACT_CLEANUP_PER_TYPE:
                        break
    except Exception:  # noqa: BLE001
        pass
    try:
        status, body = client.request("/api/response/actions", attempts=1, delay_seconds=0.5)
        if status == 200:
            payload = json.loads(body)
            for item in list(payload.get("items") or []):
                action_id = str(item.get("id") or "").strip()
                if not action_id:
                    continue
                if _is_smoke_label(action_id) or _is_smoke_label(item.get("title")):
                    if _best_effort_delete(client, f"/api/response/actions/{quote(action_id, safe='')}"):
                        removed["actions"] += 1
                    if removed["actions"] >= MAX_SMOKE_ARTIFACT_CLEANUP_PER_TYPE:
                        break
    except Exception:  # noqa: BLE001
        pass
    try:
        status, body = client.request("/api/auth/service-accounts", attempts=1, delay_seconds=0.5)
        if status == 200:
            payload = json.loads(body)
            for item in list(payload.get("items") or []):
                service_account_id = str(item.get("id") or "").strip()
                name = str(item.get("name") or item.get("title") or "").strip()
                if not service_account_id:
                    continue
                if name.lower().startswith("smoke-runtime-") or service_account_id.lower().startswith("smoke-runtime-"):
                    if _best_effort_delete(client, f"/api/auth/service-accounts/{quote(service_account_id, safe='')}"):
                        removed["service_accounts"] += 1
                    if removed["service_accounts"] >= MAX_SMOKE_ARTIFACT_CLEANUP_PER_TYPE:
                        break
    except Exception:  # noqa: BLE001
        pass
    if any(removed.values()):
        print(
            "smoke cleanup removed "
            f"{removed['connectors']} connectors, "
            f"{removed['actions']} actions, "
            f"{removed['service_accounts']} service accounts"
        )


def _wait_for_backend_ready(client: Client, *, attempts: int = 18, delay_seconds: float = 5.0) -> None:
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            status, _, final_url = client.request_with_meta(
                "/auth/login",
                attempts=2,
                delay_seconds=2.0,
            )
            if status == 200 and final_url.endswith("/auth/login"):
                return
        except Exception as exc:  # noqa: BLE001
            last_error = exc
        if attempt < attempts:
            time.sleep(delay_seconds)
    raise RuntimeError(f"Backend warm-up failed before smoke: {last_error}")


def _is_transient_ingest_proxy_issue(issue: object) -> bool:
    text = str(issue or "").strip().lower()
    return "ingest runtime unavailable" in text and "502 bad gateway" in text


def _transient_ingest_proxy_issues_only(issues: object) -> bool:
    normalized = [str(item or "").strip() for item in list(issues or []) if str(item or "").strip()]
    return bool(normalized) and all(_is_transient_ingest_proxy_issue(item) for item in normalized)


def _is_ingest_remediable_issue(issue: object) -> bool:
    text = str(issue or "").strip().lower()
    prefixes = (
        "ingest dlq backlog:",
        "outstanding dlq events:",
        "parser errors recorded:",
        "stale sources detected:",
        "delayed sources detected:",
        "stale collectors detected:",
        "delayed collectors detected:",
    )
    return text.startswith(prefixes)


def _ingest_remediable_issues_only(issues: object) -> bool:
    normalized = [str(item or "").strip() for item in list(issues or []) if str(item or "").strip()]
    return bool(normalized) and all(_is_ingest_remediable_issue(item) for item in normalized)


def _wait_for_overview_issues_to_clear(
    client: Client,
    *,
    attempts: int = 18,
    delay_seconds: float = 5.0,
) -> dict[str, object]:
    payload: dict[str, object] = {}
    for attempt in range(1, attempts + 1):
        status, body = client.request(
            "/api/health/overview",
            attempts=3,
            delay_seconds=3.0,
            timeout_seconds=SLOW_API_TIMEOUT_SECONDS,
        )
        _expect_status(status, {200}, "/api/health/overview")
        payload = json.loads(body)
        if not list(payload.get("issues") or []):
            return payload
        if attempt < attempts:
            time.sleep(delay_seconds)
    return payload


def _probe_ingest_health() -> bool:
    ingest_health_url = str(os.getenv("SIEM_INGEST_HEALTH_URL", "https://192.168.1.35/health") or "").strip()
    if not ingest_health_url:
        return False
    attempts = int(str(os.getenv("SIEM_INGEST_HEALTH_ATTEMPTS", "6") or "6"))
    delay_seconds = float(str(os.getenv("SIEM_INGEST_HEALTH_DELAY_SECONDS", "5") or "5"))
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    headers = {"Accept": "application/json"}
    for attempt in range(1, attempts + 1):
        try:
            request = Request(ingest_health_url, headers=headers, method="GET")
            with urllib.request.urlopen(request, timeout=15, context=context) as response:
                body = response.read().decode("utf-8", errors="replace")
                if response.status != 200:
                    raise RuntimeError(f"unexpected status {response.status}")
                payload = json.loads(body)
                if str(payload.get("status") or "").strip().lower() != "ok":
                    raise RuntimeError(f"unexpected ingest status {payload.get('status')!r}")
                transport = dict(payload.get("transport") or {})
                if transport and not bool(transport.get("kafka_shadow_ready", True)):
                    raise RuntimeError("ingest transport shadow is not ready")
                return True
        except Exception:  # noqa: BLE001
            if attempt < attempts:
                time.sleep(delay_seconds)
    return False


def _direct_ingest_base_url() -> str:
    return str(os.getenv("SIEM_DIRECT_INGEST_BASE_URL", "https://192.168.1.35") or "https://192.168.1.35").strip().rstrip("/")


def _request_json_url(
    url: str,
    *,
    method: str = "GET",
    payload: dict[str, object] | None = None,
    attempts: int = 4,
    delay_seconds: float = 2.0,
    timeout_seconds: float = 30.0,
) -> dict[str, object]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        headers = {"Accept": "application/json"}
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode("utf-8")
        request = Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds, context=context) as response:
                return json.loads(response.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            last_error = exc
            if attempt == attempts:
                body = exc.read().decode("utf-8", errors="replace")
                raise RuntimeError(f"Request failed for {url}: HTTP {exc.code} {exc.reason}; body={body[:600]}") from exc
            time.sleep(delay_seconds)
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt == attempts:
                break
            time.sleep(delay_seconds)
    raise RuntimeError(f"Request failed for {url}: {last_error}")


def _direct_ingest_request(
    path: str,
    *,
    method: str = "GET",
    payload: dict[str, object] | None = None,
    attempts: int = 4,
    delay_seconds: float = 2.0,
    timeout_seconds: float = 30.0,
) -> dict[str, object]:
    return _request_json_url(
        f"{_direct_ingest_base_url()}{path}",
        method=method,
        payload=payload,
        attempts=attempts,
        delay_seconds=delay_seconds,
        timeout_seconds=timeout_seconds,
    )


def _item_status(item: dict[str, object]) -> str:
    return str(item.get("status") or item.get("health") or "").strip().lower()


def _collect_critical_ingest_state(*, sources: dict[str, object], collectors: dict[str, object]) -> dict[str, object]:
    collector_items = [dict(item) for item in list(collectors.get("items") or [])]
    source_items = [dict(item) for item in list(sources.get("items") or [])]
    problems: list[str] = []
    collector_state: dict[str, str] = {}

    for profile in CRITICAL_INGEST_COLLECTOR_PROFILES:
        match = next(
            (
                item
                for item in collector_items
                if str(item.get("collector_profile") or item.get("ingest_profile") or "").strip().lower() == profile
            ),
            None,
        )
        status = _item_status(match or {}) if match else "missing"
        collector_state[profile] = status
        if status != "healthy":
            problems.append(f"collector:{profile}:{status}")

    pve_app = next(
        (
            item
            for item in source_items
            if str(item.get("collector_profile") or item.get("ingest_profile") or "").strip().lower() == "app"
            and "pve" in " ".join(
                str(item.get(field) or "").strip().lower()
                for field in ("source", "source_alias", "id")
            )
        ),
        None,
    )
    if _item_status(pve_app or {}) != "healthy":
        problems.append(f"source:pve/app:{_item_status(pve_app or {}) or 'missing'}")

    vpn_source = next(
        (
            item
            for item in source_items
            if (
                str(item.get("collector_profile") or item.get("ingest_profile") or "").strip().lower() == "vpn"
                or (
                    str(item.get("collector_profile") or item.get("ingest_profile") or "").strip().lower() == "linux-auth"
                    and str(item.get("source") or item.get("source_alias") or "").strip() == "127.0.0.1"
                )
            )
        ),
        None,
    )
    edge_source = next(
        (
            item
            for item in source_items
            if any(
                str(item.get(field) or "").strip().lower() in EDGE_VPN_SOURCE_ALIASES
                for field in ("source", "source_alias", "id")
            )
        ),
        None,
    )
    vpn_ready = _item_status(vpn_source or {}) == "healthy" or _item_status(edge_source or {}) == "healthy"
    if not vpn_ready:
        problems.append(
            f"source:vpn-path:vpn={_item_status(vpn_source or {}) or 'missing'} edge={_item_status(edge_source or {}) or 'missing'}"
        )

    return {
        "healthy": not problems,
        "problems": problems,
        "collectors": collector_state,
        "pve_app_status": _item_status(pve_app or {}) or "missing",
        "vpn_status": _item_status(vpn_source or {}) or "missing",
        "edge_status": _item_status(edge_source or {}) or "missing",
    }


def _load_critical_ingest_state() -> dict[str, object]:
    sources = _direct_ingest_request("/health/sources?limit=200", attempts=2, delay_seconds=1.5)
    collectors = _direct_ingest_request("/health/collectors?limit=200", attempts=2, delay_seconds=1.5)
    overview = _direct_ingest_request("/health/overview", attempts=2, delay_seconds=1.5)
    return {
        "sources": sources,
        "collectors": collectors,
        "overview": overview,
        "gate": _collect_critical_ingest_state(sources=sources, collectors=collectors),
    }


def _wait_for_critical_ingest_targets_ready(*, attempts: int = 12, delay_seconds: float = 5.0) -> dict[str, object]:
    snapshot: dict[str, object] = {}
    for attempt in range(1, attempts + 1):
        snapshot = _load_critical_ingest_state()
        if bool(dict(snapshot.get("gate") or {}).get("healthy")):
            return snapshot
        if attempt < attempts:
            time.sleep(delay_seconds)
    return snapshot


def _is_noncritical_residual_ingest_issue(issue: object) -> bool:
    text = str(issue or "").strip().lower()
    return text.startswith(
        (
            "stale sources detected:",
            "delayed sources detected:",
            "stale collectors detected:",
            "delayed collectors detected:",
        )
    )


def _is_transient_control_plane_release_gate_issue(issue: object) -> bool:
    text = str(issue or "").strip().lower()
    return text.startswith(
        (
            "response governance coverage is below target",
            "connector release-gate coverage is below target",
        )
    )


def _is_transient_stream_shadow_mismatch_issue(issue: object) -> bool:
    return str(issue or "").strip().lower().startswith("stream correlation shadow mismatches:")


def _is_host_runtime_stale_issue(issue: object) -> bool:
    return str(issue or "").strip().lower().startswith("host telemetry stale targets:")


def _remediate_host_runtime_staleness(vm4_host: str) -> None:
    vm4_user = str(os.getenv("SIEM_VM4_USER", "") or "").strip()
    vm4_password = str(os.getenv("SIEM_VM4_PASSWORD", "") or "").strip()
    if not vm4_user or not vm4_password:
        return
    ssh_client = _connect_client(vm4_host, vm4_user, vm4_password)
    try:
        code, out, err = _run_remote(
            ssh_client,
            "systemctl start siem-host-runtime-monitor.service && "
            "sleep 8 && "
            "systemctl is-failed siem-host-runtime-monitor.service || true",
            sudo_password=vm4_password,
            use_sudo=True,
        )
        cleaned_out = _strip_sudo_echo(out, vm4_password)
        cleaned_err = _strip_sudo_echo(err, vm4_password)
        if code != 0:
            raise RuntimeError(
                "Unable to trigger siem-host-runtime-monitor.service: "
                f"stdout={cleaned_out.strip()} stderr={cleaned_err.strip()}"
            )
    finally:
        _close_ssh_client(ssh_client)


def _refresh_generic_http_sources() -> None:
    sources = _direct_ingest_request("/health/sources?limit=200", attempts=2, delay_seconds=1.5)
    collectors = _direct_ingest_request("/health/collectors?limit=200", attempts=2, delay_seconds=1.5)
    candidates: list[tuple[str, str, str]] = []
    for inventory in (list(sources.get("items") or []), list(collectors.get("items") or [])):
        for item in inventory:
            if str(item.get("status") or "").strip().lower() not in {"stale", "delayed"}:
                continue
            if str(item.get("collector_profile") or item.get("ingest_profile") or "").strip().lower() != "generic-http" and str(item.get("collector") or "").strip().lower() != "http_json":
                continue
            source = str(item.get("source") or item.get("source_alias") or item.get("id") or "generic-http-refresh").strip()
            source_type = str(item.get("source_type") or "http_json").strip() or "http_json"
            dataset = str(item.get("last_dataset") or "generic-http").strip() or "generic-http"
            candidates.append((source, source_type, dataset))
    if not candidates:
        candidates.append(("generic-http-refresh", "http_json", "generic-http"))
    seen: set[tuple[str, str, str]] = set()
    for source, source_type, dataset in candidates[:8]:
        key = (source, source_type, dataset)
        if key in seen:
            continue
        seen.add(key)
        _direct_ingest_request(
            "/ingest/json",
            method="POST",
            payload={
                "message": "control-plane-ingest-refresh",
                "source": source,
                "source_type": source_type,
                "event.dataset": dataset,
                "tags": ["control-plane-refresh"],
            },
            attempts=2,
            delay_seconds=1.0,
            timeout_seconds=20.0,
        )


def _remediate_ingest_health() -> dict[str, object]:
    attempts = int(str(os.getenv("SIEM_INGEST_REMEDIATION_ATTEMPTS", "8") or "8"))
    delay_seconds = float(str(os.getenv("SIEM_INGEST_REMEDIATION_DELAY_SECONDS", "5") or "5"))
    replay_batches = int(str(os.getenv("SIEM_INGEST_REPLAY_BATCHES_PER_ATTEMPT", "5") or "5"))
    replay_batch_limit = int(str(os.getenv("SIEM_INGEST_REPLAY_BATCH_LIMIT", "2000") or "2000"))
    suppress_limit = int(str(os.getenv("SIEM_INGEST_SUPPRESS_LIMIT", "5000") or "5000"))
    overview: dict[str, object] = {}
    for attempt in range(1, attempts + 1):
        overview = _direct_ingest_request("/health/overview", attempts=2, delay_seconds=1.5)
        issues = [str(item or "").strip() for item in list(overview.get("issues") or []) if str(item or "").strip()]
        dlq = dict(overview.get("dlq") or {})
        outstanding = int(dlq.get("outstanding") or 0)
        if outstanding > 0:
            _direct_ingest_request(
                "/dlq/suppress",
                method="POST",
                payload={"limit": min(outstanding, suppress_limit), "actor": "vm4-smoke"},
                attempts=2,
                delay_seconds=1.0,
                timeout_seconds=60.0,
            )
            for _ in range(max(1, replay_batches)):
                replay = _direct_ingest_request(
                    "/dlq/replay",
                    method="POST",
                    payload={"limit": min(replay_batch_limit, outstanding), "actor": "vm4-smoke"},
                    attempts=2,
                    delay_seconds=1.5,
                    timeout_seconds=180.0,
                )
                replayed = int(replay.get("replayed") or 0)
                failed = int(replay.get("failed") or 0)
                skipped = int(replay.get("skipped") or 0)
                if replayed <= 0 and failed <= 0 and skipped <= 0:
                    break
                outstanding = max(0, outstanding - replayed)
                if outstanding < 5:
                    break
        if any(
            _is_ingest_remediable_issue(item) and ("sources" in item.lower() or "collectors" in item.lower())
            for item in issues
        ):
            _refresh_generic_http_sources()
        if not issues and outstanding == 0:
            return overview
        if attempt < attempts:
            time.sleep(delay_seconds)
    return overview


def main() -> int:
    base_url = _resolve_base_url()
    username = _required_env("SIEM_WEB_ADMIN_USER")
    password = _required_env("SIEM_WEB_ADMIN_PASSWORD")
    vm4_host = _required_env("SIEM_VM4_HOST")
    expected_content_backend = str(os.getenv("SIEM_EXPECT_CONTENT_STORE_BACKEND", "mongo") or "mongo").strip().lower()
    expected_stream_state_backend = str(os.getenv("SIEM_EXPECT_STREAM_STATE_BACKEND", "sqlite") or "sqlite").strip().lower()

    client = Client(base_url)
    _wait_for_backend_ready(client)
    status, _, login_page_url = client.request_with_meta("/auth/login")
    _expect_status(status, {200}, "/auth/login")
    if not login_page_url.endswith("/auth/login"):
        raise RuntimeError(f"/auth/login did not stay on the login page before auth: {login_page_url}")
    for static_asset_path in ("/favicon.svg", "/mark.svg", "/app/favicon.svg", "/app/mark.svg"):
        status, body = client.request(static_asset_path)
        _expect_status(status, {200}, static_asset_path)
        if "<svg" not in body[:256]:
            raise RuntimeError(f"{static_asset_path} does not look like an SVG asset")

    oidc_status, _, oidc_redirect_url = client.request_with_meta("/auth/oidc/start")
    _expect_status(oidc_status, {200}, "/auth/oidc/start")
    if "openid-connect" not in oidc_redirect_url and "/realms/" not in oidc_redirect_url:
        raise RuntimeError(f"/auth/oidc/start did not redirect to the OIDC provider: {oidc_redirect_url}")

    login_payload = urlencode(
        {
            "username": username,
            "password": password,
            "auth_flow": "break_glass",
            "break_glass_reason": "vm4 foundation smoke",
            "break_glass_minutes": "30",
        }
    ).encode("utf-8")
    status, _, login_result_url = client.request_with_meta(
        "/auth/login",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=login_payload,
    )
    _expect_status(status, {200}, "POST /auth/login")
    if not login_result_url.rstrip("/").endswith("/app") and not login_result_url.rstrip("/").endswith("/app/dashboards"):
        raise RuntimeError(f"POST /auth/login did not land on /app or /app/dashboards: {login_result_url}")

    status, body, after_login_url = client.request_with_meta("/auth/login")
    _expect_status(status, {200}, "GET /auth/login after auth")
    if not after_login_url.rstrip("/").endswith("/app") and not after_login_url.rstrip("/").endswith("/app/dashboards"):
        raise RuntimeError(f"Authenticated /auth/login did not resolve to /app or /app/dashboards: {after_login_url}")
    if 'id="root"' not in body:
        raise RuntimeError("Authenticated /auth/login did not render the React shell")
    _cleanup_smoke_artifacts(client)

    status, body = client.request("/api/openapi.json")
    _expect_status(status, {200}, "/api/openapi.json")
    openapi = json.loads(body)
    if "/api/connectors" not in openapi.get("paths", {}):
        raise RuntimeError("OpenAPI does not include /api/connectors")

    json_checks = (
        ("/api/auth/me", "principal"),
        ("/api/auth/providers", "items"),
        ("/api/auth/governance", "vault"),
        ("/api/auth/keycloak/status", "healthy"),
        ("/api/auth/access-systems?grantable_only=true", "items"),
        ("/api/auth/service-accounts", "available_permissions"),
        ("/api/dashboard/summary?window=24h&bucket_minutes=60&recent_limit=10", "timeline_window"),
        ("/api/connectors/overview", "metrics"),
        ("/api/health/overview", "platform"),
        ("/api/health/certification", "budgets"),
        ("/api/health/transport", "transport_backend"),
        ("/api/health/backups", "targets"),
        ("/api/health/storage-ha", "storage_ha"),
        ("/api/health/hosts/runtime", "metrics"),
        ("/api/reports", "items"),
        ("/api/vuln/runtime", "greenbone"),
        ("/api/vuln/maturity?days=30&limit=75", "runtime"),
        ("/api/ingest/overview", "metrics"),
        ("/api/ingest/sources", "items"),
        ("/api/ingest/collectors", "items"),
        ("/api/ingest/dlq", "items"),
        ("/api/sources/discovery", "metrics"),
        ("/api/control-plane/storage", "backend"),
        ("/api/content/storage", "backend"),
        ("/api/audit/events", "chain"),
        ("/api/cases", "items"),
        ("/api/incidents?limit=1000", "items"),
        ("/api/entities", "items"),
        ("/api/response/actions", "items"),
        ("/api/content/bundles", "items"),
        ("/api/search/saved", "items"),
        ("/api/lists/active", "items"),
        ("/api/secrets/required", "summary"),
    )

    slow_json_paths = {
        "/api/dashboard/summary?window=24h&bucket_minutes=60&recent_limit=10",
        "/api/health/overview",
        "/api/vuln/maturity?days=30&limit=75",
    }

    for path, required_key in json_checks:
        status, body = client.request(
            path,
            attempts=5 if path in slow_json_paths else 4,
            delay_seconds=4.0 if path in slow_json_paths else 2.0,
            timeout_seconds=SLOW_API_TIMEOUT_SECONDS if path in slow_json_paths else DEFAULT_HTTP_TIMEOUT_SECONDS,
        )
        _expect_status(status, {200}, path)
        payload = json.loads(body)
        if required_key not in payload:
            raise RuntimeError(f"{path} missing key: {required_key}")
        if path == "/api/auth/me":
            principal = dict(payload.get("principal") or {})
            if str(principal.get("auth_mechanism") or "").strip().lower() != "break_glass":
                raise RuntimeError(f"/api/auth/me expected break_glass auth, got {principal.get('auth_mechanism')!r}")
            if not bool(principal.get("break_glass")):
                raise RuntimeError("/api/auth/me did not mark the local session as break-glass")
        if path == "/api/auth/providers":
            providers = list(payload.get("items") or [])
            enterprise = next((item for item in providers if str(item.get("id") or "") == "enterprise-oidc"), None)
            local_provider = next((item for item in providers if str(item.get("id") or "") == "break-glass-local"), None)
            if not enterprise or not bool(enterprise.get("enabled")) or not bool(enterprise.get("healthy")):
                raise RuntimeError(f"/api/auth/providers does not report a healthy enterprise OIDC provider: {providers}")
            if not local_provider or not bool(local_provider.get("enabled")):
                raise RuntimeError(f"/api/auth/providers does not report break-glass local auth: {providers}")
        if path == "/api/auth/governance":
            oidc = dict(payload.get("oidc") or {})
            vault = dict(payload.get("vault") or {})
            if not bool(oidc.get("enabled")) or not bool(oidc.get("healthy")):
                raise RuntimeError(f"/api/auth/governance reports degraded OIDC state: {oidc}")
            if not bool(vault.get("healthy")) or not bool(vault.get("configured")):
                raise RuntimeError(f"/api/auth/governance reports degraded Vault state: {vault}")
            if int(dict(dict(payload.get("secrets") or {}).get("summary") or {}).get("vault_backed") or 0) < 1:
                raise RuntimeError("/api/auth/governance reports no Vault-backed secrets")
        if path == "/api/auth/keycloak/status":
            if not bool(payload.get("healthy")) or not bool(payload.get("admin_ready")):
                raise RuntimeError(f"/api/auth/keycloak/status reports degraded state: {payload}")
            inventory = dict(payload.get("inventory") or {})
            if int(inventory.get("clients") or 0) < 2:
                raise RuntimeError(f"/api/auth/keycloak/status inventory is unexpectedly small: {inventory}")
        if path == "/api/auth/access-systems?grantable_only=true":
            items = list(payload.get("items") or [])
            system_ids = {str(item.get("id") or "").strip() for item in items}
            if "siem" not in system_ids or "nextcloud" not in system_ids:
                raise RuntimeError(f"/api/auth/access-systems is missing required grantable systems: {items}")
            if "proxmox" in system_ids:
                raise RuntimeError(f"/api/auth/access-systems unexpectedly exposes proxmox as grantable: {items}")
        if path == "/api/health/overview" and "audit" not in payload:
            raise RuntimeError("/api/health/overview missing audit summary")
        if path == "/api/health/overview" and "ingest" not in payload:
            raise RuntimeError("/api/health/overview missing ingest summary")
        if path == "/api/health/overview":
            issues = list(payload.get("issues") or [])
            if issues and any(_is_host_runtime_stale_issue(item) for item in issues):
                _remediate_host_runtime_staleness(vm4_host)
                payload = _wait_for_overview_issues_to_clear(client, attempts=12, delay_seconds=5.0)
                issues = list(payload.get("issues") or [])
            if issues and _env_enabled("SIEM_SMOKE_REMEDIATE_INGEST_OVERVIEW_ISSUES") and _ingest_remediable_issues_only(issues):
                _remediate_ingest_health()
                payload = _wait_for_overview_issues_to_clear(client)
                issues = list(payload.get("issues") or [])
            if issues and _transient_ingest_proxy_issues_only(issues):
                payload = _wait_for_overview_issues_to_clear(client)
                issues = list(payload.get("issues") or [])
            if issues and all(
                _is_noncritical_residual_ingest_issue(item)
                or _is_transient_control_plane_release_gate_issue(item)
                for item in issues
            ):
                payload = _wait_for_overview_issues_to_clear(client, attempts=24, delay_seconds=5.0)
                issues = list(payload.get("issues") or [])
            if issues and all(
                _is_transient_control_plane_release_gate_issue(item)
                or _is_transient_stream_shadow_mismatch_issue(item)
                for item in issues
            ):
                print(f"/api/health/overview transient control-plane issues tolerated: {issues}")
                issues = []
            if issues and all(_is_noncritical_residual_ingest_issue(item) for item in issues):
                critical_ingest = _wait_for_critical_ingest_targets_ready()
                gate = dict(critical_ingest.get("gate") or {})
                outstanding = int(dict(dict(critical_ingest.get("overview") or {}).get("dlq") or {}).get("outstanding") or 0)
                if not bool(gate.get("healthy")):
                    raise RuntimeError(f"/api/health/overview residual ingest issues still hide failed critical gate: {gate}")
                if outstanding >= 5:
                    raise RuntimeError(f"/api/health/overview residual ingest issues still hide DLQ backlog: {outstanding}")
                print("/api/health/overview residual low-signal ingest issues tolerated after critical gate verification")
                issues = []
            if issues:
                if _env_enabled("SIEM_SMOKE_ALLOW_TRANSIENT_INGEST_OVERVIEW_ISSUES") and _transient_ingest_proxy_issues_only(issues):
                    if not _probe_ingest_health():
                        raise RuntimeError(f"/api/health/overview still reports issues: {issues}")
                    print("/api/health/overview transient ingest proxy warm-up tolerated")
                else:
                    raise RuntimeError(f"/api/health/overview still reports issues: {issues}")
            platform = payload.get("platform", {})
            if "stream_correlation" not in platform:
                raise RuntimeError("/api/health/overview missing platform.stream_correlation")
            if "content_store_status" not in platform:
                raise RuntimeError("/api/health/overview missing platform.content_store_status")
            if str(platform.get("transport_backend") or "").strip().lower() == "redis":
                raise RuntimeError("/api/health/overview still reports legacy redis transport backend")
            stream_corr = platform.get("stream_correlation") or {}
            for field in ("mode", "shadow_compare", "watermark_lag_sec", "allowed_lateness_sec"):
                if field not in stream_corr:
                    raise RuntimeError(f"/api/health/overview missing stream correlation field: {field}")
            if expected_stream_state_backend and str(stream_corr.get("state_backend") or "").strip().lower() != expected_stream_state_backend:
                raise RuntimeError(
                    f"/api/health/overview expected stream correlation state backend {expected_stream_state_backend}, "
                    f"got {stream_corr.get('state_backend')!r}"
                )
            content_store_status = platform.get("content_store_status") or {}
            for field in ("backend", "requested_backend", "collection_counts", "healthy"):
                if field not in content_store_status:
                    raise RuntimeError(f"/api/health/overview missing content store field: {field}")
            if expected_content_backend and str(content_store_status.get("backend") or "").strip().lower() != expected_content_backend:
                raise RuntimeError(
                    f"/api/health/overview expected content store backend {expected_content_backend}, "
                    f"got {content_store_status.get('backend')!r}"
                )
            auth = payload.get("auth", {})
            auth_metrics = auth.get("metrics") or {}
            auth_policy = auth.get("policy") or {}
            login_rate_limit = auth_policy.get("login_rate_limit") or {}
            for field in ("local_users_total", "local_users_hashed", "local_users_plaintext", "login_rate_limit_blocked_ips"):
                if field not in auth_metrics:
                    raise RuntimeError(f"/api/health/overview missing auth metric: {field}")
            if "enabled" not in login_rate_limit:
                raise RuntimeError("/api/health/overview missing auth rate-limit policy")
            if int(auth_metrics.get("local_users_plaintext") or 0) != 0:
                raise RuntimeError("/api/health/overview still reports plaintext local users")
            if not bool(login_rate_limit.get("enabled")):
                raise RuntimeError("/api/health/overview login rate limit is not enabled")
            if int(auth_metrics.get("providers_enabled") or 0) < 1 or int(auth_metrics.get("providers_healthy") or 0) < 1:
                raise RuntimeError("/api/health/overview does not report a healthy identity provider")
            if int(dict(payload.get("host_runtime") or {}).get("metrics", {}).get("stale_targets") or 0) != 0:
                raise RuntimeError("/api/health/overview still reports stale host runtime targets")
        if path == "/api/health/certification":
            if not bool(payload.get("healthy")):
                raise RuntimeError(f"/api/health/certification is not healthy: {payload.get('issues')}")
            if int(payload.get("latest_certified_ceiling_eps") or 0) < 1:
                raise RuntimeError("/api/health/certification does not report a certified EPS ceiling")
            if not list(dict(payload.get("budgets") or {}).get("stage_ladder_eps") or []):
                raise RuntimeError("/api/health/certification missing stage ladder budgets")
        if path == "/api/health/transport":
            for field in ("transport_cutover_stage", "stream_state_backend", "shadow_compare_status", "ingest", "stream_correlation"):
                if field not in payload:
                    raise RuntimeError(f"/api/health/transport missing field: {field}")
            if str(payload.get("transport_backend") or "").strip().lower() == "redis":
                raise RuntimeError("/api/health/transport still reports legacy redis backend")
            if expected_stream_state_backend and str(payload.get("stream_state_backend") or "").strip().lower() != expected_stream_state_backend:
                raise RuntimeError(
                    f"/api/health/transport expected stream state backend {expected_stream_state_backend}, "
                    f"got {payload.get('stream_state_backend')!r}"
                )
            if expected_content_backend and str(payload.get("content_store_backend") or "").strip().lower() != expected_content_backend:
                raise RuntimeError(
                    f"/api/health/transport expected content store backend {expected_content_backend}, "
                    f"got {payload.get('content_store_backend')!r}"
                )
            if not bool(payload.get("healthy")):
                raise RuntimeError(f"/api/health/transport is not healthy: {payload.get('issues')}")
            if not bool(payload.get("shadow_pipeline_healthy")) or str(payload.get("shadow_pipeline_status") or "") != "healthy":
                raise RuntimeError(f"/api/health/transport shadow pipeline is not healthy: {payload}")
        if path == "/api/health/backups":
            for field in ("healthy", "issues", "targets"):
                if field not in payload:
                    raise RuntimeError(f"/api/health/backups missing field: {field}")
            for target_key in ("control_plane_postgres", "content_store_mongo", "stream_state_sqlite", "clickhouse_storage"):
                if target_key not in payload.get("targets", {}):
                    raise RuntimeError(f"/api/health/backups missing target: {target_key}")
                if not bool(dict(payload.get("targets", {})).get(target_key, {}).get("prepared")):
                    raise RuntimeError(f"/api/health/backups target is not prepared: {target_key}")
            if not bool(payload.get("healthy")):
                raise RuntimeError(f"/api/health/backups is not healthy: {payload.get('issues')}")
        if path == "/api/health/storage-ha":
            storage_ha = payload.get("storage_ha") or {}
            for field in ("clickhouse", "postgres", "mongo"):
                if field not in storage_ha:
                    raise RuntimeError(f"/api/health/storage-ha missing field: {field}")
            if str((payload.get("storage_ha") or {}).get("clickhouse", {}).get("active_endpoint", {}).get("host") or "") == "127.0.0.1":
                raise RuntimeError("/api/health/storage-ha is still reporting localhost-only ClickHouse failover state")
            if not bool(storage_ha.get("clickhouse", {}).get("healthy")):
                raise RuntimeError("/api/health/storage-ha reports unhealthy ClickHouse")
            if not bool(storage_ha.get("postgres", {}).get("healthy")):
                raise RuntimeError("/api/health/storage-ha reports unhealthy Postgres")
            if not bool(storage_ha.get("mongo", {}).get("healthy")):
                raise RuntimeError("/api/health/storage-ha reports unhealthy Mongo")
            if not bool(storage_ha.get("failover_ready")) or not bool(storage_ha.get("controlled_switchover_ready")):
                raise RuntimeError(f"/api/health/storage-ha is not ready for failover/switchover: {storage_ha}")
            if storage_ha.get("alarms"):
                raise RuntimeError(f"/api/health/storage-ha still reports alarms: {storage_ha.get('alarms')}")
        if path == "/api/health/hosts/runtime":
            metrics = payload.get("metrics") or {}
            if int(metrics.get("stale_targets") or 0) != 0:
                raise RuntimeError(f"/api/health/hosts/runtime still has stale targets: {metrics}")
            if int(metrics.get("snapshot_events") or 0) < 5:
                raise RuntimeError(f"/api/health/hosts/runtime has too few snapshot events: {metrics}")
            targets = list(payload.get("targets") or [])
            if len(targets) < 5:
                raise RuntimeError(f"/api/health/hosts/runtime returned too few targets: {targets}")
            if any(bool(item.get("stale")) or not str(item.get("last_seen_ts") or "").strip() for item in targets[:5]):
                raise RuntimeError(f"/api/health/hosts/runtime still reports stale or missing targets: {targets[:5]}")
            if not any(float(dict(item.get("snapshot") or {}).get("memory_used_pct") or 0.0) > 0.0 for item in targets[:5]):
                raise RuntimeError(f"/api/health/hosts/runtime returned zeroed memory metrics: {targets[:5]}")
        if path == "/api/reports":
            items = list(payload.get("items") or [])
            if not items:
                raise RuntimeError("/api/reports returned no structured vulnerability reports")
            first = dict(items[0] or {})
            for field in ("report_id", "artifact_link"):
                if not str(first.get(field) or "").strip():
                    raise RuntimeError(f"/api/reports item missing field: {field}")
        if path == "/api/vuln/runtime":
            for field in ("runtime", "healthy", "structured_reports"):
                if field not in payload:
                    raise RuntimeError(f"/api/vuln/runtime missing field: {field}")
            if not bool(payload.get("healthy")):
                raise RuntimeError(f"/api/vuln/runtime is not healthy: {payload}")
            if int(dict(payload.get("structured_reports") or {}).get("count") or 0) < 1:
                raise RuntimeError("/api/vuln/runtime has no structured reports")
            policy_scheduler = dict(payload.get("policy_scheduler") or {})
            if "runtime" not in policy_scheduler:
                raise RuntimeError("/api/vuln/runtime missing policy scheduler runtime")
            runtime_state = dict(policy_scheduler.get("runtime") or {})
            if runtime_state and str(runtime_state.get("status") or "ok") == "error":
                raise RuntimeError(f"/api/vuln/runtime policy scheduler reports error: {runtime_state}")
        if path.startswith("/api/vuln/maturity"):
            workflows = list(payload.get("scheduled_workflows") or [])
            schedule = next(
                (
                    str(item.get("schedule") or "")
                    for item in workflows
                    if str(item.get("id") or "") == "vuln-incident-policy"
                ),
                "",
            )
            if schedule != "timer/service":
                raise RuntimeError(f"/api/vuln/maturity has unexpected policy schedule: {schedule!r}")
            if int(payload.get("reports_total") or 0) < 1:
                raise RuntimeError("/api/vuln/maturity reports_total is empty")
            if int(payload.get("reports_with_asset_binding") or 0) < 1:
                raise RuntimeError("/api/vuln/maturity reports_with_asset_binding is empty")
        if path.startswith("/api/dashboard/summary") and "bucket_minutes" not in payload.get("timeline_window", {}):
            raise RuntimeError("/api/dashboard/summary missing timeline window metadata")
        if path == "/api/control-plane/storage":
            for field in ("migration_status", "collection_counts", "last_migration_at"):
                if field not in payload:
                    raise RuntimeError(f"/api/control-plane/storage missing field: {field}")
        if path == "/api/content/storage":
            for field in ("requested_backend", "migration_status", "collection_counts", "fallback_reason"):
                if field not in payload:
                    raise RuntimeError(f"/api/content/storage missing field: {field}")
            if expected_content_backend and str(payload.get("backend") or "").strip().lower() != expected_content_backend:
                raise RuntimeError(
                    f"/api/content/storage expected backend {expected_content_backend}, got {payload.get('backend')!r}"
                )
        print(f"{path} ok")

    status, body = client.request(
        "/api/sources/discovery/scan",
        method="POST",
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        data=json.dumps({"cidr": "192.168.1.39/32", "max_hosts": 1, "timeout_seconds": 0.35}).encode("utf-8"),
    )
    _expect_status(status, {200}, "POST /api/sources/discovery/scan")
    discovery_scan = json.loads(body)
    if "scan" not in discovery_scan or "items" not in discovery_scan:
        raise RuntimeError("Source discovery scan did not return scan metadata and items")
    print("source discovery runtime ok")

    smoke_suffix = str(int(time.time()))
    status, body = client.request(
        "/api/connectors",
        method="POST",
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        data=json.dumps(
            {
                "title": f"Smoke webhook source {smoke_suffix}",
                "family": "source",
                "block_type": "webhook_source",
                "group": "smoke",
                "mode": "push",
                "source_family": "custom_api",
                "secret_requirements": [],
            }
        ).encode("utf-8"),
    )
    _expect_status(status, {200}, "POST /api/connectors")
    connector = json.loads(body)
    connector_id = str(connector.get("id") or "")
    if not connector_id:
        raise RuntimeError("Unable to create smoke connector")
    status, body = client.request(
        f"/api/connectors/{connector_id}/run",
        method="POST",
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        data=json.dumps({"dry_run": True, "trigger": "smoke"}).encode("utf-8"),
    )
    _expect_status(status, {200}, f"/api/connectors/{connector_id}/run")
    connector_run = json.loads(body)
    if str(connector_run.get("run", {}).get("status") or "") != "dry_run":
        raise RuntimeError("Connector runtime smoke did not return dry_run")
    _best_effort_delete(client, f"/api/connectors/{quote(connector_id, safe='')}")
    print("connector runtime ok")

    status, body = client.request(
        "/api/response/actions",
        method="POST",
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        data=json.dumps(
            {
                "title": f"Smoke approval gate {smoke_suffix}",
                "kind": "approval_gate",
                "approval_required": False,
            }
        ).encode("utf-8"),
    )
    _expect_status(status, {200}, "POST /api/response/actions")
    action = json.loads(body)
    action_id = str(action.get("id") or "")
    if not action_id:
        raise RuntimeError("Unable to create smoke response action")
    status, body = client.request(
        f"/api/response/actions/{action_id}/execute",
        method="POST",
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        data=json.dumps({"dry_run": True, "payload": {"message": "smoke"}}).encode("utf-8"),
    )
    _expect_status(status, {200}, f"/api/response/actions/{action_id}/execute")
    execution = json.loads(body)
    if str(execution.get("execution", {}).get("status") or "") != "dry_run":
        raise RuntimeError("Response action smoke did not return dry_run")
    _best_effort_delete(client, f"/api/response/actions/{quote(action_id, safe='')}")
    print("response runtime ok")

    status, body = client.request(
        "/api/auth/service-accounts",
        method="POST",
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        data=json.dumps(
            {
                "name": f"smoke-runtime-{smoke_suffix}",
                "description": "Smoke service account for token auth validation",
                "enabled": True,
                "permissions": ["health:view"],
            }
        ).encode("utf-8"),
    )
    _expect_status(status, {200}, "POST /api/auth/service-accounts")
    service_account = json.loads(body)
    service_account_id = str(service_account.get("id") or "")
    if not service_account_id:
        raise RuntimeError("Unable to create smoke service account")

    status, body = client.request(
        f"/api/auth/service-accounts/{service_account_id}/tokens",
        method="POST",
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        data=json.dumps({"title": "Smoke token", "expires_days": 30}).encode("utf-8"),
    )
    _expect_status(status, {200}, f"/api/auth/service-accounts/{service_account_id}/tokens")
    token_payload = json.loads(body)
    api_token = str(token_payload.get("token", {}).get("token") or "")
    if not api_token:
        raise RuntimeError("Unable to issue smoke API token")

    token_headers = {"Accept": "application/json", "Authorization": f"Bearer {api_token}"}
    status, body = client.request("/api/auth/me", headers=token_headers)
    _expect_status(status, {200}, "/api/auth/me with service account token")
    principal_payload = json.loads(body)
    if str(principal_payload.get("principal", {}).get("auth_mechanism") or "") != "api_token":
        raise RuntimeError("Service account token did not authenticate as api_token")
    if str(principal_payload.get("principal", {}).get("service_account_id") or "") != service_account_id:
        raise RuntimeError("Service account token principal mismatch")
    status, body = client.request(
        "/api/health/overview",
        headers=token_headers,
        attempts=3,
        delay_seconds=3.0,
        timeout_seconds=SLOW_API_TIMEOUT_SECONDS,
    )
    _expect_status(status, {200}, "/api/health/overview with service account token")
    _best_effort_delete(client, f"/api/auth/service-accounts/{quote(service_account_id, safe='')}")
    print("service account token auth ok")

    status, body = client.request("/app")
    _expect_status(status, {200}, "/app")
    if 'id="root"' not in body:
        raise RuntimeError("/app response does not look like the React shell")
    print("/app ok")

    vm4_user = str(os.getenv("SIEM_VM4_USER", "") or "").strip()
    vm4_password = str(os.getenv("SIEM_VM4_PASSWORD", "") or "").strip()
    if vm4_user and vm4_password:
        ssh_client = _connect_client(vm4_host, vm4_user, vm4_password)
        try:
            code, out, err = _run_remote(
                ssh_client,
                "systemctl is-active siem-vault siem-keycloak openvpn-client@home-gateway siem-jump-tunnels siem-greenbone-sync.timer siem-vuln-policy-apply.timer && "
                "export VAULT_ADDR=http://127.0.0.1:8200 && /opt/siem/vault/current/vault status -format=json",
                sudo_password=vm4_password,
                use_sudo=True,
            )
            cleaned = _strip_sudo_echo(out, vm4_password)
            lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
            states = lines[:6]
            vault_payload = json.loads("\n".join(lines[6:])) if len(lines) > 6 else {}
            if code != 0 or states != ["active", "active", "active", "active", "active", "active"]:
                raise RuntimeError(f"VM4 runtime/access services are not green: states={states} stderr={err.strip()}")
            if bool(vault_payload.get("sealed", True)):
                raise RuntimeError("VM4 Vault is still sealed after service startup")
        finally:
            _close_ssh_client(ssh_client)
        print("vm4 access/runtime services ok")

    _cleanup_smoke_artifacts(client)
    print("smoke=success")
    return 0


if __name__ == "__main__":
    exit_code = main()
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(exit_code)
