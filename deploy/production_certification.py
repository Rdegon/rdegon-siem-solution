from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any

try:
    import paramiko
except ModuleNotFoundError:  # pragma: no cover - validate-main without deploy extras
    paramiko = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from certification_runtime import certification_profile, evaluate_benchmark, save_certification_status  # noqa: E402
from deploy.distributed_eps_benchmark import DEFAULT_INJECTORS, HostSpec, parse_stages, run_stage, summarize_results  # noqa: E402
from deploy.env_file_runtime import maybe_load_runtime_env  # noqa: E402
from deploy.storage_ha_drill import build_live_storage_ha_status, build_storage_ha_drill_report  # noqa: E402


maybe_load_runtime_env()


class WebClient:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.jar = CookieJar()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPCookieProcessor(self.jar),
        )

    def request(self, path: str, *, method: str = "GET", payload: dict[str, Any] | None = None) -> tuple[int, str]:
        headers = {"Accept": "application/json"}
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            data = urllib.parse.urlencode(payload).encode("utf-8")
        request = urllib.request.Request(f"{self.base_url}{path}", data=data, headers=headers, method=method)
        with self.opener.open(request, timeout=30) as response:
            body = response.read().decode("utf-8", errors="replace")
            return response.status, body


def _required_env(name: str, *, default: str | None = None) -> str:
    value = str(os.getenv(name, default or "") or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _optional_env(name: str, *, default: str = "") -> str:
    return str(os.getenv(name, default) or "").strip()


def _load_profile() -> dict[str, Any]:
    profile = dict(certification_profile())
    stages = [max(1, int(item)) for item in list(profile.get("stage_ladder_eps") or []) if str(item).strip()]
    profile["stage_ladder_eps"] = stages or [1000, 2500, 5000]
    profile["latency_budget_skip_initial_stages"] = max(0, int(profile.get("latency_budget_skip_initial_stages") or 0))
    profile["delivery_ratio_min"] = float(profile.get("delivery_ratio_min") or 0.995)
    profile["ingest_p95_latency_ms_max"] = float(profile.get("ingest_p95_latency_ms_max") or 22000)
    profile["kafka_lag_max"] = int(profile.get("kafka_lag_max") or 5000)
    return profile


def validate_profile(profile: dict[str, Any]) -> dict[str, Any]:
    issues: list[str] = []
    stages = list(profile.get("stage_ladder_eps") or [])
    if not stages:
        issues.append("stage_ladder_eps_missing")
    if stages != sorted(stages):
        issues.append("stage_ladder_eps_not_sorted")
    if len(set(stages)) != len(stages):
        issues.append("stage_ladder_eps_not_unique")
    if int(profile.get("latency_budget_skip_initial_stages") or 0) < 0:
        issues.append("latency_budget_skip_initial_stages_invalid")
    if float(profile.get("delivery_ratio_min") or 0.0) < 0.95:
        issues.append("delivery_ratio_min_too_low")
    if int(profile.get("kafka_lag_max") or 0) <= 0:
        issues.append("kafka_lag_max_invalid")
    if float(profile.get("ingest_p95_latency_ms_max") or 0.0) <= 0:
        issues.append("ingest_p95_latency_ms_max_invalid")
    return {"healthy": not issues, "issues": issues, "profile": profile}


def _build_injectors() -> list[HostSpec]:
    return [
        HostSpec(prefix, _required_env(f"{prefix}_HOST"), _required_env(f"{prefix}_USER"), _required_env(f"{prefix}_PASSWORD"))
        for prefix in DEFAULT_INJECTORS
    ]


def _vm3_spec() -> HostSpec:
    return HostSpec("SIEM_VM3", _required_env("SIEM_VM3_HOST"), _required_env("SIEM_VM3_USER"), _required_env("SIEM_VM3_PASSWORD"))


def run_benchmark(profile: dict[str, Any]) -> dict[str, Any]:
    ingest_secret = _required_env("SIEM_INGEST_API_SHARED_SECRET")
    ingest_url = _optional_env("SIEM_BENCHMARK_INGEST_URL", default="https://192.168.1.35/ingest/json")
    duration_sec = int(_optional_env("SIEM_BENCHMARK_STAGE_DURATION_SEC", default="20") or "20")
    batch_size = int(_optional_env("SIEM_BENCHMARK_BATCH_SIZE", default="200") or "200")
    request_timeout_sec = float(_optional_env("SIEM_BENCHMARK_REQUEST_TIMEOUT_SEC", default="30") or "30")
    stages = parse_stages(",".join(str(item) for item in list(profile.get("stage_ladder_eps") or [])))
    run_id = _optional_env("SIEM_CERTIFICATION_RUN_ID", default=f"production-certification-{int(time.time())}")
    injectors = _build_injectors()
    vm3 = _vm3_spec()
    results: list[dict[str, Any]] = []
    for stage in stages:
        result = run_stage(
            run_id=run_id,
            stage_eps=int(stage),
            duration_sec=duration_sec,
            batch_size=batch_size,
            request_timeout_sec=request_timeout_sec,
            ingest_url=ingest_url,
            ingest_secret=ingest_secret,
            injectors=injectors,
            vm3=vm3,
        )
        results.append(result)
    return summarize_results(results)


def _connect_client(host: str, user: str, password: str) -> paramiko.SSHClient:
    if paramiko is None:
        raise RuntimeError("paramiko is required for certification status upload")
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


def _connect_client_with_retry(
    host: str,
    user: str,
    password: str,
    *,
    attempts: int = 3,
    delay_seconds: float = 3.0,
) -> paramiko.SSHClient:
    last_error: Exception | None = None
    for attempt in range(1, max(1, attempts) + 1):
        try:
            return _connect_client(host, user, password)
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt >= max(1, attempts):
                break
            time.sleep(delay_seconds)
    raise RuntimeError(str(last_error or f"unable to connect to {host}"))


def _run(client: paramiko.SSHClient, command: str, *, sudo_password: str = "", use_sudo: bool = False) -> tuple[int, str, str]:
    wrapped = f"sudo -S -p '' bash -lc {command!r}" if use_sudo else command
    stdin, stdout, stderr = client.exec_command(wrapped, get_pty=use_sudo)
    if use_sudo:
        stdin.write(f"{sudo_password}\n")
        stdin.flush()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    return code, out, err


def _remote_service_state(client: paramiko.SSHClient, unit: str, *, sudo_password: str) -> str:
    code, out, _ = _run(client, f"systemctl is-active {unit} || true", sudo_password=sudo_password, use_sudo=True)
    if code not in {0, 3}:
        return ""
    cleaned = str(out or "").replace("\r", "\n")
    for line in cleaned.splitlines():
        text = line.strip()
        if not text or text == sudo_password:
            continue
        if text:
            return text
    return ""


def run_drill_checks() -> dict[str, Any]:
    storage_report = _load_live_storage_ha_report()
    vm5 = HostSpec("SIEM_VM5", _required_env("SIEM_VM5_HOST"), _required_env("SIEM_VM5_USER"), _required_env("SIEM_VM5_PASSWORD"))
    vm2 = HostSpec("SIEM_VM2", _required_env("SIEM_VM2_HOST"), _required_env("SIEM_VM2_USER"), _required_env("SIEM_VM2_PASSWORD"))
    kafka_state = ""
    runner_vm2 = ""
    runner_vm5 = ""
    kafka_issues: list[str] = []
    try:
        vm5_client = _connect_client_with_retry(vm5.host, vm5.user, vm5.password)
        try:
            kafka_state = _remote_service_state(vm5_client, "siem-kafka", sudo_password=vm5.password)
            runner_vm5 = _remote_service_state(vm5_client, "actions.runner.Rdegon-siem-solution.siem-vm5.service", sudo_password=vm5.password)
            duplicate_vm2 = _remote_service_state(vm5_client, "actions.runner.Rdegon-siem-solution.siem-vm2.service", sudo_password=vm5.password)
            if duplicate_vm2 not in {"inactive", "failed", "unknown", ""}:
                kafka_issues.append(f"duplicate_vm2_runner_on_vm5:{duplicate_vm2}")
        finally:
            vm5_client.close()
    except Exception as exc:  # noqa: BLE001
        kafka_issues.append(f"vm5_probe_failed:{exc}")
    try:
        vm2_client = _connect_client_with_retry(vm2.host, vm2.user, vm2.password)
        try:
            runner_vm2 = _remote_service_state(vm2_client, "actions.runner.Rdegon-siem-solution.siem-vm2.service", sudo_password=vm2.password)
        finally:
            vm2_client.close()
    except Exception as exc:  # noqa: BLE001
        kafka_issues.append(f"vm2_probe_failed:{exc}")
    drill_items = [
        {
            "name": "kafka_transport_recovery",
            "healthy": kafka_state == "active",
            "status": "passed" if kafka_state == "active" else "failed",
            "details": {"service_state": kafka_state},
        },
        {
            "name": "postgres_failover_readiness",
            "healthy": bool(storage_report.get("checks", {}).get("postgres", {}).get("healthy")),
            "status": "passed" if bool(storage_report.get("checks", {}).get("postgres", {}).get("healthy")) else "failed",
            "details": dict(storage_report.get("checks", {}).get("postgres") or {}),
        },
        {
            "name": "mongo_stepdown_readiness",
            "healthy": bool(storage_report.get("checks", {}).get("mongo", {}).get("healthy")),
            "status": "passed" if bool(storage_report.get("checks", {}).get("mongo", {}).get("healthy")) else "failed",
            "details": dict(storage_report.get("checks", {}).get("mongo") or {}),
        },
        {
            "name": "clickhouse_primary_standby_verification",
            "healthy": bool(storage_report.get("checks", {}).get("clickhouse", {}).get("healthy")),
            "status": "passed" if bool(storage_report.get("checks", {}).get("clickhouse", {}).get("healthy")) else "failed",
            "details": dict(storage_report.get("checks", {}).get("clickhouse") or {}),
        },
        {
            "name": "runner_plane_recovery",
            "healthy": runner_vm2 == "active" and runner_vm5 == "active",
            "status": "passed" if runner_vm2 == "active" and runner_vm5 == "active" else "failed",
            "details": {"vm2_runner_state": runner_vm2, "vm5_runner_state": runner_vm5},
        },
    ]
    issues = list(storage_report.get("alarms") or []) + kafka_issues
    issues.extend(item["name"] for item in drill_items if not bool(item.get("healthy")))
    return {
        "healthy": not issues and all(bool(item.get("healthy")) for item in drill_items),
        "items": drill_items,
        "storage_ha": storage_report,
        "issues": issues,
        "last_failure_reason": issues[0] if issues else "",
    }


def _load_live_storage_ha_report() -> dict[str, Any]:
    base_url = _optional_env("SIEM_WEB_BASE_URL")
    username = _optional_env("SIEM_WEB_ADMIN_USER")
    password = _optional_env("SIEM_WEB_ADMIN_PASSWORD")
    if base_url and username and password:
        client = WebClient(base_url)
        client.request("/auth/login")
        client.request(
            "/auth/login",
            method="POST",
            payload={
                "username": username,
                "password": password,
                "auth_flow": "break_glass",
                "break_glass_reason": "production certification storage-ha drill",
                "break_glass_minutes": "30",
            },
        )
        status, body = client.request("/api/health/storage-ha")
        if status == 200:
            payload = json.loads(body)
            storage_ha = dict(payload.get("storage_ha") or {})
            return {
                "healthy": not list(storage_ha.get("alarms") or []),
                "failover_ready": bool(storage_ha.get("failover_ready")),
                "controlled_switchover_ready": bool(storage_ha.get("controlled_switchover_ready")),
                "restore_ready": bool(storage_ha.get("failover_ready")),
                "alarms": list(storage_ha.get("alarms") or []),
                "checks": {
                    "clickhouse": dict(storage_ha.get("clickhouse") or {}),
                    "postgres": dict(storage_ha.get("postgres") or {}),
                    "mongo": dict(storage_ha.get("mongo") or {}),
                },
            }
    storage_status = build_live_storage_ha_status()
    return build_storage_ha_drill_report(storage_status)


def stabilize_ingest_health() -> dict[str, Any]:
    try:
        os.environ.setdefault("SIEM_INGEST_TLS_VERIFY", "disabled")
        from ingest_runtime import get_ingest_overview, replay_ingest_dlq  # noqa: WPS433
    except Exception as exc:  # noqa: BLE001
        return {"healthy": False, "issues": [f"ingest_runtime_import_failed:{exc}"]}

    last_overview: dict[str, Any] = {}
    for _ in range(6):
        last_overview = get_ingest_overview()
        outstanding = int(dict(last_overview.get("dlq") or {}).get("outstanding") or 0)
        if outstanding <= 0:
            break
        replay_ingest_dlq(limit=min(200, max(1, outstanding)), actor="production-certification")
    last_overview = get_ingest_overview()
    return {
        "healthy": not list(last_overview.get("issues") or []),
        "issues": list(last_overview.get("issues") or []),
        "overview": last_overview,
    }


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


def _partition_post_benchmark_issues(issues: list[str]) -> tuple[list[str], list[str]]:
    blocking: list[str] = []
    tolerated: list[str] = []
    for item in issues:
        if _is_noncritical_residual_ingest_issue(item) or _is_transient_control_plane_release_gate_issue(item):
            tolerated.append(item)
        else:
            blocking.append(item)
    return blocking, tolerated


def collect_post_benchmark_health() -> dict[str, Any]:
    ingest_cleanup = stabilize_ingest_health()
    base_url = _required_env("SIEM_WEB_BASE_URL")
    username = _required_env("SIEM_WEB_ADMIN_USER")
    password = _required_env("SIEM_WEB_ADMIN_PASSWORD")
    client = WebClient(base_url)
    status, _ = client.request("/auth/login")
    if status != 200:
        raise RuntimeError(f"Unexpected login page status: {status}")
    status, _ = client.request(
        "/auth/login",
        method="POST",
        payload={
            "username": username,
            "password": password,
            "auth_flow": "break_glass",
            "break_glass_reason": "production certification gate",
            "break_glass_minutes": "30",
        },
    )
    if status != 200:
        raise RuntimeError(f"Unexpected login submit status: {status}")
    status, body = client.request("/api/health/overview")
    if status != 200:
        raise RuntimeError(f"Unexpected overview status: {status}")
    overview = json.loads(body)
    overview_issues = [
        str(item or "").strip()
        for item in list(overview.get("issues") or [])
        if str(item or "").strip() and not str(item or "").strip().startswith("Certification unhealthy:")
    ]
    ingest_cleanup_issues = [str(item or "").strip() for item in list(ingest_cleanup.get("issues") or []) if str(item or "").strip()]
    blocking_overview_issues, tolerated_overview_issues = _partition_post_benchmark_issues(overview_issues)
    blocking_ingest_issues, tolerated_ingest_issues = _partition_post_benchmark_issues(ingest_cleanup_issues)
    blocking_issues = blocking_overview_issues + blocking_ingest_issues
    tolerated_issues = tolerated_overview_issues + tolerated_ingest_issues
    return {
        "healthy": not blocking_issues,
        "issues": blocking_issues,
        "summary": {
            "latest_issue_count": len(blocking_overview_issues),
            "transport_backend": str(dict(overview.get("platform") or {}).get("transport_backend") or ""),
            "content_store_backend": str(dict(dict(overview.get("platform") or {}).get("content_store_status") or {}).get("backend") or ""),
            "ingest_issue_count": len(blocking_ingest_issues),
            "tolerated_issue_count": len(tolerated_issues),
            "tolerated_issues": tolerated_issues,
        },
        "last_failure_reason": blocking_issues[0] if blocking_issues else "",
    }


def _upload_status_to_vm4(payload: dict[str, Any]) -> None:
    if not _optional_env("SIEM_VM4_HOST"):
        return
    if paramiko is None:
        raise RuntimeError("paramiko is required for certification status upload")
    client = _connect_client(_required_env("SIEM_VM4_HOST"), _required_env("SIEM_VM4_USER"), _required_env("SIEM_VM4_PASSWORD"))
    try:
        remote_root = _required_env("SIEM_VM4_BASE_DIR")
        remote_dir = f"{remote_root.rstrip('/')}/runtime-control-plane"
        code, _, err = _run(client, f"mkdir -p {remote_dir!r}", sudo_password=_required_env('SIEM_VM4_PASSWORD'), use_sudo=True)
        if code != 0:
            raise RuntimeError(f"Unable to prepare remote certification runtime dir: {err.strip()}")
        sftp = client.open_sftp()
        try:
            local_status = ROOT / "runtime-control-plane" / "production_certification_status.json"
            remote_temp = f"/tmp/{local_status.name}"
            sftp.put(str(local_status), remote_temp)
        finally:
            sftp.close()
        code, _, err = _run(
            client,
            f"install -m 0644 {remote_temp!r} {f'{remote_dir}/production_certification_status.json'!r} && rm -f {remote_temp!r}",
            sudo_password=_required_env("SIEM_VM4_PASSWORD"),
            use_sudo=True,
        )
        if code != 0:
            raise RuntimeError(f"Unable to install remote certification status: {err.strip()}")
    finally:
        client.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run production certification benchmark and governance gate checks")
    parser.add_argument("--mode", choices=("full", "validate-profile"), default="full")
    args = parser.parse_args(argv)

    profile = _load_profile()
    profile_validation = validate_profile(profile)
    if not profile_validation["healthy"]:
        print(json.dumps(profile_validation, ensure_ascii=False, indent=2))
        return 1
    if args.mode == "validate-profile":
        print(json.dumps(profile_validation, ensure_ascii=False, indent=2))
        return 0

    benchmark = run_benchmark(profile)
    drill = run_drill_checks()
    post_benchmark_health = collect_post_benchmark_health()
    payload = save_certification_status(
        {
            "profile": profile,
            "benchmark": benchmark,
            "drill": drill,
            "post_benchmark_health": post_benchmark_health,
        }
    )
    _upload_status_to_vm4(payload)
    final_status = {
        "profile_validation": profile_validation,
        "benchmark": evaluate_benchmark(benchmark, profile),
        "drill": drill,
        "post_benchmark_health": post_benchmark_health,
        "saved": payload,
    }
    print(json.dumps(final_status, ensure_ascii=False, indent=2))
    return 0 if final_status["benchmark"]["healthy"] and drill.get("healthy") and post_benchmark_health.get("healthy") else 1


if __name__ == "__main__":
    raise SystemExit(main())
