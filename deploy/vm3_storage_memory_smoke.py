from __future__ import annotations

import os
import shlex
import sys
import time

import paramiko


CLICKHOUSE_SERVICE_UNITS = (
    "clickhouse-server",
    "siem-writer",
    "siem-writer@2",
    "siem-stream-corr",
    "siem-batch-corr",
    "siem-alert-agg",
)

DEFAULT_MAX_SERVER_MEMORY_USAGE = 16 * 1024 * 1024 * 1024
DEFAULT_MARK_CACHE_SIZE = 1024 * 1024 * 1024
DEFAULT_UNCOMPRESSED_CACHE_SIZE = 1024 * 1024 * 1024
DEFAULT_MAX_SERVER_MEMORY_USAGE_TO_RAM_RATIO = 0.6
DEFAULT_MIN_AVAILABLE_MEMORY_BYTES = 4 * 1024 * 1024 * 1024
DEFAULT_CLICKHOUSE_APP_USER = "siem_admin"


def _required_env(name: str, *, default: str | None = None) -> str:
    value = str(os.getenv(name, default or "") or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _run_command(
    client: paramiko.SSHClient,
    command: str,
    *,
    sudo_password: str = "",
    use_sudo: bool = False,
) -> tuple[int, str, str]:
    wrapped = f"sudo -S -p '' bash -lc {shlex.quote(command)}" if use_sudo else command
    stdin, stdout, stderr = client.exec_command(wrapped, get_pty=use_sudo)
    if use_sudo:
        stdin.write(f"{sudo_password}\n")
        stdin.flush()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    return code, out, err


def _strip_sudo_echo(text: str, sudo_password: str) -> str:
    if not sudo_password:
        return text
    cleaned_lines: list[str] = []
    for raw_line in str(text or "").replace("\r", "\n").split("\n"):
        line = raw_line.strip("\x00")
        if line.strip() == sudo_password:
            continue
        cleaned_lines.append(line)
    return "\n".join(cleaned_lines)


def _parse_free_bytes(output: str) -> dict[str, int]:
    for raw_line in str(output or "").splitlines():
        line = raw_line.strip()
        if not line.startswith("Mem:"):
            continue
        parts = [part for part in line.split() if part]
        if len(parts) < 7:
            break
        return {
            "total": int(parts[1]),
            "used": int(parts[2]),
            "free": int(parts[3]),
            "shared": int(parts[4]),
            "buff_cache": int(parts[5]),
            "available": int(parts[6]),
        }
    raise ValueError(f"Unable to parse free -b output: {output}")


def _format_bytes(value: int) -> str:
    size = float(max(int(value or 0), 0))
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    unit = units[0]
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            break
        size /= 1024.0
    return f"{size:.2f} {unit}"


def _within_tolerance(actual: int, expected: int, *, tolerance_bytes: int = 512 * 1024 * 1024) -> bool:
    return abs(int(actual) - int(expected)) <= int(tolerance_bytes)


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


def _run_once() -> int:
    host = _required_env("SIEM_VM3_HOST")
    user = _required_env("SIEM_VM3_USER")
    password = _required_env("SIEM_VM3_PASSWORD")
    expected_max_server_memory_usage = int(
        _required_env("SIEM_VM3_CH_MAX_SERVER_MEMORY_USAGE_BYTES", default=str(DEFAULT_MAX_SERVER_MEMORY_USAGE))
    )
    expected_mark_cache_size = int(_required_env("SIEM_VM3_CH_MARK_CACHE_SIZE_BYTES", default=str(DEFAULT_MARK_CACHE_SIZE)))
    expected_uncompressed_cache_size = int(
        _required_env("SIEM_VM3_CH_UNCOMPRESSED_CACHE_SIZE_BYTES", default=str(DEFAULT_UNCOMPRESSED_CACHE_SIZE))
    )
    expected_memory_ratio = float(
        _required_env(
            "SIEM_VM3_CH_MAX_SERVER_MEMORY_USAGE_TO_RAM_RATIO",
            default=str(DEFAULT_MAX_SERVER_MEMORY_USAGE_TO_RAM_RATIO),
        )
    )
    clickhouse_app_user = _required_env("SIEM_VM3_CH_APP_USER", default=DEFAULT_CLICKHOUSE_APP_USER)
    min_available_memory_bytes = int(
        _required_env("SIEM_VM3_STORAGE_MIN_AVAILABLE_MEMORY_BYTES", default=str(DEFAULT_MIN_AVAILABLE_MEMORY_BYTES))
    )

    client = _connect_client(host, user, password)
    try:
        active_cmd = "systemctl is-active " + " ".join(CLICKHOUSE_SERVICE_UNITS)
        code, out, err = _run_command(client, active_cmd, sudo_password=password, use_sudo=True)
        active_out = _strip_sudo_echo(out, password)
        states = [line.strip() for line in active_out.splitlines() if line.strip()]
        if code != 0 or states != ["active"] * len(CLICKHOUSE_SERVICE_UNITS):
            raise RuntimeError(f"Unexpected storage service state: stdout={states} stderr={err.strip()}")
        print("storage_services=active")

        grants_cmd = (
            "clickhouse-client --query "
            f"\"SHOW GRANTS FOR {clickhouse_app_user} FORMAT TabSeparatedRaw\""
        )
        code, out, err = _run_command(client, grants_cmd)
        if code != 0:
            raise RuntimeError(f"Unable to inspect ClickHouse grants for {clickhouse_app_user}: {err.strip()}")
        grants_output = str(out or "")
        required_grants = (
            "GRANT SELECT(metric, value) ON system.asynchronous_metrics",
            "GRANT SELECT(name, value) ON system.metrics",
            "GRANT SELECT(name, value) ON system.server_settings",
        )
        missing_grants = [grant for grant in required_grants if grant not in grants_output]
        if missing_grants:
            raise RuntimeError(
                f"ClickHouse metrics grants missing for {clickhouse_app_user}: {', '.join(missing_grants)}"
            )

        metrics_cmd = (
            "clickhouse-client --query "
            "\"SELECT metric, value FROM system.asynchronous_metrics WHERE metric IN "
            "('MemoryResident','jemalloc.allocated','MarkCacheBytes','UncompressedCacheBytes') "
            "ORDER BY metric FORMAT TabSeparated\""
        )
        code, out, err = _run_command(client, metrics_cmd)
        if code != 0:
            raise RuntimeError(f"Unable to query ClickHouse async metrics: {err.strip()}")
        metrics: dict[str, int] = {}
        for line in out.splitlines():
            if "\t" not in line:
                continue
            key, value = line.split("\t", 1)
            metrics[key.strip()] = int(value.strip() or 0)

        code, out, err = _run_command(client, "free -b")
        if code != 0:
            raise RuntimeError(f"Unable to query system memory: {err.strip()}")
        free_payload = _parse_free_bytes(out)
        if free_payload["available"] < min_available_memory_bytes:
            raise RuntimeError(
                f"Available system memory on VM3 is below threshold: {free_payload['available']} < {min_available_memory_bytes}"
            )

        settings_cmd = (
            "clickhouse-client --query "
            "\"SELECT name, value FROM system.server_settings WHERE name IN "
            "('max_server_memory_usage','mark_cache_size','uncompressed_cache_size') ORDER BY name FORMAT TabSeparated\""
        )
        code, out, err = _run_command(client, settings_cmd)
        if code != 0:
            raise RuntimeError(f"Unable to query ClickHouse server settings: {err.strip()}")
        settings: dict[str, int] = {}
        for line in out.splitlines():
            if "\t" not in line:
                continue
            key, value = line.split("\t", 1)
            settings[key.strip()] = int(value.strip() or 0)
        effective_expected_max_server_memory_usage = min(
            expected_max_server_memory_usage,
            int(free_payload["total"] * expected_memory_ratio),
        )
        if not _within_tolerance(
            settings.get("max_server_memory_usage", 0),
            effective_expected_max_server_memory_usage,
        ):
            raise RuntimeError(
                "Unexpected max_server_memory_usage: "
                f"actual={settings.get('max_server_memory_usage', 0)} "
                f"expected_effective={effective_expected_max_server_memory_usage}"
            )
        if settings.get("mark_cache_size") != expected_mark_cache_size:
            raise RuntimeError("Unexpected mark_cache_size")
        if settings.get("uncompressed_cache_size") != expected_uncompressed_cache_size:
            raise RuntimeError("Unexpected uncompressed_cache_size")

        print(f"memory_available={_format_bytes(free_payload['available'])}")
        print(f"memory_used={_format_bytes(free_payload['used'])}")
        print(f"memory_buff_cache={_format_bytes(free_payload['buff_cache'])}")
        print(f"clickhouse_effective_limit={_format_bytes(effective_expected_max_server_memory_usage)}")
        print(f"clickhouse_resident={_format_bytes(metrics.get('MemoryResident', 0))}")
        print(f"clickhouse_allocated={_format_bytes(metrics.get('jemalloc.allocated', 0))}")
        print(f"clickhouse_mark_cache={_format_bytes(metrics.get('MarkCacheBytes', 0))}")
        print(f"clickhouse_uncompressed_cache={_format_bytes(metrics.get('UncompressedCacheBytes', 0))}")
        print(f"clickhouse_metrics_grants_user={clickhouse_app_user}")
        print("smoke=success")
        return 0
    finally:
        client.close()


def main() -> int:
    attempts = int(_required_env("SIEM_VM3_STORAGE_SMOKE_ATTEMPTS", default="5"))
    delay_seconds = float(_required_env("SIEM_VM3_STORAGE_SMOKE_DELAY_SECONDS", default="6"))
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            return _run_once()
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt == attempts:
                break
            print(f"vm3_storage_smoke retry attempt={attempt}/{attempts} error={exc}")
            time.sleep(delay_seconds)
    raise SystemExit(str(last_error or "VM3 storage smoke failed"))


if __name__ == "__main__":
    sys.exit(main())
