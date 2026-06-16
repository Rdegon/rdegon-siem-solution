from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path


DEFAULT_ENV_PATH = Path("/etc/siem/storage-standby.env")
SYNC_TABLE_WHERE = {
    "stream_corr_runtime_status": "observed_ts >= now() - INTERVAL 24 HOUR",
}


def load_env_file(path: Path = DEFAULT_ENV_PATH) -> dict[str, str]:
    payload: dict[str, str] = {}
    if not path.exists():
        return payload
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        payload[key.strip()] = value.strip()
    return payload


def parse_sync_tables(env: dict[str, str]) -> tuple[str, ...]:
    raw = str(env.get("SIEM_SYNC_TABLES") or "").strip()
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def render_sync_query(env: dict[str, str], table_name: str) -> str:
    primary_host = str(env.get("SIEM_PRIMARY_CH_HOST") or "127.0.0.1").strip()
    primary_port = str(env.get("SIEM_PRIMARY_CH_PORT") or "9000").strip() or "9000"
    database = str(env.get("SIEM_CH_DB") or "siem").strip() or "siem"
    user = str(env.get("SIEM_CH_USER") or "siem_admin").strip() or "siem_admin"
    password = str(env.get("SIEM_CH_PASSWORD") or "").strip()
    where_clause = str(SYNC_TABLE_WHERE.get(table_name, "") or "").strip()
    select_sql = (
        f"SELECT * FROM remote('{primary_host}:{primary_port}', '{database}', '{table_name}', '{user}', '{password}')"
    )
    if where_clause:
        select_sql = f"{select_sql} WHERE {where_clause}"
    return (
        f"TRUNCATE TABLE IF EXISTS {database}.{table_name}; "
        f"INSERT INTO {database}.{table_name} "
        f"{select_sql}"
    )


def _run(command: str) -> tuple[int, str, str]:
    proc = subprocess.run(
        ["bash", "-lc", command],
        capture_output=True,
        text=True,
        timeout=1800,
    )
    return proc.returncode, proc.stdout, proc.stderr


def main() -> int:
    env = {**os.environ, **load_env_file()}
    tables = parse_sync_tables(env)
    if not tables:
        print("synced_tables=0")
        print("sync=skipped")
        return 0
    user = str(env.get("SIEM_CH_USER") or "siem_admin").strip() or "siem_admin"
    password = str(env.get("SIEM_CH_PASSWORD") or "").strip()
    port = str(env.get("SIEM_CH_PORT") or "9000").strip() or "9000"
    for table_name in tables:
        query = render_sync_query(env, table_name)
        command = (
            "clickhouse-client "
            f"--host 127.0.0.1 --port {shlex.quote(port)} "
            f"--user {shlex.quote(user)} --password {shlex.quote(password)} "
            f"--multiquery --query {shlex.quote(query)}"
        )
        code, out, err = _run(command)
        if out.strip():
            print(out, end="")
        if code != 0:
            raise SystemExit(f"ClickHouse standby sync failed for {table_name}: {err.strip()}")
        print(f"synced_table={table_name}")
    print(f"synced_tables={len(tables)}")
    print("sync=success")
    return 0


if __name__ == "__main__":
    sys.exit(main())
