from __future__ import annotations

import argparse
import json
import shlex
import sys
import time
from pathlib import Path
from typing import Any

try:
    import paramiko
except ModuleNotFoundError as exc:  # pragma: no cover
    raise SystemExit("paramiko is required for demo alert watcher") from exc


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULE_IDS = (2604, 2605, 2708)


def _connect(*, host: str, user: str, key_path: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        username=user,
        key_filename=key_path,
        timeout=20,
        banner_timeout=20,
        auth_timeout=20,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def _run(client: paramiko.SSHClient, command: str, *, timeout_sec: float = 60.0) -> tuple[int, str, str]:
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout_sec)
    stdin.close()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return stdout.channel.recv_exit_status(), out, err


def _clickhouse_json(client: paramiko.SSHClient, query: str) -> list[dict[str, Any]]:
    code, out, err = _run(client, "clickhouse-client --query " + shlex.quote(query), timeout_sec=120.0)
    if code != 0:
        raise RuntimeError(err.strip() or out.strip() or f"clickhouse-client exited with {code}")
    rows: list[dict[str, Any]] = []
    for line in str(out or "").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def _sql_string(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def _rule_clause(rule_ids: list[int]) -> str:
    ids = ",".join(str(int(item)) for item in rule_ids)
    return f"rule_id IN ({ids})"


def _contains_clause(columns: tuple[str, ...], value: str) -> str:
    if not value:
        return ""
    needle = _sql_string(value)
    parts = [f"positionCaseInsensitiveUTF8(toString({column}), '{needle}') > 0" for column in columns]
    return "(" + " OR ".join(parts) + ")"


def _query_alerts(client: paramiko.SSHClient, *, rule_ids: list[int], minutes: int, contains: str, limit: int) -> dict[str, Any]:
    safe_minutes = max(1, min(24 * 60, int(minutes)))
    safe_limit = max(1, min(500, int(limit)))
    base = f"ts >= now() - INTERVAL {safe_minutes} MINUTE AND {_rule_clause(rule_ids)}"
    raw_contains = _contains_clause(("context_json", "entity_key", "source", "rule_name"), contains)
    raw_where = f"{base} AND {raw_contains}" if raw_contains else base

    agg_base = f"ts_last >= now() - INTERVAL {safe_minutes} MINUTE AND {_rule_clause(rule_ids)}"
    agg_contains = _contains_clause(("group_key_json", "samples_json", "entity_key", "rule_name"), contains)
    agg_where = f"{agg_base} AND {agg_contains}" if agg_contains else agg_base

    raw_query = f"""
    SELECT
        toString(ts) AS ts_str,
        rule_id,
        rule_name,
        severity,
        status,
        entity_key,
        hits,
        source,
        left(context_json, 800) AS context_json
    FROM siem.alerts_raw
    WHERE {raw_where}
    ORDER BY ts DESC
    LIMIT {safe_limit}
    FORMAT JSONEachRow
    """
    agg_query = f"""
    SELECT
        toString(ts_last) AS ts_last_str,
        rule_id,
        rule_name,
        severity_agg,
        status,
        entity_key,
        count_alerts,
        unique_entities,
        left(group_key_json, 800) AS group_key_json,
        left(samples_json, 800) AS samples_json
    FROM siem.alerts_agg
    WHERE {agg_where}
    ORDER BY ts_last DESC
    LIMIT {safe_limit}
    FORMAT JSONEachRow
    """
    return {
        "raw": _clickhouse_json(client, raw_query),
        "agg": _clickhouse_json(client, agg_query),
    }


def parse_rule_ids(value: str) -> list[int]:
    if not str(value or "").strip():
        return list(DEFAULT_RULE_IDS)
    return [int(item.strip()) for item in str(value).split(",") if item.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only watcher for demo attack alerts.")
    parser.add_argument("--rules", default=",".join(str(item) for item in DEFAULT_RULE_IDS))
    parser.add_argument("--minutes", type=int, default=60)
    parser.add_argument("--contains", default="", help="Optional run id or marker to match in alert context.")
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--wait-seconds", type=int, default=0)
    parser.add_argument("--poll-interval", type=float, default=10.0)
    parser.add_argument("--vm3-host", default="192.168.1.38")
    parser.add_argument("--user", default="rdegon")
    parser.add_argument("--ssh-key", default=str(ROOT.parent / ".codex_tmp" / "vpnadmin_ed25519"))
    parser.add_argument("--output", default="")
    args = parser.parse_args(argv)

    rule_ids = parse_rule_ids(args.rules)
    key_path = str(Path(args.ssh_key).expanduser())
    deadline = time.time() + max(0, int(args.wait_seconds))
    last_result: dict[str, Any] = {}

    client = _connect(host=args.vm3_host, user=args.user, key_path=key_path)
    try:
        while True:
            alerts = _query_alerts(
                client,
                rule_ids=rule_ids,
                minutes=int(args.minutes),
                contains=str(args.contains or ""),
                limit=int(args.limit),
            )
            last_result = {
                "rules": rule_ids,
                "minutes": int(args.minutes),
                "contains": str(args.contains or ""),
                "raw_count": len(alerts["raw"]),
                "agg_count": len(alerts["agg"]),
                "alerts": alerts,
            }
            if last_result["raw_count"] or last_result["agg_count"] or time.time() >= deadline:
                break
            time.sleep(max(1.0, float(args.poll_interval)))
    finally:
        client.close()

    payload = json.dumps(last_result, ensure_ascii=False, indent=2)
    if str(args.output or "").strip():
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload + "\n", encoding="utf-8")
    print(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
