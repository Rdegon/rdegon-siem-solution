from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Mapping


def _state_backend(env: Mapping[str, str]) -> str:
    backend = str(env.get("SIEM_STREAM_STATE_BACKEND", "sqlite") or "sqlite").strip().lower()
    if backend not in {"redis", "sqlite"}:
        return "sqlite"
    return backend


def _sqlite_path(env: Mapping[str, str]) -> str:
    return str(
        env.get("SIEM_STREAM_STATE_SQLITE_PATH", "/var/lib/siem-stream-corr/runtime-state.db")
        or "/var/lib/siem-stream-corr/runtime-state.db"
    ).strip()


def _read_runtime_meta(conn: sqlite3.Connection) -> dict[str, Any]:
    rows = conn.execute("SELECT key, value FROM runtime_meta").fetchall()
    payload: dict[str, Any] = {}
    for key, value in rows:
        try:
            payload[str(key)] = json.loads(str(value))
        except json.JSONDecodeError:
            payload[str(key)] = str(value)
    return payload


def _read_offsets(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT transport_backend, group_name, topic_name, partition_id, offset_value, updated_ts
        FROM consumer_offsets
        ORDER BY group_name, topic_name, partition_id
        """
    ).fetchall()
    return [
        {
            "transport_backend": str(row[0] or ""),
            "group_name": str(row[1] or ""),
            "topic_name": str(row[2] or ""),
            "partition_id": int(row[3] or 0),
            "offset_value": int(row[4] or 0),
            "updated_ts": str(row[5] or ""),
        }
        for row in rows
    ]


def stream_state_runtime_status(env: Mapping[str, str] | None = None) -> dict[str, Any]:
    env_map = env or os.environ
    backend = _state_backend(env_map)
    sqlite_path = _sqlite_path(env_map)
    if backend != "sqlite":
        return {
            "backend": backend,
            "sqlite_path": sqlite_path,
            "healthy": True,
            "sqlite_exists": False,
            "stored_offsets_total": 0,
            "topics": [],
            "groups": [],
            "last_offset_ts": "",
            "runtime_meta_keys": [],
            "offsets": [],
        }

    path = Path(sqlite_path)
    if not path.exists():
        return {
            "backend": "sqlite",
            "sqlite_path": sqlite_path,
            "healthy": False,
            "sqlite_exists": False,
            "stored_offsets_total": 0,
            "topics": [],
            "groups": [],
            "last_offset_ts": "",
            "runtime_meta_keys": [],
            "offsets": [],
        }

    conn = sqlite3.connect(str(path))
    try:
        offsets = _read_offsets(conn)
        runtime_meta = _read_runtime_meta(conn)
    finally:
        conn.close()

    last_offset_ts = ""
    topics: set[str] = set()
    groups: set[str] = set()
    for row in offsets:
        topic_name = str(row.get("topic_name") or "")
        group_name = str(row.get("group_name") or "")
        updated_ts = str(row.get("updated_ts") or "")
        if topic_name:
            topics.add(topic_name)
        if group_name:
            groups.add(group_name)
        if updated_ts and updated_ts > last_offset_ts:
            last_offset_ts = updated_ts

    return {
        "backend": "sqlite",
        "sqlite_path": sqlite_path,
        "healthy": True,
        "sqlite_exists": True,
        "stored_offsets_total": len(offsets),
        "topics": sorted(topics),
        "groups": sorted(groups),
        "last_offset_ts": last_offset_ts,
        "runtime_meta_keys": sorted(str(key) for key in runtime_meta.keys()),
        "offsets": offsets,
    }
