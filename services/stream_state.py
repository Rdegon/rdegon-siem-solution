from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any

__all__ = [
    "SQLiteStreamState",
    "StreamStateSettings",
    "stream_state_runtime_status",
    "stream_state_settings_from_env",
]


@dataclass(frozen=True)
class StreamStateSettings:
    backend: str
    sqlite_path: str


def stream_state_settings_from_env(env: dict[str, str] | None = None) -> StreamStateSettings:
    env_map = env or {}
    backend = str(env_map.get("SIEM_STREAM_STATE_BACKEND") or "").strip().lower()
    if not backend:
        import os

        backend = str(os.getenv("SIEM_STREAM_STATE_BACKEND", "sqlite") or "sqlite").strip().lower()
    if backend not in {"redis", "sqlite"}:
        backend = "sqlite"
    sqlite_path = str(env_map.get("SIEM_STREAM_STATE_SQLITE_PATH") or "").strip()
    if not sqlite_path:
        import os

        sqlite_path = str(
            os.getenv("SIEM_STREAM_STATE_SQLITE_PATH", "/var/lib/siem-stream-corr/runtime-state.db")
            or "/var/lib/siem-stream-corr/runtime-state.db"
        ).strip()
    return StreamStateSettings(backend=backend, sqlite_path=sqlite_path)


class SQLiteStreamState:
    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._lock = RLock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS threshold_events (
                    rule_id INTEGER NOT NULL,
                    entity_key TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    event_epoch REAL NOT NULL,
                    PRIMARY KEY (rule_id, entity_key, mode, message_id)
                );
                CREATE INDEX IF NOT EXISTS idx_threshold_events_lookup
                    ON threshold_events(rule_id, entity_key, mode, event_epoch);

                CREATE TABLE IF NOT EXISTS last_alert (
                    rule_id INTEGER NOT NULL,
                    entity_key TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    last_alert_epoch REAL NOT NULL,
                    PRIMARY KEY (rule_id, entity_key, mode)
                );

                CREATE TABLE IF NOT EXISTS runtime_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS consumer_offsets (
                    transport_backend TEXT NOT NULL,
                    group_name TEXT NOT NULL,
                    topic_name TEXT NOT NULL,
                    partition_id INTEGER NOT NULL,
                    offset_value INTEGER NOT NULL,
                    updated_ts TEXT NOT NULL,
                    PRIMARY KEY (transport_backend, group_name, topic_name, partition_id)
                );
                """
            )
            self._conn.commit()

    def append_event(
        self,
        rule_id: int,
        entity_key: str,
        mode: str,
        message_id: str,
        event_epoch: float,
        *,
        commit: bool = True,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO threshold_events(rule_id, entity_key, mode, message_id, event_epoch)
                VALUES (?, ?, ?, ?, ?)
                """,
                (int(rule_id), str(entity_key), str(mode), str(message_id), float(event_epoch)),
            )
            if commit:
                self._conn.commit()

    def trim_events(
        self,
        rule_id: int,
        entity_key: str,
        mode: str,
        retention_floor: float,
        *,
        commit: bool = True,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                DELETE FROM threshold_events
                WHERE rule_id = ? AND entity_key = ? AND mode = ? AND event_epoch <= ?
                """,
                (int(rule_id), str(entity_key), str(mode), float(retention_floor)),
            )
            if commit:
                self._conn.commit()

    def count_events(self, rule_id: int, entity_key: str, mode: str, window_start: float, event_epoch: float) -> int:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT count(*)
                FROM threshold_events
                WHERE rule_id = ? AND entity_key = ? AND mode = ? AND event_epoch >= ? AND event_epoch <= ?
                """,
                (int(rule_id), str(entity_key), str(mode), float(window_start), float(event_epoch)),
            ).fetchone()
        return int((row or [0])[0] or 0)

    def get_last_alert(self, rule_id: int, entity_key: str, mode: str) -> float:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT last_alert_epoch
                FROM last_alert
                WHERE rule_id = ? AND entity_key = ? AND mode = ?
                """,
                (int(rule_id), str(entity_key), str(mode)),
            ).fetchone()
        return float((row or [0.0])[0] or 0.0)

    def set_last_alert(
        self,
        rule_id: int,
        entity_key: str,
        mode: str,
        event_epoch: float,
        *,
        commit: bool = True,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO last_alert(rule_id, entity_key, mode, last_alert_epoch)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(rule_id, entity_key, mode)
                DO UPDATE SET last_alert_epoch = excluded.last_alert_epoch
                """,
                (int(rule_id), str(entity_key), str(mode), float(event_epoch)),
            )
            if commit:
                self._conn.commit()

    def flush(self) -> None:
        with self._lock:
            self._conn.commit()

    def write_runtime_meta(self, payload: dict[str, Any]) -> None:
        with self._lock:
            for key, value in payload.items():
                self._conn.execute(
                    """
                    INSERT INTO runtime_meta(key, value)
                    VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                    """,
                    (str(key), json.dumps(value, ensure_ascii=False)),
                )
            self._conn.commit()

    def read_runtime_meta(self) -> dict[str, Any]:
        with self._lock:
            rows = self._conn.execute("SELECT key, value FROM runtime_meta").fetchall()
        payload: dict[str, Any] = {}
        for key, value in rows:
            try:
                payload[str(key)] = json.loads(str(value))
            except json.JSONDecodeError:
                payload[str(key)] = value
        return payload

    def save_offset(self, *, transport_backend: str, group_name: str, topic_name: str, partition_id: int, offset_value: int, updated_ts: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO consumer_offsets(transport_backend, group_name, topic_name, partition_id, offset_value, updated_ts)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(transport_backend, group_name, topic_name, partition_id)
                DO UPDATE SET offset_value = excluded.offset_value, updated_ts = excluded.updated_ts
                """,
                (str(transport_backend), str(group_name), str(topic_name), int(partition_id), int(offset_value), str(updated_ts)),
            )
            self._conn.commit()

    def list_offsets(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
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

    def status(self) -> dict[str, Any]:
        offsets = self.list_offsets()
        runtime_meta = self.read_runtime_meta()
        last_offset_ts = ""
        topic_names: set[str] = set()
        group_names: set[str] = set()
        for row in offsets:
            topic_names.add(str(row.get("topic_name") or ""))
            group_names.add(str(row.get("group_name") or ""))
            updated_ts = str(row.get("updated_ts") or "")
            if updated_ts and updated_ts > last_offset_ts:
                last_offset_ts = updated_ts
        return {
            "backend": "sqlite",
            "sqlite_path": str(self._path),
            "sqlite_exists": self._path.exists(),
            "stored_offsets_total": len(offsets),
            "topics": sorted(item for item in topic_names if item),
            "groups": sorted(item for item in group_names if item),
            "last_offset_ts": last_offset_ts,
            "runtime_meta_keys": sorted(str(key) for key in runtime_meta.keys()),
            "offsets": offsets,
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def stream_state_runtime_status(env: dict[str, str] | None = None) -> dict[str, Any]:
    settings = stream_state_settings_from_env(env)
    if settings.backend != "sqlite":
        return {
            "backend": settings.backend,
            "sqlite_path": settings.sqlite_path,
            "healthy": True,
            "stored_offsets_total": 0,
            "topics": [],
            "groups": [],
            "last_offset_ts": "",
            "runtime_meta_keys": [],
            "offsets": [],
        }
    path = Path(settings.sqlite_path)
    if not path.exists():
        return {
            "backend": "sqlite",
            "sqlite_path": settings.sqlite_path,
            "healthy": False,
            "sqlite_exists": False,
            "stored_offsets_total": 0,
            "topics": [],
            "groups": [],
            "last_offset_ts": "",
            "runtime_meta_keys": [],
            "offsets": [],
        }
    state = SQLiteStreamState(settings.sqlite_path)
    try:
        payload = state.status()
    finally:
        state.close()
    payload["healthy"] = True
    return payload
