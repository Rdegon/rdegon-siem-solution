from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from pathlib import Path
from typing import Any


class SQLiteIngestStateStore:
    backend = "sqlite"

    def __init__(self, sqlite_path: str) -> None:
        self._path = Path(str(sqlite_path or "").strip() or "/home/rdegon/.siem-state/ingest-runtime.db")
        self._lock = asyncio.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def _close_connection(self, conn: sqlite3.Connection | None) -> None:
        if conn is None:
            return
        try:
            conn.close()
        except sqlite3.Error:
            return

    def _ensure_schema(self) -> None:
        conn: sqlite3.Connection | None = None
        try:
            conn = self._connect()
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS hashes (
                    key TEXT NOT NULL,
                    field TEXT NOT NULL,
                    value TEXT NOT NULL,
                    PRIMARY KEY (key, field)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS streams (
                    stream_key TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    id TEXT NOT NULL,
                    fields_json TEXT NOT NULL,
                    PRIMARY KEY (stream_key, seq),
                    UNIQUE (stream_key, id)
                )
                """
            )
            conn.commit()
        finally:
            self._close_connection(conn)

    async def ping(self):
        return True

    async def close(self):
        return None

    async def hget(self, key: str, field: str):
        async with self._lock:
            conn: sqlite3.Connection | None = None
            try:
                conn = self._connect()
                row = conn.execute(
                    "SELECT value FROM hashes WHERE key = ? AND field = ?",
                    (str(key), str(field)),
                ).fetchone()
                return None if row is None else str(row["value"])
            finally:
                self._close_connection(conn)

    async def hgetall(self, key: str):
        async with self._lock:
            conn: sqlite3.Connection | None = None
            try:
                conn = self._connect()
                rows = conn.execute(
                    "SELECT field, value FROM hashes WHERE key = ? ORDER BY field ASC",
                    (str(key),),
                ).fetchall()
                return {str(row["field"]): str(row["value"]) for row in rows}
            finally:
                self._close_connection(conn)

    async def hvals(self, key: str):
        async with self._lock:
            conn: sqlite3.Connection | None = None
            try:
                conn = self._connect()
                rows = conn.execute(
                    "SELECT value FROM hashes WHERE key = ? ORDER BY field ASC",
                    (str(key),),
                ).fetchall()
                return [str(row["value"]) for row in rows]
            finally:
                self._close_connection(conn)

    async def hset(self, key: str, *args, mapping=None):
        updates: dict[str, str] = {}
        if mapping is not None:
            updates.update({str(item_key): "" if item_value is None else str(item_value) for item_key, item_value in mapping.items()})
        elif len(args) == 2:
            updates[str(args[0])] = "" if args[1] is None else str(args[1])
        else:
            raise AssertionError("Unsupported hset call")

        async with self._lock:
            conn: sqlite3.Connection | None = None
            try:
                conn = self._connect()
                for field, value in updates.items():
                    conn.execute(
                        """
                        INSERT INTO hashes (key, field, value)
                        VALUES (?, ?, ?)
                        ON CONFLICT(key, field) DO UPDATE SET value = excluded.value
                        """,
                        (str(key), field, value),
                    )
                conn.commit()
            finally:
                self._close_connection(conn)
        return len(updates)

    async def hincrby(self, key: str, field: str, amount: int = 1):
        current = int((await self.hget(key, field)) or 0)
        current += int(amount)
        await self.hset(key, field, str(current))
        return current

    async def xadd(self, key: str, fields: dict[str, str], maxlen=None, approximate=True):  # noqa: ARG002
        stream_key = str(key)
        payload = json.dumps({str(item_key): str(item_value) for item_key, item_value in fields.items()}, ensure_ascii=False)
        async with self._lock:
            conn: sqlite3.Connection | None = None
            try:
                conn = self._connect()
                next_seq_row = conn.execute(
                    "SELECT COALESCE(MAX(seq), 0) + 1 AS next_seq FROM streams WHERE stream_key = ?",
                    (stream_key,),
                ).fetchone()
                next_seq = int(next_seq_row["next_seq"] if next_seq_row is not None else 1)
                stream_id = f"{int(time.time() * 1000)}-{next_seq}"
                conn.execute(
                    "INSERT INTO streams (stream_key, seq, id, fields_json) VALUES (?, ?, ?, ?)",
                    (stream_key, next_seq, stream_id, payload),
                )
                if maxlen:
                    overflow = conn.execute(
                        "SELECT COUNT(*) AS total FROM streams WHERE stream_key = ?",
                        (stream_key,),
                    ).fetchone()
                    total = int(overflow["total"] if overflow is not None else 0)
                    excess = max(0, total - int(maxlen))
                    if excess:
                        conn.execute(
                            """
                            DELETE FROM streams
                            WHERE stream_key = ?
                              AND seq IN (
                                  SELECT seq FROM streams
                                  WHERE stream_key = ?
                                  ORDER BY seq ASC
                                  LIMIT ?
                              )
                            """,
                            (stream_key, stream_key, excess),
                        )
                conn.commit()
                return stream_id
            finally:
                self._close_connection(conn)

    async def xlen(self, key: str):
        async with self._lock:
            conn: sqlite3.Connection | None = None
            try:
                conn = self._connect()
                row = conn.execute(
                    "SELECT COUNT(*) AS total FROM streams WHERE stream_key = ?",
                    (str(key),),
                ).fetchone()
                return int(row["total"] if row is not None else 0)
            finally:
                self._close_connection(conn)

    async def xinfo_groups(self, key: str):  # noqa: ARG002
        return []

    async def xrevrange(self, key: str, max: str = "+", min: str = "-", count: int | None = None):  # noqa: A002
        clauses = ["stream_key = ?"]
        params: list[Any] = [str(key)]
        if max != "+":
            clauses.append("id <= ?")
            params.append(str(max))
        if min != "-":
            clauses.append("id >= ?")
            params.append(str(min))
        query = (
            "SELECT id, fields_json FROM streams "
            f"WHERE {' AND '.join(clauses)} ORDER BY seq DESC"
        )
        if count is not None:
            query += " LIMIT ?"
            params.append(int(count))
        async with self._lock:
            conn: sqlite3.Connection | None = None
            try:
                conn = self._connect()
                rows = conn.execute(query, tuple(params)).fetchall()
                return [
                    (str(row["id"]), {str(k): str(v) for k, v in json.loads(str(row["fields_json"])).items()})
                    for row in rows
                ]
            finally:
                self._close_connection(conn)

    async def xrange(self, key: str, min: str = "-", max: str = "+", count: int | None = None):  # noqa: A002
        clauses = ["stream_key = ?"]
        params: list[Any] = [str(key)]
        if min != "-":
            clauses.append("id >= ?")
            params.append(str(min))
        if max != "+":
            clauses.append("id <= ?")
            params.append(str(max))
        query = (
            "SELECT id, fields_json FROM streams "
            f"WHERE {' AND '.join(clauses)} ORDER BY seq ASC"
        )
        if count is not None:
            query += " LIMIT ?"
            params.append(int(count))
        async with self._lock:
            conn: sqlite3.Connection | None = None
            try:
                conn = self._connect()
                rows = conn.execute(query, tuple(params)).fetchall()
                return [
                    (str(row["id"]), {str(k): str(v) for k, v in json.loads(str(row["fields_json"])).items()})
                    for row in rows
                ]
            finally:
                self._close_connection(conn)
