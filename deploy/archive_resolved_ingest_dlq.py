from __future__ import annotations

import argparse
import json
import os
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


DLQ_STREAM_KEY = "siem:raw:dlq"
DLQ_REPLAY_HASH_KEY = "siem:ingest:dlq:replays"
INGEST_METRICS_HASH_KEY = "siem:ingest:metrics"
DEFAULT_SQLITE_PATH = "/home/rdegon/.siem-state/ingest-runtime.db"


@dataclass(frozen=True)
class DlqSnapshot:
    total: int
    resolved: int
    stream_rows: int
    replay_rows: int
    max_seq: int
    last_dlq_ts: str
    newest_entry_ts: str

    @property
    def outstanding(self) -> int:
        return max(0, self.total - self.resolved)


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _parse_utc(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _metric(conn: sqlite3.Connection, field: str) -> str:
    row = conn.execute(
        "SELECT value FROM hashes WHERE key = ? AND field = ?",
        (INGEST_METRICS_HASH_KEY, field),
    ).fetchone()
    return "" if row is None else str(row[0])


def _newest_entry_ts(conn: sqlite3.Connection) -> str:
    row = conn.execute(
        """
        SELECT fields_json
        FROM streams
        WHERE stream_key = ?
        ORDER BY seq DESC
        LIMIT 1
        """,
        (DLQ_STREAM_KEY,),
    ).fetchone()
    if row is None:
        return ""
    try:
        payload = json.loads(str(row[0]))
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    return str(payload.get("ingest_ts") or "")


def read_snapshot(conn: sqlite3.Connection) -> DlqSnapshot:
    stream = conn.execute(
        """
        SELECT COUNT(*) AS total, COALESCE(MAX(seq), 0) AS max_seq
        FROM streams
        WHERE stream_key = ?
        """,
        (DLQ_STREAM_KEY,),
    ).fetchone()
    replay = conn.execute(
        "SELECT COUNT(*) FROM hashes WHERE key = ?",
        (DLQ_REPLAY_HASH_KEY,),
    ).fetchone()
    return DlqSnapshot(
        total=_safe_int(_metric(conn, "dlq_total")),
        resolved=_safe_int(_metric(conn, "resolved_dlq_total")),
        stream_rows=_safe_int(stream[0] if stream else 0),
        replay_rows=_safe_int(replay[0] if replay else 0),
        max_seq=_safe_int(stream[1] if stream else 0),
        last_dlq_ts=_metric(conn, "last_dlq_ts"),
        newest_entry_ts=_newest_entry_ts(conn),
    )


def validate_snapshot(
    snapshot: DlqSnapshot,
    *,
    now: datetime,
    minimum_age: timedelta,
) -> None:
    if snapshot.outstanding:
        raise RuntimeError(
            f"refusing to archive {snapshot.outstanding} outstanding DLQ event(s)"
        )
    if not snapshot.stream_rows and not snapshot.replay_rows:
        return

    latest = _parse_utc(snapshot.last_dlq_ts) or _parse_utc(snapshot.newest_entry_ts)
    if latest is None:
        raise RuntimeError("refusing to archive DLQ rows without a valid timestamp")
    age = now.astimezone(timezone.utc) - latest
    if age < minimum_age:
        raise RuntimeError(
            "refusing to archive recent DLQ state: "
            f"age={age.total_seconds():.0f}s minimum={minimum_age.total_seconds():.0f}s"
        )


def _ensure_schema(conn: sqlite3.Connection) -> None:
    required = {
        str(row[0])
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    missing = {"hashes", "streams"} - required
    if missing:
        raise RuntimeError(f"ingest runtime schema is incomplete: {sorted(missing)}")


def _backup_database(source: sqlite3.Connection, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    backup = sqlite3.connect(str(destination), timeout=30.0)
    try:
        # Copy in bounded page batches so live health-state writers can acquire
        # the SQLite lock between backup steps.
        source.backup(backup, pages=1_024, sleep=0.01)
        backup.execute("PRAGMA quick_check")
    finally:
        backup.close()
    os.chmod(destination, 0o600)


def _prune_archives(directory: Path, *, retention: timedelta, now: datetime) -> int:
    removed = 0
    cutoff = now.timestamp() - retention.total_seconds()
    for candidate in directory.glob("ingest-runtime-dlq-*.db"):
        if candidate.stat().st_mtime < cutoff:
            candidate.unlink()
            removed += 1
    return removed


def archive_resolved_dlq(
    sqlite_path: Path,
    *,
    archive_directory: Path,
    execute: bool,
    minimum_age: timedelta,
    retention: timedelta,
    now: datetime | None = None,
) -> dict[str, Any]:
    observed_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    conn = sqlite3.connect(str(sqlite_path), timeout=30.0)
    conn.execute("PRAGMA busy_timeout=30000")
    try:
        _ensure_schema(conn)
        before = read_snapshot(conn)
        validate_snapshot(before, now=observed_at, minimum_age=minimum_age)
        result: dict[str, Any] = {
            "backend": "sqlite",
            "database": str(sqlite_path),
            "execute": execute,
            "before": asdict(before) | {"outstanding": before.outstanding},
        }
        if not execute or (not before.stream_rows and not before.replay_rows):
            result["changed"] = False
            return result

        stamp = observed_at.strftime("%Y%m%dT%H%M%SZ")
        archive_path = archive_directory / f"ingest-runtime-dlq-{stamp}.db"
        if archive_path.exists():
            raise RuntimeError(f"archive already exists: {archive_path}")
        _backup_database(conn, archive_path)

        conn.execute("BEGIN IMMEDIATE")
        locked = read_snapshot(conn)
        if locked != before:
            conn.rollback()
            archive_path.unlink(missing_ok=True)
            raise RuntimeError("DLQ state changed during backup; retry the operation")
        archived_stream_rows = conn.execute(
            "DELETE FROM streams WHERE stream_key = ?",
            (DLQ_STREAM_KEY,),
        ).rowcount
        archived_replay_rows = conn.execute(
            "DELETE FROM hashes WHERE key = ?",
            (DLQ_REPLAY_HASH_KEY,),
        ).rowcount
        conn.executemany(
            """
            INSERT INTO hashes (key, field, value)
            VALUES (?, ?, ?)
            ON CONFLICT(key, field) DO UPDATE SET value = excluded.value
            """,
            (
                (INGEST_METRICS_HASH_KEY, "dlq_total", "0"),
                (INGEST_METRICS_HASH_KEY, "resolved_dlq_total", "0"),
            ),
        )
        conn.execute(
            """
            DELETE FROM hashes
            WHERE key = ?
              AND field IN ('last_dlq_ts', 'last_dlq_id')
            """,
            (INGEST_METRICS_HASH_KEY,),
        )
        conn.commit()

        after = read_snapshot(conn)
        removed_archives = _prune_archives(
            archive_directory,
            retention=retention,
            now=observed_at,
        )
        result.update(
            {
                "changed": True,
                "archive": str(archive_path),
                "archive_retention_days": retention.days,
                "old_archives_removed": removed_archives,
                "archived_stream_rows": archived_stream_rows,
                "archived_replay_rows": archived_replay_rows,
                "after": asdict(after) | {"outstanding": after.outstanding},
            }
        )
        return result
    finally:
        conn.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Archive fully resolved ingest DLQ metadata from the SQLite runtime state."
    )
    parser.add_argument(
        "--sqlite-path",
        default=os.getenv("SIEM_INGEST_RUNTIME_STATE_SQLITE_PATH", DEFAULT_SQLITE_PATH),
    )
    parser.add_argument(
        "--archive-directory",
        default="/var/backups/siem/ingest-dlq",
    )
    parser.add_argument("--minimum-age-hours", type=int, default=24)
    parser.add_argument("--retention-days", type=int, default=7)
    parser.add_argument("--execute", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = archive_resolved_dlq(
        Path(args.sqlite_path),
        archive_directory=Path(args.archive_directory),
        execute=bool(args.execute),
        minimum_age=timedelta(hours=max(1, args.minimum_age_hours)),
        retention=timedelta(days=max(1, args.retention_days)),
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
