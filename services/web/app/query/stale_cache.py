from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Callable


def load_snapshot(
    path: Path,
    key: str,
    *,
    max_stale_seconds: int,
) -> tuple[float, list[dict[str, object]]] | None:
    try:
        if not path.exists():
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        record = payload.get(key) if isinstance(payload, dict) else None
        if not isinstance(record, dict):
            return None
        updated_ts = float(record.get("updated_ts") or 0)
        if updated_ts <= 0 or time.time() - updated_ts > max_stale_seconds:
            return None
        items = record.get("items")
        if not isinstance(items, list):
            return None
        return updated_ts, [dict(item) for item in items if isinstance(item, dict)]
    except Exception:  # noqa: BLE001
        return None


def save_snapshot(
    path: Path,
    key: str,
    rows: list[dict[str, object]],
) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, object] = {}
        if path.exists():
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                payload = loaded
        payload[key] = {
            "updated_ts": time.time(),
            "items": [dict(row) for row in rows],
        }
        temporary = path.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        temporary.replace(path)
    except Exception:  # noqa: BLE001
        return


def refresh_in_background(
    path: Path,
    key: str,
    loader: Callable[[], list[dict[str, object]]],
    *,
    lock_stale_seconds: int = 900,
) -> bool:
    lock_path = path.with_suffix(f".{key}.lock")
    try:
        if lock_path.exists() and time.time() - lock_path.stat().st_mtime > lock_stale_seconds:
            lock_path.unlink(missing_ok=True)
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
    except FileExistsError:
        return False
    except Exception:  # noqa: BLE001
        return False

    def refresh() -> None:
        try:
            rows = loader()
            if rows:
                save_snapshot(path, key, rows)
        finally:
            lock_path.unlink(missing_ok=True)

    threading.Thread(
        target=refresh,
        name=f"siem-cache-refresh-{key}",
        daemon=True,
    ).start()
    return True
