from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable

from starlette.concurrency import run_in_threadpool


class StaleRuntimeCache:
    def __init__(
        self,
        path: Path,
        *,
        ttl_seconds: int,
        max_stale_seconds: int = 86400,
    ) -> None:
        self.path = path
        self.ttl_seconds = max(1, int(ttl_seconds))
        self.max_stale_seconds = max(
            self.ttl_seconds,
            int(max_stale_seconds),
        )
        self._lock = threading.Lock()
        self._refreshing: set[str] = set()

    def get(self, key: str) -> tuple[Any, bool] | None:
        try:
            if not self.path.exists():
                return None
            records = json.loads(self.path.read_text(encoding="utf-8"))
            record = records.get(key) if isinstance(records, dict) else None
            if not isinstance(record, dict):
                return None
            updated_ts = float(record.get("updated_ts") or 0)
            age_seconds = time.time() - updated_ts
            if updated_ts <= 0 or age_seconds > self.max_stale_seconds:
                return None
            return record.get("payload"), age_seconds > self.ttl_seconds
        except Exception:  # noqa: BLE001
            return None

    def put(self, key: str, payload: Any) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            lock_path = self.path.with_suffix(".write.lock")
            if not self._acquire_file_lock(lock_path):
                return
            try:
                records: dict[str, Any] = {}
                if self.path.exists():
                    loaded = json.loads(self.path.read_text(encoding="utf-8"))
                    if isinstance(loaded, dict):
                        records = loaded
                records[key] = {
                    "updated_ts": time.time(),
                    "payload": payload,
                }
                temporary = self.path.with_suffix(
                    f".{os.getpid()}.{threading.get_ident()}.tmp"
                )
                temporary.write_text(
                    json.dumps(records, ensure_ascii=False),
                    encoding="utf-8",
                )
                temporary.replace(self.path)
            finally:
                lock_path.unlink(missing_ok=True)
        except Exception:  # noqa: BLE001
            return

    def _acquire_file_lock(self, lock_path: Path) -> bool:
        for _ in range(40):
            try:
                if (
                    lock_path.exists()
                    and time.time() - lock_path.stat().st_mtime > 60
                ):
                    lock_path.unlink(missing_ok=True)
                descriptor = os.open(
                    lock_path,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                    0o600,
                )
                os.close(descriptor)
                return True
            except FileExistsError:
                time.sleep(0.05)
            except Exception:  # noqa: BLE001
                return False
        return False

    def _refresh_lock_path(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
        return self.path.with_suffix(f".{digest}.refresh.lock")

    def schedule(self, key: str, loader: Callable[[], Any]) -> bool:
        with self._lock:
            if key in self._refreshing:
                return False
            self._refreshing.add(key)

        lock_path = self._refresh_lock_path(key)
        try:
            if lock_path.exists() and time.time() - lock_path.stat().st_mtime > 900:
                lock_path.unlink(missing_ok=True)
            descriptor = os.open(
                lock_path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
            os.close(descriptor)
        except FileExistsError:
            with self._lock:
                self._refreshing.discard(key)
            return False
        except Exception:  # noqa: BLE001
            with self._lock:
                self._refreshing.discard(key)
            return False

        def refresh() -> None:
            try:
                self.put(key, loader())
            finally:
                lock_path.unlink(missing_ok=True)
                with self._lock:
                    self._refreshing.discard(key)

        threading.Thread(
            target=refresh,
            name=f"siem-runtime-cache-{key[:32]}",
            daemon=True,
        ).start()
        return True

    async def get_or_refresh(
        self,
        key: str,
        loader: Callable[[], Any],
    ) -> Any:
        cached = self.get(key)
        if cached is not None:
            payload, stale = cached
            if stale:
                self.schedule(key, loader)
            return payload
        payload = await run_in_threadpool(loader)
        self.put(key, payload)
        return payload
