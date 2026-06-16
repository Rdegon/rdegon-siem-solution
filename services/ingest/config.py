"""
/home/siem/siem-solution/services/ingest/config.py

Назначение:
  - Загрузка конфигурации сервиса ingest из переменных окружения.
  - DEV: опционально подхватывать ./../.env через python-dotenv.
Используемые env-переменные:
  - SIEM_ENV
  - SIEM_LOG_LEVEL
  - SIEM_INSTANCE_NAME

  - SIEM_REDIS_HOST
  - SIEM_REDIS_PORT
  - SIEM_REDIS_DB
  - SIEM_REDIS_PASSWORD

  - SIEM_INGEST_SYSLOG_HOST
  - SIEM_INGEST_SYSLOG_PORT
  - SIEM_INGEST_HTTP_HOST
  - SIEM_INGEST_HTTP_PORT
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Literal


def _maybe_load_dotenv() -> None:
    """Загружает .env в DEV/LOCAL среде.

    В PROD переменные приходят из systemd EnvironmentFile=/etc/siem/siem.env.
    """
    env = os.getenv("SIEM_ENV", "dev")
    if env.lower() == "prod":
        return

    try:
        from dotenv import load_dotenv
    except ImportError:
        return

    # repo_root = /home/siem/siem-solution
    repo_root = Path(__file__).resolve().parents[2]
    env_file = repo_root / ".env"
    if env_file.exists():
        load_dotenv(env_file)


@dataclass
class IngestSettings:
    env: Literal["dev", "prod", "stage"]
    log_level: str
    instance_name: str

    redis_host: str
    redis_port: int
    redis_db: int
    redis_password: str | None
    runtime_state_backend: str
    runtime_state_sqlite_path: str

    ingest_syslog_host: str
    ingest_syslog_port: int
    ingest_syslog_audit_port: int
    ingest_syslog_network_port: int
    ingest_syslog_vpn_port: int
    ingest_syslog_app_port: int

    ingest_http_host: str
    ingest_http_port: int
    raw_stream_max_len: int
    raw_stream_soft_limit: int
    raw_stream_hard_limit: int

    def syslog_profiles(self) -> Dict[str, int]:
        return {
            "linux-auth": self.ingest_syslog_port,
            "linux-audit": self.ingest_syslog_audit_port,
            "network": self.ingest_syslog_network_port,
            "vpn": self.ingest_syslog_vpn_port,
            "app": self.ingest_syslog_app_port,
        }

    @classmethod
    def load(cls) -> "IngestSettings":
        _maybe_load_dotenv()

        env = os.getenv("SIEM_ENV", "dev").lower()
        if env not in ("dev", "prod", "stage"):
            raise ValueError(f"Invalid SIEM_ENV={env!r}, expected dev/prod/stage")

        log_level = os.getenv("SIEM_LOG_LEVEL", "INFO").upper()
        instance_name = os.getenv("SIEM_INSTANCE_NAME", "default")

        redis_host = os.getenv("SIEM_REDIS_HOST", "127.0.0.1")
        redis_port_raw = os.getenv("SIEM_REDIS_PORT", "6379")
        redis_db_raw = os.getenv("SIEM_REDIS_DB", "0")
        redis_password = os.getenv("SIEM_REDIS_PASSWORD") or None
        transport_backend = str(os.getenv("SIEM_TRANSPORT_BACKEND", "kafka") or "kafka").strip().lower()
        runtime_state_backend = str(
            os.getenv(
                "SIEM_INGEST_RUNTIME_STATE_BACKEND",
                "sqlite" if transport_backend == "kafka" else "redis",
            )
            or ("sqlite" if transport_backend == "kafka" else "redis")
        ).strip().lower()
        if runtime_state_backend not in {"redis", "sqlite"}:
            runtime_state_backend = "sqlite" if transport_backend == "kafka" else "redis"
        runtime_state_sqlite_path = str(
            os.getenv("SIEM_INGEST_RUNTIME_STATE_SQLITE_PATH", "/home/rdegon/.siem-state/ingest-runtime.db")
            or "/home/rdegon/.siem-state/ingest-runtime.db"
        ).strip()

        try:
            redis_port = int(redis_port_raw)
        except ValueError as exc:
            raise ValueError(f"Invalid SIEM_REDIS_PORT={redis_port_raw!r}") from exc

        try:
            redis_db = int(redis_db_raw)
        except ValueError as exc:
            raise ValueError(f"Invalid SIEM_REDIS_DB={redis_db_raw!r}") from exc

        ingest_syslog_host = os.getenv("SIEM_INGEST_SYSLOG_HOST", "0.0.0.0")
        ingest_syslog_port_raw = os.getenv("SIEM_INGEST_SYSLOG_PORT", "1514")
        ingest_syslog_audit_port_raw = os.getenv("SIEM_INGEST_SYSLOG_AUDIT_PORT", "1515")
        ingest_syslog_network_port_raw = os.getenv("SIEM_INGEST_SYSLOG_NETWORK_PORT", "1516")
        ingest_syslog_vpn_port_raw = os.getenv("SIEM_INGEST_SYSLOG_VPN_PORT", "1517")
        ingest_syslog_app_port_raw = os.getenv("SIEM_INGEST_SYSLOG_APP_PORT", "1518")

        ingest_http_host = os.getenv("SIEM_INGEST_HTTP_HOST", "0.0.0.0")
        ingest_http_port_raw = os.getenv("SIEM_INGEST_HTTP_PORT", "8443")
        raw_stream_max_len_raw = os.getenv("SIEM_INGEST_RAW_STREAM_MAX_LEN", "1000000")
        raw_stream_soft_limit_raw = os.getenv("SIEM_INGEST_RAW_STREAM_SOFT_LIMIT", "900000")
        raw_stream_hard_limit_raw = os.getenv("SIEM_INGEST_RAW_STREAM_HARD_LIMIT", "980000")

        try:
            ingest_syslog_port = int(ingest_syslog_port_raw)
        except ValueError as exc:
            raise ValueError(
                f"Invalid SIEM_INGEST_SYSLOG_PORT={ingest_syslog_port_raw!r}"
            ) from exc
        try:
            ingest_syslog_audit_port = int(ingest_syslog_audit_port_raw)
        except ValueError as exc:
            raise ValueError(
                f"Invalid SIEM_INGEST_SYSLOG_AUDIT_PORT={ingest_syslog_audit_port_raw!r}"
            ) from exc
        try:
            ingest_syslog_network_port = int(ingest_syslog_network_port_raw)
        except ValueError as exc:
            raise ValueError(
                f"Invalid SIEM_INGEST_SYSLOG_NETWORK_PORT={ingest_syslog_network_port_raw!r}"
            ) from exc
        try:
            ingest_syslog_vpn_port = int(ingest_syslog_vpn_port_raw)
        except ValueError as exc:
            raise ValueError(
                f"Invalid SIEM_INGEST_SYSLOG_VPN_PORT={ingest_syslog_vpn_port_raw!r}"
            ) from exc
        try:
            ingest_syslog_app_port = int(ingest_syslog_app_port_raw)
        except ValueError as exc:
            raise ValueError(
                f"Invalid SIEM_INGEST_SYSLOG_APP_PORT={ingest_syslog_app_port_raw!r}"
            ) from exc

        try:
            ingest_http_port = int(ingest_http_port_raw)
        except ValueError as exc:
            raise ValueError(
                f"Invalid SIEM_INGEST_HTTP_PORT={ingest_http_port_raw!r}"
            ) from exc
        try:
            raw_stream_max_len = int(raw_stream_max_len_raw)
        except ValueError as exc:
            raise ValueError(
                f"Invalid SIEM_INGEST_RAW_STREAM_MAX_LEN={raw_stream_max_len_raw!r}"
            ) from exc
        try:
            raw_stream_soft_limit = int(raw_stream_soft_limit_raw)
        except ValueError as exc:
            raise ValueError(
                f"Invalid SIEM_INGEST_RAW_STREAM_SOFT_LIMIT={raw_stream_soft_limit_raw!r}"
            ) from exc
        try:
            raw_stream_hard_limit = int(raw_stream_hard_limit_raw)
        except ValueError as exc:
            raise ValueError(
                f"Invalid SIEM_INGEST_RAW_STREAM_HARD_LIMIT={raw_stream_hard_limit_raw!r}"
            ) from exc
        if raw_stream_max_len <= 0:
            raise ValueError("SIEM_INGEST_RAW_STREAM_MAX_LEN must be > 0")
        if raw_stream_soft_limit <= 0:
            raise ValueError("SIEM_INGEST_RAW_STREAM_SOFT_LIMIT must be > 0")
        if raw_stream_hard_limit <= 0:
            raise ValueError("SIEM_INGEST_RAW_STREAM_HARD_LIMIT must be > 0")
        if raw_stream_soft_limit > raw_stream_hard_limit:
            raise ValueError("SIEM_INGEST_RAW_STREAM_SOFT_LIMIT must be <= SIEM_INGEST_RAW_STREAM_HARD_LIMIT")
        if raw_stream_hard_limit > raw_stream_max_len:
            raise ValueError("SIEM_INGEST_RAW_STREAM_HARD_LIMIT must be <= SIEM_INGEST_RAW_STREAM_MAX_LEN")

        return cls(
            env=env,  # type: ignore[arg-type]
            log_level=log_level,
            instance_name=instance_name,
            redis_host=redis_host,
            redis_port=redis_port,
            redis_db=redis_db,
            redis_password=redis_password,
            runtime_state_backend=runtime_state_backend,
            runtime_state_sqlite_path=runtime_state_sqlite_path,
            ingest_syslog_host=ingest_syslog_host,
            ingest_syslog_port=ingest_syslog_port,
            ingest_syslog_audit_port=ingest_syslog_audit_port,
            ingest_syslog_network_port=ingest_syslog_network_port,
            ingest_syslog_vpn_port=ingest_syslog_vpn_port,
            ingest_syslog_app_port=ingest_syslog_app_port,
            ingest_http_host=ingest_http_host,
            ingest_http_port=ingest_http_port,
            raw_stream_max_len=raw_stream_max_len,
            raw_stream_soft_limit=raw_stream_soft_limit,
            raw_stream_hard_limit=raw_stream_hard_limit,
        )
