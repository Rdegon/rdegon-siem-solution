from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal

try:
    from .secret_runtime import resolve_secret_value
except ImportError:  # pragma: no cover - local test fallback
    from secret_runtime import resolve_secret_value  # type: ignore[no-redef]


class ConfigError(RuntimeError):
    """Configuration loading error."""


def _get_env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None:
        raise ConfigError(f"Required environment variable {name} is not set")
    if value == "":
        raise ConfigError(f"Environment variable {name} is empty")
    return value


def _get_int(name: str, default: str) -> int:
    raw = _get_env(name, default)
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be integer, got: {raw!r}") from exc


def _get_optional_env(name: str, default: str = "") -> str:
    return str(os.getenv(name, default) or "").strip()


def _get_secret_env(name: str, default: str | None = None, *, required: bool = True) -> str:
    fallback = default or ""
    value, _, _ = resolve_secret_value(name, explicit_value=_get_optional_env(name))
    safe_value = str(value or "").strip()
    if safe_value:
        return safe_value
    if not required:
        return fallback
    if default is not None and str(default).strip():
        return str(default).strip()
    raise ConfigError(f"Required secret variable {name} is not set")


@dataclass(frozen=True)
class ClickHouseConfig:
    host: str
    port: int
    db: str
    user: str
    password: str


@dataclass(frozen=True)
class GreenboneConfig:
    enabled: bool
    host: str
    port: int
    username: str
    password: str
    insecure_tls: bool
    web_base_url: str
    artifact_dir: str
    default_scan_config: str
    default_scanner: str
    default_port_list: str
    default_alive_test: str
    ssh_credential_id: str
    daily_schedule_name: str
    weekly_schedule_name: str


@dataclass(frozen=True)
class WebConfig:
    env: Literal["dev", "prod", "stage"]
    instance_name: str
    log_level: str
    ch: ClickHouseConfig
    bind_host: str
    bind_port: int
    base_url: str
    jwt_secret: str
    jwt_algorithm: str
    jwt_expires_minutes: int
    admin_default_user: str
    admin_default_password: str
    admin_default_password_hash: str
    web_users_json: str
    auth_rate_limit_window_seconds: int
    auth_rate_limit_max_attempts: int
    auth_rate_limit_lockout_seconds: int
    hot_retention_hours: int
    cold_retention_days: int
    content_store_backend: Literal["auto", "filesystem", "mongo"]
    mongo_uri: str
    mongo_db: str
    greenbone: GreenboneConfig


def _get_bool(name: str, default: str = "0") -> bool:
    return str(os.getenv(name, default) or default).strip().lower() in {"1", "true", "yes", "on"}


def load_config() -> WebConfig:
    env = _get_env("SIEM_ENV", "dev")
    if env not in {"dev", "prod", "stage"}:
        raise ConfigError(f"SIEM_ENV must be one of dev/prod/stage, got: {env!r}")
    content_store_backend = _get_env("SIEM_CONTENT_STORE_BACKEND", "auto").lower()
    if content_store_backend not in {"auto", "filesystem", "mongo"}:
        raise ConfigError(
            f"SIEM_CONTENT_STORE_BACKEND must be one of auto/filesystem/mongo, got: {content_store_backend!r}"
        )

    bind_host = _get_env("SIEM_WEB_BIND_HOST", "127.0.0.1")
    bind_port = _get_int("SIEM_WEB_BIND_PORT", "8000")

    ch_cfg = ClickHouseConfig(
        host=_get_env("SIEM_CH_HOST"),
        # The web UI talks to ClickHouse over HTTP by default.
        port=_get_int("SIEM_CH_PORT", "8123"),
        db=_get_env("SIEM_CH_DB", "siem"),
        user=_get_env("SIEM_CH_USER"),
        password=_get_secret_env("SIEM_CH_PASSWORD"),
    )
    admin_default_user = _get_env("SIEM_ADMIN_DEFAULT_USER", "admin")
    admin_default_password = _get_optional_env("SIEM_ADMIN_DEFAULT_PASSWORD")
    admin_default_password_hash = _get_optional_env("SIEM_ADMIN_DEFAULT_PASSWORD_HASH")
    if not admin_default_password and not admin_default_password_hash:
        raise ConfigError("Either SIEM_ADMIN_DEFAULT_PASSWORD or SIEM_ADMIN_DEFAULT_PASSWORD_HASH must be set")
    greenbone_host = _get_optional_env("SIEM_GREENBONE_HOST")
    greenbone_username = _get_optional_env("SIEM_GREENBONE_USERNAME")
    greenbone_password = _get_secret_env("SIEM_GREENBONE_PASSWORD", required=False)
    greenbone_enabled = _get_bool("SIEM_GREENBONE_ENABLED", "1") and bool(
        greenbone_host and greenbone_username and greenbone_password
    )

    return WebConfig(
        env=env,  # type: ignore[arg-type]
        instance_name=_get_env("SIEM_INSTANCE_NAME", "siem-web"),
        log_level=_get_env("SIEM_LOG_LEVEL", "INFO").upper(),
        ch=ch_cfg,
        bind_host=bind_host,
        bind_port=bind_port,
        base_url=_get_env("SIEM_WEB_BASE_URL", f"http://{bind_host}:{bind_port}"),
        jwt_secret=_get_secret_env("SIEM_JWT_SECRET"),
        jwt_algorithm="HS256",
        jwt_expires_minutes=_get_int("SIEM_JWT_EXPIRES_MINUTES", "480"),
        admin_default_user=admin_default_user,
        admin_default_password=admin_default_password,
        admin_default_password_hash=admin_default_password_hash,
        web_users_json=_get_optional_env("SIEM_WEB_USERS_JSON"),
        auth_rate_limit_window_seconds=max(60, _get_int("SIEM_AUTH_RATE_LIMIT_WINDOW_SECONDS", "300")),
        auth_rate_limit_max_attempts=max(1, _get_int("SIEM_AUTH_RATE_LIMIT_MAX_ATTEMPTS", "5")),
        auth_rate_limit_lockout_seconds=max(30, _get_int("SIEM_AUTH_RATE_LIMIT_LOCKOUT_SECONDS", "900")),
        hot_retention_hours=_get_int("SIEM_HOT_RETENTION_HOURS", "168"),
        cold_retention_days=_get_int("SIEM_COLD_RETENTION_DAYS", "365"),
        content_store_backend=content_store_backend,  # type: ignore[arg-type]
        mongo_uri=_get_secret_env("SIEM_MONGO_URI", default="mongodb://127.0.0.1:27017", required=False),
        mongo_db=_get_optional_env("SIEM_MONGO_DB", "siem_content") or "siem_content",
        greenbone=GreenboneConfig(
            enabled=greenbone_enabled,
            host=greenbone_host,
            port=_get_int("SIEM_GREENBONE_PORT", "9390"),
            username=greenbone_username,
            password=greenbone_password,
            insecure_tls=_get_bool("SIEM_GREENBONE_INSECURE_TLS", "1"),
            web_base_url=_get_optional_env("SIEM_GREENBONE_WEB_BASE_URL"),
            artifact_dir=_get_optional_env("SIEM_GREENBONE_ARTIFACT_DIR", "/opt/siem/siem-solution/services/web/runtime-vuln/greenbone-artifacts")
            or "/opt/siem/siem-solution/services/web/runtime-vuln/greenbone-artifacts",
            default_scan_config=_get_optional_env("SIEM_GREENBONE_DEFAULT_SCAN_CONFIG", "Full and fast") or "Full and fast",
            default_scanner=_get_optional_env("SIEM_GREENBONE_DEFAULT_SCANNER"),
            default_port_list=_get_optional_env("SIEM_GREENBONE_DEFAULT_PORT_LIST", "All TCP and Nmap top 100 UDP")
            or "All TCP and Nmap top 100 UDP",
            default_alive_test=_get_optional_env("SIEM_GREENBONE_DEFAULT_ALIVE_TEST", "Consider Alive") or "Consider Alive",
            ssh_credential_id=_get_optional_env("SIEM_GREENBONE_SSH_CREDENTIAL_ID"),
            daily_schedule_name=_get_optional_env("SIEM_GREENBONE_DAILY_SCHEDULE_NAME", "SIEM Daily 02:00 MSK")
            or "SIEM Daily 02:00 MSK",
            weekly_schedule_name=_get_optional_env("SIEM_GREENBONE_WEEKLY_SCHEDULE_NAME", "SIEM Weekly Sunday 01:00 MSK")
            or "SIEM Weekly Sunday 01:00 MSK",
        ),
    )


CONFIG = load_config()
