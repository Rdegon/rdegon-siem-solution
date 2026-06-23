from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import secrets as pysecrets
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from threading import Lock
from typing import Annotated, Literal, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt

from .config import CONFIG

logger = logging.getLogger("siem_web.auth")
ROLE = Literal["admin", "analyst", "viewer", "service"]
ALLOWED_ROLES = {"admin", "analyst", "viewer", "service"}
PERMISSION = Literal[
    "dashboard:view",
    "dashboards:write",
    "events:view",
    "events:query",
    "alerts:view",
    "alerts:history:view",
    "incidents:update",
    "assets:view",
    "rules:test",
    "rules:write",
    "normalizers:write",
    "active_lists:write",
    "cmdb:write",
    "threat_intel:write",
    "resources:view",
    "docs:write",
    "storage:archive",
    "connectors:view",
    "connectors:write",
    "connectors:run",
    "cases:view",
    "cases:write",
    "entities:view",
    "entities:write",
    "response:view",
    "response:run",
    "health:view",
    "ingest:view",
    "ingest:replay",
    "vuln:operate",
    "sources:discover",
    "content:view",
    "search:write",
    "audit:view",
    "auth:view",
    "auth:write",
]
ROLE_PERMISSIONS: dict[ROLE, set[str]] = {
    "viewer": {
        "dashboard:view",
        "events:view",
        "events:query",
        "alerts:view",
        "alerts:history:view",
        "assets:view",
        "resources:view",
        "connectors:view",
        "cases:view",
        "entities:view",
        "response:view",
        "health:view",
        "ingest:view",
        "content:view",
    },
    "analyst": {
        "dashboard:view",
        "events:view",
        "events:query",
        "alerts:view",
        "alerts:history:view",
        "incidents:update",
        "assets:view",
        "rules:test",
        "resources:view",
        "connectors:view",
        "connectors:run",
        "cases:view",
        "cases:write",
        "entities:view",
        "entities:write",
        "response:view",
        "response:run",
        "health:view",
        "ingest:view",
        "ingest:replay",
        "vuln:operate",
        "sources:discover",
        "content:view",
    },
    "admin": {
        "dashboard:view",
        "dashboards:write",
        "events:view",
        "events:query",
        "alerts:view",
        "alerts:history:view",
        "incidents:update",
        "assets:view",
        "rules:test",
        "rules:write",
        "normalizers:write",
        "active_lists:write",
        "cmdb:write",
        "threat_intel:write",
        "resources:view",
        "docs:write",
        "storage:archive",
        "connectors:view",
        "connectors:write",
        "connectors:run",
        "cases:view",
        "cases:write",
        "entities:view",
        "entities:write",
        "response:view",
        "response:run",
        "health:view",
        "ingest:view",
        "ingest:replay",
        "vuln:operate",
        "sources:discover",
        "content:view",
        "search:write",
        "audit:view",
        "auth:view",
        "auth:write",
    },
    "service": set(),
}
ALL_PERMISSIONS = tuple(sorted({permission for permissions in ROLE_PERMISSIONS.values() for permission in permissions}))
PASSWORD_HASH_SCHEME = "pbkdf2_sha256"
PASSWORD_HASH_ITERATIONS = 390_000


@dataclass(frozen=True)
class ConfiguredUserRecord:
    username: str
    role: ROLE
    password_hash: str = ""
    plaintext_password: str = ""
    permissions: tuple[str, ...] = ()
    enabled: bool = True

    @property
    def uses_plaintext(self) -> bool:
        return bool(self.plaintext_password and not self.password_hash)


@dataclass
class _AuthRateLimitState:
    failure_epochs: deque[float] = field(default_factory=deque)
    blocked_until_epoch: float = 0.0
    last_failure_epoch: float = 0.0


def _identify_password_hash(value: str) -> str:
    safe_value = str(value or "").strip()
    if safe_value.startswith(f"{PASSWORD_HASH_SCHEME}$"):
        return PASSWORD_HASH_SCHEME
    if safe_value.startswith("$2"):
        return "bcrypt"
    return ""


def _encode_hash_component(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_hash_component(value: str) -> bytes:
    safe_value = str(value or "").strip()
    padding = "=" * (-len(safe_value) % 4)
    return base64.urlsafe_b64decode(f"{safe_value}{padding}".encode("ascii"))


class User:
    def __init__(
        self,
        username: str,
        role: ROLE,
        *,
        permissions: list[str] | None = None,
        principal_type: str = "user",
        service_account_id: str = "",
        auth_mechanism: str = "cookie",
        issuer: str = "",
        groups: list[str] | None = None,
        break_glass: bool = False,
        session_expires_ts: str = "",
        break_glass_session_id: str = "",
        section_access: list[str] | None = None,
        system_grants: list[dict[str, object]] | None = None,
    ) -> None:
        self.username = username
        self.role: ROLE = role
        permission_source = ROLE_PERMISSIONS.get(role, set()) if permissions is None else permissions
        self.permissions = sorted({str(item).strip() for item in permission_source if str(item).strip()})
        self.principal_type = str(principal_type or "user")
        self.service_account_id = str(service_account_id or "")
        self.auth_mechanism = str(auth_mechanism or "cookie")
        self.issuer = str(issuer or "")
        self.groups = [str(item).strip() for item in (groups or []) if str(item).strip()]
        self.break_glass = bool(break_glass)
        self.session_expires_ts = str(session_expires_ts or "")
        self.break_glass_session_id = str(break_glass_session_id or "")
        self.section_access = sorted({str(item).strip() for item in (section_access or []) if str(item).strip()})
        self.system_grants = [dict(item) for item in (system_grants or []) if isinstance(item, dict)]


@lru_cache(maxsize=1)
def _configured_users() -> dict[str, ConfiguredUserRecord]:
    users: dict[str, ConfiguredUserRecord] = {}
    raw = CONFIG.web_users_json
    if raw:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError("SIEM_WEB_USERS_JSON must be valid JSON") from exc
        if not isinstance(payload, list):
            raise RuntimeError("SIEM_WEB_USERS_JSON must be a JSON array")
        for item in payload:
            if not isinstance(item, dict):
                continue
            username = str(item.get("username", "") or "").strip()
            password_hash = str(item.get("password_hash", "") or item.get("passwordHash", "") or "").strip()
            password = str(item.get("password", "") or "")
            role = str(item.get("role", "viewer") or "viewer").strip().lower()
            if not username or role not in ALLOWED_ROLES:
                continue
            if password_hash and not _identify_password_hash(password_hash):
                raise RuntimeError(f"Invalid password_hash for configured user {username!r}")
            if not password_hash and not password:
                continue
            users[username] = ConfiguredUserRecord(
                username=username,
                role=role,  # type: ignore[arg-type]
                password_hash=password_hash,
                plaintext_password=password,
                permissions=tuple(sorted({str(item).strip() for item in (item.get("permissions") or []) if str(item).strip()})),
                enabled=bool(item.get("enabled", True)),
            )
    try:
        from .enterprise_control_plane import load_local_user_auth_records
    except Exception:
        try:
            from enterprise_control_plane import load_local_user_auth_records  # type: ignore[no-redef]
        except Exception:
            load_local_user_auth_records = None  # type: ignore[assignment]
    if callable(load_local_user_auth_records):
        try:
            for item in list(load_local_user_auth_records() or []):
                username = str(item.get("username") or "").strip()
                role = str(item.get("role") or "viewer").strip().lower()
                password_hash = str(item.get("password_hash") or "").strip()
                if not username or role not in ALLOWED_ROLES or not password_hash:
                    continue
                users[username] = ConfiguredUserRecord(
                    username=username,
                    role=role,  # type: ignore[arg-type]
                    password_hash=password_hash,
                    plaintext_password="",
                    permissions=tuple(sorted({str(entry).strip() for entry in (item.get("permissions") or []) if str(entry).strip()})),
                    enabled=bool(item.get("enabled", True)),
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to load control-plane local users: %s", exc)
    if not users:
        users[CONFIG.admin_default_user] = ConfiguredUserRecord(
            username=CONFIG.admin_default_user,
            role="admin",
            password_hash=CONFIG.admin_default_password_hash,
            plaintext_password=CONFIG.admin_default_password,
            permissions=(),
            enabled=True,
        )
    return users


def invalidate_local_auth_cache() -> None:
    _configured_users.cache_clear()


def hash_password(password: str) -> str:
    safe_password = str(password or "")
    if not safe_password:
        raise ValueError("password must not be empty")
    salt = pysecrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", safe_password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS)
    return f"{PASSWORD_HASH_SCHEME}${PASSWORD_HASH_ITERATIONS}${_encode_hash_component(salt)}${_encode_hash_component(digest)}"


def _verify_pbkdf2_password(password: str, password_hash: str) -> bool:
    try:
        scheme, iterations_raw, salt_b64, digest_b64 = str(password_hash or "").split("$", 3)
        if scheme != PASSWORD_HASH_SCHEME:
            return False
        iterations = int(iterations_raw)
        salt = _decode_hash_component(salt_b64)
        expected_digest = _decode_hash_component(digest_b64)
    except (TypeError, ValueError, binascii.Error):
        return False
    actual_digest = hashlib.pbkdf2_hmac("sha256", str(password or "").encode("utf-8"), salt, iterations)
    return pysecrets.compare_digest(actual_digest, expected_digest)


def _verify_bcrypt_password(password: str, password_hash: str) -> bool:
    try:
        import bcrypt  # type: ignore[import-not-found]
    except Exception:  # noqa: BLE001
        return False
    try:
        return bool(bcrypt.checkpw(str(password or "").encode("utf-8"), str(password_hash or "").encode("utf-8")))
    except Exception:  # noqa: BLE001
        return False


def _verify_password(password: str, record: ConfiguredUserRecord) -> bool:
    if record.password_hash:
        hash_type = _identify_password_hash(record.password_hash)
        if hash_type == PASSWORD_HASH_SCHEME:
            return _verify_pbkdf2_password(password, record.password_hash)
        if hash_type == "bcrypt":
            return _verify_bcrypt_password(password, record.password_hash)
        logger.warning("Unsupported password hash type for %s", record.username)
        return False
    if record.plaintext_password:
        return pysecrets.compare_digest(password, record.plaintext_password)
    return False


def authenticate_user(username: str, password: str) -> Optional[User]:
    record = _configured_users().get(username)
    if not record:
        return None
    if not record.enabled:
        return None
    if not _verify_password(password, record):
        return None
    return User(
        username=username,
        role=record.role,
        permissions=list(record.permissions) if record.permissions else None,
        auth_mechanism="password",
    )


def get_local_auth_summary() -> dict[str, int]:
    users = list(_configured_users().values())
    return {
        "local_users_total": len(users),
        "local_users_hashed": sum(1 for item in users if item.password_hash),
        "local_users_plaintext": sum(1 for item in users if item.uses_plaintext),
        "local_users_disabled": sum(1 for item in users if not item.enabled),
    }


class AuthRateLimiter:
    def __init__(self, *, window_seconds: int, max_attempts: int, lockout_seconds: int) -> None:
        self._window_seconds = int(window_seconds)
        self._max_attempts = int(max_attempts)
        self._lockout_seconds = int(lockout_seconds)
        self._lock = Lock()
        self._states: dict[str, _AuthRateLimitState] = {}

    @property
    def enabled(self) -> bool:
        return self._window_seconds > 0 and self._max_attempts > 0 and self._lockout_seconds > 0

    def _prune_locked(self, ip: str, now_epoch: float) -> _AuthRateLimitState:
        state = self._states.setdefault(ip, _AuthRateLimitState())
        cutoff = now_epoch - float(self._window_seconds)
        while state.failure_epochs and state.failure_epochs[0] < cutoff:
            state.failure_epochs.popleft()
        if state.blocked_until_epoch and state.blocked_until_epoch <= now_epoch:
            state.blocked_until_epoch = 0.0
        if not state.failure_epochs and not state.blocked_until_epoch:
            self._states.pop(ip, None)
            return _AuthRateLimitState()
        return state

    def check(self, ip: str) -> dict[str, int | bool]:
        if not self.enabled:
            return {"blocked": False, "retry_after_seconds": 0, "recent_failures": 0}
        safe_ip = str(ip or "unknown").strip() or "unknown"
        now_epoch = time.time()
        with self._lock:
            state = self._prune_locked(safe_ip, now_epoch)
            retry_after = max(0, int(state.blocked_until_epoch - now_epoch)) if state.blocked_until_epoch else 0
            return {"blocked": retry_after > 0, "retry_after_seconds": retry_after, "recent_failures": len(state.failure_epochs)}

    def record_failure(self, ip: str) -> dict[str, int | bool]:
        if not self.enabled:
            return {"blocked": False, "retry_after_seconds": 0, "recent_failures": 0}
        safe_ip = str(ip or "unknown").strip() or "unknown"
        now_epoch = time.time()
        with self._lock:
            state = self._prune_locked(safe_ip, now_epoch)
            state = self._states.setdefault(safe_ip, state)
            state.failure_epochs.append(now_epoch)
            state.last_failure_epoch = now_epoch
            if len(state.failure_epochs) >= self._max_attempts:
                state.blocked_until_epoch = now_epoch + float(self._lockout_seconds)
            retry_after = max(0, int(state.blocked_until_epoch - now_epoch)) if state.blocked_until_epoch else 0
            return {"blocked": retry_after > 0, "retry_after_seconds": retry_after, "recent_failures": len(state.failure_epochs)}

    def record_success(self, ip: str) -> None:
        if not self.enabled:
            return
        safe_ip = str(ip or "unknown").strip() or "unknown"
        with self._lock:
            self._states.pop(safe_ip, None)

    def snapshot(self) -> dict[str, int | bool]:
        if not self.enabled:
            return {
                "enabled": False,
                "window_seconds": self._window_seconds,
                "max_attempts": self._max_attempts,
                "lockout_seconds": self._lockout_seconds,
                "tracked_ips": 0,
                "blocked_ips": 0,
                "recent_failures": 0,
            }
        now_epoch = time.time()
        with self._lock:
            for ip in list(self._states):
                self._prune_locked(ip, now_epoch)
            return {
                "enabled": True,
                "window_seconds": self._window_seconds,
                "max_attempts": self._max_attempts,
                "lockout_seconds": self._lockout_seconds,
                "tracked_ips": len(self._states),
                "blocked_ips": sum(1 for item in self._states.values() if item.blocked_until_epoch > now_epoch),
                "recent_failures": sum(len(item.failure_epochs) for item in self._states.values()),
            }


_AUTH_RATE_LIMITER = AuthRateLimiter(
    window_seconds=CONFIG.auth_rate_limit_window_seconds,
    max_attempts=CONFIG.auth_rate_limit_max_attempts,
    lockout_seconds=CONFIG.auth_rate_limit_lockout_seconds,
)


def get_request_client_ip(request: Request) -> str:
    forwarded = str(request.headers.get("x-forwarded-for") or "").strip()
    if forwarded:
        return str(forwarded.split(",")[0] or "").strip() or "unknown"
    real_ip = str(request.headers.get("x-real-ip") or "").strip()
    if real_ip:
        return real_ip
    if request.client and request.client.host:
        return str(request.client.host or "").strip() or "unknown"
    return "unknown"


def check_auth_rate_limit(request: Request) -> dict[str, int | bool | str]:
    payload = dict(_AUTH_RATE_LIMITER.check(get_request_client_ip(request)))
    payload["client_ip"] = get_request_client_ip(request)
    return payload


def record_auth_failure(request: Request) -> dict[str, int | bool | str]:
    payload = dict(_AUTH_RATE_LIMITER.record_failure(get_request_client_ip(request)))
    payload["client_ip"] = get_request_client_ip(request)
    return payload


def record_auth_success(request: Request) -> None:
    _AUTH_RATE_LIMITER.record_success(get_request_client_ip(request))


def get_auth_rate_limit_overview() -> dict[str, int | bool]:
    return _AUTH_RATE_LIMITER.snapshot()


def issue_csrf_token() -> str:
    return pysecrets.token_urlsafe(32)


def _authenticate_service_account_token(token: str) -> Optional[User]:
    safe_token = str(token or "").strip()
    if not safe_token:
        return None
    try:
        from .enterprise_control_plane import authenticate_service_account_token
    except ImportError:  # pragma: no cover - local test fallback
        from enterprise_control_plane import authenticate_service_account_token  # type: ignore[no-redef]

    principal = authenticate_service_account_token(safe_token)
    if not principal:
        return None
    service_account = dict(principal.get("service_account") or {})
    permissions = [str(item).strip() for item in (service_account.get("permissions") or []) if str(item).strip()]
    username = str(service_account.get("name") or service_account.get("id") or "service-account")
    return User(
        username=username,
        role="service",
        permissions=permissions,
        principal_type="service_account",
        service_account_id=str(service_account.get("id") or ""),
        auth_mechanism="api_token",
    )


def create_access_token(
    *,
    subject: str,
    role: ROLE,
    principal_type: str = "user",
    service_account_id: str = "",
    auth_mechanism: str = "jwt",
    issuer: str = "",
    groups: list[str] | None = None,
    break_glass: bool = False,
    session_expires_ts: str = "",
    break_glass_session_id: str = "",
    permissions: list[str] | None = None,
    section_access: list[str] | None = None,
    system_grants: list[dict[str, object]] | None = None,
) -> str:
    expire = datetime.now(tz=timezone.utc) + timedelta(minutes=CONFIG.jwt_expires_minutes)
    return jwt.encode(
        {
            "sub": subject,
            "role": role,
            "exp": expire,
            "principal_type": str(principal_type or "user"),
            "service_account_id": str(service_account_id or ""),
            "auth_mechanism": str(auth_mechanism or "jwt"),
            "issuer": str(issuer or ""),
            "groups": [str(item).strip() for item in (groups or []) if str(item).strip()],
            "break_glass": bool(break_glass),
            "session_expires_ts": str(session_expires_ts or ""),
            "break_glass_session_id": str(break_glass_session_id or ""),
            "permissions": [str(item).strip() for item in (permissions or []) if str(item).strip()],
            "section_access": [str(item).strip() for item in (section_access or []) if str(item).strip()],
            "system_grants": [dict(item) for item in (system_grants or []) if isinstance(item, dict)],
        },
        CONFIG.jwt_secret,
        algorithm=CONFIG.jwt_algorithm,
    )


def decode_access_token(token: str) -> User:
    try:
        payload = jwt.decode(token, CONFIG.jwt_secret, algorithms=[CONFIG.jwt_algorithm])
    except JWTError as exc:
        service_account = _authenticate_service_account_token(token)
        if service_account is not None:
            return service_account
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials") from exc
    username = str(payload.get("sub") or "").strip()
    role = str(payload.get("role", "viewer") or "viewer").strip().lower()
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    if role not in ALLOWED_ROLES:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid role in authentication token")
    break_glass_session_id = str(payload.get("break_glass_session_id") or "").strip()
    break_glass = bool(payload.get("break_glass", False))
    if break_glass_session_id:
        try:
            from .control_plane_access_ops import is_break_glass_session_active
        except ImportError:  # pragma: no cover - local test fallback
            from control_plane_access_ops import is_break_glass_session_active  # type: ignore[no-redef]
        if not is_break_glass_session_active(break_glass_session_id):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Break-glass session is no longer active")
    return User(
        username=username,
        role=role,  # type: ignore[arg-type]
        permissions=[str(item).strip() for item in (payload.get("permissions") or []) if str(item).strip()],
        principal_type=str(payload.get("principal_type") or "user"),
        service_account_id=str(payload.get("service_account_id") or ""),
        auth_mechanism=str(payload.get("auth_mechanism") or "jwt"),
        issuer=str(payload.get("issuer") or ""),
        groups=[str(item).strip() for item in (payload.get("groups") or []) if str(item).strip()],
        break_glass=break_glass,
        session_expires_ts=str(payload.get("session_expires_ts") or ""),
        break_glass_session_id=break_glass_session_id,
        section_access=[str(item).strip() for item in (payload.get("section_access") or []) if str(item).strip()],
        system_grants=[dict(item) for item in (payload.get("system_grants") or []) if isinstance(item, dict)],
    )


def get_token_from_request(request: Request) -> Optional[str]:
    auth_header = str(request.headers.get("authorization") or "").strip()
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
        if token:
            return token
    header_token = str(request.headers.get("x-api-token") or "").strip()
    if header_token:
        return header_token
    token = request.cookies.get("access_token")
    return token or None


def get_current_user(request: Request) -> User:
    token = get_token_from_request(request)
    if token is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return decode_access_token(token)


def validate_csrf_request(request: Request) -> None:
    if request.method.upper() in {"GET", "HEAD", "OPTIONS"}:
        return
    if request.url.path.startswith("/auth/login"):
        return
    if request.headers.get("authorization") or request.headers.get("x-api-token"):
        return
    access_token = str(request.cookies.get("access_token") or "").strip()
    if not access_token:
        return
    cookie_token = str(request.cookies.get("csrf_token") or "").strip()
    header_token = str(request.headers.get("x-csrf-token") or "").strip()
    if not cookie_token or not header_token or not pysecrets.compare_digest(cookie_token, header_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing or invalid CSRF token")


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_roles(*required_roles: ROLE):
    accepted = set(required_roles)

    def dependency(user: CurrentUser) -> User:
        if user.role not in accepted:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient role: required one of {sorted(accepted)}, got {user.role}",
            )
        return user

    return dependency


def has_permission(user: User, permission: str) -> bool:
    return str(permission or "") in set(getattr(user, "permissions", []) or [])


def require_permissions(*required_permissions: PERMISSION):
    required = tuple(required_permissions)

    def dependency(user: CurrentUser) -> User:
        missing = [permission for permission in required if not has_permission(user, permission)]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission(s): {', '.join(missing)}",
            )
        return user

    return dependency


AdminUser = Annotated[User, Depends(require_roles("admin"))]
AnalystUser = Annotated[User, Depends(require_roles("admin", "analyst"))]


async def login_via_form(request: Request, form_data: OAuth2PasswordRequestForm = Depends()) -> str:
    limiter = check_auth_rate_limit(request)
    if limiter.get("blocked"):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many login attempts. Retry in {int(limiter.get('retry_after_seconds') or 0)} seconds.",
        )
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        outcome = record_auth_failure(request)
        if outcome.get("blocked"):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many login attempts. Retry in {int(outcome.get('retry_after_seconds') or 0)} seconds.",
            )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    record_auth_success(request)
    return create_access_token(subject=user.username, role=user.role, permissions=list(user.permissions or []))
