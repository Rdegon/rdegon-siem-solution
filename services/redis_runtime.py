from __future__ import annotations

import os
import asyncio
import inspect
from dataclasses import dataclass
from typing import Any, Mapping

try:
    from redis.asyncio import Redis
    from redis import Redis as SyncRedis
    from redis.exceptions import ConnectionError as RedisConnectionError
    from redis.exceptions import TimeoutError as RedisTimeoutError
except ModuleNotFoundError:  # pragma: no cover - local test fallback
    Redis = Any  # type: ignore[assignment,misc]
    SyncRedis = Any  # type: ignore[assignment,misc]
    RedisConnectionError = ConnectionError  # type: ignore[assignment,misc]
    RedisTimeoutError = TimeoutError  # type: ignore[assignment,misc]


@dataclass(frozen=True)
class RedisConnectionSettings:
    host: str
    port: int
    db: int
    password: str | None
    socket_connect_timeout_sec: int = 5
    socket_timeout_sec: int = 30
    sentinel_enabled: bool = False
    sentinel_master: str = "siem-master"
    sentinel_nodes: tuple[tuple[str, int], ...] = ()


def _parse_bool(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def parse_sentinel_nodes(value: object) -> tuple[tuple[str, int], ...]:
    if isinstance(value, tuple):
        return tuple((str(host), int(port)) for host, port in value)
    if isinstance(value, list):
        return tuple((str(host), int(port)) for host, port in value)
    text = str(value or "").strip()
    if not text:
        return ()
    nodes: list[tuple[str, int]] = []
    for raw_part in text.split(","):
        part = raw_part.strip()
        if not part:
            continue
        if ":" not in part:
            raise ValueError(f"Invalid Redis sentinel node={part!r}, expected host:port")
        host, port_text = part.rsplit(":", 1)
        host = host.strip()
        if not host:
            raise ValueError(f"Invalid Redis sentinel host in {part!r}")
        try:
            port = int(port_text.strip())
        except ValueError as exc:
            raise ValueError(f"Invalid Redis sentinel port in {part!r}") from exc
        nodes.append((host, port))
    return tuple(nodes)


def connection_settings_from_object(
    settings: object | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> RedisConnectionSettings:
    env_map = env or os.environ

    def attr(name: str, default: object) -> object:
        if settings is not None and hasattr(settings, name):
            value = getattr(settings, name)
            if value is not None:
                return value
        return default

    host = str(attr("redis_host", env_map.get("SIEM_REDIS_HOST", "127.0.0.1")) or "127.0.0.1")
    port = int(attr("redis_port", env_map.get("SIEM_REDIS_PORT", "6379")) or 6379)
    db = int(attr("redis_db", env_map.get("SIEM_REDIS_DB", "0")) or 0)
    password_raw = attr("redis_password", env_map.get("SIEM_REDIS_PASSWORD", ""))
    password = str(password_raw).strip() or None
    socket_connect_timeout_sec = int(
        attr("redis_socket_connect_timeout_sec", env_map.get("SIEM_REDIS_SOCKET_CONNECT_TIMEOUT_SEC", "5")) or 5
    )
    socket_timeout_sec = int(
        attr("redis_socket_timeout_sec", env_map.get("SIEM_REDIS_SOCKET_TIMEOUT_SEC", "30")) or 30
    )

    sentinel_enabled = _parse_bool(
        attr("redis_sentinel_enabled", env_map.get("SIEM_REDIS_SENTINEL_ENABLED", "false"))
    )
    sentinel_master = str(
        attr("redis_sentinel_master", env_map.get("SIEM_REDIS_SENTINEL_MASTER", "siem-master")) or "siem-master"
    ).strip() or "siem-master"
    sentinel_nodes = parse_sentinel_nodes(
        attr("redis_sentinel_nodes", env_map.get("SIEM_REDIS_SENTINEL_NODES", ""))
    )

    return RedisConnectionSettings(
        host=host,
        port=port,
        db=db,
        password=password,
        socket_connect_timeout_sec=max(1, socket_connect_timeout_sec),
        socket_timeout_sec=max(1, socket_timeout_sec),
        sentinel_enabled=sentinel_enabled and bool(sentinel_nodes),
        sentinel_master=sentinel_master,
        sentinel_nodes=sentinel_nodes,
    )


def _discover_master_address(connection: RedisConnectionSettings) -> tuple[str, int]:
    errors: list[str] = []
    for host, port in connection.sentinel_nodes:
        sentinel_client = SyncRedis(
            host=host,
            port=port,
            decode_responses=True,
            socket_connect_timeout=connection.socket_connect_timeout_sec,
            socket_timeout=connection.socket_timeout_sec,
            retry_on_timeout=True,
        )
        try:
            response = sentinel_client.execute_command("SENTINEL", "get-master-addr-by-name", connection.sentinel_master)
            if isinstance(response, (list, tuple)) and len(response) >= 2:
                master_host = str(response[0] or "").strip()
                master_port = int(response[1])
                if master_host:
                    return master_host, master_port
            errors.append(f"{host}:{port}=empty_response")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{host}:{port}={type(exc).__name__}:{exc}")
        finally:
            close = getattr(sentinel_client, "close", None)
            if callable(close):
                close()
    raise RuntimeError(f"Unable to discover Redis master for {connection.sentinel_master}: {'; '.join(errors)}")


def resolve_redis_endpoint(connection: RedisConnectionSettings) -> tuple[str, int]:
    if connection.sentinel_enabled and connection.sentinel_nodes:
        return _discover_master_address(connection)
    return connection.host, connection.port


def should_refresh_redis_connection(exc: BaseException) -> bool:
    text = str(exc or "").strip().lower()
    if "read only replica" in text or "readonly" in text:
        return True
    if "master not found" in text or "connection closed" in text or "connection reset" in text:
        return True
    return isinstance(exc, (RedisConnectionError, RedisTimeoutError, ConnectionError, TimeoutError, OSError))


def create_async_redis_client(connection: RedisConnectionSettings) -> Redis:
    common_kwargs = {
        "db": connection.db,
        "decode_responses": True,
        "health_check_interval": 30,
        "socket_connect_timeout": connection.socket_connect_timeout_sec,
        "socket_timeout": connection.socket_timeout_sec,
        "retry_on_timeout": True,
    }
    host, port = resolve_redis_endpoint(connection)
    return Redis(
        host=host,
        port=port,
        password=connection.password,
        **common_kwargs,
    )


async def _close_async_redis_client(client: Any) -> None:
    if client is None:
        return
    for attr_name in ("aclose", "close"):
        attr = getattr(client, attr_name, None)
        if not callable(attr):
            continue
        result = attr()
        if inspect.isawaitable(result):
            await result
        return


class ResilientAsyncRedis:
    def __init__(self, connection: RedisConnectionSettings) -> None:
        self._connection = connection
        self._client: Redis | None = None
        self._endpoint: tuple[str, int] | None = None
        self._lock = asyncio.Lock()

    def _create_client(self) -> Redis:
        host, port = resolve_redis_endpoint(self._connection)
        client = create_async_redis_client(
            RedisConnectionSettings(
                host=host,
                port=port,
                db=self._connection.db,
                password=self._connection.password,
                socket_connect_timeout_sec=self._connection.socket_connect_timeout_sec,
                socket_timeout_sec=self._connection.socket_timeout_sec,
                sentinel_enabled=False,
                sentinel_master=self._connection.sentinel_master,
                sentinel_nodes=(),
            )
        )
        self._endpoint = (host, port)
        return client

    async def _get_client(self) -> Redis:
        if self._client is None:
            async with self._lock:
                if self._client is None:
                    self._client = self._create_client()
        assert self._client is not None
        return self._client

    async def reconnect(self) -> Redis:
        async with self._lock:
            old_client = self._client
            self._client = self._create_client()
        await _close_async_redis_client(old_client)
        assert self._client is not None
        return self._client

    async def _ensure_current_master_binding(self) -> None:
        if not (self._connection.sentinel_enabled and self._connection.sentinel_nodes):
            return
        current_endpoint = resolve_redis_endpoint(self._connection)
        if self._client is None or self._endpoint != current_endpoint:
            await self.reconnect()

    async def aclose(self) -> None:
        async with self._lock:
            client = self._client
            self._client = None
        await _close_async_redis_client(client)

    async def close(self) -> None:
        await self.aclose()

    async def _call(self, method_name: str, *args: Any, **kwargs: Any) -> Any:
        last_error: BaseException | None = None
        for attempt in range(2):
            if method_name == "xreadgroup":
                await self._ensure_current_master_binding()
            client = await self._get_client()
            method = getattr(client, method_name)
            try:
                return await method(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                if attempt >= 1 or not should_refresh_redis_connection(exc):
                    raise
                await self.reconnect()
        if last_error is not None:
            raise last_error
        raise RuntimeError(f"Redis call failed without exception: {method_name}")

    def __getattr__(self, name: str) -> Any:
        if name in {"close", "aclose"}:
            return getattr(self, name)

        async def _method(*args: Any, **kwargs: Any) -> Any:
            return await self._call(name, *args, **kwargs)

        return _method


def create_resilient_async_redis_client(connection: RedisConnectionSettings) -> ResilientAsyncRedis:
    return ResilientAsyncRedis(connection)
