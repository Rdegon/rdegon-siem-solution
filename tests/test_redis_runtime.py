import sys
import unittest
import asyncio
from types import SimpleNamespace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services import redis_runtime


class _FakeRedisClient:
    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs


class _FakeAsyncRedisClient:
    instances: list["_FakeAsyncRedisClient"] = []

    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs
        self.closed = False
        self.xadd_calls = 0
        type(self).instances.append(self)

    async def xadd(self, *args, **kwargs):
        self.xadd_calls += 1
        if self.kwargs["host"] == "192.168.1.38":
            raise RuntimeError("READONLY You can't write against a read only replica.")
        return "1-0"

    async def ping(self):
        return "PONG"

    async def xreadgroup(self, *args, **kwargs):
        return [("siem:raw", [("1-0", {"message": "ok"})])]

    async def xgroup_create(self, *args, **kwargs):
        return True

    async def aclose(self) -> None:
        self.closed = True


class _FakeSentinelRedis:
    master_sequence = [["192.168.1.38", "6379"]]

    def __init__(self, *, host: str, port: int, **kwargs) -> None:
        self.host = host
        self.port = port
        self.kwargs = kwargs
        self.closed = False

    def execute_command(self, *parts):
        if self.host == "192.168.1.37":
            if type(self).master_sequence:
                return type(self).master_sequence.pop(0)
            return ["192.168.1.37", "6379"]
        raise RuntimeError("sentinel_unreachable")

    def close(self) -> None:
        self.closed = True


class RedisRuntimeTests(unittest.TestCase):
    def tearDown(self) -> None:
        _FakeAsyncRedisClient.instances = []
        _FakeSentinelRedis.master_sequence = [["192.168.1.38", "6379"]]

    def test_parse_sentinel_nodes_accepts_csv(self) -> None:
        nodes = redis_runtime.parse_sentinel_nodes("192.168.1.37:26379,192.168.1.38:26379")
        self.assertEqual(nodes, (("192.168.1.37", 26379), ("192.168.1.38", 26379)))

    def test_connection_settings_from_object_reads_sentinel_env(self) -> None:
        env = {
            "SIEM_REDIS_SENTINEL_ENABLED": "true",
            "SIEM_REDIS_SENTINEL_MASTER": "siem-master",
            "SIEM_REDIS_SENTINEL_NODES": "192.168.1.37:26379,192.168.1.38:26379,192.168.1.39:26379",
            "SIEM_REDIS_SOCKET_CONNECT_TIMEOUT_SEC": "7",
            "SIEM_REDIS_SOCKET_TIMEOUT_SEC": "45",
        }
        settings = SimpleNamespace(redis_host="192.168.1.37", redis_port=6379, redis_db=0, redis_password="secret")

        connection = redis_runtime.connection_settings_from_object(settings, env=env)

        self.assertTrue(connection.sentinel_enabled)
        self.assertEqual(connection.sentinel_master, "siem-master")
        self.assertEqual(
            connection.sentinel_nodes,
            (("192.168.1.37", 26379), ("192.168.1.38", 26379), ("192.168.1.39", 26379)),
        )
        self.assertEqual(connection.socket_connect_timeout_sec, 7)
        self.assertEqual(connection.socket_timeout_sec, 45)

    def test_create_async_redis_client_uses_direct_redis_without_sentinel(self) -> None:
        original_redis = redis_runtime.Redis
        try:
            redis_runtime.Redis = _FakeRedisClient  # type: ignore[assignment]
            connection = redis_runtime.RedisConnectionSettings(
                host="192.168.1.37",
                port=6379,
                db=0,
                password="secret",
            )

            client = redis_runtime.create_async_redis_client(connection)

            self.assertIsInstance(client, _FakeRedisClient)
            self.assertEqual(client.kwargs["host"], "192.168.1.37")
            self.assertEqual(client.kwargs["port"], 6379)
            self.assertEqual(client.kwargs["password"], "secret")
            self.assertEqual(client.kwargs["socket_connect_timeout"], 5)
            self.assertEqual(client.kwargs["socket_timeout"], 30)
        finally:
            redis_runtime.Redis = original_redis  # type: ignore[assignment]

    def test_create_async_redis_client_uses_sentinel_discovery_and_direct_master_client(self) -> None:
        original_sync_redis = redis_runtime.SyncRedis
        original_async_redis = redis_runtime.Redis
        try:
            redis_runtime.SyncRedis = _FakeSentinelRedis  # type: ignore[assignment]
            redis_runtime.Redis = _FakeRedisClient  # type: ignore[assignment]
            connection = redis_runtime.RedisConnectionSettings(
                host="192.168.1.37",
                port=6379,
                db=0,
                password="secret",
                sentinel_enabled=True,
                sentinel_master="siem-master",
                sentinel_nodes=(("192.168.1.37", 26379), ("192.168.1.38", 26379)),
            )

            client = redis_runtime.create_async_redis_client(connection)

            self.assertIsInstance(client, _FakeRedisClient)
            self.assertEqual(client.kwargs["host"], "192.168.1.38")
            self.assertEqual(client.kwargs["port"], 6379)
            self.assertEqual(client.kwargs["password"], "secret")
            self.assertEqual(client.kwargs["socket_timeout"], 30)
        finally:
            redis_runtime.SyncRedis = original_sync_redis  # type: ignore[assignment]
            redis_runtime.Redis = original_async_redis  # type: ignore[assignment]

    def test_resilient_client_reconnects_after_readonly_error(self) -> None:
        original_sync_redis = redis_runtime.SyncRedis
        original_async_redis = redis_runtime.Redis
        try:
            _FakeSentinelRedis.master_sequence = [
                ["192.168.1.38", "6379"],
                ["192.168.1.37", "6379"],
            ]
            redis_runtime.SyncRedis = _FakeSentinelRedis  # type: ignore[assignment]
            redis_runtime.Redis = _FakeAsyncRedisClient  # type: ignore[assignment]
            connection = redis_runtime.RedisConnectionSettings(
                host="192.168.1.37",
                port=6379,
                db=0,
                password="secret",
                sentinel_enabled=True,
                sentinel_master="siem-master",
                sentinel_nodes=(("192.168.1.37", 26379),),
            )

            client = redis_runtime.create_resilient_async_redis_client(connection)
            stream_id = asyncio.run(client.xadd("siem:raw", {"message": "ok"}))

            self.assertEqual(stream_id, "1-0")
            self.assertEqual(len(_FakeAsyncRedisClient.instances), 2)
            self.assertEqual(_FakeAsyncRedisClient.instances[0].kwargs["host"], "192.168.1.38")
            self.assertEqual(_FakeAsyncRedisClient.instances[1].kwargs["host"], "192.168.1.37")
            self.assertTrue(_FakeAsyncRedisClient.instances[0].closed)
        finally:
            redis_runtime.SyncRedis = original_sync_redis  # type: ignore[assignment]
            redis_runtime.Redis = original_async_redis  # type: ignore[assignment]

    def test_resilient_client_refreshes_master_before_xreadgroup(self) -> None:
        original_sync_redis = redis_runtime.SyncRedis
        original_async_redis = redis_runtime.Redis
        try:
            _FakeSentinelRedis.master_sequence = [
                ["192.168.1.38", "6379"],
                ["192.168.1.37", "6379"],
                ["192.168.1.37", "6379"],
            ]
            redis_runtime.SyncRedis = _FakeSentinelRedis  # type: ignore[assignment]
            redis_runtime.Redis = _FakeAsyncRedisClient  # type: ignore[assignment]
            connection = redis_runtime.RedisConnectionSettings(
                host="192.168.1.37",
                port=6379,
                db=0,
                password="secret",
                sentinel_enabled=True,
                sentinel_master="siem-master",
                sentinel_nodes=(("192.168.1.37", 26379),),
            )

            client = redis_runtime.create_resilient_async_redis_client(connection)
            asyncio.run(client.ping())
            response = asyncio.run(
                client.xreadgroup(
                    groupname="normalizer",
                    consumername="normalizer-1",
                    streams={"siem:raw": ">"},
                    count=1,
                    block=1,
                )
            )

            self.assertEqual(response[0][0], "siem:raw")
            self.assertEqual(len(_FakeAsyncRedisClient.instances), 2)
            self.assertEqual(_FakeAsyncRedisClient.instances[0].kwargs["host"], "192.168.1.38")
            self.assertEqual(_FakeAsyncRedisClient.instances[1].kwargs["host"], "192.168.1.37")
            self.assertTrue(_FakeAsyncRedisClient.instances[0].closed)
        finally:
            redis_runtime.SyncRedis = original_sync_redis  # type: ignore[assignment]
            redis_runtime.Redis = original_async_redis  # type: ignore[assignment]

    def test_resilient_client_supports_keyword_name_calls(self) -> None:
        original_sync_redis = redis_runtime.SyncRedis
        original_async_redis = redis_runtime.Redis
        try:
            redis_runtime.SyncRedis = _FakeSentinelRedis  # type: ignore[assignment]
            redis_runtime.Redis = _FakeAsyncRedisClient  # type: ignore[assignment]
            connection = redis_runtime.RedisConnectionSettings(
                host="192.168.1.37",
                port=6379,
                db=0,
                password="secret",
                sentinel_enabled=True,
                sentinel_master="siem-master",
                sentinel_nodes=(("192.168.1.37", 26379),),
            )

            client = redis_runtime.create_resilient_async_redis_client(connection)
            created = asyncio.run(
                client.xgroup_create(
                    name="siem:raw",
                    groupname="normalizer",
                    id="0-0",
                    mkstream=True,
                )
            )

            self.assertTrue(created)
            self.assertEqual(len(_FakeAsyncRedisClient.instances), 1)
            self.assertEqual(_FakeAsyncRedisClient.instances[0].kwargs["host"], "192.168.1.38")
        finally:
            redis_runtime.SyncRedis = original_sync_redis  # type: ignore[assignment]
            redis_runtime.Redis = original_async_redis  # type: ignore[assignment]


if __name__ == "__main__":
    unittest.main()
