"""
TCP syslog listeners for separated SIEM collector profiles.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import List

from typing import Any

try:
    from redis.asyncio import Redis
except ModuleNotFoundError:  # pragma: no cover - local test fallback
    Redis = Any  # type: ignore[assignment,misc]

from .config import IngestSettings
from .redis_client import push_dead_letter_event, push_raw_events_batch, record_ingest_acceptance_batch

logger = logging.getLogger(__name__)


class SyslogTcpServer:
    """Single TCP syslog listener bound to a collector profile."""

    def __init__(self, settings: IngestSettings, redis: Redis, producer: Any | None, profile: str, listen_port: int) -> None:
        self._settings = settings
        self._redis = redis
        self._producer = producer
        self._profile = profile
        self._listen_port = listen_port
        self._server: asyncio.AbstractServer | None = None
        self._active_writers: set[asyncio.StreamWriter] = set()
        self._stopping = False

    async def start(self) -> None:
        self._stopping = False
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self._settings.ingest_syslog_host,
            port=self._listen_port,
            # The ingest service runs multiple uvicorn workers on VM1.
            # Allow each worker to bind the same syslog listener port cleanly.
            reuse_port=True,
        )
        addr = ", ".join(str(sock.getsockname()) for sock in (self._server.sockets or []))
        logger.info(
            "Syslog TCP server started",
            extra={"extra": {"listen": addr, "profile": self._profile}},
        )

    async def stop(self) -> None:
        self._stopping = True
        if self._server is None:
            writers = list(self._active_writers)
        else:
            self._server.close()
            await self._server.wait_closed()
            writers = list(self._active_writers)
            self._server = None
        if writers:
            for writer in writers:
                try:
                    writer.close()
                except Exception:  # noqa: BLE001
                    pass
            await asyncio.gather(
                *(writer.wait_closed() for writer in writers),
                return_exceptions=True,
            )
        logger.info("Syslog TCP server stopped", extra={"extra": {"profile": self._profile}})

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peername = writer.get_extra_info("peername")
        host: str | None = None
        port: int | None = None
        if isinstance(peername, tuple) and len(peername) >= 2:
            host = str(peername[0])
            port = int(peername[1])

        logger.info(
            "Syslog client connected",
            extra={"extra": {"peer_host": host, "peer_port": port, "profile": self._profile}},
        )
        self._active_writers.add(writer)

        try:
            while True:
                if self._stopping:
                    break
                line = await reader.readline()
                if not line:
                    break
                lines = [line]
                eof = False
                batch_size = max(1, min(2_000, int(os.getenv("SIEM_INGEST_SYSLOG_PUBLISH_BATCH_SIZE", "250") or "250")))
                batch_timeout = max(
                    0.001,
                    min(0.25, float(os.getenv("SIEM_INGEST_SYSLOG_BATCH_TIMEOUT_MS", "10") or "10") / 1000.0),
                )
                for _ in range(batch_size - 1):
                    try:
                        next_line = await asyncio.wait_for(reader.readline(), timeout=batch_timeout)
                    except asyncio.TimeoutError:
                        break
                    if not next_line:
                        eof = True
                        break
                    lines.append(next_line)

                events: list[dict[str, object]] = []
                raw_messages: list[str] = []
                for raw_line in lines:
                    msg = raw_line.decode(errors="replace").rstrip("\r\n")
                    if not msg:
                        continue
                    raw_messages.append(msg)
                    events.append(
                        {
                            "source": host or "",
                            "source_type": "syslog",
                            "message": msg,
                            "collector": "syslog_tcp",
                            "collector_profile": self._profile,
                            "ingest_profile": self._profile,
                            "listener_port": self._listen_port,
                            "observer.collector": "syslog_tcp",
                            "observer.profile": self._profile,
                            "observer.listener_port": str(self._listen_port),
                            "event.dataset": self._profile,
                        }
                    )
                if not events:
                    if eof:
                        break
                    continue

                try:
                    accepted_batch = await push_raw_events_batch(
                        self._redis,
                        events,
                        settings=self._settings,
                        producer=self._producer,
                    )
                    await record_ingest_acceptance_batch(self._redis, accepted_batch, settings=self._settings)
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "Failed to push syslog batch to transport",
                        extra={
                            "extra": {
                                "error": str(exc),
                                "peer_host": host,
                                "peer_port": port,
                                "profile": self._profile,
                                "batch_size": len(events),
                            }
                        },
                    )
                    for msg in raw_messages:
                        await push_dead_letter_event(
                            self._redis,
                            {"message": msg},
                            reason="syslog_push_failed",
                            source_ip=host or "",
                            collector="syslog_tcp",
                            collector_profile=self._profile,
                            ingest_path=f"tcp://{self._settings.ingest_syslog_host}:{self._listen_port}",
                            metadata={
                                "source_type": "syslog",
                                "collector": "syslog_tcp",
                                "collector_profile": self._profile,
                                "ingest_profile": self._profile,
                                "event.dataset": self._profile,
                                "error": str(exc),
                            },
                        )
                if eof:
                    break
        finally:
            self._active_writers.discard(writer)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

            logger.info(
                "Syslog client disconnected",
                extra={"extra": {"peer_host": host, "peer_port": port, "profile": self._profile}},
            )


async def create_syslog_servers(settings: IngestSettings, redis: Redis, producer: Any | None = None) -> List[SyslogTcpServer]:
    servers: List[SyslogTcpServer] = []
    for profile, port in settings.syslog_profiles().items():
        if not port or port <= 0:
            continue
        server = SyslogTcpServer(settings, redis, producer, profile, port)
        await server.start()
        servers.append(server)
    return servers
