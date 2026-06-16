from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List

from .config import NormalizerSettings
from .logging_conf import configure_logging
from .normalizer_core import NormalizerRule, apply_rules, load_rules
from services.transport_runtime import create_transport_consumer, create_transport_producer, transport_backend

logger = logging.getLogger(__name__)


def _transport_field_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return str(value)


class NormalizerWorker:
    def __init__(self, settings: NormalizerSettings) -> None:
        self._settings = settings
        self._consumer = None
        self._producer = None
        self._rules: List[NormalizerRule] = []

    async def init(self) -> None:
        self._consumer = create_transport_consumer(
            self._settings,
            alias='raw',
            group=self._settings.consumer_group,
            consumer=self._settings.consumer_name,
        )
        await self._consumer.init()
        self._producer = create_transport_producer(self._settings)
        self._rules = load_rules(self._settings)
        logger.info(
            'NormalizerWorker initialized',
            extra={'extra': {
                'raw_stream': self._settings.raw_stream_key,
                'normalized_stream': self._settings.normalized_stream_key,
                'batch_size': self._settings.batch_size,
                'rules_count': len(self._rules),
                'group': self._settings.consumer_group,
                'consumer': self._settings.consumer_name,
                'transport_backend': transport_backend(self._settings),
            }},
        )

    async def _reload_rules_periodically(self) -> None:
        while True:
            try:
                self._rules = load_rules(self._settings)
            except Exception as exc:  # noqa: BLE001
                logger.error('Failed to reload normalizer rules', extra={'extra': {'error': str(exc)}})
            await asyncio.sleep(30)

    async def run(self) -> None:
        assert self._consumer is not None
        assert self._producer is not None
        asyncio.create_task(self._reload_rules_periodically())
        while True:
            try:
                messages = await self._consumer.poll(
                    batch_size=self._settings.batch_size,
                    block_ms=self._settings.block_ms,
                )
            except Exception as exc:  # noqa: BLE001
                logger.error('Transport poll failed in normalizer', extra={'extra': {'error': str(exc)}})
                await asyncio.sleep(1)
                continue
            if not messages:
                continue

            read_count = 0
            normalized_count = 0
            ack_messages: List[Any] = []
            normalized_payloads: List[Dict[str, str]] = []
            normalized_messages: List[Any] = []
            for message in messages:
                read_count += 1
                raw_event: Dict[str, Any] = dict(message.fields)
                uem = apply_rules(self._rules, raw_event)
                if uem is None:
                    ack_messages.append(message)
                    continue
                normalized_payloads.append({k: _transport_field_value(v) for k, v in uem.items()})
                normalized_messages.append(message)
            if normalized_payloads:
                try:
                    if hasattr(self._producer, "publish_many"):
                        await self._producer.publish_many('normalized', normalized_payloads)
                    else:
                        for payload in normalized_payloads:
                            await self._producer.publish('normalized', payload)
                    normalized_count += len(normalized_payloads)
                    ack_messages.extend(normalized_messages)
                except Exception as exc:  # noqa: BLE001
                    logger.error('Failed to publish normalized batch', extra={'extra': {'error': str(exc), 'events': len(normalized_payloads)}})
            if ack_messages:
                await self._consumer.ack(ack_messages)
            if read_count > 0:
                logger.info('Normalizer batch processed', extra={'extra': {'raw_events_read': read_count, 'normalized_events': normalized_count, 'acked': len(ack_messages)}})


async def main() -> None:
    configure_logging()
    settings = NormalizerSettings.load()
    worker = NormalizerWorker(settings)
    await worker.init()
    await worker.run()


if __name__ == '__main__':
    asyncio.run(main())
