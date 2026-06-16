from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from .config import FilterSettings
from .filter_core import FilterRule, eval_expr, load_filter_rules
from .logging_conf import configure_logging
from services.transport_runtime import _transport_field_value, create_transport_consumer, create_transport_producer, transport_backend

logger = logging.getLogger(__name__)


class FilterWorker:
    def __init__(self, settings: FilterSettings) -> None:
        self._settings = settings
        self._consumer = None
        self._producer = None
        self._rules: List[FilterRule] = []

    async def init(self) -> None:
        self._consumer = create_transport_consumer(
            self._settings,
            alias='normalized',
            group=self._settings.group_name,
            consumer=self._settings.consumer_name,
        )
        await self._consumer.init()
        self._producer = create_transport_producer(self._settings)
        self._rules = load_filter_rules(self._settings)
        logger.info(
            'FilterWorker initialized',
            extra={'extra': {
                'normalized_stream': self._settings.normalized_stream_key,
                'filtered_stream': self._settings.filtered_stream_key,
                'batch_size': self._settings.batch_size,
                'rules_count': len(self._rules),
                'group': self._settings.group_name,
                'consumer': self._settings.consumer_name,
                'transport_backend': transport_backend(self._settings),
            }},
        )

    async def _reload_rules_periodically(self) -> None:
        while True:
            try:
                self._rules = load_filter_rules(self._settings)
            except Exception as exc:  # noqa: BLE001
                logger.error('Failed to reload filter rules', extra={'extra': {'error': str(exc)}})
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
                logger.error('Transport poll failed in filter', extra={'extra': {'error': str(exc)}})
                await asyncio.sleep(1)
                continue
            if not messages:
                continue

            read_count = 0
            passed_count = 0
            dropped_count = 0
            tagged_count = 0
            ack_messages: List[Any] = []
            filtered_payloads: List[Dict[str, str]] = []
            filtered_messages: List[Any] = []
            for message in messages:
                read_count += 1
                event = dict(message.fields)
                decision, final_event = self.apply_rules(event)
                if decision == 'drop':
                    dropped_count += 1
                    ack_messages.append(message)
                    continue
                if decision == 'tag':
                    tagged_count += 1
                filtered_payloads.append({k: _transport_field_value(v) for k, v in final_event.items()})
                filtered_messages.append(message)
            if filtered_payloads:
                try:
                    if hasattr(self._producer, "publish_many"):
                        await self._producer.publish_many('filtered', filtered_payloads)
                    else:
                        for payload in filtered_payloads:
                            await self._producer.publish('filtered', payload)
                    passed_count += len(filtered_payloads)
                    ack_messages.extend(filtered_messages)
                except Exception as exc:  # noqa: BLE001
                    logger.error('Failed to publish filtered batch', extra={'extra': {'error': str(exc), 'events': len(filtered_payloads)}})
            if ack_messages:
                await self._consumer.ack(ack_messages)
            if read_count > 0:
                logger.info('Filter batch processed', extra={'extra': {'events_read': read_count, 'events_passed': passed_count, 'events_dropped': dropped_count, 'events_tagged': tagged_count, 'acked': len(ack_messages)}})

    def apply_rules(self, event: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
        result = dict(event)
        tags: List[str] = []
        for rule in self._rules:
            if not rule.expr_ast:
                continue
            try:
                matched = eval_expr(rule.expr_ast, event)
            except Exception as exc:  # noqa: BLE001
                logger.error('Error evaluating filter rule', extra={'extra': {'rule_id': rule.id, 'expr': rule.expr_text, 'error': str(exc)}})
                continue
            if not matched:
                continue
            if rule.action == 'drop':
                return 'drop', result
            if rule.action == 'tag':
                tags.extend(rule.tags)
                break
            if rule.action == 'pass':
                break
        if tags:
            existing = result.get('tags')
            result['tags'] = f"{existing},{','.join(tags)}" if existing else ','.join(tags)
            return 'tag', result
        return 'pass', result


async def main() -> None:
    configure_logging()
    settings = FilterSettings.load()
    worker = FilterWorker(settings)
    await worker.init()
    await worker.run()


if __name__ == '__main__':
    asyncio.run(main())
