from __future__ import annotations

import json
from typing import Any, Iterable


NON_OPERATIONAL_MARKERS: tuple[str, ...] = (
    "smoke",
    "smoke-ok",
    "smoke_test",
    "synthetic",
    "synthetic-benchmark",
    "benchmark",
    "collector-bench",
    "bench-syslog",
    "eps-bench",
    "eps-benchmark",
    "e2e",
    "e2e-correlation",
    "full-batch-e2e",
    "full-stream-e2e",
    "assignment-full",
    "assignment-full-batch",
    "assignment-full-stream",
    "validation",
    "codex-smoke",
    "cleanup-smoke",
    "host-runtime-smoke",
    "storage-ha-smoke",
    "transport-shadow-smoke",
    "greenbone-runtime-smoke",
    "benchmark-smoke",
    "eps-benchmark-smoke",
    "vm1-smoke",
    "vm4-smoke",
    "vm4 foundation smoke",
    "vm1-kafka-cutover",
    "kafka-cutover-smoke",
    "kafka shadow",
    "kafka-shadow",
    "kafka wave smoke",
    "kafka-wave-smoke",
    "smoke webhook source",
    "smoke approval gate",
    "smoke token",
    "smoke-runtime-",
    "e2e-",
    "-validation",
    " validation",
    "unit-test",
    "ci-test",
    "test-ioc",
    "example-ioc",
    "test-source",
    "test-collector",
    "test-alert",
    "test-incident",
    "pytest",
    "playwright",
    "npm run",
    "node build.cjs",
    "/opt/siem/siem-solution",
    "deploy/",
    "systemctl status siem-",
    "siem-host-runtime-agent.service",
    "install -m 0644 /tmp/siem-",
    "auditctl -r /etc/audit/audit.rules",
    "203.0.113.",
    "198.51.100.",
    "192.0.2.",
)

NON_OPERATIONAL_PREFIXES: tuple[str, ...] = (
    "smoke-",
    "test-",
    "qa-",
    "mock-",
    "dummy-",
    "sample-",
    "demo-",
    "e2e-",
)


def _iter_text_values(value: Any) -> Iterable[str]:
    if value is None:
        return
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, (int, float, bool)):
        yield str(value)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _iter_text_values(item)
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _iter_text_values(item)
        return
    yield str(value)


def contains_non_operational_marker(value: Any) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    if any(marker in text for marker in NON_OPERATIONAL_MARKERS):
        return True
    return any(text.startswith(prefix) for prefix in NON_OPERATIONAL_PREFIXES)


def is_non_operational_record(record: Any) -> bool:
    for value in _iter_text_values(record):
        if contains_non_operational_marker(value):
            return True
    try:
        haystack = json.dumps(record, ensure_ascii=False, default=str).lower()
    except Exception:
        haystack = str(record or "").lower()
    return any(marker in haystack for marker in NON_OPERATIONAL_MARKERS)
