from __future__ import annotations

try:
    from ..operational_filters import contains_non_operational_marker
except ImportError:  # pragma: no cover - local test fallback
    from operational_filters import contains_non_operational_marker  # type: ignore[no-redef]

NON_OPERATIONAL_INVENTORY_MARKERS = (
    "generic-http",
    "http refresh job",
    "задача http-обновления",
    "127.0.0.1",
    "::1",
    "localhost",
    "{'ip':",
    "vm1-smoke",
    "vm4-smoke",
    "vm1-debug",
    "vm1-probe",
    "vm2-probe",
    "codex-smoke",
    "cleanup-smoke",
    "storage-ha-smoke",
    "transport-shadow-smoke",
    "host-runtime-smoke",
    "greenbone-runtime-smoke",
    "benchmark-smoke",
    "eps-benchmark-smoke",
    "e2e",
    "assignment-full",
    "full-batch-e2e",
    "full-stream-e2e",
    "validation",
    "vm1-kafka-cutover",
    "kafka-cutover-smoke",
    "synthetic",
    "smoke webhook source",
    "smoke approval gate",
    "smoke token",
    "smoke-runtime-",
)

INVENTORY_IDENTITY_KEYS = {
    "actor",
    "alert_id",
    "alias",
    "aliases",
    "asset",
    "asset_id",
    "collector",
    "collector_id",
    "collector_name",
    "collector_profile",
    "covered_sources",
    "entity",
    "entity_key",
    "host",
    "host_name",
    "hostname",
    "id",
    "indicator",
    "ip",
    "item_value",
    "log_source",
    "name",
    "rule_name",
    "source",
    "source_alias",
    "source_name",
    "title",
}


def _parse_hours(window: str) -> int:
    text = str(window or "24h").strip().lower()
    if not text:
        return 24
    multiplier = 1
    if text.endswith("d"):
        multiplier = 24
        text = text[:-1]
    elif text.endswith("h"):
        text = text[:-1]
    try:
        return max(1, int(text) * multiplier)
    except ValueError:
        return 24


def deps_module():
    try:
        from .. import deps as deps_module_impl
    except ImportError:  # pragma: no cover - local test fallback
        import deps as deps_module_impl  # type: ignore[no-redef]

    return deps_module_impl


def runtime_docs_module():
    try:
        from .. import deps_runtime_docs_ops as runtime_docs_module_impl
    except ImportError:  # pragma: no cover - local test fallback
        import deps_runtime_docs_ops as runtime_docs_module_impl  # type: ignore[no-redef]

    return runtime_docs_module_impl


def _iter_inventory_identity_values(record: object):
    if record is None:
        return
    if isinstance(record, str):
        yield record
        return
    if isinstance(record, (int, float, bool)):
        yield str(record)
        return
    if isinstance(record, dict):
        for key, value in record.items():
            if str(key).lower() in INVENTORY_IDENTITY_KEYS:
                yield from _iter_inventory_identity_values(value)
        return
    if isinstance(record, (list, tuple, set)):
        for item in record:
            yield from _iter_inventory_identity_values(item)
        return


def is_non_operational_inventory_record(record: object) -> bool:
    for value in _iter_inventory_identity_values(record):
        text = str(value or "").strip().lower()
        if contains_non_operational_marker(text):
            return True
        if any(marker in text for marker in NON_OPERATIONAL_INVENTORY_MARKERS):
            return True
    return False
