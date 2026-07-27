from deploy import clickhouse_hot_storage_guard as guard


def test_hot_storage_guard_targets_primary_clickhouse_vm() -> None:
    assert guard.VMID == 106
    assert guard.DATA_PATH == "/var/lib/clickhouse"
    assert guard.TARGET_LABEL == "siem-clickhouse-"
    assert guard.MAINTENANCE_MARKER == "/run/siem-maintenance"


def test_hot_storage_guard_covers_clickhouse_pipeline_services() -> None:
    assert set(guard.CLICKHOUSE_SERVICES) >= {
        "clickhouse-server.service",
        "siem-writer.service",
        "siem-writer@2.service",
        "siem-stream-corr.service",
        "siem-batch-corr.service",
        "siem-alert-agg.service",
    }
    assert "RequiresMountsFor=/var/lib/clickhouse" in guard.MOUNT_DROP_IN
