from deploy import clickhouse_event_deduplication_release as release


def test_release_targets_both_independent_writers() -> None:
    targets = {
        (int(item["vmid"]), str(item["service"]))
        for item in release.TARGETS
    }
    assert targets == {
        (106, "siem-writer"),
        (108, "siem-writer-standby"),
    }
    assert "services/writer/worker.py" in release.RELEASE_FILES
    assert "sql/19_event_insert_deduplication.sql" in release.RELEASE_FILES


def test_release_uses_source_scoped_logical_event_deduplication() -> None:
    source = (
        release.ROOT / "deploy" / "clickhouse_event_deduplication_release.py"
    ).read_text(encoding="utf-8")
    assert "LIMIT 1 BY event_id, device_product, log_source, host_name" in source
    assert "REPLACE PARTITION" in source
    assert "ORDER BY ts ASC" in source
    assert "uniqExact(tuple(event_id, device_product" in source


def test_release_reconciles_both_clickhouse_nodes_after_maintenance() -> None:
    source = (
        release.ROOT / "deploy" / "clickhouse_event_deduplication_release.py"
    ).read_text(encoding="utf-8")
    assert "LEFT ANTI JOIN" in source
    assert "INSERT INTO siem.events SELECT peer.*" in source
    assert "for vmid, peer_vmid in ((106, 108), (108, 106))" in source
    assert "reconcile-cutoff-minutes" in source
    assert release.TARGET_IPS == {
        106: "10.20.10.106",
        108: "10.20.10.108",
    }
