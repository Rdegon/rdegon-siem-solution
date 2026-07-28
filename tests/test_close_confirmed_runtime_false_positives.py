from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_cleanup_is_evidence_scoped_and_preserves_real_incidents() -> None:
    source = (
        ROOT / "deploy" / "close_confirmed_runtime_false_positives.py"
    ).read_text(encoding="utf-8")

    assert "rule_id = 2706" in source
    assert "velociraptor-client.service" in source
    assert "60-static-kafka-member.conf" in source
    assert "rule_id = 8121" in source
    assert "10.20.10.105|1.1.1.1" in source
    assert "entity_key = 'gamepanel-01'" in source
    assert "assignment_batch_rule" in source
    assert "rule_id = 2604" in source
    assert "rule_id = 4005" in source
    assert "pilot-db-01" in source
    assert "'nextcloud-siem', 'soc-pki-01'" in source
    assert "sustained_load_pressure" in source
    assert "2026-07-28 00:42:00" in source
    assert "rule_id IN (8011, 8012) AND entity_key = 'opnsense-staging'" in source
    assert "rule_id = 8012 AND entity_key = 'soc-ti-01'" in source
    assert "rule_id = 2617" in source
    assert "entity_key = '192.168.3.103'" in source
    assert '"process_command": "who -q"' in source
    assert '"process_command": "uname -r"' in source
    assert "rule_id = 2704" in source
    assert "siem-storage|/etc/cron.d" in source
    assert "rule_id = 2709" in source
    assert "rule_id = 2715" in source
    assert "rule_id = 8221" in source
    assert "rule_id = 8305" in source
    assert 'status="resolved"' in source
    assert "rule_id IN (8084, 8097)" in source
    assert "rule_id IN (8001, 8002)" in source
    false_positive_section = source.split("def _resolved_predicate", 1)[0]
    resolved_section = source.split("def _resolved_predicate", 1)[1]
    assert "rule_id IN (8001, 8002)" in false_positive_section
    assert "rule_id IN (8001, 8002)" not in resolved_section
    assert "service_restart_loop" in false_positive_section
    assert "rule_id = 8212" in resolved_section
    assert "entity_key = 'siem-stream-corr'" in resolved_section
    assert "rule_id = 8047" in source
    assert "hits = 59" in source
    assert "rule_id = 8077" in source
    assert "audit_service_stop" in source
    assert "siem-ingest|/etc/systemd/system/snap.lxd." in source
    assert "rule_id = 2902" in source
    assert "qemu-ga" in source
    assert "rule_id = 8046" in source
    assert "proxmox_authentication_success" in source
    assert "rule_id = 8328" in source
    assert "pilot-gitea" in source
    assert "WHERE rule_id IN (8418, 8420, 8425, 8426, 8429)" not in source
    assert "'pilot-db-01'" in source
