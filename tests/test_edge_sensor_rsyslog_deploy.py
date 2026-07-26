from pathlib import Path

from deploy import edge_sensor_rsyslog_deploy as deployer


ROOT = Path(__file__).resolve().parents[1]


def test_suricata_imfile_survives_truncation() -> None:
    payload = (ROOT / "deploy/common/91-suricata-imfile.conf").read_text(encoding="utf-8")

    assert payload.count('reopenOnTruncate="on"') == 2
    assert 'File="/var/log/suricata/eve.json"' in payload
    assert 'File="/var/log/suricata/fast.log"' in payload


def test_edge_uses_one_durable_forward_queue() -> None:
    payload = (ROOT / "deploy/common/90-edge-siem-forward.conf").read_text(encoding="utf-8")

    assert payload.count('target="10.20.10.104"') == 1
    assert 'queue.saveOnShutdown="on"' in payload
    assert 'queue.maxDiskSpace="2g"' in payload
    assert deployer.LEGACY_FORWARD != deployer.REMOTE_FORWARD
