from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_qga_calibration_release_covers_all_siem_nodes_and_full_pack() -> None:
    source = (ROOT / "deploy" / "soc_rule_calibration_qga_release.py").read_text(
        encoding="utf-8"
    )

    assert "QEMU_RUNTIME_IDS = (102, 104, 105, 106, 107, 108, 122, 123, 124, 125, 127, 130, 131)" in source
    assert "CONTAINER_RUNTIME_IDS = (100, 120, 121, 128, 129, 132, 133)" in source
    assert "services/web/app/host_runtime_pipeline.py" in source
    assert "correlation_rule_packs/siem_detection_pack_v1.json" in source
    assert "publish_assignment_detection_pack.py" in source
    assert "siem-host-runtime-agent.service" in source
    assert "QGA" not in source
