from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_misp_vm_keeps_full_memory_during_feed_sync() -> None:
    source = (ROOT / "deploy" / "soc_misp_vm_provision.py").read_text(
        encoding="utf-8"
    )

    assert "MEMORY_MB = 8192" in source
    assert "BALLOON_MB = 8192" in source
    assert "qm set {VMID} --memory {MEMORY_MB} --balloon {BALLOON_MB}" in source
    assert "--balloon 6144" not in source
