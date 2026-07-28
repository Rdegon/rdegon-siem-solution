from deploy import ingest_health_qga_release as release


def test_ingest_health_release_targets_ingest_runtime() -> None:
    assert release.VMID == 104
    assert release.RELEASE_FILES == ("services/ingest/redis_client.py",)
    assert release.INGEST_PYTHON.endswith("/venv-ingest/bin/python")


def test_ingest_health_release_uses_ingest_health_endpoint() -> None:
    source = (release.ROOT / "deploy/ingest_health_qga_release.py").read_text(encoding="utf-8")
    assert "https://127.0.0.1/health" in source
    assert "https://127.0.0.1/healthz" not in source
