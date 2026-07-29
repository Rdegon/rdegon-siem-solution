from pathlib import Path

from deploy.configure_proxmox_startup_order import CORE_STARTUP, SYSTEM_ASSETS


ROOT = Path(__file__).resolve().parents[1]


def test_core_startup_includes_router_and_full_siem_pipeline() -> None:
    assert tuple(CORE_STARTUP) == (102, 103, 106, 108, 105, 104, 107)
    assert CORE_STARTUP[103].startswith("order=20")
    assert CORE_STARTUP[107].startswith("order=50")


def test_reconcile_checks_real_services_and_health_endpoint() -> None:
    script = (ROOT / "deploy" / "proxmox_cold_start_reconcile.sh").read_text(
        encoding="utf-8"
    )
    for token in (
        "siem-kafka",
        "siem-normalizer",
        "siem-filter",
        "clickhouse-client",
        "siem-stream-corr",
        "siem-ingest",
        "siem-vault",
        "siem-keycloak",
        "https://127.0.0.1/healthz",
    ):
        assert token in script
    assert "flock -n" in script
    assert "repair_guest" in script


def test_reconcile_assets_are_installed_from_repository() -> None:
    destinations = {destination for _, destination, _ in SYSTEM_ASSETS}
    assert "/usr/local/sbin/siem-cold-start-reconcile" in destinations
    assert "/etc/systemd/system/siem-cold-start-reconcile.service" in destinations
    assert "/etc/systemd/system/siem-cold-start-reconcile.timer" in destinations
