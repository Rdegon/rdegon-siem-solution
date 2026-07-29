from pathlib import Path

from deploy.configure_proxmox_startup_order import (
    CORE_STARTUP,
    PLATFORM_LXC_STARTUP,
    PLATFORM_QEMU_STARTUP,
    SYSTEM_ASSETS,
)


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
        "incident-telegram-bot",
        "opensearch",
        "velociraptor",
        "clamav-daemon",
        "falco",
        "step-ca",
        "minio",
        "minecraft",
        "status.php",
        "navidrome",
    ):
        assert token in script
    assert "flock -n" in script
    assert "repair_guest" in script
    assert "PLATFORM_QEMU_GUESTS" in script
    assert "PLATFORM_LXC_GUESTS" in script
    assert "START_ONLY_QEMU_GUESTS=(109 111)" in script


def test_startup_inventory_covers_all_expected_soc_guests() -> None:
    assert set(PLATFORM_QEMU_STARTUP) == {
        109,
        111,
        122,
        123,
        124,
        125,
        127,
        130,
        131,
    }
    assert set(PLATFORM_LXC_STARTUP) == {100, 120, 121, 128, 129, 132, 133}


def test_reconcile_assets_are_installed_from_repository() -> None:
    destinations = {destination for _, destination, _ in SYSTEM_ASSETS}
    assert "/usr/local/sbin/siem-cold-start-reconcile" in destinations
    assert "/etc/systemd/system/siem-cold-start-reconcile.service" in destinations
    assert "/etc/systemd/system/siem-cold-start-reconcile.timer" in destinations
