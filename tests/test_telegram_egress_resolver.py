from pathlib import Path

from deploy.common.telegram_egress_resolver import (
    HOSTS_MARKER,
    rewrite_hosts,
    unique_candidates,
)
from deploy.pilot_db_incident_bot_deploy import VM4_HOST, WEB_PUBLIC_URL
from deploy.pilot_sso_correlation_wave_deploy import (
    KEYCLOAK_HOST,
    KEYCLOAK_ISSUER,
    KEYCLOAK_PUBLIC_HOST,
)


def test_unique_candidates_filters_invalid_and_duplicates() -> None:
    assert unique_candidates(
        ["149.154.167.220", "invalid", "149.154.167.220"],
        ("149.154.166.110",),
    ) == ["149.154.167.220", "149.154.166.110"]


def test_rewrite_hosts_replaces_previous_managed_address(tmp_path: Path) -> None:
    hosts = tmp_path / "hosts"
    hosts.write_text(
        "127.0.0.1 localhost\n"
        f"149.154.166.110 api.telegram.org {HOSTS_MARKER}\n",
        encoding="utf-8",
    )

    rewrite_hosts(hosts, "149.154.167.220")

    assert hosts.read_text(encoding="utf-8") == (
        "127.0.0.1 localhost\n"
        f"149.154.167.220 api.telegram.org {HOSTS_MARKER}\n"
    )


def test_incident_bot_uses_internal_api_and_public_links() -> None:
    assert VM4_HOST == "10.20.10.107"
    assert WEB_PUBLIC_URL == "https://192.168.3.102"


def test_keycloak_uses_internal_backchannel_and_public_issuer() -> None:
    assert KEYCLOAK_HOST == "10.20.10.107"
    assert KEYCLOAK_PUBLIC_HOST == "192.168.3.102"
    assert KEYCLOAK_ISSUER == "https://192.168.3.102/realms/siem"
