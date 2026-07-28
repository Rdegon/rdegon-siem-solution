from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_keycloak_cutover_updates_browser_and_backchannel_endpoints() -> None:
    source = (
        ROOT
        / "deploy"
        / "network_relocation"
        / "migrate_keycloak_public_endpoint.sh"
    ).read_text(encoding="utf-8")

    assert 'upsert_env_value "${env_file}" "KC_HOSTNAME" "${public_base}"' in source
    assert '"SIEM_OIDC_ISSUER_URL" "${issuer}"' in source
    assert "SIEM_OIDC_BACKCHANNEL_DISCOVERY_URL" in source
    assert "http://127.0.0.1:8081/realms/${realm}" in source
    assert "SIEM_OIDC_TOKEN_URL" in source
    assert "SIEM_OIDC_USERINFO_URL" in source
    assert "keycloak_admin_runtime import get_client, save_client" in source
    assert "system-network-cutover" in source
    assert "kcadm.sh" not in source
    assert "systemctl restart siem-keycloak" in source
    assert "Unexpected Keycloak issuer" in source
