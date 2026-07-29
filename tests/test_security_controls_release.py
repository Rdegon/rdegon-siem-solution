from pathlib import Path

from deploy.security_controls_release import _opnsense_alt_hostname_script


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "deploy" / "security_controls_release.py").read_text(
    encoding="utf-8"
)


def test_opnsense_release_pins_and_enables_tls_verification() -> None:
    assert "OPNSENSE_TLS_HOSTNAME = \"opnsense.internal\"" in SOURCE
    assert "OPNSENSE_TLS_SHA256" in SOURCE
    assert "openssl x509" in SOURCE
    assert "update-ca-certificates" in SOURCE
    assert "'SIEM_OPNSENSE_VERIFY_TLS': '1'" in SOURCE
    assert "'SIEM_OPNSENSE_CA_FILE':" in SOURCE
    assert "'SIEM_OPNSENSE_VERIFY_TLS': '0'" not in SOURCE
    assert "_install_opnsense_trust(pve)" in SOURCE


def test_opnsense_hostname_update_preserves_webgui_security_settings() -> None:
    script = _opnsense_alt_hostname_script()
    assert "<althostnames>" in script
    assert "opnsense.internal" in script
    assert "config-siem-hostname-" in script
    assert "simplexml_load_file" in script
    assert "nodnsrebindcheck" not in script
    assert "<interfaces>" not in script
