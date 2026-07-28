import importlib.util
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "deploy/security/opnsense/set_system_hostname.py"
)
SPEC = importlib.util.spec_from_file_location("set_system_hostname", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_general_form_payload_preserves_current_settings() -> None:
    payload, hostname = MODULE._form_payload(
        """
        <form method="post">
          <input type="hidden" name="csrf-token" value="token">
          <input name="hostname" value="opnsense-staging">
          <input name="domain" value="lab.home.arpa">
          <select name="timezone"><option value="UTC">UTC</option>
            <option value="Europe/Moscow" selected>Europe/Moscow</option></select>
          <input type="checkbox" name="prefer_ipv4" value="yes" checked>
          <input type="checkbox" name="dnsallowoverride" value="yes">
          <input type="submit" name="Submit" value="Save">
        </form>
        """
    )

    assert hostname == "opnsense-staging"
    assert payload["csrf-token"] == "token"
    assert payload["domain"] == "lab.home.arpa"
    assert payload["timezone"] == "Europe/Moscow"
    assert payload["prefer_ipv4"] == "yes"
    assert "dnsallowoverride" not in payload
