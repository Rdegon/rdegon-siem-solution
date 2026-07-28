from __future__ import annotations

import argparse
import json
import os
import re
from typing import Any

from bs4 import BeautifulSoup, Tag

try:
    from deploy.security.opnsense.promote_internal_ngfw import DEFAULT_HOST, OPNsense
except ModuleNotFoundError:
    from promote_internal_ngfw import DEFAULT_HOST, OPNsense


GENERAL_PATH = "/system_general.php"
DEFAULT_HOSTNAME = "opnsense-edge-01"


def _form_payload(html: str) -> tuple[dict[str, Any], str]:
    soup = BeautifulSoup(html, "html.parser")
    hostname_input = soup.find("input", {"name": "hostname"})
    if not isinstance(hostname_input, Tag):
        raise RuntimeError("OPNsense general settings form does not contain hostname")
    form = hostname_input.find_parent("form")
    if not isinstance(form, Tag):
        raise RuntimeError("OPNsense hostname input is not inside a form")
    payload: dict[str, Any] = {}
    for control in form.find_all(["input", "select", "textarea"]):
        if not isinstance(control, Tag):
            continue
        name = str(control.get("name") or "").strip()
        if not name:
            continue
        if control.name == "input":
            input_type = str(control.get("type") or "text").lower()
            if input_type in {"button", "file", "image", "reset"}:
                continue
            if input_type in {"checkbox", "radio"} and not control.has_attr("checked"):
                continue
            payload[name] = str(control.get("value") or "")
        elif control.name == "select":
            selected = [
                str(option.get("value") or option.get_text(strip=True))
                for option in control.find_all("option")
                if isinstance(option, Tag) and option.has_attr("selected")
            ]
            if control.has_attr("multiple") or name.endswith("[]"):
                payload[name] = selected
            elif selected:
                payload[name] = selected[0]
            else:
                first = control.find("option")
                payload[name] = (
                    str(first.get("value") or first.get_text(strip=True))
                    if isinstance(first, Tag)
                    else ""
                )
        else:
            payload[name] = control.get_text()
    return payload, str(hostname_input.get("value") or "").strip()


def reconcile_hostname(
    client: OPNsense,
    *,
    desired_hostname: str,
    apply: bool,
) -> dict[str, Any]:
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", desired_hostname):
        raise ValueError("hostname must be a lowercase DNS label")
    response = client.session.get(
        client.host + GENERAL_PATH,
        verify=client.verify_tls,
        timeout=30,
    )
    response.raise_for_status()
    payload, current_hostname = _form_payload(response.text)
    result = {
        "mode": "apply" if apply else "plan",
        "current_hostname": current_hostname,
        "desired_hostname": desired_hostname,
        "changed": current_hostname != desired_hostname,
    }
    if not apply or current_hostname == desired_hostname:
        return result
    payload["hostname"] = desired_hostname
    payload["Submit"] = payload.get("Submit") or "Save"
    response = client.session.post(
        client.host + GENERAL_PATH,
        data=payload,
        verify=client.verify_tls,
        timeout=60,
        allow_redirects=True,
    )
    response.raise_for_status()
    verify_response = client.session.get(
        client.host + GENERAL_PATH,
        verify=client.verify_tls,
        timeout=30,
    )
    verify_response.raise_for_status()
    _, applied_hostname = _form_payload(verify_response.text)
    if applied_hostname != desired_hostname:
        raise RuntimeError(
            f"OPNsense hostname update did not persist: {applied_hostname!r}"
        )
    result["applied_hostname"] = applied_hostname
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Set the production OPNsense hostname.")
    parser.add_argument("--host", default=os.getenv("SIEM_OPNSENSE_HOST", DEFAULT_HOST))
    parser.add_argument("--username", default=os.getenv("SIEM_OPNSENSE_USER"))
    parser.add_argument("--password", default=os.getenv("SIEM_OPNSENSE_ROOT_PASSWORD"))
    parser.add_argument("--hostname", default=DEFAULT_HOSTNAME)
    parser.add_argument("--verify-tls", action="store_true")
    parser.add_argument("--apply", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.username or not args.password:
        raise SystemExit(
            "SIEM_OPNSENSE_USER and SIEM_OPNSENSE_ROOT_PASSWORD are required"
        )
    client = OPNsense(
        args.host,
        args.username,
        args.password,
        verify_tls=args.verify_tls,
    )
    client.login()
    print(
        json.dumps(
            reconcile_hostname(
                client,
                desired_hostname=args.hostname,
                apply=args.apply,
            ),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
