from __future__ import annotations

import base64
import json
import os
import shlex
import sys
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.soc_foundation_provision import Proxmox, required_env


VMID = 107
OPNSENSE_VMID = 103
REMOTE_ROOT = "/opt/siem/siem-solution"
WEB_ROOT = f"{REMOTE_ROOT}/services/web"
WEB_PYTHON = "/opt/siem/venv-web/bin/python"
OPNSENSE_TLS_HOSTNAME = "opnsense.internal"
OPNSENSE_TLS_SHA256 = "7556c198b3d0a52c15df4512c8795064361ff027c4a94b5e7725b204f13ace53"

FILES = (
    "services/web/main.py",
    "services/web/requirements-web.txt",
    "services/web/app/opnsense_control_runtime.py",
    "services/web/app/content_store.py",
    "services/web/app/incident_delivery_runtime.py",
    "services/web/app/security_services_runtime.py",
    "services/web/app/topology_layout_runtime.py",
    "services/web/app/topology_runtime.py",
    "services/web/app/deps.py",
    "services/web/app/routes/alerts.py",
    "services/web/app/routes/console_health_routes.py",
    "services/web/app/routes/console_security_services_routes.py",
    "services/web/app/routes/console_assets_routes.py",
    "correlation_rule_packs/siem_detection_pack_v1.json",
    "correlation_rule_packs/windows_activity_v1.json",
    "deploy/publish_current_fp_remediation.py",
    "frontend-react/package.json",
    "frontend-react/package-lock.json",
    "frontend-react/src/shell/api.ts",
    "frontend-react/src/shell/DashboardCanvas.tsx",
    "frontend-react/src/shell/types.ts",
    "frontend-react/src/shell/pages/SecurityControlPanel.tsx",
    "frontend-react/src/shell/pages/SecurityServicePage.tsx",
    "frontend-react/src/shell/pages/IncidentsPage.tsx",
    "frontend-react/src/shell/pages/TopologyPage.tsx",
    "frontend-react/src/shell/pages/topology/MaxGraphTopologyCanvas.tsx",
    "frontend-react/src/styles/page-families.css",
    "frontend-react/src/styles/shell.css",
)


def _remote_path(relative: str) -> str:
    if relative.startswith("frontend-react/"):
        return str(
            PurePosixPath(WEB_ROOT)
            / "frontend-react"
            / relative.removeprefix("frontend-react/")
        )
    return str(PurePosixPath(REMOTE_ROOT) / relative)


def _push_file(pve: Proxmox, relative: str, backup_root: str) -> None:
    source = ROOT / relative
    destination = _remote_path(relative)
    backup = str(PurePosixPath(backup_root) / destination.removeprefix("/").replace("/", "__"))
    encoded = base64.b64encode(source.read_bytes()).decode("ascii")
    release_id = PurePosixPath(backup_root).name
    temporary = f"/tmp/{release_id}-{source.name}.b64"
    staged = f"{destination}.{release_id}.tmp"
    pve.guest_exec(
        VMID,
        f"install -d -m 0750 {shlex.quote(backup_root)}; "
        f"install -d -o rdegon -g rdegon -m 0755 {shlex.quote(str(PurePosixPath(destination).parent))}; "
        f"if [ -f {shlex.quote(destination)} ]; then cp -a {shlex.quote(destination)} {shlex.quote(backup)}; fi; "
        f": > {shlex.quote(temporary)}",
    )
    for offset in range(0, len(encoded), 32_000):
        pve.guest_exec(
            VMID,
            f"printf %s {shlex.quote(encoded[offset:offset + 32_000])} >> {shlex.quote(temporary)}",
        )
    pve.guest_exec(
        VMID,
        f"base64 -d {shlex.quote(temporary)} > {shlex.quote(staged)}; "
        f"chmod 0644 {shlex.quote(staged)}; chown rdegon:rdegon {shlex.quote(staged)}; "
        f"mv -f {shlex.quote(staged)} {shlex.quote(destination)}; "
        f"rm -f {shlex.quote(temporary)}",
    )


def _push_bytes(pve: Proxmox, content: bytes, destination: str, *, mode: str) -> None:
    encoded = base64.b64encode(content).decode("ascii")
    temporary = f"{destination}.b64"
    pve.guest_exec(
        VMID,
        f"install -d -m 0755 {shlex.quote(str(PurePosixPath(destination).parent))}; "
        f": > {shlex.quote(temporary)}",
    )
    for offset in range(0, len(encoded), 32_000):
        pve.guest_exec(
            VMID,
            f"printf %s {shlex.quote(encoded[offset:offset + 32_000])} >> {shlex.quote(temporary)}",
        )
    pve.guest_exec(
        VMID,
        f"base64 -d {shlex.quote(temporary)} > {shlex.quote(destination)}; "
        f"rm -f {shlex.quote(temporary)}; chmod {mode} {shlex.quote(destination)}",
    )


def _opnsense_alt_hostname_script() -> str:
    return f"""#!/bin/sh
set -eu
config=/conf/config.xml
temporary=/conf/config.xml.siem-hostname
backup=/conf/backup/config-siem-hostname-$(date -u +%Y%m%dT%H%M%SZ).xml
cp "$config" "$backup"
php <<'PHP'
<?php
$config = '/conf/config.xml';
$temporary = '/conf/config.xml.siem-hostname';
$hostname = {OPNSENSE_TLS_HOSTNAME!r};
$xml = file_get_contents($config);
if ($xml === false || !preg_match('/<webgui>.*?<\\/webgui>/s', $xml, $match)) {{
    fwrite(STDERR, "webgui configuration is unavailable\\n");
    exit(1);
}}
$webgui = $match[0];
$values = [];
if (preg_match('/<althostnames>(.*?)<\\/althostnames>/s', $webgui, $current)) {{
    $decoded = html_entity_decode(trim($current[1]), ENT_QUOTES | ENT_XML1, 'UTF-8');
    $values = preg_split('/[\\s,]+/', $decoded, -1, PREG_SPLIT_NO_EMPTY);
}}
$present = false;
foreach ($values as $value) {{
    if (strcasecmp($value, $hostname) === 0) {{
        $present = true;
        break;
    }}
}}
if (!$present) {{
    $values[] = $hostname;
}}
$encoded = htmlspecialchars(implode(',', $values), ENT_QUOTES | ENT_XML1, 'UTF-8');
$line = '      <althostnames>' . $encoded . '</althostnames>';
if (preg_match('/<althostnames>.*?<\\/althostnames>/s', $webgui)) {{
    $webgui = preg_replace('/\\s*<althostnames>.*?<\\/althostnames>/s', "\\n" . $line, $webgui, 1);
}} else {{
    $webgui = preg_replace('/\\s*<\\/webgui>$/', "\\n" . $line . "\\n    </webgui>", $webgui, 1);
}}
$updated = preg_replace_callback(
    '/<webgui>.*?<\\/webgui>/s',
    static fn(array $unused): string => $webgui,
    $xml,
    1,
    $count
);
if ($count !== 1 || $updated === null || file_put_contents($temporary, $updated) === false) {{
    fwrite(STDERR, "unable to update webgui configuration\\n");
    exit(1);
}}
libxml_use_internal_errors(true);
if (simplexml_load_file($temporary) === false) {{
    fwrite(STDERR, "updated OPNsense configuration is not valid XML\\n");
    exit(1);
}}
?>
PHP
chown root:wheel "$temporary"
chmod 0644 "$temporary"
if cmp -s "$config" "$temporary"; then
  rm -f "$temporary"
else
  mv "$temporary" "$config"
  configctl webgui restart >/dev/null
fi
grep -q '<althostnames>[^<]*{OPNSENSE_TLS_HOSTNAME}[^<]*</althostnames>' "$config"
sockstat -4 -l | grep -Eq 'lighttpd.*(\\*:443|192\\.168\\.3\\.103:443)'
printf '%s\\n' OPNSENSE_ALT_HOSTNAME_READY
"""


def _read_serial_until(channel: object, marker: str, *, timeout_seconds: int) -> str:
    deadline = time.monotonic() + timeout_seconds
    output = ""
    while time.monotonic() < deadline:
        if channel.recv_ready():
            output += channel.recv(65_535).decode("utf-8", errors="replace")
            if marker in output:
                return output
        else:
            time.sleep(0.2)
    raise RuntimeError(f"Timed out waiting for OPNsense serial console marker: {marker}")


def _read_serial_until_any(
    channel: object,
    markers: tuple[str, ...],
    *,
    timeout_seconds: int,
) -> tuple[str, str]:
    deadline = time.monotonic() + timeout_seconds
    output = ""
    while time.monotonic() < deadline:
        if channel.recv_ready():
            output += channel.recv(65_535).decode("utf-8", errors="replace")
            for marker in markers:
                if marker in output:
                    return output, marker
        else:
            time.sleep(0.2)
    raise RuntimeError(
        "Timed out waiting for an OPNsense serial console prompt: "
        + output[-1_000:]
    )


def _configure_opnsense_alternate_hostname(pve: Proxmox) -> None:
    encoded = base64.b64encode(_opnsense_alt_hostname_script().encode("utf-8")).decode("ascii")
    channel = pve.client.invoke_shell(term="xterm", width=300, height=100)
    channel.settimeout(2)
    try:
        channel.send(f"qm terminal {OPNSENSE_VMID}\n")
        _read_serial_until(channel, "starting serial terminal", timeout_seconds=20)
        channel.send("\n")
        _, prompt = _read_serial_until_any(
            channel,
            ("Enter an option:", "root@opnsense-edge-01:", "\n# "),
            timeout_seconds=20,
        )
        if prompt == "Enter an option:":
            channel.send("8\n")
            _read_serial_until(channel, "root@opnsense-edge-01:", timeout_seconds=20)
            prompt = "root@opnsense-edge-01:"
        if prompt == "root@opnsense-edge-01:":
            channel.send("sh\n")
            _read_serial_until(channel, "# ", timeout_seconds=10)
        channel.send(": > /tmp/siem-opnsense-hostname.b64\n")
        _read_serial_until(channel, "# ", timeout_seconds=10)
        for offset in range(0, len(encoded), 200):
            chunk = encoded[offset : offset + 200]
            channel.send(
                f"printf %s {shlex.quote(chunk)} >> /tmp/siem-opnsense-hostname.b64\n"
            )
            _read_serial_until(channel, "# ", timeout_seconds=10)
        channel.send(
            "base64 -d /tmp/siem-opnsense-hostname.b64 > /tmp/siem-opnsense-hostname.sh; "
            "sh /tmp/siem-opnsense-hostname.sh; rc=$?; "
            "rm -f /tmp/siem-opnsense-hostname.b64 /tmp/siem-opnsense-hostname.sh; "
            "echo __SIEM_OPNSENSE_HOSTNAME_DONE__:$rc\n"
        )
        output = _read_serial_until(
            channel,
            "__SIEM_OPNSENSE_HOSTNAME_DONE__:",
            timeout_seconds=90,
        )
        if "__SIEM_OPNSENSE_HOSTNAME_DONE__:0" not in output:
            raise RuntimeError(
                "Unable to configure the trusted OPNsense hostname: "
                + output[-2_000:]
            )
        channel.send("exit\n")
        time.sleep(0.5)
        channel.send("exit\n")
        time.sleep(0.5)
        channel.send("\x0f")
    finally:
        try:
            channel.send("\x03")
            channel.send("exit\nexit\n")
            channel.send("\x0f")
        except Exception:
            pass
        channel.close()


def _install_opnsense_trust(pve: Proxmox) -> None:
    opnsense_host = required_env("SIEM_OPNSENSE_HOST", "https://192.168.3.103")
    opnsense_ip = opnsense_host.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    expected_fingerprint = str(
        os.getenv("SIEM_OPNSENSE_TLS_SHA256") or OPNSENSE_TLS_SHA256
    ).strip().lower().replace(":", "")
    certificate_path = "/usr/local/share/ca-certificates/opnsense-internal.crt"
    temporary_path = "/tmp/opnsense-internal.crt"
    script = f"""
set -euo pipefail
echo | openssl s_client \
  -connect {shlex.quote(f"{opnsense_ip}:443")} \
  -servername {shlex.quote(OPNSENSE_TLS_HOSTNAME)} \
  -showcerts 2>/dev/null |
awk '
  /-----BEGIN CERTIFICATE-----/ && !done {{ capture=1 }}
  capture {{ print }}
  /-----END CERTIFICATE-----/ && capture {{ done=1; exit }}
' > {shlex.quote(temporary_path)}
actual="$(openssl x509 -in {shlex.quote(temporary_path)} -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')"
test "$actual" = {shlex.quote(expected_fingerprint)}
openssl x509 -in {shlex.quote(temporary_path)} -noout -checkend 86400 >/dev/null
install -m 0644 {shlex.quote(temporary_path)} {shlex.quote(certificate_path)}
rm -f {shlex.quote(temporary_path)}
update-ca-certificates >/dev/null
sed -i '/[[:space:]]opnsense\\.internal\\([[:space:]]\\|$\\)/d' /etc/hosts
printf '%s %s\\n' {shlex.quote(opnsense_ip)} {shlex.quote(OPNSENSE_TLS_HOSTNAME)} >> /etc/hosts
curl --fail --silent --show-error \
  --cacert {shlex.quote(certificate_path)} \
  --resolve {shlex.quote(f"{OPNSENSE_TLS_HOSTNAME}:443:{opnsense_ip}")} \
  {shlex.quote(f"https://{OPNSENSE_TLS_HOSTNAME}/")} |
grep -q 'name="usernamefld"'
"""
    pve.guest_exec(VMID, script, timeout=180)


def _configure_opnsense_secret(pve: Proxmox) -> None:
    password = required_env("SIEM_OPNSENSE_ROOT_PASSWORD")
    secret_file = "/tmp/siem-opnsense-password"
    script_file = "/tmp/siem-configure-opnsense-secret.py"
    script = (
        "import base64\n"
        "import os\n"
        "import sys\n"
        "from pathlib import Path\n"
        "sys.path.insert(0, str(Path.cwd()))\n"
        "env_path = Path('/etc/siem/web.env')\n"
        "for raw in env_path.read_text(encoding='utf-8').splitlines():\n"
        "    if raw.strip() and not raw.lstrip().startswith('#') and '=' in raw:\n"
        "        key, value = raw.split('=', 1)\n"
        "        os.environ.setdefault(key.strip(), value.strip())\n"
        "from app.secret_runtime import _vault_request\n"
        "password = Path(sys.argv[1]).read_text(encoding='utf-8')\n"
        "operator = __import__('json').loads(Path('/etc/siem/vault-operator.json').read_text(encoding='utf-8'))\n"
        "root_token = str(operator.get('root_token') or '').strip()\n"
        "if not root_token:\n"
        "    raise RuntimeError('Vault root token is unavailable')\n"
        "_vault_request('/v1/kv/data/siem/opnsense', method='POST', payload={'data': {'password': password}}, token=root_token)\n"
        "updates = {\n"
        f"    'SIEM_OPNSENSE_HOST': {'https://' + OPNSENSE_TLS_HOSTNAME!r},\n"
        f"    'SIEM_OPNSENSE_USER': {required_env('SIEM_OPNSENSE_USER', 'root')!r},\n"
        "    'SIEM_OPNSENSE_ROOT_PASSWORD_REF': 'vault://kv/siem/opnsense#password',\n"
        "    'SIEM_OPNSENSE_VERIFY_TLS': '1',\n"
        "    'SIEM_OPNSENSE_CA_FILE': '/usr/local/share/ca-certificates/opnsense-internal.crt',\n"
        "}\n"
        "lines = env_path.read_text(encoding='utf-8').splitlines()\n"
        "seen = set()\n"
        "rendered = []\n"
        "for line in lines:\n"
        "    key = line.split('=', 1)[0].strip() if '=' in line and not line.lstrip().startswith('#') else ''\n"
        "    if key in updates:\n"
        "        rendered.append(f'{key}={updates[key]}')\n"
        "        seen.add(key)\n"
        "    elif key != 'SIEM_OPNSENSE_ROOT_PASSWORD':\n"
        "        rendered.append(line)\n"
        "for key, value in updates.items():\n"
        "    if key not in seen:\n"
        "        rendered.append(f'{key}={value}')\n"
        "temporary = env_path.with_suffix('.security-controls.tmp')\n"
        "temporary.write_text('\\n'.join(rendered).rstrip() + '\\n', encoding='utf-8')\n"
        "os.chmod(temporary, 0o600)\n"
        "temporary.replace(env_path)\n"
    )
    _push_bytes(pve, password.encode("utf-8"), secret_file, mode="0600")
    _push_bytes(pve, script.encode("utf-8"), script_file, mode="0700")
    pve.guest_exec(
        VMID,
        f"set -e; cd {shlex.quote(WEB_ROOT)}; "
        f"{shlex.quote(WEB_PYTHON)} {shlex.quote(script_file)} {shlex.quote(secret_file)}; "
        f"rm -f {shlex.quote(script_file)} {shlex.quote(secret_file)}",
        timeout=180,
    )


def main() -> int:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_root = f"/var/backups/siem/security-controls-{stamp}"
    with Proxmox() as pve:
        for relative in FILES:
            _push_file(pve, relative, backup_root)
        if str(os.getenv("SIEM_OPNSENSE_ROOT_PASSWORD") or "").strip():
            _configure_opnsense_alternate_hostname(pve)
            _install_opnsense_trust(pve)
            _configure_opnsense_secret(pve)
        output = pve.guest_exec(
            VMID,
            "set -euo pipefail; "
            f"cd {shlex.quote(WEB_ROOT)}; "
            f"{shlex.quote(WEB_PYTHON)} -m pip install --disable-pip-version-check --no-input -r requirements-web.txt >/dev/null; "
            f"{shlex.quote(WEB_PYTHON)} -m py_compile main.py app/opnsense_control_runtime.py "
            "app/content_store.py app/topology_layout_runtime.py app/topology_runtime.py "
            "app/deps.py app/routes/alerts.py app/routes/console_health_routes.py "
            "app/routes/console_security_services_routes.py app/routes/console_assets_routes.py; "
            f"cd {shlex.quote(REMOTE_ROOT)}; "
            f"{shlex.quote(WEB_PYTHON)} deploy/publish_current_fp_remediation.py >/tmp/siem-current-fp-publish.json; "
            f"cd {shlex.quote(WEB_ROOT + '/frontend-react')}; "
            "runuser -u rdegon -- npm ci --no-audit --no-fund >/dev/null; "
            "runuser -u rdegon -- npm run build >/dev/null; "
            "systemctl restart siem-web; "
            "for attempt in $(seq 1 30); do curl -kfsS --max-time 3 https://127.0.0.1/healthz >/dev/null && break; sleep 1; done; "
            "systemctl is-active siem-web nginx; "
            "curl -kfsS --max-time 5 https://127.0.0.1/healthz",
            timeout=900,
        )
    print(
        json.dumps(
            {
                "vmid": VMID,
                "files": len(FILES),
                "backup": backup_root,
                "health": output.strip().splitlines(),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
