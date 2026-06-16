from __future__ import annotations

import json
import os
import secrets
import shlex
import sys
from pathlib import Path

import paramiko


ROOT = Path(__file__).resolve().parents[1]


def _stdout_setup() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                pass


def _env(name: str, default: str = "") -> str:
    return str(os.getenv(name, default) or default).strip()


def _required_env(name: str) -> str:
    value = _env(name)
    if value:
        return value
    raise RuntimeError(f"Missing required environment variable: {name}")


def _ssh_client(host: str, user: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        username=user,
        password=password,
        timeout=20,
        banner_timeout=20,
        auth_timeout=20,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def _run(client: paramiko.SSHClient, command: str, *, sudo_password: str = "", use_sudo: bool = False) -> tuple[int, str, str]:
    wrapped = f"sudo -S -p '' bash -lc {shlex.quote(command)}" if use_sudo else command
    stdin, stdout, stderr = client.exec_command(wrapped, get_pty=use_sudo)
    if use_sudo:
        stdin.write(f"{sudo_password}\n")
        stdin.flush()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return stdout.channel.recv_exit_status(), out, err


def _require_success(code: int, out: str, err: str, message: str) -> str:
    if code != 0:
        raise RuntimeError(f"{message}: {err.strip() or out.strip()}")
    return out


def _strip_sudo_echo(text: str, sudo_password: str) -> str:
    if not sudo_password:
        return str(text or "")
    lines = []
    for raw_line in str(text or "").replace("\r", "\n").split("\n"):
        if raw_line.strip() == sudo_password:
            continue
        lines.append(raw_line)
    return "\n".join(lines)


def _parse_env_text(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def _extract_json_text(text: str) -> str:
    payload = str(text or "").strip()
    object_start = payload.find("{")
    array_start = payload.find("[")
    starts = [index for index in (object_start, array_start) if index >= 0]
    if starts:
        return payload[min(starts) :].strip()
    return payload


def _read_remote_env(client: paramiko.SSHClient, path: str, *, sudo_password: str) -> dict[str, str]:
    code, out, err = _run(client, f"cat {shlex.quote(path)}", sudo_password=sudo_password, use_sudo=True)
    text = _require_success(code, out, err, f"Unable to read {path}")
    return _parse_env_text(text)


def _configure_keycloak_nextcloud_client(
    client: paramiko.SSHClient,
    *,
    vm4_password: str,
    realm_name: str,
    admin_user: str,
    admin_password: str,
    nextcloud_base_url: str,
    nextcloud_client_id: str,
    nextcloud_client_secret: str,
) -> dict[str, object]:
    base = nextcloud_base_url.rstrip("/")
    redirect_uris = [
        f"{base}/apps/user_oidc/code",
        f"{base}/index.php/apps/user_oidc/code",
    ]
    client_payload = {
        "clientId": nextcloud_client_id,
        "name": "Nextcloud",
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "secret": nextcloud_client_secret,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "frontchannelLogout": True,
        "redirectUris": redirect_uris,
        "webOrigins": [base],
        "rootUrl": base,
        "baseUrl": base,
        "attributes": {
            "post.logout.redirect.uris": "##".join(redirect_uris),
        },
    }
    client_payload_json = json.dumps(client_payload, ensure_ascii=False)
    script = f"""
set -eu
KC_BIN=/opt/siem/keycloak/current/bin
SERVER=http://127.0.0.1:8081
$KC_BIN/kcadm.sh config credentials --server "$SERVER" --realm master --user {shlex.quote(admin_user)} --password {shlex.quote(admin_password)} >/dev/null
cat > /tmp/nextcloud-client.json <<'JSON'
{client_payload_json}
JSON
client_uuid=$($KC_BIN/kcadm.sh get clients -r {shlex.quote(realm_name)} -q clientId={shlex.quote(nextcloud_client_id)} | python3 -c "import json,sys; data=json.load(sys.stdin); print(data[0]['id'] if data else '')")
if [ -z "$client_uuid" ]; then
  $KC_BIN/kcadm.sh create clients -r {shlex.quote(realm_name)} -f /tmp/nextcloud-client.json >/dev/null
  client_uuid=$($KC_BIN/kcadm.sh get clients -r {shlex.quote(realm_name)} -q clientId={shlex.quote(nextcloud_client_id)} | python3 -c "import json,sys; data=json.load(sys.stdin); print(data[0]['id'] if data else '')")
fi
$KC_BIN/kcadm.sh update clients/$client_uuid -r {shlex.quote(realm_name)} -f /tmp/nextcloud-client.json >/dev/null
mapper_uuid=$($KC_BIN/kcadm.sh get clients/$client_uuid/protocol-mappers/models -r {shlex.quote(realm_name)} | python3 -c "import json,sys; data=json.load(sys.stdin); print(next((item['id'] for item in data if item.get('name')=='groups'), ''))")
if [ -z "$mapper_uuid" ]; then
  $KC_BIN/kcadm.sh create clients/$client_uuid/protocol-mappers/models -r {shlex.quote(realm_name)} \\
    -s name=groups \\
    -s protocol=openid-connect \\
    -s protocolMapper=oidc-group-membership-mapper \\
    -s 'config.\"full.path\"=false' \\
    -s 'config.\"id.token.claim\"=true' \\
    -s 'config.\"access.token.claim\"=true' \\
    -s 'config.\"userinfo.token.claim\"=true' \\
    -s 'config.\"claim.name\"=groups' >/dev/null
fi
client_json=$($KC_BIN/kcadm.sh get clients/$client_uuid -r {shlex.quote(realm_name)})
printf '%s' "$client_json"
"""
    code, out, err = _run(client, script, sudo_password=vm4_password, use_sudo=True)
    raw_payload = _require_success(code, out, err, "Unable to configure Nextcloud OIDC client in Keycloak") or "{}"
    payload = json.loads(_extract_json_text(_strip_sudo_echo(raw_payload, vm4_password)) or "{}")
    return {
        "client_id": str(payload.get("clientId") or nextcloud_client_id),
        "redirect_uris": payload.get("redirectUris") or redirect_uris,
        "base_url": str(payload.get("baseUrl") or base),
    }


def _configure_nextcloud_oidc(
    client: paramiko.SSHClient,
    *,
    nextcloud_vmid: str,
    nextcloud_base_url: str,
    discovery_uri: str,
    client_id: str,
    client_secret: str,
) -> dict[str, object]:
    base = nextcloud_base_url.rstrip("/")
    provider_identifier = "siem-keycloak"
    compatibility_patch_script = r"""
from pathlib import Path
import re

HELPER = "\n\tprivate function serverMajorVersion(): int {\n\t\treturn (int) explode('.', (string) $this->config->getSystemValue('version', '0.0.0'))[0];\n\t}\n"
HELPER_PATTERN = re.compile(
    r"\n[ \t]*private function serverMajorVersion\(\): int \{\n"
    r"[ \t]*return \(int\) explode\('\.', \(string\) \$this->config->getSystemValue\('version', '0\.0\.0'\)\)\[0\];\n"
    r"[ \t]*\}\n",
    re.MULTILINE,
)


def _drop_import(text: str) -> str:
    return text.replace("use OCP\\ServerVersion;\n", "")


def _drop_property(text: str) -> str:
    return text.replace("private ServerVersion $serverVersion,\n", "")


def _replace_call(text: str, threshold: int) -> str:
    return text.replace(
        f"$this->serverVersion->getMajorVersion() >= {threshold}",
        f"$this->serverMajorVersion() >= {threshold}",
    )


def _ensure_config_property(text: str) -> str:
    if "private IConfig $config," in text:
        return text
    return text.replace("\n\t\tIConfig $config,\n", "\n\t\tprivate IConfig $config,\n")


def _dedupe_helper(text: str) -> str:
    matches = list(HELPER_PATTERN.finditer(text))
    if len(matches) <= 1:
        return text
    first = matches[0].group(0)
    text = HELPER_PATTERN.sub("", text)
    insert_at = text.rfind("}")
    if insert_at < 0:
        return text + first
    return text[:insert_at] + first + text[insert_at:]


def _ensure_helper(text: str) -> str:
    if "private function serverMajorVersion(): int" in text:
        return _dedupe_helper(text)
    insert_at = text.rfind("}")
    if insert_at < 0:
        return text + HELPER
    return _dedupe_helper(text[:insert_at] + HELPER + text[insert_at:])


def _normalize(text: str, *, threshold: int, needs_config_property: bool = False) -> str:
    text = _drop_import(text)
    text = _drop_property(text)
    text = _replace_call(text, threshold)
    if needs_config_property:
        text = _ensure_config_property(text)
    text = _ensure_helper(text)
    return text


FILES = {
    "/var/www/nextcloud/apps/user_oidc/lib/User/Backend.php": dict(threshold=34, needs_config_property=False),
    "/var/www/nextcloud/apps/user_oidc/lib/Controller/LoginController.php": dict(threshold=32, needs_config_property=False),
    "/var/www/nextcloud/apps/user_oidc/lib/Controller/Id4meController.php": dict(threshold=32, needs_config_property=True),
}

for raw_path, params in FILES.items():
    path = Path(raw_path)
    original = path.read_text(encoding="utf-8")
    updated = _normalize(original, **params)
    if updated != original:
        path.write_text(updated, encoding="utf-8")
"""
    patch_runner = f"python3 - <<'PY'\n{compatibility_patch_script}\nPY"
    patch_command = (
        f"timeout 120 pct exec {shlex.quote(nextcloud_vmid)} -- bash -lc "
        f"{shlex.quote(patch_runner)}"
    )
    commands = [
        patch_command,
        f"timeout 180 pct exec {shlex.quote(nextcloud_vmid)} -- runuser -u www-data -- /usr/bin/php /var/www/nextcloud/occ app:install user_oidc",
        f"timeout 60 pct exec {shlex.quote(nextcloud_vmid)} -- runuser -u www-data -- /usr/bin/php /var/www/nextcloud/occ app:enable user_oidc",
        (
            f"timeout 60 pct exec {shlex.quote(nextcloud_vmid)} -- runuser -u www-data -- "
            f"/usr/bin/php /var/www/nextcloud/occ config:app:set --value=0 --type=boolean user_oidc allow_insecure_http"
        ),
        (
            f"timeout 60 pct exec {shlex.quote(nextcloud_vmid)} -- runuser -u www-data -- "
            f"/usr/bin/php /var/www/nextcloud/occ config:app:set --value=1 --type=boolean user_oidc httpclient.allowselfsigned"
        ),
        (
            f"timeout 60 pct exec {shlex.quote(nextcloud_vmid)} -- runuser -u www-data -- "
            f"/usr/bin/php /var/www/nextcloud/occ config:app:set --value=0 --type=string user_oidc allow_multiple_user_backends"
        ),
        (
            f"timeout 60 pct exec {shlex.quote(nextcloud_vmid)} -- runuser -u www-data -- "
            f"/usr/bin/php /var/www/nextcloud/occ config:system:set user_oidc httpclient.allowselfsigned --type=boolean --value=true"
        ),
        (
            f"timeout 120 pct exec {shlex.quote(nextcloud_vmid)} -- runuser -u www-data -- "
            f"/usr/bin/php /var/www/nextcloud/occ user_oidc:provider {shlex.quote(provider_identifier)} "
            f"--clientid={shlex.quote(client_id)} "
            f"--clientsecret={shlex.quote(client_secret)} "
            f"--discoveryuri={shlex.quote(discovery_uri)} "
            f"--scope={shlex.quote('openid email profile')} "
            f"--mapping-uid={shlex.quote('preferred_username')} "
            f"--mapping-display-name={shlex.quote('name')} "
            f"--mapping-email={shlex.quote('email')} "
            f"--mapping-groups={shlex.quote('groups')} "
            f"--group-provisioning=1 "
            f"--group-whitelist-regex={shlex.quote('^(nextcloud-users|nextcloud-admins)$')} "
            f"--group-restrict-login-to-whitelist=1 "
            f"--unique-uid=0 "
            f"--output=json_pretty"
        ),
        (
            f"timeout 60 pct exec {shlex.quote(nextcloud_vmid)} -- runuser -u www-data -- "
            f"/usr/bin/php /var/www/nextcloud/occ config:system:set allow_local_remote_servers --type=boolean --value=true"
        ),
        (
            f"timeout 60 pct exec {shlex.quote(nextcloud_vmid)} -- runuser -u www-data -- "
            f"/usr/bin/php /var/www/nextcloud/occ config:system:set trusted_domains 10 --value={shlex.quote(base.replace('https://', '').replace('http://', ''))}"
        ),
    ]
    outputs: list[str] = []
    for command in commands:
        code, out, err = _run(client, command)
        text = (out or err).strip()
        if code != 0:
            if "already enabled" in text.lower() or "already installed" in text.lower():
                outputs.append(text)
                continue
            raise RuntimeError(f"Unable to configure Nextcloud OIDC: {text or command}")
        outputs.append(text)

    verify_command = (
        f"timeout 60 pct exec {shlex.quote(nextcloud_vmid)} -- runuser -u www-data -- "
        f"/usr/bin/php /var/www/nextcloud/occ user_oidc:provider {shlex.quote(provider_identifier)} --output=json_pretty"
    )
    code, out, err = _run(client, verify_command)
    verify_text = _require_success(code, out, err, "Unable to verify Nextcloud OIDC provider")
    provider_payload = json.loads(verify_text or "{}")
    return {
        "provider_identifier": provider_identifier,
        "provider": provider_payload,
        "commands": outputs,
    }


def main() -> int:
    _stdout_setup()
    vm4_host = _env("SIEM_VM4_HOST", "192.168.1.39")
    vm4_user = _env("SIEM_VM4_USER", "rdegon")
    vm4_password = _required_env("SIEM_VM4_PASSWORD")
    proxmox_host = _env("SIEM_PROXMOX_HOST", "192.168.1.101")
    proxmox_user = _env("SIEM_PROXMOX_USER", "root")
    proxmox_password = _required_env("SIEM_PROXMOX_PASSWORD")
    nextcloud_vmid = _env("SIEM_NEXTCLOUD_VMID", "120")
    nextcloud_base_url = _env("SIEM_NEXTCLOUD_BASE_URL", "https://nextcloud-siem.lab.home.arpa")
    nextcloud_client_id = _env("SIEM_NEXTCLOUD_CLIENT_ID", "nextcloud")
    nextcloud_client_secret = _env("SIEM_NEXTCLOUD_CLIENT_SECRET", secrets.token_urlsafe(30))

    vm4 = _ssh_client(vm4_host, vm4_user, vm4_password)
    proxmox = _ssh_client(proxmox_host, proxmox_user, proxmox_password)
    try:
        keycloak_env = _read_remote_env(vm4, "/etc/siem/keycloak.env", sudo_password=vm4_password)
        web_env = _read_remote_env(vm4, "/etc/siem/web.env", sudo_password=vm4_password)
        realm_name = str(web_env.get("SIEM_KEYCLOAK_REALM") or "siem").strip() or "siem"
        admin_user = str(keycloak_env.get("KC_BOOTSTRAP_ADMIN_USERNAME") or "siem-admin").strip() or "siem-admin"
        admin_password = str(keycloak_env.get("KC_BOOTSTRAP_ADMIN_PASSWORD") or "").strip()
        if not admin_password:
            raise RuntimeError("KC_BOOTSTRAP_ADMIN_PASSWORD is empty on VM4")
        keycloak_client = _configure_keycloak_nextcloud_client(
            vm4,
            vm4_password=vm4_password,
            realm_name=realm_name,
            admin_user=admin_user,
            admin_password=admin_password,
            nextcloud_base_url=nextcloud_base_url,
            nextcloud_client_id=nextcloud_client_id,
            nextcloud_client_secret=nextcloud_client_secret,
        )
        discovery_uri = _env(
            "SIEM_NEXTCLOUD_DISCOVERY_URI",
            f"{str(web_env.get('SIEM_OIDC_ISSUER_URL') or f'http://{vm4_host}:8081/realms/{realm_name}').rstrip('/')}/.well-known/openid-configuration",
        )
        nextcloud_state = _configure_nextcloud_oidc(
            proxmox,
            nextcloud_vmid=nextcloud_vmid,
            nextcloud_base_url=nextcloud_base_url,
            discovery_uri=discovery_uri,
            client_id=nextcloud_client_id,
            client_secret=nextcloud_client_secret,
        )
        payload = {
            "status": "ok",
            "nextcloud_base_url": nextcloud_base_url,
            "discovery_uri": discovery_uri,
            "client_id": nextcloud_client_id,
            "client_secret": nextcloud_client_secret,
            "keycloak_client": keycloak_client,
            "nextcloud": nextcloud_state,
            "note": "Nextcloud is configured for internal OIDC against Keycloak. Access control is driven by mirrored nextcloud-users / nextcloud-admins groups.",
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    finally:
        proxmox.close()
        vm4.close()


if __name__ == "__main__":
    raise SystemExit(main())
