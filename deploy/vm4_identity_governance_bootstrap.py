from __future__ import annotations

import json
import os
import posixpath
import secrets
import shlex
import tempfile
import urllib.request
from pathlib import Path

try:
    import paramiko
except ModuleNotFoundError:  # pragma: no cover - deploy-only dependency
    paramiko = None  # type: ignore[assignment]


VAULT_VERSION = "1.21.3"
KEYCLOAK_VERSION = "26.4.4"
VAULT_ADDR = "http://127.0.0.1:8200"
KEYCLOAK_HTTP_URL = "http://127.0.0.1:8081"
VAULT_BIN = "/opt/siem/vault/current/vault"
ROOT = Path(__file__).resolve().parents[1]
VENDOR_ROOT = ROOT / ".build" / "vendor"


def _run_command(
    client: paramiko.SSHClient,
    command: str,
    *,
    sudo_password: str = "",
    use_sudo: bool = False,
) -> tuple[int, str, str]:
    wrapped = f"sudo -S -p '' bash -lc {shlex.quote(command)}" if use_sudo else command
    stdin, stdout, stderr = client.exec_command(wrapped, get_pty=use_sudo)
    if use_sudo:
        stdin.write(f"{sudo_password}\n")
        stdin.flush()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    return code, out, err


def _strip_sudo_echo(text: str, sudo_password: str) -> str:
    if not sudo_password:
        return text
    return "\n".join(line for line in str(text or "").replace("\r", "\n").split("\n") if line.strip() != sudo_password)


def _read_remote_file(client: paramiko.SSHClient, path: str, *, sudo_password: str, use_sudo: bool = True) -> str:
    code, out, err = _run_command(
        client,
        f"if [ -f {shlex.quote(path)} ]; then cat {shlex.quote(path)}; fi",
        sudo_password=sudo_password,
        use_sudo=use_sudo,
    )
    if code != 0:
        raise RuntimeError(f"Unable to read remote file {path}: {err.strip()}")
    return _strip_sudo_echo(out, sudo_password)


def _parse_env_text(text: str) -> dict[str, str]:
    env: dict[str, str] = {}
    for raw_line in str(text or "").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        key = key.strip()
        if key:
            env[key] = value.strip()
    return env


def _render_env_text(payload: dict[str, str]) -> str:
    lines = [f"{key}={value}" for key, value in sorted(payload.items()) if str(key).strip()]
    return "\n".join(lines) + "\n"


def _install_generated_content(
    client: paramiko.SSHClient,
    sftp: paramiko.SFTPClient,
    *,
    content: str,
    target_path: str,
    upload_root: str,
    sudo_password: str,
    mode: str = "0640",
) -> None:
    if paramiko is None:
        raise RuntimeError("paramiko is required for remote content installation")
    local_temp: str | None = None
    try:
        normalized = str(content or "").replace("\r\n", "\n").replace("\r", "\n")
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", delete=False) as handle:
            handle.write(normalized)
            local_temp = handle.name
        remote_temp = posixpath.join("/tmp", f"siem-generated-{target_path.lstrip('/').replace('/', '_')}")
        sftp.put(local_temp, remote_temp)
        install_cmd = f"install -D -m {mode} {shlex.quote(remote_temp)} {shlex.quote(target_path)} && rm -f {shlex.quote(remote_temp)}"
        code, out, err = _run_command(client, install_cmd, sudo_password=sudo_password, use_sudo=True)
        cleaned = _strip_sudo_echo(out, sudo_password)
        if cleaned.strip():
            print(cleaned, end="")
        if code != 0:
            raise RuntimeError(f"Unable to install generated content to {target_path}: {err.strip()}")
    finally:
        if local_temp:
            try:
                os.unlink(local_temp)
            except OSError:
                pass


def _random_secret(length: int = 32) -> str:
    return secrets.token_urlsafe(length)[: max(24, length)]


def _download_vendor_artifact(url: str, filename: str) -> Path:
    VENDOR_ROOT.mkdir(parents=True, exist_ok=True)
    target = VENDOR_ROOT / filename
    if target.exists() and target.stat().st_size > 0:
        return target
    request = urllib.request.Request(url, headers={"User-Agent": "siem-operator-bootstrap/1.0"})
    with urllib.request.urlopen(request, timeout=300) as response:
        data = response.read()
    target.write_bytes(data)
    return target


def _upload_vendor_artifact(
    sftp: paramiko.SFTPClient,
    *,
    local_path: Path,
    remote_path: str,
) -> None:
    remote_parent = posixpath.dirname(remote_path)
    try:
        sftp.stat(remote_parent)
    except OSError:
        raise RuntimeError(f"Remote vendor directory is missing: {remote_parent}")
    sftp.put(str(local_path), remote_path)


def _ensure_remote_directories(client: paramiko.SSHClient, *, sudo_password: str) -> None:
    command = (
        "mkdir -p /etc/siem /var/lib/siem-vault/data /opt/siem/vault /opt/siem/keycloak "
        "/var/log/siem-keycloak /var/log/siem-vault"
    )
    code, _, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to prepare VM4 identity/runtime directories: {err.strip()}")


def _remote_path_exists(
    client: paramiko.SSHClient,
    path: str,
    *,
    sudo_password: str,
) -> bool:
    code, _, _ = _run_command(
        client,
        f"test -e {shlex.quote(path)}",
        sudo_password=sudo_password,
        use_sudo=True,
    )
    return code == 0


def _ensure_current_symlink(
    client: paramiko.SSHClient,
    *,
    base_dir: str,
    version: str,
    sudo_password: str,
) -> None:
    script = f"""
set -eu
python3 - <<'PY'
import pathlib
import shutil

base = pathlib.Path({base_dir!r})
dest = base / {version!r}
current = base / "current"
if not dest.exists():
    raise SystemExit(f"missing runtime path: {{dest}}")
if current.is_symlink() or current.exists():
    if current.is_symlink() or current.is_file():
        current.unlink()
    else:
        shutil.rmtree(current)
current.symlink_to(dest, target_is_directory=True)
PY
"""
    code, out, err = _run_command(client, script, sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise RuntimeError(f"Unable to update runtime symlink in {base_dir}: {cleaned or err.strip()}")


def _ensure_vault_binary(
    client: paramiko.SSHClient,
    sftp: paramiko.SFTPClient,
    *,
    sudo_password: str,
) -> None:
    remote_binary = f"/opt/siem/vault/{VAULT_VERSION}/vault"
    if _remote_path_exists(client, remote_binary, sudo_password=sudo_password):
        _ensure_current_symlink(
            client,
            base_dir="/opt/siem/vault",
            version=VAULT_VERSION,
            sudo_password=sudo_password,
        )
        return
    vendor_path = _download_vendor_artifact(
        f"https://releases.hashicorp.com/vault/{VAULT_VERSION}/vault_{VAULT_VERSION}_linux_amd64.zip",
        f"vault_{VAULT_VERSION}_linux_amd64.zip",
    )
    remote_archive = f"/tmp/{vendor_path.name}"
    _upload_vendor_artifact(sftp, local_path=vendor_path, remote_path=remote_archive)
    script = f"""
set -eu
python3 - <<'PY'
import io
import pathlib
import shutil
import urllib.request
import zipfile

version = "{VAULT_VERSION}"
base = pathlib.Path("/opt/siem/vault")
dest = base / version
binary = dest / "vault"
if not binary.exists():
    dest.mkdir(parents=True, exist_ok=True)
    archive_path = pathlib.Path({remote_archive!r})
    data = archive_path.read_bytes()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        archive.extract("vault", str(dest))
    binary.chmod(0o755)
current = base / "current"
if current.is_symlink() or current.exists():
    if current.is_symlink() or current.is_file():
        current.unlink()
    else:
        shutil.rmtree(current)
current.symlink_to(dest, target_is_directory=True)
PY
"""
    code, out, err = _run_command(client, script, sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise RuntimeError(f"Unable to install Vault runtime: {cleaned or err.strip()}")


def _ensure_keycloak_binary(
    client: paramiko.SSHClient,
    sftp: paramiko.SFTPClient,
    *,
    sudo_password: str,
) -> None:
    remote_bin_path = f"/opt/siem/keycloak/{KEYCLOAK_VERSION}/bin/kc.sh"
    if _remote_path_exists(client, remote_bin_path, sudo_password=sudo_password):
        _ensure_current_symlink(
            client,
            base_dir="/opt/siem/keycloak",
            version=KEYCLOAK_VERSION,
            sudo_password=sudo_password,
        )
        return
    vendor_path = _download_vendor_artifact(
        f"https://github.com/keycloak/keycloak/releases/download/{KEYCLOAK_VERSION}/keycloak-{KEYCLOAK_VERSION}.tar.gz",
        f"keycloak-{KEYCLOAK_VERSION}.tar.gz",
    )
    remote_archive = f"/tmp/{vendor_path.name}"
    _upload_vendor_artifact(sftp, local_path=vendor_path, remote_path=remote_archive)
    script = f"""
set -eu
python3 - <<'PY'
import io
import pathlib
import shutil
import tarfile

version = "{KEYCLOAK_VERSION}"
base = pathlib.Path("/opt/siem/keycloak")
dest = base / version
bin_path = dest / "bin" / "kc.sh"
if not bin_path.exists():
    base.mkdir(parents=True, exist_ok=True)
    archive_path = pathlib.Path({remote_archive!r})
    data = archive_path.read_bytes()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        archive.extractall(str(base))
    extracted = base / f"keycloak-{{version}}"
    if extracted.exists() and extracted != dest:
        if dest.exists():
            shutil.rmtree(dest)
        extracted.rename(dest)
current = base / "current"
if current.is_symlink() or current.exists():
    if current.is_symlink() or current.is_file():
        current.unlink()
    else:
        shutil.rmtree(current)
current.symlink_to(dest, target_is_directory=True)
PY
"""
    code, out, err = _run_command(client, script, sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise RuntimeError(f"Unable to install Keycloak runtime: {cleaned or err.strip()}")


def _ensure_keycloak_java_runtime(client: paramiko.SSHClient, *, sudo_password: str) -> None:
    command = """
set -eu
export DEBIAN_FRONTEND=noninteractive
if command -v java >/dev/null 2>&1; then
  exit 0
fi
apt-get update -y
if apt-cache policy openjdk-21-jre-headless | grep -q 'Candidate:'; then
  apt-get install -y openjdk-21-jre-headless
else
  apt-get install -y openjdk-17-jre-headless
fi
"""
    code, out, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise RuntimeError(f"Unable to install Keycloak Java runtime: {cleaned or err.strip()}")


def _ensure_keycloak_database(
    client: paramiko.SSHClient,
    *,
    db_name: str,
    db_user: str,
    db_password: str,
    sudo_password: str,
) -> None:
    safe_password = db_password.replace("'", "''")
    role_check = "sudo -u postgres psql -tAc " + shlex.quote(
        f"SELECT 1 FROM pg_roles WHERE rolname = '{db_user}'"
    )
    code, out, err = _run_command(client, role_check, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to inspect Keycloak database role: {err.strip()}")
    if "1" not in str(out or ""):
        create_role_sql = (
            "DO $$ "
            f"BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{db_user}') THEN "
            f"CREATE ROLE {db_user} LOGIN PASSWORD '{safe_password}'; "
            "END IF; END $$;"
        )
        create_role = "sudo -u postgres psql -v ON_ERROR_STOP=1 -c " + shlex.quote(create_role_sql)
        code, _, err = _run_command(client, create_role, sudo_password=sudo_password, use_sudo=True)
        if code != 0:
            raise RuntimeError(f"Unable to create Keycloak database role: {err.strip()}")
    db_check = "sudo -u postgres psql -tAc " + shlex.quote(
        f"SELECT 1 FROM pg_database WHERE datname = '{db_name}'"
    )
    code, out, err = _run_command(client, db_check, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to inspect Keycloak database: {err.strip()}")
    if "1" not in str(out or ""):
        create_db = f"sudo -u postgres createdb -O {shlex.quote(db_user)} {shlex.quote(db_name)}"
        code, _, err = _run_command(client, create_db, sudo_password=sudo_password, use_sudo=True)
        if code != 0 and "already exists" not in err.lower():
            raise RuntimeError(f"Unable to create Keycloak database: {err.strip()}")
        code, out, err = _run_command(client, db_check, sudo_password=sudo_password, use_sudo=True)
        if code != 0 or "1" not in str(out or ""):
            raise RuntimeError(f"Keycloak database was not created successfully: {err.strip()}")


def _wait_for_remote_http(
    client: paramiko.SSHClient,
    url: str,
    *,
    sudo_password: str,
    allowed_statuses: set[int] | None = None,
    attempts: int = 20,
    delay_seconds: int = 3,
) -> None:
    script = f"""
set -eu
python3 - <<'PY'
import json
import ssl
import time
import urllib.error
import urllib.request

url = {url!r}
allowed_statuses = {sorted(allowed_statuses or {200})!r}
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
last_error = ""
for attempt in range({attempts}):
    try:
        with urllib.request.urlopen(url, timeout=10, context=context) as response:
            if response.status in allowed_statuses:
                print(response.status)
                raise SystemExit(0)
            last_error = f"unexpected status {{response.status}}"
    except urllib.error.HTTPError as exc:
        if exc.code in allowed_statuses:
            print(exc.code)
            raise SystemExit(0)
        last_error = f"HTTP Error {{exc.code}}: {{exc.reason}}"
    except Exception as exc:
        last_error = str(exc)
        time.sleep({delay_seconds})
print(last_error)
raise SystemExit(1)
PY
"""
    code, out, err = _run_command(client, script, sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if code != 0:
        raise RuntimeError(f"Remote HTTP readiness probe failed for {url}: {cleaned or err.strip()}")


def _vault_status(client: paramiko.SSHClient, *, sudo_password: str) -> dict[str, object]:
    command = f"export VAULT_ADDR={shlex.quote(VAULT_ADDR)} && /opt/siem/vault/current/vault status -format=json || true"
    code, out, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password).strip()
    if code not in {0, 2} and not cleaned:
        raise RuntimeError(f"Unable to query Vault status: {err.strip()}")
    return json.loads(cleaned) if cleaned else {}


def _ensure_vault_initialized(client: paramiko.SSHClient, *, sudo_password: str) -> dict[str, object]:
    operator_path = "/etc/siem/vault-operator.json"
    existing = _read_remote_file(client, operator_path, sudo_password=sudo_password)
    if existing.strip():
        return json.loads(existing)
    command = (
        f"export VAULT_ADDR={shlex.quote(VAULT_ADDR)} && "
        f"/opt/siem/vault/current/vault operator init -key-shares=5 -key-threshold=3 -format=json > {shlex.quote(operator_path)} && "
        f"chmod 0600 {shlex.quote(operator_path)}"
    )
    code, _, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to initialize Vault: {err.strip()}")
    return json.loads(_read_remote_file(client, operator_path, sudo_password=sudo_password))


def _ensure_vault_unsealed(client: paramiko.SSHClient, *, operator_state: dict[str, object], sudo_password: str) -> None:
    status = _vault_status(client, sudo_password=sudo_password)
    if not bool(status.get("sealed", True)):
        return
    keys = list(operator_state.get("unseal_keys_b64") or [])[:3]
    if len(keys) < 3:
        raise RuntimeError("Vault operator state does not contain enough unseal keys")
    for key in keys:
        command = (
            f"export VAULT_ADDR={shlex.quote(VAULT_ADDR)} && "
            f"/opt/siem/vault/current/vault operator unseal {shlex.quote(str(key))}"
        )
        code, _, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=True)
        if code != 0:
            raise RuntimeError(f"Unable to unseal Vault: {err.strip()}")


def _vault_exec(
    client: paramiko.SSHClient,
    command: str,
    *,
    root_token: str,
    sudo_password: str,
) -> tuple[int, str, str]:
    wrapped = (
        f"export PATH=/opt/siem/vault/current:$PATH VAULT_ADDR={shlex.quote(VAULT_ADDR)} "
        f"VAULT_TOKEN={shlex.quote(root_token)} && {command}"
    )
    return _run_command(client, wrapped, sudo_password=sudo_password, use_sudo=True)


def _ensure_vault_runtime_role(client: paramiko.SSHClient, *, root_token: str, sudo_password: str) -> tuple[str, str]:
    policy_content = (
        'path "kv/data/siem/*" { capabilities = ["read"] }\n'
        'path "kv/metadata/siem/*" { capabilities = ["read", "list"] }\n'
    )
    command = (
        "vault secrets list -format=json | grep -q '\"kv/\"' || vault secrets enable -path=kv kv-v2; "
        "vault auth list -format=json | grep -q '\"approle/\"' || vault auth enable approle; "
        f"cat <<'EOF' > /tmp/siem-runtime-policy.hcl\n{policy_content}EOF\n"
        "vault policy write siem-runtime /tmp/siem-runtime-policy.hcl >/dev/null; "
        "rm -f /tmp/siem-runtime-policy.hcl; "
        "vault write auth/approle/role/siem-web token_policies=siem-runtime token_ttl=1h token_max_ttl=24h secret_id_ttl=720h >/dev/null"
    )
    code, _, err = _vault_exec(client, command, root_token=root_token, sudo_password=sudo_password)
    if code != 0:
        raise RuntimeError(f"Unable to configure Vault AppRole runtime: {err.strip()}")
    code, out, err = _vault_exec(
        client,
        "vault read -format=json auth/approle/role/siem-web/role-id",
        root_token=root_token,
        sudo_password=sudo_password,
    )
    if code != 0:
        raise RuntimeError(f"Unable to fetch Vault AppRole role-id: {err.strip()}")
    role_id = str(json.loads(_strip_sudo_echo(out, sudo_password)).get("data", {}).get("role_id") or "").strip()
    code, out, err = _vault_exec(
        client,
        "vault write -f -format=json auth/approle/role/siem-web/secret-id",
        root_token=root_token,
        sudo_password=sudo_password,
    )
    if code != 0:
        raise RuntimeError(f"Unable to issue Vault AppRole secret-id: {err.strip()}")
    secret_id = str(json.loads(_strip_sudo_echo(out, sudo_password)).get("data", {}).get("secret_id") or "").strip()
    if not role_id or not secret_id:
        raise RuntimeError("Vault AppRole credentials were generated empty")
    return role_id, secret_id


def _vault_put_secret(
    client: paramiko.SSHClient,
    *,
    root_token: str,
    path: str,
    values: dict[str, str],
    sudo_password: str,
) -> None:
    args = " ".join(shlex.quote(f"{key}={value}") for key, value in values.items() if str(value).strip())
    if not args:
        return
    code, _, err = _vault_exec(
        client,
        f"vault kv put {shlex.quote(path)} {args} >/dev/null",
        root_token=root_token,
        sudo_password=sudo_password,
    )
    if code != 0:
        raise RuntimeError(f"Unable to store Vault secret at {path}: {err.strip()}")


def _ensure_keycloak_running(client: paramiko.SSHClient, *, sudo_password: str) -> None:
    command = "systemctl enable siem-keycloak >/dev/null && systemctl restart siem-keycloak"
    code, _, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to start Keycloak service: {err.strip()}")
    _wait_for_remote_http(
        client,
        f"{KEYCLOAK_HTTP_URL}/realms/master/.well-known/openid-configuration",
        sudo_password=sudo_password,
        allowed_statuses={200},
        attempts=30,
        delay_seconds=4,
    )


def _ensure_keycloak_firewall_access(client: paramiko.SSHClient, *, sudo_password: str) -> None:
    command = """
set -eu
if ! command -v ufw >/dev/null 2>&1; then
  exit 0
fi
status="$(ufw status || true)"
if printf '%s\n' "$status" | grep -F "8081/tcp" | grep -F "192.168.1.0/24" >/dev/null 2>&1; then
  :
else
  ufw allow from 192.168.1.0/24 to any port 8081 proto tcp comment 'siem-keycloak-oidc-lan' >/dev/null
fi
if printf '%s\n' "$status" | grep -F "8081/tcp" | grep -F "10.66.66.0/24" >/dev/null 2>&1; then
  :
else
  ufw allow from 10.66.66.0/24 to any port 8081 proto tcp comment 'siem-keycloak-oidc-vpn' >/dev/null
fi
"""
    code, out, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise RuntimeError(f"Unable to expose Keycloak firewall access: {cleaned or err.strip()}")


def _configure_keycloak(
    client: paramiko.SSHClient,
    *,
    admin_user: str,
    admin_password: str,
    realm_name: str,
    base_url: str,
    operator_username: str,
    operator_password: str,
    client_secret: str,
    admin_client_secret: str,
    sudo_password: str,
) -> None:
    redirect_uri = f"{base_url.rstrip('/')}/auth/oidc/callback"
    realm_roles = ("siem-admin", "siem-analyst", "siem-viewer")
    admin_client_roles = (
        "query-users",
        "query-groups",
        "query-clients",
        "query-realms",
        "view-users",
        "manage-users",
        "view-clients",
        "manage-clients",
        "view-realm",
        "manage-realm",
    )
    script = f"""
set -eu
KC_BIN=/opt/siem/keycloak/current/bin
$KC_BIN/kcadm.sh config credentials --server {shlex.quote(KEYCLOAK_HTTP_URL)} --realm master --user {shlex.quote(admin_user)} --password {shlex.quote(admin_password)} >/dev/null
$KC_BIN/kcadm.sh get realms/{shlex.quote(realm_name)} >/dev/null 2>&1 || $KC_BIN/kcadm.sh create realms -s realm={shlex.quote(realm_name)} -s enabled=true >/dev/null
for role_name in {" ".join(shlex.quote(role) for role in realm_roles)}; do
  $KC_BIN/kcadm.sh get roles/$role_name -r {shlex.quote(realm_name)} >/dev/null 2>&1 || $KC_BIN/kcadm.sh create roles -r {shlex.quote(realm_name)} -s name=$role_name >/dev/null
done
client_id=$($KC_BIN/kcadm.sh get clients -r {shlex.quote(realm_name)} -q clientId=siem-web | python3 -c "import json,sys; data=json.load(sys.stdin); print(data[0]['id'] if data else '')")
if [ -z "$client_id" ]; then
  $KC_BIN/kcadm.sh create clients -r {shlex.quote(realm_name)} \\
    -s clientId=siem-web \\
    -s enabled=true \\
    -s protocol=openid-connect \\
    -s publicClient=false \\
    -s secret={shlex.quote(client_secret)} \\
    -s standardFlowEnabled=true \\
    -s directAccessGrantsEnabled=true \\
    -s serviceAccountsEnabled=false \\
    -s 'redirectUris=["{redirect_uri}"]' \\
    -s 'webOrigins=["{base_url.rstrip('/')}"]' >/dev/null
  client_id=$($KC_BIN/kcadm.sh get clients -r {shlex.quote(realm_name)} -q clientId=siem-web | python3 -c "import json,sys; data=json.load(sys.stdin); print(data[0]['id'] if data else '')")
fi
$KC_BIN/kcadm.sh update clients/$client_id -r {shlex.quote(realm_name)} \\
  -s enabled=true \\
  -s secret={shlex.quote(client_secret)} \\
  -s standardFlowEnabled=true \\
  -s directAccessGrantsEnabled=true \\
  -s publicClient=false \\
  -s 'redirectUris=["{redirect_uri}"]' \\
  -s 'webOrigins=["{base_url.rstrip('/')}"]' >/dev/null
admin_client_id=$($KC_BIN/kcadm.sh get clients -r {shlex.quote(realm_name)} -q clientId=siem-keycloak-admin | python3 -c "import json,sys; data=json.load(sys.stdin); print(data[0]['id'] if data else '')")
if [ -z "$admin_client_id" ]; then
  $KC_BIN/kcadm.sh create clients -r {shlex.quote(realm_name)} \\
    -s clientId=siem-keycloak-admin \\
    -s name='SIEM Realm Admin' \\
    -s enabled=true \\
    -s protocol=openid-connect \\
    -s publicClient=false \\
    -s secret={shlex.quote(admin_client_secret)} \\
    -s standardFlowEnabled=false \\
    -s directAccessGrantsEnabled=false \\
    -s serviceAccountsEnabled=true >/dev/null
  admin_client_id=$($KC_BIN/kcadm.sh get clients -r {shlex.quote(realm_name)} -q clientId=siem-keycloak-admin | python3 -c "import json,sys; data=json.load(sys.stdin); print(data[0]['id'] if data else '')")
fi
$KC_BIN/kcadm.sh update clients/$admin_client_id -r {shlex.quote(realm_name)} \\
  -s enabled=true \\
  -s protocol=openid-connect \\
  -s publicClient=false \\
  -s secret={shlex.quote(admin_client_secret)} \\
  -s standardFlowEnabled=false \\
  -s directAccessGrantsEnabled=false \\
  -s serviceAccountsEnabled=true >/dev/null
for role_name in {" ".join(shlex.quote(role) for role in admin_client_roles)}; do
  $KC_BIN/kcadm.sh add-roles -r {shlex.quote(realm_name)} --uusername service-account-siem-keycloak-admin --cclientid realm-management --rolename $role_name >/dev/null 2>&1 || true
done
user_id=$($KC_BIN/kcadm.sh get users -r {shlex.quote(realm_name)} -q username={shlex.quote(operator_username)} -q exact=true | python3 -c "import json,sys; data=json.load(sys.stdin); print(data[0]['id'] if data else '')")
if [ -z "$user_id" ]; then
  $KC_BIN/kcadm.sh create users -r {shlex.quote(realm_name)} -s username={shlex.quote(operator_username)} -s enabled=true -s emailVerified=true >/dev/null
  user_id=$($KC_BIN/kcadm.sh get users -r {shlex.quote(realm_name)} -q username={shlex.quote(operator_username)} -q exact=true | python3 -c "import json,sys; data=json.load(sys.stdin); print(data[0]['id'] if data else '')")
fi
$KC_BIN/kcadm.sh set-password -r {shlex.quote(realm_name)} --userid "$user_id" --new-password {shlex.quote(operator_password)} >/dev/null
$KC_BIN/kcadm.sh add-roles -r {shlex.quote(realm_name)} --uid "$user_id" --rolename siem-admin >/dev/null 2>&1 || true
"""
    code, _, err = _run_command(client, script, sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to configure Keycloak realm/client/user: {err.strip()}")


def bootstrap_vm4_identity_governance(
    client: paramiko.SSHClient,
    sftp: paramiko.SFTPClient,
    *,
    host: str,
    remote_root: str,
    upload_root: str,
    sudo_password: str,
) -> dict[str, str]:
    if paramiko is None:
        raise RuntimeError("paramiko is required for VM4 identity bootstrap")
    _ensure_remote_directories(client, sudo_password=sudo_password)
    _ensure_vault_binary(client, sftp, sudo_password=sudo_password)
    _ensure_keycloak_binary(client, sftp, sudo_password=sudo_password)
    _ensure_keycloak_java_runtime(client, sudo_password=sudo_password)

    web_env = _parse_env_text(_read_remote_file(client, "/etc/siem/web.env", sudo_password=sudo_password))
    keycloak_env = _parse_env_text(_read_remote_file(client, "/etc/siem/keycloak.env", sudo_password=sudo_password))
    base_url = str(web_env.get("SIEM_WEB_BASE_URL") or os.getenv("SIEM_WEB_BASE_URL") or f"https://{host}").strip().rstrip("/")
    realm_name = "siem"
    operator_username = str(web_env.get("SIEM_ADMIN_DEFAULT_USER") or os.getenv("SIEM_WEB_ADMIN_USER") or "admin").strip() or "admin"
    operator_password = str(web_env.get("SIEM_ADMIN_DEFAULT_PASSWORD") or os.getenv("SIEM_WEB_ADMIN_PASSWORD") or keycloak_env.get("SIEM_OPERATOR_PASSWORD") or "").strip()
    if not operator_password:
        raise RuntimeError("SIEM_ADMIN_DEFAULT_PASSWORD/SIEM_WEB_ADMIN_PASSWORD/SIEM_OPERATOR_PASSWORD is required")
    keycloak_db_name = str(keycloak_env.get("KC_DB_URL_DATABASE") or "siem_keycloak").strip() or "siem_keycloak"
    keycloak_db_user = str(keycloak_env.get("KC_DB_USERNAME") or "siem_keycloak").strip() or "siem_keycloak"
    keycloak_db_password = str(keycloak_env.get("KC_DB_PASSWORD") or _random_secret(32)).strip()
    keycloak_admin_user = str(keycloak_env.get("KC_BOOTSTRAP_ADMIN_USERNAME") or "siem-admin").strip()
    keycloak_admin_password = str(keycloak_env.get("KC_BOOTSTRAP_ADMIN_PASSWORD") or _random_secret(32)).strip()
    oidc_client_secret = str(web_env.get("SIEM_OIDC_CLIENT_SECRET") or _random_secret(40)).strip()
    keycloak_admin_client_secret = str(web_env.get("SIEM_KEYCLOAK_ADMIN_CLIENT_SECRET") or _random_secret(40)).strip()

    vault_env = {
        "VAULT_ADDR": VAULT_ADDR,
    }
    keycloak_runtime_env = {
        "KC_DB": "postgres",
        "KC_DB_URL": f"jdbc:postgresql://127.0.0.1:5432/{keycloak_db_name}",
        "KC_DB_URL_DATABASE": keycloak_db_name,
        "KC_DB_USERNAME": keycloak_db_user,
        "KC_DB_PASSWORD": keycloak_db_password,
        "KC_BOOTSTRAP_ADMIN_USERNAME": keycloak_admin_user,
        "KC_BOOTSTRAP_ADMIN_PASSWORD": keycloak_admin_password,
        "KC_HTTP_ENABLED": "true",
        "KC_HTTP_PORT": "8081",
        "KC_HOSTNAME": f"https://{host}",
        "KC_HOSTNAME_STRICT": "false",
        "KC_PROXY_HEADERS": "xforwarded",
        "JAVA_OPTS_KC_HEAP": "-Xms96m -Xmx320m -XX:MaxMetaspaceSize=224m",
        "SIEM_OPERATOR_PASSWORD": operator_password,
    }
    _install_generated_content(
        client,
        sftp,
        content=_render_env_text(vault_env),
        target_path="/etc/siem/vault.env",
        upload_root=upload_root,
        sudo_password=sudo_password,
    )
    _install_generated_content(
        client,
        sftp,
        content=_render_env_text(keycloak_runtime_env),
        target_path="/etc/siem/keycloak.env",
        upload_root=upload_root,
        sudo_password=sudo_password,
    )

    _ensure_keycloak_database(
        client,
        db_name=keycloak_db_name,
        db_user=keycloak_db_user,
        db_password=keycloak_db_password,
        sudo_password=sudo_password,
    )

    code, _, err = _run_command(client, "systemctl daemon-reload", sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to daemon-reload before identity bootstrap: {err.strip()}")

    code, _, err = _run_command(client, "systemctl enable siem-vault >/dev/null && systemctl restart siem-vault", sudo_password=sudo_password, use_sudo=True)
    if code != 0:
        raise RuntimeError(f"Unable to start Vault service: {err.strip()}")
    _wait_for_remote_http(
        client,
        f"{VAULT_ADDR}/v1/sys/health",
        sudo_password=sudo_password,
        allowed_statuses={200, 429, 472, 473, 501, 503},
        attempts=20,
        delay_seconds=3,
    )
    operator_state = _ensure_vault_initialized(client, sudo_password=sudo_password)
    _ensure_vault_unsealed(client, operator_state=operator_state, sudo_password=sudo_password)
    root_token = str(operator_state.get("root_token") or "").strip()
    if not root_token:
        raise RuntimeError("Vault operator state does not contain root token")
    role_id, secret_id = _ensure_vault_runtime_role(client, root_token=root_token, sudo_password=sudo_password)

    secret_specs = (
        ("SIEM_JWT_SECRET", "kv/siem/jwt", "SIEM_JWT_SECRET_REF", {"value": str(web_env.get("SIEM_JWT_SECRET") or "")}),
        ("SIEM_WEBHOOK_SHARED_SECRET", "kv/siem/webhook", "SIEM_WEBHOOK_SHARED_SECRET_REF", {"value": str(web_env.get("SIEM_WEBHOOK_SHARED_SECRET") or "")}),
        ("SIEM_TELEGRAM_BOT_TOKEN", "kv/siem/telegram", "SIEM_TELEGRAM_BOT_TOKEN_REF", {"value": str(web_env.get("SIEM_TELEGRAM_BOT_TOKEN") or "")}),
        ("SIEM_SMTP_PASSWORD", "kv/siem/smtp", "SIEM_SMTP_PASSWORD_REF", {"value": str(web_env.get("SIEM_SMTP_PASSWORD") or "")}),
        ("SIEM_VENDOR_API_TOKEN", "kv/siem/vendor", "SIEM_VENDOR_API_TOKEN_REF", {"value": str(web_env.get("SIEM_VENDOR_API_TOKEN") or "")}),
        ("SIEM_WINDOWS_BOOTSTRAP_TOKEN", "kv/siem/windows-bootstrap", "SIEM_WINDOWS_BOOTSTRAP_TOKEN_REF", {"value": str(web_env.get("SIEM_WINDOWS_BOOTSTRAP_TOKEN") or "")}),
        ("SIEM_CH_PASSWORD", "kv/siem/clickhouse", "SIEM_CH_PASSWORD_REF", {"value": str(web_env.get("SIEM_CH_PASSWORD") or "")}),
        ("SIEM_GREENBONE_PASSWORD", "kv/siem/greenbone", "SIEM_GREENBONE_PASSWORD_REF", {"value": str(web_env.get("SIEM_GREENBONE_PASSWORD") or "")}),
        ("SIEM_MONGO_URI", "kv/siem/mongo", "SIEM_MONGO_URI_REF", {"value": str(web_env.get("SIEM_MONGO_URI") or "")}),
        ("SIEM_OIDC_CLIENT_SECRET", "kv/siem/oidc", "SIEM_OIDC_CLIENT_SECRET_REF", {"client_secret": oidc_client_secret}),
        (
            "SIEM_KEYCLOAK_ADMIN_CLIENT_SECRET",
            "kv/siem/keycloak-admin-client",
            "SIEM_KEYCLOAK_ADMIN_CLIENT_SECRET_REF",
            {"client_secret": keycloak_admin_client_secret},
        ),
    )
    for plain_env, vault_path, ref_env, values in secret_specs:
        if any(str(value).strip() for value in values.values()):
            _vault_put_secret(client, root_token=root_token, path=vault_path, values=values, sudo_password=sudo_password)
            field_name = next(iter(values.keys()))
            web_env[ref_env] = f"vault://{vault_path}#{field_name}"
        web_env.pop(plain_env, None)

    _ensure_keycloak_running(client, sudo_password=sudo_password)
    _ensure_keycloak_firewall_access(client, sudo_password=sudo_password)
    _configure_keycloak(
        client,
        admin_user=keycloak_admin_user,
        admin_password=keycloak_admin_password,
        realm_name=realm_name,
        base_url=base_url,
        operator_username=operator_username,
        operator_password=operator_password,
        client_secret=oidc_client_secret,
        admin_client_secret=keycloak_admin_client_secret,
        sudo_password=sudo_password,
    )

    web_env.update(
        {
            "SIEM_OIDC_ENABLED": "1",
            "SIEM_OIDC_ISSUER_URL": f"https://{host}/realms/{realm_name}",
            "SIEM_OIDC_CLIENT_ID": "siem-web",
            "SIEM_OIDC_TLS_VERIFY": "disabled",
            "SIEM_OIDC_DEFAULT_ROLE": "viewer",
            "SIEM_OIDC_GROUP_ROLE_MAP_JSON": '{"siem-admin":"admin","siem-analyst":"analyst","siem-viewer":"viewer"}',
            "SIEM_KEYCLOAK_BASE_URL": f"https://{host}",
            "SIEM_KEYCLOAK_REALM": realm_name,
            "SIEM_KEYCLOAK_ADMIN_CLIENT_ID": "siem-keycloak-admin",
            "SIEM_KEYCLOAK_TLS_VERIFY": "disabled",
            "SIEM_VAULT_ADDR": VAULT_ADDR,
            "SIEM_VAULT_AUTH_METHOD": "approle",
            "SIEM_VAULT_ROLE_ID": role_id,
            "SIEM_VAULT_SECRET_ID": secret_id,
        }
    )
    _install_generated_content(
        client,
        sftp,
        content=_render_env_text(web_env),
        target_path="/etc/siem/web.env",
        upload_root=upload_root,
        sudo_password=sudo_password,
    )
    return {
        "web_base_url": base_url,
        "oidc_issuer": f"https://{host}/realms/{realm_name}",
        "vault_addr": VAULT_ADDR,
        "operator_username": operator_username,
    }
