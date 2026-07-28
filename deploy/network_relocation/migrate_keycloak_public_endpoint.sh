#!/usr/bin/env bash
set -euo pipefail

public_base="${1:-https://192.168.3.102}"
realm="${SIEM_KEYCLOAK_REALM:-siem}"
client_id="${SIEM_OIDC_CLIENT_ID:-siem-web}"
env_file="${SIEM_KEYCLOAK_ENV_FILE:-/etc/siem/keycloak.env}"
web_env_file="${SIEM_WEB_ENV_FILE:-/etc/siem/web.env}"
remote_root="${SIEM_REMOTE_ROOT:-/opt/siem/siem-solution}"
web_python="${SIEM_WEB_PYTHON:-/opt/siem/venv-web/bin/python}"

upsert_env_value() {
  local path="$1"
  local key="$2"
  local value="$3"
  local temp
  temp="$(mktemp "${path}.XXXXXX")"
  awk -v key="${key}" -v value="${value}" '
    BEGIN { updated = 0 }
    index($0, key "=") == 1 {
      print key "=" value
      updated = 1
      next
    }
    { print }
    END {
      if (!updated) {
        print key "=" value
      }
    }
  ' "${path}" >"${temp}"
  chmod --reference="${path}" "${temp}"
  chown --reference="${path}" "${temp}"
  mv -f "${temp}" "${path}"
}

(
  cd "${remote_root}"
  PUBLIC_BASE="${public_base}" CLIENT_ID="${client_id}" WEB_ENV_FILE="${web_env_file}" \
    "${web_python}" - <<'PY'
import json
import os
from pathlib import Path

for raw_line in Path(os.environ["WEB_ENV_FILE"]).read_text(
    encoding="utf-8"
).splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#") or "=" not in raw_line:
        continue
    key, value = raw_line.split("=", 1)
    if key.strip():
        os.environ.setdefault(key.strip(), value)

from services.web.app.keycloak_admin_runtime import get_client, save_client

public_base = os.environ["PUBLIC_BASE"].rstrip("/")
client_id = os.environ["CLIENT_ID"]
current = get_client(client_id)
updated = save_client(
    {
        "client_id": client_id,
        "redirect_uris": [f"{public_base}/auth/oidc/callback"],
        "web_origins": [public_base],
        "root_url": public_base,
        "base_url": public_base,
    },
    actor="system-network-cutover",
    client_id=client_id,
)
print(
    json.dumps(
        {
            "client_id": updated.get("client_id"),
            "redirect_uris": updated.get("redirect_uris"),
            "web_origins": updated.get("web_origins"),
            "root_url": updated.get("root_url"),
            "base_url": updated.get("base_url"),
        },
        ensure_ascii=True,
    )
)
PY
)

issuer="${public_base}/realms/${realm}"
upsert_env_value "${env_file}" "KC_HOSTNAME" "${public_base}"
upsert_env_value "${web_env_file}" "SIEM_OIDC_ISSUER_URL" "${issuer}"
upsert_env_value \
  "${web_env_file}" \
  "SIEM_OIDC_BACKCHANNEL_DISCOVERY_URL" \
  "http://127.0.0.1:8081/realms/${realm}/.well-known/openid-configuration"
upsert_env_value \
  "${web_env_file}" \
  "SIEM_OIDC_TOKEN_URL" \
  "http://127.0.0.1:8081/realms/${realm}/protocol/openid-connect/token"
upsert_env_value \
  "${web_env_file}" \
  "SIEM_OIDC_USERINFO_URL" \
  "http://127.0.0.1:8081/realms/${realm}/protocol/openid-connect/userinfo"
upsert_env_value \
  "${web_env_file}" \
  "SIEM_OIDC_END_SESSION_URL" \
  "${issuer}/protocol/openid-connect/logout"

systemctl restart siem-keycloak
for _ in $(seq 1 60); do
  if curl -fsS \
    "http://127.0.0.1:8081/realms/${realm}/.well-known/openid-configuration" \
    >/tmp/siem-keycloak-discovery.json 2>/dev/null; then
    break
  fi
  sleep 2
done

actual_issuer="$(
  python3 -c 'import json; print(json.load(open("/tmp/siem-keycloak-discovery.json", encoding="utf-8")).get("issuer", ""))'
)"
rm -f /tmp/siem-keycloak-discovery.json
if [[ "${actual_issuer}" != "${issuer}" ]]; then
  echo "Unexpected Keycloak issuer: ${actual_issuer}" >&2
  exit 1
fi

systemctl restart siem-web
systemctl is-active --quiet siem-keycloak siem-web nginx

printf 'issuer=%s\n' "${actual_issuer}"
printf 'services=active\n'
