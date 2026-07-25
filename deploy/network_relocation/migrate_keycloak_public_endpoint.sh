#!/usr/bin/env bash
set -euo pipefail

public_base="${1:-https://192.168.3.102}"
realm="${SIEM_KEYCLOAK_REALM:-siem}"
client_id="${SIEM_OIDC_CLIENT_ID:-siem-web}"
env_file="${SIEM_KEYCLOAK_ENV_FILE:-/etc/siem/keycloak.env}"
kcadm="${SIEM_KCADM_PATH:-/opt/siem/keycloak/26.4.4/bin/kcadm.sh}"
config_file="$(mktemp /tmp/siem-kcadm-cutover.XXXXXX)"
trap 'rm -f "${config_file}"' EXIT

read_env_value() {
  local key="$1"
  sed -n "s/^${key}=//p" "${env_file}" | tail -1
}

admin_user="$(read_env_value KC_BOOTSTRAP_ADMIN_USERNAME)"
admin_password="$(read_env_value KC_BOOTSTRAP_ADMIN_PASSWORD)"
if [[ -z "${admin_user}" || -z "${admin_password}" ]]; then
  echo "Keycloak bootstrap admin credentials are missing from ${env_file}" >&2
  exit 1
fi

"${kcadm}" config credentials \
  --config "${config_file}" \
  --server "http://127.0.0.1:8081" \
  --realm master \
  --user "${admin_user}" \
  --password "${admin_password}" >/dev/null

internal_id="$(
  "${kcadm}" get clients \
    --config "${config_file}" \
    -r "${realm}" \
    -q "clientId=${client_id}" \
    --fields id \
    --format csv \
    --noquotes |
    head -1
)"
if [[ -z "${internal_id}" ]]; then
  echo "Keycloak client ${client_id} was not found in realm ${realm}" >&2
  exit 1
fi

"${kcadm}" update "clients/${internal_id}" \
  --config "${config_file}" \
  -r "${realm}" \
  -s "rootUrl=\"${public_base}\"" \
  -s "baseUrl=\"${public_base}\"" \
  -s "redirectUris=[\"${public_base}/auth/oidc/callback\"]" \
  -s "webOrigins=[\"${public_base}\"]"

"${kcadm}" get "clients/${internal_id}" \
  --config "${config_file}" \
  -r "${realm}" \
  --fields clientId,redirectUris,webOrigins,rootUrl,baseUrl
