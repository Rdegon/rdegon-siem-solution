#!/usr/bin/env bash
set -euo pipefail

public_ip="${SIEM_WEB_PUBLIC_IP:-192.168.3.102}"
internal_ip="${SIEM_WEB_INTERNAL_IP:-10.20.10.107}"
dns_name="${SIEM_WEB_DNS_NAME:-siem-web.lab.home.arpa}"
cert_path="${SIEM_WEB_CERT_PATH:-/etc/siem/tls/web.crt}"
key_path="${SIEM_WEB_KEY_PATH:-/etc/siem/tls/web.key}"
force="${SIEM_WEB_CERT_FORCE:-0}"

certificate_has_expected_names() {
  [[ -f "${cert_path}" ]] || return 1
  local names
  names="$(openssl x509 -in "${cert_path}" -noout -ext subjectAltName 2>/dev/null || true)"
  grep -Fq "IP Address:${public_ip}" <<<"${names}" &&
    grep -Fq "IP Address:${internal_ip}" <<<"${names}"
}

if [[ "${force}" != "1" ]] && certificate_has_expected_names; then
  echo "Web certificate already contains the expected public and internal IP addresses."
  exit 0
fi

install -d -m 0750 "$(dirname "${cert_path}")"
backup_root="/var/backups/siem-web-tls-$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 0700 "${backup_root}"
[[ -f "${cert_path}" ]] && cp -a "${cert_path}" "${backup_root}/web.crt"
[[ -f "${key_path}" ]] && cp -a "${key_path}" "${backup_root}/web.key"

temp_dir="$(mktemp -d /etc/siem/tls/.web-renew.XXXXXX)"
trap 'rm -rf "${temp_dir}"' EXIT
openssl req -x509 -nodes -newkey rsa:3072 -sha256 -days 825 \
  -keyout "${temp_dir}/web.key" \
  -out "${temp_dir}/web.crt" \
  -subj "/CN=${public_ip}" \
  -addext "subjectAltName=IP:${public_ip},IP:${internal_ip},DNS:${dns_name}"

install -m 0600 "${temp_dir}/web.key" "${key_path}"
install -m 0644 "${temp_dir}/web.crt" "${cert_path}"
nginx -t
systemctl reload nginx
openssl x509 -in "${cert_path}" -noout -subject -issuer -fingerprint -sha256 -ext subjectAltName
