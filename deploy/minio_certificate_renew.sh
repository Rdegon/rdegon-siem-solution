#!/usr/bin/env bash
set -euo pipefail

readonly CERT=/etc/minio/certs/public.crt
readonly KEY=/etc/minio/certs/private.key
readonly ROOT=/usr/local/share/ca-certificates/soc-root-ca.crt
readonly CA_URL=https://10.20.10.132:9000

if ! step certificate needs-renewal "${CERT}" --expires-in 240h; then
  exit 0
fi

step ca renew "${CERT}" "${KEY}" \
  --force \
  --ca-url "${CA_URL}" \
  --root "${ROOT}"
chown minio-user:minio-user "${CERT}" "${KEY}"
chmod 0644 "${CERT}"
chmod 0600 "${KEY}"
systemctl restart minio.service

for attempt in $(seq 1 30); do
  if curl -fsS https://10.20.10.133:9000/minio/health/ready >/dev/null; then
    exit 0
  fi
  sleep 2
done
exit 1
