#!/bin/bash
set -euo pipefail

VAULT_BIN="/opt/siem/vault/current/vault"
OPERATOR_STATE="/etc/siem/vault-operator.json"
VAULT_ADDR_VALUE="${SIEM_VAULT_ADDR:-${VAULT_ADDR:-http://127.0.0.1:8200}}"
STATUS_PATH="/tmp/siem-vault-status.json"

export VAULT_ADDR="$VAULT_ADDR_VALUE"
export VAULT_CLIENT_TIMEOUT="${VAULT_CLIENT_TIMEOUT:-5s}"

if [[ ! -x "$VAULT_BIN" ]]; then
  echo "vault binary missing: $VAULT_BIN" >&2
  exit 1
fi

rm -f "$STATUS_PATH"
for _attempt in $(seq 1 45); do
  if timeout 6s "$VAULT_BIN" status -format=json >"$STATUS_PATH" 2>/dev/null; then
    break
  fi
  # Vault returns a non-zero code while sealed, but still emits valid JSON.
  # Do not burn the whole systemd start timeout waiting for an exit code 0.
  if [[ -s "$STATUS_PATH" ]]; then
    break
  fi
  sleep 2
done

python3 - <<'PY'
import json
import os
import subprocess
from pathlib import Path

vault_bin = Path("/opt/siem/vault/current/vault")
status_path = Path("/tmp/siem-vault-status.json")
operator_path = Path("/etc/siem/vault-operator.json")
env = dict(os.environ)
env["VAULT_ADDR"] = env.get("VAULT_ADDR", "http://127.0.0.1:8200")

if not status_path.exists():
    raise SystemExit("vault status probe did not produce a status file")

status = json.loads(status_path.read_text(encoding="utf-8"))
if not bool(status.get("initialized", False)):
    raise SystemExit(0)
if not bool(status.get("sealed", True)):
    raise SystemExit(0)

if not operator_path.exists() or operator_path.stat().st_size == 0:
    raise SystemExit(0)

operator_state = json.loads(operator_path.read_text(encoding="utf-8"))
keys = list(operator_state.get("unseal_keys_b64") or [])[:3]
if len(keys) < 3:
    raise SystemExit("vault operator state does not contain enough unseal keys")

for key in keys:
    subprocess.run(
        [str(vault_bin), "operator", "unseal", str(key)],
        env=env,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

final_status = subprocess.run(
    [str(vault_bin), "status", "-format=json"],
    env=env,
    check=True,
    capture_output=True,
    text=True,
)
payload = json.loads(final_status.stdout or "{}")
if bool(payload.get("sealed", True)):
    raise SystemExit("vault is still sealed after automatic unseal")
PY

rm -f "$STATUS_PATH"
