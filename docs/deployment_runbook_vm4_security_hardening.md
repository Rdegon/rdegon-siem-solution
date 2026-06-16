# VM4 Security Hardening Runbook

## Purpose

This runbook applies the `2026-03-21` web-auth and ingest-proxy hardening slice on `VM4`:

- migrate local web users from plaintext passwords in `/etc/siem/web.env` to `pbkdf2_sha256` hashes
- enable login rate limiting for `/auth/login`
- install the trusted ingest certificate from `VM1` onto `VM4`
- switch `VM4 -> VM1` ingest-proxy traffic from `CERT_NONE` to CA-backed TLS verification

## Scope

- target node: `VM4` (`192.168.1.39`)
- supporting source: `VM1` (`192.168.1.35`)
- live env file: `/etc/siem/web.env`
- trusted ingest CA path on `VM4`: `/etc/siem/tls/ingest-ca.crt`
- service restarted by this runbook: `siem-web`

## Credentials

Use the authoritative documents for live values:

- [OPERATOR_ACCESS_BUNDLE.md](C:/Users/lolol/Documents/Playground/product-docs/OPERATOR_ACCESS_BUNDLE.md)
- [SYSTEM_ACCESS_MATRIX.md](C:/Users/lolol/Documents/Playground/product-docs/SYSTEM_ACCESS_MATRIX.md)

Required environment variables:

- `SIEM_VM1_HOST`
- `SIEM_VM1_USER`
- `SIEM_VM1_PASSWORD`
- `SIEM_VM4_HOST`
- `SIEM_VM4_USER`
- `SIEM_VM4_PASSWORD`

Optional overrides:

- `SIEM_VM1_TLS_CERT_PATH`
- `SIEM_VM4_INGEST_CA_PATH`
- `SIEM_VM4_WEB_ENV_PATH`
- `SIEM_AUTH_RATE_LIMIT_WINDOW_SECONDS`
- `SIEM_AUTH_RATE_LIMIT_MAX_ATTEMPTS`
- `SIEM_AUTH_RATE_LIMIT_LOCKOUT_SECONDS`
- `SIEM_INGEST_TLS_VERIFY`
- `SIEM_OPERATOR_ADMIN_PASSWORD`
- `SIEM_OPERATOR_WEB_USERS_JSON`

## Tooling

Script:

- `deploy/vm4_security_hardening.py`

Validation:

- `deploy/vm4_enterprise_foundation_smoke.py`

## Standard Procedure

1. Ensure the latest code slice is already deployed to `VM4` with:

```powershell
$env:PYTHONIOENCODING="utf-8"
python C:\Users\lolol\Documents\Playground\remote-edit2\deploy\vm4_enterprise_foundation_deploy.py
```

2. Apply security hardening:

```powershell
python C:\Users\lolol\Documents\Playground\remote-edit2\deploy\vm4_security_hardening.py
```

The hardening script will:

- fetch `/etc/siem/tls/ingest.crt` from `VM1`
- back up `/etc/siem/web.env` and `/etc/siem/tls/ingest-ca.crt` on `VM4`
- rewrite `SIEM_WEB_USERS_JSON` to use `password_hash`
- remove `SIEM_ADMIN_DEFAULT_PASSWORD` and replace it with `SIEM_ADMIN_DEFAULT_PASSWORD_HASH`
- set auth rate-limit env values on `VM4`
- set `SIEM_INGEST_TLS_VERIFY=ca_file`
- set `SIEM_INGEST_TLS_CA_FILE=/etc/siem/tls/ingest-ca.crt`
- restart `siem-web`

3. Run smoke:

```powershell
python C:\Users\lolol\Documents\Playground\remote-edit2\deploy\vm4_enterprise_foundation_smoke.py
```

The smoke now also verifies:

- `/api/health/overview` includes auth hardening metrics
- `local_users_plaintext == 0`
- login rate limiting is enabled
- the React shell still loads after the auth hardening

## Rollback

Use the backup root printed by `vm4_security_hardening.py`, for example:

```text
/tmp/siem-web-security-hardening-<timestamp>
```

To roll back:

1. restore `/etc/siem/web.env` from the backup copy
2. restore `/etc/siem/tls/ingest-ca.crt` if needed
3. restart `siem-web`

## Notes

- This slice does not rotate the human-known passwords from the operator bundle; it removes plaintext storage from the live service env.
- The operator passwords remain duplicated in [OPERATOR_ACCESS_BUNDLE.md](C:/Users/lolol/Documents/Playground/product-docs/OPERATOR_ACCESS_BUNDLE.md) for manual support.
- If the ingest certificate on `VM1` is rotated, rerun `vm4_security_hardening.py` before expecting the `VM4` ingest proxy to work again.
- If live `web.env` already contains only hashes and you need to recover from a broken env rewrite, provide:
  - `SIEM_OPERATOR_ADMIN_PASSWORD`
  - `SIEM_OPERATOR_WEB_USERS_JSON`
  so the script can rebuild the hashed records from the operator-known credentials.
