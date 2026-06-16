# Deployment Runbook: VM4 Mongo Content Store

This runbook enables the live MongoDB-backed content store on `VM4`.

## Purpose

Use this when the content/document plane must run on `mongo` instead of filesystem snapshots.

The runbook now also handles the required VM CPU-profile remediation on Proxmox, because MongoDB 7 needs `AVX` and the original `VM4` guest profile did not expose it.

## Prerequisites

Required environment variables:

- `SIEM_VM4_HOST`
- `SIEM_VM4_USER`
- `SIEM_VM4_PASSWORD`
- `SIEM_VM4_BASE_DIR`
- `SIEM_VM4_MONGO_DB`
- `SIEM_VM4_MONGO_USER`
- `SIEM_VM4_MONGO_PASSWORD`

Required for automatic CPU-profile remediation:

- `SIEM_PROXMOX_HOST`
- `SIEM_PROXMOX_USER`
- `SIEM_PROXMOX_PASSWORD`
- `SIEM_VM4_VMID`

## Command

```powershell
python C:\Users\lolol\Documents\Playground\remote-edit2\deploy\vm4_content_store_mongo_cutover.py
```

## What The Script Does

1. Verifies whether the `VM4` guest already exposes `AVX`.
2. If not, connects to Proxmox and:
   - backs up `qm config <vmid>`
   - changes the guest CPU profile to `x86-64-v3`
   - reboots the VM
   - waits for SSH to return
3. Backs up:
   - `/etc/siem/web.env`
   - `/etc/mongod.conf`
   - `/opt/siem/runtime-docs`
4. Installs and enables `mongod`.
5. Creates or updates the Mongo user for the content database.
6. Enables Mongo authorization in `/etc/mongod.conf`.
7. Updates `web.env`:
   - `SIEM_CONTENT_STORE_BACKEND=mongo`
   - `SIEM_MONGO_URI=...`
   - `SIEM_MONGO_DB=...`
8. Runs `migrate_content_store()` through the live web application code.
9. Restarts `siem-web`.

## Validation

### Service checks

```bash
sudo systemctl is-active mongod siem-web
```

Expected:

- `active`
- `active`

### API checks

```bash
curl -k https://127.0.0.1/api/content/storage
curl -k https://127.0.0.1/api/health/transport
```

Expected highlights:

- `/api/content/storage`
  - `backend=mongo`
  - `migration_status=completed`
- `/api/health/transport`
  - `content_store_backend=mongo`
  - `stream_state_backend=sqlite`

### Full authenticated smoke

```powershell
python C:\Users\lolol\Documents\Playground\remote-edit2\deploy\vm4_enterprise_foundation_smoke.py
```

The current smoke expects `mongo` as the live content-store backend by default.

## Backup Anchors

The script prints two important backup roots:

- content cutover backup:
  - `/tmp/siem-web-content-store-backup-<timestamp>`
- Proxmox CPU-profile backup:
  - `/tmp/siem-vm4-cpu-profile-backup-<timestamp>`

## Rollback

If Mongo content-store enablement must be rolled back:

1. Restore `/etc/siem/web.env` from the printed backup root.
2. Set `SIEM_CONTENT_STORE_BACKEND=filesystem`.
3. Restart `siem-web`.
4. Stop `mongod` if you do not want it to stay provisioned.

If the issue is CPU-profile related and you must revert the VM profile too:

1. Inspect the saved Proxmox config backup.
2. Restore the original `qm set <vmid> --cpu ...` value.
3. Reboot the VM.

## Notes

- Do not store Mongo secrets in repo docs; keep them only in the lab-only operator bundle and access matrix.
- MongoDB is now live only for the content/document plane. It is not the control-plane database and not the event/alert store.
- This runbook does not change the live transport backend. Current transport truth is Kafka; Mongo remains only the content/document backend.
