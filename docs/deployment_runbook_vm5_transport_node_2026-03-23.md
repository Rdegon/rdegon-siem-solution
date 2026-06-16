# VM5 Transport Node Runbook

## Goal

Provision `VM5` as the transport and warm-standby processing node for the Kafka migration wave.

Current target identity:

- Proxmox VMID: `108`
- hostname: `siem-transport`
- LAN address: `192.168.1.40`
- runner name: `siem-vm5`
- live repo root: `/opt/siem/siem-solution`

Current live state as of `2026-03-23`:

- guest provisioned and reachable over LAN SSH
- runner `siem-vm5` is online
- standby processing units `siem-normalizer@1/@2` and `siem-filter@1/@2` are active
- Kafka wave is `prepared_only` on `VM5`

## Provision From Workstation

Required env:

```powershell
$env:SIEM_PROXMOX_HOST = "192.168.1.101"
$env:SIEM_PROXMOX_USER = "root"
$env:SIEM_PROXMOX_PASSWORD = "<from operator bundle>"
$env:SIEM_VM5_HOST = "192.168.1.40"
$env:SIEM_VM5_USER = "rdegon"
$env:SIEM_VM5_PASSWORD = "<from operator bundle>"
$env:SIEM_VM5_VMID = "108"
$env:GITHUB_PAT = "<repo PAT>"
python C:\Users\lolol\Documents\Playground\remote-edit2\deploy\vm5_transport_provision.py
```

This flow:

- clones `VM105` to `VM108` if the guest does not exist
- sets the guest hostname and static LAN identity
- enables `qemu-guest-agent`
- enables direct SSH on `192.168.1.40`
- provisions the `siem-vm5` GitHub runner when `GITHUB_PAT` is present

## Provision Smoke

```powershell
$env:GITHUB_REPOSITORY = "Rdegon/siem-solution"
$env:GITHUB_TOKEN = "<repo PAT>"
python C:\Users\lolol\Documents\Playground\remote-edit2\deploy\vm5_transport_provision_smoke.py
```

Expected highlights:

- `qm status 108` reports `running`
- guest hostname is `siem-transport`
- `/etc/netplan/01-siem.yaml` contains `192.168.1.40/24`
- `qemu-guest-agent` and `ssh` are active
- GitHub runner `siem-vm5` is online

## Deploy VM5 Transport Wave

```powershell
$env:SIEM_VM5_HOST = "192.168.1.40"
$env:SIEM_VM5_USER = "rdegon"
$env:SIEM_VM5_PASSWORD = "<from operator bundle>"
$env:SIEM_VM5_BASE_DIR = "/opt/siem/siem-solution"
$env:SIEM_VM5_EXPECT_HOST = "siem-transport"
python C:\Users\lolol\Documents\Playground\remote-edit2\deploy\vm5_transport_wave_deploy.py
python C:\Users\lolol\Documents\Playground\remote-edit2\deploy\vm5_transport_wave_smoke.py
```

This deploy slice:

- uploads VM5 processing and Kafka wave artifacts
- compiles the uploaded runtime
- applies `deploy/vm5_processing_prepare.py`
- applies `deploy/kafka_wave_prepare.py`
- validates the standby processing plane and Kafka scaffold

## GitHub Actions Path

Automatic deployment is now part of:

- [deploy-homelab.yml](C:/Users/lolol/Documents/Playground/remote-edit2/.github/workflows/deploy-homelab.yml)

The workflow target list now includes `vm5`.

## Recovery Notes

- if direct SSH fails but Proxmox still sees the guest, use `qm guest exec 108 -- ...` first
- if the runner drops offline, reprovision via [vm5_transport_provision.py](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/vm5_transport_provision.py)
- until Kafka is live, `siem-kafka` on `VM5` is expected to be in `prepared_only` or inactive state depending on the current wave

## Rollback Anchor

`vm5_transport_wave_deploy.py` creates:

```text
/tmp/siem-vm5-wave-backup-<timestamp>
```

`vm5_processing_prepare.py` creates:

```text
/tmp/siem-vm5-processing-backup-<timestamp>
```
