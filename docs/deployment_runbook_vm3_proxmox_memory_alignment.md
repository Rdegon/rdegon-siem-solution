# Deployment Runbook: VM3 Proxmox Memory Alignment

Use this runbook when `VM3` looks "full" in Proxmox even though the guest still has large `MemAvailable` headroom.

## Purpose

This slice aligns `VM106` memory behavior across:

- Proxmox host accounting
- the Linux guest on `VM3`
- ClickHouse runtime expectations

It does **not** add RAM by default. The goal is to stop the storage node from pinning near the full `28 GiB` guest ceiling just because Linux page cache grew, while still leaving the storage services with safe headroom.

## Default Policy

- Proxmox VMID: `106`
- max guest memory remains `28672 MiB`
- balloon floor becomes `24576 MiB`
- host-reported memory should stay below `24 GiB`
- guest `MemAvailable` should remain above `12 GiB`

## Required Environment

- `SIEM_VM3_HOST`
- `SIEM_VM3_USER`
- `SIEM_VM3_PASSWORD`
- `SIEM_PROXMOX_HOST`
- `SIEM_PROXMOX_USER`
- `SIEM_PROXMOX_PASSWORD`

Optional overrides:

- `SIEM_VM3_VMID`
- `SIEM_VM3_PROXMOX_MEMORY_MIB`
- `SIEM_VM3_PROXMOX_BALLOON_MIB`
- `SIEM_VM3_PROXMOX_MAX_REPORTED_MEMORY_BYTES`
- `SIEM_VM3_MIN_AVAILABLE_MEMORY_BYTES`
- `SIEM_VM3_MAX_GUEST_TOTAL_BYTES` (`0` disables the guest-total ceiling check; the default path relies on host-reported memory plus guest available memory)

## Commands

```powershell
python C:\Users\lolol\Documents\Playground\remote-edit2\deploy\vm3_proxmox_memory_alignment.py
python C:\Users\lolol\Documents\Playground\remote-edit2\deploy\vm3_proxmox_memory_smoke.py
```

## What The Deploy Script Changes

1. backs up `qm config 106`
2. ensures `agent: 1` on the Proxmox VM config
3. persists `balloon: 24576` on `VM106`
4. installs and enables `qemu-guest-agent` inside the guest if it is missing
5. applies a live balloon target through QMP so the change is visible immediately instead of waiting for a later pressure event
6. validates that ClickHouse and the storage workers remain healthy after the guest memory drops

## Validation

The smoke path verifies:

- Proxmox config keeps the expected balloon floor
- Proxmox guest exec works against `VM106`
- host-reported VM memory falls below the configured ceiling
- guest available memory remains healthy after the alignment
- guest `MemAvailable` remains healthy
- `qemu-guest-agent`, `clickhouse-server`, `siem-writer`, `siem-writer@2`, `siem-stream-corr`, `siem-batch-corr`, and `siem-alert-agg` are all active

## When To Add More RAM Instead

Do not add RAM only because Proxmox reports high memory usage while:

- `MemAvailable` inside the guest is still high
- swap is near zero
- ClickHouse pressure remains `healthy`

Consider adding RAM only if these all hold:

- guest `MemAvailable` stays low after balloon alignment
- ClickHouse pressure becomes `high` or `critical`
- merges or query concurrency start to stall because of real memory pressure
