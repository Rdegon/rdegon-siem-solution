# VM2 Processing Resilience Runbook

## Purpose

Current `VM2` role:

- Kafka node
- active processing node for `normalizer` and `filter`
- self-hosted runner target

This runbook covers the current Kafka-era resilience shape, not the retired Redis slice.

## Scope

- target VM: `VM2` `192.168.1.37`
- hostname: `siem-processing`
- services:
  - `siem-kafka`
  - `siem-normalizer`
  - `siem-normalizer@2`
  - `siem-filter`
  - `siem-filter@2`
  - `actions.runner.Rdegon-siem-solution.siem-vm2.service`

## Deploy And Smoke

- deploy script: `deploy/vm2_processing_resilience_deploy.py`
- smoke script: `deploy/vm2_processing_resilience_smoke.py`
- live env file: `/etc/siem/processing.env`
- live netplan file: `/etc/netplan/01-siem.yaml`

## What The Deploy Script Must Preserve

- canonical network layout and LAN DNS pin
- Kafka-backed processing configuration
- scale-out `normalizer` and `filter` template units
- runner-safe restart behavior when the job executes locally on `siem-vm2`

## Smoke Expectations

The smoke passes only if:

- `siem-kafka`, `siem-normalizer`, `siem-normalizer@2`, `siem-filter`, `siem-filter@2`, `ssh`, and the local runner are `active`
- VM2 hostname is `siem-processing`
- canonical netplan file exists and legacy duplicate netplan file stays absent
- GitHub runner DNS still resolves required Actions endpoints

## Manual Validation

```powershell
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -i "D:\University\Project_VPN\vpnadmin_ed25519" rdegon@192.168.1.37
```

```bash
sudo systemctl is-active siem-kafka siem-normalizer siem-normalizer@2 siem-filter siem-filter@2 actions.runner.Rdegon-siem-solution.siem-vm2.service
sudo systemctl cat siem-normalizer@.service
sudo systemctl cat siem-filter@.service
```

## Rollback

1. restore the latest `/tmp/siem-vm2-processing-backup-<timestamp>`
2. restore `/etc/siem/processing.env`
3. restore `/etc/netplan/01-siem.yaml`
4. restart:

```bash
sudo systemctl restart systemd-resolved ssh siem-kafka siem-normalizer siem-filter siem-normalizer@2 siem-filter@2 actions.runner.Rdegon-siem-solution.siem-vm2.service
```

## Notes

- Redis is retired from the live runtime path and should not be reintroduced on `VM2`.
- Historical Redis recovery notes remain in archival docs only.
