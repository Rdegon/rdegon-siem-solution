# Deployment Runbook: VM5 Processing Wave Preparation

This runbook captures the repo-owned preparation path for turning `VM5` into the secondary Kafka-era processing node.

## Scope

- seed `/etc/siem/processing.env` on `VM5`
- sync the shared processing runtime from the repo
- install VM5-specific `normalizer` and `filter` systemd templates
- optionally enable `siem-normalizer@1`, `siem-filter@1`, `siem-normalizer@2`, `siem-filter@2`

## Repo Artifacts

- [vm5_processing_prepare.py](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/vm5_processing_prepare.py)
- [vm5_processing_smoke.py](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/vm5_processing_smoke.py)
- [siem-normalizer@.service](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/vm5/siem-normalizer@.service)
- [siem-filter@.service](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/vm5/siem-filter@.service)
- [prepare-kafka-wave.yml](C:/Users/lolol/Documents/Playground/remote-edit2/.github/workflows/prepare-kafka-wave.yml)

## Manual Execution

Run on `VM5` through the self-hosted runner or directly on the node:

```powershell
$env:SIEM_VM5_PASSWORD="..."
$env:SIEM_VM5_EXPECT_HOST="siem-transport"
$env:SIEM_VM5_ENABLE_PROCESSING="0"
python deploy/vm5_processing_prepare.py
python deploy/vm5_processing_smoke.py
```

To enable the processing units immediately:

```powershell
$env:SIEM_VM5_ENABLE_PROCESSING="1"
python deploy/vm5_processing_prepare.py
python deploy/vm5_processing_smoke.py
```

## What The Prepare Step Writes

- `/etc/siem/processing.env`
- `/etc/systemd/system/siem-normalizer@.service`
- `/etc/systemd/system/siem-filter@.service`

The environment is seeded for the Kafka wave with:

- `SIEM_TRANSPORT_BACKEND=dual`
- `SIEM_TRANSPORT_CONSUMER_BACKEND=kafka`
- `SIEM_KAFKA_BOOTSTRAP_SERVERS=192.168.1.35:9092,192.168.1.37:9092,192.168.1.40:9092`

## Rollback

Every run creates a backup in `/tmp/siem-vm5-processing-backup-*`.

Rollback is:

1. stop any enabled `siem-normalizer@*` and `siem-filter@*` units on `VM5`
2. restore the backed-up `/etc/siem/processing.env`
3. restore the backed-up systemd templates if needed
4. `systemctl daemon-reload`

## Notes

- This runbook prepares `VM5` for the Kafka-era processing role; it does not itself provision Kafka binaries.
- The Kafka node prepare/smoke path remains in [deployment_runbook_kafka_vm5_wave_2026-03-22.md](C:/Users/lolol/Documents/Playground/remote-edit2/docs/deployment_runbook_kafka_vm5_wave_2026-03-22.md).
