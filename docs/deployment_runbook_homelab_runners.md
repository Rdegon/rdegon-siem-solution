# Homelab Runners Runbook

## Goal

Run CD from the distributed homelab runner plane while keeping ownership and health strict enough for unattended `main` deploys.

## Runner Layout

- `VM1` -> `siem-vm1`
- `VM2` -> `siem-vm2`
- `VM3` -> `siem-vm3`
- `VM4` -> `siem-vm4`
- `VM5` -> `siem-vm5`
- shared pool label -> `siem-homelab`

## Ownership Rule

These two labels are single-owner labels and must never drift:

- `siem-vm2` only on `VM2`
- `siem-vm5` only on `VM5`

The watchdog and smoke path should fail if:

- `siem-vm2` is absent on `VM2`
- `siem-vm5` is absent on `VM5`
- either label appears on the wrong node

## Standard Workflow Path

- `.github/workflows/validate-main.yml` validates `main`
- `.github/workflows/deploy-homelab.yml` performs the standard production rollout after `Validate Main`
- `.github/workflows/watchdog-homelab.yml` performs scheduled stand verification and repair

`deploy-homelab.yml` is the only standard release path for production-green.

## Provisioning

Provision one runner:

```powershell
$env:GITHUB_PAT = "<repo PAT>"
$env:RUNNER_TARGET_HOST = "192.168.1.35"
$env:RUNNER_TARGET_USER = "rdegon"
$env:RUNNER_TARGET_PASSWORD = "<vm password>"
$env:RUNNER_NAME = "siem-vm1"
$env:RUNNER_LABELS = "siem-homelab,siem-vm1"
python .\deploy\github_runner_provision.py
```

Provision the whole plane:

```powershell
python .\deploy\provision_homelab_runners.py
```

## Validation

Check on the target node:

```bash
sudo systemctl status actions.runner.Rdegon-siem-solution.siem-vm2.service
sudo systemctl status actions.runner.Rdegon-siem-solution.siem-vm5.service
```

Run the watchdog:

```powershell
python .\deploy\homelab_watchdog.py
```

## Recovery Order

1. verify the runner exists on the intended node
2. remove any duplicate ownership on the wrong node
3. restart the correct runner service
4. rerun the watchdog
5. only then rerun the deploy workflow
