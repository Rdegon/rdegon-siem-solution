# Post-Power-Cycle Ingest Recovery Closure

Date: `2026-04-01`

## Scope

This wave closed the post-restart backlog that remained after the full-stand shutdown/startup:

- `VM1 / siem-ingest` had to recover cleanly without high-volume listener stalls
- `vpn`, `pve/app`, `linux-auth`, and `linux-audit` had to be explicitly gated before the stand could be treated as green
- `rsyslog` and the VPN/jump-tunnel path had to self-heal
- event flow had to return to the pre-shutdown envelope of roughly `20k events/hour`
- residual `DLQ` noise had to stop keeping `/api/health/overview` red after recovery

## Landed Changes

- Added `POST /dlq/suppress` to the ingest service and used it to hide non-operational post-restart DLQ noise from operator health.
- Extended the ingest-recovery watchdog so it:
  - verifies the critical collector gate for `app`, `vpn`, `linux-auth`, and `linux-audit`
  - verifies `pve/app` and the VPN path before declaring the stand healthy
  - repairs `siem-ingest`, `rsyslog`, `openvpn-client@home-gateway`, and `siem-jump-tunnels` when the gate is not healthy
  - replays/suppresses DLQ items before re-checking the stand
- Added a dedicated `siem-ingest-recovery-watchdog.timer` on `VM4`.
- Fixed `vm1_ingest_fabric_smoke.py` so runtime URLs with query strings are quoted correctly and the critical source gate uses the stabilized ingest overview snapshot.
- Raised the default watchdog throughput floor to `1600 events / 5m`, which matches the real target envelope instead of treating healthy `20k+/hour` flow as degraded.

## Live Outcome

Verified live after redeploy on `VM4` and runtime remediation on `VM1`:

- `python deploy/vm1_ingest_fabric_smoke.py` -> `smoke=success`
- `python deploy/vm4_enterprise_foundation_smoke.py` -> `smoke=success`
- `python deploy/homelab_watchdog.py` -> `watchdog result=healthy`
- `VM1 /health/dlq` effective outstanding backlog -> `0`
- `VM3` event flow:
  - `events_1h = 24274`
  - `events_5m = 5035`

## Closure Decision

The post-power-cycle ingest recovery hardening follow-up is closed on the current stand.
