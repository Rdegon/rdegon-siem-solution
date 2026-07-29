# Security Operations UI Closure 2026-07-29

This record defines the production behavior of the security control, incident,
topology and cold-start surfaces.

## Security Controls

- NGFW mutations call the OPNsense runtime API and require `response:run`.
- Supported firewall operations are create, update, enable, disable and delete.
- A rule with ports must use TCP, UDP or TCP/UDP rather than protocol `any`.
- IPS ruleset changes are transactional: a failed apply restores the previous
  selection.
- Suricata reload reports the device result; a rendered button without a real
  backend operation is not an accepted implementation.

Release and verification:

```powershell
python deploy/security_controls_release.py
python -m pytest -q tests/test_opnsense_control_runtime.py
```

## Incident And Telegram Queue

The bot polls only the main aggregated queue. A card that leaves that queue is
marked `expired`; deletion from Telegram is attempted after the configured
grace period. Telegram may reject deletion of an old message, but that message
must not remain an active SIEM delivery record.

The Web delivery contract accepts `deleted`, `expired` and `delete_failed` as
card lifecycle states. Transport exceptions are redacted before logging so a
Telegram bot token cannot appear in the journal.

Verification:

```powershell
python deploy/incident_bot_release.py
python -m pytest -q tests/test_incident_delivery_runtime.py tests/test_incident_telegram_bot.py
```

The current incident page must report a delivery queue count equal to the
number of incidents shown in the main queue.

## Topology

Blueprint mode uses the local `@maxgraph/core` library. It does not load a
third-party editor or send topology data outside the platform.

Placement priority is:

1. explicit `network_segment`;
2. IP CIDR;
3. asset group and platform kind;
4. `unassigned`.

The current CIDR mapping is:

| Segment | CIDR |
| --- | --- |
| `sec` | `10.20.10.0/24` |
| `servers-games` | `10.20.20.0/24` |
| `lab` | `10.20.30.0/24` |
| `users` | `10.20.40.0/24` |
| `mgmt` | `192.168.3.0/24` |
| `legacy` | `192.168.1.0/24` |

New source, fleet and discovery records are included without a fixed
first-N truncation and are placed automatically. Segment rows use their actual
content height, so populated zones cannot overlap the next row. Operators with
`cmdb:write` may move nodes and persist the layout through
`GET/PUT /api/topology/layout`.

## Cold Start

`siem-cold-start-reconcile.timer` runs after boot and every five minutes. The
reconciler starts and verifies the core SIEM, OPNsense-adjacent platform
services, source workloads and SOC services. A healthy run covers the core
VMs, platform VMs, platform containers and intentionally start-only guests.

Verify both the guest startup order and the service result:

```powershell
python deploy/configure_proxmox_startup_order.py
python deploy/proxmox_fleet_wave_smoke.py
```

Do not declare recovery complete only from the Proxmox `running` state. The
service-level probes and current source event timestamps must also pass.
