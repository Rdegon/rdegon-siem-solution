# Power Recovery: 2026-03-13

## Incident Summary

A power event rebooted the home-lab stand and left `VM3` and `VM4` partially alive but unreachable on their expected LAN addresses.

Observed impact:

- `VM1` and `VM2` stayed reachable and their core services were still active.
- `VM3` and `VM4` accepted TCP connections from some paths, but did not answer ARP or complete SSH banners on the lab LAN.
- `VM1` ingest kept receiving data from the surviving sources, but the storage and web nodes stopped forwarding fresh Linux audit telemetry from their expected IPs.
- `siem-jump-tunnels.service` on `VM4` entered a restart loop.

## Root Cause

Two separate drifts surfaced after the reboot:

1. `VM3` and `VM4` both booted with the primary NIC renamed from `ens19` to `ens18`, while netplan still matched only `ens18` by interface name and allowed DHCP to reassign addresses.
2. `VM4` infrastructure still assumed the old routing path for remote reverse tunnels:
   - `siem-jump-tunnels.service` targeted `vpnadmin_rdegon@176.108.250.215`
   - `openvpn` helper scripts hardcoded `ens19`

After the NIC rename, the OpenVPN client itself still came up, but the jump-tunnel service no longer had a reliable route to the jump SSH endpoint and the helper scripts no longer matched the live LAN interface.

## Recovery Actions

The following actions restored the stand:

1. Offline filesystem checks were run on the `VM3` and `VM4` root disks from `Proxmox`.
2. `VM3` and `VM4` netplan configs were rewritten offline to bind the NIC by MAC address and keep the expected static IPs:
   - `VM3` -> `192.168.1.38`
   - `VM4` -> `192.168.1.39`
3. `cloud-init` network regeneration was disabled on both nodes via `99-disable-network-config.cfg`.
4. `VM4` OpenVPN helper scripts were rewritten to discover the live LAN interface dynamically instead of hardcoding `ens19`.
5. `siem-jump-tunnels.service` was updated to use the VPN-side jump endpoint `vpnadmin_rdegon@10.66.66.1` instead of the public SSH path.
6. `openvpn-client@home-gateway` and `siem-jump-tunnels` were restarted and verified.

## Validation

After recovery:

- `VM1`, `VM2`, `VM3`, and `VM4` all answered SSH on their expected LAN IPs.
- `VM3` core services were active:
  - `clickhouse-server`
  - `siem-writer`
  - `siem-stream-corr`
  - `siem-batch-corr`
- `VM4` core services were active:
  - `siem-web`
  - `nginx`
  - `openvpn-client@home-gateway`
  - `siem-jump-tunnels`
- `VM1` ingest health showed fresh telemetry again from:
  - `192.168.1.38`
  - `192.168.1.39`
  - `192.168.1.37`
  - `192.168.1.35`
  - `192.168.1.120`
  - `192.168.1.121`
  - `192.168.1.101`
- `ClickHouse` on `VM3` showed fresh events in the last 30 minutes from:
  - `siem-ingest`
  - `siem-processing`
  - `siem-storage`
  - `siem-web`
  - `nextcloud-siem`
  - `pve`
  - `vuln-siem`

## Expected Residual Signals

These signals are expected after the incident and do not indicate a current outage:

- `VM1` source health may keep historical `192.168.1.31` and `192.168.1.32` records in delayed state until they age out.
- `vuln-siem` is timer-driven from `192.168.1.121`, so it can appear delayed between scheduled runs.
- The generic `vm1-smoke` source remains stale by design and should not be treated as production telemetry.

## Follow-Up Hardening

- Keep the `VM4` jump/OpenVPN assets under version control:
  - `deploy/vm4/siem-jump-tunnels.service`
  - `deploy/vm4/home-gateway-up.sh`
  - `deploy/vm4/home-gateway-down.sh`
- Make `deploy/vm4_enterprise_foundation_deploy.py` install those assets on every rollout.
- Preserve the MAC-pinned static network configuration for `VM3` and `VM4` during future rebuilds or cloning operations.
