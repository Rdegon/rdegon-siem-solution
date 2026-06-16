# Jump Host Access-Plane Remediation: 2026-05-06

## Scope

This note records the live remediation for `176.108.250.215` / `vpn-host-khanov`.

## Root Cause

The jump-host hardening completed on `2026-04-01` intentionally closed public SSH on `176.108.250.215:22`; SSH is allowed only through the OpenVPN side as `10.66.66.1:22`.

Two legacy services on `siem-ingest` still targeted the public SSH endpoint:

- `siem-jump-lan-access.service`
- `siem-jump-syslog-tunnel.service`

Both services were still marked active because `autossh` was running, but their child SSH process was failing with `Connection refused`. This broke jump-host syslog delivery and left `vpn-host-khanov` absent from ClickHouse telemetry.

## Fix Applied

`siem-web` already owns the healthy OpenVPN access-plane connection. Its `siem-jump-tunnels` runtime was expanded to hold:

- compatibility SSH reverse ports `10035`, `10037`, `10038`, `10039`
- compatibility HTTPS reverse ports `10435`, `10439`
- jump-host syslog reverse ports `5514 -> siem-ingest:1514` and `5517 -> siem-ingest:1517`
- existing recovery SSH ports `22102`, `22104-22108`, `22120-22126`

The updated source file is `deploy/vm4/siem-jump-tunnels.sh`.

The two legacy `siem-ingest` services were disabled and stopped because they cannot operate against the hardened public SSH policy.

## Verification

Live checks after remediation:

- `openvpn-client@home-gateway` on `siem-web`: active.
- `siem-jump-tunnels` on `siem-web`: active.
- Jump-host listeners now include `127.0.0.1:5514` and `127.0.0.1:5517`.
- `siem-ingest` has established TCP sessions from the VM4 tunnel to `1514` and `1517`.
- Fresh marker events sent from `vpn-host-khanov` arrived in ClickHouse with `host_name = vpn-host-khanov` and `log_source = vpn-host-khanov`.

Validation query result included:

```text
2026-05-06 16:33:55 | vpn-host-khanov | syslog | jump-current-siem-daemon-ok
2026-05-06 16:33:55 | vpn-host-khanov | syslog | jump-current-siem-telemetry-ok
```

## Additional Cleanup

`osconfig.service` on the jump-host was disabled because it was restarting continuously with `Unable to register agent: no token provided` and producing high-volume noise in syslog.

## Operational Rule

Future jump-host recovery and telemetry tunnels must use `10.66.66.1` through OpenVPN. Do not restore `siem-ingest -> 176.108.250.215:22`; that path conflicts with the current security model.
