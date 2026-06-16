# SIEM detection pack generation report

- Pack: `siem-detection-pack-v1`
- Total rules: 487
- Active stream rules: 355
- Batch/correlation SQL rules: 132

## Status counts

- `active`: 355
- `active_batch`: 80
- `active_correlation`: 52

## Prefix counts

- `ALERT`: 5
- `AUTH`: 20
- `BCK`: 10
- `CH`: 16
- `CORR`: 46
- `DB`: 5
- `DCK`: 25
- `DNS`: 7
- `EDGE`: 6
- `GAME`: 12
- `GW`: 10
- `HB`: 20
- `IAM`: 20
- `IDS`: 15
- `ING`: 25
- `KFK`: 10
- `MC`: 8
- `MET`: 20
- `MONGO`: 8
- `NAV`: 6
- `NC`: 12
- `PG`: 10
- `PILOT`: 20
- `PROC`: 20
- `PVE`: 40
- `STR`: 6
- `SVC`: 15
- `SYSLOG`: 5
- `VAULT`: 5
- `VULN`: 15
- `WEB`: 15
- `WIN`: 25
- `WR`: 5

## Asset group counts

- `devops`: 43 rules; hosts: Gitea, GitHub, GitHub Runner, CI/CD
- `edge_gateway`: 109 rules; hosts: 102 lab-edge-01, 126 openclaw-gateway
- `game`: 128 rules; hosts: 100 minecraft-01, 130 gamepanel-01
- `identity`: 88 rules; hosts: Keycloak, SIEM IAM/SSO
- `linux_common`: 188 rules; hosts: all Linux VM/LXC
- `pilot`: 132 rules; hosts: 123 pilot-web-01, 124 pilot-db-01, 125 pilot-cache-01
- `proxmox`: 98 rules; hosts: pve
- `public_services`: 183 rules; hosts: 120 nextcloud-siem, 121 navidrome-01, 123 pilot-web-01, 126 openclaw-gateway, 130 gamepanel-01
- `siem_core`: 258 rules; hosts: 104 SIEM-Ingest, 105 SIEM-Processing, 106 SIEM-Storage, 107 SIEM-WEB, 108 SIEM-Transport
- `vuln`: 97 rules; hosts: 122 vuln-mgr-01
- `windows`: 72 rules; hosts: 101 win-test, 111 WIN-RTX-test
