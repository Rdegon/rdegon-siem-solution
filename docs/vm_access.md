# VM Access Guide

## Purpose

Use this guide for current LAN and remote VPN access. Secrets and individual
VPN profiles are intentionally kept outside Git in the operator access bundle.

## Entry Points

| Service | Address |
| --- | --- |
| OpenVPN | `176.108.250.215:443/TCP` |
| SIEM Web and SSO | `https://192.168.3.102/app` |
| SIEM ingest | `https://192.168.3.102:8443` |
| Proxmox | `https://192.168.3.101:8006` |
| Operator workstation RDP | `192.168.3.81:3389` |
| OPNsense NGFW | `https://192.168.3.103` |

`45.89.111.208` is an outbound VLESS host. It is not a management entry
point.

## Current Inventory

| ID | Address | Role |
| --- | --- | --- |
| PVE | `192.168.3.101` | Proxmox hypervisor |
| 102 | `192.168.3.102`, `10.20.10/20/30/40.1` | public SIEM entry, ingress proxy and recovery edge |
| 103 | `192.168.3.103`, `10.20.10/20/30/40.254` | production OPNsense router, DNS, NGFW and inline IPS |
| 104 | `10.20.10.104` | SIEM ingest |
| 105 | `10.20.10.105` | SIEM processing |
| 106 | `10.20.10.106` | SIEM storage and correlation |
| 107 | `10.20.10.107` | SIEM Web, Keycloak, Vault, VPN anchor |
| 108 | `10.20.10.108` | SIEM transport and standby |
| 111 | `192.168.3.81` | Windows operator workstation and source |
| 120 | `10.20.20.120` | Nextcloud |
| 121 | `10.20.20.121` | Navidrome |
| 122 | `10.20.30.122` | Greenbone/OpenVAS |
| 123-125 | `10.20.30.123-125` | pilot Web, DB and cache |
| 127 | `10.20.10.127` | Zeek NDR |
| 128 | `10.20.10.128` | Velociraptor DFIR |
| 129 | `10.20.30.129` | static analysis |
| 130 | `10.20.20.130` | Gamepanel and Pterodactyl Wings |
| 131-133 | `10.20.30.131-133` | MISP, PKI and evidence storage |

## OpenVPN Access

Import the individual `siem-full-lab` profile into OpenVPN Connect or the
OpenVPN Community Client. The profile installs split routes for:

- `192.168.3.0/24`;
- `10.20.10.0/24`;
- `10.20.20.0/24`;
- `10.20.30.0/24`;
- `10.20.40.0/24`.

The VPN profile contains a private key. Do not commit, share or place it in a
public cloud. Revoke and reissue the certificate if the file is lost.

### Managed profiles in SIEM

The SIEM page `Средства защиты -> VPN` monitors the live OpenVPN access plane
and can issue route-limited client profiles from the jump-host CA. The
supported presets are ingest-only, ingest-and-Web, core administration and the
full segmented lab. A generated profile is available only to an authenticated
operator with `response:run`; its inline private key is stored outside Git with
mode `0600` until the profile is revoked.

Revoking a profile from its detail drawer updates the OpenVPN CRL, removes the
download artifact and restarts the jump-host OpenVPN unit without changing the
VM107 autostart configuration. VLESS is intentionally shown as retired outbound
egress because no inbound VLESS remote-access server is currently deployed.

To reinstall the controller after rebuilding VM107, keep the operator key
outside the repository and run:

```powershell
$env:SIEM_PROXMOX_PASSWORD = '<from operator secret store>'
$env:SIEM_VPNADMIN_SSH_KEY_PATH = '<path to vpnadmin SSH key>'
python deploy/install_managed_vpn_controller.py
```

OPNsense management access is intentionally restricted. When direct access to
`192.168.3.103` is denied, connect by RDP to `192.168.3.81` and manage
OPNsense from the operator workstation.

## Access-Plane Health

The local WireGuard service `siem-vpn-access.service` runs on Proxmox and
installs routes to every internal segment through OPNsense. The remote peer
must be online for Internet-to-lab connectivity. The expected remote path is:

```text
operator -> remote WireGuard peer -> Proxmox wg0 -> OPNsense -> routed lab networks
```

Check `wg show wg0` before relying on remote access. A zero latest-handshake
value means that the external peer is unavailable even when all local routes
and services are healthy.
