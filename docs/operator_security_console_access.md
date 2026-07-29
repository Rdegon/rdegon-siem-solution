# Security console access

The SIEM uses two kinds of integration:

- managed SIEM control for OPNsense firewall and Suricata;
- authenticated pivots to native consoles for product-specific workflows.

The native consoles are not exposed as public Internet services. The edge
gateway publishes local/VPN-only console entry points on `192.168.3.102`, so
the standard SIEM workspace links work without a host route.

Operators who need direct access to the internal service addresses can install
the optional route through OPNsense:

```powershell
Start-Process powershell.exe -Verb RunAs -Wait -ArgumentList @(
  "-ExecutionPolicy", "Bypass",
  "-File", "C:\path\to\siem-solution-clean\deploy\operator_security_console_route.ps1"
)
```

The script installs a persistent `10.20.0.0/16 -> 192.168.3.103` route and
checks the Arkime, Velociraptor, Greenbone, MISP and MinIO console ports. VPN
clients must receive the same `10.20.0.0/16` route from their VPN profile.

| Workspace | Address |
| --- | --- |
| SIEM | `https://192.168.3.102/` |
| OPNsense | `https://192.168.3.103/` |
| Arkime | `http://192.168.3.102:8005/` |
| Velociraptor | `https://192.168.3.102:8889/app/index.html` |
| Greenbone | `http://192.168.3.102:9392/` |
| MISP | `https://192.168.3.102:8444/` |
| MinIO | `https://192.168.3.102:9001/` |
| Gitea | `http://192.168.3.102:3000/` |

## Cold-start order

Proxmox starts the core dependency chain in this order:

1. VM102 `lab-edge-01`, order 10.
2. VM103 `opnsense-edge-01`, order 20.
3. VM106 `SIEM-Storage`, order 30.
4. VM108 `SIEM-Transport`, order 35.
5. VM105 `SIEM-Processing`, order 40.
6. VM104 `SIEM-Ingest`, order 45.
7. VM107 `SIEM-WEB`, order 50.

The order is reproducible with:

```powershell
python deploy/configure_proxmox_startup_order.py
```

After an unclean shutdown, verify:

```text
https://192.168.3.102/healthz
https://192.168.3.102/realms/siem/.well-known/openid-configuration
https://192.168.3.103/
```

Then open SIEM `Data flow` and confirm that operational source and collector
counts contain no delayed or stale rows. The standby PostgreSQL node on VM104
must report `pg_is_in_recovery() = true` and one streaming WAL receiver. If WAL
segments were lost during the outage, use the guarded re-base procedure in
`docs/postgres_standby_recovery.md`.

Arkime and Velociraptor return HTTP 401 before native authentication; this is a
healthy endpoint response. Greenbone, MISP and MinIO should return their login
page with HTTP 200.

Do not forward these edge ports from the upstream Internet router. OPNsense and
Suricata changes should normally be made from the SIEM control page, where the
operation is validated, applied, verified and audited.

Design references:

- [Microsoft Sentinel incident automation](https://learn.microsoft.com/en-us/azure/sentinel/automate-incident-handling-with-automation-rules)
- [Elastic Security investigations](https://www.elastic.co/docs/solutions/security/investigate)
- [OPNsense firewall API](https://docs.opnsense.org/development/api/core/firewall.html)
- [OPNsense IDS API](https://docs.opnsense.org/development/api/core/ids.html)
- [Suricata rule management](https://docs.suricata.io/en/suricata-8.0.1/rule-management/suricata-update.html)
