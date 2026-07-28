# Production Plan Readiness Audit

Audit date: 2026-07-28

This record compares the approved clean-repository, EPS, rule-calibration,
decomposition and SOC rollout plan with the deployed system. A component is
marked ready only when live evidence exists. Source code or a deploy script
without a successful runtime check is not treated as completion.

## Executive Status

| Workstream | Status | Live evidence or remaining gate |
| --- | --- | --- |
| Clean GitHub source | Ready | `main` is maintained in `Rdegon/rdegon-siem-solution`; hygiene and secret gates are part of final validation. The deployed repository name differs from the originally proposed `siem-solution-clean`, but the selected production contents follow the allowlist. |
| Internal Gitea source | Ready | Private `pilot.operator/siem-solution-clean` repository exists on `pilot-web-01`; all six local branches are mirrored. Temporary synchronization tokens are removed after use. |
| Ingest and transport | Ready | `23/23` sources and `35/35` operational collectors healthy; collector inventory contains no benchmark/test IDs and reports `synthetic=0`; Kafka transport healthy; outstanding DLQ is `0`. |
| Storage and control plane | Ready | ClickHouse, PostgreSQL and MongoDB HA report healthy; failover and controlled switchover are ready with no active alarms. |
| Web/API hot path | Ready with cold-start risk | Live warm responses: incidents `65-74 ms`, sources `62-88 ms`, collectors `72-130 ms`, overview `106-113 ms`, transport `371-437 ms`, storage HA `1245-1539 ms`. Cold overview requests after Web restarts took up to `22.0 s` (`21.2 s` on the final deploy) and exceeded the old `20 s` client timeout, so cold-start latency remains a performance gate. |
| EPS 500 | Ready at measured ceiling | Latest certification reports `493 EPS`; the nominal 500 stage achieved `492.83 EPS`, delivery ratio `1.0`, ingest p95 `1945.8 ms`, maximum consumer lag `0`. |
| EPS 750-4500 | Not certified | No current production-transport evidence certifies 750, 1000, 1250, 1500 or 4500 EPS across every collector type. Resource reservations or synthetic direct-path results are not certification. |
| Full rule inventory | Ready | `609` audited definitions: `463` stream and `146` batch. Every rule has an audit decision. Runtime has `452/456` stream, `134/134` batch, `581/588` catalog, `1/1` normalizer and `16/16` filter rules enabled; disabled entries are documented replacements or retired duplicates, not missing coverage. |
| False-positive calibration | Ready for known classes | Historical month audit and targeted shadow tests are complete. The 2026-07-28 follow-up tuned rules `2706`, `2902`, `8046`, `8212` and `8328`, marked exactly `13` raw and `13` aggregate records false-positive, resolved one stale `8212` health signal in each alert table, and preserved real open alerts `2604` and `4005`. Future zero false positives cannot be guaranteed; the runbook requires recurring review. |
| Monolith decomposition | Partial | Large modules remain: `deps.py` about 8.8k nonblank lines, `normalizer_core.py` about 2.2k, `enterprise_control_plane.py` about 1.5k and `control_plane_response_ops.py` about 2.2k. Route and runtime extraction has started, but the approved bounded-context split is not complete. |
| SOC services | Ready with intentional exclusions | NDR, DFIR, static analysis, TI, PKI, evidence, Greenbone, OPNsense/Suricata, Nextcloud, Navidrome, Pilot and Gamepanel checks pass. CAPE and disposable Windows guests remain intentionally excluded. OpenClaw is intentionally stopped. |
| Vulnerability management | Partial | Greenbone has `22` scannable guests and the retired OpenClaw target is removed. Only `5` guests currently have a recent completed scan and one guest remains unresolved, so a fresh full-fleet scan is still required. |
| Segmented LAN access | Ready | Proxmox is reachable at `192.168.3.101`; operator Web is reachable at `192.168.3.102`; internal service traffic uses segmented `10.20.x.x` addresses. |
| Internet VPN access | Not accepted | Local VPN services are configured, but the external peer has no current handshake. External access, especially to `WIN-RTX-test`, must not be represented as production-ready until an Internet-side E2E test passes. |
| Power recovery | Ready with hardware limits | Guest service smoke and expected stopped-state checks pass. There is no UPS. The remaining operational risks are abrupt power loss, host boot-disk pressure/fragmentation and Gamepanel disk utilization. |

## Rule Follow-up Evidence

The latest runtime false positives and stale health signal had five distinct causes:

| Rule | Cause | Production correction | Preserved true-positive behavior |
| --- | --- | --- | --- |
| `2706` Linux Systemd Unit Modified | LXD snap regenerated `/etc/systemd/system/snap.lxd.*` on `siem-ingest`. | Exclude only that host/path combination. | Any unrelated unit creation or modification still matches. |
| `2902` Gitea Administrative Change Burst | QEMU guest-agent commands contained `gitea admin`, but were not Gitea application actions. | Require `linux.pilot-gitea` and explicit repository, organization, auth-source or admin-role changes. | A structured admin promotion or matching Gitea change still matches. |
| `8046` PVE root login | Proxmox authenticated its own API requests from `192.168.3.101`. | Require structured successful `root@pam` authentication and exclude loopback and the PVE self-address. | An external successful root login matches immediately and is deduplicated by source IP. |
| `8328` Pilot path traversal | A Gitea source filename contained `.../actions/...`, which matched a generic `../` substring test. | Require an nginx access provider and a traversal sequence in normalized request path or request line. | Encoded or plain traversal in an HTTP request still matches. |
| `8212` Stream correlator unhealthy | A missing service name in a host-runtime snapshot was treated as an explicit service failure; the batch rule could recreate the resolved historical candidate. | Require the `siem-stream-corr` service identity and an explicit `inactive`, `failed`, `dead` or `unknown` state in at least three snapshots. | Three explicit unhealthy snapshots within five minutes still create a high-severity alert. |

The updated stream expressions and batch SQL are enabled in the runtime rule tables. No open
raw or aggregate alerts for these five rules remained after the scoped cleanup and control window.

## Live Service Acceptance

The fleet smoke passed on:

- `nextcloud-siem`, `navidrome-01`, `vuln-mgr-01`, `pilot-web-01`,
  `pilot-db-01`, `pilot-cache-01`;
- `soc-ndr-01`, `soc-dfir-01`, `soc-analysis-01`, `gamepanel-01`,
  `soc-ti-01`, `soc-pki-01`, `soc-evidence-01`;
- expected stopped guests: `win-test` and `openclaw-gateway`.

Web and data-plane evidence:

- `/api/health/overview`: `issues=[]`;
- `/api/health/transport`: Kafka, healthy, shadow pipeline healthy;
- `/api/health/storage-ha`: failover ready, switchover ready, alarms empty;
- `/api/ingest/sources`: `23` healthy of `23`;
- `/api/ingest/collectors`: `35` healthy operational collectors of `35`, with no benchmark/test collector IDs;
- `/api/ingest/dlq`: `0` outstanding;
- `/api/incidents`: preserved real security incidents `2604` and `4005`, plus current operational high-iowait signal `8425`, returned successfully.

## Remaining Required Work

1. Run and publish a production-transport EPS ladder for 750, 1000, 1250,
   1500 and only then higher targets. Include collector-specific delivery,
   ingest p50/p95, Kafka lag, ClickHouse insert latency, correlation lag and
   Web p95.
2. Complete the bounded-context split of the four remaining monoliths with
   contract tests before and after each extraction.
3. Run a fresh full-fleet Greenbone scan and reach recent coverage for every
   reachable scannable guest.
4. Re-run the production certification drill against the current segmented
   addresses. The saved drill record still contains pre-relocation addresses,
   even though the live HA surface is healthy.
5. Complete an external VPN handshake and verify routed access from the
   Internet to the approved management targets.
6. Measure and remove the Web cold-start path that can exceed the client
   timeout after a service restart.

## Reproduction

```powershell
python deploy\proxmox_fleet_wave_smoke.py
python deploy\publish_targeted_rule_calibration.py --dry-run
python -m pytest -q
python tools\repo_hygiene_check.py
```

Use credentials only from the local operator environment. Do not place the
operator bundle, Gitea tokens, VPN profiles or runtime secrets in this
repository.
