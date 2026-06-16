# TI / SOC / VOC Platform Expansion Plan: 2026-04-01

## Purpose

This document explains:

1. what is already implemented in the current platform baseline
2. what must be added or written to turn the current SIEM into a full TI / SOC / VOC platform
3. how long that work will likely take

`VOC` in this document means `Vulnerability Operations Center / vulnerability operations`, not customer-feedback tooling.

## Source Baseline

The assessment is based on the current repository documentation and runtime shape, primarily:

- `architecture.md`
- `project_closure_execution_plan_2026-03-26.md`
- `endpoints.md`
- `soar_response_hardening_2026-03-26.md`
- `vulnerability_maturity_2026-03-25.md`
- `pilot_sso_correlation_wave_2026-03-28.md`
- `openclaw_incident_ai_telegram_wave_2026-03-29.md`
- `windows_linux_telemetry_expansion_2026-03-30.md`
- `app_section_guide_and_usability_2026-03-28.md`
- live Proxmox host and VM configuration inspected on `2026-04-01`

## Executive Summary

The current stand is no longer "just SIEM". It already contains:

- a production-grade SIEM data plane: ingest, normalization, transport, storage, correlation, alerting
- an operational SOC baseline: incidents, cases, entities, risk signals, response actions, approval flows
- an operational vulnerability baseline: Greenbone import, structured reports, maturity scoring, policy-driven case creation
- an initial TI baseline: IOC catalog, event-side IOC matches, geo/reputation drill-down, TI pivots from incidents and events

The main gap is not the infrastructure layer. The main gap is domain depth:

- TI is currently IOC-centric, but not yet a full intelligence program with feeds, sightings, actor/campaign/TTP relations, and lifecycle management
- SOC is strong in triage and response, but not yet complete in SLA, escalation, analyst workload control, ticketing, and response-provider depth
- VOC is strong in import, exposure visibility, and policy initiation, but not yet complete in remediation program management, exception handling, KEV/EPSS-style prioritization, and rescan closure

## Requested Expansion Scope

The target scope is now wider than the original TI / SOC / VOC roadmap.

The requested platform should also be able to:

- actively scan hosts and services, not only import scanner output
- detect misconfigurations and hardening drift
- detect outdated or unnecessary services and propose one-click shutdown
- build and maintain network topology automatically
- discover new network assets and propose onboarding them into the platform
- run controlled pentest or adversary-emulation workflows inside approved scope

Important boundary:

- `automatic pentest` should be implemented as `controlled adversary emulation / controlled pentest automation`
- `switch off service by button` should be approval-gated, scope-limited, reversible where possible, and backed by dry-run plus operator-visible evidence

## Current State By Domain

### Platform Foundation

Already implemented:

- Kafka transport, ClickHouse event storage, Postgres control plane, Mongo content plane
- React operator shell under `/app/*`
- OIDC-first human auth through Keycloak
- Vault-backed runtime secrets
- storage HA baseline and production-green health gates
- source discovery, Proxmox fleet visibility, host-runtime observability

Implication:

- the foundation does not need a rewrite
- the next wave should build on the existing control plane, query layer, runtime docs plane, and `/app/*` shell

### SOC Baseline

Already implemented:

- incident queues and incident detail flows
- case management with comments, tasks, evidence, and audit trail
- entity and risk-signal model
- response action registry, approval quorum, retries, DLQ replay, execution ledger, analytics
- correlation pack workspace and publish flow
- incident AI assessment through OpenClaw
- Telegram incident bot with safe host actions

Current maturity level:

- `strong baseline`
- not yet a fully mature SOC operating system

### TI Baseline

Already implemented:

- threat-intel IOC storage in the platform
- IOC import and manual indicator save path
- provider/severity/type catalog overview
- event-side IOC matches against stored indicators
- malicious-source and geo/reputation drill-down
- pivots from selected IP into events and incidents

Current maturity level:

- `initial TI workbench`
- currently centered on indicators and reputation, not on intelligence operations as a full domain

### VOC Baseline

Already implemented:

- Greenbone runtime probe and sync health
- structured vulnerability import and report inventory
- views by hosts, software, CVEs, findings, reports
- asset binding and maturity scoring
- unmapped target accounting and operator remediation path
- scheduled vulnerability policy application
- automatic propagation into cases and risk signals for critical findings

Current maturity level:

- `good operational vulnerability baseline`
- not yet a full remediation and exposure-management program

### Discovery And Attack-Surface Baseline

Already implemented:

- source discovery workflow
- onboarding package preparation and execution
- Proxmox-backed fleet inventory
- OpenClaw and pilot-service coverage in the monitored estate
- operator-managed binding remediation

Current maturity level:

- `partial attack-surface and discovery baseline`
- discovery exists, but it is not yet a full autonomous topology, network mapping, or active scanning plane

## Gap Matrix

| Domain | Current status | What is already implemented | What must be added / written | Rough duration |
| --- | --- | --- | --- | --- |
| Platform foundation | Strong | Ingest, Kafka, ClickHouse, Postgres, Mongo, `/app/*`, OIDC, Vault, HA, source discovery | Mostly productization follow-up, not replatforming | `1-2 weeks` |
| TI data acquisition | Partial | Manual/import-based IOC catalog, provider and severity views, event matching | Feed connectors, scheduler, TAXII/STIX/MISP/OpenCTI style adapters, dedup, TTL/expiry, source trust scoring | `2-3 weeks` |
| TI knowledge model | Partial | IOC records and IP-level pivots | Actor, campaign, malware, tool, TTP, sighting, relation graph, collections, watchlists | `2-3 weeks` |
| TI workflows | Initial | IOC overview and investigation pivots | Feed curation, sighting workflow, intel packages, hunt tasks, intel-to-detection loop | `2-3 weeks` |
| SOC operations | Good baseline | Incidents, cases, entities, risk signals, correlation workspace, incident AI | SLA, queue rules, escalation, merge/split incidents, assignment automation, shift-ready analyst views | `2-3 weeks` |
| SOC response | Good baseline | Response registry, approvals, retries, DLQ, analytics, Telegram bot | Jira/ServiceNow/Slack/Teams/EDR/firewall adapters, multi-step provider workflows, delegated escalation | `2-3 weeks` |
| SOC metrics and governance | Partial | Basic response analytics, audit trail, health gates | MTTA/MTTR, backlog aging, false-positive metrics, content quality KPIs, team workload reporting | `1-2 weeks` |
| VOC coverage and prioritization | Good baseline | Structured imports, reports, findings, CVEs, asset binding, policy application | KEV/EPSS-like prioritization, exploitability weighting, external exposure factors, scan policy tiers | `2-3 weeks` |
| VOC remediation program | Initial | Critical findings can create cases and signals | Remediation backlog, owner mapping, SLA, exception workflow, compensating controls, rescan closure | `2-3 weeks` |
| Network topology and source auto-onboarding | Partial | Source discovery, onboarding prep, Proxmox fleet inventory | Active subnet scan, host classification, L2/L3 topology graph, trust scoring, onboarding recommendations and one-click guided enrollment | `3-4 weeks` |
| Edge routing, NGFW, and LAN DNS | Initial / partial | Proxmox inventory exists and an internal BSD router VM already exists | Decide router stack, zone model, IDS/IPS policy, local hostname model, DHCP-to-DNS registration, DNS overrides, and SIEM log forwarding from the edge | `1-2 weeks` |
| Active scanning and misconfiguration assessment | Initial | OpenVAS-first vuln flow, source inventory, host/runtime context | Authenticated scanners, service census, config and hardening audit profiles, stale-service detection, scanner scheduling and drift history | `3-5 weeks` |
| Controlled pentest and adversary emulation | Initial / missing | Incident AI, safe host actions, response approval model | Scope engine, job orchestration, non-destructive modules, proof capture, finding normalization, approval-gated offensive workflows | `4-6 weeks` |
| Service lifecycle control recommendations | Missing | Response action framework, approval and DLQ model | Detect inactive/obsolete services, propose disable actions, maintenance-window checks, dry-run, rollback/snapshot hooks, one-click approved execution | `2-3 weeks` |
| Shared integration layer | Partial | Connectors framework and response actions exist | Stable adapter contracts, job scheduler model, idempotent syncs, sync-state visibility, secret-governed external integrations | `2-3 weeks` |
| Stabilization and release proof | Partial | Tests, deploy waves, health gates, production-green discipline | New migrations, regression pack, throughput check for new jobs, RBAC hardening, operator runbooks | `2-3 weeks` |

## Open-Source Router, NGFW, And Local DNS Options

The current server can host these functions, but the design should stay pragmatic:

- do not virtualize the only household or office edge if the Proxmox host itself is the single point of failure
- on the current stand, the safest use is `virtual router / NGFW / DNS for the SIEM lab and internal service segment`, not the only upstream gateway for the whole site

### Candidate Solutions

| Project | Role fit | Strengths | Limits | Recommendation for this stand |
| --- | --- | --- | --- | --- |
| `OPNsense` | Router + firewall + IDS/IPS + local DNS | Mature web UI, VLANs, NAT, policy routing, `Unbound` DNS, `Suricata` IDS/IPS, good VM fit | Heavier than OpenWrt, should not be the only household edge without a fallback | `Recommended default` |
| `OpenWrt` | Lightweight router / gateway | Very small footprint, good package ecosystem, easy basic routing and DNS through `dnsmasq` | Not the strongest fit when you also want NGFW-style inspection and richer policy UX | `Use only if you want a lighter router and accept less NGFW depth` |
| `Technitium DNS Server` | Dedicated local DNS authority | Strong DNS UX, API, recursive + authoritative patterns, useful if you want DNS as a separate service plane | Extra moving part if the router already provides working local DNS | `Optional later` |
| `Pi-hole` / `AdGuard Home` | DNS filtering layer | Good for ad-blocking and upstream filtering | Better as filtering layers than as the primary authoritative LAN naming system | `Optional add-on, not the primary LAN DNS authority` |

### Recommended Stack On The Current Host

Recommended practical choice:

- repurpose `VM102` into `OPNsense`
- use `OPNsense` for:
  - router functions for the lab or service segment
  - `NGFW-lite` through firewall policy plus `Suricata`
  - local DNS through `Unbound`
  - DHCP reservations and DNS host overrides for stable hostname resolution
- do not add a separate DNS VM in the first pass
- add `Technitium DNS` only if you later need:
  - split-horizon zones
  - richer DNS administration than `Unbound` overrides
  - API-first DNS workflows independent of the router

Operational implication:

- if `OPNsense` is chosen, a separate `NGFW VM` is not required on the current hardware
- if `OpenWrt` is chosen instead, you will likely still want a separate inspection or richer firewall layer later

## What Needs To Be Written

The main missing deliverables are not new pages first. They are new domain services and contracts.

### TI Layer

Needs to be written:

- feed-ingestion runtime for TI providers
- normalized TI object model with relation support
- sighting ingestion and sighting history
- indicator lifecycle logic: deduplication, expiry, confidence merge, suppression, watchlists
- intel-to-case and intel-to-rule recommendation flow

### SOC Layer

Needs to be written:

- incident queue policy engine: SLA, assignment, escalation, priority aging
- richer case workflow primitives: merge, split, promote, handoff, closure reason model
- provider adapters for ITSM, chat, notification, EDR, firewall, IAM
- analyst KPI and shift reporting layer

### VOC Layer

Needs to be written:

- remediation-program model with owners, due dates, waivers, accepted risk, and compensating controls
- rescan-and-close workflow
- prioritization model that combines CVSS with exploitability and asset criticality
- external exposure and scanner-policy tiering logic

### Edge Services And Naming Layer

Needs to be written or finalized:

- final router and firewall stack decision: `OPNsense` vs `OpenWrt`
- zone model for the SIEM lab, internal services, and management paths
- local hostname model:
  - static DHCP reservations
  - DNS overrides
  - reverse lookup consistency
- SIEM ingestion of edge logs:
  - firewall decisions
  - DNS queries
  - IDS/IPS alerts
- operator runbooks for fallback access when the virtual edge is being changed

### Exposure Discovery And Active Assessment Layer

Needs to be written:

- active network discovery scheduler with scoped subnet profiles
- topology graph builder for hosts, segments, services, gateways, and trust paths
- authenticated scanning orchestrator for OS, packages, services, web surfaces, and configuration checks
- misconfiguration and hardening rule packs
- outdated-service and stale-service recommendation engine
- onboarding recommendation engine for newly discovered assets and sources
- controlled pentest / adversary-emulation runner with proof capture and normalized findings

### Shared Cross-Domain Layer

Needs to be written:

- unified object linkage across `asset -> source -> event -> indicator -> incident -> case -> response -> vulnerability`
- stable background-job model for recurrent imports and reconciliation
- common adapter contract for external systems
- cross-domain reporting and executive KPI views

## Current Host Snapshot And Recommended VM Resource Split

Live host facts checked on `2026-04-01`:

- Proxmox host CPU: `2 x Intel Xeon E5-2680 v3`
- available host threads: `48`
- host RAM: about `164 GiB`
- memory available at the capture moment: about `103 GiB`
- passed-through GPU: `RTX 3080 Ti` assigned to `WIN-RTX-test`
- current production bottleneck for the SIEM stack is still the ingest acknowledgment path, not raw host CPU saturation

Practical consequence:

- the current host can run the platform plus router / NGFW / local DNS on the same machine
- the best current tradeoff is to consolidate `router + NGFW + local DNS` into `VM102`
- keep extra headroom for `VM106` storage, `VM122` vulnerability work, and `VM111` GPU workloads
- reduce `VM111 WIN-RTX-test` from `12 vCPU` to `8 vCPU` so the platform has more stable CPU scheduling headroom

### Live Segmentation Status After 2026-04-01 Rollout

The network baseline is no longer only a recommendation. A first live segmentation wave is now in place:

- `VM102` is the internal routed edge with `192.168.1.102`, `10.20.10.1`, `10.20.20.1`, and `10.20.30.1`
- `VM104-108` are dual-homed on `192.168.1.x` and `10.20.10.x`
- `CT120-121` are now single-homed on `10.20.20.120` and `10.20.20.121`
- `VM122-126` remain on `10.20.30.x`
- the jump-host `OpenVPN` path now carries the segmented subnets for remote operator access

The live implementation details, validation notes, and remaining upstream-router dependency are documented in:

- `network_segmentation_rollout_2026-04-01.md`

### Recommended VM Layout On The Current Server

The table below is the recommended target split for the current host, not a statement that every VM must be changed immediately.

| VMID | VM / Service | Target role | Target vCPU | Target RAM | Target disk | Recommendation |
| --- | --- | --- | --- | --- | --- | --- |
| `101` | `win-test` | Reserve / ad hoc lab VM | `4` when powered on | `8 GiB` | `100 GiB` | Keep powered off by default so it does not steal headroom from the platform |
| `102` | `BSDRP-internal` -> `OPNsense` | Router + NGFW + local DNS | `4` | `6 GiB` | `40 GiB` | Rebuild as `OPNsense`; keep `vmbr0` and `vmbr1`; use `Unbound` and `Suricata` |
| `104` | `SIEM-Ingest` | Ingest edge | `8` | `12 GiB` | `100 GiB` | Keep stable; focus on ingest ACK-path tuning instead of more RAM first |
| `105` | `SIEM-Processing` | Kafka and processing | `10` | `16 GiB` | `100 GiB` | Good baseline for normalizer and filter workload on the current stand |
| `106` | `SIEM-Storage` | ClickHouse and correlation | `12` | `32 GiB` fixed, no ballooning | `100 GiB + 800 GiB + 300 GiB` | Main storage and correlation node; keep as the most memory-rich VM and avoid dynamic memory changes |
| `107` | `SIEM-WEB` | Web / API / Keycloak / Vault / Postgres / Mongo | `6` | `12 GiB` | `100 GiB` | Increase from the current web baseline so UI, auth, Mongo, and Postgres coexist more comfortably |
| `108` | `SIEM-Transport` | Kafka standby and transport helpers | `6` | `12 GiB` | `100 GiB` | Keep as the transport and standby node, not as a general extra-app host |
| `111` | `WIN-RTX-test` | GPU workstation VM | `8` | `18 GiB` | `200 GiB` | Reduce CPU allotment from the current `12 vCPU`; keep GPU passthrough and RAM intact |
| `120` | `nextcloud-siem` | Files and collaboration | `4` | `8 GiB` | `350 GiB` | Current allocation is acceptable; no urgent resize needed |
| `121` | `navidrome-01` | Music streaming | `4` | `6 GiB` | `120 GiB` | Increase from the current `4 GiB / 20 GiB` so the service is usable with a real library |
| `122` | `vuln-mgr-01` | Vulnerability manager and scanner coordinator | `6` | `10 GiB` | `200 GiB` | Give more room for future active scanning and report retention |
| `123` | `pilot-web-01` | Pilot service | `2` | `2 GiB` | `20 GiB` | Small but no longer starved |
| `124` | `pilot-db-01` | Pilot database service | `2` | `4 GiB` | `40 GiB` | Enough for service demos plus moderate internal use |
| `125` | `pilot-cache-01` | Pilot cache / queue helper | `2` | `2 GiB` | `20 GiB` | Keep lightweight |
| `126` | `openclaw-gateway` | Incident AI and service gateway | `4` | `6 GiB` | `80 GiB` | Enough for the current OpenClaw role without oversizing it |

### Aggregate Planning Notes

Approximate result of the recommended target split for running VMs:

- total platform and service RAM allocation: about `146 GiB`
- remaining host headroom: about `18 GiB`
- total assigned vCPU across the running set: about `78`

This is acceptable on the current host because:

- actual host CPU use is still moderate
- the biggest documented platform bottleneck is ingest-path latency, not CPU starvation
- not every VM is CPU-bound all the time
- `VM101` stays off by default and serves as reserve capacity only

If you later decide to add a separate DNS plane instead of using `OPNsense Unbound`, reserve:

- `1` small LXC or VM
- `2 vCPU`
- `2-4 GiB RAM`
- `20-40 GiB disk`

On the current host, that extra DNS VM should be funded by either:

- keeping `VM101` off permanently
- or not growing `VM122` and `VM126` at the same time

## Recommended Delivery Principles

The current platform should be expanded, not rewritten.

Recommended principles:

- keep the current storage and transport shape
- keep `/app/*` as the primary operator shell
- add domain modules behind the existing control-plane and query patterns
- prefer one integrated edge service VM on the current host instead of three separate small VMs for router, NGFW, and DNS
- treat TI, SOC, and VOC as linked domains, not three disconnected pages
- make every new automation idempotent and auditable from day one
- keep active scanning and pentest workflows scope-bound, allowlist-driven, and non-destructive by default
- require approval, dry-run evidence, and rollback hooks for service-disable or containment actions

## Phased Plan

| Phase | Goal | Main deliverables | Exit criteria | Duration |
| --- | --- | --- | --- | --- |
| `Phase 0` | Freeze the target model | Domain map, backlog split, canonical object relations, integration shortlist, edge stack choice, VM resource allocation plan | Scope is fixed and linked to current runtime modules and the target VM layout is agreed | `1 week` |
| `Phase 1` | Build autonomous discovery and topology | Active network discovery, host classification, topology graph, onboarding recommendations, topology views, router / NGFW / local DNS baseline | The platform can discover new assets and explain where they sit in the network and what can be onboarded, and hostnames resolve consistently inside the lab | `3-4 weeks` |
| `Phase 2` | Build active scanning and misconfiguration assessment | Authenticated scan jobs, service census, config audits, stale-service detection, scheduler and findings history | The platform no longer depends only on imported scanner data and can actively assess systems in allowed scope | `4-5 weeks` |
| `Phase 3` | Build controlled pentest automation | Pentest/adversary-emulation runner, scope policy engine, proof capture, normalized findings, approval flows | The platform can run approved non-destructive pentest workflows and convert them into evidence and findings | `4-6 weeks` |
| `Phase 4` | Turn TI into a real domain | Feed adapters, TI scheduler, dedup/expiry, sightings, provider trust model, first actor/campaign/TTP relations | TI no longer depends only on manual IOC import and can continuously enrich incidents | `3-4 weeks` |
| `Phase 5` | Mature SOC and VOC operations | SLA, queue rules, richer case flow, remediation backlog, exception flow, owner workflow, rescan closure | Incident handling and vulnerability remediation become closed-loop operating processes | `4-6 weeks` |
| `Phase 6` | Deepen automation and service control | ITSM/chat/EDR/firewall adapters, response-provider chains, one-click approved service-disable recommendations, connector hardening | TI, SOC, and VOC are operationally connected to external systems and can execute safe guided change actions | `3-4 weeks` |
| `Phase 7` | Stabilize and certify the new layers | Regression tests, migration checks, RBAC pass, docs, runbooks, performance check | New platform layers are supportable in production | `3-4 weeks` |

## Calendar Estimate

Assumption for the estimate:

- `2 backend/fullstack engineers`
- `1 security engineer / vuln-pentest owner`
- `0.5-1 security analyst / detection-vulnerability owner`
- occasional DevOps support
- existing infrastructure is reused

Estimated delivery time:

- `working TI / SOC / VOC + active scanning + topology + controlled pentest platform on top of the current baseline`: `24-32 calendar weeks`
- `more mature product-grade version with broader integrations, safer automation, and cleaner analytics`: `32-44 calendar weeks`

If the work is done by `one engineer`, the realistic duration is closer to:

- `48-72 calendar weeks`

## Suggested First-Wave Priorities

If the goal is to maximize value quickly, the first sequence should be:

1. agree the VM layout and deploy the `router / NGFW / DNS` baseline
2. topology discovery and active source identification
3. authenticated vulnerability and misconfiguration scanning
4. stale-service detection with approved disable recommendations
5. TI feed bus and indicator lifecycle
6. incident SLA and queue policy engine
7. remediation backlog, exception handling, and rescan closure
8. controlled pentest / adversary-emulation workflows
9. ITSM, chat, and enforcement integrations
10. analyst and program KPI dashboards

## Final Assessment

The project is already close to a multi-domain cyber operations platform, but it is still asymmetric:

- SOC is the most mature operator domain
- VOC is the most mature adjacent domain
- TI exists, but is still at the `IOC + enrichment + pivot` level
- active discovery, topology, pentest automation, and service-control recommendations are only partially present or not present yet

That means the fastest path is not "build everything from zero". The fastest path is:

- keep the current SIEM/SOC foundation
- add a real active discovery and topology layer
- add active vuln and misconfiguration scanning
- add controlled pentest automation instead of unrestricted autonomous offense
- add a real TI program layer
- close the VOC remediation loop
- deepen SOC operating workflows and external integrations

That is now a realistic `6-8 month` program for a small focused team, or roughly `12-18 months` for one engineer working alone.
