# Enterprise Market Gap Delivery Plan: 2026-04-08

## Purpose

This document translates the market-gap comparison into an implementation plan for the current homelab stand.

It answers three questions:

1. what the platform still needs in order to approach enterprise-class SIEM/SOAR products
2. what can be implemented on the current `5-VM` server configuration
3. what requires a real architecture or infrastructure change rather than only code work

This is a post-closure expansion plan. It does not reopen the already-closed project slabs.

## Current Stand Constraint

Authoritative live topology remains:

- `VM1` -> ingest edge
- `VM2` -> Kafka and processing
- `VM3` -> ClickHouse, writer, stream correlation, batch correlation, alert aggregation, SQLite runtime state
- `VM4` -> web/API, React shell, Postgres control plane, Mongo content plane
- `VM5` -> Kafka and standby processing/storage services

What this stand is already good for:

- product and workflow iteration
- content expansion
- connector expansion
- moderate telemetry growth
- UEBA or graph proof-of-concept layers
- SOAR and governance iteration
- operator UX and process maturity work

What this stand is not ideal for:

- true enterprise-scale query and retention growth
- deep multi-tenant isolation
- large graph-heavy analytics at long time ranges
- very wide connector expansion without careful ingest budgeting
- production-grade distributed storage and search scale-out

## Executive Conclusion

The current stand is sufficient to implement a large part of the next enterprise uplift, but not all of it.

### Can be implemented now on the current stand

- content operations and rule-pack maturity
- broader connector and telemetry coverage
- initial UEBA and entity baseline analytics
- evidence graph v1 at operator level
- richer SOAR playbooks and approval policy packs
- stronger reporting, compliance, and governance surfaces
- better admin and analyst UX

### Can be implemented only partially on the current stand

- multi-tenancy
- full MSSP readiness
- advanced graph analytics at scale
- long-retention archive plus fast rehydrate
- heavy AI investigation workflows on very large data volumes

### Requires architecture or infrastructure change

- real shard/replica storage topology for analytical scale
- true enterprise HA/DR posture across all core layers
- very large retention horizons with fast search
- clean tenant isolation at data-plane level
- packaged large-scale service-provider operating model

## Feasibility Matrix

| Workstream | Needed | Current stand fit | Realistic on current stand | Blocking constraint |
| --- | --- | --- | --- | --- |
| Scale-out storage and query layer | critical | weak | `partial only` | single primary analytical node pattern, no true distributed shard topology |
| Content operations and detection engineering | critical | strong | `yes` | mainly engineering time, not hardware |
| Connector and telemetry expansion | critical | medium | `yes, with ingest budgeting` | ACK path, storage growth, parser debt |
| UEBA and entity baselines | high | medium | `yes, v1/v2` | storage cost and graph complexity at scale |
| Evidence graph and lineage | high | medium | `yes, v1` | data model maturity more than raw hardware |
| SOAR playbook expansion | high | strong | `yes` | integration effort, governance, testing |
| IAM and governance depth | medium | strong | `yes` | federation and role model work |
| Multi-tenancy and MSSP readiness | high | weak | `partial only` | shared storage and shared query plane |
| Compliance packs and executive reporting | medium | strong | `yes` | content authoring effort |
| Product UX and admin lifecycle | high | strong | `yes` | frontend/backend product work |
| Long-term archive and rehydrate | high | weak | `partial only` | storage economics and data-tier design |
| Enterprise DR and multi-site failover | high | weak | `partial only` | current stand lacks true independent scale-out redundancy |

## What We Should Do First

The correct strategy is not to begin with shard-everything replatforming.

The highest-value order is:

1. make the platform operationally deeper on the current stand
2. push that stand to its honest limit
3. only then rework storage and tenancy where the current architecture becomes the real blocker

## Phase 1: What We Can Deliver On The Current Stand

Target horizon:

- `0-6 weeks`

Primary goal:

- turn the current system from a strong custom SIEM stack into a much more enterprise-like product without first changing the VM topology

### Workstream 1. Detection and content operations

Implement now:

- versioned content bundles
- signed or at least integrity-checked bundle publication
- content promotion rings: `draft -> validated -> live`
- parser and rule regression suite
- bundle-level metadata:
  - owner
  - version
  - source coverage
  - validation status
  - rollback target
- detection QA dataset library

Why now:

- this yields the highest quality uplift without needing new hardware

Current stand feasibility:

- `fully feasible`

### Workstream 2. Connector and telemetry expansion

Implement now:

- connector program for:
  - `AD / Entra ID`
  - `mail`
  - `proxy`
  - `firewall`
  - `EDR`
  - `SaaS`
  - `cloud audit`
  - `Kubernetes`
  - `CI/CD`
- per-source telemetry quality score
- per-source parsing coverage score
- explicit enrichment stage ownership
- onboarding templates by source family

Why now:

- this is the fastest way to increase real investigative depth

Current stand feasibility:

- `feasible with ingest budgeting`

Operational caution:

- every new connector wave must be measured against:
  - ingest ACK latency
  - Kafka retention pressure
  - ClickHouse growth

### Workstream 3. UEBA and entity baseline v1

Implement now:

- per-user baseline
- per-host baseline
- per-service baseline
- first-seen / rare / drift signals
- repeated failed auth behavior model
- lateral movement precursor scoring
- execution-from-temp and privilege-escalation behavior profiles
- richer entity cards and incident actor context

Why now:

- this is the biggest intelligence gap versus enterprise leaders after content breadth

Current stand feasibility:

- `feasible for v1 and moderate volume`

Not yet targetable on this stand:

- very deep graph-heavy behavior analytics on very long history windows

### Workstream 4. Evidence graph and investigation model v1

Implement now:

- graph edges for:
  - `source_ip -> host`
  - `user -> host`
  - `process -> parent process`
  - `host -> service`
  - `asset -> vuln`
  - `indicator -> host`
  - `host -> outbound destination`
- case-linked evidence bundles
- timeline + actor + target + process lineage in incident view
- graph-backed AI prompt grounding

Why now:

- this directly improves investigations and AI quality

Current stand feasibility:

- `feasible as a product-layer graph, not as a huge graph database platform`

### Workstream 5. SOAR playbooks and execution maturity

Implement now:

- playbook catalog
- playbook templates by incident family
- action preconditions
- approval policy packs
- action rollback notes
- ticketing integration
- identity actions
- EDR-style host actions where safe
- better incident-to-case-to-response linkage

Why now:

- our current SOAR is real, but still too narrow compared to enterprise peers

Current stand feasibility:

- `fully feasible`

### Workstream 6. Reporting, compliance, and governance packs

Implement now:

- audit-ready reporting templates
- compliance content packs
- management dashboards
- SOC KPI reporting
- control-plane policy views
- service-account and secret posture reporting

Current stand feasibility:

- `fully feasible`

### Workstream 7. UX and admin maturity

Implement now:

- richer investigation surfaces
- consistent filter and pivot UX
- content-lifecycle admin UX
- connector lifecycle UX
- response playbook UX
- tenant-ready RBAC surfaces even before full multi-tenancy

Current stand feasibility:

- `fully feasible`

## Phase 2: What We Can Start But Only Partially Finish On The Current Stand

Target horizon:

- `6-12 weeks`

### Workstream 8. Multi-tenancy and MSSP preparation

Implementable now:

- tenant-aware RBAC model
- tenant tags on content and cases
- tenant-scoped dashboards and views
- tenant ownership on service accounts and tokens
- tenant-safe content promotion rules

Not fully implementable now:

- hard data-plane isolation
- tenant-by-tenant storage boundaries
- strong noisy-neighbor control
- predictable MSSP-scale usage segmentation

Current stand feasibility:

- `partial`

Reason:

- the current stand still uses a shared analytical data plane and shared core storage model

### Workstream 9. Archive, tiering, and rehydrate maturity

Implementable now:

- better retention policy UX
- archive policy definitions
- cold-search entrypoints
- rehydrate job framework

Not fully implementable now:

- large long-term searchable archive with enterprise-like performance guarantees

Current stand feasibility:

- `partial`

Reason:

- current storage design is still optimized for a compact lab and moderate retention

### Workstream 10. AI investigator maturity

Implementable now:

- grounded prompt packs
- evidence graph context
- safer recommendations
- better external enrichment
- confidence and explanation controls

Not fully implementable now:

- wide-scale AI investigation over very large historical slices with heavy graph context

Current stand feasibility:

- `partial`

Reason:

- compute and storage economics become the limiting factor before product logic does

## Phase 3: What Requires Architecture Change

Target horizon:

- after the current stand has delivered all feasible product-level gains

### Workstream 11. True scale-out analytical architecture

Needs:

- real shard topology
- replica-aware storage and query routing
- better separation of:
  - hot search
  - cold archive
  - operational control-plane queries
  - graph or analytical side workloads

Current stand feasibility:

- `not fully feasible`

Why:

- current design is still fundamentally centered around a single primary analytical node pattern

### Workstream 12. Enterprise-grade multi-site resilience

Needs:

- stronger failover posture across data, query, and control planes
- cleaner active/passive or active/active strategy
- formal DR cutover paths
- better blast-radius separation

Current stand feasibility:

- `partial only`

Why:

- the current homelab can simulate and harden failover, but it is not the same thing as a true enterprise resilience topology

### Workstream 13. Full MSSP operating model

Needs:

- strict tenant isolation
- usage metering
- tenant-specific content boundaries
- service-provider workflow separation
- tenant-safe reporting and case segregation

Current stand feasibility:

- `not fully feasible`

Why:

- this depends on both product design and real data-plane isolation

## Recommended Delivery Order

### Wave A

Do now on the current stand:

- content operations
- connector expansion
- telemetry quality scoring
- UEBA v1
- evidence graph v1
- SOAR playbook expansion
- compliance and reporting packs
- UX and admin maturity

Expected result:

- very large enterprise-quality uplift without touching base topology

### Wave B

Start on the current stand, but design for later scale-out:

- tenant-aware RBAC and object model
- archive policy UX
- rehydrate jobs
- AI grounding improvements

Expected result:

- the platform becomes architecture-ready for enterprise isolation and long retention, even if the current stand cannot finish the full target state

### Wave C

Schedule only after Waves A and B:

- real shard/replica analytical architecture
- strong tenant isolation
- MSSP-grade service model
- broader DR topology

Expected result:

- movement from strong custom enterprise stack toward true enterprise platform class

## Honest Answer On Feasibility

### Yes, we can implement on the current stand

- most of the product depth work
- much better detection and response maturity
- much better operator experience
- stronger AI and investigation quality
- much richer source coverage and content lifecycle

### No, we cannot fully implement on the current stand

- true enterprise-scale search and retention architecture
- clean MSSP-grade tenant isolation
- large-scale graph-heavy analytics with long history windows
- fully enterprise-grade resilience posture

### The correct decision

Do not treat the current infrastructure as the first blocker.

The current blocker is not only hardware. The bigger near-term gap is product maturity:

- content operations
- integrations
- UEBA depth
- evidence graph
- SOAR breadth
- admin lifecycle

Those should be delivered first.

Only after that should storage, tenancy, and resilience be reworked at the architecture level.

## Documentation Impact

This document should be used as the authoritative implementation plan when the task is:

- how to move from the current SIEM baseline toward enterprise-class parity
- what can still be built on the current 5-VM stand
- what should be deferred until after an architectural replatforming step

It supplements:

- `project_closure_execution_plan_2026-03-26.md`
- `architecture.md`
- `storage_rebalance_and_retention_hardening_2026-04-05.md`

It does not replace them.
