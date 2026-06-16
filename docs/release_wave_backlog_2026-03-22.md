# Release Wave Backlog: Six Large Slices

This is the large-slice roadmap sized for a `4-6 person` team working in `3-4 week` delivery blocks.

## Update: 2026-03-26

The original wave order still holds, but the live platform has moved materially forward.

For accelerated project close-out, the active execution baseline is now:

- `project_closure_execution_plan_2026-03-26.md`

Use that document for future task ordering. Keep this backlog as the large-slice historical roadmap and capability ledger.

Operationally completed baseline waves:

- Wave 1 transport transition baseline
- Wave 2 storage / control-plane HA baseline plus first backend decomposition slice
- Wave 3 host telemetry + runtime observability baseline
- Wave 4 identity / secrets / access maturity for the current stand
- Wave 5 response / SOAR hardening baseline
- Wave 6 release certification baseline for the current stand

Large-slice work that is now live and should be treated as completed for this roadmap layer:

- idempotent response execution ledger
- retries and DLQ handling for response actions
- richer approval state, quorum, and rejection flow
- response policy packs and reusable playbook templates
- stronger linkage between detections, cases, vulnerability findings, and actions
- source discovery live execution for Linux SSH rollout
- Windows native-agent package generation through discovery workflows
- network-device SSH config push automation
- asset binding that now uses CMDB plus source-inventory alias evidence
- first decomposition slice for `deps.py`, `enterprise_control_plane.py`, and `console.py`

What remains strategic after this pass:

- deeper backend domain split and worker isolation
- safe parallel batch correlation implementation
- Windows / network / vulnerability quality completion
- additional auth provider depth beyond the landed OIDC-first model if the product scope expands

The remaining items are now grouped operationally into the final active closure slabs:

1. `Platform Finalization`
2. `Coverage Completion`

## Active Next Two Waves

### Wave 1: Kafka + VM5 + Redis Exit

- provision `VM5`
- build Kafka KRaft on `VM1 + VM2 + VM5`
- dual-write and shadow-validate the transport path
- cut ingest, processing, and writer to Kafka
- remove Redis from the live data plane after the green window

### Wave 2: Storage / Control-Plane HA + Backend Decomposition

- ClickHouse warm-standby or replica preparation
- Postgres backup and standby hardening
- Mongo backup and failover hardening
- first domain split for `deps.py`, `enterprise_control_plane.py`, and `console.py`

## Next Four Waves After That

### Wave 3: Host Telemetry + Runtime Observability Correlation

- ship host telemetry collectors and normalized `host.metrics` events
- publish the host runtime observability rule pack
- raise CPU, RAM, disk, load, swap, and stale-telemetry incidents from correlation instead of only dashboards
- split collectors by source family and host role

### Wave 4: Identity, Secrets, and Access Maturity

- enterprise SSO bridge
- secret rotation workflows
- token lifecycle hardening
- service-account lifecycle governance
- operator-safe break-glass paths

### Wave 5: Response / SOAR Hardening

- idempotent execution ledger
- retries and dead-letter handling for response actions
- richer approval workflows
- response policy packs and execution templates
- stronger audit links between detections, cases, and actions

### Wave 6: Release Hardening And Certification

- chaos and failover drills across `VM1-VM5`
- performance and capacity certification
- load/lag budgets for transport and storage
- disaster-recovery runbooks and rollback validation
- release gate for production-like promotion

## Why This Backlog Order

The order is deliberate:

1. stabilize transport
2. stabilize persistence and maintainability
3. make runtime health first-class detection content
4. harden enterprise access
5. harden response automation
6. certify release posture under failure and load
