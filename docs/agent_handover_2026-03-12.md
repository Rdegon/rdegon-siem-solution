# Agent Handover: Enterprise Foundation And Ingest Runtime

Archive note: this handover still contains Redis-era and pre-cutover milestones as historical context. Current runtime truth is `kafka` transport, `sqlite` stream state, `postgres` control plane, and `mongo` content store. Use current runbooks and `/api/health/*` surfaces for live operations.

## Source Of Truth

- Baseline code directory: `C:\Users\Rdegon\Projects\siem_xfer_2026-03-25\repo`
- Deployment targets for the current live slice: `VM1`, `VM3`, and `VM4`
- Authoritative credentials document: [SYSTEM_ACCESS_MATRIX.md](C:/Users/lolol/Documents/Playground/product-docs/SYSTEM_ACCESS_MATRIX.md)
- Lab-only duplicated operator bundle: [OPERATOR_ACCESS_BUNDLE.md](C:/Users/lolol/Documents/Playground/product-docs/OPERATOR_ACCESS_BUNDLE.md)

## What This Slice Added

- control-plane persistence for connectors, cases, entities, risk signals, response actions, content bundles, and saved searches
- aggregated health overview
- secret-readiness inventory
- real connector executors for REST pull and sqlite poll
- real response executors for webhook, Telegram, email, and approval-gated actions
- service accounts with scoped permissions and one-time API token issuance
- hash-chained control-plane audit log with tamper detection
- optional Postgres-backed control-plane storage with filesystem fallback
- live Postgres cutover tooling for the VM4 control plane with explicit migration reporting
- ingest-edge source heartbeat, collector heartbeat, DLQ, and replay
- VM4 ingest proxy APIs
- React shell route for ingest operations
- React shell routes for connectors, cases, and entities
- React shell route for access and service-account operations
- dashboard timeline drill-down and timezone-aware chart formatting
- incident queue time filters and larger row limits
- LAN discovery plane with candidate-source persistence and onboarding jobs
- frontend remediation baseline for the React shell: lazy routes, minified split build, focus trap, skip link, focus-visible styling, visibility-aware polling, and typed event columns
- frontend remediation follow-up for analyst UX: compact dashboard and event-search time controls, richer severity hover detail, refreshed section icons, readable incident summaries, and basic keyboard triage
- frontend remediation follow-up for severity UX: floating widget-level hover detail for donut charts, seamless severity-matrix layout, and safer drawer overflow behavior for wide event payloads
- frontend remediation visual-polish follow-up for donut charts: recentered rings, softer segment separators, and a lighter floating detail card so the chart remains visually dominant
- frontend remediation popup follow-up for donut charts: the severity detail card now stays hidden until hover or focus instead of permanently occupying widget space
- frontend breakthrough follow-up for dashboard hierarchy and dense queues: integrated overview landing card, lighter overview section headers, windowed event and incident tables, and sticky table headers
- frontend engineering quality-gate follow-up: targeted shell typecheck, ESLint, Vitest plus Testing Library coverage, lazy GeoIP map extraction, grouped sidebar navigation, and repo-local Node 20 bootstrap on VM4 for frontend validation
- analyst-workflow follow-up: saved-search application and save-current flow in `Events`, URL plus session persistence for `Events` and `Incidents`, incident deep-link copy, and `/auth/login` redirect into `/app` with preserved safe `next` path
- React shell foundation follow-up: `ui.tsx` reduced to a barrel export, shared chart and surface modules extracted, shared async gate added, stale-while-refresh hooks enabled, typed response contracts added for Access/Cases/Connectors, and frontend tests expanded to cover async rendering plus refresh retention
- React shell closure follow-up: typed response contracts and shared `AsyncGate` coverage now also include `Assets`, `Collectors`, `Entities`, `Ingest`, `Sources`, and `ThreatIntel`, and the shell now exposes a shortcuts drawer with `?` and `Alt+1..4` navigation
- full React-shell closure follow-up: `Builders`, `ControlPanel`, `Documentation`, `Inventory`, and `Vuln` now sit inside the same typed-contract, lint, test, and production-build gate as the rest of the React operator shell, and VM4 deploy mappings now explicitly ship those pages
- GitHub Actions validation workflow for `main` and pull requests now covers frontend typecheck, lint, tests, and production build in addition to backend unit tests
- second-audit closure follow-up: explicit `any` is now banned in the frontend lint gate, the shared shell API contracts cover the remaining incident/event/connector/case/entity/geo/response/vulnerability payloads, `IncidentsPage` is typed end-to-end, shared drawer/list surfaces expose semantic table roles, dashboard polling exposes a polite live region, and cookie-authenticated mutations now require a CSRF token
- feedback closure follow-up: the React shell now has a shared `FeedbackProvider` for toast notifications plus live announcements, and the operator pages now emit visible feedback for save, run, copy-link, and refresh actions instead of silent state changes
- VM4 frontend validation follow-up: deploy validation now runs each Vitest file sequentially because the lab VM can OOM on a one-process full-suite run even when the code is healthy
- expanded RBAC for the new runtime domains
- generated OpenAPI at `/api/openapi.json`
- event-time-aware stream correlation with watermark, lateness controls, timestamp fallback accounting, and optional processing-time shadow comparison
- ClickHouse runtime snapshots for stream correlation so VM4 health can surface correlation mode and mismatch counters
- transport/runtime visibility through VM1 `/health/transport` and VM4 `/api/health/transport`
- storage-memory visibility through `/api/health/storage` plus a dedicated VM3 ClickHouse tuning deploy path
- SQLite WAL runtime state for live stream correlation on `VM3`
- live Mongo-backed content/document storage on `VM4` with filesystem kept only as bootstrap/export/rollback state
- automatic Proxmox-side CPU-profile remediation in the Mongo cutover script so `VM4` can expose `AVX` and run MongoDB 7
- VM4 security hardening for local-user password hashing, per-IP login rate limiting, and CA-backed ingest TLS verification

## Local Validation Commands

```powershell
python -m py_compile auth.py enterprise_control_plane.py source_discovery.py security.py deps.py alerts.py console.py main.py stream_worker.py deploy\vm4_enterprise_foundation_deploy.py deploy\vm4_enterprise_foundation_smoke.py deploy\vm4_control_plane_postgres_cutover.py deploy\vm3_stream_corr_event_time_deploy.py deploy\vm3_stream_corr_event_time_smoke.py
python -m unittest discover -s tests -v
```

## Deployment Commands

```powershell
python C:\Users\Rdegon\Projects\siem_xfer_2026-03-25\repo\deploy\vm1_ingest_fabric_deploy.py
python C:\Users\Rdegon\Projects\siem_xfer_2026-03-25\repo\deploy\vm1_ingest_fabric_smoke.py
python C:\Users\Rdegon\Projects\siem_xfer_2026-03-25\repo\deploy\vm4_enterprise_foundation_deploy.py
python C:\Users\Rdegon\Projects\siem_xfer_2026-03-25\repo\deploy\vm4_security_hardening.py
python C:\Users\Rdegon\Projects\siem_xfer_2026-03-25\repo\deploy\vm4_control_plane_postgres_cutover.py
python C:\Users\Rdegon\Projects\siem_xfer_2026-03-25\repo\deploy\vm4_enterprise_foundation_smoke.py
python C:\Users\Rdegon\Projects\siem_xfer_2026-03-25\repo\deploy\vm3_stream_corr_event_time_deploy.py
python C:\Users\Rdegon\Projects\siem_xfer_2026-03-25\repo\deploy\vm3_stream_corr_event_time_smoke.py
python C:\Users\Rdegon\Projects\siem_xfer_2026-03-25\repo\deploy\vm3_storage_memory_tuning.py
python C:\Users\Rdegon\Projects\siem_xfer_2026-03-25\repo\deploy\vm3_storage_memory_smoke.py
```

## Remote File Mapping

- local `main.py` -> remote `services/web/main.py`
- local `auth.py` -> remote `services/web/app/routes/auth.py`
- local `login.html` -> remote `services/web/app/templates/login.html`
- local `services/ingest/*` -> remote `services/ingest/*`
- local `security.py` -> remote `services/web/app/security.py`
- local `console.py` -> remote `services/web/app/routes/console.py`
- local `enterprise_control_plane.py` -> remote `services/web/app/enterprise_control_plane.py`
- local `source_discovery.py` -> remote `services/web/app/source_discovery.py`
- local `deps.py` -> remote `services/web/app/deps.py`
- local `stream_worker.py` -> remote `services/stream_corr/worker.py`
- local `alerts.py` -> remote `services/web/app/routes/alerts.py`
- local `ingest_runtime.py` -> remote `services/web/app/ingest_runtime.py`
- local `frontend-react/src/shell/*` -> remote `services/web/frontend-react/src/shell/*`
- local `frontend-react/build.cjs` -> remote `services/web/frontend-react/build.cjs`
- local `frontend-react/src/styles.css` -> remote `services/web/frontend-react/src/styles.css`
- local `docs/*` -> remote `docs/*`

## Operational Notes

- The current control plane now supports a live Postgres cutover path. Filesystem should be treated as snapshot/export state, not the intended long-term authority.
- The current content plane now supports a live Mongo cutover path. Filesystem should be treated as bootstrap/export/rollback state, not the intended long-term authority.
- The current VM4 auth hardening stores only `pbkdf2_sha256` password hashes in `/etc/siem/web.env`; operator-known plaintext passwords live only in the lab-only operator bundle.
- `deploy/vm4_security_hardening.py` is now idempotent on already-hashed env files and can also rebuild hashed auth values from operator-provided overrides when a broken env rewrite has already scrubbed plaintext values from the live file.
- The first `2026-03-21` hardening attempt exposed a cert-copy bug that inserted blank lines into `/etc/siem/tls/ingest-ca.crt`, which broke `VM4 -> VM1` TLS verification. The live cert file was repaired and the script now strips empty lines from privileged file reads.
- Service-account API tokens are hashed at rest and shown only once at issuance time.
- The access matrix and the duplicated operator bundle contain raw secret values for the lab. Do not re-copy them into general app-repo docs or scripts.
- `vm4_enterprise_foundation_deploy.py` creates a backup directory under `/tmp/siem-web-backup-<timestamp>` before overwriting files.
- `vm1_ingest_fabric_deploy.py` creates a backup directory under `/tmp/siem-ingest-backup-<timestamp>` before overwriting files.
- `vm4_control_plane_postgres_cutover.py` creates a backup directory under `/tmp/siem-web-postgres-cutover-<timestamp>` before enabling the database-backed control plane.
- `vm3_stream_corr_event_time_deploy.py` creates a backup directory under `/tmp/siem-stream-corr-backup-<timestamp>` before replacing the worker and env file.
- `vm3_storage_memory_tuning.py` creates a backup directory under `/tmp/siem-storage-memory-backup-<timestamp>` before updating the ClickHouse memory baseline on `VM3`.
- The ingest/runtime path is now Kafka-backed. Redis-era notes below are historical and should not be used as current deployment guidance.
- `vm1-smoke` is a synthetic smoke emitter and should remain excluded from operational ingest metrics.
- The new source discovery plane persists candidate hosts and onboarding jobs on VM4. It is a live operator aid, not just a local utility.
- Discovery rescans now auto-supersede stale onboarding jobs when the target host is recognized as already connected.
- The web shell now lazy-loads route modules and no longer requires the heavy chart/map bundle on the very first shell bootstrap path.
- The GeoIP map now lazy-loads through a dedicated `GeoDotMapCanvas` module instead of living inside the shared `ui.tsx` base path.
- The `2026-03-21` loading-shell incident was caused by unstable inline loaders in `services/web/frontend-react/src/shell/App.tsx`. Keep shell bootstrap and platform polling loaders wrapped in `useCallback`, otherwise `useAsyncData`/`usePolledData` will restart on every render and the browser can hammer `/api/ui/bootstrap` and `/api/platform/status`.
- The same `2026-03-21` incident pattern also existed in multiple page routes. Keep page-level loaders stable in `Assets`, `Builders`, `Collectors`, `Entities`, `Events`, `Incidents`, `Ingest`, `Inventory`, `Sources`, and `ThreatIntel`; do not pass inline loaders directly into the shared async hooks.
- The `siem-processing` label shown in ingest health is a source alias for VM2 telemetry, not a standalone systemd unit. The live VM2 workers are `siem-normalizer.service` and `siem-filter.service`.
- The `2026-03-22` outage showed that a stopped `VM2` can make the whole stand appear dead even while the rest of the lab still responds. When events suddenly flatline, check `VM105` on Proxmox before assuming a ClickHouse or UI failure.
- `VM2` now has `qemu-guest-agent` enabled, so Proxmox-side `qm guest exec 105 -- ...` is the first fallback recovery path if direct SSH becomes unstable again.
- The `2026-03-22` ingest hotfix changed raw-stream backpressure semantics on `VM1`: do not revert to the older `XLEN >= hard_limit` stop logic without also checking `xinfo_groups(...).pending` for the `raw` consumer group.
- `VM2` direct LAN SSH is now restored as an operator path. The public half of `D:\University\Project_VPN\vpnadmin_ed25519` is present in `rdegon`'s `authorized_keys`, and `/etc/ssh/sshd_config.d/60-rdegon-lan.conf` carries the live SSH stabilizers (`UseDNS no`, `AddressFamily inet`, raised `MaxStartups`).
- The follow-up `2026-03-22` network repair removed a stale duplicate netplan file from `VM2`. The canonical live state is now a single `/etc/netplan/01-siem.yaml` with `ens19` only and LAN DNS pinned to `192.168.1.1`.
- The current `VM2` resilience slice also makes the processing node a real CD target through `deploy-vm2`, and the live Redis config on `VM2` must keep AOF enabled (`appendonly yes`, `appendfsync everysec`) unless a replacement HA transport is already in place.
- The `2026-03-22` Redis HA slice now depends on Sentinel reachability from the ingest edge too, not only from the Redis and web peers. If `VM1 /health` starts hanging after a Redis change, check `26379/tcp` reachability from `VM1` to `VM2`, `VM3`, and `VM4` before debugging FastAPI or syslog listeners.
- The final Redis runtime no longer uses `redis.asyncio.sentinel.Sentinel.master_for(...)` for the data path. It resolves the active master through `SENTINEL get-master-addr-by-name` and then opens a normal async Redis connection to that master. Keep that behavior unless you replace Redis entirely or can prove a safer Sentinel client under live failover.
- The first resilient Redis wrapper shipped with one live regression: its internal `_call(name, ...)` signature collided with Redis methods that also accept `name=...`, which crash-looped `VM2` processing and stalled the stand. The fixed live wrapper now uses a non-conflicting internal parameter name and is covered by regression tests in `tests/test_redis_runtime.py`.
- The first Redis HA deploy also exposed a live path mismatch for `siem-writer`: the service executes `services/writer/worker.py`, not the root-level `writer_worker.py`. Do not revert the corrected deploy mapping in `deploy/redis_ha_resilience_deploy.py`.
- `deploy/homelab_watchdog.py` now repairs `VM2` in two stages:
  - recover the VM itself through Proxmox if `VM105` is stopped
  - restart `redis-server`, `siem-normalizer`, and `siem-filter` if Redis or processing looks stalled even while the guest is still up
  - repair the `VM2` DNS-plus-runner path if GitHub registration drops or the canonical single-netplan network state regresses
- `VM4` frontend deploys no longer depend on the host's legacy Node 12 runtime; the deploy script bootstraps a repo-local Node 20 toolchain under `/opt/siem/siem-solution/.tools`.
- The `2026-03-21` stream-correlation slice writes runtime status snapshots even during idle periods, so smoke and health do not depend on a new event arriving immediately after restart.
- The `2026-03-22` Mongo cutover required a real infra prerequisite: `VM4` now runs with Proxmox CPU profile `x86-64-v3` instead of `x86-64-v2-AES`. MongoDB 7 will crash with `status=4/ILL` if that CPU profile regresses.
- `deploy/vm4_content_store_mongo_cutover.py` can now repair that CPU profile automatically if `SIEM_PROXMOX_HOST`, `SIEM_PROXMOX_USER`, `SIEM_PROXMOX_PASSWORD`, and `SIEM_VM4_VMID` are available.
- The live stream-correlation state backend is now SQLite at `/var/lib/siem-stream-corr/runtime-state.db`; do not describe Redis as the live correlation-state store anymore.
- The first live Kafka shadow pass exposed three real cutover bugs that are now fixed:
  - Kafka broker firewalls on `VM1`, `VM2`, and `VM5` must allow `9092/tcp` from `VM3` and `VM4`
  - `VM1` syslog ingest must pass the transport producer into `push_raw_event(...)`, otherwise only the HTTP ingest path dual-writes to Kafka
  - `VM5` shadow processing must stay `kafka/kafka`, not `dual/kafka`, otherwise the producer path regresses into Redis/Sentinel dependency and stalls normalized/filtered shadow flow
- The same Kafka shadow wave also exposed a main-path bug in the shared transport abstraction: during `dual` mode, Redis publish must target Redis stream keys (`siem:raw`, `siem:normalized`, `siem:filtered`), not Kafka topic names. If `events_shadow` is fresh while `siem.events` is stale, verify the live `VM1` ingest runtime contains that fix before blaming Redis or ClickHouse.
- `VM4 /api/health/transport` now exposes `transport_shadow`, which is the main operator view for Kafka-wave readiness: use it to judge shadow freshness and parity before any live cutover.
- The `2026-03-22` storage review showed that the scary `27 GiB` figure on `VM3` was mostly Linux page cache. Actual ClickHouse RSS was around `1.38 GiB`, but the configured cache ceilings were still too loose and now have their own deploy/smoke path.
- The follow-up `2026-03-22` VM3 Proxmox alignment slice keeps the storage node from looking pinned near the full 28 GiB ceiling: `VM106` now uses `balloon=24576`, `qemu-guest-agent` is installed in the guest, and the live balloon target can be re-applied from the repo through `deploy/vm3_proxmox_memory_alignment.py`.
- The `2026-03-21` Postgres cutover stores migration state in the control plane itself and exposes it through `/api/control-plane/storage`.
- On Windows consoles, set `PYTHONIOENCODING=utf-8` before running the VM4 deploy script, otherwise Unicode lint output can trip a local `cp1251` encoding failure even when the remote validation is healthy.
- The `2026-03-13` power recovery proved that `VM3` and `VM4` must keep MAC-pinned static netplan config. Do not switch them back to DHCP-only bootstrap config.
- `VM4` reverse tunnels now depend on `openvpn-client@home-gateway` and target `vpnadmin_rdegon@10.66.66.1`, not the public SSH endpoint.

## Deployment Status

- Deployment targets: `VM1`, `VM3`, and `VM4`, with critical operational dependency on `VM2`
- Initial enterprise-foundation deployment date: `2026-03-12`
- Follow-up rollout dates: `2026-03-13`
- Last successful VM1 backup directory: `/tmp/siem-ingest-backup-20260313T001101Z`
- Last successful VM4 backup directory: `/tmp/siem-web-backup-20260313T001150Z`
- Remote React build: passed
- Remote backend compile: passed on both targets
- `siem-ingest` status after restart: `active`
- `siem-web` status after restart: `active`
- Smoke result on `VM1`: passed for `/health`, `/health/overview`, `/health/sources`, `/health/collectors`, `/dlq/events`, and `/dlq/replay`
- Smoke result on `VM4`: passed for OpenAPI, auth/service-account APIs, ingest APIs, connectors, health, control-plane storage, audit, cases, entities, response, content, active lists, secret readiness, connector dry-run runtime, response dry-run runtime, service-account token auth, and `/app`
- The current auth-routing follow-up also expects smoke to verify that successful `/auth/login` requests resolve into `/app`, not the legacy root UI
- The `2026-03-13` rollout exposed `/api/audit/events`, `/api/control-plane/storage`, and the audit plus control-plane summary inside `/api/health/overview` on live VM4
- The `2026-03-13` rollout also exposed `/api/ingest/*` on VM4 and live ingest admin endpoints on VM1
- The current rollout also adds `/api/sources/discovery*`, richer `/api/dashboard/summary`, and wider `/api/incidents` filtering
- The current rollout also adds `/api/health/overview.auth` metrics for:
  - local hashed/plaintext user counts
  - login rate-limit state
- A validated full-lab discovery rescan on `2026-03-13` found `14` hosts, `6` already connected telemetry sources, `8` unmanaged candidates, and `4` auto-ready Linux candidates
- The stale prepared job `onboard-f0086de489` for `192.168.1.38` is no longer operational debt: it now shows `status=superseded` because that node is correctly recognized as the connected `siem-storage` host
- Live VM4 now runs the control plane on `postgres` and exposes migration state through `/api/control-plane/storage`
- Live VM4 now supports service-account token auth for API callers, but it is still local machine auth rather than enterprise SSO
- Live VM3 now supports `event` or `processing` primary correlation mode with `shadow_compare` telemetry exposed through `/api/health/overview`
- Power-event recovery on `2026-03-13` restored `VM3` and `VM4` to `192.168.1.38` and `192.168.1.39`, revalidated all core services, and reactivated `siem-jump-tunnels` through `openvpn-client@home-gateway`
- Latest successful VM4 backup directory after the discovery-state fix: `/tmp/siem-web-backup-20260313T210354Z`
- Latest successful VM4 backup directory after the frontend remediation slice: `/tmp/siem-web-backup-20260319T174432Z`
- Latest successful VM4 backup directory after the analyst-UX follow-up: `/tmp/siem-web-backup-20260319T205034Z`
- Latest successful VM4 backup directory after the overview-windowing breakthrough slice: `/tmp/siem-web-backup-20260319T212117Z`
- Latest successful VM4 backup directory after the frontend engineering quality-gate slice: `/tmp/siem-web-backup-20260319T220134Z`
- Latest successful VM4 backup directory after the auth-routing and persisted-views slice: `/tmp/siem-web-backup-20260319T223027Z`
- Latest successful VM4 backup directory after the React shell foundation slice: `/tmp/siem-web-backup-20260319T231420Z`
- Latest successful VM4 backup directory after the React shell closure slice: `/tmp/siem-web-backup-20260320T020931Z`
- Latest successful VM4 backup directory after the `Loading Shell` hotfix: `/tmp/siem-web-backup-20260321T064428Z`
- Latest successful VM4 backup directory after the route-wide loader-stability hotfix: `/tmp/siem-web-backup-20260321T065705Z`
- Latest successful VM4 backup directory after the backend security hardening deploy: `/tmp/siem-web-backup-20260321T093653Z`
- Latest successful VM4 backup directory after the backend security hardening env rewrite: `/tmp/siem-web-security-hardening-20260321T094022Z`
- Latest successful VM1 ingest backup directory after the VM2 outage recovery hotfix: `/tmp/siem-ingest-backup-20260321T223814Z`
- Latest successful VM4 backup directory after the full React-shell closure pass: `/tmp/siem-web-backup-20260320T060342Z`
- Latest successful VM4 backup directory after the second-audit closure pass: `/tmp/siem-web-backup-20260320T111354Z`
- Latest successful VM4 backup directory after the feedback-and-live-announcement follow-up: `/tmp/siem-web-backup-20260320T140130Z`
- Latest successful VM4 backup directory after the Postgres-ready sync rollout: `/tmp/siem-web-backup-20260320T223028Z`
- Latest successful VM4 Postgres cutover backup directory: `/tmp/siem-web-postgres-cutover-20260320T223709Z`
- Latest successful VM3 stream-correlation backup directory: `/tmp/siem-stream-corr-backup-20260320T223801Z`
- The `2026-03-21` rollout also adds:
  - VM4 Postgres cutover validation through `/api/control-plane/storage`
  - VM3 event-time stream-correlation validation through `siem.stream_corr_runtime_status`
  - a lab-only duplicated operator secret bundle at `C:\Users\lolol\Documents\Playground\product-docs\OPERATOR_ACCESS_BUNDLE.md`
- Latest post-rollout validation for the `2026-03-21` backend slice:
  - backend unit tests: `35/35 OK`
  - `vm4_enterprise_foundation_smoke.py`: passed
  - `vm3_stream_corr_event_time_smoke.py`: passed
  - `/api/control-plane/storage`: `backend=postgres`, `migration_status=completed`
  - `/api/health/overview.platform.stream_correlation`: `mode=event`, `shadow_compare=true`, `shadow_compare_mismatches_total=0`
  - `/api/health/overview.auth.metrics.local_users_plaintext`: `0`
  - `/api/health/overview.auth.policy.login_rate_limit.enabled`: `true`
- Latest content-plane validation on `2026-03-22`:
  - `vm4_content_store_mongo_cutover.py`: passed
  - Proxmox VM107 CPU profile: `x86-64-v3`
  - latest VM4 Mongo cutover backup directory: `/tmp/siem-web-content-store-backup-20260322T173858Z`
  - latest Proxmox VM4 CPU-profile backup directory: `/tmp/siem-vm4-cpu-profile-backup-20260322T173859Z`
  - live `/api/content/storage`: `backend=mongo`, `migration_status=completed`
  - live `/api/health/transport`: `content_store_backend=mongo`, `stream_state_backend=sqlite`
  - live `/api/health/overview.platform.content_store_status.backend`: `mongo`
- Latest post-recovery validation for the `2026-03-22` VM2 outage:
  - `VM2` service state through Proxmox guest agent: `ssh=active`, `redis-server=active`, `qemu-guest-agent=active`, `siem-normalizer=active`, `siem-filter=active`, `siem-vm2 runner=active`
  - current event flow on `VM3`: `countIf(ts >= now() - INTERVAL 5 MINUTE)=1377`, `countIf(ts >= now() - INTERVAL 60 MINUTE)=3007`, `max(ts)=2026-03-21 22:43:24`
  - current alert flow on `VM3`: `countIf(ts >= now() - INTERVAL 60 MINUTE)=1807`, `max(ts)=2026-03-21 22:43:53`, `max(updated_ts)=2026-03-21 22:43:53`
  - runner plane status: `siem-vm1`, `siem-vm2`, `siem-vm3`, and `siem-vm4` all live
  - direct `VM2` SSH validation after the LAN hardening follow-up: repeated key-based and password-based logins from `192.168.1.27` succeeded after the post-restart settle window
  - current resilience follow-up expectation on `VM2`: Redis persistence should report `aof_enabled=1`, and `deploy-vm2` plus `vm2_processing_resilience_smoke.py` should stay green
  - latest runtime expectation on `VM2`: `deploy-vm2` now also refreshes the live `services/normalizer` and `services/filter` packages from `main`, and smoke must confirm the deployed workers contain `xreadgroup` plus `xack`
- latest scale-out expectation on `VM2`: `siem-normalizer@2` and `siem-filter@2` should also stay active, and the watchdog should treat them as part of the expected processing bundle
- latest Kafka shadow expectation on `VM1 + VM3 + VM5`:
  - `siem.raw`, `siem.normalized`, and `siem.filtered` consumer groups should show current offsets with near-zero lag
  - `siem.events_shadow` should keep recent rows
  - `/api/health/transport.transport_shadow.healthy` should be `true`
  - [vm3_kafka_shadow_writer_smoke.py](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/vm3_kafka_shadow_writer_smoke.py) should report non-empty `shadow_events_15m` when `SIEM_KAFKA_REQUIRE_SHADOW_FLOW=1`
  - the latest full-lab activation run is [23418190986](https://github.com/Rdegon/siem-solution/actions/runs/23418190986), and it completed successfully across `prepare-vm1-kafka`, `prepare-vm2-kafka`, `prepare-vm5-kafka`, `bootstrap-kafka-topics`, `activate-vm1-dual-write`, and `activate-vm3-shadow-writer`
  - the last workflow blocker was an ownership mismatch on `VM1`; if `activate-vm1-dual-write` fails again with `Permission denied` writing into `/opt/siem/siem-solution/services/ingest/*`, confirm that the node has the runner-safe [vm1_kafka_shadow_prepare.py](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/vm1_kafka_shadow_prepare.py) from `main`
- latest Redis HA validation on `2026-03-22`:
  - `redis_ha_resilience_smoke.py`: passed
  - active Sentinel-reported master: `192.168.1.37`
  - fresh flow after final recovery: `flow_events_5m=10399`, `flow_alerts_5m=1835`
  - watchdog validation after final recovery: `watchdog counts_before events_5m=10594`, `watchdog result=healthy`
  - latest Redis HA deploy backups: `/tmp/siem-redis-ha-backup-20260322T135420Z`, `/tmp/siem-redis-ha-backup-20260322T140148Z`, and `/tmp/siem-redis-ha-backup-20260322T143723Z`
  - latest VM3 stream-correlation backup after the wrapper fix: `/tmp/siem-stream-corr-backup-20260322T143801Z`
- Latest post-rollout validation for the full React-shell closure pass:
  - `vm4_enterprise_foundation_smoke.py`: passed
  - backend unit tests: `26/26 OK`
  - frontend quality gate on `VM4`: `typecheck`, `lint`, `test`, and `build` all passed
  - service status after rollout: `VM1 siem-ingest=active`, `VM2 redis-server=active`, `VM2 siem-normalizer=active`, `VM2 siem-filter=active`, `VM3 clickhouse-server=active`, `VM4 siem-web=active`, `VM4 siem-jump-tunnels=active`, `VM4 openvpn-client@home-gateway=active`
  - follow-up note: the first immediate post-restart smoke saw a transient `502` on `/api/ingest/overview`, but direct `VM4 -> VM1` ingest health remained healthy and the repeated authenticated smoke passed without code changes
  - current follow-up note: frontend tests now run one file at a time during VM4 deploy validation, which keeps the test gate green inside the stand's memory envelope
- Frontend remediation code slice baseline: `d71f11d`
- Primary GitHub publication target: `main`

## Remaining Gaps

- live validation of `siem-processing` freshness after the updated source-health thresholds are rolled out
- historical stale sources `192.168.1.31` and `192.168.1.32` still exist in ingest health but did not answer the latest discovery scan, so they are currently treated as offline or transient senders
- keep tightening typed contracts and shared shell behavior now that the main React route surface is already inside the quality gate
- continue splitting the remaining frontend foundation, especially `chrome.tsx` and the broader API layer, and keep evolving the current shell-wide keyboard workflow beyond the first `?` and `Alt+1..4` shortcuts
- the next UI audit should no longer spend time on emergency closure items like explicit `any`, missing semantic relationships, or missing CSRF on cookie mutations; the next wave is maturity work: toast feedback, broader page-flow tests, stronger design-token depth, and longer-term CSS/system modularization
- richer saved views for incidents beyond the current URL plus session persistence and deep-link copy flow
- Kafka ingestion backbone
- full Kafka cutover for the live transport bus
- transport-wide DLQ/backpressure beyond the VM1 ingest edge
- warm-standby processing beyond one active node, even though Redis HA plus Sentinel is now live across `VM2`, `VM3`, and `VM4`
- Redis stabilization itself is no longer the main blocker; the next transport wave should be Kafka cutover plus warm-standby processing instead of another Redis basic-recovery pass
- MongoDB is now live for the content plane, but it is still single-primary and should get backup/failover follow-up after Kafka
- the next large release wave is now explicitly `Kafka + VM5 + storage hardening`, not another Redis-only increment
- monitor stream-correlation shadow mismatches after the event-time rollout and decide when the rollback toggle can be retired
- enterprise SSO and directory-backed auth beyond the current service-account model
- platform-wide immutable audit outside the VM4 control plane
- full SOAR or approval workflows beyond the current basic model
- fully automated Windows and network-device onboarding beyond the current Linux-first SSH rollout

