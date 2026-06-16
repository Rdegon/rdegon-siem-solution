# Product Priorities: 2026-03-13

This document captures the user-reported product priorities added after the reboot and the later frontend-focused priorities introduced during the Claude-driven UX remediation pass.

Historical note:

- this file is a historical priority snapshot from `March 13, 2026`
- many items below are already landed on the current stand
- the active project baseline is now `project_closure_execution_plan_2026-03-26.md`
- for live UI state and follow-up product-quality work, use `ui_ux_system_audit_2026-03-27.md`

## Priority Order

### P0

0. Keep the backend architecture follow-up moving after UI closure:
   - live Postgres control-plane cutover on `VM4`
   - event-time stream correlation with shadow compare on `VM3`
   - a separate lab-only operator bundle with duplicated secrets outside the app repo
   - explicit documentation of the remaining backend resilience risks after hardening, especially Redis SPOF and transport durability
   - real CI on every change and a deployable CD path for the homelab
   - a distributed CD runner on each lab node so deploy automation does not depend on one in-lab runner host
   - the next ingest reliability slice: stop silent event loss when Redis raw stream approaches `MAX_STREAM_LEN`
   - the next processing reliability slice: make `VM2` a first-class deploy target, enable durable Redis AOF persistence, and let the watchdog repair stuck processing before the stand goes dark
   - close the Redis stabilization block all the way: live Sentinel quorum, replica flow, resilient Redis clients, event-flow smoke, and watchdog repair must all be green before transport work moves to Kafka
   - after Redis stabilization, move the next backend release wave to Kafka cutover, live Mongo content storage, and SQLite-backed stream-correlation state so transport and content layers stop depending on tactical filesystem or Redis-only runtime state
   - treat storage-memory visibility and VM3 ClickHouse tuning as part of release prep, because the stand is already surfacing false “memory full” alarms from oversized cache ceilings
   - treat Proxmox-side VM3 memory accounting as part of the same storage hardening slice: keep ballooning, qemu-guest-agent, and host-visible memory ceilings aligned so the storage node does not look saturated while it still has large guest headroom
   - after the current VM3 alignment, take the next two large release-oriented backend waves as one coordinated path:
     - `Kafka + VM5 + Redis exit`
     - `storage/control-plane HA + backend decomposition`
   - add a real host-runtime correlation pack to the rules roadmap so CPU, RAM, disk, load, swap, inode pressure, and stale host telemetry become first-class detection content instead of only dashboard signals
1. Keep dashboard and event-search time controls compact so the first screen stays focused on metrics, charts, and analyst context instead of oversized filters.
2. Preserve chart drill-down into exact event or incident time windows, including higher-resolution buckets for spike analysis.
3. Restore severity-distribution hover details with top contributing sources and top event summaries so the operator can understand the distribution without leaving the chart.
4. Make incidents and alerts more readable by replacing raw empty-array output such as `[]` with meaningful summaries, readable context cards, and better cluster rendering.
5. Let severity hover details float at the widget level instead of overlapping the donut itself, and make the whole severity block look like one seamless analytical surface rather than three isolated cards.
6. Polish the donut-chart visual language so the chart remains the focal element and the floating detail card does not make the widget feel lopsided or broken.
7. Make the severity detail list truly popup-based so it appears only on hover or focus, and keep it from colliding with the static caption and legend area.
8. Fix event-detail drawer overflow so opening a wide event does not expand the page or push the drawer off the expected viewport edge.
9. Continue the Claude-audit remediation on the items that most affect analyst operations: keyboard flow, accessibility, layout regressions, and shell readability.
10. Keep timezone switching correct so chart labels, event timestamps, and incident timestamps all move when the operator changes timezone.
11. Keep synthetic smoke emitters out of operational ingest health, and re-check `siem-processing` freshness after rollout.
12. Keep the overview landing surface coherent so the hero, time-focus controls, KPI snapshot, and section headers read as one operating surface instead of stacked unrelated cards.
13. Keep dense event and incident queues fast by windowing or virtualizing rows instead of rendering the full DOM for enterprise-sized pages.
14. Finish the React-shell closure pass so the next external UI audit sees one consistent shell: typed data contracts, shared async and error handling, keyboard-first navigation, and fewer page-local loading hacks.
15. Close the remaining second-audit UI blockers in one pass: remove explicit `any` from the remaining operator-critical routes, add semantic relationships to shared table-like surfaces, keep the lint gate strict, and wire CSRF into authenticated mutations.
16. Emergency production guardrail: if the React shell ever hangs on `Loading Rdegon SIEM shell...`, treat it as a shell-bootstrap regression first and verify that `/api/ui/bootstrap` and `/api/platform/status` are not being re-requested on every render.

### P1

17. Increase analyst-visible alert and incident volume in the queue so investigations do not stop at the first small page.
18. Refresh section icons and shell navigation affordances where the current icon set is too similar or too noisy.
19. Discover unmanaged LAN hosts, store them as candidate sources, classify what they likely are, and prepare onboarding paths.

### P2

20. Execute auto-monitoring rollout from the platform for the candidates where safe automation is possible.
21. Expand Windows and network-device auto-onboarding beyond the initial Linux-first rollout path.
22. Finish the remaining frontend-engineering gaps from the Claude audit: broader page-test coverage, design-system maturity, toast feedback, and further shell decomposition beyond the current operator-safe surface.
23. Make `/auth/login` land in the React shell at `/app` and preserve the internal target path so analysts return to the intended workspace after authentication.

## Implemented In This Slice

- Dashboard summary now accepts `window`, `from_ts`, `to_ts`, `bucket_minutes`, and `recent_limit`.
- Timeline widgets now return `bucket_start`, `bucket_end`, and `bucket_minutes`, and clicking a spike opens `/app/events` or `/app/incidents` scoped to that exact time range.
- React dashboard pages now expose preset and custom time ranges, bucket-size controls, and deeper incident preview limits.
- Time formatting in charts now uses the current shell timezone, and timezone switching preserves the same absolute instant when the operator changes the timezone selector.
- The topbar timezone control now uses shorter labels and more compact styling.
- The Overview timeline-focus card and the Events search card now use compact layouts, tighter control spacing, and conditional `from` / `to` fields so they no longer dominate the first viewport.
- Event-search quick filters no longer duplicate the larger time-focus toolbar, and the query panel now shows a concise active-window summary instead of forcing the operator to parse multiple oversized controls.
- Incident API and UI now support wider limits, including `1000` rows for aggregated or raw incidents.
- Severity and status distribution donuts now expose hover details with top source groups and top event summaries pulled from live backend aggregates.
- Severity hover detail now floats as a separate panel inside the overall donut widget instead of covering the donut surface itself.
- The severity widget now renders as one seamless matrix instead of three visually isolated nested cards.
- The donut visual polish follow-up re-centered the chart, softened harsh slice outlines, and moved the floating detail card into a less dominant overlay position so the chart remains the focal point.
- The severity detail card is now a true popup again: it stays hidden until hover or focus instead of permanently taking space inside the widget.
- Incident and alert drawers now render readable summaries for message, category, user, host, destination, and top rules, while empty list-like fields no longer appear as raw `[]`.
- Event-drawer JSON and message previews now clamp and wrap more safely so wide payloads stop forcing horizontal page growth.
- Incident triage now has basic keyboard flow for `J`, `K`, `Enter`, and `Esc`.
- The React shell now also has shell-wide keyboard navigation:
  - `?` opens shortcut help
  - `Alt+1` jumps to Overview
  - `Alt+2` jumps to Incidents
  - `Alt+3` jumps to Events
  - `Alt+4` jumps to Sources
- The overview landing surface now uses one integrated operating card for the hero, time focus, and KPI snapshot instead of separate awkward top-of-page blocks.
- Dashboard section headers are now lighter-weight and more consistent, so the overview reads as one workspace rather than a stack of unrelated banners.
- `EventsPage` and `IncidentsPage` now use windowed row rendering with sticky table headers, so dense queues render only the visible slice instead of the full DOM.
- A first GitHub Actions workflow now validates `main` and pull requests by running backend unit tests plus React shell typecheck and production build.
- The repository now also carries a manual GitHub Actions homelab deploy workflow skeleton targeting a `self-hosted` runner labeled `siem-homelab`; this is enough for automatic CD once a runner with LAN access to `VM1-VM4` is provisioned.
- The CD direction is now a distributed per-node runner plane instead of one shared lab runner:
  - `siem-vm1`
  - `siem-vm2`
  - `siem-vm3`
  - `siem-vm4`
  - shared label `siem-homelab`
- The CI/CD plane now also includes a scheduled watchdog workflow that validates the full stand and can auto-heal the most obvious repeat of the `2026-03-22` outage by starting `VM105` through Proxmox and rechecking fresh event flow.
- The latest ingest reliability follow-up now adds a raw-stream pressure model on `VM1`: health exposes raw stream length and pressure state, and events that arrive beyond the hard limit are diverted to DLQ instead of being silently trimmed out of the raw Redis stream.
- The latest `VM2` resilience follow-up now adds a dedicated `deploy-vm2` CD job, durable Redis AOF persistence on the processing node, and a smarter watchdog path that restarts `redis-server`, `siem-normalizer`, and `siem-filter` before escalating into broader ingest and detection restarts.
- The latest `2026-03-22` scale-out follow-up now also installs and starts secondary `normalizer` and `filter` workers on `VM2`, turning the processing plane into a real multi-consumer stage instead of one singleton worker per transform step.
- The final `2026-03-22` Redis-runtime follow-up now also fixes the last resilient-wrapper regression that had crash-looped `VM2` processing on keyword-style Redis API calls, and Redis HA smoke plus watchdog are both green again with fresh event flow.
- The `2026-03-22` transport/content follow-up now adds live transport health visibility (`/health/transport` on VM1 and `/api/health/transport` on VM4), keeps event-time correlation state in SQLite on `VM3`, and moves the content/document backend on `VM4` to live MongoDB.
- The same Mongo follow-up also hardens the infra truth for `VM4`: the Proxmox guest CPU profile is now `x86-64-v3` so MongoDB 7 can actually start, and the cutover script can remediate that profile automatically before enabling `mongod`.
- The frontend now has a real quality stack foundation: targeted TypeScript quality-gate coverage, ESLint on the hardened core-shell surface, and Vitest plus Testing Library smoke tests for timezone helpers, windowed rows, and drawer behavior.
- `VM4` deploys now bootstrap a repo-local Node 20 toolchain before running frontend validation, so lint, tests, and production builds no longer depend on the host's legacy system Node version.
- The heavy GeoIP map rendering path is now split into its own lazy module, so pages that only need common `ui.tsx` primitives no longer pay for `react-simple-maps` and `world-atlas` up front.
- The shared React shell surface is now materially more modular:
  - `ui.tsx` is a barrel only
  - chart widgets moved to `charts.tsx`
  - card, badge, drawer, and layout primitives moved to `surfaces.tsx`
  - shared async gating moved to `async.tsx`
  - typed shell response contracts moved to `types.ts`
- Shared shell data hooks now keep the previous payload visible during refresh and transient refresh failures, which removes another class of blank-screen flicker from the React UI.
- `Access`, `Cases`, and `Connectors` now use the shared async gate plus typed API responses instead of repeated page-local loading guards.
- `Assets`, `Collectors`, `Entities`, `Ingest`, `Sources`, and `ThreatIntel` now also use typed API responses and the shared async gate instead of page-local ad-hoc loading branches.
- Sidebar navigation is now grouped into clearer operational sections instead of presenting the full route list as one flat block.
- `EventsPage` now turns saved searches into a real analyst flow: the operator can apply saved views, save the current live query, and keep the active search state persisted in URL plus session storage.
- `IncidentsPage` now persists the current queue context in URL plus session storage and exposes copy-link plus reset actions for deeper analyst handoffs.
- `/auth/login` now redirects authenticated users into `/app` instead of the legacy root UI and preserves safe internal `next` paths during auth redirects.
- Several shell sections now use refreshed icons so navigation feels less repetitive.
- The shell quality gate now covers the broader operational React surface above instead of stopping at the original Access/Cases/Connectors remediation boundary.
- The React-shell closure pass now also brings `Builders`, `ControlPanel`, `Documentation`, `Inventory`, and `Vuln` under the same typed-contract, lint, test, and production-build gate that already covered the rest of the operator shell.
- The VM4 deploy path now explicitly ships those route modules, which closes the earlier rollout gap between local remediation and live stand state.
- The second external audit closure pass now also lands:
  - `no-explicit-any = error` in the frontend lint gate
  - typed incident, event, connector, case, entity, geo, response, and vulnerability contracts across the shared shell API layer
  - a typed `IncidentsPage` triage flow instead of `row: any`
  - semantic table roles in shared drawer/list surfaces
  - `aria-live="polite"` overview refresh announcements on the dashboard
  - CSRF protection for cookie-authenticated mutations through `X-CSRF-Token`
  - strict lint over the source tree instead of a hand-maintained file list
- The `2026-03-21` emergency production hotfix now stabilizes the React shell bootstrap path by keeping the `bootstrap` and `platformStatus` loaders in `App.tsx` referentially stable, which prevents the previous render-triggered request storm against `/api/ui/bootstrap` and `/api/platform/status`.
- The `2026-03-21` route-wide follow-up now applies the same stability rule to page-level loaders, removing inline async loaders from the main React routes so the request-loop defect does not simply move from `/app` into individual workspaces.
- A transient post-restart `502` from `/api/ingest/overview` was observed on the first immediate smoke after the `2026-03-20` rollout, but direct `VM4 -> VM1` ingest health stayed healthy and the repeated authenticated smoke passed without additional code changes.
- Ingest health now marks smoke and synthetic emitters as `synthetic` instead of counting them as delayed or stale operational sources.
- A new LAN discovery plane now exists on `VM4`:
  - `GET /api/sources/discovery`
  - `POST /api/sources/discovery/scan`
  - `POST /api/sources/discovery/{candidate_id}/prepare`
  - `POST /api/sources/discovery/jobs/{job_id}/execute`
- The discovery plane stores candidate hosts, open ports, inferred role, OS family, collector recommendation, and prepared onboarding jobs.
- Linux and Proxmox-like candidates can now generate an SSH-driven `rsyslog` onboarding job with dry-run support.
- Discovery rescans now supersede stale prepared jobs once a host is recognized as already connected, so the operator no longer sees false `prepared` state on active SIEM nodes.

## Still Open

Historical note:

- the items below should be read as historical carry-over priorities, not as current blocker truth for the stand on `March 27, 2026`
- several major waves listed here were completed in later passes:
  - `Kafka + VM5 + Redis exit`
  - `storage/control-plane HA + backend decomposition`
  - `host telemetry + runtime observability correlation`
  - `identity, secrets, and enterprise access maturity`
  - `response / SOAR hardening`
  - `release hardening and certification`


- Keep the now-complete four-node CI/CD runner plane healthy after reboots, especially `VM2` with its new Proxmox guest-agent fallback path.
- Keep the new watchdog path healthy too: GitHub Actions must retain Proxmox access and the `VM2` guest-agent path, otherwise the auto-heal loop degrades back into manual recovery.
- AOF and watchdog repair improve restart durability, but they do not eliminate the Redis SPOF; full replica or Sentinel failover still remains the next transport-resilience milestone.
- VM2 runtime sync is now live, so the next processing-plane reliability jump should target warm-standby or failover for `normalizer` and `filter`, not just faster repair of the single active node.
- After the new secondary workers on `VM2`, the next reliability jump should move from local scale-out to cross-node standby or failover, so `VM2` is no longer both the only Redis node and the only active processing host.
- Redis stabilization is now considered closed enough for release preparation; the next transport-wave priorities are Kafka cutover plus warm-standby processing beyond one node.
- MongoDB is now live for the content plane, so the next persistence-wave priorities are storage HA and backend decomposition rather than another filesystem content-store pass.
- Validate live `siem-processing` freshness after the current rollout. This is now rechecked and healthy on `VM1`, so the remaining work is to keep that state stable under future reboots and transport failures.
- Finish a broader visual layout review pass across the full React shell, now that the main operator routes are inside one consistent quality gate.
- Add explicit pagination and saved-view controls for large incident queues, instead of only raising the current limit.
- Keep tightening React-shell contracts and design consistency across the now-validated route surface instead of reopening page-local loading and typing drift.
- The UI is now in a state where the next external audit should focus on higher-level maturity rather than P0 closure: toast feedback, broader page-test coverage, design-system depth, and remaining shell visual consistency.
- Toast feedback is now live in the shell, so the next maturity step is broader page-flow coverage and stronger visual consistency rather than silent-mutation basics.
- Continue splitting the remaining shell foundation beyond the new barrelized `ui.tsx`, especially `chrome.tsx`, and keep strengthening shared API typing beyond the current operational slice.
- Keep the full four-node runner plane reliable in practice and reduce Redis single-node blast radius on `VM2`.
- Extend candidate discovery into a recurring scheduled scan and automatic candidate aging.
- Add real Windows bootstrap execution and network-device config push instead of manual job preparation only.
- Investigate historical stale source rows `192.168.1.31` and `192.168.1.32`. They did not answer the latest discovery scan, so they currently look like offline or transient senders rather than managed live hosts.
- Publish the new host-runtime observability pack after the host-telemetry collector wave lands; until then, keep the pack visible as planned content and saved-search seed instead of pretending the runtime event family already exists.
- Execute the next two large release waves in order:
  - `Kafka + VM5 + Redis exit`
  - `storage/control-plane HA + backend decomposition`
- After those two waves, move to the queued four-wave backlog:
  - `host telemetry + runtime observability correlation`
  - `identity, secrets, and enterprise access maturity`
  - `response / SOAR hardening`
  - `release hardening and certification`
