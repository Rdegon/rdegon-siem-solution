# Frontend Remediation Slice: 2026-03-19

This document records the frontend remediation work taken after the external Claude audit of the React shell.

## Audit Direction Accepted

The audit correctly called out several production gaps in the frontend shell:

- no route-level code splitting
- production build shipped without minification
- no focus trap or keyboard close behavior in drawers
- no global `:focus-visible` treatment
- no skip link for keyboard users
- polling continued to run in hidden tabs
- `EventsPage` column renderers still used `any`
- shell bootstrap imported the heavy `ui.tsx` module, which pulled charts and map assets into the initial path

## What This Slice Implemented

### Production build and bundle shape

- `frontend-react/build.cjs` now enables:
  - `minify: true`
  - `splitting: true`
  - `format: "esm"`
  - `chunkNames: "chunks/[name]-[hash]"`
- The current live build on `VM4` now emits route chunks such as:
  - `chunks/DashboardPage-*`
  - `chunks/EventsPage-*`
  - `chunks/IncidentsPage-*`
  - `chunks/VulnPage-*`

### Route-level lazy loading

- `frontend-react/src/shell/App.tsx` now lazy-loads page modules through `React.lazy()`.
- Each route is wrapped with its own `ReactErrorBoundary` and `Suspense` fallback so a single page failure does not take down the entire shell.

### Lighter shell bootstrap

- Lightweight shell primitives moved into `frontend-react/src/shell/chrome.tsx`:
  - `Icon`
  - `EmptyState`
  - `ReactErrorBoundary`
- `App.tsx` now imports from `chrome.tsx` instead of the heavy `ui.tsx` bundle, reducing the amount of chart and map code pulled into the initial shell path.
- The heavy GeoIP map path now lives in `frontend-react/src/shell/GeoDotMapCanvas.tsx` and is lazy-loaded through `ui.tsx`, so shells that only need shared cards, badges, drawers, and charts no longer pull `react-simple-maps` and `world-atlas` into their base path.

### Accessibility and focus handling

- `DrawerOverlay` in `frontend-react/src/shell/ui.tsx` now has:
  - focus capture on open
  - `Escape` close behavior
  - `Tab` / `Shift+Tab` focus trapping
  - focus restore on close
  - `role="dialog"` on the panel
  - `aria-labelledby` and conditional `aria-describedby`
- `frontend-react/src/styles.css` now adds:
  - global `:focus-visible` outlines
  - a keyboard-accessible skip link
  - a slightly safer base font size via `--font-size-base: 12px`

### Token foundation

- Initial CSS custom properties now exist for:
  - background colors
  - text colors
  - accent colors
  - spacing steps
  - radii
  - base font size
- This is not yet a full design system, but it establishes the first real token layer instead of pure hardcoded values.

### Polling behavior

- `frontend-react/src/shell/hooks.ts` now suppresses interval polling while the document is hidden.
- When the tab becomes visible again, the hook performs an immediate refresh and restarts the interval.

### Safer typing

- `frontend-react/src/shell/pages/EventsPage.tsx` now uses:
  - typed `EventRow`
  - typed `EventsQueryResponse`
  - generic `Column<TRow>`
- This removes the immediate `render(row: any)` problem from the event table configuration.

### Time-focus compaction and analyst density

- The Overview timeline-focus card now uses a more compact control layout so the first screen emphasizes metrics and charts instead of oversized time filters.
- The Events search panel now uses compact spacing, a shorter query editor, and conditional `from` / `to` inputs that only expand when the operator chooses a custom window.
- The Events page now renders a concise active-window summary instead of duplicating large quick-filter controls above the search area.

### Richer chart detail and alert readability

- Severity and status donut charts now restore hover detail instead of showing only the slice label.
- Hover content now includes:
  - total count and share
  - top contributing source groups
  - top contributing event summaries
- Hover detail is now rendered as a separate floating detail card at the widget level instead of sitting on top of the donut surface itself.
- The severity widget now renders as one continuous matrix instead of three isolated nested cards, which reduces the visual seams between the three related charts.
- The donut polish follow-up re-centered the chart, softened the slice separators, and reduced the visual weight of the floating detail card so the chart itself stays primary.
- The latest follow-up also restores true popup behavior for the severity detail card: it now appears on hover or focus instead of permanently living inside the widget layout.
- Incident and alert drawers now render a readable summary card for the most useful operator context instead of dumping raw cluster structures first.
- Empty array-style values are now suppressed or replaced with human-readable fallback text, which removes the visible `[]` problem from the incident UI.
- Event-drawer previews now clamp wide text and JSON more safely, which reduces the horizontal overflow case where opening a large event made the page feel wider than the viewport.
- The dashboard landing surface now uses one integrated overview operating card, combining hero context, compact time focus, and KPI snapshot instead of three disconnected top-of-page blocks.
- Dashboard section headers now use a lighter hierarchy so the overview reads like one workspace rather than a stack of separate panels.
- `EventsPage` and `IncidentsPage` now use windowed row rendering with sticky table headers, which reduces DOM pressure for dense result sets while keeping click-to-drawer and keyboard triage behavior intact.
- A first GitHub Actions workflow now validates `main` and pull requests by running backend unit tests plus React shell typecheck and production build.

### Navigation and keyboard flow

- Several shell sections now use refreshed icons for better section differentiation.
- Sidebar navigation is now grouped into clearer operational buckets instead of one flat list, which makes analyst-critical routes faster to scan.
- `IncidentsPage` now supports basic triage hotkeys:
  - `J` / `ArrowDown` for next row
  - `K` / `ArrowUp` for previous row
  - `Enter` to open the selected incident
  - `Escape` to close the drawer

### Frontend quality gate

- `frontend-react/package.json` now defines:
  - `npm run typecheck`
  - `npm run lint`
  - `npm run test`
  - `npm run build`
- `frontend-react/.eslintrc.cjs` now establishes the first frontend linting baseline for the remediated core shell.
- `frontend-react/tsconfig.quality.json` now scopes a targeted TypeScript quality gate to the hardened shell surface instead of pretending the whole legacy shell is already clean.
- `frontend-react/vitest.config.ts` plus `frontend-react/src/test/*` now add the first frontend test stack.
- Current tests cover:
  - timezone conversion helpers
  - windowed row rendering behavior
  - drawer focus and keyboard close behavior
  - session-backed persistence helpers for the shell
- `deploy/vm4_enterprise_foundation_deploy.py` now bootstraps a repo-local Node 20 runtime on `VM4`, then runs:
  - `npm run typecheck`
  - `npm run lint`
  - `npm run test`
  - `npm run build`
- `.github/workflows/validate-main.yml` now runs the same frontend quality gate in CI for `main` and pull requests.

### Modular shell foundation and async behavior

- `frontend-react/src/shell/ui.tsx` is now only a barrel export instead of a multi-hundred-line mixed component file.
- The former shared UI monolith is now split into:
  - `frontend-react/src/shell/charts.tsx`
  - `frontend-react/src/shell/surfaces.tsx`
  - `frontend-react/src/shell/async.tsx`
  - `frontend-react/src/shell/types.ts`
- `frontend-react/src/shell/hooks.ts` now keeps previously loaded payloads visible during refresh boundaries and after transient refresh failures instead of blanking the page back to `null`.
- `frontend-react/src/shell/App.tsx` now reads platform health through the shared polling layer instead of its own ad-hoc interval.
- `AccessPage`, `CasesPage`, and `ConnectorsPage` now consume the shared async gate and typed response shapes instead of relying on repeated ad-hoc loading guards plus `any`.
- `EmptyState` in `frontend-react/src/shell/chrome.tsx` now announces itself as a live status region for assistive technology.
- `frontend-react/src/styles.css` now enables `scrollbar-gutter: stable both-edges;` on `body`, which reduces the layout jump when drawers lock page scroll.
- Frontend tests now also cover:
  - async gate rendering
  - stale-while-refresh behavior in `useAsyncData`

### Broader typed shell coverage and shell-wide shortcuts

- The shared shell typing layer in `frontend-react/src/shell/types.ts` now covers a wider operational surface:
  - assets and asset inventory
  - source inventory and source discovery
  - collector inventory
  - ingest overview, source heartbeat, collector heartbeat, and DLQ payloads
  - threat-intel overview and geo detail payloads
  - entity and risk-signal payloads
- `frontend-react/src/shell/api.ts` now returns typed responses for the remediated operational routes instead of keeping those pages on implicit `any` contracts.
- The following route modules now consume typed payloads plus the shared `AsyncGate` loading pattern instead of repeating ad-hoc loading branches:
  - `AssetsPage`
  - `CollectorsPage`
  - `EntitiesPage`
  - `IngestPage`
  - `SourcesPage`
  - `ThreatIntelPage`
- The React shell now exposes a shell-wide shortcuts drawer:
  - `?` opens the shortcut help surface
  - `Alt+1` navigates to Overview
  - `Alt+2` navigates to Incidents
  - `Alt+3` navigates to Events
  - `Alt+4` navigates to Sources
- This is not yet a full command palette, but it closes one more practical SOC-operator gap from the external audit by making keyboard-first navigation available beyond the incidents queue.
- The frontend quality gate now explicitly includes the remediated operational pages above instead of stopping at the earlier Access/Cases/Connectors slice.

### React shell closure pass

- The shell-quality gate now also covers the remaining React route modules that were still outside the hardened slice:
  - `BuildersPage`
  - `ControlPanelPage`
  - `DocumentationPage`
  - `InventoryPage`
  - `VulnPage`
- `frontend-react/src/shell/types.ts` and `frontend-react/src/shell/api.ts` now expose typed contracts for:
  - dashboard registry and widget catalog payloads
  - document and playbook index/detail payloads
  - builder drafts, validation, test, and publish payloads
  - vulnerability overview, reports, findings, row views, and import contract payloads
  - inventory payloads across assets, sources, and collectors
- `deploy/vm4_enterprise_foundation_deploy.py` now explicitly ships those route modules to `VM4`, which closes the earlier rollout gap where part of the React shell could validate locally but remain stale on the stand.
- This closure pass leaves the operator-facing React shell in one consistent validation envelope for the next external UI audit: route chunks, typed contracts, shared async gating, lint, tests, and production build all pass together on `VM4`.

### Analyst workflow persistence and auth routing

- `EventsPage` now exposes saved-search application and in-place saving of the current live query, so the existing control-plane `saved_search` object is usable directly from the analyst console.
- `EventsPage` now persists its current search context into both the URL and session storage:
  - query text
  - time window
  - explicit custom range
  - storage selector
  - row limit
- `IncidentsPage` now persists its queue context into both the URL and session storage:
  - view mode
  - scope
  - query text
  - explicit time range
  - row limit
  - focused incident id
- `IncidentsPage` now exposes:
  - copy-link for the current deep-linked queue state
  - reset to the default queue posture
- `/auth/login` now redirects successful logins into `/app` instead of the legacy root UI.
- Protected-route redirects now preserve a safe internal `next` path so authentication can return the operator to the intended React shell workspace.

### Audit-closure hardening from the second external review

- `frontend-react/src/shell/types.ts` now covers the remaining audit-critical contracts that were still leaking `unknown` or implicit `any` behavior:
  - incidents and incident detail
  - events query responses
  - connector detail and run payloads
  - case detail and mutations
  - entity detail
  - geo-source and geo-country detail payloads
  - response action and execution payloads
  - active-list, content-bundle, and secret-readiness payloads
  - vulnerability overview, findings, report catalog, report detail, and import-contract payloads
- `frontend-react/src/shell/api.ts` now sends typed responses through those routes instead of leaving the core operator flows on `getJson<any>` or `postJson<any>`.
- `frontend-react/src/shell/pages/IncidentsPage.tsx` is now typed end-to-end for list, detail, history, and status transitions, removing the remaining audit-highlighted `any` drift from the triage queue.
- `frontend-react/src/shell/pages/DashboardPage.tsx`, `frontend-react/src/shell/DashboardCanvas.tsx`, and `frontend-react/src/shell/pages/VulnPage.tsx` now render from shared typed contracts instead of page-local loose objects.
- `frontend-react/.eslintrc.cjs` now enforces `@typescript-eslint/no-explicit-any = "error"` and no longer hides `react-hooks/exhaustive-deps` issues behind a file-level override.
- `frontend-react/package.json` now lints the actual source tree through `eslint src --ext .ts,.tsx src/test --max-warnings=0` instead of relying on a manually curated file list.
- `frontend-react/src/shell/hooks.ts` now uses a lint-safe loader contract:
  - pages stabilize loaders with `useCallback`
  - shared hooks depend on the loader itself
  - the older optional dependency-array parameter remains only as a compatibility shim while the shell migrates fully to stable callbacks
- `frontend-react/src/shell/surfaces.tsx` now adds semantic table roles to reusable key-value and info-list surfaces, which closes the audit's semantic-relationship gap for the shared drawer/table primitives.
- `frontend-react/src/shell/pages/DashboardPage.tsx` now exposes a polite live region summarizing refreshed overview counts so polling-based dashboard updates are no longer silent for assistive technology.
- `auth.py`, `security.py`, `main.py`, and `frontend-react/src/shell/api.ts` now implement the first CSRF round-trip for cookie-authenticated mutations:
  - login issues a `csrf_token` cookie
  - unsafe cookie-authenticated requests require `X-CSRF-Token`
  - bearer-token and `X-API-Token` machine-auth requests stay exempt
- `.github/workflows/validate-main.yml` is part of the current live slice and matches the same frontend quality gate executed on `VM4` during deploys.

## Live Validation

Validated on `VM4` after rollout:

- remote React production build: passed
- `vm4_enterprise_foundation_smoke.py`: passed
- `/app`: passed
- `/auth/login` authenticated redirect to `/app`: passed
- lazy-loaded production chunk files exist under `services/web/frontend-react/dist/assets/chunks/`
- live service status after rollout: `siem-web = active`
- `npm run typecheck`: passed
- `npm run lint`: passed
- `npm run test`: passed
- `npm run build`: passed
- frontend test count on `VM4`: `8/8`
- the expanded shell-quality slice also validated the typed operational pages plus shell-wide shortcuts drawer on live `VM4`
- the full React-shell closure slice also validated the remediated builder, documentation, control-panel, inventory, and vulnerability routes on live `VM4`
- the second-audit closure slice also validated:
  - typed `IncidentsPage`
  - typed shared API contracts with `no-explicit-any = error`
  - semantic table-role surfaces
  - CSRF-protected authenticated mutations
- the feedback-and-live-announcement slice also validated:
  - shell-wide toast feedback through `frontend-react/src/shell/feedback.tsx`
  - polite live announcements for refreshed operator pages
  - VM4-safe sequential Vitest execution during deploy validation
- the `2026-03-21` shell-bootstrap hotfix also validated:
  - `App.tsx` now stabilizes the bootstrap and platform-status loaders with `useCallback`
  - authenticated `/app` flow no longer stalls in `Loading Rdegon SIEM shell...`
  - post-deploy journal inspection no longer showed the previous `/api/ui/bootstrap` and `/api/platform/status` request storm after the new rollout window
- the follow-up `2026-03-21` route-wide hotfix also validated:
  - route loaders in `Assets`, `Builders`, `Collectors`, `Entities`, `Events`, `Incidents`, `Ingest`, `Inventory`, `Sources`, and `ThreatIntel` are now stabilized with `useCallback`
  - the React shell no longer relies on inline loader functions for page-level `useAsyncData` or `usePolledData` calls
  - post-deploy smoke and `siem-web` restart logs stayed clean without the earlier browser-driven request storm pattern
- stand service check after the closure rollout:
  - `VM1`: `siem-ingest = active`
  - `VM2`: `redis-server = active`, `siem-normalizer = active`, `siem-filter = active`
  - `VM3`: `clickhouse-server = active`
  - `VM4`: `siem-web = active`, `siem-jump-tunnels = active`, `openvpn-client@home-gateway = active`
- live post-restart smoke on `2026-03-20` ended green after the service restart window settled:
  - `/api/ingest/overview` briefly returned `502` during the first immediate smoke pass after `siem-web` restart
  - direct health checks from `VM4` to `VM1` stayed healthy
  - the repeated authenticated smoke then passed end-to-end without code changes

Latest backup for this slice:

- `/tmp/siem-web-backup-20260319T223027Z`
- `/tmp/siem-web-backup-20260319T231137Z`
- `/tmp/siem-web-backup-20260319T231420Z`
- `/tmp/siem-web-backup-20260320T015723Z`
- `/tmp/siem-web-backup-20260320T020402Z`
- `/tmp/siem-web-backup-20260320T020931Z`
- `/tmp/siem-web-backup-20260320T060342Z`
- `/tmp/siem-web-backup-20260320T111354Z`
- `/tmp/siem-web-backup-20260320T140130Z`
- `/tmp/siem-web-backup-20260321T064428Z`
- `/tmp/siem-web-backup-20260321T065705Z`

Published Git refs for this slice:

- frontend remediation code slice was first published from commit `d71f11d`
- GitHub publish branch: `codex/frontend-remediation-2026-03-19`
- later docs-only sync commits can advance the branch tip beyond the code slice above

## Remaining Frontend Gaps

The audit is still directionally correct on these open areas:

- `api.ts` is now substantially more typed for the React shell, but the broader platform surface still needs more contract tightening beyond the current route inventory
- the former `ui.tsx` monolith is now split, but `chrome.tsx` still carries the icon catalog and should eventually be decomposed further
- incident triage hotkeys and shell shortcuts now exist, but there is still no broader command-palette or richer keyboard workflow
- the Overview landing surface is much cleaner now, but it still deserves one more polish pass after the next external audit
- the severity widget is materially better now, but it may still need one more design pass after the next external audit
- no full design system or Storybook yet
- no `TanStack Query` data layer yet
- VM4 still needs sequential per-file test execution during deploy validation because the full one-process Vitest run can OOM on the lab host
