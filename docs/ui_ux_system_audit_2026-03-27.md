# UI/UX System Audit: 2026-03-27

Note:

- the closure status for the remaining P0 UI findings is recorded in `docs/ui_ux_followup_closure_2026-03-27.md`
- where this audit conflicts with the later follow-up document, the later follow-up document is authoritative

## Evidence basis

This audit is based on three evidence classes.

Directly observed facts:

- repository code under `frontend-react/`, `docs/`, and the runtime modules that feed `/app/*`
- live browser capture on `VM4` after deployment:
  - `../.artifacts/browser/live-audit/results.json`
  - `../.artifacts/browser/live-audit/*.png`
- authenticated runtime endpoints used by the shell

Strong inferences:

- usability and scanability conclusions drawn from the live rendered pages and the component structure
- maintainability conclusions drawn from file boundaries, shared UI primitives, and test coverage

Cannot verify from current evidence:

- actual operator dwell-time analytics
- real production analyst usage sessions
- screen-reader audits or manual assistive-technology testing
- a Storybook or published visual-spec system, because none exists in the repo

## 1. Executive summary

The `/app/*` shell is now a coherent branded enterprise product rather than a generic dark admin UI. The strongest surfaces are:

- the shell identity and navigation model
- the `Access` workspace for Keycloak and governance operations
- the dense data-plane treatment in `Events`, `Sources`, and `Vulnerability`
- the live operational credibility created by the green stand, live OIDC, Vault, and health-driven runtime

The biggest remaining weaknesses are not "broken UI" issues. They are maturity and product-shape issues:

- the `Overview` surface is still too tall and report-like for a first-screen command workspace
- the investigation model is still fragmented across `Events`, `Entities`, `Assets`, and `Threat Intel`
- charts are substantially better than before, but they are still mostly strong wrappers around chart-library primitives rather than a fully ownable data-viz language
- the documentation baseline is now aligned again, so the remaining work is concentrated in page curation, investigation cohesion, and design-system maturity

Bottom line:

- premium feel: `yes`
- credible diploma / recruiter demo surface: `yes`
- enterprise-operational credibility: `yes`
- fully mature design-system program: `not yet`
- best-in-class SOC product polish: `not yet`

## 2. Reconstructed product intent

### Intended product

Direct fact:

- the project is a browser-based SIEM / SOC platform with ingest, detection, incident handling, source onboarding, vulnerability analysis, SOAR, identity governance, and operator docs

Evidence:

- `docs/architecture.md`
- `docs/project_closure_execution_plan_2026-03-26.md`
- `docs/production_certification_and_governance_closure_2026-03-26.md`
- `frontend-react/src/shell/App.tsx`

### Primary personas

Strong inference from docs, routing, and page structure:

- SOC analyst
- incident responder
- detection / content engineer
- platform administrator
- security engineer / exposure owner
- project reviewer / technical lead / potential customer in demo contexts

Evidence:

- `frontend-react/src/shell/App.tsx`
- `docs/product_priorities_2026-03-13.md`
- `docs/soar_response_hardening_2026-03-26.md`
- `docs/vulnerability_maturity_2026-03-25.md`

### Core user flows

Direct fact:

- monitor the stand and current pressure from `Overview`
- investigate raw telemetry from `Events`
- triage clusters and queue work in `Incidents`
- onboard and manage telemetry via `Sources`
- review exposure and act on findings in `Vulnerability`
- manage rules and graph content in `Builders`
- manage identity and secrets in `Access`

Evidence:

- `frontend-react/src/shell/App.tsx`
- live screenshots in `../.artifacts/browser/live-audit/`

### Docs -> implemented screens -> gap summary

| Doc / requirement | Implemented screen / flow | Status | Gap / contradiction |
| --- | --- | --- | --- |
| `docs/architecture.md`: React shell and control plane on `VM4` | `/app/*` shell on live `VM4` | complete | none |
| `docs/production_certification_and_governance_closure_2026-03-26.md`: `/app/access` as identity control center | `/app/access?tab=keycloak-users` and related tabs | complete | none |
| `docs/source_discovery.md`: discovery plus onboarding workflows | `/app/sources` with discovery and onboarding preview | complete | right-side context still depends on explicit selection |
| `docs/vulnerability_maturity_2026-03-25.md`: action-first vulnerability surface | `/app/vuln` top section matches this | partial | lower page still carries reference-heavy density that weakens first-screen action focus |
| `docs/product_priorities_2026-03-13.md`: unified shell, compact controls, investigation UX | implemented in shell and pages | complete as a historical snapshot | file now explicitly marks itself as historical rather than active blocker truth |
| `docs/project_closure_execution_plan_2026-03-26.md`: slabs closed and `/app/*` primary | repo and live UI confirm | complete | none |
| `docs/architecture.md`: OIDC / vault planned upgrades | live `/api/auth/providers`, `/api/auth/governance`, `/app/access` | aligned after this pass | historical wording now distinguishes landed features from future federation follow-up |

## 3. Documentation / project conformance matrix

| Requirement / doc section | Implemented? | Evidence | Gap | Recommendation |
| --- | --- | --- | --- | --- |
| `docs/README.md`: `/app/*` is the primary operator surface | yes | `docs/README.md`, `frontend-react/src/shell/App.tsx` | none | keep as source of truth |
| `docs/architecture.md`: topology and shell on `VM4` | yes | `docs/architecture.md`, live `/app` | none | keep |
| `docs/architecture.md`: OIDC and vault historical slice notes | yes | live `/auth/login`, `/api/auth/providers`, `/api/auth/governance`, `/app/access`, updated doc text | none | keep |
| `docs/project_closure_execution_plan_2026-03-26.md`: slabs 3 and 4 closed | yes | live rollout, `docs/live_rollout_verification_2026-03-27.md` | none | keep |
| `docs/product_priorities_2026-03-13.md`: historical priority snapshot remains readable without pretending to be current blocker truth | yes | updated historical note in the file | none | keep as historical reference |
| `docs/platform_finalization_and_app_redesign_2026-03-27.md`: branded shell and layered CSS | yes | `frontend-react/src/styles.css`, `frontend-react/build.cjs`, live screenshots | none | keep |
| `docs/sso_operations_and_external_integrations_2026-03-26.md`: live OIDC-first UX | yes | `/auth/login`, `/app/access` | none | keep |
| `docs/vulnerability_maturity_2026-03-25.md`: reduced unmapped targets and action-first vuln lane | yes | `/api/vuln/maturity`, `/app/vuln` | small UX gap in lower-page information layering | split reference-heavy content into secondary tabs or collapsible zones |

## 4. Frontend architecture assessment

### What is solid

Direct fact:

- route surface is centralized in `frontend-react/src/shell/App.tsx`
- pages are lazy-loaded instead of bundled eagerly
- API calls are typed and centralized in `frontend-react/src/shell/api.ts`
- the shell now has reusable surface primitives in `frontend-react/src/shell/surfaces.tsx`
- charts are wrapped in `frontend-react/src/shell/charts.tsx`
- CSS is layered through `frontend-react/src/styles.css` importing:
  - `tokens.css`
  - `base.css`
  - `shell.css`
  - `components.css`
  - `data-surfaces.css`
  - `charts.css`
  - `page-families.css`
- the build pipeline emits branded assets and favicon through `frontend-react/build.cjs`
- frontend quality gates exist through `TypeScript`, `ESLint`, `Vitest`, and `Playwright`-based verification

Evidence:

- `frontend-react/src/shell/App.tsx`
- `frontend-react/src/shell/api.ts`
- `frontend-react/src/shell/surfaces.tsx`
- `frontend-react/src/shell/charts.tsx`
- `frontend-react/src/styles.css`
- `frontend-react/build.cjs`
- `frontend-react/package.json`
- `frontend-react/tsconfig.json`
- `frontend-react/src/shell/__tests__/`

### What is still structurally weak

Direct fact:

- `frontend-react/src/shell/App.tsx` still carries too many responsibilities:
  - bootstrap
  - platform polling
  - keyboard shortcuts
  - navigation definition
  - sidebar grouping
  - layout shell
  - topbar logic
  - route wiring
- `frontend-react/src/styles.css` still imports `legacy.css` first, which means the design-system layering is not yet fully isolated from compatibility styling
- there is no Storybook, visual-regression suite, or token catalog artifact in the repo

Evidence:

- `frontend-react/src/shell/App.tsx`
- `frontend-react/src/styles.css`
- absence of `storybook` config in `frontend-react/`

Assessment:

- architecture maturity: `good`
- design-system-program maturity: `medium`
- long-term UI scalability without further decomposition: `medium`

## 5. Visual maturity assessment

### Overall impression

Direct fact from live renders:

- the shell now has a real brand, not placeholder admin chrome
- the typography choice is distinctive and appropriate for cyber operations
- the palette is disciplined and readable
- the product feels more like a control plane than a startup dashboard template

Evidence:

- `../.artifacts/browser/live-audit/overview.png`
- `../.artifacts/browser/live-audit/events.png`
- `../.artifacts/browser/live-audit/access-users.png`
- `frontend-react/build.cjs`

### Visual-system scorecard

| Dimension | Assessment | Evidence | Conclusion |
| --- | --- | --- | --- |
| Premium feel | strong | branded shell, favicon, IBM Plex, layered CSS, live screenshots | no longer feels like a generic dark admin template |
| Trustworthiness | strong | stable dark palette, tight badges, dense tables, live green runtime | serious operational tool rather than portfolio-only mockup |
| Visual hierarchy | good | `Overview`, `Access`, `Incidents`, section containers | good overall, but the longest pages are still too assembled rather than fully curated |
| Density vs readability | good | `Events`, `Sources`, `Access` screenshots | dense-but-readable, which fits the enterprise SOC target |
| Dark-theme maturity | strong | `tokens.css`, live screenshots | dark theme is disciplined and readable rather than muddy |
| Brand distinctiveness | strong | `Rdegon Sentinel` shell, favicon, mark asset | product has its own recognizable identity now |
| Shell consistency | good | shared navigation and surface primitives | flagship surfaces feel related, though not yet fully normalized |
| Admin/control-center feel | strong in `Access`, moderate elsewhere | `access-users.png`, `AccessWorkspace.tsx` | `Access` feels fully productized; not every admin surface is at that level yet |
| Visual noise | controlled on most pages, elevated on longest pages | `overview.png`, `vuln.png` | main issue is page length and module count, not color chaos |

### Main visual weaknesses

Direct fact:

- `Overview` is extremely tall in the live capture and reads more like a long executive report than a strict first-screen command surface
- the lower half of `Vulnerability` still mixes action-first and reference-heavy material too early

Evidence:

- `../.artifacts/browser/live-audit/overview.png`
- `../.artifacts/browser/live-audit/vuln.png`
- `frontend-react/src/shell/pages/DashboardPage.tsx`
- `frontend-react/src/shell/pages/VulnPage.tsx`

Strong inference:

- the visual system is now strong enough that the remaining gaps are mostly about page curation, sequence, and dominance rather than raw styling quality

## 6. Page-by-page usability audit

### Overview dashboard

- purpose: command surface for current system pressure, trend, and immediate pivots
- primary persona: SOC analyst, admin, reviewer
- first `5-10s` question it should answer: `what is under pressure now, where is it, and what should I click next`
- evidence:
  - `../.artifacts/browser/live-audit/overview.png`
  - `frontend-react/src/shell/pages/DashboardPage.tsx`
  - `frontend-react/src/shell/DashboardCanvas.tsx`
- what works:
  - strong branded first impression
  - rich telemetry breadth
  - preserved multi-dashboard and geo patterns
- what hurts:
  - above-the-fold command story is weaker than the total amount of good content below
  - page is too long and visually assembled from several strong sections
  - secondary modules compete too early with the main pressure story
- what to change:
  - compress to a stronger first-screen command strip
  - demote secondary reference blocks
  - make primary timeline and pressure indicators more dominant
- scores:
  - visual quality: `8 / 10`
  - usability: `7 / 10`
  - scanability: `6 / 10`
  - operational efficiency: `7 / 10`
  - consistency: `8 / 10`
  - demo / selling impact: `8 / 10`

### Events

- purpose: dense investigation and search workspace over raw telemetry
- primary persona: analyst, detection engineer
- first `5-10s` question: `what am I looking at, how do I narrow it fast, and where is the evidence detail`
- evidence:
  - `../.artifacts/browser/live-audit/events.png`
  - `frontend-react/src/shell/pages/EventsPage.tsx`
- what works:
  - dense search and table treatment feels credible
  - good scanability for a data-heavy explorer
  - page feels like a working tool, not a demo-only screen
- what hurts:
  - it is still query-first before it is investigation-first
  - detail context is better than before but could still expose a clearer parsed evidence narrative
- what to change:
  - strengthen the drawer as a unified evidence narrative
  - make key pivots and adjacent context more visible on first interaction
- scores:
  - visual quality: `8 / 10`
  - usability: `8 / 10`
  - scanability: `8 / 10`
  - operational efficiency: `8 / 10`
  - consistency: `8 / 10`
  - demo / selling impact: `8 / 10`

### Incidents

- purpose: queue-first triage and workflow surface
- primary persona: incident responder, SOC lead
- first `5-10s` question: `what needs ownership now and what is the safest next action`
- evidence:
  - `../.artifacts/browser/live-audit/incidents.png`
  - `frontend-react/src/shell/pages/IncidentsPage.tsx`
- what works:
  - clear queue semantics
  - selected-row handling is materially better than table-only triage
  - toolbar is cleaner than a generic admin list
- what hurts:
  - ownership and next-step emphasis could still be stronger
  - workflow rail can be made more dominant for the active incident
- what to change:
  - strengthen ownership summary and action rail
  - surface SLA / queue pressure more explicitly where relevant
- scores:
  - visual quality: `8 / 10`
  - usability: `8 / 10`
  - scanability: `8 / 10`
  - operational efficiency: `8 / 10`
  - consistency: `8 / 10`
  - demo / selling impact: `8 / 10`

### Sources

- purpose: source register, freshness, integrations, and discovery onboarding
- primary persona: platform admin, engineer
- first `5-10s` question: `which sources are healthy, what can I onboard next, and what action is available`
- evidence:
  - `../.artifacts/browser/live-audit/sources.png`
  - `frontend-react/src/shell/pages/SourcesPage.tsx`
  - `docs/source_discovery.md`
- what works:
  - discovery remains a strong differentiator
  - families are more clearly separated than before
  - onboarding preview adds real operator value
- what hurts:
  - right-side context still depends too much on active selection
  - empty/default state guidance can be clearer when nothing is selected
- what to change:
  - improve default explanatory context in the right rail
  - make discovery recommendation hierarchy more obvious at first glance
- scores:
  - visual quality: `8 / 10`
  - usability: `8 / 10`
  - scanability: `8 / 10`
  - operational efficiency: `8 / 10`
  - consistency: `8 / 10`
  - demo / selling impact: `8 / 10`

### Vulnerability

- purpose: action-first exposure and maturity workspace
- primary persona: security engineer, admin, responder
- first `5-10s` question: `what needs attention right now and what can I remediate from here`
- evidence:
  - `../.artifacts/browser/live-audit/vuln.png`
  - `frontend-react/src/shell/pages/VulnPage.tsx`
  - `/api/vuln/maturity`
- what works:
  - top-of-page runtime and maturity treatment is clear
  - critical queue and exposure surfaces are operationally useful
- what hurts:
  - lower-page content becomes reference-heavy too early
  - page still reads as a stack of good sections rather than one tightly curated story
- what to change:
  - split action, inventory, and reference modes more clearly
  - move more reference material below or behind secondary views
- scores:
  - visual quality: `8 / 10`
  - usability: `7 / 10`
  - scanability: `7 / 10`
  - operational efficiency: `8 / 10`
  - consistency: `8 / 10`
  - demo / selling impact: `8 / 10`

### Builders

- purpose: graph-first detection and content engineering surface
- primary persona: detection engineer, platform engineer
- first `5-10s` question: `where is the graph, what state is the draft in, and how do I validate or publish`
- evidence:
  - `../.artifacts/browser/live-audit/builders.png`
  - `frontend-react/src/shell/pages/BuildersPage.tsx`
- what works:
  - graph-first identity is preserved
  - page still signals power-user capability
- what hurts:
  - cognitive load remains relatively high
  - state transitions between draft/config/validation/publish can still be clearer
- what to change:
  - further clarify mode boundaries and state transitions
  - reduce incidental visual competition around the graph core
- scores:
  - visual quality: `8 / 10`
  - usability: `7 / 10`
  - scanability: `7 / 10`
  - operational efficiency: `8 / 10`
  - consistency: `8 / 10`
  - demo / selling impact: `8 / 10`

### Access

- purpose: identity, governance, recovery, service-account, and secret workspace
- primary persona: administrator, security engineer
- first `5-10s` question: `which identity system is active, what is the current state, and what risky action is available`
- evidence:
  - `../.artifacts/browser/live-audit/access-users.png`
  - `../.artifacts/browser/live-audit/access-clients.png`
  - `frontend-react/src/shell/pages/access/AccessWorkspace.tsx`
- what works:
  - strongest admin/control surface in the product
  - tab model is clear and enterprise-like
  - separation between Keycloak identities, break-glass users, and service accounts is explicit
- what hurts:
  - breadth of scope means more secondary help text may be useful for less frequent operators
- what to change:
  - add more contextual help for rare governance tasks if operator population expands
- scores:
  - visual quality: `9 / 10`
  - usability: `8 / 10`
  - scanability: `8 / 10`
  - operational efficiency: `9 / 10`
  - consistency: `9 / 10`
  - demo / selling impact: `9 / 10`

### Entities / Assets / Threat Intel

- purpose: investigative context around subjects, infrastructure, and intel artifacts
- primary persona: analyst, responder
- first `5-10s` question: `what is this object, what evidence belongs to it, and what should I pivot to next`
- evidence:
  - `../.artifacts/browser/live-audit/entities.png`
  - `../.artifacts/browser/live-audit/assets.png`
  - `../.artifacts/browser/live-audit/threat-intel.png`
  - corresponding page modules under `frontend-react/src/shell/pages/`
- what works:
  - shell consistency is good
  - pages now feel related rather than completely separate visual worlds
- what hurts:
  - investigation model is still conceptually fragmented
  - shared evidence timeline pattern is not yet dominant enough
- what to change:
  - unify detail drawer and evidence timeline patterns
  - make cross-pivots feel like one investigation system
- scores:
  - visual quality: `8 / 10`
  - usability: `7 / 10`
  - scanability: `7 / 10`
  - operational efficiency: `7 / 10`
  - consistency: `8 / 10`
  - demo / selling impact: `7 / 10`

### Cases / Connectors / Control surfaces

Direct fact:

- routes exist for cases and admin/control-family pages in the shell

Cannot verify from current evidence:

- high-confidence live visual quality for `Cases`, `Connectors`, and `Control Panel`, because this audit did not capture those routes in the live browser artifact set

Recommendation:

- expand the next live browser audit set to include those pages so the admin/control family can be scored as a whole

## 7. Chart / graph / diagram audit

| Module | Question it answers | Keep / move / resize / replace | Evidence | Scores |
| --- | --- | --- | --- | --- |
| Overview main timelines | what pressure and trend changed over time | keep, make more dominant | `DashboardCanvas.tsx`, `overview.png` | relevance `9`, clarity `8`, placement `8`, interpretability `8`, actionability `9`, visual quality `8` |
| Severity and status ring modules | what is the severity / state distribution right now | keep, refine direct labeling and hover states | `charts.tsx`, `overview.png` | relevance `8`, clarity `7`, placement `8`, interpretability `7`, actionability `7`, visual quality `8` |
| Top source breakdown bars | which sources dominate current activity or issues | keep | `DashboardCanvas.tsx`, `overview.png` | relevance `8`, clarity `8`, placement `8`, interpretability `8`, actionability `8`, visual quality `7` |
| Geo source map | where the issue or source pressure is concentrated | keep, resize and synchronize more tightly with companion table | `charts.tsx`, `overview.png` | relevance `8`, clarity `7`, placement `7`, interpretability `7`, actionability `7`, visual quality `8` |
| Geo VPN / destination map | where important destination context exists | keep, subordinate to the main command story | `overview.png` | relevance `8`, clarity `7`, placement `7`, interpretability `7`, actionability `7`, visual quality `8` |
| Vulnerability exposure tables | what exposure needs action now | keep | `VulnPage.tsx`, `vuln.png` | relevance `9`, clarity `8`, placement `8`, interpretability `8`, actionability `9`, visual quality `7` |
| Event histogram / stats | how event volume behaves over the current search slice | keep | `EventsPage.tsx`, `events.png` | relevance `8`, clarity `8`, placement `8`, interpretability `8`, actionability `8`, visual quality `7` |

### Charting conclusions

Direct fact:

- charts are wrapped consistently through shared helpers
- the product preserved maps, rings, bars, and timelines rather than collapsing into table-only admin UI

Evidence:

- `frontend-react/src/shell/charts.tsx`
- `frontend-react/src/shell/DashboardCanvas.tsx`
- live screenshots in `../.artifacts/browser/live-audit/`

Strong inference:

- the next maturity jump is not about adding more chart types; it is about making the existing chart family feel more distinctly product-owned with better direct labeling, clearer unit framing, and tighter sync with adjacent tables and drawers

## 8. Design-system maturity assessment

### What already works

- semantic layout primitives exist in `frontend-react/src/shell/surfaces.tsx`
- metric strips, headers, badges, drawers, info lists, and section containers are shared rather than page-local hacks
- CSS is layered instead of growing as one file
- brand assets are emitted through the normal build pipeline

### What remains weak

- `legacy.css` is still imported, which means the compatibility layer has not fully retired
- there is no Storybook, token catalog, or design-system docs site
- some page modules remain large and still mix composition, data logic, and copy

Evidence:

- `frontend-react/src/styles.css`
- `frontend-react/src/shell/surfaces.tsx`
- `frontend-react/build.cjs`
- no Storybook configuration under `frontend-react/`

Assessment:

- design-system maturity: `7 / 10`

## 9. Responsiveness and layout stability risks

Direct fact from live browser verification:

- no horizontal overflow was observed at `1280x800` on:
  - `/app`
  - `/app/events`
  - `/app/sources`
  - `/app/vuln`
  - `/app/access?tab=keycloak-users`
- no horizontal overflow was observed at `1024x768` on:
  - `/app/events`
  - `/app/sources`
  - `/app/access?tab=keycloak-users`

Evidence:

- `../.artifacts/browser/live-audit/results.json`

Strong inference:

- the main residual responsiveness risk is vertical overload rather than horizontal breakage

Direct fact:

- `Overview` live scroll height is about `7493px`
- `Vulnerability` live scroll height is about `4016px`

Evidence:

- `../.artifacts/browser/live-audit/results.json`

Conclusion:

- layout stability is materially better than before
- the next refinement should target vertical curation and progressive disclosure, not emergency responsive fixes

## 10. Accessibility risks

What is positive:

- a skip link exists
- keyboard shortcuts are implemented in the shell
- shared key-value and info-table structures use consistent primitives

Evidence:

- `frontend-react/src/shell/App.tsx`
- `frontend-react/src/shell/surfaces.tsx`

Risks:

- chart accessibility remains limited
- many state cues still rely on color first
- full keyboard parity was not verified route by route in this pass
- there is no explicit accessibility test suite in CI

Assessment:

- accessibility maturity: `6.5 / 10`

## 11. Performance risks that affect UX

Direct fact:

- `AccessWorkspace` polls several independent sources on a timer
- the shell bootstrap in `App.tsx` owns platform-level polling and refresh behavior

Evidence:

- `frontend-react/src/shell/pages/access/AccessWorkspace.tsx`
- `frontend-react/src/shell/App.tsx`

Strong inference:

- this is acceptable for the current stand, but the next scale step should reduce polling fan-out or make polling visibility-aware on inactive tabs

Direct fact:

- no browser console noise was observed in the live audit
- all captured pages rendered successfully under real data

Evidence:

- `../.artifacts/browser/live-audit/results.json`

## 12. Top 20 problems ranked by severity

1. `Overview` is too long and assembled for a first-screen command surface.
2. Investigation context is still fragmented across `Events`, `Entities`, `Assets`, and `Threat Intel`.
3. `frontend-react/src/shell/App.tsx` remains a large shell hotspot.
4. `frontend-react/src/styles.css` still imports `legacy.css`.
5. There is no Storybook or visual regression framework.
6. `Sources` depends too much on selection for right-side context.
7. `Vulnerability` becomes reference-heavy too early.
8. The multi-dashboard identity is not yet expressed strongly enough in the live shell narrative.
9. The chart language is improved but still visibly library-derived.
10. `Access` is strong, but the broader admin/control family is not yet equally unified.
11. There is no high-confidence bilingual live verification for every flagship route.
12. `Cases`, `Connectors`, and `Control Panel` were not included in the live visual capture set.
13. There is no screen-reader evidence.
14. Dense-table keyboard workflows are not fully evidenced route by route.
15. Vertical page length still creates cognitive load on the longest surfaces.
16. UI test coverage exists, but the strongest explicit route-level evidence still favors `Access`, `Incidents`, `Sources`, and `Vulnerability`.
17. Live overview connector inventory still includes a Greenbone connector runtime error state, even though the page remains usable.
18. There is no UI-specific ADR, token documentation artifact, or visual-spec reference.
19. Chart accessibility and non-color semantic reinforcement remain limited.
20. Polling behavior on admin-heavy surfaces will need visibility-aware throttling as the stand grows.

## 13. Top 20 improvements ranked by impact

1. Re-curate `Overview` into a stronger above-the-fold command surface.
2. Build one shared investigation drawer and evidence timeline across `Events`, `Entities`, `Assets`, and `Threat Intel`.
3. Add Storybook plus screenshot diff coverage.
4. Split `App.tsx` further.
5. Reduce and eventually retire `legacy.css`.
6. Improve default right-rail guidance in `Sources`.
7. Split `Vulnerability` into clearer action, inventory, and reference modes.
8. Improve direct labels and semantic emphasis in ring modules.
9. Make the multi-dashboard model more explicit in the shell and dashboard framing.
10. Add visibility-aware polling budgets.
11. Expand live browser verification to `Cases`, `Connectors`, and `Control Panel`.
12. Run a full bilingual live UI pass.
13. Add an explicit accessibility pass and test coverage.
14. Add stronger table-state controls where helpful.
15. Promote binding-remediation quick actions deeper into vuln and source queues.
16. Add an executive / readiness dashboard family if demo value matters.
17. Add a design-system documentation artifact.
18. Tighten chart guidance around units, direct labels, and contextual actions.
19. Normalize the rest of the admin/control family to the same quality bar as `Access`.
20. Add CI checks for documented-vs-live UI conformance drift.

## 14. P0 / P1 / P2 roadmap

### P0

- redesign `Overview` hierarchy around one dominant command story
- unify the investigation detail model across `Events`, `Entities`, `Assets`, and `Threat Intel`
- extend live browser evidence to `Cases`, `Connectors`, and `Control Panel`

### P1

- add Storybook and visual regression coverage
- continue shell decomposition beyond `App.tsx`
- refine `Vulnerability` and `Sources` information hierarchy

### P2

- expand dashboard families where demo or operator needs justify it
- add deeper accessibility and i18n validation
- add a design-system ADR or visual-spec artifact

## 15. What to redesign first

1. `Overview`
2. shared investigation model
3. `Vulnerability`
4. `Sources`

## 16. What already works well

- the shell now has a real product identity
- `Access` is a convincing enterprise governance workspace
- `Events`, `Incidents`, and `Sources` feel like serious operational tools
- typography and color direction are credible and product-grade
- no obvious layout instability was observed in the live browser pass
- the live `/app/*` routes rendered without console noise in the captured audit set
- the product is much stronger as a diploma and portfolio artifact than a generic SOC dashboard clone

## 17. Missing artifacts that prevent a higher-confidence visual audit

- Storybook or a component catalog
- visual regression snapshots in CI
- explicit design-system ADR or token documentation
- full live capture for `Cases`, `Connectors`, and `Control Panel`
- assistive-technology audit evidence
- product analytics or operator session recordings

## 18. Final verdict

Scores:

- visual quality: `8.3 / 10`
- usability: `7.8 / 10`
- operational efficiency: `8.1 / 10`
- data visualization quality: `7.6 / 10`
- consistency: `7.9 / 10`
- project / documentation conformance: `7.8 / 10`
- demo / selling readiness: `8.6 / 10`
- scalability of the UI architecture: `7.4 / 10`

Final verdict:

- this is now a strong selling element for the project rather than a weak support layer
- the product looks serious, modern, and operationally credible
- it is good enough to impress a diploma reviewer, recruiter, technically literate customer, or security lead
- it is not yet the final word in dashboard curation, investigation cohesion, or design-system maturity
- the remaining work is refinement and productization follow-up, not rescue
