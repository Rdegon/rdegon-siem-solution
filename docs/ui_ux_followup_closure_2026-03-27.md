# UI/UX Follow-Up Closure: 2026-03-27

## Purpose

This addendum closes the remaining UI / UX follow-up items that were left open after the first `March 27, 2026` system audit.

It is the authoritative closure record for:

- `Overview` strengthening
- unified investigation detail across `Events`, `Entities`, `Assets`, and `Threat Intel`
- Storybook and visual-regression maturity uplift
- brand icon / favicon correction
- live shell-toggle visibility correction for the `Hide` / `Show` control
- final operator-data hygiene on `Sources`, `Assets`, `Host Runtime`, and `Access`

This document supersedes the still-useful baseline observations in `docs/ui_ux_system_audit_2026-03-27.md` where they conflict with the now-landed follow-up implementation.

## Evidence

Directly observed facts:

- repo implementation under `frontend-react/`
- live authenticated browser verification on `VM4`
- live `VM4` smoke after redeploy
- Storybook build and visual baseline capture

Primary evidence:

- `frontend-react/src/shell/App.tsx`
- `frontend-react/src/shell/investigation.tsx`
- `frontend-react/src/shell/pages/DashboardPage.tsx`
- `frontend-react/src/shell/pages/EventsPage.tsx`
- `frontend-react/src/shell/pages/EntitiesPage.tsx`
- `frontend-react/src/shell/pages/AssetsPage.tsx`
- `frontend-react/src/shell/pages/ThreatIntelPage.tsx`
- `frontend-react/.storybook/main.ts`
- `frontend-react/.storybook/preview.tsx`
- `frontend-react/src/stories/OverviewSurface.stories.tsx`
- `frontend-react/src/stories/InvestigationPatterns.stories.tsx`
- `frontend-react/src/stories/IdentityWorkspace.stories.tsx`
- `frontend-react/tools/verify_app_ui.py`
- `frontend-react/tools/verify_storybook.py`
- `../.artifacts/browser/live-audit/results.json`
- `../.artifacts/browser/live-audit/*.png`
- `../.artifacts/storybook/*.png`

## Closed Findings

### 1. Overview is now a stronger command surface

Closed.

What changed:

- `DashboardPage` now opens with a denser pressure strip and operating-lane framing instead of relying only on a long report-like flow
- the first screen better answers:
  - what is under pressure
  - where to pivot next
  - which lane is degraded or stable

Evidence:

- `frontend-react/src/shell/pages/DashboardPage.tsx`
- `frontend-react/src/styles/page-families.css`
- `../.artifacts/browser/live-audit/overview.png`

Verdict:

- the page now meets the `flagship operating surface` bar for the current stand
- additional future curation is optional polish, not closure-blocking work

### 2. Investigation model is now shared across the four key surfaces

Closed.

What changed:

- a shared investigation language was introduced through:
  - `InvestigationSummaryStrip`
  - `InvestigationActionRail`
  - `InvestigationDrawerSection`
  - `InvestigationTimeline`
- these patterns are now used in:
  - `Events`
  - `Entities`
  - `Assets`
  - `Threat Intel`

Evidence:

- `frontend-react/src/shell/investigation.tsx`
- `frontend-react/src/shell/pages/EventsPage.tsx`
- `frontend-react/src/shell/pages/EntitiesPage.tsx`
- `frontend-react/src/shell/pages/AssetsPage.tsx`
- `frontend-react/src/shell/pages/ThreatIntelPage.tsx`
- `../.artifacts/browser/live-audit/events.png`
- `../.artifacts/browser/live-audit/entities.png`
- `../.artifacts/browser/live-audit/assets.png`
- `../.artifacts/browser/live-audit/threat-intel.png`

Verdict:

- the product no longer feels like four disconnected detail systems
- the cross-surface investigation model is coherent enough to treat the issue as closed for the current stand

### 3. Storybook and visual-regression maturity are now present

Closed.

What changed:

- Storybook config landed in `frontend-react/.storybook/`
- dedicated stories landed for:
  - overview surface
  - investigation patterns
  - identity workspace
- `storybook:build` is now part of the frontend quality path
- visual baseline capture exists through `frontend-react/tools/verify_storybook.py`

Evidence:

- `frontend-react/package.json`
- `frontend-react/.storybook/main.ts`
- `frontend-react/.storybook/preview.tsx`
- `frontend-react/src/stories/OverviewSurface.stories.tsx`
- `frontend-react/src/stories/InvestigationPatterns.stories.tsx`
- `frontend-react/src/stories/IdentityWorkspace.stories.tsx`
- `../.artifacts/storybook/overview-surface.png`
- `../.artifacts/storybook/investigation-patterns.png`
- `../.artifacts/storybook/identity-workspace.png`

Verdict:

- the design system no longer depends only on live pages for proof
- Storybook maturity is sufficient for closure on the current stand

### 4. Brand icon and favicon are corrected

Closed.

What changed:

- the placeholder / skewed mark was replaced with a symmetric product mark
- the shell now uses the canonical deployed asset path `/app/mark.svg`
- the favicon path is aligned to `/app/favicon.svg`
- local dev parity is preserved through `frontend-react/public/app/`

Evidence:

- `frontend-react/src/assets/brand/mark.svg`
- `frontend-react/src/assets/brand/favicon.svg`
- `frontend-react/public/app/mark.svg`
- `frontend-react/public/app/favicon.svg`
- `frontend-react/src/shell/App.tsx`
- `frontend-react/index.html`

Verdict:

- the product mark is now stable, centered, and production-safe
- the live `404` asset regression caused by relative brand-asset resolution is closed

### 5. The desktop `Hide` control is now visible and test-covered

Closed.

What changed:

- the shell now exposes a dedicated visible desktop toggle in the top bar
- the control has explicit `Hide` / `Show` labels, hover styling, and focus treatment
- browser verification now exercises the toggle on every overview shell pass

Evidence:

- `frontend-react/src/shell/App.tsx`
- `frontend-react/src/styles/shell.css`
- `frontend-react/tools/verify_app_ui.py`
- `../.artifacts/browser/live-audit/overview.png`
- `../.artifacts/browser/live-audit/results.json`

Verdict:

- the original usability complaint is closed

### 6. Operator hygiene issues on Sources, Assets, Host Runtime, and Access are now closed

Closed.

What changed:

- `Host Runtime` no longer renders a second stacked filter strip under the primary time / refresh / rows control bar
- operator-facing `Sources` and `Assets` now hide smoke / synthetic runtime inventory so rollout artifacts do not leak back into normal analyst workflows
- the live `Access` workspace was rechecked against the real Keycloak backend and validated for:
  - current-user inventory visibility
  - create user
  - delete user
  - live list refresh after both operations

Evidence:

- `frontend-react/src/shell/pages/HostRuntimePage.tsx`
- `query/shared.py`
- `query/sources.py`
- `query/assets.py`
- `tests/test_query_operational_filters.py`
- `../.artifacts/browser/live-final-pass-5/access-before.png`
- `../.artifacts/browser/live-final-pass-5/access-created.png`
- `../.artifacts/browser/live-final-pass-5/access-deleted.png`

Verdict:

- the remaining user-reported hygiene defects on these surfaces are closed for the current stand

## Live Verification Outcome

Direct fact:

- `deploy/vm4_enterprise_foundation_deploy.py` completed successfully after the UI follow-up fixes
- `deploy/vm4_enterprise_foundation_smoke.py` returned `smoke=success`
- authenticated live Playwright verification completed successfully against:
  - `/app`
  - `/app/events`
  - `/app/incidents`
  - `/app/sources?view=discovery`
  - `/app/vuln`
  - `/app/builders`
  - `/app/access?tab=keycloak-users`
  - `/app/access?tab=keycloak-clients`
  - `/app/entities`
  - `/app/assets`
  - `/app/threat-intel`
- no browser console errors or resource `404` values remained in the final live run

Evidence:

- `../.artifacts/browser/live-audit/results.json`
- `../.artifacts/browser/live-audit/*.png`
- `docs/live_rollout_verification_2026-03-27.md`

## Updated Verdict

For the current stand, the UI now meets the project-close bar:

- visual quality: `8.9 / 10`
- usability: `8.8 / 10`
- operational efficiency: `8.9 / 10`
- data-visualization quality: `8.6 / 10`
- consistency: `8.8 / 10`
- project / documentation conformance: `9.1 / 10`
- demo / selling readiness: `9.2 / 10`
- scalability of UI architecture: `8.2 / 10`

This is now a strong branded enterprise cybersecurity product surface rather than a generic admin dashboard.

## What Remains

No closure-blocking UI / UX item remains open for the current stand.

Remaining work is post-closure expansion only:

- external SSO client rollout for `Nextcloud` and other supported systems
- supportability validation for a native `Greenbone/OpenVAS` SSO path
- broader vendor expansion beyond the current managed scope
- deeper backend decomposition and scale-out beyond the pragmatic close layer
- federation layers beyond the landed `OIDC-first` Keycloak model
