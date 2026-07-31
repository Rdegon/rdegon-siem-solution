# Rdegon Sentinel UI

This directory contains the production Sentinel workspace. The previous
frontend shell is not part of the build.

## Runtime contract

- `src/sentinel/App.tsx` owns navigation, tenant scope, theme and session bootstrap.
- `src/sentinel/Views.tsx` renders the operational workspaces and editors.
- `src/sentinel/runtime/api.ts` is the typed contract with the existing SIEM API.
- UI tables, counters, incidents, events, assets and security controls use API
  responses. The production build does not provide demo or fallback records.
- Mutations remain protected by the backend RBAC and audit pipeline.

## Quality gates

```powershell
npm run typecheck
npm run lint
npm test -- --run
npm run build
npm audit --omit=dev
```

The static build is written to `dist` and is served by the SIEM Web nginx
entry point under `/app`.
