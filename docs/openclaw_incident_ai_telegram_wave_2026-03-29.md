# OpenClaw Incident AI And Telegram Wave 2026-03-29

## Summary

This wave closes the incident-analysis loop for OpenClaw-backed alerts:

1. SIEM incidents now expose a dedicated `AI assessment` panel driven by OpenClaw
2. the Telegram incident bot can request AI analysis, switch chat-local time, and run safe host actions
3. aggregated incidents now carry real event counts and stable IDs instead of empty `Events: 0`
4. source coverage rules were expanded and republished live for pilot services, OpenClaw, Windows and BSD/Linux coverage gaps
5. the final live state is green after DLQ remediation, `VM4` redeploy, browser verification, and new desktop screenshots

This wave is only considered complete when these conditions are true together:

- `VM4` is redeployed and `deploy/vm4_enterprise_foundation_smoke.py` returns `success`
- the Telegram bot on `pilot-db-01` is active
- OpenClaw AI assessment reaches `ready` for live incidents
- host actions run through the mapped Proxmox guest path
- browser verification of `/app/incidents` is clean

## Incident AI Flow

Primary routes:

- `/api/incident-ops/{view}/{record_id}/ai`
- `/api/incident-ops/{view}/{record_id}/ai/generate`
- `/api/incident-ops/{view}/{record_id}/host-action`
- `/app/incidents`

The live flow is now:

1. operator or Telegram bot requests AI analysis for an incident
2. SIEM builds a structured incident bundle with counts, source context, asset context, and host mapping
3. the bundle is handed to OpenClaw through the configured guest-exec bridge
4. OpenClaw can use:
   - local investigation context
   - `web_search`
   - `web_fetch`
   - browser-backed lookup paths
   through the OpenClaw runtime, not only through a single browser path
5. the result is normalized into a stable JSON assessment and stored in the incident-AI runtime cache
6. the incident drawer shows score, confidence, recommended status, assignee hint, recommended actions, search findings, and safe machine actions

## Root Causes Fixed In This Wave

### Empty incident counts

Aggregated incident rows previously missed stable operator fields, which caused downstream consumers to behave as if incidents had no useful event count.

The aggregated incident payload now carries:

- `record_id`
- `title`
- `count_events`

This fixes the visible `Events: 0` style gap for aggregated incidents.

### Broken host-action mapping

The incident-AI host mapper assumed Proxmox fleet inventory always arrived as a list. In live runtime it may also arrive as a payload shaped like:

- `{ "items": [...] }`

The inventory index now supports both shapes, which restores host mapping for OpenClaw and other fleet-backed incidents.

### Broken OpenClaw command execution

The original remote execution path embedded Python inline in a way that caused syntax errors on the target host. The active runtime now uses a heredoc-based Python execution path and correctly parses both:

- `messages[]`
- `payloads[].text`

from OpenClaw JSON output.

## Telegram Bot Changes

Host:

- `pilot-db-01`

Service:

- `incident-telegram-bot.service`

The bot now supports:

- incident notification to the configured chat
- `Перейти в SIEM`
- `AI-разбор`
- `В работу`
- `Закрыть`
- `Снимок хоста`
- `Освежить телеметрию`
- chat-local timezone switching:
  - `UTC`
  - `UTC+3` / `Europe/Moscow`

Current behavior:

- taking an incident `В работу` updates incident status and assignee in SIEM
- `Закрыть` closes the incident from Telegram
- AI follow-up posts a second message with the structured OpenClaw assessment
- host actions call the live SIEM incident-ops API and return the result to Telegram

## OpenClaw Search And Internet Context

OpenClaw incident analysis is not limited to a single browser-based lookup path.

The live prompt and runtime path explicitly allow OpenClaw to use:

- `web_search`
- `web_fetch`
- browser-backed lookups when needed

The goal is to let AI analysis enrich suspicious domains, services, IPs, and error patterns from multiple external search paths, while still grounding the result in local SIEM evidence first.

## Rule Coverage Expansion

`source_coverage_v1.json` was expanded and republished live.

Notable additions in this wave:

- PostgreSQL authentication failure burst
- Valkey persistence or restart burst
- SIEM web / Keycloak authentication degradation
- generic source telemetry stall
- Windows or BSD guest coverage gap

Live publish result on `VM4`:

- total published rules: `58`
- `source-coverage-v1` published rules: `10`

## Humanization And Operator Readability

The runtime humanization layer was refreshed so investigation surfaces can render friendlier labels for:

- pilot services
- SIEM nodes
- OpenClaw
- common auth / audit / SSH tokens
- raw source names and aliases

This does not fully remove every raw technical value from legacy data, but it materially improves incident readability in live operator flows.

## Live Verification

Local verification:

- `python -m py_compile incident_ai_runtime.py runtime_humanization.py services/incident_telegram_bot.py alerts.py deps.py proxmox_guest_ops.py`
- `pytest tests/test_incident_ai_runtime.py tests/test_incident_telegram_bot.py`
- `frontend-react`: `typecheck`, `build`

Live verification:

- `deploy/vm4_enterprise_foundation_deploy.py` -> `deployment=success`
- `deploy/vm4_enterprise_foundation_smoke.py` -> `smoke=success`
- `deploy/pilot_db_incident_bot_smoke.py` -> `healthy=true`
- `incident-telegram-bot.service` -> `active`
- `/api/health/overview` -> `issues=[]`
- `/api/incidents?view=agg&window=24h` returns non-zero `count_events`
- OpenClaw AI assessment for `asset:openclaw-gateway|campaign:linux_dns_query` reaches `ready`
- host actions for the same incident return `200`
- browser console errors on the final incidents pass -> `0`

## Screenshots

Fresh desktop screenshots from this wave live in:

- `.artifacts/browser/openclaw-incident-ai-2026-03-29/`

Primary files:

- `incident-ai-drawer-1920.png`
- `incident-ai-assessment-1920.png`

## Operational Notes

- AI analysis remains advisory. It suggests status and assignee, but the actual incident workflow remains operator-controlled.
- Local incident state such as `open` and `unassigned` is expected until an analyst or Telegram action changes it.
- Host actions remain deliberately narrow in this wave:
  - `snapshot`
  - `refresh_telemetry`

These are safe operational actions and do not yet perform SOAR-grade containment or destructive remediation.
