# Builders, Access, Humanization, And Incident Bot Wave 2026-03-29

## Summary

This wave closes four operator-facing gaps together:

1. `Builders` is rebuilt into a window-first workspace instead of a crowded flat page
2. `Access` reduces identity noise and exposes cleaner human summaries
3. investigation surfaces gain an alias / humanization layer for raw technical values
4. `pilot-db-01` now runs a Telegram incident bot that delivers incidents through the OpenClaw VLESS egress path

The wave is only considered complete when these are all true:

- `VM4` frontend and API are redeployed
- live browser verification of `/app/*` is green
- the Telegram bot is live on `pilot-db-01`
- incident delivery to Telegram is confirmed

## Builders

`Builders` no longer behaves like a large stacked dashboard. The current operator flow is window-first:

- overview cards open focused drawers
- flow topology opens in its own side window
- block editing opens in a dedicated block window
- correlation packs, rules, validation, test, and publish each have their own execution window

The intent is to keep one active task in view at a time, rather than forcing the operator to scan the whole page for every action.

Primary route:

- `/app/builders`

Correlation route:

- `/app/builders?workspace=correlation`

## Access And Humanization

The `Access` workspace now emphasizes:

- shorter user summaries
- cleaner grant grouping
- less raw identity noise in cards and drawers

The new humanization layer maps raw values into operator-readable aliases across investigation surfaces. It is consumed by:

- `Events`
- `Assets`
- `Entities`
- `Access`

Examples:

- raw pilot host IPs now render as named pilot services
- `vuln-siem` now renders as `navidrome-01`
- raw event tokens such as `USER_LOGIN` and `SSH_LOGIN_FAILURE` are converted into readable labels
- embedded IP values inside JSON-like strings are extracted and humanized where possible

## Telegram Incident Bot

Host:

- `pilot-db-01`

Service:

- `incident-telegram-bot.service`

Purpose:

- poll SIEM incidents through a service-account token
- store delivery state in PostgreSQL
- send incident notifications to Telegram
- include direct link back into the SIEM incident view

Runtime path:

- Telegram traffic uses the OpenClaw VLESS client as an HTTP proxy
- proxy front: `http://192.168.1.126:10809`

Key files:

- `services/incident_telegram_bot.py`
- `deploy/common/incident-telegram-bot.service`
- `deploy/pilot_db_incident_bot_deploy.py`
- `deploy/pilot_db_incident_bot_smoke.py`

Important deployment note:

- `SIEM_TELEGRAM_CHAT_ID` is now required explicitly during deploy
- the deploy script no longer carries a user-specific default chat id

## Verification

Local:

- `python -m py_compile services/incident_telegram_bot.py deploy/pilot_db_incident_bot_deploy.py deploy/pilot_db_incident_bot_smoke.py deploy/vm4_enterprise_foundation_deploy.py`
- `frontend-react`: `typecheck`, `lint`, targeted `vitest`, `build`

Live:

- `deploy/pilot_db_incident_bot_smoke.py` -> `success`
- `deploy/vm4_enterprise_foundation_smoke.py` -> `success`
- `incident-telegram-bot.service` -> `active`
- PostgreSQL delivery state contains `telegram.status=sent`
- browser console errors on the final UI pass -> `0`

## Screenshots

Fresh desktop screenshots from this wave live in:

- `.artifacts/browser/one-pass-builders-access-bot-2026-03-29/`

Primary files:

- `builders-correlation-window-1920.png`
- `access-user-window-1920.png`
- `events-humanized-1920.png`
- `assets-humanized-1920.png`
