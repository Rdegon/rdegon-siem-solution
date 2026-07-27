# Network dependency recovery, 2026-07-27

## Scope

This recovery removes two stale dependencies left after the move from
`192.168.1.0/24` to the segmented `10.20.0.0/16` service networks:

- Navidrome OAuth2 Proxy no longer uses the old Keycloak address.
- The incident Telegram bot no longer depends on `openclaw-gateway`.

## Keycloak paths

The public OIDC issuer remains `https://192.168.3.102/realms/siem`, because
browser redirects must use the router address available to users. Server-side
token redemption and JWKS retrieval use `https://10.20.10.107`, so internal
service communication does not depend on hairpin NAT.

Navidrome OAuth2 Proxy uses explicit OIDC endpoints with discovery disabled.
Its CA file is synchronized from the current SIEM Web certificate.

## Telegram egress

`pilot-db-01` runs `siem-telegram-egress.service` before the incident bot. The
oneshot resolver probes Telegram API endpoints with TLS hostname validation and
writes only the reachable address into a marked `/etc/hosts` entry. The bot
connects directly and does not use the retired OpenClaw VLESS proxy.

The following artifacts own this behavior:

- `deploy/common/telegram_egress_resolver.py`
- `deploy/common/siem-telegram-egress.service`
- `deploy/common/incident-telegram-bot.service`
- `deploy/pilot_db_incident_bot_deploy.py`

## Verified runtime state

- `navidrome-oauth2-proxy.service`: active, public login redirect is correct.
- `siem-telegram-egress.service`: active.
- `incident-telegram-bot.service`: active and delivering incidents.
- VM126 `openclaw-gateway`: stopped, `onboot=0`.
