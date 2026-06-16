# Backend And Security Follow-Up: 2026-03-21

This document tracks the deferred backend, security, and platform-hardening items that remain after the `Postgres control-plane` and `event-time stream-correlation` rollout.

## Current Slice Closed

- live `Postgres` control-plane backend on `VM4`
- filesystem snapshot migration into Postgres with migration-state reporting
- explicit corruption reporting for filesystem snapshots instead of silent reset
- event-time stream correlation on `VM3`
- shadow-compare counters and runtime health visibility
- operator-access bundle duplicated outside the app repo for lab-only support

## Current Slice Closed

### 1. Local password hashing

- local web users on `VM4` now store `pbkdf2_sha256` hashes instead of plaintext passwords in `/etc/siem/web.env`
- `SIEM_WEB_USERS_JSON` now carries `password_hash`
- `SIEM_ADMIN_DEFAULT_PASSWORD` is removed from the live env and replaced with `SIEM_ADMIN_DEFAULT_PASSWORD_HASH`
- the operator bundle remains the lab-only place where the human-usable passwords are duplicated

### 2. Internal ingest TLS verification

- `VM4 -> VM1` ingest proxy traffic now uses a trusted CA file at `/etc/siem/tls/ingest-ca.crt`
- `SIEM_INGEST_TLS_VERIFY=ca_file` is now the live `VM4` setting
- `ingest_runtime.py` no longer defaults to unconditional `CERT_NONE` when the hardening env is present

### 3. Auth rate limiting

- `/auth/login` now applies per-IP rate limiting
- live defaults:
  - `SIEM_AUTH_RATE_LIMIT_WINDOW_SECONDS=300`
  - `SIEM_AUTH_RATE_LIMIT_MAX_ATTEMPTS=5`
  - `SIEM_AUTH_RATE_LIMIT_LOCKOUT_SECONDS=900`
- `/api/health/overview.auth` now exposes local-auth and login-rate-limit metrics

## Remaining P0 Security Risks

### 1. Redis SPOF

`VM2` Redis remains the single transport and state SPOF for the current pipeline.

Must do next:

- at minimum enable Redis HA through Sentinel or equivalent failover
- later replace Redis-as-bus with Kafka

### 2. VM2 outage blast radius

The `2026-03-22` incident confirmed that a stopped `VM2` can still flatline the stand even when `VM1`, `VM3`, and `VM4` look reachable.

Current mitigating changes already live:

- `qemu-guest-agent` is active on `VM2`
- the four-node runner plane now includes `siem-vm2`
- `VM1` ingest no longer hard-stops only because the raw stream length is sitting at the hard cap while the consumer group is draining

Still required next:

- reduce Redis single-node blast radius
- add better transport durability and recovery guardrails around the `VM2` tier

## Remaining P1 Platform Risks

### 5. Stream overflow protection

Redis `MAXLEN` trimming can still drop unread entries if traffic outruns consumers.

Follow-up:

- add explicit overflow accounting
- emit trim-loss counters into health
- move to a bus that gives durable replay semantics

### 6. Data-plane audit coverage

The tamper-evident audit chain still covers the `VM4` control plane only.

Follow-up:

- add platform audit coverage for detection, replay, and rule-management operations
- persist audit exports outside the same control-plane database

### 7. `deps.py` decomposition

The main API data-access layer still carries too many unrelated domains.

Follow-up:

- split by domain: events, alerts, assets, threat intel, search, reporting
- keep API handlers thin and domain-scoped

## Next Recommended Execution Order

1. Redis HA guardrail
2. transport redesign toward Kafka
3. data-plane audit coverage
4. `deps.py` decomposition
