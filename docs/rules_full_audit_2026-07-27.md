# Full Rule Audit

- Generated: 2026-07-27T08:02:23Z
- Lookback days: 30
- Live metrics: True
- Total rules: 601
- All rules have decision: True
- All runtime rules have decision: True
- Normalized provider/type pairs: 294

## Decisions

- deduplicate: 13
- keep: 381
- narrow_condition: 182
- scope_asset_group: 20
- tune_threshold: 5

## Runtime Inventory

- stream: 450 total, 444 enabled, 6 disabled
- batch: 137 total, 135 enabled, 2 disabled
- catalog: 582 total, 574 enabled, 8 disabled
- normalizer: 1 total, 1 enabled, 0 disabled
- filter: 16 total, 16 enabled, 0 disabled

## Rules

| rule_id | source_id | layer | severity | cost | alerts | fp | open | decision | title |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | --- | --- |
| 4101 | 4101 | batch | high | low | 0 | 0 | 0 | narrow_condition | Host Telemetry Missing Daily Review |
| 4102 | 4102 | batch | medium | low | 0 | 0 | 0 | narrow_condition | Host Service Flapping Trend Review |
| 4103 | 4103 | batch | high | low | 0 | 0 | 0 | narrow_condition | Storage Node Pressure Trend Review |
| 4104 | 4104 | batch | medium | low | 0 | 0 | 0 | narrow_condition | Control Plane Runtime Trend Review |
| 4201 | 4201 | batch | medium | low | 0 | 0 | 0 | narrow_condition | Fleet Telemetry Coverage Review |
| 4301 | 4301 | batch | medium | low | 0 | 0 | 0 | narrow_condition | OpenClaw New-Destination Review |
| 4401 | 4401 | batch | medium | low | 0 | 0 | 0 | narrow_condition | Fleet Scan Freshness Review |
| 4402 | 4402 | batch | medium | low | 0 | 0 | 0 | narrow_condition | Fleet Unmapped Target Review |
| 4501 | 4501 | batch | medium | low | 0 | 0 | 0 | narrow_condition | Pilot Service Error Trend Review |
| 4601 | 4601 | batch | medium | low | 0 | 0 | 0 | narrow_condition | Windows Privilege Change Review |
| 4602 | 4602 | batch | medium | low | 0 | 0 | 0 | narrow_condition | Windows Remote Administration Review |
| 4701 | 4701 | batch | medium | low | 0 | 0 | 0 | narrow_condition | Linux Persistence Change Review |
| 4702 | 4702 | batch | medium | low | 0 | 0 | 0 | narrow_condition | Linux Administrative Tool Review |
| 4901 | 4901 | batch | medium | low | 0 | 0 | 0 | narrow_condition | Source Coverage Review |
| 8001 | HB-001 | batch | medium | medium | 144 | 142 | 1 | scope_asset_group | HB-001 Нет событий от хоста 24 часа |
| 8002 | HB-002 | batch | high | medium | 6 | 6 | 0 | scope_asset_group | HB-002 Нет событий от хоста 48 часов |
| 8003 | HB-003 | batch | critical | medium | 6 | 6 | 0 | scope_asset_group | HB-003 Нет событий от хоста 72 часа |
| 8004 | HB-004 | batch | critical | medium | 9 | 4 | 5 | scope_asset_group | HB-004 Нет событий от критичного SIEM-хоста 15 минут |
| 8005 | HB-005 | batch | medium | medium | 0 | 0 | 0 | scope_asset_group | HB-005 Новый hostname в логах |
| 8006 | HB-006 | batch | medium | medium | 24 | 21 | 3 | scope_asset_group | HB-006 Новый IP в логах |
| 8007 | HB-007 | batch | medium | medium | 0 | 0 | 0 | scope_asset_group | HB-007 Known host сменил IP |
| 8008 | HB-008 | batch | medium | medium | 0 | 0 | 0 | scope_asset_group | HB-008 Known IP сменил hostname |
| 8009 | HB-009 | batch | high | medium | 0 | 0 | 0 | scope_asset_group | HB-009 Time drift больше 5 минут |
| 8010 | HB-010 | batch | medium | medium | 3 | 3 | 0 | scope_asset_group | HB-010 События приходят из будущего |
| 8011 | HB-011 | batch | high | medium | 15 | 13 | 2 | scope_asset_group | HB-011 Host отправляет слишком много событий |
| 8012 | HB-012 | batch | high | medium | 10 | 5 | 5 | scope_asset_group | HB-012 Host резко перестал отправлять события |
| 8013 | HB-013 | batch | high | medium | 2 | 1 | 1 | scope_asset_group | HB-013 Новый хост в сети без мониторинга |
| 8014 | HB-014 | batch | high | medium | 1 | 1 | 0 | scope_asset_group | HB-014 Новый открытый порт на known host |
| 8015 | HB-015 | batch | high | medium | 0 | 0 | 0 | scope_asset_group | HB-015 Порт пропал с критичного сервиса |
| 8016 | HB-016 | batch | high | medium | 0 | 0 | 0 | scope_asset_group | HB-016 VM/LXC есть в Proxmox, но нет в SIEM inventory |
| 8017 | HB-017 | batch | low | medium | 0 | 0 | 0 | scope_asset_group | HB-017 SIEM inventory содержит удалённый asset |
| 8018 | HB-018 | batch | low | medium | 0 | 0 | 0 | scope_asset_group | HB-018 Host без asset criticality |
| 8019 | HB-019 | batch | low | medium | 0 | 0 | 0 | scope_asset_group | HB-019 Host без owner |
| 8020 | HB-020 | batch | medium | medium | 0 | 0 | 0 | scope_asset_group | HB-020 Host не попадает ни в одну группу правил |
| 8048 | PVE-028 | batch | critical | medium | 0 | 0 | 0 | keep | PVE-028 Успешный вход после ошибок |
| 8049 | PVE-029 | batch | high | medium | 0 | 0 | 0 | keep | PVE-029 Вход в Proxmox с нового IP |
| 8055 | PVE-035 | batch | high | low | 0 | 0 | 0 | narrow_condition | PVE-035 Создана VM/LXC и нет heartbeat 30 минут |
| 8064 | AUTH-004 | batch | critical | low | 0 | 0 | 0 | narrow_condition | AUTH-004 Успешный SSH после bruteforce |
| 8065 | AUTH-005 | batch | high | medium | 13 | 13 | 0 | narrow_condition | AUTH-005 Вход с нового IP |
| 8066 | AUTH-006 | batch | medium | medium | 0 | 0 | 0 | keep | AUTH-006 Вход во внерабочее окно |
| 8079 | AUTH-019 | batch | low | medium | 0 | 0 | 0 | keep | AUTH-019 Новый SSH client fingerprint/user-agent |
| 8099 | EDGE-004 | batch | critical | high | 66 | 65 | 1 | narrow_condition | EDGE-004 Suricata EVE перестал поступать |
| 8100 | EDGE-005 | batch | high | medium | 0 | 0 | 0 | keep | EDGE-005 DNS logs перестали поступать |
| 8113 | IDS-012 | batch | high | medium | 0 | 0 | 0 | keep | IDS-012 Data exfil volume |
| 8124 | SYSLOG-001 | batch | high | medium | 0 | 0 | 0 | keep | SYSLOG-001 Syslog flood from one sender |
| 8142 | ING-014 | batch | high | medium | 0 | 0 | 0 | keep | ING-014 Ingest input EPS падение |
| 8143 | ING-015 | batch | high | medium | 0 | 0 | 0 | keep | ING-015 Ingest input EPS рост |
| 8146 | ING-018 | batch | medium | medium | 0 | 0 | 0 | keep | ING-018 Ingest latency p95 degraded |
| 8159 | KFK-006 | batch | high | medium | 0 | 0 | 0 | keep | KFK-006 Kafka consumer lag high |
| 8171 | PROC-008 | batch | high | medium | 0 | 0 | 0 | keep | PROC-008 Filter drop rate too high |
| 8175 | PROC-012 | batch | high | medium | 0 | 0 | 0 | keep | PROC-012 Processing latency p95 degraded |
| 8206 | WR-001 | batch | high | medium | 0 | 0 | 0 | keep | WR-001 Writer lag high |
| 8207 | WR-002 | batch | critical | medium | 0 | 0 | 0 | keep | WR-002 Writer input zero while Kafka has data |
| 8210 | WR-005 | batch | high | medium | 0 | 0 | 0 | keep | WR-005 Batch insert too slow |
| 8211 | CORR-S-001 | batch | medium | medium | 0 | 0 | 0 | narrow_condition | CORR-S-001 Stream correlator alert spike |
| 8212 | CORR-S-002 | batch | low | low | 2 | 1 | 1 | keep | CORR-S-002 Stream correlator no alerts too long |
| 8213 | CORR-S-003 | batch | critical | medium | 0 | 0 | 0 | narrow_condition | CORR-S-003 Stream state backend error |
| 8214 | CORR-B-001 | batch | high | medium | 0 | 0 | 0 | narrow_condition | CORR-B-001 Batch correlator job failed |
| 8215 | CORR-B-002 | batch | high | medium | 0 | 0 | 0 | narrow_condition | CORR-B-002 Batch correlator job overdue |
| 8216 | CORR-B-003 | batch | medium | low | 0 | 0 | 0 | narrow_condition | CORR-B-003 Batch correlator returned extreme count |
| 8221 | ALERT-005 | batch | high | medium | 7 | 6 | 1 | narrow_condition | ALERT-005 Critical alert not acknowledged |
| 8253 | IAM-017 | batch | critical | medium | 0 | 0 | 0 | keep | IAM-017 Успешный вход после bruteforce SSO |
| 8255 | IAM-019 | batch | medium | medium | 0 | 0 | 0 | keep | IAM-019 Вход с нового IP |
| 8256 | IAM-020 | batch | high | medium | 0 | 0 | 0 | keep | IAM-020 Вход из новой страны/ASN |
| 8261 | VAULT-005 | batch | high | medium | 2 | 1 | 1 | keep | VAULT-005 Vault secret read spike |
| 8282 | DB-003 | batch | high | medium | 0 | 0 | 0 | keep | DB-003 DB backup overdue |
| 8342 | PILOT-018 | batch | critical | medium | 0 | 0 | 0 | keep | PILOT-018 Redis dangerous command |
| 8343 | PILOT-019 | batch | medium | medium | 0 | 0 | 0 | keep | PILOT-019 Pilot service latency degraded |
| 8351 | GW-007 | batch | high | medium | 0 | 0 | 0 | keep | GW-007 Gateway outgoing traffic spike |
| 8354 | GW-010 | batch | critical | low | 2 | 2 | 0 | deduplicate | GW-010 Gateway logs stopped |
| 8357 | MC-003 | batch | high | medium | 0 | 0 | 0 | keep | MC-003 Mass connections to 25565 |
| 8365 | NC-003 | batch | critical | medium | 0 | 0 | 0 | keep | NC-003 Nextcloud success after bruteforce |
| 8378 | NAV-004 | batch | medium | medium | 5 | 5 | 0 | narrow_condition | NAV-004 Mass media download/stream |
| 8396 | WIN-004 | batch | high | medium | 0 | 0 | 0 | keep | WIN-004 RDP login from new IP |
| 8414 | WIN-022 | batch | critical | medium | 0 | 0 | 0 | keep | WIN-022 Successful login after failures |
| 8417 | WIN-025 | batch | high | medium | 0 | 0 | 0 | keep | WIN-025 Large outbound traffic from Windows |
| 8418 | MET-001 | batch | medium | medium | 3 | 2 | 1 | narrow_condition | MET-001 CPU > 90% 10m |
| 8419 | MET-002 | batch | high | medium | 6 | 6 | 0 | narrow_condition | MET-002 CPU > 95% 15m |
| 8420 | MET-003 | batch | medium | medium | 3 | 2 | 1 | narrow_condition | MET-003 RAM > 90% 10m |
| 8421 | MET-004 | batch | high | low | 0 | 0 | 0 | keep | MET-004 RAM > 95% 15m |
| 8422 | MET-005 | batch | high | medium | 0 | 0 | 0 | narrow_condition | MET-005 Disk > 85% |
| 8423 | MET-006 | batch | critical | medium | 0 | 0 | 0 | narrow_condition | MET-006 Disk > 95% |
| 8424 | MET-007 | batch | high | medium | 0 | 0 | 0 | narrow_condition | MET-007 Disk growth >20GB/h |
| 8425 | MET-008 | batch | high | medium | 3 | 2 | 1 | narrow_condition | MET-008 High iowait |
| 8426 | MET-009 | batch | high | medium | 3 | 2 | 1 | narrow_condition | MET-009 Load average high |
| 8427 | MET-010 | batch | medium | medium | 0 | 0 | 0 | keep | MET-010 Network drops/errors |
| 8428 | MET-011 | batch | medium | low | 0 | 0 | 0 | keep | MET-011 Traffic spike |
| 8429 | MET-012 | batch | high | medium | 3 | 2 | 1 | narrow_condition | MET-012 Process restart loop |
| 8430 | MET-013 | batch | high | medium | 0 | 0 | 0 | keep | MET-013 Proxmox host storage high |
| 8431 | MET-014 | batch | critical | medium | 0 | 0 | 0 | narrow_condition | MET-014 ClickHouse disk high |
| 8432 | MET-015 | batch | high | medium | 0 | 0 | 0 | narrow_condition | MET-015 Kafka disk high |
| 8433 | MET-016 | batch | high | medium | 0 | 0 | 0 | narrow_condition | MET-016 Docker disk high |
| 8434 | MET-017 | batch | high | medium | 0 | 0 | 0 | keep | MET-017 PostgreSQL connections high |
| 8435 | MET-018 | batch | medium | medium | 0 | 0 | 0 | keep | MET-018 MongoDB connections high |
| 8436 | MET-019 | batch | medium | medium | 0 | 0 | 0 | narrow_condition | MET-019 Nginx active connections spike |
| 8437 | MET-020 | batch | medium | medium | 0 | 0 | 0 | narrow_condition | MET-020 Service latency p95 high |
| 8438 | BCK-001 | batch | high | medium | 0 | 0 | 0 | narrow_condition | BCK-001 Proxmox backup failed |
| 8439 | BCK-002 | batch | critical | medium | 0 | 0 | 0 | keep | BCK-002 Proxmox backup disabled/deleted |
| 8440 | BCK-003 | batch | high | medium | 0 | 0 | 0 | narrow_condition | BCK-003 SIEM DB backup failed |
| 8441 | BCK-004 | batch | high | medium | 0 | 0 | 0 | narrow_condition | BCK-004 PostgreSQL backup failed |
| 8442 | BCK-005 | batch | high | medium | 4 | 4 | 0 | narrow_condition | BCK-005 Backup overdue 24h |
| 8443 | BCK-006 | batch | critical | medium | 0 | 0 | 0 | narrow_condition | BCK-006 Backup overdue 72h |
| 8444 | BCK-007 | batch | high | medium | 0 | 0 | 0 | keep | BCK-007 Backup size dropped |
| 8445 | BCK-008 | batch | critical | medium | 0 | 0 | 0 | keep | BCK-008 Backup deleted |
| 8446 | BCK-009 | batch | high | medium | 0 | 0 | 0 | keep | BCK-009 Restore started |
| 8447 | BCK-010 | batch | high | medium | 0 | 0 | 0 | keep | BCK-010 Restore failed |
| 8448 | CORR-001 | batch | high | low | 0 | 0 | 0 | narrow_condition | CORR-001 Proxmox admin login → VM/LXC created |
| 8449 | CORR-002 | batch | high | low | 0 | 0 | 0 | narrow_condition | CORR-002 VM/LXC created → no heartbeat |
| 8450 | CORR-003 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-003 VM/LXC created → new exposed port |
| 8451 | CORR-004 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-004 VM/LXC deleted after failed backup |
| 8452 | CORR-005 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-005 Root SSH login → dangerous sudo |
| 8453 | CORR-006 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-006 SSH bruteforce → success → sudo |
| 8454 | CORR-007 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-007 SSO admin role assigned → SIEM admin login |
| 8455 | CORR-008 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-008 MFA disabled → login from new IP |
| 8456 | CORR-009 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-009 Client secret changed → API activity from new IP |
| 8457 | CORR-010 | batch | critical | low | 1 | 0 | 1 | narrow_condition | CORR-010 Vault unseal → secret read spike |
| 8458 | CORR-011 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-011 SIEM EPS drop → multiple hosts no heartbeat |
| 8459 | CORR-012 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-012 Kafka lag → writer errors |
| 8460 | CORR-013 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-013 ClickHouse error → alert aggregator issue |
| 8461 | CORR-014 | batch | high | low | 0 | 0 | 0 | narrow_condition | CORR-014 Rule reload failed → normalization errors spike |
| 8462 | CORR-015 | batch | high | low | 0 | 0 | 0 | narrow_condition | CORR-015 Filter drop rate high → EPS to storage drops |
| 8463 | CORR-016 | batch | high | low | 0 | 0 | 0 | narrow_condition | CORR-016 Public share → outbound spike |
| 8464 | CORR-017 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-017 Nextcloud admin login → mass downloads |
| 8465 | CORR-018 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-018 OpenVAS critical vuln → public exposed service |
| 8466 | CORR-019 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-019 IDS scan → successful SSH |
| 8467 | CORR-020 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-020 DNS malware domain → outbound suspicious port |
| 8468 | CORR-021 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-021 Docker privileged container → new published port |
| 8469 | CORR-022 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-022 Docker socket mount → container starts new image |
| 8470 | CORR-023 | batch | high | low | 0 | 0 | 0 | deduplicate | CORR-023 OpenClaw gateway route change → inbound spike |
| 8471 | CORR-024 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-024 Pilot DB access anomaly → DB dump/export |
| 8472 | CORR-025 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-025 Redis dangerous command → cache container down |
| 8473 | CORR-026 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-026 Pterodactyl admin granted → server created |
| 8474 | CORR-027 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-027 New Pterodactyl API key → server deleted |
| 8475 | CORR-028 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-028 Minecraft Log4Shell pattern → outbound connection |
| 8476 | CORR-029 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-029 Windows admin login → Defender disabled |
| 8477 | CORR-030 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-030 Windows RDP login → service created |
| 8478 | CORR-031 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-031 Windows failed logins → success → admin group change |
| 8479 | CORR-032 | batch | high | low | 0 | 0 | 0 | narrow_condition | CORR-032 Suricata severity1 → host traffic spike |
| 8480 | CORR-033 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-033 Gateway firewall/proxy change → new exposed port |
| 8481 | CORR-034 | batch | critical | medium | 0 | 0 | 0 | narrow_condition | CORR-034 rsyslog stopped → host heartbeat lost |
| 8482 | CORR-035 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-035 Backup disabled → storage/disk changes |
| 8483 | CORR-036 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-036 ClickHouse DROP/TRUNCATE → EPS/alerts drop |
| 8484 | CORR-037 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-037 Keycloak redirect URI changed → login from new domain/IP |
| 8485 | CORR-038 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-038 OpenVAS scans unapproved range → IDS scan alerts |
| 8486 | CORR-039 | batch | high | low | 0 | 0 | 0 | narrow_condition | CORR-039 Incident bot stopped → critical alerts unsent |
| 8487 | CORR-040 | batch | critical | low | 0 | 0 | 0 | narrow_condition | CORR-040 No Suricata logs → suspicious gateway traffic still present |
| 2101 | 2101 | stream | high | low | 0 | 0 | 0 | narrow_condition | Host CPU Pressure Sustained |
| 2102 | 2102 | stream | high | low | 0 | 0 | 0 | narrow_condition | Host Memory Pressure Sustained |
| 2103 | 2103 | stream | high | low | 0 | 0 | 0 | narrow_condition | Host Disk Pressure Sustained |
| 2104 | 2104 | stream | medium | low | 7 | 3 | 4 | narrow_condition | Host Load Pressure Sustained |
| 2105 | 2105 | stream | high | low | 0 | 0 | 0 | narrow_condition | Host Swap Thrash Burst |
| 2106 | 2106 | stream | medium | low | 0 | 0 | 0 | narrow_condition | Host Filesystem Inode Pressure |
| 2107 | 2107 | stream | high | low | 0 | 0 | 0 | narrow_condition | Host Telemetry Missing |
| 2108 | 2108 | stream | medium | low | 6 | 4 | 2 | narrow_condition | Host Service Flapping |
| 2109 | 2109 | stream | high | low | 0 | 0 | 0 | narrow_condition | Storage Node Runtime Pressure |
| 2110 | 2110 | stream | medium | low | 0 | 0 | 0 | narrow_condition | Control Plane Runtime Pressure |
| 2201 | 2201 | stream | high | low | 0 | 0 | 0 | narrow_condition | Extended Fleet Telemetry Missing |
| 2202 | 2202 | stream | medium | low | 0 | 0 | 0 | narrow_condition | Extended Fleet Service Flapping |
| 2203 | 2203 | stream | high | low | 0 | 0 | 0 | narrow_condition | Extended Fleet Runtime Pressure |
| 2301 | 2301 | stream | high | low | 0 | 0 | 0 | narrow_condition | OpenClaw Outbound Connection Burst |
| 2302 | 2302 | stream | medium | low | 0 | 0 | 0 | deduplicate | OpenClaw DNS Query Burst |
| 2303 | 2303 | stream | high | low | 7 | 7 | 0 | narrow_condition | OpenClaw Privileged Configuration Change |
| 2304 | 2304 | stream | medium | low | 0 | 0 | 0 | narrow_condition | OpenClaw Proxy Error Burst |
| 2305 | 2305 | stream | high | low | 0 | 0 | 0 | narrow_condition | OpenClaw Suspicious Interactive Privilege Activity |
| 2401 | 2401 | stream | high | low | 0 | 0 | 0 | narrow_condition | Critical Exposure On Fleet Service |
| 2402 | 2402 | stream | high | low | 0 | 0 | 0 | narrow_condition | Public Service Vulnerability Burst |
| 2501 | 2501 | stream | medium | low | 0 | 0 | 0 | deduplicate | Repeated External App Authentication Failures |
| 2501 | 2501 | stream | medium | low | 0 | 0 | 0 | deduplicate | Pilot Service Runtime Instability |
| 2502 | 2502 | stream | low | low | 0 | 0 | 0 | deduplicate | First-Seen Login On SSO-Enabled Internal App |
| 2502 | 2502 | stream | high | low | 0 | 0 | 0 | deduplicate | Pilot Service Telemetry Missing |
| 2503 | 2503 | stream | high | low | 0 | 0 | 0 | deduplicate | SSO Role Or Grant Drift Detected |
| 2503 | 2503 | stream | medium | low | 0 | 0 | 0 | deduplicate | Pilot Service Auth Error Burst |
| 2511 | 2511 | stream | medium | low | 0 | 0 | 0 | narrow_condition | Gitea Failed Login Burst |
| 2512 | 2512 | stream | high | low | 0 | 0 | 0 | narrow_condition | Gitea Administrative Change |
| 2513 | 2513 | stream | medium | low | 0 | 0 | 0 | narrow_condition | Gitea Repository Activity Spike |
| 2521 | 2521 | stream | medium | low | 0 | 0 | 0 | deduplicate | Navidrome Proxy Authentication Failure Burst |
| 2522 | 2522 | stream | low | low | 0 | 0 | 0 | narrow_condition | Navidrome First-Seen User |
| 2523 | 2523 | stream | medium | low | 0 | 0 | 0 | narrow_condition | Navidrome Abnormal Playback Or API Burst |
| 2531 | 2531 | stream | high | low | 0 | 0 | 0 | narrow_condition | Greenbone Sync Or Import Degradation |
| 2532 | 2532 | stream | medium | low | 0 | 0 | 0 | narrow_condition | Fleet Scan Coverage Stale |
| 2533 | 2533 | stream | medium | low | 0 | 0 | 0 | narrow_condition | Scanner Target Drift Against Proxmox Inventory |
| 2601 | 2601 | stream | medium | low | 2 | 2 | 0 | narrow_condition | Windows Logon Failure Burst |
| 2602 | 2602 | stream | high | low | 0 | 0 | 0 | narrow_condition | Windows Audit Log Cleared |
| 2603 | 2603 | stream | high | low | 0 | 0 | 0 | narrow_condition | Windows Privileged Group Membership Change |
| 2604 | 2604 | stream | high | low | 5 | 3 | 2 | keep | Windows Encoded PowerShell Command |
| 2605 | 2605 | stream | high | low | 1 | 0 | 1 | keep | Windows Service Installed |
| 2606 | 2606 | stream | medium | low | 0 | 0 | 0 | narrow_condition | Windows User Created |
| 2607 | 2607 | stream | high | low | 2 | 2 | 0 | keep | Windows Scheduled Task Created |
| 2608 | 2608 | stream | high | low | 0 | 0 | 0 | narrow_condition | Windows Registry Persistence Change |
| 2609 | 2609 | stream | medium | low | 0 | 0 | 0 | narrow_condition | Windows Suspicious Process Creation Burst |
| 2610 | 2610 | stream | medium | low | 0 | 0 | 0 | narrow_condition | Windows User Deleted |
| 2611 | 2611 | stream | high | low | 1 | 1 | 0 | keep | Windows Special Privileges Assigned |
| 2612 | 2612 | stream | medium | low | 2 | 2 | 0 | keep | Windows Explicit Credentials Logon |
| 2613 | 2613 | stream | high | low | 0 | 0 | 0 | narrow_condition | Windows Audit Policy Changed |
| 2614 | 2614 | stream | high | low | 0 | 0 | 0 | narrow_condition | Windows Password Reset Or Change |
| 2615 | 2615 | stream | high | low | 0 | 0 | 0 | narrow_condition | Windows Defender Malware Detected |
| 2616 | 2616 | stream | high | low | 2 | 2 | 0 | keep | Windows Defender Configuration Changed |
| 2617 | 2617 | stream | medium | low | 1 | 1 | 0 | narrow_condition | Windows RDP Authentication Burst |
| 2618 | 2618 | stream | high | low | 2 | 2 | 0 | tune_threshold | Windows WMI Activity Burst |
| 2619 | 2619 | stream | critical | low | 1 | 0 | 1 | keep | Windows WMI Permanent Event Consumer |
| 2701 | 2701 | stream | medium | low | 0 | 0 | 0 | tune_threshold | Linux SSH Login Failure Burst |
| 2702 | 2702 | stream | high | low | 0 | 0 | 0 | keep | Linux Root SSH Login |
| 2703 | 2703 | stream | medium | low | 0 | 0 | 0 | keep | Linux Sudo To Root Burst |
| 2704 | 2704 | stream | high | low | 29 | 15 | 14 | narrow_condition | Linux Cron Modified |
| 2705 | 2705 | stream | high | low | 0 | 0 | 0 | narrow_condition | Linux Sudoers Modified |
| 2706 | 2706 | stream | high | low | 51 | 43 | 8 | narrow_condition | Linux Systemd Unit Modified |
| 2707 | 2707 | stream | high | low | 0 | 0 | 0 | narrow_condition | Linux Security-Critical Service Disabled |
| 2708 | 2708 | stream | medium | low | 0 | 0 | 0 | tune_threshold | Linux SSH Invalid User Burst |
| 2709 | 2709 | stream | high | low | 13 | 5 | 8 | narrow_condition | Linux Authorized Keys Modified |
| 2710 | 2710 | stream | high | low | 0 | 0 | 0 | narrow_condition | Linux Passwd Or Shadow Access |
| 2711 | 2711 | stream | high | low | 26 | 26 | 0 | narrow_condition | Linux Execution From Temporary Paths |
| 2712 | 2712 | stream | high | low | 0 | 0 | 0 | narrow_condition | Linux Audit Rules Cleared |
| 2713 | 2713 | stream | high | low | 0 | 0 | 0 | narrow_condition | Linux Firewall Disabled |
| 2714 | 2714 | stream | high | low | 0 | 0 | 0 | narrow_condition | Linux Remote Access Or Reverse Shell Activity |
| 2715 | 2715 | stream | high | low | 32 | 16 | 16 | narrow_condition | Linux Audit Configuration Changed |
| 2716 | 2716 | stream | high | low | 29 | 15 | 14 | narrow_condition | Linux SSHD Configuration Changed |
| 2717 | 2717 | stream | high | low | 50 | 34 | 16 | narrow_condition | Linux Logging Configuration Changed |
| 2718 | 2718 | stream | medium | low | 0 | 0 | 0 | narrow_condition | Linux User Lifecycle Change |
| 2719 | 2719 | stream | medium | low | 0 | 0 | 0 | narrow_condition | Linux Download Utility Burst |
| 2720 | 2720 | stream | high | low | 0 | 0 | 0 | narrow_condition | Linux Network Tool Or Packet Capture Activity |
| 2721 | 2721 | stream | high | low | 13 | 5 | 8 | narrow_condition | Linux Kernel Or Sysctl Tampering |
| 2722 | 2722 | stream | high | low | 0 | 0 | 0 | narrow_condition | Linux Capability Or Setuid Tampering |
| 2723 | 2723 | stream | high | low | 0 | 0 | 0 | deduplicate | Linux LD Preload Modified |
| 2724 | 2724 | stream | high | low | 0 | 0 | 0 | narrow_condition | Linux Pkexec Execution |
| 2725 | 2725 | stream | medium | low | 0 | 0 | 0 | narrow_condition | Linux Data Compression Burst |
| 2726 | 2726 | stream | medium | low | 12 | 11 | 1 | narrow_condition | Linux System Recon Burst |
| 2901 | 2901 | stream | medium | low | 0 | 0 | 0 | narrow_condition | Nextcloud Authentication Failure Burst |
| 2902 | 2902 | stream | high | low | 0 | 0 | 0 | narrow_condition | Gitea Administrative Change Burst |
| 2903 | 2903 | stream | medium | low | 0 | 0 | 0 | narrow_condition | Navidrome Proxy Authentication Failure Burst |
| 2904 | 2904 | stream | high | low | 0 | 0 | 0 | narrow_condition | VPN Edge Telemetry Drop |
| 2905 | 2905 | stream | medium | low | 0 | 0 | 0 | narrow_condition | Proxmox Fleet and Scan Drift |
| 2906 | 2906 | stream | high | low | 0 | 0 | 0 | narrow_condition | PostgreSQL Authentication Failure Burst |
| 2907 | 2907 | stream | medium | low | 2 | 2 | 0 | narrow_condition | Valkey Persistence Or Restart Burst |
| 2908 | 2908 | stream | high | low | 0 | 0 | 0 | narrow_condition | SIEM Web Or Keycloak Authentication Degradation |
| 2909 | 2909 | stream | medium | low | 0 | 0 | 0 | narrow_condition | Generic Source Telemetry Stall |
| 2910 | 2910 | stream | medium | low | 0 | 0 | 0 | narrow_condition | Windows Or BSD Guest Coverage Gap |
| 2911 | 2911 | stream | medium | low | 0 | 0 | 0 | narrow_condition | VPN SSH Invalid User Burst |
| 2912 | 2912 | stream | medium | low | 0 | 0 | 0 | narrow_condition | VPN Firewall Blocked Probe Burst |
| 2913 | 2913 | stream | medium | low | 0 | 0 | 0 | narrow_condition | Jump Host SSH Failure Burst |
| 8021 | PVE-001 | stream | high | low | 0 | 0 | 0 | keep | PVE-001 Создана новая VM |
| 8022 | PVE-002 | stream | high | low | 0 | 0 | 0 | keep | PVE-002 Создан новый LXC |
| 8023 | PVE-003 | stream | critical | low | 0 | 0 | 0 | keep | PVE-003 Удалена VM |
| 8024 | PVE-004 | stream | critical | low | 0 | 0 | 0 | keep | PVE-004 Удалён LXC |
| 8025 | PVE-005 | stream | medium | low | 3 | 2 | 1 | keep | PVE-005 Изменены CPU/RAM VM/LXC |
| 8026 | PVE-006 | stream | high | low | 0 | 0 | 0 | keep | PVE-006 Изменён диск VM/LXC |
| 8027 | PVE-007 | stream | high | low | 3 | 2 | 1 | keep | PVE-007 Изменён сетевой интерфейс VM/LXC |
| 8028 | PVE-008 | stream | high | low | 0 | 0 | 0 | keep | PVE-008 Добавлен новый bridge/interface |
| 8029 | PVE-009 | stream | high | low | 0 | 0 | 0 | keep | PVE-009 Изменено правило Proxmox firewall |
| 8030 | PVE-010 | stream | critical | low | 0 | 0 | 0 | keep | PVE-010 Firewall отключён на VM/LXC |
| 8031 | PVE-011 | stream | medium | low | 0 | 0 | 0 | keep | PVE-011 Создан snapshot |
| 8032 | PVE-012 | stream | high | low | 0 | 0 | 0 | keep | PVE-012 Удалён snapshot |
| 8033 | PVE-013 | stream | high | low | 0 | 0 | 0 | keep | PVE-013 Rollback snapshot |
| 8034 | PVE-014 | stream | medium | low | 0 | 0 | 0 | keep | PVE-014 Запуск VM/LXC вне окна работ |
| 8035 | PVE-015 | stream | high | low | 0 | 0 | 0 | keep | PVE-015 Остановка VM/LXC вне окна работ |
| 8036 | PVE-016 | stream | high | low | 1 | 1 | 0 | tune_threshold | PVE-016 Перезагрузка критичной VM |
| 8037 | PVE-017 | stream | high | low | 0 | 0 | 0 | keep | PVE-017 Изменён boot order |
| 8038 | PVE-018 | stream | high | low | 0 | 0 | 0 | keep | PVE-018 Подключён ISO/CD-ROM |
| 8039 | PVE-019 | stream | high | low | 0 | 0 | 0 | keep | PVE-019 Добавлен USB passthrough |
| 8040 | PVE-020 | stream | high | low | 0 | 0 | 0 | keep | PVE-020 Добавлен PCI/GPU passthrough |
| 8041 | PVE-021 | stream | high | low | 0 | 0 | 0 | keep | PVE-021 Изменён cloud-init |
| 8042 | PVE-022 | stream | critical | low | 0 | 0 | 0 | keep | PVE-022 Изменены SSH keys через cloud-init |
| 8043 | PVE-023 | stream | critical | low | 0 | 0 | 0 | keep | PVE-023 Создан пользователь Proxmox |
| 8044 | PVE-024 | stream | high | low | 0 | 0 | 0 | keep | PVE-024 Удалён пользователь Proxmox |
| 8045 | PVE-025 | stream | critical | low | 0 | 0 | 0 | keep | PVE-025 Назначена роль Administrator |
| 8046 | PVE-026 | stream | high | low | 2 | 1 | 1 | keep | PVE-026 Успешный вход root@pam |
| 8047 | PVE-027 | stream | medium | low | 2 | 1 | 1 | keep | PVE-027 Неуспешные входы в Proxmox |
| 8050 | PVE-030 | stream | critical | low | 3 | 2 | 1 | keep | PVE-030 Изменены storage-настройки |
| 8051 | PVE-031 | stream | high | low | 0 | 0 | 0 | keep | PVE-031 Подключён новый storage |
| 8052 | PVE-032 | stream | critical | low | 0 | 0 | 0 | keep | PVE-032 Удалён storage |
| 8053 | PVE-033 | stream | high | low | 0 | 0 | 0 | keep | PVE-033 Ошибка backup job |
| 8054 | PVE-034 | stream | critical | low | 0 | 0 | 0 | keep | PVE-034 Backup job отключён |
| 8056 | PVE-036 | stream | critical | low | 1 | 1 | 0 | keep | PVE-036 Создана VM/LXC с публичным bridge |
| 8057 | PVE-037 | stream | high | low | 0 | 0 | 0 | keep | PVE-037 Критичной VM добавлен второй NIC |
| 8058 | PVE-038 | stream | medium | low | 0 | 0 | 0 | keep | PVE-038 VM мигрирована между узлами |
| 8059 | PVE-039 | stream | high | low | 0 | 0 | 0 | keep | PVE-039 Миграция критичной VM неуспешна |
| 8060 | PVE-040 | stream | medium | low | 0 | 0 | 0 | keep | PVE-040 Консольный доступ к VM |
| 8061 | AUTH-001 | stream | high | low | 0 | 0 | 0 | keep | AUTH-001 Успешный SSH-вход root |
| 8062 | AUTH-002 | stream | medium | low | 0 | 0 | 0 | keep | AUTH-002 Неуспешный SSH-вход root |
| 8063 | AUTH-003 | stream | high | low | 0 | 0 | 0 | keep | AUTH-003 Массовые неуспешные SSH-входы |
| 8067 | AUTH-007 | stream | info | low | 0 | 0 | 0 | keep | AUTH-007 sudo-команда |
| 8068 | AUTH-008 | stream | high | low | 0 | 0 | 0 | keep | AUTH-008 Опасная sudo-команда |
| 8069 | AUTH-009 | stream | critical | low | 0 | 0 | 0 | keep | AUTH-009 Пользователь добавлен в sudo/wheel/adm |
| 8070 | AUTH-010 | stream | high | low | 0 | 0 | 0 | keep | AUTH-010 Создан Linux-пользователь |
| 8071 | AUTH-011 | stream | high | low | 0 | 0 | 0 | keep | AUTH-011 Удалён Linux-пользователь |
| 8072 | AUTH-012 | stream | critical | low | 0 | 0 | 0 | keep | AUTH-012 Изменён пароль root |
| 8073 | AUTH-013 | stream | high | low | 0 | 0 | 0 | keep | AUTH-013 su в root |
| 8074 | AUTH-014 | stream | medium | low | 0 | 0 | 0 | keep | AUTH-014 Неуспешные su |
| 8075 | AUTH-015 | stream | medium | low | 0 | 0 | 0 | keep | AUTH-015 SSH session opened to critical host |
| 8076 | AUTH-016 | stream | high | low | 0 | 0 | 0 | keep | AUTH-016 SSH login from public internet |
| 8077 | AUTH-017 | stream | medium | low | 0 | 0 | 0 | keep | AUTH-017 PAM authentication errors spike |
| 8078 | AUTH-018 | stream | medium | low | 0 | 0 | 0 | keep | AUTH-018 SSH disconnect storm |
| 8080 | AUTH-020 | stream | critical | low | 0 | 0 | 0 | keep | AUTH-020 Остановлен sshd |
| 8081 | SVC-001 | stream | critical | low | 16 | 5 | 11 | keep | SVC-001 Критичный service stopped |
| 8082 | SVC-002 | stream | high | low | 0 | 0 | 0 | keep | SVC-002 Критичный service restarted |
| 8083 | SVC-003 | stream | high | low | 8 | 1 | 7 | keep | SVC-003 Service restart loop |
| 8084 | SVC-004 | stream | high | low | 32 | 15 | 17 | keep | SVC-004 Unit entered failed state |
| 8085 | SVC-005 | stream | high | low | 1 | 0 | 1 | keep | SVC-005 Dependency failed for service |
| 8086 | SVC-006 | stream | critical | low | 0 | 0 | 0 | keep | SVC-006 OOMKilled service |
| 8087 | SVC-007 | stream | critical | low | 0 | 0 | 0 | keep | SVC-007 Filesystem read-only |
| 8088 | SVC-008 | stream | critical | low | 0 | 0 | 0 | keep | SVC-008 Kernel panic/oops |
| 8089 | SVC-009 | stream | info | low | 0 | 0 | 0 | keep | SVC-009 Package manager transaction |
| 8090 | SVC-010 | stream | critical | low | 4 | 4 | 0 | narrow_condition | SVC-010 Удалён monitoring/logging/security package |
| 8091 | SVC-011 | stream | critical | low | 1 | 1 | 0 | keep | SVC-011 rsyslog stopped |
| 8092 | SVC-012 | stream | high | low | 0 | 0 | 0 | keep | SVC-012 nginx stopped |
| 8093 | SVC-013 | stream | critical | low | 0 | 0 | 0 | keep | SVC-013 postgresql stopped |
| 8094 | SVC-014 | stream | high | low | 0 | 0 | 0 | keep | SVC-014 mongod stopped |
| 8095 | SVC-015 | stream | medium | low | 0 | 0 | 0 | keep | SVC-015 qemu-guest-agent stopped |
| 8096 | EDGE-001 | stream | critical | low | 8 | 8 | 0 | narrow_condition | EDGE-001 Suricata stopped/failed |
| 8097 | EDGE-002 | stream | critical | low | 13 | 13 | 0 | narrow_condition | EDGE-002 Unbound stopped/failed |
| 8098 | EDGE-003 | stream | critical | low | 4 | 4 | 0 | narrow_condition | EDGE-003 rsyslog stopped/failed |
| 8101 | EDGE-006 | stream | critical | low | 7 | 7 | 0 | narrow_condition | EDGE-006 Syslog relay перестал принимать события |
| 8102 | IDS-001 | stream | critical | low | 9 | 9 | 0 | narrow_condition | IDS-001 Suricata alert severity 1 |
| 8103 | IDS-002 | stream | high | low | 9 | 7 | 2 | narrow_condition | IDS-002 Suricata alert severity 2 |
| 8104 | IDS-003 | stream | critical | low | 5 | 5 | 0 | narrow_condition | IDS-003 Exploit kit / RCE signature |
| 8105 | IDS-004 | stream | critical | low | 7 | 7 | 0 | narrow_condition | IDS-004 Malware C2 signature |
| 8106 | IDS-005 | stream | high | low | 9 | 9 | 0 | narrow_condition | IDS-005 ET SCAN / portscan |
| 8107 | IDS-006 | stream | high | low | 7 | 7 | 0 | narrow_condition | IDS-006 SSH bruteforce from IDS perspective |
| 8108 | IDS-007 | stream | critical | low | 7 | 7 | 0 | narrow_condition | IDS-007 RDP scan/bruteforce |
| 8109 | IDS-008 | stream | critical | low | 7 | 7 | 0 | narrow_condition | IDS-008 Inbound to database ports |
| 8110 | IDS-009 | stream | high | low | 7 | 7 | 0 | narrow_condition | IDS-009 Outbound to suspicious ports |
| 8111 | IDS-010 | stream | high | low | 9 | 7 | 2 | narrow_condition | IDS-010 Outbound to TOR/VPN/proxy |
| 8112 | IDS-011 | stream | critical | low | 7 | 7 | 0 | narrow_condition | IDS-011 Crypto/mining pool traffic |
| 8114 | IDS-013 | stream | high | low | 9 | 9 | 0 | narrow_condition | IDS-013 Internal lateral scan |
| 8115 | IDS-014 | stream | high | low | 7 | 7 | 0 | narrow_condition | IDS-014 New external service exposed |
| 8116 | IDS-015 | stream | critical | low | 7 | 7 | 0 | narrow_condition | IDS-015 DNS tunneling suspicion |
| 8117 | DNS-001 | stream | medium | low | 7 | 7 | 0 | narrow_condition | DNS-001 NXDOMAIN spike by client |
| 8118 | DNS-002 | stream | medium | low | 0 | 0 | 0 | keep | DNS-002 Query to dynamic DNS |
| 8119 | DNS-003 | stream | low | low | 7 | 7 | 0 | narrow_condition | DNS-003 Query to newly seen domain |
| 8120 | DNS-004 | stream | critical | low | 0 | 0 | 0 | keep | DNS-004 Query to known malware/phishing domain |
| 8121 | DNS-005 | stream | high | low | 23 | 19 | 2 | narrow_condition | DNS-005 Internal host uses external DNS directly |
| 8122 | DNS-006 | stream | medium | low | 1 | 1 | 0 | keep | DNS-006 DoH/DoT bypass |
| 8123 | DNS-007 | stream | medium | low | 3 | 3 | 0 | narrow_condition | DNS-007 Unbound SERVFAIL spike |
| 8125 | SYSLOG-002 | stream | medium | low | 0 | 0 | 0 | keep | SYSLOG-002 Malformed syslog spike |
| 8126 | SYSLOG-003 | stream | medium | low | 0 | 0 | 0 | keep | SYSLOG-003 TLS/syslog input errors |
| 8127 | SYSLOG-004 | stream | high | low | 0 | 0 | 0 | keep | SYSLOG-004 Unexpected syslog sender |
| 8128 | SYSLOG-005 | stream | low | low | 0 | 0 | 0 | keep | SYSLOG-005 Known sender changed facility/app-name profile |
| 8129 | ING-001 | stream | critical | low | 0 | 0 | 0 | keep | ING-001 siem-ingest stopped/failed |
| 8130 | ING-002 | stream | high | low | 0 | 0 | 0 | keep | ING-002 nginx stopped/failed on ingest |
| 8131 | ING-003 | stream | critical | low | 0 | 0 | 0 | keep | ING-003 siem-kafka stopped/failed on ingest |
| 8132 | ING-004 | stream | critical | low | 0 | 0 | 0 | keep | ING-004 rsyslog stopped/failed on ingest |
| 8133 | ING-005 | stream | high | low | 0 | 0 | 0 | keep | ING-005 mongod stopped/failed on ingest |
| 8134 | ING-006 | stream | high | low | 0 | 0 | 0 | keep | ING-006 postgresql stopped/failed on ingest |
| 8135 | ING-007 | stream | high | low | 0 | 0 | 0 | keep | ING-007 Ingest HTTP 5xx spike |
| 8136 | ING-008 | stream | medium | low | 0 | 0 | 0 | keep | ING-008 Ingest HTTP 4xx spike |
| 8137 | ING-009 | stream | medium | low | 0 | 0 | 0 | keep | ING-009 Payload too large |
| 8138 | ING-010 | stream | high | low | 0 | 0 | 0 | keep | ING-010 Unauthorized ingest attempts |
| 8139 | ING-011 | stream | high | low | 0 | 0 | 0 | keep | ING-011 Unknown ingest source token |
| 8140 | ING-012 | stream | medium | low | 0 | 0 | 0 | keep | ING-012 Duplicate event_id spike |
| 8141 | ING-013 | stream | high | low | 0 | 0 | 0 | keep | ING-013 Malformed JSON/syslog spike |
| 8144 | ING-016 | stream | critical | low | 0 | 0 | 0 | keep | ING-016 Kafka publish failures from ingest |
| 8145 | ING-017 | stream | high | low | 0 | 0 | 0 | keep | ING-017 Nginx upstream siem-ingest unavailable |
| 8147 | ING-019 | stream | medium | low | 0 | 0 | 0 | keep | ING-019 Источник отправляет события с неправильным временем |
| 8148 | ING-020 | stream | medium | low | 0 | 0 | 0 | keep | ING-020 События с пустым hostname/source |
| 8149 | ING-021 | stream | critical | low | 0 | 0 | 0 | keep | ING-021 Ingest endpoint accessed from public IP |
| 8150 | ING-022 | stream | high | low | 0 | 0 | 0 | keep | ING-022 Запрос к admin/debug endpoint ingest |
| 8151 | ING-023 | stream | high | low | 0 | 0 | 0 | keep | ING-023 Config reload failed ingest |
| 8152 | ING-024 | stream | high | low | 0 | 0 | 0 | keep | ING-024 Ingest started in debug mode |
| 8153 | ING-025 | stream | medium | low | 0 | 0 | 0 | keep | ING-025 qemu-guest-agent stopped on ingest |
| 8154 | KFK-001 | stream | critical | low | 0 | 0 | 0 | keep | KFK-001 Kafka stopped on 104 |
| 8155 | KFK-002 | stream | critical | low | 0 | 0 | 0 | keep | KFK-002 Kafka stopped on 105 |
| 8156 | KFK-003 | stream | critical | low | 0 | 0 | 0 | keep | KFK-003 Kafka stopped on 108 |
| 8157 | KFK-004 | stream | critical | low | 0 | 0 | 0 | keep | KFK-004 Kafka broker unavailable |
| 8158 | KFK-005 | stream | high | low | 0 | 0 | 0 | keep | KFK-005 Kafka under-replicated partitions |
| 8160 | KFK-007 | stream | critical | low | 0 | 0 | 0 | keep | KFK-007 Kafka topic missing |
| 8161 | KFK-008 | stream | high | low | 0 | 0 | 0 | keep | KFK-008 Kafka disk pressure |
| 8162 | KFK-009 | stream | high | low | 0 | 0 | 0 | keep | KFK-009 Kafka ISR shrink |
| 8163 | KFK-010 | stream | high | low | 0 | 0 | 0 | keep | KFK-010 Kafka auth failure |
| 8164 | PROC-001 | stream | critical | low | 0 | 0 | 0 | keep | PROC-001 siem-normalizer stopped |
| 8165 | PROC-002 | stream | critical | low | 0 | 0 | 0 | keep | PROC-002 siem-filter stopped |
| 8166 | PROC-003 | stream | high | low | 0 | 0 | 0 | keep | PROC-003 normalizer instance imbalance |
| 8167 | PROC-004 | stream | high | low | 0 | 0 | 0 | keep | PROC-004 filter instance imbalance |
| 8168 | PROC-005 | stream | high | low | 0 | 0 | 0 | keep | PROC-005 Normalizer parse error spike |
| 8169 | PROC-006 | stream | high | low | 0 | 0 | 0 | keep | PROC-006 Normalizer mapping error spike |
| 8170 | PROC-007 | stream | high | low | 0 | 0 | 0 | tune_threshold | PROC-007 JMESPath/YAML rule failed |
| 8172 | PROC-009 | stream | critical | low | 0 | 0 | 0 | keep | PROC-009 Filter pass rate zero |
| 8173 | PROC-010 | stream | medium | low | 0 | 0 | 0 | keep | PROC-010 Unknown event category spike |
| 8174 | PROC-011 | stream | medium | low | 0 | 0 | 0 | keep | PROC-011 Missing required normalized fields |
| 8176 | PROC-013 | stream | high | low | 0 | 0 | 0 | keep | PROC-013 Poison event loop |
| 8177 | PROC-014 | stream | high | low | 0 | 0 | 0 | keep | PROC-014 Rules reload failed |
| 8178 | PROC-015 | stream | high | low | 0 | 0 | 0 | keep | PROC-015 Rules version rollback |
| 8179 | PROC-016 | stream | high | low | 0 | 0 | 0 | keep | PROC-016 Standby writer active unexpectedly |
| 8180 | PROC-017 | stream | high | low | 0 | 0 | 0 | keep | PROC-017 Standby writer not ready |
| 8181 | PROC-018 | stream | critical | low | 0 | 0 | 0 | keep | PROC-018 Processing stopped receiving from Kafka |
| 8182 | PROC-019 | stream | critical | low | 0 | 0 | 0 | keep | PROC-019 Processing output to storage stopped |
| 8183 | PROC-020 | stream | critical | low | 0 | 0 | 0 | keep | PROC-020 Restart storm processing services |
| 8184 | STR-001 | stream | critical | low | 0 | 0 | 0 | keep | STR-001 clickhouse-server stopped |
| 8185 | STR-002 | stream | critical | low | 0 | 0 | 0 | keep | STR-002 siem-writer stopped |
| 8186 | STR-003 | stream | high | low | 0 | 0 | 0 | keep | STR-003 siem-writer-shadow stopped |
| 8187 | STR-004 | stream | critical | low | 0 | 0 | 0 | keep | STR-004 siem-stream-corr stopped |
| 8188 | STR-005 | stream | high | low | 0 | 0 | 0 | keep | STR-005 siem-batch-corr stopped |
| 8189 | STR-006 | stream | critical | low | 0 | 0 | 0 | keep | STR-006 siem-alert-agg stopped |
| 8190 | CH-001 | stream | critical | low | 0 | 0 | 0 | keep | CH-001 ClickHouse недоступен |
| 8191 | CH-002 | stream | critical | low | 0 | 0 | 0 | keep | CH-002 ClickHouse insert failed |
| 8192 | CH-003 | stream | high | low | 0 | 0 | 0 | keep | CH-003 ClickHouse query timeout |
| 8193 | CH-004 | stream | high | low | 0 | 0 | 0 | keep | CH-004 ClickHouse memory limit exceeded |
| 8194 | CH-005 | stream | high | low | 0 | 0 | 0 | keep | CH-005 ClickHouse too many parts |
| 8195 | CH-006 | stream | critical | low | 0 | 0 | 0 | keep | CH-006 ClickHouse disk full/readonly |
| 8196 | CH-007 | stream | critical | low | 0 | 0 | 0 | keep | CH-007 DROP/TRUNCATE/DELETE in SIEM DB |
| 8197 | CH-008 | stream | critical | low | 0 | 0 | 0 | keep | CH-008 ALTER TABLE SIEM schema |
| 8198 | CH-009 | stream | critical | low | 0 | 0 | 0 | keep | CH-009 CREATE USER/GRANT in ClickHouse |
| 8199 | CH-010 | stream | high | low | 0 | 0 | 0 | keep | CH-010 Login failure ClickHouse |
| 8200 | CH-011 | stream | critical | low | 0 | 0 | 0 | keep | CH-011 Query from non-allowed source |
| 8201 | CH-012 | stream | medium | low | 0 | 0 | 0 | keep | CH-012 Long query on hot tables |
| 8202 | CH-013 | stream | high | low | 0 | 0 | 0 | keep | CH-013 Massive SELECT export |
| 8203 | CH-014 | stream | high | low | 0 | 0 | 0 | keep | CH-014 Mutation backlog |
| 8204 | CH-015 | stream | high | low | 0 | 0 | 0 | keep | CH-015 Replication errors if used |
| 8205 | CH-016 | stream | medium | low | 0 | 0 | 0 | keep | CH-016 TTL/merge backlog |
| 8208 | WR-003 | stream | high | low | 0 | 0 | 0 | keep | WR-003 Writer shadow diverges |
| 8209 | WR-004 | stream | high | low | 0 | 0 | 0 | keep | WR-004 Dead-letter queue grows |
| 8217 | ALERT-001 | stream | high | low | 0 | 0 | 0 | keep | ALERT-001 Alert aggregator stopped grouping |
| 8218 | ALERT-002 | stream | high | low | 0 | 0 | 0 | keep | ALERT-002 Suppression rule too broad |
| 8219 | ALERT-003 | stream | high | low | 0 | 0 | 0 | keep | ALERT-003 Notification delivery failed |
| 8220 | ALERT-004 | stream | medium | low | 0 | 0 | 0 | keep | ALERT-004 Alert storm by one rule |
| 8222 | WEB-001 | stream | critical | low | 0 | 0 | 0 | keep | WEB-001 siem-web stopped |
| 8223 | WEB-002 | stream | high | low | 0 | 0 | 0 | keep | WEB-002 nginx stopped on web |
| 8224 | WEB-003 | stream | critical | low | 0 | 0 | 0 | keep | WEB-003 siem-keycloak stopped |
| 8225 | WEB-004 | stream | critical | low | 0 | 0 | 0 | keep | WEB-004 siem-vault stopped |
| 8226 | WEB-005 | stream | critical | low | 0 | 0 | 0 | keep | WEB-005 postgresql stopped on web |
| 8227 | WEB-006 | stream | high | low | 0 | 0 | 0 | keep | WEB-006 mongod stopped on web |
| 8228 | WEB-007 | stream | high | low | 0 | 0 | 0 | keep | WEB-007 siem-jump-tunnels stopped |
| 8229 | WEB-008 | stream | high | low | 0 | 0 | 0 | keep | WEB-008 SIEM UI/API 5xx spike |
| 8230 | WEB-009 | stream | medium | low | 0 | 0 | 0 | keep | WEB-009 SIEM UI/API 401/403 spike |
| 8231 | WEB-010 | stream | high | low | 1 | 1 | 0 | keep | WEB-010 Запросы к debug/admin/metrics извне |
| 8232 | WEB-011 | stream | high | low | 1 | 1 | 0 | keep | WEB-011 Path traversal/secret probing |
| 8233 | WEB-012 | stream | high | low | 1 | 1 | 0 | keep | WEB-012 SQLi/XSS/RCE pattern to SIEM UI |
| 8234 | WEB-013 | stream | high | low | 0 | 0 | 0 | keep | WEB-013 Nginx upstream siem-web unavailable |
| 8235 | WEB-014 | stream | high | low | 0 | 0 | 0 | keep | WEB-014 TLS cert expires soon |
| 8236 | WEB-015 | stream | medium | low | 0 | 0 | 0 | keep | WEB-015 TLS handshake error spike |
| 8237 | IAM-001 | stream | high | low | 0 | 0 | 0 | keep | IAM-001 Создан SSO-пользователь |
| 8238 | IAM-002 | stream | high | low | 0 | 0 | 0 | keep | IAM-002 Удалён SSO-пользователь |
| 8239 | IAM-003 | stream | high | low | 0 | 0 | 0 | keep | IAM-003 Пользователь включён/отключён |
| 8240 | IAM-004 | stream | high | low | 0 | 0 | 0 | keep | IAM-004 Создана роль |
| 8241 | IAM-005 | stream | high | low | 0 | 0 | 0 | keep | IAM-005 Изменена/удалена роль |
| 8242 | IAM-006 | stream | critical | low | 0 | 0 | 0 | keep | IAM-006 Назначена admin-роль |
| 8243 | IAM-007 | stream | high | low | 0 | 0 | 0 | keep | IAM-007 Создана группа/профиль доступа |
| 8244 | IAM-008 | stream | high | low | 0 | 0 | 0 | keep | IAM-008 Изменён профиль доступа |
| 8245 | IAM-009 | stream | critical | low | 0 | 0 | 0 | keep | IAM-009 Отключена MFA/OTP |
| 8246 | IAM-010 | stream | high | low | 0 | 0 | 0 | keep | IAM-010 Сброс пароля пользователя |
| 8247 | IAM-011 | stream | critical | low | 0 | 0 | 0 | keep | IAM-011 Сброс пароля администратора |
| 8248 | IAM-012 | stream | high | low | 0 | 0 | 0 | keep | IAM-012 Создан/изменён client |
| 8249 | IAM-013 | stream | critical | low | 0 | 0 | 0 | keep | IAM-013 Изменён redirect URI |
| 8250 | IAM-014 | stream | critical | low | 0 | 0 | 0 | keep | IAM-014 Создан/ротирован client secret |
| 8251 | IAM-015 | stream | critical | low | 0 | 0 | 0 | keep | IAM-015 Изменена политика паролей/realm settings |
| 8252 | IAM-016 | stream | high | low | 0 | 0 | 0 | keep | IAM-016 Массовые неуспешные входы SSO |
| 8254 | IAM-018 | stream | high | low | 0 | 0 | 0 | keep | IAM-018 Admin login в SIEM |
| 8257 | VAULT-001 | stream | critical | low | 0 | 0 | 0 | keep | VAULT-001 Vault sealed |
| 8258 | VAULT-002 | stream | critical | low | 3 | 2 | 1 | keep | VAULT-002 Vault unseal operation |
| 8259 | VAULT-003 | stream | critical | low | 0 | 0 | 0 | keep | VAULT-003 Vault root/admin token usage |
| 8260 | VAULT-004 | stream | critical | low | 4 | 3 | 1 | keep | VAULT-004 Vault policy changed |
| 8262 | PG-001 | stream | high | low | 0 | 0 | 0 | keep | PG-001 PostgreSQL auth failure spike |
| 8263 | PG-002 | stream | high | low | 0 | 0 | 0 | keep | PG-002 PostgreSQL superuser login |
| 8264 | PG-003 | stream | critical | low | 0 | 0 | 0 | keep | PG-003 PostgreSQL login from non-allowed host |
| 8265 | PG-004 | stream | critical | low | 0 | 0 | 0 | keep | PG-004 PostgreSQL DDL on app DB |
| 8266 | PG-005 | stream | critical | low | 0 | 0 | 0 | keep | PG-005 PostgreSQL mass export/copy |
| 8267 | PG-006 | stream | high | low | 1 | 0 | 1 | keep | PG-006 PostgreSQL too many connections |
| 8268 | PG-007 | stream | medium | low | 0 | 0 | 0 | keep | PG-007 PostgreSQL slow query spike |
| 8269 | PG-008 | stream | high | low | 1 | 1 | 0 | keep | PG-008 PostgreSQL restart/crash recovery |
| 8270 | PG-009 | stream | high | low | 0 | 0 | 0 | keep | PG-009 PostgreSQL config reload failed |
| 8271 | PG-010 | stream | critical | low | 0 | 0 | 0 | keep | PG-010 PostgreSQL role/grant changed |
| 8272 | MONGO-001 | stream | high | low | 0 | 0 | 0 | keep | MONGO-001 MongoDB auth failure spike |
| 8273 | MONGO-002 | stream | high | low | 0 | 0 | 0 | keep | MONGO-002 MongoDB admin/root login |
| 8274 | MONGO-003 | stream | critical | low | 0 | 0 | 0 | keep | MONGO-003 MongoDB access from non-allowed host |
| 8275 | MONGO-004 | stream | critical | low | 0 | 0 | 0 | keep | MONGO-004 MongoDB user/role changed |
| 8276 | MONGO-005 | stream | critical | low | 0 | 0 | 0 | keep | MONGO-005 MongoDB collection dropped |
| 8277 | MONGO-006 | stream | medium | low | 0 | 0 | 0 | keep | MONGO-006 MongoDB slow query spike |
| 8278 | MONGO-007 | stream | high | low | 0 | 0 | 0 | keep | MONGO-007 MongoDB replication/storage error |
| 8279 | MONGO-008 | stream | critical | low | 6 | 3 | 3 | keep | MONGO-008 MongoDB bind/access misconfiguration |
| 8280 | DB-001 | stream | critical | low | 0 | 0 | 0 | keep | DB-001 DB service stopped on critical host |
| 8281 | DB-002 | stream | high | low | 0 | 0 | 0 | keep | DB-002 DB backup failed |
| 8283 | DB-004 | stream | critical | low | 6 | 4 | 2 | keep | DB-004 DB dump file created in web-accessible path |
| 8284 | DB-005 | stream | high | low | 0 | 0 | 0 | keep | DB-005 DB credentials error spike |
| 8285 | DCK-001 | stream | critical | low | 2 | 0 | 2 | keep | DCK-001 docker service stopped |
| 8286 | DCK-002 | stream | critical | low | 2 | 0 | 2 | keep | DCK-002 containerd stopped |
| 8287 | DCK-003 | stream | medium | low | 0 | 0 | 0 | keep | DCK-003 New container created |
| 8288 | DCK-004 | stream | high | low | 0 | 0 | 0 | keep | DCK-004 Container started from new image |
| 8289 | DCK-005 | stream | critical | low | 0 | 0 | 0 | keep | DCK-005 Privileged container started |
| 8290 | DCK-006 | stream | critical | low | 0 | 0 | 0 | keep | DCK-006 Container with host network |
| 8291 | DCK-007 | stream | critical | low | 0 | 0 | 0 | keep | DCK-007 Container with host PID/IPC |
| 8292 | DCK-008 | stream | critical | low | 0 | 0 | 0 | keep | DCK-008 Docker socket mounted |
| 8293 | DCK-009 | stream | high | low | 0 | 0 | 0 | keep | DCK-009 Sensitive host path mounted |
| 8294 | DCK-010 | stream | high | low | 0 | 0 | 0 | keep | DCK-010 Container restart loop |
| 8295 | DCK-011 | stream | medium | low | 0 | 0 | 0 | keep | DCK-011 Container exited unexpectedly |
| 8296 | DCK-012 | stream | high | low | 0 | 0 | 0 | keep | DCK-012 Image pulled from unapproved registry |
| 8297 | DCK-013 | stream | high | low | 1 | 0 | 1 | keep | DCK-013 Docker login performed |
| 8298 | DCK-014 | stream | critical | low | 0 | 0 | 0 | keep | DCK-014 Docker API exposed |
| 8299 | DCK-015 | stream | high | low | 0 | 0 | 0 | keep | DCK-015 Container logs contain fatal/panic |
| 8300 | DCK-016 | stream | medium | low | 0 | 0 | 0 | keep | DCK-016 Container logs error spike |
| 8301 | DCK-017 | stream | medium | low | 0 | 0 | 0 | keep | DCK-017 Docker prune/remove image/container |
| 8302 | DCK-018 | stream | high | low | 0 | 0 | 0 | keep | DCK-018 OpenVAS container down |
| 8303 | DCK-019 | stream | critical | low | 2 | 2 | 0 | deduplicate | DCK-019 OpenClaw gateway container down |
| 8304 | DCK-020 | stream | high | low | 3 | 1 | 2 | keep | DCK-020 Pilot cache container down |
| 8305 | DCK-021 | stream | high | low | 3 | 2 | 1 | keep | DCK-021 Gamepanel/Wings container down |
| 8306 | DCK-022 | stream | high | low | 0 | 0 | 0 | keep | DCK-022 Container started with new published port |
| 8307 | DCK-023 | stream | critical | low | 1 | 1 | 0 | keep | DCK-023 Container env contains visible secret in logs |
| 8308 | DCK-024 | stream | medium | low | 0 | 0 | 0 | keep | DCK-024 Container CPU/RAM high |
| 8309 | DCK-025 | stream | high | low | 0 | 0 | 0 | keep | DCK-025 Docker disk usage high |
| 8310 | VULN-001 | stream | high | low | 0 | 0 | 0 | keep | VULN-001 OpenVAS/GVM UI unavailable |
| 8311 | VULN-002 | stream | info | low | 0 | 0 | 0 | keep | VULN-002 OpenVAS scan started |
| 8312 | VULN-003 | stream | medium | low | 0 | 0 | 0 | keep | VULN-003 OpenVAS scan outside window |
| 8313 | VULN-004 | stream | critical | low | 0 | 0 | 0 | keep | VULN-004 OpenVAS scans unapproved range |
| 8314 | VULN-005 | stream | medium | low | 0 | 0 | 0 | keep | VULN-005 New scan target created |
| 8315 | VULN-006 | stream | high | low | 0 | 0 | 0 | keep | VULN-006 Scan target changed |
| 8316 | VULN-007 | stream | critical | low | 0 | 0 | 0 | keep | VULN-007 Critical vulnerability found |
| 8317 | VULN-008 | stream | high | low | 0 | 0 | 0 | keep | VULN-008 High vulnerability found |
| 8318 | VULN-009 | stream | critical | low | 0 | 0 | 0 | keep | VULN-009 Рост Critical vulnerabilities |
| 8319 | VULN-010 | stream | high | low | 0 | 0 | 0 | keep | VULN-010 Feed update failed |
| 8320 | VULN-011 | stream | high | low | 0 | 0 | 0 | keep | VULN-011 Feeds stale |
| 8321 | VULN-012 | stream | high | low | 0 | 0 | 0 | keep | VULN-012 OpenVAS admin login |
| 8322 | VULN-013 | stream | high | low | 0 | 0 | 0 | keep | VULN-013 OpenVAS auth failures |
| 8323 | VULN-014 | stream | medium | low | 0 | 0 | 0 | keep | VULN-014 Report exported |
| 8324 | VULN-015 | stream | medium | low | 0 | 0 | 0 | keep | VULN-015 Scan errors spike |
| 8325 | PILOT-001 | stream | high | low | 0 | 0 | 0 | keep | PILOT-001 nginx stopped on pilot-web |
| 8326 | PILOT-002 | stream | high | low | 0 | 0 | 0 | keep | PILOT-002 Pilot web 5xx spike |
| 8327 | PILOT-003 | stream | medium | low | 0 | 0 | 0 | keep | PILOT-003 Pilot web 4xx scan pattern |
| 8328 | PILOT-004 | stream | high | low | 2 | 1 | 1 | keep | PILOT-004 Path traversal on pilot web |
| 8329 | PILOT-005 | stream | high | low | 1 | 0 | 1 | keep | PILOT-005 SQLi/RCE pattern on pilot web |
| 8330 | PILOT-006 | stream | high | low | 0 | 0 | 0 | keep | PILOT-006 Request to .env/secrets/backups |
| 8331 | PILOT-007 | stream | critical | low | 0 | 0 | 0 | keep | PILOT-007 PostgreSQL stopped on pilot-db |
| 8332 | PILOT-008 | stream | high | low | 0 | 0 | 0 | keep | PILOT-008 Telegram bot stopped/failed |
| 8333 | PILOT-009 | stream | high | low | 0 | 0 | 0 | keep | PILOT-009 Telegram bot delivery failed |
| 8334 | PILOT-010 | stream | high | low | 0 | 0 | 0 | keep | PILOT-010 Pilot DB auth failure spike |
| 8335 | PILOT-011 | stream | high | low | 0 | 0 | 0 | keep | PILOT-011 Pilot DB admin login |
| 8336 | PILOT-012 | stream | critical | low | 0 | 0 | 0 | keep | PILOT-012 Pilot DB access not from pilot-web/bot |
| 8337 | PILOT-013 | stream | critical | low | 0 | 0 | 0 | keep | PILOT-013 Pilot DB dump/export |
| 8338 | PILOT-014 | stream | high | low | 0 | 0 | 0 | keep | PILOT-014 Pilot DB schema changed |
| 8339 | PILOT-015 | stream | critical | low | 1 | 0 | 1 | keep | PILOT-015 Docker stopped on pilot-cache |
| 8340 | PILOT-016 | stream | high | low | 3 | 1 | 2 | keep | PILOT-016 Cache container down |
| 8341 | PILOT-017 | stream | critical | low | 0 | 0 | 0 | keep | PILOT-017 Redis/cache accessed not from trusted host |
| 8344 | PILOT-020 | stream | medium | low | 0 | 0 | 0 | keep | PILOT-020 Pilot public endpoint hit from unusual country |
| 8345 | GW-001 | stream | critical | low | 0 | 0 | 0 | deduplicate | GW-001 OpenClaw gateway container down |
| 8346 | GW-002 | stream | high | low | 0 | 0 | 0 | keep | GW-002 Gateway/proxy 5xx spike |
| 8347 | GW-003 | stream | high | low | 0 | 0 | 0 | keep | GW-003 Gateway upstream unavailable |
| 8348 | GW-004 | stream | high | low | 0 | 0 | 0 | keep | GW-004 New public route/proxy mapping |
| 8349 | GW-005 | stream | high | low | 0 | 0 | 0 | keep | GW-005 Admin endpoint exposed/hit |
| 8350 | GW-006 | stream | high | low | 0 | 0 | 0 | keep | GW-006 Suspicious inbound scan on gateway |
| 8352 | GW-008 | stream | high | low | 0 | 0 | 0 | keep | GW-008 TLS cert problem on gateway |
| 8353 | GW-009 | stream | high | low | 0 | 0 | 0 | keep | GW-009 Docker published new gateway port |
| 8355 | MC-001 | stream | high | low | 3 | 2 | 1 | keep | MC-001 Minecraft server stopped |
| 8356 | MC-002 | stream | high | low | 0 | 0 | 0 | keep | MC-002 Minecraft crash/restart loop |
| 8358 | MC-004 | stream | medium | low | 0 | 0 | 0 | keep | MC-004 Minecraft failed auth spike |
| 8359 | MC-005 | stream | high | low | 5 | 3 | 2 | keep | MC-005 Minecraft operator granted |
| 8360 | MC-006 | stream | high | low | 5 | 3 | 2 | keep | MC-006 Whitelist disabled |
| 8361 | MC-007 | stream | high | low | 0 | 0 | 0 | keep | MC-007 server.properties changed |
| 8362 | MC-008 | stream | critical | low | 0 | 0 | 0 | keep | MC-008 Log4Shell pattern |
| 8363 | NC-001 | stream | high | low | 0 | 0 | 0 | keep | NC-001 Nextcloud admin login |
| 8364 | NC-002 | stream | high | low | 0 | 0 | 0 | keep | NC-002 Nextcloud login failures |
| 8366 | NC-004 | stream | high | low | 0 | 0 | 0 | keep | NC-004 Nextcloud user created |
| 8367 | NC-005 | stream | critical | low | 1 | 1 | 0 | keep | NC-005 Nextcloud user got admin |
| 8368 | NC-006 | stream | medium | low | 0 | 0 | 0 | keep | NC-006 Public share created |
| 8369 | NC-007 | stream | high | low | 5 | 3 | 2 | keep | NC-007 Public share without password/expiry |
| 8370 | NC-008 | stream | high | low | 0 | 0 | 0 | keep | NC-008 Mass file downloads |
| 8371 | NC-009 | stream | high | low | 0 | 0 | 0 | keep | NC-009 Mass file deletion |
| 8372 | NC-010 | stream | high | low | 0 | 0 | 0 | keep | NC-010 Nextcloud app installed/enabled |
| 8373 | NC-011 | stream | medium | low | 0 | 0 | 0 | keep | NC-011 Nextcloud maintenance mode enabled |
| 8374 | NC-012 | stream | high | low | 0 | 0 | 0 | keep | NC-012 Nextcloud DB/PHP errors spike |
| 8375 | NAV-001 | stream | medium | low | 0 | 0 | 0 | keep | NAV-001 Navidrome admin login |
| 8376 | NAV-002 | stream | medium | low | 0 | 0 | 0 | keep | NAV-002 Navidrome failed logins |
| 8377 | NAV-003 | stream | medium | low | 0 | 0 | 0 | keep | NAV-003 Navidrome user created |
| 8379 | NAV-005 | stream | high | low | 1 | 1 | 0 | keep | NAV-005 Navidrome config changed |
| 8380 | NAV-006 | stream | medium | low | 0 | 0 | 0 | keep | NAV-006 Navidrome service unavailable |
| 8381 | GAME-001 | stream | high | low | 0 | 0 | 0 | keep | GAME-001 Создан новый сервер Pterodactyl |
| 8382 | GAME-002 | stream | high | low | 0 | 0 | 0 | keep | GAME-002 Удалён сервер Pterodactyl |
| 8383 | GAME-003 | stream | medium | low | 0 | 0 | 0 | keep | GAME-003 Изменены лимиты сервера |
| 8384 | GAME-004 | stream | high | low | 0 | 0 | 0 | keep | GAME-004 Изменён egg/image |
| 8385 | GAME-005 | stream | high | low | 0 | 0 | 0 | keep | GAME-005 Создан пользователь Pterodactyl |
| 8386 | GAME-006 | stream | critical | low | 0 | 0 | 0 | keep | GAME-006 Пользователь получил admin |
| 8387 | GAME-007 | stream | critical | low | 0 | 0 | 0 | keep | GAME-007 Создан API key |
| 8388 | GAME-008 | stream | medium | low | 0 | 0 | 0 | keep | GAME-008 Wings errors spike |
| 8389 | GAME-009 | stream | high | low | 0 | 0 | 0 | keep | GAME-009 Wings stopped/failed |
| 8390 | GAME-010 | stream | high | low | 0 | 0 | 0 | keep | GAME-010 Game server restart loop |
| 8391 | GAME-011 | stream | high | low | 0 | 0 | 0 | keep | GAME-011 New allocation/port created |
| 8392 | GAME-012 | stream | medium | low | 0 | 0 | 0 | keep | GAME-012 Suspicious console command |
| 8393 | WIN-001 | stream | high | low | 0 | 0 | 0 | keep | WIN-001 Успешный вход Administrator |
| 8394 | WIN-002 | stream | medium | low | 0 | 0 | 0 | keep | WIN-002 Неуспешный вход Administrator |
| 8395 | WIN-003 | stream | medium | low | 0 | 0 | 0 | keep | WIN-003 RDP login |
| 8397 | WIN-005 | stream | high | low | 0 | 0 | 0 | keep | WIN-005 Local user created |
| 8398 | WIN-006 | stream | high | low | 0 | 0 | 0 | keep | WIN-006 Local user deleted |
| 8399 | WIN-007 | stream | critical | low | 0 | 0 | 0 | keep | WIN-007 User added to Administrators |
| 8400 | WIN-008 | stream | high | low | 0 | 0 | 0 | keep | WIN-008 User removed from Administrators |
| 8401 | WIN-009 | stream | high | low | 0 | 0 | 0 | keep | WIN-009 Service created |
| 8402 | WIN-010 | stream | high | low | 0 | 0 | 0 | keep | WIN-010 Scheduled task created |
| 8403 | WIN-011 | stream | critical | low | 0 | 0 | 0 | keep | WIN-011 Security log cleared |
| 8404 | WIN-012 | stream | critical | low | 0 | 0 | 0 | keep | WIN-012 Windows Defender disabled |
| 8405 | WIN-013 | stream | critical | low | 0 | 0 | 0 | keep | WIN-013 Firewall disabled/changed |
| 8406 | WIN-014 | stream | critical | low | 0 | 0 | 0 | keep | WIN-014 Defender exclusion added |
| 8407 | WIN-015 | stream | critical | low | 0 | 0 | 0 | keep | WIN-015 PowerShell EncodedCommand |
| 8408 | WIN-016 | stream | critical | low | 0 | 0 | 0 | keep | WIN-016 PowerShell download cradle |
| 8409 | WIN-017 | stream | high | low | 0 | 0 | 0 | keep | WIN-017 Suspicious LOLBin |
| 8410 | WIN-018 | stream | high | low | 0 | 0 | 0 | keep | WIN-018 New process from temp/downloads |
| 8411 | WIN-019 | stream | critical | low | 0 | 0 | 0 | keep | WIN-019 LSASS access/dump |
| 8412 | WIN-020 | stream | critical | low | 0 | 0 | 0 | keep | WIN-020 Agent stopped/uninstalled |
| 8413 | WIN-021 | stream | high | low | 0 | 0 | 0 | keep | WIN-021 Mass failed logins |
| 8415 | WIN-023 | stream | medium | low | 0 | 0 | 0 | keep | WIN-023 New USB storage |
| 8416 | WIN-024 | stream | medium | low | 0 | 0 | 0 | keep | WIN-024 NVIDIA/GPU driver errors |
| 9001 | 9001 | stream | high | low | 0 | 0 | 0 | narrow_condition | Threat Intel IOC Match On Enriched Event |
| 9002 | 9002 | stream | high | low | 0 | 0 | 0 | narrow_condition | Repeated IOC Destination |
| 9003 | 9003 | stream | medium | low | 0 | 0 | 0 | keep | Network Port Scan Burst |
| 9004 | 9004 | stream | medium | low | 0 | 0 | 0 | keep | Suspicious Windows LOLBin Process Burst |
| 9005 | 9005 | stream | medium | low | 20 | 16 | 4 | narrow_condition | Repeated Non-Informational Network Destination |
| 9006 | 9006 | stream | high | low | 23 | 23 | 0 | narrow_condition | Protected Public IP Probe Burst |
| 9007 | 9007 | stream | high | low | 0 | 0 | 0 | keep | Protected Public SSH Spray |
