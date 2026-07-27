# Endpoint Reference

This document reflects the live operator-facing API and entry surfaces on `VM4` as of `2026-03-27`.

Primary operator UX for current work is the React shell under `/app/*`.

Legacy pages such as `/dashboards` remain compatibility surfaces and are not the primary operator shell for the current closure layer.

## Entry And UI Routes

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/app` | Primary operator shell |
| `GET` | `/app/access` | Identity control center; deep-linkable `?tab=` workspace |
| `GET,POST` | `/auth/login` | Auth entrypoint; OIDC-first with break-glass local fallback |
| `GET` | `/auth/oidc/start` | OIDC authorization start |
| `GET` | `/auth/oidc/callback` | OIDC callback |
| `GET` | `/healthz` | Base web health check |
| `GET` | `/alerts` | Alerts page |
| `GET` | `/assets` | Assets page |
| `GET,POST` | `/dashboards` | Legacy dashboards page and create |
| `POST` | `/dashboards/delete` | Delete dashboard |
| `GET` | `/documentation` | Documentation page |
| `POST` | `/documentation/delete` | Delete document |
| `GET` | `/documentation/files/{doc_name}` | Document file page |
| `GET` | `/documentation/playbooks/{slug}` | Playbook page |
| `POST` | `/documentation/save` | Save document |
| `POST` | `/documentation/upload` | Upload document |
| `GET` | `/events` | Events page |
| `GET` | `/reports` | Reports page |
| `GET` | `/reports/{report_id}` | Report detail page |
| `GET` | `/resources` | Resources page |
| `GET` | `/sources` | Sources page |
| `GET` | `/collectors` | Collectors page |

## Auth And Access APIs

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/auth/me` | Current principal |
| `GET` | `/api/auth/providers` | Auth provider registry |
| `GET` | `/api/auth/governance` | Governance inventory |
| `GET` | `/api/auth/permissions` | Effective permissions |
| `GET,POST` | `/api/auth/break-glass` | Break-glass lifecycle |
| `GET,POST` | `/api/auth/service-accounts` | Service-account inventory and upsert |
| `GET,DELETE` | `/api/auth/service-accounts/{service_account_id}` | Service-account detail and delete |
| `GET,POST` | `/api/auth/service-accounts/{service_account_id}/tokens` | Token inventory and issue |
| `POST` | `/api/auth/service-accounts/{service_account_id}/rotate` | Service-account rotation |
| `POST` | `/api/auth/service-accounts/{service_account_id}/tokens/{token_id}/revoke` | Token revoke |
| `GET,POST` | `/api/auth/users` | Local-user inventory and upsert |
| `GET,DELETE` | `/api/auth/users/{username}` | Local-user detail and delete |
| `POST` | `/api/auth/users/{username}/password` | Local-user password rotation |
| `GET` | `/api/auth/keycloak/status` | Keycloak runtime and realm inventory health |
| `GET,POST` | `/api/auth/keycloak/users` | Keycloak user inventory and create |
| `GET,POST` | `/api/auth/keycloak/users/{user_id}` | Keycloak user detail and update |
| `POST` | `/api/auth/keycloak/users/{user_id}/password` | Keycloak password reset |
| `POST` | `/api/auth/keycloak/users/{user_id}/groups` | Keycloak group membership update |
| `POST` | `/api/auth/keycloak/users/{user_id}/roles` | Keycloak role assignment update |
| `GET,POST` | `/api/auth/keycloak/groups` | Keycloak group inventory and create |
| `POST` | `/api/auth/keycloak/groups/{group_id}` | Keycloak group update |
| `GET,POST` | `/api/auth/keycloak/roles` | Keycloak role inventory and create |
| `POST` | `/api/auth/keycloak/roles/{role_name}` | Keycloak role update |
| `GET,POST` | `/api/auth/keycloak/clients` | Keycloak client inventory and create |
| `GET,POST` | `/api/auth/keycloak/clients/{client_id}` | Keycloak client detail and update |
| `POST` | `/api/auth/keycloak/clients/{client_id}/secret/rotate` | Keycloak client secret rotation |

## Platform, Bootstrap, And Health APIs

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/ui/bootstrap` | Shell bootstrap metadata |
| `GET` | `/api/platform/status` | Platform KPI summary |
| `GET` | `/api/dashboard/summary` | Dashboard time-window summary |
| `GET` | `/api/control-plane/storage` | Control-plane backend state |
| `GET` | `/api/content/storage` | Content-store backend state |
| `GET` | `/api/health/overview` | Top-level production-green gate |
| `GET` | `/api/health/certification` | Production certification surface |
| `GET` | `/api/health/transport` | Kafka transport and shadow gate |
| `GET` | `/api/health/backups` | Backup-readiness gate |
| `GET` | `/api/health/storage` | Storage runtime summary |
| `GET` | `/api/health/storage-ha` | HA topology and failover gate |
| `GET` | `/api/health/hosts/runtime` | Host-runtime freshness gate |

## Ingest, Source, And Collector APIs

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/ingest/overview` | Proxied ingest health |
| `GET` | `/api/ingest/sources` | Proxied source heartbeat |
| `GET` | `/api/ingest/collectors` | Proxied collector heartbeat |
| `GET` | `/api/ingest/dlq` | DLQ inventory |
| `POST` | `/api/ingest/dlq/replay` | DLQ replay |
| `GET` | `/api/sources` | Source inventory |
| `GET` | `/api/sources/discovery` | Discovery candidates |
| `POST` | `/api/sources/discovery/scan` | Discovery scan |
| `POST` | `/api/sources/discovery/{candidate_id}/prepare` | Onboarding package prepare |
| `POST` | `/api/sources/discovery/jobs/{job_id}/execute` | Discovery execution |
| `GET` | `/api/collectors` | Collector inventory |
| `GET` | `/api/security-services` | SOC security-service telemetry catalog |
| `GET` | `/api/security-services/{service_id}` | NDR, DFIR, analysis, TI, PKI, or evidence-store detail |
| `POST` | `/api/assets/normalizers` | Asset normalizer save |

## Event, Incident, Case, And Entity APIs

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | `/api/events/query` | Event search |
| `GET` | `/api/incidents` | Incident inventory |
| `GET` | `/api/incidents/{view}/{record_id}` | Incident detail |
| `POST` | `/api/alerts/{view}/{record_id}` | Alert update |
| `GET` | `/api/alerts/{view}/{record_id}/history` | Alert history |
| `GET,POST` | `/api/cases` | Case inventory and upsert |
| `GET` | `/api/cases/{case_id}` | Case detail |
| `POST` | `/api/cases/{case_id}/comments` | Add comment |
| `POST` | `/api/cases/{case_id}/tasks` | Add task |
| `POST` | `/api/cases/{case_id}/evidence` | Add evidence |
| `GET` | `/api/entities` | Entity inventory |
| `GET` | `/api/entities/{entity_id}` | Entity detail |
| `POST` | `/api/entities/signals` | Record risk signal |
| `POST` | `/api/entities/{entity_id}/promote` | Promote entity to case |

## Connector, Builder, And Response APIs

| Method | Path | Notes |
| --- | --- | --- |
| `GET,POST` | `/api/connectors` | Connector inventory and upsert |
| `GET` | `/api/connectors/overview` | Connector overview |
| `GET` | `/api/connectors/{connector_id}` | Connector detail |
| `POST` | `/api/connectors/{connector_id}/run` | Connector execute |
| `POST` | `/api/connectors/{connector_id}/webhook` | Connector webhook preview |
| `GET,POST` | `/api/builders/drafts` | Draft inventory and save |
| `DELETE` | `/api/builders/drafts/{draft_id}` | Draft delete |
| `POST` | `/api/builders/validate` | Builder validate |
| `POST` | `/api/builders/test` | Builder test |
| `POST` | `/api/builders/publish/{draft_id}` | Builder publish |
| `GET` | `/api/correlation/packs` | Correlation pack inventory |
| `GET` | `/api/correlation/packs/{pack_id}` | Correlation pack detail |
| `POST` | `/api/correlation/packs` | Correlation pack save |
| `POST` | `/api/correlation/packs/{pack_id}/validate` | Correlation pack validate |
| `POST` | `/api/correlation/packs/{pack_id}/test` | Correlation pack test |
| `POST` | `/api/correlation/packs/{pack_id}/publish` | Correlation pack publish |
| `GET,POST` | `/api/response/actions` | Response action inventory and save |
| `POST` | `/api/response/actions/{action_id}/execute` | Response action execute |
| `GET` | `/api/response/executions` | Execution history |
| `POST` | `/api/response/executions/{execution_id}/approve` | Approve gated execution |
| `POST` | `/api/response/executions/{execution_id}/reject` | Reject gated execution |
| `POST` | `/api/response/executions/{execution_id}/retry` | Retry execution |
| `GET` | `/api/response/ledger` | Response execution ledger |
| `GET` | `/api/response/analytics` | Response analytics |
| `GET` | `/api/response/dlq` | Response DLQ |
| `POST` | `/api/response/dlq/{dlq_id}/replay` | Response DLQ replay |
| `POST` | `/api/rules/{rule_id}/test` | Rule test |

## Documentation, Content, Dashboard, And Control APIs

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/docs` | Runtime doc inventory |
| `GET` | `/api/docs/{doc_name}` | Runtime doc detail |
| `GET` | `/api/content/bundles` | Content-bundle inventory |
| `GET,POST` | `/api/dashboards` | Dashboard registry and save |
| `DELETE` | `/api/dashboards/{dashboard_id}` | Dashboard delete |
| `GET` | `/api/integrations/catalog` | Integration catalog |
| `GET` | `/api/playbooks` | Playbook inventory |
| `GET` | `/api/playbooks/{slug}` | Playbook detail |
| `GET,POST` | `/api/search/saved` | Saved-search inventory and save |
| `GET,POST` | `/api/lists/active` | Active-list inventory and save |
| `GET` | `/api/secrets/required` | Secret readiness inventory |
| `GET` | `/api/audit/events` | Audit-chain inventory |
| `POST` | `/api/resources/archive-hot` | Hot-event archive operation |

## Asset, Geo, Threat, And Vulnerability APIs

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/assets/catalog` | Asset catalog |
| `GET` | `/api/assets/inventory` | Asset inventory |
| `GET,POST` | `/api/assets/binding-overrides` | Operator-managed binding overrides |
| `POST` | `/api/assets/binding-overrides/{override_id}` | Binding override update |
| `DELETE` | `/api/assets/binding-overrides/{override_id}` | Binding override delete |
| `GET` | `/api/geo/sources` | Source geography |
| `GET` | `/api/geo/vpn` | VPN geography |
| `GET` | `/api/geo/ip/{ip_text}` | IP geography detail |
| `GET` | `/api/geo/countries/{country_name}` | Country geography detail |
| `GET` | `/api/threat-intel/overview` | Threat-intel overview |
| `GET` | `/api/vuln/integration-contract` | Vulnerability integration contract |
| `POST` | `/api/vuln/import` | Structured vulnerability import |
| `POST` | `/api/vuln/sync` | Vulnerability sync trigger |
| `GET` | `/api/vuln/runtime` | Vulnerability runtime gate |
| `GET` | `/api/vuln/maturity` | Vulnerability maturity gate |
| `GET` | `/api/vuln/workbench` | Risk-based exposure queue with KEV, EPSS and SLA |
| `GET` | `/api/vuln/overview` | Vulnerability overview |
| `GET` | `/api/vuln/findings` | Finding inventory |
| `GET` | `/api/vuln/hosts` | Host inventory |
| `GET` | `/api/vuln/software` | Software inventory |
| `GET` | `/api/vuln/cves` | CVE inventory |
| `POST` | `/api/vuln/policies/apply` | Policy application |
| `POST` | `/api/vuln/intelligence/sync` | Refresh CISA KEV and FIRST EPSS cache |
| `POST` | `/api/vuln/exposure/apply` | Create risk-based remediation cases and tasks |
| `POST` | `/api/vuln/scans/start` | Start targeted scans for current CMDB bindings |

## Reports APIs

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/reports` | Structured report inventory |
| `GET` | `/api/reports/{report_id}` | Report detail |
| `GET` | `/api/reports/{report_id}/artifact` | Artifact download or retrieval |

## Production-Green Subset

The release gate uses these endpoints as the operational truth:

- `GET /api/health/overview`
- `GET /api/health/certification`
- `GET /api/health/transport`
- `GET /api/health/backups`
- `GET /api/health/storage-ha`
- `GET /api/health/hosts/runtime`
- `GET /api/vuln/runtime`
- `GET /api/vuln/maturity`
- `GET /api/vuln/workbench`
- `GET /api/reports`
