# SOAR / Response Hardening: 2026-03-26

## Status

The SOAR hardening slice is now operationally complete for the current platform baseline.

The response plane now provides:

- idempotent execution ledger
- retries and DLQ replay for response actions
- approval quorum and rejection flow
- response policy packs and reusable playbook templates
- stronger linkage between detections, cases, findings, and actions
- analytics for trigger mix, approval modes, and linked executions

## Authoritative API Surfaces

- `GET /api/response/actions`
- `POST /api/response/actions`
- `POST /api/response/actions/{action_id}/execute`
- `GET /api/response/executions`
- `POST /api/response/executions/{execution_id}/approve`
- `POST /api/response/executions/{execution_id}/reject`
- `POST /api/response/executions/{execution_id}/retry`
- `GET /api/response/ledger`
- `GET /api/response/analytics`
- `GET /api/response/dlq`
- `POST /api/response/dlq/{dlq_id}/replay`

## Execution Model

Each action now carries:

- `policy_pack_id`
- `approval`
- `owners`
- `trigger_kinds`
- `default_linkage`
- optional chained `steps`

Each execution now carries:

- `approval`
- `linkage`
- `policy_pack_id`
- approval and rejection actor/timestamp fields
- retry and DLQ lineage

## Approval Semantics

Supported approval modes:

- `none`
- `single`
- `two_man`

Approval state supports:

- minimum approver count
- required roles
- expiry window
- operator note on approval
- operator reason on rejection

## UI / UX Surfaces

The React shell response page now exposes:

- policy pack cards
- operator playbook templates
- action registry with pack/approval/trigger summary
- editor fields for linkage, ownership, trigger kinds, and approval rules
- execution queue with approve / reject / retry controls
- ledger and DLQ drawers for payload inspection

The intent is to let the operator stay on one response surface instead of pivoting between response, cases, and raw JSON just to understand whether an action is safe to run.

## Remaining Strategic Follow-Up

This slice does not yet claim:

- provider-deep SOAR integrations for every downstream system
- multi-step human approval routing with delegation / escalation
- response sandboxing per provider tenant
- fully policy-driven action dispatch from every detection family

Those remain next-layer maturity work, not blockers for the current operational baseline.
