# Incident Notification Aggregation

## Contract

The Telegram worker consumes only `GET /api/incidents?view=agg&scope=main`.
Raw alerts never produce Telegram cards directly. Each active aggregation scope has
one `delivery_key`, one durable PostgreSQL state row and at most one active Telegram
message id.

The stable key is resolved in this order:

1. `group_key.incident_key`;
2. `group_key.agg_id`;
3. the aggregated Web `agg_id` / `record_id`.

Changes to status, severity, assignee, title, hit count or hosts change the state
fingerprint and edit the existing card. They do not send a replacement card.
`closed`, `false_positive`, `expired`, `merged`, `suppressed` and
`suppressed_by_tuning` retract the active card. A failed delete is retried against
the same message id and is not counted as an active Web delivery.

## Durable Operation State

Before a Telegram call, the worker persists an operation key and state `prepared`.
After a confirmed response it commits the new fingerprint and message id. Retryable
edit/delete failures retain the previous fingerprint and message id so the same
operation is retried.

An interrupted initial send is intentionally marked `uncertain` and is not sent
again after restart. Telegram Bot API has no idempotency key or API for listing a
bot's own sent messages, so automatically replaying an ambiguous send could create
a duplicate. The uncertain state is exposed to Web delivery metrics for explicit
operator reconciliation.

## Queue Reconciliation

The worker expires cards absent from a complete Web queue snapshot after the stale
grace period. If `available_count` exceeds the returned page, reconciliation is
deferred. This prevents cards outside a limited page from being deleted and
re-created on the next poll.

Web metrics are calculated only for the aggregated incidents returned by the same
queue request. `active_cards` counts unique active message ids in that scope;
terminal/retracted rows are reported separately.

## Safety

- Tests stub every Telegram request and never use a live token or chat.
- Transport and API errors redact both Telegram and SIEM bearer tokens.
- Historical alerts and incidents are not deleted.
- The generic response-action Telegram executor remains an explicit operator action;
  it is not an automatic raw-alert notification path.
