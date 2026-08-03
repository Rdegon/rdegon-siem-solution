# Unified rule inventory

The unified inventory is the backend source of truth for detection-rule views. It
reconciles, rather than copies, the following live sources:

- `siem.correlation_rules_stream`;
- `siem.correlation_rules_batch`;
- `siem.detection_rule_catalog`;
- authored `correlation_rule_packs/*.json` provenance.

## Identity and counts

Every numeric rule ID maps to one stable identity: `rule:<id>`. A catalog row and
stream/batch runtime rows with the same numeric ID are one rule, not multiple
rules. Duplicate MergeTree rows are collapsed to the row with the latest
`updated_ts`. A rule present in both runtimes has kind `hybrid` and both engines
are listed.

`rule_count` counts stable identities. `enabled_rule_count` and `coverage_count`
count enabled stable identities. Retired definitions linked through
`replacement_rule_id` remain visible but do not add active coverage. Normalizer
and filter counts are returned under `summary.linked_processing` and explicitly
do not contribute to detection-rule totals.

Noise fields come from grouped `siem.alerts_raw` data for a bounded 1-90 day
window. Per-rule execution cost is reported as unavailable until worker-level
instrumentation exists; the API does not fabricate a cost estimate.

## API

- `GET /api/rules/unified` (`resources:view`)
- `GET /api/rules/unified/{rule:<id>}` (`resources:view`)
- `POST /api/rules/unified/{rule:<id>}/publish` (`rules:write`)
- `POST /api/rules/unified/{rule:<id>}/enabled` (`rules:write`)

Search, status, engine and pack filters are applied after static ClickHouse
queries. User strings are never interpolated into SQL.

Publishing delegates to `publish_correlation_pack`. A stream rule can be
retired only when the request supplies a meaningful reason and a different,
currently enabled replacement rule. The pack is saved and republished through
the existing publisher, the operation is appended to the control-plane audit
chain, and the authored pack is rolled back if publication fails. Batch-only
rules remain read-only because the current platform has no safe callable batch
publisher; the API never claims that such an operation succeeded.
