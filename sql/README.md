# SQL Seeds

ClickHouse schema and rule seed SQL live here.

| File | Purpose |
| --- | --- |
| `10_detection_rule_catalog.sql` | Detection catalog base seed. |
| `11_event_schema_enrichment.sql` | Event schema enrichment seed. |
| `12_filter_rule_seed.sql` | Filter rule seed. |
| `13_batch_corr_seed.sql` | Batch correlation seed. |
| `14_cmdb_ti_enrichment.sql` | CMDB and threat-intel enrichment seed. |
| `15_batch_corr_soc_seed.sql` | SOC-oriented batch correlation seed. |
| `16_lab_cmdb_seed.sql` | Lab CMDB seed. |
| `17_lab_ti_seed.sql` | Lab threat-intel seed. |
| `18_security_analytics_schema.sql` | Searchable Zeek, endpoint, container, vulnerability, rule, and evidence fields. |
| `19_event_insert_deduplication.sql` | Enables deterministic insert-block deduplication for at-least-once Kafka writers. |

Publishing utilities that consume these files:

- `deploy/publish_filter_rules.py`
- `deploy/publish_batch_rules.py`
- `deploy/publish_rule_noise_tuning.py`
