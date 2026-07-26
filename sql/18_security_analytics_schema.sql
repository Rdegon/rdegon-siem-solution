ALTER TABLE siem.events
    ADD COLUMN IF NOT EXISTS community_id String DEFAULT '',
    ADD COLUMN IF NOT EXISTS file_sha256 String DEFAULT '',
    ADD COLUMN IF NOT EXISTS container_id String DEFAULT '',
    ADD COLUMN IF NOT EXISTS vulnerability_id String DEFAULT '',
    ADD COLUMN IF NOT EXISTS rule_name String DEFAULT '',
    ADD COLUMN IF NOT EXISTS evidence_id String DEFAULT '';

ALTER TABLE siem.events_cold
    ADD COLUMN IF NOT EXISTS community_id String DEFAULT '',
    ADD COLUMN IF NOT EXISTS file_sha256 String DEFAULT '',
    ADD COLUMN IF NOT EXISTS container_id String DEFAULT '',
    ADD COLUMN IF NOT EXISTS vulnerability_id String DEFAULT '',
    ADD COLUMN IF NOT EXISTS rule_name String DEFAULT '',
    ADD COLUMN IF NOT EXISTS evidence_id String DEFAULT '';

ALTER TABLE siem.events
    ADD INDEX IF NOT EXISTS idx_community_id community_id TYPE bloom_filter(0.01) GRANULARITY 4,
    ADD INDEX IF NOT EXISTS idx_file_sha256 file_sha256 TYPE bloom_filter(0.01) GRANULARITY 4,
    ADD INDEX IF NOT EXISTS idx_vulnerability_id vulnerability_id TYPE bloom_filter(0.01) GRANULARITY 4,
    ADD INDEX IF NOT EXISTS idx_rule_name rule_name TYPE bloom_filter(0.01) GRANULARITY 4;

ALTER TABLE siem.events_cold
    ADD INDEX IF NOT EXISTS idx_community_id community_id TYPE bloom_filter(0.01) GRANULARITY 4,
    ADD INDEX IF NOT EXISTS idx_file_sha256 file_sha256 TYPE bloom_filter(0.01) GRANULARITY 4,
    ADD INDEX IF NOT EXISTS idx_vulnerability_id vulnerability_id TYPE bloom_filter(0.01) GRANULARITY 4,
    ADD INDEX IF NOT EXISTS idx_rule_name rule_name TYPE bloom_filter(0.01) GRANULARITY 4;
