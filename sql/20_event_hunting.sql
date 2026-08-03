CREATE TABLE IF NOT EXISTS siem.hunting_saved_searches
(
    tenant_id LowCardinality(String),
    owner String,
    search_id String,
    name String,
    description String,
    specification_json String,
    deleted UInt8 DEFAULT 0,
    revision UInt64,
    updated_at DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(revision)
ORDER BY (tenant_id, owner, search_id);
