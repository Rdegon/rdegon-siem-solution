ALTER TABLE siem.events
    MODIFY SETTING
        non_replicated_deduplication_window = 50000;
