from deploy import migrate_cmdb_replacing


def test_migration_uses_stable_asset_id_key_and_latest_version():
    class FakeProxmox:
        def __init__(self):
            self.queries = []

        def guest_exec(self, vmid, command, timeout=0):
            self.queries.append(command)
            if "SELECT engine FROM system.tables" in command:
                return "MergeTree\n"
            if "uniqExact(asset_id)" in command:
                return "14\t14\t14\n"
            return ""

    fake = FakeProxmox()
    result = migrate_cmdb_replacing.migrate(fake, 106)
    rendered = "\n".join(fake.queries)

    assert result == "migrated rows=14 keys=14"
    assert "ReplacingMergeTree(updated_ts)" in rendered
    assert "ORDER BY asset_id" in rendered
    assert "LIMIT 1 BY asset_id" in rendered
    assert "DROP TABLE siem.cmdb_assets_merge_tree_backup SYNC" in rendered
