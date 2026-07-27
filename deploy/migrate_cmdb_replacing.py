from __future__ import annotations

import argparse
import shlex

try:
    from deploy.soc_foundation_provision import Proxmox
except ModuleNotFoundError:
    from soc_foundation_provision import Proxmox


PRIMARY_VMID = 106
STANDBY_VMID = 108
TABLE = "siem.cmdb_assets"
TEMP_TABLE = "siem.cmdb_assets_replacing_migration"
BACKUP_TABLE = "siem.cmdb_assets_merge_tree_backup"


def _query(pve: Proxmox, vmid: int, sql: str, timeout: int = 300) -> str:
    return pve.guest_exec(
        vmid,
        f"clickhouse-client --multiquery --query {shlex.quote(sql)}",
        timeout=timeout,
    )


def migrate(pve: Proxmox, vmid: int) -> str:
    engine = _query(
        pve,
        vmid,
        "SELECT engine FROM system.tables "
        "WHERE database='siem' AND name='cmdb_assets' FORMAT TSV",
        timeout=60,
    ).strip()
    if engine == "ReplacingMergeTree":
        return "already_replacing"
    if engine != "MergeTree":
        raise RuntimeError(f"Unexpected {TABLE} engine on VM{vmid}: {engine or 'missing'}")

    sql = f"""
    DROP TABLE IF EXISTS {TEMP_TABLE} SYNC;
    DROP TABLE IF EXISTS {BACKUP_TABLE} SYNC;
    CREATE TABLE {TEMP_TABLE} AS {TABLE}
    ENGINE = ReplacingMergeTree(updated_ts)
    ORDER BY asset_id;
    INSERT INTO {TEMP_TABLE}
    SELECT *
    FROM {TABLE}
    ORDER BY updated_ts DESC
    LIMIT 1 BY asset_id;
    RENAME TABLE
        {TABLE} TO {BACKUP_TABLE},
        {TEMP_TABLE} TO {TABLE};
    """
    _query(pve, vmid, sql, timeout=600)
    counts = _query(
        pve,
        vmid,
        f"""
        SELECT
            (SELECT count() FROM {TABLE}),
            (SELECT uniqExact(asset_id) FROM {TABLE}),
            (SELECT uniqExact(asset_id) FROM {BACKUP_TABLE})
        FORMAT TSV
        """,
        timeout=120,
    ).strip()
    current_rows, current_keys, backup_keys = (int(item) for item in counts.split("\t"))
    if current_rows != current_keys or current_keys != backup_keys:
        raise RuntimeError(
            f"CMDB migration verification failed on VM{vmid}: {counts}"
        )
    _query(pve, vmid, f"DROP TABLE {BACKUP_TABLE} SYNC", timeout=300)
    return f"migrated rows={current_rows} keys={current_keys}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Migrate the small CMDB table away from per-asset mutations"
    )
    parser.add_argument(
        "--vmids",
        default=f"{PRIMARY_VMID},{STANDBY_VMID}",
        help="Comma-separated ClickHouse VM IDs",
    )
    args = parser.parse_args()
    vmids = [int(item.strip()) for item in args.vmids.split(",") if item.strip()]
    with Proxmox() as pve:
        for vmid in vmids:
            print(f"VM{vmid}: {migrate(pve, vmid)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
