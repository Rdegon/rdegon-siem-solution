from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.runtime_imports import import_app_module  # noqa: E402


deps = import_app_module("deps")
ASSIGNEE = "system-fp-calibration-20260728"
RECOVERY_ASSIGNEE = "system-recovery-validation-20260728"
OPEN_STATUSES = (
    "lower(status) NOT IN ('closed', 'false_positive', 'resolved', 'suppressed')"
)


def _managed_unit_predicate() -> str:
    return """
    (
        rule_id = 2706
        AND
        (
            positionCaseInsensitiveUTF8(entity_key, '/etc/systemd/system/siem-') > 0
            OR positionCaseInsensitiveUTF8(entity_key, '/etc/systemd/system/velociraptor-client.service') > 0
            OR positionCaseInsensitiveUTF8(entity_key, '60-static-kafka-member.conf') > 0
            OR
            (
                positionCaseInsensitiveUTF8(entity_key, '/etc/systemd/system/snap-') > 0
                AND positionCaseInsensitiveUTF8(entity_key, '.mount') > 0
            )
            OR
            (
                positionCaseInsensitiveUTF8(
                    entity_key,
                    'siem-ingest|/etc/systemd/system/snap.lxd.'
                ) > 0
                AND ts_last <= toDateTime('2026-07-28 14:10:00')
            )
        )
    )
    """


def _false_positive_predicate(table_name: str) -> str:
    evidence_column = "context_json" if table_name.endswith("alerts_raw") else "samples_json"
    pve_hit_guard = "AND hits = 59" if table_name.endswith("alerts_raw") else ""
    return f"""
    (
        {_managed_unit_predicate()}
        OR (rule_id IN (8011, 8012) AND entity_key = 'opnsense-staging')
        OR (rule_id = 8012 AND entity_key = 'soc-ti-01')
        OR
        (
            rule_id = 8121
            AND entity_key = '10.20.10.105|1.1.1.1'
            AND ts_last <= toDateTime('2026-07-27 22:00:00')
        )
        OR
        (
            rule_id IN (8418, 8420, 8425, 8426, 8429)
            AND entity_key = 'gamepanel-01'
            AND positionCaseInsensitiveUTF8(
                toString({evidence_column}),
                'assignment_batch_rule'
            ) > 0
        )
        OR
        (
            rule_id = 8426
            AND entity_key IN ('nextcloud-siem', 'soc-pki-01')
            AND ts_last <= toDateTime('2026-07-28 00:42:00')
            AND positionCaseInsensitiveUTF8(
                toString({evidence_column}),
                'sustained_load_pressure'
            ) > 0
        )
        OR
        (
            rule_id = 2704
            AND entity_key IN
            (
                'lab-edge-01|/etc/cron.d',
                'lab-edge-01|/etc/cron.daily',
                'lab-edge-01|/etc/cron.hourly',
                'lab-edge-01|/etc/cron.monthly',
                'lab-edge-01|/etc/cron.weekly',
                'siem-storage|/etc/cron.d',
                'siem-storage|/etc/cron.daily',
                'siem-storage|/etc/cron.hourly',
                'siem-storage|/etc/cron.monthly',
                'siem-storage|/etc/cron.weekly',
                'siem-storage|/var/spool/cron'
            )
            AND ts_last <= toDateTime('2026-07-28 10:00:00')
        )
        OR
        (
            rule_id = 2709
            AND entity_key = 'siem-storage'
            AND ts_last <= toDateTime('2026-07-28 10:00:00')
        )
        OR
        (
            rule_id = 2715
            AND entity_key IN
            (
                'lab-edge-01',
                'lab-edge-01|/etc/audit/rules.d',
                'siem-storage',
                'siem-storage|/etc/audit/rules.d'
            )
            AND ts_last <= toDateTime('2026-07-28 10:00:00')
        )
        OR
        (
            rule_id = 2617
            AND entity_key = '192.168.3.103'
            AND ts_last <= toDateTime('2026-07-28 10:00:00')
        )
        OR
        (
            rule_id = 2726
            AND entity_key = 'lab-edge-01'
            AND
            (
                positionCaseInsensitiveUTF8(
                    toString({evidence_column}),
                    '"process_command": "who -q"'
                ) > 0
                OR
                (
                    ts_last <= toDateTime('2026-07-28 12:27:00')
                    AND
                    (
                        positionCaseInsensitiveUTF8(
                            toString({evidence_column}),
                            '"process_command": "uname -m"'
                        ) > 0
                        OR positionCaseInsensitiveUTF8(
                            toString({evidence_column}),
                            '"process_command": "uname -o"'
                        ) > 0
                        OR positionCaseInsensitiveUTF8(
                            toString({evidence_column}),
                            '"process_command": "uname -r"'
                        ) > 0
                    )
                )
            )
        )
        OR (rule_id = 8305 AND entity_key = 'minecraft-01')
        OR
        (
            rule_id = 8221
            AND entity_key = 'lab-edge-01'
            AND ts_last <= toDateTime('2026-07-28 12:40:00')
        )
        OR
        (
            rule_id = 8047
            AND entity_key = '192.168.3.101'
            {pve_hit_guard}
            AND ts_last = toDateTime('2026-07-28 11:17:41')
        )
        OR
        (
            rule_id = 8077
            AND entity_key = 'siem-transport|10.20.10.108'
            AND ts_last <= toDateTime('2026-07-28 12:07:00')
            AND positionCaseInsensitiveUTF8(
                toString({evidence_column}),
                'audit_service_stop'
            ) > 0
        )
        OR
        (
            rule_id IN (8001, 8002)
            AND entity_key = 'win-rtx-test'
            AND ts_last <= toDateTime('2026-07-28 00:00:00')
        )
        OR
        (
            rule_id = 8429
            AND entity_key = 'siem-processing|siem-normalizer'
            AND ts_last <= toDateTime('2026-07-28 12:22:00')
            AND positionCaseInsensitiveUTF8(
                toString({evidence_column}),
                'service_restart_loop'
            ) > 0
        )
        OR
        (
            rule_id = 2902
            AND entity_key = 'pilot-web-01'
            AND ts_last <= toDateTime('2026-07-28 13:34:00')
            AND positionCaseInsensitiveUTF8(
                toString({evidence_column}),
                'qemu-ga'
            ) > 0
        )
        OR
        (
            rule_id = 8046
            AND entity_key = 'pve'
            AND ts_last <= toDateTime('2026-07-28 14:02:00')
            AND positionCaseInsensitiveUTF8(
                toString({evidence_column}),
                'proxmox_authentication_success'
            ) > 0
        )
        OR
        (
            rule_id = 8328
            AND entity_key = 'pilot-web-01'
            AND ts_last <= toDateTime('2026-07-28 13:41:00')
            AND positionCaseInsensitiveUTF8(
                toString({evidence_column}),
                'pilot-gitea'
            ) > 0
        )
    )
    AND {OPEN_STATUSES}
    """


def _resolved_predicate() -> str:
    return f"""
    (
        (rule_id = 2108 AND entity_key = 'siem-storage')
        OR
        (
            rule_id = 8429
            AND entity_key IN
            (
                'siem-storage|siem-stream-corr',
                'siem-storage|siem-batch-corr'
            )
        )
        OR
        (
            rule_id = 8004
            AND entity_key IN
            (
                'siem-ingest',
                'siem-processing',
                'siem-storage',
                'siem-transport'
            )
        )
        OR
        (
            rule_id = 8425
            AND entity_key IN
            (
                'siem-processing',
                'vuln-mgr-01',
                'pilot-db-01'
            )
            AND ts_last <= toDateTime('2026-07-28 11:16:00')
        )
        OR
        (
            rule_id = 8212
            AND entity_key = 'siem-stream-corr'
            AND ts_last <= toDateTime('2026-07-28 09:48:00')
        )
        OR (rule_id = 8355 AND entity_key = 'minecraft-01')
        OR
        (
            rule_id IN (8084, 8097)
            AND entity_key = 'lab-edge-01|unbound.service'
            AND ts_last <= toDateTime('2026-07-28 04:00:00')
        )
        OR (rule_id = 2102 AND entity_key = 'soc-ti-01')
    )
    AND {OPEN_STATUSES}
    """


def _count(table_name: str, predicate: str) -> int:
    result = deps.get_ch_client().query(
        f"SELECT count() FROM {table_name} WHERE {predicate}"
    ).result_rows
    return int(result[0][0]) if result and result[0] else 0


def _apply_status(
    table_name: str,
    *,
    predicate: str,
    status: str,
    assignee: str,
) -> dict[str, int]:
    before = _count(table_name, predicate)
    if before:
        deps.get_ch_client().command(
            f"""
            ALTER TABLE {table_name}
            UPDATE
                status = '{status}',
                assignee = '{assignee}',
                updated_ts = now()
            WHERE {predicate}
            SETTINGS mutations_sync = 2
            """
        )
    after = _count(table_name, predicate)
    if after:
        raise RuntimeError(
            f"Rows with target status {status} remain in {table_name}: {after}"
        )
    return {"before": before, "after": after}


def main() -> int:
    deps.ensure_incident_workflow_support()
    results: dict[str, dict[str, dict[str, int]]] = {}
    for table_name in ("siem.alerts_raw", "siem.alerts_agg"):
        results[table_name] = {
            "false_positive": _apply_status(
                table_name,
                predicate=_false_positive_predicate(table_name),
                status="false_positive",
                assignee=ASSIGNEE,
            ),
            "resolved": _apply_status(
                table_name,
                predicate=_resolved_predicate(),
                status="resolved",
                assignee=RECOVERY_ASSIGNEE,
            ),
        }

    protected = deps.get_ch_client().query(
        """
        SELECT rule_id, entity_key
        FROM siem.alerts_agg FINAL
        WHERE lower(status) NOT IN ('closed', 'false_positive', 'resolved', 'suppressed')
          AND
          (
              rule_id = 2604
              OR rule_id = 4005
          )
        ORDER BY rule_id, entity_key
        """
    ).result_rows
    print(
        json.dumps(
            {
                "updated": results,
                "protected_open_incidents": [
                    {"rule_id": int(row[0]), "entity_key": str(row[1])}
                    for row in protected
                ],
            },
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
