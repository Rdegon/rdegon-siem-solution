import json
from pathlib import Path

from deploy.proxmox_resource_rightsize import (
    LXC_LIMITS_MB,
    OPENCLAW_RULE_IDS,
    PRIMARY_CLICKHOUSE_CONFIG,
    RESTART_ORDER,
    SIEM_PROFILES,
    STORAGE_SYSTEM_DISK,
    STANDBY_CLICKHOUSE_CONFIG,
    _replace_env_values,
)

ROOT = Path(__file__).resolve().parents[1]


def test_siem_profile_preserves_role_headroom() -> None:
    profiles = {profile.vmid: profile for profile in SIEM_PROFILES}
    assert profiles[104].balloon_mb >= 8_192
    assert profiles[105].balloon_mb >= 10_240
    assert profiles[106].balloon_mb >= 18_432
    assert profiles[107].balloon_mb >= 8_192
    assert profiles[108].balloon_mb >= 8_192
    assert all(profile.memory_mb >= profile.balloon_mb for profile in SIEM_PROFILES)
    assert set(RESTART_ORDER) == set(profiles)


def test_clickhouse_caps_fit_guest_profiles() -> None:
    assert "12884901888" in PRIMARY_CLICKHOUSE_CONFIG
    assert "6442450944" in STANDBY_CLICKHOUSE_CONFIG
    storage = next(profile for profile in SIEM_PROFILES if profile.vmid == 106)
    transport = next(profile for profile in SIEM_PROFILES if profile.vmid == 108)
    assert 12 * 1024 < storage.balloon_mb
    assert 6 * 1024 < transport.balloon_mb
    assert STORAGE_SYSTEM_DISK == "toshiba1ter:106/vm-106-disk-1.qcow2"


def test_openclaw_retirement_covers_source_specific_rules() -> None:
    assert {2301, 2303, 2304, 2305, 8303, 8345, 8354, 8470}.issubset(
        set(OPENCLAW_RULE_IDS)
    )


def test_openclaw_rules_cannot_be_republished_active() -> None:
    detection_pack = json.loads(
        (ROOT / "correlation_rule_packs" / "siem_detection_pack_v1.json").read_text(
            encoding="utf-8"
        )
    )
    rules_by_id = {
        int(rule["id"]): rule
        for rule in (
            detection_pack["stream_rules"] + detection_pack["batch_rules"]
        )
    }
    for rule_id in (8303, 8345, 8354, 8470):
        assert rules_by_id[rule_id]["status"] == "retired_asset"

    openclaw_pack = json.loads(
        (ROOT / "correlation_rule_packs" / "openclaw_behavior_v1.json").read_text(
            encoding="utf-8"
        )
    )
    source_rules = {
        int(rule["id"]): rule
        for rule in openclaw_pack["stream_rules"] + openclaw_pack["batch_rules"]
    }
    for rule_id in (2301, 2303, 2304, 2305):
        assert source_rules[rule_id]["status"] == "retired_asset"


def test_lxc_limits_leave_analysis_workloads_unchanged() -> None:
    assert LXC_LIMITS_MB == {100: 8_192, 120: 4_096, 121: 2_048}


def test_replace_env_values_preserves_unrelated_settings() -> None:
    rendered = _replace_env_values(
        "SIEM_OPENCLAW_PROXY_URL=http://old\nKEEP=value\n",
        {
            "SIEM_OPENCLAW_PROXY_URL": "",
            "SIEM_TELEGRAM_PROXY_URL": "",
        },
    )
    assert rendered == (
        "SIEM_OPENCLAW_PROXY_URL=\n"
        "KEEP=value\n"
        "SIEM_TELEGRAM_PROXY_URL=\n"
    )
