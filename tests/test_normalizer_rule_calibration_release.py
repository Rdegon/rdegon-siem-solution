from deploy import normalizer_rule_calibration_release as release


def test_release_updates_both_processing_planes() -> None:
    assert release.TARGET_VMIDS == (105, 108)
    assert release.RELEASE_FILES == (
        "services/normalizer/normalizer_core.py",
        "services/normalizer/linux_service_normalizers.py",
        "services/normalizer/security_tool_normalizers.py",
    )
    assert set(release.NORMALIZER_UNITS) == {
        "siem-normalizer.service",
        "siem-normalizer@1.service",
        "siem-normalizer@2.service",
    }


def test_release_preserves_import_permissions_and_requires_active_units() -> None:
    source = (
        release.ROOT / "deploy" / "normalizer_rule_calibration_release.py"
    ).read_text(encoding="utf-8")
    assert "chmod 0755" in source
    assert "grep -c '^active$'" in source
    assert "test \\\"$(printf '%s\\\\n' \\\"$states\\\"" in source
