from deploy.soc_host_runtime_deploy import TARGETS, _selected_targets, render_environment


def test_runtime_targets_cover_current_linux_fleet():
    assert {target.vmid for target in TARGETS} == {
        100,
        102,
        104,
        105,
        106,
        107,
        108,
        120,
        121,
        122,
        123,
        124,
        125,
        127,
        128,
        129,
        130,
        131,
        132,
        133,
    }


def test_runtime_environment_requires_trusted_ingest_tls():
    rendered = render_environment(_selected_targets("127")[0])
    assert "SIEM_HOST_RUNTIME_INGEST_TLS_VERIFY=required" in rendered
    assert "SIEM_HOST_RUNTIME_INGEST_CA_FILE=/etc/siem/pki/ingest-ca.crt" in rendered
    assert "disabled" not in rendered


def test_runtime_target_selection_rejects_unknown_vmids():
    try:
        _selected_targets("999")
    except ValueError as exc:
        assert "999" in str(exc)
    else:
        raise AssertionError("Unknown VMID must be rejected")
