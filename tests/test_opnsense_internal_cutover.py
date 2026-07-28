from deploy.network.opnsense_internal_cutover import (
    GUESTS,
    _ct_live_script,
    _lab_edge_unbound_script,
    _vm_script,
)


def test_cutover_inventory_covers_all_running_internal_guests() -> None:
    assert {guest.vmid for guest in GUESTS} == {
        100,
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


def test_cutover_uses_segment_local_opnsense_gateway() -> None:
    for guest in GUESTS:
        assert guest.new_gateway.endswith(".254")
        assert guest.old_gateway.endswith(".1")


def test_guest_scripts_verify_route_dns_and_ingest() -> None:
    vm_script = _vm_script("10.20.10.1", "10.20.10.254", "test")
    ct_script = _ct_live_script("10.20.20.254")
    assert "netplan generate" in vm_script
    assert "10\\.20\\.10\\.1([^0-9]|$)" in vm_script
    assert "legacy-disabled" in vm_script
    assert "1\\.1\\.1\\.1" in vm_script
    assert "10.20.10.104/health" in vm_script
    assert "ip route replace default via 10.20.20.254" in ct_script
    assert "getent ahostsv4 github.com >/dev/null" in ct_script


def test_cutover_rebinds_lab_edge_unbound_after_gateway_move() -> None:
    apply_script = _lab_edge_unbound_script(rollback=False)
    rollback_script = _lab_edge_unbound_script(rollback=True)

    assert 'mode == "apply"' in apply_script
    assert "legacy_interfaces" in apply_script
    assert 'target = "10.20.10.1" if mode == "rollback" else "192.168.3.102"' in apply_script
    assert "systemctl restart unbound.service" in apply_script
    assert "ss -lunt | grep -q '192.168.3.102:53'" in apply_script
    assert "python3 - \"$conf\" apply" in apply_script
    assert "python3 - \"$conf\" rollback" in rollback_script
