from deploy import vuln_manager_boot_hardening


def test_boot_hardening_marks_efi_mount_optional():
    assert "nofail" in vuln_manager_boot_hardening.FSTAB_PATCH
    assert "x-systemd.device-timeout=10s" in vuln_manager_boot_hardening.FSTAB_PATCH


def test_boot_hardening_preserves_greenbone_autostart():
    class FakeProxmox:
        def __init__(self):
            self.commands = []

        def run(self, command, timeout=0):
            self.commands.append(("host", command, timeout))
            return ""

        def guest_exec(self, vmid, command, timeout=0):
            self.commands.append((vmid, command, timeout))
            return "active"

    fake = FakeProxmox()
    assert vuln_manager_boot_hardening.harden(fake) == "active"
    rendered = "\n".join(command for _, command, _ in fake.commands)
    assert "qm set 122 --onboot 1" in rendered
    assert "systemctl enable" in rendered
    assert "openvas.service" in rendered
    assert "vm.overcommit_memory = 1" in rendered
