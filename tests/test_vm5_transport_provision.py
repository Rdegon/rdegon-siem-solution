import unittest

from deploy import vm5_transport_provision as vm5_provision


class VM5TransportProvisionTests(unittest.TestCase):
    def test_render_vm5_netplan_uses_static_lab_address(self) -> None:
        payload = vm5_provision.render_vm5_netplan()

        self.assertIn("ens19:", payload)
        self.assertIn("- 192.168.1.40/24", payload)
        self.assertIn("via: 192.168.1.1", payload)
        self.assertIn("addresses: [192.168.1.1]", payload)

    def test_render_vm5_resolved_conf_points_to_lab_dns(self) -> None:
        payload = vm5_provision.render_vm5_resolved_conf()

        self.assertIn("[Resolve]", payload)
        self.assertIn("DNS=192.168.1.1", payload)
        self.assertIn("FallbackDNS=1.1.1.1 8.8.8.8", payload)

    def test_guest_personalization_script_writes_expected_files(self) -> None:
        payload = vm5_provision.build_guest_personalization_script(
            hostname="siem-transport",
            netplan_content="network:\n  version: 2\n",
            resolved_conf_content="[Resolve]\nDNS=192.168.1.1\n",
        )

        self.assertIn("Path('/etc/hostname').write_text", payload)
        self.assertIn("Path('/etc/netplan/01-siem.yaml').write_text", payload)
        self.assertIn("Path('/etc/systemd/resolved.conf').write_text", payload)
        self.assertIn("hostnamectl', 'set-hostname', hostname", payload)
        self.assertIn("systemctl', 'restart', 'ssh'", payload)
        self.assertIn("systemctl', 'restart', 'qemu-guest-agent'", payload)


if __name__ == "__main__":
    unittest.main()
