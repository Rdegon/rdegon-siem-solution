from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from deploy.vm2_processing_resilience_deploy import (
    PROCESSING_SYNC_PATHS,
    VM2_NETPLAN_CONTENT,
    VM2_RESOLVED_CONF_CONTENT,
    _resolve_bash_path,
    _sync_processing_runtime,
    update_redis_conf,
)


class Vm2ProcessingResilienceTests(unittest.TestCase):
    def test_update_redis_conf_rewrites_and_appends_required_settings(self) -> None:
        text = "\n".join(
            [
                "bind 127.0.0.1 192.168.1.37",
                "appendonly no",
                "appendfsync no",
                "save 900 1",
                "",
            ]
        )

        updated = update_redis_conf(text)

        self.assertIn("appendonly yes", updated)
        self.assertIn("appendfsync everysec", updated)
        self.assertIn("auto-aof-rewrite-percentage 100", updated)
        self.assertIn("auto-aof-rewrite-min-size 64mb", updated)
        self.assertNotIn("appendonly no", updated)
        self.assertNotIn("appendfsync no", updated)

    def test_vm2_netplan_content_is_single_nic_and_lan_dns_pinned(self) -> None:
        self.assertIn("ens19", VM2_NETPLAN_CONTENT)
        self.assertIn("addresses: [192.168.1.1]", VM2_NETPLAN_CONTENT)
        self.assertNotIn("ens18", VM2_NETPLAN_CONTENT)
        self.assertNotIn("1.1.1.1", VM2_NETPLAN_CONTENT)

    def test_vm2_resolved_conf_uses_router_dns_and_keeps_fallbacks(self) -> None:
        self.assertIn("DNS=192.168.1.1", VM2_RESOLVED_CONF_CONTENT)
        self.assertIn("FallbackDNS=1.1.1.1 8.8.8.8", VM2_RESOLVED_CONF_CONTENT)

    def test_processing_sync_paths_cover_runtime_packages(self) -> None:
        self.assertIn(Path("services/normalizer"), PROCESSING_SYNC_PATHS)
        self.assertIn(Path("services/filter"), PROCESSING_SYNC_PATHS)
        self.assertIn(Path("services/__init__.py"), PROCESSING_SYNC_PATHS)
        self.assertIn(Path("deploy/kafka_cluster_layout.py"), PROCESSING_SYNC_PATHS)
        self.assertIn(Path("deploy/kafka_wave_prepare.py"), PROCESSING_SYNC_PATHS)

    def test_sync_processing_runtime_uses_staging_and_sudo_install(self) -> None:
        import deploy.vm2_processing_resilience_deploy as vm2_deploy

        commands: list[str] = []

        def fake_run(command: str, **_: object) -> tuple[int, str, str]:
            commands.append(command)
            return 0, "", ""

        original_paths = vm2_deploy.PROCESSING_SYNC_PATHS
        original_run = vm2_deploy._run
        try:
            vm2_deploy.PROCESSING_SYNC_PATHS = (
                Path("services/__init__.py"),
                Path("services/normalizer"),
            )
            vm2_deploy._run = fake_run  # type: ignore[assignment]
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                workspace = root / "workspace"
                live = root / "live"
                stage = root / "stage"
                (workspace / "services").mkdir(parents=True)
                (workspace / "services/__init__.py").write_text("# runtime\n", encoding="utf-8")
                (workspace / "services/normalizer").mkdir(parents=True)
                (workspace / "services/normalizer/worker.py").write_text("print('ok')\n", encoding="utf-8")

                _sync_processing_runtime(
                    workspace,
                    live,
                    temp_root=stage,
                    sudo_password="secret",
                )

                staged_file = stage / "processing-runtime/services/__init__.py"
                staged_dir_file = stage / "processing-runtime/services/normalizer/worker.py"
                self.assertTrue(staged_file.exists())
                self.assertTrue(staged_dir_file.exists())
                self.assertTrue(any("install -m 0644" in command for command in commands))
                self.assertTrue(any("cp -R" in command for command in commands))
        finally:
            vm2_deploy.PROCESSING_SYNC_PATHS = original_paths
            vm2_deploy._run = original_run  # type: ignore[assignment]

    def test_resolve_bash_path_uses_portable_git_fallback_on_windows_workstation(self) -> None:
        import deploy.vm2_processing_resilience_deploy as vm2_deploy

        original_which = vm2_deploy.shutil.which
        original_home = vm2_deploy.Path.home
        try:
            vm2_deploy.shutil.which = lambda _: None  # type: ignore[assignment]
            vm2_deploy.Path.home = classmethod(lambda cls: Path("C:/Users/Rdegon"))  # type: ignore[assignment]
            resolved = _resolve_bash_path()
            self.assertTrue(resolved.replace("\\", "/").endswith("PortableGit/bin/bash.exe"))
        finally:
            vm2_deploy.shutil.which = original_which  # type: ignore[assignment]
            vm2_deploy.Path.home = original_home  # type: ignore[assignment]


if __name__ == "__main__":
    unittest.main()
