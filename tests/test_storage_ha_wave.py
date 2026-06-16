import base64
import os
import unittest
from unittest import mock

from deploy import storage_ha_wave_deploy as storage_wave


class StorageHAWaveTests(unittest.TestCase):
    def test_render_control_plane_pg_dsn_includes_primary_and_standby(self) -> None:
        rendered = storage_wave.render_control_plane_pg_dsn(
            primary_host="192.168.1.39",
            standby_host="192.168.1.35",
            db="siem_control_plane",
            user="siem_control",
            password="secret",
        )

        self.assertIn("host=192.168.1.39,192.168.1.35", rendered)
        self.assertIn("target_session_attrs=read-write", rendered)

    def test_render_mongo_replica_uri_uses_all_members(self) -> None:
        rendered = storage_wave.render_mongo_replica_uri(
            hosts=("192.168.1.39", "192.168.1.35", "192.168.1.40"),
            db="siem_content",
            user="siem_content",
            password="pw",
            replica_set="siem-rs",
        )

        self.assertIn("192.168.1.39:27017,192.168.1.35:27017,192.168.1.40:27017", rendered)
        self.assertIn("replicaSet=siem-rs", rendered)

    def test_render_clickhouse_hosts_contains_primary_and_standby(self) -> None:
        rendered = storage_wave.render_clickhouse_hosts(primary_host="192.168.1.38", standby_host="192.168.1.40")

        self.assertEqual("192.168.1.38:8123,192.168.1.40:8123", rendered)

    def test_storage_ha_env_keyfile_b64_round_trips_to_ascii(self) -> None:
        encoded = base64.b64encode("safe-ascii-keyfile".encode("ascii")).decode("ascii")
        decoded = base64.b64decode(encoded).decode("utf-8", errors="strict")

        self.assertEqual("safe-ascii-keyfile", decoded)

    def test_normalize_mongo_keyfile_replaces_invalid_urlsafe_payload(self) -> None:
        invalid = base64.b64encode("bad_key-with-urlsafe".encode("ascii")).decode("ascii")

        normalized = storage_wave._normalize_mongo_keyfile_b64(invalid)
        decoded = base64.b64decode(normalized, validate=True).decode("ascii", errors="strict")

        self.assertTrue(6 <= len(decoded) <= 1024)
        self.assertTrue(all(ch.isalnum() for ch in decoded))

    def test_normalize_mongo_keyfile_preserves_valid_alnum_payload(self) -> None:
        valid = base64.b64encode("ValidMongoKey123".encode("ascii")).decode("ascii")

        normalized = storage_wave._normalize_mongo_keyfile_b64(valid)

        self.assertEqual(valid, normalized)

    def test_required_env_uses_default_when_secret_is_present_but_blank(self) -> None:
        with mock.patch.dict(os.environ, {"SIEM_VM1_VMID": ""}, clear=False):
            self.assertEqual("104", storage_wave._required_env("SIEM_VM1_VMID", default="104"))

    def test_last_nonempty_line_ignores_leading_noise(self) -> None:
        payload = "\npermission denied\nf\n\n"

        self.assertEqual("f", storage_wave._last_nonempty_line(payload))

    def test_split_ssh_host_port_normalizes_proxmox_ui_port(self) -> None:
        self.assertEqual(("192.168.1.101", 22), storage_wave._split_ssh_host_port("192.168.1.101:8006"))

    def test_configure_postgres_standby_updates_pg_hba_for_primary_and_standby(self) -> None:
        client = object()
        run_results = [
            (0, "t\n", ""),  # pg_basebackup + verification
            (0, "", ""),  # pg_hba update script
            (0, "t\n", ""),  # restart + recovery verification
        ]
        with mock.patch.object(storage_wave, "_ensure_postgres_install") as ensure_install:
            with mock.patch.object(storage_wave, "_run_command", side_effect=run_results) as run_command:
                storage_wave._configure_postgres_standby(
                    client,
                    sudo_password="pw",
                    primary_host="192.168.1.39",
                    standby_host="192.168.1.35",
                    replication_user="siem_repl",
                    replication_password="secret",
                    major="14",
                )

        ensure_install.assert_called_once_with(client, sudo_password="pw")
        commands = [args.args[1] for args in run_command.call_args_list]
        self.assertIn("host all all 192.168.1.39/32 scram-sha-256", commands[1])
        self.assertIn("host all all 192.168.1.35/32 scram-sha-256", commands[1])
        self.assertIn("ALTER SYSTEM SET hot_standby='on';", commands[2])
        self.assertIn("ALTER SYSTEM SET listen_addresses='*';", commands[2])

    def test_configure_mongo_replicaset_renders_js_safe_user_literals(self) -> None:
        vm4_client = object()
        vm1_client = object()
        vm5_client = object()
        mongosh_calls: list[str] = []

        with mock.patch.object(storage_wave, "_ensure_mongodb_install"), \
            mock.patch.object(storage_wave, "_configure_mongod_node"), \
            mock.patch.object(storage_wave.time, "sleep"), \
            mock.patch.object(storage_wave, "render_mongo_replica_uri", return_value="mongodb://example"), \
            mock.patch.object(storage_wave, "_run_mongosh_eval", side_effect=lambda *_args, script="", **_kwargs: mongosh_calls.append(script) or "1"):
            storage_wave._configure_mongo_replicaset(
                vm4_client,
                vm1_client,
                vm5_client,
                vm4_password="pw4",
                vm1_password="pw1",
                vm5_password="pw5",
                vm4_host="192.168.1.39",
                vm1_host="192.168.1.35",
                vm5_host="192.168.1.40",
                app_db='siem_content"prod',
                app_user='svc"user',
                app_password='pw"quoted\\slash',
                admin_user='admin"user',
                admin_password='root"quoted\\slash',
                replica_set="siem-rs",
                keyfile_b64=base64.b64encode(b"ValidMongoKey123").decode("ascii"),
            )

        self.assertGreaterEqual(len(mongosh_calls), 3)
        rs_script = mongosh_calls[0]
        user_script = mongosh_calls[1]
        self.assertIn('"siem-rs"', rs_script)
        self.assertIn('"192.168.1.39:27017"', rs_script)
        self.assertIn('"admin\\"user"', user_script)
        self.assertIn('"root\\"quoted\\\\slash"', user_script)
        self.assertIn('"siem_content\\"prod"', user_script)
        self.assertIn('"svc\\"user"', user_script)
        self.assertIn('"pw\\"quoted\\\\slash"', user_script)

    def test_run_mongosh_eval_uses_remote_script_file(self) -> None:
        client = object()
        with mock.patch.object(storage_wave, "_write_remote_text") as write_remote_text, \
            mock.patch.object(storage_wave, "_run_command", return_value=(0, "1\n", "")) as run_command:
            result = storage_wave._run_mongosh_eval(
                client,
                sudo_password="pw",
                script='db.getSiblingDB("admin").runCommand({ ping: 1 })',
                uri="mongodb://user:pw@127.0.0.1:27017/admin",
            )

        self.assertEqual("1", result)
        write_remote_text.assert_called_once_with(
            client,
            "/tmp/siem-storage-ha-mongosh.js",
            'db.getSiblingDB("admin").runCommand({ ping: 1 })',
            mode="0600",
            sudo_password="pw",
        )
        command = run_command.call_args.args[1]
        self.assertIn("mongosh", command)
        self.assertIn("/tmp/siem-storage-ha-mongosh.js", command)
        self.assertNotIn("--eval", command)

    def test_resolve_remote_secret_env_values_parses_json_payload(self) -> None:
        client = object()
        response = '{"SIEM_MONGO_URI":"mongodb://siem_content:pw@127.0.0.1:27017/siem_content"}\n'

        with mock.patch.object(storage_wave, "_run_command", return_value=(0, response, "")) as run_command:
            resolved = storage_wave._resolve_remote_secret_env_values(
                client,
                sudo_password="pw",
                env_path="/etc/siem/web.env",
                env_names=("SIEM_MONGO_URI", "SIEM_PG_PASSWORD"),
            )

        self.assertEqual("mongodb://siem_content:pw@127.0.0.1:27017/siem_content", resolved["SIEM_MONGO_URI"])
        command = run_command.call_args.args[1]
        self.assertIn("/etc/siem/web.env", command)
        self.assertIn("secret_runtime", command)

    def test_reset_clickhouse_table_for_bootstrap_purges_broken_parts_and_recreates_table(self) -> None:
        client = object()
        broken_output = "Code: 231. DB::Exception: TOO_MANY_UNEXPECTED_DATA_PARTS"

        with mock.patch.object(storage_wave, "_write_remote_text") as write_remote_text, mock.patch.object(
            storage_wave,
            "_run_command",
            side_effect=[
                (210, broken_output, ""),
                (0, "ATTACH TABLE _ UUID '7cd45869-2fa4-4de7-ad97-740cd0d3d76e'\n", ""),
                (0, "active\n", ""),
                (0, "", ""),
            ],
        ) as run_command:
            storage_wave._reset_clickhouse_table_for_bootstrap(
                client,
                db_name="siem",
                table_name="events",
                ddl="CREATE TABLE siem.events (`ts` DateTime) ENGINE = MergeTree ORDER BY ts",
                sudo_password="pw",
            )

        cleanup_command = run_command.call_args_list[2].args[1]
        self.assertIn("/var/lib/clickhouse/store/7cd/7cd45869-2fa4-4de7-ad97-740cd0d3d76e", cleanup_command)
        self.assertIn("systemctl start clickhouse-server", cleanup_command)
        rendered_ddl = write_remote_text.call_args.args[2]
        self.assertIn("CREATE TABLE IF NOT EXISTS siem.events", rendered_ddl)

    def test_bootstrap_clickhouse_standby_reports_stdout_failure_details(self) -> None:
        vm3_client = object()
        vm5_client = object()

        with mock.patch.object(storage_wave, "BOOTSTRAP_TABLES", ("events",)), mock.patch.object(
            storage_wave, "_ensure_clickhouse_install"
        ), mock.patch.object(storage_wave, "_configure_clickhouse_standby_network"), mock.patch.object(
            storage_wave, "_remote_clickhouse_schema", return_value={"events": "CREATE TABLE siem.events (`ts` DateTime) ENGINE = MergeTree ORDER BY ts"}
        ), mock.patch.object(storage_wave, "_reset_clickhouse_table_for_bootstrap"), mock.patch.object(
            storage_wave,
            "_run_command",
            side_effect=[
                (0, "", ""),
                (0, "", ""),
                (210, "Received exception from server: broken bootstrap", ""),
            ],
        ):
            with self.assertRaisesRegex(RuntimeError, "broken bootstrap"):
                storage_wave._bootstrap_clickhouse_standby(
                    vm3_client,
                    vm5_client,
                    vm3_password="pw3",
                    vm5_password="pw5",
                    vm4_host="192.168.1.39",
                    vm5_host="192.168.1.40",
                    primary_env={
                        "SIEM_CH_HOST": "192.168.1.38",
                        "SIEM_CH_PORT": "9000",
                        "SIEM_CH_DB": "siem",
                        "SIEM_CH_USER": "siem_admin",
                        "SIEM_CH_PASSWORD": "secret",
                    },
                )

    def test_bootstrap_clickhouse_standby_skips_optional_cold_table_data(self) -> None:
        vm3_client = object()
        vm5_client = object()
        schema = {
            "events": "CREATE TABLE siem.events (`ts` DateTime) ENGINE = MergeTree ORDER BY ts",
            "events_cold": "CREATE TABLE siem.events_cold (`ts` DateTime) ENGINE = MergeTree ORDER BY ts",
        }

        with mock.patch.object(storage_wave, "BOOTSTRAP_TABLES", ("events", "events_cold")), mock.patch.object(
            storage_wave, "_ensure_clickhouse_install"
        ), mock.patch.object(storage_wave, "_configure_clickhouse_standby_network"), mock.patch.object(
            storage_wave, "_remote_clickhouse_schema", return_value=schema
        ), mock.patch.object(storage_wave, "_reset_clickhouse_table_for_bootstrap"), mock.patch.object(
            storage_wave,
            "_run_command",
            side_effect=[
                (0, "", ""),
                (0, "", ""),
                (0, "", ""),
            ],
        ) as run_command:
            storage_wave._bootstrap_clickhouse_standby(
                vm3_client,
                vm5_client,
                vm3_password="pw3",
                vm5_password="pw5",
                vm4_host="192.168.1.39",
                vm5_host="192.168.1.40",
                primary_env={
                    "SIEM_CH_HOST": "192.168.1.38",
                    "SIEM_CH_PORT": "9000",
                    "SIEM_CH_DB": "siem",
                    "SIEM_CH_USER": "siem_admin",
                    "SIEM_CH_PASSWORD": "secret",
                },
            )

        commands = [args.args[1] for args in run_command.call_args_list]
        insert_commands = [command for command in commands if "INSERT INTO siem." in command]
        self.assertEqual(1, len(insert_commands))
        self.assertIn("INSERT INTO siem.events", insert_commands[0])
        self.assertIn("WHERE ts >= now() - INTERVAL 6 HOUR", insert_commands[0])
        self.assertNotIn("events_cold", insert_commands[0])


if __name__ == "__main__":
    unittest.main()
