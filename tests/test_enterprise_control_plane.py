import importlib
import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MODULE_NAME = "enterprise_control_plane"


def _control_plane_module_path() -> Path:
    candidates = (
        ROOT / "enterprise_control_plane.py",
        ROOT / "services" / "web" / "app" / "enterprise_control_plane.py",
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError("Unable to resolve enterprise control plane module path")


class _FakePgCursor:
    def __init__(self, store: dict[str, str]) -> None:
        self._store = store
        self._rows: list[tuple[str, ...]] = []

    def execute(self, query: str, params=None) -> "_FakePgCursor":
        normalized = " ".join(str(query or "").split()).upper()
        if normalized.startswith("CREATE TABLE IF NOT EXISTS"):
            return self
        if normalized.startswith("SELECT PAYLOAD::TEXT"):
            collection_name = str((params or ("",))[0])
            payload = self._store.get(collection_name)
            self._rows = [(payload,)] if payload is not None else []
            return self
        if normalized.startswith("SELECT COLLECTION_NAME FROM"):
            self._rows = [(name,) for name in sorted(self._store)]
            return self
        if normalized.startswith("INSERT INTO"):
            collection_name = str((params or ("", ""))[0])
            payload = str((params or ("", ""))[1])
            self._store[collection_name] = payload
            self._rows = []
            return self
        raise AssertionError(f"Unexpected query: {query}")

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)

    def __enter__(self) -> "_FakePgCursor":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


class _FakePgConnection:
    def __init__(self, store: dict[str, str]) -> None:
        self._store = store

    def cursor(self) -> _FakePgCursor:
        return _FakePgCursor(self._store)

    def __enter__(self) -> "_FakePgConnection":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


class _FakePsycopgModule:
    def __init__(self) -> None:
        self.storage: dict[str, str] = {}
        self.connections: list[str] = []

    def connect(self, dsn: str, autocommit: bool = True) -> _FakePgConnection:  # noqa: ARG002
        self.connections.append(str(dsn))
        return _FakePgConnection(self.storage)


class EnterpriseControlPlaneTests(unittest.TestCase):
    def setUp(self) -> None:
        self._module_dir = str(_control_plane_module_path().parent)
        if self._module_dir not in sys.path:
            sys.path.insert(0, self._module_dir)
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ["SIEM_CONTROL_PLANE_DIR"] = self.temp_dir.name
        for key in (
            "SIEM_CONTROL_PLANE_BACKEND",
            "SIEM_CONTROL_PLANE_PG_DSN",
            "SIEM_CONTROL_PLANE_PG_TABLE",
            "SIEM_PG_HOST",
            "SIEM_PG_PORT",
            "SIEM_PG_DB",
            "SIEM_PG_USER",
            "SIEM_PG_PASSWORD",
            "SIEM_JWT_SECRET",
            "SIEM_JWT_SECRET_REF",
            "SIEM_WEBHOOK_SHARED_SECRET",
            "SIEM_WEBHOOK_SHARED_SECRET_REF",
            "SIEM_TELEGRAM_BOT_TOKEN",
            "SIEM_TELEGRAM_BOT_TOKEN_REF",
            "SIEM_SMTP_PASSWORD",
            "TEST_WEBHOOK_SECRET",
        ):
            os.environ.pop(key, None)
        sys.modules.pop(MODULE_NAME, None)
        sys.modules.pop("psycopg", None)
        self.module = importlib.import_module(MODULE_NAME)

    def tearDown(self) -> None:
        sys.modules.pop(MODULE_NAME, None)
        sys.modules.pop("psycopg", None)
        os.environ.pop("SIEM_CONTROL_PLANE_DIR", None)
        self.temp_dir.cleanup()
        while self._module_dir in sys.path:
            sys.path.remove(self._module_dir)

    def _reload_module(self):
        sys.modules.pop(MODULE_NAME, None)
        self.module = importlib.import_module(MODULE_NAME)
        return self.module

    def _start_capture_server(self, response_body: dict | list | str, *, status: int = 200, content_type: str = "application/json"):
        captured: list[dict[str, object]] = []
        body_bytes = response_body.encode("utf-8") if isinstance(response_body, str) else json.dumps(response_body).encode("utf-8")

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self._respond()

            def do_POST(self):  # noqa: N802
                self._respond()

            def log_message(self, format: str, *args) -> None:  # noqa: A003
                return

            def _respond(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                raw_body = self.rfile.read(length) if length else b""
                captured.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "headers": {str(key).lower(): str(value) for key, value in self.headers.items()},
                        "body": raw_body.decode("utf-8", errors="replace"),
                    }
                )
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.end_headers()
                self.wfile.write(body_bytes)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread, captured, f"http://127.0.0.1:{server.server_address[1]}"

    def test_connector_run_updates_runtime_health(self) -> None:
        connector = self.module.save_connector_definition(
            {
                "title": "Custom REST Feed",
                "family": "source",
                "group": "api",
                "mode": "pull",
                "source_family": "custom_api",
            }
        )
        result = self.module.record_connector_run(
            connector["id"],
            status="success",
            actor="tester",
            dry_run=True,
            stats={"accepted_events": 42},
        )

        self.assertEqual(result["run"]["connector_id"], connector["id"])
        self.assertEqual(result["connector"]["runtime"]["health"]["last_status"], "dry_run")
        self.assertGreaterEqual(result["connector"]["runtime"]["health"]["success_rate_24h"], 100.0)

    def test_risk_signal_promotes_entity_and_case(self) -> None:
        recorded = self.module.record_risk_signal(
            {
                "entity_type": "host",
                "entity_name": "srv-auth-01",
                "summary": "Multiple auth failures and suspicious process start",
                "score": 72,
                "severity": "high",
                "source": "unit-test",
            },
            actor="tester",
        )
        entity = recorded["entity"]

        self.assertEqual(entity["risk_level"], "high")
        self.assertEqual(entity["signals_recent"], 1)

        case_item = self.module.promote_entity_to_case(entity["id"], created_by="tester")
        self.assertIn(entity["id"], case_item["related_entities"])
        self.assertEqual(case_item["source"], "entity_promotion")

    def test_secret_inventory_marks_reference_without_exposing_value(self) -> None:
        os.environ["SIEM_JWT_SECRET_REF"] = "vault://kv/siem/jwt"
        inventory = self.module.get_secret_inventory()
        jwt_item = next(item for item in inventory["items"] if item["id"] == "jwt-signing")

        self.assertEqual(jwt_item["status"], "reference")
        self.assertEqual(jwt_item["source"], "SIEM_JWT_SECRET_REF")

    def test_control_plane_storage_status_defaults_to_filesystem(self) -> None:
        status = self.module.control_plane_storage_status()

        self.assertEqual(status["backend"], "filesystem")
        self.assertEqual(status["requested_backend"], "auto")
        self.assertIn("path", status)
        self.assertFalse(status["supports_transactions"])

    def test_legacy_connector_rows_are_backfilled_with_seed_telemetry(self) -> None:
        self.module._save_collection(  # noqa: SLF001
            "connector_definitions",
            [
                {
                    "id": "webhook-source",
                    "type": "connector_definition",
                    "title": "Webhook source",
                    "family": "source",
                    "block_type": "webhook_source",
                    "enabled": True,
                    "status": "ready",
                }
            ],
        )

        rows = self.module.list_connector_definitions()
        webhook = next(item for item in rows if item["id"] == "webhook-source")
        identity = next(item for item in rows if item["id"] == "identity-provider-audit")
        overview = self.module.get_connectors_overview()

        self.assertGreater(webhook["telemetry"]["coverage_score"], 0)
        self.assertTrue(webhook["operations"]["bundle_id"])
        self.assertGreaterEqual(len(rows), 8)
        self.assertEqual("identity-provider-audit", identity["id"])
        self.assertGreater(overview["metrics"]["telemetry_coverage_avg"], 0.0)

    def test_legacy_response_actions_are_backfilled_with_governance_defaults(self) -> None:
        self.module._save_collection(  # noqa: SLF001
            "response_actions",
            [
                {
                    "id": "telegram-primary",
                    "type": "response_action",
                    "kind": "telegram",
                    "title": "Telegram primary channel",
                    "enabled": True,
                    "dangerous": False,
                    "approval_required": False,
                }
            ],
        )

        actions = self.module.list_response_actions()
        telegram = next(item for item in actions if item["id"] == "telegram-primary")
        response_ops = importlib.import_module("control_plane_response_ops")
        analytics = response_ops.get_response_analytics(limit=20)

        self.assertTrue(telegram["owners"])
        self.assertTrue(telegram["evidence_contract"])
        self.assertTrue(telegram["compliance_controls"])
        self.assertFalse(telegram["rollback_required"])
        self.assertGreater(analytics["metrics"]["governed_actions"], 0)
        self.assertGreater(analytics["metrics"]["owner_coverage_pct"], 0.0)
        self.assertEqual(100.0, analytics["metrics"]["rollback_ready_pct"])
        self.assertGreater(analytics["metrics"]["rollback_not_applicable_actions"], 0)

    def test_postgres_control_plane_backend_round_trip_with_fake_driver(self) -> None:
        fake_psycopg = _FakePsycopgModule()
        sys.modules["psycopg"] = fake_psycopg
        os.environ["SIEM_CONTROL_PLANE_BACKEND"] = "postgres"
        os.environ["SIEM_CONTROL_PLANE_PG_DSN"] = "postgresql://siem:secret@pg.example/siem"
        module = self._reload_module()

        connector = module.save_connector_definition(
            {
                "title": "Postgres backed connector",
                "family": "source",
                "group": "api",
                "mode": "pull",
                "source_family": "custom_api",
                "_audit_actor": "pg-test",
            }
        )
        fetched = module.get_connector_definition(connector["id"])
        status = module.control_plane_storage_status()

        self.assertIsNotNone(fetched)
        self.assertEqual(status["backend"], "postgres")
        self.assertTrue(status["supports_transactions"])
        self.assertEqual(status["dsn_source"], "SIEM_CONTROL_PLANE_PG_DSN")
        self.assertTrue(fake_psycopg.connections)

    def test_postgres_control_plane_migrates_filesystem_snapshot(self) -> None:
        connector_path = Path(self.temp_dir.name) / "connector_definitions.json"
        discovery_path = Path(self.temp_dir.name) / "source_discovery_candidates.json"
        connector_path.write_text(
            json.dumps([{"id": "connector-1", "title": "Imported connector"}], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        discovery_path.write_text(
            json.dumps([{"id": "candidate-1", "ip": "192.168.1.50"}], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        fake_psycopg = _FakePsycopgModule()
        sys.modules["psycopg"] = fake_psycopg
        os.environ["SIEM_CONTROL_PLANE_BACKEND"] = "postgres"
        os.environ["SIEM_CONTROL_PLANE_PG_DSN"] = "postgresql://siem:secret@pg.example/siem"
        module = self._reload_module()

        report = module.migrate_filesystem_snapshot_to_active_store(actor="tester")
        status = module.control_plane_storage_status()

        self.assertEqual(report["migration_status"], "completed")
        self.assertIn("connector_definitions", report["imported_collections"])
        self.assertIn("source_discovery_candidates", report["imported_collections"])
        self.assertEqual(status["backend"], "postgres")
        self.assertEqual(status["migration_status"], "completed")
        self.assertEqual(status["collection_counts"]["connector_definitions"], 1)
        self.assertEqual(status["collection_counts"]["source_discovery_candidates"], 1)

    def test_corrupted_filesystem_collection_is_reported_without_reset(self) -> None:
        audit_path = Path(self.temp_dir.name) / "audit_events.json"
        audit_path.write_text("{bad json", encoding="utf-8")

        audit = self.module.list_audit_events(limit=10)
        status = self.module.control_plane_storage_status()

        self.assertEqual(audit["items"], [])
        self.assertEqual(audit_path.read_text(encoding="utf-8"), "{bad json")
        self.assertTrue(status["corrupt_collections"])
        self.assertEqual(status["corrupt_collections"][0]["collection"], "audit_events")

    def test_case_comment_task_and_evidence_are_persisted(self) -> None:
        case_item = self.module.save_case({"title": "Investigate test flow", "summary": "Case persistence smoke test"}, actor="tester")
        self.module.append_case_comment(case_item["id"], body="Analyst note", author="analyst1")
        self.module.append_case_task(case_item["id"], title="Validate source coverage", assignee="analyst1", actor="analyst1")
        updated = self.module.attach_case_evidence(case_item["id"], title="Suspicious payload", content="{}", actor="analyst1")

        self.assertEqual(len(updated["comments"]), 1)
        self.assertEqual(len(updated["tasks"]), 1)
        self.assertEqual(len(updated["evidence"]), 1)

    def test_audit_chain_tracks_control_plane_changes(self) -> None:
        self.module.save_connector_definition(
            {
                "title": "Audited connector",
                "family": "source",
                "group": "api",
                "mode": "pull",
                "source_family": "custom_api",
                "_audit_actor": "auditor",
            }
        )
        self.module.save_saved_search(
            {
                "title": "Audited search",
                "query": "event.category = 'authentication'",
                "storage": "hot",
                "_audit_actor": "auditor",
            }
        )

        audit = self.module.list_audit_events(limit=20)
        actions = [str(item.get("action") or "") for item in audit["items"]]

        self.assertTrue(audit["chain"]["valid"])
        self.assertIn("connector.saved", actions)
        self.assertIn("saved_search.saved", actions)
        self.assertTrue(all(str(item.get("hash") or "") for item in audit["items"]))

    def test_audit_chain_detects_tampering(self) -> None:
        self.module.save_response_action(
            {
                "title": "Audited response action",
                "kind": "approval_gate",
                "_audit_actor": "auditor",
            }
        )
        audit_path = self.module._collection_path("audit_events")
        audit_rows = json.loads(audit_path.read_text(encoding="utf-8"))
        audit_rows[0]["summary"] = "tampered"
        audit_path.write_text(json.dumps(audit_rows, ensure_ascii=False, indent=2), encoding="utf-8")

        verification = self.module.verify_audit_chain()

        self.assertFalse(verification["valid"])
        self.assertEqual(verification["reason"], "hash_mismatch")

    def test_health_overview_includes_audit_summary(self) -> None:
        self.module.save_connector_definition(
            {
                "title": "Health audited connector",
                "family": "source",
                "group": "api",
                "mode": "pull",
                "source_family": "custom_api",
                "_audit_actor": "health-check",
            }
        )

        overview = self.module.build_health_overview(
            platform_status={"status": "ok"},
            source_inventory=[],
            collector_inventory=[],
        )

        self.assertIn("audit", overview)
        self.assertIn("control_plane", overview)
        self.assertTrue(overview["audit"]["chain"]["valid"])
        self.assertEqual(overview["control_plane"]["backend"], "filesystem")
        self.assertGreaterEqual(int(overview["audit"]["events_total"]), 1)

    def test_health_overview_surfaces_kafka_shadow_pipeline_issue(self) -> None:
        overview = self.module.build_health_overview(
            platform_status={
                "status": "ok",
                "transport_backend": "dual",
                "transport_shadow_status": {
                    "healthy": False,
                    "issues": ["Kafka shadow pipeline is stale (last event 1800s ago)"],
                },
            },
            source_inventory=[],
            collector_inventory=[],
        )

        self.assertIn("transport", overview)
        self.assertIn("shadow", overview["transport"])
        self.assertIn("Kafka shadow pipeline is stale (last event 1800s ago)", overview["issues"])

    def test_health_overview_ignores_retired_shadow_in_kafka_only_mode(self) -> None:
        overview = self.module.build_health_overview(
            platform_status={
                "status": "ok",
                "transport_backend": "kafka",
                "stream_correlation": {"shadow_compare": False},
                "transport_shadow_status": {
                    "healthy": False,
                    "issues": ["Kafka shadow pipeline has no events in the last 15 minutes"],
                },
            },
            source_inventory=[],
            collector_inventory=[],
        )

        self.assertNotIn(
            "Kafka shadow pipeline has no events in the last 15 minutes",
            overview["issues"],
        )

    def test_health_overview_ignores_synthetic_and_loopback_source_inventory(self) -> None:
        overview = self.module.build_health_overview(
            platform_status={"status": "ok"},
            source_inventory=[
                {
                    "source_name": "vm1-smoke",
                    "status": "stale",
                    "categories": ["synthetic"],
                    "products": ["synthetic"],
                },
                {
                    "source_name": "127.0.0.1",
                    "status": "delayed",
                    "categories": ["syslog"],
                    "products": ["linux.syslog"],
                },
            ],
            collector_inventory=[],
        )

        self.assertNotIn("Stale sources detected: 1", overview["issues"])
        self.assertNotIn("Delayed sources detected: 1", overview["issues"])
        self.assertEqual(overview["sources"]["total"], 0)

    def test_health_overview_suppresses_low_signal_ingest_noise(self) -> None:
        overview = self.module.build_health_overview(
            platform_status={"status": "ok"},
            source_inventory=[],
            collector_inventory=[],
            ingest_runtime={
                "dlq": {"outstanding": 3},
                "issues": [
                    "Outstanding DLQ events: 3",
                    "Parser errors recorded: 38844",
                    "Delayed sources detected: 1",
                    "Stale sources detected: 1",
                ],
            },
        )

        self.assertNotIn("Ingest DLQ backlog: 3", overview["issues"])
        self.assertNotIn("Outstanding DLQ events: 3", overview["issues"])
        self.assertNotIn("Parser errors recorded: 38844", overview["issues"])
        self.assertNotIn("Delayed sources detected: 1", overview["issues"])
        self.assertNotIn("Stale sources detected: 1", overview["issues"])

    def test_content_bundle_release_gate_marks_live_ready_bundle(self) -> None:
        content_ops = importlib.import_module("control_plane_content_ops")
        bundle = content_ops.save_content_bundle(
            {
                "title": "Enterprise SOC Core",
                "bundle_type": "rule_pack",
                "version": "2026.04.09",
                "stage": "active",
                "objects": 18,
                "coverage_domains": ["linux", "identity", "network"],
                "personas": ["soc_analyst", "detection_engineer"],
                "release_ring": "soc-core",
                "quality_gates": {
                    "ci_status": "passed",
                    "validation_status": "validated",
                    "approval_status": "approved",
                    "regression_status": "passed",
                    "test_coverage_pct": 96,
                },
                "integrity": {"signed": True, "signed_by": "release-bot"},
                "qa_datasets": ["auth-baseline", "vpn-abuse"],
                "rollback_targets": ["enterprise-soc-core-2026.04.08"],
            }
        )

        self.assertEqual("live_ready", bundle["release_gate"]["status"])
        self.assertTrue(bundle["release_gate"]["ready_for_live"])
        self.assertFalse(bundle["release_gate"]["missing"])

    def test_connector_release_gates_and_health_overview_advisories_are_exposed(self) -> None:
        health_module = importlib.import_module("control_plane_health")
        response_ops = importlib.import_module("control_plane_response_ops")
        connector = self.module.save_connector_definition(
            {
                "id": "cloud-audit-enterprise",
                "title": "Cloud audit enterprise",
                "family": "source",
                "group": "cloud",
                "mode": "pull",
                "source_family": "cloud_control_plane",
                "telemetry": {
                    "coverage_score": 92,
                    "parsing_coverage_pct": 91,
                    "telemetry_quality_pct": 93,
                    "event_families": ["auth", "policy", "network"],
                    "evidence_fields": ["src_ip", "user_name", "target_user"],
                    "investigation_pivots": ["src_ip", "user_name"],
                    "actor_ip_ready": True,
                    "entity_mapping_ready": True,
                },
                "operations": {
                    "owner": "cloud-platform",
                    "bundle_id": "enterprise-soc-core",
                    "runbook_id": "rb-cloud-audit-onboarding",
                    "onboarding_template": "cloud-audit-onboarding",
                    "playbooks": ["account-disable-approval"],
                    "compliance_controls": ["ISO27001-A.8", "NIST-PR.AC"],
                    "release_stage": "active",
                },
            }
        )
        action = self.module.save_response_action(
            {
                "title": "Governed webhook response",
                "kind": "webhook",
                "approval_required": False,
                "owners": ["soc-lead"],
                "evidence_contract": ["incident", "actor_ip"],
                "rollback_contract": ["ticket-reopen"],
                "compliance_controls": ["SOC2-CC7", "NIST-IR.4"],
                "preconditions": ["ticket_open"],
                "integration_targets": ["jira"],
                "target": {"url": "https://example.invalid/hook", "method": "POST"},
            }
        )
        self.assertTrue(connector["release_gate"]["ready_for_live"])
        self.assertTrue(action["owners"])

        with patch.object(
            self.module,
            "list_content_bundles",
            return_value=[
                {
                    "id": "bundle-live",
                    "release_gate": {"ready_for_live": True},
                }
            ],
        ):
            with patch.object(
                self.module,
                "get_connectors_overview",
                return_value={
                    "metrics": {"total": 1, "degraded": 0, "delayed": 0, "stale": 0, "release_gate_ready": 1},
                    "posture": {"release_gate_ready_pct": 100.0},
                },
            ):
                with patch.object(
                    response_ops,
                    "get_response_analytics",
                    return_value={
                        "metrics": {
                            "owner_coverage_pct": 100.0,
                            "evidence_contract_pct": 100.0,
                            "compliance_coverage_pct": 100.0,
                            "precondition_coverage_pct": 100.0,
                        }
                    },
                ):
                    with patch.object(
                        health_module,
                        "local_host_runtime_overview",
                        return_value={
                            "metrics": {
                                "stale_targets": 0,
                                "pressure_targets": 0,
                                "cache_heavy_targets": 2,
                            },
                            "memory_truth": {
                                "summary": "Cache-heavy Linux memory usage is expected unless pressure or swap growth is present."
                            },
                        },
                    ):
                        with patch.object(health_module, "local_certification_runtime_status", return_value={"healthy": True}):
                            with patch.object(health_module, "local_provider_status", return_value={"healthy": True}):
                                with patch.object(health_module, "local_vault_runtime_status", return_value={"healthy": True}):
                                    overview = self.module.build_health_overview(
                                        platform_status={
                                            "status": "ok",
                                            "stream_correlation": {"shadow_compare_mismatches_total": 7},
                                        },
                                        source_inventory=[],
                                        collector_inventory=[],
                                    )

        self.assertEqual(100.0, overview["release_gates"]["content"]["ready_pct"])
        self.assertEqual(100.0, overview["release_gates"]["connectors"]["ready_pct"])
        self.assertTrue(overview["release_gates"]["response"]["ready"])
        self.assertEqual(2, overview["release_gates"]["runtime"]["cache_heavy_targets"])
        self.assertIn("Stream correlation shadow mismatches: 7", overview["advisories"])
        self.assertNotIn("Connector release-gate coverage is below target", overview["issues"])

    def test_service_account_token_authentication_and_revoke(self) -> None:
        account = self.module.save_service_account(
            {
                "name": "Webhook runtime",
                "description": "Machine identity for outbound integrations",
                "enabled": True,
                "permission_bundles": ["dashboard-editor"],
                "permissions": ["health:view", "connectors:run"],
            },
            actor="iam-admin",
        )
        issued = self.module.issue_service_account_token(account["id"], title="Primary", actor="iam-admin", expires_days=14)
        token_value = str(issued["token"]["token"])

        principal = self.module.authenticate_service_account_token(token_value)
        self.assertIsNotNone(principal)
        self.assertEqual(principal["service_account"]["id"], account["id"])
        self.assertIn("health:view", principal["service_account"]["permissions"])
        self.assertIn("dashboards:write", principal["service_account"]["permissions"])
        self.assertIn("dashboard-editor", principal["service_account"]["permission_bundles"])
        self.assertEqual(principal["token"]["status"], "active")
        self.assertTrue(principal["token"]["last_used_ts"])

        revoked = self.module.revoke_service_account_token(account["id"], principal["token"]["id"], actor="iam-admin")
        self.assertEqual(revoked["status"], "revoked")
        self.assertIsNone(self.module.authenticate_service_account_token(token_value))

    def test_service_account_delete_removes_tokens_and_returns_deleted_bundles(self) -> None:
        account = self.module.save_service_account(
            {
                "name": "Retired integration",
                "enabled": True,
                "permission_bundles": ["rule-editor"],
            },
            actor="iam-admin",
        )
        issued = self.module.issue_service_account_token(account["id"], title="Primary", actor="iam-admin", expires_days=14)

        deleted = self.module.delete_service_account(account["id"], actor="iam-admin")

        self.assertEqual(account["id"], deleted["id"])
        self.assertEqual(["rule-editor"], deleted["permission_bundles"])
        self.assertEqual(1, deleted["deleted_tokens"])
        self.assertEqual([], self.module.list_service_account_tokens(service_account_id=account["id"], include_revoked=True))
        self.assertIsNone(self.module.get_service_account(account["id"]))

    def test_auth_overview_counts_service_accounts_and_tokens(self) -> None:
        account = self.module.save_service_account(
            {
                "name": "Health bot",
                "enabled": True,
                "permissions": ["health:view"],
            },
            actor="iam-admin",
        )
        self.module.issue_service_account_token(account["id"], title="Health bot token", actor="iam-admin", expires_days=7)

        overview = self.module.get_auth_overview()

        self.assertEqual(overview["metrics"]["service_accounts_total"], 1)
        self.assertEqual(overview["metrics"]["active_tokens"], 1)
        self.assertGreaterEqual(overview["metrics"]["tokens_expiring_14d"], 1)
        self.assertIn("local_users_total", overview["metrics"])
        self.assertIn("login_rate_limit_blocked_ips", overview["metrics"])
        self.assertIn("login_rate_limit", overview["policy"])
        self.assertTrue(any(item["label"] == "health:view" for item in overview["breakdowns"]["permission_usage"]))

    def test_permission_inventory_exposes_dashboard_rule_and_normalizer_bundles(self) -> None:
        inventory = self.module.get_permission_inventory()

        bundle_ids = {str(item.get("id") or "") for item in inventory["permission_bundles"]}
        category_ids = {str(item.get("id") or "") for item in inventory["permission_categories"]}

        self.assertIn("dashboard-editor", bundle_ids)
        self.assertIn("rule-editor", bundle_ids)
        self.assertIn("normalizer-editor", bundle_ids)
        self.assertIn("dashboard", category_ids)
        self.assertIn("rules", category_ids)
        self.assertIn("normalizers", category_ids)

    def test_rest_connector_runtime_executes_http_pull(self) -> None:
        server, thread, captured, base_url = self._start_capture_server({"events": [{"id": 1}, {"id": 2}]})
        try:
            connector = self.module.save_connector_definition(
                {
                    "title": "Runtime REST feed",
                    "family": "source",
                    "block_type": "rest_pull",
                    "group": "api",
                    "mode": "pull",
                    "source_family": "custom_api",
                    "runtime": {
                        "request": {"url": f"{base_url}/feed", "method": "GET", "timeout_ms": 3000},
                        "response": {"records_path": "events"},
                    },
                    "secret_requirements": [],
                }
            )
            result = self.module.run_connector_definition(connector["id"], actor="tester", dry_run=False)

            self.assertEqual(result["run"]["status"], "success")
            self.assertEqual(result["run"]["stats"]["accepted_events"], 2)
            self.assertEqual(captured[0]["path"], "/feed")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_sql_connector_runtime_executes_sqlite_query(self) -> None:
        db_path = os.path.join(self.temp_dir.name, "connector.db")
        conn = sqlite3.connect(db_path)
        try:
            conn.execute("create table events (id integer primary key, message text)")
            conn.execute("insert into events(message) values ('alpha')")
            conn.execute("insert into events(message) values ('beta')")
            conn.commit()
        finally:
            conn.close()

        connector = self.module.save_connector_definition(
            {
                "title": "Runtime sqlite source",
                "family": "source",
                "block_type": "sql_source",
                "group": "database",
                "mode": "poll",
                "source_family": "database_sql",
                "runtime": {
                    "connection": {"driver": "sqlite", "path": db_path},
                    "query": "select id, message from events order by id",
                },
                "secret_requirements": [],
            }
        )
        result = self.module.run_connector_definition(connector["id"], actor="tester", dry_run=False)

        self.assertEqual(result["run"]["status"], "success")
        self.assertEqual(result["run"]["stats"]["accepted_events"], 2)
        self.assertEqual(result["run"]["payload_sample"][0]["message"], "alpha")

    def test_greenbone_connector_legacy_definition_is_normalized(self) -> None:
        connector_ops = importlib.import_module("control_plane_connector_ops")
        connector_ops.save_connector_definition(
            {
                "id": "greenbone-openvas-import",
                "title": "Greenbone / OpenVAS import",
                "family": "source",
                "block_type": "rest_pull",
                "group": "vulnerability",
                "mode": "pull",
                "source_family": "vulnerability_manager",
                "status": "error",
                "runtime": {
                    "health": {
                        "last_status": "error",
                        "last_error": "REST connector requires runtime.request.url or runtime.request.url_env",
                        "success_rate_24h": 0,
                        "consecutive_failures": 2,
                    }
                },
                "secret_requirements": [],
            }
        )

        connector = connector_ops.get_connector_definition("greenbone-openvas-import")

        self.assertIsNotNone(connector)
        self.assertEqual(connector["block_type"], "vuln_runtime")
        self.assertEqual(connector["status"], "ready")
        self.assertEqual(connector["runtime"]["operation"], "sync_import")
        self.assertEqual(connector["runtime"]["health"]["last_status"], "never")
        self.assertEqual(connector["runtime"]["health"]["last_error"], "")

    def test_greenbone_vuln_runtime_connector_dry_run_uses_runtime_status(self) -> None:
        connector_ops = importlib.import_module("control_plane_connector_ops")
        connector_ops._build_vulnerability_runtime_status_runtime = lambda days=14: {  # type: ignore[assignment]
            "healthy": True,
            "reports_total": 7,
            "fleet_coverage": {"total_guests": 5},
            "probe": {"status": "ok"},
        }
        connector_ops._sync_vulnerability_targets_runtime = lambda limit=500: {"items": [{"asset_id": "asset-1"}]}  # type: ignore[assignment]
        connector_ops._import_greenbone_reports_runtime = lambda limit=20: {"imported": 2, "runs": [{"scan_run_id": "scan-1"}]}  # type: ignore[assignment]

        result = connector_ops.run_connector_definition("greenbone-openvas-import", actor="tester", dry_run=True)

        self.assertEqual(result["run"]["status"], "dry_run")
        self.assertEqual(result["run"]["stats"]["executor"], "vuln_runtime")
        self.assertEqual(result["run"]["stats"]["probe_status"], "ok")
        self.assertEqual(result["run"]["stats"]["accepted_events"], 7)

    def test_response_action_approval_executes_webhook_with_secret_reference(self) -> None:
        os.environ["TEST_WEBHOOK_SECRET"] = "super-secret"
        os.environ["SIEM_WEBHOOK_SHARED_SECRET_REF"] = "${TEST_WEBHOOK_SECRET}"
        server, thread, captured, base_url = self._start_capture_server({"ok": True})
        try:
            action = self.module.save_response_action(
                {
                    "title": "Webhook bridge runtime",
                    "kind": "webhook",
                    "approval_required": True,
                    "target": {"url": f"{base_url}/ticket", "method": "POST"},
                    "secret_requirements": [{"env": "SIEM_WEBHOOK_SHARED_SECRET", "label": "Webhook secret", "required": True}],
                }
            )
            queued = self.module.execute_response_action(action["id"], actor="tester", dry_run=False, payload={"message": "Escalate", "case_id": "case-1"})
            self.assertEqual(queued["execution"]["status"], "awaiting_approval")

            approved = self.module.approve_response_execution(queued["execution"]["id"], actor="lead")
            body = json.loads(str(captured[0]["body"]))

            self.assertEqual(approved["status"], "executed")
            self.assertEqual(captured[0]["headers"]["x-rdegon-webhook-secret"], "super-secret")
            self.assertEqual(body["payload"]["case_id"], "case-1")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_default_host_runtime_bundle_and_saved_searches_are_exposed(self) -> None:
        bundles = self.module.list_content_bundles()
        searches = self.module.list_saved_searches()

        bundle_ids = {str(item.get("id") or "") for item in bundles}
        search_ids = {str(item.get("id") or "") for item in searches}

        self.assertIn("host-runtime-observability-v1", bundle_ids)
        self.assertIn("host-runtime-pressure", search_ids)
        self.assertIn("host-telemetry-gaps", search_ids)

    def test_local_user_lifecycle_and_password_rotation(self) -> None:
        created = self.module.save_local_user(
            {
                "username": "platform-analyst",
                "password": "InitialSecret!23",
                "role": "analyst",
                "permission_bundles": ["normalizer-editor"],
                "permissions": ["dashboard:view", "normalizers:write"],
                "enabled": True,
            },
            actor="iam-admin",
        )
        rotated = self.module.set_local_user_password("platform-analyst", new_password="RotatedSecret!23", actor="iam-admin")
        listed = self.module.list_local_users()
        records = self.module.load_local_user_auth_records()
        deleted = self.module.delete_local_user("platform-analyst", actor="iam-admin")

        self.assertEqual("platform-analyst", created["username"])
        self.assertIn("normalizers:write", created["permissions"])
        self.assertIn("assets:view", created["permissions"])
        self.assertEqual(["normalizer-editor"], created["permission_bundles"])
        self.assertEqual("platform-analyst", rotated["username"])
        self.assertTrue(any(item["username"] == "platform-analyst" for item in listed))
        auth_record = next(item for item in records if item["username"] == "platform-analyst")
        self.assertEqual("analyst", auth_record["role"])
        self.assertTrue(auth_record["password_hash"])
        self.assertEqual(["normalizer-editor"], auth_record["permission_bundles"])
        self.assertEqual("platform-analyst", deleted["username"])

    def test_response_retry_and_dlq_replay_flow(self) -> None:
        server, thread, captured, base_url = self._start_capture_server({"ok": True}, status=503)
        try:
            action = self.module.save_response_action(
                {
                    "title": "Retry webhook action",
                    "kind": "webhook",
                    "approval_required": False,
                    "target": {"url": f"{base_url}/retry", "method": "POST", "retry_attempts": 2, "retry_backoff_ms": 0},
                }
            )
            failed = self.module.execute_response_action(action["id"], actor="tester", dry_run=False, payload={"message": "retry-me"})
            dlq = self.module.list_response_dlq(limit=10)

            self.assertEqual("error", failed["execution"]["status"])
            self.assertEqual(2, failed["execution"]["attempts_total"])
            self.assertEqual(action["id"], dlq[0]["action_id"])
            self.assertGreaterEqual(len(captured), 2)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        server, thread, captured, base_url = self._start_capture_server({"ok": True}, status=200)
        try:
            action = self.module.save_response_action(
                {
                    "id": action["id"],
                    "title": "Retry webhook action",
                    "kind": "webhook",
                    "approval_required": False,
                    "target": {"url": f"{base_url}/retry", "method": "POST", "retry_attempts": 1, "retry_backoff_ms": 0},
                }
            )
            retried = self.module.retry_response_execution(failed["execution"]["id"], actor="tester")
            replayed = self.module.replay_response_dlq(self.module.list_response_dlq(limit=10)[0]["id"], actor="tester")

            self.assertEqual("executed", retried["execution"]["status"])
            self.assertEqual("executed", replayed["execution"]["status"])
            self.assertTrue(captured)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_response_chain_partial_failure_can_resume_from_failed_step(self) -> None:
        first_server, first_thread, first_captured, first_url = self._start_capture_server({"ok": True}, status=200)
        failing_server, failing_thread, _, failing_url = self._start_capture_server({"ok": False}, status=503)
        try:
            action = self.module.save_response_action(
                {
                    "title": "Escalation chain",
                    "approval_required": False,
                    "steps": [
                        {"id": "first-hop", "title": "First hop", "kind": "webhook", "target": {"url": f"{first_url}/first", "method": "POST"}},
                        {"id": "second-hop", "title": "Second hop", "kind": "webhook", "target": {"url": f"{failing_url}/second", "method": "POST", "retry_attempts": 1, "retry_backoff_ms": 0}},
                    ],
                }
            )
            failed = self.module.execute_response_action(action["id"], actor="tester", dry_run=False, payload={"message": "chain"})

            self.assertEqual("partial_failure", failed["execution"]["status"])
            self.assertEqual(1, failed["execution"]["details"]["resume_from_step"])
            self.assertEqual(2, len(failed["execution"]["details"]["steps"]))
            self.assertTrue(first_captured)
        finally:
            first_server.shutdown()
            first_server.server_close()
            first_thread.join(timeout=2)
            failing_server.shutdown()
            failing_server.server_close()
            failing_thread.join(timeout=2)

        recovery_server, recovery_thread, recovery_captured, recovery_url = self._start_capture_server({"ok": True}, status=200)
        try:
            self.module.save_response_action(
                {
                    "id": action["id"],
                    "title": "Escalation chain",
                    "approval_required": False,
                    "steps": [
                        {"id": "first-hop", "title": "First hop", "kind": "webhook", "target": {"url": f"{recovery_url}/first", "method": "POST"}},
                        {"id": "second-hop", "title": "Second hop", "kind": "webhook", "target": {"url": f"{recovery_url}/second", "method": "POST", "retry_attempts": 1, "retry_backoff_ms": 0}},
                    ],
                }
            )
            retried = self.module.retry_response_execution(failed["execution"]["id"], actor="tester")
            self.assertEqual("executed", retried["execution"]["status"])
            self.assertEqual(1, len(recovery_captured))
            self.assertEqual("/second", recovery_captured[0]["path"])
        finally:
            recovery_server.shutdown()
            recovery_server.server_close()
            recovery_thread.join(timeout=2)

    def test_enterprise_release_gates_and_evidence_pack_are_exportable(self) -> None:
        governance = importlib.import_module("control_plane_governance_ops")

        gates = governance.build_enterprise_release_gates()
        evidence = governance.build_compliance_evidence_pack()

        self.assertFalse(gates["release_blocked"])
        self.assertEqual(0, gates["summary"]["failed"])
        self.assertGreaterEqual(len(gates["gates"]), 8)
        self.assertTrue(evidence["governance"]["export_supported"])
        self.assertIn("user_to_host", evidence["entity_operations"]["graph_relationships"])
        self.assertIn("host_outbound_destination", evidence["entity_operations"]["graph_relationships"])
        self.assertGreaterEqual(len(evidence["connector_registry"]), 10)

    def test_structured_risk_signal_materializes_behavior_and_graph_context(self) -> None:
        entity_id = ""
        for index, actor_ip in enumerate(("10.0.0.1", "10.0.0.2", "10.0.0.3"), start=1):
            recorded = self.module.record_risk_signal(
                {
                    "entity_type": "host",
                    "entity_name": "srv-web-01",
                    "summary": "failed auth burst winrm lateral privilege powershell execution",
                    "kind": "failed_auth",
                    "score": 25,
                    "severity": "high",
                    "source": "unit-test",
                    "context": {
                        "actor_ip": actor_ip,
                        "user_name": "alice",
                        "destination": "db01.internal",
                        "destination_ip": "198.51.100.20",
                        "service": "winrm",
                        "asset_id": f"srv-web-0{index}",
                        "indicator": "evil.example",
                        "vulnerability": "CVE-2026-1000",
                        "process_name": "powershell.exe",
                        "parent_process": "wmic.exe",
                        "host_name": "srv-web-01",
                    },
                },
                actor="tester",
            )
            entity_id = str(recorded["entity"]["id"])

        detail = self.module.get_entity(entity_id)
        self.assertIsNotNone(detail)
        assert detail is not None

        self.assertTrue(detail["baseline"]["failed_auth_burst"])
        self.assertTrue(detail["baseline"]["lateral_movement_precursor"])
        self.assertTrue(detail["baseline"]["privilege_escalation_precursor"])

        edge_labels = {str(item.get("label") or "") for item in detail["evidence_graph"]["edges"]}
        self.assertIn("user_to_host", edge_labels)
        self.assertIn("indicator_to_host", edge_labels)
        self.assertIn("asset_to_vulnerability", edge_labels)
        self.assertIn("process_to_parent", edge_labels)
        self.assertIn("host_outbound_destination", edge_labels)

        self.assertIn("evil.example", detail["investigation_bundle"]["indicators"])
        self.assertIn("CVE-2026-1000", detail["investigation_bundle"]["vulnerabilities"])
        self.assertIn("powershell.exe", detail["investigation_bundle"]["processes"])


if __name__ == "__main__":
    unittest.main()
