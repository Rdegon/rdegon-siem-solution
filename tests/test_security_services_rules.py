from __future__ import annotations

import json
from pathlib import Path

from services.filter.filter_core import eval_expr, parse_expr


ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = ROOT / "correlation_rule_packs" / "security_services_v1.json"


def _rules() -> dict[int, dict[str, object]]:
    payload = json.loads(PACK_PATH.read_text(encoding="utf-8"))
    return {int(item["id"]): item for item in payload["stream_rules"]}


def _matches(rule: dict[str, object], event: dict[str, str]) -> bool:
    return bool(eval_expr(parse_expr(str(rule["expr"])), event))


def test_security_service_rules_are_active_and_parseable() -> None:
    rules = _rules()
    assert set(rules) == {3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008}
    for rule in rules.values():
        assert rule["status"] == "active"
        assert parse_expr(str(rule["expr"]))


def test_zeek_capture_loss_is_health_not_attack() -> None:
    rule = _rules()[3001]
    assert not _matches(
        rule,
        {
            "event.provider": "zeek",
            "event.type": "zeek_notice",
            "rule.name": "PacketFilter::Dropped_Packets",
            "tags": "",
        },
    )
    assert _matches(
        rule,
        {
            "event.provider": "zeek",
            "event.type": "zeek_notice",
            "rule.name": "SSH::Password_Guessing",
            "tags": "",
        },
    )


def test_falco_canary_and_routine_velociraptor_collection_do_not_alert() -> None:
    rules = _rules()
    assert not _matches(
        rules[3002],
        {
            "event.provider": "falco",
            "event.type": "falco_runtime_alert",
            "event.severity": "medium",
            "rule.name": "SIEM Falco Pipeline Canary",
            "process.command_line": "siem-falco-e2e",
            "tags": "",
        },
    )
    assert not _matches(
        rules[3004],
        {
            "event.provider": "velociraptor",
            "event.type": "velociraptor_artifact_result",
            "event.severity": "info",
            "host.name": "WIN-RTX-test",
            "tags": "telemetry:endpoint",
        },
    )


def test_confirmed_malware_and_repeated_service_failure_match() -> None:
    rules = _rules()
    assert _matches(
        rules[3003],
        {
            "event.type": "malware_analysis_result",
            "event.outcome": "failure",
            "file.sha256": "a" * 64,
            "tags": "analysis:static,verdict:malicious",
        },
    )
    assert _matches(
        rules[3005],
        {
            "event.provider": "host.metrics",
            "event.type": "host_service_down",
            "host.name": "soc-evidence-01",
            "service.name": "minio",
            "tags": "",
        },
    )
    assert not _matches(
        rules[3005],
        {
            "event.provider": "host.metrics",
            "event.type": "host_service_down",
            "host.name": "pilot-web-01",
            "service.name": "docker",
            "tags": "",
        },
    )


def test_minio_rule_requires_explicit_repeated_authorization_failures() -> None:
    rule = _rules()[3006]
    assert _matches(
        rule,
        {
            "event.provider": "minio",
            "event.type": "object_storage_access",
            "event.outcome": "failure",
            "http.response.status_code": "403",
            "source.ip": "10.20.40.15",
            "tags": "",
        },
    )
    assert not _matches(
        rule,
        {
            "event.provider": "minio",
            "event.type": "object_storage_access",
            "event.outcome": "failure",
            "http.response.status_code": "404",
            "source.ip": "10.20.40.15",
            "tags": "",
        },
    )
    assert not _matches(
        rule,
        {
            "event.provider": "minio",
            "event.type": "object_storage_access",
            "event.outcome": "success",
            "http.response.status_code": "200",
            "source.ip": "10.20.40.15",
            "tags": "",
        },
    )


def test_pki_and_arkime_rules_ignore_successful_operations() -> None:
    rules = _rules()
    assert _matches(
        rules[3007],
        {
            "event.provider": "step-ca",
            "event.type": "certificate_issued",
            "event.outcome": "failure",
            "source.ip": "10.20.40.15",
            "tags": "",
        },
    )
    assert not _matches(
        rules[3007],
        {
            "event.provider": "step-ca",
            "event.type": "certificate_issued",
            "event.outcome": "success",
            "source.ip": "10.20.40.15",
            "tags": "",
        },
    )
    assert _matches(
        rules[3008],
        {
            "event.provider": "arkime",
            "event.type": "ndr_capture_health",
            "event.outcome": "failure",
            "host.name": "soc-ndr-01",
            "tags": "",
        },
    )
    assert not _matches(
        rules[3008],
        {
            "event.provider": "arkime",
            "event.type": "ndr_capture_health",
            "event.outcome": "success",
            "host.name": "soc-ndr-01",
            "tags": "",
        },
    )
