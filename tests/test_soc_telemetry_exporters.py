from __future__ import annotations

import json

from deploy.journal_event_exporter import journal_document
from deploy.minio_audit_receiver import AuditWriter


def test_step_ca_journal_json_is_preserved_and_decorated() -> None:
    document = journal_document(
        {
            "MESSAGE": json.dumps(
                {
                    "method": "POST",
                    "path": "/1.0/sign",
                    "status": 201,
                    "remote-address": "10.20.10.133:42210",
                }
            ),
            "__REALTIME_TIMESTAMP": "1785191000000000",
            "__CURSOR": "cursor-1",
            "_PID": "42",
        },
        provider="step-ca",
        host_name="soc-pki-01",
    )

    assert document is not None
    assert document["method"] == "POST"
    assert document["event.dataset"] == "step-ca.audit"
    assert document["host.name"] == "soc-pki-01"
    assert document["journal.cursor"] == "cursor-1"


def test_step_ca_logfmt_is_parsed_without_sensitive_material() -> None:
    document = journal_document(
        {
            "MESSAGE": (
                'time="2026-07-28T01:41:54+03:00" level=info method=POST '
                "path=/sign status=201 remote-address=10.20.10.132 "
                "request-id=req-1 subject=service-1 certificate=MIICSECRET "
                "ott=eyJhbGciOiJIUzI1NiJ9.secret.signature"
            ),
            "__REALTIME_TIMESTAMP": "1785191000000000",
        },
        provider="step-ca",
        host_name="soc-pki-01",
    )

    assert document is not None
    assert document["path"] == "/sign"
    assert document["status"] == "201"
    assert document["subject"] == "service-1"
    assert "certificate" not in document
    assert "ott" not in document
    assert "MIICSECRET" not in document["message"]
    assert "eyJhbGci" not in document["message"]


def test_minio_audit_writer_accepts_batches(tmp_path) -> None:
    output = tmp_path / "audit.jsonl"
    writer = AuditWriter(output)

    assert writer.append([{"api": {"name": "PutObject"}}, {"api": {"name": "GetObject"}}]) == 2
    records = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert [record["api"]["name"] for record in records] == ["PutObject", "GetObject"]


def test_minio_audit_writer_rejects_non_objects(tmp_path) -> None:
    writer = AuditWriter(tmp_path / "audit.jsonl")
    assert writer.append(["not-an-event", 42]) == 0
