from deploy.velociraptor_flow_exporter import _flow_event, _timestamp_from_micros


def test_flow_event_preserves_client_and_collection_identity():
    identity, event = _flow_event(
        {"client_id": "C.123", "hostname": "endpoint-01", "system": "windows"},
        {
            "client_id": "C.123",
            "session_id": "F.456",
            "active_time": 1_700_000_000_000_000,
            "state": "FINISHED",
            "total_collected_rows": 12,
            "artifacts_with_results": ["Generic.Client.Info/BasicInformation"],
        },
    )

    assert identity == "C.123:F.456"
    assert event["client_id"] == "C.123"
    assert event["flow_id"] == "F.456"
    assert event["hostname"] == "endpoint-01"
    assert event["event.outcome"] == "success"
    assert event["collected_rows"] == 12


def test_timestamp_from_micros_is_utc_iso8601():
    assert _timestamp_from_micros(1_700_000_000_000_000).endswith("Z")
