# Deployment Runbook

1. Verify the source tree:

```powershell
git status --short
python -m pytest tests/test_transport_runtime.py tests/test_ingest_fabric.py tests/test_stream_worker.py tests/test_full_rule_audit.py tests/test_event_incident_query_stability.py
```

2. Deploy in order:
- VM1 ingest/transport;
- VM2 normalizer/filter workers;
- VM3 writer, ClickHouse and stream correlation;
- VM4 Web/API;
- collectors/sources.

3. Smoke checks:
- `/health` on ingest and web;
- Kafka consumer lag for raw, normalized and filtered topics;
- ClickHouse writes into `siem.events`;
- stream correlation runtime status freshness;
- Web pages: incidents, events, sources, assets and rules.

4. Apply the stock performance profile, first as dry-run and then with an explicit execute:

```powershell
python deploy/apply_stock_performance_profile.py --profile balanced --restart --output runtime-control-plane/stock-profile-dry-run.json
python deploy/apply_stock_performance_profile.py --profile balanced --execute --restart --output runtime-control-plane/stock-profile-apply.json
```

If sudo is not passwordless, set per-host environment variables such as
`SIEM_VM1_PASSWORD`, `SIEM_VM2_PASSWORD`, `SIEM_VM3_PASSWORD`, `SIEM_VM5_PASSWORD`
or pass a shared fallback with `--sudo-password-env SIEM_NODE_PASSWORD`.

Use `--profile aggressive` only after the balanced profile has a clean EPS report.

5. EPS validation:

```powershell
python deploy/eps_ladder_live.py --stages 500,750,1000,1250,1500 --output runtime-control-plane/eps-ladder-live/eps_ladder.json
python deploy/cleanup_eps_benchmark_events.py --report runtime-control-plane/eps-ladder-live/eps_ladder.json --execute
```

6. Do not promote if:
- ingest p95 ACK keeps growing across a 10 minute 500 EPS run;
- Kafka lag does not drain after the test window;
- incident drawer cannot load details within the UI timeout;
- rule audit reports rules without decisions.
