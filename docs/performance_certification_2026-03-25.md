# Performance Certification

## Current State

The old single-client HTTPS benchmark remains useful for regression checks, but not for platform capacity claims.

This wave adds a distributed benchmark harness:

- remote injector worker
- coordinated multi-host execution
- stage-based EPS ramp
- ClickHouse delivery verification
- Kafka consumer lag snapshot

## Operator Commands

- `python deploy/distributed_eps_benchmark.py`
- `python tools/siem_operator_cli.py performance distributed-eps --stages 1000,2500,5000`

## Metrics Captured

- target EPS per stage
- achieved EPS
- stored event count
- delivery ratio
- max observed consumer lag

## Residual Gap

- alert latency remains conditional on deterministic rule firing for the synthetic workload
- final release certification still needs a repeated multi-run budget table per topology
