# Deployment Runbook: Kafka + VM5 Wave Preparation

This runbook is the executable scaffold for the first of the next two large release waves.

## Scope

- `VM5` as the additional transport and warm-standby processing node
- Kafka KRaft on `VM1 + VM2 + VM5`
- dual-write preparation and shadow-path readiness
- repo-owned service/unit/config skeletons before live cutover

## Repo Artifacts

- [kafka_cluster_layout.py](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/kafka_cluster_layout.py)
- [kafka_wave_prepare.py](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/kafka_wave_prepare.py)
- [kafka_wave_smoke.py](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/kafka_wave_smoke.py)
- [siem-kafka.service](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/vm1/siem-kafka.service)
- [siem-kafka.service](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/vm2/siem-kafka.service)
- [siem-kafka.service](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/vm5/siem-kafka.service)
- [vm5_processing_prepare.py](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/vm5_processing_prepare.py)
- [vm5_processing_smoke.py](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/vm5_processing_smoke.py)
- [prepare-kafka-wave.yml](C:/Users/lolol/Documents/Playground/remote-edit2/.github/workflows/prepare-kafka-wave.yml)

## Planned Node Map

- `VM1` -> broker/controller `node.id=1`, `192.168.1.35`
- `VM2` -> broker/controller `node.id=2`, `192.168.1.37`
- `VM5` -> broker/controller `node.id=3`, `192.168.1.40`

## Immediate Deliverables In This Preparation Slice

- repo-tracked KRaft topology and quorum layout
- repo-tracked bootstrap env exports for application services
- repo-tracked systemd unit scaffold for all three Kafka nodes
- repo-tracked prepare/smoke scripts for the Kafka wave
- repo-tracked VM5 processing prepare/smoke scripts for warm-standby workers
- repo-tracked manual GitHub Actions workflow for the Kafka preparation wave
- transport health API enriched with Kafka configuration visibility
- shadow-path health enriched with freshness/parity visibility so the cutover can be judged from `/api/health/transport` instead of ad-hoc ClickHouse queries

## Not Yet Live

This runbook does not claim a live Kafka cutover yet. It prepares the deployment truth so the next execution pass can focus on installation, dual-write validation, and Redis exit without inventing topology on the fly.

## Current Live Shadow Notes

- Kafka broker firewalls must allow `9092/tcp` not only from `VM1`, `VM2`, and `VM5`, but also from:
  - `VM3` for `siem-writer-shadow`
  - `VM4` for runtime and health probes
- `9093/tcp` should stay broker-only for the controller quorum
- `VM1` shadow ingress depends on both HTTP and syslog listeners using the transport producer path; if `siem.events_shadow` is flat while `siem.raw` grows, verify [syslog_server.py](C:/Users/lolol/Documents/Playground/remote-edit2/services/ingest/syslog_server.py) is deployed with producer-aware `push_raw_event(...)`
- if `siem.events_shadow` is fresh but `siem.events` suddenly flatlines during `dual_write`, verify [transport_runtime.py](C:/Users/lolol/Documents/Playground/remote-edit2/services/transport_runtime.py) is deployed with Redis-side dual-write publishing to `siem:raw` / `siem:normalized` / `siem:filtered` stream keys rather than Kafka topic names
- `VM5` shadow processing must keep:
  - `SIEM_TRANSPORT_BACKEND=kafka`
  - `SIEM_TRANSPORT_CONSUMER_BACKEND=kafka`
  A `dual` producer backend on `VM5` will regress into Redis/Sentinel dependency and stall the shadow path.
- [vm3_kafka_shadow_writer_smoke.py](C:/Users/lolol/Documents/Playground/remote-edit2/deploy/vm3_kafka_shadow_writer_smoke.py) now prints `shadow_events_5m`, `shadow_events_15m`, and `shadow_max_ts`; set `SIEM_KAFKA_REQUIRE_SHADOW_FLOW=1` when you need the smoke to fail hard on an empty shadow pipeline.
