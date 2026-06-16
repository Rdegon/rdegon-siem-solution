# Configuration And Runtime Layout

## Runtime Env Files

### VM1 `192.168.1.35`

- path: `/etc/siem/ingest.env`
- purpose: ingest edge, syslog listeners, HTTP ingest, Kafka producer settings
- key settings:
  - `SIEM_TRANSPORT_BACKEND`
  - `SIEM_KAFKA_BOOTSTRAP_SERVERS`
  - `SIEM_KAFKA_TOPIC_RAW`
  - `SIEM_INGEST_SYSLOG_*`
  - `SIEM_INGEST_HTTP_HOST`
  - `SIEM_INGEST_HTTP_PORT`
  - `SIEM_INGEST_RAW_STREAM_SOFT_LIMIT`
  - `SIEM_INGEST_RAW_STREAM_HARD_LIMIT`

### VM2 `192.168.1.37`

- path: `/etc/siem/processing.env`
- purpose: Kafka-backed normalizer/filter runtime
- key settings:
  - `SIEM_TRANSPORT_BACKEND=kafka`
  - `SIEM_KAFKA_BOOTSTRAP_SERVERS`
  - `SIEM_KAFKA_TOPIC_RAW`
  - `SIEM_KAFKA_TOPIC_NORMALIZED`
  - `SIEM_KAFKA_TOPIC_FILTERED`
  - `SIEM_FILTER_BATCH_SIZE`
  - `SIEM_CH_HOST`
  - `SIEM_CH_PORT`
  - `SIEM_CH_DB`

### VM3 `192.168.1.38`

- path: `/etc/siem/storage.env`
- purpose: ClickHouse primary, Kafka-backed writer/correlation, SQLite runtime state
- key settings:
  - `SIEM_TRANSPORT_BACKEND=kafka`
  - `SIEM_KAFKA_BOOTSTRAP_SERVERS`
  - `SIEM_KAFKA_TOPIC_FILTERED`
  - `SIEM_STREAM_STATE_BACKEND=sqlite`
  - `SIEM_STREAM_STATE_SQLITE_PATH`
  - `SIEM_STREAM_CORR_TIME_MODE`
  - `SIEM_STREAM_CORR_ALLOWED_LATENESS_SEC`
  - `SIEM_STREAM_CORR_WATERMARK_LAG_SEC`
  - `SIEM_BATCH_CORR_INTERVAL_SEC`
  - `SIEM_ALERT_AGG_INTERVAL_SEC`
  - `SIEM_CH_HOST`
  - `SIEM_CH_PORT`
  - `SIEM_CH_DB`

### VM4 `192.168.1.39`

- path: `/etc/siem/web.env`
- purpose: web/API, auth, Postgres control plane, Mongo content plane
- key settings:
  - `SIEM_CH_HOST`
  - `SIEM_CH_PORT`
  - `SIEM_CH_DB`
  - `SIEM_WEB_BIND_HOST`
  - `SIEM_WEB_BIND_PORT`
  - `SIEM_WEB_BASE_URL`
  - `SIEM_JWT_SECRET`
  - `SIEM_ADMIN_DEFAULT_PASSWORD_HASH`
  - `SIEM_WEB_USERS_JSON`
  - `SIEM_CONTROL_PLANE_BACKEND=postgres`
  - `SIEM_CONTROL_PLANE_PG_DSN`
  - `SIEM_CONTENT_STORE_BACKEND=mongo`
  - `SIEM_MONGO_URI`
  - `SIEM_MONGO_DB`

### VM4 storage HA env

- path: `/etc/siem/storage-ha.env`
- purpose: Postgres standby and Mongo replica topology

### VM5 `192.168.1.40`

- paths:
  - `/etc/siem/processing.env`
  - `/etc/siem/storage-standby.env`
- purpose: Kafka node, secondary processing, ClickHouse standby, Mongo secondary

## Systemd Units

### VM1

- `siem-ingest.service`
- `nginx.service`
- `actions.runner.Rdegon-siem-solution.siem-vm1.service`
- `siem-host-runtime-agent.timer`

### VM2

- `siem-normalizer.service`
- `siem-normalizer@2.service`
- `siem-filter.service`
- `siem-filter@2.service`
- `siem-kafka.service`
- `actions.runner.Rdegon-siem-solution.siem-vm2.service`
- `siem-host-runtime-agent.timer`

### VM3

- `clickhouse-server.service`
- `siem-writer.service`
- `siem-writer@2.service`
- `siem-stream-corr.service`
- `siem-batch-corr.service`
- `siem-alert-agg.service`
- `actions.runner.Rdegon-siem-solution.siem-vm3.service`
- `siem-host-runtime-agent.timer`

### VM4

- `siem-web.service`
- `postgresql.service`
- `mongod.service`
- `nginx.service`
- `openvpn-client@home-gateway.service`
- `siem-jump-tunnels.service`
- `siem-host-runtime-agent.timer`
- `siem-host-runtime-monitor.timer`
- `actions.runner.Rdegon-siem-solution.siem-vm4.service`

### VM5

- `siem-kafka.service`
- `siem-normalizer@1.service`
- `siem-normalizer@2.service`
- `siem-filter@1.service`
- `siem-filter@2.service`
- `siem-clickhouse-standby-sync.timer`
- `actions.runner.Rdegon-siem-solution.siem-vm5.service`
- `siem-host-runtime-agent.timer`

## Code Layout

### Web/API

- `services/web/main.py`
- `services/web/app/config.py`
- `services/web/app/security.py`
- `services/web/app/content_store.py`
- `services/web/app/deps.py`
- `services/web/app/routes/*`
- `services/web/app/templates/*`

### Ingest

- `services/ingest/app.py`
- `services/ingest/syslog_server.py`
- `services/ingest/config.py`
- `services/transport_runtime.py`

### Processing

- `services/normalizer/worker.py`
- `services/normalizer/normalizer_core.py`
- `services/filter/worker.py`
- `services/filter/filter_core.py`

### Storage / Correlation

- `services/writer/worker.py`
- `services/stream_corr/worker.py`
- `services/stream_corr/rules.py`
- `services/stream_state.py`
- `services/batch_corr/worker.py`
- `services/alert_agg/worker.py`

## Notes

- Redis is retired from the live runtime path.
- Historical documents from the Redis wave remain in the repo as incident history, not as current runtime guidance.
- VM access and operator entry points are documented in `docs/vm_access.md` and the approved operator bundle.
