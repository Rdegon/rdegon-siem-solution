# EPS Benchmark 2026-03-24

This run measured the current ceiling of the **existing single-client HTTPS benchmark harness**, not the theoretical maximum of the backend under distributed load.

## Result

- validated delivery for earlier stages at `2000`, `4000`, and `6000` target EPS on the original stage-counting pass
- the first upper-band probes at `7000+` destabilized the storage plane enough to require a controlled `VM3` storage restart
- the corrected harness shows the current injector ceiling clearly:

```json
{
  "eps_target": 6500,
  "stage_duration_sec": 10,
  "sent": 65000,
  "stored": 65000,
  "delivery_ratio": 1.0,
  "actual_duration_sec": 367.46,
  "achieved_eps": 176.89
}
```

## Interpretation

- The bottleneck in this benchmark is the **single-threaded HTTPS event injector path**, not the Kafka/ClickHouse storage plane.
- The harness tried to pace at `6500 EPS`, but only achieved about `176.89 EPS` end-to-end from one client.
- This means the current script is useful for regression and delivery-ratio checks, but **not** for claiming the platform's true maximum backend EPS.

## Operational Conclusion

- The current validated ceiling for the existing benchmark harness is about `177 EPS`.
- After the benchmark and controlled recovery, the live platform returned to a healthy state:
  - `/api/health/storage-ha` -> all three backends healthy
  - `/api/health/transport` -> `kafka`, shadow healthy
  - `/api/health/overview` -> fresh events and alerts visible again

## Next Benchmarking Step

To measure the real backend ceiling, the next benchmark wave should use:

- concurrent ingest workers
- multiple HTTP clients or direct collector fan-out
- separate measurement of:
  - ingest accept rate
  - Kafka lag
  - ClickHouse write rate
  - end-to-end alert latency
