from __future__ import annotations

from typing import Any


def _dedupe_window(item: dict[str, Any]) -> int:
    value = item.get("dedupe_window_s") or item.get("_dedupe_window_s") or 86400
    return max(300, int(value))


def _sql_literal(value: object) -> str:
    return str(value or "").replace("\\", "\\\\").replace("'", "''")


def _wrap_batch_candidate(
    item: dict[str, Any],
    *,
    candidate_sql: str,
) -> str:
    rule_id = int(item["id"])
    title = _sql_literal(item.get("title") or item.get("source_id") or rule_id)
    severity = _sql_literal(item.get("severity") or "medium")
    dedupe_window_s = _dedupe_window(item)
    return f"""INSERT INTO siem.alerts_raw
(ts, alert_id, rule_id, rule_name, severity, ts_first, ts_last, window_s, entity_key, hits, context_json, source, status)
SELECT
    now(),
    generateUUIDv4(),
    {rule_id},
    '{title}',
    '{severity}',
    candidate.ts_first,
    candidate.ts_last,
    {{WINDOW_S}},
    candidate.entity_key,
    candidate.hits,
    candidate.context_json,
    candidate.source,
    'open'
FROM
(
{candidate_sql}
) AS candidate
LEFT JOIN
(
    SELECT entity_key
    FROM siem.alerts_raw
    WHERE rule_id = {rule_id}
      AND ts >= now() - INTERVAL {dedupe_window_s} SECOND
      AND lower(status) IN ('open', 'false_positive', 'suppressed')
    GROUP BY entity_key
) AS existing
ON candidate.entity_key = existing.entity_key
WHERE existing.entity_key = ''"""


def _new_internal_ip_sql(item: dict[str, Any]) -> str:
    candidate_sql = """    SELECT
        IPv4NumToString(e.src_ip) AS entity_key,
        IPv4NumToString(e.src_ip) AS source,
        min(e.ts) AS ts_first,
        max(e.ts) AS ts_last,
        count() AS hits,
        concat(
            '{"event_type":"new_internal_ip","source_id":"HB-006","source":"',
            IPv4NumToString(e.src_ip), '","hits":', toString(count()), '}'
        ) AS context_json
    FROM siem.events AS e
    LEFT JOIN
    (
        SELECT ip
        FROM siem.cmdb_assets FINAL
        WHERE enabled = 1 AND ip != ''
        GROUP BY ip
    ) AS known
      ON known.ip = IPv4NumToString(e.src_ip)
    PREWHERE e.ts >= now() - INTERVAL {WINDOW_S} SECOND
    WHERE e.src_ip != 0
      AND
      (
          isIPAddressInRange(IPv4NumToString(e.src_ip), '10.20.0.0/16')
      )
      AND IPv4NumToString(e.src_ip) NOT IN
      (
          '10.20.10.1', '10.20.20.1', '10.20.30.1',
          '10.20.40.1', '10.20.50.1', '10.20.10.254'
      )
      AND known.ip = ''
      AND positionCaseInsensitiveUTF8(toString(e.tags), 'allowlist:') = 0
      AND positionCaseInsensitiveUTF8(toString(e.tags), 'benchmark') = 0
      AND positionCaseInsensitiveUTF8(toString(e.tags), 'synthetic') = 0
      AND positionCaseInsensitiveUTF8(toString(e.tags), 'e2e') = 0
    GROUP BY entity_key, source
    HAVING hits >= 20"""
    return _wrap_batch_candidate(item, candidate_sql=candidate_sql)


def _unmonitored_discovered_host_sql(item: dict[str, Any]) -> str:
    candidate_sql = """    SELECT
        IPv4NumToString(e.dst_ip) AS entity_key,
        IPv4NumToString(e.dst_ip) AS source,
        min(e.ts) AS ts_first,
        max(e.ts) AS ts_last,
        count() AS hits,
        concat(
            '{"event_type":"unmonitored_discovered_host","source_id":"HB-013","source":"',
            IPv4NumToString(e.dst_ip), '","hits":', toString(count()), '}'
        ) AS context_json
    FROM siem.events AS e
    LEFT JOIN
    (
        SELECT ip
        FROM siem.cmdb_assets FINAL
        WHERE enabled = 1 AND ip != ''
        GROUP BY ip
    ) AS known
      ON known.ip = IPv4NumToString(e.dst_ip)
    PREWHERE e.ts >= now() - INTERVAL {WINDOW_S} SECOND
    WHERE e.dst_ip != 0
      AND
      (
          e.device_product IN ('vuln.nmap', 'asset.discovery', 'host.discovery')
          OR e.category IN ('asset', 'discovery', 'vulnerability')
      )
      AND
      (
          isIPAddressInRange(IPv4NumToString(e.dst_ip), '10.20.0.0/16')
          OR isIPAddressInRange(IPv4NumToString(e.dst_ip), '192.168.3.0/24')
      )
      AND known.ip = ''
      AND positionCaseInsensitiveUTF8(toString(e.tags), 'allowlist:') = 0
      AND positionCaseInsensitiveUTF8(toString(e.tags), 'benchmark') = 0
      AND positionCaseInsensitiveUTF8(toString(e.tags), 'synthetic') = 0
      AND positionCaseInsensitiveUTF8(toString(e.tags), 'e2e') = 0
    GROUP BY entity_key, source
    HAVING hits >= 3"""
    return _wrap_batch_candidate(item, candidate_sql=candidate_sql)


def _unexpected_known_host_port_sql(item: dict[str, Any]) -> str:
    candidate_sql = """    SELECT
        c.hostname AS entity_key,
        c.hostname AS source,
        min(e.ts) AS ts_first,
        max(e.ts) AS ts_last,
        count() AS hits,
        concat(
            '{"event_type":"unexpected_known_host_port","source_id":"HB-014","source":"',
            c.hostname, '","destination_ip":"', c.ip, '","hits":', toString(count()), '}'
        ) AS context_json
    FROM siem.events AS e
    INNER JOIN siem.cmdb_assets AS c FINAL
      ON c.ip = IPv4NumToString(e.dst_ip)
    PREWHERE e.ts >= now() - INTERVAL {WINDOW_S} SECOND
    WHERE c.enabled = 1
      AND e.dst_ip != 0
      AND e.dst_port > 0
      AND c.expected_ports != ''
      AND
      (
          e.device_product IN ('vuln.nmap', 'asset.discovery', 'host.discovery')
          OR e.category = 'vulnerability'
      )
      AND
      (
          e.event_action = 'finding'
          OR positionCaseInsensitiveUTF8(toString(e.message), 'Open service ') = 1
      )
      AND NOT has(
          splitByChar(',', replaceAll(c.expected_ports, ' ', '')),
          toString(e.dst_port)
      )
      AND positionCaseInsensitiveUTF8(toString(e.tags), 'allowlist:') = 0
      AND positionCaseInsensitiveUTF8(toString(e.tags), 'benchmark') = 0
      AND positionCaseInsensitiveUTF8(toString(e.tags), 'synthetic') = 0
      AND positionCaseInsensitiveUTF8(toString(e.tags), 'e2e') = 0
    GROUP BY entity_key, source, c.ip
    HAVING hits >= 3"""
    return _wrap_batch_candidate(item, candidate_sql=candidate_sql)


def _host_silence_sql(
    item: dict[str, Any],
    *,
    source_id: str,
    silence_hours: int,
    siem_core_only: bool = False,
) -> str:
    rule_id = int(item["id"])
    title = _sql_literal(item.get("title") or f"{source_id} source silence")
    severity = _sql_literal(item.get("severity") or "high")
    dedupe_window_s = _dedupe_window(item)
    scope_clause = (
        "AND c.hostname IN "
        "('siem-ingest', 'siem-processing', 'siem-storage', 'siem-web', 'siem-transport')"
        if siem_core_only
        else """AND
      (
          positionCaseInsensitiveUTF8(c.tags, 'proxmox-fleet') > 0
          OR positionCaseInsensitiveUTF8(c.tags, 'siem') > 0
          OR positionCaseInsensitiveUTF8(c.tags, 'pilot') > 0
          OR positionCaseInsensitiveUTF8(c.tags, 'public_services') > 0
          OR positionCaseInsensitiveUTF8(c.tags, 'game') > 0
          OR positionCaseInsensitiveUTF8(c.tags, 'vuln') > 0
          OR positionCaseInsensitiveUTF8(c.tags, 'edge_gateway') > 0
          OR c.hostname IN ('pve', 'lab-edge-01')
      )"""
    )
    return f"""INSERT INTO siem.alerts_raw
(ts, alert_id, rule_id, rule_name, severity, ts_first, ts_last, window_s, entity_key, hits, context_json, source, status)
SELECT
    now(),
    generateUUIDv4(),
    {rule_id},
    '{title}',
    '{severity}',
    candidate.ts_first,
    candidate.ts_last,
    {{WINDOW_S}},
    candidate.entity_key,
    candidate.hits,
    candidate.context_json,
    candidate.source,
    'open'
FROM
(
    SELECT
        heartbeat.hostname AS entity_key,
        heartbeat.hostname AS source,
        heartbeat.last_seen_ts AS ts_first,
        heartbeat.last_seen_ts AS ts_last,
        1 AS hits,
        concat(
            '{{"event_type":"source_silence","source_id":"{source_id}",',
            '"source":"', heartbeat.hostname, '","last_seen":"',
            toString(heartbeat.last_seen_ts), '","silence_hours":{silence_hours}}}'
        ) AS context_json
    FROM
    (
        SELECT
            c.hostname AS hostname,
            max(e.last_seen_ts) AS last_seen_ts
        FROM siem.cmdb_assets AS c FINAL
        INNER JOIN
        (
            SELECT
                lowerUTF8(if(host_name != '' AND host_name != '-', host_name, log_source)) AS host_key,
                max(ts) AS last_seen_ts
            FROM siem.events
            PREWHERE ts >= now() - INTERVAL 30 DAY
            WHERE if(host_name != '' AND host_name != '-', host_name, log_source) != ''
              AND positionCaseInsensitiveUTF8(toString(tags), 'benchmark') = 0
              AND positionCaseInsensitiveUTF8(toString(tags), 'synthetic') = 0
              AND positionCaseInsensitiveUTF8(toString(tags), 'e2e') = 0
              AND positionCaseInsensitiveUTF8(lowerUTF8(if(host_name != '' AND host_name != '-', host_name, log_source)), 'assignment-full') = 0
              AND positionCaseInsensitiveUTF8(lowerUTF8(if(host_name != '' AND host_name != '-', host_name, log_source)), 'validation') = 0
              AND positionCaseInsensitiveUTF8(lowerUTF8(if(host_name != '' AND host_name != '-', host_name, log_source)), 'eps-bench') = 0
            GROUP BY host_key
        ) AS e
          ON lowerUTF8(c.hostname) = e.host_key OR lowerUTF8(c.ip) = e.host_key
        WHERE c.enabled = 1
          AND c.hostname != ''
          AND lowerUTF8(c.hostname) NOT IN ('win-rtx-test', 'desktop-5jmjvbh')
          AND positionCaseInsensitiveUTF8(c.tags, 'planned_offline') = 0
          AND positionCaseInsensitiveUTF8(c.tags, 'auto-discovered') = 0
          AND positionCaseInsensitiveUTF8(c.tags, 'operator') = 0
          AND match(c.hostname, '^[0-9]{{1,3}}(\\.[0-9]{{1,3}}){{3}}$') = 0
          {scope_clause}
        GROUP BY c.hostname
        HAVING max(e.last_seen_ts) < now() - INTERVAL {silence_hours} HOUR
    ) AS heartbeat
) AS candidate
LEFT JOIN
(
    SELECT entity_key
    FROM siem.alerts_raw
    WHERE rule_id = {rule_id}
      AND ts >= now() - INTERVAL {dedupe_window_s} SECOND
      AND lower(status) IN ('open', 'false_positive', 'suppressed')
    GROUP BY entity_key
) AS existing
ON candidate.entity_key = existing.entity_key
WHERE existing.entity_key = ''"""


def _host_volume_spike_sql(item: dict[str, Any]) -> str:
    candidate_sql = """    WITH recent AS
    (
        SELECT
            if(host_name != '' AND host_name != '-', host_name, log_source) AS entity_key,
            count() AS recent_hits,
            min(ts) AS ts_first,
            max(ts) AS ts_last
        FROM siem.events
        PREWHERE ts >= now() - INTERVAL {WINDOW_S} SECOND
        WHERE if(host_name != '' AND host_name != '-', host_name, log_source) != ''
          AND positionCaseInsensitiveUTF8(toString(tags), 'allowlist:') = 0
          AND positionCaseInsensitiveUTF8(toString(tags), 'benchmark') = 0
          AND positionCaseInsensitiveUTF8(toString(tags), 'synthetic') = 0
          AND positionCaseInsensitiveUTF8(toString(tags), 'e2e') = 0
        GROUP BY entity_key
    ), baseline AS
    (
        SELECT
            if(host_name != '' AND host_name != '-', host_name, log_source) AS entity_key,
            greatest(count() / 144, 1) AS baseline_10m
        FROM siem.events
        PREWHERE ts >= now() - INTERVAL 24 HOUR
        WHERE ts < now() - INTERVAL {WINDOW_S} SECOND
          AND if(host_name != '' AND host_name != '-', host_name, log_source) != ''
          AND positionCaseInsensitiveUTF8(toString(tags), 'allowlist:') = 0
          AND positionCaseInsensitiveUTF8(toString(tags), 'benchmark') = 0
          AND positionCaseInsensitiveUTF8(toString(tags), 'synthetic') = 0
          AND positionCaseInsensitiveUTF8(toString(tags), 'e2e') = 0
        GROUP BY entity_key
    )
    SELECT
        r.entity_key AS entity_key,
        r.entity_key AS source,
        r.ts_first AS ts_first,
        r.ts_last AS ts_last,
        r.recent_hits AS hits,
        concat(
            '{"event_type":"host_volume_spike","source_id":"HB-011","source":"',
            r.entity_key, '","recent_hits":', toString(r.recent_hits),
            ',"baseline_10m":', toString(b.baseline_10m), '}'
        ) AS context_json
    FROM recent AS r
    INNER JOIN baseline AS b ON r.entity_key = b.entity_key
    WHERE b.baseline_10m >= 100
      AND r.recent_hits >= greatest(toUInt64(100000), toUInt64(b.baseline_10m * 20))"""
    return _wrap_batch_candidate(item, candidate_sql=candidate_sql)


def _host_volume_drop_sql(item: dict[str, Any]) -> str:
    candidate_sql = """    SELECT
        entity_key,
        source,
        ts_first,
        ts_last,
        hits,
        context_json
    FROM
    (
        WITH recent AS
        (
            SELECT
                if(host_name != '' AND host_name != '-', host_name, log_source) AS entity_key,
                count() AS recent_hits
            FROM siem.events
            PREWHERE ts >= now() - INTERVAL {WINDOW_S} SECOND
            WHERE if(host_name != '' AND host_name != '-', host_name, log_source) != ''
              AND positionCaseInsensitiveUTF8(toString(tags), 'allowlist:') = 0
              AND positionCaseInsensitiveUTF8(toString(tags), 'benchmark') = 0
              AND positionCaseInsensitiveUTF8(toString(tags), 'synthetic') = 0
              AND positionCaseInsensitiveUTF8(toString(tags), 'e2e') = 0
            GROUP BY entity_key
        ), baseline AS
        (
            SELECT
                if(host_name != '' AND host_name != '-', host_name, log_source) AS entity_key,
                greatest(count() / 23, 1) AS baseline_1h
            FROM siem.events
            PREWHERE ts >= now() - INTERVAL 24 HOUR
            WHERE ts < now() - INTERVAL {WINDOW_S} SECOND
              AND if(host_name != '' AND host_name != '-', host_name, log_source) != ''
              AND positionCaseInsensitiveUTF8(toString(tags), 'allowlist:') = 0
              AND positionCaseInsensitiveUTF8(toString(tags), 'benchmark') = 0
              AND positionCaseInsensitiveUTF8(toString(tags), 'synthetic') = 0
              AND positionCaseInsensitiveUTF8(toString(tags), 'e2e') = 0
            GROUP BY entity_key
        )
        SELECT
            b.entity_key AS entity_key,
            b.entity_key AS source,
            now() - INTERVAL {WINDOW_S} SECOND AS ts_first,
            now() AS ts_last,
            toUInt64(ifNull(r.recent_hits, 0)) AS hits,
            concat(
                '{"event_type":"host_volume_drop","source_id":"HB-012","source":"',
                b.entity_key, '","recent_hits":', toString(ifNull(r.recent_hits, 0)),
                ',"baseline_1h":', toString(b.baseline_1h), '}'
            ) AS context_json,
            count() OVER () AS dropped_entities
        FROM baseline AS b
        LEFT JOIN recent AS r ON r.entity_key = b.entity_key
        INNER JOIN siem.cmdb_assets AS c FINAL ON lowerUTF8(c.hostname) = lowerUTF8(b.entity_key)
        WHERE c.enabled = 1
          AND positionCaseInsensitiveUTF8(c.tags, 'planned_offline') = 0
          AND positionCaseInsensitiveUTF8(c.tags, 'bursty-telemetry') = 0
          AND lowerUTF8(b.entity_key) NOT IN ('opnsense-staging', '127.0.0.1')
          AND b.baseline_1h >= 500
          AND ifNull(r.recent_hits, 0) < greatest(toUInt64(5), toUInt64(b.baseline_1h * 0.01))
    )
    WHERE dropped_entities <= 2"""
    return _wrap_batch_candidate(item, candidate_sql=candidate_sql)


def _future_event_sql(item: dict[str, Any]) -> str:
    rule_id = int(item["id"])
    title = _sql_literal(item.get("title") or "HB-010 Future event timestamp")
    severity = _sql_literal(item.get("severity") or "medium")
    dedupe_window_s = _dedupe_window(item)
    legacy_exclusions: list[str] = []
    for host_name, raw_offset in dict(item.get("legacy_event_offset_cutoffs") or {}).items():
        safe_host = _sql_literal(host_name).lower()
        cutoff = max(0, int(raw_offset))
        legacy_exclusions.append(
            "("
            "lowerUTF8(if(host_name != '' AND host_name != '-', host_name, log_source)) "
            f"= '{safe_host}' "
            "AND startsWith(event_id, 'siem.filtered:') "
            "AND toUInt64OrZero(extract(event_id, '([0-9]+)$')) "
            f"<= {cutoff}"
            ")"
        )
    legacy_exclusion_sql = ""
    if legacy_exclusions:
        legacy_exclusion_sql = "\n      AND NOT (" + " OR ".join(legacy_exclusions) + ")"
    return f"""INSERT INTO siem.alerts_raw
(ts, alert_id, rule_id, rule_name, severity, ts_first, ts_last, window_s, entity_key, hits, context_json, source, status)
SELECT
    now(),
    generateUUIDv4(),
    {rule_id},
    '{title}',
    '{severity}',
    candidate.ts_first,
    candidate.ts_last,
    {{WINDOW_S}},
    candidate.entity_key,
    candidate.hits,
    candidate.context_json,
    candidate.source,
    'open'
FROM
(
    SELECT
        if(host_name != '' AND host_name != '-', host_name, log_source) AS entity_key,
        if(host_name != '' AND host_name != '-', host_name, log_source) AS source,
        min(ts) AS ts_first,
        max(ts) AS ts_last,
        count() AS hits,
        concat(
            '{{"event_type":"future_event_timestamp","source_id":"HB-010",',
            '"source":"',
            if(host_name != '' AND host_name != '-', host_name, log_source),
            '","max_event_ts":"', toString(max(ts)), '","clock_skew_seconds":',
            toString(dateDiff('second', now(), max(ts))), '}}'
        ) AS context_json
    FROM siem.events
    PREWHERE ts > now() + INTERVAL 2 MINUTE
    WHERE ts <= now() + INTERVAL 1 DAY
      AND if(host_name != '' AND host_name != '-', host_name, log_source) != ''
      AND positionCaseInsensitiveUTF8(toString(tags), 'allowlist:') = 0
      AND positionCaseInsensitiveUTF8(toString(tags), 'benchmark') = 0
      AND positionCaseInsensitiveUTF8(toString(tags), 'synthetic') = 0
      AND positionCaseInsensitiveUTF8(toString(tags), 'e2e') = 0
      {legacy_exclusion_sql}
    GROUP BY entity_key, source
    HAVING hits >= 1
) AS candidate
LEFT JOIN
(
    SELECT entity_key
    FROM siem.alerts_raw
    WHERE rule_id = {rule_id}
      AND ts >= now() - INTERVAL {dedupe_window_s} SECOND
      AND lower(status) IN ('open', 'false_positive', 'suppressed')
    GROUP BY entity_key
) AS existing
ON candidate.entity_key = existing.entity_key
WHERE existing.entity_key = ''"""


def _sustained_cpu_pressure_sql(item: dict[str, Any]) -> str:
    candidate_sql = """    SELECT
        if(host_name != '' AND host_name != '-', host_name, log_source) AS entity_key,
        if(host_name != '' AND host_name != '-', host_name, log_source) AS source,
        minIf(ts, cpu_pct > 95) AS ts_first,
        maxIf(ts, cpu_pct > 95) AS ts_last,
        countIf(cpu_pct > 95) AS hits,
        concat(
            '{"event_type":"sustained_cpu_pressure","source_id":"MET-002","source":"',
            if(host_name != '' AND host_name != '-', host_name, log_source),
            '","high_samples":', toString(countIf(cpu_pct > 95)),
            ',"samples":', toString(count()),
            ',"average_cpu_pct":', toString(round(avg(cpu_pct), 1)), '}'
        ) AS context_json
    FROM
    (
        SELECT
            ts,
            host_name,
            log_source,
            toFloat64OrZero(
                extract(toString(normalized_json), '"cpu_pct":([0-9.]+)')
            ) AS cpu_pct
        FROM siem.events
        PREWHERE ts >= now() - INTERVAL {WINDOW_S} SECOND
        WHERE device_product = 'host.metrics'
          AND subcategory = 'host_runtime_snapshot'
          AND positionCaseInsensitiveUTF8(toString(tags), 'allowlist:') = 0
          AND positionCaseInsensitiveUTF8(toString(tags), 'benchmark') = 0
          AND positionCaseInsensitiveUTF8(toString(tags), 'synthetic') = 0
          AND positionCaseInsensitiveUTF8(toString(tags), 'e2e') = 0
    )
    GROUP BY entity_key, source
    HAVING count() >= 5
       AND hits >= 5
       AND hits / count() >= 0.8
       AND avg(cpu_pct) > 90"""
    return _wrap_batch_candidate(item, candidate_sql=candidate_sql)


def _sustained_runtime_metric_sql(
    item: dict[str, Any],
    *,
    source_id: str,
    metric_name: str,
    threshold: float,
    event_type: str,
    required_json_marker: str = "",
) -> str:
    threshold_literal = str(float(threshold)).rstrip("0").rstrip(".")
    condition = f"{metric_name} > {threshold_literal}"
    scope_clause = (
        "\n          AND positionCaseInsensitiveUTF8(toString(normalized_json), "
        f"'{required_json_marker}') > 0"
        if required_json_marker
        else ""
    )
    candidate_sql = f"""    SELECT
        if(host_name != '' AND host_name != '-', host_name, log_source) AS entity_key,
        if(host_name != '' AND host_name != '-', host_name, log_source) AS source,
        minIf(ts, {condition}) AS ts_first,
        maxIf(ts, {condition}) AS ts_last,
        countIf({condition}) AS hits,
        concat(
            '{{"event_type":"{event_type}","source_id":"{source_id}","source":"',
            if(host_name != '' AND host_name != '-', host_name, log_source),
            '","high_samples":', toString(countIf({condition})),
            ',"samples":', toString(count()),
            ',"average_{metric_name}":', toString(round(avg({metric_name}), 1)), '}}'
        ) AS context_json
    FROM
    (
        SELECT
            ts,
            host_name,
            log_source,
            toFloat64OrZero(
                extract(toString(normalized_json), '"{metric_name}":([0-9.]+)')
            ) AS {metric_name}
        FROM siem.events
        PREWHERE ts >= now() - INTERVAL {{WINDOW_S}} SECOND
        WHERE device_product = 'host.metrics'
          AND subcategory = 'host_runtime_snapshot'
          AND positionCaseInsensitiveUTF8(toString(normalized_json), '"{metric_name}"') > 0
          {scope_clause}
          AND positionCaseInsensitiveUTF8(toString(tags), 'allowlist:') = 0
          AND positionCaseInsensitiveUTF8(toString(tags), 'benchmark') = 0
          AND positionCaseInsensitiveUTF8(toString(tags), 'synthetic') = 0
          AND positionCaseInsensitiveUTF8(toString(tags), 'e2e') = 0
    )
    GROUP BY entity_key, source
    HAVING count() >= 10
       AND hits >= 8
       AND hits / count() >= 0.8
       AND avg({metric_name}) > {threshold_literal}
       AND maxIf(ts, {condition}) >= now() - INTERVAL 5 MINUTE"""
    return _wrap_batch_candidate(item, candidate_sql=candidate_sql)


def _sustained_memory_pressure_sql(item: dict[str, Any]) -> str:
    candidate_sql = """    SELECT
        if(host_name != '' AND host_name != '-', host_name, log_source) AS entity_key,
        if(host_name != '' AND host_name != '-', host_name, log_source) AS source,
        minIf(ts, memory_available_pct < 10 OR swap_used_pct > 30) AS ts_first,
        maxIf(ts, memory_available_pct < 10 OR swap_used_pct > 30) AS ts_last,
        countIf(memory_available_pct < 10 OR swap_used_pct > 30) AS hits,
        concat(
            '{"event_type":"sustained_memory_pressure","source_id":"MET-003","source":"',
            if(host_name != '' AND host_name != '-', host_name, log_source),
            '","pressure_samples":', toString(countIf(memory_available_pct < 10 OR swap_used_pct > 30)),
            ',"samples":', toString(count()),
            ',"average_available_pct":', toString(round(avg(memory_available_pct), 1)),
            ',"average_swap_pct":', toString(round(avg(swap_used_pct), 1)), '}'
        ) AS context_json
    FROM
    (
        SELECT
            ts,
            host_name,
            log_source,
            toFloat64OrZero(
                extract(toString(normalized_json), '"memory_available_pct":([0-9.]+)')
            ) AS memory_available_pct,
            toFloat64OrZero(
                extract(toString(normalized_json), '"swap_used_pct":([0-9.]+)')
            ) AS swap_used_pct
        FROM siem.events
        PREWHERE ts >= now() - INTERVAL {WINDOW_S} SECOND
        WHERE device_product = 'host.metrics'
          AND subcategory = 'host_runtime_snapshot'
          AND positionCaseInsensitiveUTF8(toString(normalized_json), '"memory_available_pct"') > 0
          AND positionCaseInsensitiveUTF8(toString(tags), 'allowlist:') = 0
          AND positionCaseInsensitiveUTF8(toString(tags), 'benchmark') = 0
          AND positionCaseInsensitiveUTF8(toString(tags), 'synthetic') = 0
          AND positionCaseInsensitiveUTF8(toString(tags), 'e2e') = 0
    )
    GROUP BY entity_key, source
    HAVING count() >= 5
       AND hits >= 4
       AND hits / count() >= 0.8
       AND (avg(memory_available_pct) < 10 OR avg(swap_used_pct) > 30)"""
    return _wrap_batch_candidate(item, candidate_sql=candidate_sql)


def _service_restart_loop_sql(item: dict[str, Any]) -> str:
    candidate_sql = """    SELECT
        concat(host_key, '|', service_name) AS entity_key,
        host_key AS source,
        min(ts) AS ts_first,
        max(ts) AS ts_last,
        count() AS hits,
        concat(
            '{"event_type":"service_restart_loop","source_id":"MET-012","source":"',
            host_key, '","service":"', service_name,
            '","restart_events":', toString(count()), '}'
        ) AS context_json
    FROM
    (
        SELECT
            ts,
            if(host_name != '' AND host_name != '-', host_name, log_source) AS host_key,
            if(
                extract(toString(normalized_json), '"service":"([^"]+)"') != '',
                extract(toString(normalized_json), '"service":"([^"]+)"'),
                if(
                    extract(toString(message), '([A-Za-z0-9_.@-]+\\.service)') != '',
                    extract(toString(message), '([A-Za-z0-9_.@-]+\\.service)'),
                    'unknown-service'
                )
            ) AS service_name,
            subcategory
        FROM siem.events
        PREWHERE ts >= now() - INTERVAL {WINDOW_S} SECOND
        WHERE
          (
              subcategory = 'host_service_flapping'
              OR
              (
                  subcategory = 'linux_systemd_restart_scheduled'
                  AND event_action = 'service_restart'
              )
          )
          AND positionCaseInsensitiveUTF8(toString(message), 'container-getty@') = 0
          AND positionCaseInsensitiveUTF8(toString(message), 'getty@') = 0
          AND positionCaseInsensitiveUTF8(toString(message), 'apt.systemd.daily') = 0
          AND positionCaseInsensitiveUTF8(toString(message), 'unattended-upgrade') = 0
          AND positionCaseInsensitiveUTF8(toString(tags), 'allowlist:') = 0
          AND positionCaseInsensitiveUTF8(toString(tags), 'benchmark') = 0
          AND positionCaseInsensitiveUTF8(toString(tags), 'synthetic') = 0
          AND positionCaseInsensitiveUTF8(toString(tags), 'e2e') = 0
    )
    GROUP BY host_key, service_name
    HAVING countIf(subcategory = 'host_service_flapping') >= 3
        OR countIf(subcategory = 'linux_systemd_restart_scheduled') >= 5"""
    return _wrap_batch_candidate(item, candidate_sql=candidate_sql)


def _critical_alert_unacknowledged_sql(item: dict[str, Any]) -> str:
    candidate_sql = """    SELECT
        concat(
            if(source != '', source, entity_key),
            '|rule:',
            toString(rule_id)
        ) AS entity_key,
        if(source != '', source, entity_key) AS source,
        min(ts_first) AS ts_first,
        max(ts_last) AS ts_last,
        count() AS hits,
        concat(
            '{"event_type":"critical_alert_unacknowledged",',
            '"source_id":"ALERT-005","source":"',
            if(source != '', source, entity_key),
            '","target_rule_id":', toString(rule_id),
            ',"open_alerts":', toString(count()), '}'
        ) AS context_json
    FROM siem.alerts_raw
    PREWHERE ts >= now() - INTERVAL {WINDOW_S} SECOND
    WHERE rule_id != 8221
      AND lowerUTF8(severity) = 'critical'
      AND lowerUTF8(status) = 'open'
      AND assignee = ''
      AND ts <= now() - INTERVAL 15 MINUTE
      AND positionCaseInsensitiveUTF8(toString(context_json), 'benchmark') = 0
      AND positionCaseInsensitiveUTF8(toString(context_json), 'synthetic') = 0
      AND positionCaseInsensitiveUTF8(toString(context_json), 'e2e') = 0
    GROUP BY source, rule_id, entity_key"""
    return _wrap_batch_candidate(item, candidate_sql=candidate_sql)


def _stream_corr_no_alerts_sql(item: dict[str, Any]) -> str:
    rule_id = int(item["id"])
    dedupe_window_s = _dedupe_window(item)
    return f"""INSERT INTO siem.alerts_raw
(ts, alert_id, rule_id, rule_name, severity, ts_first, ts_last, window_s, entity_key, hits, context_json, source, status)
SELECT
    now(),
    generateUUIDv4(),
    {rule_id},
    'CORR-S-002 Stream correlator unhealthy',
    'high',
    candidate.ts_first,
    candidate.ts_last,
    {{WINDOW_S}},
    'siem-stream-corr',
    candidate.unhealthy_snapshots,
    concat(
        '{{"event_type":"stream_correlation_unhealthy","source_id":"CORR-S-002",',
        '"unhealthy_snapshots":', toString(candidate.unhealthy_snapshots), '}}'
    ),
    'siem-stream-corr',
    'open'
FROM
(
    SELECT
        min(ts) AS ts_first,
        max(ts) AS ts_last,
        count() AS unhealthy_snapshots
    FROM siem.events
    PREWHERE ts >= now() - INTERVAL {{WINDOW_S}} SECOND
    WHERE log_source = 'siem-storage'
      AND device_product = 'host.metrics'
      AND subcategory = 'host_runtime_snapshot'
      AND
      (
          position(toString(normalized_json), '"name":"siem-stream-corr"') = 0
          OR match(
              toString(normalized_json),
              '"name":"siem-stream-corr"[^}}]*"status":"(inactive|failed|dead|unknown)"'
          )
      )
    HAVING unhealthy_snapshots >= 3
) AS candidate
WHERE NOT EXISTS
(
    SELECT 1
    FROM siem.alerts_raw
    WHERE rule_id = {rule_id}
      AND entity_key = 'siem-stream-corr'
      AND ts >= now() - INTERVAL {dedupe_window_s} SECOND
      AND lower(status) IN ('open', 'false_positive', 'suppressed')
)"""


def _gateway_logs_stopped_sql(item: dict[str, Any]) -> str:
    rule_id = int(item["id"])
    dedupe_window_s = _dedupe_window(item)
    return f"""INSERT INTO siem.alerts_raw
(ts, alert_id, rule_id, rule_name, severity, ts_first, ts_last, window_s, entity_key, hits, context_json, source, status)
SELECT
    now(),
    generateUUIDv4(),
    {rule_id},
    'GW-010 Gateway logs stopped',
    'critical',
    candidate.ts_first,
    candidate.ts_last,
    {{WINDOW_S}},
    candidate.entity_key,
    candidate.hits,
    candidate.context_json,
    candidate.source,
    'open'
FROM
(
    SELECT
        'openclaw-gateway' AS entity_key,
        'openclaw-gateway' AS source,
        max(ts) AS ts_first,
        max(ts) AS ts_last,
        count() AS hits,
        concat(
            '{{"event_type":"gateway_telemetry_stale","source_id":"GW-010",',
            '"source":"openclaw-gateway","last_seen":"',
            toString(max(ts)),
            '"}}'
        ) AS context_json
    FROM siem.events
    PREWHERE ts >= now() - INTERVAL 1 DAY
    WHERE lowerUTF8(host_name) = 'openclaw-gateway'
      AND device_product = 'host.metrics'
      AND subcategory = 'host_runtime_snapshot'
      AND positionCaseInsensitiveUTF8(toString(tags), 'benchmark') = 0
      AND positionCaseInsensitiveUTF8(toString(tags), 'synthetic') = 0
      AND positionCaseInsensitiveUTF8(toString(tags), 'e2e') = 0
    HAVING ts_last > toDateTime(0)
       AND ts_last < now() - INTERVAL {{WINDOW_S}} SECOND
) AS candidate
LEFT JOIN
(
    SELECT entity_key
    FROM siem.alerts_raw
    WHERE rule_id = {rule_id}
      AND ts >= now() - INTERVAL {dedupe_window_s} SECOND
      AND lower(status) IN ('open', 'false_positive', 'suppressed')
    GROUP BY entity_key
) AS existing
ON candidate.entity_key = existing.entity_key
WHERE existing.entity_key = ''"""


def _navidrome_mass_transfer_sql(item: dict[str, Any]) -> str:
    rule_id = int(item["id"])
    dedupe_window_s = _dedupe_window(item)
    return f"""INSERT INTO siem.alerts_raw
(ts, alert_id, rule_id, rule_name, severity, ts_first, ts_last, window_s, entity_key, hits, context_json, source, status)
SELECT
    now(),
    generateUUIDv4(),
    {rule_id},
    'NAV-004 Mass media download/stream',
    'medium',
    candidate.ts_first,
    candidate.ts_last,
    {{WINDOW_S}},
    candidate.entity_key,
    candidate.hits,
    candidate.context_json,
    candidate.source,
    'open'
FROM
(
    SELECT
        if(
            user_name != '',
            user_name,
            if(src_ip != 0, IPv4NumToString(src_ip), 'navidrome-01')
        ) AS entity_key,
        'navidrome-01' AS source,
        min(ts) AS ts_first,
        max(ts) AS ts_last,
        count() AS hits,
        sum(
            toUInt64OrZero(
                extract(toString(normalized_json), '"bytes"[ ]*:[ ]*"?([0-9]+)')
            )
        ) AS transferred_bytes,
        concat(
            '{{"event_type":"navidrome_mass_transfer","source_id":"NAV-004",',
            '"source":"navidrome-01","hits":',
            toString(count()),
            ',"bytes":',
            toString(transferred_bytes),
            '}}'
        ) AS context_json
    FROM siem.events
    PREWHERE ts >= now() - INTERVAL {{WINDOW_S}} SECOND
    WHERE lowerUTF8(host_name) = 'navidrome-01'
      AND device_product IN ('linux.navidrome', 'linux.nginx', 'linux.oauth2-proxy')
      AND
      (
          subcategory IN ('navidrome_stream', 'navidrome_download', 'media_stream', 'media_download')
          OR event_action IN ('playback', 'media_stream', 'media_download')
          OR positionCaseInsensitiveUTF8(toString(message), 'stream started') > 0
          OR positionCaseInsensitiveUTF8(toString(message), 'download started') > 0
          OR positionCaseInsensitiveUTF8(toString(message), '/rest/stream') > 0
          OR positionCaseInsensitiveUTF8(toString(message), '/rest/download') > 0
      )
      AND positionCaseInsensitiveUTF8(toString(tags), 'allowlist:') = 0
      AND positionCaseInsensitiveUTF8(toString(tags), 'benchmark') = 0
      AND positionCaseInsensitiveUTF8(toString(tags), 'synthetic') = 0
      AND positionCaseInsensitiveUTF8(toString(tags), 'e2e') = 0
    GROUP BY entity_key
    HAVING transferred_bytes >= 1073741824 OR hits >= 100
) AS candidate
LEFT JOIN
(
    SELECT entity_key
    FROM siem.alerts_raw
    WHERE rule_id = {rule_id}
      AND ts >= now() - INTERVAL {dedupe_window_s} SECOND
      AND lower(status) IN ('open', 'false_positive', 'suppressed')
    GROUP BY entity_key
) AS existing
ON candidate.entity_key = existing.entity_key
WHERE existing.entity_key = ''"""


def curated_batch_sql(item: dict[str, Any]) -> str:
    source_id = str(item.get("source_id") or "").upper()
    if source_id == "HB-001":
        return _host_silence_sql(item, source_id=source_id, silence_hours=24)
    if source_id == "HB-002":
        return _host_silence_sql(item, source_id=source_id, silence_hours=48)
    if source_id == "HB-003":
        return _host_silence_sql(item, source_id=source_id, silence_hours=72)
    if source_id == "HB-004":
        return _host_silence_sql(
            item,
            source_id=source_id,
            silence_hours=1,
            siem_core_only=True,
        ).replace(
            "max(e.last_seen_ts) < now() - INTERVAL 1 HOUR",
            "max(e.last_seen_ts) < now() - INTERVAL 15 MINUTE",
        )
    if source_id == "HB-010":
        return _future_event_sql(item)
    if source_id == "MET-001":
        return _sustained_runtime_metric_sql(
            item,
            source_id=source_id,
            metric_name="cpu_pct",
            threshold=90,
            event_type="sustained_cpu_pressure",
            required_json_marker='"cpu_scope":"',
        )
    if source_id == "MET-002":
        return _sustained_cpu_pressure_sql(item)
    if source_id == "MET-003":
        return _sustained_memory_pressure_sql(item)
    if source_id == "MET-008":
        return _sustained_runtime_metric_sql(
            item,
            source_id=source_id,
            metric_name="iowait_pct",
            threshold=35,
            event_type="sustained_iowait_pressure",
            required_json_marker='"iowait_scope":"host"',
        )
    if source_id == "MET-009":
        return _sustained_runtime_metric_sql(
            item,
            source_id=source_id,
            metric_name="load_ratio",
            threshold=2,
            event_type="sustained_load_pressure",
            required_json_marker='"load_scope":"host"',
        )
    if source_id == "MET-012":
        return _service_restart_loop_sql(item)
    if source_id == "ALERT-005":
        return _critical_alert_unacknowledged_sql(item)
    if source_id == "HB-006":
        return _new_internal_ip_sql(item)
    if source_id == "HB-011":
        return _host_volume_spike_sql(item)
    if source_id == "HB-012":
        return _host_volume_drop_sql(item)
    if source_id == "HB-013":
        return _unmonitored_discovered_host_sql(item)
    if source_id == "HB-014":
        return _unexpected_known_host_port_sql(item)
    if source_id == "CORR-S-002":
        return _stream_corr_no_alerts_sql(item)
    if source_id == "GW-010":
        return _gateway_logs_stopped_sql(item)
    if source_id == "NAV-004":
        return _navidrome_mass_transfer_sql(item)
    return ""
