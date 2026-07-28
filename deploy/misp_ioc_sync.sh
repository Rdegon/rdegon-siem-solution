#!/usr/bin/env bash
set -euo pipefail

set -a
# shellcheck disable=SC1091
. /etc/siem/storage.env
set +a

clickhouse() {
  clickhouse-client \
    --host "${SIEM_CH_HOST:-127.0.0.1}" \
    --port "${SIEM_CH_PORT:-9000}" \
    --user "${SIEM_CH_USER:-default}" \
    --password "${SIEM_CH_PASSWORD:-}" \
    "$@"
}

clickhouse --query "
  ALTER TABLE siem.threat_intel_iocs
  DELETE WHERE provider = 'MISP'
  SETTINGS mutations_sync = 2
"

clickhouse --query "
  INSERT INTO siem.threat_intel_iocs
  (
    indicator_type,
    indicator,
    provider,
    severity,
    confidence,
    description,
    tags,
    enabled,
    expires_ts,
    updated_ts
  )
  SELECT
    mapped_type,
    mapped_indicator,
    'MISP',
    severity,
    confidence,
    description,
    tags,
    1,
    now() + INTERVAL 7 DAY,
    now()
  FROM
  (
    SELECT
      multiIf(
        misp_type IN ('ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port'), 'ip',
        misp_type IN ('domain', 'hostname'), 'domain',
        misp_type IN ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
                      'filename|md5', 'filename|sha1', 'filename|sha256', 'filename|sha512'), 'hash',
        misp_type IN ('url', 'uri'), 'url',
        ''
      ) AS mapped_type,
      multiIf(
        misp_type IN ('ip-src|port', 'ip-dst|port'), arrayElement(splitByChar('|', raw_indicator), 1),
        startsWith(misp_type, 'filename|'), arrayElement(splitByChar('|', raw_indicator), -1),
        raw_indicator
      ) AS mapped_indicator,
      lower(severity) AS severity,
      toUInt8(50) AS confidence,
      rule_name AS description,
      concat('misp,ioc_type:', misp_type) AS tags
    FROM
    (
      SELECT
        lower(JSONExtractString(normalized_json, 'threat', 'indicator_type')) AS misp_type,
        lower(JSONExtractString(normalized_json, 'threat', 'indicator')) AS raw_indicator,
        severity,
        rule_name,
        normalized_json
      FROM siem.events
      WHERE device_product = 'misp'
        AND JSONExtractBool(normalized_json, 'threat', 'active') = 1
        AND (
          greatest(
            toInt64OrZero(JSONExtractString(normalized_json, 'threat', 'last_seen')),
            toInt64OrZero(JSONExtractString(normalized_json, 'threat', 'valid_until'))
          ) = 0
          OR greatest(
            toInt64OrZero(JSONExtractString(normalized_json, 'threat', 'last_seen')),
            toInt64OrZero(JSONExtractString(normalized_json, 'threat', 'valid_until'))
          )
             >= toUnixTimestamp(now() - INTERVAL 180 DAY)
        )
    )
    WHERE mapped_type != ''
      AND mapped_indicator != ''
  )
  GROUP BY
    mapped_type,
    mapped_indicator,
    severity,
    confidence,
    description,
    tags
"

clickhouse --query "
  SELECT
    count() AS active_iocs,
    uniqExact(indicator) AS unique_indicators,
    groupUniqArray(indicator_type) AS types
  FROM siem.threat_intel_iocs
  WHERE provider = 'MISP'
  FORMAT JSONEachRow
"
