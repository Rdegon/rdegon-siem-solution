#!/usr/bin/env bash
set -euo pipefail

JOURNAL_MAX_USE="${SIEM_JOURNAL_MAX_USE:-256M}"
JOURNAL_MAX_RETENTION="${SIEM_JOURNAL_MAX_RETENTION:-14d}"

journalctl --rotate >/dev/null 2>&1 || true
journalctl --vacuum-size="${JOURNAL_MAX_USE}" >/dev/null 2>&1 || true
journalctl --vacuum-time="${JOURNAL_MAX_RETENTION}" >/dev/null 2>&1 || true

if command -v logrotate >/dev/null 2>&1; then
  /usr/sbin/logrotate /etc/logrotate.conf >/dev/null 2>&1 || true
fi

if command -v apt-get >/dev/null 2>&1; then
  apt-get clean >/dev/null 2>&1 || true
fi

find /var/log -type f \( -name "*.gz" -o -name "*.old" -o -name "*.1" \) -mtime +14 -delete >/dev/null 2>&1 || true

if [ -d /opt/actions-runners ]; then
  find /opt/actions-runners -type f -path "*/_diag/*" -mtime +7 -delete >/dev/null 2>&1 || true
fi
