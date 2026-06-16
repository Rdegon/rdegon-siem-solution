# Incident False Positive Remediation 2026-03-29

## Что проверялось

Проверка была выполнена по live очереди агрегированных инцидентов и по сохранённым AI-оценкам. Целью было отделить:

- реальные инциденты, требующие расследования;
- подтверждённые ложноположительные кластеры;
- исторический backlog, который выглядел как `open` из-за ошибок в runtime или из-за повторного поступления одинакового шумного сигнала.

## Подтверждённые ложноположительные семейства

По live-выборке и после повторного AI-разбора подтверждены как ложноположительные или служебные:

- `asset:openclaw-gateway|campaign:reconnaissance`
- `asset:openclaw-gateway|campaign:syslog`
- `asset:openclaw-gateway|campaign:linux_dns_query`
- `asset:nextcloud-siem|campaign:host_load_pressure`
- `asset:navidrome-01|campaign:host_load_pressure`
- `asset:siem-processing|campaign:privilege_escalation`
- `asset:siem-web|campaign:privilege_escalation`

Смысл этих кластеров:

- OpenClaw создавал ожидаемую исследовательскую и прокси-активность, которую корреляция видела как угрозу.
- Отдельные `sudo/systemctl` вызовы на узлах SIEM оказались нашими же служебными проверками и диагностикой.
- Часть host-runtime сигналов осталась от кратковременного давления, а не от текущей деградации.

## Что было исправлено

### 1. AI runtime

Исправлены две реальные проблемы в `incident_ai_runtime.py`:

- мост в OpenClaw больше не генерирует битый inline Python c `;try:`;
- фоновые оценки из ad-hoc вызовов больше не зависают в `pending` из-за daemon-thread поведения.

Также усилен fallback-разбор:

- служебная активность OpenClaw теперь явно помечается как ожидаемая;
- `sudo systemctl/journalctl` проверки на SIEM-узлах трактуются как operational false positive, а не как подтверждённое повышение привилегий.

### 2. Aggregate status update

Исправлен `agg`-update path в `deps.py`.

Раньше обновление статуса для агрегированных инцидентов пыталось закрывать raw-alerts по упрощённому SQL-ключу. Это было неверно для инцидентов, чьи ключи собираются Python-логикой `asset/actor/campaign`.

Теперь update path:

- вычисляет тот же incident scope key, что и `fetch_alerts_agg`;
- находит реальные `alert_id`, принадлежащие агрегированному кластеру;
- обновляет именно их.

Это убрало ложное “переоткрытие” части инцидентов после ручного или AI-закрытия.

### 3. Нормализация

В `normalizer_core.py` и `services/normalizer/normalizer_core.py` усилены allowlist-маркеры:

- ожидаемые OpenClaw research-команды;
- ожидаемые OpenClaw DNS-запросы;
- служебные `sudo`-проверки SIEM.

### 4. Filter rules

В `sql_12_filter_rule_seed.sql` добавлены дополнительные filter rules для подавления событий с allowlist-тегами:

- `allowlist:openclaw_research_activity`
- `allowlist:openclaw_expected_dns`
- `allowlist:openclaw_proxy_runtime`
- `allowlist:openclaw_expected_activity`
- `allowlist:siem_operational_sudo`

## Что осталось открытым после remediation

На момент финальной live-перепроверки открытыми оставались кластеры, которые не были подтверждены как фолсы:

- `asset:openclaw-gateway|actor:192.168.1.35|campaign:network_intrusion`
- `asset:openclaw-gateway|campaign:host_service_flapping`
- `asset:asset-vpn-host|ti:172.234.218.34|campaign:threat_intel`
- `asset:asset-vpn-host|ti:45.205.1.5|campaign:threat_intel`
- часть multi-host intrusion / SSH brute-force кластеров

Эти инциденты требуют ручной проверки и не были автоматически закрыты.

## Остаточный риск

После внесённых правок confirmed false positive families стали понятнее и управляемее, но остаётся один live-хвост:

- OpenClaw research/syslog/DNS шум всё ещё виден в очереди как повторный поток под теми же incident keys.

Это уже не связано с ошибкой AI-оценки. Это означает, что:

- либо filter-layer ещё догоняет уже накопившийся backlog;
- либо часть OpenClaw-expected событий продолжает доходить до корреляции не через тот suppress-path, который сейчас покрыт.

То есть ситуация стала лучше и прозрачнее, но OpenClaw noise floor ещё не доведён до нуля.

## Локальная проверка

Локально прошли:

- `pytest tests/test_incident_assignment.py`
- `pytest tests/test_incident_ai_runtime.py`
- `pytest tests/test_normalizer_core.py`
- `pytest tests/test_service_normalizer_core.py`
- `py_compile deps.py incident_ai_runtime.py normalizer_core.py services/normalizer/normalizer_core.py`

## Live state summary

Итог live-проверки:

- AI-оценки для подтверждённых false positive кластеров формируются корректно;
- часть ложноположительных кластеров переведена в `false_positive`;
- `siem-web` и `siem-processing` служебные `sudo`-кластеры больше не должны считаться подтверждённым privilege escalation;
- в очереди остаются реальные или спорные инциденты, а также остаточный OpenClaw шум, который требует отдельной донастройки suppress-path.
