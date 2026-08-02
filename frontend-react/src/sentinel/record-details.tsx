import { Badge, EmptyState, StatusCell } from "./ui";
import { formatTime, number, severityTone, text } from "./runtime/query";

type Row = Record<string, unknown>;
type DetailKind =
  | "access"
  | "asset"
  | "case"
  | "collector"
  | "discovery"
  | "identity"
  | "integration"
  | "node"
  | "report"
  | "resource"
  | "rule"
  | "service"
  | "soar"
  | "threat"
  | "vulnerability";

const FIELD_LABELS: Record<string, string> = {
  id: "ID", uuid: "UUID", name: "Название", title: "Название", description: "Описание", summary: "Описание",
  status: "Статус", enabled: "Включен", healthy: "Состояние", telemetry_state: "Телеметрия", integration_state: "Интеграция",
  severity: "Важность", priority: "Приоритет", priority_score: "Приоритет", risk: "Риск", risk_score: "Риск",
  asset: "Актив", asset_id: "ID актива", cmdb_asset_id: "ID актива CMDB", asset_hostname: "Актив", target: "Цель",
  cmdb_owner: "Владелец", owner: "Владелец", assignee: "Исполнитель", created_by: "Создал", actor: "Инициатор",
  cmdb_criticality: "Критичность", cmdb_environment: "Сегмент", cmdb_service: "Сервис", cmdb_tags: "Теги CMDB",
  username: "Пользователь", display_name: "Отображаемое имя", email: "Email", role: "Роль", roles: "Роли",
  groups: "Группы", permissions: "Разрешения", permission_bundles: "Наборы разрешений", scopes: "Области доступа",
  principal_kind: "Тип субъекта", principal_id: "Субъект", tenant_id: "Тенант", tenant_scope: "Область тенанта",
  service_id: "ID сервиса", service_account_id: "Сервисная учетная запись", system_id: "Система", client_id: "ID клиента",
  auth_mechanism: "Механизм входа", provider: "Провайдер", issuer: "Издатель",
  host_name: "Узел", hostname: "Имя узла", node: "Узел", host_ip: "IP узла", ip: "IP-адрес", target_ip: "IP цели",
  address: "Адрес", placement: "Размещение", asset_group: "Группа активов", segment: "Сегмент", layer: "Уровень",
  source: "Источник", source_name: "Источник", source_ip: "IP источника", src_ip: "IP источника", destination: "Назначение", destination_ip: "IP назначения",
  dst_ip: "IP назначения", port: "Порт", ports: "Порты", open_ports: "Открытые порты", port_summary: "Порты",
  destination_port: "Порт назначения", dst_port: "Порт назначения", interface: "Интерфейс", protocol: "Протокол", protocols: "Протоколы",
  product: "Продукт", products: "Продукты", services: "Сервисы", categories: "Категории", environments: "Среды", ti_hits: "TI-совпадения", expected_products: "Ожидаемые продукты", missing_products: "Не обнаружено",
  matched_products: "Обнаруженные продукты", capabilities: "Возможности", pivots: "Переходы", workspaces: "Рабочие области",
  integration_mode: "Режим интеграции", native_console_route: "Встроенная консоль", connected_source: "Источник SIEM",
  collector_name: "Коллектор", collector_id: "ID коллектора", collector_profile: "Профиль коллектора", source_type: "Тип источника",
  source_types: "Типы источников", sources_count: "Источники", covered_sources: "Покрытые источники",
  events: "События", events_15m: "События 15 мин", events_1h: "События 1 ч", events_24h: "События 24 ч",
  notable_events: "Значимые события", audit_events: "События аудита", record_count: "Записей", section_count: "Разделов",
  duration_ms: "Длительность", confidence: "Достоверность", reputation: "Репутация", indicator: "Индикатор", indicator_type: "Тип индикатора",
  cves: "CVE", cvss_score: "CVSS", epss: "EPSS", kev: "CISA KEV", finding_key: "Ключ находки", report_id: "ID отчета",
  due_ts: "SLA", sla_due_ts: "SLA", mitre: "MITRE ATT&CK", related_iocs: "Связанные IoC", related_entities: "Связанные сущности",
  tasks: "Задачи", comments: "Комментарии", evidence: "Доказательства", source_alerts: "Связанные алерты", audit_trail: "История изменений",
  tags: "Теги", type: "Тип", kind: "Тип", version: "Версия", schema_version: "Версия схемы", origin: "Происхождение",
  formats: "Форматы", sections: "Разделы", period: "Период", schedule: "Расписание", errors: "Ошибки", error: "Ошибка",
  config: "Конфигурация", bindings: "Связи", activation: "Активация", blocks: "Pipeline", policy: "Политика",
  action: "Действие", action_id: "ID действия", approval_required: "Требует подтверждения", requires_approval: "Требует подтверждения",
  dangerous: "Повышенный риск", dry_run: "Тестовый режим", command: "Команда", params: "Параметры", steps: "Шаги",
  created_ts: "Создан", updated_ts: "Изменен", completed_ts: "Завершен", published_ts: "Опубликован",
  last_seen: "Последняя активность", latest_event: "Последнее событие", first_seen: "Первое наблюдение",
  generated_ts: "Сформирован", password_updated_ts: "Пароль изменен", expires_ts: "Истекает",
};

const KIND_LABELS: Record<DetailKind, string> = {
  access: "Объект доступа", asset: "Актив", case: "Кейс", collector: "Коллектор", discovery: "Обнаруженный узел",
  identity: "Объект идентификации", integration: "Интеграция", node: "Узел топологии", report: "Отчет", resource: "Ресурс платформы",
  rule: "Контент детектирования", service: "Средство защиты", soar: "Объект SOAR", threat: "Threat Intelligence",
  vulnerability: "Уязвимость",
};

const SECTION_LABELS = {
  main: "Основные сведения",
  security: "Контекст безопасности",
  network: "Сеть и размещение",
  access: "Доступ и ответственность",
  activity: "Активность и время",
  configuration: "Конфигурация и связи",
} as const;

type Section = keyof typeof SECTION_LABELS;

function asRow(value: unknown): Row | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Row : null;
}

function empty(value: unknown) {
  return value === undefined || value === null || value === "" || (Array.isArray(value) && value.length === 0);
}

function labelFor(key: string) {
  if (FIELD_LABELS[key]) return FIELD_LABELS[key];
  return key.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function sectionFor(key: string): Section {
  if (/severity|priority|risk|cvss|epss|cve|kev|mitre|threat|indicator|reputation|confidence|finding|sla|due|ioc|malicious/i.test(key)) return "security";
  if (/ip|port|host|node|address|placement|segment|network|interface|protocol|source_ip|src_ip|destination_ip|dst_ip|domain|collector/i.test(key)) return "network";
  if (/user|account|owner|assignee|actor|role|group|permission|scope|tenant|grant|auth|provider|client/i.test(key)) return "access";
  if (/event|count|total|duration|created|updated|completed|published|last_|first_|latest_|generated|expires|time|date|metric/i.test(key)) return "activity";
  if (/config|binding|activation|product|capabilit|pivot|workspace|policy|schedule|format|section|tag|block|step|param|command|expected|missing|matched/i.test(key)) return "configuration";
  return "main";
}

function PrimitiveValue({ field, value }: { field: string; value: unknown }) {
  if (typeof value === "boolean") return <StatusCell value={value ? "Включено" : "Выключено"} />;
  if (/status|state|health|enabled$/i.test(field)) return <StatusCell value={text(value)} />;
  if (/severity|criticality|priority$/i.test(field)) return <Badge tone={severityTone(value)}>{text(value)}</Badge>;
  if (/(_ts|_at|last_seen|latest_event|first_seen|date|time)$/i.test(field)) return <>{formatTime(value)}</>;
  if (typeof value === "number") return <>{number(value).toLocaleString("ru-RU")}</>;
  const rendered = text(value);
  if (/^https?:\/\//i.test(rendered)) return <a className="record-detail-link" href={rendered} rel="noreferrer" target="_blank">{rendered}</a>;
  if (field === "href" && rendered.startsWith("/")) {
    const routeAliases: Record<string, string> = { "/host-runtime": "/app/runtime", "/vuln": "/app/exposure", "/threat-intel": "/app/intel" };
    const base = rendered.split("?")[0];
    const query = rendered.includes("?") ? `?${rendered.split("?").slice(1).join("?")}` : "";
    const href = `${routeAliases[base] ?? (base.startsWith("/app/") ? base : `/app${base}`)}${query}`;
    return <a className="record-detail-link" href={href}>{rendered}</a>;
  }
  return <span className="record-detail-text">{rendered}</span>;
}

function ObjectValue({ value, depth }: { value: Row; depth: number }) {
  const entries = Object.entries(value).filter(([, item]) => !empty(item));
  if (!entries.length) return <span>Нет данных</span>;
  if (depth > 1) return <span>{entries.length} полей</span>;
  return <dl className="record-nested-kv">{entries.slice(0, 20).map(([key, item]) => <div key={key}><dt>{labelFor(key)}</dt><dd><ValueView depth={depth + 1} field={key} value={item} /></dd></div>)}</dl>;
}

function ObjectTable({ rows, depth }: { rows: Row[]; depth: number }) {
  const columns = [...new Set(rows.flatMap((row) => Object.keys(row)))].filter((key) => rows.some((row) => !empty(row[key]))).slice(0, 6);
  if (!columns.length) return <span>{rows.length} объектов</span>;
  return <div className="record-mini-table"><table><thead><tr>{columns.map((key) => <th key={key}>{labelFor(key)}</th>)}</tr></thead><tbody>{rows.slice(0, 12).map((row, index) => <tr key={text(row.id ?? row.name ?? row.title, String(index))}>{columns.map((key) => <td key={key}><ValueView depth={depth + 1} field={key} value={row[key]} /></td>)}</tr>)}</tbody></table>{rows.length > 12 ? <small>Показано 12 из {rows.length}</small> : null}</div>;
}

function ValueView({ field, value, depth = 0 }: { field: string; value: unknown; depth?: number }) {
  if (empty(value)) return <span>—</span>;
  if (Array.isArray(value)) {
    const objects = value.map(asRow).filter((item): item is Row => Boolean(item));
    if (objects.length === value.length && objects.length) return <ObjectTable depth={depth} rows={objects} />;
    return <div className="record-chip-list">{value.slice(0, 24).map((item, index) => <span key={`${text(item)}-${index}`}>{text(item)}</span>)}{value.length > 24 ? <b>+{value.length - 24}</b> : null}</div>;
  }
  const record = asRow(value);
  if (record) return <ObjectValue depth={depth} value={record} />;
  return <PrimitiveValue field={field} value={value} />;
}

export function RecordDetails({ value, kind }: { value: Row; kind: DetailKind }) {
  const entries = Object.entries(value).filter(([, item]) => !empty(item));
  if (!entries.length) return <EmptyState detail="Объект не содержит доступных атрибутов" />;
  const groups = new Map<Section, Array<[string, unknown]>>();
  for (const entry of entries) {
    const section = sectionFor(entry[0]);
    groups.set(section, [...(groups.get(section) ?? []), entry]);
  }
  const status = value.status ?? value.telemetry_state ?? value.integration_state ?? value.healthy;
  const severity = value.severity ?? value.cmdb_criticality ?? value.priority;
  const identifier = value.id ?? value.uuid ?? value.asset_id ?? value.cmdb_asset_id ?? value.finding_key ?? value.service_id;
  return <div className="record-details">
    <div className="record-detail-summary"><span>{KIND_LABELS[kind]}</span>{!empty(status) ? <StatusCell value={text(status)} /> : null}{!empty(severity) ? <Badge tone={severityTone(severity)}>{text(severity)}</Badge> : null}{!empty(identifier) ? <code>{text(identifier)}</code> : null}</div>
    <div className="record-detail-cards">{(Object.keys(SECTION_LABELS) as Section[]).map((section) => {
      const sectionEntries = groups.get(section) ?? [];
      if (!sectionEntries.length) return null;
      return <section className={`record-detail-card record-detail-${section}`} key={section}><header><h3>{SECTION_LABELS[section]}</h3><span>{sectionEntries.length}</span></header><dl>{sectionEntries.map(([key, item]) => <div className={Array.isArray(item) || asRow(item) ? "record-detail-wide" : ""} key={key}><dt>{labelFor(key)}</dt><dd><ValueView field={key} value={item} /></dd></div>)}</dl></section>;
    })}</div>
  </div>;
}

export function RuntimeOverviewCards({ ingest, health, certification }: { ingest: Row; health: Row; certification: Row }) {
  const ingestMetrics = asRow(ingest.metrics) ?? {};
  const platform = asRow(health.platform) ?? {};
  const transport = asRow(ingest.transport) ?? {};
  const streams = asRow(ingest.streams) ?? {};
  const rawStream = asRow(streams.raw) ?? {};
  const dlq = asRow(ingest.dlq) ?? {};
  const benchmark = asRow(certification.latest_benchmark) ?? {};
  return <div className="record-details runtime-overview-cards">
    <div className="record-detail-cards">
      <section className="record-detail-card"><header><h3>Прием событий</h3><StatusCell value={text(ingestMetrics.raw_stream_pressure_state, "Норма")} /></header><dl>
        <div><dt>Получено</dt><dd>{number(ingestMetrics.received_total).toLocaleString("ru-RU")}</dd></div>
        <div><dt>Принято</dt><dd>{number(ingestMetrics.accepted_total).toLocaleString("ru-RU")}</dd></div>
        <div><dt>Активные источники</dt><dd>{number(ingestMetrics.active_sources)}</dd></div>
        <div><dt>Активные коллекторы</dt><dd>{number(ingestMetrics.active_collectors)}</dd></div>
        <div><dt>Последнее событие</dt><dd>{formatTime(ingestMetrics.last_event_ts)}</dd></div>
        <div><dt>Последний источник</dt><dd>{text(ingestMetrics.last_source)}</dd></div>
      </dl></section>
      <section className="record-detail-card"><header><h3>Transport</h3><StatusCell value={transport.kafka_enabled ? "Kafka active" : text(transport.backend, "Active")} /></header><dl>
        <div><dt>Backend</dt><dd>{text(transport.backend)}</dd></div>
        <div><dt>Consumer backend</dt><dd>{text(transport.consumer_backend)}</dd></div>
        <div><dt>Security</dt><dd>{text(transport.security_protocol)}</dd></div>
        <div><dt>Pressure</dt><dd>{text(rawStream.pressure_state ?? ingestMetrics.raw_stream_pressure_state)}</dd></div>
        <div><dt>Raw stream</dt><dd>{number(ingestMetrics.raw_stream_length).toLocaleString("ru-RU")}</dd></div>
        <div><dt>DLQ outstanding</dt><dd>{number(dlq.outstanding)}</dd></div>
      </dl></section>
      <section className="record-detail-card"><header><h3>Сертификация нагрузки</h3><StatusCell value={certification.healthy ? "Healthy" : "Degraded"} /></header><dl>
        <div><dt>Сертифицированный EPS</dt><dd>{number(certification.latest_certified_ceiling_eps).toLocaleString("ru-RU")}</dd></div>
        <div><dt>Лучший sustained EPS</dt><dd>{number(benchmark.best_sustained_eps).toLocaleString("ru-RU")}</dd></div>
        <div><dt>Delivery ratio</dt><dd>{number(benchmark.best_delivery_ratio).toLocaleString("ru-RU")}</dd></div>
        <div><dt>Ingest p95</dt><dd>{number(benchmark.observed_ingest_p95_latency_ms).toLocaleString("ru-RU")} мс</dd></div>
        <div><dt>Consumer lag</dt><dd>{number(benchmark.max_observed_consumer_lag).toLocaleString("ru-RU")}</dd></div>
        <div><dt>Обновлено</dt><dd>{formatTime(certification.last_updated_ts)}</dd></div>
      </dl></section>
      <section className="record-detail-card"><header><h3>Storage и control plane</h3><StatusCell value={platform.clickhouse_ok ? "Healthy" : "Degraded"} /></header><dl>
        <div><dt>ClickHouse</dt><dd>{platform.clickhouse_ok ? "Доступен" : "Недоступен"}</dd></div>
        <div><dt>Content store</dt><dd>{text(platform.content_store_status ?? platform.content_store_backend)}</dd></div>
        <div><dt>Stream correlation</dt><dd><ValueView field="stream_correlation" value={platform.stream_correlation} /></dd></div>
        <div><dt>События 5 мин</dt><dd>{number(platform.events_5m).toLocaleString("ru-RU")}</dd></div>
        <div><dt>Алерты 24 ч</dt><dd>{number(platform.alerts_24h).toLocaleString("ru-RU")}</dd></div>
        <div><dt>Последнее событие</dt><dd>{formatTime(platform.last_event_ts)}</dd></div>
      </dl></section>
    </div>
  </div>;
}
