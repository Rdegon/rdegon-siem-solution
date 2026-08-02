import { useState } from "react";
import type { IncidentDetailResponse } from "./runtime/types";
import { formatTime, number, severityTone, text } from "./runtime/query";
import { Badge, EmptyState, KeyValue, Tabs } from "./ui";

type Row = Record<string, unknown>;

function rows(value: unknown): Row[] {
  return Array.isArray(value) ? value.filter((item): item is Row => Boolean(item) && typeof item === "object") : [];
}

function record(value: unknown): Row {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Row : {};
}

export function humanizeEntity(value: unknown): string {
  let item = value;
  if (typeof item === "string" && item.trim().startsWith("{")) {
    try { item = JSON.parse(item); } catch { return String(item); }
  }
  if (!item || typeof item !== "object" || Array.isArray(item)) return text(item, "");
  const entity = item as Row;
  const preferred = ["display_name", "name", "hostname", "host.name", "user.name", "process.name", "ip", "address", "value", "id"];
  for (const key of preferred) {
    const label = text(entity[key], "");
    if (label && !label.startsWith("{")) return label;
  }
  const scalar = Object.entries(entity).find(([, current]) => ["string", "number"].includes(typeof current) && String(current).trim());
  return scalar ? String(scalar[1]) : "Объект без имени";
}

function Chips({ values, empty = "Нет данных" }: { values: unknown; empty?: string }) {
  const items = Array.isArray(values) ? [...new Set(values.map(humanizeEntity).filter(Boolean))] : [];
  if (!items.length) return <span className="muted">{empty}</span>;
  return <div className="sentinel-chip-list">{items.map((item) => <span key={item}>{item}</span>)}</div>;
}

function MiniTable({ items, columns }: { items: Row[]; columns: Array<{ key: string; label: string; render?: (row: Row) => React.ReactNode }> }) {
  if (!items.length) return <EmptyState detail="Связанные записи отсутствуют" />;
  return <div className="native-grid sentinel-detail-table"><table><thead><tr>{columns.map((column) => <th key={column.key}>{column.label}</th>)}</tr></thead><tbody>{items.map((item, index) => <tr key={text(item.event_id ?? item.alert_id ?? item.ts, String(index))}>{columns.map((column) => <td key={column.key}>{column.render ? column.render(item) : text(item[column.key])}</td>)}</tr>)}</tbody></table></div>;
}

function SummaryTab({ detail }: { detail: IncidentDetailResponse }) {
  const item = record(detail.item);
  const summary = record(detail.summary);
  const risk = record(detail.risk);
  const entities = record(detail.entities);
  const recommendations = Array.isArray(detail.recommendations) ? detail.recommendations : [];
  return <div className="sentinel-detail-stack">
    <section className="sentinel-incident-hero"><div><Badge tone={severityTone(item.severity_agg ?? item.severity)}>{text(item.severity_agg ?? item.severity)}</Badge><strong>{text(summary.trigger_reason ?? item.rule_name)}</strong><p>{text(summary.description, "Корреляционное правило обнаружило активность, требующую triage.")}</p></div><div className="sentinel-risk-score"><strong>{number(risk.risk_score)}</strong><span>risk score</span></div></section>
    <section><h3>Операционная сводка</h3><KeyValue rows={[
      ["Основная сущность", text(summary.main_entity ?? item.entity_key)],
      ["Источник", text(item.source_summary ?? item.source)],
      ["Временной диапазон", text(summary.time_range, `${formatTime(item.ts_first)} — ${formatTime(item.ts_last)}`)],
      ["MITRE ATT&CK", [text(summary.mitre_tactic, ""), text(summary.mitre_technique, "")].filter(Boolean).join(" · ") || "—"],
      ["Приоритет", text(risk.priority)], ["Уверенность", text(risk.confidence)], ["Влияние", text(risk.impact)],
      ["Срабатывания", number(item.raw_alerts_total ?? item.count_alerts).toLocaleString("ru-RU")],
    ]} /></section>
    <section><h3>Сущности</h3><div className="sentinel-entity-grid"><div><span>Хосты</span><Chips values={entities.hosts} /></div><div><span>IP-адреса</span><Chips values={entities.ips} /></div><div><span>Пользователи</span><Chips values={entities.users} /></div><div><span>Процессы</span><Chips values={entities.processes} /></div></div></section>
    <section><h3>Рекомендованные действия</h3>{recommendations.length ? <ol className="sentinel-recommendations">{recommendations.map((item, index) => <li key={`${text(item)}-${index}`}>{text(item)}</li>)}</ol> : <EmptyState detail="Рекомендации для этого типа события не определены" />}</section>
  </div>;
}

function TimelineTab({ detail }: { detail: IncidentDetailResponse }) {
  const timeline = rows(detail.timeline);
  if (!timeline.length) return <EmptyState detail="Временная шкала отсутствует" />;
  return <ol className="sentinel-incident-timeline">{timeline.map((item, index) => <li key={`${text(item.event_id ?? item.ts)}-${index}`}><i className={`tone-${severityTone(item.severity)}`} /><time>{formatTime(item.ts)}</time><div><strong>{text(item.description ?? item.type)}</strong><span>{text(item.source)} · {humanizeEntity(item.entity)}</span></div></li>)}</ol>;
}

function EvidenceTab({ detail }: { detail: IncidentDetailResponse }) {
  const related = record(detail.related_events);
  const rawAlerts = record(detail.raw_alerts);
  const commands = rows(detail.command_evidence);
  const events = rows(related.items);
  const alerts = rows(rawAlerts.items);
  return <div className="sentinel-detail-stack">
    <section><h3>Связанные события <span>{number(related.total)}</span></h3><MiniTable columns={[
      { key: "ts", label: "Время", render: (row) => formatTime(row.ts) }, { key: "log_source", label: "Источник" }, { key: "category", label: "Категория" }, { key: "host_name", label: "Хост" }, { key: "message", label: "Событие", render: (row) => <span className="sentinel-evidence-message">{text(row.message)}</span> },
    ]} items={events} /></section>
    <section><h3>Командная активность <span>{commands.length}</span></h3><MiniTable columns={[
      { key: "ts", label: "Время", render: (row) => formatTime(row.ts) }, { key: "host_name", label: "Хост" }, { key: "user_name", label: "Пользователь" }, { key: "process_name", label: "Процесс" }, { key: "process_command", label: "Команда", render: (row) => <code>{text(row.process_command)}</code> },
    ]} items={commands} /></section>
    <section><h3>Исходные алерты <span>{number(rawAlerts.total)}</span></h3><MiniTable columns={[
      { key: "ts_last", label: "Время", render: (row) => formatTime(row.ts_last ?? row.ts) }, { key: "rule_id", label: "Rule ID" }, { key: "rule_name", label: "Правило" }, { key: "severity", label: "Важность", render: (row) => <Badge tone={severityTone(row.severity)}>{text(row.severity)}</Badge> }, { key: "hits", label: "Hits" },
    ]} items={alerts} /></section>
  </div>;
}

function RuleTab({ detail }: { detail: IncidentDetailResponse }) {
  const rules = rows(detail.rules);
  const network = record(detail.network_context);
  const auth = record(detail.authentication_context);
  return <div className="sentinel-detail-stack">
    {rules.map((rule) => <section key={text(rule.rule_id)}><h3>{text(rule.rule_name)}</h3><p className="sentinel-detail-copy">{text(rule.description)}</p><KeyValue rows={[["Rule ID", text(rule.rule_id)], ["Тип", text(rule.rule_type)], ["Версия", text(rule.rule_version)], ["Окно", `${number(rule.window_s)} сек`], ["Порог", text(rule.threshold)], ["Группировка", text(rule.group_by)], ["MITRE тактики", text(rule.mitre_tactics ?? rule.mitre_tactic)], ["MITRE техники", text(rule.mitre_techniques ?? rule.mitre_technique)], ["Логика", text(rule.logic_summary)]]} /></section>)}
    <section><h3>Сетевой контекст</h3><KeyValue rows={[["Source IP", text(network.source_ips)], ["Destination IP", text(network.destination_ips)], ["Порты назначения", text(network.destination_ports)], ["Внешние источники", number(network.external_source_ip_count)], ["Внешние назначения", number(network.external_destination_ip_count)]]} /></section>
    <section><h3>Аутентификация</h3><KeyValue rows={[["Всего событий", number(auth.auth_event_count)], ["Неуспешные входы", number(auth.failed_login_count)], ["Успешные входы", number(auth.successful_login_count)], ["Пользователи", <Chips key="auth-users" values={auth.users} />], ["Хосты", <Chips key="auth-hosts" values={auth.hosts} />]]} /></section>
  </div>;
}

export function IncidentDetailContent({ detail }: { detail: IncidentDetailResponse }) {
  const [tab, setTab] = useState("summary");
  const related = record(detail.related_events);
  const rawAlerts = record(detail.raw_alerts);
  return <div className="kuma-drawer sentinel-incident-detail"><Tabs label="Разделы карточки инцидента" onChange={setTab} value={tab} items={[
    { id: "summary", label: "Сводка" }, { id: "timeline", label: "Хронология", count: rows(detail.timeline).length }, { id: "evidence", label: "Evidence", count: number(related.total) + number(rawAlerts.total) }, { id: "rule", label: "Правило", count: rows(detail.rules).length },
  ]} />
    {tab === "summary" ? <SummaryTab detail={detail} /> : null}
    {tab === "timeline" ? <TimelineTab detail={detail} /> : null}
    {tab === "evidence" ? <EvidenceTab detail={detail} /> : null}
    {tab === "rule" ? <RuleTab detail={detail} /> : null}
  </div>;
}

export function EventDetailContent({ event }: { event: Row }) {
  const [tab, setTab] = useState("normalized");
  const networkPresent = [event.src_ip, event.dst_ip, event.src_port, event.dst_port].some((value) => text(value, ""));
  return <div className="kuma-drawer sentinel-event-detail"><section className="sentinel-event-hero"><Badge tone={severityTone(event.severity)}>{text(event.severity)}</Badge><div><strong>{text(event.message, text(event.category))}</strong><span>{text(event.log_source)} · {formatTime(event.ts)}</span></div></section><Tabs label="Разделы события" onChange={setTab} value={tab} items={[{ id: "normalized", label: "Нормализованные поля" }, { id: "context", label: "Контекст" }]} />
    {tab === "normalized" ? <section><h3>Основные поля</h3><KeyValue rows={[["Event ID", text(event.event_id)], ["Источник", text(event.log_source)], ["Коллектор", text(event.collector_profile ?? event.observer_collector)], ["Категория", text(event.category)], ["Подкатегория", text(event.subcategory)], ["Действие", text(event.event_action)], ["Результат", text(event.event_outcome)], ["Хост", text(event.host_name)], ["Актив", text(event.asset_id)], ["Пользователь", text(event.user_name ?? event.target_user)]]} /></section> : null}
    {tab === "context" ? <div className="sentinel-detail-stack"><section><h3>Сеть</h3>{networkPresent ? <KeyValue rows={[["Source", `${text(event.src_ip)}:${text(event.src_port)}`], ["Destination", `${text(event.dst_ip)}:${text(event.dst_port)}`], ["Протокол", text(event.network_protocol ?? event.protocol)]]} /> : <EmptyState detail="Сетевые поля для события отсутствуют" />}</section><section><h3>Процесс</h3><KeyValue rows={[["Имя", text(event.process_name)], ["Executable", text(event.process_executable)], ["PID", text(event.process_id)], ["Командная строка", <code key="command">{text(event.process_command)}</code>]]} /></section></div> : null}
  </div>;
}
