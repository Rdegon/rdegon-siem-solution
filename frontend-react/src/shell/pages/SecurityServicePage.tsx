import { useCallback, useMemo } from "react";
import { Link, useParams } from "react-router-dom";

import { api } from "../api";
import { AsyncGate } from "../async";
import { t, useShellContext } from "../context";
import { usePolledData } from "../hooks";
import { MetricStrip, PageTabs, PanelHeader, SectionIntro, SeverityBadge, StatusBadge } from "../ui";
import type { RuntimeBlob, SecurityServiceDetailResponse } from "../types";


const SERVICE_TABS = [
  { id: "ndr", label: "NDR", to: "/security/ndr" },
  { id: "ngfw", label: "NGFW", to: "/security/ngfw" },
  { id: "ips", label: "IPS", to: "/security/ips" },
  { id: "dfir", label: "DFIR", to: "/security/dfir" },
  { id: "analysis", label: "Analysis", to: "/security/analysis" },
  { id: "vulnerability", label: "VM", to: "/security/vulnerability" },
  { id: "runtime", label: "Runtime", to: "/security/runtime" },
  { id: "threat-intel", label: "MISP", to: "/security/threat-intel" },
  { id: "pki", label: "PKI", to: "/security/pki" },
  { id: "evidence", label: "Evidence", to: "/security/evidence" },
];

function numberValue(value: unknown) {
  const numeric = Number(value || 0);
  return Number.isFinite(numeric) ? numeric.toLocaleString() : "0";
}

function textValue(value: unknown) {
  const text = String(value ?? "").trim();
  return text || "n/a";
}

function listValue(value: unknown) {
  return Array.isArray(value) ? value.map((item) => String(item || "").trim()).filter(Boolean) : [];
}

export function SecurityServicePage() {
  const { serviceId = "ndr" } = useParams();
  const { lang, formatTimestamp } = useShellContext();
  const normalizedServiceId = SERVICE_TABS.some((item) => item.id === serviceId) ? serviceId : "ndr";
  const loadService = useCallback(() => api.securityService(normalizedServiceId), [normalizedServiceId]);
  const state = usePolledData<SecurityServiceDetailResponse>(loadService, 30_000);
  const data = state.data;
  const service = data?.service;
  const telemetry = data?.telemetry || {};
  const events = useMemo(() => data?.recent_events || [], [data?.recent_events]);
  const alerts = useMemo(() => data?.recent_alerts || [], [data?.recent_alerts]);
  const breakdown = useMemo(() => data?.signal_breakdown || [], [data?.signal_breakdown]);
  const pivots = service?.pivots || {};
  const capabilities = listValue(service?.capabilities);
  const products = listValue(telemetry.products);

  return (
    <AsyncGate
      states={[state]}
      loadingMessage={t(lang, { en: "Loading security service telemetry...", ru: "Загрузка телеметрии сервиса безопасности..." })}
    >
      <div className="react-page react-page-security-service">
        <SectionIntro
          kicker={t(lang, { en: "Security Systems", ru: "Системы безопасности" })}
          title={service?.title || normalizedServiceId}
          subtitle={`${textValue(service?.product)} | ${textValue(service?.host_name)} | ${textValue(service?.address)}`}
          icon="intel"
          actions={<StatusBadge value={String(telemetry.state || "stale")} />}
        />

        <PageTabs items={SERVICE_TABS} />

        <MetricStrip
          items={[
            {
              label: t(lang, { en: "Events 15m", ru: "События 15 мин" }),
              value: numberValue(telemetry.events_15m),
              hint: t(lang, { en: "Fresh telemetry accepted by SIEM.", ru: "Свежая телеметрия, принятая SIEM." }),
              tone: Number(telemetry.events_15m || 0) > 0 ? "success" : "critical",
            },
            {
              label: t(lang, { en: "Events 1h", ru: "События 1 ч" }),
              value: numberValue(telemetry.events_1h),
              hint: t(lang, { en: "Normalized source events in the last hour.", ru: "Нормализованные события источника за последний час." }),
              tone: "info",
            },
            {
              label: t(lang, { en: "Products", ru: "Продукты" }),
              value: numberValue(products.length),
              hint: t(lang, { en: "Normalized products observed for this service.", ru: "Нормализованные продукты, замеченные у этого сервиса." }),
              tone: "default",
            },
            {
              label: t(lang, { en: "Alerts 7d", ru: "Алерты 7 дн" }),
              value: numberValue(telemetry.alerts_7d_returned),
              hint: t(lang, { en: "Recent operational alerts linked to this source.", ru: "Последние рабочие алерты, связанные с источником." }),
              tone: Number(telemetry.alerts_7d_returned || 0) > 0 ? "warning" : "success",
            },
            {
              label: t(lang, { en: "Last event", ru: "Последнее событие" }),
              value: formatTimestamp(telemetry.latest_event, "compact"),
              hint: t(lang, { en: "Most recent stored event timestamp.", ru: "Время последнего сохраненного события." }),
              tone: "default",
            },
          ]}
        />

        <section className="react-card">
          <PanelHeader
            title={t(lang, { en: "Integration state", ru: "Состояние интеграции" })}
            subtitle={t(lang, {
              en: "Placement, normalized products and SIEM pivots for the selected security service.",
              ru: "Размещение, нормализованные продукты и переходы внутри SIEM для выбранного сервиса.",
            })}
            icon="sources"
            actions={
              <div className="react-actions">
                <Link className="react-link-button" to={String(pivots.events || "/events")}>
                  {t(lang, { en: "Events", ru: "События" })}
                </Link>
                <Link className="react-link-button" to={String(pivots.incidents || "/incidents")}>
                  {t(lang, { en: "Incidents", ru: "Инциденты" })}
                </Link>
              </div>
            }
          />
          <div className="react-kv-grid">
            <div className="react-kv"><div className="react-kv-label">{t(lang, { en: "Placement", ru: "Размещение" })}</div><div className="react-kv-value">{textValue(service?.placement)}</div></div>
            <div className="react-kv"><div className="react-kv-label">{t(lang, { en: "Role", ru: "Роль" })}</div><div className="react-kv-value">{textValue(service?.role)}</div></div>
            <div className="react-kv"><div className="react-kv-label">{t(lang, { en: "Asset group", ru: "Группа активов" })}</div><div className="react-kv-value">{textValue(service?.asset_group)}</div></div>
            <div className="react-kv"><div className="react-kv-label">{t(lang, { en: "Products seen", ru: "Продукты в событиях" })}</div><div className="react-kv-value">{products.join(", ") || "n/a"}</div></div>
          </div>
          {capabilities.length ? <div className="react-chip-row" style={{ marginTop: 16 }}>{capabilities.map((item) => <span key={item} className="react-chip">{item}</span>)}</div> : null}
        </section>

        <section className="react-card">
          <PanelHeader
            title={t(lang, { en: "Signal breakdown", ru: "Распределение сигналов" })}
            subtitle={t(lang, { en: "Normalized source families observed during the last hour.", ru: "Нормализованные семейства событий за последний час." })}
            icon="events"
          />
          <div className="react-table-wrap">
            <table className="react-table">
              <thead><tr><th>Product</th><th>Category</th><th>Signal</th><th>Severity</th><th>Events</th><th>Latest</th></tr></thead>
              <tbody>
                {breakdown.map((row, index) => (
                  <tr key={`${row.device_product || "product"}-${row.category || "category"}-${row.subcategory || "subcategory"}-${row.severity || index}`}>
                    <td>{textValue(row.device_product)}</td>
                    <td>{textValue(row.category)}</td>
                    <td>{textValue(row.subcategory)}</td>
                    <td><SeverityBadge value={String(row.severity || "info")} /></td>
                    <td>{numberValue(row.event_count)}</td>
                    <td>{formatTimestamp(row.latest_event, "compact")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="react-card">
          <PanelHeader
            title={t(lang, { en: "Recent alerts", ru: "Последние алерты" })}
            subtitle={t(lang, { en: "Correlation output linked to this service during the last seven days.", ru: "Результаты корреляции, связанные с сервисом за последние семь дней." })}
            icon="incidents"
          />
          {alerts.length ? (
            <div className="react-table-wrap">
              <table className="react-table">
                <thead><tr><th>Time</th><th>Rule</th><th>Severity</th><th>Hits</th><th>Entity</th><th>Status</th></tr></thead>
                <tbody>
                  {alerts.map((row, index) => (
                    <tr key={String(row.alert_id || index)}>
                      <td>{formatTimestamp(row.ts_last, "compact")}</td>
                      <td>{textValue(row.rule_name)}</td>
                      <td><SeverityBadge value={String(row.severity || "info")} /></td>
                      <td>{numberValue(row.hits)}</td>
                      <td>{textValue(row.entity_key)}</td>
                      <td><StatusBadge value={String(row.status || "new")} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <div className="react-empty">{t(lang, { en: "No linked alerts in the selected period.", ru: "Связанных алертов за выбранный период нет." })}</div>}
        </section>

        <section className="react-card">
          <PanelHeader
            title={t(lang, { en: "Recent source events", ru: "Последние события источника" })}
            subtitle={t(lang, { en: "Normalized evidence stored in the central SIEM event table.", ru: "Нормализованные данные, сохраненные в центральной таблице событий SIEM." })}
            icon="events"
          />
          <div className="react-table-wrap">
            <table className="react-table">
              <thead><tr><th>Time</th><th>Product</th><th>Signal</th><th>Severity</th><th>Host</th><th>Message</th></tr></thead>
              <tbody>
                {events.map((row: RuntimeBlob, index) => (
                  <tr key={String(row.event_id || index)}>
                    <td>{formatTimestamp(row.ts, "compact")}</td>
                    <td>{textValue(row.device_product)}</td>
                    <td>{textValue(row.subcategory || row.category)}</td>
                    <td><SeverityBadge value={String(row.severity || "info")} /></td>
                    <td>{textValue(row.host_name || row.log_source)}</td>
                    <td>{textValue(row.message).slice(0, 280)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </AsyncGate>
  );
}
