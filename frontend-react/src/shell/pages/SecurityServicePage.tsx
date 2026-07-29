import { useCallback, useMemo } from "react";
import { Link, useParams } from "react-router-dom";

import { api } from "../api";
import { AsyncGate } from "../async";
import { t, useShellContext } from "../context";
import { usePolledData } from "../hooks";
import type { RuntimeBlob, SecurityServiceDetailResponse } from "../types";
import { MetricStrip, PageTabs, PanelHeader, SectionIntro, SeverityBadge, StatusBadge } from "../ui";
import { SecurityControlPanel } from "./SecurityControlPanel";


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
  return String(value ?? "").trim() || "n/a";
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
  const interactive = normalizedServiceId === "ngfw" || normalizedServiceId === "ips";
  const workspaces = Array.isArray(service?.workspaces) ? service.workspaces as RuntimeBlob[] : [];
  const integrationMode = textValue(service?.integration_mode);

  return (
    <AsyncGate
      states={[state]}
      loadingMessage={t(lang, {
        en: "Loading security service telemetry...",
        ru: "Загрузка телеметрии системы безопасности...",
      })}
    >
      <div className="react-page react-page-security-service">
        <SectionIntro
          kicker={t(lang, { en: "Security systems", ru: "Системы безопасности" })}
          title={service?.title || normalizedServiceId}
          subtitle={`${textValue(service?.product)} | ${textValue(service?.host_name)} | ${textValue(service?.address)}`}
          icon="intel"
          actions={<StatusBadge value={String(telemetry.state || "stale")} />}
        />

        <PageTabs items={SERVICE_TABS} />

        {interactive ? <SecurityControlPanel serviceId={normalizedServiceId} /> : null}

        <section className="react-card react-security-workspaces">
          <PanelHeader
            title="Operational workspaces"
            subtitle="Verified SIEM workflows and native product consoles. Native 10.20.x.x consoles require the routed operator or VPN network."
            icon="control"
            actions={<StatusBadge value={integrationMode} />}
          />
          <div className="react-security-workspace-grid">
            {workspaces.map((workspace, index) => {
              const href = textValue(workspace.href);
              const content = (
                <>
                  <strong>{textValue(workspace.label)}</strong>
                  <span>{textValue(workspace.description)}</span>
                  <small>{workspace.kind === "native" ? "Native product" : "SIEM workspace"}</small>
                </>
              );
              return workspace.external ? (
                <a key={`${href}-${index}`} className="react-security-workspace-link" href={href} target="_blank" rel="noreferrer">
                  {content}
                </a>
              ) : (
                <Link key={`${href}-${index}`} className="react-security-workspace-link" to={href}>
                  {content}
                </Link>
              );
            })}
          </div>
          {service?.native_console_route && service.native_console_route !== "direct" ? (
            <div className="react-inline-note react-inline-note-spaced">
              Native route: {textValue(service.native_console_route)}
            </div>
          ) : null}
        </section>

        <MetricStrip
          items={[
            {
              label: t(lang, { en: "Events 15m", ru: "События 15 мин" }),
              value: numberValue(telemetry.events_15m),
              hint: t(lang, { en: "Fresh normalized telemetry.", ru: "Свежая нормализованная телеметрия." }),
              tone: Number(telemetry.events_15m || 0) > 0 ? "success" : "critical",
            },
            {
              label: t(lang, { en: "Events 1h", ru: "События 1 ч" }),
              value: numberValue(telemetry.events_1h),
              hint: t(lang, { en: "Stored source events.", ru: "Сохраненные события источника." }),
              tone: "info",
            },
            {
              label: t(lang, { en: "Products", ru: "Продукты" }),
              value: numberValue(products.length),
              hint: t(lang, { en: "Observed normalized products.", ru: "Обнаруженные нормализованные продукты." }),
              tone: "default",
            },
            {
              label: t(lang, { en: "Alerts 7d", ru: "Алерты 7 дней" }),
              value: numberValue(telemetry.alerts_7d_returned),
              hint: t(lang, { en: "Linked correlation alerts.", ru: "Связанные алерты корреляции." }),
              tone: Number(telemetry.alerts_7d_returned || 0) > 0 ? "warning" : "success",
            },
            {
              label: t(lang, { en: "Last event", ru: "Последнее событие" }),
              value: formatTimestamp(telemetry.latest_event, "compact"),
              hint: t(lang, { en: "Latest stored timestamp.", ru: "Время последнего сохраненного события." }),
              tone: "default",
            },
          ]}
        />

        <section className="react-card">
          <PanelHeader
            title={t(lang, { en: "Integration state", ru: "Состояние интеграции" })}
            subtitle={t(lang, {
              en: "Placement, normalized products and investigation pivots.",
              ru: "Размещение, нормализованные продукты и переходы расследования.",
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
          {capabilities.length ? (
            <div className="react-chip-row" style={{ marginTop: 16 }}>
              {capabilities.map((item) => <span key={item} className="react-chip">{item}</span>)}
            </div>
          ) : null}
        </section>

        <section className="react-card">
          <PanelHeader
            title={t(lang, { en: "Signal breakdown", ru: "Распределение сигналов" })}
            subtitle={t(lang, { en: "Normalized event families observed during the last hour.", ru: "Нормализованные семейства событий за последний час." })}
            icon="events"
          />
          <div className="react-table-wrap">
            <table className="react-table">
              <thead><tr><th>Product</th><th>Category</th><th>Signal</th><th>Severity</th><th>Events</th><th>Latest</th></tr></thead>
              <tbody>
                {breakdown.map((row, index) => (
                  <tr key={`${row.device_product || "product"}-${row.subcategory || index}`}>
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
            subtitle={t(lang, { en: "Correlation output linked to this service.", ru: "Результаты корреляции, связанные с этой системой." })}
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
          ) : <div className="react-empty">{t(lang, { en: "No linked alerts.", ru: "Связанных алертов нет." })}</div>}
        </section>

        <section className="react-card">
          <PanelHeader
            title={t(lang, { en: "Recent source events", ru: "Последние события источника" })}
            subtitle={t(lang, { en: "Normalized evidence stored in SIEM.", ru: "Нормализованные данные, сохраненные в SIEM." })}
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
