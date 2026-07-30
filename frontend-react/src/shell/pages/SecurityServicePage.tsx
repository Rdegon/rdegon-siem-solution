import { useCallback, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { api } from "../api";
import { AsyncGate } from "../async";
import { t, useShellContext } from "../context";
import { usePolledData } from "../hooks";
import type { RuntimeBlob, SecurityServiceDetailResponse } from "../types";
import { MetricStrip, PageTabs, PanelHeader, SeverityBadge, StatusBadge } from "../ui";
import { NativePageHeader } from "../native";
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
  return Array.isArray(value)
    ? value.map((item) => String(item || "").trim()).filter(Boolean)
    : [];
}

function percentValue(value: unknown) {
  const numeric = Number(value || 0);
  return `${Math.round(Math.max(0, Math.min(1, numeric)) * 100)}%`;
}

export function SecurityServicePage() {
  const { serviceId = "ndr" } = useParams();
  const { lang, formatTimestamp } = useShellContext();
  const [refreshToken, setRefreshToken] = useState(0);
  const [evidenceView, setEvidenceView] = useState<"alerts" | "events">("alerts");
  const normalizedServiceId = SERVICE_TABS.some((item) => item.id === serviceId) ? serviceId : "ndr";
  const loadService = useCallback(() => {
    void refreshToken;
    return api.securityService(normalizedServiceId);
  }, [normalizedServiceId, refreshToken]);
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
  const matchedProducts = listValue(telemetry.matched_products);
  const missingProducts = listValue(telemetry.missing_products);
  const integrationState = textValue(telemetry.integration_state || telemetry.state);
  const hostState = textValue(telemetry.host_telemetry_state);
  const interactive = normalizedServiceId === "ngfw" || normalizedServiceId === "ips";
  const workspaces = Array.isArray(service?.workspaces) ? service.workspaces as RuntimeBlob[] : [];

  return (
    <AsyncGate
      states={[state]}
      loadingMessage={t(lang, {
        en: "Loading security service telemetry...",
        ru: "Загрузка телеметрии системы безопасности...",
      })}
    >
      <div className="react-page react-page-security-service native-page">
        <NativePageHeader
          title={service?.title || normalizedServiceId}
          subtitle={`${textValue(service?.product)} | ${textValue(service?.host_name)} | ${textValue(service?.address)}`}
          icon="intel"
          actions={
            <div className="react-actions">
              <button className="react-link-button" type="button" onClick={() => setRefreshToken((value) => value + 1)}>
                {t(lang, { en: "Refresh", ru: "Обновить" })}
              </button>
              <StatusBadge value={integrationState} />
            </div>
          }
        />

        <PageTabs items={SERVICE_TABS} />

        <section className="react-security-commandbar" aria-label={t(lang, { en: "Service actions", ru: "Действия системы" })}>
          <div className="react-security-commandbar-state">
            <StatusBadge value={hostState} />
            <div>
              <strong>{t(lang, { en: "Host telemetry", ru: "Телеметрия узла" })}</strong>
              <span>{formatTimestamp(telemetry.latest_event, "compact")}</span>
            </div>
          </div>
          <div className="react-actions react-wrap">
            <Link className="react-link-button" to={String(pivots.events || "/events")}>
              {t(lang, { en: "Events", ru: "События" })}
            </Link>
            <Link className="react-link-button" to={String(pivots.incidents || "/incidents")}>
              {t(lang, { en: "Incidents", ru: "Инциденты" })}
            </Link>
            <Link className="react-link-button" to={String(pivots.host_runtime || "/host-runtime")}>
              {t(lang, { en: "Host runtime", ru: "Состояние узла" })}
            </Link>
          </div>
        </section>

        {missingProducts.length ? (
          <div className="react-callout react-security-health-warning" role="status">
            <strong>{t(lang, { en: "Product telemetry is incomplete.", ru: "Телеметрия продукта неполная." })}</strong>
            <span>
              {t(lang, { en: "Missing:", ru: "Не поступают:" })} {missingProducts.join(", ")}
            </span>
          </div>
        ) : null}

        <MetricStrip
          items={[
            {
              label: t(lang, { en: "Events 15m", ru: "События за 15 минут" }),
              value: numberValue(telemetry.events_15m),
              hint: t(lang, { en: "Current normalized flow.", ru: "Текущий нормализованный поток." }),
              tone: Number(telemetry.events_15m || 0) > 0 ? "success" : "critical",
            },
            {
              label: t(lang, { en: "Events 1h", ru: "События за час" }),
              value: numberValue(telemetry.events_1h),
              hint: t(lang, { en: "Stored source evidence.", ru: "Сохранённые события источника." }),
              tone: "info",
            },
            {
              label: t(lang, { en: "Product coverage", ru: "Покрытие продуктов" }),
              value: percentValue(telemetry.product_coverage),
              hint: matchedProducts.join(", ") || t(lang, { en: "No product signals.", ru: "Сигналов продукта нет." }),
              tone: missingProducts.length ? "warning" : "success",
            },
            {
              label: t(lang, { en: "Alerts 7d", ru: "Алерты за 7 дней" }),
              value: numberValue(telemetry.alerts_7d_returned),
              hint: t(lang, { en: "Correlation output linked to the service.", ru: "Связанные результаты корреляции." }),
              tone: Number(telemetry.alerts_7d_returned || 0) > 0 ? "warning" : "default",
            },
          ]}
        />

        {interactive ? <SecurityControlPanel serviceId={normalizedServiceId} /> : null}

        <div className="react-security-ops-grid">
          <section className="react-security-ops-panel">
            <PanelHeader
              title={t(lang, { en: "Integration and access", ru: "Интеграция и доступ" })}
              subtitle={t(lang, {
                en: "Real SIEM workspaces and native product consoles.",
                ru: "Рабочие области SIEM и штатные консоли продукта.",
              })}
              icon="control"
            />
            <div className="react-security-facts">
              <div><span>{t(lang, { en: "Placement", ru: "Размещение" })}</span><strong>{textValue(service?.placement)}</strong></div>
              <div><span>{t(lang, { en: "Role", ru: "Роль" })}</span><strong>{textValue(service?.role)}</strong></div>
              <div><span>{t(lang, { en: "Asset group", ru: "Группа активов" })}</span><strong>{textValue(service?.asset_group)}</strong></div>
              <div><span>{t(lang, { en: "Observed", ru: "Обнаружено" })}</span><strong>{products.join(", ") || "n/a"}</strong></div>
            </div>
            <nav className="react-security-workspace-list" aria-label={t(lang, { en: "Operational workspaces", ru: "Рабочие области" })}>
              {workspaces.map((workspace, index) => {
                const href = textValue(workspace.href);
                const content = (
                  <>
                    <span>
                      <strong>{textValue(workspace.label)}</strong>
                      <small>{workspace.kind === "native" ? t(lang, { en: "Native", ru: "Штатная" }) : "SIEM"}</small>
                    </span>
                    <span>{textValue(workspace.description)}</span>
                  </>
                );
                return workspace.external ? (
                  <a key={`${href}-${index}`} href={href} target="_blank" rel="noreferrer">{content}</a>
                ) : (
                  <Link key={`${href}-${index}`} to={href}>{content}</Link>
                );
              })}
            </nav>
          </section>

          <section className="react-security-ops-panel">
            <PanelHeader
              title={t(lang, { en: "Signal coverage", ru: "Покрытие сигналов" })}
              subtitle={t(lang, { en: "Normalized families observed during the last hour.", ru: "Нормализованные семейства за последний час." })}
              icon="events"
            />
            <div className="react-table-wrap">
              <table className="react-table react-table-compact">
                <thead><tr><th>Product</th><th>Signal</th><th>Severity</th><th>Events</th></tr></thead>
                <tbody>
                  {breakdown.slice(0, 12).map((row, index) => (
                    <tr key={`${row.device_product || "product"}-${row.subcategory || index}`}>
                      <td>{textValue(row.device_product)}</td>
                      <td>{textValue(row.subcategory || row.category)}</td>
                      <td><SeverityBadge value={String(row.severity || "info")} /></td>
                      <td>{numberValue(row.event_count)}</td>
                    </tr>
                  ))}
                  {!breakdown.length ? <tr><td colSpan={4}>{t(lang, { en: "No product signals.", ru: "Сигналы продукта не поступали." })}</td></tr> : null}
                </tbody>
              </table>
            </div>
            {capabilities.length ? (
              <div className="react-chip-row react-security-capabilities">
                {capabilities.map((item) => <span key={item} className="react-chip">{item}</span>)}
              </div>
            ) : null}
          </section>
        </div>

        <section className="react-security-evidence-panel">
          <PanelHeader
            title={t(lang, { en: "Operational evidence", ru: "Операционные данные" })}
            subtitle={t(lang, {
              en: "Correlation alerts and normalized source events without leaving the service context.",
              ru: "Алерты корреляции и события источника в контексте системы.",
            })}
            icon="incidents"
            actions={
              <div className="react-segmented react-segmented-compact">
                <button type="button" className={evidenceView === "alerts" ? "active" : ""} onClick={() => setEvidenceView("alerts")}>
                  {t(lang, { en: `Alerts (${alerts.length})`, ru: `Алерты (${alerts.length})` })}
                </button>
                <button type="button" className={evidenceView === "events" ? "active" : ""} onClick={() => setEvidenceView("events")}>
                  {t(lang, { en: `Events (${events.length})`, ru: `События (${events.length})` })}
                </button>
              </div>
            }
          />
          <div className="react-table-wrap">
            {evidenceView === "alerts" ? (
              <table className="react-table">
                <thead><tr><th>{t(lang, { en: "Time", ru: "Время" })}</th><th>{t(lang, { en: "Rule", ru: "Правило" })}</th><th>Severity</th><th>Hits</th><th>{t(lang, { en: "Entity", ru: "Сущность" })}</th><th>Status</th></tr></thead>
                <tbody>
                  {alerts.map((row, index) => (
                    <tr key={String(row.alert_id || index)}>
                      <td>{formatTimestamp(row.ts_last, "compact")}</td>
                      <td><Link to={`/incidents?view=raw&focus=${encodeURIComponent(String(row.alert_id || ""))}`}>{textValue(row.rule_name)}</Link></td>
                      <td><SeverityBadge value={String(row.severity || "info")} /></td>
                      <td>{numberValue(row.hits)}</td>
                      <td>{textValue(row.entity_key)}</td>
                      <td><StatusBadge value={String(row.status || "new")} /></td>
                    </tr>
                  ))}
                  {!alerts.length ? <tr><td colSpan={6}>{t(lang, { en: "No linked alerts.", ru: "Связанных алертов нет." })}</td></tr> : null}
                </tbody>
              </table>
            ) : (
              <table className="react-table">
                <thead><tr><th>{t(lang, { en: "Time", ru: "Время" })}</th><th>Product</th><th>{t(lang, { en: "Signal", ru: "Сигнал" })}</th><th>Severity</th><th>{t(lang, { en: "Host", ru: "Узел" })}</th><th>{t(lang, { en: "Message", ru: "Сообщение" })}</th></tr></thead>
                <tbody>
                  {events.map((row: RuntimeBlob, index) => (
                    <tr key={String(row.event_id || index)}>
                      <td>{formatTimestamp(row.ts, "compact")}</td>
                      <td>{textValue(row.device_product)}</td>
                      <td><Link to={`/events?q=${encodeURIComponent(String(row.event_id || row.subcategory || ""))}`}>{textValue(row.subcategory || row.category)}</Link></td>
                      <td><SeverityBadge value={String(row.severity || "info")} /></td>
                      <td>{textValue(row.host_name || row.log_source)}</td>
                      <td className="react-security-message">{textValue(row.message).slice(0, 280)}</td>
                    </tr>
                  ))}
                  {!events.length ? <tr><td colSpan={6}>{t(lang, { en: "No source events.", ru: "События источника не поступали." })}</td></tr> : null}
                </tbody>
              </table>
            )}
          </div>
        </section>
      </div>
    </AsyncGate>
  );
}
