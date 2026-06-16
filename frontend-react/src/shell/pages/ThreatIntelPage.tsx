import { useCallback, useMemo, useState } from "react";
import { api } from "../api";
import { AsyncGate } from "../async";
import { t, useShellContext } from "../context";
import { useAsyncData, useDebouncedValue } from "../hooks";
import {
  BreakdownBars,
  DrawerFieldGrid,
  DrawerOverlay,
  EmptyState,
  InvestigationActionRail,
  InvestigationSummaryStrip,
  InvestigationTimeline,
  KeyValue,
  PanelHeader,
  SectionIntro,
  SeverityBadge,
  StatCard,
} from "../ui";
import { localizeRuleName } from "../runtimeLocalization";
import type {
  ThreatIntelCatalogEntry,
  ThreatIntelGeoDetailResponse,
  ThreatIntelMaliciousSource,
  ThreatIntelMatchRecord,
  ThreatIntelOverviewResponse,
} from "../types";

function includesToken(value: unknown, token: string) {
  if (!token) return true;
  return JSON.stringify(value).toLowerCase().includes(token);
}

export function ThreatIntelPage() {
  const { lang } = useShellContext();
  const loadOverview = useCallback(() => api.threatIntelOverview({ hours: 24, limit: 20 }), []);
  const overviewState = useAsyncData<ThreatIntelOverviewResponse>(loadOverview);
  const [query, setQuery] = useState("");
  const [selectedIp, setSelectedIp] = useState("");
  const debouncedQuery = useDebouncedValue(query, 250);
  const loadDetail = useCallback(
    () => (selectedIp ? api.geoIpDetail(selectedIp, { hours: 72 }) : Promise.resolve(null)),
    [selectedIp],
  );
  const detailState = useAsyncData<ThreatIntelGeoDetailResponse | null>(loadDetail);

  const matches = useMemo(() => {
    const rows = overviewState.data?.recent_matches || [];
    const token = String(debouncedQuery || "").trim().toLowerCase();
    return rows.filter((row) => includesToken(row, token));
  }, [overviewState.data?.recent_matches, debouncedQuery]);

  const entries = useMemo(() => {
    const rows = overviewState.data?.entries || [];
    const token = String(debouncedQuery || "").trim().toLowerCase();
    return rows.filter((row) => includesToken(row, token));
  }, [overviewState.data?.entries, debouncedQuery]);

  const data = overviewState.data;
  const detail = detailState.data;
  const detailSummary = useMemo(
    () =>
      detail
        ? [
            { label: "IP", value: detail.ip || selectedIp, tone: "info" as const },
            { label: "Reputation", value: detail.reputation?.label || "unknown", tone: detail.reputation?.label === "malicious" ? ("critical" as const) : ("warning" as const) },
            { label: "Country", value: detail.geo?.country || "Unknown" },
            { label: "Events 72h", value: detail.summary?.events || 0 },
            { label: "TI hits", value: detail.summary?.ti_events || 0, tone: Number(detail.summary?.ti_events || 0) ? ("warning" as const) : ("default" as const) },
            { label: "Notable", value: detail.summary?.notable_events || 0, tone: Number(detail.summary?.notable_events || 0) ? ("critical" as const) : ("default" as const) },
          ]
        : [],
    [detail, selectedIp],
  );
  const detailTimeline = useMemo(() => {
    if (!detail) return [];
    const tiEntries = (detail.threat_intel || []).slice(0, 2).map((row, index) => ({
      id: `ti-${index}`,
      title: String(row.provider || "Threat-intel entry"),
      subtitle: String(row.description || "Indicator context"),
      meta: `${row.severity || "n/a"} · conf ${row.confidence || 0}`,
      tone: String(row.severity || "").toLowerCase() === "critical" ? ("critical" as const) : ("warning" as const),
      body: (detail.reputation?.sources || []).join(", ") || "feed-backed reputation",
    }));
    const recentEntries = (detail.recent_events || []).slice(0, 2).map((row, index) => ({
      id: `evt-${index}`,
      title: String(row.log_source || "Observed event"),
      subtitle: `${row.category || "event"} / ${row.subcategory || "record"}`,
      meta: String(row.ts || ""),
      tone: "info" as const,
      body: String(row.message || ""),
    }));
    const incidentEntries = (detail.incidents || []).slice(0, 2).map((row, index) => ({
      id: `inc-${index}`,
      title: localizeRuleName(row.rule_name || t(lang, { en: "Related incident", ru: "Связанный инцидент" }), lang),
      subtitle: String(row.status || t(lang, { en: "open", ru: "открыто" })),
      meta: String(row.last_seen || ""),
      tone: String(row.severity || "").toLowerCase() === "critical" ? ("critical" as const) : ("warning" as const),
      body: String(row.severity || "n/a"),
    }));
    return [...tiEntries, ...recentEntries, ...incidentEntries];
  }, [detail, lang]);

  return (
    <AsyncGate states={[overviewState]} loadingMessage={t(lang, { en: "Loading threat-intel workbench...", ru: "Загрузка рабочей области киберразведки..." })}>
      <div className="react-page">
        <SectionIntro
          kicker={t(lang, { en: "Threat Intel", ru: "Киберразведка" })}
          title={t(lang, { en: "Reputation and IOC workbench", ru: "Рабочее место репутации и индикаторов компрометации" })}
          icon="intel"
          actions={<input className="react-input react-input-grow" value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t(lang, { en: "Search indicator, provider, IP, source...", ru: "Поиск по индикатору, провайдеру, IP или источнику..." })} />}
        />

        <div className="react-grid react-grid-4">
          <StatCard label={t(lang, { en: "Indicators", ru: "Индикаторы" })} value={data?.summary?.indicators || 0} hint={t(lang, { en: "Published TI indicators currently loaded into the platform.", ru: "Опубликованные индикаторы киберразведки, загруженные в платформу." })} />
          <StatCard label={t(lang, { en: "Providers", ru: "Провайдеры" })} value={data?.summary?.providers || 0} hint={t(lang, { en: "Distinct TI feeds or provider labels in the current catalog.", ru: "Уникальные фиды и провайдеры в текущем каталоге." })} />
          <StatCard label={t(lang, { en: "Matches 24h", ru: "Совпадения 24ч" })} value={data?.summary?.matches_24h || 0} hint={t(lang, { en: "Event-side matches against TI indicators during the last day.", ru: "Совпадения событий с индикаторами за последние сутки." })} />
          <StatCard label={t(lang, { en: "Malicious IPs", ru: "Вредоносные IP" })} value={data?.summary?.malicious_ips || 0} hint={t(lang, { en: "Observed public IPs marked malicious or watchlisted.", ru: "Наблюдаемые публичные IP, помеченные как вредоносные или из списка наблюдения." })} />
        </div>

        <div className="react-grid react-grid-3">
          <section className="react-card">
            <PanelHeader title={t(lang, { en: "Provider mix", ru: "Структура провайдеров" })} subtitle={t(lang, { en: "Distribution of active TI content by provider.", ru: "Распределение активного контента киберразведки по провайдерам." })} />
            <BreakdownBars items={data?.providers || []} valueKey="count" labelKey="provider" />
          </section>
          <section className="react-card">
            <PanelHeader title={t(lang, { en: "Severity mix", ru: "Структура важности" })} subtitle={t(lang, { en: "Severity labels declared by threat-intel content.", ru: "Уровни важности, заявленные в контенте киберразведки." })} />
            <BreakdownBars items={data?.severity || []} />
          </section>
          <section className="react-card">
            <PanelHeader title={t(lang, { en: "Attacking countries", ru: "Страны-источники атак" })} subtitle={t(lang, { en: "Countries represented in malicious or watchlisted source IPs.", ru: "Страны, представленные во вредоносных IP или IP из списка наблюдения." })} />
            <BreakdownBars items={data?.countries || []} valueKey="events" labelKey="country" />
          </section>
        </div>

        <div className="react-split react-split-xl">
          <section className="react-card">
            <PanelHeader title={t(lang, { en: "Recent indicator matches", ru: "Свежие совпадения индикаторов" })} subtitle={t(lang, { en: "Observed TI matches in events with one-click IP drill-down.", ru: "Наблюдаемые совпадения индикаторов в событиях с быстрым переходом в детализацию IP." })} />
            <div className="react-table-wrap">
              <table className="react-table">
                <thead>
                  <tr>
                    <th>{t(lang, { en: "Indicator", ru: "Индикатор" })}</th>
                    <th>{t(lang, { en: "Type", ru: "Тип" })}</th>
                    <th>{t(lang, { en: "Provider", ru: "Провайдер" })}</th>
                    <th>{t(lang, { en: "Severity", ru: "Важность" })}</th>
                    <th>{t(lang, { en: "Events", ru: "События" })}</th>
                    <th>{t(lang, { en: "Sample IP", ru: "Пример IP" })}</th>
                    <th>{t(lang, { en: "Last seen", ru: "Последняя активность" })}</th>
                  </tr>
                </thead>
                <tbody>
                  {matches.map((row: ThreatIntelMatchRecord, index: number) => (
                    <tr key={`${row.indicator}-${index}`}>
                      <td><strong>{row.indicator}</strong></td>
                      <td>{row.indicator_type}</td>
                      <td>{row.provider || "n/a"}</td>
                      <td><SeverityBadge value={row.severity || "medium"} /></td>
                      <td>{row.events || 0}</td>
                      <td>
                        {row.sample_ip ? (
                          <button type="button" className="react-inline-action" onClick={() => setSelectedIp(String(row.sample_ip))}>
                            {row.sample_ip}
                          </button>
                        ) : "n/a"}
                      </td>
                      <td>{row.last_seen || "n/a"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <PanelHeader title={t(lang, { en: "Observed malicious sources", ru: "Наблюдаемые вредоносные источники" })} subtitle={t(lang, { en: "GeoIP and reputation view for public sources with TI or deny/watchlist context.", ru: "GeoIP и репутационный срез для публичных источников с контекстом киберразведки или списка блокировки." })} />
            <div className="react-table-wrap">
              <table className="react-table">
                <thead>
                  <tr>
                    <th>IP</th>
                    <th>{t(lang, { en: "Country", ru: "Страна" })}</th>
                    <th>{t(lang, { en: "Reputation", ru: "Репутация" })}</th>
                    <th>{t(lang, { en: "Events", ru: "События" })}</th>
                    <th>{t(lang, { en: "Auth", ru: "Аутентификация" })}</th>
                    <th>{t(lang, { en: "TI hits", ru: "Совпадения TI" })}</th>
                  </tr>
                </thead>
                <tbody>
                  {(data?.malicious_sources || []).map((row: ThreatIntelMaliciousSource, index: number) => (
                    <tr key={`${row.ip}-${index}`}>
                      <td>
                        <button type="button" className="react-inline-action" onClick={() => setSelectedIp(String(row.ip || ""))}>
                          {row.ip}
                        </button>
                      </td>
                      <td>{row.country}</td>
                      <td>{row.reputation}</td>
                      <td>{row.events || 0}</td>
                      <td>{row.auth_events || 0}</td>
                      <td>{row.ti_hits || 0}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </div>

        <DrawerOverlay
          open={Boolean(selectedIp)}
          title={detail?.ip || selectedIp || t(lang, { en: "IP detail", ru: "Детали IP" })}
          subtitle={`${detail?.geo?.country || t(lang, { en: "Unknown", ru: "Неизвестно" })} / ${detail?.geo?.org || t(lang, { en: "Unknown org", ru: "Неизвестная организация" })}`}
          onClose={() => setSelectedIp("")}
        >
          {selectedIp ? (
            <AsyncGate states={[detailState]} loadingMessage={t(lang, { en: "Loading IP context...", ru: "Загрузка контекста IP..." })}>
              {detail ? (
                <>
                  <InvestigationSummaryStrip items={detailSummary} />
                  <InvestigationActionRail
                    items={[
                      { label: t(lang, { en: "Open events", ru: "Открыть события" }), href: `/app/events?q=${encodeURIComponent(selectedIp)}` },
                      { label: t(lang, { en: "Open incidents", ru: "Открыть инциденты" }), href: `/app/incidents?q=${encodeURIComponent(selectedIp)}` },
                    ]}
                  />
                  <InvestigationTimeline
                    title={t(lang, { en: "IP investigation chain", ru: "Цепочка расследования по IP" })}
                    subtitle={t(lang, { en: "Reputation evidence, recent events and linked incidents around the selected address.", ru: "Репутационные доказательства, недавние события и связанные инциденты вокруг выбранного адреса." })}
                    icon="intel"
                    items={detailTimeline}
                    emptyMessage={t(lang, { en: "No investigation evidence available for this IP.", ru: "Для этого IP пока нет расследовательских данных." })}
                  />
                  <DrawerFieldGrid>
                    <KeyValue label={t(lang, { en: "Country", ru: "Страна" })} value={detail.geo?.country || t(lang, { en: "Unknown", ru: "Неизвестно" })} />
                    <KeyValue label={t(lang, { en: "City", ru: "Город" })} value={detail.geo?.city || "n/a"} />
                    <KeyValue label={t(lang, { en: "Organization", ru: "Организация" })} value={detail.geo?.org || "n/a"} />
                    <KeyValue label={t(lang, { en: "Reputation", ru: "Репутация" })} value={detail.reputation?.label || t(lang, { en: "unknown", ru: "неизвестно" })} />
                    <KeyValue label={t(lang, { en: "Reputation sources", ru: "Источники репутации" })} value={(detail.reputation?.sources || []).join(", ") || "n/a"} />
                    <KeyValue label={t(lang, { en: "Events 72h", ru: "События 72ч" })} value={detail.summary?.events || 0} />
                    <KeyValue label={t(lang, { en: "As source", ru: "Как источник" })} value={detail.summary?.as_source || 0} />
                    <KeyValue label={t(lang, { en: "As destination", ru: "Как назначение" })} value={detail.summary?.as_destination || 0} />
                    <KeyValue label={t(lang, { en: "Auth events", ru: "События аутентификации" })} value={detail.summary?.auth_events || 0} />
                    <KeyValue label={t(lang, { en: "TI events", ru: "TI-события" })} value={detail.summary?.ti_events || 0} />
                    <KeyValue label={t(lang, { en: "Notable events", ru: "Значимые события" })} value={detail.summary?.notable_events || 0} />
                    <KeyValue label={t(lang, { en: "Last seen", ru: "Последняя активность" })} value={detail.summary?.last_seen || "n/a"} />
                    <KeyValue label={t(lang, { en: "Sources", ru: "Источники" })} value={(detail.summary?.log_sources || []).join(", ") || "n/a"} />
                    <KeyValue label={t(lang, { en: "Categories", ru: "Категории" })} value={(detail.summary?.categories || []).join(", ") || "n/a"} />
                    <KeyValue label={t(lang, { en: "Ports", ru: "Порты" })} value={(detail.summary?.dst_ports || []).join(", ") || "n/a"} />
                  </DrawerFieldGrid>
                  <details className="react-details" open>
                    <summary>{t(lang, { en: "Threat-intel entries", ru: "Записи киберразведки" })}</summary>
                    <div className="react-table-wrap">
                      <table className="react-table">
                        <thead><tr><th>{t(lang, { en: "Provider", ru: "Провайдер" })}</th><th>{t(lang, { en: "Severity", ru: "Важность" })}</th><th>{t(lang, { en: "Confidence", ru: "Доверие" })}</th><th>{t(lang, { en: "Description", ru: "Описание" })}</th></tr></thead>
                        <tbody>
                          {(detail.threat_intel || []).map((row, index: number) => (
                            <tr key={`${row.provider}-${index}`}>
                              <td>{row.provider || "n/a"}</td>
                              <td>{row.severity || "n/a"}</td>
                              <td>{row.confidence || 0}</td>
                              <td>{row.description || "n/a"}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </details>
                  <details className="react-details">
                    <summary>{t(lang, { en: "Recent events", ru: "Недавние события" })}</summary>
                    <div className="react-table-wrap">
                      <table className="react-table">
                        <thead><tr><th>{t(lang, { en: "Time", ru: "Время" })}</th><th>{t(lang, { en: "Source", ru: "Источник" })}</th><th>{t(lang, { en: "Category", ru: "Категория" })}</th><th>{t(lang, { en: "Message", ru: "Сообщение" })}</th></tr></thead>
                        <tbody>
                          {(detail.recent_events || []).map((row, index: number) => (
                            <tr key={`${row.ts}-${index}`}>
                              <td>{row.ts}</td>
                              <td>{row.log_source}</td>
                              <td>{row.category} / {row.subcategory}</td>
                              <td>{row.message}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </details>
                  <details className="react-details">
                    <summary>{t(lang, { en: "Related incidents", ru: "Связанные инциденты" })}</summary>
                    <div className="react-table-wrap">
                      <table className="react-table">
                        <thead><tr><th>{t(lang, { en: "Rule", ru: "Правило" })}</th><th>{t(lang, { en: "Status", ru: "Статус" })}</th><th>{t(lang, { en: "Severity", ru: "Важность" })}</th><th>{t(lang, { en: "Last seen", ru: "Последняя активность" })}</th></tr></thead>
                        <tbody>
                          {(detail.incidents || []).map((row, index: number) => (
                            <tr key={`${row.agg_id}-${index}`}>
                              <td>{localizeRuleName(row.rule_name, lang)}</td>
                              <td>{row.status}</td>
                              <td>{row.severity}</td>
                              <td>{row.last_seen}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </details>
                </>
              ) : (
                <EmptyState message={t(lang, { en: "No IP context loaded.", ru: "Контекст по IP не загружен." })} />
              )}
            </AsyncGate>
          ) : (
            <EmptyState message={t(lang, { en: "Select an IP from the match or malicious-source tables to open the investigation drawer.", ru: "Выберите IP из таблиц совпадений или вредоносных источников, чтобы открыть окно расследования." })} />
          )}
        </DrawerOverlay>

        <section className="react-card">
          <PanelHeader title={t(lang, { en: "Indicator catalog", ru: "Каталог индикаторов" })} subtitle={t(lang, { en: "Loaded TI objects currently available to enrichment and correlation.", ru: "Загруженные TI-объекты, доступные для обогащения и корреляции." })} />
          <div className="react-table-wrap">
            <table className="react-table">
              <thead>
                <tr>
                  <th>{t(lang, { en: "Indicator", ru: "Индикатор" })}</th>
                  <th>{t(lang, { en: "Type", ru: "Тип" })}</th>
                  <th>{t(lang, { en: "Provider", ru: "Провайдер" })}</th>
                  <th>{t(lang, { en: "Severity", ru: "Важность" })}</th>
                  <th>{t(lang, { en: "Confidence", ru: "Доверие" })}</th>
                  <th>{t(lang, { en: "Updated", ru: "Обновлено" })}</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((row: ThreatIntelCatalogEntry, index: number) => (
                  <tr key={`${row.indicator}-${index}`}>
                    <td>{row.indicator}</td>
                    <td>{row.indicator_type}</td>
                    <td>{row.provider || "n/a"}</td>
                    <td><SeverityBadge value={row.severity || "medium"} /></td>
                    <td>{row.confidence || 0}</td>
                    <td>{row.updated_ts || "n/a"}</td>
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
