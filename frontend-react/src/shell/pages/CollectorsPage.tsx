import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { AsyncGate } from "../async";
import { t, useShellContext } from "../context";
import { useAsyncData, useDebouncedValue } from "../hooks";
import {
  DrawerFieldGrid,
  DrawerOverlay,
  EmptyState,
  Icon,
  KeyValue,
  PanelHeader,
  SectionIntro,
  StatCard,
  StatusBadge,
} from "../ui";
import type { CollectorInventoryRecord, CollectorsInventoryResponse, IntegrationTemplateRecord, IntegrationsCatalogResponse } from "../types";

type CollectorView = "pipelines" | "protocols" | "coverage";

function textList(values: unknown, fallback = "н/д") {
  return Array.isArray(values) && values.length ? values.join(", ") : fallback;
}

function localizeCollectorName(collector: CollectorInventoryRecord, lang: "en" | "ru") {
  const normalized = String(collector.collector_id || collector.name || "").trim().toLowerCase();
  const known: Record<string, { en: string; ru: string }> = {
    "linux-syslog-audit": { en: "Linux Syslog / Audit Collector", ru: "Коллектор Linux Syslog / Audit" },
    "app-json-syslog": { en: "Application JSON / Syslog Collector", ru: "Коллектор приложений JSON / Syslog" },
    "vulnerability-import": { en: "Vulnerability Import Collector", ru: "Коллектор импорта уязвимостей" },
    "storage-correlation": { en: "Storage / Correlation Core", ru: "Ядро хранения и корреляции" },
    "network-syslog": { en: "Network Syslog Collector", ru: "Сетевой Syslog-коллектор" },
    "windows-event-http": { en: "Windows Event Collector", ru: "Коллектор событий Windows" },
  };
  return known[normalized] ? t(lang, known[normalized]) : String(collector.name || collector.collector_id || "");
}

function localizeCollectorDescription(collector: CollectorInventoryRecord, lang: "en" | "ru") {
  const normalized = String(collector.collector_id || "").trim().toLowerCase();
  const known: Record<string, { en: string; ru: string }> = {
    "linux-syslog-audit": {
      en: "Edge ingest and normalization path for Linux syslog, auditd, sshd, sudo, and VPN-side auth telemetry.",
      ru: "Контур приёма и нормализации Linux syslog, auditd, sshd, sudo и VPN-телеметрии аутентификации.",
    },
    "app-json-syslog": {
      en: "Webhook and structured application log path for custom apps and API-driven sources.",
      ru: "Путь webhook и структурированных логов приложений для кастомных сервисов и API-источников.",
    },
    "vulnerability-import": {
      en: "Import path for OpenVAS / Greenbone / scanner findings into structured vulnerability tables and incident context.",
      ru: "Контур импорта находок OpenVAS / Greenbone в структурированные таблицы уязвимостей и контекст инцидентов.",
    },
    "storage-correlation": {
      en: "Core storage, stream correlation, batch correlation, alert aggregation, and retention execution plane.",
      ru: "Контур хранения, потоковой и пакетной корреляции, агрегации алертов и исполнения политик удержания.",
    },
    "network-syslog": {
      en: "Network-device syslog path with CLI-assisted forwarding automation for supported SSH-managed devices.",
      ru: "Контур сетевого syslog с автоматизацией включения пересылки для поддерживаемых SSH-управляемых устройств.",
    },
    "windows-event-http": {
      en: "Native Windows service or staged bootstrap package for Security, Sysmon, PowerShell, and core OS channels over HTTPS.",
      ru: "Нативный Windows-агент или staged bootstrap package для Security, Sysmon, PowerShell и базовых каналов ОС по HTTPS.",
    },
  };
  return known[normalized] ? t(lang, known[normalized]) : String(collector.description || collector.role || "");
}

export function CollectorsPage() {
  const { lang } = useShellContext();
  const loadCollectors = useCallback(() => api.collectorsInventory(), []);
  const loadIntegrations = useCallback(() => api.integrationsCatalog(), []);
  const state = useAsyncData<CollectorsInventoryResponse>(loadCollectors);
  const integrationsState = useAsyncData<IntegrationsCatalogResponse>(loadIntegrations);
  const [searchParams] = useSearchParams();
  const [query, setQuery] = useState("");
  const [selectedCollector, setSelectedCollector] = useState<CollectorInventoryRecord | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [view, setView] = useState<CollectorView>("pipelines");
  const debouncedQuery = useDebouncedValue(query, 250);

  const items = useMemo(() => {
    const rows = state.data?.items || [];
    const token = String(debouncedQuery || "").trim().toLowerCase();
    if (!token) return rows;
    return rows.filter((item: CollectorInventoryRecord) => JSON.stringify(item).toLowerCase().includes(token));
  }, [state.data, debouncedQuery]);

  const sourceIntegrations = useMemo(
    () => (integrationsState.data?.items || []).filter((item: IntegrationTemplateRecord) => item.family === "source"),
    [integrationsState.data],
  );

  const protocolLens = useMemo(() => {
    const counts = new Map<string, number>();
    for (const item of items) {
      for (const protocol of item.protocols || []) {
        counts.set(protocol, (counts.get(protocol) || 0) + 1);
      }
    }
    return Array.from(counts.entries())
      .map(([label, count]) => ({ label, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }, [items]);

  const sourceClassLens = useMemo(() => {
    const counts = new Map<string, number>();
    for (const item of items) {
      for (const sourceClass of item.source_classes || []) {
        counts.set(sourceClass, (counts.get(sourceClass) || 0) + 1);
      }
    }
    return Array.from(counts.entries())
      .map(([label, count]) => ({ label, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }, [items]);

  const transportAdapters = useMemo(() => {
    const counts = new Map<string, number>();
    for (const item of sourceIntegrations) {
      for (const protocol of item.protocols || []) {
        counts.set(protocol, (counts.get(protocol) || 0) + 1);
      }
    }
    return Array.from(counts.entries())
      .map(([label, count]) => ({ label, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }, [sourceIntegrations]);
  const vulnerabilityAdapters = useMemo(
    () => sourceIntegrations.filter((item: IntegrationTemplateRecord) => String(item.group || "").toLowerCase() === "vulnerability"),
    [sourceIntegrations],
  );
  const collectorIssues = [
    state.error,
    integrationsState.error ? `Integrations: ${integrationsState.error}` : "",
  ].filter(Boolean);
  const fallbackCollectorCount = items.filter((item: CollectorInventoryRecord) => item.inventory_source === "ingest-health-fallback").length;
  const collectorAdapterSurfaces = useMemo(
    () =>
      items.map((item: CollectorInventoryRecord) => {
        const itemProtocols = new Set((item.protocols || []).map((protocol: string) => String(protocol).toLowerCase()));
        const adapters = sourceIntegrations.filter((integration: IntegrationTemplateRecord) =>
          (integration.protocols || []).some((protocol: string) => itemProtocols.has(String(protocol).toLowerCase())),
        );
        return {
          collector_id: item.collector_id,
          adapters,
        };
      }),
    [items, sourceIntegrations],
  );
  const coverageHotspots = useMemo(
    () =>
      items
        .slice()
        .sort((left: CollectorInventoryRecord, right: CollectorInventoryRecord) => Number(right.sources_count || 0) - Number(left.sources_count || 0))
        .slice(0, 8),
    [items],
  );
  const adapterLens = useMemo(
    () =>
      collectorAdapterSurfaces
        .map((item) => ({
          collector_id: item.collector_id,
          adapters: item.adapters.map((adapter: IntegrationTemplateRecord) => adapter.title),
          count: item.adapters.length,
        }))
        .sort((left, right) => right.count - left.count),
    [collectorAdapterSurfaces],
  );

  useEffect(() => {
    const nextQuery = String(searchParams.get("q") || "").trim();
    const nextView = String(searchParams.get("view") || "").trim().toLowerCase();
    const focus = String(searchParams.get("focus") || "").trim();
    if (searchParams.has("q")) {
      setQuery(nextQuery);
    }
    if (nextView === "pipelines" || nextView === "protocols" || nextView === "coverage") {
      setView(nextView as CollectorView);
    }
    if (focus) {
      setSelectedCollector((current: CollectorInventoryRecord | null) => {
        if (current?.collector_id === focus || current?.name === focus) return current;
        const row = (state.data?.items || []).find(
          (item: CollectorInventoryRecord) => String(item.collector_id || "") === focus || String(item.name || "") === focus,
        );
        return row || current;
      });
    }
  }, [searchParams, state.data]);

  useEffect(() => {
    const selectedStillVisible = selectedCollector
      ? items.some(
          (item: CollectorInventoryRecord) =>
            String(item.collector_id || "") === String(selectedCollector.collector_id || "") ||
            String(item.name || "") === String(selectedCollector.name || ""),
        )
      : false;
    if (selectedCollector && !selectedStillVisible) {
      setSelectedCollector(debouncedQuery && items.length ? items[0] : null);
      return;
    }
    if (!selectedCollector && items.length && debouncedQuery) {
      setSelectedCollector(items[0]);
    }
  }, [debouncedQuery, items, selectedCollector]);

  const kpiCards = [
    {
      label: t(lang, { en: "Collectors", ru: "Коллекторы" }),
      value: items.length,
      hint: t(lang, {
        en: "Defined transport and processing pipelines.",
        ru: "Определенные транспортные и процессинговые пайплайны.",
      }),
    },
    {
      label: t(lang, { en: "Healthy", ru: "Здоровые" }),
      value: items.filter((item: CollectorInventoryRecord) => item.status === "active").length,
      hint: t(lang, {
        en: "Collectors with healthy source coverage.",
        ru: "Коллекторы с нормальным покрытием источников.",
      }),
    },
    {
      label: t(lang, { en: "Sources", ru: "Источники" }),
      value: items.reduce((sum: number, item: CollectorInventoryRecord) => sum + Number(item.sources_count || 0), 0),
      hint: t(lang, {
        en: "Total covered sources across the collector plane.",
        ru: "Общее число источников, покрытых коллекторным слоем.",
      }),
    },
    {
      label: t(lang, { en: "Protocols", ru: "Протоколы" }),
      value: protocolLens.length,
      hint: t(lang, {
        en: "Distinct transport surfaces used by collectors.",
        ru: "Уникальные транспортные поверхности, используемые коллекторами.",
      }),
    },
    {
      label: t(lang, { en: "Adapters", ru: "Адаптеры" }),
      value: transportAdapters.length,
      hint: t(lang, {
        en: "Webhook, database and API transport adapters available to the collector layer.",
        ru: "Webhook, БД и API-адаптеры, доступные на уровне коллекторов.",
      }),
    },
  ];

  return (
    <AsyncGate states={[state]} loadingMessage={t(lang, { en: "Loading collectors...", ru: "Загрузка коллекторов..." })}>
    <div className="react-page">
      <SectionIntro
        kicker={t(lang, { en: "Collectors", ru: "Коллекторы" })}
        title={t(lang, { en: "Collector pipelines", ru: "Пайплайны коллекторов" })}
        icon="collectors"
        actions={
          <div className="react-actions react-wrap">
            <input
              className="react-input react-input-grow"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder={t(lang, {
                en: "Search collector, protocol, role...",
                ru: "Поиск по коллектору, протоколу или роли...",
              })}
            />
            <button
              type="button"
              className="react-icon-button"
              onClick={() => setSettingsOpen(true)}
              aria-label={t(lang, { en: "Collector page settings", ru: "Настройки страницы коллекторов" })}
            >
              <Icon name="control" size={15} />
            </button>
          </div>
        }
      />

      {fallbackCollectorCount ? (
        <div className="react-inline-note react-inline-note-spaced">
          Collector inventory is using ingest runtime fallback for {fallbackCollectorCount} collectors while ClickHouse inventory is degraded or empty.
        </div>
      ) : null}
      {collectorIssues.length ? (
        <div className="react-inline-note react-inline-note-spaced">
          Partial collector workspace: {collectorIssues.join(" / ")}
        </div>
      ) : null}

      <div className="react-grid react-grid-5">
        {kpiCards.map((card) => (
          <StatCard key={card.label} label={card.label} value={card.value} hint={card.hint} />
        ))}
      </div>

      <div className="react-segmented">
        <button type="button" className={view === "pipelines" ? "active" : ""} onClick={() => setView("pipelines")}>
          {t(lang, { en: "Pipelines", ru: "Пайплайны" })}
        </button>
        <button type="button" className={view === "protocols" ? "active" : ""} onClick={() => setView("protocols")}>
          {t(lang, { en: "Protocols", ru: "Протоколы" })}
        </button>
        <button type="button" className={view === "coverage" ? "active" : ""} onClick={() => setView("coverage")}>
          {t(lang, { en: "Coverage", ru: "Покрытие" })}
        </button>
      </div>

      {view === "pipelines" ? (
        <div className="react-split react-split-xl">
          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Collector matrix", ru: "Матрица коллекторов" })}
              subtitle={t(lang, {
                en: "Transport pipelines with operational role, protocols and source coverage.",
                ru: "Транспортные пайплайны с операционной ролью, протоколами и покрытием источников.",
              })}
            />
            <div className="react-grid react-grid-2">
              {items.map((item: CollectorInventoryRecord) => (
                <button
                  type="button"
                  key={item.collector_id}
                  className={`react-card react-card-button ${selectedCollector?.collector_id === item.collector_id ? "active" : ""}`}
                  onClick={() => setSelectedCollector(item)}
                >
                  <div className="react-card-button-header">
                    <div>
                      <div className="react-top-kicker">{item.collector_id}</div>
                      <h3>{localizeCollectorName(item, lang)}</h3>
                    </div>
                    <StatusBadge value={item.status || "ready"} />
                  </div>
                  <div className="react-card-button-copy">
                    {localizeCollectorDescription(item, lang) || t(lang, { en: "Collector pipeline", ru: "Пайплайн коллектора" })}
                  </div>
                  <div className="react-card-button-grid">
                    <span>{t(lang, { en: "Node", ru: "Узел" })}</span>
                    <strong>{item.node || t(lang, { en: "n/a", ru: "н/д" })}</strong>
                    <span>{t(lang, { en: "Sources", ru: "Источники" })}</span>
                    <strong>{item.sources_count || 0}</strong>
                    <span>{t(lang, { en: "Events 24h", ru: "События за 24ч" })}</span>
                    <strong>{item.events || 0}</strong>
                    <span>{t(lang, { en: "Last seen", ru: "Последняя активность" })}</span>
                    <strong>{item.last_seen || t(lang, { en: "n/a", ru: "н/д" })}</strong>
                  </div>
                </button>
              ))}
            </div>
          </section>

          <aside className="react-card react-drawer">
            {selectedCollector ? (
              <>
                <PanelHeader title={localizeCollectorName(selectedCollector, lang)} subtitle={selectedCollector.collector_id} />
                <div className="react-actions react-wrap">
                  <Link className="react-link-button" to={`/events?q=${encodeURIComponent(`collector_profile = '${selectedCollector.collector_id}'`)}`}>
                    {t(lang, { en: "Collector events", ru: "События коллектора" })}
                  </Link>
                  <Link className="react-link-button" to="/sources">{t(lang, { en: "Covered sources", ru: "Покрытые источники" })}</Link>
                  <Link className="react-link-button" to="/builders">{t(lang, { en: "Builder paths", ru: "Маршруты конструкторов" })}</Link>
                  <Link className="react-link-button" to="/builders?kind=integration">{t(lang, { en: "Integration builder", ru: "Конструктор интеграций" })}</Link>
                </div>
                <section className="react-card react-card-nested">
                  <PanelHeader
                    title={t(lang, { en: "Transport role", ru: "Транспортная роль" })}
                    subtitle={t(lang, { en: "Operational transport context and pipeline health.", ru: "Операционный транспортный контекст и состояние пайплайна." })}
                  />
                  <DrawerFieldGrid>
                    <KeyValue label={t(lang, { en: "Status", ru: "Статус" })} value={<StatusBadge value={selectedCollector.status || "ready"} />} />
                    <KeyValue label={t(lang, { en: "Node", ru: "Узел" })} value={selectedCollector.node || t(lang, { en: "n/a", ru: "н/д" })} />
                    <KeyValue label={t(lang, { en: "Role", ru: "Роль" })} value={selectedCollector.role || t(lang, { en: "n/a", ru: "н/д" })} />
                    <KeyValue label={t(lang, { en: "Sources count", ru: "Количество источников" })} value={selectedCollector.sources_count || 0} />
                    <KeyValue label={t(lang, { en: "Events 24h", ru: "События за 24ч" })} value={selectedCollector.events || 0} />
                    <KeyValue label={t(lang, { en: "Last seen", ru: "Последняя активность" })} value={selectedCollector.last_seen || t(lang, { en: "n/a", ru: "н/д" })} />
                  </DrawerFieldGrid>
                </section>
                <section className="react-card react-card-nested">
                  <PanelHeader
                    title={t(lang, { en: "Protocols and coverage", ru: "Протоколы и покрытие" })}
                    subtitle={t(lang, { en: "Transport surfaces and current source coverage for this collector.", ru: "Транспортные поверхности и текущее покрытие источников для этого коллектора." })}
                  />
                  <DrawerFieldGrid>
                    <KeyValue label={t(lang, { en: "Source classes", ru: "Классы источников" })} value={textList(selectedCollector.source_classes, t(lang, { en: "n/a", ru: "н/д" }))} />
                    <KeyValue label={t(lang, { en: "Protocols", ru: "Протоколы" })} value={textList(selectedCollector.protocols, t(lang, { en: "n/a", ru: "н/д" }))} />
                    <KeyValue label={t(lang, { en: "Covered sources", ru: "Покрытые источники" })} value={textList(selectedCollector.covered_sources, t(lang, { en: "n/a", ru: "н/д" }))} />
                    <KeyValue label={t(lang, { en: "Description", ru: "Описание" })} value={localizeCollectorDescription(selectedCollector, lang) || t(lang, { en: "n/a", ru: "н/д" })} />
                    <KeyValue
                      label={t(lang, { en: "Adapter surfaces", ru: "Поверхности адаптеров" })}
                      value={
                          collectorAdapterSurfaces
                          .find((item) => item.collector_id === selectedCollector.collector_id)
                          ?.adapters.map((item: IntegrationTemplateRecord) => item.title)
                          .slice(0, 4)
                          .join(", ") || t(lang, { en: "n/a", ru: "н/д" })
                      }
                    />
                    <KeyValue
                      label={t(lang, { en: "Vuln import path", ru: "Контур импорта уязвимостей" })}
                      value={
                        (collectorAdapterSurfaces.find((item) => item.collector_id === selectedCollector.collector_id)?.adapters || [])
                          .filter((item: IntegrationTemplateRecord) => String(item.group || "").toLowerCase() === "vulnerability")
                          .map((item: IntegrationTemplateRecord) => item.title)
                          .join(", ") || t(lang, { en: "n/a", ru: "н/д" })
                      }
                    />
                  </DrawerFieldGrid>
                </section>
                <section className="react-card react-card-nested">
                  <PanelHeader
                    title={t(lang, { en: "Integration surfaces", ru: "Поверхности интеграций" })}
                    subtitle={t(lang, { en: "Adapters and transport templates that can land on this collector.", ru: "Адаптеры и транспортные шаблоны, которые могут работать через этот коллектор." })}
                  />
                  <div className="react-chip-grid">
                    {(collectorAdapterSurfaces.find((item) => item.collector_id === selectedCollector.collector_id)?.adapters || []).map((item: IntegrationTemplateRecord) => (
                      <div key={item.id} className="react-chip-card">
                        <div className="react-top-kicker">{item.group || t(lang, { en: "general", ru: "общее" })}</div>
                        <strong>{item.title}</strong>
                        <span>{item.mode} / {textList(item.protocols)}</span>
                        <Link className="react-link-button" to={`/builders?kind=integration&template=${encodeURIComponent(String(item.id || ""))}`}>
                          {t(lang, { en: "Open builder", ru: "Открыть конструктор" })}
                        </Link>
                      </div>
                    ))}
                  </div>
                </section>
              </>
            ) : (
              <EmptyState message={t(lang, { en: "Select a collector to inspect transport role, protocols and covered sources.", ru: "Выберите коллектор, чтобы посмотреть транспортную роль, протоколы и покрытые источники." })} />
            )}
          </aside>
        </div>
      ) : null}

      {view === "protocols" ? (
        <div className="react-grid react-grid-2">
          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Protocol surfaces", ru: "Протокольные поверхности" })}
              subtitle={t(lang, { en: "Listening and transport interfaces exposed by collector pipelines.", ru: "Прослушиваемые и транспортные интерфейсы, которые раскрывают пайплайны коллекторов." })}
            />
            <div className="react-chip-grid">
              {protocolLens.map((row) => (
                <div key={row.label} className="react-chip-card">
                  <div className="react-top-kicker">{t(lang, { en: "Protocol", ru: "Протокол" })}</div>
                  <strong>{row.label}</strong>
                  <span>{t(lang, { en: `${row.count} collectors`, ru: `${row.count} коллекторов` })}</span>
                </div>
              ))}
            </div>
          </section>
          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Integration-ready adapters", ru: "Адаптеры, готовые к интеграции" })}
              subtitle={t(lang, { en: "Transport adapters available to webhook, database and API-driven sources.", ru: "Транспортные адаптеры, доступные для webhook-, database- и API-источников." })}
            />
            <div className="react-chip-grid">
              {transportAdapters.map((row) => (
                <div key={row.label} className="react-chip-card">
                  <div className="react-top-kicker">{t(lang, { en: "Adapter", ru: "Адаптер" })}</div>
                  <strong>{row.label}</strong>
                  <span>{t(lang, { en: `${row.count} source templates`, ru: `${row.count} шаблонов источников` })}</span>
                  <Link className="react-link-button" to="/builders?kind=integration">
                    {t(lang, { en: "Open builder", ru: "Открыть конструктор" })}
                  </Link>
                </div>
              ))}
            </div>
          </section>
          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Collector adapter lens", ru: "Срез адаптеров по коллекторам" })}
              subtitle={t(lang, { en: "Which collectors expose the broadest integration surface.", ru: "Какие коллекторы раскрывают самую широкую интеграционную поверхность." })}
            />
            <div className="react-table-wrap">
              <table className="react-table">
                <thead>
                  <tr>
                    <th>{t(lang, { en: "Collector", ru: "Коллектор" })}</th>
                    <th>{t(lang, { en: "Adapter count", ru: "Число адаптеров" })}</th>
                    <th>{t(lang, { en: "Adapters", ru: "Адаптеры" })}</th>
                  </tr>
                </thead>
                <tbody>
                  {adapterLens.map((row) => (
                    <tr key={row.collector_id}>
                      <td>{row.collector_id}</td>
                      <td>{row.count}</td>
                      <td>{row.adapters.join(", ") || t(lang, { en: "n/a", ru: "н/д" })}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Vulnerability import path", ru: "Контур импорта уязвимостей" })}
              subtitle={t(lang, { en: "Transport adapters that can receive or poll vulnerability findings from the future external manager.", ru: "Транспортные адаптеры, которые уже подходят для приема или опроса внешних находок по уязвимостям." })}
            />
            <div className="react-chip-grid">
              {vulnerabilityAdapters.map((item: IntegrationTemplateRecord) => (
                <div key={item.id} className="react-chip-card">
                  <div className="react-top-kicker">{item.group || t(lang, { en: "vulnerability", ru: "уязвимости" })}</div>
                  <strong>{item.title}</strong>
                  <span>{item.mode} / {textList(item.protocols)}</span>
                  <Link className="react-link-button" to={`/builders?kind=integration&template=${encodeURIComponent(String(item.id || ""))}`}>
                    {t(lang, { en: "Open builder", ru: "Открыть конструктор" })}
                  </Link>
                </div>
              ))}
            </div>
          </section>
        </div>
      ) : null}

      {view === "coverage" ? (
        <div className="react-grid react-grid-2">
          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Coverage by source class", ru: "Покрытие по классам источников" })}
              subtitle={t(lang, { en: "Which telemetry families each collector tier is responsible for.", ru: "Какие семейства телеметрии покрывает каждый уровень коллекторов." })}
            />
            <div className="react-chip-grid">
              {sourceClassLens.map((row) => (
                <div key={row.label} className="react-chip-card">
                  <div className="react-top-kicker">{t(lang, { en: "Source class", ru: "Класс источника" })}</div>
                  <strong>{row.label}</strong>
                  <span>{t(lang, { en: `${row.count} collectors`, ru: `${row.count} коллекторов` })}</span>
                </div>
              ))}
            </div>
          </section>
          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Transport model", ru: "Транспортная модель" })}
              subtitle={t(lang, { en: "Collectors own transport, schedules and parser surfaces, not business identity.", ru: "Коллекторы отвечают за транспорт, расписания и parser-поверхности, а не за бизнес-идентичность." })}
            />
            <div className="react-info-list">
              <div className="react-info-row">
                <span>{t(lang, { en: "Primary lens", ru: "Главный фокус" })}</span>
                <strong>{t(lang, { en: "Transport / ingest", ru: "Транспорт / приём" })}</strong>
              </div>
              <div className="react-info-row">
                <span>{t(lang, { en: "Best use", ru: "Лучшее применение" })}</span>
                <strong>{t(lang, { en: "Ports, protocols, lag, parser errors, source coverage", ru: "Порты, протоколы, лаг, ошибки парсеров и покрытие источников" })}</strong>
              </div>
              <div className="react-info-row">
                <span>{t(lang, { en: "Integration role", ru: "Роль интеграций" })}</span>
                <strong>{t(lang, { en: "Webhook listeners, SQL/NoSQL polling, REST pulls, outbound automation", ru: "Webhook-слушатели, SQL/NoSQL-опрос, REST-pull и исходящая автоматизация" })}</strong>
              </div>
            </div>
          </section>
          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Coverage hotspots", ru: "Горячие точки покрытия" })}
              subtitle={t(lang, { en: "Collectors with the broadest source estate or busiest transport surface.", ru: "Коллекторы с самым широким покрытием источников или самой занятой транспортной поверхностью." })}
            />
            <div className="react-list react-list-compact">
              {coverageHotspots.map((item: CollectorInventoryRecord) => (
                  <button key={item.collector_id} type="button" className="react-list-item" onClick={() => { setSelectedCollector(item); setView("pipelines"); }}>
                    <strong>{localizeCollectorName(item, lang)}</strong>
                    <span>{textList(item.protocols)} / {textList(item.source_classes)}</span>
                    <span>{t(lang, { en: `${item.sources_count || 0} sources / ${item.events || 0} events`, ru: `${item.sources_count || 0} источников / ${item.events || 0} событий` })}</span>
                  </button>
                ))}
            </div>
          </section>
          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Adapter hotspots", ru: "Горячие точки адаптеров" })}
              subtitle={t(lang, { en: "Collectors that can host the broadest integration and vulnerability import surface.", ru: "Коллекторы, которые поддерживают самую широкую интеграционную поверхность и импорт уязвимостей." })}
            />
            <div className="react-table-wrap">
              <table className="react-table">
                <thead>
                  <tr>
                    <th>{t(lang, { en: "Collector", ru: "Коллектор" })}</th>
                    <th>{t(lang, { en: "Adapters", ru: "Адаптеры" })}</th>
                    <th>{t(lang, { en: "Surface", ru: "Поверхность" })}</th>
                  </tr>
                </thead>
                <tbody>
                  {adapterLens.slice(0, 8).map((row) => (
                    <tr key={row.collector_id}>
                      <td>{row.collector_id}</td>
                      <td>{row.count}</td>
                      <td>{row.adapters.slice(0, 3).join(", ") || t(lang, { en: "n/a", ru: "н/д" })}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      ) : null}

      <DrawerOverlay
        open={settingsOpen}
        title={t(lang, { en: "Collector page settings", ru: "Настройки страницы коллекторов" })}
        subtitle={t(lang, { en: "Transport-plane controls, health pivots and integration surfaces.", ru: "Управление транспортным слоем, pivots по состоянию и поверхности интеграций." })}
        onClose={() => setSettingsOpen(false)}
      >
        <section className="react-card react-card-nested">
          <PanelHeader title={t(lang, { en: "Transport pivots", ru: "Транспортные переходы" })} subtitle={t(lang, { en: "Move from collector health into operational workspaces.", ru: "Быстрые переходы от состояния коллекторов в рабочие разделы." })} icon="collectors" />
          <div className="react-actions react-wrap">
            <Link className="react-link-button" to="/events" onClick={() => setSettingsOpen(false)}>
              {t(lang, { en: "Open event console", ru: "Открыть консоль событий" })}
            </Link>
            <Link className="react-link-button" to="/sources" onClick={() => setSettingsOpen(false)}>
              {t(lang, { en: "Source freshness", ru: "Свежесть источников" })}
            </Link>
            <Link className="react-link-button" to="/builders" onClick={() => setSettingsOpen(false)}>
              {t(lang, { en: "Builder workspace", ru: "Рабочая зона конструкторов" })}
            </Link>
          </div>
        </section>
        <section className="react-card react-card-nested">
          <PanelHeader title={t(lang, { en: "Integration surfaces", ru: "Поверхности интеграций" })} subtitle={t(lang, { en: "Source families that rely on collector transport and scheduling.", ru: "Семейства источников, которые опираются на транспорт и расписания коллекторов." })} icon="sources" />
          <div className="react-chip-grid">
            {sourceIntegrations.map((item: IntegrationTemplateRecord) => (
              <div key={item.id} className="react-chip-card">
                <div className="react-top-kicker">{item.group || t(lang, { en: "general", ru: "общее" })}</div>
                <strong>{item.title}</strong>
                <span>{item.description}</span>
                <span>{item.mode} / {textList(item.protocols)}</span>
              </div>
            ))}
          </div>
        </section>
        <section className="react-card react-card-nested">
          <PanelHeader title={t(lang, { en: "Vulnerability import surfaces", ru: "Поверхности импорта уязвимостей" })} subtitle={t(lang, { en: "Collectors and adapters that are already suitable for external vulnerability findings.", ru: "Коллекторы и адаптеры, которые уже подходят для приема внешних находок по уязвимостям." })} icon="vuln" />
          <div className="react-chip-grid">
            {vulnerabilityAdapters.map((item: IntegrationTemplateRecord) => (
              <div key={item.id} className="react-chip-card">
                <div className="react-top-kicker">{item.mode || t(lang, { en: "pull", ru: "опрос" })}</div>
                <strong>{item.title}</strong>
                <span>{textList(item.protocols)}</span>
              </div>
            ))}
          </div>
        </section>
      </DrawerOverlay>
    </div>
    </AsyncGate>
  );
}
