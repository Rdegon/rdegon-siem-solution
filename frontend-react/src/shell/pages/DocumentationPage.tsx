import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { api } from "../api";
import { useAsyncData, useDebouncedValue } from "../hooks";
import { AsyncGate } from "../async";
import { t, useShellContext } from "../context";
import { Breadcrumbs, EmptyState, PageTabs, PanelHeader, SectionIntro } from "../ui";
import type { DocSectionRecord, DocumentDetailResponse, DocsIndexResponse, PlaybookDetailResponse, PlaybookSummary, TocItem } from "../types";

function humanizeDocStem(name: string) {
  return String(name || "")
    .replace(/\.md$/i, "")
    .replace(/^[0-9]+[_-]?/, "")
    .replace(/[_-]+/g, " ")
    .trim();
}

function russianizeDocTitle(cleaned: string) {
  const normalized = cleaned.trim().toLowerCase();
  const known: Record<string, string> = {
    "access matrix": "Матрица доступа",
    "remote access": "Удаленный доступ",
    "nextcloud usage": "Работа с Nextcloud",
    "windows vpn operations": "VPN-операции для Windows",
    "credentials registry": "Реестр учетных данных",
    "vm access": "Доступ к виртуальным машинам",
    "correlation rules": "Правила корреляции",
    architecture: "Архитектура",
    configuration: "Конфигурация",
    endpoints: "Точки API",
    "source discovery": "Обнаружение источников",
    "vulnerability reports": "Отчеты по уязвимостям",
    "app section guide and usability 2026 03 28": "Разделы системы и оценка удобства",
    readme: "Сводка документации",
    "agent handover 2026 03 12": "Передача смены агента 2026 03 12",
    "audit 2026 03 12": "Аудит 2026 03 12",
    collectors: "Коллекторы",
    debugging: "Отладка",
    "enterprise foundation": "Основа платформы",
    "host runtime observability 2026 03 22": "Наблюдаемость runtime узлов 2026 03 22",
    "redis ha resilience 2026 03 22": "Отказоустойчивость Redis HA 2026 03 22",
    "scaling and decomposition plan 2026 03 22": "План масштабирования и декомпозиции 2026 03 22",
    "storage control plane ha prep 2026 03 22": "Подготовка отказоустойчивого control plane хранилища 2026 03 22",
    "soar response hardening 2026 03 26": "Усиление контура реагирования 2026 03 26",
    "sso operations and external integrations 2026 03 26": "Операции SSO и внешние интеграции 2026 03 26",
    "diploma readme": "Сводка дипломной документации",
    "diploma rdegon siem diploma documentation 2026 03 28": "Дипломная документация 2026 03 28",
    "builder drafts.json": "Черновики конструкторов",
    "dashboards.json": "Каталог дашбордов",
    "dns cache.json": "DNS-кэш",
    "geoip cache.json": "GeoIP-кэш",
    "soc scenarios": "SOC-сценарии",
    "windows onboarding": "Онбординг Windows",
    "public host security": "Защита публичного хоста",
    "platform status": "Статус платформы",
    ingest: "Прием данных",
    redis: "Redis",
    "siem vuln integration 2026 03 23": "Интеграция SIEM с контуром уязвимостей 2026 03 23",
    "windows ingest": "Прием событий Windows",
    "backend security followup 2026 03 21": "Follow-up по безопасности backend 2026 03 21",
    "frontend remediation 2026 03 19": "Исправления фронтенда 2026 03 19",
  };
  if (known[normalized]) return known[normalized];
  const replacements: Array<[RegExp, string]> = [
    [/\bdeployment runbook\b/gi, "регламент развертывания"],
    [/\brelease wave\b/gi, "волна релиза"],
    [/\blive rollout verification\b/gi, "проверка живого развертывания"],
    [/\bperformance certification\b/gi, "сертификация производительности"],
    [/\bperformance eps assessment\b/gi, "оценка производительности EPS"],
    [/\bproject closure execution plan\b/gi, "план закрытия проекта"],
    [/\bplatform finalization and app redesign\b/gi, "финализация платформы и переработка приложения"],
    [/\bpilot sso correlation wave\b/gi, "волна SSO pilot-сервисов и корреляции"],
    [/\bproxmox fleet openclaw wave\b/gi, "волна Proxmox fleet и OpenClaw"],
    [/\bwindowed access builders wave\b/gi, "оконная модель доступа и конструкторов"],
    [/\bui ux system audit\b/gi, "системный аудит UI/UX"],
    [/\bui ux followup closure\b/gi, "закрытие follow-up по UI/UX"],
    [/\bui access memory closure\b/gi, "закрытие UI, доступа и памяти"],
    [/\bdistribution toolkit\b/gi, "инструментарий дистрибуции"],
    [/\boperator cli bundle\b/gi, "операторский CLI-бандл"],
    [/\bparallel batch correlation design\b/gi, "пакетная корреляция и дизайн правил"],
    [/\bproduction certification and governance closure\b/gi, "закрытие сертификации и управления"],
    [/\bproduction green remediation\b/gi, "зеленое восстановление production"],
    [/\bvulnerability manager integration\b/gi, "интеграция менеджера уязвимостей"],
    [/\bvulnerability maturity\b/gi, "зрелость управления уязвимостями"],
    [/\bwindows collection strategy\b/gi, "стратегия сбора Windows"],
    [/\bwindows ingest\b/gi, "прием событий Windows"],
    [/\bpower recovery\b/gi, "восстановление после отключения питания"],
    [/\bproduct priorities\b/gi, "приоритеты продукта"],
    [/\bstorage ha\b/gi, "отказоустойчивое хранилище"],
    [/\bstorage memory review\b/gi, "обзор памяти хранилища"],
    [/\btransport content runtime\b/gi, "runtime транспорта и контента"],
    [/\bbackend runtime wave\b/gi, "волна backend runtime"],
    [/\bfrontend remediation\b/gi, "исправления фронтенда"],
    [/\bbackend security followup\b/gi, "follow-up по безопасности backend"],
    [/\bcicd\b/gi, "CI/CD"],
    [/\beps\b/gi, "EPS"],
    [/\bsso\b/gi, "SSO"],
    [/\bux\b/gi, "UX"],
    [/\bui\b/gi, "UI"],
    [/\bapi\b/gi, "API"],
    [/\bcli\b/gi, "CLI"],
    [/\bhomelab runners\b/gi, "исполнители homelab"],
    [/\bkafka vm5 wave\b/gi, "волна Kafka на VM5"],
    [/\bvm1 ingest fabric\b/gi, "контур приема VM1"],
    [/\bvm2 processing resilience\b/gi, "устойчивость обработки VM2"],
    [/\bvm2 recovery\b/gi, "восстановление VM2"],
    [/\bvm3 proxmox memory alignment\b/gi, "согласование памяти Proxmox на VM3"],
    [/\bvm3 storage memory tuning\b/gi, "настройка памяти хранилища на VM3"],
    [/\bvm3 stream corr event time\b/gi, "время событий stream-корреляции на VM3"],
    [/\bvm4 content store mongo\b/gi, "контентное хранилище Mongo на VM4"],
    [/\bvm4 enterprise foundation\b/gi, "базовая платформа VM4"],
    [/\bvm4 security hardening\b/gi, "усиление безопасности VM4"],
    [/\bvm5 processing wave\b/gi, "волна обработки на VM5"],
    [/\bvm5 transport node\b/gi, "транспортный узел VM5"],
    [/\bplatform release\b/gi, "релиз платформы"],
    [/\bfollow-up\b/gi, "доработка"],
    [/\bstream corr\b/gi, "stream-корреляция"],
    [/\bcontent store\b/gi, "контентное хранилище"],
    [/\bsecurity hardening\b/gi, "усиление безопасности"],
  ];
  let result = cleaned;
  for (const [pattern, replacement] of replacements) {
    result = result.replace(pattern, replacement);
  }
  return result.charAt(0).toUpperCase() + result.slice(1);
}

function friendlyDocTitle(name: string, lang: "en" | "ru") {
  const key = String(name || "").trim().toLowerCase();
  const known: Record<string, { en: string; ru: string }> = {
    "00_access_matrix.md": { en: "Access Matrix", ru: "Матрица доступа" },
    "01_remote_access.md": { en: "Remote Access", ru: "Удаленный доступ" },
    "02_nextcloud_usage.md": { en: "Nextcloud Usage", ru: "Работа с Nextcloud" },
    "03_windows_onboarding.md": { en: "Windows Onboarding", ru: "Онбординг Windows" },
    "04_soc_scenarios.md": { en: "SOC Scenarios", ru: "SOC-сценарии" },
    "05_public_host_security.md": { en: "Public Host Security", ru: "Защита публичного хоста" },
    "06_platform_status.md": { en: "Platform Status", ru: "Статус платформы" },
    "07_vpn_windows_operations.md": { en: "Windows VPN Operations", ru: "VPN-операции для Windows" },
    "credentials_registry.md": { en: "Credentials Registry", ru: "Реестр учетных данных" },
    "vm_access.md": { en: "VM Access", ru: "Доступ к виртуальным машинам" },
    "correlation_rules.md": { en: "Correlation Rules", ru: "Правила корреляции" },
    "deployment_runbook_homelab_runners.md": { en: "Deployment Runbook Homelab Runners", ru: "Регламент развертывания исполнителей homelab" },
    "deployment_runbook_kafka_vm5_wave_2026-03-22.md": { en: "Deployment Runbook Kafka VM5 Wave 2026 03 22", ru: "Регламент развертывания волны Kafka на VM5 2026 03 22" },
    "deployment_runbook_vm1_ingest_fabric.md": { en: "Deployment Runbook VM1 Ingest Fabric", ru: "Регламент развертывания контура приема VM1" },
    "deployment_runbook_vm2_processing_resilience.md": { en: "Deployment Runbook VM2 Processing Resilience", ru: "Регламент развертывания устойчивости обработки VM2" },
    "deployment_runbook_vm3_proxmox_memory_alignment.md": { en: "Deployment Runbook VM3 Proxmox Memory Alignment", ru: "Регламент развертывания согласования памяти Proxmox на VM3" },
    "deployment_runbook_vm3_storage_memory_tuning.md": { en: "Deployment Runbook VM3 Storage Memory Tuning", ru: "Регламент развертывания настройки памяти хранилища на VM3" },
    "deployment_runbook_vm3_stream_corr_event_time.md": { en: "Deployment Runbook VM3 Stream Corr Event Time", ru: "Регламент развертывания времени событий stream-корреляции на VM3" },
    "deployment_runbook_vm4_content_store_mongo.md": { en: "Deployment Runbook VM4 Content Store Mongo", ru: "Регламент развертывания контентного хранилища Mongo на VM4" },
    "deployment_runbook_vm4_enterprise_foundation.md": { en: "Deployment Runbook VM4 Enterprise Foundation", ru: "Регламент развертывания базовой платформы VM4" },
    "deployment_runbook_vm4_security_hardening.md": { en: "Deployment Runbook VM4 Security Hardening", ru: "Регламент развертывания усиления безопасности VM4" },
    "deployment_runbook_vm5_processing_wave_2026-03-22.md": { en: "Deployment Runbook VM5 Processing Wave 2026 03 22", ru: "Регламент развертывания волны обработки на VM5 2026 03 22" },
    "deployment_runbook_vm5_transport_node_2026-03-23.md": { en: "Deployment Runbook VM5 Transport Node 2026 03 23", ru: "Регламент развертывания транспортного узла VM5 2026 03 23" },
    "architecture.md": { en: "Architecture", ru: "Архитектура" },
    "configuration.md": { en: "Configuration", ru: "Конфигурация" },
    "endpoints.md": { en: "Endpoints", ru: "Точки API" },
    "source_discovery.md": { en: "Source Discovery", ru: "Обнаружение источников" },
    "vuln_reports.md": { en: "Vulnerability Reports", ru: "Отчеты по уязвимостям" },
    "app_section_guide_and_usability_2026-03-28.md": { en: "App Section Guide and Usability", ru: "Разделы системы и оценка удобства" },
    "diploma__readme.md": { en: "Diploma README", ru: "Сводка дипломной документации" },
    "diploma__rdegon_siem_diploma_documentation_2026-03-28.md": { en: "Diploma Documentation 2026 03 28", ru: "Дипломная документация 2026 03 28" },
    "builder_drafts.json": { en: "Builder Drafts", ru: "Черновики конструкторов" },
    "dashboards.json": { en: "Dashboards Catalog", ru: "Каталог дашбордов" },
    "dns_cache.json": { en: "DNS Cache", ru: "DNS-кэш" },
    "geoip_cache.json": { en: "GeoIP Cache", ru: "GeoIP-кэш" },
    "backend_security_followup_2026-03-21.md": { en: "Backend Security Follow-up 2026 03 21", ru: "Доработка безопасности backend 2026 03 21" },
    "storage_ha_operations_2026-03-25.md": { en: "Storage HA Operations 2026 03 25", ru: "Операции отказоустойчивого хранилища 2026 03 25" },
    "release_wave_backlog_2026-03-22.md": { en: "Release Wave Backlog 2026 03 22", ru: "Волна релиза backlog 2026 03 22" },
    "release_wave_kafka_vm5_2026-03-22.md": { en: "Release Wave Kafka VM5 2026 03 22", ru: "Волна релиза Kafka на VM5 2026 03 22" },
    "release_wave_platform_release_2026-03-22.md": { en: "Release Wave Platform Release 2026 03 22", ru: "Волна релиза платформы 2026 03 22" },
    "backend_runtime_wave_2026-03-25.md": { en: "Backend Runtime Wave 2026 03 25", ru: "Волна runtime backend 2026 03 25" },
    "eps_benchmark_2026-03-24.md": { en: "EPS Benchmark 2026 03 24", ru: "EPS-бенчмарк 2026 03 24" },
    "vm2_recovery_2026-03-22.md": { en: "VM2 Recovery 2026 03 22", ru: "Восстановление VM2 2026 03 22" },
  };
  if (known[key]) return known[key][lang];
  const cleaned = humanizeDocStem(name);
  if (!cleaned) return name;
  if (lang === "ru") return russianizeDocTitle(cleaned);
  return cleaned
    .split(" ")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function docSectionTitle(section: DocSectionRecord, lang: "en" | "ru") {
  const title = String(section?.title || "").trim();
  if (!title) return lang === "ru" ? "Раздел" : "Section";
  const normalized = title.toLowerCase();
  const known: Record<string, { en: string; ru: string }> = {
    "access and credentials": { en: "Access and Credentials", ru: "Доступ и учетные данные" },
    "operations and runbooks": { en: "Operations and Runbooks", ru: "Операции и регламенты" },
    "operations and maintenance": { en: "Operations and Maintenance", ru: "Операции и сопровождение" },
    "platform and architecture": { en: "Platform and Architecture", ru: "Платформа и архитектура" },
    "deployment and recovery": { en: "Deployment and Recovery", ru: "Развертывание и восстановление" },
    "security and governance": { en: "Security and Governance", ru: "Безопасность и управление" },
    "integrations and sso": { en: "Integrations and SSO", ru: "Интеграции и SSO" },
    "performance and certification": { en: "Performance and Certification", ru: "Производительность и сертификация" },
    "product and ux": { en: "Product and UX", ru: "Продукт и UX" },
    "investigation scenarios": { en: "Investigation Scenarios", ru: "Сценарии расследования" },
    miscellaneous: { en: "Miscellaneous", ru: "Прочие материалы" },
  };
  return known[normalized] ? known[normalized][lang] : title;
}

function docSectionSubtitle(section: DocSectionRecord | undefined, lang: "en" | "ru") {
  if (!section?.subtitle) {
    return lang === "ru" ? "Операционные документы и инструкции по текущему стенду." : "Operational documents and instructions for the current stand.";
  }
  return section.subtitle;
}

export function DocumentationPage() {
  const { lang } = useShellContext();
  const navigate = useNavigate();
  const params = useParams();
  const selectedDoc = params.docName ? decodeURIComponent(params.docName) : "";
  const selectedPlaybook = params.playbookSlug ? decodeURIComponent(params.playbookSlug) : "";
  const loadDocsIndex = useCallback<() => Promise<DocsIndexResponse>>(() => api.docsIndex(), []);
  const indexState = useAsyncData<DocsIndexResponse>(loadDocsIndex);
  const [query, setQuery] = useState("");
  const debouncedQuery = useDebouncedValue(query, 150);

  const loadDocDetail = useCallback(
    () => (selectedDoc ? api.docDetail(selectedDoc) : Promise.resolve(null)),
    [selectedDoc],
  );
  const docDetailState = useAsyncData(loadDocDetail);
  const loadPlaybookDetail = useCallback(
    () => (selectedPlaybook ? api.playbookDetail(selectedPlaybook) : Promise.resolve(null)),
    [selectedPlaybook],
  );
  const playbookDetailState = useAsyncData(loadPlaybookDetail);

  const filteredSections = useMemo(() => {
    const sections = indexState.data?.doc_sections || [];
    const token = debouncedQuery.trim().toLowerCase();
    if (!token) return sections;
    return sections
      .map((section: DocSectionRecord) => ({
        ...section,
        items: (section.items || []).filter((item) => {
          const haystack = JSON.stringify(item || {}).toLowerCase();
          return haystack.includes(token);
        }),
      }))
      .filter((section) => section.items.length);
  }, [debouncedQuery, indexState.data]);

  const filteredPlaybooks = useMemo(() => {
    const items = indexState.data?.playbooks || [];
    const token = debouncedQuery.trim().toLowerCase();
    if (!token) return items;
    return items.filter((item: PlaybookSummary) => JSON.stringify(item).toLowerCase().includes(token));
  }, [debouncedQuery, indexState.data]);

  const preferredDoc = useMemo(() => {
    const allDocs = filteredSections.flatMap((section) => section.items || []);
    return allDocs.find((item) => item.name === "app_section_guide_and_usability_2026-03-28.md")?.name || allDocs[0]?.name || "";
  }, [filteredSections]);

  useEffect(() => {
    if (selectedDoc || selectedPlaybook || !preferredDoc) return;
    navigate(`/docs/page/${encodeURIComponent(preferredDoc)}`, { replace: true });
  }, [navigate, preferredDoc, selectedDoc, selectedPlaybook]);

  const activeDocMeta = filteredSections.flatMap((section) => section.items || []).find((item) => item.name === selectedDoc);
  const activeDocSection = filteredSections.find((section) => (section.items || []).some((item) => item.name === selectedDoc));
  const activePlaybook = filteredPlaybooks.find((item) => item.slug === selectedPlaybook);
  const detailState = selectedPlaybook ? playbookDetailState : docDetailState;
  const detailData = (detailState.data as DocumentDetailResponse | PlaybookDetailResponse | null) || null;
  const toc = detailData?.toc || [];
  const selectedTitle = selectedPlaybook
    ? activePlaybook?.title || t(lang, { en: "Playbook", ru: "Плейбук" })
    : activeDocMeta?.name
      ? friendlyDocTitle(activeDocMeta.name, lang)
      : t(lang, { en: "Document", ru: "Документ" });
  const selectedSubtitle = selectedPlaybook
    ? t(lang, { en: "Operational investigation and recovery scenario.", ru: "Операционный сценарий расследования и восстановления." })
    : docSectionSubtitle(activeDocSection, lang);

  return (
    <AsyncGate states={[indexState]} loadingMessage={t(lang, { en: "Loading documentation...", ru: "Загрузка документации..." })}>
      <div className="react-page">
        <SectionIntro
          kicker={t(lang, { en: "Documentation", ru: "Документация" })}
          title={t(lang, { en: "Knowledge base and playbooks", ru: "База знаний и плейбуки" })}
          subtitle={t(lang, {
            en: "Operational portal for access, runbooks, onboarding, recovery and investigation workflows.",
            ru: "Операционный портал для доступа, регламентов, онбординга, восстановления и сценариев расследования.",
          })}
          actions={
            <div className="react-actions react-wrap">
              <input
                className="react-input react-input-grow"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder={t(lang, { en: "Search documentation and playbooks", ru: "Поиск по документации и плейбукам" })}
              />
            </div>
          }
        />

        <PageTabs
          items={[
            { to: "/docs", label: t(lang, { en: "Knowledge Base", ru: "База знаний" }) },
            { to: "/docs/playbooks/ssh-auth-failures", label: t(lang, { en: "Playbooks", ru: "Плейбуки" }) },
          ]}
        />

        <div className="react-docs-shell">
          <aside className="react-card react-sticky react-docs-rail">
            <div className="react-doc-tree">
              {filteredSections.map((section) => (
                <div key={section.id} className="react-doc-section">
                  <div className="react-doc-section-title">{docSectionTitle(section, lang)}</div>
                  {(section.items || []).map((item) => (
                    <button
                      key={item.name}
                      className={`react-doc-link ${selectedDoc === item.name ? "active" : ""}`}
                      onClick={() => navigate(`/docs/page/${encodeURIComponent(item.name)}`)}
                      type="button"
                    >
                      <strong>{friendlyDocTitle(item.name || "", lang)}</strong>
                      <span>{item.modified_ts || t(lang, { en: "Runtime document", ru: "Runtime-документ" })}</span>
                    </button>
                  ))}
                </div>
              ))}
              <div className="react-doc-section">
                <div className="react-doc-section-title">{t(lang, { en: "Playbooks", ru: "Плейбуки" })}</div>
                {filteredPlaybooks.map((item) => (
                  <button
                    key={item.slug}
                    className={`react-doc-link ${selectedPlaybook === item.slug ? "active" : ""}`}
                    onClick={() => navigate(`/docs/playbooks/${encodeURIComponent(item.slug)}`)}
                    type="button"
                  >
                    <strong>{item.title}</strong>
                    <span>{item.summary || t(lang, { en: "Investigation playbook", ru: "Плейбук расследования" })}</span>
                  </button>
                ))}
              </div>
            </div>
          </aside>

          <section className="react-card react-doc-main">
            <Breadcrumbs
              items={[
                { label: t(lang, { en: "Documentation", ru: "Документация" }), href: "/app/docs" },
                selectedPlaybook
                  ? { label: t(lang, { en: "Playbooks", ru: "Плейбуки" }), href: "/app/docs" }
                  : {
                      label: docSectionTitle(
                        activeDocSection || { id: "", title: t(lang, { en: "Knowledge Base", ru: "База знаний" }), subtitle: "", items: [] },
                        lang,
                      ),
                      href: "/app/docs",
                    },
                { label: selectedTitle },
              ]}
            />
            <PanelHeader title={selectedTitle} subtitle={selectedSubtitle} />
            <AsyncGate states={[detailState]} loadingMessage={t(lang, { en: "Loading article...", ru: "Загрузка материала..." })}>
              {detailData ? (
                <div className="react-doc-content-layout">
                  <article className="react-html-view" dangerouslySetInnerHTML={{ __html: detailData.content_html || detailData.html || "" }} />
                  <aside className="react-doc-toc react-sticky">
                    <div className="react-toc-title">{t(lang, { en: "On this page", ru: "На этой странице" })}</div>
                    <div className="react-toc-list">
                      {toc.length ? (
                        toc.map((item: TocItem) => (
                          <a key={`${item.id}-${item.level}`} href={`#${item.id}`} className={`react-toc-link level-${item.level}`}>
                            {item.name}
                          </a>
                        ))
                      ) : (
                        <span className="react-muted">{t(lang, { en: "No generated headings", ru: "Сгенерированные заголовки отсутствуют" })}</span>
                      )}
                    </div>
                  </aside>
                </div>
              ) : (
                <EmptyState message={t(lang, { en: "Select a document or playbook from the navigation tree.", ru: "Выберите документ или плейбук в навигационном дереве." })} />
              )}
            </AsyncGate>
          </section>
        </div>
      </div>
    </AsyncGate>
  );
}
