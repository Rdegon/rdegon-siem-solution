import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { useAsyncData } from "../hooks";
import { AsyncGate } from "../async";
import {
  DrawerFieldGrid,
  DrawerOverlay,
  EmptyState,
  Icon,
  InfoList,
  JsonPreview,
  KeyValue,
  PanelHeader,
  SectionIntro,
  StatCard,
  StatusBadge,
} from "../ui";
import { t, useShellContext } from "../context";
import type {
  AssetCatalogResponse,
  BuilderBlockRecord,
  BuilderDraftRecord,
  BuilderDraftsResponse,
  BuilderPublishResponse,
  BuilderTestResponse,
  BuilderValidationResponse,
  CorrelationBatchRuleRecord,
  CorrelationPackDetailResponse,
  CorrelationPackRecord,
  CorrelationPacksResponse,
  CorrelationPackTestResponse,
  CorrelationRuleRecord,
  IntegrationTemplateRecord,
  IntegrationsCatalogResponse,
  RuntimeBlob,
} from "../types";

const STAGES = [
  { id: "ingest", label: "Ingest", hint: "Collector binding and source entry." },
  { id: "parse", label: "Parse", hint: "Raw parsing, extraction and normalization." },
  { id: "enrich", label: "Enrich", hint: "Lookups, lists, context and reputation." },
  { id: "detect", label: "Detect", hint: "Thresholds, sequences and detection logic." },
  { id: "incident", label: "Incident", hint: "Queue projection, ownership and severity." },
  { id: "publish", label: "Publish", hint: "Runtime artifact generation and release." },
];

const DEFAULT_STAGE: Record<string, string> = {
  source: "ingest",
  webhook_source: "ingest",
  sql_source: "ingest",
  nosql_source: "ingest",
  rest_pull: "ingest",
  normalizer: "parse",
  active_list: "enrich",
  ti_lookup: "enrich",
  webhook_output: "publish",
  telegram_output: "publish",
  filter: "enrich",
  detection: "detect",
  incident: "incident",
  publish: "publish",
};

const CORE_BLOCK_LIBRARY: BuilderBlockDefinition[] = [
  { type: "source", label: "Source block", hint: "Collector/source selector and profile binding." },
  { type: "normalizer", label: "Normalizer block", hint: "Field mapping and category normalization." },
  { type: "active_list", label: "Active-list block", hint: "Allow, deny, watch and enrichment logic." },
  { type: "ti_lookup", label: "Threat-intel block", hint: "IOC lookup and reputation decisions." },
  { type: "filter", label: "Filter block", hint: "Noise suppression and routing conditions." },
  { type: "detection", label: "Detection block", hint: "Threshold, sequence and alert definition." },
  { type: "incident", label: "Incident block", hint: "Queue, ownership and incident projection." },
  { type: "publish", label: "Publish block", hint: "Runtime output target and deployment metadata." },
];

const BUILDER_FAMILIES = [
  { id: "detection", label: "Detection Builder", hint: "Thresholds, sequences, alert projection and incident promotion." },
  { id: "normalizer", label: "Normalizer Builder", hint: "Parsing, mapping and category normalization for new telemetry." },
  { id: "active-list", label: "Active List Builder", hint: "Allow, deny, watch and business-context lists." },
  { id: "threat-intel", label: "TI Feed Builder", hint: "External IOC sources, reputation logic and enrichment." },
  { id: "integration", label: "Integration Builder", hint: "Inbound webhooks, database polling and outbound automations." },
] as const;

const BUILDER_STARTERS: Record<string, string[]> = {
  detection: ["source", "normalizer", "filter", "detection", "incident", "publish"],
  normalizer: ["source", "normalizer", "publish"],
  "active-list": ["source", "active_list", "publish"],
  "threat-intel": ["rest_pull", "ti_lookup", "detection", "incident", "publish"],
  integration: ["webhook_source", "sql_source", "rest_pull", "webhook_output"],
};

type BuilderLang = "en" | "ru";

const STAGE_COPY: Record<string, { en: string; ru: string; hintEn: string; hintRu: string }> = {
  ingest: {
    en: "Ingest",
    ru: "Прием",
    hintEn: "Collector binding and source entry.",
    hintRu: "Подключение коллектора и точка входа источника.",
  },
  parse: {
    en: "Parse",
    ru: "Разбор",
    hintEn: "Raw parsing, extraction and normalization.",
    hintRu: "Разбор сырого потока, извлечение полей и нормализация.",
  },
  enrich: {
    en: "Enrich",
    ru: "Обогащение",
    hintEn: "Lookups, lists, context and reputation.",
    hintRu: "Списки, контекст, репутация и справочные проверки.",
  },
  detect: {
    en: "Detect",
    ru: "Выявление",
    hintEn: "Thresholds, sequences and detection logic.",
    hintRu: "Пороговые условия, последовательности и логика детектирования.",
  },
  incident: {
    en: "Incident",
    ru: "Инцидент",
    hintEn: "Queue projection, ownership and severity.",
    hintRu: "Проекция в очередь, владение и итоговая важность.",
  },
  publish: {
    en: "Publish",
    ru: "Публикация",
    hintEn: "Runtime artifact generation and release.",
    hintRu: "Сборка runtime-артефакта и выпуск в рабочий контур.",
  },
};

const CORE_BLOCK_COPY: Record<string, { en: string; ru: string; hintEn: string; hintRu: string }> = {
  source: {
    en: "Source block",
    ru: "Блок источника",
    hintEn: "Collector/source selector and profile binding.",
    hintRu: "Выбор коллектора, источника и профиля подключения.",
  },
  normalizer: {
    en: "Normalizer block",
    ru: "Блок нормализации",
    hintEn: "Field mapping and category normalization.",
    hintRu: "Маппинг полей и приведение события к нормализованной категории.",
  },
  active_list: {
    en: "Active-list block",
    ru: "Блок активных списков",
    hintEn: "Allow, deny, watch and enrichment logic.",
    hintRu: "Логика allow, deny, watch и дополнительного обогащения.",
  },
  ti_lookup: {
    en: "Threat-intel block",
    ru: "Блок киберразведки",
    hintEn: "IOC lookup and reputation decisions.",
    hintRu: "Проверка IOC и принятие решений по репутации.",
  },
  filter: {
    en: "Filter block",
    ru: "Блок фильтрации",
    hintEn: "Noise suppression and routing conditions.",
    hintRu: "Подавление шума и условия маршрутизации.",
  },
  detection: {
    en: "Detection block",
    ru: "Блок детектирования",
    hintEn: "Threshold, sequence and alert definition.",
    hintRu: "Пороговые условия, последовательности и правило генерации алерта.",
  },
  incident: {
    en: "Incident block",
    ru: "Блок инцидента",
    hintEn: "Queue, ownership and incident projection.",
    hintRu: "Очередь, владение и проекция события в инцидент.",
  },
  publish: {
    en: "Publish block",
    ru: "Блок публикации",
    hintEn: "Runtime output target and deployment metadata.",
    hintRu: "Целевой runtime-контур и метаданные публикации.",
  },
};

const BUILDER_FAMILY_COPY: Record<string, { en: string; ru: string; hintEn: string; hintRu: string }> = {
  detection: {
    en: "Detection Builder",
    ru: "Конструктор детектов",
    hintEn: "Thresholds, sequences, alert projection and incident promotion.",
    hintRu: "Пороги, последовательности, проекция алертов и подъем в инциденты.",
  },
  normalizer: {
    en: "Normalizer Builder",
    ru: "Конструктор нормализации",
    hintEn: "Parsing, mapping and category normalization for new telemetry.",
    hintRu: "Разбор, маппинг и нормализация категорий для новой телеметрии.",
  },
  "active-list": {
    en: "Active List Builder",
    ru: "Конструктор активных списков",
    hintEn: "Allow, deny, watch and business-context lists.",
    hintRu: "Списки allow, deny, watch и бизнес-контекста.",
  },
  "threat-intel": {
    en: "TI Feed Builder",
    ru: "Конструктор TI-потоков",
    hintEn: "External IOC sources, reputation logic and enrichment.",
    hintRu: "Внешние IOC-источники, логика репутации и обогащения.",
  },
  integration: {
    en: "Integration Builder",
    ru: "Конструктор интеграций",
    hintEn: "Inbound webhooks, database polling and outbound automations.",
    hintRu: "Входящие webhooks, опрос БД и исходящие автоматизации.",
  },
};

const CORRELATION_PACK_TITLE_RU: Record<string, string> = {
  "fleet-observability-v1": "Пакет наблюдаемости fleet",
  "gitea-activity-v1": "Пакет активности Gitea",
  "host-runtime-observability-v1": "Пакет наблюдаемости runtime узлов",
  "host-runtime-policy-v1": "Пакет политик runtime узлов",
  "identity-access-v1": "Пакет контроля доступа",
  "linux-activity-v1": "Пакет Linux-активности",
  "navidrome-activity-v1": "Пакет активности Navidrome",
  "openclaw-behavior-v1": "Пакет поведения OpenClaw",
  "pilot-services-v1": "Пакет pilot-сервисов",
  "scanner-runtime-v1": "Пакет runtime сканеров",
  "vuln-coverage-v1": "Пакет покрытия уязвимостей",
  "windows-activity-v1": "Пакет Windows-активности",
};

const CORRELATION_RULE_TITLE_RU: Record<string, Record<number, string>> = {
  "fleet-observability-v1": {
    2201: "Длительное отсутствие телеметрии fleet",
    2202: "Флаппинг сервисов fleet",
    2203: "Давление на runtime fleet",
    4201: "Проверка полноты телеметрии fleet",
  },
  "gitea-activity-v1": {
    2511: "Всплеск неудачных входов в Gitea",
    2512: "Административное изменение в Gitea",
    2513: "Всплеск активности репозиториев Gitea",
  },
  "host-runtime-observability-v1": {
    2101: "Устойчивое давление по CPU",
    2102: "Устойчивое давление по памяти",
    2103: "Устойчивое давление по дискам",
    2104: "Устойчивое давление по load average",
    2105: "Всплеск thrashing по swap",
    2106: "Давление по inode файловой системы",
    2107: "Отсутствие телеметрии узла",
    2108: "Флаппинг сервисов узла",
    2109: "Давление на storage-узел",
    2110: "Давление на control plane",
    4101: "Ежедневная проверка отсутствующей телеметрии узлов",
    4102: "Тренд флаппинга сервисов узлов",
    4103: "Тренд давления storage-узлов",
    4104: "Тренд давления control plane",
  },
  "identity-access-v1": {
    2501: "Повторяющиеся ошибки аутентификации во внешнем приложении",
    2502: "Первый вход в SSO-приложение",
    2503: "Обнаружен дрейф роли или гранта SSO",
  },
  "linux-activity-v1": {
    2701: "Всплеск ошибок входа по SSH в Linux",
    2702: "Прямой вход root по SSH в Linux",
    2703: "Всплеск sudo до root в Linux",
    2704: "Изменение cron в Linux",
    2705: "Изменение sudoers в Linux",
    2706: "Изменение systemd-unit в Linux",
    2707: "Отключение критичного сервиса безопасности в Linux",
    4701: "Проверка изменений механизма закрепления в Linux",
  },
  "navidrome-activity-v1": {
    2521: "Всплеск ошибок аутентификации через прокси Navidrome",
    2522: "Первый пользователь в Navidrome",
    2523: "Аномальный всплеск playback/API в Navidrome",
  },
  "openclaw-behavior-v1": {
    2301: "Всплеск исходящих соединений OpenClaw",
    2302: "Всплеск DNS-запросов OpenClaw",
    2303: "Привилегированное изменение конфигурации OpenClaw",
    2304: "Всплеск proxy-ошибок OpenClaw",
    2305: "Подозрительная интерактивная привилегированная активность OpenClaw",
    4301: "Проверка новых направлений OpenClaw",
  },
  "pilot-services-v1": {
    2501: "Нестабильность runtime pilot-сервиса",
    2502: "Отсутствие телеметрии pilot-сервиса",
    2503: "Всплеск ошибок аутентификации pilot-сервиса",
    4501: "Проверка тренда ошибок pilot-сервисов",
  },
  "scanner-runtime-v1": {
    2531: "Деградация синхронизации или импорта Greenbone",
    2532: "Устаревшее покрытие fleet сканированием",
    2533: "Дрейф scanner target относительно инвентаря Proxmox",
  },
  "vuln-coverage-v1": {
    2401: "Критическая экспозиция на сервисе fleet",
    2402: "Всплеск уязвимостей публичного сервиса",
    4401: "Проверка свежести сканирования fleet",
    4402: "Проверка неразмеченных целей fleet",
  },
  "windows-activity-v1": {
    2601: "Всплеск ошибок входа Windows",
    2602: "Очистка журнала аудита Windows",
    2603: "Изменение членства в привилегированной группе Windows",
    2604: "Закодированная команда PowerShell в Windows",
    2605: "Установка сервиса в Windows",
    2606: "Создание пользователя в Windows",
    4601: "Проверка изменений привилегий Windows",
  },
};

function stageLabel(id: string, lang: BuilderLang) {
  return lang === "ru" ? (STAGE_COPY[id]?.ru || id) : (STAGE_COPY[id]?.en || id);
}

function stageHint(id: string, lang: BuilderLang) {
  return lang === "ru" ? (STAGE_COPY[id]?.hintRu || "") : (STAGE_COPY[id]?.hintEn || "");
}

function familyLabel(id: string, lang: BuilderLang) {
  return lang === "ru" ? (BUILDER_FAMILY_COPY[id]?.ru || id) : (BUILDER_FAMILY_COPY[id]?.en || id);
}

function familyHint(id: string, lang: BuilderLang) {
  return lang === "ru" ? (BUILDER_FAMILY_COPY[id]?.hintRu || "") : (BUILDER_FAMILY_COPY[id]?.hintEn || "");
}

function blockLabel(type: string, fallback: string, lang: BuilderLang) {
  const copy = CORE_BLOCK_COPY[type];
  return lang === "ru" ? (copy?.ru || fallback) : (copy?.en || fallback);
}

function blockHint(type: string, fallback: string, lang: BuilderLang) {
  const copy = CORE_BLOCK_COPY[type];
  return lang === "ru" ? (copy?.hintRu || fallback) : (copy?.hintEn || fallback);
}

function localizedPackTitle(packId: string, fallback: string, lang: BuilderLang) {
  return lang === "ru" ? (CORRELATION_PACK_TITLE_RU[packId] || fallback) : fallback;
}

function localizedRuleTitle(packId: string, ruleId: number, fallback: string, lang: BuilderLang) {
  return lang === "ru" ? (CORRELATION_RULE_TITLE_RU[packId]?.[ruleId] || fallback) : fallback;
}

const BUILDER_SAMPLE_LABEL_RU: Record<string, string> = {
  "Linux Auth Collector": "Коллектор Linux-аутентификации",
  "Linux auth normalizer": "Нормализатор Linux-аутентификации",
  "Denylist lookup": "Проверка denylist",
  "SSH failure burst": "Всплеск ошибок SSH",
  "Queue incident": "Постановка в очередь инцидентов",
  "Publish runtime": "Публикация в runtime",
  "Linux auth detection": "Детект Linux-аутентификации",
};

const BUILDER_SAMPLE_TEXT_RU: Record<string, string> = {
  "Collector -> normalizer -> active-list -> detection -> incident pipeline.": "Коллектор -> нормализация -> активные списки -> детектирование -> инцидентный конвейер.",
};

function builderDisplayLabel(value: string, lang: BuilderLang) {
  const text = String(value || "").trim();
  if (!text || lang !== "ru") return text;
  return BUILDER_SAMPLE_LABEL_RU[text] || text;
}

function builderDisplayText(value: string, lang: BuilderLang) {
  const text = String(value || "").trim();
  if (!text || lang !== "ru") return text;
  return BUILDER_SAMPLE_TEXT_RU[text] || BUILDER_SAMPLE_LABEL_RU[text] || text;
}

function builderStatusLabel(value: string, lang: BuilderLang) {
  const status = String(value || "").trim().toLowerCase();
  if (lang !== "ru") return status || value;
  if (status === "draft") return "черновик";
  if (status === "published") return "опубликовано";
  if (status === "active") return "активно";
  return status || value;
}

function builderHistoryActionLabel(value: string, lang: BuilderLang) {
  const action = String(value || "").trim().toLowerCase();
  if (lang !== "ru") return action || value;
  if (action === "save") return "сохранение";
  if (action === "publish") return "публикация";
  if (action === "validate") return "проверка";
  if (action === "test") return "тест";
  return action || value;
}

type BuilderBlockDefinition = {
  type: string;
  label: string;
  hint: string;
  integrationId?: string;
  group?: string;
  mode?: string;
  protocols?: string[];
  family?: string;
  defaultStage?: string;
};

type BuilderGraphNode = {
  id: string;
  type: string;
  stage: string;
  label: string;
};

type BuilderGraphEdge = {
  id: string;
  source: string;
  target: string;
};

type BuilderGraphEdgeDetail = BuilderGraphEdge & {
  sourceLabel: string;
  sourceStage: string;
  targetLabel: string;
  targetStage: string;
};

type BuilderRuntimeOutput = BuilderValidationResponse | BuilderTestResponse | BuilderPublishResponse | { error: string };
type BuilderWorkspace = "graph" | "correlation";
type CorrelationEditorState = {
  pack_id: string;
  title: string;
  version: string;
  status: string;
  owner: string;
  notes: string[];
  stream_rules: CorrelationRuleRecord[];
  batch_rules: CorrelationBatchRuleRecord[];
};

function safeBuilderWorkspace(value: string | null): BuilderWorkspace {
  return value === "correlation" ? "correlation" : "graph";
}

function emptyCorrelationPack(): CorrelationEditorState {
  return {
    pack_id: "",
    title: "",
    version: "1.0.0",
    status: "draft",
    owner: "platform-release",
    notes: [],
    stream_rules: [],
    batch_rules: [],
  };
}

function readDefinitionMeta(item: { type: string; label: string; hint: string }) {
  const candidate = item as Partial<BuilderBlockDefinition>;
  return {
    group: candidate.group,
    mode: candidate.mode,
    protocols: candidate.protocols || [],
  };
}

function readBlockTargets(block?: BuilderBlockRecord | null) {
  const targets = block?.config?.links_to;
  if (!Array.isArray(targets)) return [];
  return targets.map((item) => String(item || "")).filter(Boolean);
}

function upsertDraft(list: BuilderDraftRecord[], draft: BuilderDraftRecord) {
  const next = list.filter((item) => item.id !== draft.id);
  next.push(draft);
  return next.sort((left, right) => String(left.title || "").localeCompare(String(right.title || "")));
}

export function BuildersPage() {
  const { lang } = useShellContext();
  const [searchParams, setSearchParams] = useSearchParams();
  const loadCatalog = useCallback(() => api.assetCatalog(), []);
  const loadDrafts = useCallback(() => api.builderDrafts(), []);
  const loadIntegrations = useCallback(() => api.integrationsCatalog(), []);
  const catalog = useAsyncData<AssetCatalogResponse>(loadCatalog);
  const draftsState = useAsyncData<BuilderDraftsResponse>(loadDrafts);
  const integrationsState = useAsyncData<IntegrationsCatalogResponse>(loadIntegrations);
  const requestedWorkspace = safeBuilderWorkspace(searchParams.get("workspace"));
  const [drafts, setDrafts] = useState<BuilderDraftRecord[]>([]);
  const [workspace, setWorkspace] = useState<BuilderWorkspace>(requestedWorkspace);
  const [selectedDraftId, setSelectedDraftId] = useState("");
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [kind, setKind] = useState("detection");
  const [blocks, setBlocks] = useState<BuilderBlockRecord[]>([]);
  const [selectedBlockId, setSelectedBlockId] = useState("");
  const [selectedEdgeId, setSelectedEdgeId] = useState("");
  const [connectTargetId, setConnectTargetId] = useState("");
  const [dragIndex, setDragIndex] = useState<number | null>(null);
  const [saveState, setSaveState] = useState("");
  const [validationOutput, setValidationOutput] = useState<BuilderRuntimeOutput | null>(null);
  const [testOutput, setTestOutput] = useState<BuilderRuntimeOutput | null>(null);
  const [publishOutput, setPublishOutput] = useState<BuilderRuntimeOutput | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [paletteView, setPaletteView] = useState<"core" | "integrations">("core");
  const [paletteQuery, setPaletteQuery] = useState("");
  const [correlationRefreshToken, setCorrelationRefreshToken] = useState(0);
  const [selectedCorrelationPackId, setSelectedCorrelationPackId] = useState("");
  const [selectedCorrelationRuleId, setSelectedCorrelationRuleId] = useState(0);
  const [correlationPackForm, setCorrelationPackForm] = useState<CorrelationEditorState>(emptyCorrelationPack());
  const [correlationSaveState, setCorrelationSaveState] = useState("");
  const [correlationValidationOutput, setCorrelationValidationOutput] = useState<RuntimeBlob | null>(null);
  const [correlationTestOutput, setCorrelationTestOutput] = useState<CorrelationPackTestResponse | null>(null);
  const [correlationPublishOutput, setCorrelationPublishOutput] = useState<RuntimeBlob | null>(null);
  const [correlationPackEditorOpen, setCorrelationPackEditorOpen] = useState(false);
  const [correlationRuleEditorOpen, setCorrelationRuleEditorOpen] = useState(false);
  const [correlationOpsOpen, setCorrelationOpsOpen] = useState(false);
  const [correlationPackSearch, setCorrelationPackSearch] = useState("");
  const [correlationRuleSearch, setCorrelationRuleSearch] = useState("");
  const correlationPacksState = useAsyncData<CorrelationPacksResponse>(
    useCallback(() => {
      void correlationRefreshToken;
      return api.correlationPacks();
    }, [correlationRefreshToken]),
  );
  const correlationPackDetailState = useAsyncData<CorrelationPackDetailResponse>(
    useCallback(() => {
      void correlationRefreshToken;
      return selectedCorrelationPackId
        ? api.correlationPackDetail(selectedCorrelationPackId)
        : Promise.resolve({ item: null });
    }, [correlationRefreshToken, selectedCorrelationPackId]),
  );

  useEffect(() => {
    if (draftsState.data?.items) {
      setDrafts(draftsState.data.items);
    }
  }, [draftsState.data]);

  useEffect(() => {
    setWorkspace(requestedWorkspace);
  }, [requestedWorkspace]);

  useEffect(() => {
    if (!selectedDraftId && drafts.length) {
      setSelectedDraftId(String(drafts[0].id || ""));
    }
  }, [drafts, selectedDraftId]);

  const selectedDraft = useMemo(
    () => drafts.find((item) => item.id === selectedDraftId) || drafts[0] || null,
    [drafts, selectedDraftId],
  );
  const stages = useMemo(
    () => STAGES.map((stage) => ({ ...stage, label: stageLabel(stage.id, lang), hint: stageHint(stage.id, lang) })),
    [lang],
  );
  const localizedCoreBlockLibrary = useMemo(
    () =>
      CORE_BLOCK_LIBRARY.map((item) => ({
        ...item,
        label: blockLabel(item.type, item.label, lang),
        hint: blockHint(item.type, item.hint, lang),
      })),
    [lang],
  );
  const sourceIntegrations = useMemo(
    () => (integrationsState.data?.items || []).filter((item: IntegrationTemplateRecord) => item.family === "source"),
    [integrationsState.data],
  );
  const actionIntegrations = useMemo(
    () => (integrationsState.data?.items || []).filter((item: IntegrationTemplateRecord) => item.family === "action"),
    [integrationsState.data],
  );
  const integrationBlocks = useMemo<BuilderBlockDefinition[]>(
    () =>
      [...sourceIntegrations, ...actionIntegrations].map((item) => ({
        type: String(item.block_type || item.id).replace(/-/g, "_"),
        label: String(item.title || item.id || "Integration block"),
        hint: String(item.description || "Runtime integration block."),
        integrationId: String(item.id || ""),
        group: String(item.group || "general"),
        mode: String(item.mode || "runtime"),
        protocols: item.protocols || [],
        family: item.family || "source",
        defaultStage: String(item.stage || DEFAULT_STAGE[String(item.block_type || item.id).replace(/-/g, "_")] || "ingest"),
      })),
    [actionIntegrations, sourceIntegrations],
  );
  const allBlockLibrary = useMemo<BuilderBlockDefinition[]>(
    () => [...localizedCoreBlockLibrary, ...integrationBlocks],
    [integrationBlocks, localizedCoreBlockLibrary],
  );
  const visibleBlockLibrary = useMemo<BuilderBlockDefinition[]>(
    () => (paletteView === "integrations" ? integrationBlocks : localizedCoreBlockLibrary),
    [integrationBlocks, localizedCoreBlockLibrary, paletteView],
  );
  const filteredBlockLibrary = useMemo<BuilderBlockDefinition[]>(() => {
    const token = String(paletteQuery || "").trim().toLowerCase();
    if (!token) return visibleBlockLibrary;
    return visibleBlockLibrary.filter((item) => {
      const meta = readDefinitionMeta(item);
      return [item.type, item.label, item.hint, meta.group, meta.mode, ...meta.protocols]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(token);
    });
  }, [paletteQuery, visibleBlockLibrary]);
  const selectedFamily = useMemo(
    () => BUILDER_FAMILIES.find((item) => item.id === kind) || BUILDER_FAMILIES[0],
    [kind],
  );
  const requestedKind = searchParams.get("kind") || "";
  const requestedTemplateId = searchParams.get("template") || "";
  const requestedTemplate = useMemo(
    () => integrationBlocks.find((item) => item.integrationId === requestedTemplateId) || null,
    [integrationBlocks, requestedTemplateId],
  );
  const correlationPacks = useMemo(() => correlationPacksState.data?.items || [], [correlationPacksState.data?.items]);
  const selectedCorrelationPack = (correlationPackDetailState.data?.item || null) as CorrelationPackRecord | null;
  const filteredCorrelationPacks = useMemo(() => {
    const query = String(correlationPackSearch || "").trim().toLowerCase();
    if (!query) return correlationPacks;
    return correlationPacks.filter((pack) =>
      [pack.pack_id, pack.title, pack.owner, pack.status, ...(pack.notes || [])]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(query),
    );
  }, [correlationPackSearch, correlationPacks]);
  const selectedCorrelationPackTitle = localizedPackTitle(
    correlationPackForm.pack_id,
    correlationPackForm.title || correlationPackForm.pack_id || (lang === "ru" ? "Безымянный пакет" : "Untitled draft pack"),
    lang,
  );

  useEffect(() => {
    if (requestedKind && BUILDER_FAMILIES.some((item) => item.id === requestedKind) && requestedKind !== kind) {
      setKind(requestedKind);
    }
    if (requestedKind === "integration") {
      setPaletteView("integrations");
    }
  }, [kind, requestedKind]);

  useEffect(() => {
    if (!selectedDraft) {
      setTitle("");
      setDescription("");
      setKind("detection");
      setBlocks([]);
      setSelectedBlockId("");
      return;
    }
    setTitle(builderDisplayText(String(selectedDraft.title || ""), lang));
    setDescription(builderDisplayText(String(selectedDraft.description || ""), lang));
    setKind(String(selectedDraft.kind || "generic"));
    const nextBlocks = (selectedDraft.blocks || []).map((item: BuilderBlockRecord) => ({
      ...item,
      stage: item.stage || DEFAULT_STAGE[item.type] || "publish",
      label: builderDisplayText(String(item.label || ""), lang),
      config: item.config || {},
    }));
    setBlocks(nextBlocks);
    setSelectedBlockId(String(nextBlocks?.[0]?.id || ""));
    setValidationOutput(null);
    setTestOutput(null);
    setPublishOutput(null);
  }, [selectedDraft, lang]);

  useEffect(() => {
    if (!selectedCorrelationPackId && correlationPacks.length) {
      setSelectedCorrelationPackId(String(correlationPacks[0].pack_id || ""));
    }
  }, [correlationPacks, selectedCorrelationPackId]);

  useEffect(() => {
    if (!selectedCorrelationPack) {
      return;
    }
    setCorrelationPackForm({
      pack_id: String(selectedCorrelationPack.pack_id || ""),
      title: String(selectedCorrelationPack.title || ""),
      version: String(selectedCorrelationPack.version || "1.0.0"),
      status: String(selectedCorrelationPack.status || "draft"),
      owner: String(selectedCorrelationPack.owner || "platform-release"),
      notes: [...(selectedCorrelationPack.notes || [])],
      stream_rules: [...(selectedCorrelationPack.stream_rules || [])],
      batch_rules: [...(selectedCorrelationPack.batch_rules || [])],
    });
    setSelectedCorrelationRuleId(Number((selectedCorrelationPack.stream_rules || [])[0]?.id || 0));
    setCorrelationValidationOutput(null);
    setCorrelationTestOutput(null);
    setCorrelationPublishOutput(null);
  }, [selectedCorrelationPack]);

  const selectedBlock = useMemo(
    () => blocks.find((item) => item.id === selectedBlockId) || null,
    [blocks, selectedBlockId],
  );
  const availableConnectionTargets = useMemo(
    () =>
      selectedBlock
        ? blocks.filter(
            (item) =>
              item.id !== selectedBlock.id &&
              !readBlockTargets(selectedBlock).includes(item.id),
          )
        : [],
    [blocks, selectedBlock],
  );

  const generatedPreview = useMemo(() => {
    const ordered = [...blocks].sort((left, right) => {
      const leftIndex = STAGES.findIndex((stage) => stage.id === left.stage);
      const rightIndex = STAGES.findIndex((stage) => stage.id === right.stage);
      return leftIndex - rightIndex;
    });
    const explicitEdges = ordered.flatMap((item) =>
      readBlockTargets(item)
        .filter((targetId) => ordered.some((candidate) => candidate.id === targetId))
        .map((targetId) => ({
          id: `edge-${item.id}-${targetId}`,
          source: item.id,
          target: targetId,
        })),
    );
    const graphEdges = explicitEdges.length
      ? explicitEdges
      : ordered.slice(0, -1).map((item, index) => ({
          id: `edge-${item.id}-${ordered[index + 1].id}`,
          source: item.id,
          target: ordered[index + 1].id,
        }));
    return {
      title,
      kind,
      graph: {
        nodes: ordered.map((item): BuilderGraphNode => ({
          id: item.id,
          type: item.type,
          stage: item.stage,
          label: builderDisplayLabel(item.label, lang),
        })),
        edges: graphEdges as BuilderGraphEdge[],
      },
      output: ordered
        .map(
          (item, index) =>
            `${index + 1}. [${stageLabel(item.stage, lang)}] ${blockLabel(item.type, item.type, lang)}: ${builderDisplayLabel(item.label, lang)}`,
        )
        .join("\n"),
    };
  }, [blocks, kind, lang, title]);

  const graphEdgeDetails = useMemo<BuilderGraphEdgeDetail[]>(
    () =>
      generatedPreview.graph.edges.map((edge) => {
        const source = generatedPreview.graph.nodes.find((node) => node.id === edge.source);
        const target = generatedPreview.graph.nodes.find((node) => node.id === edge.target);
        return {
          ...edge,
          sourceLabel: source?.label || edge.source,
          sourceStage: source?.stage || "n/a",
          targetLabel: target?.label || edge.target,
          targetStage: target?.stage || "n/a",
        };
      }),
    [generatedPreview.graph.edges, generatedPreview.graph.nodes],
  );
  const selectedEdge = useMemo(
    () => graphEdgeDetails.find((edge) => edge.id === selectedEdgeId) || null,
    [graphEdgeDetails, selectedEdgeId],
  );
  const filteredCorrelationRules = useMemo(() => {
    const query = String(correlationRuleSearch || "").trim().toLowerCase();
    if (!query) return correlationPackForm.stream_rules;
    return correlationPackForm.stream_rules.filter((rule) =>
      [
        rule.title,
        rule.severity,
        rule.status,
        rule.entity_field,
        rule.operator_action,
        rule.suppression_key,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(query),
    );
  }, [correlationPackForm.stream_rules, correlationRuleSearch]);
  const selectedCorrelationRule = useMemo(() => {
    const exact = correlationPackForm.stream_rules.find((item) => Number(item.id || 0) === selectedCorrelationRuleId) || null;
    if (!correlationRuleSearch) return exact || correlationPackForm.stream_rules[0] || null;
    return filteredCorrelationRules.find((item) => Number(item.id || 0) === selectedCorrelationRuleId)
      || filteredCorrelationRules[0]
      || exact
      || null;
  }, [correlationPackForm.stream_rules, correlationRuleSearch, filteredCorrelationRules, selectedCorrelationRuleId]);
  const correlationOverviewMetrics = useMemo(
    () => [
      {
        label: t(lang, { en: "Visible packs", ru: "Видимые пакеты" }),
        value: filteredCorrelationPacks.length,
        hint: t(lang, { en: "Filtered operational packs ready for inspection or publish.", ru: "Отфильтрованные рабочие пакеты, готовые к просмотру или публикации." }),
      },
      {
        label: t(lang, { en: "Selected rules", ru: "Правила пакета" }),
        value: correlationPackForm.stream_rules.length,
        hint: t(lang, { en: "Stream rules currently carried by the selected pack.", ru: "Потоковые правила, которые сейчас входят в выбранный пакет." }),
      },
      {
        label: t(lang, { en: "Visible rules", ru: "Видимые правила" }),
        value: filteredCorrelationRules.length,
        hint: t(lang, { en: "Rules remaining after the current search and focus filter.", ru: "Правила, оставшиеся после текущего поиска и фильтра фокуса." }),
      },
      {
        label: t(lang, { en: "Batch reviews", ru: "Пакетные проверки" }),
        value: correlationPackForm.batch_rules.length,
        hint: t(lang, { en: "Follow-up batch reviews attached to the current pack.", ru: "Дополнительные пакетные проверки, привязанные к текущему пакету." }),
      },
    ],
    [correlationPackForm.batch_rules.length, correlationPackForm.stream_rules.length, filteredCorrelationPacks.length, filteredCorrelationRules.length, lang],
  );

  useEffect(() => {
    if (!selectedBlock) {
      setConnectTargetId("");
      return;
    }
    setConnectTargetId((current) => {
      if (current && availableConnectionTargets.some((item) => item.id === current)) return current;
      return availableConnectionTargets[0]?.id || "";
    });
  }, [availableConnectionTargets, selectedBlock]);

  useEffect(() => {
    if (selectedEdgeId && !generatedPreview.graph.edges.some((edge) => edge.id === selectedEdgeId)) {
      setSelectedEdgeId("");
    }
  }, [generatedPreview.graph.edges, selectedEdgeId]);
  const graphCanvas = useMemo(() => {
      const stageSpacing = 182;
    const nodeSpacing = 84;
    const startX = 92;
    const startY = 70;
    const stageNodes = new Map<string, BuilderGraphNode[]>();
      for (const stage of stages) {
        stageNodes.set(stage.id, generatedPreview.graph.nodes.filter((node) => node.stage === stage.id));
      }
      const positions = new Map<string, { x: number; y: number }>();
      let maxRows = 1;
      stages.forEach((stage, stageIndex) => {
        const nodes = stageNodes.get(stage.id) || [];
      maxRows = Math.max(maxRows, nodes.length || 1);
      nodes.forEach((node, nodeIndex) => {
        positions.set(node.id, {
          x: startX + stageIndex * stageSpacing,
          y: startY + nodeIndex * nodeSpacing,
        });
      });
    });
      const width = startX * 2 + stageSpacing * Math.max(stages.length - 1, 1);
    const height = startY + maxRows * nodeSpacing + 70;
    return {
      width,
      height,
        stageHeaders: stages.map((stage, stageIndex) => ({
          ...stage,
          x: startX + stageIndex * stageSpacing,
        })),
      nodes: generatedPreview.graph.nodes.map((node) => ({
        ...node,
        position: positions.get(node.id) || { x: startX, y: startY },
      })),
      edges: generatedPreview.graph.edges.map((edge) => ({
        ...edge,
        source: positions.get(edge.source) || { x: startX, y: startY },
        target: positions.get(edge.target) || { x: startX, y: startY },
      })),
    };
  }, [generatedPreview.graph.edges, generatedPreview.graph.nodes, stages]);

  const integrationTypes = useMemo(() => new Set(integrationBlocks.map((item) => item.type)), [integrationBlocks]);
  const integrationUsage = useMemo(
    () => blocks.filter((item) => integrationTypes.has(item.type)),
    [blocks, integrationTypes],
  );

  const draftMetrics = useMemo(
    () => ({
      drafts: drafts.length,
      published: drafts.filter((item) => item.status === "published").length,
      blocks: blocks.length,
      stages: new Set(blocks.map((item) => item.stage)).size,
      edges: generatedPreview.graph.edges.length,
      integrations: integrationUsage.length,
    }),
    [blocks, drafts, generatedPreview.graph.edges.length, integrationUsage.length],
  );

  function createBlockFromDefinition(definition: BuilderBlockDefinition) {
    return {
      id: `${definition.type}-${Date.now()}-${Math.round(Math.random() * 1000)}`,
      type: definition.type,
      stage: definition.defaultStage || DEFAULT_STAGE[definition.type] || "publish",
      label: definition.label,
      config: definition.integrationId
        ? {
            integration_id: definition.integrationId,
            mode: definition.mode,
            protocols: definition.protocols || [],
            group: definition.group,
            family: definition.family,
          }
        : {},
    };
  }

  function buildStarterBlocks(familyId: string) {
    const starter = BUILDER_STARTERS[familyId] || BUILDER_STARTERS.detection;
    const seeded = starter.map((type, index) => {
      const definition = allBlockLibrary.find((item) => item.type === type);
      const block = definition
        ? createBlockFromDefinition(definition)
        : {
            id: `${type}-${Date.now()}-${index}`,
            type,
            stage: DEFAULT_STAGE[type] || "publish",
            label: type,
            config: {},
          };
      return {
        ...block,
        config: {
          ...(block.config || {}),
          links_to: [],
        },
      };
    });
    return seeded.map((block, index) => ({
      ...block,
      config: {
        ...(block.config || {}),
        links_to: index < seeded.length - 1 ? [seeded[index + 1].id] : [],
      },
    }));
  }

  function addBlock(type: string) {
    const definition = allBlockLibrary.find((item) => item.type === type);
    const next = definition
      ? createBlockFromDefinition(definition)
      : {
          id: `${type}-${Date.now()}`,
          type,
          stage: DEFAULT_STAGE[type] || "publish",
          label: type,
          config: {},
        };
    setBlocks((current) => [...current, next]);
    setSelectedBlockId(next.id);
  }

  function applyStarter(familyId: string) {
    const nextBlocks = buildStarterBlocks(familyId);
    setKind(familyId);
    setBlocks(nextBlocks);
    setSelectedBlockId(String(nextBlocks[0]?.id || ""));
    setSelectedEdgeId("");
    setValidationOutput(null);
    setTestOutput(null);
    setPublishOutput(null);
      setSaveState(t(lang, {
        en: `Applied ${familyLabel(familyId, "en")} starter`,
        ru: `Применен стартовый шаблон «${familyLabel(familyId, "ru")}»`,
      }));
  }

  function addIntegrationTemplate(definition: BuilderBlockDefinition | null) {
    if (!definition) return;
    const next = createBlockFromDefinition(definition);
    setKind("integration");
    setPaletteView("integrations");
    setBlocks((current) => [...current, next]);
    setSelectedBlockId(next.id);
  }

  function autoWireGraph() {
    setBlocks((current) => {
      const ordered = [...current].sort((left, right) => {
        const leftStage = STAGES.findIndex((stage) => stage.id === left.stage);
        const rightStage = STAGES.findIndex((stage) => stage.id === right.stage);
        if (leftStage !== rightStage) return leftStage - rightStage;
        return String(left.label || left.type).localeCompare(String(right.label || right.type));
      });
      return ordered.map((item, index) => ({
        ...item,
        config: {
          ...(item.config || {}),
          links_to: index < ordered.length - 1 ? [ordered[index + 1].id] : [],
        },
      }));
    });
    setSelectedEdgeId("");
    setSaveState(t(lang, { en: "Auto-wired graph", ru: "Граф автоматически связан" }));
  }

  function clearEdges() {
    setBlocks((current) =>
      current.map((item) => ({
        ...item,
        config: {
          ...(item.config || {}),
          links_to: [],
        },
      })),
    );
    setSelectedEdgeId("");
    setSaveState(t(lang, { en: "Cleared graph edges", ru: "Связи графа очищены" }));
  }

  function removeBlock(blockId: string) {
    setBlocks((current) =>
      current
        .filter((item) => item.id !== blockId)
        .map((item) => ({
          ...item,
          config: {
            ...(item.config || {}),
            links_to: readBlockTargets(item).filter((targetId) => targetId !== blockId),
          },
        })),
    );
    if (selectedBlockId === blockId) {
      setSelectedBlockId("");
    }
    setSelectedEdgeId("");
  }

  function duplicateBlock(blockId: string) {
    const source = blocks.find((item) => item.id === blockId);
    if (!source) return;
    const next = {
      ...source,
      id: `${source.type}-${Date.now()}-${Math.round(Math.random() * 1000)}`,
      label: t(lang, { en: `${source.label} copy`, ru: `${source.label} копия` }),
      config: {
        ...(source.config || {}),
        links_to: [],
      },
    };
    setBlocks((current) => [...current, next]);
    setSelectedBlockId(next.id);
  }

  function moveBlock(targetIndex: number) {
    if (dragIndex === null || dragIndex === targetIndex) return;
    setBlocks((current) => {
      const next = [...current];
      const [moved] = next.splice(dragIndex, 1);
      next.splice(targetIndex, 0, moved);
      return next;
    });
    setDragIndex(null);
  }

  function moveBlockToStage(blockId: string, stage: string) {
    setBlocks((current) => current.map((item) => (item.id === blockId ? { ...item, stage } : item)));
    setDragIndex(null);
  }

  function addEdge(sourceId: string, targetId: string) {
    if (!sourceId || !targetId || sourceId === targetId) return;
    setBlocks((current) =>
      current.map((item) =>
        item.id === sourceId
          ? {
              ...item,
              config: {
                ...(item.config || {}),
                links_to: Array.from(new Set([...readBlockTargets(item), targetId])),
              },
            }
          : item,
      ),
    );
    setSelectedEdgeId(`edge-${sourceId}-${targetId}`);
    setConnectTargetId("");
  }

  function removeEdge(edgeId: string) {
    const edge = generatedPreview.graph.edges.find((item) => item.id === edgeId);
    if (!edge) return;
    const { source: sourceId, target: targetId } = edge;
    setBlocks((current) =>
      current.map((item) =>
        item.id === sourceId
          ? {
              ...item,
              config: {
                ...(item.config || {}),
                links_to: readBlockTargets(item).filter((candidate) => candidate !== targetId),
              },
            }
          : item,
      ),
    );
    setSelectedEdgeId("");
  }

  async function saveDraft(nextStatus?: string) {
    setSaveState("Saving draft...");
    try {
      const payload = await api.saveBuilderDraft({
        id: selectedDraft?.id || "",
        title,
        description,
        kind,
        status: nextStatus || selectedDraft?.status || "draft",
        blocks,
      });
      setDrafts((current) => upsertDraft(current, payload));
      setSelectedDraftId(String(payload.id || ""));
      setSaveState(`Saved ${payload.title}`);
      return payload;
    } catch (error) {
      const message = error instanceof Error ? error.message : t(lang, { en: "Save failed", ru: "Ошибка сохранения" });
      setSaveState(message);
      throw error;
    }
  }

  async function validateDraft() {
    try {
      const payload = await api.validateBuilder({ title, description, kind, blocks });
      setValidationOutput(payload);
      setSaveState(payload.valid ? t(lang, { en: "Validation passed.", ru: "Проверка пройдена." }) : t(lang, { en: "Validation returned errors.", ru: "Проверка вернула ошибки." }));
    } catch (error) {
      setValidationOutput({ error: error instanceof Error ? error.message : t(lang, { en: "Validation failed", ru: "Ошибка проверки" }) });
    }
  }

  async function testDraft() {
    try {
      const payload = await api.testBuilder({ title, description, kind, blocks });
      setTestOutput(payload);
      setSaveState(payload.valid ? t(lang, { en: "Builder test completed.", ru: "Тест конструктора завершен." }) : t(lang, { en: "Builder test returned validation errors.", ru: "Тест конструктора вернул ошибки проверки." }));
    } catch (error) {
      setTestOutput({ error: error instanceof Error ? error.message : t(lang, { en: "Test failed", ru: "Ошибка теста" }) });
    }
  }

  async function publishDraft() {
    try {
      const saved = await saveDraft("draft");
      const payload = await api.publishBuilder(String(saved.id));
      const mergedDraft = {
        ...saved,
        status: payload.status,
        version: payload.version,
        published_ts: payload.published_ts,
        updated_ts: payload.published_ts,
        history: [
          {
            ts: payload.published_ts,
            action: "publish",
            version: payload.version,
            status: payload.status,
          },
          ...((saved.history || []).slice(0, 11)),
        ],
      };
      setDrafts((current) => upsertDraft(current, mergedDraft));
      setPublishOutput(payload);
      setSaveState(`Published ${saved.title}`);
    } catch (error) {
      setPublishOutput({ error: error instanceof Error ? error.message : "Publish failed" });
    }
  }

  const switchWorkspace = useCallback((nextWorkspace: BuilderWorkspace) => {
    setWorkspace(nextWorkspace);
    const next = new URLSearchParams(searchParams);
    if (nextWorkspace === "correlation") {
      next.set("workspace", "correlation");
    } else {
      next.delete("workspace");
    }
    setSearchParams(next, { replace: true });
  }, [searchParams, setSearchParams]);

  function createCorrelationPack() {
    setSelectedCorrelationPackId("");
    setCorrelationPackForm(emptyCorrelationPack());
    setSelectedCorrelationRuleId(0);
      setCorrelationSaveState(t(lang, { en: "New correlation pack", ru: "Новый пакет корреляции" }));
    setCorrelationValidationOutput(null);
    setCorrelationTestOutput(null);
    setCorrelationPublishOutput(null);
    setCorrelationPackEditorOpen(true);
  }

  function createCorrelationRule() {
    const nextId = Math.max(2400, ...correlationPackForm.stream_rules.map((item) => Number(item.id || 0))) + 1;
    const rule: CorrelationRuleRecord = {
      id: nextId,
      title: t(lang, { en: "New correlation rule", ru: "Новое правило корреляции" }),
      severity: "medium",
      window_s: 300,
      threshold: 1,
      entity_field: "host.name",
      suppression_key: "host.name + service.name + rule-family",
      status: "draft",
      operator_action: "",
      sigma_yaml: "title: New correlation rule\nid: sigma-new-correlation-rule\nstatus: experimental\nlogsource:\n  product: custom\n  service: runtime\ndetection:\n  selection:\n    event.provider: custom.runtime\n  condition: selection\nlevel: medium\n",
    };
    setCorrelationPackForm((current) => ({ ...current, stream_rules: [...current.stream_rules, rule] }));
    setSelectedCorrelationRuleId(nextId);
    setCorrelationRuleEditorOpen(true);
  }

  function updateCorrelationRule(ruleId: number, patch: Partial<CorrelationRuleRecord>) {
    setCorrelationPackForm((current) => ({
      ...current,
      stream_rules: current.stream_rules.map((item) => (Number(item.id || 0) === ruleId ? { ...item, ...patch } : item)),
    }));
  }

  function removeCorrelationRule(ruleId: number) {
    setCorrelationPackForm((current) => ({
      ...current,
      stream_rules: current.stream_rules.filter((item) => Number(item.id || 0) !== ruleId),
    }));
    if (selectedCorrelationRuleId === ruleId) {
      setSelectedCorrelationRuleId(0);
    }
    setCorrelationRuleEditorOpen(false);
  }

  async function saveCorrelationPackAction() {
    setCorrelationSaveState(t(lang, { en: "Saving pack...", ru: "Сохраняю пакет..." }));
    try {
      const payload = await api.saveCorrelationPack(correlationPackForm as unknown as Record<string, unknown>);
      setSelectedCorrelationPackId(String(payload.pack_id || ""));
      setCorrelationRefreshToken((current) => current + 1);
      setCorrelationValidationOutput((payload.validation || null) as RuntimeBlob | null);
      setCorrelationSaveState(
        t(lang, {
          en: `Saved ${payload.title || payload.pack_id}`,
          ru: `Пакет сохранён: ${payload.title || payload.pack_id}`,
        }),
      );
      setCorrelationPackEditorOpen(false);
    } catch (error) {
      setCorrelationSaveState(error instanceof Error ? error.message : t(lang, { en: "Correlation pack save failed", ru: "Ошибка сохранения пакета корреляции" }));
    }
  }

  async function validateCorrelationPackAction() {
    try {
      const payload = await api.validateCorrelationPack(correlationPackForm.pack_id || "draft-pack", correlationPackForm as unknown as Record<string, unknown>);
      setCorrelationValidationOutput(payload as RuntimeBlob);
      setCorrelationSaveState(payload.valid ? t(lang, { en: "Pack validation passed", ru: "Пакет прошел проверку" }) : t(lang, { en: "Pack validation returned issues", ru: "Пакет вернул замечания проверки" }));
      setCorrelationOpsOpen(true);
    } catch (error) {
      setCorrelationValidationOutput({ error: error instanceof Error ? error.message : t(lang, { en: "Correlation pack validation failed", ru: "Ошибка проверки пакета корреляции" }) });
      setCorrelationOpsOpen(true);
    }
  }

  async function testCorrelationPackAction() {
    try {
      const payload = await api.testCorrelationPack(correlationPackForm.pack_id || "draft-pack", correlationPackForm as unknown as Record<string, unknown>);
      setCorrelationTestOutput(payload);
      setCorrelationSaveState(payload.status === "ok" ? t(lang, { en: "Correlation pack test passed", ru: "Тест пакета корреляции пройден" }) : t(lang, { en: "Correlation pack test returned degraded results", ru: "Тест пакета корреляции вернул деградацию" }));
      setCorrelationOpsOpen(true);
    } catch (error) {
      setCorrelationTestOutput({
        status: "error",
        validation: { valid: false },
          items: [{ compile_error: error instanceof Error ? error.message : t(lang, { en: "Correlation pack test failed", ru: "Ошибка теста пакета корреляции" }) }],
      });
      setCorrelationOpsOpen(true);
    }
  }

  async function publishCorrelationPackAction() {
    if (!correlationPackForm.pack_id) {
      await saveCorrelationPackAction();
    }
    try {
      const payload = await api.publishCorrelationPack(correlationPackForm.pack_id);
      setCorrelationPublishOutput(payload as RuntimeBlob);
      setCorrelationRefreshToken((current) => current + 1);
      setCorrelationSaveState(t(lang, { en: `Published ${correlationPackForm.pack_id}`, ru: `Опубликован пакет ${correlationPackForm.pack_id}` }));
      setCorrelationOpsOpen(true);
    } catch (error) {
      setCorrelationPublishOutput({ error: error instanceof Error ? error.message : t(lang, { en: "Correlation pack publish failed", ru: "Ошибка публикации пакета корреляции" }) });
      setCorrelationOpsOpen(true);
    }
  }

  const selectedHistory = useMemo(
    () =>
      (selectedDraft?.history || []).map((item) => ({
        ...item,
        action: builderHistoryActionLabel(String(item.action || "save"), lang),
        status: builderStatusLabel(String(item.status || "draft"), lang),
      })),
    [lang, selectedDraft],
  );
  const catalogData = catalog.data || {};
  const catalogCounts = {
    rules: catalogData.detection_rules?.length || 0,
    normalizers: catalogData.normalizers?.length || 0,
    active: catalogData.active_lists?.length || 0,
    ti: catalogData.threat_intel?.length || 0,
  };

  return (
    <AsyncGate states={[catalog, draftsState, integrationsState]} loadingMessage={t(lang, { en: "Loading builder workspace...", ru: "Загрузка рабочего пространства конструкторов..." })}>
      <div className="react-page react-page-builders">
      <SectionIntro
        kicker={t(lang, { en: "Builders", ru: "Конструкторы" })}
        title={t(lang, { en: "Operational content builders", ru: "Операционный конструктор контента" })}
        subtitle={t(lang, {
          en: "Assemble detection flows, normalization chains and correlation packs from a calmer, window-driven workspace.",
          ru: "Собирайте потоки детектирования, цепочки нормализации и пакеты корреляции из более спокойной оконной рабочей области.",
        })}
        icon="builders"
        actions={
          <div className="react-actions react-wrap">
            <div className="react-segmented">
              <button type="button" className={workspace === "graph" ? "active" : ""} onClick={() => switchWorkspace("graph")}>{t(lang, { en: "Graph", ru: "Граф" })}</button>
              <button type="button" className={workspace === "correlation" ? "active" : ""} onClick={() => switchWorkspace("correlation")}>{t(lang, { en: "Correlation", ru: "Корреляция" })}</button>
            </div>
            {workspace === "graph" ? (
              <>
            <button type="button" className="react-icon-button" onClick={() => setSettingsOpen(true)} aria-label={t(lang, { en: "Builder page settings", ru: "Настройки раздела конструкторов" })}>
              <Icon name="control" size={15} />
            </button>
            <button type="button" className="react-link-button" onClick={() => {
              setSelectedDraftId("");
              setTitle(t(lang, { en: "Untitled draft", ru: "Новый черновик" }));
              setDescription("");
              setKind("detection");
              setBlocks([]);
              setSelectedBlockId("");
            }}>
              {t(lang, { en: "New draft", ru: "Новый черновик" })}
            </button>
            <button type="button" className="react-primary-button" onClick={() => void saveDraft()}>
              {t(lang, { en: "Save", ru: "Сохранить" })}
            </button>
            <button type="button" className="react-link-button" onClick={() => void validateDraft()}>
              {t(lang, { en: "Validate", ru: "Проверить" })}
            </button>
            <button type="button" className="react-link-button" onClick={() => void testDraft()}>
              {t(lang, { en: "Test", ru: "Тест" })}
            </button>
            <button type="button" className="react-link-button" onClick={() => void publishDraft()}>
              {t(lang, { en: "Publish", ru: "Опубликовать" })}
            </button>
              </>
            ) : (
              <>
                <button type="button" className="react-link-button" onClick={createCorrelationPack}>{t(lang, { en: "New pack", ru: "Новый пакет" })}</button>
                <button type="button" className="react-primary-button" onClick={() => setCorrelationPackEditorOpen(true)}>{t(lang, { en: "Pack window", ru: "Окно пакета" })}</button>
                <button type="button" className="react-link-button" onClick={() => setCorrelationRuleEditorOpen(true)} disabled={!selectedCorrelationRule}>{t(lang, { en: "Rule window", ru: "Окно правила" })}</button>
                <button type="button" className="react-link-button" onClick={() => setCorrelationOpsOpen(true)}>{t(lang, { en: "Lifecycle window", ru: "Окно жизненного цикла" })}</button>
              </>
            )}
          </div>
        }
      />

      {workspace === "graph" ? (
        <div className="react-grid react-grid-5">
          <StatCard label={t(lang, { en: "Rules", ru: "Правила" })} value={catalogCounts.rules} hint={t(lang, { en: "Detection content accessible for composition and testing.", ru: "Контент детектирования, доступный для сборки и тестирования." })} />
          <StatCard label={t(lang, { en: "Normalizers", ru: "Нормализаторы" })} value={catalogCounts.normalizers} hint={t(lang, { en: "Normalization assets ready for staged pipelines.", ru: "Нормализаторы, готовые для поэтапных конвейеров." })} />
          <StatCard label={t(lang, { en: "Active lists", ru: "Активные списки" })} value={catalogCounts.active} hint={t(lang, { en: "Allow, deny and watch lists available for enrich blocks.", ru: "Списки allow, deny и watch, доступные для блоков обогащения." })} />
          <StatCard label={t(lang, { en: "Drafts", ru: "Черновики" })} value={draftMetrics.drafts} hint={t(lang, { en: "Saved builder drafts stored on the server.", ru: "Сохраненные черновики конструктора на сервере." })} />
          <StatCard label={t(lang, { en: "Published", ru: "Опубликовано" })} value={draftMetrics.published} hint={t(lang, { en: "Drafts already promoted to published runtime state.", ru: "Черновики, уже переведенные в опубликованное runtime-состояние." })} />
          <StatCard label={t(lang, { en: "Integrations", ru: "Интеграции" })} value={integrationBlocks.length} hint={t(lang, { en: "Webhook, database, API pull and Telegram templates exposed to the builder.", ru: "Шаблоны webhook, базы данных, API pull и Telegram, доступные в конструкторе." })} />
        </div>
      ) : (
        <div className="react-grid react-grid-5">
          <StatCard label={t(lang, { en: "Packs", ru: "Пакеты" })} value={correlationPacks.length} hint={t(lang, { en: "Operational correlation packs available for authoring and publish.", ru: "Рабочие пакеты корреляции, доступные для редактирования и публикации." })} />
          <StatCard label={t(lang, { en: "Active stream rules", ru: "Активные потоковые правила" })} value={correlationPacks.reduce((sum, item) => sum + Number(item.active_stream_rules || 0), 0)} hint={t(lang, { en: "Rules currently marked active across the available packs.", ru: "Правила, которые сейчас помечены как активные во всех доступных пакетах." })} />
          <StatCard label={t(lang, { en: "Selected rules", ru: "Правила пакета" })} value={correlationPackForm.stream_rules.length} hint={t(lang, { en: "Rules currently carried by the selected pack.", ru: "Правила, которые сейчас входят в выбранный пакет." })} />
          <StatCard label={t(lang, { en: "Batch reviews", ru: "Пакетные проверки" })} value={correlationPackForm.batch_rules.length} hint={t(lang, { en: "Batch review metadata attached to the selected pack.", ru: "Метаданные пакетных проверок, привязанных к выбранному пакету." })} />
          <StatCard label={t(lang, { en: "Lifecycle", ru: "Жизненный цикл" })} value={correlationPackForm.status || "draft"} hint={t(lang, { en: "Draft, validate, test, publish and rollback for operational packs.", ru: "Черновик, проверка, тест, публикация и откат для рабочих пакетов." })} />
        </div>
      )}

      {workspace === "graph" ? (
        <>
      <div className="react-split react-split-xl">
        <section className="react-card react-window-launcher">
          <PanelHeader
            title={t(lang, { en: "Builder mode", ru: "Режим конструктора" })}
            subtitle={t(lang, {
              en: "Pick a family, apply a starter and keep the main workspace focused on the active flow.",
              ru: "Выберите семейство, примените стартовый шаблон и держите основную рабочую область сфокусированной на текущем потоке.",
            })}
            icon="builders"
            actions={
              <div className="react-actions react-wrap">
                <button type="button" className="react-link-button" onClick={() => applyStarter(kind)}>
                  {t(lang, { en: "Use starter", ru: "Применить шаблон" })}
                </button>
                <button type="button" className="react-link-button" onClick={autoWireGraph}>
                  {t(lang, { en: "Auto-wire", ru: "Автосвязь" })}
                </button>
              </div>
            }
          />
          <div className="react-chip-grid">
            {BUILDER_FAMILIES.map((family) => (
              <button
                key={family.id}
                type="button"
                className={`react-chip-card react-chip-card-button ${kind === family.id ? "active" : ""}`}
                onClick={() => setKind(family.id)}
              >
                <div className="react-top-kicker">{t(lang, { en: "Family", ru: "Семейство" })}</div>
                <strong>{familyLabel(family.id, lang)}</strong>
                <span>{familyHint(family.id, lang)}</span>
              </button>
            ))}
          </div>
          <div className="react-grid react-grid-4 react-builder-summary-grid">
            <StatCard label={t(lang, { en: "Drafts", ru: "Черновики" })} value={draftMetrics.drafts} hint={t(lang, { en: "Saved graph drafts available on the server.", ru: "Сохраненные черновики графов на сервере." })} />
            <StatCard label={t(lang, { en: "Published", ru: "Опубликовано" })} value={draftMetrics.published} hint={t(lang, { en: "Drafts already promoted into runtime.", ru: "Черновики, уже выведенные в runtime." })} />
            <StatCard label={t(lang, { en: "Blocks", ru: "Блоки" })} value={draftMetrics.blocks} hint={t(lang, { en: "Nodes currently assembled in the selected draft.", ru: "Узлы, собранные в выбранном черновике." })} />
            <StatCard label={t(lang, { en: "Integrations", ru: "Интеграции" })} value={integrationUsage.length} hint={t(lang, { en: "Shared integration templates currently embedded into the flow.", ru: "Шаблоны интеграций, уже встроенные в текущий поток." })} />
          </div>
          {requestedTemplate ? (
            <section className="react-card react-card-nested">
              <PanelHeader
                title={t(lang, { en: "Suggested integration template", ru: "Предлагаемый шаблон интеграции" })}
                subtitle={t(lang, {
                  en: "This builder was opened from the shared integration catalog. Insert the template or continue with the current draft.",
                  ru: "Этот конструктор открыт из общего каталога интеграций. Вставьте шаблон или продолжайте работу с текущим черновиком.",
                })}
                icon="sources"
                actions={
                  <div className="react-actions react-wrap">
                    <button type="button" className="react-link-button" onClick={() => addIntegrationTemplate(requestedTemplate)}>
                      {t(lang, { en: "Insert template", ru: "Вставить шаблон" })}
                    </button>
                    <Link className="react-link-button" to="/sources">
                      {t(lang, { en: "Back to sources", ru: "К источникам" })}
                    </Link>
                  </div>
                }
              />
              <DrawerFieldGrid>
                <KeyValue label={t(lang, { en: "Template", ru: "Шаблон" })} value={requestedTemplate.label} />
                <KeyValue label={t(lang, { en: "Family", ru: "Семейство" })} value={requestedTemplate.family || "source"} />
                <KeyValue label={t(lang, { en: "Group", ru: "Группа" })} value={requestedTemplate.group || t(lang, { en: "general", ru: "общее" })} />
                <KeyValue label={t(lang, { en: "Mode", ru: "Режим" })} value={requestedTemplate.mode || t(lang, { en: "runtime", ru: "рабочий контур" })} />
                <KeyValue label={t(lang, { en: "Protocols", ru: "Протоколы" })} value={(requestedTemplate.protocols || []).join(", ") || t(lang, { en: "n/a", ru: "н/д" })} />
                <KeyValue label={t(lang, { en: "Default stage", ru: "Этап по умолчанию" })} value={stageLabel(requestedTemplate.defaultStage || "ingest", lang)} />
              </DrawerFieldGrid>
            </section>
          ) : null}
        </section>
        <section className="react-card">
          <PanelHeader
            title={t(lang, { en: "Flow topology", ru: "Топология потока" })}
            subtitle={t(lang, {
              en: "One overview layer for stages, links and integration usage. The detailed editing stays below and in side windows.",
              ru: "Один обзорный слой для этапов, связей и используемых интеграций. Детальное редактирование остается ниже и в боковых окнах.",
            })}
            icon="builders"
            actions={<button type="button" className="react-link-button" onClick={clearEdges}>{t(lang, { en: "Clear edges", ru: "Очистить связи" })}</button>}
          />
          <div className="react-card react-card-nested">
            <PanelHeader
              title={t(lang, { en: "Canvas", ru: "Полотно" })}
              subtitle={t(lang, {
                en: "Stage rails stay fixed while nodes and links reflect the current draft.",
                ru: "Этапы закреплены как рабочие рельсы, а узлы и связи отражают текущее состояние черновика.",
              })}
            />
            <div className="react-builder-graph-shell">
              <svg
                className="react-builder-graph-svg"
                viewBox={`0 0 ${graphCanvas.width} ${graphCanvas.height}`}
                role="img"
                aria-label={t(lang, { en: "Builder graph preview", ru: "Предпросмотр графа конструктора" })}
              >
                {graphCanvas.stageHeaders.map((stage) => (
                  <g key={stage.id}>
                    <text x={stage.x} y="26" textAnchor="middle" className="react-builder-graph-label">
                      {stage.label}
                    </text>
                    <line
                      x1={stage.x}
                      y1="42"
                      x2={stage.x}
                      y2={graphCanvas.height - 24}
                      className="react-builder-graph-rail"
                    />
                  </g>
                ))}
                {graphCanvas.edges.map((edge) => (
                  <path
                    key={edge.id}
                    d={`M ${edge.source.x} ${edge.source.y} C ${edge.source.x + 44} ${edge.source.y}, ${edge.target.x - 44} ${edge.target.y}, ${edge.target.x} ${edge.target.y}`}
                    className={`react-builder-graph-edge ${selectedEdgeId === edge.id ? "active" : ""}`}
                    onClick={() => setSelectedEdgeId(edge.id)}
                  />
                ))}
                {graphCanvas.nodes.map((node) => (
                  <g
                    key={node.id}
                    className={`react-builder-graph-node ${selectedBlockId === node.id ? "active" : ""}`}
                    onClick={() => setSelectedBlockId(node.id)}
                  >
                    <rect x={node.position.x - 56} y={node.position.y - 24} rx="16" ry="16" width="112" height="48" />
                    <text x={node.position.x} y={node.position.y - 4} textAnchor="middle" className="react-builder-graph-node-title">
                      {builderDisplayLabel(node.label, lang)}
                    </text>
                    <text x={node.position.x} y={node.position.y + 12} textAnchor="middle" className="react-builder-graph-node-subtitle">
                      {blockLabel(node.type, node.type, lang)}
                    </text>
                  </g>
                ))}
              </svg>
            </div>
          </div>
          <div className="react-grid react-grid-2 react-builder-summary-grid" style={{ marginTop: 16 }}>
            <section className="react-card react-card-nested">
              <PanelHeader title={t(lang, { en: "Connections", ru: "Связи" })} subtitle={t(lang, { en: "Execution order and currently focused edge.", ru: "Порядок исполнения и текущее выбранное ребро." })} />
              <div className="react-list react-list-compact react-builder-edge-list">
                {graphEdgeDetails.length ? (
                  graphEdgeDetails.map((edge) => (
                    <div key={edge.id} className="react-builder-edge-item">
                      <strong>{builderDisplayLabel(edge.sourceLabel, lang)}</strong>
                      <span>{stageLabel(edge.sourceStage, lang)} {"->"} {stageLabel(edge.targetStage, lang)}</span>
                      <span>{builderDisplayLabel(edge.targetLabel, lang)}</span>
                    </div>
                  ))
                ) : (
                  <EmptyState message={t(lang, { en: "Add more than one node to see graph edges.", ru: "Добавьте больше одного узла, чтобы увидеть связи графа." })} />
                )}
              </div>
              {selectedEdge ? (
                <DrawerFieldGrid>
                  <KeyValue label={t(lang, { en: "Source", ru: "Источник" })} value={builderDisplayLabel(selectedEdge.sourceLabel, lang)} />
                  <KeyValue label={t(lang, { en: "Target", ru: "Цель" })} value={builderDisplayLabel(selectedEdge.targetLabel, lang)} />
                  <KeyValue label={t(lang, { en: "Source stage", ru: "Этап источника" })} value={stageLabel(selectedEdge.sourceStage, lang)} />
                  <KeyValue label={t(lang, { en: "Target stage", ru: "Этап цели" })} value={stageLabel(selectedEdge.targetStage, lang)} />
                </DrawerFieldGrid>
              ) : null}
            </section>
            <section className="react-card react-card-nested">
              <PanelHeader title={t(lang, { en: "Integration usage", ru: "Использование интеграций" })} subtitle={t(lang, { en: "Templates from the shared catalog already participating in the current draft.", ru: "Шаблоны из общего каталога, уже участвующие в текущем черновике." })} />
              <div className="react-chip-grid">
                {integrationUsage.length ? (
                  integrationUsage.map((item) => (
                    <div key={item.id} className="react-chip-card">
                      <div className="react-top-kicker">{stageLabel(item.stage, lang)}</div>
                      <strong>{builderDisplayLabel(item.label, lang)}</strong>
                      <span>{blockLabel(item.type, item.type, lang)}</span>
                    </div>
                  ))
                ) : (
                  <div className="react-chip-card">
                    <div className="react-top-kicker">{t(lang, { en: "Integrations", ru: "Интеграции" })}</div>
                    <strong>{t(lang, { en: "None selected", ru: "Пока не выбраны" })}</strong>
                    <span>{t(lang, { en: "Add webhook, database, REST or bot nodes from the palette below.", ru: "Добавьте webhook, базу данных, REST или bot-узлы из палитры ниже." })}</span>
                  </div>
                )}
              </div>
            </section>
          </div>
        </section>
      </div>

      <div className="react-split react-split-xl">
        <section className="react-card">
          <PanelHeader
            title={t(lang, { en: "Graph workspace", ru: "Рабочая область графа" })}
            subtitle={t(lang, {
              en: "A staged editor from ingest to publish. Drag blocks across lanes and inspect each node in the side window.",
              ru: "Редактор по этапам от приема данных до публикации. Перетаскивайте блоки между полосами и открывайте детали узла в боковом окне.",
            })}
            actions={
              <div className="react-actions react-wrap">
                <select className="react-select react-select-inline" value={selectedDraft?.id || ""} onChange={(event) => setSelectedDraftId(event.target.value)}>
                  {drafts.map((item) => (
                    <option value={item.id} key={item.id}>{builderDisplayText(item.title, lang)}</option>
                  ))}
                </select>
                <select className="react-select react-select-inline" value={kind} onChange={(event) => setKind(event.target.value)}>
                  <option value="detection">{familyLabel("detection", lang)}</option>
                  <option value="normalizer">{familyLabel("normalizer", lang)}</option>
                  <option value="active-list">{familyLabel("active-list", lang)}</option>
                  <option value="threat-intel">{familyLabel("threat-intel", lang)}</option>
                  <option value="integration">{familyLabel("integration", lang)}</option>
                </select>
              </div>
            }
          />

          <div className="react-form-grid">
            <input className="react-input" value={title} onChange={(event) => setTitle(event.target.value)} placeholder={t(lang, { en: "Draft title", ru: "Название черновика" })} />
            <input className="react-input" value={description} onChange={(event) => setDescription(event.target.value)} placeholder={t(lang, { en: "Description", ru: "Описание" })} />
            {saveState ? <span className="react-inline-note">{saveState}</span> : null}
          </div>

          <div className="react-block-editor">
            <div className="react-block-palette">
              <div className="react-block-palette-title">{t(lang, { en: "Palette", ru: "Палитра" })}</div>
              <div className="react-segmented">
                <button type="button" className={paletteView === "core" ? "active" : ""} onClick={() => setPaletteView("core")}>
                  {t(lang, { en: "Core", ru: "База" })}
                </button>
                <button type="button" className={paletteView === "integrations" ? "active" : ""} onClick={() => setPaletteView("integrations")}>
                  {t(lang, { en: "Integrations", ru: "Интеграции" })}
                </button>
              </div>
              <input
                className="react-input"
                value={paletteQuery}
                onChange={(event) => setPaletteQuery(event.target.value)}
                placeholder={paletteView === "integrations" ? t(lang, { en: "Find integration block...", ru: "Найти интеграционный блок..." }) : t(lang, { en: "Find core block...", ru: "Найти базовый блок..." })}
              />
              {filteredBlockLibrary.map((item) => {
                const meta = readDefinitionMeta(item);
                return (
                  <button type="button" className="react-list-item" key={item.type} onClick={() => addBlock(item.type)}>
                    <strong>{builderDisplayLabel(item.label, lang)}</strong>
                    <span>{item.hint}</span>
                    {meta.group || meta.protocols.length ? (
                      <span className="react-inline-note">
                        {[meta.group, meta.mode, ...meta.protocols.slice(0, 2)].filter(Boolean).join(" / ")}
                      </span>
                    ) : null}
                  </button>
                );
              })}
              {!filteredBlockLibrary.length ? <EmptyState message={t(lang, { en: "No blocks match the current filter.", ru: "Нет блоков, подходящих под текущий фильтр." })} /> : null}
            </div>
            <div className="react-block-canvas">
              {stages.map((stage) => {
                const laneBlocks = blocks.filter((item) => item.stage === stage.id);
                return (
                  <div
                    key={stage.id}
                    className="react-builder-lane"
                    onDragOver={(event) => event.preventDefault()}
                    onDrop={() => {
                      if (dragIndex === null) return;
                      const moved = blocks[dragIndex];
                      if (moved) moveBlockToStage(moved.id, stage.id);
                    }}
                  >
                    <div className="react-builder-lane-head">
                      <div>
                        <div className="react-top-kicker">{t(lang, { en: "Stage", ru: "Этап" })}</div>
                        <strong>{stage.label}</strong>
                      </div>
                      <span>{stage.hint}</span>
                    </div>
                    <div className="react-builder-lane-body">
                      {laneBlocks.map((item) => {
                        const index = blocks.findIndex((row) => row.id === item.id);
                        return (
                          <div
                            key={item.id}
                            className={`react-block-node ${selectedBlockId === item.id ? "active" : ""}`}
                            draggable
                            onDragStart={() => setDragIndex(index)}
                            onDragOver={(event) => event.preventDefault()}
                            onDrop={() => moveBlock(index)}
                            onClick={() => setSelectedBlockId(item.id)}
                          >
                            <div className="react-block-node-kicker">{blockLabel(item.type, item.type, lang)}</div>
                            <strong>{builderDisplayLabel(item.label, lang)}</strong>
                            <span>{stageLabel(item.stage, lang)} / {Object.keys(item.config || {}).length} {t(lang, { en: "config keys", ru: "полей конфигурации" })}</span>
                          </div>
                        );
                      })}
                      {!laneBlocks.length ? <div className="react-builder-lane-empty">{t(lang, { en: "Drop blocks here", ru: "Перетащите блок сюда" })}</div> : null}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </section>

        <aside className="react-card react-drawer">
          {selectedBlock ? (
            <>
              <PanelHeader
                title={builderDisplayLabel(selectedBlock.label, lang)}
                subtitle={`${t(lang, { en: "Type", ru: "Тип" })}: ${blockLabel(selectedBlock.type, selectedBlock.type, lang)}`}
                actions={
                  <div className="react-actions react-wrap">
                    <button type="button" className="react-link-button" onClick={() => duplicateBlock(selectedBlock.id)}>{t(lang, { en: "Duplicate", ru: "Дублировать" })}</button>
                    <button type="button" className="react-link-button" onClick={() => removeBlock(selectedBlock.id)}>{t(lang, { en: "Remove block", ru: "Удалить блок" })}</button>
                  </div>
                }
              />
              <DrawerFieldGrid>
                <KeyValue label={t(lang, { en: "Draft status", ru: "Статус черновика" })} value={<StatusBadge value={selectedDraft?.status || "draft"} />} />
                <KeyValue label={t(lang, { en: "Version", ru: "Версия" })} value={selectedDraft?.version || 1} />
                <KeyValue label={t(lang, { en: "Updated", ru: "Обновлен" })} value={selectedDraft?.updated_ts || t(lang, { en: "n/a", ru: "н/д" })} />
                <KeyValue label={t(lang, { en: "Published", ru: "Опубликован" })} value={selectedDraft?.published_ts || t(lang, { en: "n/a", ru: "н/д" })} />
                <KeyValue label={t(lang, { en: "Builder family", ru: "Семейство" })} value={familyLabel(selectedFamily.id, lang)} />
              </DrawerFieldGrid>
              <div className="react-form-grid">
                <input
                  className="react-input"
                  value={selectedBlock.label}
                  onChange={(event) =>
                    setBlocks((current) =>
                      current.map((item) => (item.id === selectedBlock.id ? { ...item, label: event.target.value } : item)),
                    )
                  }
                  placeholder={t(lang, { en: "Block label", ru: "Название блока" })}
                />
                <select
                  className="react-select"
                  value={selectedBlock.stage || "publish"}
                  onChange={(event) =>
                    setBlocks((current) =>
                      current.map((item) => (item.id === selectedBlock.id ? { ...item, stage: event.target.value } : item)),
                    )
                  }
                >
                  {stages.map((stage) => (
                    <option value={stage.id} key={stage.id}>{stage.label}</option>
                  ))}
                </select>
                <textarea
                  className="react-query-editor"
                  value={JSON.stringify(selectedBlock.config || {}, null, 2)}
                  onChange={(event) => {
                    try {
                      const parsed = JSON.parse(event.target.value || "{}");
                      setBlocks((current) =>
                        current.map((item) => (item.id === selectedBlock.id ? { ...item, config: parsed } : item)),
                      );
                    } catch {
                      return;
                    }
                  }}
                />
              </div>
              <section className="react-card react-card-nested">
                <PanelHeader title={t(lang, { en: "Graph relations", ru: "Связи графа" })} subtitle={t(lang, { en: "Upstream and downstream neighbors for the selected node.", ru: "Входящие и исходящие связи выбранного узла." })} />
                <DrawerFieldGrid>
                  <KeyValue
                    label={t(lang, { en: "Previous", ru: "Предыдущий" })}
                    value={builderDisplayLabel(graphEdgeDetails.find((edge) => edge.target === selectedBlock.id)?.sourceLabel || t(lang, { en: "n/a", ru: "н/д" }), lang)}
                  />
                  <KeyValue
                    label={t(lang, { en: "Next", ru: "Следующий" })}
                    value={builderDisplayLabel(graphEdgeDetails.find((edge) => edge.source === selectedBlock.id)?.targetLabel || t(lang, { en: "n/a", ru: "н/д" }), lang)}
                  />
                  <KeyValue label={t(lang, { en: "Stage", ru: "Этап" })} value={stageLabel(selectedBlock.stage || "publish", lang)} />
                  <KeyValue label={t(lang, { en: "Config keys", ru: "Поля конфигурации" })} value={Object.keys(selectedBlock.config || {}).length} />
                </DrawerFieldGrid>
                <div className="react-form-grid">
                  <label className="react-inline-note">{t(lang, { en: "Connections", ru: "Связи" })}</label>
                  <div className="react-actions react-wrap">
                    <select
                      className="react-select react-select-inline"
                      value={connectTargetId}
                      onChange={(event) => setConnectTargetId(event.target.value)}
                    >
                      <option value="">{t(lang, { en: "Select target", ru: "Выберите цель" })}</option>
                      {availableConnectionTargets.map((item) => (
                        <option key={item.id} value={item.id}>
                          {builderDisplayLabel(item.label, lang)} ({stageLabel(item.stage, lang)})
                        </option>
                      ))}
                    </select>
                    <button
                      type="button"
                      className="react-link-button"
                      disabled={!connectTargetId}
                      onClick={() => addEdge(selectedBlock.id, connectTargetId)}
                      >
                        {t(lang, { en: "Add edge", ru: "Добавить связь" })}
                      </button>
                    </div>
                  <div className="react-list react-list-compact react-builder-edge-list">
                    {graphEdgeDetails.filter((edge) => edge.source === selectedBlock.id).length ? (
                      graphEdgeDetails
                        .filter((edge) => edge.source === selectedBlock.id)
                        .map((edge) => (
                          <div key={edge.id} className="react-builder-edge-item">
                            <strong>{builderDisplayLabel(edge.targetLabel, lang)}</strong>
                            <span>{stageLabel(edge.targetStage, lang)}</span>
                            <div className="react-actions react-wrap">
                              <button type="button" className="react-link-button" onClick={() => setSelectedEdgeId(edge.id)}>
                                {t(lang, { en: "Focus edge", ru: "Открыть связь" })}
                              </button>
                              <button type="button" className="react-link-button" onClick={() => removeEdge(edge.id)}>
                                {t(lang, { en: "Remove", ru: "Удалить" })}
                              </button>
                            </div>
                          </div>
                        ))
                    ) : (
                      <EmptyState message={t(lang, { en: "No explicit outgoing edges yet.", ru: "Явные исходящие связи пока не заданы." })} />
                    )}
                  </div>
                </div>
              </section>
              <section className="react-card react-card-nested">
                <PanelHeader title={t(lang, { en: "Runtime preview", ru: "Предпросмотр выполнения" })} subtitle={t(lang, { en: "Compiled graph preview generated from the current draft state.", ru: "Собранный предпросмотр графа из текущего состояния черновика." })} />
                <div className="react-list react-list-compact">
                  <div className="react-builder-edge-item">
                    <strong>{builderDisplayText(generatedPreview.title, lang)}</strong>
                    <span>{familyLabel(kind, lang)}</span>
                    <span>{t(lang, { en: "Nodes", ru: "Узлы" })}: {generatedPreview.graph.nodes.length} · {t(lang, { en: "Edges", ru: "Связи" })}: {generatedPreview.graph.edges.length}</span>
                  </div>
                  {generatedPreview.graph.nodes.map((item, index) => (
                    <div key={item.id} className="react-builder-edge-item">
                      <strong>{index + 1}. {builderDisplayLabel(item.label, lang)}</strong>
                      <span>{stageLabel(item.stage, lang)}</span>
                      <span>{blockLabel(item.type, item.type, lang)}</span>
                    </div>
                  ))}
                </div>
                <details className="react-details-shell" style={{ marginTop: 12 }}>
                  <summary>{t(lang, { en: "Open raw preview JSON", ru: "Открыть сырой JSON-предпросмотр" })}</summary>
                  <JsonPreview value={generatedPreview} />
                </details>
              </section>
            </>
          ) : (
            <EmptyState message={t(lang, { en: "Select or add a block to inspect it.", ru: "Выберите или добавьте блок, чтобы открыть его детали." })} />
          )}
        </aside>
      </div>

      <div className="react-grid react-grid-3">
        <section className="react-card">
          <PanelHeader
            title={t(lang, { en: "Draft lifecycle", ru: "Жизненный цикл черновика" })}
            subtitle={t(lang, { en: "Current state, versioning and publish readiness.", ru: "Текущее состояние черновика, версии и готовность к публикации." })}
          />
          <DrawerFieldGrid>
            <KeyValue label={t(lang, { en: "Drafts", ru: "Черновики" })} value={draftMetrics.drafts} />
            <KeyValue label={t(lang, { en: "Published", ru: "Опубликовано" })} value={draftMetrics.published} />
            <KeyValue label={t(lang, { en: "Blocks", ru: "Блоки" })} value={draftMetrics.blocks} />
            <KeyValue label={t(lang, { en: "Stages used", ru: "Используемые этапы" })} value={draftMetrics.stages} />
            <KeyValue label={t(lang, { en: "Edges", ru: "Связи" })} value={draftMetrics.edges} />
          </DrawerFieldGrid>
        </section>
        <section className="react-card">
          <PanelHeader
            title={t(lang, { en: "Validation output", ru: "Результат проверки" })}
            subtitle={t(lang, { en: "Schema, stage and required-block validation for the current draft.", ru: "Проверка схемы, этапов и обязательных блоков для текущего черновика." })}
          />
          {validationOutput ? <JsonPreview value={validationOutput} /> : <EmptyState message={t(lang, { en: "Run validation to see builder diagnostics.", ru: "Запустите проверку, чтобы увидеть диагностику конструктора." })} />}
        </section>
        <section className="react-card">
          <PanelHeader
            title={t(lang, { en: "Test and publish", ru: "Тест и публикация" })}
            subtitle={t(lang, { en: "Execution previews and publish metadata for the current draft.", ru: "Предпросмотр выполнения и метаданные публикации для текущего черновика." })}
          />
          <div className="react-page">
            {testOutput ? <JsonPreview value={testOutput} /> : <EmptyState message={t(lang, { en: "Run a builder test to inspect runtime checks.", ru: "Запустите тест конструктора, чтобы проверить runtime-контракт." })} />}
            {publishOutput ? <JsonPreview value={publishOutput} /> : null}
          </div>
        </section>
      </div>

      <section className="react-card">
        <PanelHeader
          title={t(lang, { en: "Version history", ru: "История версий" })}
          subtitle={t(lang, { en: "Most recent changes recorded for the selected draft.", ru: "Последние изменения, зафиксированные для выбранного черновика." })}
        />
        {selectedHistory.length ? (
          <div className="react-list react-list-compact">
            {selectedHistory.map((item, index: number) => (
              <div key={`${item.ts}-${index}`} className="react-history-item">
                <strong>{item.action || t(lang, { en: "save", ru: "сохранение" })}</strong>
                <span>{item.ts || t(lang, { en: "n/a", ru: "н/д" })}</span>
                <span>{t(lang, { en: "version", ru: "версия" })} {item.version || 1} / {item.status || "draft"}</span>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState message={t(lang, { en: "This draft does not have recorded history yet.", ru: "Для этого черновика история изменений пока не записана." })} />
        )}
      </section>

      <DrawerOverlay
        open={settingsOpen}
        title={t(lang, { en: "Builder page settings", ru: "Настройки конструктора" })}
        subtitle={t(lang, { en: "Templates, integration connectors and content-plane storage details.", ru: "Шаблоны, интеграционные коннекторы и параметры хранилища контента." })}
        onClose={() => setSettingsOpen(false)}
      >
        <section className="react-card react-card-nested">
          <PanelHeader
            title={t(lang, { en: "Builder families", ru: "Семейства конструкторов" })}
            subtitle={t(lang, { en: "Dedicated builders for detections, normalizers, lists, TI and integrations.", ru: "Выделенные конструкторы для правил, нормализации, списков, киберразведки и интеграций." })}
            icon="builders"
          />
          <div className="react-chip-grid">
            {BUILDER_FAMILIES.map((family) => (
              <div key={family.id} className="react-chip-card">
                <div className="react-top-kicker">{t(lang, { en: "Builder", ru: "Конструктор" })}</div>
                <strong>{familyLabel(family.id, lang)}</strong>
                <span>{familyHint(family.id, lang)}</span>
              </div>
            ))}
          </div>
        </section>
        <section className="react-card react-card-nested">
          <PanelHeader
            title={t(lang, { en: "Integration templates", ru: "Шаблоны интеграций" })}
            subtitle={t(lang, { en: "Webhook, database and bot-oriented runtime patterns.", ru: "Runtime-шаблоны для webhook, баз данных и бот-ориентированных сценариев." })}
            icon="sources"
          />
          <div className="react-chip-grid">
            {[...sourceIntegrations, ...actionIntegrations].map((item) => (
              <div key={item.id} className="react-chip-card">
                <div className="react-top-kicker">{item.group || t(lang, { en: "general", ru: "общее" })}</div>
                <strong>{item.title}</strong>
                <span>{item.description}</span>
                <span>{item.mode} / {(item.protocols || []).join(", ")}</span>
              </div>
            ))}
          </div>
          <div className="react-page-settings-note">
            {t(lang, {
              en: "Drafts and metadata are currently persisted in the local runtime store. MongoDB remains the next content-plane target once a compatible host is available.",
              ru: "Черновики и метаданные сейчас сохраняются в локальном runtime-хранилище. MongoDB останется следующей целевой площадкой контентного слоя, когда появится совместимый узел.",
            })}
          </div>
        </section>
      </DrawerOverlay>
        </>
      ) : (
        <>
          <div className="react-grid react-grid-4">
            {correlationOverviewMetrics.map((metric) => (
              <StatCard key={metric.label} label={metric.label} value={metric.value} hint={metric.hint} />
            ))}
          </div>
          <div className="react-split react-split-xl">
            <section className="react-card">
              <PanelHeader
                title={t(lang, { en: "Correlation packs", ru: "Пакеты корреляции" })}
                subtitle={t(lang, { en: "Operational packs built on top of the runtime stream and batch correlation model.", ru: "Рабочие пакеты, собранные поверх потоковой и пакетной модели корреляции." })}
                icon="builders"
                actions={<button type="button" className="react-link-button" onClick={createCorrelationPack}>{t(lang, { en: "Create pack", ru: "Создать пакет" })}</button>}
              />
              <div className="react-command-toolbar">
                <input
                  className="react-input react-input-full"
                  value={correlationPackSearch}
                  onChange={(event) => setCorrelationPackSearch(event.target.value)}
                  placeholder={t(lang, { en: "Search packs by ID, owner or notes", ru: "Поиск пакетов по ID, владельцу или заметкам" })}
                />
              </div>
              <div className="react-list">
                {filteredCorrelationPacks.map((pack) => (
                  <button
                    key={pack.pack_id}
                    type="button"
                    className={`react-list-item react-list-item-stack ${selectedCorrelationPackId === pack.pack_id ? "active" : ""}`}
                    onClick={() => {
                      setSelectedCorrelationPackId(pack.pack_id);
                      setCorrelationPackEditorOpen(true);
                    }}
                  >
                    <div>
                      <strong>{localizedPackTitle(pack.pack_id || "", pack.title || pack.pack_id || t(lang, { en: "Untitled draft pack", ru: "Пакет без названия" }), lang)}</strong>
                      <div className="react-card-button-copy">{pack.pack_id || "draft-pack"} | {pack.rule_count || 0} {t(lang, { en: "rules", ru: "правил" })}</div>
                    </div>
                    <StatusBadge value={pack.status || "draft"} />
                  </button>
                ))}
                {!filteredCorrelationPacks.length ? <EmptyState message={t(lang, { en: "No correlation packs match the current search.", ru: "Под текущий поиск пакеты корреляции не найдены." })} /> : null}
              </div>
            </section>
            <aside className="react-card react-drawer react-window-launcher">
              <PanelHeader
                title={selectedCorrelationPackTitle}
                subtitle={t(lang, { en: "Pack metadata and lifecycle semantics are now edited from a dedicated side window.", ru: "Метаданные пакета и жизненный цикл теперь редактируются в отдельном боковом окне." })}
                actions={<StatusBadge value={correlationPackForm.status || "draft"} />}
              />
              <DrawerFieldGrid>
                <KeyValue label={t(lang, { en: "Pack ID", ru: "ID пакета" })} value={correlationPackForm.pack_id || "draft-pack"} />
                <KeyValue label={t(lang, { en: "Version", ru: "Версия" })} value={correlationPackForm.version || "1.0.0"} />
                <KeyValue label={t(lang, { en: "Owner", ru: "Владелец" })} value={correlationPackForm.owner || "platform-release"} />
                <KeyValue label={t(lang, { en: "Rules", ru: "Правила" })} value={correlationPackForm.stream_rules.length} />
                <KeyValue label={t(lang, { en: "Batch reviews", ru: "Пакетные проверки" })} value={correlationPackForm.batch_rules.length} />
                <KeyValue label={t(lang, { en: "Status", ru: "Статус" })} value={correlationPackForm.status || "draft"} />
              </DrawerFieldGrid>
              {correlationSaveState ? <div className="react-inline-note" style={{ marginTop: 12 }}>{correlationSaveState}</div> : null}
              <div className="react-actions react-wrap" style={{ marginTop: 16 }}>
                <button type="button" className="react-primary-button" onClick={() => setCorrelationPackEditorOpen(true)}>
                  {t(lang, { en: "Open pack window", ru: "Открыть окно пакета" })}
                </button>
                <button type="button" className="react-link-button" onClick={() => setCorrelationOpsOpen(true)}>
                  {t(lang, { en: "Open lifecycle window", ru: "Открыть окно жизненного цикла" })}
                </button>
              </div>
              <section className="react-card react-card-nested react-window-launcher" style={{ marginTop: 16 }}>
                <PanelHeader title={t(lang, { en: "Lifecycle contract", ru: "Контракт жизненного цикла" })} subtitle={t(lang, { en: "Draft, validate, targeted test, publish and rollback are explicit operator actions.", ru: "Черновик, проверка, адресный тест, публикация и откат выполняются как явные действия оператора." })} />
                <DrawerFieldGrid>
                  <KeyValue label={t(lang, { en: "Rules write", ru: "Изменение правил" })} value="rules:write" />
                  <KeyValue label={t(lang, { en: "Rules test", ru: "Тестирование правил" })} value="rules:test" />
                  <KeyValue label={t(lang, { en: "Suppression", ru: "Подавление" })} value="host + service + rule family" />
                  <KeyValue label={t(lang, { en: "Publish source", ru: "Источник публикации" })} value="correlation_rule_packs/*.json" />
                </DrawerFieldGrid>
              </section>
              <section className="react-card react-card-nested react-command-deck" style={{ marginTop: 16 }}>
                <PanelHeader title={t(lang, { en: "Next operator move", ru: "Следующее действие оператора" })} subtitle={t(lang, { en: "Keep the main page short: inspect the pack, then jump straight into the relevant side window.", ru: "Основная страница должна оставаться короткой: проверьте пакет и переходите прямо в нужное боковое окно." })} />
                <div className="react-command-list">
                  <div className="react-command-item"><strong>{t(lang, { en: "Pack metadata", ru: "Метаданные пакета" })}</strong><span>{t(lang, { en: "Edit owner, notes, version and publish status.", ru: "Измените владельца, заметки, версию и статус публикации." })}</span></div>
                  <div className="react-command-item"><strong>{t(lang, { en: "Rule authoring", ru: "Редактирование правил" })}</strong><span>{t(lang, { en: "Pick a rule, review suppression, then open the rule window for thresholds and Sigma.", ru: "Выберите правило, проверьте подавление и откройте окно правила для порогов и Sigma." })}</span></div>
                  <div className="react-command-item"><strong>{t(lang, { en: "Lifecycle", ru: "Жизненный цикл" })}</strong><span>{t(lang, { en: "Validate, targeted test and publish only after the compact summary looks correct.", ru: "Проверяйте, запускайте адресный тест и публикуйте только после того, как компактная сводка выглядит корректно." })}</span></div>
                </div>
              </section>
            </aside>
          </div>

          <div className="react-split react-split-xl">
            <section className="react-card">
              <PanelHeader
                title={t(lang, { en: "Rule editor", ru: "Редактор правил" })}
                subtitle={t(lang, { en: "Rules stay list-first on the page; detailed authoring now happens in a side window.", ru: "Правила остаются в формате списка на странице, а детальное редактирование вынесено в боковое окно." })}
                icon="control"
                actions={<button type="button" className="react-link-button" onClick={createCorrelationRule}>{t(lang, { en: "Add rule", ru: "Добавить правило" })}</button>}
              />
              <div className="react-command-toolbar">
                <input
                  className="react-input react-input-full"
                  value={correlationRuleSearch}
                  onChange={(event) => setCorrelationRuleSearch(event.target.value)}
                  placeholder={t(lang, { en: "Search rule title, severity, entity or operator action", ru: "Поиск по названию правила, severity, сущности или действию оператора" })}
                />
              </div>
              <div className="react-split">
                <div className="react-list react-list-compact">
                  {filteredCorrelationRules.map((rule) => (
                    <button
                      key={String(rule.id || "")}
                      type="button"
                      className={`react-list-item react-list-item-stack ${selectedCorrelationRuleId === Number(rule.id || 0) ? "active" : ""}`}
                      onClick={() => {
                        setSelectedCorrelationRuleId(Number(rule.id || 0));
                        setCorrelationRuleEditorOpen(true);
                      }}
                    >
                      <div>
                        <strong>{localizedRuleTitle(correlationPackForm.pack_id || "", Number(rule.id || 0), rule.title || t(lang, { en: `Rule ${rule.id}`, ru: `Правило ${rule.id}` }), lang)}</strong>
                        <div className="react-card-button-copy">{rule.entity_field || "host.name"} | {t(lang, { en: "threshold", ru: "порог" })} {rule.threshold || 1}</div>
                      </div>
                      <StatusBadge value={rule.status || "draft"} />
                    </button>
                  ))}
                  {!filteredCorrelationRules.length ? <EmptyState message={t(lang, { en: "No rules match the current search.", ru: "Под текущий поиск правила не найдены." })} /> : null}
                </div>
                <div className="react-page">
                  {selectedCorrelationRule ? (
                    <>
                      <DrawerFieldGrid>
                        <KeyValue label={t(lang, { en: "Rule", ru: "Правило" })} value={localizedRuleTitle(correlationPackForm.pack_id || "", Number(selectedCorrelationRule.id || 0), selectedCorrelationRule.title || t(lang, { en: `Rule ${selectedCorrelationRule.id}`, ru: `Правило ${selectedCorrelationRule.id}` }), lang)} />
                        <KeyValue label={t(lang, { en: "Severity", ru: "Критичность" })} value={selectedCorrelationRule.severity || "medium"} />
                        <KeyValue label={t(lang, { en: "Window", ru: "Окно" })} value={`${selectedCorrelationRule.window_s || 300}s`} />
                        <KeyValue label={t(lang, { en: "Threshold", ru: "Порог" })} value={selectedCorrelationRule.threshold || 1} />
                        <KeyValue label={t(lang, { en: "Entity", ru: "Сущность" })} value={selectedCorrelationRule.entity_field || "host.name"} />
                        <KeyValue label={t(lang, { en: "Status", ru: "Статус" })} value={selectedCorrelationRule.status || "draft"} />
                      </DrawerFieldGrid>
                      <div className="react-grid react-grid-2 react-builder-summary-grid" style={{ marginTop: 16 }}>
                        <section className="react-card react-card-nested react-command-deck">
                          <PanelHeader title={t(lang, { en: "Suppression and response", ru: "Подавление и реакция" })} subtitle={t(lang, { en: "Keep the routing intent visible before opening the full editor window.", ru: "Сохраняйте логику маршрутизации видимой ещё до открытия полного окна редактора." })} />
                          <InfoList
                            items={[
                              { label: t(lang, { en: "Suppression key", ru: "Ключ подавления" }), value: selectedCorrelationRule.suppression_key || t(lang, { en: "n/a", ru: "н/д" }) },
                              { label: t(lang, { en: "Operator action", ru: "Действие оператора" }), value: selectedCorrelationRule.operator_action || t(lang, { en: "n/a", ru: "н/д" }) },
                            ]}
                          />
                        </section>
                        <section className="react-card react-card-nested react-command-deck">
                          <PanelHeader title={t(lang, { en: "Rule command deck", ru: "Панель действий правила" })} subtitle={t(lang, { en: "Shortcuts for the selected stream rule.", ru: "Короткие действия для выбранного потокового правила." })} />
                          <div className="react-command-list">
                            <div className="react-command-item"><strong>{t(lang, { en: "Inspect Sigma", ru: "Проверить Sigma" })}</strong><span>{t(lang, { en: "Open the rule window to edit the Sigma payload and runtime thresholds.", ru: "Откройте окно правила, чтобы изменить Sigma-полезную нагрузку и runtime-пороги." })}</span></div>
                            <div className="react-command-item"><strong>{t(lang, { en: "Validate pack", ru: "Проверить пакет" })}</strong><span>{t(lang, { en: "Use the lifecycle window after changing severity, thresholds or entity mappings.", ru: "Используйте окно жизненного цикла после изменения критичности, порогов или привязок сущностей." })}</span></div>
                            <div className="react-command-item"><strong>{t(lang, { en: "Remove rule", ru: "Удалить правило" })}</strong><span>{t(lang, { en: "Use only when the pack contract no longer needs this detection path.", ru: "Используйте только тогда, когда контракт пакета больше не требует этот путь детектирования." })}</span></div>
                          </div>
                        </section>
                      </div>
                      <div className="react-actions react-wrap" style={{ marginTop: 16 }}>
                        <button type="button" className="react-primary-button" onClick={() => setCorrelationRuleEditorOpen(true)}>{t(lang, { en: "Open rule window", ru: "Открыть окно правила" })}</button>
                        <button type="button" className="react-link-button" onClick={() => removeCorrelationRule(Number(selectedCorrelationRule.id || 0))}>{t(lang, { en: "Remove rule", ru: "Удалить правило" })}</button>
                      </div>
                    </>
                  ) : (
                    <EmptyState message={t(lang, { en: "Select a rule to edit its metadata and Sigma payload.", ru: "Выберите правило, чтобы изменить его метаданные и Sigma-полезную нагрузку." })} />
                  )}
                </div>
              </div>
              <section className="react-card react-card-nested react-window-launcher" style={{ marginTop: 16 }}>
                <PanelHeader title={t(lang, { en: "Batch review queue", ru: "Очередь пакетных проверок" })} subtitle={t(lang, { en: "Keep batch follow-up human-readable on the main page; raw payloads stay in the pack window.", ru: "Оставляйте пакетные проверки читаемыми на основной странице, а сырые полезные нагрузки держите в окне пакета." })} />
                <div className="react-command-list">
                  {correlationPackForm.batch_rules.map((rule) => (
                    <div key={String(rule.id || "")} className="react-command-item react-command-item-stack">
                      <div>
                        <strong>{rule.title || t(lang, { en: `Batch review ${rule.id}`, ru: `Пакетная проверка ${rule.id}` })}</strong>
                        <span>{rule.description || t(lang, { en: "No batch review description provided.", ru: "Описание пакетной проверки пока не задано." })}</span>
                      </div>
                      <div className="react-command-item-meta">
                        <StatusBadge value={rule.status || "planned"} />
                        <span>{rule.severity || "medium"}</span>
                      </div>
                    </div>
                  ))}
                  {!correlationPackForm.batch_rules.length ? <EmptyState message={t(lang, { en: "No batch reviews are attached to the selected pack.", ru: "К выбранному пакету не привязаны пакетные проверки." })} /> : null}
                </div>
              </section>
            </section>
            <aside className="react-card react-drawer react-window-launcher">
              <PanelHeader title={t(lang, { en: "Validation, test and publish", ru: "Проверка, тест и публикация" })} subtitle={t(lang, { en: "Lifecycle execution now runs from a dedicated side window while the page keeps a compact operator summary.", ru: "Выполнение жизненного цикла вынесено в отдельное боковое окно, а на странице остаётся компактная операторская сводка." })} />
              <div className="react-actions react-wrap" style={{ marginBottom: 16 }}>
                <button type="button" className="react-primary-button" onClick={() => setCorrelationOpsOpen(true)}>
                  {t(lang, { en: "Open lifecycle window", ru: "Открыть окно жизненного цикла" })}
                </button>
                <button type="button" className="react-link-button" onClick={() => void validateCorrelationPackAction()}>
                  {t(lang, { en: "Validate now", ru: "Проверить сейчас" })}
                </button>
              </div>
              <section className="react-card react-card-nested">
                <PanelHeader title={t(lang, { en: "Validation output", ru: "Результат проверки" })} subtitle={t(lang, { en: "Structure, rule fields and pack metadata checks.", ru: "Проверка структуры, полей правил и метаданных пакета." })} />
                {correlationValidationOutput ? <JsonPreview value={correlationValidationOutput} /> : <EmptyState message={t(lang, { en: "Run validate to inspect pack issues and warnings.", ru: "Запустите проверку, чтобы увидеть ошибки и предупреждения пакета." })} />}
              </section>
              <section className="react-card react-card-nested">
                <PanelHeader title={t(lang, { en: "Test output", ru: "Результат теста" })} subtitle={t(lang, { en: "Compile Sigma, run targeted rule tests and inspect runtime previews.", ru: "Компилируйте Sigma, запускайте адресные тесты правил и проверяйте runtime-предпросмотр." })} />
                {correlationTestOutput ? <JsonPreview value={correlationTestOutput} /> : <EmptyState message={t(lang, { en: "Run test to inspect compile and runtime-test results.", ru: "Запустите тест, чтобы увидеть компиляцию и результаты runtime-проверок." })} />}
              </section>
              <section className="react-card react-card-nested">
                <PanelHeader title={t(lang, { en: "Publish output", ru: "Результат публикации" })} subtitle={t(lang, { en: "Operational publish result written to the live stream-correlation catalog.", ru: "Результат публикации, записанный в рабочий каталог потоковой корреляции." })} />
                {correlationPublishOutput ? <JsonPreview value={correlationPublishOutput} /> : <EmptyState message={t(lang, { en: "Publish the selected pack to see runtime rule IDs and timestamps.", ru: "Опубликуйте выбранный пакет, чтобы увидеть runtime-ID правил и временные метки." })} />}
              </section>
            </aside>
          </div>

          <section className="react-card">
            <PanelHeader title={t(lang, { en: "Authoring guidance", ru: "Рекомендации по созданию" })} subtitle={t(lang, { en: "Use packs to keep rule families coherent across identity, vulnerability, fleet and pilot-service workloads.", ru: "Используйте пакеты, чтобы держать семейства правил согласованными для доступа, уязвимостей, fleet-нагрузки и pilot-сервисов." })} />
            <div className="react-grid react-grid-3 react-builder-summary-grid">
              <div className="react-card react-card-nested react-command-deck">
                <div className="react-top-kicker">{t(lang, { en: "Draft", ru: "Черновик" })}</div>
                <strong>{t(lang, { en: "Define the pack contract", ru: "Определите контракт пакета" })}</strong>
                <p>{t(lang, { en: "Set pack owner, notes, suppression policy and operator action expectations before adding stream rules.", ru: "Задайте владельца пакета, заметки, политику подавления и ожидаемые действия оператора до добавления потоковых правил." })}</p>
              </div>
              <div className="react-card react-card-nested react-command-deck">
                <div className="react-top-kicker">{t(lang, { en: "Validate and test", ru: "Проверка и тест" })}</div>
                <strong>{t(lang, { en: "Compile before publish", ru: "Компилируйте до публикации" })}</strong>
                <p>{t(lang, { en: "Validation checks shape and required fields. Test compiles Sigma and runs targeted runtime checks against the live catalog.", ru: "Проверка анализирует форму и обязательные поля. Тест компилирует Sigma и выполняет адресные runtime-проверки по живому каталогу." })}</p>
              </div>
              <div className="react-card react-card-nested react-command-deck">
                <div className="react-top-kicker">{t(lang, { en: "Publish", ru: "Публикация" })}</div>
                <strong>{t(lang, { en: "Promote only active rules", ru: "Публикуйте только активные правила" })}</strong>
                <p>{t(lang, { en: "Only rules with active publish status are inserted into the live detection and stream-correlation tables.", ru: "В рабочие таблицы детектирования и потоковой корреляции попадают только правила со статусом активной публикации." })}</p>
              </div>
            </div>
          </section>
          <DrawerOverlay
            open={correlationPackEditorOpen}
            title={selectedCorrelationPackTitle}
            subtitle={t(lang, { en: "Edit pack metadata here, then save back into the operational pack catalog.", ru: "Изменяйте метаданные пакета здесь, затем сохраняйте их обратно в рабочий каталог пакетов." })}
            onClose={() => setCorrelationPackEditorOpen(false)}
          >
            <div className="react-form-grid">
              <input className="react-input" value={correlationPackForm.pack_id} onChange={(event) => setCorrelationPackForm((current) => ({ ...current, pack_id: event.target.value }))} placeholder={t(lang, { en: "pack_id", ru: "id_пакета" })} />
              <input className="react-input" value={correlationPackForm.title} onChange={(event) => setCorrelationPackForm((current) => ({ ...current, title: event.target.value }))} placeholder={t(lang, { en: "Pack title", ru: "Название пакета" })} />
              <input className="react-input" value={correlationPackForm.version} onChange={(event) => setCorrelationPackForm((current) => ({ ...current, version: event.target.value }))} placeholder={t(lang, { en: "Version", ru: "Версия" })} />
              <input className="react-input" value={correlationPackForm.owner} onChange={(event) => setCorrelationPackForm((current) => ({ ...current, owner: event.target.value }))} placeholder={t(lang, { en: "Owner", ru: "Владелец" })} />
              <select className="react-select" value={correlationPackForm.status} onChange={(event) => setCorrelationPackForm((current) => ({ ...current, status: event.target.value }))}>
                <option value="draft">{t(lang, { en: "draft", ru: "черновик" })}</option>
                <option value="active">{t(lang, { en: "active", ru: "активно" })}</option>
                <option value="maintenance">{t(lang, { en: "maintenance", ru: "обслуживание" })}</option>
              </select>
              <textarea className="react-query-editor" value={correlationPackForm.notes.join("\n")} onChange={(event) => setCorrelationPackForm((current) => ({ ...current, notes: event.target.value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean) }))} />
            </div>
            {correlationSaveState ? <div className="react-inline-note" style={{ marginTop: 12 }}>{correlationSaveState}</div> : null}
            <div className="react-actions react-wrap" style={{ marginTop: 20 }}>
              <button type="button" className="react-primary-button" onClick={() => void saveCorrelationPackAction()}>{t(lang, { en: "Save pack", ru: "Сохранить пакет" })}</button>
            </div>
          </DrawerOverlay>
          <DrawerOverlay
            open={correlationRuleEditorOpen}
            title={selectedCorrelationRule ? localizedRuleTitle(correlationPackForm.pack_id || "", Number(selectedCorrelationRule.id || 0), selectedCorrelationRule.title || t(lang, { en: "Correlation rule window", ru: "Окно правила корреляции" }), lang) : t(lang, { en: "Correlation rule window", ru: "Окно правила корреляции" })}
            subtitle={t(lang, { en: "Edit thresholds, suppression keys, windows and Sigma payloads in one side window.", ru: "Изменяйте пороги, ключи подавления, окна и Sigma-полезную нагрузку в одном боковом окне." })}
            onClose={() => setCorrelationRuleEditorOpen(false)}
          >
            {selectedCorrelationRule ? (
              <>
                <div className="react-form-grid">
                  <input className="react-input" value={selectedCorrelationRule.title || ""} onChange={(event) => updateCorrelationRule(Number(selectedCorrelationRule.id || 0), { title: event.target.value })} placeholder={t(lang, { en: "Rule title", ru: "Название правила" })} />
                  <select className="react-select" value={selectedCorrelationRule.severity || "medium"} onChange={(event) => updateCorrelationRule(Number(selectedCorrelationRule.id || 0), { severity: event.target.value })}>
                    <option value="critical">{t(lang, { en: "critical", ru: "критично" })}</option>
                    <option value="high">{t(lang, { en: "high", ru: "высокая" })}</option>
                    <option value="medium">{t(lang, { en: "medium", ru: "средняя" })}</option>
                    <option value="low">{t(lang, { en: "low", ru: "низкая" })}</option>
                  </select>
                  <input className="react-input" value={String(selectedCorrelationRule.window_s || 300)} onChange={(event) => updateCorrelationRule(Number(selectedCorrelationRule.id || 0), { window_s: Number(event.target.value || 300) })} placeholder={t(lang, { en: "Window seconds", ru: "Окно в секундах" })} />
                  <input className="react-input" value={String(selectedCorrelationRule.threshold || 1)} onChange={(event) => updateCorrelationRule(Number(selectedCorrelationRule.id || 0), { threshold: Number(event.target.value || 1) })} placeholder={t(lang, { en: "Threshold", ru: "Порог" })} />
                  <input className="react-input react-input-full" value={selectedCorrelationRule.entity_field || "host.name"} onChange={(event) => updateCorrelationRule(Number(selectedCorrelationRule.id || 0), { entity_field: event.target.value })} placeholder={t(lang, { en: "Entity field", ru: "Поле сущности" })} />
                  <input className="react-input react-input-full" value={selectedCorrelationRule.suppression_key || ""} onChange={(event) => updateCorrelationRule(Number(selectedCorrelationRule.id || 0), { suppression_key: event.target.value })} placeholder={t(lang, { en: "Suppression key", ru: "Ключ подавления" })} />
                  <select className="react-select" value={selectedCorrelationRule.status || "draft"} onChange={(event) => updateCorrelationRule(Number(selectedCorrelationRule.id || 0), { status: event.target.value })}>
                    <option value="draft">{t(lang, { en: "draft", ru: "черновик" })}</option>
                    <option value="active">{t(lang, { en: "active", ru: "активно" })}</option>
                    <option value="publish_ready_after_host_metrics">{t(lang, { en: "publish_ready_after_host_metrics", ru: "готово после метрик узлов" })}</option>
                  </select>
                  <input className="react-input react-input-full" value={selectedCorrelationRule.operator_action || ""} onChange={(event) => updateCorrelationRule(Number(selectedCorrelationRule.id || 0), { operator_action: event.target.value })} placeholder={t(lang, { en: "Expected operator action", ru: "Ожидаемое действие оператора" })} />
                  <textarea className="react-query-editor" value={selectedCorrelationRule.sigma_yaml || ""} onChange={(event) => updateCorrelationRule(Number(selectedCorrelationRule.id || 0), { sigma_yaml: event.target.value })} />
                </div>
                <div className="react-actions react-wrap" style={{ marginTop: 20 }}>
                  <button type="button" className="react-link-button" onClick={() => removeCorrelationRule(Number(selectedCorrelationRule.id || 0))}>{t(lang, { en: "Remove rule", ru: "Удалить правило" })}</button>
                </div>
              </>
            ) : (
              <EmptyState message={t(lang, { en: "Select a rule to edit its metadata and Sigma payload.", ru: "Выберите правило, чтобы изменить его метаданные и Sigma-полезную нагрузку." })} />
            )}
          </DrawerOverlay>
          <DrawerOverlay
            open={correlationOpsOpen}
            title={t(lang, { en: "Correlation lifecycle window", ru: "Окно жизненного цикла корреляции" })}
            subtitle={t(lang, { en: "Validate, test and publish the selected pack from one execution console.", ru: "Проверяйте, тестируйте и публикуйте выбранный пакет из одной консоли выполнения." })}
            onClose={() => setCorrelationOpsOpen(false)}
          >
            <div className="react-actions react-wrap" style={{ marginBottom: 16 }}>
              <button type="button" className="react-primary-button" onClick={() => void validateCorrelationPackAction()}>{t(lang, { en: "Validate", ru: "Проверить" })}</button>
              <button type="button" className="react-link-button" onClick={() => void testCorrelationPackAction()}>{t(lang, { en: "Test", ru: "Тестировать" })}</button>
              <button type="button" className="react-link-button" onClick={() => void publishCorrelationPackAction()}>{t(lang, { en: "Publish", ru: "Опубликовать" })}</button>
            </div>
            <section className="react-card react-card-nested">
              <PanelHeader title={t(lang, { en: "Validation output", ru: "Результат проверки" })} subtitle={t(lang, { en: "Structure, rule fields and pack metadata checks.", ru: "Проверка структуры, полей правил и метаданных пакета." })} />
              {correlationValidationOutput ? <JsonPreview value={correlationValidationOutput} /> : <EmptyState message={t(lang, { en: "Run validate to inspect pack issues and warnings.", ru: "Запустите проверку, чтобы увидеть ошибки и предупреждения пакета." })} />}
            </section>
            <section className="react-card react-card-nested" style={{ marginTop: 16 }}>
              <PanelHeader title={t(lang, { en: "Test output", ru: "Результат теста" })} subtitle={t(lang, { en: "Compile Sigma, run targeted rule tests and inspect runtime previews.", ru: "Компилируйте Sigma, запускайте адресные тесты правил и проверяйте runtime-предпросмотр." })} />
              {correlationTestOutput ? <JsonPreview value={correlationTestOutput} /> : <EmptyState message={t(lang, { en: "Run test to inspect compile and runtime-test results.", ru: "Запустите тест, чтобы увидеть компиляцию и результаты runtime-проверок." })} />}
            </section>
            <section className="react-card react-card-nested" style={{ marginTop: 16 }}>
              <PanelHeader title={t(lang, { en: "Publish output", ru: "Результат публикации" })} subtitle={t(lang, { en: "Operational publish result written to the live stream-correlation catalog.", ru: "Результат публикации, записанный в рабочий каталог потоковой корреляции." })} />
              {correlationPublishOutput ? <JsonPreview value={correlationPublishOutput} /> : <EmptyState message={t(lang, { en: "Publish the selected pack to see runtime rule IDs and timestamps.", ru: "Опубликуйте выбранный пакет, чтобы увидеть runtime-ID правил и временные метки." })} />}
            </section>
          </DrawerOverlay>
        </>
      )}
      </div>
    </AsyncGate>
  );
}
