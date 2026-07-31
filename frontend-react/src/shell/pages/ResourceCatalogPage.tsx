import { useCallback, useEffect, useMemo, useState } from "react";
import { Search } from "lucide-react";
import { api } from "../api";
import { AsyncGate } from "../async";
import { t, useShellContext } from "../context";
import { useFeedback } from "../feedback";
import { useAsyncData } from "../hooks";
import { DrawerOverlay, EmptyState, JsonPreview, KeyValue, PanelHeader, StatusBadge } from "../ui";
import { NativeActionBar, NativePageHeader, NativePager } from "../native";
import type {
  KumaResourceRecord,
  KumaResourcesResponse,
  KumaStatusResponse,
  ResourceCatalogRecord,
  ResourceCatalogResponse,
  ResourceValidationResponse,
  RuntimeBlob,
} from "../types";

const RESOURCE_KINDS = [
  "collector",
  "correlator",
  "correlationRule",
  "normalizer",
  "filter",
  "connector",
  "destination",
  "enrichmentRule",
  "activeList",
  "responseRule",
] as const;

type ResourceKind = typeof RESOURCE_KINDS[number];
const SENTINEL_PAGE_SIZE = 25;

const KIND_LABELS: Record<ResourceKind, { en: string; ru: string }> = {
  collector: { en: "Collectors", ru: "Коллекторы" },
  correlator: { en: "Correlators", ru: "Корреляторы" },
  correlationRule: { en: "Correlation rules", ru: "Правила корреляции" },
  normalizer: { en: "Normalizers", ru: "Нормализаторы" },
  filter: { en: "Filters", ru: "Фильтры" },
  connector: { en: "Connectors", ru: "Коннекторы" },
  destination: { en: "Destinations", ru: "Назначения" },
  enrichmentRule: { en: "Enrichment", ru: "Обогащение" },
  activeList: { en: "Active lists", ru: "Активные листы" },
  responseRule: { en: "Response rules", ru: "Правила реагирования" },
};

type ResourceForm = {
  id: string;
  name: string;
  kind: ResourceKind;
  description: string;
  config: RuntimeBlob;
  bindings: RuntimeBlob;
};

function emptyResource(kind: ResourceKind = "collector"): ResourceForm {
  const configByKind: Record<ResourceKind, RuntimeBlob> = {
    collector: { collector_profile: "", transport: "http", source_type: "", parsing_format: "json", target: "siem.raw" },
    correlator: { engine: "stream", handlers: 2 },
    correlationRule: { rule_id: 0, severity: "medium", expr: "", window_s: 300, threshold: 3, entity_field: "host.name", suppression_key: "host.name" },
    normalizer: { rule_id: 0, priority: 100, source_type: "", event_matcher: "", uem_mapping: {} },
    filter: { rule_id: 0, priority: 100, expr: "", action: "tag", tags: [] },
    connector: { connector_type: "http", enabled: true },
    destination: { destination_type: "kafka", target: "" },
    enrichmentRule: { lookup_field: "", output_field: "" },
    activeList: { key_field: "value", ttl_seconds: 0 },
    responseRule: { action_id: "", approval_required: true },
  };
  return {
    id: "",
    name: "",
    kind,
    description: "",
    config: configByKind[kind],
    bindings: kind === "correlator" ? { correlation_rules: [] } : {},
  };
}

function formFromResource(resource: ResourceCatalogRecord, duplicate = false): ResourceForm {
  return {
    id: duplicate || resource.read_only ? "" : resource.id,
    name: duplicate ? `${resource.name} copy` : resource.name,
    kind: resource.kind as ResourceKind,
    description: resource.description || "",
    config: { ...(resource.config || {}) },
    bindings: { ...(resource.bindings || {}) },
  };
}

function kindLabel(kind: string, lang: "en" | "ru") {
  return KIND_LABELS[kind as ResourceKind]?.[lang] || kind;
}

function ConfigField({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return <label className="react-resource-field"><span>{label}</span>{children}</label>;
}

export function ResourceCatalogPage() {
  const { lang, formatTimestamp } = useShellContext();
  const { pushToast } = useFeedback();
  const [refreshToken, setRefreshToken] = useState(0);
  const [workspace, setWorkspace] = useState<"sentinel" | "kuma">("sentinel");
  const [kind, setKind] = useState<ResourceKind | "all">("all");
  const [query, setQuery] = useState("");
  const [sentinelPage, setSentinelPage] = useState(1);
  const [selected, setSelected] = useState<ResourceCatalogRecord | null>(null);
  const [editorOpen, setEditorOpen] = useState(false);
  const [form, setForm] = useState<ResourceForm>(() => emptyResource());
  const [validation, setValidation] = useState<ResourceValidationResponse | null>(null);
  const [operationOutput, setOperationOutput] = useState<RuntimeBlob | null>(null);
  const [kumaSelection, setKumaSelection] = useState<string[]>([]);
  const [kumaPassword, setKumaPassword] = useState("");
  const [kumaPackage, setKumaPackage] = useState<File | null>(null);
  const [kumaOperation, setKumaOperation] = useState<"import" | "export" | null>(null);
  const [resourceAction, setResourceAction] = useState<"save" | "validate" | "publish" | null>(null);

  const loadCatalog = useCallback(() => api.resourceCatalog(), []);
  const loadKumaStatus = useCallback(() => api.kumaStatus(), []);
  const catalogState = useAsyncData<ResourceCatalogResponse>(loadCatalog, [refreshToken]);
  const kumaStatusState = useAsyncData<KumaStatusResponse>(loadKumaStatus, [refreshToken]);
  const loadKumaResources = useCallback(
    () => kumaStatusState.data?.healthy
      ? api.kumaResources({ page: 1, kind: kind === "all" ? undefined : [kind] })
      : Promise.resolve({ items: [], total: 0, page: 1 } as KumaResourcesResponse),
    [kind, kumaStatusState.data?.healthy],
  );
  const kumaResourcesState = useAsyncData<KumaResourcesResponse>(loadKumaResources, [kind, kumaStatusState.data?.healthy, refreshToken]);

  const sentinelItems = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return (catalogState.data?.items || []).filter((item) => {
      if (kind !== "all" && item.kind !== kind) return false;
      return !normalized || `${item.name} ${item.description} ${item.kind} ${item.origin}`.toLowerCase().includes(normalized);
    });
  }, [catalogState.data?.items, kind, query]);
  const sentinelPageCount = Math.max(1, Math.ceil(sentinelItems.length / SENTINEL_PAGE_SIZE));
  const sentinelVisibleItems = useMemo(() => {
    const start = (sentinelPage - 1) * SENTINEL_PAGE_SIZE;
    return sentinelItems.slice(start, start + SENTINEL_PAGE_SIZE);
  }, [sentinelItems, sentinelPage]);

  useEffect(() => {
    setSentinelPage(1);
  }, [kind, query, workspace]);

  useEffect(() => {
    if (sentinelPage > sentinelPageCount) setSentinelPage(sentinelPageCount);
  }, [sentinelPage, sentinelPageCount]);

  const kumaItems = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return (kumaResourcesState.data?.items || []).filter((item) =>
      !normalized || `${item.name} ${item.description} ${item.kind} ${item.tenantName}`.toLowerCase().includes(normalized),
    );
  }, [kumaResourcesState.data?.items, query]);

  const updateConfig = (key: string, value: unknown) => {
    setForm((current) => ({ ...current, config: { ...current.config, [key]: value } }));
    setValidation(null);
  };

  const updateBindings = (key: string, value: unknown) => {
    setForm((current) => ({ ...current, bindings: { ...current.bindings, [key]: value } }));
    setValidation(null);
  };

  const openCreate = (resourceKind: ResourceKind = kind === "all" ? "collector" : kind) => {
    setForm(emptyResource(resourceKind));
    setValidation(null);
    setOperationOutput(null);
    setEditorOpen(true);
  };

  const openEdit = (resource: ResourceCatalogRecord, duplicate = false) => {
    setSelected(resource);
    setForm(formFromResource(resource, duplicate));
    setValidation(null);
    setOperationOutput(null);
    setEditorOpen(true);
  };

  async function saveCurrent(notify = true) {
    const saved = await api.saveResource({
      id: form.id,
      name: form.name,
      kind: form.kind,
      description: form.description,
      tenant_id: "main",
      config: form.config,
      bindings: form.bindings,
    });
    setForm(formFromResource(saved));
    setSelected(saved);
    setRefreshToken((value) => value + 1);
    if (notify) {
      pushToast({ title: t(lang, { en: "Resource saved", ru: "Ресурс сохранен" }), message: saved.name, tone: "success" });
    }
    return saved;
  }

  async function validateCurrent() {
    const saved = await saveCurrent(false);
    const result = await api.validateResource(saved.id);
    setValidation(result);
    pushToast({
      title: result.valid ? t(lang, { en: "Validation passed", ru: "Проверка пройдена" }) : t(lang, { en: "Validation failed", ru: "Проверка не пройдена" }),
      message: result.valid ? saved.name : result.errors.join("; "),
      tone: result.valid ? "success" : "error",
    });
  }

  async function publishCurrent() {
    const saved = await saveCurrent(false);
    const checked = await api.validateResource(saved.id);
    setValidation(checked);
    if (!checked.valid) {
      pushToast({ title: t(lang, { en: "Publication blocked", ru: "Публикация заблокирована" }), message: checked.errors.join("; "), tone: "error" });
      return;
    }
    const result = await api.publishResource(saved.id);
    setOperationOutput(result.activation);
    setSelected(result.resource);
    setForm(formFromResource(result.resource));
    setRefreshToken((value) => value + 1);
    pushToast({ title: t(lang, { en: "Published to runtime", ru: "Опубликовано в runtime" }), message: result.resource.name, tone: "success" });
  }

  async function runResourceAction(action: "save" | "validate" | "publish") {
    if (resourceAction) return;
    setResourceAction(action);
    try {
      if (action === "save") await saveCurrent();
      if (action === "validate") await validateCurrent();
      if (action === "publish") await publishCurrent();
    } catch (error) {
      pushToast({
        title: t(lang, { en: "Resource operation failed", ru: "Операция с ресурсом не выполнена" }),
        message: error instanceof Error ? error.message : String(error),
        tone: "error",
      });
    } finally {
      setResourceAction(null);
    }
  }

  async function importKuma() {
    if (!kumaPackage || !kumaPassword) return;
    try {
      const result = await api.importKumaPackage(kumaPackage, kumaPassword, kumaStatusState.data?.tenant_id || "");
      setOperationOutput(result);
      setKumaOperation(null);
      setKumaPackage(null);
      setKumaPassword("");
      setRefreshToken((value) => value + 1);
      pushToast({ title: "KUMA", message: t(lang, { en: "Resource package imported", ru: "Пакет ресурсов импортирован" }), tone: "success" });
    } catch (error) {
      pushToast({ title: "KUMA", message: error instanceof Error ? error.message : String(error), tone: "error" });
    }
  }

  async function exportKuma() {
    if (!kumaSelection.length || !kumaPassword) return;
    try {
      const result = await api.exportKumaResources(kumaSelection, kumaPassword, kumaStatusState.data?.tenant_id || "");
      const url = URL.createObjectURL(result.blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `kuma-resources-${new Date().toISOString().slice(0, 10)}.kuma`;
      anchor.click();
      URL.revokeObjectURL(url);
      setKumaOperation(null);
      setKumaPassword("");
      pushToast({ title: "KUMA", message: t(lang, { en: "Encrypted resource package exported", ru: "Зашифрованный пакет ресурсов экспортирован" }), tone: "success" });
    } catch (error) {
      pushToast({ title: "KUMA", message: error instanceof Error ? error.message : String(error), tone: "error" });
    }
  }

  function renderKindFields() {
    const config = form.config;
    if (form.kind === "collector") {
      return (
        <>
          <ConfigField label="Collector profile"><input className="react-input" value={String(config.collector_profile || "")} onChange={(event) => updateConfig("collector_profile", event.target.value)} /></ConfigField>
          <ConfigField label={t(lang, { en: "Transport", ru: "Транспорт" })}><select className="react-select" value={String(config.transport || "http")} onChange={(event) => updateConfig("transport", event.target.value)}><option value="http">HTTP JSON</option><option value="syslog_tcp">Syslog TCP</option><option value="syslog_udp">Syslog UDP</option><option value="kafka">Kafka</option></select></ConfigField>
          <ConfigField label={t(lang, { en: "Source type", ru: "Тип источника" })}><input className="react-input" value={String(config.source_type || "")} onChange={(event) => updateConfig("source_type", event.target.value)} /></ConfigField>
          <ConfigField label={t(lang, { en: "Parsing format", ru: "Формат парсинга" })}><select className="react-select" value={String(config.parsing_format || "json")} onChange={(event) => updateConfig("parsing_format", event.target.value)}><option value="json">JSON</option><option value="cef">CEF</option><option value="syslog">RFC5424</option><option value="windows_xml">Windows XML</option></select></ConfigField>
        </>
      );
    }
    if (form.kind === "correlator") {
      const rules = (configValueList(form.bindings.correlation_rules)).join(", ");
      return (
        <>
          <ConfigField label={t(lang, { en: "Engine", ru: "Движок" })}><select className="react-select" value={String(config.engine || "stream")} onChange={(event) => updateConfig("engine", event.target.value)}><option value="stream">Stream</option><option value="batch">Batch</option></select></ConfigField>
          <ConfigField label={t(lang, { en: "Handlers", ru: "Обработчики" })}><input className="react-input" type="number" min={1} value={Number(config.handlers || 1)} onChange={(event) => updateConfig("handlers", Number(event.target.value))} /></ConfigField>
          <ConfigField label={t(lang, { en: "Bound rule IDs", ru: "Привязанные ID правил" })}><textarea className="react-input react-resource-textarea" value={rules} onChange={(event) => updateBindings("correlation_rules", event.target.value.split(",").map((item) => item.trim()).filter(Boolean))} /></ConfigField>
        </>
      );
    }
    if (form.kind === "correlationRule") {
      return (
        <>
          <ConfigField label="Rule ID"><input className="react-input" type="number" min={1} value={Number(config.rule_id || 0)} onChange={(event) => updateConfig("rule_id", Number(event.target.value))} /></ConfigField>
          <ConfigField label="Severity"><select className="react-select" value={String(config.severity || "medium")} onChange={(event) => updateConfig("severity", event.target.value)}><option>low</option><option>medium</option><option>high</option><option>critical</option></select></ConfigField>
          <ConfigField label={t(lang, { en: "Condition", ru: "Условие" })}><textarea className="react-input react-resource-code" value={String(config.expr || "")} onChange={(event) => updateConfig("expr", event.target.value)} /></ConfigField>
          <ConfigField label={t(lang, { en: "Window, seconds", ru: "Окно, секунд" })}><input className="react-input" type="number" min={60} value={Number(config.window_s || 300)} onChange={(event) => updateConfig("window_s", Number(event.target.value))} /></ConfigField>
          <ConfigField label={t(lang, { en: "Threshold", ru: "Порог" })}><input className="react-input" type="number" min={1} value={Number(config.threshold || 1)} onChange={(event) => updateConfig("threshold", Number(event.target.value))} /></ConfigField>
          <ConfigField label={t(lang, { en: "Entity field", ru: "Поле сущности" })}><input className="react-input" value={String(config.entity_field || "host.name")} onChange={(event) => updateConfig("entity_field", event.target.value)} /></ConfigField>
        </>
      );
    }
    if (form.kind === "normalizer") {
      const mapping = typeof config.uem_mapping === "string" ? config.uem_mapping : JSON.stringify(config.uem_mapping || {}, null, 2);
      return (
        <>
          <ConfigField label="Rule ID"><input className="react-input" type="number" min={0} value={Number(config.rule_id || 0)} onChange={(event) => updateConfig("rule_id", Number(event.target.value))} /></ConfigField>
          <ConfigField label={t(lang, { en: "Priority", ru: "Приоритет" })}><input className="react-input" type="number" min={1} value={Number(config.priority || 100)} onChange={(event) => updateConfig("priority", Number(event.target.value))} /></ConfigField>
          <ConfigField label={t(lang, { en: "Source type", ru: "Тип источника" })}><input className="react-input" value={String(config.source_type || "")} onChange={(event) => updateConfig("source_type", event.target.value)} /></ConfigField>
          <ConfigField label={t(lang, { en: "Event matcher", ru: "Условие события" })}><textarea className="react-input react-resource-code" value={String(config.event_matcher || "")} onChange={(event) => updateConfig("event_matcher", event.target.value)} /></ConfigField>
          <ConfigField label="UEM mapping"><textarea className="react-input react-resource-code react-resource-code-tall" value={mapping} onChange={(event) => { try { updateConfig("uem_mapping", JSON.parse(event.target.value)); } catch { updateConfig("uem_mapping", event.target.value); } }} /></ConfigField>
        </>
      );
    }
    if (form.kind === "filter") {
      return (
        <>
          <ConfigField label="Rule ID"><input className="react-input" type="number" min={0} value={Number(config.rule_id || 0)} onChange={(event) => updateConfig("rule_id", Number(event.target.value))} /></ConfigField>
          <ConfigField label={t(lang, { en: "Priority", ru: "Приоритет" })}><input className="react-input" type="number" min={1} value={Number(config.priority || 100)} onChange={(event) => updateConfig("priority", Number(event.target.value))} /></ConfigField>
          <ConfigField label={t(lang, { en: "Expression", ru: "Выражение" })}><textarea className="react-input react-resource-code" value={String(config.expr || "")} onChange={(event) => updateConfig("expr", event.target.value)} /></ConfigField>
          <ConfigField label={t(lang, { en: "Action", ru: "Действие" })}><select className="react-select" value={String(config.action || "tag")} onChange={(event) => updateConfig("action", event.target.value)}><option value="tag">tag</option><option value="drop">drop</option><option value="pass">pass</option></select></ConfigField>
          <ConfigField label={t(lang, { en: "Tags", ru: "Теги" })}><input className="react-input" value={configValueList(config.tags).join(", ")} onChange={(event) => updateConfig("tags", event.target.value.split(",").map((item) => item.trim()).filter(Boolean))} /></ConfigField>
        </>
      );
    }
    return <ConfigField label={t(lang, { en: "Configuration", ru: "Конфигурация" })}><textarea className="react-input react-resource-code react-resource-code-tall" value={JSON.stringify(config, null, 2)} onChange={(event) => { try { setForm((current) => ({ ...current, config: JSON.parse(event.target.value) })); } catch { /* keep last valid object */ } }} /></ConfigField>;
  }

  if (editorOpen) {
    return (
      <div className="react-page native-page native-resource-wizard">
        <NativePageHeader
          title={form.id ? t(lang, { en: "Edit resource", ru: "Изменение ресурса" }) : t(lang, { en: "Create resource", ru: "Создание ресурса" })}
          subtitle={kindLabel(form.kind, lang)}
          icon="builders"
          actions={(
            <>
              <button type="button" className="react-link-button" onClick={() => setEditorOpen(false)}>{t(lang, { en: "Cancel", ru: "Отмена" })}</button>
              <button type="button" className="react-link-button" disabled={Boolean(resourceAction)} onClick={() => void runResourceAction("save")}>{resourceAction === "save" ? t(lang, { en: "Saving...", ru: "Сохранение..." }) : t(lang, { en: "Save draft", ru: "Сохранить черновик" })}</button>
              <button type="button" className="react-link-button" disabled={Boolean(resourceAction)} onClick={() => void runResourceAction("validate")}>{resourceAction === "validate" ? t(lang, { en: "Validating...", ru: "Проверка..." }) : t(lang, { en: "Validate", ru: "Проверить" })}</button>
              <button type="button" className="react-primary-button" disabled={Boolean(resourceAction)} onClick={() => void runResourceAction("publish")}>{resourceAction === "publish" ? t(lang, { en: "Publishing...", ru: "Публикация..." }) : t(lang, { en: "Publish", ru: "Опубликовать" })}</button>
            </>
          )}
        />
        <div className="native-resource-wizard-steps" aria-label={t(lang, { en: "Resource workflow", ru: "Этапы ресурса" })}>
          <span className="active"><b>1</b>{t(lang, { en: "General", ru: "Общие параметры" })}</span>
          <span className="active"><b>2</b>{t(lang, { en: "Configuration", ru: "Конфигурация" })}</span>
          <span className={validation ? "active" : ""}><b>3</b>{t(lang, { en: "Validation", ru: "Проверка" })}</span>
          <span className={operationOutput ? "active" : ""}><b>4</b>{t(lang, { en: "Runtime", ru: "Runtime" })}</span>
        </div>
        <div className="native-resource-wizard-body">
          <section>
            <h2>{t(lang, { en: "General", ru: "Общие параметры" })}</h2>
            <div className="react-resource-form-grid">
              <ConfigField label={t(lang, { en: "Name", ru: "Название" })}><input className="react-input" value={form.name} onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))} /></ConfigField>
              <ConfigField label={t(lang, { en: "Kind", ru: "Тип" })}><select className="react-select" value={form.kind} onChange={(event) => setForm(emptyResource(event.target.value as ResourceKind))} disabled={Boolean(form.id)}>{RESOURCE_KINDS.map((item) => <option key={item} value={item}>{kindLabel(item, lang)}</option>)}</select></ConfigField>
              <ConfigField label={t(lang, { en: "Description", ru: "Описание" })}><textarea className="react-input react-resource-textarea" value={form.description} onChange={(event) => setForm((current) => ({ ...current, description: event.target.value }))} /></ConfigField>
            </div>
          </section>
          <section>
            <h2>{t(lang, { en: "Configuration", ru: "Конфигурация" })}</h2>
            <div className="react-resource-form-grid">{renderKindFields()}</div>
          </section>
          <aside>
            <h2>{t(lang, { en: "Publication state", ru: "Состояние публикации" })}</h2>
            <KeyValue label={t(lang, { en: "Resource kind", ru: "Тип ресурса" })} value={kindLabel(form.kind, lang)} />
            <KeyValue label={t(lang, { en: "Draft ID", ru: "ID черновика" })} value={form.id || t(lang, { en: "Not saved", ru: "Не сохранен" })} />
            <KeyValue label={t(lang, { en: "Validation", ru: "Проверка" })} value={validation ? <StatusBadge value={validation.valid ? "active" : "failed"} /> : t(lang, { en: "Not run", ru: "Не запускалась" })} />
            {validation ? <div className={`react-alert ${validation.valid ? "react-alert-success" : "react-alert-danger"}`}><strong>{validation.valid ? t(lang, { en: "Valid", ru: "Проверка пройдена" }) : t(lang, { en: "Invalid", ru: "Есть ошибки" })}</strong><span>{[...validation.errors, ...validation.warnings].join(" / ") || t(lang, { en: "No blocking issues", ru: "Блокирующих проблем нет" })}</span></div> : null}
            {operationOutput ? <JsonPreview value={operationOutput} /> : null}
          </aside>
        </div>
      </div>
    );
  }

  return (
    <AsyncGate states={[catalogState, kumaStatusState]} loadingMessage={t(lang, { en: "Loading resources...", ru: "Загрузка ресурсов..." })}>
      <div className="react-page react-page-resources native-page">
        <NativePageHeader
          title={t(lang, { en: "Resources", ru: "Ресурсы" })}
          icon="builders"
          actions={<>
            <button type="button" className="react-link-button" onClick={() => setRefreshToken((value) => value + 1)}>{t(lang, { en: "Refresh", ru: "Обновить" })}</button>
            <a className="react-link-button" href="/builders">{t(lang, { en: "Flow builder", ru: "Конструктор потоков" })}</a>
            <a className="react-link-button" href="/builders?workspace=correlation">{t(lang, { en: "Correlation builder", ru: "Конструктор корреляции" })}</a>
            <button type="button" className="react-primary-button" onClick={() => openCreate()}>{t(lang, { en: "Create", ru: "Создать" })}</button>
          </>}
        />
        <div className="native-list-search">
          <label className="native-search-field">
            <Search size={16} aria-hidden="true" />
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t(lang, { en: "Search resources by name, kind and origin", ru: "Поиск ресурсов по названию, типу и источнику" })} />
          </label>
          <select value={kind} onChange={(event) => setKind(event.target.value as ResourceKind | "all")}>
            <option value="all">{t(lang, { en: "All resource types", ru: "Все типы ресурсов" })}</option>
            {RESOURCE_KINDS.map((item) => <option key={item} value={item}>{kindLabel(item, lang)}</option>)}
          </select>
          <button type="button" className="react-link-button" onClick={() => { setQuery(""); setKind("all"); }}>{t(lang, { en: "Clear", ru: "Очистить" })}</button>
        </div>
        <div className="native-workspace-tabs">
          <div>
            <button type="button" className={workspace === "sentinel" ? "active" : ""} onClick={() => setWorkspace("sentinel")}>Rdegon Sentinel</button>
            <button type="button" className={workspace === "kuma" ? "active" : ""} onClick={() => setWorkspace("kuma")}>KUMA 3.4</button>
          </div>
          <span>{workspace === "sentinel" ? `${catalogState.data?.total || 0} resources` : `${kumaStatusState.data?.resource_count || 0} resources`}</span>
        </div>
        <NativeActionBar
          primary={workspace === "kuma" ? (
            <>
              <button type="button" className="react-link-button" onClick={() => setKumaOperation("import")}>{t(lang, { en: "Import", ru: "Импорт" })}</button>
              <button type="button" className="react-link-button" disabled={!kumaSelection.length} onClick={() => setKumaOperation("export")}>{t(lang, { en: "Export", ru: "Экспорт" })}</button>
            </>
          ) : <button type="button" className="react-link-button" onClick={() => openCreate(kind === "all" ? "collector" : kind)}>{t(lang, { en: "New resource", ru: "Новый ресурс" })}</button>}
          meta={(
            <>
              <span>{t(lang, { en: "Active rules", ru: "Активные правила" })}: <strong>{(catalogState.data?.items || []).filter((item) => item.kind === "correlationRule" && item.status === "active").length}</strong></span>
              <span>{t(lang, { en: "Issues", ru: "Проблемы" })}: <strong>{(catalogState.data?.issues || []).length + (kumaStatusState.data?.issues || []).length}</strong></span>
            </>
          )}
        />

        <div className="react-resource-layout">
          <aside className="react-resource-kind-list">
            <button type="button" className={kind === "all" ? "active" : ""} onClick={() => setKind("all")}><span>{t(lang, { en: "All resources", ru: "Все ресурсы" })}</span><b>{workspace === "sentinel" ? catalogState.data?.total || 0 : kumaResourcesState.data?.total || 0}</b></button>
            {RESOURCE_KINDS.map((item) => (
              <button key={item} type="button" className={kind === item ? "active" : ""} onClick={() => setKind(item)}>
                <span>{kindLabel(item, lang)}</span>
                <b>{workspace === "sentinel" ? catalogState.data?.summary?.[item] || 0 : (kumaResourcesState.data?.items || []).filter((resource) => resource.kind === item).length}</b>
              </button>
            ))}
          </aside>

          <section className="react-card react-resource-catalog">
            <PanelHeader
              title={workspace === "sentinel" ? "Rdegon Sentinel" : "KUMA"}
              subtitle={kind === "all" ? t(lang, { en: "All resource types", ru: "Все типы ресурсов" }) : kindLabel(kind, lang)}
            />
            {workspace === "sentinel" ? (
              <div className="react-table-wrap">
                <table className="react-table">
                  <thead><tr><th>{t(lang, { en: "Name", ru: "Название" })}</th><th>{t(lang, { en: "Kind", ru: "Тип" })}</th><th>{t(lang, { en: "Status", ru: "Статус" })}</th><th>{t(lang, { en: "Origin", ru: "Источник" })}</th><th>{t(lang, { en: "Updated", ru: "Обновлено" })}</th><th /></tr></thead>
                  <tbody>
                    {sentinelVisibleItems.map((item) => (
                      <tr key={item.id} className={selected?.id === item.id ? "selected" : ""} onClick={() => setSelected(item)}>
                        <td><strong>{item.name}</strong><small>{item.description || item.id}</small></td>
                        <td>{kindLabel(item.kind, lang)}</td>
                        <td><StatusBadge value={item.status} /></td>
                        <td>{item.origin}</td>
                        <td>{item.updated_ts ? formatTimestamp(item.updated_ts, "compact") : "n/a"}</td>
                        <td><button type="button" className="react-inline-action" onClick={(event) => { event.stopPropagation(); openEdit(item, item.read_only); }}>{item.read_only ? t(lang, { en: "Duplicate", ru: "Дублировать" }) : t(lang, { en: "Edit", ru: "Изменить" })}</button></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!sentinelItems.length ? <EmptyState message={t(lang, { en: "No matching resources.", ru: "Ресурсы не найдены." })} /> : null}
                {sentinelItems.length ? (
                  <div className="react-resource-pagination">
                    <span>
                      {Math.min((sentinelPage - 1) * SENTINEL_PAGE_SIZE + 1, sentinelItems.length)}
                      {"–"}
                      {Math.min(sentinelPage * SENTINEL_PAGE_SIZE, sentinelItems.length)}
                      {" / "}
                      {sentinelItems.length}
                    </span>
                    <div className="react-actions">
                      <button
                        type="button"
                        className="react-inline-action"
                        disabled={sentinelPage <= 1}
                        onClick={() => setSentinelPage((current) => Math.max(1, current - 1))}
                      >
                        {t(lang, { en: "Previous", ru: "Назад" })}
                      </button>
                      <strong>{sentinelPage} / {sentinelPageCount}</strong>
                      <button
                        type="button"
                        className="react-inline-action"
                        disabled={sentinelPage >= sentinelPageCount}
                        onClick={() => setSentinelPage((current) => Math.min(sentinelPageCount, current + 1))}
                      >
                        {t(lang, { en: "Next", ru: "Далее" })}
                      </button>
                    </div>
                  </div>
                ) : null}
              </div>
            ) : (
              <>
                {!kumaStatusState.data?.healthy ? <div className="react-alert react-alert-warning">{(kumaStatusState.data?.issues || ["KUMA REST API unavailable"]).join(" / ")}</div> : null}
                <div className="react-table-wrap">
                  <table className="react-table">
                    <thead><tr><th /><th>{t(lang, { en: "Name", ru: "Название" })}</th><th>{t(lang, { en: "Kind", ru: "Тип" })}</th><th>{t(lang, { en: "Tenant", ru: "Тенант" })}</th><th>{t(lang, { en: "Updated", ru: "Обновлено" })}</th><th>{t(lang, { en: "Owner", ru: "Владелец" })}</th></tr></thead>
                    <tbody>
                      {kumaItems.map((item: KumaResourceRecord) => (
                        <tr key={item.id}>
                          <td><input type="checkbox" checked={kumaSelection.includes(item.id)} onChange={() => setKumaSelection((current) => current.includes(item.id) ? current.filter((id) => id !== item.id) : [...current, item.id])} aria-label={`${t(lang, { en: "Select", ru: "Выбрать" })} ${item.name}`} /></td>
                          <td><strong>{item.name}</strong><small>{item.description || item.id}</small></td>
                          <td>{kindLabel(item.kind, lang)}</td>
                          <td>{item.tenantName || item.tenantID}</td>
                          <td>{item.updated ? formatTimestamp(item.updated, "compact") : "n/a"}</td>
                          <td>{item.userName || item.userID}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {!kumaItems.length && kumaStatusState.data?.healthy ? <EmptyState message={t(lang, { en: "KUMA returned no matching resources.", ru: "KUMA не вернула подходящих ресурсов." })} /> : null}
                </div>
              </>
            )}
          </section>
        </div>
        {workspace === "sentinel" ? <NativePager shown={sentinelVisibleItems.length} total={sentinelItems.length} lang={lang} /> : <NativePager shown={kumaItems.length} total={kumaResourcesState.data?.total || kumaItems.length} lang={lang} />}

        {workspace === "sentinel" && selected ? (
          <DrawerOverlay
            open
            title={selected.name}
            subtitle={`${kindLabel(selected.kind, lang)} · ${selected.id}`}
            onClose={() => setSelected(null)}
          >
          <section className="react-card react-card-nested react-resource-detail">
            <PanelHeader title={selected.name} subtitle={`${kindLabel(selected.kind, lang)} · ${selected.id}`} actions={<div className="react-actions"><button type="button" className="react-link-button" onClick={() => openEdit(selected, true)}>{t(lang, { en: "Duplicate", ru: "Дублировать" })}</button>{!selected.read_only ? <button type="button" className="react-primary-button" onClick={() => openEdit(selected)}>{t(lang, { en: "Edit", ru: "Изменить" })}</button> : null}</div>} />
            <div className="react-kv-grid">
              <KeyValue label={t(lang, { en: "Status", ru: "Статус" })} value={selected.status} />
              <KeyValue label={t(lang, { en: "Version", ru: "Версия" })} value={selected.version} />
              <KeyValue label={t(lang, { en: "Tenant", ru: "Тенант" })} value={selected.tenant_id} />
              <KeyValue label={t(lang, { en: "Origin", ru: "Источник" })} value={selected.origin} />
            </div>
            <JsonPreview value={{ config: selected.config, bindings: selected.bindings, activation: selected.activation || {} }} />
          </section>
          </DrawerOverlay>
        ) : null}
      </div>

      <DrawerOverlay open={editorOpen} title={form.id ? t(lang, { en: "Edit resource", ru: "Изменение ресурса" }) : t(lang, { en: "Create resource", ru: "Создание ресурса" })} subtitle={kindLabel(form.kind, lang)} onClose={() => setEditorOpen(false)} panelClassName="react-drawer-panel-wide">
        <div className="react-resource-editor">
          <section className="react-card react-card-nested">
            <PanelHeader title={t(lang, { en: "General", ru: "Общие параметры" })} subtitle={t(lang, { en: "Identity and runtime ownership.", ru: "Идентификатор и владение runtime." })} />
            <div className="react-resource-form-grid">
              <ConfigField label={t(lang, { en: "Name", ru: "Название" })}><input className="react-input" value={form.name} onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))} /></ConfigField>
              <ConfigField label={t(lang, { en: "Kind", ru: "Тип" })}><select className="react-select" value={form.kind} onChange={(event) => setForm(emptyResource(event.target.value as ResourceKind))} disabled={Boolean(form.id)}>{RESOURCE_KINDS.map((item) => <option key={item} value={item}>{kindLabel(item, lang)}</option>)}</select></ConfigField>
              <ConfigField label={t(lang, { en: "Description", ru: "Описание" })}><textarea className="react-input react-resource-textarea" value={form.description} onChange={(event) => setForm((current) => ({ ...current, description: event.target.value }))} /></ConfigField>
            </div>
          </section>
          <section className="react-card react-card-nested">
            <PanelHeader title={t(lang, { en: "Configuration", ru: "Конфигурация" })} subtitle={kindLabel(form.kind, lang)} />
            <div className="react-resource-form-grid">{renderKindFields()}</div>
          </section>
          {validation ? <section className={`react-alert ${validation.valid ? "react-alert-success" : "react-alert-danger"}`}><strong>{validation.valid ? t(lang, { en: "Valid", ru: "Проверка пройдена" }) : t(lang, { en: "Invalid", ru: "Есть ошибки" })}</strong><span>{[...validation.errors, ...validation.warnings].join(" / ") || t(lang, { en: "No blocking issues", ru: "Блокирующих проблем нет" })}</span></section> : null}
          {operationOutput ? <JsonPreview value={operationOutput} /> : null}
          <div className="react-actions react-resource-editor-actions">
            <button type="button" className="react-link-button" disabled={Boolean(resourceAction)} onClick={() => void runResourceAction("save")}>{resourceAction === "save" ? t(lang, { en: "Saving...", ru: "Сохранение..." }) : t(lang, { en: "Save draft", ru: "Сохранить черновик" })}</button>
            <button type="button" className="react-link-button" disabled={Boolean(resourceAction)} onClick={() => void runResourceAction("validate")}>{resourceAction === "validate" ? t(lang, { en: "Validating...", ru: "Проверка..." }) : t(lang, { en: "Validate", ru: "Проверить" })}</button>
            <button type="button" className="react-primary-button" disabled={Boolean(resourceAction)} onClick={() => void runResourceAction("publish")}>{resourceAction === "publish" ? t(lang, { en: "Publishing...", ru: "Публикация..." }) : t(lang, { en: "Publish", ru: "Опубликовать" })}</button>
          </div>
        </div>
      </DrawerOverlay>

      <DrawerOverlay open={kumaOperation !== null} title={kumaOperation === "import" ? t(lang, { en: "Import KUMA package", ru: "Импорт пакета KUMA" }) : t(lang, { en: "Export KUMA resources", ru: "Экспорт ресурсов KUMA" })} subtitle={kumaStatusState.data?.api_url || "KUMA REST API"} onClose={() => setKumaOperation(null)}>
        <section className="react-card react-card-nested">
          <div className="react-resource-form-grid">
            {kumaOperation === "import" ? <ConfigField label={t(lang, { en: "Encrypted resource package", ru: "Зашифрованный пакет ресурсов" })}><input type="file" onChange={(event) => setKumaPackage(event.target.files?.[0] || null)} /></ConfigField> : <KeyValue label={t(lang, { en: "Selected resources", ru: "Выбрано ресурсов" })} value={kumaSelection.length} />}
            <ConfigField label={t(lang, { en: "Package password", ru: "Пароль пакета" })}><input className="react-input" type="password" value={kumaPassword} onChange={(event) => setKumaPassword(event.target.value)} /></ConfigField>
          </div>
          <div className="react-actions">
            <button type="button" className="react-primary-button" disabled={!kumaPassword || (kumaOperation === "import" ? !kumaPackage : !kumaSelection.length)} onClick={() => void (kumaOperation === "import" ? importKuma() : exportKuma())}>{kumaOperation === "import" ? t(lang, { en: "Import", ru: "Импортировать" }) : t(lang, { en: "Export", ru: "Экспортировать" })}</button>
          </div>
        </section>
      </DrawerOverlay>
    </AsyncGate>
  );
}

function configValueList(value: unknown): string[] {
  return Array.isArray(value) ? value.map((item) => String(item)) : [];
}
