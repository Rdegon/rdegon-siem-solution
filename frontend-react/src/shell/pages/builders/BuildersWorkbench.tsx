import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../../api";
import { AsyncGate } from "../../async";
import { t, useShellContext } from "../../context";
import { useFeedback } from "../../feedback";
import { useAsyncData } from "../../hooks";
import {
  DrawerFieldGrid,
  DrawerOverlay,
  EmptyState,
  JsonPreview,
  KeyValue,
  PanelHeader,
  SectionIntro,
  StatCard,
  StatusBadge,
} from "../../ui";
import type {
  BuilderBlockRecord,
  BuilderDraftRecord,
  BuilderPublishResponse,
  BuilderTestResponse,
  BuilderValidationResponse,
  CorrelationPackRecord,
  CorrelationPackTestResponse,
  CorrelationRuleRecord,
  RuntimeBlob,
} from "../../types";

type BuilderWorkspace = "graph" | "correlation";
type BuilderLang = "en" | "ru";
type BuilderFamilyId = "detection" | "normalizer" | "active-list" | "threat-intel" | "integration";
type BuilderDraftForm = {
  id: string;
  title: string;
  description: string;
  kind: BuilderFamilyId;
  status: string;
  blocks: BuilderBlockRecord[];
};
type CorrelationPackForm = {
  pack_id: string;
  title: string;
  version: string;
  status: string;
  owner: string;
  notes: string[];
  stream_rules: CorrelationRuleRecord[];
};

type BuilderFamilyDefinition = {
  id: BuilderFamilyId;
  title: { en: string; ru: string };
  subtitle: { en: string; ru: string };
};

type BlockDefinition = {
  type: string;
  stage: string;
  title: { en: string; ru: string };
  subtitle: { en: string; ru: string };
};

const BUILDER_FAMILIES: BuilderFamilyDefinition[] = [
  {
    id: "detection",
    title: { en: "Detection flow", ru: "Поток детектирования" },
    subtitle: { en: "Thresholds, routing and incident promotion.", ru: "Пороги, маршрутизация и подъем в инциденты." },
  },
  {
    id: "normalizer",
    title: { en: "Normalizer flow", ru: "Поток нормализации" },
    subtitle: { en: "Parsing, field mapping and category cleanup.", ru: "Разбор, маппинг полей и нормализация категорий." },
  },
  {
    id: "active-list",
    title: { en: "Active-list flow", ru: "Поток активных списков" },
    subtitle: { en: "Allow, deny and contextual enrichment.", ru: "Allow, deny и контекстное обогащение." },
  },
  {
    id: "threat-intel",
    title: { en: "Threat-intel flow", ru: "Поток киберразведки" },
    subtitle: { en: "IOC lookup and reputation decisions.", ru: "Проверка IOC и решения по репутации." },
  },
  {
    id: "integration",
    title: { en: "Integration flow", ru: "Поток интеграции" },
    subtitle: { en: "Inbound webhooks and outbound automations.", ru: "Входящие webhooks и исходящие автоматизации." },
  },
];

const BLOCK_LIBRARY: BlockDefinition[] = [
  {
    type: "source",
    stage: "ingest",
    title: { en: "Source", ru: "Источник" },
    subtitle: { en: "Collector binding and source profile.", ru: "Привязка коллектора и профиль источника." },
  },
  {
    type: "normalizer",
    stage: "parse",
    title: { en: "Normalizer", ru: "Нормализатор" },
    subtitle: { en: "Field mapping and taxonomy cleanup.", ru: "Маппинг полей и очистка таксономии." },
  },
  {
    type: "filter",
    stage: "enrich",
    title: { en: "Filter", ru: "Фильтр" },
    subtitle: { en: "Noise suppression and routing logic.", ru: "Подавление шума и логика маршрутизации." },
  },
  {
    type: "active_list",
    stage: "enrich",
    title: { en: "Active list", ru: "Активный список" },
    subtitle: { en: "Allow, deny and watch lists.", ru: "Списки allow, deny и watch." },
  },
  {
    type: "ti_lookup",
    stage: "enrich",
    title: { en: "Threat intel", ru: "Киберразведка" },
    subtitle: { en: "IOC lookup and reputation context.", ru: "Проверка IOC и контекст репутации." },
  },
  {
    type: "detection",
    stage: "detect",
    title: { en: "Detection", ru: "Детект" },
    subtitle: { en: "Conditions, thresholds and alert logic.", ru: "Условия, пороги и логика алерта." },
  },
  {
    type: "incident",
    stage: "incident",
    title: { en: "Incident", ru: "Инцидент" },
    subtitle: { en: "Queue projection and ownership.", ru: "Проекция в очередь и владение." },
  },
  {
    type: "publish",
    stage: "publish",
    title: { en: "Publish", ru: "Публикация" },
    subtitle: { en: "Runtime artifact and release gate.", ru: "Runtime-артефакт и выпуск в рабочий контур." },
  },
];

const STAGES = [
  { id: "ingest", en: "Ingest", ru: "Прием" },
  { id: "parse", en: "Parse", ru: "Разбор" },
  { id: "enrich", en: "Enrich", ru: "Обогащение" },
  { id: "detect", en: "Detect", ru: "Выявление" },
  { id: "incident", en: "Incident", ru: "Инцидент" },
  { id: "publish", en: "Publish", ru: "Публикация" },
];

const STARTER_LIBRARY: Record<BuilderFamilyId, string[]> = {
  detection: ["source", "normalizer", "filter", "detection", "incident", "publish"],
  normalizer: ["source", "normalizer", "publish"],
  "active-list": ["source", "active_list", "publish"],
  "threat-intel": ["source", "ti_lookup", "detection", "incident", "publish"],
  integration: ["source", "filter", "publish"],
};

function copy<T extends { en: string; ru: string }>(value: T, lang: BuilderLang) {
  return value[lang];
}

function builderWorkspaceFromQuery(value: string | null): BuilderWorkspace {
  return value === "correlation" ? "correlation" : "graph";
}

function starterBlocks(kind: BuilderFamilyId, lang: BuilderLang) {
  return (STARTER_LIBRARY[kind] || STARTER_LIBRARY.detection).map((type, index) => {
    const definition = BLOCK_LIBRARY.find((item) => item.type === type) || BLOCK_LIBRARY[0];
    return {
      id: `${type}-${Date.now()}-${index}`,
      type,
      stage: definition.stage,
      label: copy(definition.title, lang),
      config: { links_to: [] },
    } satisfies BuilderBlockRecord;
  });
}

function emptyDraftForm(lang: BuilderLang): BuilderDraftForm {
  return {
    id: "",
    title: lang === "ru" ? "Новый поток" : "New flow",
    description: "",
    kind: "detection",
    status: "draft",
    blocks: starterBlocks("detection", lang),
  };
}

function emptyCorrelationPack(lang: BuilderLang): CorrelationPackForm {
  return {
    pack_id: "",
    title: lang === "ru" ? "Новый пакет корреляции" : "New correlation pack",
    version: "1.0.0",
    status: "draft",
    owner: "soc-platform",
    notes: [],
    stream_rules: [],
  };
}

function draftFromRecord(record: BuilderDraftRecord | null, lang: BuilderLang): BuilderDraftForm {
  if (!record) return emptyDraftForm(lang);
  return {
    id: String(record.id || ""),
    title: String(record.title || (lang === "ru" ? "Новый поток" : "New flow")),
    description: String(record.description || ""),
    kind: (String(record.kind || "detection") as BuilderFamilyId),
    status: String(record.status || "draft"),
    blocks: Array.isArray(record.blocks) ? record.blocks.map((block) => ({ ...block, config: { ...(block.config || {}), links_to: Array.isArray(block.config?.links_to) ? [...block.config.links_to] : [] } })) : starterBlocks("detection", lang),
  };
}

function packFromRecord(record: CorrelationPackRecord | null, lang: BuilderLang): CorrelationPackForm {
  if (!record) return emptyCorrelationPack(lang);
  return {
    pack_id: String(record.pack_id || ""),
    title: String(record.title || (lang === "ru" ? "Новый пакет корреляции" : "New correlation pack")),
    version: String(record.version || "1.0.0"),
    status: String(record.status || "draft"),
    owner: String(record.owner || "soc-platform"),
    notes: Array.isArray(record.notes) ? record.notes.map((item) => String(item || "")) : [],
    stream_rules: Array.isArray(record.stream_rules) ? record.stream_rules.map((rule) => ({ ...rule })) : [],
  };
}

function upsertDraft(items: BuilderDraftRecord[], next: BuilderDraftRecord) {
  const existing = items.some((item) => String(item.id || "") === String(next.id || ""));
  if (existing) {
    return items.map((item) => (String(item.id || "") === String(next.id || "") ? { ...item, ...next } : item));
  }
  return [next, ...items];
}

function upsertPack(items: CorrelationPackRecord[], next: CorrelationPackRecord) {
  const existing = items.some((item) => String(item.pack_id || "") === String(next.pack_id || ""));
  if (existing) {
    return items.map((item) => (String(item.pack_id || "") === String(next.pack_id || "") ? { ...item, ...next } : item));
  }
  return [next, ...items];
}

function summarizeBlocksByStage(blocks: BuilderBlockRecord[], lang: BuilderLang) {
  return STAGES.map((stage) => {
    const items = blocks.filter((block) => String(block.stage || "") === stage.id);
    return {
      id: stage.id,
      label: lang === "ru" ? stage.ru : stage.en,
      items,
    };
  });
}

function createBlock(type: string, lang: BuilderLang, index: number) {
  const definition = BLOCK_LIBRARY.find((item) => item.type === type) || BLOCK_LIBRARY[0];
  return {
    id: `${type}-${Date.now()}-${index}`,
    type,
    stage: definition.stage,
    label: copy(definition.title, lang),
    config: { links_to: [] },
  } satisfies BuilderBlockRecord;
}

function localizedBuilderStatus(status: string, lang: BuilderLang) {
  const map: Record<string, { en: string; ru: string }> = {
    draft: { en: "draft", ru: "черновик" },
    active: { en: "active", ru: "активно" },
    published: { en: "published", ru: "опубликовано" },
    maintenance: { en: "maintenance", ru: "обслуживание" },
  };
  return map[status]?.[lang] || status;
}

function localizedStage(stageId: string, lang: BuilderLang) {
  const item = STAGES.find((stage) => stage.id === stageId);
  return item ? (lang === "ru" ? item.ru : item.en) : stageId;
}

function localizedBlockTitle(block: BuilderBlockRecord, lang: BuilderLang) {
  const definition = BLOCK_LIBRARY.find((item) => item.type === block.type);
  return String(block.label || (definition ? copy(definition.title, lang) : block.type));
}

function defaultRule(lang: BuilderLang, nextId: number): CorrelationRuleRecord {
  return {
    id: nextId,
    title: lang === "ru" ? "Новое правило корреляции" : "New correlation rule",
    severity: "medium",
    window_s: 300,
    threshold: 1,
    entity_field: "host.name",
    suppression_key: "host.name + service.name + rule_family",
    status: "draft",
    operator_action: "",
    sigma_yaml: "title: New correlation rule\nid: sigma-new-correlation-rule\nstatus: experimental\nlogsource:\n  product: custom\n  service: runtime\ndetection:\n  selection:\n    event.provider: custom.runtime\n  condition: selection\nlevel: medium\n",
  };
}

function WindowCard({
  kicker,
  title,
  subtitle,
  status,
  onOpen,
  actionLabel,
}: {
  kicker: string;
  title: string;
  subtitle: string;
  status?: string;
  onOpen: () => void;
  actionLabel: string;
}) {
  return (
    <section className="react-card react-card-nested react-window-launcher react-builders-window-card">
      <div className="react-window-launcher-copy">
        <div className="react-top-kicker">{kicker}</div>
        <strong>{title}</strong>
        <p className="react-muted">{subtitle}</p>
      </div>
      <div className="react-actions react-wrap react-window-launcher-actions">
        {status ? <StatusBadge value={status} /> : null}
        <button type="button" className="react-primary-button" onClick={onOpen}>
          {actionLabel}
        </button>
      </div>
    </section>
  );
}

export function BuildersWorkbench() {
  const { lang, formatTimestamp } = useShellContext();
  const { pushToast } = useFeedback();
  const [searchParams, setSearchParams] = useSearchParams();
  const [workspace, setWorkspace] = useState<BuilderWorkspace>(() => builderWorkspaceFromQuery(searchParams.get("workspace")));
  const [draftRefreshToken, setDraftRefreshToken] = useState(0);
  const [correlationRefreshToken, setCorrelationRefreshToken] = useState(0);
  const [selectedDraftId, setSelectedDraftId] = useState("");
  const [selectedPackId, setSelectedPackId] = useState("");
  const [selectedBlockId, setSelectedBlockId] = useState("");
  const [selectedRuleId, setSelectedRuleId] = useState(0);
  const [draftForm, setDraftForm] = useState<BuilderDraftForm>(() => emptyDraftForm(lang));
  const [correlationForm, setCorrelationForm] = useState<CorrelationPackForm>(() => emptyCorrelationPack(lang));
  const [blockForm, setBlockForm] = useState<BuilderBlockRecord | null>(null);
  const [draftEditorOpen, setDraftEditorOpen] = useState(false);
  const [draftTopologyOpen, setDraftTopologyOpen] = useState(false);
  const [blockEditorOpen, setBlockEditorOpen] = useState(false);
  const [draftLifecycleOpen, setDraftLifecycleOpen] = useState(false);
  const [packEditorOpen, setPackEditorOpen] = useState(false);
  const [ruleEditorOpen, setRuleEditorOpen] = useState(false);
  const [packLifecycleOpen, setPackLifecycleOpen] = useState(false);
  const [draftSearch, setDraftSearch] = useState("");
  const [packSearch, setPackSearch] = useState("");
  const [draftValidationOutput, setDraftValidationOutput] = useState<BuilderValidationResponse | RuntimeBlob | null>(null);
  const [draftTestOutput, setDraftTestOutput] = useState<BuilderTestResponse | RuntimeBlob | null>(null);
  const [draftPublishOutput, setDraftPublishOutput] = useState<BuilderPublishResponse | RuntimeBlob | null>(null);
  const [packValidationOutput, setPackValidationOutput] = useState<BuilderValidationResponse | RuntimeBlob | null>(null);
  const [packTestOutput, setPackTestOutput] = useState<CorrelationPackTestResponse | RuntimeBlob | null>(null);
  const [packPublishOutput, setPackPublishOutput] = useState<BuilderPublishResponse | RuntimeBlob | null>(null);
  const draftsState = useAsyncData(
    useCallback(() => {
      void draftRefreshToken;
      return api.builderDrafts();
    }, [draftRefreshToken]),
  );
  const correlationPacksState = useAsyncData(
    useCallback(() => {
      void correlationRefreshToken;
      return api.correlationPacks();
    }, [correlationRefreshToken]),
  );
  const correlationPackDetailState = useAsyncData(
    useCallback(() => (selectedPackId ? api.correlationPackDetail(selectedPackId) : Promise.resolve({ item: null })), [selectedPackId]),
  );
  const [drafts, setDrafts] = useState<BuilderDraftRecord[]>([]);
  const [correlationPacks, setCorrelationPacks] = useState<CorrelationPackRecord[]>([]);
  const selectedDraft = useMemo(
    () => drafts.find((item) => String(item.id || "") === selectedDraftId) || null,
    [drafts, selectedDraftId],
  );
  const selectedRule = useMemo(
    () => correlationForm.stream_rules.find((item) => Number(item.id || 0) === selectedRuleId) || null,
    [correlationForm.stream_rules, selectedRuleId],
  );
  useEffect(() => {
    if (draftsState.data?.items) {
      setDrafts(draftsState.data.items);
      if (!selectedDraftId && draftsState.data.items[0]?.id) {
        setSelectedDraftId(String(draftsState.data.items[0].id || ""));
      }
    }
  }, [draftsState.data?.items, selectedDraftId]);

  useEffect(() => {
    if (correlationPacksState.data?.items) {
      setCorrelationPacks(correlationPacksState.data.items);
      if (!selectedPackId && correlationPacksState.data.items[0]?.pack_id) {
        setSelectedPackId(String(correlationPacksState.data.items[0].pack_id || ""));
      }
    }
  }, [correlationPacksState.data?.items, selectedPackId]);

  useEffect(() => {
    if (selectedDraft) {
      setDraftForm(draftFromRecord(selectedDraft, lang));
      const firstBlock = selectedDraft.blocks?.[0];
      setSelectedBlockId(firstBlock ? String(firstBlock.id || "") : "");
    }
  }, [lang, selectedDraft]);

  useEffect(() => {
    if (correlationPackDetailState.data?.item) {
      const nextForm = packFromRecord(correlationPackDetailState.data.item, lang);
      setCorrelationForm(nextForm);
      const firstRule = nextForm.stream_rules[0];
      setSelectedRuleId(firstRule ? Number(firstRule.id || 0) : 0);
    }
  }, [correlationPackDetailState.data?.item, lang]);

  useEffect(() => {
    const next = new URLSearchParams(searchParams);
    if (workspace === "correlation") {
      next.set("workspace", "correlation");
    } else {
      next.delete("workspace");
    }
    if (next.toString() !== searchParams.toString()) {
      setSearchParams(next, { replace: true });
    }
  }, [searchParams, setSearchParams, workspace]);

  const filteredDrafts = useMemo(() => {
    const query = String(draftSearch || "").trim().toLowerCase();
    if (!query) return drafts;
    return drafts.filter((item) =>
      [item.title, item.description, item.kind, item.status].some((value) => String(value || "").toLowerCase().includes(query)),
    );
  }, [draftSearch, drafts]);

  const filteredPacks = useMemo(() => {
    const query = String(packSearch || "").trim().toLowerCase();
    if (!query) return correlationPacks;
    return correlationPacks.filter((item) =>
      [item.pack_id, item.title, item.owner, item.status].some((value) => String(value || "").toLowerCase().includes(query)),
    );
  }, [correlationPacks, packSearch]);

  const builderMetrics = useMemo(
    () => ({
      drafts: drafts.length,
      published: drafts.filter((item) => String(item.status || "").toLowerCase() === "published").length,
      blocks: draftForm.blocks.length,
    }),
    [draftForm.blocks.length, drafts],
  );

  const correlationMetrics = useMemo(
    () => ({
      packs: correlationPacks.length,
      rules: correlationForm.stream_rules.length,
      active: correlationPacks.reduce((total, item) => total + Number(item.active_stream_rules || 0), 0),
    }),
    [correlationForm.stream_rules.length, correlationPacks],
  );

  const stageSummary = useMemo(() => summarizeBlocksByStage(draftForm.blocks, lang), [draftForm.blocks, lang]);

  function openNewDraft(kind: BuilderFamilyId = "detection") {
    const next = emptyDraftForm(lang);
    next.kind = kind;
    next.blocks = starterBlocks(kind, lang);
    setSelectedDraftId("");
    setSelectedBlockId(String(next.blocks[0]?.id || ""));
    setDraftForm(next);
    setDraftEditorOpen(true);
  }

  function openDraftFromList(draft: BuilderDraftRecord) {
    setSelectedDraftId(String(draft.id || ""));
    setDraftForm(draftFromRecord(draft, lang));
    setSelectedBlockId(String(draft.blocks?.[0]?.id || ""));
  }

  async function saveDraft() {
    const payload = await api.saveBuilderDraft({
      id: draftForm.id,
      title: draftForm.title,
      description: draftForm.description,
      kind: draftForm.kind,
      status: draftForm.status || "draft",
      blocks: draftForm.blocks,
    });
    setDrafts((current) => upsertDraft(current, payload));
    setSelectedDraftId(String(payload.id || ""));
    setDraftForm(draftFromRecord(payload, lang));
    setDraftRefreshToken((current) => current + 1);
    pushToast({
      title: t(lang, { en: "Draft saved", ru: "Черновик сохранен" }),
      message: t(lang, {
        en: "The current builder flow is saved and ready for validation.",
        ru: "Текущий поток конструктора сохранен и готов к проверке.",
      }),
      tone: "success",
    });
    setDraftEditorOpen(false);
    return payload;
  }

  async function validateDraft() {
    const payload = await api.validateBuilder({
      title: draftForm.title,
      description: draftForm.description,
      kind: draftForm.kind,
      blocks: draftForm.blocks,
    });
    setDraftValidationOutput(payload);
    setDraftLifecycleOpen(true);
  }

  async function testDraft() {
    const payload = await api.testBuilder({
      title: draftForm.title,
      description: draftForm.description,
      kind: draftForm.kind,
      blocks: draftForm.blocks,
    });
    setDraftTestOutput(payload);
    setDraftLifecycleOpen(true);
  }

  async function publishDraft() {
    const saved = await saveDraft();
    const payload = await api.publishBuilder(String(saved.id || ""));
    setDraftPublishOutput(payload);
    setDrafts((current) =>
      upsertDraft(current, {
        ...saved,
        status: String(payload.status || "published"),
        version: payload.version,
        published_ts: payload.published_ts,
        updated_ts: payload.published_ts,
      }),
    );
    setDraftLifecycleOpen(true);
  }

  async function deleteDraft() {
    if (!selectedDraftId) return;
    if (!window.confirm(t(lang, { en: "Delete this draft?", ru: "Удалить этот черновик?" }))) return;
    await api.deleteBuilderDraft(selectedDraftId);
    setDrafts((current) => current.filter((item) => String(item.id || "") !== selectedDraftId));
    setSelectedDraftId("");
    setDraftForm(emptyDraftForm(lang));
    setSelectedBlockId("");
    pushToast({
      title: t(lang, { en: "Draft removed", ru: "Черновик удален" }),
      message: t(lang, {
        en: "The builder draft was removed from the workbench list.",
        ru: "Черновик убран из списка рабочего стола.",
      }),
      tone: "success",
    });
    setDraftRefreshToken((current) => current + 1);
  }

  function openNewBlock(type?: string) {
    const block = createBlock(type || BLOCK_LIBRARY[0].type, lang, draftForm.blocks.length + 1);
    setBlockForm(block);
    setBlockEditorOpen(true);
  }

  function openExistingBlock(block: BuilderBlockRecord) {
    setSelectedBlockId(String(block.id || ""));
    setBlockForm({ ...block, config: { ...(block.config || {}), links_to: Array.isArray(block.config?.links_to) ? [...block.config.links_to] : [] } });
    setBlockEditorOpen(true);
  }

  function saveBlock() {
    if (!blockForm) return;
    setDraftForm((current) => {
      const existing = current.blocks.some((item) => String(item.id || "") === String(blockForm.id || ""));
      const blocks = existing
        ? current.blocks.map((item) => (String(item.id || "") === String(blockForm.id || "") ? blockForm : item))
        : [...current.blocks, blockForm];
      return { ...current, blocks };
    });
    setSelectedBlockId(String(blockForm.id || ""));
    setBlockEditorOpen(false);
  }

  function removeBlock(blockId: string) {
    setDraftForm((current) => ({
      ...current,
      blocks: current.blocks
        .filter((item) => String(item.id || "") !== blockId)
        .map((item) =>
          String(item.id || "") === String(blockForm?.id || "")
            ? item
            : {
                ...item,
                config: {
                  ...(item.config || {}),
                  links_to: (item.config?.links_to || []).filter((targetId) => String(targetId || "") !== blockId),
                },
              },
        ),
    }));
    if (selectedBlockId === blockId) {
      setSelectedBlockId("");
    }
  }

  function createCorrelationPack() {
    setSelectedPackId("");
    setSelectedRuleId(0);
    setCorrelationForm(emptyCorrelationPack(lang));
    setPackEditorOpen(true);
  }

  function createCorrelationRule() {
    const nextId = Math.max(2400, ...correlationForm.stream_rules.map((item) => Number(item.id || 0))) + 1;
    const nextRule = defaultRule(lang, nextId);
    setCorrelationForm((current) => ({ ...current, stream_rules: [...current.stream_rules, nextRule] }));
    setSelectedRuleId(nextId);
    setRuleEditorOpen(true);
  }

  function updateCorrelationRule(ruleId: number, patch: Partial<CorrelationRuleRecord>) {
    setCorrelationForm((current) => ({
      ...current,
      stream_rules: current.stream_rules.map((item) => (Number(item.id || 0) === ruleId ? { ...item, ...patch } : item)),
    }));
  }

  function removeCorrelationRule(ruleId: number) {
    setCorrelationForm((current) => ({
      ...current,
      stream_rules: current.stream_rules.filter((item) => Number(item.id || 0) !== ruleId),
    }));
    if (selectedRuleId === ruleId) {
      setSelectedRuleId(0);
    }
    setRuleEditorOpen(false);
  }

  async function saveCorrelationPack() {
    const payload = await api.saveCorrelationPack(correlationForm as unknown as Record<string, unknown>);
    setCorrelationPacks((current) => upsertPack(current, payload));
    setSelectedPackId(String(payload.pack_id || ""));
    setCorrelationForm(packFromRecord(payload, lang));
    setCorrelationRefreshToken((current) => current + 1);
    pushToast({
      title: t(lang, { en: "Pack saved", ru: "Пакет сохранен" }),
      message: t(lang, {
        en: "The correlation pack is saved and ready for validation or publish.",
        ru: "Пакет корреляции сохранен и готов к проверке или публикации.",
      }),
      tone: "success",
    });
    setPackEditorOpen(false);
    return payload;
  }

  async function validateCorrelationPack() {
    const payload = await api.validateCorrelationPack(correlationForm.pack_id || "draft-pack", correlationForm as unknown as Record<string, unknown>);
    setPackValidationOutput(payload);
    setPackLifecycleOpen(true);
  }

  async function testCorrelationPack() {
    const payload = await api.testCorrelationPack(correlationForm.pack_id || "draft-pack", correlationForm as unknown as Record<string, unknown>);
    setPackTestOutput(payload);
    setPackLifecycleOpen(true);
  }

  async function publishCorrelationPack() {
    const saved = correlationForm.pack_id ? correlationForm : await saveCorrelationPack();
    const payload = await api.publishCorrelationPack(saved.pack_id);
    setPackPublishOutput(payload);
    setCorrelationRefreshToken((current) => current + 1);
    setPackLifecycleOpen(true);
  }

  return (
    <AsyncGate
      states={[draftsState, correlationPacksState, correlationPackDetailState]}
      loadingMessage={t(lang, { en: "Loading builder workspace...", ru: "Загрузка рабочего пространства конструкторов..." })}
    >
      <div className="react-page react-page-builders react-builders-workbench">
        <SectionIntro
          kicker={t(lang, { en: "Builders", ru: "Конструкторы" })}
          title={t(lang, { en: "Windowed content workbench", ru: "Оконный рабочий стол контента" })}
          subtitle={t(lang, {
            en: "Detection flows and correlation packs now live in a cleaner launcher-and-drawer layout.",
            ru: "Потоки детектирования и пакеты корреляции теперь живут в более чистой схеме с лаунчером и боковыми окнами.",
          })}
          icon="builders"
          actions={
            <div className="react-actions react-wrap">
              <div className="react-segmented">
                <button type="button" className={workspace === "graph" ? "active" : ""} onClick={() => setWorkspace("graph")}>
                  {t(lang, { en: "Flows", ru: "Потоки" })}
                </button>
                <button type="button" className={workspace === "correlation" ? "active" : ""} onClick={() => setWorkspace("correlation")}>
                  {t(lang, { en: "Correlation", ru: "Корреляция" })}
                </button>
              </div>
              <button
                type="button"
                className="react-primary-button"
                onClick={() => (workspace === "graph" ? openNewDraft() : createCorrelationPack())}
              >
                {workspace === "graph"
                  ? t(lang, { en: "New flow", ru: "Новый поток" })
                  : t(lang, { en: "New pack", ru: "Новый пакет" })}
              </button>
            </div>
          }
        />

        <div className="react-builders-shell">
          <aside className="react-builders-sidebar">
            {workspace === "graph" ? (
              <>
                <div className="react-grid react-grid-1 react-builders-metric-grid">
                  <StatCard
                    label={t(lang, { en: "Drafts", ru: "Черновики" })}
                    value={builderMetrics.drafts}
                    hint={t(lang, { en: "Workbench flows in progress", ru: "Потоки в работе" })}
                  />
                  <StatCard
                    label={t(lang, { en: "Published", ru: "Опубликовано" })}
                    value={builderMetrics.published}
                    hint={t(lang, { en: "Runtime-ready flows", ru: "Потоки, готовые к runtime" })}
                  />
                  <StatCard
                    label={t(lang, { en: "Blocks in focus", ru: "Блоков в фокусе" })}
                    value={builderMetrics.blocks}
                    hint={t(lang, { en: "Visible in the current flow", ru: "Видно в текущем потоке" })}
                  />
                </div>
                <WindowCard
                  kicker={t(lang, { en: "Window 1", ru: "Окно 1" })}
                  title={draftForm.title}
                  subtitle={t(lang, { en: "Metadata, family and release state for the current flow.", ru: "Метаданные, семейство и состояние выпуска текущего потока." })}
                  status={localizedBuilderStatus(draftForm.status || "draft", lang)}
                  actionLabel={t(lang, { en: "Open flow window", ru: "Открыть окно потока" })}
                  onOpen={() => setDraftEditorOpen(true)}
                />
                <WindowCard
                  kicker={t(lang, { en: "Window 2", ru: "Окно 2" })}
                  title={t(lang, { en: "Topology and blocks", ru: "Топология и блоки" })}
                  subtitle={t(lang, { en: "Manage stage lanes, add blocks and wire the flow.", ru: "Управляйте дорожками этапов, добавляйте блоки и связывайте поток." })}
                  status={`${draftForm.blocks.length} ${t(lang, { en: "blocks", ru: "блоков" })}`}
                  actionLabel={t(lang, { en: "Open topology", ru: "Открыть топологию" })}
                  onOpen={() => setDraftTopologyOpen(true)}
                />
                <WindowCard
                  kicker={t(lang, { en: "Window 3", ru: "Окно 3" })}
                  title={t(lang, { en: "Validation and publish", ru: "Проверка и публикация" })}
                  subtitle={t(lang, { en: "Run validate, test and publish from one execution drawer.", ru: "Запускайте проверку, тест и публикацию из одного окна выполнения." })}
                  actionLabel={t(lang, { en: "Open lifecycle", ru: "Открыть lifecycle" })}
                  onOpen={() => setDraftLifecycleOpen(true)}
                />
              </>
            ) : (
              <>
                <div className="react-grid react-grid-1 react-builders-metric-grid">
                  <StatCard
                    label={t(lang, { en: "Packs", ru: "Пакеты" })}
                    value={correlationMetrics.packs}
                    hint={t(lang, { en: "Correlation families on the desk", ru: "Пакеты корреляции на столе" })}
                  />
                  <StatCard
                    label={t(lang, { en: "Rules in pack", ru: "Правил в пакете" })}
                    value={correlationMetrics.rules}
                    hint={t(lang, { en: "Rules in the selected pack", ru: "Правила в выбранном пакете" })}
                  />
                  <StatCard
                    label={t(lang, { en: "Active stream rules", ru: "Активных stream-правил" })}
                    value={correlationMetrics.active}
                    hint={t(lang, { en: "Already enabled in runtime", ru: "Уже включены в runtime" })}
                  />
                </div>
                <WindowCard
                  kicker={t(lang, { en: "Window 1", ru: "Окно 1" })}
                  title={correlationForm.title}
                  subtitle={t(lang, { en: "Pack metadata, owner and pack-level notes.", ru: "Метаданные пакета, владелец и заметки верхнего уровня." })}
                  status={localizedBuilderStatus(correlationForm.status || "draft", lang)}
                  actionLabel={t(lang, { en: "Open pack window", ru: "Открыть окно пакета" })}
                  onOpen={() => setPackEditorOpen(true)}
                />
                <WindowCard
                  kicker={t(lang, { en: "Window 2", ru: "Окно 2" })}
                  title={t(lang, { en: "Rules", ru: "Правила" })}
                  subtitle={t(lang, { en: "Create and edit stream rules in a focused side editor.", ru: "Создавайте и редактируйте stream-правила в отдельном боковом редакторе." })}
                  status={`${correlationForm.stream_rules.length} ${t(lang, { en: "rules", ru: "правил" })}`}
                  actionLabel={t(lang, { en: "Open rule window", ru: "Открыть окно правил" })}
                  onOpen={() => {
                    if (!correlationForm.stream_rules.length) createCorrelationRule();
                    else setRuleEditorOpen(true);
                  }}
                />
                <WindowCard
                  kicker={t(lang, { en: "Window 3", ru: "Окно 3" })}
                  title={t(lang, { en: "Validation and publish", ru: "Проверка и публикация" })}
                  subtitle={t(lang, { en: "Run validation, test compilation and publish here.", ru: "Запускайте проверку, тестовую компиляцию и публикацию здесь." })}
                  actionLabel={t(lang, { en: "Open lifecycle", ru: "Открыть lifecycle" })}
                  onOpen={() => setPackLifecycleOpen(true)}
                />
              </>
            )}
          </aside>

          <div className="react-builders-main">
            {workspace === "graph" ? (
              <>
                <section className="react-card">
                  <PanelHeader
                    title={t(lang, { en: "Builder families", ru: "Семейства конструкторов" })}
                    subtitle={t(lang, { en: "Start from a family template instead of building from a blank canvas.", ru: "Стартуйте от семейства, а не от пустого полотна." })}
                    icon="builders"
                  />
                  <div className="react-builders-launch-grid">
                    {BUILDER_FAMILIES.map((family) => (
                      <button key={family.id} type="button" className="react-chip-card react-chip-card-button react-builders-family-card" onClick={() => openNewDraft(family.id)}>
                        <div className="react-top-kicker">{family.id}</div>
                        <strong>{copy(family.title, lang)}</strong>
                        <span>{copy(family.subtitle, lang)}</span>
                      </button>
                    ))}
                  </div>
                </section>
                <section className="react-card">
                  <PanelHeader
                    title={t(lang, { en: "Flow library", ru: "Библиотека потоков" })}
                    subtitle={t(lang, { en: "Select a draft, then open the appropriate side window for metadata, topology or release.", ru: "Выберите черновик, затем откройте нужное боковое окно для метаданных, топологии или выпуска." })}
                    icon="dashboard"
                    actions={
                      <input
                        className="react-input"
                        value={draftSearch}
                        onChange={(event) => setDraftSearch(event.target.value)}
                        placeholder={t(lang, { en: "Search flow title, family or state...", ru: "Поиск по названию потока, семейству или состоянию..." })}
                      />
                    }
                  />
                  <div className="react-builders-draft-grid">
                    {filteredDrafts.map((draft) => (
                      <button key={draft.id} type="button" className={`react-card react-card-button react-builders-draft-card ${selectedDraftId === draft.id ? "active" : ""}`} onClick={() => openDraftFromList(draft)}>
                        <div className="react-card-button-header">
                          <div>
                            <strong>{draft.title}</strong>
                            <div className="react-card-button-copy">{copy(BUILDER_FAMILIES.find((item) => item.id === draft.kind)?.title || BUILDER_FAMILIES[0].title, lang)}</div>
                          </div>
                          <StatusBadge value={draft.status || "draft"} />
                        </div>
                        <div className="react-card-button-copy">{draft.description || t(lang, { en: "No description yet.", ru: "Описание пока не задано." })}</div>
                        <div className="react-card-button-grid">
                          <span>{t(lang, { en: "Blocks", ru: "Блоки" })}</span>
                          <strong>{draft.blocks?.length || 0}</strong>
                          <span>{t(lang, { en: "Updated", ru: "Обновлен" })}</span>
                          <strong>{draft.updated_ts ? formatTimestamp(draft.updated_ts, "compact") : t(lang, { en: "n/a", ru: "н/д" })}</strong>
                        </div>
                      </button>
                    ))}
                    {!filteredDrafts.length ? <EmptyState message={t(lang, { en: "No drafts found for the current search.", ru: "По текущему запросу черновики не найдены." })} /> : null}
                  </div>
                </section>
                <section className="react-card">
                  <PanelHeader
                    title={t(lang, { en: "Stage overview", ru: "Обзор этапов" })}
                    subtitle={t(lang, { en: "Each lane shows the current flow composition without forcing you into an overloaded canvas.", ru: "Каждая дорожка показывает состав текущего потока без перегруженного canvas." })}
                    icon="events"
                  />
                  <div className="react-builder-stage-grid">
                    {stageSummary.map((stage) => (
                      <section key={stage.id} className="react-card react-card-nested react-builder-stage-card">
                        <div className="react-card-button-header">
                          <strong>{stage.label}</strong>
                          <span className="react-badge soft">{stage.items.length}</span>
                        </div>
                        <div className="react-builders-stage-list">
                          {stage.items.length ? stage.items.slice(0, 4).map((block) => (
                            <button key={block.id} type="button" className="react-list-item" onClick={() => openExistingBlock(block)}>
                              <strong>{localizedBlockTitle(block, lang)}</strong>
                              <span>{block.type}</span>
                            </button>
                          )) : <EmptyState message={t(lang, { en: "No blocks in this lane yet.", ru: "В этой дорожке пока нет блоков." })} />}
                        </div>
                      </section>
                    ))}
                  </div>
                </section>
              </>
            ) : (
              <>
                <section className="react-card">
                  <PanelHeader
                    title={t(lang, { en: "Correlation packs", ru: "Пакеты корреляции" })}
                    subtitle={t(lang, { en: "Pack-level navigation replaces the previous overloaded all-in-one screen.", ru: "Навигация на уровне пакетов заменяет прежний перегруженный экран." })}
                    icon="builders"
                    actions={
                      <input
                        className="react-input"
                        value={packSearch}
                        onChange={(event) => setPackSearch(event.target.value)}
                        placeholder={t(lang, { en: "Search pack id, title or owner...", ru: "Поиск по id пакета, названию или владельцу..." })}
                      />
                    }
                  />
                  <div className="react-builders-pack-grid">
                    {filteredPacks.map((pack) => (
                      <button key={pack.pack_id} type="button" className={`react-card react-card-button react-builders-pack-card ${selectedPackId === pack.pack_id ? "active" : ""}`} onClick={() => setSelectedPackId(String(pack.pack_id || ""))}>
                        <div className="react-card-button-header">
                          <div>
                            <strong>{pack.title || pack.pack_id}</strong>
                            <div className="react-card-button-copy">{pack.pack_id}</div>
                          </div>
                          <StatusBadge value={pack.status || "draft"} />
                        </div>
                        <div className="react-card-button-grid">
                          <span>{t(lang, { en: "Rules", ru: "Правила" })}</span>
                          <strong>{pack.rule_count || pack.stream_rules?.length || 0}</strong>
                          <span>{t(lang, { en: "Active", ru: "Активно" })}</span>
                          <strong>{pack.active_stream_rules || 0}</strong>
                        </div>
                      </button>
                    ))}
                    {!filteredPacks.length ? <EmptyState message={t(lang, { en: "No packs found for the current search.", ru: "По текущему запросу пакеты не найдены." })} /> : null}
                  </div>
                </section>
                <section className="react-card">
                  <PanelHeader
                    title={t(lang, { en: "Rule deck", ru: "Дека правил" })}
                    subtitle={t(lang, { en: "Rules stay readable on the page; deep editing happens inside a focused side editor.", ru: "На странице правила остаются читаемыми, а глубокое редактирование уходит в отдельный редактор." })}
                    icon="incidents"
                    actions={
                      <button type="button" className="react-link-button" onClick={createCorrelationRule}>
                        {t(lang, { en: "New rule", ru: "Новое правило" })}
                      </button>
                    }
                  />
                  <div className="react-builders-rule-list">
                    {correlationForm.stream_rules.map((rule) => (
                      <button key={rule.id} type="button" className={`react-list-item react-builders-rule-row ${selectedRuleId === rule.id ? "active" : ""}`} onClick={() => { setSelectedRuleId(Number(rule.id || 0)); setRuleEditorOpen(true); }}>
                        <div>
                          <strong>{rule.title}</strong>
                          <div className="react-card-button-copy">{rule.suppression_key || "host.name + service.name + rule_family"}</div>
                        </div>
                        <div className="react-actions react-wrap">
                          <span className="react-badge soft">{rule.threshold || 1}</span>
                          <span className="react-badge soft">{rule.window_s || 300}s</span>
                          <StatusBadge value={rule.status || "draft"} />
                        </div>
                      </button>
                    ))}
                    {!correlationForm.stream_rules.length ? <EmptyState message={t(lang, { en: "This pack has no stream rules yet.", ru: "В этом пакете пока нет stream-правил." })} /> : null}
                  </div>
                </section>
              </>
            )}
          </div>
        </div>

        <DrawerOverlay
          open={draftEditorOpen}
          title={t(lang, { en: "Flow window", ru: "Окно потока" })}
          subtitle={t(lang, { en: "Metadata, family and release state for the selected builder flow.", ru: "Метаданные, семейство и состояние выпуска выбранного потока." })}
          onClose={() => setDraftEditorOpen(false)}
        >
          <div className="react-form-grid">
            <input className="react-input" value={draftForm.title} onChange={(event) => setDraftForm((current) => ({ ...current, title: event.target.value }))} placeholder={t(lang, { en: "Flow title", ru: "Название потока" })} />
            <select className="react-select" value={draftForm.kind} onChange={(event) => setDraftForm((current) => ({ ...current, kind: event.target.value as BuilderFamilyId, blocks: current.id ? current.blocks : starterBlocks(event.target.value as BuilderFamilyId, lang) }))}>
              {BUILDER_FAMILIES.map((family) => <option key={family.id} value={family.id}>{copy(family.title, lang)}</option>)}
            </select>
            <select className="react-select" value={draftForm.status} onChange={(event) => setDraftForm((current) => ({ ...current, status: event.target.value }))}>
              <option value="draft">{localizedBuilderStatus("draft", lang)}</option>
              <option value="active">{localizedBuilderStatus("active", lang)}</option>
              <option value="published">{localizedBuilderStatus("published", lang)}</option>
              <option value="maintenance">{localizedBuilderStatus("maintenance", lang)}</option>
            </select>
            <textarea className="react-query-editor react-input-full" value={draftForm.description} onChange={(event) => setDraftForm((current) => ({ ...current, description: event.target.value }))} />
          </div>
          <DrawerFieldGrid>
            <KeyValue label={t(lang, { en: "Blocks", ru: "Блоки" })} value={draftForm.blocks.length} />
            <KeyValue label={t(lang, { en: "Selected flow", ru: "Выбранный поток" })} value={selectedDraftId || t(lang, { en: "new draft", ru: "новый черновик" })} />
          </DrawerFieldGrid>
          <div className="react-actions react-wrap" style={{ marginTop: 20 }}>
            <button type="button" className="react-primary-button" onClick={() => void saveDraft()}>{t(lang, { en: "Save flow", ru: "Сохранить поток" })}</button>
            <button type="button" className="react-link-button" onClick={() => setDraftTopologyOpen(true)}>{t(lang, { en: "Open topology", ru: "Открыть топологию" })}</button>
            <button type="button" className="react-link-button" onClick={() => setDraftLifecycleOpen(true)}>{t(lang, { en: "Open lifecycle", ru: "Открыть lifecycle" })}</button>
            {selectedDraftId ? <button type="button" className="react-link-button" onClick={() => void deleteDraft()}>{t(lang, { en: "Delete draft", ru: "Удалить черновик" })}</button> : null}
          </div>
        </DrawerOverlay>

        <DrawerOverlay
          open={draftTopologyOpen}
          title={t(lang, { en: "Topology window", ru: "Окно топологии" })}
          subtitle={t(lang, { en: "All block editing stays here: stage lanes, labels and links.", ru: "Все редактирование блоков живет здесь: дорожки этапов, метки и связи." })}
          onClose={() => setDraftTopologyOpen(false)}
        >
          <section className="react-card react-card-nested">
            <PanelHeader title={t(lang, { en: "Block palette", ru: "Палитра блоков" })} subtitle={t(lang, { en: "Click a block type to spawn it into the current flow.", ru: "Нажмите на тип блока, чтобы добавить его в текущий поток." })} />
            <div className="react-builders-palette">
              {BLOCK_LIBRARY.map((item) => (
                <button key={item.type} type="button" className="react-chip-card react-chip-card-button react-builders-palette-card" onClick={() => openNewBlock(item.type)}>
                  <strong>{copy(item.title, lang)}</strong>
                  <span>{copy(item.subtitle, lang)}</span>
                </button>
              ))}
            </div>
          </section>
          <div className="react-builder-stage-grid" style={{ marginTop: 16 }}>
            {stageSummary.map((stage) => (
              <section key={stage.id} className="react-card react-card-nested react-builder-stage-card">
                <div className="react-card-button-header">
                  <strong>{stage.label}</strong>
                  <button type="button" className="react-link-button" onClick={() => openNewBlock(BLOCK_LIBRARY.find((item) => item.stage === stage.id)?.type || "source")}>
                    {t(lang, { en: "Add block", ru: "Добавить блок" })}
                  </button>
                </div>
                <div className="react-builders-stage-list">
                  {stage.items.map((block) => (
                    <div key={block.id} className="react-list-item react-builders-stage-row">
                      <div>
                        <strong>{localizedBlockTitle(block, lang)}</strong>
                        <div className="react-card-button-copy">{block.type}</div>
                      </div>
                      <div className="react-actions react-wrap">
                        <button type="button" className="react-link-button" onClick={() => openExistingBlock(block)}>{t(lang, { en: "Edit", ru: "Изменить" })}</button>
                        <button type="button" className="react-link-button" onClick={() => removeBlock(String(block.id || ""))}>{t(lang, { en: "Remove", ru: "Удалить" })}</button>
                      </div>
                    </div>
                  ))}
                  {!stage.items.length ? <EmptyState message={t(lang, { en: "Lane is empty.", ru: "Дорожка пуста." })} /> : null}
                </div>
              </section>
            ))}
          </div>
        </DrawerOverlay>

        <DrawerOverlay
          open={blockEditorOpen}
          title={t(lang, { en: "Block window", ru: "Окно блока" })}
          subtitle={t(lang, { en: "Edit a single block without losing context of the whole flow.", ru: "Редактируйте один блок, не теряя контекст всего потока." })}
          onClose={() => setBlockEditorOpen(false)}
        >
          {blockForm ? (
            <>
              <div className="react-form-grid">
                <input className="react-input" value={blockForm.label || ""} onChange={(event) => setBlockForm((current) => current ? { ...current, label: event.target.value } : current)} placeholder={t(lang, { en: "Block label", ru: "Название блока" })} />
                <select className="react-select" value={blockForm.stage || "ingest"} onChange={(event) => setBlockForm((current) => current ? { ...current, stage: event.target.value } : current)}>
                  {STAGES.map((stage) => <option key={stage.id} value={stage.id}>{localizedStage(stage.id, lang)}</option>)}
                </select>
                <input className="react-input" value={blockForm.type || ""} onChange={(event) => setBlockForm((current) => current ? { ...current, type: event.target.value } : current)} placeholder={t(lang, { en: "Block type", ru: "Тип блока" })} />
              </div>
              <section className="react-card react-card-nested" style={{ marginTop: 16 }}>
                <PanelHeader title={t(lang, { en: "Outgoing links", ru: "Исходящие связи" })} subtitle={t(lang, { en: "Choose which blocks receive the output of the current block.", ru: "Выберите, какие блоки получают выход текущего блока." })} />
                <div className="react-list react-list-compact">
                  {draftForm.blocks.filter((item) => String(item.id || "") !== String(blockForm.id || "")).map((item) => {
                    const links = Array.isArray(blockForm.config?.links_to) ? blockForm.config.links_to : [];
                    const checked = links.includes(String(item.id || ""));
                    return (
                      <label key={item.id} className="react-toggle react-toggle-card">
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => {
                            const nextLinks = checked ? links.filter((value) => value !== String(item.id || "")) : [...links, String(item.id || "")];
                            setBlockForm((current) => current ? { ...current, config: { ...(current.config || {}), links_to: nextLinks } } : current);
                          }}
                        />
                        <span>
                          <strong>{localizedBlockTitle(item, lang)}</strong>
                          <small>{localizedStage(String(item.stage || "ingest"), lang)}</small>
                        </span>
                      </label>
                    );
                  })}
                </div>
              </section>
              <div className="react-actions react-wrap" style={{ marginTop: 20 }}>
                <button type="button" className="react-primary-button" onClick={saveBlock}>{t(lang, { en: "Save block", ru: "Сохранить блок" })}</button>
              </div>
            </>
          ) : <EmptyState message={t(lang, { en: "Select or create a block first.", ru: "Сначала выберите или создайте блок." })} />}
        </DrawerOverlay>

        <DrawerOverlay
          open={draftLifecycleOpen}
          title={t(lang, { en: "Flow lifecycle", ru: "Жизненный цикл потока" })}
          subtitle={t(lang, { en: "Validate, test and publish without leaving the current workspace.", ru: "Проверяйте, тестируйте и публикуйте, не покидая текущее рабочее пространство." })}
          onClose={() => setDraftLifecycleOpen(false)}
        >
          <div className="react-actions react-wrap" style={{ marginBottom: 16 }}>
            <button type="button" className="react-primary-button" onClick={() => void validateDraft()}>{t(lang, { en: "Validate", ru: "Проверить" })}</button>
            <button type="button" className="react-link-button" onClick={() => void testDraft()}>{t(lang, { en: "Test", ru: "Тестировать" })}</button>
            <button type="button" className="react-link-button" onClick={() => void publishDraft()}>{t(lang, { en: "Publish", ru: "Опубликовать" })}</button>
          </div>
          <div className="react-builders-drawer-stack">
            <section className="react-card react-card-nested">
              <PanelHeader title={t(lang, { en: "Validation output", ru: "Результат проверки" })} subtitle={t(lang, { en: "Shape and metadata validation for the selected flow.", ru: "Проверка формы и метаданных выбранного потока." })} />
              {draftValidationOutput ? <JsonPreview value={draftValidationOutput} /> : <EmptyState message={t(lang, { en: "Run validate to inspect flow issues.", ru: "Запустите проверку, чтобы увидеть замечания по потоку." })} />}
            </section>
            <section className="react-card react-card-nested">
              <PanelHeader title={t(lang, { en: "Test output", ru: "Результат теста" })} subtitle={t(lang, { en: "Compile and runtime checks for the current flow.", ru: "Компиляция и runtime-проверки текущего потока." })} />
              {draftTestOutput ? <JsonPreview value={draftTestOutput} /> : <EmptyState message={t(lang, { en: "Run test to inspect the execution preview.", ru: "Запустите тест, чтобы увидеть превью выполнения." })} />}
            </section>
            <section className="react-card react-card-nested">
              <PanelHeader title={t(lang, { en: "Publish output", ru: "Результат публикации" })} subtitle={t(lang, { en: "Release response from the live builder pipeline.", ru: "Ответ контура публикации рабочего конструктора." })} />
              {draftPublishOutput ? <JsonPreview value={draftPublishOutput} /> : <EmptyState message={t(lang, { en: "Publish to inspect version and timestamps.", ru: "Опубликуйте поток, чтобы увидеть версию и временные метки." })} />}
            </section>
          </div>
        </DrawerOverlay>

        <DrawerOverlay
          open={packEditorOpen}
          title={t(lang, { en: "Correlation pack window", ru: "Окно пакета корреляции" })}
          subtitle={t(lang, { en: "Pack metadata, owner, version and notes stay here.", ru: "Метаданные пакета, владелец, версия и заметки живут здесь." })}
          onClose={() => setPackEditorOpen(false)}
        >
          <div className="react-form-grid">
            <input className="react-input" value={correlationForm.pack_id} onChange={(event) => setCorrelationForm((current) => ({ ...current, pack_id: event.target.value }))} placeholder={t(lang, { en: "pack_id", ru: "pack_id" })} />
            <input className="react-input" value={correlationForm.title} onChange={(event) => setCorrelationForm((current) => ({ ...current, title: event.target.value }))} placeholder={t(lang, { en: "Pack title", ru: "Название пакета" })} />
            <input className="react-input" value={correlationForm.version} onChange={(event) => setCorrelationForm((current) => ({ ...current, version: event.target.value }))} placeholder={t(lang, { en: "Version", ru: "Версия" })} />
            <input className="react-input" value={correlationForm.owner} onChange={(event) => setCorrelationForm((current) => ({ ...current, owner: event.target.value }))} placeholder={t(lang, { en: "Owner", ru: "Владелец" })} />
            <select className="react-select" value={correlationForm.status} onChange={(event) => setCorrelationForm((current) => ({ ...current, status: event.target.value }))}>
              <option value="draft">{localizedBuilderStatus("draft", lang)}</option>
              <option value="active">{localizedBuilderStatus("active", lang)}</option>
              <option value="maintenance">{localizedBuilderStatus("maintenance", lang)}</option>
            </select>
            <textarea className="react-query-editor react-input-full" value={correlationForm.notes.join("\n")} onChange={(event) => setCorrelationForm((current) => ({ ...current, notes: event.target.value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean) }))} />
          </div>
          <div className="react-actions react-wrap" style={{ marginTop: 20 }}>
            <button type="button" className="react-primary-button" onClick={() => void saveCorrelationPack()}>{t(lang, { en: "Save pack", ru: "Сохранить пакет" })}</button>
          </div>
        </DrawerOverlay>

        <DrawerOverlay
          open={ruleEditorOpen}
          title={t(lang, { en: "Rule window", ru: "Окно правила" })}
          subtitle={t(lang, { en: "Thresholds, suppression keys and Sigma stay in one focused editor.", ru: "Пороги, ключи подавления и Sigma находятся в одном сфокусированном редакторе." })}
          onClose={() => setRuleEditorOpen(false)}
        >
          {selectedRule ? (
            <>
              <div className="react-form-grid">
                <input className="react-input" value={selectedRule.title || ""} onChange={(event) => updateCorrelationRule(Number(selectedRule.id || 0), { title: event.target.value })} placeholder={t(lang, { en: "Rule title", ru: "Название правила" })} />
                <select className="react-select" value={selectedRule.severity || "medium"} onChange={(event) => updateCorrelationRule(Number(selectedRule.id || 0), { severity: event.target.value })}>
                  <option value="critical">critical</option>
                  <option value="high">high</option>
                  <option value="medium">medium</option>
                  <option value="low">low</option>
                </select>
                <input className="react-input" value={String(selectedRule.window_s || 300)} onChange={(event) => updateCorrelationRule(Number(selectedRule.id || 0), { window_s: Number(event.target.value || 300) })} placeholder={t(lang, { en: "Window seconds", ru: "Окно в секундах" })} />
                <input className="react-input" value={String(selectedRule.threshold || 1)} onChange={(event) => updateCorrelationRule(Number(selectedRule.id || 0), { threshold: Number(event.target.value || 1) })} placeholder={t(lang, { en: "Threshold", ru: "Порог" })} />
                <input className="react-input react-input-full" value={selectedRule.entity_field || "host.name"} onChange={(event) => updateCorrelationRule(Number(selectedRule.id || 0), { entity_field: event.target.value })} placeholder={t(lang, { en: "Entity field", ru: "Поле сущности" })} />
                <input className="react-input react-input-full" value={selectedRule.suppression_key || ""} onChange={(event) => updateCorrelationRule(Number(selectedRule.id || 0), { suppression_key: event.target.value })} placeholder={t(lang, { en: "Suppression key", ru: "Ключ подавления" })} />
                <input className="react-input react-input-full" value={selectedRule.operator_action || ""} onChange={(event) => updateCorrelationRule(Number(selectedRule.id || 0), { operator_action: event.target.value })} placeholder={t(lang, { en: "Operator action", ru: "Действие оператора" })} />
                <textarea className="react-query-editor react-input-full" value={selectedRule.sigma_yaml || ""} onChange={(event) => updateCorrelationRule(Number(selectedRule.id || 0), { sigma_yaml: event.target.value })} />
              </div>
              <div className="react-actions react-wrap" style={{ marginTop: 20 }}>
                <button type="button" className="react-primary-button" onClick={() => setRuleEditorOpen(false)}>{t(lang, { en: "Done", ru: "Готово" })}</button>
                <button type="button" className="react-link-button" onClick={() => removeCorrelationRule(Number(selectedRule.id || 0))}>{t(lang, { en: "Remove rule", ru: "Удалить правило" })}</button>
              </div>
            </>
          ) : <EmptyState message={t(lang, { en: "Select or create a rule first.", ru: "Сначала выберите или создайте правило." })} />}
        </DrawerOverlay>

        <DrawerOverlay
          open={packLifecycleOpen}
          title={t(lang, { en: "Correlation lifecycle", ru: "Жизненный цикл корреляции" })}
          subtitle={t(lang, { en: "Validation, test and publish now run from one quiet execution drawer.", ru: "Проверка, тест и публикация теперь выполняются из одного спокойного окна." })}
          onClose={() => setPackLifecycleOpen(false)}
        >
          <div className="react-actions react-wrap" style={{ marginBottom: 16 }}>
            <button type="button" className="react-primary-button" onClick={() => void validateCorrelationPack()}>{t(lang, { en: "Validate", ru: "Проверить" })}</button>
            <button type="button" className="react-link-button" onClick={() => void testCorrelationPack()}>{t(lang, { en: "Test", ru: "Тестировать" })}</button>
            <button type="button" className="react-link-button" onClick={() => void publishCorrelationPack()}>{t(lang, { en: "Publish", ru: "Опубликовать" })}</button>
          </div>
          <div className="react-builders-drawer-stack">
            <section className="react-card react-card-nested">
              <PanelHeader title={t(lang, { en: "Validation output", ru: "Результат проверки" })} subtitle={t(lang, { en: "Pack structure and rule metadata checks.", ru: "Проверка структуры пакета и метаданных правил." })} />
              {packValidationOutput ? <JsonPreview value={packValidationOutput} /> : <EmptyState message={t(lang, { en: "Run validate to inspect pack issues.", ru: "Запустите проверку, чтобы увидеть замечания по пакету." })} />}
            </section>
            <section className="react-card react-card-nested">
              <PanelHeader title={t(lang, { en: "Test output", ru: "Результат теста" })} subtitle={t(lang, { en: "Compile Sigma and run targeted pack tests.", ru: "Компилируйте Sigma и запускайте адресные тесты пакета." })} />
              {packTestOutput ? <JsonPreview value={packTestOutput} /> : <EmptyState message={t(lang, { en: "Run test to inspect pack execution.", ru: "Запустите тест, чтобы увидеть выполнение пакета." })} />}
            </section>
            <section className="react-card react-card-nested">
              <PanelHeader title={t(lang, { en: "Publish output", ru: "Результат публикации" })} subtitle={t(lang, { en: "Operational publish result written to the live catalog.", ru: "Результат публикации, записанный в рабочий каталог." })} />
              {packPublishOutput ? <JsonPreview value={packPublishOutput} /> : <EmptyState message={t(lang, { en: "Publish the pack to inspect runtime identifiers.", ru: "Опубликуйте пакет, чтобы увидеть runtime-идентификаторы." })} />}
            </section>
          </div>
        </DrawerOverlay>
      </div>
    </AsyncGate>
  );
}

export { BuildersWorkbench as BuildersPage };
