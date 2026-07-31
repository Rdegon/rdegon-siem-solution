import { useCallback, useEffect, useMemo, useState } from "react";
import { Download, FileJson, Play, Plus, Search } from "lucide-react";
import { useNavigate, useParams } from "react-router-dom";
import { api } from "../api";
import { t, useShellContext } from "../context";
import { useFeedback } from "../feedback";
import { useAsyncData, useDebouncedValue } from "../hooks";
import { NativeActionBar, NativePageHeader, NativePager } from "../native";
import {
  DrawerFieldGrid,
  DrawerOverlay,
  EmptyState,
  JsonPreview,
  KeyValue,
  SeverityBadge,
  StatusBadge,
} from "../ui";
import type {
  GeneratedReportDetailResponse,
  GeneratedReportRecord,
  GeneratedReportsResponse,
  ReportTemplateRecord,
  ReportTemplatesResponse,
  VulnFindingRow,
  VulnReportDetailResponse,
  VulnReportsResponse,
  VulnReportSummary,
} from "../types";

type ReportsTab = "templates" | "generated" | "scanner";

type TemplateDraft = {
  id?: string;
  name: string;
  description: string;
  owner: string;
  tenant_scope: string;
  period: ReportTemplateRecord["period"];
  retention_days: number;
  sections: string[];
  formats: Array<"json" | "csv">;
  schedule_enabled: boolean;
  schedule_frequency: string;
  schedule_time: string;
  schedule_timezone: string;
  schedule_recipients: string;
};

const REPORT_PAGE_SIZE = 25;
const SECTION_OPTIONS = [
  ["executive_summary", "Executive summary"],
  ["incidents", "Incidents and cases"],
  ["sources", "Source health"],
  ["assets", "Asset visibility"],
  ["vulnerabilities", "Vulnerability reports"],
  ["platform", "Platform status"],
] as const;

const EMPTY_DRAFT: TemplateDraft = {
  name: "",
  description: "",
  owner: "soc-ops",
  tenant_scope: "all",
  period: "24h",
  retention_days: 90,
  sections: ["executive_summary", "incidents", "sources", "platform"],
  formats: ["json", "csv"],
  schedule_enabled: false,
  schedule_frequency: "daily",
  schedule_time: "08:00",
  schedule_timezone: "Europe/Moscow",
  schedule_recipients: "",
};

function listText(value: unknown) {
  if (Array.isArray(value)) return value.map((item) => String(item || "").trim()).filter(Boolean).join(", ");
  return String(value || "").trim();
}

function templateToDraft(template: ReportTemplateRecord): TemplateDraft {
  return {
    id: template.id,
    name: template.name,
    description: template.description || "",
    owner: template.owner || "soc-ops",
    tenant_scope: listText(template.tenant_scope) || "all",
    period: template.period,
    retention_days: template.retention_days || 90,
    sections: [...(template.sections || [])],
    formats: [...(template.formats || ["json"])],
    schedule_enabled: Boolean(template.schedule?.enabled),
    schedule_frequency: template.schedule?.frequency || "daily",
    schedule_time: template.schedule?.time || "08:00",
    schedule_timezone: template.schedule?.timezone || "Europe/Moscow",
    schedule_recipients: listText(template.schedule?.recipients),
  };
}

function splitList(value: string) {
  return value.split(",").map((item) => item.trim()).filter(Boolean);
}

export function ReportsPage() {
  const { lang, formatTimestamp } = useShellContext();
  const { pushToast } = useFeedback();
  const navigate = useNavigate();
  const params = useParams<{ reportId?: string }>();
  const [tab, setTab] = useState<ReportsTab>(params.reportId ? "scanner" : "templates");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [refreshToken, setRefreshToken] = useState(0);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState<TemplateDraft>(EMPTY_DRAFT);
  const [selectedRunId, setSelectedRunId] = useState("");
  const [mutationState, setMutationState] = useState("");
  const debouncedQuery = useDebouncedValue(query, 250);
  const selectedScannerReportId = String(params.reportId || "");

  const loadTemplates = useCallback(() => {
    void refreshToken;
    return api.reportTemplates();
  }, [refreshToken]);
  const templatesState = useAsyncData<ReportTemplatesResponse>(loadTemplates);
  const loadRuns = useCallback(() => {
    void refreshToken;
    return api.generatedReports({ limit: 200 });
  }, [refreshToken]);
  const runsState = useAsyncData<GeneratedReportsResponse>(loadRuns);
  const loadScannerReports = useCallback(() => {
    void refreshToken;
    return api.reports();
  }, [refreshToken]);
  const scannerState = useAsyncData<VulnReportsResponse>(loadScannerReports);
  const loadRunDetail = useCallback(
    () => {
      void refreshToken;
      return selectedRunId ? api.generatedReportDetail(selectedRunId) : Promise.resolve(null);
    },
    [selectedRunId, refreshToken],
  );
  const runDetailState = useAsyncData<GeneratedReportDetailResponse | null>(loadRunDetail);
  const loadScannerDetail = useCallback(
    () => {
      void refreshToken;
      return selectedScannerReportId ? api.reportDetail(selectedScannerReportId) : Promise.resolve(null);
    },
    [selectedScannerReportId, refreshToken],
  );
  const scannerDetailState = useAsyncData<VulnReportDetailResponse | null>(loadScannerDetail);

  const token = debouncedQuery.trim().toLowerCase();
  const templates = useMemo(
    () => (templatesState.data?.items || []).filter((row) => !token || JSON.stringify(row).toLowerCase().includes(token)),
    [templatesState.data?.items, token],
  );
  const generatedReports = useMemo(
    () => (runsState.data?.items || []).filter((row) => !token || JSON.stringify(row).toLowerCase().includes(token)),
    [runsState.data?.items, token],
  );
  const scannerReports = useMemo(
    () => (scannerState.data?.items || []).filter((row) => !token || JSON.stringify(row).toLowerCase().includes(token)),
    [scannerState.data?.items, token],
  );
  const rows = tab === "templates" ? templates : tab === "generated" ? generatedReports : scannerReports;
  const pageCount = Math.max(1, Math.ceil(rows.length / REPORT_PAGE_SIZE));
  const visibleRows = useMemo(() => {
    const start = (page - 1) * REPORT_PAGE_SIZE;
    return rows.slice(start, start + REPORT_PAGE_SIZE);
  }, [page, rows]);

  useEffect(() => {
    setPage(1);
  }, [debouncedQuery, tab]);

  useEffect(() => {
    if (page > pageCount) setPage(pageCount);
  }, [page, pageCount]);

  useEffect(() => {
    if (params.reportId) setTab("scanner");
  }, [params.reportId]);

  const activeState = tab === "templates" ? templatesState : tab === "generated" ? runsState : scannerState;

  function openNewTemplate() {
    setDraft({ ...EMPTY_DRAFT, sections: [...EMPTY_DRAFT.sections], formats: [...EMPTY_DRAFT.formats] });
    setEditing(true);
  }

  function openTemplate(template: ReportTemplateRecord) {
    setDraft(templateToDraft(template));
    setEditing(true);
  }

  function toggleDraftList(field: "sections" | "formats", value: string) {
    setDraft((current) => {
      const values = current[field] as string[];
      const next = values.includes(value) ? values.filter((item) => item !== value) : [...values, value];
      return { ...current, [field]: next };
    });
  }

  async function saveTemplate() {
    if (!draft.name.trim() || !draft.sections.length || !draft.formats.length) {
      pushToast({
        tone: "warning",
        title: t(lang, { en: "Template is incomplete", ru: "Шаблон не заполнен" }),
        message: t(lang, {
          en: "Name, at least one section and one format are required.",
          ru: "Нужны название, хотя бы один раздел и один формат.",
        }),
      });
      return;
    }
    setMutationState("saving");
    try {
      await api.saveReportTemplate({
        id: draft.id,
        name: draft.name.trim(),
        description: draft.description.trim(),
        owner: draft.owner.trim(),
        tenant_scope: splitList(draft.tenant_scope),
        period: draft.period,
        retention_days: draft.retention_days,
        sections: draft.sections,
        formats: draft.formats,
        schedule: {
          enabled: draft.schedule_enabled,
          frequency: draft.schedule_frequency,
          time: draft.schedule_time,
          timezone: draft.schedule_timezone,
          recipients: splitList(draft.schedule_recipients),
        },
      });
      setEditing(false);
      setRefreshToken((value) => value + 1);
      pushToast({
        tone: "success",
        message: t(lang, { en: "Report template saved.", ru: "Шаблон отчёта сохранён." }),
      });
    } catch (error) {
      pushToast({ tone: "error", message: error instanceof Error ? error.message : String(error) });
    } finally {
      setMutationState("");
    }
  }

  async function deleteTemplate(template: ReportTemplateRecord) {
    if (!window.confirm(t(lang, {
      en: `Delete report template "${template.name}"?`,
      ru: `Удалить шаблон отчёта «${template.name}»?`,
    }))) return;
    setMutationState(`delete:${template.id}`);
    try {
      await api.deleteReportTemplate(template.id);
      setRefreshToken((value) => value + 1);
      pushToast({ tone: "success", message: t(lang, { en: "Template deleted.", ru: "Шаблон удалён." }) });
    } catch (error) {
      pushToast({ tone: "error", message: error instanceof Error ? error.message : String(error) });
    } finally {
      setMutationState("");
    }
  }

  async function runTemplate(template: ReportTemplateRecord) {
    setMutationState(`run:${template.id}`);
    try {
      const run = await api.runReportTemplate(template.id);
      setRefreshToken((value) => value + 1);
      setTab("generated");
      setSelectedRunId(run.id);
      pushToast({
        tone: run.status === "completed" ? "success" : "warning",
        title: t(lang, { en: "Report generated", ru: "Отчёт сформирован" }),
        message: `${run.record_count} records, ${run.duration_ms} ms`,
      });
    } catch (error) {
      pushToast({ tone: "error", message: error instanceof Error ? error.message : String(error) });
    } finally {
      setMutationState("");
    }
  }

  function downloadGenerated(run: GeneratedReportRecord, format: "json" | "csv") {
    const anchor = document.createElement("a");
    anchor.href = `/api/reporting/runs/${encodeURIComponent(run.id)}/artifact?format=${format}`;
    anchor.download = "";
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
  }

  function exportScannerRegister() {
    if (!scannerReports.length) return;
    const header = ["report_id", "title", "scanner", "targets", "first_seen", "last_seen"];
    const lines = scannerReports.map((row) => [
      row.report_id,
      row.title || "",
      row.scanner_family || row.scanner_source || "",
      listText(row.targets),
      row.ts_first || "",
      row.ts_last || "",
    ].map((value) => `"${String(value).replace(/"/g, "\"\"")}"`).join(","));
    const blob = new Blob([[header.join(","), ...lines].join("\n")], { type: "text/csv;charset=utf-8" });
    const anchor = document.createElement("a");
    anchor.href = URL.createObjectURL(blob);
    anchor.download = `scanner-reports-${new Date().toISOString().slice(0, 10)}.csv`;
    anchor.click();
    URL.revokeObjectURL(anchor.href);
  }

  return (
    <div className="react-page native-page">
      <NativePageHeader
        title={t(lang, { en: "Reports", ru: "Отчёты" })}
        subtitle={t(lang, {
          en: "Reusable report templates, generated SIEM snapshots and scanner artifacts.",
          ru: "Шаблоны, сформированные снимки SIEM и отчёты сканеров.",
        })}
        icon="docs"
        actions={(
          <>
            {tab === "templates" ? (
              <button type="button" className="react-primary-button" onClick={openNewTemplate}>
                <Plus size={16} aria-hidden="true" />
                {t(lang, { en: "New template", ru: "Новый шаблон" })}
              </button>
            ) : null}
            <button type="button" className="react-link-button" onClick={() => setRefreshToken((value) => value + 1)}>
              {t(lang, { en: "Refresh", ru: "Обновить" })}
            </button>
          </>
        )}
      />

      <div className="native-workspace-tabs" role="tablist" aria-label={t(lang, { en: "Report views", ru: "Разделы отчётов" })}>
        <div>
          <button type="button" role="tab" aria-selected={tab === "templates"} className={tab === "templates" ? "active" : ""} onClick={() => setTab("templates")}>
            {t(lang, { en: "Templates", ru: "Шаблоны" })} <strong>{templatesState.data?.items?.length || 0}</strong>
          </button>
          <button type="button" role="tab" aria-selected={tab === "generated"} className={tab === "generated" ? "active" : ""} onClick={() => setTab("generated")}>
            {t(lang, { en: "Generated", ru: "Сформированные" })} <strong>{runsState.data?.items?.length || 0}</strong>
          </button>
          <button type="button" role="tab" aria-selected={tab === "scanner"} className={tab === "scanner" ? "active" : ""} onClick={() => setTab("scanner")}>
            {t(lang, { en: "Scanner reports", ru: "Отчёты сканеров" })} <strong>{scannerState.data?.items?.length || 0}</strong>
          </button>
        </div>
        <span>{t(lang, { en: "Data", ru: "Данные" })}: <strong>production API</strong></span>
      </div>

      <div className="native-list-search">
        <label className="native-search-field">
          <Search size={16} aria-hidden="true" />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={t(lang, { en: "Search reports and templates", ru: "Поиск по отчётам и шаблонам" })}
          />
        </label>
        <button type="button" className="react-link-button" onClick={() => setQuery("")}>
          {t(lang, { en: "Clear", ru: "Очистить" })}
        </button>
      </div>
      <NativeActionBar
        primary={tab === "scanner" ? (
          <button type="button" className="react-link-button" disabled={!scannerReports.length} onClick={exportScannerRegister}>CSV</button>
        ) : null}
        meta={<span>{t(lang, { en: "Found", ru: "Найдено" })}: <strong>{rows.length}</strong></span>}
      />

      {activeState.loading ? <EmptyState message={t(lang, { en: "Loading reports...", ru: "Загрузка отчётов..." })} /> : null}
      {activeState.error ? <EmptyState message={activeState.error} /> : null}
      {!activeState.loading && !activeState.error && !rows.length ? (
        <EmptyState message={t(lang, { en: "No reports match the current filter.", ru: "По текущему фильтру отчётов нет." })} />
      ) : null}

      {!activeState.loading && !activeState.error && rows.length ? (
        <>
          <section className="native-grid native-reports-grid">
            <div className="react-table-wrap">
              {tab === "templates" ? (
                <table className="react-table">
                  <thead><tr>
                    <th>{t(lang, { en: "Template", ru: "Шаблон" })}</th>
                    <th>{t(lang, { en: "Period", ru: "Период" })}</th>
                    <th>{t(lang, { en: "Sections", ru: "Разделы" })}</th>
                    <th>{t(lang, { en: "Schedule", ru: "Расписание" })}</th>
                    <th>{t(lang, { en: "Updated", ru: "Изменён" })}</th>
                    <th>{t(lang, { en: "Actions", ru: "Действия" })}</th>
                  </tr></thead>
                  <tbody>
                    {(visibleRows as ReportTemplateRecord[]).map((row) => (
                      <tr key={row.id}>
                        <td>
                          <button type="button" className="native-primary-cell" onClick={() => openTemplate(row)}>
                            <strong>{row.name}</strong><small>{row.id} · {row.owner}</small>
                          </button>
                        </td>
                        <td><code>{row.period}</code></td>
                        <td>{row.sections.length}</td>
                        <td>
                          <StatusBadge value={row.schedule?.enabled ? "enabled" : "disabled"} />
                          {row.schedule?.enabled ? <small className="react-inline-note"> {row.schedule.frequency} {row.schedule.time}</small> : null}
                        </td>
                        <td>{formatTimestamp(row.updated_ts, "compact")}</td>
                        <td>
                          <div className="react-actions">
                            <button type="button" className="react-inline-action" disabled={Boolean(mutationState)} onClick={() => runTemplate(row)}>
                              <Play size={14} aria-hidden="true" /> {mutationState === `run:${row.id}` ? "..." : t(lang, { en: "Run", ru: "Запустить" })}
                            </button>
                            <button type="button" className="react-inline-action" onClick={() => openTemplate(row)}>
                              {t(lang, { en: "Edit", ru: "Изменить" })}
                            </button>
                            <button type="button" className="react-inline-action react-danger-button" disabled={Boolean(mutationState)} onClick={() => deleteTemplate(row)}>
                              {t(lang, { en: "Delete", ru: "Удалить" })}
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : null}

              {tab === "generated" ? (
                <table className="react-table">
                  <thead><tr>
                    <th>{t(lang, { en: "Report", ru: "Отчёт" })}</th>
                    <th>{t(lang, { en: "Status", ru: "Статус" })}</th>
                    <th>{t(lang, { en: "Period", ru: "Период" })}</th>
                    <th>{t(lang, { en: "Records", ru: "Записи" })}</th>
                    <th>{t(lang, { en: "Created", ru: "Создан" })}</th>
                    <th>{t(lang, { en: "Artifacts", ru: "Артефакты" })}</th>
                  </tr></thead>
                  <tbody>
                    {(visibleRows as GeneratedReportRecord[]).map((row) => (
                      <tr key={row.id} className={selectedRunId === row.id ? "selected" : ""}>
                        <td>
                          <button type="button" className="native-primary-cell" onClick={() => setSelectedRunId(row.id)}>
                            <strong>{row.name}</strong><small>{row.id} · {row.template_id}</small>
                          </button>
                        </td>
                        <td><StatusBadge value={row.status} /></td>
                        <td>{row.period?.window || "n/a"}</td>
                        <td>{row.record_count || 0}</td>
                        <td>{formatTimestamp(row.created_ts, "full")}</td>
                        <td>
                          <div className="react-actions">
                            <button type="button" className="react-inline-action" onClick={() => downloadGenerated(row, "json")}><FileJson size={14} /> JSON</button>
                            <button type="button" className="react-inline-action" onClick={() => downloadGenerated(row, "csv")}><Download size={14} /> CSV</button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : null}

              {tab === "scanner" ? (
                <table className="react-table">
                  <thead><tr>
                    <th>ID</th>
                    <th>{t(lang, { en: "Name", ru: "Название" })}</th>
                    <th>{t(lang, { en: "Scanner", ru: "Сканер" })}</th>
                    <th>{t(lang, { en: "Targets", ru: "Цели" })}</th>
                    <th>{t(lang, { en: "Last seen", ru: "Последнее появление" })}</th>
                    <th>{t(lang, { en: "State", ru: "Состояние" })}</th>
                  </tr></thead>
                  <tbody>
                    {(visibleRows as VulnReportSummary[]).map((row) => (
                      <tr key={row.report_id} className={selectedScannerReportId === row.report_id ? "selected" : ""}>
                        <td><code>{row.report_id}</code></td>
                        <td><button type="button" className="native-primary-cell" onClick={() => navigate(`/reports/${encodeURIComponent(row.report_id)}`)}><strong>{row.title || row.report_id}</strong><small>{row.summary_message || "scanner report"}</small></button></td>
                        <td>{row.scanner_family || row.scanner_source || "n/a"}</td>
                        <td>{listText(row.targets) || "n/a"}</td>
                        <td>{formatTimestamp(row.ts_last, "full")}</td>
                        <td><StatusBadge value="completed" /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : null}
            </div>
          </section>
          <div className="react-resource-pagination native-report-pagination">
            <NativePager shown={visibleRows.length} total={rows.length} lang={lang} />
            <div className="react-actions">
              <button type="button" className="react-inline-action" disabled={page <= 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>
                {t(lang, { en: "Previous", ru: "Назад" })}
              </button>
              <strong>{page} / {pageCount}</strong>
              <button type="button" className="react-inline-action" disabled={page >= pageCount} onClick={() => setPage((value) => Math.min(pageCount, value + 1))}>
                {t(lang, { en: "Next", ru: "Далее" })}
              </button>
            </div>
          </div>
        </>
      ) : null}

      <DrawerOverlay
        open={editing}
        title={draft.id ? t(lang, { en: "Edit report template", ru: "Изменение шаблона отчёта" }) : t(lang, { en: "New report template", ru: "Новый шаблон отчёта" })}
        subtitle={draft.id || t(lang, { en: "Server-side report configuration", ru: "Серверная конфигурация отчёта" })}
        onClose={() => setEditing(false)}
        panelClassName="react-drawer-panel-wide"
      >
        <div className="react-form-grid">
          <label className="react-field">
            <span>{t(lang, { en: "Name", ru: "Название" })}</span>
            <input className="react-input" value={draft.name} onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value }))} />
          </label>
          <label className="react-field">
            <span>{t(lang, { en: "Description", ru: "Описание" })}</span>
            <textarea className="react-input" value={draft.description} onChange={(event) => setDraft((current) => ({ ...current, description: event.target.value }))} />
          </label>
          <div className="react-form-grid react-report-template-grid">
            <label className="react-field"><span>{t(lang, { en: "Owner", ru: "Владелец" })}</span><input className="react-input" value={draft.owner} onChange={(event) => setDraft((current) => ({ ...current, owner: event.target.value }))} /></label>
            <label className="react-field"><span>{t(lang, { en: "Tenant scope", ru: "Область тенантов" })}</span><input className="react-input" value={draft.tenant_scope} onChange={(event) => setDraft((current) => ({ ...current, tenant_scope: event.target.value }))} /></label>
            <label className="react-field"><span>{t(lang, { en: "Period", ru: "Период" })}</span><select className="react-select" value={draft.period} onChange={(event) => setDraft((current) => ({ ...current, period: event.target.value as TemplateDraft["period"] }))}><option value="12h">12h</option><option value="24h">24h</option><option value="7d">7d</option><option value="30d">30d</option></select></label>
            <label className="react-field"><span>{t(lang, { en: "Retention, days", ru: "Хранение, дней" })}</span><input className="react-input" type="number" min={1} max={3650} value={draft.retention_days} onChange={(event) => setDraft((current) => ({ ...current, retention_days: Number(event.target.value) }))} /></label>
          </div>
        </div>

        <section className="react-card react-card-nested">
          <h3>{t(lang, { en: "Report sections", ru: "Разделы отчёта" })}</h3>
          <div className="react-report-option-grid">
            {SECTION_OPTIONS.map(([value, label]) => (
              <label key={value} className="react-report-option">
                <input type="checkbox" checked={draft.sections.includes(value)} onChange={() => toggleDraftList("sections", value)} />
                <span>{label}</span>
              </label>
            ))}
          </div>
        </section>

        <section className="react-card react-card-nested">
          <h3>{t(lang, { en: "Artifacts and schedule", ru: "Артефакты и расписание" })}</h3>
          <div className="react-report-option-grid">
            {(["json", "csv"] as const).map((format) => (
              <label key={format} className="react-report-option">
                <input type="checkbox" checked={draft.formats.includes(format)} onChange={() => toggleDraftList("formats", format)} />
                <span>{format.toUpperCase()}</span>
              </label>
            ))}
            <label className="react-report-option">
              <input type="checkbox" checked={draft.schedule_enabled} onChange={(event) => setDraft((current) => ({ ...current, schedule_enabled: event.target.checked }))} />
              <span>{t(lang, { en: "Scheduled generation", ru: "Формирование по расписанию" })}</span>
            </label>
          </div>
          {draft.schedule_enabled ? (
            <div className="react-form-grid react-report-template-grid">
              <label className="react-field"><span>{t(lang, { en: "Frequency", ru: "Частота" })}</span><select className="react-select" value={draft.schedule_frequency} onChange={(event) => setDraft((current) => ({ ...current, schedule_frequency: event.target.value }))}><option value="shift">shift</option><option value="daily">daily</option><option value="weekly">weekly</option><option value="monthly">monthly</option></select></label>
              <label className="react-field"><span>{t(lang, { en: "Time", ru: "Время" })}</span><input className="react-input" type="time" value={draft.schedule_time} onChange={(event) => setDraft((current) => ({ ...current, schedule_time: event.target.value }))} /></label>
              <label className="react-field"><span>{t(lang, { en: "Timezone", ru: "Часовой пояс" })}</span><select className="react-select" value={draft.schedule_timezone} onChange={(event) => setDraft((current) => ({ ...current, schedule_timezone: event.target.value }))}><option value="Europe/Moscow">Europe/Moscow</option><option value="UTC">UTC</option></select></label>
            </div>
          ) : null}
        </section>
        <div className="react-actions">
          <button type="button" className="react-link-button" onClick={() => setEditing(false)}>{t(lang, { en: "Cancel", ru: "Отмена" })}</button>
          <button type="button" className="react-primary-button" disabled={mutationState === "saving"} onClick={saveTemplate}>{mutationState === "saving" ? "..." : t(lang, { en: "Save template", ru: "Сохранить шаблон" })}</button>
        </div>
      </DrawerOverlay>

      <DrawerOverlay
        open={Boolean(selectedRunId)}
        title={runDetailState.data?.item?.name || selectedRunId || t(lang, { en: "Generated report", ru: "Сформированный отчёт" })}
        subtitle={runDetailState.data?.item ? `${runDetailState.data.item.record_count} records · ${runDetailState.data.item.duration_ms} ms` : ""}
        onClose={() => setSelectedRunId("")}
        panelClassName="react-drawer-panel-wide"
      >
        {runDetailState.loading ? <EmptyState message={t(lang, { en: "Loading report...", ru: "Загрузка отчёта..." })} /> : null}
        {runDetailState.error ? <EmptyState message={runDetailState.error} /> : null}
        {runDetailState.data?.item ? (
          <>
            <DrawerFieldGrid>
              <KeyValue label="ID" value={runDetailState.data.item.id} />
              <KeyValue label={t(lang, { en: "Status", ru: "Статус" })} value={<StatusBadge value={runDetailState.data.item.status} />} />
              <KeyValue label={t(lang, { en: "Template", ru: "Шаблон" })} value={runDetailState.data.item.template_id} />
              <KeyValue label={t(lang, { en: "Period", ru: "Период" })} value={`${formatTimestamp(runDetailState.data.item.period.from_ts, "full")} — ${formatTimestamp(runDetailState.data.item.period.to_ts, "full")}`} />
              <KeyValue label={t(lang, { en: "Sections", ru: "Разделы" })} value={listText(runDetailState.data.item.sections)} />
              <KeyValue label={t(lang, { en: "Errors", ru: "Ошибки" })} value={runDetailState.data.item.errors.length} />
            </DrawerFieldGrid>
            <div className="react-actions">
              <button type="button" className="react-inline-action" onClick={() => downloadGenerated(runDetailState.data!.item, "json")}><FileJson size={14} /> JSON</button>
              <button type="button" className="react-inline-action" onClick={() => downloadGenerated(runDetailState.data!.item, "csv")}><Download size={14} /> CSV</button>
            </div>
            {runDetailState.data.item.errors.length ? <JsonPreview value={runDetailState.data.item.errors} /> : null}
            <details className="react-details" open>
              <summary>{t(lang, { en: "Report data", ru: "Данные отчёта" })}</summary>
              <JsonPreview value={runDetailState.data.item.snapshot || {}} />
            </details>
          </>
        ) : null}
      </DrawerOverlay>

      <DrawerOverlay
        open={Boolean(selectedScannerReportId)}
        title={scannerDetailState.data?.title || selectedScannerReportId || t(lang, { en: "Scanner report", ru: "Отчёт сканера" })}
        subtitle={scannerDetailState.data ? `${scannerDetailState.data.scanner_family || scannerDetailState.data.scanner_source || "scanner"} · ${scannerDetailState.data.finding_count || scannerDetailState.data.findings?.length || 0} findings` : ""}
        onClose={() => navigate("/reports")}
        panelClassName="react-drawer-panel-wide"
      >
        {scannerDetailState.loading ? <EmptyState message={t(lang, { en: "Loading scanner report...", ru: "Загрузка отчёта сканера..." })} /> : null}
        {scannerDetailState.error ? <EmptyState message={scannerDetailState.error} /> : null}
        {scannerDetailState.data ? (
          <>
            <DrawerFieldGrid>
              <KeyValue label="Report ID" value={scannerDetailState.data.report_id || selectedScannerReportId} />
              <KeyValue label={t(lang, { en: "Scanner", ru: "Сканер" })} value={scannerDetailState.data.scanner_family || scannerDetailState.data.scanner_source || "n/a"} />
              <KeyValue label={t(lang, { en: "Targets", ru: "Цели" })} value={listText(scannerDetailState.data.targets) || "n/a"} />
              <KeyValue label="CVE" value={listText(scannerDetailState.data.cves) || "n/a"} />
              <KeyValue label={t(lang, { en: "Findings", ru: "Находки" })} value={scannerDetailState.data.finding_count || scannerDetailState.data.findings?.length || 0} />
            </DrawerFieldGrid>
            <div className="react-table-wrap">
              <table className="react-table">
                <thead><tr><th>{t(lang, { en: "Severity", ru: "Важность" })}</th><th>{t(lang, { en: "Target", ru: "Цель" })}</th><th>{t(lang, { en: "Service", ru: "Сервис" })}</th><th>CVE</th><th>{t(lang, { en: "Summary", ru: "Описание" })}</th></tr></thead>
                <tbody>
                  {(scannerDetailState.data.findings || []).map((finding: VulnFindingRow, index: number) => (
                    <tr key={`${finding.report_id || selectedScannerReportId}-${index}`}>
                      <td><SeverityBadge value={finding.severity || "info"} /></td>
                      <td>{finding.target || finding.host_name || finding.dst_ip || "n/a"}</td>
                      <td>{finding.service || finding.process_name || "n/a"}</td>
                      <td>{listText(finding.cves) || "n/a"}</td>
                      <td>{finding.summary_message || finding.message || "n/a"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        ) : null}
      </DrawerOverlay>
    </div>
  );
}
