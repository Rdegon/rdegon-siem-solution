import { useCallback, useEffect, useMemo, useState } from "react";
import { Search } from "lucide-react";
import { useNavigate, useParams } from "react-router-dom";
import { api } from "../api";
import { t, useShellContext } from "../context";
import { useAsyncData, useDebouncedValue } from "../hooks";
import { NativeActionBar, NativePageHeader, NativePager } from "../native";
import { DrawerFieldGrid, DrawerOverlay, EmptyState, JsonPreview, KeyValue, SeverityBadge, StatusBadge } from "../ui";
import type { VulnFindingRow, VulnReportDetailResponse, VulnReportsResponse, VulnReportSummary } from "../types";

function listText(value: unknown) {
  if (Array.isArray(value)) return value.map((item) => String(item || "").trim()).filter(Boolean).join(", ");
  return String(value || "").trim();
}

const REPORT_PAGE_SIZE = 25;

export function ReportsPage() {
  const { lang, formatTimestamp } = useShellContext();
  const navigate = useNavigate();
  const params = useParams<{ reportId?: string }>();
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [refreshToken, setRefreshToken] = useState(0);
  const debouncedQuery = useDebouncedValue(query, 250);
  const selectedReportId = String(params.reportId || "");
  const loadReports = useCallback(() => {
    void refreshToken;
    return api.reports();
  }, [refreshToken]);
  const reportsState = useAsyncData<VulnReportsResponse>(loadReports);
  const loadDetail = useCallback(() => {
    void refreshToken;
    return selectedReportId ? api.reportDetail(selectedReportId) : Promise.resolve(null);
  }, [refreshToken, selectedReportId]);
  const detailState = useAsyncData<VulnReportDetailResponse | null>(loadDetail);
  const reports = useMemo(() => {
    const token = debouncedQuery.trim().toLowerCase();
    const rows = reportsState.data?.items || [];
    if (!token) return rows;
    return rows.filter((row) => JSON.stringify(row).toLowerCase().includes(token));
  }, [debouncedQuery, reportsState.data?.items]);
  const pageCount = Math.max(1, Math.ceil(reports.length / REPORT_PAGE_SIZE));
  const visibleReports = useMemo(() => {
    const start = (page - 1) * REPORT_PAGE_SIZE;
    return reports.slice(start, start + REPORT_PAGE_SIZE);
  }, [page, reports]);

  useEffect(() => {
    setPage(1);
  }, [debouncedQuery]);

  useEffect(() => {
    if (page > pageCount) setPage(pageCount);
  }, [page, pageCount]);

  function openReport(report: VulnReportSummary) {
    navigate(`/reports/${encodeURIComponent(report.report_id)}`);
  }

  function exportRegister() {
    if (!reports.length) return;
    const header = ["report_id", "title", "scanner", "targets", "first_seen", "last_seen"];
    const lines = reports.map((row) => [
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
    anchor.download = `rdegon-reports-${new Date().toISOString().slice(0, 10)}.csv`;
    anchor.click();
    URL.revokeObjectURL(anchor.href);
  }

  return (
    <div className="react-page native-page">
      <NativePageHeader
        title={t(lang, { en: "Reports", ru: "Отчеты" })}
        icon="docs"
        actions={(
          <button type="button" className="react-primary-button" onClick={() => setRefreshToken((value) => value + 1)}>
            {t(lang, { en: "Refresh", ru: "Обновить" })}
          </button>
        )}
      />
      <div className="native-list-search">
        <label className="native-search-field">
          <Search size={16} aria-hidden="true" />
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t(lang, { en: "Search reports, scanners and targets", ru: "Поиск по отчетам, сканерам и целям" })} />
        </label>
        <button type="button" className="react-link-button" onClick={() => setQuery("")}>{t(lang, { en: "Clear", ru: "Очистить" })}</button>
      </div>
      <div className="native-workspace-tabs">
        <div><button type="button" className="active">{t(lang, { en: "Generated reports", ru: "Сформированные отчеты" })}</button></div>
        <span>{t(lang, { en: "Source", ru: "Источник" })}: <strong>Vulnerability Manager</strong></span>
      </div>
      <NativeActionBar
        primary={<button type="button" className="react-link-button" disabled={!reports.length} onClick={exportRegister}>CSV</button>}
        meta={<span>{t(lang, { en: "Found", ru: "Найдено" })}: <strong>{reports.length}</strong></span>}
      />

      {reportsState.loading ? <EmptyState message={t(lang, { en: "Loading reports...", ru: "Загрузка отчетов..." })} /> : null}
      {reportsState.error ? <EmptyState message={reportsState.error} /> : null}
      {!reportsState.loading && !reportsState.error ? (
        <>
          <section className="native-grid native-reports-grid">
            <div className="react-table-wrap">
              <table className="react-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>{t(lang, { en: "Name", ru: "Название" })}</th>
                    <th>{t(lang, { en: "Scanner", ru: "Сканер" })}</th>
                    <th>{t(lang, { en: "Targets", ru: "Цели" })}</th>
                    <th>{t(lang, { en: "First seen", ru: "Первое появление" })}</th>
                    <th>{t(lang, { en: "Last seen", ru: "Последнее появление" })}</th>
                    <th>{t(lang, { en: "State", ru: "Состояние" })}</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleReports.map((row) => (
                    <tr key={row.report_id} className={selectedReportId === row.report_id ? "selected" : ""} onClick={() => openReport(row)}>
                      <td><code>{row.report_id}</code></td>
                      <td><button type="button" className="native-primary-cell" onClick={() => openReport(row)}><strong>{row.title || row.report_id}</strong><small>{row.summary_message || "scanner report"}</small></button></td>
                      <td>{row.scanner_family || row.scanner_source || "n/a"}</td>
                      <td>{listText(row.targets) || "n/a"}</td>
                      <td>{formatTimestamp(row.ts_first, "full")}</td>
                      <td>{formatTimestamp(row.ts_last, "full")}</td>
                      <td><StatusBadge value="completed" /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
          <div className="react-resource-pagination native-report-pagination">
            <NativePager shown={visibleReports.length} total={reports.length} lang={lang} />
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
        open={Boolean(selectedReportId)}
        title={detailState.data?.title || selectedReportId || t(lang, { en: "Report details", ru: "Детали отчета" })}
        subtitle={detailState.data ? `${detailState.data.scanner_family || detailState.data.scanner_source || "scanner"} / ${detailState.data.finding_count || detailState.data.findings?.length || 0} findings` : ""}
        onClose={() => navigate("/reports")}
        panelClassName="react-drawer-panel-wide"
      >
        {detailState.loading ? <EmptyState message={t(lang, { en: "Loading report...", ru: "Загрузка отчета..." })} /> : null}
        {detailState.error ? <EmptyState message={detailState.error} /> : null}
        {detailState.data ? (
          <>
            <section className="react-card react-card-nested">
              <DrawerFieldGrid>
                <KeyValue label="Report ID" value={detailState.data.report_id || selectedReportId} />
                <KeyValue label={t(lang, { en: "Scanner", ru: "Сканер" })} value={detailState.data.scanner_family || detailState.data.scanner_source || "n/a"} />
                <KeyValue label={t(lang, { en: "Targets", ru: "Цели" })} value={listText(detailState.data.targets) || "n/a"} />
                <KeyValue label="CVE" value={listText(detailState.data.cves) || "n/a"} />
                <KeyValue label={t(lang, { en: "Ports", ru: "Порты" })} value={listText(detailState.data.ports) || "n/a"} />
                <KeyValue label={t(lang, { en: "Findings", ru: "Находки" })} value={detailState.data.finding_count || detailState.data.findings?.length || 0} />
              </DrawerFieldGrid>
            </section>
            <section className="native-grid native-report-findings">
              <div className="react-table-wrap">
                <table className="react-table">
                  <thead>
                    <tr>
                      <th>{t(lang, { en: "Severity", ru: "Важность" })}</th>
                      <th>{t(lang, { en: "Target", ru: "Цель" })}</th>
                      <th>{t(lang, { en: "Service", ru: "Сервис" })}</th>
                      <th>CVE</th>
                      <th>{t(lang, { en: "Summary", ru: "Описание" })}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(detailState.data.findings || []).map((finding: VulnFindingRow, index: number) => (
                      <tr key={`${finding.report_id || selectedReportId}-${index}`}>
                        <td><SeverityBadge value={finding.severity || "info"} /></td>
                        <td>{finding.target || finding.host_name || finding.dst_ip || "n/a"}</td>
                        <td>{finding.service || finding.process_name || "n/a"}{finding.port || finding.dst_port ? `:${finding.port || finding.dst_port}` : ""}</td>
                        <td>{listText(finding.cves) || "n/a"}</td>
                        <td>{finding.summary_message || finding.message || "n/a"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
            <details className="react-details">
              <summary>JSON</summary>
              <JsonPreview value={detailState.data} />
            </details>
          </>
        ) : null}
      </DrawerOverlay>
    </div>
  );
}
