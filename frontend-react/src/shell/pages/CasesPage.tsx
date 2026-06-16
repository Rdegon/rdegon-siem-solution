import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { AsyncGate } from "../async";
import { useFeedback } from "../feedback";
import { usePolledData } from "../hooks";
import {
  DrawerFieldGrid,
  DrawerOverlay,
  InfoList,
  JsonPreview,
  KeyValue,
  PanelHeader,
  SectionIntro,
  SeverityBadge,
  StatCard,
  StatusBadge,
} from "../ui";
import { t, useShellContext } from "../context";
import type { CaseComment, CaseEvidence, CaseTask } from "../types";

export function CasesPage() {
  const { lang, formatTimestamp } = useShellContext();
  const { announce, pushToast } = useFeedback();
  const [refreshTick, setRefreshTick] = useState(0);
  const loadCases = useCallback(() => {
    void refreshTick;
    return api.cases();
  }, [refreshTick]);
  const state = usePolledData(loadCases, 30000);
  const [selectedCaseId, setSelectedCaseId] = useState("");
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [saveState, setSaveState] = useState("");
  const [caseForm, setCaseForm] = useState({ title: "", summary: "", severity: "medium" });
  const [comment, setComment] = useState("");
  const [taskTitle, setTaskTitle] = useState("");
  const [evidenceTitle, setEvidenceTitle] = useState("");
  const [announcedItems, setAnnouncedItems] = useState(-1);

  const items = useMemo(() => state.data?.items || [], [state.data?.items]);
  const selected = useMemo(
    () => items.find((item) => String(item.id) === selectedCaseId) || null,
    [items, selectedCaseId],
  );

  useEffect(() => {
    if (!selectedCaseId && items.length) {
      setSelectedCaseId(String(items[0].id || ""));
    }
  }, [items, selectedCaseId]);

  useEffect(() => {
    if (!state.data || items.length === announcedItems) return;
    setAnnouncedItems(items.length);
    announce(
      t(lang, {
        en: `Cases updated. ${items.length} active case objects are visible.`,
        ru: `Кейсы обновлены. Сейчас видно ${items.length} активных кейсов.`,
      }),
    );
  }, [announce, announcedItems, items.length, lang, state.data]);

  async function createCase() {
    setSaveState(t(lang, { en: "Saving case...", ru: "Сохраняю кейс..." }));
    try {
      const payload = await api.saveCase(caseForm);
      pushToast({
        title: t(lang, { en: "Case saved", ru: "Кейс сохранен" }),
        message: payload.title,
        tone: "success",
      });
      setSaveState(`${t(lang, { en: "Saved", ru: "Сохранен" })}: ${payload.title}`);
      setCaseForm({ title: "", summary: "", severity: "medium" });
      setSelectedCaseId(String(payload.id || ""));
      setRefreshTick((value) => value + 1);
    } catch (error) {
      const message = error instanceof Error ? error.message : t(lang, { en: "Save failed", ru: "Не удалось сохранить кейс" });
      setSaveState(message);
      pushToast({
        title: t(lang, { en: "Case save failed", ru: "Не удалось сохранить кейс" }),
        message,
        tone: "error",
      });
    }
  }

  async function addComment() {
    if (!selectedCaseId || !comment.trim()) return;
    setSaveState(t(lang, { en: "Saving comment...", ru: "Сохраняю комментарий..." }));
    try {
      await api.addCaseComment(selectedCaseId, { body: comment });
      setComment("");
      pushToast({
        title: t(lang, { en: "Comment saved", ru: "Комментарий сохранен" }),
        message: t(lang, { en: "The case timeline has a new analyst note.", ru: "В таймлайне кейса появилась новая заметка аналитика." }),
        tone: "success",
      });
      setSaveState(t(lang, { en: "Comment saved", ru: "Комментарий сохранен" }));
      setRefreshTick((value) => value + 1);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Comment failed";
      setSaveState(message);
      pushToast({
        title: t(lang, { en: "Comment failed", ru: "Не удалось сохранить комментарий" }),
        message,
        tone: "error",
      });
    }
  }

  async function addTask() {
    if (!selectedCaseId || !taskTitle.trim()) return;
    setSaveState(t(lang, { en: "Adding task...", ru: "Добавляю задачу..." }));
    try {
      await api.addCaseTask(selectedCaseId, { title: taskTitle });
      setTaskTitle("");
      pushToast({
        title: t(lang, { en: "Task saved", ru: "Задача сохранена" }),
        message: taskTitle,
        tone: "success",
      });
      setSaveState(t(lang, { en: "Task saved", ru: "Задача сохранена" }));
      setRefreshTick((value) => value + 1);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Task failed";
      setSaveState(message);
      pushToast({
        title: t(lang, { en: "Task failed", ru: "Не удалось сохранить задачу" }),
        message,
        tone: "error",
      });
    }
  }

  async function addEvidence() {
    if (!selectedCaseId || !evidenceTitle.trim()) return;
    setSaveState(t(lang, { en: "Attaching evidence...", ru: "Добавляю доказательство..." }));
    try {
      await api.addCaseEvidence(selectedCaseId, { title: evidenceTitle, kind: "note" });
      setEvidenceTitle("");
      pushToast({
        title: t(lang, { en: "Evidence saved", ru: "Доказательство сохранено" }),
        message: evidenceTitle,
        tone: "success",
      });
      setSaveState(t(lang, { en: "Evidence saved", ru: "Доказательство сохранено" }));
      setRefreshTick((value) => value + 1);
    } catch (error) {
      const message = error instanceof Error ? error.message : t(lang, { en: "Evidence failed", ru: "Не удалось добавить доказательство" });
      setSaveState(message);
      pushToast({
        title: t(lang, { en: "Evidence failed", ru: "Не удалось добавить доказательство" }),
        message,
        tone: "error",
      });
    }
  }

  const kpis = [
    {
      label: t(lang, { en: "Cases", ru: "Кейсы" }),
      value: items.length,
      hint: t(lang, { en: "Case-management objects above the alert queue.", ru: "Рабочие кейсы над очередью алертов и сигналов." }),
    },
    {
      label: t(lang, { en: "Open", ru: "Открытые" }),
      value: items.filter((item) => !["closed", "false_positive"].includes(String(item.status || ""))).length,
      hint: t(lang, { en: "Active SOC workload for analysts and owners.", ru: "Активная SOC-нагрузка для аналитиков и владельцев." }),
    },
    {
      label: t(lang, { en: "With evidence", ru: "С доказательствами" }),
      value: items.filter((item) => (item.evidence || []).length > 0).length,
      hint: t(lang, { en: "Cases with attached notes or evidence payloads.", ru: "Кейсы с прикрепленными заметками и материалами расследования." }),
    },
    {
      label: t(lang, { en: "Assigned", ru: "Назначенные" }),
      value: items.filter((item) => String(item.assignee || "").trim()).length,
      hint: t(lang, { en: "Cases that already have an owner.", ru: "Кейсы, у которых уже есть владелец." }),
    },
  ];

  return (
    <AsyncGate states={[state]} loadingMessage={t(lang, { en: "Loading cases...", ru: "Загрузка кейсов..." })}>
      <div className="react-page">
        <SectionIntro
          kicker={t(lang, { en: "Cases", ru: "Кейсы" })}
          title={t(lang, { en: "Case management", ru: "Кейс-менеджмент" })}
          subtitle={t(lang, {
            en: "SOC workflow layer with comments, evidence, tasks and audit trail above detections and incidents.",
            ru: "Операционный слой расследования с комментариями, доказательствами, задачами и журналом действий поверх сигналов и инцидентов.",
          })}
          icon="cases"
        />

        <div className="react-grid react-grid-4">
          {kpis.map((card) => (
            <StatCard key={card.label} label={card.label} value={card.value} hint={card.hint} />
          ))}
        </div>

        <div className="react-grid react-grid-4">
          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Case queue", ru: "Очередь кейсов" })}
              subtitle={t(lang, { en: "Operational case objects promoted out of detections and risk.", ru: "Операционные кейсы, поднятые из сигналов, риска и расследований." })}
              icon="cases"
            />
            <div className="react-list">
              {items.map((item) => (
                <button
                  type="button"
                  className={`react-card react-card-button ${selectedCaseId === item.id ? "active" : ""}`}
                  key={item.id}
                  onClick={() => {
                    setSelectedCaseId(String(item.id || ""));
                    setDetailsOpen(true);
                  }}
                >
                  <div className="react-card-button-header">
                    <div>
                      <strong>{item.title}</strong>
                      <div className="react-card-button-copy">{item.summary || t(lang, { en: "No summary", ru: "Краткое описание отсутствует" })}</div>
                    </div>
                    <StatusBadge value={String(item.status || "new")} />
                  </div>
                  <div className="react-card-button-grid">
                    <span>{t(lang, { en: "Severity", ru: "Важность" })}</span>
                    <strong>{String(item.severity || "medium")}</strong>
                    <span>{t(lang, { en: "Owner", ru: "Владелец" })}</span>
                    <strong>{String(item.assignee || t(lang, { en: "unassigned", ru: "не назначен" }))}</strong>
                    <span>{t(lang, { en: "Updated", ru: "Обновлен" })}</span>
                    <strong>{formatTimestamp(item.updated_ts, "compact")}</strong>
                  </div>
                </button>
              ))}
            </div>
          </section>

          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Create case", ru: "Создать кейс" })}
              subtitle={t(lang, { en: "Create a first-class case record, not just an alert status update.", ru: "Создайте полноценный кейс, а не просто обновление статуса алерта." })}
              icon="control"
              actions={saveState ? <span className="react-inline-note">{saveState}</span> : undefined}
            />
            <div className="react-form-grid">
              <input className="react-input" value={caseForm.title} onChange={(event) => setCaseForm((current) => ({ ...current, title: event.target.value }))} placeholder={t(lang, { en: "Case title", ru: "Название кейса" })} />
              <input className="react-input" value={caseForm.summary} onChange={(event) => setCaseForm((current) => ({ ...current, summary: event.target.value }))} placeholder={t(lang, { en: "Summary", ru: "Сводка" })} />
              <select className="react-select react-select-inline" value={caseForm.severity} onChange={(event) => setCaseForm((current) => ({ ...current, severity: event.target.value }))}>
                <option value="critical">{t(lang, { en: "critical", ru: "критично" })}</option>
                <option value="high">{t(lang, { en: "high", ru: "высоко" })}</option>
                <option value="medium">{t(lang, { en: "medium", ru: "средне" })}</option>
                <option value="low">{t(lang, { en: "low", ru: "низко" })}</option>
                <option value="info">{t(lang, { en: "info", ru: "инфо" })}</option>
              </select>
              <button type="button" className="react-primary-button" onClick={createCase}>
                {t(lang, { en: "Save case", ru: "Сохранить кейс" })}
              </button>
            </div>
          </section>

          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Status breakdown", ru: "Разбивка статусов" })}
              subtitle={t(lang, { en: "Status model beyond the raw alert queue.", ru: "Статусная модель расследования поверх очереди сырых алертов." })}
              icon="dashboard"
            />
            <InfoList
              items={Array.from(
                items.reduce((map: Map<string, number>, item) => {
                  const key = String(item.status || "new");
                  map.set(key, (map.get(key) || 0) + 1);
                  return map;
                }, new Map<string, number>()).entries(),
              ).map(([label, value]) => ({ label, value }))}
            />
          </section>

          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "MITRE / context", ru: "MITRE / контекст" })}
              subtitle={t(lang, { en: "Current links and enrichment fields inside the case plane.", ru: "Текущие связи и поля обогащения внутри слоя кейсов." })}
              icon="docs"
            />
            <div className="react-list react-list-compact">
              {items.slice(0, 6).map((item) => (
                <div className="react-list-item" key={`mitre-${item.id}`}>
                  <strong>{item.title}</strong>
                  <span>{(item.related_entities || []).length} сущностей / {(item.source_alerts || []).length} сигналов</span>
                </div>
              ))}
            </div>
          </section>
        </div>

        <DrawerOverlay
          open={detailsOpen && Boolean(selected)}
          title={selected?.title || ""}
          subtitle={selected?.summary || ""}
          onClose={() => setDetailsOpen(false)}
        >
          {selected ? (
            <>
              <section className="react-card react-card-nested">
                <PanelHeader title={t(lang, { en: "Case profile", ru: "Профиль кейса" })} subtitle={t(lang, { en: "Status, severity, owner and related objects.", ru: "Статус, важность, владелец и связанные объекты." })} icon="cases" />
                <DrawerFieldGrid>
                  <KeyValue label="ID" value={selected.id} />
                  <KeyValue label={t(lang, { en: "Status", ru: "Статус" })} value={<StatusBadge value={String(selected.status || "new")} />} />
                  <KeyValue label={t(lang, { en: "Severity", ru: "Важность" })} value={<SeverityBadge value={String(selected.severity || "medium")} />} />
                  <KeyValue label={t(lang, { en: "Owner", ru: "Владелец" })} value={selected.assignee || t(lang, { en: "unassigned", ru: "не назначен" })} />
                  <KeyValue label={t(lang, { en: "Updated", ru: "Обновлен" })} value={formatTimestamp(selected.updated_ts, "compact")} />
                  <KeyValue label={t(lang, { en: "Created", ru: "Создан" })} value={formatTimestamp(selected.created_ts, "compact")} />
                </DrawerFieldGrid>
              </section>

              <section className="react-card react-card-nested">
                <PanelHeader title={t(lang, { en: "Comments", ru: "Комментарии" })} subtitle={t(lang, { en: "Collaborative analyst notes and decision trail.", ru: "Совместные заметки аналитиков и след принятия решений." })} icon="docs" />
                <div className="react-form-grid">
                  <input className="react-input" value={comment} onChange={(event) => setComment(event.target.value)} placeholder={t(lang, { en: "Add comment", ru: "Добавить комментарий" })} />
                  <button type="button" className="react-primary-button" onClick={addComment}>{t(lang, { en: "Save comment", ru: "Сохранить комментарий" })}</button>
                </div>
                <div className="react-list react-list-compact">
                  {(selected.comments || []).map((item: CaseComment) => (
                    <div className="react-list-item" key={item.id}>
                      <strong>{item.author}</strong>
                      <span>{formatTimestamp(item.ts, "compact")} / {item.body}</span>
                    </div>
                  ))}
                </div>
              </section>

              <section className="react-card react-card-nested">
                <PanelHeader title={t(lang, { en: "Tasks and evidence", ru: "Задачи и доказательства" })} subtitle={t(lang, { en: "Action items and preserved investigation material.", ru: "Список действий и сохраненный материал расследования." })} icon="builders" />
                <div className="react-form-grid">
                  <input className="react-input" value={taskTitle} onChange={(event) => setTaskTitle(event.target.value)} placeholder={t(lang, { en: "Task title", ru: "Название задачи" })} />
                  <button type="button" className="react-primary-button" onClick={addTask}>{t(lang, { en: "Add task", ru: "Добавить задачу" })}</button>
                  <input className="react-input" value={evidenceTitle} onChange={(event) => setEvidenceTitle(event.target.value)} placeholder={t(lang, { en: "Evidence title", ru: "Название доказательства" })} />
                  <button type="button" className="react-primary-button" onClick={addEvidence}>{t(lang, { en: "Add evidence", ru: "Добавить доказательство" })}</button>
                </div>
                <InfoList items={(selected.tasks || []).map((item: CaseTask) => ({ label: item.title, value: item.status }))} />
                <InfoList items={(selected.evidence || []).map((item: CaseEvidence) => ({ label: item.title, value: item.kind }))} />
              </section>

              <section className="react-card react-card-nested">
                <PanelHeader title={t(lang, { en: "Audit trail", ru: "Журнал действий" })} subtitle={t(lang, { en: "Immutable-style activity log for the current case object.", ru: "Журнал активности по текущему кейсу с неизменяемым следом действий." })} icon="events" />
                <JsonPreview value={selected.audit_trail || []} />
              </section>
            </>
          ) : null}
        </DrawerOverlay>
      </div>
    </AsyncGate>
  );
}
