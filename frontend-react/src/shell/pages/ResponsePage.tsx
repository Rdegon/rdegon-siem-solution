import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { AsyncGate } from "../async";
import { t, useShellContext } from "../context";
import { useFeedback } from "../feedback";
import { usePolledData } from "../hooks";
import { BreakdownBars, DrawerOverlay, JsonPreview, MetricStrip, PanelHeader, SectionIntro, StatusBadge, WorkspaceSection } from "../ui";
import type { ResponseActionRecord, ResponseExecutionRecord, RuntimeBlob } from "../types";

type ActionForm = {
  id: string;
  title: string;
  description: string;
  kind: string;
  targetUrl: string;
  messageTemplate: string;
  enabled: boolean;
  dangerous: boolean;
  policyPackId: string;
  approvalMode: string;
  minApprovers: string;
  requiredRoles: string;
  owners: string;
  triggerKinds: string;
  playbookClass: string;
  governanceTier: string;
  evidenceContract: string;
  rollbackContract: string;
  preconditions: string;
  integrationTargets: string;
  operatorNotesText: string;
  rollbackNotesText: string;
  complianceControls: string;
  linkageCaseId: string;
  linkageAlertId: string;
  linkageDetectionId: string;
  linkageFindingKey: string;
  linkageAssetId: string;
  stepsJson: string;
};

const ACTION_KINDS = ["webhook", "email", "telegram", "runtime_doc", "case_comment", "slack_webhook", "ansible_playbook", "vuln_sync", "vuln_import", "vuln_policy_apply", "chain", "approval_gate"];
const PLAYBOOK_TEMPLATES = [
  {
    id: "contain-host",
    title: "Contain host after detection",
    pack: "endpoint-containment",
    approvalMode: "two_man",
    triggerKinds: "detection_alert,case",
    messageTemplate: "Isolate {{entity.host}} and update {{case_id}} after analyst quorum.",
    requiredRoles: "admin,analyst",
    playbookClass: "containment",
    governanceTier: "high-risk",
    dangerous: true,
    integrationTargets: "edr,ticketing,case-management",
    evidenceContract: "actor_ip,host_snapshot,case_id",
    rollbackContract: "containment_state,case_note,approval_ticket",
    preconditions: "case_linked,asset_confirmed,approval_chain_satisfied",
    complianceControls: "SOC2-CC7,NIST-RS.MI",
    stepsJson: JSON.stringify([
      { id: "isolate", title: "EDR isolate", kind: "webhook", target: { url: "https://edr.example/api/isolate-host", retry_attempts: 3, retry_backoff_ms: 5000 } },
      { id: "case-note", title: "Case note", kind: "case_comment", message_template: "Host {{entity.host}} isolated under case {{case_id}}." },
    ], null, 2),
  },
  {
    id: "identity-disable",
    title: "Suspend identity from case",
    pack: "identity-containment",
    approvalMode: "two_man",
    triggerKinds: "case,detection_alert",
    messageTemplate: "Suspend {{entity_name}} with identity controls and document the decision trail.",
    requiredRoles: "admin,analyst",
    playbookClass: "containment",
    governanceTier: "high-risk",
    dangerous: true,
    integrationTargets: "iam,idp,ad,entra_id,ticketing",
    evidenceContract: "actor_ip,user_name,case_id",
    rollbackContract: "identity_state,case_note,approval_ticket",
    preconditions: "identity_confirmed,case_linked,approval_chain_satisfied",
    complianceControls: "SOC2-CC6,NIST-PR.AC",
    stepsJson: JSON.stringify([
      { id: "idp-suspend", title: "Suspend in IdP", kind: "webhook", target: { url: "https://idp.example/api/suspend-user", retry_attempts: 2, retry_backoff_ms: 3000 } },
      { id: "case-note", title: "Case note", kind: "case_comment", message_template: "Identity {{entity_name}} was suspended under {{case_id}}." },
    ], null, 2),
  },
  {
    id: "critical-vuln",
    title: "Critical vulnerability escalation",
    pack: "vulnerability-response",
    approvalMode: "single",
    triggerKinds: "vulnerability_finding,report",
    messageTemplate: "Escalate {{finding_key}} on {{asset_id}} and notify remediation owner.",
    requiredRoles: "analyst",
    playbookClass: "workflow",
    governanceTier: "supervisor",
    dangerous: false,
    integrationTargets: "ticketing,email,cmdb",
    evidenceContract: "finding_key,asset_id,severity",
    rollbackContract: "ticket_id,case_note",
    preconditions: "finding_confirmed,asset_enriched",
    complianceControls: "PCI-6.3,NIST-RA",
    stepsJson: JSON.stringify([
      { id: "ticket", title: "Create remediation ticket", kind: "webhook", target: { url: "https://itsm.example/api/vuln-remediation", retry_attempts: 2, retry_backoff_ms: 4000 } },
      { id: "notify", title: "Notify owner", kind: "email", target: { url: "mailto:remediation@example.com" } },
    ], null, 2),
  },
  {
    id: "ansible-host-triage",
    title: "Ansible host triage",
    pack: "machine-orchestration",
    approvalMode: "none",
    triggerKinds: "manual,incident,case",
    messageTemplate: "Collect host evidence for {{asset_id}} through Ansible.",
    requiredRoles: "analyst,platform-engineer",
    playbookClass: "evidence",
    governanceTier: "operator",
    dangerous: false,
    integrationTargets: "ansible,linux-hosts,case-management",
    evidenceContract: "asset_id,host_name,journal,services,disk",
    rollbackContract: "",
    preconditions: "target_host_selected,ssh_reachable,playbook_reviewed",
    complianceControls: "NIST-DE.CM,SOC2-CC7",
    stepsJson: JSON.stringify([
      { id: "collect", title: "Collect host evidence", kind: "ansible_playbook", target: { inventory: "/opt/siem/soar/ansible/inventory.ini", playbook: "/opt/siem/soar/ansible/collect_triage.yml", limit: "siem_web", check_mode: false, timeout_ms: 180000 } },
      { id: "case-note", title: "Case note", kind: "case_comment", message_template: "Ansible triage evidence collected for {{asset_id}}." },
    ], null, 2),
  },
  {
    id: "ansible-restart-service",
    title: "Ansible controlled service restart",
    pack: "machine-orchestration",
    approvalMode: "two_man",
    triggerKinds: "manual,incident,case",
    messageTemplate: "Restart {{service_name}} on {{asset_id}} and collect post-check evidence.",
    requiredRoles: "admin,platform-engineer",
    playbookClass: "remediation",
    governanceTier: "high-risk",
    dangerous: true,
    integrationTargets: "ansible,systemd,case-management",
    evidenceContract: "asset_id,service_name,case_id",
    rollbackContract: "pre_status,post_status,journal_tail",
    preconditions: "case_linked,service_name_allowlisted,approval_chain_satisfied",
    complianceControls: "NIST-RS.MI,SOC2-CC7",
    stepsJson: JSON.stringify([
      { id: "restart", title: "Restart allowlisted service", kind: "ansible_playbook", target: { inventory: "/opt/siem/soar/ansible/inventory.ini", playbook: "/opt/siem/soar/ansible/restart_service.yml", limit: "siem_web", check_mode: false, timeout_ms: 180000, extra_vars: { service_name: "siem-web.service" } } },
      { id: "case-note", title: "Case note", kind: "case_comment", message_template: "Service {{service_name}} restart workflow executed for {{asset_id}}." },
    ], null, 2),
  },
  {
    id: "ansible-quarantine-host",
    title: "Ansible host quarantine",
    pack: "machine-orchestration",
    approvalMode: "two_man",
    triggerKinds: "incident,case",
    messageTemplate: "Quarantine {{asset_id}} with Ansible after analyst approval.",
    requiredRoles: "admin,analyst",
    playbookClass: "containment",
    governanceTier: "high-risk",
    dangerous: true,
    integrationTargets: "ansible,linux-firewall,case-management",
    evidenceContract: "asset_id,case_id,actor_ip,approval_ticket",
    rollbackContract: "iptables_backup,connectivity_check,case_note",
    preconditions: "case_linked,target_confirmed,approval_chain_satisfied",
    complianceControls: "NIST-RS.MI,SOC2-CC7",
    stepsJson: JSON.stringify([
      { id: "quarantine-check", title: "Quarantine dry-run", kind: "ansible_playbook", target: { inventory: "/opt/siem/soar/ansible/inventory.ini", playbook: "/opt/siem/soar/ansible/quarantine_host.yml", limit: "pilot_web", check_mode: true, timeout_ms: 180000, extra_vars: { quarantine_apply: false } } },
      { id: "case-note", title: "Case note", kind: "case_comment", message_template: "Quarantine workflow validated for {{asset_id}}." },
    ], null, 2),
  },
  {
    id: "ansible-openvas-refresh",
    title: "Ansible OpenVAS refresh and import",
    pack: "vulnerability-response",
    approvalMode: "none",
    triggerKinds: "manual,report",
    messageTemplate: "Refresh scanner context and import Greenbone reports.",
    requiredRoles: "analyst,platform-engineer",
    playbookClass: "orchestration",
    governanceTier: "operator",
    dangerous: false,
    integrationTargets: "ansible,greenbone,siem-import",
    evidenceContract: "scanner_host,report_id,import_result",
    rollbackContract: "",
    preconditions: "scanner_reachable,import_credentials_configured",
    complianceControls: "PCI-DSS-11,NIST-RA.5",
    stepsJson: JSON.stringify([
      { id: "scanner-refresh", title: "Refresh scanner context", kind: "ansible_playbook", target: { inventory: "/opt/siem/soar/ansible/inventory.ini", playbook: "/opt/siem/soar/ansible/openvas_refresh.yml", limit: "vuln_mgr", check_mode: false, timeout_ms: 180000 } },
      { id: "import-greenbone-reports", title: "Import Greenbone reports", kind: "vuln_import", target: { limit: 50 } },
    ], null, 2),
  },
  {
    id: "firewall-block",
    title: "Block source on firewall",
    pack: "network-containment",
    approvalMode: "two_man",
    triggerKinds: "case,detection_alert",
    messageTemplate: "Block {{actor_ip}} on perimeter firewall and document the containment scope.",
    requiredRoles: "admin,analyst",
    playbookClass: "containment",
    governanceTier: "high-risk",
    dangerous: true,
    integrationTargets: "firewall,ngfw,ticketing,chatops",
    evidenceContract: "actor_ip,case_id,detection_id",
    rollbackContract: "firewall_rule_id,approval_ticket,case_note",
    preconditions: "actor_ip_confirmed,case_linked,approval_chain_satisfied",
    complianceControls: "SOC2-CC7,NIST-RS.MI",
    stepsJson: JSON.stringify([
      { id: "block-ip", title: "Block IP on firewall", kind: "webhook", target: { url: "https://firewall.example/api/block-ip", retry_attempts: 2, retry_backoff_ms: 3000 } },
      { id: "ticket", title: "Open ITSM ticket", kind: "webhook", target: { url: "https://itsm.example/api/incidents", retry_attempts: 2, retry_backoff_ms: 3000 } },
      { id: "notify", title: "Notify chatops", kind: "slack_webhook", target: { url: "https://chatops.example/hooks/security" } },
    ], null, 2),
  },
  {
    id: "major-incident-war-room",
    title: "Major incident war room",
    pack: "major-incident",
    approvalMode: "single",
    triggerKinds: "case,report,manual",
    messageTemplate: "Open ticket, create war room and synchronize stakeholders for {{case_id}}.",
    requiredRoles: "analyst,supervisor",
    playbookClass: "communication",
    governanceTier: "supervisor",
    dangerous: false,
    integrationTargets: "ticketing,telegram,slack,teams",
    evidenceContract: "case_id,incident_summary,owners",
    rollbackContract: "ticket_id,chat_channel_id,case_note",
    preconditions: "case_linked,scope_confirmed",
    complianceControls: "SOC2-CC7,NIST-IR",
    stepsJson: JSON.stringify([
      { id: "ticket", title: "Create major incident ticket", kind: "webhook", target: { url: "https://itsm.example/api/major-incident", retry_attempts: 2, retry_backoff_ms: 3000 } },
      { id: "telegram", title: "Create Telegram room", kind: "telegram", message_template: "Major incident war room opened for {{case_id}}." },
      { id: "slack", title: "Notify Slack", kind: "slack_webhook", target: { url: "https://chatops.example/hooks/major-incident" } },
    ], null, 2),
  },
  {
    id: "freeze-pipeline",
    title: "Freeze CI/CD pipeline",
    pack: "devsecops-containment",
    approvalMode: "two_man",
    triggerKinds: "case,detection_alert,manual",
    messageTemplate: "Freeze pipeline {{asset_id}} / {{entity_name}} and preserve change evidence.",
    requiredRoles: "admin,analyst,platform-engineer",
    playbookClass: "containment",
    governanceTier: "change_board",
    dangerous: true,
    integrationTargets: "cicd,ticketing,chatops",
    evidenceContract: "asset_id,case_id,detection_id",
    rollbackContract: "pipeline_id,change_ticket,case_note",
    preconditions: "pipeline_confirmed,change_board_notified,approval_chain_satisfied",
    complianceControls: "SOC2-CC8,NIST-PR.IP",
    stepsJson: JSON.stringify([
      { id: "freeze", title: "Pause pipeline", kind: "webhook", target: { url: "https://cicd.example/api/pause-pipeline", retry_attempts: 2, retry_backoff_ms: 3000 } },
      { id: "ticket", title: "Open change ticket", kind: "webhook", target: { url: "https://itsm.example/api/change", retry_attempts: 2, retry_backoff_ms: 3000 } },
      { id: "notify", title: "Notify chatops", kind: "slack_webhook", target: { url: "https://chatops.example/hooks/platform-security" } },
    ], null, 2),
  },
];

const emptyForm = (): ActionForm => ({
  id: "",
  title: "",
  description: "",
  kind: "webhook",
  targetUrl: "",
  messageTemplate: "",
  enabled: true,
  dangerous: false,
  policyPackId: "",
  approvalMode: "none",
  minApprovers: "1",
  requiredRoles: "",
  owners: "",
  triggerKinds: "",
  playbookClass: "workflow",
  governanceTier: "operator",
  evidenceContract: "",
  rollbackContract: "",
  preconditions: "",
  integrationTargets: "",
  operatorNotesText: "",
  rollbackNotesText: "",
  complianceControls: "",
  linkageCaseId: "",
  linkageAlertId: "",
  linkageDetectionId: "",
  linkageFindingKey: "",
  linkageAssetId: "",
  stepsJson: "[]",
});

function asCsv(value: unknown): string {
  return Array.isArray(value) ? value.map((item) => String(item || "").trim()).filter(Boolean).join(", ") : "";
}

function linkageSummary(value: RuntimeBlob | undefined, lang: "en" | "ru") {
  const pairs = Object.entries(value || {}).filter(([, item]) => String(item || "").trim());
  return pairs.length ? pairs.map(([key, item]) => `${key}: ${String(item)}`).join(" | ") : t(lang, { en: "unlinked", ru: "без привязки" });
}

function actionKindLabel(kind: string, lang: "en" | "ru") {
  const labels: Record<string, { en: string; ru: string }> = {
    webhook: { en: "Webhook", ru: "Вебхук" },
    email: { en: "Email", ru: "Почта" },
    telegram: { en: "Telegram", ru: "Telegram" },
    runtime_doc: { en: "Runtime doc", ru: "Runtime-документ" },
    case_comment: { en: "Case comment", ru: "Комментарий в кейс" },
    slack_webhook: { en: "Slack webhook", ru: "Slack-вебхук" },
    vuln_sync: { en: "Vulnerability sync", ru: "Синхронизация уязвимостей" },
    vuln_import: { en: "Vulnerability import", ru: "Импорт уязвимостей" },
    vuln_policy_apply: { en: "Apply vulnerability policies", ru: "Применение политик уязвимостей" },
    chain: { en: "Chain", ru: "Цепочка действий" },
    approval_gate: { en: "Approval gate", ru: "Шлюз согласования" },
  };
  return labels[kind] ? t(lang, labels[kind]) : kind;
}

function templateTitle(templateId: string, lang: "en" | "ru") {
  const titles: Record<string, { en: string; ru: string }> = {
    "contain-host": { en: "Contain host after detection", ru: "Изолировать хост после детекта" },
    "identity-disable": { en: "Suspend identity from case", ru: "Отключить учетную запись из кейса" },
    "critical-vuln": { en: "Critical vulnerability escalation", ru: "Эскалация критичной уязвимости" },
    "firewall-block": { en: "Block source on firewall", ru: "Заблокировать источник на firewall" },
    "major-incident-war-room": { en: "Major incident war room", ru: "War room для major incident" },
    "freeze-pipeline": { en: "Freeze CI/CD pipeline", ru: "Заморозить CI/CD pipeline" },
  };
  return titles[templateId] ? t(lang, titles[templateId]) : PLAYBOOK_TEMPLATES.find((item) => item.id === templateId)?.title || templateId;
}

function templateMessage(templateId: string, lang: "en" | "ru") {
  const messages: Record<string, { en: string; ru: string }> = {
    "contain-host": { en: "Isolate {{entity.host}} and update {{case_id}} after analyst quorum.", ru: "Изолируйте {{entity.host}} и обновите {{case_id}} после подтверждения аналитиков." },
    "identity-disable": { en: "Suspend {{entity_name}} with identity controls and document the decision trail.", ru: "Приостановите {{entity_name}} через контур управления доступом и зафиксируйте цепочку решения." },
    "critical-vuln": { en: "Escalate {{finding_key}} on {{asset_id}} and notify remediation owner.", ru: "Эскалируйте {{finding_key}} на {{asset_id}} и уведомите владельца исправления." },
    "firewall-block": { en: "Block {{actor_ip}} on perimeter firewall and document the containment scope.", ru: "Заблокируйте {{actor_ip}} на perimeter firewall и зафиксируйте контур сдерживания." },
    "major-incident-war-room": { en: "Open ticket, create war room and synchronize stakeholders for {{case_id}}.", ru: "Откройте тикет, создайте war room и синхронизируйте стейкхолдеров по {{case_id}}." },
    "freeze-pipeline": { en: "Freeze pipeline {{asset_id}} / {{entity_name}} and preserve change evidence.", ru: "Заморозьте pipeline {{asset_id}} / {{entity_name}} и сохраните change evidence." },
  };
  return messages[templateId] ? t(lang, messages[templateId]) : PLAYBOOK_TEMPLATES.find((item) => item.id === templateId)?.messageTemplate || "";
}

function templateSummary(template: (typeof PLAYBOOK_TEMPLATES)[number], lang: "en" | "ru") {
  return t(lang, {
    en: `Approval ${template.approvalMode} | roles ${template.requiredRoles}`,
    ru: `Согласование ${template.approvalMode} | роли ${template.requiredRoles}`,
  });
}

function formFromAction(action: ResponseActionRecord | null): ActionForm {
  if (!action) return emptyForm();
  const approval = (action.approval || {}) as RuntimeBlob;
  const target = (action.target || {}) as RuntimeBlob;
  const linkage = (action.default_linkage || {}) as RuntimeBlob;
  return {
    id: String(action.id || ""),
    title: String(action.title || ""),
    description: String(action.description || ""),
    kind: String(action.kind || action.action_type || "webhook"),
    targetUrl: String(target.url || target.playbook || ""),
    messageTemplate: String(action.message_template || ""),
    enabled: Boolean(action.enabled ?? true),
    dangerous: Boolean(action.dangerous),
    policyPackId: String(action.policy_pack_id || ""),
    approvalMode: String(approval.mode || (action.approval_required || action.requires_approval ? "single" : "none")),
    minApprovers: String(approval.min_approvers || 1),
    requiredRoles: asCsv(approval.required_roles),
    owners: asCsv(action.owners),
    triggerKinds: asCsv(action.trigger_kinds),
    playbookClass: String(action.playbook_class || "workflow"),
    governanceTier: String(action.governance_tier || "operator"),
    evidenceContract: asCsv(action.evidence_contract),
    rollbackContract: asCsv(action.rollback_contract),
    preconditions: asCsv(action.preconditions),
    integrationTargets: asCsv(action.integration_targets),
    operatorNotesText: String(action.operator_notes || ""),
    rollbackNotesText: String(action.rollback_notes || ""),
    complianceControls: asCsv(action.compliance_controls),
    linkageCaseId: String(linkage.case_id || ""),
    linkageAlertId: String(linkage.alert_id || ""),
    linkageDetectionId: String(linkage.detection_id || ""),
    linkageFindingKey: String(linkage.finding_key || ""),
    linkageAssetId: String(linkage.asset_id || ""),
    stepsJson: JSON.stringify(action.steps || [], null, 2),
  };
}

export function ResponsePage() {
  const { lang, formatTimestamp } = useShellContext();
  const { pushToast } = useFeedback();
  const [refreshTick, setRefreshTick] = useState(0);
  const [selectedActionId, setSelectedActionId] = useState("");
  const [form, setForm] = useState<ActionForm>(emptyForm());
  const [operatorNotes, setOperatorNotes] = useState<Record<string, string>>({});
  const [selectedPayload, setSelectedPayload] = useState<RuntimeBlob | null>(null);
  const [selectedTitle, setSelectedTitle] = useState("");

  const loadActions = useCallback(() => { void refreshTick; return api.responseActions(); }, [refreshTick]);
  const loadAnalytics = useCallback(() => { void refreshTick; return api.responseAnalytics({ limit: 200 }); }, [refreshTick]);
  const loadExecutions = useCallback(() => { void refreshTick; return api.responseExecutions({ limit: 200 }); }, [refreshTick]);
  const loadDlq = useCallback(() => { void refreshTick; return api.responseDlq({ limit: 200 }); }, [refreshTick]);

  const actionsState = usePolledData(loadActions, 30000);
  const analyticsState = usePolledData(loadAnalytics, 30000);
  const executionsState = usePolledData(loadExecutions, 20000);
  const dlqState = usePolledData(loadDlq, 30000);

  const actions = useMemo(() => actionsState.data?.items || [], [actionsState.data?.items]);
  const approvalQueue = useMemo(() => actionsState.data?.approval_queue || [], [actionsState.data?.approval_queue]);
  const policyPacks = useMemo(
    () => actionsState.data?.policy_packs || analyticsState.data?.policy_packs || [],
    [actionsState.data?.policy_packs, analyticsState.data?.policy_packs],
  );
  const ledger = useMemo(
    () => actionsState.data?.ledger || analyticsState.data?.recent_ledger || [],
    [actionsState.data?.ledger, analyticsState.data?.recent_ledger],
  );
  const executions = useMemo(() => executionsState.data?.items || [], [executionsState.data?.items]);
  const dlq = useMemo(() => dlqState.data?.items || [], [dlqState.data?.items]);
  const selectedAction = useMemo(() => actions.find((item) => String(item.id || "") === selectedActionId) || null, [actions, selectedActionId]);
  const metrics = analyticsState.data?.metrics || {};

  useEffect(() => {
    if (!selectedActionId && actions.length) setSelectedActionId(String(actions[0].id || ""));
  }, [actions, selectedActionId]);

  useEffect(() => {
    setForm(formFromAction(selectedAction));
  }, [selectedAction]);

  const metricItems = [
    { label: t(lang, { en: "Actions", ru: "Действия" }), value: metrics.actions_total || actions.length || 0, hint: t(lang, { en: "Registered response actions and chains.", ru: "Зарегистрированные ответные действия и цепочки." }), tone: "info" as const },
    { label: t(lang, { en: "Pending approval", ru: "Ждут согласования" }), value: metrics.pending_approvals || approvalQueue.length || 0, hint: t(lang, { en: "Executions waiting for operator quorum.", ru: "Исполнения, ожидающие кворума операторов." }), tone: Number(metrics.pending_approvals || approvalQueue.length || 0) ? ("warning" as const) : ("success" as const) },
    { label: t(lang, { en: "Linked runs", ru: "Связанные запуски" }), value: metrics.linked_executions || 0, hint: t(lang, { en: "Executions bound to detections, cases or findings.", ru: "Запуски, связанные с детектами, кейсами и находками." }), tone: "default" as const },
    { label: "DLQ", value: metrics.dlq_total || dlq.length || 0, hint: t(lang, { en: "Replayable failed actions.", ru: "Ошибочные действия, доступные для повтора." }), tone: Number(metrics.dlq_total || dlq.length || 0) ? ("critical" as const) : ("success" as const) },
    { label: t(lang, { en: "Two-man", ru: "Два оператора" }), value: metrics.two_man_actions || 0, hint: t(lang, { en: "Actions protected by multi-operator approval.", ru: "Действия, защищенные согласованием несколькими операторами." }), tone: "default" as const },
    { label: t(lang, { en: "P95 latency", ru: "Задержка P95" }), value: `${Number(metrics.p95_latency_ms || 0).toFixed(1)} ms`, hint: t(lang, { en: "Observed response execution latency.", ru: "Наблюдаемая задержка выполнения действий." }), tone: "default" as const },
    { label: t(lang, { en: "Preconditions", ru: "Preconditions" }), value: `${Number(metrics.precondition_coverage_pct || 0).toFixed(1)}%`, hint: t(lang, { en: "Coverage of execution preconditions across the response library.", ru: "Coverage of execution preconditions across the response library." }), tone: "default" as const },
    { label: t(lang, { en: "Integration targets", ru: "Integration targets" }), value: `${Number(metrics.integration_target_pct || 0).toFixed(1)}%`, hint: t(lang, { en: "Coverage of explicit downstream systems bound to actions.", ru: "Coverage of explicit downstream systems bound to actions." }), tone: "default" as const },
  ];

  async function saveAction() {
    try {
      const steps = form.stepsJson.trim() ? JSON.parse(form.stepsJson) : [];
      const payload = {
        id: form.id || undefined,
        title: form.title,
        description: form.description,
        kind: form.kind,
        enabled: form.enabled,
        dangerous: form.dangerous,
        target:
          form.kind === "ansible_playbook"
            ? { inventory: "/opt/siem/soar/ansible/inventory.ini", playbook: form.targetUrl || undefined, limit: "siem_web", check_mode: true, timeout_ms: 180000 }
            : { url: form.targetUrl || undefined },
        message_template: form.messageTemplate,
        policy_pack_id: form.policyPackId || undefined,
        owners: form.owners.split(",").map((item) => item.trim()).filter(Boolean),
        trigger_kinds: form.triggerKinds.split(",").map((item) => item.trim()).filter(Boolean),
        playbook_class: form.playbookClass || undefined,
        governance_tier: form.governanceTier || undefined,
        evidence_contract: form.evidenceContract.split(",").map((item) => item.trim()).filter(Boolean),
        rollback_contract: form.rollbackContract.split(",").map((item) => item.trim()).filter(Boolean),
        preconditions: form.preconditions.split(",").map((item) => item.trim()).filter(Boolean),
        integration_targets: form.integrationTargets.split(",").map((item) => item.trim()).filter(Boolean),
        operator_notes: form.operatorNotesText || undefined,
        rollback_notes: form.rollbackNotesText || undefined,
        compliance_controls: form.complianceControls.split(",").map((item) => item.trim()).filter(Boolean),
        default_linkage: {
          case_id: form.linkageCaseId || undefined,
          alert_id: form.linkageAlertId || undefined,
          detection_id: form.linkageDetectionId || undefined,
          finding_key: form.linkageFindingKey || undefined,
          asset_id: form.linkageAssetId || undefined,
        },
        approval: {
          mode: form.approvalMode,
          min_approvers: Number(form.minApprovers || 1),
          required_roles: form.requiredRoles.split(",").map((item) => item.trim()).filter(Boolean),
          role_separation_required: Number(form.minApprovers || 1) > 1 || form.requiredRoles.split(",").filter(Boolean).length > 1,
        },
        steps: Array.isArray(steps) ? steps : [],
      };
      const saved = await api.saveResponseAction(payload);
      setSelectedActionId(String(saved.id || ""));
      setRefreshTick((current) => current + 1);
      pushToast({ title: t(lang, { en: "Response action saved", ru: "Действие сохранено" }), message: String(saved.title || saved.id || ""), tone: "success" });
    } catch (error) {
      pushToast({ title: t(lang, { en: "Save failed", ru: "Сохранение не удалось" }), message: error instanceof Error ? error.message : t(lang, { en: "Unable to save response action", ru: "Не удалось сохранить ответное действие" }), tone: "error" });
    }
  }

  async function runAction(actionId: string, dryRun: boolean) {
    try {
      await api.executeResponseAction(actionId, {
        dry_run: dryRun,
        payload: {
          source: "react-shell",
          initiated_from: "response-page",
          request_note: t(lang, { en: "Operator initiated from Approval & Execution Control workspace", ru: "Запуск выполнен оператором из рабочей области согласования и исполнения" }),
          linkage: {
            trigger_kind: form.linkageFindingKey ? "vulnerability_finding" : form.linkageCaseId ? "case" : form.linkageAlertId ? "detection_alert" : "manual",
            case_id: form.linkageCaseId || undefined,
            alert_id: form.linkageAlertId || undefined,
            detection_id: form.linkageDetectionId || undefined,
            finding_key: form.linkageFindingKey || undefined,
            asset_id: form.linkageAssetId || undefined,
          },
        },
      });
      setRefreshTick((current) => current + 1);
      pushToast({ title: dryRun ? t(lang, { en: "Dry-run completed", ru: "Пробный запуск завершен" }) : t(lang, { en: "Execution accepted", ru: "Исполнение принято" }), message: actionId, tone: "success" });
    } catch (error) {
      pushToast({ title: t(lang, { en: "Execution failed", ru: "Исполнение не удалось" }), message: error instanceof Error ? error.message : t(lang, { en: "Unable to execute action", ru: "Не удалось выполнить действие" }), tone: "error" });
    }
  }

  async function approveExecution(item: ResponseExecutionRecord) {
    try {
      await api.approveResponseExecution(String(item.id || ""), { note: operatorNotes[String(item.id || "")] || "" });
      setRefreshTick((current) => current + 1);
      pushToast({ title: t(lang, { en: "Approval recorded", ru: "Согласование зафиксировано" }), message: String(item.id || ""), tone: "success" });
    } catch (error) {
      pushToast({ title: t(lang, { en: "Approval failed", ru: "Не удалось согласовать" }), message: error instanceof Error ? error.message : t(lang, { en: "Unable to approve execution", ru: "Не удалось подтвердить исполнение" }), tone: "error" });
    }
  }

  async function rejectExecution(item: ResponseExecutionRecord) {
    try {
      await api.rejectResponseExecution(String(item.id || ""), { reason: operatorNotes[String(item.id || "")] || t(lang, { en: "Rejected by operator", ru: "Отклонено оператором" }) });
      setRefreshTick((current) => current + 1);
      pushToast({ title: t(lang, { en: "Execution rejected", ru: "Исполнение отклонено" }), message: String(item.id || ""), tone: "success" });
    } catch (error) {
      pushToast({ title: t(lang, { en: "Reject failed", ru: "Отклонение не удалось" }), message: error instanceof Error ? error.message : t(lang, { en: "Unable to reject execution", ru: "Не удалось отклонить исполнение" }), tone: "error" });
    }
  }

  async function retryExecution(executionId: string) {
    try {
      await api.retryResponseExecution(executionId);
      setRefreshTick((current) => current + 1);
      pushToast({ title: t(lang, { en: "Retry accepted", ru: "Повторный запуск принят" }), message: executionId, tone: "success" });
    } catch (error) {
      pushToast({ title: t(lang, { en: "Retry failed", ru: "Повтор не удался" }), message: error instanceof Error ? error.message : t(lang, { en: "Unable to retry execution", ru: "Не удалось повторить исполнение" }), tone: "error" });
    }
  }

  async function replayDlq(dlqId: string) {
    try {
      await api.replayResponseDlq(dlqId);
      setRefreshTick((current) => current + 1);
      pushToast({ title: t(lang, { en: "DLQ replay accepted", ru: "Повтор из DLQ принят" }), message: dlqId, tone: "success" });
    } catch (error) {
      pushToast({ title: t(lang, { en: "DLQ replay failed", ru: "Повтор из DLQ не удался" }), message: error instanceof Error ? error.message : t(lang, { en: "Unable to replay DLQ", ru: "Не удалось повторить запись из DLQ" }), tone: "error" });
    }
  }

  return (
    <AsyncGate states={[actionsState, analyticsState, executionsState, dlqState]} loadingMessage={t(lang, { en: "Loading SOAR workspace...", ru: "Загрузка рабочей области реагирования..." })}>
      <div className="react-page">
        <SectionIntro
          kicker={t(lang, { en: "Response", ru: "Реагирование" })}
          title={t(lang, { en: "Approval and execution control", ru: "Согласование и исполнение действий" })}
          subtitle={t(lang, {
            en: "Idempotent execution, policy packs, linkage guardrails, approval quorum and DLQ recovery.",
            ru: "Идемпотентное исполнение, policy pack, правила привязки, кворум согласования и восстановление через DLQ.",
          })}
          icon="control"
        />
        <MetricStrip items={metricItems} />

        <div className="react-grid react-grid-3">
          <WorkspaceSection
            title={t(lang, { en: "Policy packs", ru: "Пакеты политик" })}
            subtitle={t(lang, {
              en: "Guardrails grouped by identity, endpoint, vulnerability and resilience.",
              ru: "Ограничения и guardrails, сгруппированные по доступу, хостам, уязвимостям и устойчивости.",
            })}
            icon="builders"
            tone="emphasis"
          >
            <div className="react-list">
              {policyPacks.map((pack, index) => {
                const item = pack as RuntimeBlob;
                return (
                  <section key={`${String(item.id || "pack")}-${index}`} className="react-card react-card-nested">
                    <strong>{String(item.title || item.id || t(lang, { en: "Policy pack", ru: "Пакет политик" }))}</strong>
                    <div className="react-card-button-copy">{String(item.description || t(lang, { en: "Approval, linkage and execution defaults.", ru: "Базовые правила согласования, привязки и исполнения." }))}</div>
                    <div className="react-card-button-grid">
                      <span>{t(lang, { en: "Modes", ru: "Режимы" })}</span><strong>{asCsv(item.approval_modes) || String(item.default_approval_mode || "single")}</strong>
                      <span>{t(lang, { en: "Roles", ru: "Роли" })}</span><strong>{asCsv(item.required_roles) || "n/a"}</strong>
                      <span>{t(lang, { en: "Triggers", ru: "Триггеры" })}</span><strong>{asCsv(item.trigger_kinds || item.recommended_trigger_kinds) || "n/a"}</strong>
                    </div>
                  </section>
                );
              })}
            </div>
          </WorkspaceSection>

          <WorkspaceSection
            title={t(lang, { en: "Operator templates", ru: "Операторские шаблоны" })}
            subtitle={t(lang, {
              en: "Fast playbooks with prewired pack, quorum and linkage defaults.",
              ru: "Быстрые плейбуки с заранее настроенными policy pack, кворумом и правилами привязки.",
            })}
            icon="connectors"
          >
            <div className="react-list">
              {PLAYBOOK_TEMPLATES.map((template) => (
                <button
                  key={template.id}
                  type="button"
                  className="react-card react-card-button"
                  onClick={() =>
                    setForm((current) => ({
                      ...current,
                      title: templateTitle(template.id, lang),
                      policyPackId: template.pack,
                      approvalMode: template.approvalMode,
                      triggerKinds: template.triggerKinds,
                      requiredRoles: template.requiredRoles,
                      messageTemplate: templateMessage(template.id, lang),
                      stepsJson: template.stepsJson,
                      kind: "chain",
                      playbookClass: String(template.playbookClass || current.playbookClass || "workflow"),
                      governanceTier: String(template.governanceTier || current.governanceTier || "operator"),
                      dangerous: Boolean(template.dangerous),
                      integrationTargets: String(template.integrationTargets || ""),
                      evidenceContract: String(template.evidenceContract || ""),
                      rollbackContract: String(template.rollbackContract || ""),
                      preconditions: String(template.preconditions || ""),
                      complianceControls: String(template.complianceControls || ""),
                    }))
                  }
                >
                  <div className="react-card-button-header"><strong>{templateTitle(template.id, lang)}</strong><span className="react-badge soft">{template.pack}</span></div>
                  <div className="react-card-button-copy">{templateSummary(template, lang)}</div>
                </button>
              ))}
            </div>
          </WorkspaceSection>

          <WorkspaceSection title={t(lang, { en: "Analytics", ru: "Аналитика" })} subtitle={t(lang, { en: "Where load, approvals and recovery pressure concentrate.", ru: "Где концентрируются нагрузка, согласования и давление на восстановление." })} icon="dashboard">
            <section className="react-card react-card-nested"><PanelHeader title={t(lang, { en: "Kinds", ru: "Типы" })} /><BreakdownBars items={analyticsState.data?.breakdowns?.action_kinds || []} /></section>
            <section className="react-card react-card-nested"><PanelHeader title={t(lang, { en: "Trigger mix", ru: "Смесь триггеров" })} /><BreakdownBars items={analyticsState.data?.breakdowns?.trigger_kinds || []} /></section>
            <section className="react-card react-card-nested"><PanelHeader title={t(lang, { en: "Approval modes", ru: "Режимы согласования" })} /><BreakdownBars items={analyticsState.data?.breakdowns?.approval_modes || []} /></section>
          </WorkspaceSection>
        </div>

        <div className="react-grid react-grid-3">
          <WorkspaceSection title={t(lang, { en: "Registry", ru: "Реестр" })} subtitle={t(lang, { en: "Linked actions with pack, trigger and quorum coverage.", ru: "Связанные действия с pack, триггерами и покрытием по кворуму." })} icon="events" tone="emphasis">
            <div className="react-list">
              {actions.map((item) => (
                <button key={item.id} type="button" className={`react-card react-card-button ${selectedActionId === item.id ? "active" : ""}`} onClick={() => setSelectedActionId(String(item.id || ""))}>
                  <div className="react-card-button-header"><div><strong>{item.title || item.id}</strong><div className="react-card-button-copy">{item.description || actionKindLabel(String(item.kind || "webhook"), lang) || t(lang, { en: "response action", ru: "ответное действие" })}</div></div><StatusBadge value={String(item.health?.last_status || item.status || "unknown")} /></div>
                  <div className="react-card-button-grid"><span>{t(lang, { en: "Pack", ru: "Пакет" })}</span><strong>{String(item.policy_pack_id || "n/a")}</strong><span>{t(lang, { en: "Approval", ru: "Согласование" })}</span><strong>{String(((item.approval || {}) as RuntimeBlob).mode || "none")}</strong><span>{t(lang, { en: "Triggers", ru: "Триггеры" })}</span><strong>{asCsv(item.trigger_kinds) || "n/a"}</strong></div>
                </button>
              ))}
            </div>
          </WorkspaceSection>

          <WorkspaceSection title={t(lang, { en: "Action editor", ru: "Редактор действий" })} subtitle={t(lang, { en: "Design dangerous flows with linkage and approval before execution.", ru: "Собирайте опасные сценарии с привязкой и согласованием до запуска." })} icon="control">
            <div className="react-form-grid">
              <input className="react-input" value={form.title} onChange={(event) => setForm((current) => ({ ...current, title: event.target.value }))} placeholder={t(lang, { en: "Action title", ru: "Название действия" })} />
              <input className="react-input" value={form.description} onChange={(event) => setForm((current) => ({ ...current, description: event.target.value }))} placeholder={t(lang, { en: "Description", ru: "Описание" })} />
              <select className="react-select react-select-inline" value={form.kind} onChange={(event) => setForm((current) => ({ ...current, kind: event.target.value }))}>{ACTION_KINDS.map((kind) => <option key={kind} value={kind}>{actionKindLabel(kind, lang)}</option>)}</select>
              <input className="react-input" value={form.policyPackId} onChange={(event) => setForm((current) => ({ ...current, policyPackId: event.target.value }))} placeholder={t(lang, { en: "Policy pack", ru: "Пакет политик" })} />
              <input className="react-input" value={form.targetUrl} onChange={(event) => setForm((current) => ({ ...current, targetUrl: event.target.value }))} placeholder={t(lang, { en: "Primary target URL", ru: "Основной целевой URL" })} />
              <textarea className="react-query-editor" rows={3} value={form.messageTemplate} onChange={(event) => setForm((current) => ({ ...current, messageTemplate: event.target.value }))} placeholder={t(lang, { en: "Execution message template", ru: "Шаблон сообщения исполнения" })} />
              <div className="react-actions react-wrap">
                <label className="react-toggle"><input type="checkbox" checked={form.enabled} onChange={(event) => setForm((current) => ({ ...current, enabled: event.target.checked }))} /><span>{t(lang, { en: "Enabled", ru: "Включено" })}</span></label>
                <label className="react-toggle"><input type="checkbox" checked={form.dangerous} onChange={(event) => setForm((current) => ({ ...current, dangerous: event.target.checked }))} /><span>{t(lang, { en: "Dangerous", ru: "Опасное" })}</span></label>
              </div>
              <div className="react-actions react-wrap">
                <input className="react-input" value={form.triggerKinds} onChange={(event) => setForm((current) => ({ ...current, triggerKinds: event.target.value }))} placeholder={t(lang, { en: "Trigger kinds: detection_alert,case,finding", ru: "Типы триггеров: detection_alert,case,finding" })} />
                <input className="react-input" value={form.owners} onChange={(event) => setForm((current) => ({ ...current, owners: event.target.value }))} placeholder={t(lang, { en: "Owners: soc-lead,secops", ru: "Владельцы: soc-lead,secops" })} />
              </div>
              <div className="react-actions react-wrap">
                <select className="react-select react-select-inline" value={form.playbookClass} onChange={(event) => setForm((current) => ({ ...current, playbookClass: event.target.value }))}>
                  <option value="workflow">workflow</option>
                  <option value="containment">containment</option>
                  <option value="eradication">eradication</option>
                  <option value="communication">communication</option>
                  <option value="evidence">evidence</option>
                </select>
                <select className="react-select react-select-inline" value={form.governanceTier} onChange={(event) => setForm((current) => ({ ...current, governanceTier: event.target.value }))}>
                  <option value="operator">operator</option>
                  <option value="supervisor">supervisor</option>
                  <option value="high-risk">high-risk</option>
                  <option value="change_board">change_board</option>
                </select>
                <input className="react-input" value={form.complianceControls} onChange={(event) => setForm((current) => ({ ...current, complianceControls: event.target.value }))} placeholder="Compliance controls: pci.10,nist.ir" />
              </div>
              <div className="react-actions react-wrap">
                <input className="react-input" value={form.evidenceContract} onChange={(event) => setForm((current) => ({ ...current, evidenceContract: event.target.value }))} placeholder="Evidence contract: actor_ip,host_snapshot" />
                <input className="react-input" value={form.rollbackContract} onChange={(event) => setForm((current) => ({ ...current, rollbackContract: event.target.value }))} placeholder="Rollback contract: case_note,approval_ticket" />
              </div>
              <div className="react-actions react-wrap">
                <input className="react-input" value={form.preconditions} onChange={(event) => setForm((current) => ({ ...current, preconditions: event.target.value }))} placeholder="Preconditions: ticket_opened,case_linked" />
                <input className="react-input" value={form.integrationTargets} onChange={(event) => setForm((current) => ({ ...current, integrationTargets: event.target.value }))} placeholder="Integration targets: jira,edr,idp" />
              </div>
              <textarea className="react-query-editor" rows={3} value={form.operatorNotesText} onChange={(event) => setForm((current) => ({ ...current, operatorNotesText: event.target.value }))} placeholder={t(lang, { en: "Operator guidance and guardrails", ru: "Подсказки оператору и guardrails" })} />
              <textarea className="react-query-editor" rows={3} value={form.rollbackNotesText} onChange={(event) => setForm((current) => ({ ...current, rollbackNotesText: event.target.value }))} placeholder={t(lang, { en: "Rollback notes and recovery steps", ru: "Заметки по rollback и шаги восстановления" })} />
              <div className="react-actions react-wrap">
                <select className="react-select react-select-inline" value={form.approvalMode} onChange={(event) => setForm((current) => ({ ...current, approvalMode: event.target.value }))}>
                  <option value="none">{t(lang, { en: "none", ru: "нет" })}</option>
                  <option value="single">{t(lang, { en: "single", ru: "один оператор" })}</option>
                  <option value="two_man">{t(lang, { en: "two_man", ru: "два оператора" })}</option>
                </select>
                <input className="react-input" value={form.minApprovers} onChange={(event) => setForm((current) => ({ ...current, minApprovers: event.target.value }))} placeholder={t(lang, { en: "Min approvers", ru: "Минимум подтверждений" })} />
                <input className="react-input" value={form.requiredRoles} onChange={(event) => setForm((current) => ({ ...current, requiredRoles: event.target.value }))} placeholder={t(lang, { en: "Required roles", ru: "Обязательные роли" })} />
              </div>
              <div className="react-actions react-wrap">
                <input className="react-input" value={form.linkageCaseId} onChange={(event) => setForm((current) => ({ ...current, linkageCaseId: event.target.value }))} placeholder={t(lang, { en: "Default case_id", ru: "Базовый case_id" })} />
                <input className="react-input" value={form.linkageAlertId} onChange={(event) => setForm((current) => ({ ...current, linkageAlertId: event.target.value }))} placeholder={t(lang, { en: "Default alert_id", ru: "Базовый alert_id" })} />
              </div>
              <div className="react-actions react-wrap">
                <input className="react-input" value={form.linkageDetectionId} onChange={(event) => setForm((current) => ({ ...current, linkageDetectionId: event.target.value }))} placeholder={t(lang, { en: "Default detection_id", ru: "Базовый detection_id" })} />
                <input className="react-input" value={form.linkageFindingKey} onChange={(event) => setForm((current) => ({ ...current, linkageFindingKey: event.target.value }))} placeholder={t(lang, { en: "Default finding_key", ru: "Базовый finding_key" })} />
                <input className="react-input" value={form.linkageAssetId} onChange={(event) => setForm((current) => ({ ...current, linkageAssetId: event.target.value }))} placeholder={t(lang, { en: "Default asset_id", ru: "Базовый asset_id" })} />
              </div>
              <textarea className="react-query-editor" rows={10} value={form.stepsJson} onChange={(event) => setForm((current) => ({ ...current, stepsJson: event.target.value }))} placeholder={t(lang, { en: "Chain steps JSON", ru: "JSON шагов цепочки" })} />
              <div className="react-actions react-wrap">
                <button type="button" className="react-primary-button" onClick={saveAction} disabled={!form.title.trim()}>{t(lang, { en: "Save action", ru: "Сохранить действие" })}</button>
                <button type="button" className="react-link-button" onClick={() => setForm(emptyForm())}>{t(lang, { en: "New action", ru: "Новое действие" })}</button>
                <button type="button" className="react-link-button" disabled={!selectedAction} onClick={() => selectedAction && void runAction(String(selectedAction.id || ""), true)}>{t(lang, { en: "Dry-run", ru: "Пробный запуск" })}</button>
                <button type="button" className="react-link-button" disabled={!selectedAction} onClick={() => selectedAction && void runAction(String(selectedAction.id || ""), false)}>{t(lang, { en: "Execute", ru: "Выполнить" })}</button>
              </div>
            </div>
          </WorkspaceSection>

          <WorkspaceSection title={t(lang, { en: "Approval queue", ru: "Очередь согласования" })} subtitle={t(lang, { en: "Quorum, justification, linkage and execution state.", ru: "Кворум, обоснование, привязка и текущее состояние исполнения." })} icon="incidents">
            <div className="react-list react-list-compact">
              {executions.slice(0, 12).map((item) => {
                const approval = (item.approval || {}) as RuntimeBlob;
                return (
                  <section key={item.id} className="react-card react-card-nested">
                    <div className="react-card-button-header">
                      <div>
                        <strong>{item.id}</strong>
                        <div className="react-card-button-copy">{item.action_id || "n/a"} | {linkageSummary(item.linkage, lang)}</div>
                      </div>
                      <StatusBadge value={String(item.status || "unknown")} />
                    </div>
                    <div className="react-card-button-grid">
                      <span>{t(lang, { en: "Progress", ru: "Прогресс" })}</span><strong>{String(approval.approval_progress || "0/0")}</strong>
                      <span>{t(lang, { en: "Roles", ru: "Роли" })}</span><strong>{asCsv(approval.required_roles) || "n/a"}</strong>
                      <span>{t(lang, { en: "Expires", ru: "Истекает" })}</span><strong>{approval.expires_ts ? formatTimestamp(approval.expires_ts, "compact") : "n/a"}</strong>
                    </div>
                    <textarea className="react-query-editor" rows={2} value={operatorNotes[item.id] || ""} onChange={(event) => setOperatorNotes((current) => ({ ...current, [item.id]: event.target.value }))} placeholder={t(lang, { en: "Approval or rejection note", ru: "Заметка для согласования или отклонения" })} />
                    <div className="react-actions react-wrap">
                      {String(item.status || "") === "awaiting_approval" ? <button type="button" className="react-primary-button" onClick={() => void approveExecution(item)}>{t(lang, { en: "Approve", ru: "Согласовать" })}</button> : null}
                      {String(item.status || "") === "awaiting_approval" ? <button type="button" className="react-link-button" onClick={() => void rejectExecution(item)}>{t(lang, { en: "Reject", ru: "Отклонить" })}</button> : null}
                      {["error", "failed", "blocked", "partial_failure"].includes(String(item.status || "")) ? <button type="button" className="react-link-button" onClick={() => void retryExecution(String(item.id || ""))}>{t(lang, { en: "Retry", ru: "Повторить" })}</button> : null}
                      <button type="button" className="react-link-button" onClick={() => { setSelectedTitle(String(item.id || "")); setSelectedPayload((item.details || item.payload || item) as RuntimeBlob); }}>{t(lang, { en: "Details", ru: "Детали" })}</button>
                    </div>
                  </section>
                );
              })}
            </div>
          </WorkspaceSection>
        </div>

        <div className="react-grid react-grid-2">
          <WorkspaceSection title={t(lang, { en: "Ledger", ru: "Журнал исполнения" })} subtitle={t(lang, { en: "Idempotency, approval and replay trail for recent executions.", ru: "След идемпотентности, согласования и повторов для недавних запусков." })} icon="sources">
            <div className="react-list react-list-compact">
              {ledger.slice(0, 12).map((entry, index) => (
                <button key={`${String((entry as RuntimeBlob).execution_id || "ledger")}-${index}`} type="button" className="react-list-item" onClick={() => { setSelectedTitle(String((entry as RuntimeBlob).event || "ledger")); setSelectedPayload(entry as RuntimeBlob); }}>
                  <strong>{String((entry as RuntimeBlob).event || t(lang, { en: "ledger", ru: "журнал" }))}</strong>
                  <span>{String((entry as RuntimeBlob).execution_id || (entry as RuntimeBlob).action_id || "n/a")}</span>
                  <span>{String((entry as RuntimeBlob).ts || "n/a")}</span>
                </button>
              ))}
            </div>
          </WorkspaceSection>

          <WorkspaceSection title={t(lang, { en: "DLQ recovery", ru: "Восстановление через DLQ" })} subtitle={t(lang, { en: "Replay failed action attempts with full payload visibility.", ru: "Повторяйте неудачные действия с полной видимостью их payload." })} icon="events">
            <div className="react-list react-list-compact">
              {dlq.slice(0, 12).map((item) => (
                <section key={String(item.id || "dlq")} className="react-card react-card-nested">
                  <div className="react-card-button-header"><div><strong>{String(item.id || "dlq")}</strong><div className="react-card-button-copy">{String(item.action_id || "n/a")} | {String(item.error || t(lang, { en: "failed action", ru: "ошибка действия" }))}</div></div><StatusBadge value={String(item.status || "failed")} /></div>
                  <div className="react-card-button-grid"><span>{t(lang, { en: "Attempts", ru: "Попытки" })}</span><strong>{Number(item.attempts || 0).toLocaleString()}</strong><span>{t(lang, { en: "Linkage", ru: "Привязка" })}</span><strong>{linkageSummary(item.linkage as RuntimeBlob | undefined, lang)}</strong></div>
                  <div className="react-actions react-wrap">
                    <button type="button" className="react-link-button" onClick={() => void replayDlq(String(item.id || ""))}>{t(lang, { en: "Replay", ru: "Повторить" })}</button>
                    <button type="button" className="react-link-button" onClick={() => { setSelectedTitle(String(item.id || "")); setSelectedPayload((item.payload || item) as RuntimeBlob); }}>{t(lang, { en: "Payload", ru: "Payload" })}</button>
                  </div>
                </section>
              ))}
            </div>
          </WorkspaceSection>
        </div>

        <DrawerOverlay open={Boolean(selectedPayload)} title={selectedTitle || t(lang, { en: "Response detail", ru: "Детали реагирования" })} subtitle={t(lang, { en: "Execution, ledger or DLQ payload", ru: "Payload исполнения, журнала или DLQ" })} onClose={() => { setSelectedPayload(null); setSelectedTitle(""); }}>
          <JsonPreview value={selectedPayload || {}} />
        </DrawerOverlay>
      </div>
    </AsyncGate>
  );
}
