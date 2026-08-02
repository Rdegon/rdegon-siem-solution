export type View =
  | "overview"
  | "alerts"
  | "incidents"
  | "events"
  | "cases"
  | "assets"
  | "reports"
  | "resources"
  | "sources"
  | "tasks"
  | "rules"
  | "runtime"
  | "access"
  | "coverage"
  | "topology"
  | "discovery"
  | "response"
  | "exposure"
  | "intel"
  | "identity"
  | "container"
  | "ngfw"
  | "ndr"
  | "ids"
  | "dfir"
  | "analysis"
  | "pki"
  | "evidence"
  | "vpn";

export const viewMeta: Record<View, { title: string; short: string; group: "soc" | "platform" | "security" }> = {
  overview: { title: "Панель мониторинга", short: "Мониторинг", group: "soc" },
  alerts: { title: "Алерты", short: "Алерты", group: "soc" },
  incidents: { title: "Инциденты", short: "Инциденты", group: "soc" },
  events: { title: "Поиск событий", short: "События", group: "soc" },
  cases: { title: "Кейсы", short: "Кейсы", group: "soc" },
  assets: { title: "Активы", short: "Активы", group: "soc" },
  reports: { title: "Отчеты", short: "Отчеты", group: "soc" },
  resources: { title: "Ресурсы платформы", short: "Ресурсы", group: "platform" },
  sources: { title: "Источники и коллекторы", short: "Источники", group: "platform" },
  tasks: { title: "Диспетчер задач", short: "Задачи", group: "platform" },
  rules: { title: "Контент детектирования", short: "Правила", group: "platform" },
  runtime: { title: "Состояние платформы", short: "Runtime", group: "platform" },
  access: { title: "Доступ и учетные записи", short: "Доступ", group: "platform" },
  coverage: { title: "Покрытие средствами защиты", short: "Покрытие", group: "security" },
  topology: { title: "Топология сети", short: "Топология", group: "security" },
  discovery: { title: "Обнаружение и агенты", short: "Discovery", group: "security" },
  response: { title: "SOAR и автоматизация", short: "SOAR", group: "security" },
  exposure: { title: "Управление уязвимостями", short: "Уязвимости", group: "security" },
  intel: { title: "Threat Intelligence", short: "Threat Intel", group: "security" },
  identity: { title: "Identity Security", short: "Identity", group: "security" },
  container: { title: "Container Runtime Security", short: "Container", group: "security" },
  ngfw: { title: "OPNsense Network Firewall", short: "NGFW", group: "security" },
  ndr: { title: "Network Detection and Response", short: "NDR", group: "security" },
  ids: { title: "Suricata Network IPS", short: "IDS/IPS", group: "security" },
  dfir: { title: "Endpoint DFIR", short: "DFIR", group: "security" },
  analysis: { title: "Malware Analysis", short: "Анализ", group: "security" },
  pki: { title: "Internal PKI", short: "PKI", group: "security" },
  evidence: { title: "Evidence Storage", short: "Evidence", group: "security" },
  vpn: { title: "VPN и защищенный доступ", short: "VPN", group: "security" },
};

export const mainNavigation: View[] = ["overview", "alerts", "incidents", "events", "cases", "assets", "reports"];
export const platformNavigation: View[] = ["resources", "sources", "tasks", "rules", "runtime", "access"];
export const securityNavigationGroups: Array<{ id: string; title: string; items: View[] }> = [
  { id: "security-control", title: "Контроль", items: ["coverage", "topology", "discovery", "response"] },
  { id: "security-exposure", title: "Экспозиция и доступ", items: ["exposure", "intel", "identity"] },
  { id: "security-network", title: "Сеть и runtime", items: ["ngfw", "ndr", "ids", "container", "vpn"] },
  { id: "security-investigation", title: "Расследование и доверие", items: ["dfir", "analysis", "evidence", "pki"] },
];
export const securityNavigation: View[] = securityNavigationGroups.flatMap((group) => group.items);

export const commandHints: Partial<Record<View, string>> = {
  overview: "Макеты мониторинга и приоритеты смены",
  alerts: "Сигналы корреляции до объединения в инцидент",
  incidents: "Очередь, triage и расследование",
  events: "Query console и pivots",
  cases: "Evidence, задачи и response plans",
  assets: "Инвентарь и бизнес-контекст",
  reports: "Шаблоны, расписания и сформированные отчеты",
  resources: "Коллекторы, корреляторы, хранилища и коннекторы",
  sources: "Heartbeat, lag, DLQ и onboarding",
  tasks: "Отчеты, response executions и discovery jobs",
  rules: "Правила, fixtures и historical replay",
  runtime: "Узлы, services и runbooks",
  access: "Users, service accounts и grants",
  coverage: "Матрица сенсоров и интеграций",
  topology: "Сегменты, источники, связи и статистика",
  discovery: "Сканирование сети, onboarding и агенты",
  response: "Playbooks, approvals и executions",
  exposure: "CVE, remediation и автозакрытие",
  intel: "IoC, feeds, sightings и STIX",
  identity: "Keycloak, OIDC, пользователи и роли",
  ngfw: "OPNsense: политики и enforcement",
  ndr: "Zeek и Arkime: flows, sessions и PCAP",
  ids: "Suricata: сигнатуры и IPS",
  container: "Falco: runtime detections и workloads",
  vpn: "OpenVPN, WireGuard и защищенный доступ",
  dfir: "Velociraptor: hunts, triage и acquisitions",
  analysis: "ClamAV, YARA и анализ артефактов",
  evidence: "MinIO: evidence и chain of custody",
  pki: "step-ca: сертификаты и rotation",
};

export const pathByView: Record<View, string> = Object.fromEntries(
  (Object.keys(viewMeta) as View[]).map((view) => [view, view === "overview" ? "/app" : `/app/${view}`]),
) as Record<View, string>;

export function viewFromPath(pathname: string): View {
  const value = pathname.replace(/^\/app\/?/, "").split("/")[0] as View;
  return value && value in viewMeta ? value : "overview";
}
