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
export const platformNavigation: View[] = ["resources", "sources", "rules", "runtime", "access"];
export const securityNavigation: View[] = [
  "coverage", "topology", "discovery", "response", "exposure", "intel", "identity",
  "ngfw", "ndr", "ids", "container", "vpn", "dfir", "analysis", "evidence", "pki",
];

export const pathByView: Record<View, string> = Object.fromEntries(
  (Object.keys(viewMeta) as View[]).map((view) => [view, view === "overview" ? "/app" : `/app/${view}`]),
) as Record<View, string>;

export function viewFromPath(pathname: string): View {
  const value = pathname.replace(/^\/app\/?/, "").split("/")[0] as View;
  return value && value in viewMeta ? value : "overview";
}
