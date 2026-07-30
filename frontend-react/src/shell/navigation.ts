import type { IconName } from "./chrome";
import { t } from "./context";

export type ShellNavItem = {
  to: string;
  label: string;
  icon: IconName;
  section: string;
};

export type ShellNavGroup = {
  id: string;
  title: string;
  items: ShellNavItem[];
};

export function primaryNavigation(lang: "en" | "ru"): ShellNavGroup[] {
  return [
    {
      id: "soc",
      title: "SOC",
      items: [
        { to: "/dashboards", label: t(lang, { en: "Monitoring", ru: "Мониторинг" }), icon: "dashboard", section: "overview" },
        { to: "/alerts", label: t(lang, { en: "Alerts", ru: "Алерты" }), icon: "incidents", section: "incidents" },
        { to: "/incidents", label: t(lang, { en: "Incidents", ru: "Инциденты" }), icon: "incidents", section: "incidents" },
        { to: "/events", label: t(lang, { en: "Event search", ru: "Поиск событий" }), icon: "events", section: "events" },
        { to: "/cases", label: t(lang, { en: "Cases", ru: "Кейсы" }), icon: "cases", section: "cases" },
        { to: "/entities", label: t(lang, { en: "Entities", ru: "Сущности" }), icon: "entities", section: "entities" },
        { to: "/assets", label: t(lang, { en: "Assets", ru: "Активы" }), icon: "assets", section: "assets" },
        { to: "/reports", label: t(lang, { en: "Reports", ru: "Отчеты" }), icon: "docs", section: "vuln" },
      ],
    },
    {
      id: "platform",
      title: t(lang, { en: "Platform", ru: "Платформа" }),
      items: [
        { to: "/resources", label: t(lang, { en: "Resources", ru: "Ресурсы" }), icon: "builders", section: "builders" },
        { to: "/sources", label: t(lang, { en: "Source status", ru: "Состояние источников" }), icon: "sources", section: "sources" },
        { to: "/collectors", label: t(lang, { en: "Collectors", ru: "Коллекторы" }), icon: "collectors", section: "collectors" },
        { to: "/connectors", label: t(lang, { en: "Connectors", ru: "Коннекторы" }), icon: "connectors", section: "connectors" },
        { to: "/tasks", label: t(lang, { en: "Task manager", ru: "Диспетчер задач" }), icon: "control", section: "response" },
        { to: "/rules", label: t(lang, { en: "Detection content", ru: "Контент детектирования" }), icon: "builders", section: "builders" },
        { to: "/metrics", label: t(lang, { en: "Metrics", ru: "Метрики" }), icon: "dashboard", section: "host-runtime" },
        { to: "/control", label: "Control Plane", icon: "control", section: "control" },
        { to: "/access", label: t(lang, { en: "Settings", ru: "Параметры" }), icon: "access", section: "access" },
        { to: "/docs", label: t(lang, { en: "Documentation", ru: "Документация" }), icon: "docs", section: "docs" },
      ],
    },
  ];
}

export function securityNavigation(lang: "en" | "ru"): ShellNavGroup[] {
  return [
    {
      id: "security-control",
      title: t(lang, { en: "Control", ru: "Контроль" }),
      items: [
        { to: "/security/coverage", label: t(lang, { en: "Coverage", ru: "Покрытие" }), icon: "connectors", section: "connectors" },
        { to: "/topology", label: t(lang, { en: "Topology", ru: "Топология" }), icon: "map", section: "sources" },
        { to: "/security/discovery", label: "Discovery", icon: "sources", section: "sources" },
        { to: "/response", label: "SOAR", icon: "control", section: "response" },
      ],
    },
    {
      id: "security-exposure",
      title: t(lang, { en: "Exposure and access", ru: "Экспозиция и доступ" }),
      items: [
        { to: "/vuln", label: "Vulnerability Manager", icon: "vuln", section: "vuln" },
        { to: "/threat-intel", label: "MISP / Threat Intelligence", icon: "intel", section: "threat-intel" },
        { to: "/security/identity", label: "Keycloak / OIDC", icon: "access", section: "access" },
      ],
    },
    {
      id: "security-network",
      title: t(lang, { en: "Network and runtime", ru: "Сеть и runtime" }),
      items: [
        { to: "/security/ngfw", label: "OPNsense / NGFW", icon: "access", section: "sources" },
        { to: "/security/ndr", label: "Zeek / Arkime", icon: "map", section: "sources" },
        { to: "/security/ips", label: "Suricata / IPS", icon: "incidents", section: "sources" },
        { to: "/security/runtime", label: "Falco / Runtime", icon: "dashboard", section: "sources" },
        { to: "/security/vpn", label: "VPN", icon: "globe", section: "sources" },
      ],
    },
    {
      id: "security-investigation",
      title: t(lang, { en: "Investigation and trust", ru: "Расследование и доверие" }),
      items: [
        { to: "/security/dfir", label: "Velociraptor / DFIR", icon: "cases", section: "sources" },
        { to: "/security/analysis", label: t(lang, { en: "Malware analysis", ru: "Анализ файлов" }), icon: "vuln", section: "sources" },
        { to: "/security/evidence", label: "MinIO / Evidence", icon: "cases", section: "sources" },
        { to: "/security/pki", label: "step-ca / PKI", icon: "access", section: "sources" },
      ],
    },
  ];
}

export function isSecurityPath(pathname: string) {
  return (
    pathname.startsWith("/security/") ||
    pathname === "/topology" ||
    pathname === "/response" ||
    pathname === "/vuln" ||
    pathname.startsWith("/vuln/") ||
    pathname === "/threat-intel"
  );
}
