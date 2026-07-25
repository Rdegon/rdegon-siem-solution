import type { KeycloakUserRecord } from "./types";
import type { UiLang } from "./runtimeLocalization";

type LocalizedCopy = { en: string; ru: string };

const SOURCE_ALIAS_OVERRIDES: Record<string, string> = {
  "192.168.3.81": "desktop-rdegon",
  "192.168.3.101": "pve",
  "192.168.3.102": "lab-edge-01",
  "192.168.1.22": "desktop-rdegon",
  "192.168.1.102": "lab-edge-01",
  "192.168.1.35": "siem-ingest",
  "192.168.1.37": "siem-processing",
  "192.168.1.38": "siem-storage",
  "192.168.1.39": "siem-web",
  "192.168.1.40": "siem-transport",
  "192.168.1.101": "pve",
  "192.168.1.120": "nextcloud-siem",
  "192.168.1.121": "navidrome-01",
  "10.20.10.1": "lab-edge-01",
  "10.20.10.104": "siem-ingest",
  "10.20.10.105": "siem-processing",
  "10.20.10.106": "siem-storage",
  "10.20.10.107": "siem-web",
  "10.20.10.108": "siem-transport",
  "10.20.20.1": "lab-edge-01",
  "10.20.20.100": "minecraft-01",
  "10.20.20.120": "nextcloud-siem",
  "10.20.20.121": "navidrome-01",
  "10.20.20.130": "gamepanel-01",
  "10.20.30.1": "lab-edge-01",
  "10.20.30.122": "vuln-mgr-01",
  "10.20.30.123": "pilot-web-01",
  "10.20.30.124": "pilot-db-01",
  "10.20.30.125": "pilot-cache-01",
  "10.20.30.126": "openclaw-gateway",
  "10.20.40.1": "lab-edge-01",
  "opnsense-edge-01": "lab-edge-01",
  "pilot-web-01.lab.home.arpa": "pilot-web-01",
  "openclaw-gateway.lab.home.arpa": "openclaw-gateway",
  "45.89.111.208": "vm15611031",
  "176.108.250.215": "vpn-host-khanov",
  "vuln-siem": "navidrome-01",
  "vuln siem": "navidrome-01",
  "generic http": "generic-http-collector",
  "generic http refresh": "generic-http-refresh",
};

const SOURCE_FRIENDLY_COPY: Record<string, LocalizedCopy> = {
  "desktop-rdegon": { en: "Analyst workstation", ru: "Рабочая станция аналитика" },
  "vuln-mgr-01": { en: "Vulnerability manager", ru: "Узел менеджера уязвимостей" },
  "pilot-web-01": { en: "Pilot web service", ru: "Пилотный веб-сервис" },
  "pilot-cache-01": { en: "Pilot cache service", ru: "Пилотный кэш-сервис" },
  "pilot-db-01": { en: "Pilot PostgreSQL node", ru: "Пилотный узел PostgreSQL" },
  "siem-ingest": { en: "SIEM ingest node", ru: "Узел приема SIEM" },
  "siem-processing": { en: "SIEM processing node", ru: "Узел обработки SIEM" },
  "siem-storage": { en: "SIEM storage node", ru: "Узел хранения SIEM" },
  "siem-web": { en: "SIEM web node", ru: "Веб-узел SIEM" },
  "siem-transport": { en: "SIEM standby transport", ru: "Резервный транспортный узел SIEM" },
  pve: { en: "Proxmox hypervisor", ru: "Гипервизор Proxmox" },
  "nextcloud-siem": { en: "Nextcloud service", ru: "Сервис Nextcloud" },
  "navidrome-01": { en: "Music service", ru: "Музыкальный сервис" },
  "openclaw-gateway": { en: "OpenClaw gateway", ru: "Шлюз OpenClaw" },
  vm15611031: { en: "External VPN node", ru: "Внешний VPN-узел" },
  "vpn-host-khanov": { en: "Jump and VPN host", ru: "Прыжковый и VPN-хост" },
  "generic-http-collector": { en: "Universal HTTP collector", ru: "Универсальный HTTP-коллектор" },
  "generic-http-refresh": { en: "HTTP refresh job", ru: "Задача HTTP-обновления" },
};

const EVENT_TOKEN_COPY: Record<string, LocalizedCopy> = {
  USER_LOGIN: { en: "User login", ru: "Вход пользователя" },
  USER_LOGOUT: { en: "User logout", ru: "Выход пользователя" },
  USER_AUTH: { en: "User authentication", ru: "Аутентификация пользователя" },
  USER_AUTH_FAILURE: { en: "Authentication failure", ru: "Ошибка аутентификации" },
  AUDIT_USER_LOGIN_FAILURE: { en: "Audit login failure", ru: "Ошибка входа по аудиту" },
  SSH_LOGIN: { en: "SSH login", ru: "Вход по SSH" },
  SSH_LOGIN_FAILURE: { en: "SSH login failure", ru: "Ошибка входа по SSH" },
  SUDO_ROOT: { en: "Privilege escalation", ru: "Повышение привилегий" },
  POWERSHELL_ENCODED_COMMAND: { en: "Encoded PowerShell command", ru: "Закодированная команда PowerShell" },
  SERVICE_CHANGE: { en: "Service change", ru: "Изменение сервиса" },
  CONFIG_CHANGE: { en: "Configuration change", ru: "Изменение конфигурации" },
};

function localized(copy: LocalizedCopy | undefined, lang: UiLang) {
  return copy ? copy[lang] : "";
}

function titleCaseParts(parts: string[]) {
  return parts
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join(" ");
}

function prettifyTechnicalToken(value: string) {
  const normalized = String(value || "").trim();
  if (!normalized) return "";
  if (/^[A-Z0-9_]+$/.test(normalized)) {
    return normalized
      .split("_")
      .map((part) => titleCaseParts([part]))
      .join(" ");
  }
  if (/^[a-z0-9_.-]+$/.test(normalized) && /[_-]/.test(normalized)) {
    return titleCaseParts(normalized.split(/[_-]+/));
  }
  return normalized;
}

function canonicalizeSource(value: string) {
  const trimmed = String(value || "").trim();
  if (!trimmed) return "";
  const embeddedIp = trimmed.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  if (embeddedIp?.[0] && SOURCE_ALIAS_OVERRIDES[embeddedIp[0].toLowerCase()]) {
    return SOURCE_ALIAS_OVERRIDES[embeddedIp[0].toLowerCase()];
  }
  return SOURCE_ALIAS_OVERRIDES[trimmed.toLowerCase()] || trimmed;
}

function dedupe(parts: Array<string | undefined | null>) {
  return Array.from(new Set(parts.map((item) => String(item || "").trim()).filter(Boolean)));
}

export function humanizeSourceName(value: unknown, lang: UiLang, options?: { technicalSuffix?: boolean }) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  const canonical = canonicalizeSource(raw);
  const friendly = localized(SOURCE_FRIENDLY_COPY[String(canonical).toLowerCase()], lang) || prettifyTechnicalToken(canonical);
  if (!friendly) return raw;
  if (options?.technicalSuffix === false) return friendly;
  if (String(canonical).toLowerCase() === raw.toLowerCase()) return friendly;
  return `${friendly} (${canonical})`;
}

export function humanizeTechnicalValue(value: unknown, lang: UiLang) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  const tokenCopy = EVENT_TOKEN_COPY[raw.toUpperCase()];
  if (tokenCopy) return localized(tokenCopy, lang);
  if (SOURCE_ALIAS_OVERRIDES[raw.toLowerCase()] || SOURCE_FRIENDLY_COPY[raw.toLowerCase()]) {
    return humanizeSourceName(raw, lang);
  }
  return prettifyTechnicalToken(raw);
}

export function humanizeHandle(value: unknown) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  if (raw.includes("@")) {
    return raw.split("@")[0].replace(/[._-]+/g, " ");
  }
  return raw.replace(/[._-]+/g, " ");
}

export function describeIdentity(user: Partial<KeycloakUserRecord>, lang: UiLang) {
  const fullName = [user.first_name, user.last_name]
    .map((item) => String(item || "").trim())
    .filter(Boolean)
    .join(" ");
  const username = String(user.username || "").trim();
  const email = String(user.email || "").trim();
  const handle = humanizeHandle(email || username);
  const friendlyHandle = handle ? titleCaseParts(handle.split(/\s+/)) : "";
  const title =
    fullName ||
    friendlyHandle ||
    username ||
    email ||
    (lang === "ru" ? "Идентичность" : "Identity");
  const subtitle = dedupe([
    fullName || undefined,
    email || undefined,
    username && username !== email ? username : undefined,
  ]).join(" · ");
  const technical = dedupe([username, email]).join(" · ");
  return { title, subtitle, technical };
}

export function humanizeEventLabel(value: unknown, lang: UiLang) {
  return humanizeTechnicalValue(value, lang) || String(value || "").trim();
}
