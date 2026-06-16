export type UiLang = "en" | "ru";

const RULE_TITLE_RU: Record<string, string> = {
  "Extended Fleet Telemetry Missing": "Расширенное отсутствие телеметрии fleet",
  "Extended Fleet Service Flapping": "Флаппинг сервисов fleet",
  "Extended Fleet Runtime Pressure": "Давление на runtime fleet",
  "Fleet Telemetry Coverage Review": "Проверка полноты телеметрии fleet",
  "Gitea Failed Login Burst": "Всплеск неудачных входов в Gitea",
  "Gitea Administrative Change": "Административное изменение в Gitea",
  "Gitea Repository Activity Spike": "Всплеск активности репозиториев Gitea",
  "Host CPU Pressure Sustained": "Устойчивое давление по CPU",
  "Host Memory Pressure Sustained": "Устойчивое давление по памяти",
  "Host Disk Pressure Sustained": "Устойчивое давление по дискам",
  "Host Load Pressure Sustained": "Устойчивое давление по load average",
  "Host Swap Thrash Burst": "Всплеск thrashing по swap",
  "Host Filesystem Inode Pressure": "Давление по inode файловой системы",
  "Host Telemetry Missing": "Отсутствие телеметрии узла",
  "Host Service Flapping": "Флаппинг сервисов узла",
  "Storage Node Runtime Pressure": "Давление на storage-узел",
  "Control Plane Runtime Pressure": "Давление на control plane",
  "Host Telemetry Missing Daily Review": "Ежедневная проверка отсутствующей телеметрии узлов",
  "Host Service Flapping Trend Review": "Проверка тренда флаппинга сервисов узлов",
  "Storage Node Pressure Trend Review": "Проверка тренда давления storage-узлов",
  "Control Plane Runtime Trend Review": "Проверка тренда давления control plane",
  "Repeated External App Authentication Failures": "Повторяющиеся ошибки аутентификации во внешнем приложении",
  "First-Seen Login On SSO-Enabled Internal App": "Первый вход в SSO-приложение",
  "SSO Role Or Grant Drift Detected": "Обнаружен дрейф роли или гранта SSO",
  "Linux SSH Brute Force Burst": "Всплеск перебора SSH в Linux",
  "Linux Multi-Host SSH Brute Force": "Мультихостовый перебор SSH в Linux",
  "Linux Audit USER_LOGIN Failures": "Ошибки Linux Audit USER_LOGIN",
  "Linux Root SSH Login": "Прямой вход root по SSH в Linux",
  "Linux Root SSH Login Success": "Успешный вход root по SSH в Linux",
  "Linux Sudo To Root": "Sudo до root в Linux",
  "Linux Sudo To Root Burst": "Всплеск sudo до root в Linux",
  "Linux Exec As Root Burst": "Всплеск выполнения от root в Linux",
  "Linux Suspicious Download Utility": "Подозрительная утилита загрузки в Linux",
  "Linux Netcat Execution": "Запуск netcat в Linux",
  "Linux Sudo Root Session Opened": "Открыта root-сессия sudo в Linux",
  "Linux Authorized Keys Modified": "Изменение authorized_keys в Linux",
  "Linux Cron Modified": "Изменение cron в Linux",
  "Linux Passwd Or Shadow Access": "Доступ к passwd или shadow в Linux",
  "Linux Sudoers Modified": "Изменение sudoers в Linux",
  "Linux Systemd Unit Modified": "Изменение systemd-unit в Linux",
  "Linux Security-Critical Service Disabled": "Отключение критичного сервиса безопасности в Linux",
  "Linux Persistence Change Review": "Проверка изменений механизма закрепления в Linux",
  "Linux System Recon Burst": "Всплеск системной разведки в Linux",
  "Linux Audit Config Changed": "Изменение конфигурации Linux Audit",
  "Navidrome Proxy Authentication Failure Burst": "Всплеск ошибок аутентификации через прокси Navidrome",
  "Navidrome First-Seen User": "Первый пользователь в Navidrome",
  "Navidrome Abnormal Playback Or API Burst": "Аномальный всплеск playback/API в Navidrome",
  "OpenClaw Outbound Connection Burst": "Всплеск исходящих соединений OpenClaw",
  "OpenClaw DNS Query Burst": "Всплеск DNS-запросов OpenClaw",
  "OpenClaw Privileged Configuration Change": "Привилегированное изменение конфигурации OpenClaw",
  "OpenClaw Proxy Error Burst": "Всплеск proxy-ошибок OpenClaw",
  "OpenClaw Suspicious Interactive Privilege Activity": "Подозрительная интерактивная привилегированная активность OpenClaw",
  "OpenClaw New-Destination Review": "Проверка новых направлений OpenClaw",
  "Pilot Service Runtime Instability": "Нестабильность runtime pilot-сервиса",
  "Pilot Service Telemetry Missing": "Отсутствие телеметрии pilot-сервиса",
  "Pilot Service Auth Error Burst": "Всплеск ошибок аутентификации pilot-сервиса",
  "Pilot Service Error Trend Review": "Проверка тренда ошибок pilot-сервисов",
  "Greenbone Sync Or Import Degradation": "Деградация синхронизации или импорта Greenbone",
  "Fleet Scan Coverage Stale": "Устаревшее покрытие fleet сканированием",
  "Scanner Target Drift Against Proxmox Inventory": "Дрейф scanner target относительно инвентаря Proxmox",
  "Critical Exposure On Fleet Service": "Критическая экспозиция на сервисе fleet",
  "Public Service Vulnerability Burst": "Всплеск уязвимостей публичного сервиса",
  "Fleet Scan Freshness Review": "Проверка свежести сканирования fleet",
  "Fleet Unmapped Target Review": "Проверка неразмеченных целей fleet",
  "Windows Logon Failure Burst": "Всплеск ошибок входа Windows",
  "Windows Audit Log Cleared": "Очистка журнала аудита Windows",
  "Windows Privileged Group Membership Change": "Изменение членства в привилегированной группе Windows",
  "Windows Privileged Group Membership Changed": "Изменение членства в привилегированной группе Windows",
  "Windows Encoded PowerShell Command": "Закодированная команда PowerShell в Windows",
  "Windows Suspicious PowerShell Encoded Command": "Подозрительная закодированная команда PowerShell в Windows",
  "Windows Service Installed": "Установка сервиса в Windows",
  "Windows User Created": "Создание пользователя в Windows",
  "Windows Privilege Change Review": "Проверка изменений привилегий Windows",
  "Threat Intel Hit On Critical Asset": "Совпадение киберразведки на критичном активе",
  "Internet Multi-Port Probe": "Многопортовое зондирование из интернета",
};

const DASHBOARD_TITLE_RU: Record<string, string> = {
  "Security Overview / Обзор безопасности": "Обзор безопасности",
  "Collector Health / Коллекторы": "Состояние коллекторов",
  "Incident Operations / Операции SOC": "Операции SOC",
  "SOC Overview": "SOC-обзор",
  "Threat Geography": "География угроз",
  "Threat Intelligence": "Киберразведка",
  "Collector Health": "Состояние коллекторов",
  "Incident Operations": "Операции SOC",
  "External Traffic": "Внешний трафик",
};

function normalizeText(value: unknown): string {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function localizedSlashSuffix(text: string): string {
  const parts = text.split("/").map((item) => item.trim()).filter(Boolean);
  if (parts.length < 2) return "";
  const last = parts[parts.length - 1];
  return /[А-Яа-яЁё]/.test(last) ? last : "";
}

export function localizeRuleName(value: unknown, lang: UiLang): string {
  const text = normalizeText(value);
  if (!text) return "";
  if (lang !== "ru") return text;
  return RULE_TITLE_RU[text] || text;
}

export function localizeRuleNames(values: unknown, lang: UiLang): string[] {
  if (!Array.isArray(values)) return [];
  return values.map((item) => localizeRuleName(item, lang)).map((item) => item.trim()).filter(Boolean);
}

export function localizeDashboardTitle(value: unknown, lang: UiLang): string {
  const text = normalizeText(value);
  if (!text) return "";
  if (lang !== "ru") return text;
  return DASHBOARD_TITLE_RU[text] || localizedSlashSuffix(text) || text;
}
