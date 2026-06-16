import { createContext, useContext } from "react";

export const TIMEZONE_OPTIONS = [
  { value: "Europe/Moscow", label: "Moscow (UTC+3)" },
  { value: "UTC", label: "UTC" },
  { value: "Europe/Berlin", label: "Berlin" },
  { value: "Europe/London", label: "London" },
  { value: "America/New_York", label: "New York" },
  { value: "Asia/Dubai", label: "Dubai" },
  { value: "Asia/Almaty", label: "Almaty" },
];

type TimestampStyle = "full" | "compact" | "date" | "time";

export function timeZoneDisplayLabel(timeZone: string, lang: "en" | "ru" = "en") {
  if (timeZone === "Europe/Moscow") {
    return lang === "ru" ? "МСК (UTC+3)" : "MSK (UTC+3)";
  }
  if (timeZone === "UTC") {
    return "UTC";
  }
  const option = TIMEZONE_OPTIONS.find((item) => item.value === timeZone);
  if (!option) {
    return timeZone;
  }
  const match = option.label.match(/\(([^)]+)\)\s*$/);
  return match?.[1] || option.label;
}

function parseTimestamp(value: unknown) {
  if (value instanceof Date) {
    return Number.isFinite(value.getTime()) ? value : null;
  }
  const text = String(value ?? "").trim();
  if (!text) return null;
  let normalized = text;
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(normalized)) {
    normalized = normalized.replace(" ", "T") + "Z";
  } else if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?$/.test(normalized) && !/[zZ]|[+-]\d{2}:?\d{2}$/.test(normalized)) {
    normalized = `${normalized}Z`;
  }
  const parsed = new Date(normalized);
  return Number.isFinite(parsed.getTime()) ? parsed : null;
}

function getTimeZoneParts(date: Date, timeZone: string) {
  const formatter = new Intl.DateTimeFormat("en-CA", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
  const values = Object.fromEntries(
    formatter
      .formatToParts(date)
      .filter((part) => part.type !== "literal")
      .map((part) => [part.type, part.value]),
  ) as Record<string, string>;
  return {
    year: Number(values.year || 0),
    month: Number(values.month || 1),
    day: Number(values.day || 1),
    hour: Number(values.hour || 0),
    minute: Number(values.minute || 0),
    second: Number(values.second || 0),
  };
}

function toUtcTimestampString(date: Date) {
  const iso = date.toISOString();
  return iso.slice(0, 19).replace("T", " ");
}

function parseInputDateTime(value: string) {
  const match = String(value || "").trim().match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/);
  if (!match) return null;
  return {
    year: Number(match[1]),
    month: Number(match[2]),
    day: Number(match[3]),
    hour: Number(match[4]),
    minute: Number(match[5]),
  };
}

export function formatTimestampValue(value: unknown, timeZone: string, lang: "en" | "ru", style: TimestampStyle = "full") {
  const parsed = parseTimestamp(value);
  if (!parsed) return lang === "ru" ? "н/д" : "n/a";
  const locale = lang === "ru" ? "ru-RU" : "en-US";
  const optionsByStyle: Record<TimestampStyle, Intl.DateTimeFormatOptions> = {
    full: {
      timeZone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    },
    compact: {
      timeZone,
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    },
    date: {
      timeZone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    },
    time: {
      timeZone,
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    },
  };
  return new Intl.DateTimeFormat(locale, optionsByStyle[style]).format(parsed);
}

export function toTimeZoneInputValue(value: unknown, timeZone: string) {
  const parsed = parseTimestamp(value);
  if (!parsed) return "";
  const parts = getTimeZoneParts(parsed, timeZone);
  return `${String(parts.year).padStart(4, "0")}-${String(parts.month).padStart(2, "0")}-${String(parts.day).padStart(2, "0")}T${String(parts.hour).padStart(2, "0")}:${String(parts.minute).padStart(2, "0")}`;
}

export function toUtcQueryValue(value: string, timeZone: string) {
  const parts = parseInputDateTime(value);
  if (!parts) return "";
  const desiredEpoch = Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, 0);
  let utcMs = desiredEpoch;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const actual = getTimeZoneParts(new Date(utcMs), timeZone);
    const actualEpoch = Date.UTC(actual.year, actual.month - 1, actual.day, actual.hour, actual.minute, 0);
    if (actualEpoch === desiredEpoch) break;
    utcMs += desiredEpoch - actualEpoch;
  }
  return toUtcTimestampString(new Date(utcMs));
}

export function shiftTimeZoneInputValue(value: string, fromTimeZone: string, toTimeZone: string) {
  const utcValue = toUtcQueryValue(value, fromTimeZone);
  if (!utcValue) return "";
  return toTimeZoneInputValue(utcValue, toTimeZone);
}

type ShellContextValue = {
  lang: "en" | "ru";
  setLang: (lang: "en" | "ru") => void;
  theme: "dark" | "light";
  timezone: string;
  setTimezone: (timezone: string) => void;
  permissions: string[];
  sectionAccess: string[];
  formatTimestamp: (value: unknown, style?: TimestampStyle) => string;
  toInputDateTime: (value: unknown) => string;
  toUtcQueryValue: (value: string) => string;
};

export const ShellContext = createContext<ShellContextValue>({
  lang: "ru",
  setLang: () => undefined,
  theme: "dark",
  timezone: "Europe/Moscow",
  setTimezone: () => undefined,
  permissions: [],
  sectionAccess: [],
  formatTimestamp: () => "n/a",
  toInputDateTime: () => "",
  toUtcQueryValue: () => "",
});

export function useShellContext() {
  return useContext(ShellContext);
}

export function t(lang: "en" | "ru", values: { en: string; ru: string }) {
  return lang === "ru" ? values.ru : values.en;
}
