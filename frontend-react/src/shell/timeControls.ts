import { t } from "./context";

export type SupportedLang = "en" | "ru";
export type TimeRangePreset = "15m" | "1h" | "6h" | "24h" | "72h" | "7d" | "30d" | "all" | "custom";

export type SelectOption = {
  value: string;
  label: string;
};

export const DEFAULT_ROW_OPTIONS = [10, 25, 50, 100, 250, 500, 1000];
export const DEFAULT_REFRESH_SECONDS = ["0", "30", "60", "120", "300", "900"];

export function timeRangeOptions(lang: SupportedLang): SelectOption[] {
  return [
    { value: "15m", label: t(lang, { en: "15 minutes", ru: "\u0031\u0035 \u043c\u0438\u043d\u0443\u0442" }) },
    { value: "1h", label: t(lang, { en: "1 hour", ru: "\u0031 \u0447\u0430\u0441" }) },
    { value: "6h", label: t(lang, { en: "6 hours", ru: "\u0036 \u0447\u0430\u0441\u043e\u0432" }) },
    { value: "24h", label: t(lang, { en: "24 hours", ru: "\u0032\u0034 \u0447\u0430\u0441\u0430" }) },
    { value: "72h", label: t(lang, { en: "72 hours", ru: "\u0037\u0032 \u0447\u0430\u0441\u0430" }) },
    { value: "7d", label: t(lang, { en: "7 days", ru: "\u0037 \u0434\u043d\u0435\u0439" }) },
    { value: "30d", label: t(lang, { en: "30 days", ru: "\u0033\u0030 \u0434\u043d\u0435\u0439" }) },
    { value: "all", label: t(lang, { en: "All available", ru: "\u0412\u0441\u0451 \u0434\u043e\u0441\u0442\u0443\u043f\u043d\u043e\u0435" }) },
    { value: "custom", label: t(lang, { en: "Custom range", ru: "\u0421\u0432\u043e\u0439 \u0434\u0438\u0430\u043f\u0430\u0437\u043e\u043d" }) },
  ];
}

export function refreshOptions(lang: SupportedLang): SelectOption[] {
  return DEFAULT_REFRESH_SECONDS.map((value) => {
    if (value === "0") {
      return { value, label: t(lang, { en: "No refresh", ru: "\u0411\u0435\u0437 \u0430\u0432\u0442\u043e\u043e\u0431\u043d\u043e\u0432\u043b\u0435\u043d\u0438\u044f" }) };
    }
    const seconds = Number(value || 0);
    if (seconds < 60) {
      return { value, label: t(lang, { en: `${seconds}s`, ru: `${seconds}\u0441` }) };
    }
    const minutes = Math.round(seconds / 60);
    return {
      value,
      label: t(lang, {
        en: `${minutes}m`,
        ru: `${minutes}\u043c`,
      }),
    };
  });
}

export function rowOptions(values: number[] = DEFAULT_ROW_OPTIONS): SelectOption[] {
  return values.map((value) => ({ value: String(value), label: String(value) }));
}

export function refreshIntervalMs(value: string): number {
  const seconds = Number(value || 0);
  return Number.isFinite(seconds) && seconds > 0 ? seconds * 1000 : 0;
}

export function presetToRange(
  preset: string,
  toInputDateTime: (value: unknown) => string,
): { fromTs: string; toTs: string } {
  const now = new Date();
  const minutesByPreset: Record<string, number> = {
    "15m": 15,
    "1h": 60,
    "6h": 360,
    "24h": 24 * 60,
    "72h": 72 * 60,
    "7d": 7 * 24 * 60,
    "30d": 30 * 24 * 60,
  };
  const minutes = minutesByPreset[preset];
  if (!minutes) {
    return { fromTs: "", toTs: "" };
  }
  const start = new Date(now.getTime() - minutes * 60 * 1000);
  return {
    fromTs: toInputDateTime(start.toISOString()),
    toTs: toInputDateTime(now.toISOString()),
  };
}

export function timeScopeSummary(
  lang: SupportedLang,
  {
    rangeLabel,
    refreshSeconds,
    rows,
    fromTs,
    toTs,
  }: {
    rangeLabel: string;
    refreshSeconds: string;
    rows: string | number;
    fromTs: string;
    toTs: string;
  },
): string {
  const refreshText =
    refreshSeconds === "0"
      ? t(lang, { en: "manual refresh", ru: "\u0440\u0443\u0447\u043d\u043e\u0435 \u043e\u0431\u043d\u043e\u0432\u043b\u0435\u043d\u0438\u0435" })
      : t(lang, {
          en: `${refreshSeconds}s refresh`,
          ru: `${refreshSeconds}\u0441 \u0430\u0432\u0442\u043e\u043e\u0431\u043d\u043e\u0432\u043b\u0435\u043d\u0438\u0435`,
        });
  if (fromTs || toTs) {
    return t(lang, {
      en: `${rangeLabel}: ${fromTs || "?"} -> ${toTs || "?"} | ${refreshText} | ${rows} rows`,
      ru: `${rangeLabel}: ${fromTs || "?"} -> ${toTs || "?"} | ${refreshText} | ${rows} \u0441\u0442\u0440\u043e\u043a`,
    });
  }
  return t(lang, {
    en: `${rangeLabel} | ${refreshText} | ${rows} rows`,
    ru: `${rangeLabel} | ${refreshText} | ${rows} \u0441\u0442\u0440\u043e\u043a`,
  });
}
