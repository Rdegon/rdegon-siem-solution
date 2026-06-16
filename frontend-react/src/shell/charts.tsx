import { Suspense, lazy, memo, useMemo, useState } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { EmptyState, ReactErrorBoundary } from "./chrome";
import { t, useShellContext } from "./context";
import type { GeoDotMapProps } from "./GeoDotMapCanvas";

const CHART_COLORS = ["#5ca2ff", "#22d3a6", "#ffbf66", "#ff7d95", "#b08cff", "#71d7ff"];

type ChartDatum = Record<string, unknown> & {
  __label: string;
  __value: number;
};

function metricValue(
  item: Record<string, unknown> | null | undefined,
  keys: string[] = ["count", "cnt", "events", "visits", "attempts", "value"],
) {
  for (const key of keys) {
    const raw = item?.[key];
    if (raw === 0 || raw === "0") return 0;
    if (raw !== undefined && raw !== null && raw !== "") {
      const numeric = Number(raw);
      if (Number.isFinite(numeric)) return numeric;
    }
  }
  return 0;
}

function textList(value: unknown, limit = 4) {
  return Array.isArray(value)
    ? value
        .map((item) => String(item || "").trim())
        .filter(Boolean)
        .slice(0, limit)
    : [];
}

function localizeBreakdownLabel(value: unknown, lang: "en" | "ru") {
  const text = String(value || "").trim();
  if (!text || lang !== "ru") return text || "unknown";
  const normalized = text.toLowerCase();
  const map: Record<string, string> = {
    info: "инфо",
    low: "низкая",
    medium: "средняя",
    high: "высокая",
    critical: "критическая",
    open: "открыто",
    closed: "закрыто",
    resolved: "устранено",
    acknowledged: "подтверждено",
    active: "активно",
    inactive: "неактивно",
    enabled: "включено",
    disabled: "отключено",
    unknown: "неизвестно",
  };
  return map[normalized] || text;
}

const LazyGeoDotMapCanvas = lazy(async () => {
  const module = await import("./GeoDotMapCanvas");
  return { default: module.GeoDotMapCanvas };
});

export function SparklineChart({
  items,
  labelKey = "bucket",
  valueKey = "count",
  height = 260,
  onSelect,
}: {
  items: Array<Record<string, unknown>>;
  labelKey?: string;
  valueKey?: string;
  height?: number;
  onSelect?: (item: Record<string, unknown>) => void;
}) {
  const { formatTimestamp, lang } = useShellContext();
  const normalized = useMemo<ChartDatum[]>(
    () =>
      (items || []).map((item) => ({
        ...item,
        __label: String(item?.[labelKey] || ""),
        __value: metricValue(item, [valueKey, "cnt", "count", "events"]),
      })),
    [items, labelKey, valueKey],
  );
  const [activeIndex, setActiveIndex] = useState(Math.max(0, normalized.length - 1));

  if (!normalized.length) return <EmptyState message={t(lang, { en: "No timeline data available.", ru: "Данные таймлайна отсутствуют." })} />;
  const current = normalized[Math.max(0, Math.min(activeIndex, normalized.length - 1))] || normalized[normalized.length - 1];
  const compactFormatter = normalized.length > 36 ? "compact" : "time";
  const currentRangeLabel =
    current?.bucket_end && String(current.bucket_end || "") !== String(current.__label || "")
      ? `${formatTimestamp(current.__label, "compact")} -> ${formatTimestamp(current.bucket_end, "compact")}`
      : formatTimestamp(current?.__label, "compact");

  return (
    <div className={`react-chart-shell ${onSelect ? "interactive" : ""}`}>
      <div className="react-chart-frame" style={{ height }}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart
            data={normalized}
            margin={{ top: 16, right: 12, left: 8, bottom: 8 }}
            onMouseMove={(state) => {
              if (typeof state?.activeTooltipIndex === "number") {
                setActiveIndex(state.activeTooltipIndex);
              }
            }}
            onClick={(state) => {
              const point = (state?.activePayload?.[0]?.payload || null) as Record<string, unknown> | null;
              if (point && onSelect) {
                onSelect(point);
              }
            }}
          >
            <defs>
              <linearGradient id="spark-area" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#5ca2ff" stopOpacity={0.38} />
                <stop offset="100%" stopColor="#5ca2ff" stopOpacity={0.04} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="rgba(255,255,255,0.08)" vertical={false} strokeDasharray="5 7" />
            <XAxis
              dataKey="__label"
              tickLine={false}
              axisLine={false}
              minTickGap={18}
              tickFormatter={(value) => formatTimestamp(value, compactFormatter)}
              tick={{ fill: "#90a6c1", fontSize: 12 }}
            />
            <YAxis hide />
            <Tooltip
              cursor={{ stroke: "rgba(158, 208, 255, 0.35)", strokeWidth: 1, strokeDasharray: "5 6" }}
              content={({ active, payload, label }) => {
                if (!active || !payload?.length) return null;
                const point = payload[0]?.payload;
                return (
                  <div className="react-chart-tooltip">
                    <div className="react-chart-tooltip-label">
                      {point?.bucket_end && String(point.bucket_end || "") !== String(label || "")
                        ? `${formatTimestamp(label, "full")} -> ${formatTimestamp(point.bucket_end, "full")}`
                        : formatTimestamp(label, "full")}
                    </div>
                    <div className="react-chart-tooltip-value">{Number(point?.__value || 0).toLocaleString()}</div>
                  </div>
                );
              }}
            />
            <Area
              type="monotone"
              dataKey="__value"
              stroke="#5ca2ff"
              strokeWidth={3}
              fill="url(#spark-area)"
              activeDot={{ r: 6, fill: "#eef5ff", stroke: "#5ca2ff", strokeWidth: 2 }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <div className={`react-chart-summary ${onSelect ? "interactive" : ""}`} onClick={() => current && onSelect?.(current)}>
        <strong>{Number(current?.__value || 0).toLocaleString()}</strong>
        <span>{currentRangeLabel}</span>
      </div>
    </div>
  );
}

export function BreakdownBars({
  items,
  valueKey = "count",
  labelKey = "label",
}: {
  items: Array<Record<string, unknown>>;
  valueKey?: string;
  labelKey?: string;
}) {
  const { lang } = useShellContext();
  const values = (items || []).map((item) => metricValue(item, [valueKey, "cnt", "count", "events", "visits", "attempts"]));
  const maxValue = Math.max(...values, 1);
  if (!items?.length) return <EmptyState message={t(lang, { en: "No breakdown available.", ru: "Нет доступной разбивки." })} />;
  return (
    <div className="react-breakdown">
      {items.map((item, index) => {
        const value = values[index];
        const width = `${Math.max(6, Math.round((value / maxValue) * 100))}%`;
        const label = localizeBreakdownLabel(item[labelKey] || item.label || item.severity || item.status || "unknown", lang);
        return (
          <div key={`${item[labelKey]}-${index}`} className="react-breakdown-row">
            <div className="react-breakdown-meta">
              <span>{label}</span>
              <strong>{value.toLocaleString()}</strong>
            </div>
            <div className="react-breakdown-track">
              <div className="react-breakdown-fill" style={{ width }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

export function DonutChart({
  items,
  valueKey = "count",
  labelKey = "label",
}: {
  items: Array<Record<string, unknown>>;
  valueKey?: string;
  labelKey?: string;
}) {
  const { lang } = useShellContext();
  const normalized = useMemo<ChartDatum[]>(
    () =>
      (items || []).map((item) => ({
        ...item,
        __value: metricValue(item, [valueKey, "cnt", "count", "events", "visits", "attempts"]),
        __label: localizeBreakdownLabel(item[labelKey] || item.label || item.severity || item.status || "unknown", lang),
      })),
    [items, labelKey, lang, valueKey],
  );

  const largestIndex = normalized.reduce((best, item, index, array) => {
    return Number(item.__value || 0) > Number(array[best]?.__value || 0) ? index : best;
  }, 0);
  const [hoverIndex, setHoverIndex] = useState<number | null>(null);

  if (!normalized.length) return <EmptyState message={t(lang, { en: "No chart data available.", ru: "Нет данных для диаграммы." })} />;
  const activeIndex = hoverIndex ?? largestIndex;
  const active = normalized[Math.max(0, Math.min(activeIndex, normalized.length - 1))];
  const total = Math.max(normalized.reduce((sum, item) => sum + Number(item.__value || 0), 0), 1);
  const activeShare = Math.max(0, Math.min(100, Math.round((Number(active?.__value || 0) / total) * 1000) / 10));
  const topSources = textList(active?.top_sources);
  const topEvents = textList(active?.top_events);

  return (
    <div className="react-donut-shell">
      <div className="react-donut-stage">
        <div className="react-donut-flyout">
          <div className="react-donut-flyout-label">{String(active?.__label || "unknown")}</div>
          <div className="react-donut-flyout-value">
            {Number(active?.__value || 0).toLocaleString()} / {activeShare.toLocaleString()}%
          </div>
          <div className="react-donut-flyout-subtle">{total.toLocaleString()} total</div>
          {topSources.length ? (
            <div className="react-chart-tooltip-section">
              <strong>{t(lang, { en: "Top sources", ru: "\u0422\u043e\u043f \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u043e\u0432" })}</strong>
              <div className="react-chart-tooltip-list">{topSources.join(", ")}</div>
            </div>
          ) : null}
          {topEvents.length ? (
            <div className="react-chart-tooltip-section">
              <strong>{t(lang, { en: "Top events", ru: "\u0422\u043e\u043f \u0441\u043e\u0431\u044b\u0442\u0438\u0439" })}</strong>
              <div className="react-chart-tooltip-list">{topEvents.join(", ")}</div>
            </div>
          ) : null}
        </div>
        <div className="react-donut-visual">
          <ResponsiveContainer width="100%" height={236}>
            <PieChart>
              <Tooltip
                wrapperStyle={{ display: "none" }}
                content={({ active, payload }) => {
                  if (!active || !payload?.length) return null;
                  const point = payload[0]?.payload || {};
                  const pointSources = textList(point?.top_sources);
                  const pointEvents = textList(point?.top_events);
                  return (
                    <div className="react-chart-tooltip react-chart-tooltip-wide">
                      <div className="react-chart-tooltip-label">{String(point?.__label || "unknown")}</div>
                      <div className="react-chart-tooltip-value">
                        {Number(point?.__value || 0).toLocaleString()} /{" "}
                        {Math.max(0, Math.min(100, Math.round((Number(point?.__value || 0) / total) * 1000) / 10)).toLocaleString()}%
                      </div>
                      {pointSources.length ? (
                        <div className="react-chart-tooltip-section">
                          <strong>{t(lang, { en: "Top sources", ru: "\u0422\u043e\u043f \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u043e\u0432" })}</strong>
                          <div className="react-chart-tooltip-list">{pointSources.join(", ")}</div>
                        </div>
                      ) : null}
                      {pointEvents.length ? (
                        <div className="react-chart-tooltip-section">
                          <strong>{t(lang, { en: "Top events", ru: "\u0422\u043e\u043f \u0441\u043e\u0431\u044b\u0442\u0438\u0439" })}</strong>
                          <div className="react-chart-tooltip-list">{pointEvents.join(", ")}</div>
                        </div>
                      ) : null}
                    </div>
                  );
                }}
              />
              <Pie
                data={normalized}
                dataKey="__value"
                nameKey="__label"
                innerRadius={58}
                outerRadius={86}
                paddingAngle={3}
                cornerRadius={12}
                stroke="rgba(7, 15, 27, 0.92)"
                strokeWidth={2}
                onMouseEnter={(_, index) => setHoverIndex(typeof index === "number" ? index : null)}
                onMouseLeave={() => setHoverIndex(null)}
                onClick={(_, index) => setHoverIndex(typeof index === "number" ? index : null)}
              >
                {normalized.map((item, index) => (
                  <Cell key={`${item.__label}-${index}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          <div className="react-donut-center">
            <div className="react-donut-center-value">{Number(active?.__value || 0).toLocaleString()}</div>
            <div className="react-donut-center-label">{String(active?.__label || "unknown")}</div>
            <div className="react-donut-center-subtle">{total.toLocaleString()} total</div>
          </div>
        </div>
      </div>
      <div className="react-donut-active">
        <strong>{String(active?.__label || "unknown")}</strong>
        <span>
          {Number(active?.__value || 0).toLocaleString()} / {activeShare.toLocaleString()}%
        </span>
      </div>
      <div className="react-donut-legend">
        {normalized.map((item, index) => (
          <button
            type="button"
            className={`react-donut-legend-row ${index === activeIndex ? "active" : ""}`}
            key={`${item.__label}-${index}`}
            onMouseEnter={() => setHoverIndex(index)}
            onMouseLeave={() => setHoverIndex(null)}
            onClick={() => setHoverIndex(index)}
          >
            <span className="react-donut-swatch" style={{ backgroundColor: CHART_COLORS[index % CHART_COLORS.length] }} />
            <span>{String(item.__label || "unknown")}</span>
            <strong>{Number(item.__value || 0).toLocaleString()}</strong>
          </button>
        ))}
      </div>
    </div>
  );
}

export const GeoDotMap = memo(function GeoDotMap(props: GeoDotMapProps) {
  const { lang } = useShellContext();
  return (
    <ReactErrorBoundary title="Map widget failed to render">
      <Suspense fallback={<EmptyState message={t(lang, { en: "Loading geo map...", ru: "Загрузка геокарты..." })} />}>
        <LazyGeoDotMapCanvas {...props} />
      </Suspense>
    </ReactErrorBoundary>
  );
});
