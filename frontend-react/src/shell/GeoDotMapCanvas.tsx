import { memo, useMemo, useState } from "react";
import { ComposableMap, Geographies, Geography, Marker, ZoomableGroup } from "react-simple-maps";
import worldAtlas from "world-atlas/countries-110m.json";
import { EmptyState } from "./chrome";
import { t, useShellContext } from "./context";

export type GeoDotMapPoint = Record<string, unknown> & {
  lat?: number | string;
  lon?: number | string;
  ip?: string;
  domain?: string;
};

type GeographyShape = {
  rsmKey: string;
  properties: {
    name?: string;
  };
};

export type GeoDotMapProps = {
  points: GeoDotMapPoint[];
  valueKey?: string;
  labelKey?: string;
  titleKey?: string;
  metricLabel?: string;
  onCountryClick?: (country: string) => void;
  onPointClick?: (point: GeoDotMapPoint) => void;
};

function metricValue(item: Record<string, unknown>, keys: string[] = ["count", "cnt", "events", "visits", "attempts", "value"]) {
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

function normalizeCountryName(value: string) {
  const raw = String(value || "").trim().toLowerCase();
  const aliases: Record<string, string> = {
    "russian federation": "russia",
    "russia": "russia",
    "united states": "united states of america",
    "usa": "united states of america",
    "u.s.a.": "united states of america",
    "uk": "united kingdom",
    "u.k.": "united kingdom",
    "czechia": "czech republic",
    "korea, republic of": "south korea",
  };
  return aliases[raw] || raw;
}

function mixColor(intensity: number) {
  const start = [20, 34, 54];
  const end = [92, 162, 255];
  const clamped = Math.max(0, Math.min(1, intensity));
  const parts = start.map((item, index) => Math.round(item + (end[index] - item) * clamped));
  return `rgb(${parts[0]}, ${parts[1]}, ${parts[2]})`;
}

export const GeoDotMapCanvas = memo(function GeoDotMapCanvas({
  points,
  valueKey = "events",
  labelKey = "country",
  titleKey = "ip",
  metricLabel = "events",
  onCountryClick,
  onPointClick,
}: GeoDotMapProps) {
  const { lang } = useShellContext();
  const normalizedPoints = useMemo(
    () =>
      (points || [])
        .map((item) => ({
          ...item,
          __country: String(item?.[labelKey] || t(lang, { en: "Unknown", ru: "Неизвестно" })),
          __name: String(item?.[titleKey] || item?.ip || item?.domain || t(lang, { en: "item", ru: "объект" })),
          __value: metricValue(item, [valueKey, "events", "visits", "count"]),
        }))
        .filter((item) => Number.isFinite(Number(item.lat)) && Number.isFinite(Number(item.lon))),
    [labelKey, lang, points, titleKey, valueKey],
  );
  const [activePointIndex, setActivePointIndex] = useState(0);
  const metricLabelText = lang === "ru"
    ? ({ events: "событий", visits: "визитов", attempts: "попыток", count: "сигналов", value: "единиц" }[String(metricLabel || "").toLowerCase()] || metricLabel)
    : metricLabel;

  if (!normalizedPoints.length) return <EmptyState message={t(lang, { en: "No geo points available.", ru: "Геоточки отсутствуют." })} />;

  const countries = new Map<string, { name: string; events: number; ips: number }>();
  for (const point of normalizedPoints) {
    const key = normalizeCountryName(point.__country);
    const current = countries.get(key) || { name: point.__country, events: 0, ips: 0 };
    current.events += Number(point.__value || 0);
    current.ips += 1;
    countries.set(key, current);
  }
  const maxCountryEvents = Math.max(...Array.from(countries.values()).map((item) => item.events), 1);
  const maxPointValue = Math.max(...normalizedPoints.map((row) => Number(row.__value || 0)), 1);
  const dominantPoint = normalizedPoints.reduce(
    (best, item) => (Number(item.__value || 0) > Number(best?.__value || 0) ? item : best),
    normalizedPoints[0],
  );
  const dominantCountry = Array.from(countries.values()).sort((left, right) => right.events - left.events)[0] || null;
  const currentPoint =
    onPointClick && normalizedPoints[Math.max(0, Math.min(activePointIndex, normalizedPoints.length - 1))]
      ? normalizedPoints[Math.max(0, Math.min(activePointIndex, normalizedPoints.length - 1))]
      : dominantPoint;
  const renderMarkers = Boolean(onPointClick);

  return (
    <div className="react-map-shell">
      <div className="react-map-stage">
        <ComposableMap projection="geoMercator" projectionConfig={{ scale: 125 }}>
          <ZoomableGroup center={[10, 18]} zoom={1} disablePanning disableZooming>
            <Geographies geography={worldAtlas as never}>
              {({ geographies }: { geographies: GeographyShape[] }) =>
                geographies.map((geo: GeographyShape) => {
                  const props = geo.properties as { name?: string };
                  const key = normalizeCountryName(String(props?.name || ""));
                  const country = countries.get(key);
                  const intensity = country ? country.events / maxCountryEvents : 0;
                  return (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      fill={country ? mixColor(0.18 + intensity * 0.82) : "rgba(255,255,255,0.06)"}
                      stroke="rgba(255,255,255,0.08)"
                      strokeWidth={0.5}
                      onClick={() => {
                        if (country) onCountryClick?.(country.name);
                      }}
                      style={{
                        default: { outline: "none", cursor: country && onCountryClick ? "pointer" : "default" },
                        hover: {
                          outline: "none",
                          fill: country ? mixColor(Math.min(1, intensity + 0.04)) : "rgba(255,255,255,0.08)",
                          cursor: country && onCountryClick ? "pointer" : "default",
                        },
                        pressed: { outline: "none" },
                      }}
                    />
                  );
                })
              }
            </Geographies>
            {renderMarkers
              ? normalizedPoints.map((item, index) => {
                  const radius = 4 + (Number(item.__value || 0) / maxPointValue) * 10;
                  return (
                    <Marker
                      key={`${item.__name}-${index}`}
                      coordinates={[Number(item.lon), Number(item.lat)]}
                      onClick={() => {
                        setActivePointIndex(index);
                        onPointClick?.(item);
                      }}
                    >
                      <g>
                        <circle r={radius + 6} fill="rgba(0,0,0,0)" className="react-map-point-hit" />
                        <circle r={radius} fill="rgba(92, 162, 255, 0.24)" />
                        <circle r={Math.max(3, radius - 2)} fill="#7cc3ff" className="react-map-point-clickable" />
                      </g>
                    </Marker>
                  );
                })
              : null}
          </ZoomableGroup>
        </ComposableMap>
      </div>
      <div className="react-map-meta-grid">
        <div className="react-map-meta-card">
          <span className="react-top-kicker">{t(lang, { en: "Countries", ru: "Страны" })}</span>
          <strong>{countries.size.toLocaleString()}</strong>
          <span>{dominantCountry ? dominantCountry.name : t(lang, { en: "n/a", ru: "н/д" })}</span>
        </div>
        <div className="react-map-meta-card">
          <span className="react-top-kicker">{t(lang, { en: "IPs / points", ru: "IP / точки" })}</span>
          <strong>{normalizedPoints.length.toLocaleString()}</strong>
          <span>{Number(maxPointValue || 0).toLocaleString()} {t(lang, { en: "max", ru: "макс." })} {metricLabelText}</span>
        </div>
        <div className="react-map-meta-card">
          <span className="react-top-kicker">{t(lang, { en: "Focus", ru: "Фокус" })}</span>
          <strong>{String(currentPoint?.__country || dominantCountry?.name || t(lang, { en: "Unknown", ru: "Неизвестно" }))}</strong>
          <span>{Number(currentPoint?.__value || dominantCountry?.events || 0).toLocaleString()} {metricLabelText}</span>
        </div>
      </div>
    </div>
  );
});
