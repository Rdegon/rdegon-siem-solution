import type { IncidentRecord } from "./types";

export type IncidentView = "agg" | "raw";

export function incidentRowId(row: IncidentRecord | null | undefined, view: IncidentView) {
  return String((view === "raw" ? row?.alert_id : row?.agg_id) || "");
}

export function buildIncidentDeepLink(origin: string, search: string) {
  return `${origin}/app/incidents${search || ""}`;
}
