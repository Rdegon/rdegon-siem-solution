from __future__ import annotations

import math
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "output" / "db-schemas-2026-04-07"

BG = "#f5f7fb"
GRID = "#e3e8f0"
TEXT = "#152033"
MUTED = "#5e6f86"
LINE = "#6d86a3"
PANEL = "#ffffff"
PANEL_SHADOW = "#edf2f8"
HEADER = "#0f1d32"
CH = "#2f80ed"
PG = "#27ae60"
MO = "#9b51e0"
SQ = "#f2994a"
RULE = "#eb5757"
ENRICH = "#56ccf2"
VULN = "#f2c94c"


def font(size: int, *, bold: bool = False, mono: bool = False):
    candidates: list[str] = []
    if mono:
        candidates += [
            "C:/Windows/Fonts/consola.ttf",
            "C:/Windows/Fonts/consolab.ttf" if bold else "C:/Windows/Fonts/consola.ttf",
            "DejaVuSansMono-Bold.ttf" if bold else "DejaVuSansMono.ttf",
        ]
    else:
        candidates += [
            "C:/Windows/Fonts/segoeuib.ttf" if bold else "C:/Windows/Fonts/segoeui.ttf",
            "C:/Windows/Fonts/arialbd.ttf" if bold else "C:/Windows/Fonts/arial.ttf",
            "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf",
        ]
    for path in candidates:
        try:
            return ImageFont.truetype(path, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


TITLE_FONT = font(38, bold=True)
SUBTITLE_FONT = font(18)
TABLE_TITLE_FONT = font(18, bold=True)
TABLE_META_FONT = font(13)
ROW_FONT = font(14, mono=True)
NOTE_FONT = font(13)
FOOTER_FONT = font(12)
NODE_FONT = font(16, bold=True)

GRAPH_NODE = "#2f343d"
GRAPH_NODE_BORDER = "#4a5563"
GRAPH_NODE_TEXT = "#f5f7fb"


def canvas(width: int, height: int) -> tuple[Image.Image, ImageDraw.ImageDraw]:
    image = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(image)
    for x in range(0, width, 60):
        draw.line((x, 0, x, height), fill=GRID)
    for y in range(0, height, 60):
        draw.line((0, y, width, y), fill=GRID)
    return image, draw


def header(draw: ImageDraw.ImageDraw, title: str, subtitle: str, *, width: int) -> None:
    draw.rectangle((0, 0, width, 120), fill=HEADER)
    draw.text((48, 30), title, font=TITLE_FONT, fill="#f7fbff")
    draw.text((50, 78), subtitle, font=SUBTITLE_FONT, fill="#c3d1e3")


def panel(draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], *, radius: int = 18) -> None:
    x1, y1, x2, y2 = box
    draw.rounded_rectangle((x1 + 6, y1 + 8, x2 + 6, y2 + 8), radius=radius, fill=PANEL_SHADOW)
    draw.rounded_rectangle(box, radius=radius, fill=PANEL, outline="#cfd8e3", width=2)


def section_box(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    *,
    color: str,
    title: str,
    subtitle: str = "",
    rows: list[str],
    note: str = "",
) -> None:
    panel(draw, box)
    x1, y1, x2, y2 = box
    draw.rounded_rectangle((x1, y1, x2, y1 + 54), radius=18, fill=color)
    draw.rectangle((x1, y1 + 34, x2, y1 + 54), fill=color)
    draw.text((x1 + 20, y1 + 14), title, font=TABLE_TITLE_FONT, fill="#ffffff")
    if subtitle:
        draw.text((x1 + 20, y1 + 64), subtitle, font=TABLE_META_FONT, fill=MUTED)
    cursor = y1 + (88 if subtitle else 68)
    for row in rows:
        wrapped = textwrap.wrap(row, width=max(16, int((x2 - x1 - 34) / 9)))
        for part in wrapped:
            draw.text((x1 + 18, cursor), part, font=ROW_FONT, fill=TEXT)
            cursor += 20
        cursor += 4
        if cursor < y2 - 50:
            draw.line((x1 + 16, cursor - 3, x2 - 16, cursor - 3), fill="#edf1f6")
    if note:
        draw.text((x1 + 18, y2 - 30), note, font=NOTE_FONT, fill=MUTED)


def arrow_head(
    draw: ImageDraw.ImageDraw,
    start: tuple[int, int],
    end: tuple[int, int],
    *,
    color: str = LINE,
) -> None:
    sx, sy = start
    ex, ey = end
    dx = ex - sx
    dy = ey - sy
    if abs(dx) >= abs(dy):
        if dx >= 0:
            points = [(ex, ey), (ex - 16, ey - 8), (ex - 16, ey + 8)]
        else:
            points = [(ex, ey), (ex + 16, ey - 8), (ex + 16, ey + 8)]
    else:
        if dy >= 0:
            points = [(ex, ey), (ex - 8, ey - 16), (ex + 8, ey - 16)]
        else:
            points = [(ex, ey), (ex - 8, ey + 16), (ex + 8, ey + 16)]
    draw.polygon(points, fill=color)


def arrow(
    draw: ImageDraw.ImageDraw,
    start: tuple[int, int],
    end: tuple[int, int],
    *,
    color: str = LINE,
    width: int = 4,
) -> None:
    draw.line((start[0], start[1], end[0], end[1]), fill=color, width=width)
    arrow_head(draw, start, end, color=color)


def poly_arrow(
    draw: ImageDraw.ImageDraw,
    points: list[tuple[int, int]],
    *,
    color: str = LINE,
    width: int = 4,
) -> None:
    if len(points) < 2:
        return
    for start, end in zip(points, points[1:]):
        draw.line((start[0], start[1], end[0], end[1]), fill=color, width=width)
    arrow_head(draw, points[-2], points[-1], color=color)


def bezier_point(
    p0: tuple[int, int],
    p1: tuple[int, int],
    p2: tuple[int, int],
    p3: tuple[int, int],
    t: float,
) -> tuple[float, float]:
    mt = 1.0 - t
    x = (
        mt * mt * mt * p0[0]
        + 3 * mt * mt * t * p1[0]
        + 3 * mt * t * t * p2[0]
        + t * t * t * p3[0]
    )
    y = (
        mt * mt * mt * p0[1]
        + 3 * mt * mt * t * p1[1]
        + 3 * mt * t * t * p2[1]
        + t * t * t * p3[1]
    )
    return x, y


def curve_arrow(
    draw: ImageDraw.ImageDraw,
    p0: tuple[int, int],
    p1: tuple[int, int],
    p2: tuple[int, int],
    p3: tuple[int, int],
    *,
    color: str = LINE,
    width: int = 4,
    steps: int = 40,
) -> None:
    points: list[tuple[int, int]] = []
    for idx in range(steps + 1):
        t = idx / steps
        x, y = bezier_point(p0, p1, p2, p3, t)
        points.append((int(round(x)), int(round(y))))
    draw.line(points, fill=color, width=width, joint="curve")
    arrow_head(draw, points[-2], points[-1], color=color)


def footer(draw: ImageDraw.ImageDraw, text: str, *, y: int) -> None:
    draw.text((48, y), text, font=FOOTER_FONT, fill=MUTED)


def graph_node(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    title: str,
    *,
    fill: str = GRAPH_NODE,
) -> None:
    x1, y1, x2, y2 = box
    draw.rounded_rectangle((x1 + 4, y1 + 6, x2 + 4, y2 + 6), radius=12, fill="#dbe4ef")
    draw.rounded_rectangle(box, radius=12, fill=fill, outline=GRAPH_NODE_BORDER, width=2)
    bbox = draw.textbbox((0, 0), title, font=NODE_FONT)
    tw = bbox[2] - bbox[0]
    th = bbox[3] - bbox[1]
    draw.text((x1 + (x2 - x1 - tw) / 2, y1 + (y2 - y1 - th) / 2 - 2), title, font=NODE_FONT, fill=GRAPH_NODE_TEXT)


def save(image: Image.Image, name: str) -> Path:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / name
    image.save(path)
    return path


def render_overview() -> Path:
    w, h = 2000, 1200
    image, draw = canvas(w, h)
    header(draw, "Rdegon Sentinel: Database Topology", "Live database roles and data flow across the platform", width=w)

    section_box(draw, (90, 190, 560, 420), color=CH, title="ClickHouse / siem", subtitle="Primary analytics store", rows=[
        "events / events_cold / events_shadow",
        "alerts_raw / alerts_agg / alert_history",
        "cmdb_assets / threat_intel_iocs / active_list_items",
        "vuln_* and stream_corr_runtime_status",
    ], note="Role: events, detections, enrichment, runtime analytics")

    section_box(draw, (760, 190, 1240, 380), color=PG, title="PostgreSQL / siem_control_plane", subtitle="Control-plane registry", rows=[
        "public.siem_control_plane_collections",
        "collection_name PK",
        "payload JSONB",
        "updated_ts TIMESTAMPTZ",
    ], note="Role: named operator collections and control state")

    section_box(draw, (1430, 190, 1900, 420), color=MO, title="MongoDB / siem_content", subtitle="Content-plane document store", rows=[
        "docs_pages",
        "builder_drafts",
        "dashboard_instances",
        "_content_store_meta",
    ], note="Role: docs, builders, dashboard content")

    section_box(draw, (760, 610, 1240, 900), color=SQ, title="SQLite / runtime-state.db", subtitle="Local stream-state on VM3", rows=[
        "threshold_events",
        "last_alert",
        "runtime_meta",
        "consumer_offsets",
    ], note="Role: worker memory, offsets and suppression state")

    section_box(draw, (90, 620, 560, 900), color="#4f9cf9", title="Sources and Collectors", subtitle="Ingress side", rows=[
        "Windows, Linux, VPN, Proxmox, OpenClaw",
        "Application logs, scanners, host runtime",
        "Normalized flow enters ClickHouse",
    ], note="Role: telemetry ingress")

    section_box(draw, (1430, 610, 1900, 900), color="#3dbb87", title="Web / API", subtitle="Serving layer on VM4", rows=[
        "Reads analytics from ClickHouse",
        "Reads and writes control state in PostgreSQL",
        "Reads and writes content state in MongoDB",
    ], note="Role: operator UI and API")

    curve_arrow(draw, (560, 285), (635, 245), (685, 245), (760, 250))
    curve_arrow(draw, (1240, 250), (1315, 245), (1360, 245), (1430, 280))
    curve_arrow(draw, (325, 620), (285, 560), (285, 485), (325, 420))
    curve_arrow(draw, (1000, 610), (940, 555), (940, 435), (1000, 380))
    curve_arrow(draw, (1240, 760), (1300, 735), (1370, 735), (1430, 760))
    curve_arrow(draw, (560, 345), (780, 500), (1510, 410), (1670, 610), color="#8da6c2", width=3)

    footer(draw, "Operational meaning: ClickHouse stores signal; Postgres stores control decisions; Mongo stores content; SQLite stores local stream-correlation runtime state.", y=1138)
    return save(image, "overview-data-stores.png")


def render_clickhouse() -> Path:
    w, h = 2400, 1600
    image, draw = canvas(w, h)
    header(draw, "ClickHouse / siem", "Detailed logical schema grouped by operational domain", width=w)

    section_box(draw, (60, 170, 720, 580), color=CH, title="Event Storage", subtitle="3 physical tables", rows=[
        "events                MergeTree / PARTITION BY toDate(ts)",
        "  ts, event_id, category, subcategory, src_ip, dst_ip, log_source, severity, message ...",
        "  TTL: ts + 30d",
        "events_cold           MergeTree / ORDER BY (ts, log_source, event_id)",
        "  cold archive copy of normalized events",
        "events_shadow         MergeTree / PARTITION BY toDate(ts)",
        "  shadow transport validation, schema mirrors events",
        "  TTL: ts + 30d",
    ], note="Hot path lands in events. App-level retention migrates older rows to events_cold.")

    section_box(draw, (60, 650, 720, 1060), color=RULE, title="Alerting", subtitle="Incident and workflow layer", rows=[
        "alerts_raw            MergeTree / PARTITION BY toDate(ts)",
        "  alert_id, rule_id, rule_name, severity, entity_key, context_json, status, assignee",
        "alerts_agg            ReplacingMergeTree / PARTITION BY toDate(ts)",
        "  agg_id, rule_id, rule_name, ts_first, ts_last, count_alerts, status, assignee",
        "alert_history         MergeTree",
        "  changed_ts, view, record_id, previous_status, next_status, previous_assignee, next_assignee",
    ], note="alerts_raw -> alerts_agg -> alert_history describes the full incident lifecycle.")

    section_box(draw, (840, 170, 1530, 690), color="#bb6bd9", title="Rules and Detection Catalog", subtitle="Normalization and detection control", rows=[
        "normalizer_rules      priority, source_type, event_matcher, uem_mapping, enabled",
        "filter_rules          priority, expr, action, tags, enabled",
        "correlation_rules_stream",
        "  pattern, window_s, threshold, expr, entity_field",
        "correlation_rules_batch",
        "  sql_template, severity, window_s",
        "detection_rule_catalog",
        "  title, sigma_id, source_format, expr, verification_query, enabled",
    ], note="This group defines how raw telemetry becomes normalized events and detections.")

    section_box(draw, (840, 790, 1530, 1230), color=ENRICH, title="Enrichment and Context", subtitle="Operator context tables", rows=[
        "cmdb_assets           asset_id, hostname, ip, owner, criticality, environment, business_service",
        "threat_intel_iocs     indicator_type, indicator, provider, severity, confidence, expires_ts",
        "active_list_items     list_name, value, value_type, label, tags, enabled",
    ], note="These tables enrich or re-score events and alerts at read time or correlation time.")

    section_box(draw, (1650, 170, 2320, 480), color="#5fa8ff", title="Correlation Runtime Telemetry", subtitle="Worker self-observability", rows=[
        "stream_corr_runtime_status",
        "  observed_ts, instance_name, mode, watermark_lag_sec, late_events_total,",
        "  shadow_compare_mismatches_total, last_batch_events, last_batch_alerts, state_backend",
    ], note="This table measures the health of the stream correlation engine itself.")

    section_box(draw, (1650, 620, 2320, 1120), color=VULN, title="Vulnerability Domain", subtitle="Scanner ingestion and normalized findings", rows=[
        "vuln_asset_bindings   asset_id, scanner_family, profile, target_id, task_id, sync_status",
        "vuln_scan_runs        scan_run_id, task_id, target_id, started_at, finished_at, finding_count",
        "vuln_findings         finding_id, scan_run_id, asset_id, cve, cvss_score, severity_normalized, status",
    ], note="This is the separate vulnerability model that feeds the vuln UI and reporting.")

    curve_arrow(draw, (720, 360), (770, 330), (800, 330), (840, 360))
    curve_arrow(draw, (390, 580), (355, 610), (355, 625), (390, 650))
    curve_arrow(draw, (720, 860), (770, 900), (790, 980), (840, 1010))
    curve_arrow(draw, (1185, 690), (1140, 730), (1140, 755), (1185, 790))
    curve_arrow(draw, (1530, 320), (1580, 290), (1600, 290), (1650, 320))
    curve_arrow(draw, (1530, 1010), (1590, 980), (1610, 900), (1650, 870))

    footer(draw, "This is a logical schema view. ClickHouse does not enforce relational foreign keys here; links represent operational flow and semantic dependencies.", y=1540)
    return save(image, "clickhouse-logical-schema.png")


def render_clickhouse_table_relations() -> Path:
    w, h = 2500, 1300
    bg = "#111418"
    image = Image.new("RGB", (w, h), bg)
    draw = ImageDraw.Draw(image)
    draw.text((54, 36), "1. ClickHouse", font=TITLE_FONT, fill="#f4f7fb")
    draw.text((54, 88), "Суть: это основная аналитическая БД SIEM. Здесь лежат события, алерты, правила, TI и vuln-данные.", font=SUBTITLE_FONT, fill="#d0d7e2")

    def dark_node(box: tuple[int, int, int, int], title: str, *, fill: str = "#2d323b") -> None:
        x1, y1, x2, y2 = box
        draw.rounded_rectangle(box, radius=10, fill=fill, outline="#3f4651", width=2)
        bbox = draw.textbbox((0, 0), title, font=NODE_FONT)
        tw = bbox[2] - bbox[0]
        th = bbox[3] - bbox[1]
        draw.text((x1 + (x2 - x1 - tw) / 2, y1 + (y2 - y1 - th) / 2 - 1), title, font=NODE_FONT, fill="#f6f8fb")

    boxes = {
        "active_list_items": (480, 180, 760, 260),
        "threat_intel_iocs": (840, 180, 1120, 260),
        "cmdb_assets": (1200, 180, 1480, 260),
        "filter_rules": (1560, 180, 1840, 260),
        "normalizer_rules": (1920, 180, 2240, 260),
        "detection_rule_catalog": (70, 430, 410, 510),
        "correlation_rules_batch": (470, 430, 810, 510),
        "correlation_rules_stream": (890, 430, 1250, 510),
        "events": (1325, 430, 1495, 510),
        "vuln_asset_bindings": (2010, 180, 2330, 260),
        "alerts_raw": (500, 680, 760, 760),
        "events_cold": (1345, 680, 1595, 760),
        "events_shadow": (1810, 680, 2090, 760),
        "vuln_scan_runs": (2045, 430, 2305, 510),
        "alerts_agg": (500, 920, 760, 1000),
        "vuln_findings": (2050, 680, 2300, 760),
        "alert_history": (500, 1140, 760, 1220),
        "stream_corr_runtime_status": (1180, 920, 1640, 1000),
    }

    primary = "#d7dde7"
    secondary = "#9aa8bb"
    runtime = "#7d95b6"

    def link(p0, p1, p2, p3, *, color=primary, width=2):
        curve_arrow(draw, p0, p1, p2, p3, color=color, width=width)

    # Main semantic links, drawn first behind nodes.
    link((760, 220), (900, 275), (1210, 350), (1325, 470), color=secondary)
    link((1120, 220), (1210, 280), (1290, 355), (1325, 470), color=secondary)
    link((1340, 260), (1360, 320), (1390, 375), (1410, 430), color=secondary)
    link((1700, 260), (1710, 325), (1530, 375), (1495, 470), color=secondary)
    link((2080, 260), (2090, 330), (1560, 360), (1495, 455), color=secondary)
    link((1250, 470), (1270, 470), (1290, 470), (1325, 470), color=primary, width=3)

    link((410, 470), (440, 560), (470, 640), (500, 720), color=secondary)
    link((640, 510), (640, 590), (620, 635), (620, 680), color=secondary)
    link((1080, 510), (1080, 590), (800, 635), (760, 720), color=secondary)
    link((1325, 490), (1180, 565), (910, 635), (760, 720), color=secondary)

    link((630, 760), (630, 830), (630, 875), (630, 920), color=primary)
    link((630, 1000), (630, 1060), (630, 1095), (630, 1140), color=primary)

    link((1410, 510), (1410, 575), (1460, 630), (1470, 680), color=secondary)
    link((1495, 470), (1665, 520), (1785, 615), (1950, 680), color=secondary)

    link((2170, 260), (2170, 325), (2170, 370), (2170, 430), color=primary)
    link((2170, 510), (2170, 575), (2170, 620), (2170, 680), color=primary)

    link((1495, 470), (1610, 430), (1810, 350), (2045, 470), color=secondary)
    link((1410, 510), (1410, 635), (1410, 790), (1410, 920), color=runtime)

    for name, box in boxes.items():
        fill = "#2d323b"
        if name == "events":
            fill = "#383d46"
        elif name.startswith("alerts") or name == "alert_history":
            fill = "#4a3434"
        elif name.startswith("vuln_"):
            fill = "#6b5921"
        elif name == "stream_corr_runtime_status":
            fill = "#314357"
        dark_node(box, name, fill=fill)

    footer(draw, "Подробная схема на уровне таблиц ClickHouse: основная обработка событий, поток детектов, cold/shadow storage и vuln-контур.", y=1260)
    return save(image, "clickhouse-table-relations.png")


def render_postgres() -> Path:
    w, h = 1600, 980
    image, draw = canvas(w, h)
    header(draw, "PostgreSQL / siem_control_plane", "Exact relational schema used for control-plane persistence", width=w)
    section_box(draw, (120, 180, 1480, 720), color=PG, title="public.siem_control_plane_collections", subtitle="Single canonical registry table", rows=[
        "PK  collection_name   TEXT",
        "    payload           JSONB NOT NULL",
        "    updated_ts        TIMESTAMPTZ NOT NULL DEFAULT now()",
        "",
        "Design meaning:",
        "  one row = one named control-plane collection",
        "  payload stores the collection body as JSONB",
        "  updated_ts tracks the last write",
    ], note="This is intentionally simple: Postgres behaves as the durable control-plane document registry.")
    footer(draw, "Live schema export matches the current database: one table, one primary key, JSONB payload.", y=930)
    return save(image, "postgres-control-plane-schema.png")


def render_mongo() -> Path:
    w, h = 1800, 1100
    image, draw = canvas(w, h)
    header(draw, "MongoDB / siem_content", "Document collections and their live meaning", width=w)
    section_box(draw, (90, 190, 790, 430), color=MO, title="docs_pages", subtitle="Collection / default _id index", rows=[
        "_id               ObjectId",
        "page content documents for /app/docs",
        "schemaless payload, rendered at application level",
    ], note="Purpose: documentation content.")
    section_box(draw, (1010, 190, 1710, 430), color=CH, title="builder_drafts", subtitle="Collection / default _id index", rows=[
        "_id               ObjectId",
        "draft objects for Builders workspace",
        "schemaless payload, interpreted by the application",
    ], note="Purpose: saved authoring drafts.")
    section_box(draw, (90, 560, 790, 800), color=PG, title="dashboard_instances", subtitle="Collection / default _id index", rows=[
        "_id               ObjectId",
        "dashboard definitions and saved instances",
        "schemaless payload, interpreted by dashboard runtime",
    ], note="Purpose: dashboard content state.")
    section_box(draw, (1010, 560, 1710, 800), color=SQ, title="_content_store_meta", subtitle="Collection / default _id index", rows=[
        "_id               ObjectId",
        "internal content-store metadata",
        "service-owned housekeeping collection",
    ], note="Purpose: service metadata.")
    footer(draw, "Mongo is schema-flexible in this system. The live database currently uses only the default _id index on every collection.", y=1044)
    return save(image, "mongo-content-plane-schema.png")


def render_sqlite() -> Path:
    w, h = 2000, 1280
    image, draw = canvas(w, h)
    header(draw, "SQLite / runtime-state.db", "Exact local stream correlation state schema on VM3", width=w)
    section_box(draw, (70, 180, 900, 500), color=SQ, title="threshold_events", subtitle="Window memory for threshold logic", rows=[
        "PK  rule_id          INTEGER",
        "PK  entity_key       TEXT",
        "PK  mode             TEXT",
        "PK  message_id       TEXT",
        "    event_epoch      REAL",
        "IDX idx_threshold_events_lookup(rule_id, entity_key, mode, event_epoch)",
    ], note="Stores recent event hits for windowed correlation.")
    section_box(draw, (1090, 180, 1870, 440), color=RULE, title="last_alert", subtitle="Suppression memory", rows=[
        "PK  rule_id          INTEGER",
        "PK  entity_key       TEXT",
        "PK  mode             TEXT",
        "    last_alert_epoch REAL",
    ], note="Prevents duplicate alert emission bursts.")
    section_box(draw, (1090, 560, 1870, 820), color=PG, title="runtime_meta", subtitle="Generic worker metadata", rows=[
        "PK  key              TEXT",
        "    value            TEXT",
    ], note="Stores runtime metadata blobs.")
    section_box(draw, (520, 700, 1440, 1080), color=CH, title="consumer_offsets", subtitle="Transport consumption offsets", rows=[
        "PK  transport_backend TEXT",
        "PK  group_name        TEXT",
        "PK  topic_name        TEXT",
        "PK  partition_id      INTEGER",
        "    offset_value      INTEGER",
        "    updated_ts        TEXT",
    ], note="Tracks where the stream worker has consumed to.")
    curve_arrow(draw, (900, 300), (980, 260), (1020, 260), (1090, 300))
    curve_arrow(draw, (500, 500), (540, 590), (900, 560), (980, 700))
    curve_arrow(draw, (1480, 560), (1440, 520), (1440, 470), (1480, 440))
    footer(draw, "SQLite is a local durability layer for the stream worker. It is not part of the operator-facing hot/cold event storage path.", y=1225)
    return save(image, "sqlite-stream-state-schema.png")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rendered = [
        render_overview(),
        render_clickhouse(),
        render_clickhouse_table_relations(),
        render_postgres(),
        render_mongo(),
        render_sqlite(),
    ]
    for path in rendered:
        print(path)


if __name__ == "__main__":
    main()
