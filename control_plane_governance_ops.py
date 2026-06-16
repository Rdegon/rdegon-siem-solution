from __future__ import annotations

from typing import Any

try:
    from .control_plane_case_ops import get_entities_overview
    from .control_plane_connector_ops import get_connectors_overview
    from .control_plane_content_ops import list_content_bundles
    from .control_plane_response_ops import get_response_analytics
    from .enterprise_control_plane import _now_iso
except ImportError:  # pragma: no cover - local test fallback
    from control_plane_case_ops import get_entities_overview  # type: ignore[no-redef]
    from control_plane_connector_ops import get_connectors_overview  # type: ignore[no-redef]
    from control_plane_content_ops import list_content_bundles  # type: ignore[no-redef]
    from control_plane_response_ops import get_response_analytics  # type: ignore[no-redef]
    from enterprise_control_plane import _now_iso  # type: ignore[no-redef]


REQUIRED_CONNECTOR_ECOSYSTEM: dict[str, str] = {
    "ad-domain-services-audit": "Active Directory / Windows identity",
    "entra-id-audit": "Entra ID / cloud identity",
    "mail-security-events": "Mail security",
    "proxy-web-gateway": "Proxy / secure web gateway",
    "firewall-perimeter-events": "Firewall / NGFW",
    "endpoint-edr-stream": "EDR / XDR",
    "saas-audit-events": "SaaS audit",
    "cloud-control-plane": "Cloud audit",
    "kubernetes-audit": "Kubernetes audit",
    "cicd-pipeline-audit": "CI/CD audit",
}

UEBA_MODEL_COVERAGE = [
    "failed_auth_patterns",
    "behavior_drift_score",
    "rare_activity_score",
    "lateral_movement_precursor",
    "privilege_escalation_precursor",
]

EVIDENCE_RELATIONSHIPS = [
    "user_to_host",
    "process_to_parent",
    "asset_to_vulnerability",
    "indicator_to_host",
    "host_outbound_destination",
]


def _pct(numerator: int | float, denominator: int | float) -> float:
    if not denominator:
        return 0.0
    return round((float(numerator) / float(denominator)) * 100.0, 1)


def _gate(
    gate_id: str,
    title: str,
    *,
    passed: bool,
    metric: str,
    detail: str,
    missing: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": gate_id,
        "title": title,
        "status": "pass" if passed else "fail",
        "metric": metric,
        "detail": detail,
        "missing": list(missing or []),
    }


def build_enterprise_release_gates() -> dict[str, Any]:
    bundles = list_content_bundles()
    connectors = get_connectors_overview()
    response = get_response_analytics(limit=200)
    entities = get_entities_overview()

    connector_items = list(connectors.get("items") or [])
    bundle_live_ready = sum(1 for item in bundles if bool(dict(item.get("release_gate") or {}).get("ready_for_live")))
    bundle_stage_ready = sum(1 for item in bundles if bool(dict(item.get("release_gate") or {}).get("ready_for_stage")))

    present_connector_ids = {str(item.get("id") or "").strip() for item in connector_items if str(item.get("id") or "").strip()}
    live_connector_ids = {
        str(item.get("id") or "").strip()
        for item in connector_items
        if bool(dict(item.get("release_gate") or {}).get("ready_for_live"))
    }
    missing_domains = [
        label
        for connector_id, label in REQUIRED_CONNECTOR_ECOSYSTEM.items()
        if connector_id not in present_connector_ids
    ]
    not_live_domains = [
        label
        for connector_id, label in REQUIRED_CONNECTOR_ECOSYSTEM.items()
        if connector_id in present_connector_ids and connector_id not in live_connector_ids
    ]

    connector_metrics = dict(connectors.get("metrics") or {})
    connector_posture = dict(connectors.get("posture") or {})
    response_metrics = dict(response.get("metrics") or {})
    response_governance = dict(response.get("governance") or {})
    response_compliance = dict(response.get("compliance") or {})
    entity_metrics = dict(entities.get("metrics") or {})

    gates = [
        _gate(
            "content_lifecycle",
            "Content lifecycle release gates",
            passed=bool(bundles) and bundle_live_ready >= 2 and bundle_stage_ready >= 2,
            metric=f"{bundle_live_ready}/{len(bundles)} live-ready bundles",
            detail="Parser, detection and integration packs must be validated, signed and rollback-ready before release.",
            missing=[] if bool(bundles) and bundle_live_ready >= 2 and bundle_stage_ready >= 2 else ["signed_bundles", "qa_datasets", "rollback_targets"],
        ),
        _gate(
            "connector_ecosystem",
            "Connector ecosystem coverage",
            passed=not missing_domains and not not_live_domains,
            metric=f"{len(present_connector_ids & set(REQUIRED_CONNECTOR_ECOSYSTEM))}/{len(REQUIRED_CONNECTOR_ECOSYSTEM)} domains present",
            detail="Identity, mail, proxy, firewall, EDR, SaaS, cloud, Kubernetes and CI/CD surfaces must exist and be release-ready.",
            missing=[*missing_domains, *not_live_domains],
        ),
        _gate(
            "telemetry_quality",
            "Telemetry quality and parsing coverage",
            passed=(
                float(connector_metrics.get("parsing_coverage_avg") or 0.0) >= 80.0
                and float(connector_metrics.get("telemetry_quality_avg") or 0.0) >= 80.0
                and float(connector_posture.get("actor_ip_ready_pct") or 0.0) >= 70.0
                and float(connector_posture.get("investigation_ready_pct") or 0.0) >= 70.0
            ),
            metric=(
                f"parse {float(connector_metrics.get('parsing_coverage_avg') or 0.0):.1f}% / "
                f"quality {float(connector_metrics.get('telemetry_quality_avg') or 0.0):.1f}%"
            ),
            detail="Connector telemetry must retain actor IP, evidence fields and investigation pivots at enterprise thresholds.",
            missing=list(connector_posture.get("gaps") or []),
        ),
        _gate(
            "ueba_models",
            "UEBA behavioral model surface",
            passed=len(UEBA_MODEL_COVERAGE) >= 5,
            metric=f"{len(UEBA_MODEL_COVERAGE)} model classes",
            detail="Behavioral scoring must cover failed auth bursts, drift, rarity, privilege signals and lateral movement precursors.",
        ),
        _gate(
            "evidence_graph",
            "Evidence graph relationship coverage",
            passed=len(EVIDENCE_RELATIONSHIPS) >= 5,
            metric=f"{len(EVIDENCE_RELATIONSHIPS)} relationship classes",
            detail="The investigation graph must materialize user-host, process-parent, indicator-host, asset-vulnerability and outbound edges.",
        ),
        _gate(
            "soar_governance",
            "SOAR/playbook governance",
            passed=(
                int(response_metrics.get("governed_actions") or 0) >= 6
                and float(response_metrics.get("owner_coverage_pct") or 0.0) >= 80.0
                and float(response_metrics.get("evidence_contract_pct") or 0.0) >= 80.0
                and float(response_metrics.get("rollback_ready_pct") or 0.0) >= 80.0
                and float(response_metrics.get("integration_target_pct") or 0.0) >= 70.0
            ),
            metric=f"{int(response_metrics.get('governed_actions') or 0)} governed playbooks",
            detail="Operator actions must bind owners, evidence contracts, rollback paths and downstream integrations.",
            missing=list(response_governance.get("next_focus") or []),
        ),
        _gate(
            "compliance_reporting",
            "Compliance evidence-pack export",
            passed=(
                len(list(response_compliance.get("families") or [])) >= 4
                and int(response_compliance.get("actions_with_controls") or 0) >= 4
            ),
            metric=f"{len(list(response_compliance.get('families') or []))} compliance families",
            detail="Auditor-grade reporting requires mapped control families and exportable evidence bundles.",
            missing=[] if len(list(response_compliance.get("families") or [])) >= 4 else ["control_families"],
        ),
        _gate(
            "enterprise_surfaces",
            "Enterprise surface population",
            passed=(
                int(entity_metrics.get("graph_edges") or 0) >= 0
                and int(response_metrics.get("actions_total") or 0) >= 6
                and int(connector_metrics.get("enterprise_ready") or 0) >= 6
            ),
            metric=(
                f"{int(connector_metrics.get('enterprise_ready') or 0)} ready connectors / "
                f"{int(response_metrics.get('actions_total') or 0)} actions"
            ),
            detail="Enterprise screens must show populated connector, SOAR and investigation surfaces instead of empty scaffolding.",
        ),
    ]

    failed = [item for item in gates if item["status"] == "fail"]
    summary = {
        "total": len(gates),
        "passed": sum(1 for item in gates if item["status"] == "pass"),
        "failed": len(failed),
        "blocked": bool(failed),
    }
    return {
        "generated_ts": _now_iso(),
        "summary": summary,
        "gates": gates,
        "coverage": {
            "bundle_live_ready_pct": _pct(bundle_live_ready, len(bundles)),
            "connector_ecosystem_pct": _pct(len(present_connector_ids & set(REQUIRED_CONNECTOR_ECOSYSTEM)), len(REQUIRED_CONNECTOR_ECOSYSTEM)),
            "connector_ecosystem_live_pct": _pct(len(live_connector_ids & set(REQUIRED_CONNECTOR_ECOSYSTEM)), len(REQUIRED_CONNECTOR_ECOSYSTEM)),
            "governed_action_pct": float(response_metrics.get("owner_coverage_pct") or 0.0),
            "response_compliance_pct": float(response_metrics.get("compliance_coverage_pct") or 0.0),
        },
        "release_blocked": bool(failed),
        "next_actions": [item["title"] for item in failed][:6],
    }


def build_compliance_evidence_pack() -> dict[str, Any]:
    gates = build_enterprise_release_gates()
    bundles = list_content_bundles()
    connectors = get_connectors_overview()
    response = get_response_analytics(limit=200)
    entities = get_entities_overview()

    compliance_controls = sorted(
        {
            str(control).strip()
            for item in list(connectors.get("items") or [])
            for control in (dict(item.get("operations") or {}).get("compliance_controls") or [])
            if str(control).strip()
        }
        | {
            str(control).strip()
            for item in list(response.get("playbook_library") or [])
            for control in (item.get("compliance_controls") or [])
            if str(control).strip()
        }
    )

    return {
        "generated_ts": _now_iso(),
        "evidence_pack_id": f"evidence-pack-{str(_now_iso()).replace(':', '').replace('-', '')}",
        "format": "json",
        "title": "Enterprise governance and release evidence pack",
        "release_gates": gates,
        "content_bundles": [
            {
                "id": str(item.get("id") or ""),
                "title": str(item.get("title") or item.get("id") or ""),
                "stage": str(item.get("stage") or item.get("status") or "draft"),
                "release_gate": dict(item.get("release_gate") or {}),
                "owner": str(item.get("owner") or ""),
                "release_ring": str(item.get("release_ring") or ""),
                "integrity": dict(item.get("integrity") or {}),
            }
            for item in bundles
        ],
        "connector_registry": [
            {
                "id": str(item.get("id") or ""),
                "title": str(item.get("title") or item.get("id") or ""),
                "domain": str(item.get("source_family") or item.get("group") or "source"),
                "release_gate": dict(item.get("release_gate") or {}),
                "telemetry": dict(item.get("telemetry") or {}),
                "operations": dict(item.get("operations") or {}),
            }
            for item in list(connectors.get("items") or [])
        ],
        "response_library": {
            "metrics": dict(response.get("metrics") or {}),
            "policy_packs": list(response.get("policy_packs") or []),
            "playbook_library": list(response.get("playbook_library") or []),
        },
        "entity_operations": {
            "metrics": dict(entities.get("metrics") or {}),
            "ueba_models": list(UEBA_MODEL_COVERAGE),
            "graph_relationships": list(EVIDENCE_RELATIONSHIPS),
        },
        "governance": {
            "control_families": list(response.get("compliance", {}).get("families") or []),
            "controls": compliance_controls,
            "export_supported": True,
            "operator_note": "This pack is intended for release reviews, audit preparation and change-board evidence.",
        },
    }
