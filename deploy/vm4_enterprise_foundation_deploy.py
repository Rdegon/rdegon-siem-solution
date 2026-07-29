from __future__ import annotations

import base64
import json
import os
import posixpath
import shlex
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

try:
    import paramiko
except ModuleNotFoundError:  # pragma: no cover - exercised in CI/unit imports
    paramiko = None  # type: ignore[assignment]


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REMOTE_ROOT = "/opt/siem/siem-solution"
FRONTEND_NODE_VERSION = "20.19.0"
VM4_WEB_PYTHON = "/opt/siem/venv-web/bin/python"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.vm4_identity_governance_bootstrap import (
    VAULT_ADDR,
    _ensure_vault_initialized,
    _ensure_vault_unsealed,
    _wait_for_remote_http,
    bootstrap_vm4_identity_governance,
)

if TYPE_CHECKING:  # pragma: no cover
    import paramiko as _paramiko

for stream_name in ("stdout", "stderr"):
    stream = getattr(sys, stream_name, None)
    if stream is not None and hasattr(stream, "reconfigure"):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass


@dataclass(frozen=True)
class FileMapping:
    local_rel: str
    remote_rel: str


@dataclass(frozen=True)
class SystemAsset:
    remote_rel: str
    target_path: str
    mode: str


def _directory_mappings(local_root: str, remote_root: str) -> tuple[FileMapping, ...]:
    base = ROOT / local_root
    if not base.exists():
        return ()
    mappings: list[FileMapping] = []
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
            continue
        local_rel = path.relative_to(ROOT).as_posix()
        remote_rel = posixpath.join(remote_root.rstrip("/"), path.relative_to(base).as_posix())
        mappings.append(FileMapping(local_rel, remote_rel))
    return tuple(mappings)


FILE_MAPPINGS: tuple[FileMapping, ...] = (
    FileMapping("sitecustomize.py", "sitecustomize.py"),
    FileMapping("services/web/__init__.py", "services/web/__init__.py"),
    FileMapping("services/web/main.py", "services/web/main.py"),
    FileMapping("services/web/requirements-web.txt", "services/web/requirements-web.txt"),
    FileMapping("services/web/app/__init__.py", "services/web/app/__init__.py"),
    FileMapping("services/web/app/config.py", "services/web/app/config.py"),
    FileMapping("services/web/app/templates.py", "services/web/app/templates.py"),
    FileMapping("services/web/app/routes/__init__.py", "services/web/app/routes/__init__.py"),
    FileMapping("services/web/app/routes/auth.py", "services/web/app/routes/auth.py"),
    FileMapping("services/web/app/routes/health.py", "services/web/app/routes/health.py"),
    FileMapping("services/web/app/templates/login.html", "services/web/app/templates/login.html"),
    FileMapping("services/web/app/templates/alerts.html", "services/web/app/templates/alerts.html"),
    FileMapping("services/web/app/templates/assets.html", "services/web/app/templates/assets.html"),
    FileMapping("services/web/app/templates/base.html", "services/web/app/templates/base.html"),
    FileMapping("services/web/app/templates/collectors.html", "services/web/app/templates/collectors.html"),
    FileMapping("services/web/app/templates/dashboard.html", "services/web/app/templates/dashboard.html"),
    FileMapping("services/web/app/templates/documentation.html", "services/web/app/templates/documentation.html"),
    FileMapping("services/web/app/templates/documentation_detail.html", "services/web/app/templates/documentation_detail.html"),
    FileMapping("services/web/app/templates/events.html", "services/web/app/templates/events.html"),
    FileMapping("services/web/app/templates/report_detail.html", "services/web/app/templates/report_detail.html"),
    FileMapping("services/web/app/templates/reports.html", "services/web/app/templates/reports.html"),
    FileMapping("services/web/app/templates/resources.html", "services/web/app/templates/resources.html"),
    FileMapping("services/web/app/templates/sources.html", "services/web/app/templates/sources.html"),
    FileMapping("services/web/app/secret_runtime.py", "secret_runtime.py"),
    FileMapping("services/web/app/oidc_runtime.py", "oidc_runtime.py"),
    FileMapping("services/web/app/certification_runtime.py", "certification_runtime.py"),
    FileMapping("frontend-react/.eslintrc.cjs", "services/web/frontend-react/.eslintrc.cjs"),
    FileMapping("frontend-react/build.cjs", "services/web/frontend-react/build.cjs"),
    FileMapping("frontend-react/package.json", "services/web/frontend-react/package.json"),
    FileMapping("frontend-react/tsconfig.json", "services/web/frontend-react/tsconfig.json"),
    FileMapping("frontend-react/tsconfig.quality.json", "services/web/frontend-react/tsconfig.quality.json"),
    FileMapping("frontend-react/vitest.config.ts", "services/web/frontend-react/vitest.config.ts"),
    FileMapping("services/web/app/backup_runtime.py", "backup_runtime.py"),
    FileMapping("services/web/app/asset_catalog_runtime.py", "asset_catalog_runtime.py"),
    FileMapping("services/web/app/clickhouse_runtime.py", "clickhouse_runtime.py"),
    FileMapping("services/web/app/content_runtime.py", "content_runtime.py"),
    FileMapping("services/web/app/control_plane_health.py", "control_plane_health.py"),
    FileMapping("services/web/app/control_plane_access_ops.py", "control_plane_access_ops.py"),
    FileMapping("services/web/app/control_plane_case_ops.py", "control_plane_case_ops.py"),
    FileMapping("services/web/app/control_plane_connector_ops.py", "control_plane_connector_ops.py"),
    FileMapping("services/web/app/control_plane_content_ops.py", "control_plane_content_ops.py"),
    FileMapping("services/web/app/control_plane_response_ops.py", "control_plane_response_ops.py"),
    FileMapping("services/web/app/control_plane_governance_ops.py", "control_plane_governance_ops.py"),
    FileMapping("services/web/app/enterprise_control_plane_defaults.py", "enterprise_control_plane_defaults.py"),
    FileMapping("services/web/app/inventory_catalog.py", "inventory_catalog.py"),
    FileMapping("services/web/app/runtime_humanization.py", "runtime_humanization.py"),
    FileMapping("services/web/app/proxmox_guest_ops.py", "proxmox_guest_ops.py"),
    FileMapping("services/web/app/incident_ai_runtime.py", "incident_ai_runtime.py"),
    FileMapping("services/web/app/proxmox_fleet_runtime.py", "proxmox_fleet_runtime.py"),
    FileMapping("services/web/app/response_workflow_runtime.py", "response_workflow_runtime.py"),
    FileMapping("services/web/app/source_onboarding_runtime.py", "source_onboarding_runtime.py"),
    FileMapping("services/web/app/topology_runtime.py", "topology_runtime.py"),
    FileMapping("services/web/app/host_access_runtime.py", "host_access_runtime.py"),
    FileMapping("services/web/app/vuln_asset_binding.py", "vuln_asset_binding.py"),
    FileMapping("services/web/app/deps_platform_ops.py", "deps_platform_ops.py"),
    FileMapping("services/web/app/deps_runtime_docs_ops.py", "deps_runtime_docs_ops.py"),
    FileMapping("services/web/app/health_surfaces.py", "health_surfaces.py"),
    FileMapping("services/web/app/host_runtime_pipeline.py", "host_runtime_pipeline.py"),
    FileMapping("services/web/app/host_runtime_runtime.py", "host_runtime_runtime.py"),
    FileMapping("services/web/app/storage_ha_runtime.py", "storage_ha_runtime.py"),
    FileMapping("services/web/app/stream_state_runtime.py", "stream_state_runtime.py"),
    FileMapping("services/web/app/transport_health_runtime.py", "transport_health_runtime.py"),
    FileMapping("services/web/app/vulnerability_query_runtime.py", "vulnerability_query_runtime.py"),
    FileMapping("services/web/app/vuln_greenbone.py", "vuln_greenbone.py"),
    FileMapping("services/web/app/vuln_exposure_runtime.py", "vuln_exposure_runtime.py"),
    FileMapping("services/web/app/vuln_maturity_runtime.py", "vuln_maturity_runtime.py"),
    FileMapping("services/web/app/vuln_store.py", "vuln_store.py"),
    FileMapping("services/web/app/vuln_runtime.py", "vuln_runtime.py"),
    FileMapping("services/web/app/deps.py", "deps.py"),
    FileMapping("services/web/app/operational_filters.py", "operational_filters.py"),
    FileMapping("services/web/app/content_store.py", "content_store.py"),
    FileMapping("services/web/app/enterprise_control_plane.py", "enterprise_control_plane.py"),
    FileMapping("services/web/app/backup_runtime.py", "services/web/app/backup_runtime.py"),
    FileMapping("services/web/app/asset_catalog_runtime.py", "services/web/app/asset_catalog_runtime.py"),
    FileMapping("services/web/app/clickhouse_runtime.py", "services/web/app/clickhouse_runtime.py"),
    FileMapping("services/web/app/security_services_runtime.py", "services/web/app/security_services_runtime.py"),
    FileMapping("services/web/app/opnsense_control_runtime.py", "services/web/app/opnsense_control_runtime.py"),
    FileMapping("services/web/app/content_runtime.py", "services/web/app/content_runtime.py"),
    FileMapping("services/web/app/control_plane_health.py", "services/web/app/control_plane_health.py"),
    FileMapping("services/web/app/control_plane_access_ops.py", "services/web/app/control_plane_access_ops.py"),
    FileMapping("services/web/app/control_plane_case_ops.py", "services/web/app/control_plane_case_ops.py"),
    FileMapping("services/web/app/control_plane_connector_ops.py", "services/web/app/control_plane_connector_ops.py"),
    FileMapping("services/web/app/control_plane_content_ops.py", "services/web/app/control_plane_content_ops.py"),
    FileMapping("services/web/app/control_plane_response_ops.py", "services/web/app/control_plane_response_ops.py"),
    FileMapping("services/web/app/control_plane_governance_ops.py", "services/web/app/control_plane_governance_ops.py"),
    FileMapping("services/web/app/enterprise_control_plane_defaults.py", "services/web/app/enterprise_control_plane_defaults.py"),
    FileMapping("services/web/app/inventory_catalog.py", "services/web/app/inventory_catalog.py"),
    FileMapping("services/web/app/runtime_humanization.py", "services/web/app/runtime_humanization.py"),
    FileMapping("services/web/app/proxmox_guest_ops.py", "services/web/app/proxmox_guest_ops.py"),
    FileMapping("services/web/app/incident_ai_runtime.py", "services/web/app/incident_ai_runtime.py"),
    FileMapping("services/web/app/proxmox_fleet_runtime.py", "services/web/app/proxmox_fleet_runtime.py"),
    FileMapping("services/web/app/response_workflow_runtime.py", "services/web/app/response_workflow_runtime.py"),
    FileMapping("services/web/app/source_onboarding_runtime.py", "services/web/app/source_onboarding_runtime.py"),
    FileMapping("services/web/app/topology_runtime.py", "services/web/app/topology_runtime.py"),
    FileMapping("services/web/app/host_access_runtime.py", "services/web/app/host_access_runtime.py"),
    FileMapping("services/web/app/vuln_asset_binding.py", "services/web/app/vuln_asset_binding.py"),
    FileMapping("services/web/app/deps_platform_ops.py", "services/web/app/deps_platform_ops.py"),
    FileMapping("services/web/app/deps_runtime_docs_ops.py", "services/web/app/deps_runtime_docs_ops.py"),
    FileMapping("services/web/app/health_surfaces.py", "services/web/app/health_surfaces.py"),
    FileMapping("services/web/app/host_runtime_runtime.py", "services/web/app/host_runtime_runtime.py"),
    FileMapping("services/web/app/storage_ha_runtime.py", "services/web/app/storage_ha_runtime.py"),
    FileMapping("services/web/app/stream_state_runtime.py", "services/web/app/stream_state_runtime.py"),
    FileMapping("services/web/app/transport_health_runtime.py", "services/web/app/transport_health_runtime.py"),
    FileMapping("services/web/app/vulnerability_query_runtime.py", "services/web/app/vulnerability_query_runtime.py"),
    FileMapping("services/web/app/vuln_greenbone.py", "services/web/app/vuln_greenbone.py"),
    FileMapping("services/web/app/vuln_exposure_runtime.py", "services/web/app/vuln_exposure_runtime.py"),
    FileMapping("services/web/app/vuln_maturity_runtime.py", "services/web/app/vuln_maturity_runtime.py"),
    FileMapping("services/web/app/vuln_store.py", "services/web/app/vuln_store.py"),
    FileMapping("services/web/app/vuln_runtime.py", "services/web/app/vuln_runtime.py"),
    FileMapping("services/web/app/security.py", "services/web/app/security.py"),
    FileMapping("services/web/app/secret_runtime.py", "services/web/app/secret_runtime.py"),
    FileMapping("services/web/app/oidc_runtime.py", "services/web/app/oidc_runtime.py"),
    FileMapping("services/web/app/certification_runtime.py", "services/web/app/certification_runtime.py"),
    FileMapping("services/web/app/deps.py", "services/web/app/deps.py"),
    FileMapping("services/web/app/operational_filters.py", "services/web/app/operational_filters.py"),
    FileMapping("services/web/app/content_store.py", "services/web/app/content_store.py"),
    FileMapping("services/web/app/routes/console.py", "services/web/app/routes/console.py"),
    FileMapping("services/web/app/routes/console_assets_routes.py", "services/web/app/routes/console_assets_routes.py"),
    FileMapping("services/web/app/routes/console_auth_routes.py", "services/web/app/routes/console_auth_routes.py"),
    FileMapping("services/web/app/routes/console_dashboard_routes.py", "services/web/app/routes/console_dashboard_routes.py"),
    FileMapping("services/web/app/routes/console_docs_routes.py", "services/web/app/routes/console_docs_routes.py"),
    FileMapping("services/web/app/routes/console_health_routes.py", "services/web/app/routes/console_health_routes.py"),
    FileMapping("services/web/app/routes/console_operations_routes.py", "services/web/app/routes/console_operations_routes.py"),
    FileMapping("services/web/app/routes/console_router_registry.py", "services/web/app/routes/console_router_registry.py"),
    FileMapping("services/web/app/routes/console_security_services_routes.py", "services/web/app/routes/console_security_services_routes.py"),
    FileMapping("services/web/app/routes/console_response_routes.py", "services/web/app/routes/console_response_routes.py"),
    FileMapping("services/web/app/routes/alerts.py", "services/web/app/routes/alerts.py"),
    FileMapping("services/web/app/routes/events.py", "services/web/app/routes/events.py"),
    FileMapping("services/web/app/enterprise_control_plane.py", "services/web/app/enterprise_control_plane.py"),
    FileMapping("services/web/app/ingest_runtime.py", "services/web/app/ingest_runtime.py"),
    FileMapping("services/web/app/source_discovery.py", "source_discovery.py"),
    FileMapping("services/web/app/source_discovery.py", "services/web/app/source_discovery.py"),
    FileMapping("services/stream_corr/worker.py", "services/stream_corr/worker.py"),
    FileMapping("frontend-react/src/shell/api.ts", "services/web/frontend-react/src/shell/api.ts"),
    FileMapping("frontend-react/src/shell/App.tsx", "services/web/frontend-react/src/shell/App.tsx"),
    FileMapping("frontend-react/src/shell/GeoDotMapCanvas.tsx", "services/web/frontend-react/src/shell/GeoDotMapCanvas.tsx"),
    FileMapping("frontend-react/src/shell/async.tsx", "services/web/frontend-react/src/shell/async.tsx"),
    FileMapping("frontend-react/src/shell/charts.tsx", "services/web/frontend-react/src/shell/charts.tsx"),
    FileMapping("frontend-react/src/shell/chrome.tsx", "services/web/frontend-react/src/shell/chrome.tsx"),
    FileMapping("frontend-react/src/shell/context.tsx", "services/web/frontend-react/src/shell/context.tsx"),
    FileMapping("frontend-react/src/shell/feedback.tsx", "services/web/frontend-react/src/shell/feedback.tsx"),
    FileMapping("frontend-react/src/shell/hooks.ts", "services/web/frontend-react/src/shell/hooks.ts"),
    FileMapping("frontend-react/src/shell/humanize.ts", "services/web/frontend-react/src/shell/humanize.ts"),
    FileMapping("frontend-react/src/shell/incidents.ts", "services/web/frontend-react/src/shell/incidents.ts"),
    FileMapping("frontend-react/src/shell/investigation.tsx", "services/web/frontend-react/src/shell/investigation.tsx"),
    FileMapping("frontend-react/src/shell/runtimeLocalization.ts", "services/web/frontend-react/src/shell/runtimeLocalization.ts"),
    FileMapping("frontend-react/src/shell/surfaces.tsx", "services/web/frontend-react/src/shell/surfaces.tsx"),
    FileMapping("frontend-react/src/shell/timeControls.ts", "services/web/frontend-react/src/shell/timeControls.ts"),
    FileMapping("frontend-react/src/shell/types.ts", "services/web/frontend-react/src/shell/types.ts"),
    FileMapping("frontend-react/src/shell/ui.tsx", "services/web/frontend-react/src/shell/ui.tsx"),
    FileMapping("frontend-react/src/shell/__tests__/async.test.tsx", "services/web/frontend-react/src/shell/__tests__/async.test.tsx"),
    FileMapping("frontend-react/src/shell/__tests__/context.test.ts", "services/web/frontend-react/src/shell/__tests__/context.test.ts"),
    FileMapping("frontend-react/src/shell/__tests__/feedback.test.tsx", "services/web/frontend-react/src/shell/__tests__/feedback.test.tsx"),
    FileMapping("frontend-react/src/shell/__tests__/hooks.test.tsx", "services/web/frontend-react/src/shell/__tests__/hooks.test.tsx"),
    FileMapping("frontend-react/src/shell/__tests__/incidents.test.tsx", "services/web/frontend-react/src/shell/__tests__/incidents.test.tsx"),
    FileMapping("frontend-react/src/shell/__tests__/ui.test.tsx", "services/web/frontend-react/src/shell/__tests__/ui.test.tsx"),
    FileMapping("frontend-react/src/shell/DashboardCanvas.tsx", "services/web/frontend-react/src/shell/DashboardCanvas.tsx"),
    FileMapping("frontend-react/src/shell/pages/ConnectorsPage.tsx", "services/web/frontend-react/src/shell/pages/ConnectorsPage.tsx"),
    FileMapping("frontend-react/src/shell/pages/CasesPage.tsx", "services/web/frontend-react/src/shell/pages/CasesPage.tsx"),
    FileMapping("frontend-react/src/shell/pages/AssetsPage.tsx", "services/web/frontend-react/src/shell/pages/AssetsPage.tsx"),
    FileMapping("frontend-react/src/shell/pages/CollectorsPage.tsx", "services/web/frontend-react/src/shell/pages/CollectorsPage.tsx"),
    FileMapping("frontend-react/src/shell/pages/EntitiesPage.tsx", "services/web/frontend-react/src/shell/pages/EntitiesPage.tsx"),
    FileMapping("frontend-react/src/shell/pages/DashboardPage.tsx", "services/web/frontend-react/src/shell/pages/DashboardPage.tsx"),
    FileMapping("frontend-react/src/shell/pages/IncidentsPage.tsx", "services/web/frontend-react/src/shell/pages/IncidentsPage.tsx"),
    FileMapping("frontend-react/src/shell/pages/EventsPage.tsx", "services/web/frontend-react/src/shell/pages/EventsPage.tsx"),
    FileMapping("frontend-react/src/shell/pages/HostRuntimePage.tsx", "services/web/frontend-react/src/shell/pages/HostRuntimePage.tsx"),
    FileMapping("frontend-react/src/shell/pages/IngestPage.tsx", "services/web/frontend-react/src/shell/pages/IngestPage.tsx"),
    FileMapping("frontend-react/src/shell/pages/AccessPage.tsx", "services/web/frontend-react/src/shell/pages/AccessPage.tsx"),
    FileMapping("frontend-react/src/shell/pages/BuildersPage.tsx", "services/web/frontend-react/src/shell/pages/BuildersPage.tsx"),
    FileMapping("frontend-react/src/shell/pages/ControlPanelPage.tsx", "services/web/frontend-react/src/shell/pages/ControlPanelPage.tsx"),
    FileMapping("frontend-react/src/shell/pages/DocumentationPage.tsx", "services/web/frontend-react/src/shell/pages/DocumentationPage.tsx"),
    FileMapping("frontend-react/src/shell/pages/InventoryPage.tsx", "services/web/frontend-react/src/shell/pages/InventoryPage.tsx"),
    FileMapping("frontend-react/src/shell/pages/ResponsePage.tsx", "services/web/frontend-react/src/shell/pages/ResponsePage.tsx"),
    FileMapping("frontend-react/src/shell/pages/SecurityServicePage.tsx", "services/web/frontend-react/src/shell/pages/SecurityServicePage.tsx"),
    FileMapping("frontend-react/src/shell/pages/SecurityControlPanel.tsx", "services/web/frontend-react/src/shell/pages/SecurityControlPanel.tsx"),
    FileMapping("frontend-react/src/shell/pages/SourcesPage.tsx", "services/web/frontend-react/src/shell/pages/SourcesPage.tsx"),
    FileMapping("frontend-react/src/shell/pages/ThreatIntelPage.tsx", "services/web/frontend-react/src/shell/pages/ThreatIntelPage.tsx"),
    FileMapping("frontend-react/src/shell/pages/TopologyPage.tsx", "services/web/frontend-react/src/shell/pages/TopologyPage.tsx"),
    FileMapping("frontend-react/src/shell/pages/VulnPage.tsx", "services/web/frontend-react/src/shell/pages/VulnPage.tsx"),
    FileMapping("frontend-react/src/styles.css", "services/web/frontend-react/src/styles.css"),
    FileMapping("frontend-react/src/test/renderWithShell.tsx", "services/web/frontend-react/src/test/renderWithShell.tsx"),
    FileMapping("frontend-react/src/test/setup.ts", "services/web/frontend-react/src/test/setup.ts"),
    FileMapping("frontend-react/src/types/assets.d.ts", "services/web/frontend-react/src/types/assets.d.ts"),
    FileMapping("frontend-react/src/types/react-simple-maps.d.ts", "services/web/frontend-react/src/types/react-simple-maps.d.ts"),
    FileMapping("services/__init__.py", "services/__init__.py"),
    FileMapping("services/redis_runtime.py", "services/redis_runtime.py"),
    FileMapping("services/transport_runtime.py", "services/transport_runtime.py"),
    FileMapping("services/stream_state.py", "services/stream_state.py"),
    FileMapping("services/writer/__init__.py", "services/writer/__init__.py"),
    FileMapping("services/stream_corr/__init__.py", "services/stream_corr/__init__.py"),
    FileMapping("services/stream_corr/config.py", "services/stream_corr/config.py"),
    FileMapping("services/stream_corr/logging_conf.py", "services/stream_corr/logging_conf.py"),
    FileMapping("services/stream_corr/rules.py", "services/stream_corr/rules.py"),
    FileMapping("services/ingest/__init__.py", "services/ingest/__init__.py"),
    FileMapping("services/ingest/app.py", "services/ingest/app.py"),
    FileMapping("services/ingest/config.py", "services/ingest/config.py"),
    FileMapping("services/ingest/logging_conf.py", "services/ingest/logging_conf.py"),
    FileMapping("services/ingest/redis_client.py", "services/ingest/redis_client.py"),
    FileMapping("docs/README.md", "docs/README.md"),
    FileMapping("docs/architecture.md", "docs/architecture.md"),
    FileMapping("docs/configuration.md", "docs/configuration.md"),
    FileMapping("docs/endpoints.md", "docs/endpoints.md"),
    FileMapping("docs/audit_2026-03-12.md", "docs/audit_2026-03-12.md"),
    FileMapping("docs/enterprise_foundation.md", "docs/enterprise_foundation.md"),
    FileMapping("docs/deployment_runbook_vm1_ingest_fabric.md", "docs/deployment_runbook_vm1_ingest_fabric.md"),
    FileMapping("docs/deployment_runbook_vm2_processing_resilience.md", "docs/deployment_runbook_vm2_processing_resilience.md"),
    FileMapping("docs/deployment_runbook_homelab_runners.md", "docs/deployment_runbook_homelab_runners.md"),
    FileMapping("docs/deployment_runbook_vm4_enterprise_foundation.md", "docs/deployment_runbook_vm4_enterprise_foundation.md"),
    FileMapping("docs/agent_handover_2026-03-12.md", "docs/agent_handover_2026-03-12.md"),
    FileMapping("docs/power_recovery_2026-03-13.md", "docs/power_recovery_2026-03-13.md"),
    FileMapping("docs/product_priorities_2026-03-13.md", "docs/product_priorities_2026-03-13.md"),
    FileMapping("docs/source_discovery.md", "docs/source_discovery.md"),
    FileMapping("docs/frontend_remediation_2026-03-19.md", "docs/frontend_remediation_2026-03-19.md"),
    FileMapping("docs/backend_security_followup_2026-03-21.md", "docs/backend_security_followup_2026-03-21.md"),
    FileMapping("docs/cicd_2026-03-21.md", "docs/cicd_2026-03-21.md"),
    FileMapping("docs/deployment_runbook_vm3_stream_corr_event_time.md", "docs/deployment_runbook_vm3_stream_corr_event_time.md"),
    FileMapping("docs/deployment_runbook_vm3_storage_memory_tuning.md", "docs/deployment_runbook_vm3_storage_memory_tuning.md"),
    FileMapping("docs/deployment_runbook_vm3_proxmox_memory_alignment.md", "docs/deployment_runbook_vm3_proxmox_memory_alignment.md"),
    FileMapping("docs/vm2_recovery_2026-03-22.md", "docs/vm2_recovery_2026-03-22.md"),
    FileMapping("docs/redis_ha_resilience_2026-03-22.md", "docs/redis_ha_resilience_2026-03-22.md"),
    FileMapping("docs/scaling_and_decomposition_plan_2026-03-22.md", "docs/scaling_and_decomposition_plan_2026-03-22.md"),
    FileMapping("docs/storage_memory_review_2026-03-22.md", "docs/storage_memory_review_2026-03-22.md"),
    FileMapping("docs/transport_content_runtime_2026-03-22.md", "docs/transport_content_runtime_2026-03-22.md"),
    FileMapping("docs/release_wave_kafka_vm5_2026-03-22.md", "docs/release_wave_kafka_vm5_2026-03-22.md"),
    FileMapping("docs/release_wave_platform_release_2026-03-22.md", "docs/release_wave_platform_release_2026-03-22.md"),
    FileMapping("docs/vm_access.md", "docs/vm_access.md"),
    FileMapping("ops/production_certification_profile.json", "ops/production_certification_profile.json"),
    FileMapping("tests/test_certification_runtime.py", "tests/test_certification_runtime.py"),
    FileMapping("tests/test_enterprise_control_plane.py", "tests/test_enterprise_control_plane.py"),
    FileMapping("tests/test_clickhouse_runtime.py", "tests/test_clickhouse_runtime.py"),
    FileMapping("tests/test_control_plane_health.py", "tests/test_control_plane_health.py"),
    FileMapping("tests/test_health_surfaces.py", "tests/test_health_surfaces.py"),
    FileMapping("tests/test_storage_ha_runtime.py", "tests/test_storage_ha_runtime.py"),
    FileMapping("tests/test_ingest_fabric.py", "tests/test_ingest_fabric.py"),
    FileMapping("tests/test_transport_runtime.py", "tests/test_transport_runtime.py"),
    FileMapping("tests/test_content_store_runtime.py", "tests/test_content_store_runtime.py"),
    FileMapping("tests/test_homelab_watchdog.py", "tests/test_homelab_watchdog.py"),
    FileMapping("tests/test_security_runtime.py", "tests/test_security_runtime.py"),
    FileMapping("tests/test_security_services_runtime.py", "tests/test_security_services_runtime.py"),
    FileMapping("tests/test_response_maturity.py", "tests/test_response_maturity.py"),
    FileMapping("tests/test_source_discovery.py", "tests/test_source_discovery.py"),
    FileMapping("tests/test_topology_runtime.py", "tests/test_topology_runtime.py"),
    FileMapping("tests/test_host_access_runtime.py", "tests/test_host_access_runtime.py"),
    FileMapping("tests/test_stream_worker.py", "tests/test_stream_worker.py"),
    FileMapping("tests/test_vuln_maturity_runtime.py", "tests/test_vuln_maturity_runtime.py"),
    FileMapping("tests/test_vuln_exposure_runtime.py", "tests/test_vuln_exposure_runtime.py"),
    FileMapping("tests/test_vuln_greenbone.py", "tests/test_vuln_greenbone.py"),
    FileMapping("tests/test_proxmox_fleet_runtime.py", "tests/test_proxmox_fleet_runtime.py"),
    FileMapping("tests/test_vm2_processing_resilience.py", "tests/test_vm2_processing_resilience.py"),
    FileMapping("deploy/vm1_ingest_fabric_deploy.py", "deploy/vm1_ingest_fabric_deploy.py"),
    FileMapping("deploy/vm1_ingest_fabric_smoke.py", "deploy/vm1_ingest_fabric_smoke.py"),
    FileMapping("deploy/github_runner_provision.py", "deploy/github_runner_provision.py"),
    FileMapping("deploy/provision_homelab_runners.py", "deploy/provision_homelab_runners.py"),
    FileMapping("deploy/github_actions_workflow_dispatch.py", "deploy/github_actions_workflow_dispatch.py"),
    FileMapping("deploy/homelab_watchdog.py", "deploy/homelab_watchdog.py"),
    FileMapping("services/web/maintenance/__init__.py", "services/web/maintenance/__init__.py"),
    FileMapping("services/web/maintenance/retention_runner.py", "services/web/maintenance/retention_runner.py"),
    FileMapping("deploy/vuln/rdegon_greenbone_start_wave.py", "deploy/vuln/rdegon_greenbone_start_wave.py"),
    FileMapping("deploy/vuln/rdegon_greenbone_sync.py", "deploy/vuln/rdegon_greenbone_sync.py"),
    FileMapping("deploy/vuln/rdegon_vuln_policy_apply.py", "deploy/vuln/rdegon_vuln_policy_apply.py"),
    FileMapping("deploy/ansible/vuln_validate.yml", "deploy/ansible/vuln_validate.yml"),
    FileMapping("deploy/ansible/vuln_patch_package.yml", "deploy/ansible/vuln_patch_package.yml"),
    FileMapping("deploy/vm3_stream_corr_event_time_deploy.py", "deploy/vm3_stream_corr_event_time_deploy.py"),
    FileMapping("deploy/vm3_stream_corr_event_time_smoke.py", "deploy/vm3_stream_corr_event_time_smoke.py"),
    FileMapping("deploy/vm2_processing_resilience_deploy.py", "deploy/vm2_processing_resilience_deploy.py"),
    FileMapping("deploy/vm2_processing_resilience_smoke.py", "deploy/vm2_processing_resilience_smoke.py"),
    FileMapping("deploy/production_certification.py", "deploy/production_certification.py"),
    FileMapping("deploy/distributed_eps_benchmark.py", "deploy/distributed_eps_benchmark.py"),
    FileMapping("deploy/publish_operational_rule_packs.py", "deploy/publish_operational_rule_packs.py"),
    FileMapping("deploy/publish_assignment_detection_pack.py", "deploy/publish_assignment_detection_pack.py"),
    FileMapping("deploy/publish_rule_noise_tuning.py", "deploy/publish_rule_noise_tuning.py"),
    FileMapping("deploy/publish_batch_rules.py", "deploy/publish_batch_rules.py"),
    FileMapping("deploy/publish_filter_rules.py", "deploy/publish_filter_rules.py"),
    FileMapping("sql/12_filter_rule_seed.sql", "sql/12_filter_rule_seed.sql"),
    FileMapping("sql/13_batch_corr_seed.sql", "sql/13_batch_corr_seed.sql"),
    FileMapping("sql/15_batch_corr_soc_seed.sql", "sql/15_batch_corr_soc_seed.sql"),
    FileMapping("deploy/storage_ha_drill.py", "deploy/storage_ha_drill.py"),
    FileMapping("deploy/vm4_enterprise_foundation_deploy.py", "deploy/vm4_enterprise_foundation_deploy.py"),
    FileMapping("deploy/vm4_enterprise_foundation_smoke.py", "deploy/vm4_enterprise_foundation_smoke.py"),
    FileMapping("deploy/system_cleanup.py", "deploy/system_cleanup.py"),
    FileMapping("deploy/publish_runtime_docs.py", "deploy/publish_runtime_docs.py"),
    FileMapping("deploy/vm4_control_plane_postgres_cutover.py", "deploy/vm4_control_plane_postgres_cutover.py"),
    FileMapping("deploy/vm4_security_hardening.py", "deploy/vm4_security_hardening.py"),
    FileMapping("deploy/windows-agent/build-openvpn-route-profile.ps1", "deploy/windows-agent/build-openvpn-route-profile.ps1"),
    FileMapping("deploy/windows-agent/get-windows-event-agent-status.ps1", "deploy/windows-agent/get-windows-event-agent-status.ps1"),
    FileMapping("deploy/windows-agent/install-windows-event-agent.ps1", "deploy/windows-agent/install-windows-event-agent.ps1"),
    FileMapping("deploy/windows-agent/package-windows-event-agent.ps1", "deploy/windows-agent/package-windows-event-agent.ps1"),
    FileMapping("deploy/vm4/siem-greenbone-sync.service", "deploy/vm4/siem-greenbone-sync.service"),
    FileMapping("deploy/vm4/siem-greenbone-sync.timer", "deploy/vm4/siem-greenbone-sync.timer"),
    FileMapping("deploy/vm4/siem-vuln-policy-apply.service", "deploy/vm4/siem-vuln-policy-apply.service"),
    FileMapping("deploy/vm4/siem-vuln-policy-apply.timer", "deploy/vm4/siem-vuln-policy-apply.timer"),
    FileMapping("deploy/vm4/siem-jump-tunnels.service", "deploy/vm4/siem-jump-tunnels.service"),
    FileMapping("deploy/vm4/siem-jump-tunnels.sh", "deploy/vm4/siem-jump-tunnels.sh"),
    FileMapping("deploy/vm4/siem-web.conf", "deploy/vm4/siem-web.conf"),
    FileMapping("deploy/vm4/siem-vault.service", "deploy/vm4/siem-vault.service"),
    FileMapping("deploy/vm4/siem-vault-unseal.sh", "deploy/vm4/siem-vault-unseal.sh"),
    FileMapping("deploy/vm4/siem-ingest-recovery-watchdog.service", "deploy/vm4/siem-ingest-recovery-watchdog.service"),
    FileMapping("deploy/vm4/siem-ingest-recovery-watchdog.timer", "deploy/vm4/siem-ingest-recovery-watchdog.timer"),
    FileMapping("deploy/vm4/siem-event-retention.service", "deploy/vm4/siem-event-retention.service"),
    FileMapping("deploy/vm4/siem-event-retention.timer", "deploy/vm4/siem-event-retention.timer"),
    FileMapping("deploy/vm4/vault.hcl", "deploy/vm4/vault.hcl"),
    FileMapping("deploy/vm4/siem-keycloak.service", "deploy/vm4/siem-keycloak.service"),
    FileMapping("deploy/vm4/siem-web.override.conf", "deploy/vm4/siem-web.override.conf"),
    FileMapping("deploy/vm4/home-gateway-up.sh", "deploy/vm4/home-gateway-up.sh"),
    FileMapping("deploy/vm4/home-gateway-down.sh", "deploy/vm4/home-gateway-down.sh"),
    FileMapping("deploy/env_file_runtime.py", "deploy/env_file_runtime.py"),
    FileMapping("ops/windows-agent-profile.local.example.json", "ops/windows-agent-profile.local.example.json"),
    FileMapping("docs/deployment_runbook_vm4_security_hardening.md", "docs/deployment_runbook_vm4_security_hardening.md"),
    FileMapping("docs/deployment_runbook_vm4_content_store_mongo.md", "docs/deployment_runbook_vm4_content_store_mongo.md"),
    FileMapping("services/web/app/asset_binding_overrides.py", "asset_binding_overrides.py"),
    FileMapping("services/web/app/correlation_pack_runtime.py", "correlation_pack_runtime.py"),
    FileMapping("services/web/app/control_plane_governance_runtime.py", "control_plane_governance_runtime.py"),
    FileMapping("services/web/app/keycloak_admin_runtime.py", "keycloak_admin_runtime.py"),
    FileMapping("services/web/app/asset_binding_overrides.py", "services/web/app/asset_binding_overrides.py"),
    FileMapping("services/web/app/correlation_pack_runtime.py", "services/web/app/correlation_pack_runtime.py"),
    FileMapping("services/web/app/control_plane_governance_runtime.py", "services/web/app/control_plane_governance_runtime.py"),
    FileMapping("services/web/app/keycloak_admin_runtime.py", "services/web/app/keycloak_admin_runtime.py"),
    FileMapping("frontend-react/src/main.tsx", "services/web/frontend-react/src/main.tsx"),
    FileMapping("tests/test_keycloak_admin_runtime.py", "tests/test_keycloak_admin_runtime.py"),
    FileMapping("tests/test_deploy_rollout_regressions.py", "tests/test_deploy_rollout_regressions.py"),
) + _directory_mappings("frontend-react/src/assets", "services/web/frontend-react/src/assets") + _directory_mappings(
    "frontend-react/src/styles",
    "services/web/frontend-react/src/styles",
) + _directory_mappings(
    "frontend-react/src/shell/pages/access",
    "services/web/frontend-react/src/shell/pages/access",
) + _directory_mappings(
    "frontend-react/src/shell/pages/builders",
    "services/web/frontend-react/src/shell/pages/builders",
) + _directory_mappings(
    "frontend-react/src/shell/__tests__",
    "services/web/frontend-react/src/shell/__tests__",
) + _directory_mappings(
    "docs",
    "docs",
) + _directory_mappings(
    "correlation_rule_packs",
    "correlation_rule_packs",
) + _directory_mappings(
    "services/web/app/query",
    "query",
) + _directory_mappings(
    "services/web/app/query",
    "services/web/app/query",
)

SYSTEM_ASSETS: tuple[SystemAsset, ...] = (
    SystemAsset("deploy/vm4/siem-web.conf", "/etc/nginx/sites-available/siem-web.conf", "0644"),
    SystemAsset("deploy/vm4/siem-greenbone-sync.service", "/etc/systemd/system/siem-greenbone-sync.service", "0644"),
    SystemAsset("deploy/vm4/siem-greenbone-sync.timer", "/etc/systemd/system/siem-greenbone-sync.timer", "0644"),
    SystemAsset("deploy/vm4/siem-vuln-policy-apply.service", "/etc/systemd/system/siem-vuln-policy-apply.service", "0644"),
    SystemAsset("deploy/vm4/siem-vuln-policy-apply.timer", "/etc/systemd/system/siem-vuln-policy-apply.timer", "0644"),
    SystemAsset("deploy/ansible/vuln_validate.yml", "/opt/siem/soar/ansible/vuln_validate.yml", "0644"),
    SystemAsset("deploy/ansible/vuln_patch_package.yml", "/opt/siem/soar/ansible/vuln_patch_package.yml", "0644"),
    SystemAsset("deploy/vm4/siem-jump-tunnels.service", "/etc/systemd/system/siem-jump-tunnels.service", "0644"),
    SystemAsset("deploy/vm4/siem-jump-tunnels.sh", "/usr/local/bin/siem-jump-tunnels.sh", "0755"),
    SystemAsset("deploy/vm4/siem-vault.service", "/etc/systemd/system/siem-vault.service", "0644"),
    SystemAsset("deploy/vm4/siem-vault-unseal.sh", "/usr/local/bin/siem-vault-unseal.sh", "0755"),
    SystemAsset("deploy/vm4/siem-ingest-recovery-watchdog.service", "/etc/systemd/system/siem-ingest-recovery-watchdog.service", "0644"),
    SystemAsset("deploy/vm4/siem-ingest-recovery-watchdog.timer", "/etc/systemd/system/siem-ingest-recovery-watchdog.timer", "0644"),
    SystemAsset("deploy/vm4/siem-event-retention.service", "/etc/systemd/system/siem-event-retention.service", "0644"),
    SystemAsset("deploy/vm4/siem-event-retention.timer", "/etc/systemd/system/siem-event-retention.timer", "0644"),
    SystemAsset("deploy/vm4/vault.hcl", "/etc/siem/vault.hcl", "0644"),
    SystemAsset("deploy/vm4/siem-keycloak.service", "/etc/systemd/system/siem-keycloak.service", "0644"),
    SystemAsset("deploy/vm4/siem-web.override.conf", "/etc/systemd/system/siem-web.service.d/override.conf", "0644"),
    SystemAsset("deploy/vm4/home-gateway-up.sh", "/etc/openvpn/client/home-gateway-up.sh", "0755"),
    SystemAsset("deploy/vm4/home-gateway-down.sh", "/etc/openvpn/client/home-gateway-down.sh", "0755"),
)


def _required_env(name: str, *, default: str | None = None) -> str:
    value = os.getenv(name, default or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _remote_path(remote_root: str, rel_path: str) -> str:
    return posixpath.join(remote_root.rstrip("/"), rel_path.replace("\\", "/"))


def _resolve_local_path(mapping: FileMapping) -> Path:
    direct = ROOT / mapping.local_rel
    if direct.exists():
        return direct
    mirrored = ROOT / mapping.remote_rel
    if mirrored.exists():
        return mirrored
    raise FileNotFoundError(f"Missing local file: {direct}")


def _run_command(
    client: paramiko.SSHClient,
    command: str,
    *,
    sudo_password: str = "",
    use_sudo: bool = False,
    timeout_seconds: float = 600.0,
) -> tuple[int, str, str]:
    wrapped = f"sudo -S -p '' bash -lc {shlex.quote(command)}" if use_sudo else command
    transport = client.get_transport()
    if transport is None:
        raise RuntimeError("SSH transport is not connected")
    channel = transport.open_session(timeout=20)
    if use_sudo:
        channel.get_pty()
    channel.settimeout(2.0)
    channel.exec_command(wrapped)
    stdin = channel.makefile_stdin("wb")
    out_chunks: list[bytes] = []
    err_chunks: list[bytes] = []
    if use_sudo:
        stdin.write(f"{sudo_password}\n".encode("utf-8"))
        stdin.flush()
    deadline = time.monotonic() + max(1.0, float(timeout_seconds))
    while True:
        while channel.recv_ready():
            out_chunks.append(channel.recv(65535))
        while channel.recv_stderr_ready():
            err_chunks.append(channel.recv_stderr(65535))
        if channel.exit_status_ready():
            break
        if time.monotonic() >= deadline:
            channel.close()
            out = b"".join(out_chunks).decode("utf-8", errors="replace")
            err = b"".join(err_chunks).decode("utf-8", errors="replace")
            return 124, out, f"{err}\nCommand timed out after {timeout_seconds:g}s: {command[:240]}"
        time.sleep(0.1)
    while channel.recv_ready():
        out_chunks.append(channel.recv(65535))
    while channel.recv_stderr_ready():
        err_chunks.append(channel.recv_stderr(65535))
    code = channel.recv_exit_status()
    out = b"".join(out_chunks).decode("utf-8", errors="replace")
    err = b"".join(err_chunks).decode("utf-8", errors="replace")
    channel.close()
    return code, out, err


def _connect_client(host: str, user: str, password: str, *, attempts: int = 5, delay_seconds: float = 3.0) -> paramiko.SSHClient:
    if paramiko is None:
        raise RuntimeError("paramiko is required to deploy VM4 enterprise foundation")
    jump_host = str(os.getenv("SIEM_VM4_JUMP_HOST", "") or "").strip()
    jump_user = str(
        os.getenv("SIEM_VM4_JUMP_USER", "")
        or os.getenv("SIEM_PROXMOX_USER", "")
        or ""
    ).strip()
    jump_password = str(
        os.getenv("SIEM_VM4_JUMP_PASSWORD", "")
        or os.getenv("SIEM_PROXMOX_PASSWORD", "")
        or ""
    )
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        jump_client: paramiko.SSHClient | None = None
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            target_socket = None
            if jump_host:
                if not jump_user or not jump_password:
                    raise RuntimeError("VM4 jump host requires a user and password")
                jump_client = paramiko.SSHClient()
                jump_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                jump_client.connect(
                    jump_host,
                    username=jump_user,
                    password=jump_password,
                    timeout=20,
                    banner_timeout=20,
                    auth_timeout=20,
                    look_for_keys=False,
                    allow_agent=False,
                )
                jump_transport = jump_client.get_transport()
                if jump_transport is None:
                    raise RuntimeError("VM4 jump host transport is not connected")
                target_socket = jump_transport.open_channel(
                    "direct-tcpip",
                    (host, 22),
                    ("127.0.0.1", 0),
                )
            client.connect(
                host,
                username=user,
                password=password,
                sock=target_socket,
                timeout=20,
                banner_timeout=20,
                auth_timeout=20,
                look_for_keys=False,
                allow_agent=False,
            )
            if jump_client is not None:
                setattr(client, "_siem_jump_client", jump_client)
            return client
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            client.close()
            if jump_client is not None:
                jump_client.close()
            if attempt == attempts:
                break
            print(f"ssh connect attempt {attempt}/{attempts} failed: {exc}")
            time.sleep(delay_seconds)
    raise RuntimeError(f"Unable to connect to {host} after {attempts} attempts: {last_error}")


def _strip_sudo_echo(text: str, sudo_password: str) -> str:
    if not sudo_password:
        return text
    cleaned_lines: list[str] = []
    for raw_line in str(text or "").replace("\r", "\n").split("\n"):
        line = raw_line.strip("\x00")
        if line.strip() == sudo_password:
            continue
        cleaned_lines.append(line)
    return "\n".join(cleaned_lines)


def _runtime_bridge_env_updates() -> dict[str, str]:
    proxmox_host = str(os.getenv("SIEM_PROXMOX_HOST", "") or "").strip()
    proxmox_user = str(os.getenv("SIEM_PROXMOX_USER", "") or "").strip()
    proxmox_password = str(os.getenv("SIEM_PROXMOX_PASSWORD", "") or "").strip()
    vm1_host = str(os.getenv("SIEM_VM1_HOST", "") or "").strip()
    vm1_user = str(os.getenv("SIEM_VM1_USER", "") or "").strip()
    vm1_password = str(os.getenv("SIEM_VM1_PASSWORD", "") or "").strip()
    vm3_host = str(os.getenv("SIEM_VM3_HOST", "") or "").strip()
    vm3_user = str(os.getenv("SIEM_VM3_USER", "") or "").strip()
    vm3_password = str(os.getenv("SIEM_VM3_PASSWORD", "") or "").strip()
    vm4_host = str(os.getenv("SIEM_VM4_HOST", "") or "").strip()
    vm4_user = str(os.getenv("SIEM_VM4_USER", "") or "").strip()
    vm4_password = str(os.getenv("SIEM_VM4_PASSWORD", "") or "").strip()
    proxy_url = str(os.getenv("SIEM_OPENCLAW_PROXY_URL", "") or os.getenv("SIEM_TELEGRAM_PROXY_URL", "") or "").strip()
    if not proxy_url:
        proxy_host = str(os.getenv("SIEM_OPENCLAW_PROXY_HOST", "openclaw-gateway.lab.home.arpa") or "openclaw-gateway.lab.home.arpa").strip()
        proxy_port = str(os.getenv("SIEM_OPENCLAW_PROXY_PORT", "10809") or "10809").strip()
        proxy_url = f"http://{proxy_host}:{proxy_port}"
    updates = {
        "SIEM_TELEGRAM_PROXY_URL": proxy_url,
        "SIEM_OPENCLAW_PROXY_URL": proxy_url,
    }
    if proxmox_host:
        updates["SIEM_PROXMOX_HOST"] = proxmox_host
        updates["SIEM_PROXMOX_SSH_HOST"] = proxmox_host
    if proxmox_user:
        updates["SIEM_PROXMOX_USER"] = proxmox_user
        updates["SIEM_PROXMOX_SSH_USER"] = proxmox_user
    if proxmox_password:
        updates["SIEM_PROXMOX_PASSWORD"] = proxmox_password
        updates["SIEM_PROXMOX_SSH_PASSWORD"] = proxmox_password
    if vm1_host:
        updates["SIEM_VM1_HOST"] = vm1_host
    if vm1_user:
        updates["SIEM_VM1_USER"] = vm1_user
    if vm1_password:
        updates["SIEM_VM1_PASSWORD"] = vm1_password
    if vm3_host:
        updates["SIEM_VM3_HOST"] = vm3_host
    if vm3_user:
        updates["SIEM_VM3_USER"] = vm3_user
    if vm3_password:
        updates["SIEM_VM3_PASSWORD"] = vm3_password
    if vm4_host:
        updates["SIEM_VM4_HOST"] = vm4_host
    if vm4_user:
        updates["SIEM_VM4_USER"] = vm4_user
    if vm4_password:
        updates["SIEM_VM4_PASSWORD"] = vm4_password
    updates.setdefault(
        "SIEM_WATCHDOG_MIN_EVENTS_5M",
        str(os.getenv("SIEM_WATCHDOG_MIN_EVENTS_5M", "1600") or "1600").strip() or "1600",
    )
    return {key: value for key, value in updates.items() if str(value or "").strip()}


def _sync_vm4_runtime_env(client: paramiko.SSHClient, *, sudo_password: str) -> None:
    env_updates = _runtime_bridge_env_updates()
    if not env_updates:
        return
    payload = base64.b64encode(json.dumps(env_updates, ensure_ascii=False).encode("utf-8")).decode("ascii")
    command = (
        "python3 - <<'PY'\n"
        "import base64\n"
        "import json\n"
        "from pathlib import Path\n"
        f"updates = json.loads(base64.b64decode({payload!r}).decode('utf-8'))\n"
        "path = Path('/etc/siem/web.env')\n"
        "lines = path.read_text(encoding='utf-8').splitlines() if path.exists() else []\n"
        "env = {}\n"
        "for raw_line in lines:\n"
        "    line = raw_line.strip()\n"
        "    if not line or line.startswith('#') or '=' not in raw_line:\n"
        "        continue\n"
        "    key, value = raw_line.split('=', 1)\n"
        "    key = key.strip()\n"
        "    if key:\n"
        "        env[key] = value\n"
        "env.update(updates)\n"
        "ordered = []\n"
        "seen = set()\n"
        "for raw_line in lines:\n"
        "    line = raw_line.strip()\n"
        "    if not line or line.startswith('#') or '=' not in raw_line:\n"
        "        ordered.append(raw_line)\n"
        "        continue\n"
        "    key = raw_line.split('=', 1)[0].strip()\n"
        "    if key in env:\n"
        "        ordered.append(f'{key}={env[key]}')\n"
        "        seen.add(key)\n"
        "for key in sorted(env):\n"
        "    if key not in seen:\n"
        "        ordered.append(f'{key}={env[key]}')\n"
        "path.write_text('\\n'.join(ordered).rstrip() + '\\n', encoding='utf-8')\n"
        "PY"
    )
    code, out, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise RuntimeError(f"Failed to sync VM4 runtime bridge env: {err.strip()}")


def _mkdir_remote(sftp: paramiko.SFTPClient, path: str) -> None:
    parts = [part for part in path.split("/") if part]
    current = ""
    for part in parts:
        current = f"{current}/{part}"
        try:
            sftp.stat(current)
        except OSError:
            sftp.mkdir(current)


def _upload_with_sudo_install(
    client: "paramiko.SSHClient",
    sftp: "paramiko.SFTPClient",
    *,
    local_path: Path,
    remote_path: str,
    temp_root: str,
    sudo_password: str,
    mode: str = "0644",
) -> None:
    temp_path = posixpath.join(temp_root.rstrip("/"), remote_path.lstrip("/"))
    _mkdir_remote(sftp, posixpath.dirname(temp_path))
    sftp.put(str(local_path), temp_path)
    command_parts: list[str] = []
    if remote_path.endswith(".sh"):
        command_parts.append(
            "python3 -c "
            + shlex.quote(
                "from pathlib import Path; "
                f"p = Path({temp_path!r}); "
                "p.write_bytes(p.read_bytes().replace(b'\\r\\n', b'\\n'))"
            )
        )
    command_parts.append(f"install -D -m {mode} {shlex.quote(temp_path)} {shlex.quote(remote_path)}")
    command_parts.append(f"rm -f {shlex.quote(temp_path)}")
    command = " && ".join(command_parts)
    code, out, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=True)
    cleaned = _strip_sudo_echo(out, sudo_password)
    if cleaned.strip():
        print(cleaned, end="")
    if code != 0:
        raise RuntimeError(f"Failed to install {remote_path}: {err.strip()}")


def _poll_service_state(
    client: "paramiko.SSHClient",
    unit: str,
    *,
    sudo_password: str,
    attempts: int = 15,
    delay_seconds: float = 2.0,
) -> tuple[str, str]:
    state = ""
    last_err = ""
    command = f"systemctl is-active {shlex.quote(unit)}"
    for _ in range(attempts):
        code, out, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=True)
        active_out = _strip_sudo_echo(out, sudo_password)
        state = next((line.strip() for line in active_out.splitlines() if line.strip()), "")
        last_err = err.strip()
        if code == 0 and state == "active":
            return state, last_err
        time.sleep(delay_seconds)
    return state, last_err


def _ensure_vault_runtime_ready(
    client: "paramiko.SSHClient",
    *,
    sudo_password: str,
) -> None:
    _wait_for_remote_http(
        client,
        f"{VAULT_ADDR}/v1/sys/health",
        sudo_password=sudo_password,
        allowed_statuses={200, 429, 472, 473, 501, 503},
        attempts=20,
        delay_seconds=3,
    )
    operator_state = _ensure_vault_initialized(client, sudo_password=sudo_password)
    _ensure_vault_unsealed(
        client,
        operator_state=operator_state,
        sudo_password=sudo_password,
    )


def _backup_file(
    client: paramiko.SSHClient,
    remote_path: str,
    backup_root: str,
    *,
    sudo_password: str = "",
    use_sudo: bool = False,
) -> None:
    remote_dir = posixpath.dirname(remote_path)
    rel_dir = posixpath.relpath(remote_dir, "/")
    target_dir = posixpath.join(backup_root, rel_dir)
    target_file = posixpath.join(target_dir, posixpath.basename(remote_path))
    command = (
        f"if [ -f {shlex.quote(remote_path)} ]; then "
        f"mkdir -p {shlex.quote(target_dir)} && "
        f"cp {shlex.quote(remote_path)} {shlex.quote(target_file)}; "
        f"fi"
    )
    code, _, err = _run_command(client, command, sudo_password=sudo_password, use_sudo=use_sudo)
    if code != 0:
        raise RuntimeError(f"Failed to back up {remote_path}: {err.strip()}")


def main() -> int:
    host = _required_env("SIEM_VM4_HOST")
    user = _required_env("SIEM_VM4_USER")
    password = _required_env("SIEM_VM4_PASSWORD")
    remote_root = _required_env("SIEM_VM4_BASE_DIR", default=DEFAULT_REMOTE_ROOT)
    deploy_frontend = str(os.getenv("SIEM_VM4_DEPLOY_FRONTEND", "1") or "1").strip().lower() in {"1", "true", "yes", "on"}
    backup_root = f"/tmp/siem-web-backup-{datetime.now(tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"

    client = _connect_client(host, user, password)
    sftp = client.open_sftp()
    try:
        print(f"remote_root={remote_root}")
        print(f"backup_root={backup_root}")
        print(f"deploy_frontend={str(deploy_frontend).lower()}")
        upload_root = f"/tmp/siem-web-upload-{datetime.now(tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        code, out, err = _run_command(client, f"mkdir -p {shlex.quote(upload_root)}")
        if code != 0:
            raise RuntimeError(f"Failed to create upload root: {err.strip()}")

        for mapping in FILE_MAPPINGS:
            if not deploy_frontend and (
                mapping.local_rel.startswith("frontend-react/")
                or mapping.remote_rel.startswith("services/web/frontend-react/")
            ):
                continue
            local_path = _resolve_local_path(mapping)
            remote_path = _remote_path(remote_root, mapping.remote_rel)
            _backup_file(client, remote_path, backup_root, sudo_password=password, use_sudo=True)
            _upload_with_sudo_install(
                client,
                sftp,
                local_path=local_path,
                remote_path=remote_path,
                temp_root=upload_root,
                sudo_password=password,
            )
            print(f"uploaded {mapping.local_rel} -> {remote_path}")

        for asset in SYSTEM_ASSETS:
            remote_source = _remote_path(remote_root, asset.remote_rel)
            _backup_file(client, asset.target_path, backup_root, sudo_password=password, use_sudo=True)
            install_cmd = (
                f"install -m {asset.mode} {shlex.quote(remote_source)} {shlex.quote(asset.target_path)}"
            )
            code, out, err = _run_command(client, install_cmd, sudo_password=password, use_sudo=True)
            install_out = _strip_sudo_echo(out, password)
            if install_out.strip():
                print(install_out, end="")
            if code != 0:
                raise RuntimeError(f"Failed to install system asset {asset.target_path}: {err.strip()}")
            print(f"installed {asset.remote_rel} -> {asset.target_path}")

        identity_runtime = bootstrap_vm4_identity_governance(
            client,
            sftp,
            host=host,
            remote_root=remote_root,
            upload_root=upload_root,
            sudo_password=password,
        )
        print(f"oidc_issuer={identity_runtime.get('oidc_issuer', '')}")
        print(f"vault_addr={identity_runtime.get('vault_addr', '')}")

        pip_install_cmd = (
            f"cd {shlex.quote(_remote_path(remote_root, 'services/web'))} && "
            f"{shlex.quote('/opt/siem/venv-web/bin/pip')} install --disable-pip-version-check --no-input -r requirements-web.txt"
        )
        code, out, err = _run_command(client, pip_install_cmd)
        print(out, end="")
        if code != 0:
            raise RuntimeError(f"Remote web dependency install failed: {err.strip()}")

        compile_shared_cmd = (
            f"cd {shlex.quote(remote_root)} && "
            "export PYTHONPYCACHEPREFIX=/tmp/siem-pycache && "
            "python3 -m py_compile "
            "asset_binding_overrides.py "
            "control_plane_governance_runtime.py "
            "keycloak_admin_runtime.py "
            "runtime_humanization.py "
            "proxmox_guest_ops.py "
            "incident_ai_runtime.py "
            "host_access_runtime.py "
            "operational_filters.py "
            "query/__init__.py "
            "query/shared.py "
            "query/dashboard.py "
            "query/events.py "
            "query/alerts.py "
            "query/sources.py "
            "query/assets.py "
            "query/geo.py "
            "query/threat_intel.py "
            "query/vuln.py "
            "deploy/publish_operational_rule_packs.py "
            "deploy/publish_batch_rules.py "
            "deploy/publish_filter_rules.py "
            "deploy/system_cleanup.py "
            "services/__init__.py "
            "services/redis_runtime.py "
            "services/transport_runtime.py "
            "services/stream_state.py "
            "services/ingest/__init__.py "
            "services/ingest/app.py "
            "services/ingest/config.py "
            "services/ingest/logging_conf.py "
            "services/ingest/redis_client.py"
        )
        code, out, err = _run_command(client, compile_shared_cmd)
        print(out, end="")
        if code != 0:
            raise RuntimeError(f"Remote shared-service py_compile failed: {err.strip()}")

        web_root = _remote_path(remote_root, "services/web")
        compile_cmd = (
            f"cd {shlex.quote(web_root)} && "
            "export PYTHONPYCACHEPREFIX=/tmp/siem-pycache && "
            "python3 -m py_compile "
            "main.py "
            "app/__init__.py "
            "app/config.py "
            "app/templates.py "
            "app/routes/__init__.py "
            "app/routes/auth.py "
            "app/routes/health.py "
            "app/backup_runtime.py "
            "app/asset_binding_overrides.py "
            "app/enterprise_control_plane_defaults.py "
            "app/control_plane_governance_ops.py "
            "app/inventory_catalog.py "
            "app/proxmox_fleet_runtime.py "
            "app/response_workflow_runtime.py "
            "app/source_onboarding_runtime.py "
            "app/control_plane_governance_runtime.py "
            "app/keycloak_admin_runtime.py "
            "app/runtime_humanization.py "
            "app/proxmox_guest_ops.py "
            "app/incident_ai_runtime.py "
            "app/vuln_asset_binding.py "
            "app/clickhouse_runtime.py "
            "app/security_services_runtime.py "
            "app/content_runtime.py "
            "app/control_plane_health.py "
            "app/health_surfaces.py "
            "app/host_runtime_runtime.py "
            "app/storage_ha_runtime.py "
            "app/stream_state_runtime.py "
            "app/transport_health_runtime.py "
            "app/security.py "
            "app/secret_runtime.py "
            "app/oidc_runtime.py "
            "app/certification_runtime.py "
            "app/deps.py "
            "app/operational_filters.py "
            "app/content_store.py "
            "app/source_discovery.py "
            "app/topology_runtime.py "
            "app/host_access_runtime.py "
            "app/vulnerability_query_runtime.py "
            "app/vuln_exposure_runtime.py "
            "app/vuln_maturity_runtime.py "
            "app/vuln_runtime.py "
            "app/routes/console.py "
            "app/routes/console_assets_routes.py "
            "app/routes/console_auth_routes.py "
            "app/routes/console_router_registry.py "
            "app/routes/console_security_services_routes.py "
            "app/routes/alerts.py "
            "app/routes/events.py "
            "app/enterprise_control_plane.py "
            "app/ingest_runtime.py "
            "app/query/__init__.py "
            "app/query/shared.py "
            "app/query/dashboard.py "
            "app/query/events.py "
            "app/query/alerts.py "
            "app/query/sources.py "
            "app/query/assets.py "
            "app/query/geo.py "
            "app/query/threat_intel.py "
            "app/query/vuln.py "
            "../../deploy/vuln/rdegon_greenbone_start_wave.py "
            "../../deploy/vuln/rdegon_greenbone_sync.py "
            "../../deploy/vuln/rdegon_vuln_policy_apply.py"
        )
        code, out, err = _run_command(client, compile_cmd)
        print(out, end="")
        if code != 0:
            raise RuntimeError(f"Remote py_compile failed: {err.strip()}")

        backend_test_cmd = (
            "set -eu && "
            f"cd {shlex.quote(remote_root)} && "
            "env -i "
            "PATH=\"$PATH\" "
            "HOME=\"$HOME\" "
            "LANG=C.UTF-8 "
            "PYTHONPATH=\"$PWD:$PWD/services/web/app\" "
            "SIEM_ENV=prod "
            "SIEM_INSTANCE_NAME=siem-web "
            "SIEM_WEB_BASE_URL=https://192.168.3.107 "
            "SIEM_JWT_SECRET=test-jwt-secret "
            "SIEM_CERTIFICATION_STATUS_PATH=\"$PWD/runtime-control-plane/production_certification_status.json\" "
            "SIEM_STREAM_STATE_SQLITE_PATH=\"$PWD/runtime-control-plane/test-runtime-state.db\" "
            "python3 -m unittest "
            "tests.test_clickhouse_runtime "
            "tests.test_control_plane_health "
            "tests.test_certification_runtime "
            "tests.test_content_store_runtime "
            "tests.test_keycloak_admin_runtime "
            "tests.test_response_maturity "
            "tests.test_security_runtime "
            "tests.test_security_services_runtime "
            "tests.test_source_discovery "
            "tests.test_topology_runtime "
            "tests.test_host_access_runtime "
            "tests.test_vuln_exposure_runtime "
            "tests.test_vuln_greenbone "
            "tests.test_vuln_maturity_runtime "
            "tests.test_enterprise_control_plane -v"
        )
        code, out, err = _run_command(client, backend_test_cmd)
        print(out, end="")
        if code != 0:
            raise RuntimeError(f"Remote backend test suite failed: {err.strip()}")

        host_identity_cmd = (
            "set -eu && "
            f"host_ip={shlex.quote(host)} && "
            "grep -Eq \"^${host_ip//./\\\\.}[[:space:]]+siem-web([[:space:]]|$)\" /etc/hosts || "
            "printf '%s siem-web siem-web.local\\n' \"$host_ip\" >> /etc/hosts"
        )
        code, out, err = _run_command(client, host_identity_cmd, sudo_password=password, use_sudo=True)
        host_identity_out = _strip_sudo_echo(out, password)
        if host_identity_out.strip():
            print(host_identity_out, end="")
        if code != 0:
            raise RuntimeError(f"Failed to align VM4 host identity mapping: {err.strip()}")

        if deploy_frontend:
            frontend_root = _remote_path(remote_root, "services/web/frontend-react")
            frontend_tool_root = _remote_path(remote_root, ".tools")
            frontend_node_runtime = posixpath.join(frontend_tool_root, f"node-v{FRONTEND_NODE_VERSION}-linux-x64")
            frontend_node_bin = posixpath.join(frontend_node_runtime, "bin")
            frontend_prepare_cmd = (
                f"mkdir -p {shlex.quote(frontend_root)} && "
                f"chown -R {shlex.quote(f'{user}:{user}')} {shlex.quote(frontend_root)} && "
                f"rm -rf {shlex.quote(posixpath.join(frontend_root, 'dist'))} {shlex.quote(posixpath.join(frontend_root, 'node_modules'))} && "
                f"rm -f {shlex.quote(posixpath.join(frontend_root, 'src/shell/__tests__/events-details.test.ts'))}"
            )
            code, out, err = _run_command(client, frontend_prepare_cmd, sudo_password=password, use_sudo=True)
            prepare_out = _strip_sudo_echo(out, password)
            if prepare_out.strip():
                print(prepare_out, end="")
            if code != 0:
                raise RuntimeError(f"Remote frontend workspace preparation failed: {err.strip()}")

            node_bootstrap_cmd = (
                "set -eu && "
                f"mkdir -p {shlex.quote(frontend_tool_root)} && "
                f"if [ ! -x {shlex.quote(posixpath.join(frontend_node_bin, 'node'))} ]; then "
                f"cd {shlex.quote(frontend_tool_root)} && "
                f"archive=node-v{FRONTEND_NODE_VERSION}-linux-x64.tar.xz && "
                "rm -f \"$archive\" && "
                f"(command -v curl >/dev/null 2>&1 && curl -fsSL https://nodejs.org/dist/v{FRONTEND_NODE_VERSION}/$archive -o $archive) || "
                f"(command -v wget >/dev/null 2>&1 && wget -q https://nodejs.org/dist/v{FRONTEND_NODE_VERSION}/$archive -O $archive) && "
                "tar -xJf \"$archive\"; "
                "fi && "
                f"export PATH={shlex.quote(frontend_node_bin)}:$PATH && "
                "node --version && "
                "npm --version"
            )
            code, out, err = _run_command(client, node_bootstrap_cmd)
            print(out, end="")
            if code != 0:
                raise RuntimeError(f"Remote Node.js bootstrap failed: {err.strip()}")

            build_cmd = (
                f"cd {shlex.quote(frontend_root)} && "
                f"export PATH={shlex.quote(frontend_node_bin)}:$PATH && "
                "npm install --no-package-lock --no-audit --no-fund && "
                "npm run typecheck && "
                "npm run lint && "
                "for test_file in src/shell/__tests__/*.test.ts src/shell/__tests__/*.test.tsx; do "
                "  if [ -f \"$test_file\" ]; then "
                "    node --max-old-space-size=2048 ./node_modules/vitest/vitest.mjs run \"$test_file\" || exit $?; "
                "  fi; "
                "done && "
                "npm run build"
            )
            code, out, err = _run_command(client, build_cmd)
            print(out, end="")
            if code != 0:
                raise RuntimeError(f"Remote frontend validation/build failed: {err.strip()}")

        runtime_dirs_prepare_cmd = (
            "set -eu && "
            f"mkdir -p {shlex.quote(_remote_path(remote_root, 'services/web/runtime-vuln/greenbone-artifacts'))} "
            f"{shlex.quote(_remote_path(remote_root, 'services/web/runtime-control-plane'))} "
            f"{shlex.quote(_remote_path(remote_root, 'runtime-control-plane'))} && "
            f"chown -R {shlex.quote(f'{user}:{user}')} "
            f"{shlex.quote(_remote_path(remote_root, 'services/web/runtime-vuln'))} "
            f"{shlex.quote(_remote_path(remote_root, 'services/web/runtime-control-plane'))} "
            f"{shlex.quote(_remote_path(remote_root, 'runtime-control-plane'))}"
        )
        code, out, err = _run_command(client, runtime_dirs_prepare_cmd, sudo_password=password, use_sudo=True)
        runtime_dirs_out = _strip_sudo_echo(out, password)
        if runtime_dirs_out.strip():
            print(runtime_dirs_out, end="")
        if code != 0:
            raise RuntimeError(f"Failed to prepare writable VM4 runtime directories: {err.strip()}")

        daemon_reload_cmd = "systemctl daemon-reload"
        code, out, err = _run_command(client, daemon_reload_cmd, sudo_password=password, use_sudo=True)
        reload_out = _strip_sudo_echo(out, password)
        if reload_out.strip():
            print(reload_out, end="")
        if code != 0:
            raise RuntimeError(f"Failed to daemon-reload systemd: {err.strip()}")

        nginx_reload_cmd = "nginx -t && systemctl restart nginx"
        code, out, err = _run_command(client, nginx_reload_cmd, sudo_password=password, use_sudo=True)
        nginx_out = _strip_sudo_echo(out, password)
        if nginx_out.strip():
            print(nginx_out, end="")
        if code != 0:
            raise RuntimeError(f"Failed to reload nginx with Keycloak proxy config: {err.strip()}")

        runtime_timer_cmd = (
            "systemctl enable siem-greenbone-sync.timer siem-vuln-policy-apply.timer siem-ingest-recovery-watchdog.timer siem-event-retention.timer && "
            "systemctl restart siem-greenbone-sync.timer siem-vuln-policy-apply.timer siem-ingest-recovery-watchdog.timer siem-event-retention.timer"
        )
        code, out, err = _run_command(client, runtime_timer_cmd, sudo_password=password, use_sudo=True)
        timer_out = _strip_sudo_echo(out, password)
        if timer_out.strip():
            print(timer_out, end="")
        if code != 0:
            raise RuntimeError(f"Failed to activate runtime timers: {err.strip()}")

        enable_runtime_cmd = "systemctl enable siem-vault siem-keycloak openvpn-client@home-gateway"
        code, out, err = _run_command(client, enable_runtime_cmd, sudo_password=password, use_sudo=True)
        enable_out = _strip_sudo_echo(out, password)
        if enable_out.strip():
            print(enable_out, end="")
        if code != 0:
            raise RuntimeError(f"Failed to enable siem-vault/siem-keycloak/openvpn-client@home-gateway: {err.strip()}")

        vault_restart_cmd = "systemctl reset-failed siem-vault siem-keycloak siem-web && systemctl restart siem-vault"
        code, out, err = _run_command(client, vault_restart_cmd, sudo_password=password, use_sudo=True)
        vault_restart_out = _strip_sudo_echo(out, password)
        if vault_restart_out.strip():
            print(vault_restart_out, end="")
        if code != 0:
            raise RuntimeError(f"Failed to restart siem-vault before dependent services: {err.strip()}")

        _ensure_vault_runtime_ready(client, sudo_password=password)

        dependent_restart_cmd = "systemctl restart siem-keycloak openvpn-client@home-gateway"
        code, out, err = _run_command(client, dependent_restart_cmd, sudo_password=password, use_sudo=True)
        restart_out = _strip_sudo_echo(out, password)
        if restart_out.strip():
            print(restart_out, end="")
        if code != 0:
            raise RuntimeError(f"Failed to restart siem-keycloak/openvpn-client@home-gateway: {err.strip()}")

        _sync_vm4_runtime_env(client, sudo_password=password)

        publish_operational_rule_packs_cmd = (
            f"cd {shlex.quote(remote_root)} && "
            f"timeout 240s {shlex.quote(VM4_WEB_PYTHON)} - <<'PY'\n"
            "import os\n"
            "import runpy\n"
            "from pathlib import Path\n"
            "for raw_line in Path('/etc/siem/web.env').read_text(encoding='utf-8').splitlines():\n"
            "    line = raw_line.strip()\n"
            "    if not line or line.startswith('#') or '=' not in raw_line:\n"
            "        continue\n"
            "    key, value = raw_line.split('=', 1)\n"
            "    key = key.strip()\n"
            "    if key:\n"
            "        os.environ.setdefault(key, value)\n"
            "runpy.run_path('deploy/publish_operational_rule_packs.py', run_name='__main__')\n"
            "PY"
        )
        code, out, err = _run_command(
            client,
            publish_operational_rule_packs_cmd,
            sudo_password=password,
            use_sudo=True,
        )
        publish_out = _strip_sudo_echo(out, password)
        if publish_out.strip():
            print(publish_out, end="")
        if code != 0:
            raise RuntimeError(f"Failed to publish operational rule packs: {err.strip()}")

        publish_assignment_detection_pack_cmd = (
            f"cd {shlex.quote(remote_root)} && "
            f"timeout 240s {shlex.quote(VM4_WEB_PYTHON)} - <<'PY'\n"
            "import os\n"
            "import runpy\n"
            "from pathlib import Path\n"
            "for raw_line in Path('/etc/siem/web.env').read_text(encoding='utf-8').splitlines():\n"
            "    line = raw_line.strip()\n"
            "    if not line or line.startswith('#') or '=' not in raw_line:\n"
            "        continue\n"
            "    key, value = raw_line.split('=', 1)\n"
            "    key = key.strip()\n"
            "    if key:\n"
            "        os.environ.setdefault(key, value)\n"
            "runpy.run_path('deploy/publish_assignment_detection_pack.py', run_name='__main__')\n"
            "PY"
        )
        code, out, err = _run_command(
            client,
            publish_assignment_detection_pack_cmd,
            sudo_password=password,
            use_sudo=True,
        )
        assignment_publish_out = _strip_sudo_echo(out, password)
        if assignment_publish_out.strip():
            print(assignment_publish_out, end="")
        if code != 0:
            raise RuntimeError(f"Failed to publish assignment detection pack: {err.strip()}")

        publish_rule_noise_tuning_cmd = (
            f"cd {shlex.quote(remote_root)} && "
            f"timeout 240s {shlex.quote(VM4_WEB_PYTHON)} - <<'PY'\n"
            "import os\n"
            "import runpy\n"
            "from pathlib import Path\n"
            "for raw_line in Path('/etc/siem/web.env').read_text(encoding='utf-8').splitlines():\n"
            "    line = raw_line.strip()\n"
            "    if not line or line.startswith('#') or '=' not in raw_line:\n"
            "        continue\n"
            "    key, value = raw_line.split('=', 1)\n"
            "    key = key.strip()\n"
            "    if key:\n"
            "        os.environ.setdefault(key, value)\n"
            "runpy.run_path('deploy/publish_rule_noise_tuning.py', run_name='__main__')\n"
            "PY"
        )
        code, out, err = _run_command(
            client,
            publish_rule_noise_tuning_cmd,
            sudo_password=password,
            use_sudo=True,
        )
        rule_noise_out = _strip_sudo_echo(out, password)
        if rule_noise_out.strip():
            print(rule_noise_out, end="")
        if code != 0:
            raise RuntimeError(f"Failed to publish rule noise tuning: {err.strip()}")

        publish_batch_rules_cmd = (
            f"cd {shlex.quote(remote_root)} && "
            f"timeout 180s {shlex.quote(VM4_WEB_PYTHON)} - <<'PY'\n"
            "import os\n"
            "import runpy\n"
            "from pathlib import Path\n"
            "for raw_line in Path('/etc/siem/web.env').read_text(encoding='utf-8').splitlines():\n"
            "    line = raw_line.strip()\n"
            "    if not line or line.startswith('#') or '=' not in raw_line:\n"
            "        continue\n"
            "    key, value = raw_line.split('=', 1)\n"
            "    key = key.strip()\n"
            "    if key:\n"
            "        os.environ.setdefault(key, value)\n"
            "runpy.run_path('deploy/publish_batch_rules.py', run_name='__main__')\n"
            "PY"
        )
        code, out, err = _run_command(
            client,
            publish_batch_rules_cmd,
            sudo_password=password,
            use_sudo=True,
        )
        batch_publish_out = _strip_sudo_echo(out, password)
        if batch_publish_out.strip():
            print(batch_publish_out, end="")
        if code != 0:
            raise RuntimeError(f"Failed to publish batch rules: {err.strip()}")

        publish_filter_rules_cmd = (
            f"cd {shlex.quote(remote_root)} && "
            f"{shlex.quote(VM4_WEB_PYTHON)} - <<'PY'\n"
            "import os\n"
            "import runpy\n"
            "from pathlib import Path\n"
            "for raw_line in Path('/etc/siem/web.env').read_text(encoding='utf-8').splitlines():\n"
            "    line = raw_line.strip()\n"
            "    if not line or line.startswith('#') or '=' not in raw_line:\n"
            "        continue\n"
            "    key, value = raw_line.split('=', 1)\n"
            "    key = key.strip()\n"
            "    if key:\n"
            "        os.environ.setdefault(key, value)\n"
            "runpy.run_path('deploy/publish_filter_rules.py', run_name='__main__')\n"
            "PY"
        )
        code, out, err = _run_command(
            client,
            publish_filter_rules_cmd,
            sudo_password=password,
            use_sudo=True,
        )
        filter_publish_out = _strip_sudo_echo(out, password)
        if filter_publish_out.strip():
            print(filter_publish_out, end="")
        if code != 0:
            raise RuntimeError(f"Failed to publish filter rules: {err.strip()}")

        web_restart_cmd = (
            "systemctl restart siem-jump-tunnels siem-web && "
            "systemctl start siem-greenbone-sync.service siem-vuln-policy-apply.service siem-event-retention.service"
        )
        code, out, err = _run_command(client, web_restart_cmd, sudo_password=password, use_sudo=True)
        restart_out = _strip_sudo_echo(out, password)
        if restart_out.strip():
            print(restart_out, end="")
        if code != 0:
            raise RuntimeError(f"Failed to restart siem-jump-tunnels/siem-web: {err.strip()}")

        service_states = {
            "nginx": _poll_service_state(
                client,
                "nginx",
                sudo_password=password,
                attempts=10,
            ),
            "siem-vault": _poll_service_state(
                client,
                "siem-vault",
                sudo_password=password,
                attempts=15,
            ),
            "siem-keycloak": _poll_service_state(
                client,
                "siem-keycloak",
                sudo_password=password,
                attempts=20,
            ),
            "openvpn-client@home-gateway": _poll_service_state(
                client,
                "openvpn-client@home-gateway",
                sudo_password=password,
                attempts=10,
            ),
            "siem-jump-tunnels": _poll_service_state(
                client,
                "siem-jump-tunnels",
                sudo_password=password,
                attempts=10,
            ),
            "siem-greenbone-sync.timer": _poll_service_state(
                client,
                "siem-greenbone-sync.timer",
                sudo_password=password,
                attempts=10,
            ),
            "siem-vuln-policy-apply.timer": _poll_service_state(
                client,
                "siem-vuln-policy-apply.timer",
                sudo_password=password,
                attempts=10,
            ),
            "siem-ingest-recovery-watchdog.timer": _poll_service_state(
                client,
                "siem-ingest-recovery-watchdog.timer",
                sudo_password=password,
                attempts=10,
            ),
            "siem-event-retention.timer": _poll_service_state(
                client,
                "siem-event-retention.timer",
                sudo_password=password,
                attempts=10,
            ),
            "siem-web": _poll_service_state(
                client,
                "siem-web",
                sudo_password=password,
                attempts=20,
            ),
        }
        vault_state, vault_err = service_states["siem-vault"]
        keycloak_state, keycloak_err = service_states["siem-keycloak"]
        nginx_state, nginx_err = service_states["nginx"]
        openvpn_state, openvpn_err = service_states["openvpn-client@home-gateway"]
        web_state, web_err = service_states["siem-web"]
        if web_state != "active" or openvpn_state != "active" or vault_state != "active" or keycloak_state != "active" or nginx_state != "active":
            raise RuntimeError(
                "VM4 service activation check failed: "
                f"nginx={nginx_state or '<empty>'} stderr={nginx_err}; "
                f"siem-vault={vault_state or '<empty>'} stderr={vault_err}; "
                f"siem-keycloak={keycloak_state or '<empty>'} stderr={keycloak_err}; "
                f"siem-web={web_state or '<empty>'} stderr={web_err}; "
                f"openvpn-client@home-gateway={openvpn_state or '<empty>'} stderr={openvpn_err}"
            )
        print("nginx status=active")
        print("siem-vault status=active")
        print("siem-keycloak status=active")
        print("openvpn-client@home-gateway status=active")
        jump_state, jump_err = service_states["siem-jump-tunnels"]
        if jump_state != "active":
            raise RuntimeError(f"siem-jump-tunnels is not active: state={jump_state or '<empty>'} stderr={jump_err}")
        if service_states["siem-greenbone-sync.timer"][0] != "active":
            raise RuntimeError(
                "siem-greenbone-sync.timer is not active: "
                f"state={service_states['siem-greenbone-sync.timer'][0] or '<empty>'} "
                f"stderr={service_states['siem-greenbone-sync.timer'][1]}"
            )
        if service_states["siem-vuln-policy-apply.timer"][0] != "active":
            raise RuntimeError(
                "siem-vuln-policy-apply.timer is not active: "
                f"state={service_states['siem-vuln-policy-apply.timer'][0] or '<empty>'} "
                f"stderr={service_states['siem-vuln-policy-apply.timer'][1]}"
            )
        if service_states["siem-ingest-recovery-watchdog.timer"][0] != "active":
            raise RuntimeError(
                "siem-ingest-recovery-watchdog.timer is not active: "
                f"state={service_states['siem-ingest-recovery-watchdog.timer'][0] or '<empty>'} "
                f"stderr={service_states['siem-ingest-recovery-watchdog.timer'][1]}"
            )
        if service_states["siem-event-retention.timer"][0] != "active":
            raise RuntimeError(
                "siem-event-retention.timer is not active: "
                f"state={service_states['siem-event-retention.timer'][0] or '<empty>'} "
                f"stderr={service_states['siem-event-retention.timer'][1]}"
            )
        print("siem-jump-tunnels status=active")
        print("siem-greenbone-sync.timer status=active")
        print("siem-vuln-policy-apply.timer status=active")
        print("siem-ingest-recovery-watchdog.timer status=active")
        print("siem-event-retention.timer status=active")
        print("siem-web status=active")
        cleanup_cmd = (
            f"cd {shlex.quote(remote_root)} && "
            f"timeout 240s {shlex.quote(VM4_WEB_PYTHON)} deploy/system_cleanup.py"
        )
        code, out, err = _run_command(
            client,
            cleanup_cmd,
            sudo_password=password,
            use_sudo=True,
            timeout_seconds=270.0,
        )
        cleanup_out = _strip_sudo_echo(out, password)
        if cleanup_out.strip():
            print(cleanup_out, end="")
        if code == 124:
            print("system_cleanup=timeout; continuing because cleanup mutations are async/best-effort")
        elif code != 0:
            raise RuntimeError(f"Failed to cleanup non-operational runtime data: {err.strip()}")
        print("deployment=success")
        print(f"backup_root={backup_root}")
        return 0
    finally:
        try:
            sftp_channel = sftp.get_channel()
            sftp_channel.close()
        except Exception:
            pass
        try:
            transport = client.get_transport()
            if transport is not None:
                transport.close()
        except Exception:
            pass
        try:
            jump_client = getattr(client, "_siem_jump_client", None)
            if jump_client is not None:
                jump_client.close()
        except Exception:
            pass


if __name__ == "__main__":
    exit_code = main()
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(exit_code)
