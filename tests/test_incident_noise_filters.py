import importlib.util
import json
import sys
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ROOT_PACKAGE = "fake_incident_filters"
APP_PACKAGE = f"{ROOT_PACKAGE}.app"
ROUTES_PACKAGE = f"{APP_PACKAGE}.routes"


def _clear_fake_modules() -> None:
    for name in ("fastapi", "fastapi.responses", "fastapi.templating", "operational_filters"):
        sys.modules.pop(name, None)
    for name in list(sys.modules):
        if name == ROOT_PACKAGE or name.startswith(f"{ROOT_PACKAGE}."):
            sys.modules.pop(name, None)


def _install_alert_stubs() -> None:
    fastapi_module = types.ModuleType("fastapi")

    class APIRouter:
        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            def decorator(fn):
                return fn

            return decorator

        def post(self, *args, **kwargs):  # noqa: ANN002, ANN003
            def decorator(fn):
                return fn

            return decorator

    class Request:
        url = types.SimpleNamespace(path="/", query="")

    def Depends(dependency=None):  # noqa: N802
        return dependency

    def Query(default=None, *args, **kwargs):  # noqa: N802, ANN002, ANN003
        return default

    def Body(default=None, *args, **kwargs):  # noqa: N802, ANN002, ANN003
        return default

    fastapi_module.APIRouter = APIRouter
    fastapi_module.Body = Body
    fastapi_module.Depends = Depends
    fastapi_module.Query = Query
    fastapi_module.Request = Request
    sys.modules["fastapi"] = fastapi_module

    responses_module = types.ModuleType("fastapi.responses")

    class Response:
        pass

    class HTMLResponse:
        pass

    class JSONResponse:
        def __init__(self, content=None, status_code: int = 200) -> None:  # noqa: ANN001
            self.content = content
            self.status_code = status_code

    class RedirectResponse:
        def __init__(self, url: str, status_code: int = 302) -> None:
            self.url = url
            self.status_code = status_code

    responses_module.Response = Response
    responses_module.HTMLResponse = HTMLResponse
    responses_module.JSONResponse = JSONResponse
    responses_module.RedirectResponse = RedirectResponse
    sys.modules["fastapi.responses"] = responses_module

    root_package = types.ModuleType(ROOT_PACKAGE)
    root_package.__path__ = []  # type: ignore[attr-defined]
    sys.modules[ROOT_PACKAGE] = root_package

    app_package = types.ModuleType(APP_PACKAGE)
    app_package.__path__ = []  # type: ignore[attr-defined]
    sys.modules[APP_PACKAGE] = app_package

    routes_package = types.ModuleType(ROUTES_PACKAGE)
    routes_package.__path__ = []  # type: ignore[attr-defined]
    sys.modules[ROUTES_PACKAGE] = routes_package

    auth_module = types.ModuleType(f"{ROUTES_PACKAGE}.auth")
    auth_module.canonical_ui_redirect_path = lambda path: "/app/dashboards"  # noqa: E731
    auth_module.get_current_user = lambda: None  # noqa: E731
    sys.modules[f"{ROUTES_PACKAGE}.auth"] = auth_module

    security_module = types.ModuleType(f"{APP_PACKAGE}.security")
    security_module.require_permissions = lambda *args, **kwargs: (lambda: True)  # noqa: E731
    sys.modules[f"{APP_PACKAGE}.security"] = security_module

    deps_module = types.ModuleType(f"{APP_PACKAGE}.deps")
    deps_module.INCIDENT_STATUS_TRANSITIONS = {}
    deps_module.fetch_alert_history = lambda *args, **kwargs: []  # noqa: E731
    deps_module.fetch_alert_metrics = lambda *args, **kwargs: {}  # noqa: E731
    deps_module.fetch_alerts_agg = lambda *args, **kwargs: []  # noqa: E731
    deps_module.fetch_alerts_raw = lambda *args, **kwargs: []  # noqa: E731
    deps_module.fetch_incident_detail_bundle = lambda *args, **kwargs: {}  # noqa: E731
    deps_module.update_alert_assignment = lambda *args, **kwargs: {}  # noqa: E731
    sys.modules[f"{APP_PACKAGE}.deps"] = deps_module

    incident_ai_module = types.ModuleType(f"{APP_PACKAGE}.incident_ai_runtime")
    incident_ai_module.get_incident_ai_assessment = lambda *args, **kwargs: None  # noqa: E731
    incident_ai_module.queue_incident_ai_assessment = lambda *args, **kwargs: {}  # noqa: E731
    incident_ai_module.run_incident_host_action = lambda *args, **kwargs: {}  # noqa: E731
    sys.modules[f"{APP_PACKAGE}.incident_ai_runtime"] = incident_ai_module

    from services.web.app.operational_filters import contains_non_operational_marker, is_non_operational_record

    operational_filters_module = types.ModuleType(f"{APP_PACKAGE}.operational_filters")
    operational_filters_module.contains_non_operational_marker = contains_non_operational_marker
    operational_filters_module.is_non_operational_record = is_non_operational_record
    sys.modules[f"{APP_PACKAGE}.operational_filters"] = operational_filters_module
    sys.modules["operational_filters"] = operational_filters_module

    templates_module = types.ModuleType(f"{APP_PACKAGE}.templates")
    templates_module.templates = object()
    sys.modules[f"{APP_PACKAGE}.templates"] = templates_module

    ui_text_module = types.ModuleType(f"{APP_PACKAGE}.ui_text")
    ui_text_module.ui_context = lambda *args, **kwargs: {}  # noqa: E731
    sys.modules[f"{APP_PACKAGE}.ui_text"] = ui_text_module


def _load_alerts_module():
    spec = importlib.util.spec_from_file_location(f"{ROUTES_PACKAGE}.alerts", ROOT / "services" / "web" / "app" / "routes" / "alerts.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    module.__package__ = ROUTES_PACKAGE
    sys.modules[f"{ROUTES_PACKAGE}.alerts"] = module
    spec.loader.exec_module(module)
    return module


def _load_query_shared_module():
    spec = importlib.util.spec_from_file_location("query_shared_for_tests", ROOT / "query" / "shared.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["query_shared_for_tests"] = module
    spec.loader.exec_module(module)
    return module


class IncidentNoiseFilterTests(unittest.TestCase):
    def setUp(self) -> None:
        _clear_fake_modules()
        _install_alert_stubs()
        self.alerts_module = _load_alerts_module()
        self.query_shared_module = _load_query_shared_module()

    def tearDown(self) -> None:
        _clear_fake_modules()
        sys.modules.pop("query_shared_for_tests", None)

    def test_vm4_smoke_records_are_marked_non_operational(self) -> None:
        self.assertTrue(self.query_shared_module.is_non_operational_inventory_record({"actor": "vm4-smoke"}))
        self.assertTrue(self.query_shared_module.is_non_operational_inventory_record({"title": "Smoke token"}))

    def test_runtime_test_sources_are_hidden_from_incident_views(self) -> None:
        self.assertTrue(self.alerts_module._is_internal_maintenance_alert({"source": "win-rtx-test"}))
        self.assertTrue(self.alerts_module._is_internal_maintenance_alert({"entity_key": "test-incident-001"}))

    def test_host_runtime_agent_install_is_hidden_as_internal_maintenance(self) -> None:
        row = {
            "context_json": json.dumps(
                {
                    "process_command": "install -m 0644 /tmp/siem-host-runtime-agent.service /etc/systemd/system/siem-host-runtime-agent.service"
                }
            )
        }
        self.assertTrue(self.alerts_module._is_internal_maintenance_alert(row))

    def test_audit_rule_reload_is_hidden_as_internal_maintenance(self) -> None:
        row = {
            "context_json": json.dumps(
                {
                    "process_command": "/sbin/auditctl -R /etc/audit/audit.rules"
                }
            )
        }
        self.assertTrue(self.alerts_module._is_internal_maintenance_alert(row))


if __name__ == "__main__":
    unittest.main()
