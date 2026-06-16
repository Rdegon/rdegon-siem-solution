import importlib.util
import sys
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ROOT_PACKAGE = "fake_auth_redirects"
APP_PACKAGE = f"{ROOT_PACKAGE}.app"
ROUTES_PACKAGE = f"{APP_PACKAGE}.routes"


def _clear_fake_modules() -> None:
    for name in ("fastapi", "fastapi.responses", "fastapi.templating"):
        sys.modules.pop(name, None)
    for name in list(sys.modules):
        if name == ROOT_PACKAGE or name.startswith(f"{ROOT_PACKAGE}."):
            sys.modules.pop(name, None)


def _install_stubs() -> None:
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

    class HTTPException(Exception):
        def __init__(self, status_code: int, detail: str = "", headers=None) -> None:
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail
            self.headers = headers or {}

    class Request:
        query_params = {}
        cookies = {}
        url = types.SimpleNamespace(path="/", query="")

    def Depends(dependency=None):  # noqa: N802
        return dependency

    def Form(default=None, *args, **kwargs):  # noqa: N802, ANN002, ANN003
        return default

    fastapi_module.APIRouter = APIRouter
    fastapi_module.Depends = Depends
    fastapi_module.Form = Form
    fastapi_module.HTTPException = HTTPException
    fastapi_module.Request = Request
    fastapi_module.status = types.SimpleNamespace(
        HTTP_302_FOUND=302,
        HTTP_303_SEE_OTHER=303,
        HTTP_307_TEMPORARY_REDIRECT=307,
        HTTP_400_BAD_REQUEST=400,
        HTTP_401_UNAUTHORIZED=401,
        HTTP_403_FORBIDDEN=403,
        HTTP_429_TOO_MANY_REQUESTS=429,
        HTTP_503_SERVICE_UNAVAILABLE=503,
    )
    sys.modules["fastapi"] = fastapi_module

    responses_module = types.ModuleType("fastapi.responses")

    class Response:
        pass

    class RedirectResponse:
        def __init__(self, url: str, status_code: int = 302) -> None:
            self.url = url
            self.status_code = status_code

        def set_cookie(self, *args, **kwargs):  # noqa: ANN002, ANN003
            return None

        def delete_cookie(self, *args, **kwargs):  # noqa: ANN002, ANN003
            return None

    responses_module.Response = Response
    responses_module.RedirectResponse = RedirectResponse
    sys.modules["fastapi.responses"] = responses_module

    templating_module = types.ModuleType("fastapi.templating")

    class Jinja2Templates:
        def __init__(self, directory: str) -> None:  # noqa: ARG002
            pass

        def TemplateResponse(self, template: str, payload: dict, status_code: int = 200):  # noqa: ANN001
            return {"template": template, "payload": payload, "status_code": status_code}

    templating_module.Jinja2Templates = Jinja2Templates
    sys.modules["fastapi.templating"] = templating_module

    root_package = types.ModuleType(ROOT_PACKAGE)
    root_package.__path__ = []  # type: ignore[attr-defined]
    sys.modules[ROOT_PACKAGE] = root_package

    app_package = types.ModuleType(APP_PACKAGE)
    app_package.__path__ = []  # type: ignore[attr-defined]
    sys.modules[APP_PACKAGE] = app_package

    routes_package = types.ModuleType(ROUTES_PACKAGE)
    routes_package.__path__ = []  # type: ignore[attr-defined]
    sys.modules[ROUTES_PACKAGE] = routes_package

    config_module = types.ModuleType(f"{APP_PACKAGE}.config")
    config_module.CONFIG = types.SimpleNamespace(base_url="https://example.test", jwt_expires_minutes=60)
    sys.modules[f"{APP_PACKAGE}.config"] = config_module

    oidc_module = types.ModuleType(f"{APP_PACKAGE}.oidc_runtime")
    oidc_module.build_authorize_redirect = lambda redirect_uri, next_path: ("https://idp.example/authorize", "state")  # noqa: E731
    oidc_module.finalize_callback = lambda **kwargs: {}  # noqa: E731
    oidc_module.oidc_enabled = lambda: False  # noqa: E731
    oidc_module.provider_status = lambda: {"healthy": False, "issuer": ""}  # noqa: E731
    oidc_module.providers_inventory = lambda: []  # noqa: E731
    sys.modules[f"{APP_PACKAGE}.oidc_runtime"] = oidc_module

    access_module = types.ModuleType(f"{APP_PACKAGE}.control_plane_access_ops")
    access_module.record_break_glass_session = lambda *args, **kwargs: {}  # noqa: E731
    access_module.resolve_keycloak_principal_access = lambda *args, **kwargs: {"allowed": True, "role": "admin", "permissions": []}  # noqa: E731
    sys.modules[f"{APP_PACKAGE}.control_plane_access_ops"] = access_module

    security_module = types.ModuleType(f"{APP_PACKAGE}.security")

    class CurrentUser:
        def __init__(self, username: str = "admin", role: str = "admin") -> None:
            self.username = username
            self.role = role
            self.permissions = []

    security_module.CurrentUser = CurrentUser
    security_module.authenticate_user = lambda username, password: CurrentUser(username=username, role="admin")  # noqa: E731
    security_module.check_auth_rate_limit = lambda request: {"blocked": False, "client_ip": "127.0.0.1"}  # noqa: E731
    security_module.create_access_token = lambda **kwargs: "token"  # noqa: E731
    security_module.decode_access_token = lambda token: CurrentUser()  # noqa: E731
    security_module.get_token_from_request = lambda request: None  # noqa: E731
    security_module.issue_csrf_token = lambda: "csrf-token"  # noqa: E731
    security_module.record_auth_failure = lambda request: {"blocked": False, "retry_after_seconds": 0}  # noqa: E731
    security_module.record_auth_success = lambda request: None  # noqa: E731
    sys.modules[f"{APP_PACKAGE}.security"] = security_module

    ui_text_module = types.ModuleType(f"{APP_PACKAGE}.ui_text")
    ui_text_module.UI_TEXT = {"ru": {}, "en": {}}
    ui_text_module.resolve_ui_lang = lambda request: "ru"  # noqa: E731
    sys.modules[f"{APP_PACKAGE}.ui_text"] = ui_text_module


def _load_auth_module():
    spec = importlib.util.spec_from_file_location(f"{ROUTES_PACKAGE}.auth", ROOT / "auth.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    module.__package__ = ROUTES_PACKAGE
    sys.modules[f"{ROUTES_PACKAGE}.auth"] = module
    spec.loader.exec_module(module)
    return module


class LegacyUiRedirectTests(unittest.TestCase):
    def setUp(self) -> None:
        _clear_fake_modules()
        _install_stubs()
        self.module = _load_auth_module()

    def tearDown(self) -> None:
        _clear_fake_modules()

    def test_root_redirects_to_new_dashboard_shell(self) -> None:
        self.assertEqual(self.module.canonical_ui_redirect_path("/"), "/app/dashboards")

    def test_legacy_alerts_redirect_to_incidents_shell(self) -> None:
        self.assertEqual(self.module.canonical_ui_redirect_path("/alerts?view=raw&q=ssh"), "/app/incidents?view=raw&q=ssh")
        self.assertEqual(self.module.canonical_ui_redirect_path("/alerts_raw"), "/app/incidents?view=raw")

    def test_legacy_documentation_and_reports_redirect_to_new_shell(self) -> None:
        self.assertEqual(self.module.canonical_ui_redirect_path("/documentation"), "/app/docs")
        self.assertEqual(self.module.canonical_ui_redirect_path("/documentation/files/runbook.md"), "/app/docs/page/runbook.md")
        self.assertEqual(self.module.canonical_ui_redirect_path("/documentation/playbooks/linux-audit"), "/app/docs/playbooks/linux-audit")
        self.assertEqual(self.module.canonical_ui_redirect_path("/reports/rep-42?tab=findings"), "/app/vuln/reports/rep-42?tab=findings")

    def test_existing_app_paths_stay_under_app(self) -> None:
        self.assertEqual(self.module.canonical_ui_redirect_path("/app/events?window=72h"), "/app/events?window=72h")

    def test_api_paths_never_become_post_login_targets(self) -> None:
        self.assertEqual(self.module.canonical_ui_redirect_path("/api/dashboard/summary?window=24h"), "/app/dashboards")
        self.assertEqual(self.module.canonical_ui_redirect_path("/api/incidents?limit=50"), "/app/dashboards")


if __name__ == "__main__":
    unittest.main()
