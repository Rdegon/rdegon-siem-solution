import importlib.util
import hashlib
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_NAME = "fake_web_security"


def _resolve_module_path(*relative_candidates: str) -> Path:
    for candidate in relative_candidates:
        path = ROOT / candidate
        if path.exists():
            return path
    raise FileNotFoundError(f"Unable to resolve module path from candidates: {relative_candidates}")


def _clear_fake_modules() -> None:
    for name in list(sys.modules):
        if name == PACKAGE_NAME or name.startswith(f"{PACKAGE_NAME}."):
            sys.modules.pop(name, None)


def _install_dependency_stubs() -> None:
    fastapi_module = types.ModuleType("fastapi")

    class HTTPException(Exception):
        def __init__(self, status_code: int, detail: str = "", headers=None) -> None:
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail
            self.headers = headers or {}

    class Request:
        pass

    def Depends(dependency=None):  # noqa: N802
        return dependency

    fastapi_module.Depends = Depends
    fastapi_module.HTTPException = HTTPException
    fastapi_module.Request = Request
    fastapi_module.status = types.SimpleNamespace(
        HTTP_401_UNAUTHORIZED=401,
        HTTP_403_FORBIDDEN=403,
        HTTP_429_TOO_MANY_REQUESTS=429,
    )
    sys.modules["fastapi"] = fastapi_module

    security_module = types.ModuleType("fastapi.security")

    class OAuth2PasswordRequestForm:
        def __init__(self, username: str = "", password: str = "") -> None:
            self.username = username
            self.password = password

    security_module.OAuth2PasswordRequestForm = OAuth2PasswordRequestForm
    sys.modules["fastapi.security"] = security_module

    jose_module = types.ModuleType("jose")

    class JWTError(Exception):
        pass

    class _JWTModule:
        @staticmethod
        def encode(payload, secret, algorithm="HS256"):  # noqa: ARG004
            return json.dumps(payload, sort_keys=True)

        @staticmethod
        def decode(token, secret, algorithms=None):  # noqa: ARG004
            return json.loads(token)

    jose_module.JWTError = JWTError
    jose_module.jwt = _JWTModule
    sys.modules["jose"] = jose_module

    passlib_module = types.ModuleType("passlib")
    context_module = types.ModuleType("passlib.context")

    class CryptContext:
        def __init__(self, schemes=None, deprecated="auto") -> None:  # noqa: ARG002
            self.schemes = schemes or ["bcrypt"]

        def hash(self, password: str) -> str:
            digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
            return f"$2b$stub${digest}"

        def verify(self, password: str, password_hash: str) -> bool:
            return password_hash == self.hash(password)

        def identify(self, password_hash: str):
            return "bcrypt" if str(password_hash).startswith("$2") else None

    context_module.CryptContext = CryptContext
    passlib_module.context = context_module
    sys.modules["passlib"] = passlib_module
    sys.modules["passlib.context"] = context_module


def _load_package_module(module_name: str, file_name: str):
    spec = importlib.util.spec_from_file_location(
        f"{PACKAGE_NAME}.{module_name}",
        _resolve_module_path(file_name, f"services/web/app/{file_name}"),
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    if module_name == "config":
        package = types.ModuleType(PACKAGE_NAME)
        package.__path__ = []  # type: ignore[attr-defined]
        sys.modules[PACKAGE_NAME] = package
    module.__package__ = PACKAGE_NAME
    sys.modules[f"{PACKAGE_NAME}.{module_name}"] = module
    spec.loader.exec_module(module)
    return module


class _FakeClient:
    def __init__(self, host: str) -> None:
        self.host = host


class _FakeRequest:
    def __init__(self, host: str = "127.0.0.1", forwarded_for: str = "") -> None:
        self.client = _FakeClient(host)
        self.headers = {}
        if forwarded_for:
            self.headers["x-forwarded-for"] = forwarded_for


class SecurityRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_env = {
            key: os.environ.get(key)
            for key in (
                "SIEM_ENV",
                "SIEM_INSTANCE_NAME",
                "SIEM_LOG_LEVEL",
                "SIEM_CH_HOST",
                "SIEM_CH_PORT",
                "SIEM_CH_DB",
                "SIEM_CH_USER",
                "SIEM_CH_PASSWORD",
                "SIEM_WEB_BIND_HOST",
                "SIEM_WEB_BIND_PORT",
                "SIEM_WEB_BASE_URL",
                "SIEM_JWT_SECRET",
                "SIEM_JWT_EXPIRES_MINUTES",
                "SIEM_ADMIN_DEFAULT_USER",
                "SIEM_ADMIN_DEFAULT_PASSWORD",
                "SIEM_ADMIN_DEFAULT_PASSWORD_HASH",
                "SIEM_WEB_USERS_JSON",
                "SIEM_AUTH_RATE_LIMIT_WINDOW_SECONDS",
                "SIEM_AUTH_RATE_LIMIT_MAX_ATTEMPTS",
                "SIEM_AUTH_RATE_LIMIT_LOCKOUT_SECONDS",
                "SIEM_INGEST_TLS_VERIFY",
                "SIEM_INGEST_TLS_CA_FILE",
            )
        }
        os.environ["SIEM_ENV"] = "prod"
        os.environ["SIEM_INSTANCE_NAME"] = "siem-web"
        os.environ["SIEM_LOG_LEVEL"] = "INFO"
        os.environ["SIEM_CH_HOST"] = "127.0.0.1"
        os.environ["SIEM_CH_PORT"] = "8123"
        os.environ["SIEM_CH_DB"] = "siem"
        os.environ["SIEM_CH_USER"] = "siem"
        os.environ["SIEM_CH_PASSWORD"] = "secret"
        os.environ["SIEM_WEB_BIND_HOST"] = "127.0.0.1"
        os.environ["SIEM_WEB_BIND_PORT"] = "8000"
        os.environ["SIEM_WEB_BASE_URL"] = "https://192.168.1.39"
        os.environ["SIEM_JWT_SECRET"] = "jwt-secret"
        os.environ["SIEM_JWT_EXPIRES_MINUTES"] = "480"
        os.environ["SIEM_ADMIN_DEFAULT_USER"] = "admin"
        os.environ["SIEM_ADMIN_DEFAULT_PASSWORD"] = "admin-password"
        os.environ.pop("SIEM_ADMIN_DEFAULT_PASSWORD_HASH", None)
        os.environ["SIEM_WEB_USERS_JSON"] = ""
        os.environ["SIEM_AUTH_RATE_LIMIT_WINDOW_SECONDS"] = "300"
        os.environ["SIEM_AUTH_RATE_LIMIT_MAX_ATTEMPTS"] = "5"
        os.environ["SIEM_AUTH_RATE_LIMIT_LOCKOUT_SECONDS"] = "900"
        os.environ.pop("SIEM_INGEST_TLS_VERIFY", None)
        os.environ.pop("SIEM_INGEST_TLS_CA_FILE", None)
        _clear_fake_modules()
        sys.modules.pop("ingest_runtime", None)

    def tearDown(self) -> None:
        _clear_fake_modules()
        sys.modules.pop("ingest_runtime", None)
        for key, value in self.original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _load_security_module(self):
        _clear_fake_modules()
        _install_dependency_stubs()
        _load_package_module("config", "config.py")
        control_plane_stub = types.ModuleType(f"{PACKAGE_NAME}.enterprise_control_plane")
        control_plane_stub.load_local_user_auth_records = lambda: []
        sys.modules[f"{PACKAGE_NAME}.enterprise_control_plane"] = control_plane_stub
        return _load_package_module("security", "security.py")

    def test_plaintext_user_records_remain_backward_compatible(self) -> None:
        os.environ["SIEM_WEB_USERS_JSON"] = json.dumps([{"username": "analyst", "password": "plain-secret", "role": "analyst"}])
        module = self._load_security_module()

        user = module.authenticate_user("analyst", "plain-secret")
        summary = module.get_local_auth_summary()

        self.assertIsNotNone(user)
        self.assertEqual(user.role, "analyst")
        self.assertEqual(summary["local_users_plaintext"], 1)
        self.assertEqual(summary["local_users_hashed"], 0)

    def test_vpn_permissions_are_read_only_for_viewer_and_analyst_by_default(self) -> None:
        module = self._load_security_module()

        self.assertIn("vpn:view", module.ROLE_PERMISSIONS["viewer"])
        self.assertIn("vpn:view", module.ROLE_PERMISSIONS["analyst"])
        self.assertNotIn("vpn:manage", module.ROLE_PERMISSIONS["viewer"])
        self.assertNotIn("vpn:manage", module.ROLE_PERMISSIONS["analyst"])
        self.assertNotIn("vpn:profile:issue", module.ROLE_PERMISSIONS["analyst"])
        self.assertTrue(
            {"vpn:view", "vpn:manage", "vpn:profile:issue"}.issubset(module.ROLE_PERMISSIONS["admin"])
        )

    def test_hashed_user_records_verify_without_plaintext_storage(self) -> None:
        module = self._load_security_module()
        password_hash = module.hash_password("hashed-secret")
        os.environ["SIEM_WEB_USERS_JSON"] = json.dumps([{"username": "admin", "password_hash": password_hash, "role": "admin"}])

        module = self._load_security_module()
        user = module.authenticate_user("admin", "hashed-secret")
        summary = module.get_local_auth_summary()

        self.assertIsNotNone(user)
        self.assertEqual(summary["local_users_hashed"], 1)
        self.assertEqual(summary["local_users_plaintext"], 0)

    def test_rate_limiter_blocks_after_configured_failures(self) -> None:
        os.environ["SIEM_AUTH_RATE_LIMIT_MAX_ATTEMPTS"] = "2"
        os.environ["SIEM_AUTH_RATE_LIMIT_WINDOW_SECONDS"] = "60"
        os.environ["SIEM_AUTH_RATE_LIMIT_LOCKOUT_SECONDS"] = "120"
        module = self._load_security_module()
        request = _FakeRequest("10.0.0.55")

        self.assertFalse(module.check_auth_rate_limit(request)["blocked"])
        self.assertFalse(module.record_auth_failure(request)["blocked"])
        blocked = module.record_auth_failure(request)

        self.assertTrue(blocked["blocked"])
        self.assertGreaterEqual(int(blocked["retry_after_seconds"]), 1)
        snapshot = module.get_auth_rate_limit_overview()
        self.assertEqual(snapshot["blocked_ips"], 1)

        module.record_auth_success(request)
        self.assertFalse(module.check_auth_rate_limit(request)["blocked"])

    def test_ingest_runtime_tls_context_uses_ca_file_when_configured(self) -> None:
        cert_pem = """-----BEGIN CERTIFICATE-----
MIIC7jCCAdagAwIBAgIUCfzJ0anMMVrN/rbetOiab8k6qBUwDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMMTkyLjE2OC4xLjM1MB4XDTI2MDMwNTIyMDgyM1oXDTI3
MDMwNTIyMDgyM1owFzEVMBMGA1UEAwwMMTkyLjE2OC4xLjM1MIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7dCSNbyC9hXH6zUl+pYhBaM1mnxXr9pPQN9u
UybnlnWaGaJkqsvv7/j8MC6qyAAo6KpxqKGbGQpJnvIBy4LUqBjnG0/Vs4W1GTjy
d2oWwo7RKKvQ+qoBKMIAywiSwCqUsC9+O9oQ/C/B4MnZIXWNmUyyE1L3NCJvWlYp
rfUyNfh5dt1kswb2UO3g6//MG9v/qFus6TNGMCbSr0eli5lEw31srzBwc290lYAh
h3J9LsALkcmeUFEglD75JX8iElAWtSqw8bLn8BpiFLvNuITUsuFCu4kXS7iFoE2l
PAOY/2inxoM87AT85FiN0rkVgXaEN4K38qoA6uyl3OeQETSCswIDAQABozIwMDAP
BgNVHREECDAGhwTAqAEjMB0GA1UdDgQWBBQ4oxFIjE/FnxBvxn/+ksjOR7yC8DAN
BgkqhkiG9w0BAQsFAAOCAQEAsvUfewnKA9bO+X3dUCWcJXC/pnZk+oolnLSEXH01
9ukBQlbY81ACAwc4H8GAJLbcpdmltFqLmtbYRcRCSrQYtoumT1T/JdDORBoVr4p9
Bs4RzFIgnOD8LuvNf/nOMGvl6BLAQyBY5j/heAxVYHafFtTTVGjq+BZTt/hTXIdE
sW6ywgtIa7fbV6Wl24fyOmQthMnw3Ny6pFYKgJGi86gklS+Kb1SjEKp7ZHuRL9uj
yQSzIxETxc9B0LCFW4sT/zywgmUvQXW+czKgp+Vz6JddjjGvt6X9Dvtyk8VYToDR
JtIeBjdllGBWBQmE4yqnN3dmNniijDqvIrLagMYV/yZcaw==
-----END CERTIFICATE-----
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            ca_file = Path(temp_dir) / "ingest-ca.crt"
            ca_file.write_text(cert_pem, encoding="utf-8")
            os.environ["SIEM_INGEST_TLS_VERIFY"] = "ca_file"
            os.environ["SIEM_INGEST_TLS_CA_FILE"] = str(ca_file)
            spec = importlib.util.spec_from_file_location(
                "ingest_runtime",
                _resolve_module_path("ingest_runtime.py", "services/web/app/ingest_runtime.py"),
            )
            assert spec and spec.loader
            module = importlib.util.module_from_spec(spec)
            sys.modules["ingest_runtime"] = module
            spec.loader.exec_module(module)

            context = module._ssl_context("https://192.168.1.35")

            self.assertEqual(context.verify_mode, module.ssl.CERT_REQUIRED)
            self.assertTrue(context.check_hostname)


if __name__ == "__main__":
    unittest.main()
