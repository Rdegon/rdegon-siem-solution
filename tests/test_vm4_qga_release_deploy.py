from deploy.vm4_qga_release_deploy import (
    ROOT,
    RELEASE_FILES,
    _publish_rules_command,
    _remote_path,
)


def test_frontend_files_are_mapped_into_deployed_frontend_tree() -> None:
    assert (
        _remote_path("frontend-react/src/shell/App.tsx")
        == "/opt/siem/siem-solution/services/web/frontend-react/src/shell/App.tsx"
    )
    assert (
        _remote_path("services/web/app/security_services_runtime.py")
        == "/opt/siem/siem-solution/services/web/app/security_services_runtime.py"
    )


def test_release_contains_backend_frontend_and_rule_pack() -> None:
    assert "services/web/app/security_services_runtime.py" in RELEASE_FILES
    assert "services/web/app/inventory_catalog.py" in RELEASE_FILES
    assert "services/web/app/runtime_humanization.py" in RELEASE_FILES
    assert "deploy/close_confirmed_runtime_false_positives.py" in RELEASE_FILES
    assert "frontend-react/src/shell/App.tsx" in RELEASE_FILES
    assert "frontend-react/src/shell/humanize.ts" in RELEASE_FILES
    assert "correlation_rule_packs/security_services_v1.json" in RELEASE_FILES
    assert 'Path("/etc/siem/web.env")' in _publish_rules_command()
    assert "runpy.run_path" in _publish_rules_command()
    source = (ROOT / "deploy" / "vm4_qga_release_deploy.py").read_text(
        encoding="utf-8"
    )
    assert "chmod o+x" in source
