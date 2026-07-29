from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_operator_web_trust_requires_a_pinned_sha256_fingerprint() -> None:
    script = (
        ROOT
        / "deploy"
        / "network_relocation"
        / "install_operator_web_trust.ps1"
    ).read_text(encoding="utf-8")

    assert "ExpectedSha256" in script
    assert "fingerprint mismatch" in script
    assert "StoreLocation]::CurrentUser" in script
    assert "StoreName]::Root" in script
