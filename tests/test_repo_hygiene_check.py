from __future__ import annotations

import json

from tools import repo_hygiene_check


PRIVATE_KEY_MARKER = "-----BEGIN " + "PRIVATE KEY-----"
RSA_PRIVATE_KEY_MARKER = "-----BEGIN RSA " + "PRIVATE KEY-----"


def test_detection_rule_private_key_marker_is_not_treated_as_a_secret(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(repo_hygiene_check, "ROOT", tmp_path)
    pack = tmp_path / "correlation_rule_packs" / "detections.json"
    pack.parent.mkdir()
    pack.write_text(
        json.dumps(
            {
                "expr": (
                    "event.original icontains "
                    f"'{RSA_PRIVATE_KEY_MARKER}'"
                )
            }
        ),
        encoding="utf-8",
    )

    assert repo_hygiene_check._scan_content(pack) is None


def test_private_key_content_in_detection_pack_is_still_rejected(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(repo_hygiene_check, "ROOT", tmp_path)
    pack = tmp_path / "correlation_rule_packs" / "detections.json"
    pack.parent.mkdir()
    pack.write_text(
        json.dumps({"private_key": PRIVATE_KEY_MARKER}),
        encoding="utf-8",
    )

    assert "suspicious secret pattern" in str(repo_hygiene_check._scan_content(pack))


def test_private_key_marker_outside_detection_pack_is_rejected(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(repo_hygiene_check, "ROOT", tmp_path)
    candidate = tmp_path / "deploy" / "config.txt"
    candidate.parent.mkdir()
    candidate.write_text(
        f"event.original icontains '{PRIVATE_KEY_MARKER}'",
        encoding="utf-8",
    )

    assert "suspicious secret pattern" in str(
        repo_hygiene_check._scan_content(candidate)
    )
