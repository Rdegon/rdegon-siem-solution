from __future__ import annotations

import importlib
import importlib.machinery
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("SIEM_CH_HOST", "127.0.0.1")
os.environ.setdefault("SIEM_CH_USER", "default")
os.environ.setdefault("SIEM_CH_PASSWORD", "test-password")
os.environ.setdefault("SIEM_ADMIN_DEFAULT_PASSWORD", "test-password")
os.environ.setdefault("SIEM_JWT_SECRET", "test-jwt-secret")

if "repo_testpkg" not in sys.modules:
    package = importlib.util.module_from_spec(importlib.machinery.ModuleSpec("repo_testpkg", loader=None))
    package.__path__ = [str(ROOT)]
    sys.modules["repo_testpkg"] = package

deps = importlib.import_module("repo_testpkg.deps")


class _FakeQueryResult:
    def __init__(self, rows):
        self.result_rows = rows


class _FakeClient:
    def __init__(self, existing_ids):
        self.existing_ids = set(existing_ids)
        self.commands = []
        self.inserts = []

    def query(self, query):
        if "WHERE id IN" in query:
            return _FakeQueryResult([(rule_id,) for rule_id in sorted(self.existing_ids)])
        return _FakeQueryResult([])

    def command(self, query):
        self.commands.append(query)

    def insert(self, *args, **kwargs):
        self.inserts.append((args, kwargs))


class DetectionRuleSeedingTests(unittest.TestCase):
    def test_default_sigma_seed_skips_existing_rules_without_clickhouse_mutations(self) -> None:
        rule_id = 910001
        fake_rule = {
            "id": rule_id,
            "threshold": 1,
            "window_s": 300,
            "entity_field": "host.name",
            "yaml": (
                "title: Existing Seeded Rule\n"
                "id: sigma-existing-seeded-rule\n"
                "status: experimental\n"
                "logsource:\n"
                "  product: linux\n"
                "detection:\n"
                "  selection:\n"
                "    event.provider: linux\n"
                "  condition: selection\n"
                "level: medium\n"
            ),
        }
        client = _FakeClient(existing_ids={rule_id})
        with (
            patch.object(deps, "DEFAULT_SIGMA_RULES", [fake_rule]),
            patch.object(deps, "DEFAULT_SIGMA_RETIRED_DUPLICATE_IDS", set()),
            patch.object(deps, "get_ch_client", return_value=client),
        ):
            deps._seed_default_sigma_rules()

        self.assertEqual([], client.commands)
        self.assertEqual([], client.inserts)


if __name__ == "__main__":
    unittest.main()
