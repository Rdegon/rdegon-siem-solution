from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from deploy.misp_event_exporter import _attribute_documents, _load_key


class MispEventExporterTests(unittest.TestCase):
    def test_attribute_documents_are_unique_and_keep_event_context(self) -> None:
        items = [
            {
                "Event": {
                    "id": "42",
                    "uuid": "event-uuid",
                    "info": "Lab campaign",
                    "Galaxy": [{"name": "must-not-be-forwarded"}],
                    "Attribute": [
                        {
                            "id": "7",
                            "uuid": "attribute-uuid",
                            "timestamp": "1785029000",
                            "type": "domain",
                            "value": "example.invalid",
                            "ShadowAttribute": [{"value": "must-not-be-forwarded"}],
                        }
                    ],
                }
            }
        ]

        documents = list(_attribute_documents(items))

        self.assertEqual(1, len(documents))
        identity, timestamp, document = documents[0]
        self.assertEqual("event-uuid:attribute-uuid:1785029000", identity)
        self.assertEqual(1785029000, timestamp)
        self.assertNotIn("Attribute", document["Event"])
        self.assertNotIn("Galaxy", document["Event"])
        self.assertEqual("example.invalid", document["Attribute"]["value"])
        self.assertNotIn("ShadowAttribute", document["Attribute"])

    def test_load_key_rejects_malformed_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "misp.env"
            path.write_text("MISP_API_KEY=short\n", encoding="ascii")
            self.assertEqual("", _load_key(path))

            path.write_text("MISP_API_KEY=" + "a" * 40 + "\n", encoding="ascii")
            self.assertEqual("a" * 40, _load_key(path))


if __name__ == "__main__":
    unittest.main()
