import unittest

from deploy.vm4_content_store_mongo_cutover import _parse_cpu_flags, _parse_qm_cpu_model


class Vm4MongoCutoverTests(unittest.TestCase):
    def test_parse_cpu_flags_extracts_avx_family(self) -> None:
        payload = """
Architecture: x86_64
Flags: fpu sse sse2 ssse3 avx avx2 aes
"""
        flags = _parse_cpu_flags(payload)
        self.assertIn("avx", flags)
        self.assertIn("avx2", flags)
        self.assertIn("aes", flags)

    def test_parse_cpu_flags_returns_empty_set_when_flags_missing(self) -> None:
        self.assertEqual(_parse_cpu_flags("Model name: QEMU Virtual CPU"), set())

    def test_parse_qm_cpu_model_reads_cpu_line(self) -> None:
        config = """
agent: 1
cores: 2
cpu: x86-64-v2-AES
memory: 8192
"""
        self.assertEqual(_parse_qm_cpu_model(config), "x86-64-v2-AES")


if __name__ == "__main__":
    unittest.main()
