from __future__ import annotations

import unittest

from deploy.soc_control_plane_e2e import _query_siem


class _Pve:
    def __init__(self) -> None:
        self.calls: list[int] = []

    def guest_exec(self, vmid: int, script: str, timeout: int = 180) -> str:
        self.calls.append(vmid)
        if vmid == 106:
            raise RuntimeError("guest agent unavailable")
        return (
            '{"device_product":"minio","category":"application",'
            '"subcategory":"audit","event_action":"put",'
            '"event_outcome":"success","events":1,'
            '"latest":"2026-07-28 12:00:00"}\n'
        )


class SocControlPlaneE2ETests(unittest.TestCase):
    def test_query_falls_back_to_standby_storage(self) -> None:
        pve = _Pve()

        vmid, rows = _query_siem(pve)

        self.assertEqual(pve.calls, [106, 108])
        self.assertEqual(vmid, 108)
        self.assertEqual(rows[0]["device_product"], "minio")

    def test_query_reports_all_storage_failures(self) -> None:
        class _Unavailable:
            def guest_exec(self, vmid: int, script: str, timeout: int = 180) -> str:
                raise RuntimeError("offline")

        with self.assertRaisesRegex(RuntimeError, "VM106.*VM108"):
            _query_siem(_Unavailable())
