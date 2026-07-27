import subprocess
from unittest.mock import patch

from deploy import clamav_update_guard


def test_successful_update_reloads_daemon():
    with patch.object(clamav_update_guard, "usable_database_paths", return_value=["local.hdb"]):
        with patch.object(
            clamav_update_guard.subprocess,
            "run",
            side_effect=[
                subprocess.CompletedProcess(["freshclam"], 0),
                subprocess.CompletedProcess(["systemctl"], 0),
            ],
        ) as run:
            assert clamav_update_guard.main() == 0

    assert run.call_count == 2


def test_failed_update_keeps_usable_local_database():
    with patch.object(clamav_update_guard, "usable_database_paths", return_value=["local.hdb"]):
        with patch.object(
            clamav_update_guard.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(["freshclam"], 17),
        ):
            assert clamav_update_guard.main() == 0


def test_failed_update_without_database_is_fatal():
    with patch.object(clamav_update_guard, "usable_database_paths", return_value=[]):
        with patch.object(
            clamav_update_guard.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(["freshclam"], 17),
        ):
            assert clamav_update_guard.main() == 1
