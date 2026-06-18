from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class AlertAggSettings:
    env: str
    instance_name: str
    ch_host: str
    ch_port: int
    ch_db: str
    ch_user: str
    ch_password: str
    ch_timeout_secs: int
    interval_sec: int

    @classmethod
    def load(cls) -> "AlertAggSettings":
        return cls(
            env=os.getenv("SIEM_ENV", "dev"),
            instance_name=os.getenv("SIEM_INSTANCE_NAME", "dev-instance"),
            ch_host=os.getenv("SIEM_CH_HOST", "127.0.0.1"),
            ch_port=int(os.getenv("SIEM_CH_PORT", "9000")),
            ch_db=os.getenv("SIEM_CH_DB", "siem"),
            ch_user=os.getenv("SIEM_CH_USER", "siem_admin"),
            ch_password=os.getenv("SIEM_CH_PASSWORD", ""),
            ch_timeout_secs=int(os.getenv("SIEM_CH_TIMEOUT_SECS", "10")),
            interval_sec=int(os.getenv("SIEM_ALERT_AGG_INTERVAL_SEC", "30")),
        )
