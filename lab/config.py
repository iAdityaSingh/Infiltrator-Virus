from __future__ import annotations

import os
from dataclasses import dataclass, replace
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]

# Hard-coded loopback on purpose: this lab can never talk to a real mail server.
SMTP_HOST = "127.0.0.1"


@dataclass(frozen=True)
class Config:
    interval: float = 30.0       # seconds between "reports"
    event_period: float = 2.0    # seconds between synthetic events
    jitter: float = 0.0          # 0.0 = perfectly regular beacon; 0.3 = +/-30%
    smtp_port: int = 1025        # local Mailpit-style sink
    log_dir: Path = BASE_DIR / "logs"
    outbox_dir: Path = BASE_DIR / "outbox"
    host: str = "LAB-WS-01"
    user: str = "demo_user"
    sender: str = "simulator@infiltrator.local"
    recipient: str = "analyst@defender.local"

    @property
    def events_file(self) -> Path:
        return self.log_dir / "events.jsonl"

    @property
    def network_file(self) -> Path:
        return self.log_dir / "network.jsonl"

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            interval=float(os.getenv("LAB_INTERVAL", cls.interval)),
            event_period=float(os.getenv("LAB_EVENT_PERIOD", cls.event_period)),
            jitter=float(os.getenv("LAB_JITTER", cls.jitter)),
            smtp_port=int(os.getenv("LAB_SMTP_PORT", cls.smtp_port)),
        )

    def with_overrides(self, **kwargs) -> "Config":
        return replace(self, **{k: v for k, v in kwargs.items() if v is not None})

    def reset_logs(self) -> None:
        """Each lab run starts with clean logs so results are reproducible."""
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.outbox_dir.mkdir(parents=True, exist_ok=True)
        for f in (self.events_file, self.network_file):
            f.write_text("", encoding="utf-8")
