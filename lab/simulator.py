from __future__ import annotations

import random
import threading

from . import jsonl
from .config import Config

DEMO_EVENTS = [
    "demo_user typed a harmless sample phrase",
    "sensitive fields are redacted in this training scenario",
    "no real keyboard input was collected",
    "analyst should review process and network telemetry",
]


class EventSimulator(threading.Thread):
    """Writes pre-defined synthetic events. There is no keyboard hook anywhere."""

    def __init__(self, cfg: Config, stop: threading.Event):
        super().__init__(name="synthetic-events", daemon=True)
        self.cfg, self.stop = cfg, stop

    def emit_one(self) -> dict:
        event = {
            "timestamp": jsonl.now_iso(),
            "event_type": "SIM_INPUT_ACTIVITY",
            "host": self.cfg.host,
            "user": self.cfg.user,
            "data": random.choice(DEMO_EVENTS),
            "synthetic": True,
        }
        jsonl.append(self.cfg.events_file, event)
        return event

    def run(self) -> None:
        self.cfg.log_dir.mkdir(parents=True, exist_ok=True)
        while not self.stop.is_set():
            ev = self.emit_one()
            print(f"[SIM]    {ev['data']}")
            self.stop.wait(self.cfg.event_period)
