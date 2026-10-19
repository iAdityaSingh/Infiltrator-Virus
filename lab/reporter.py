from __future__ import annotations

import random
import smtplib
import threading
from email.message import EmailMessage

from . import jsonl
from .config import SMTP_HOST, Config


class LocalReporter(threading.Thread):
    """Periodically 'reports' NEW synthetic events to a loopback SMTP sink.

    If no sink is listening, the message is saved to outbox/ as an .eml file instead.
    Either way a synthetic network-telemetry record is written for the detector.
    """

    def __init__(self, cfg: Config, stop: threading.Event):
        super().__init__(name="local-reporter", daemon=True)
        self.cfg, self.stop = cfg, stop
        self.offset = 0  # bytes of events.jsonl already reported

    def _read_new_lines(self) -> list[str]:
        path = self.cfg.events_file
        if not path.exists():
            return []
        with path.open("rb") as fh:
            fh.seek(self.offset)
            chunk = fh.read()
        end = chunk.rfind(b"\n")
        if end == -1:  # no complete line yet
            return []
        self.offset += end + 1
        return chunk[: end + 1].decode("utf-8").splitlines()

    def flush_once(self) -> str | None:
        lines = self._read_new_lines()
        if not lines:
            print("[REPORT] nothing new to report")
            return None

        msg = EmailMessage()
        msg["Subject"] = "[INFLTR-SIM] Synthetic lab report"
        msg["From"], msg["To"] = self.cfg.sender, self.cfg.recipient
        body = "Training simulation. All records are synthetic.\n\n" + "\n".join(lines)
        msg.set_content(body)

        try:
            with smtplib.SMTP(SMTP_HOST, self.cfg.smtp_port, timeout=3) as server:
                server.send_message(msg)
            outcome = "smtp_sink"
            print(f"[REPORT] sent {len(lines)} events to {SMTP_HOST}:{self.cfg.smtp_port}")
        except (OSError, smtplib.SMTPException):
            self.cfg.outbox_dir.mkdir(parents=True, exist_ok=True)
            name = jsonl.now_iso().replace(":", "-") + ".eml"
            (self.cfg.outbox_dir / name).write_bytes(bytes(msg))
            outcome = "outbox_file"
            print(f"[REPORT] no sink on :{self.cfg.smtp_port}; saved outbox/{name}")

        jsonl.append(self.cfg.network_file, {
            "timestamp": jsonl.now_iso(),
            "event_type": "SIM_NETWORK_CONNECTION",
            "host": self.cfg.host,
            "process": "python.exe",
            "dest_ip": SMTP_HOST,
            "dest_port": self.cfg.smtp_port,
            "protocol": "smtp",
            "bytes": len(body),
            "outcome": outcome,
            "synthetic": True,
        })
        return outcome

    def _next_delay(self) -> float:
        j = self.cfg.jitter
        return self.cfg.interval * (1 + random.uniform(-j, j)) if j else self.cfg.interval

    def run(self) -> None:
        print(f"[REPORT] scheduler started (every ~{self.cfg.interval}s, jitter {self.cfg.jitter})")
        while not self.stop.wait(self._next_delay()):
            self.flush_once()
