import json
import socket
import threading
from datetime import datetime, timedelta, timezone

from lab import jsonl
from lab.config import Config
from lab.detector import detect_beaconing, detect_unexpected_smtp
from lab.reporter import LocalReporter
from lab.simulator import EventSimulator


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def cfg_for(tmp_path) -> Config:
    return Config(log_dir=tmp_path / "logs", outbox_dir=tmp_path / "outbox", smtp_port=free_port())


def net_events(gaps):
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    out = []
    for g in [0, *gaps]:
        t += timedelta(seconds=g)
        out.append({"timestamp": t.isoformat(), "host": "H", "process": "python.exe",
                    "dest_ip": "127.0.0.1", "dest_port": 1025})
    return out


def test_jsonl_has_one_event_per_line(tmp_path):
    cfg = cfg_for(tmp_path)
    cfg.reset_logs()
    sim = EventSimulator(cfg, threading.Event())
    for _ in range(3):
        sim.emit_one()
    lines = cfg.events_file.read_text().splitlines()
    assert len(lines) == 3
    assert all(json.loads(l)["synthetic"] is True for l in lines)


def test_reporter_sends_only_new_events_and_falls_back_to_outbox(tmp_path):
    cfg = cfg_for(tmp_path)
    cfg.reset_logs()
    sim, rep = EventSimulator(cfg, threading.Event()), LocalReporter(cfg, threading.Event())
    sim.emit_one()
    assert rep.flush_once() == "outbox_file"          # nothing listening on the port
    assert rep.flush_once() is None                    # nothing new -> nothing sent
    sim.emit_one()
    assert rep.flush_once() == "outbox_file"
    assert len(list(cfg.outbox_dir.glob("*.eml"))) == 2
    assert len(jsonl.load(cfg.network_file)) == 2


def test_regular_beacon_is_flagged():
    assert detect_beaconing(net_events([30, 30, 30, 30, 30]))


def test_irregular_traffic_is_not_flagged():
    assert not detect_beaconing(net_events([5, 90, 12, 200, 41]))


def test_smtp_from_python_flagged_but_mail_client_ignored():
    ev = net_events([30])
    assert len(detect_unexpected_smtp(ev)) == 1        # deduplicated per flow
    for e in ev:
        e["process"] = "outlook.exe"
    assert not detect_unexpected_smtp(ev)
