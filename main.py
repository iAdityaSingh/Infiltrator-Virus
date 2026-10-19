"""Infiltrator Lab CLI.  Synthetic data only; loopback only.

  python main.py demo                 # 40s run, then analysis (best first command)
  python main.py run --interval 10    # run until Ctrl+C
  python main.py analyze              # analyze logs/network.jsonl
"""
from __future__ import annotations

import argparse
import signal
import threading
import time

from lab import jsonl
from lab.config import Config
from lab.detector import analyze
from lab.reporter import LocalReporter
from lab.simulator import EventSimulator

BANNER = "INFILTRATOR LAB | synthetic data only | loopback only | no keyboard capture"


def run(cfg: Config, duration: float | None) -> None:
    print("=" * len(BANNER), BANNER, "=" * len(BANNER), sep="\n")
    cfg.reset_logs()
    stop = threading.Event()
    for sig in (signal.SIGINT, getattr(signal, "SIGTERM", None)):
        if sig is not None:
            signal.signal(sig, lambda *_: stop.set())

    sim, rep = EventSimulator(cfg, stop), LocalReporter(cfg, stop)
    sim.start()
    rep.start()
    deadline = time.monotonic() + duration if duration else None
    try:
        while not stop.wait(0.25):  # short waits keep Ctrl+C responsive on Windows
            if deadline and time.monotonic() >= deadline:
                break
    finally:
        stop.set()
        sim.join(2)
        rep.join(2)
        print("[STOP] clean shutdown")


def report_alerts(cfg: Config) -> int:
    net = jsonl.load(cfg.network_file)
    print(f"\n--- Detector: {len(net)} network events analysed ---")
    alerts = analyze(net)
    if not alerts:
        print("No alerts. (Too few events, or traffic is irregular enough to evade the cv test.)")
    for a in alerts:
        print(f"[{a['severity'].upper():6}] {a['rule']} ({a['attack']}): {a['detail']}")
    return len(alerts)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("run", "demo"):
        s = sub.add_parser(name)
        s.add_argument("--interval", type=float, help="seconds between reports")
        s.add_argument("--jitter", type=float, help="0.0-0.9 randomisation of the interval")
        s.add_argument("--port", type=int, help="local SMTP sink port (default 1025)")
        s.add_argument("--duration", type=float, help="auto-stop after N seconds")
    sub.add_parser("analyze")
    args = p.parse_args()

    cfg = Config.from_env()
    if args.cmd == "analyze":
        report_alerts(cfg)
        return
    cfg = cfg.with_overrides(interval=args.interval, jitter=args.jitter, smtp_port=args.port)
    if args.cmd == "demo":
        cfg = cfg.with_overrides(interval=args.interval or 6.0)
        run(cfg, args.duration or 40)
        report_alerts(cfg)
    else:
        run(cfg, args.duration)
        report_alerts(cfg)


if __name__ == "__main__":
    main()
