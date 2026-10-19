from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from statistics import mean, pstdev

SMTP_PORTS = {25, 465, 587, 2525, 1025}
MAIL_CLIENTS = {"outlook.exe", "olk.exe", "thunderbird.exe"}


def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s)


def detect_unexpected_smtp(net_events: list[dict]) -> list[dict]:
    """Outbound SMTP from a process that is not a known mail client (one alert per flow)."""
    alerts, seen = [], set()
    for e in net_events:
        if e.get("dest_port") in SMTP_PORTS and e.get("process", "").lower() not in MAIL_CLIENTS:
            flow = (e["host"], e["process"], e["dest_ip"], e["dest_port"])
            if flow in seen:
                continue
            seen.add(flow)
            alerts.append({
                "rule": "SMTP_FROM_NON_MAIL_PROCESS",
                "severity": "medium",
                "attack": "T1048.003",
                "detail": f"{e['process']} -> {e['dest_ip']}:{e['dest_port']} (first seen {e['timestamp']})",
            })
    return alerts


def detect_beaconing(net_events: list[dict], min_events: int = 4, max_cv: float = 0.15) -> list[dict]:
    """Flag connections to one destination at suspiciously regular intervals.

    cv = std-dev / mean of the gaps. Human-driven traffic is bursty (high cv);
    a timer-driven reporter is regular (low cv). Jitter defeats this simple test,
    which is the point of experimenting with --jitter.
    """
    groups: dict[tuple, list[datetime]] = defaultdict(list)
    for e in net_events:
        groups[(e["host"], e["process"], e["dest_ip"], e["dest_port"])].append(_ts(e["timestamp"]))

    alerts = []
    for key, times in groups.items():
        if len(times) < min_events:
            continue
        times.sort()
        gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
        avg = mean(gaps)
        if avg <= 0:
            continue
        cv = pstdev(gaps) / avg
        if cv <= max_cv:
            alerts.append({
                "rule": "REGULAR_BEACON_INTERVAL",
                "severity": "high",
                "attack": "T1020",
                "detail": f"{key[1]} -> {key[2]}:{key[3]}: {len(times)} conns, "
                          f"mean gap {avg:.1f}s, cv {cv:.3f} (threshold {max_cv})",
            })
    return alerts


def analyze(net_events: list[dict]) -> list[dict]:
    return detect_unexpected_smtp(net_events) + detect_beaconing(net_events)
