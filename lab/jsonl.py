from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

_LOCK = threading.Lock()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def append(path: Path, record: dict) -> None:
    line = json.dumps(record, separators=(",", ":")) + "\n"  # a real newline
    with _LOCK:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line)


def load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out
