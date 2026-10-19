# Infiltrator Lab: Exfiltration Detection Engineering Simulator

A safe lab that generates **synthetic** "collect, stage, report by email" telemetry so you can
write and test detections for it. It never reads real keystrokes and only talks to `127.0.0.1`.

## What you get
| Piece | Purpose |
|---|---|
| `lab/simulator.py` | Writes synthetic events to `logs/events.jsonl` |
| `lab/reporter.py` | Sends only *new* events on a timer to a local SMTP sink (falls back to `outbox/*.eml`) and logs network telemetry |
| `lab/detector.py` | Detection logic: SMTP from a non-mail process, and regular-interval beaconing (coefficient of variation) |
| `detection/*.yar, *.yml, *.md` | YARA, Sigma (network + process) and Sentinel/Defender KQL |
| `docs/attack-lifecycle.md` | ATT&CK mapping, control references, investigation checklist, experiments |
| `tests/` | pytest suite |

## Run it (VS Code)
Requires Python 3.9+. No packages needed to run.

```bash
# 1. open the infiltrator-lab folder in VS Code, then open a terminal
python -m venv .venv
# Windows:      .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate

# 2. 40-second demo, then detector output
python main.py demo
```
Expected: events print every 2s, a report every 6s, then the detector raises
`SMTP_FROM_NON_MAIL_PROCESS` and `REGULAR_BEACON_INTERVAL`.

Try to evade your own detector:
```bash
python main.py demo --jitter 0.4     # randomised interval -> beacon rule goes quiet
```
Other commands:
```bash
python main.py run --interval 10     # run until Ctrl+C
python main.py analyze               # re-analyse logs/network.jsonl
```
In VS Code you can also use **Run and Debug**, which has two ready-made configs.

## Optional: real SMTP sink (see the emails arrive)
Without a sink, reports are saved as `.eml` files in `outbox/`. To receive them:
```bash
docker run --rm -p 8025:8025 -p 1025:1025 axllent/mailpit    # inspect at http://localhost:8025
# or, without Docker:
pip install aiosmtpd && python -m aiosmtpd -n -l 127.0.0.1:1025
```
Then run `python main.py demo` in another terminal.

## Tests and rule validation
```bash
pip install -r requirements-dev.txt
python -m pytest -q
python -c "import yara; yara.compile(filepath='detection/infiltrator.yar'); print('YARA ok')"
```
Sigma: `pip install sigma-cli`, then `sigma convert -t splunk detection/sigma_smtp_from_script_runtime.yml`
(pick the backend and pipeline for your SIEM).

## Configuration
CLI flags `--interval --jitter --port --duration`, or env vars `LAB_INTERVAL`, `LAB_EVENT_PERIOD`,
`LAB_JITTER`, `LAB_SMTP_PORT`. Each `run`/`demo` clears `logs/` first.

## Limits
The detector and rules are teaching templates, not production detections. Validate them against your
own telemetry, tune thresholds, and expect false positives from legitimate alert-mailing scripts.
