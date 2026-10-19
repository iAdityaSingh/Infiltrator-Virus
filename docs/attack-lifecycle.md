# Simulated Attack Lifecycle, ATT&CK Mapping and Defensive Controls

This is conceptual. Nothing in the repo is a real keylogger or a deployable attachment.

| Stage | What the lab simulates | ATT&CK | Where to detect | Control reference |
|---|---|---|---|---|
| Delivery | Not simulated (a user receives a file) | T1566.001 | Mail gateway, attachment sandbox | ISO 27001:2022 A.8.23 / A.5.14 |
| Execution | Python process launched | T1059.006 | Process creation (Sigma `sigma_lab_process.yml`) | A.8.7 malware protection |
| Collection | Synthetic "input" events in `events.jsonl` | T1056.001 (conceptual) | EDR hooks, API-monitoring alerts | A.8.16 monitoring |
| Staging | Local JSONL log, offset-tracked | T1074.001 | File-creation telemetry | A.8.16 |
| Exfiltration | Timed SMTP to loopback | T1048.003, T1020 | Network events (Sigma, KQL, `detector.py`) | A.8.16, A.8.20 networks security |

Opening or downloading an ordinary PDF or image does not execute code. A real chain needs a separate execution step or a vulnerability, which is why patching and attachment sandboxing matter.

## Investigation checklist
1. Which process made the connection, and who launched it (parent process)?
2. Is the destination an expected mail server? Is the interval suspiciously regular?
3. What files did the process create or read recently?
4. Preserve logs and timestamps before remediating; isolate the host; rotate exposed credentials after a real incident.

## Experiments
- Run `python main.py demo` then `python main.py demo --jitter 0.4` and compare the detector output. Why does jitter evade the cv test? What would catch it instead (volume, destination reputation, process lineage)?
- Lower `max_cv` or raise `min_events` and watch false positives and negatives change.
- Convert the Sigma rule to your SIEM syntax (`sigma convert`) and test it on Sysmon Event ID 3 logs.
