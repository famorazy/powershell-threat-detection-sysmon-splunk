# Evidence Index

The curated evidence sequence is:

1. `01_sysmon_event_counts.png` — Sysmon Event IDs 1, 3, and 11
2. `02_powershell_process_detection.png` — controlled PowerShell process event
3. `03_processguid_correlation.png` — Event IDs 1, 11, and 3 sharing one `ProcessGuid`
4. `04_detection_results.png` — detection reason, severity, analyst context, and sanitised parent category
5. `05_alert_email_triggered.jpeg` — email notification confirming that the scheduled alert triggered

The noisy 35-event searches, raw CSV, raw PDF, and screenshots containing unnecessary application-specific parent paths were excluded. Before adding future evidence, follow [`../docs/redaction-checklist.md`](../docs/redaction-checklist.md).
