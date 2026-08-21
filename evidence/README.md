# Evidence Checklist

Add only sanitised images to this folder. Recommended filenames:

1. `01_sysmon_event_counts.png` — Sysmon Event IDs 1, 3, and 11
2. `02_powershell_process_detection.png` — controlled PowerShell process event
3. `03_processguid_correlation.png` — Event IDs 1, 11, and 3 sharing one `ProcessGuid`
4. `04_detection_results.png` — detection reason, severity, and analyst context
5. `05_saved_report.png` — saved Splunk report or alert configuration
6. `06_alert_email_triggered.png` — alert notification with personal details redacted

Before committing an image, follow [`../docs/redaction-checklist.md`](../docs/redaction-checklist.md). Do not add raw screenshots containing credentials, session tokens, email addresses, private Splunk URLs, account names, public IP addresses, or unrelated personal information.
