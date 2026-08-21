# SOC Incident Investigation Report

## Incident Summary

| Field | Value |
|---|---|
| Incident title | Suspicious PowerShell Execution |
| Classification | Medium severity — laboratory simulation |
| Detection source | Splunk Cloud and Microsoft Sysmon |
| Asset | Windows lab endpoint |
| MITRE ATT&CK | T1059.001 — PowerShell |
| Disposition | Benign / authorised security testing |

## Description

A Splunk detection identified PowerShell execution exhibiting behaviour associated with encoded commands and web activity. The investigation correlated Sysmon process, file, and network telemetry to determine whether the activity was malicious.

## Evidence

### Process Creation

Sysmon Event ID 1 recorded the execution of Windows PowerShell. The event supplied the command line, user, parent process, and `ProcessGuid` used during the investigation.

### File Creation

Sysmon Event ID 11 recorded the creation of the controlled test file `sysmon-test.txt`.

### Network Activity

Sysmon Event ID 3 recorded outbound network activity from the same PowerShell process.

### Correlation

The three events shared the same Sysmon `ProcessGuid`, establishing this sequence:

```text
Process creation -> File creation -> Network connection
```

## Detection Logic

The SPL detection searches Sysmon process-creation events for PowerShell command lines containing behavioural indicators including:

- `Invoke-WebRequest`
- `DownloadString`
- `EncodedCommand`
- `-enc`

The rule assigns a detection reason and severity, and provides parent-process and analyst context for triage.

## Analyst Assessment

The behaviour warranted investigation because PowerShell can be used for script execution, payload retrieval, and obfuscation. The detection alone did not establish malicious intent.

Review of the process chain and surrounding telemetry confirmed that the event was generated intentionally as part of an authorised SOC lab. Legitimate application-driven PowerShell activity was also observed during testing, demonstrating why parent-process, command-line, destination, user, and prevalence checks are necessary.

## Response

- **Containment:** Not required
- **Eradication:** Not required
- **Recovery:** Not required
- **Disposition:** Benign / authorised security testing

## Lessons Learned

1. Behavioural detection is more reusable than matching a unique lab string.
2. Sysmon `ProcessGuid` can reliably correlate multiple event types from one process.
3. Sysmon filtering determines which evidence is available to the analyst.
4. A detection is not proof of compromise.
5. Process ancestry and command-line context are essential for false-positive analysis.

## Conclusion

The exercise demonstrated a complete SOC workflow: endpoint telemetry ingestion, behavioural detection, event correlation, alert generation, analyst investigation, MITRE ATT&CK mapping, and incident disposition. The scheduled alert successfully generated an email notification, validating the pipeline end to end.
