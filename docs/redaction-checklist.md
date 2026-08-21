# Publication Redaction Checklist

Review every screenshot, CSV, and PDF page at full resolution before publishing.

Remove or obscure:

- passwords, API keys, tokens, cookies, and certificates;
- email addresses and notification recipients;
- Splunk Cloud instance URLs and tenant identifiers;
- account names and unnecessary usernames;
- public IP addresses, internal addressing, and sensitive hostnames;
- browser bookmarks, tabs, notifications, and unrelated applications;
- search history or data unrelated to this lab; and
- metadata that identifies a private environment.

Keep visible when safe and useful:

- Sysmon Event IDs;
- generic process names;
- the controlled test filename;
- detection reason and severity;
- a shortened or masked `ProcessGuid`; and
- the alert title and trigger count.

After redaction, export a new copy rather than overwriting the only original. Inspect the exported copy again to ensure text layers, comments, attachments, or document metadata do not retain the removed values.
