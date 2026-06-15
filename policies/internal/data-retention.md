---
id: INT-002
domain: policy
topic: data-retention
severity: medium
controls:
  - SOC2-P4.1
  - GDPR-Art17
  - ISO27001-A.18.1.3
keywords:
  - data-retention
  - deletion
  - gdpr
  - right-to-erasure
  - pii
  - logs
  - backups
locales: []
---

# Data Retention Policy

Personal data and audit logs must be retained for the minimum period required by regulation and
deleted securely when the retention window expires.

## Retention schedule

| Data type          | Retention period | Deletion method     |
|--------------------|-----------------|---------------------|
| Audit logs         | 1 year          | Secure log deletion |
| PII (user records) | Until erasure request or 3 years post-inactivity | Cryptographic erasure |
| Scan results       | 90 days         | Automated purge     |
| Backups            | 30 days rolling | Key deletion        |

## Required controls

- Automated retention jobs must run on a schedule and be monitored.
- Deletion requests (GDPR Art. 17) must be processed within 30 days.
- Logs must not contain raw PII (tokenize or hash identifiers before logging).

## References

- SOC 2 P4.1 — Personal information collected for specified purposes
- GDPR Article 17 — Right to erasure
- ISO 27001 A.18.1.3 — Protection of records
