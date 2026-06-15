---
id: INT-003
domain: policy
topic: incident-response
severity: high
controls:
  - SOC2-CC7.4
  - ISO27001-A.16.1.5
  - NIST-800-53-IR-4
keywords:
  - incident
  - response
  - breach
  - notification
  - runbook
  - escalation
locales: []
---

# Incident Response Policy

Security incidents must be detected, classified, contained, and reported within defined
time-to-respond windows.

## Severity tiers and response times

| Severity | Definition                        | Containment SLA | Notification SLA |
|----------|-----------------------------------|-----------------|------------------|
| P0       | Active breach / data exfiltration | 1 hour          | 2 hours          |
| P1       | Confirmed vulnerability exploited | 4 hours         | 8 hours          |
| P2       | Suspected incident / anomaly      | 24 hours        | 24 hours         |

## Required controls

- On-call rotation must be maintained and paged for P0/P1 incidents.
- Post-incident review (PIR) must be completed within 5 business days.
- External notification (customers, regulators) follows the breach-notification runbook.

## References

- SOC 2 CC7.4 — Incident response
- ISO 27001 A.16.1.5 — Response to information security incidents
- NIST SP 800-53 IR-4 — Incident handling
