---
id: INT-001
domain: policy
topic: code-review
severity: medium
controls:
  - SOC2-CC8.1
  - ISO27001-A.14.2.2
keywords:
  - code-review
  - pull-request
  - peer-review
  - approval
  - four-eyes
locales: []
---

# Code Review Policy

All changes to a protected branch (main, develop) must be reviewed and approved by at least
one team member other than the author before merging.

## Required controls

- Pull requests must have at least one approving review from a code owner.
- Review must include both correctness and security considerations.
- No force-pushes to protected branches.
- Merge commits must reference the issue number they close.
- CI must be green before merge is permitted.

## Exceptions

Hotfixes on a declared incident may bypass the approval requirement but must be reviewed
retrospectively within 24 hours and documented in the incident record.

## References

- SOC 2 CC8.1 — Change management
- ISO 27001 A.14.2.2 — System change control procedures
