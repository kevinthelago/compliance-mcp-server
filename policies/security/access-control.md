---
id: SEC-003
domain: security
topic: access-control
severity: high
controls:
  - SOC2-CC6.3
  - ISO27001-A.9.1.2
  - NIST-800-53-AC-3
keywords:
  - access
  - authorization
  - rbac
  - least-privilege
  - permissions
  - authentication
locales: []
---

# Access Control Policy

All services and tools must enforce the principle of least privilege. Access must be granted
based on role, not identity, and reviewed quarterly.

## Required controls

- Every API endpoint or tool operation must verify the caller's authorization before proceeding.
- Service accounts must have the minimum permissions required for their function.
- Privileged access (admin, root, IAM mutation) requires multi-factor authentication.
- Access control lists must be stored in version-controlled configuration, not ad hoc.

## MCP-specific guidance

MCP tool handlers must validate that the invoking session has the expected role or scope before
executing state-mutating operations (scans, gate decisions, report generation).

## References

- SOC 2 CC6.3 — Access is restricted to authorized users
- ISO 27001 A.9.1.2 — Access to networks and network services
- NIST SP 800-53 AC-3 — Access enforcement
