---
id: SEC-005
domain: security
topic: input-validation
severity: high
controls:
  - SOC2-CC6.6
  - OWASP-A03
keywords:
  - sql-injection
  - xss
  - input
  - validation
  - sanitization
locales:
  - en
---

# Input Validation Policy

All user-supplied input **must** be validated and sanitized before use.

- Use parameterized queries for SQL operations.
- Escape output for HTML contexts to prevent XSS.
- Validate all inputs at the application boundary.

## References

- SOC 2 CC6.6 — Logical access security measures
- OWASP A03:2021 — Injection
