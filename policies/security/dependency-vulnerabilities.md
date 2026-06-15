---
id: SEC-002
domain: security
topic: dependency-vulnerabilities
severity: high
controls:
  - SOC2-CC7.1
  - ISO27001-A.12.6.1
  - PCI-DSS-6.3.3
keywords:
  - dependencies
  - cve
  - vulnerabilities
  - packages
  - trivy
  - sbom
  - supply-chain
locales: []
---

# Dependency Vulnerability Policy

Third-party dependencies with known CVEs at CVSS **7.0 or above** (high/critical) must be
remediated before merging to the default branch.

## Required controls

- Run Trivy or equivalent SCA tooling on every pull request.
- Critical CVEs (CVSS ≥ 9.0) block merges immediately with no exception path.
- High CVEs (CVSS 7.0–8.9) must be fixed or formally accepted within 14 days.
- Accept entries must be documented in `policies/baseline.yaml` with a justification and
  expiry date.

## Remediation priority

1. Update to the patched version.
2. Replace the dependency with a maintained alternative.
3. Apply a vendor patch / fork if no upstream fix exists.
4. File a baseline exception (last resort, time-limited).

## References

- SOC 2 CC7.1 — Threat and vulnerability identification
- ISO 27001 A.12.6.1 — Management of technical vulnerabilities
- PCI DSS 6.3.3 — Known vulnerabilities are addressed
