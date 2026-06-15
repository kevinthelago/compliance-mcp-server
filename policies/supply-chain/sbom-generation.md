---
id: SUP-003
domain: supply_chain
topic: sbom-generation
severity: medium
controls:
  - SOC2-CC9.2
  - NIST-800-53-SA-12
keywords:
  - sbom
  - software-bill-of-materials
  - cyclonedx
  - syft
  - inventory
  - provenance
locales: []
---

# SBOM Generation Policy

A Software Bill of Materials (SBOM) in CycloneDX JSON format must be generated for every
release artifact and stored alongside it.

## Required controls

- Syft (or equivalent) must run as part of the CI release pipeline.
- The SBOM must list all direct and transitive dependencies with name, version, and SPDX
  license expression.
- SBOMs must be attached to GitHub releases as assets and optionally uploaded to a central
  SBOM repository.
- The SBOM feeds the license evaluator and Trivy CVE scan in the same pipeline.

## References

- SOC 2 CC9.2 — Third-party risk
- NIST SP 800-53 SA-12 — Supply chain protection
