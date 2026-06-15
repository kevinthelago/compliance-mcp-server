---
id: SUP-001
domain: supply_chain
topic: license-approval
severity: high
controls:
  - SOC2-CC9.2
  - ISO27001-A.15.1.2
keywords:
  - license
  - open-source
  - gpl
  - mit
  - apache
  - spdx
  - copyleft
locales: []
---

# Open-Source License Approval Policy

Third-party open-source packages must use a license on the approved list before they are added
as a runtime dependency.

## Approved licenses (allow-list)

MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Python-2.0, PSF-2.0, Unlicense, CC0-1.0

## Review required

LGPL-2.0, LGPL-2.1, LGPL-3.0, MPL-2.0, EUPL-1.2

## Denied licenses (deny-list)

GPL-2.0, GPL-3.0, AGPL-3.0, SSPL-1.0, and any commercial-use-restricted licenses.

## Controls

- The SBOM (CycloneDX) is generated on every build via Syft and evaluated by the license
  evaluator before merging.
- A denied-license finding blocks the merge gate.
- Review-list entries require written approval from the engineering lead filed in the issue.

## References

- SOC 2 CC9.2 — Vendor and third-party risk management
- ISO 27001 A.15.1.2 — Addressing security within supplier agreements
