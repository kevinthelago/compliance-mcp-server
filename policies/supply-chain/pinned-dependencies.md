---
id: SUP-002
domain: supply_chain
topic: pinned-dependencies
severity: medium
controls:
  - SOC2-CC7.2
  - ISO27001-A.12.6.1
keywords:
  - pinned
  - lockfile
  - reproducible
  - hash
  - semver
  - dependencies
  - integrity
locales: []
---

# Pinned Dependency Policy

All package managers must use a lock file and dependencies must be pinned to exact versions
(or integrity hashes) to ensure reproducible builds.

## Required controls

- `package-lock.json`, `yarn.lock`, `uv.lock`, `poetry.lock`, `Cargo.lock`, or equivalent
  must be committed to version control.
- Automated dependency update tools (Renovate, Dependabot) must open PRs for upgrades;
  updates must not be applied manually by editing the manifest without updating the lock file.
- Docker base images must be pinned to a digest (`image@sha256:…`) in production Dockerfiles.

## References

- SOC 2 CC7.2 — Change management controls
- ISO 27001 A.12.6.1 — Technical vulnerabilities management
