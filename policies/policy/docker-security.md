---
id: POL-002
domain: policy
topic: docker-security
severity: high
controls:
  - SOC2-CC6.6
  - ISO27001-A.12.6.2
keywords:
  - dockerfile
  - docker
  - root
  - user
  - pinned
  - base-image
locales:
  - en
---

# Docker Security Policy

Dockerfiles must:

- Run as a non-root user (USER directive, not root).
- Pin base image to a specific version tag or digest.
- Not expose unnecessary ports.
- Use multi-stage builds for production images.

## References

- SOC 2 CC6.6 — Logical access security measures
- ISO 27001 A.12.6.2 — Restrictions on software installation
