---
id: SEC-004
domain: security
topic: encryption-at-rest
severity: high
controls:
  - SOC2-CC6.1
  - ISO27001-A.10.1.1
  - HIPAA-164.312.a.2.iv
keywords:
  - encryption
  - at-rest
  - storage
  - aes
  - kms
  - disk
  - database
locales: []
---

# Encryption at Rest Policy

All persistent data that contains PII, credentials, or business-sensitive information must be
encrypted at rest using AES-256 or equivalent.

## Required controls

- Database volumes and object storage buckets must have server-side encryption enabled.
- Encryption keys must be managed through a KMS (not hard-coded or stored alongside data).
- Key rotation must occur at least annually.
- Encryption configuration must be auditable via IaC (Terraform, Pulumi, CloudFormation).

## References

- SOC 2 CC6.1 — Data protection controls
- ISO 27001 A.10.1.1 — Policy on the use of cryptographic controls
- HIPAA 164.312(a)(2)(iv) — Encryption and decryption
