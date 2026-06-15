---
id: SEC-001
domain: security
topic: credential-storage
severity: critical
controls:
  - SOC2-CC6.1
  - ISO27001-A.9.4.3
  - NIST-800-53-IA-5
keywords:
  - credentials
  - secrets
  - passwords
  - tokens
  - api-keys
  - vault
  - environment-variables
locales: []
---

# Credential Storage Policy

Credentials (passwords, API keys, tokens, private keys) **must not** be stored in source code,
committed to version control, or embedded in container images at build time.

## Required controls

- Use a secrets manager (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) or environment
  variables injected at runtime.
- Never hard-code credentials in `*.py`, `*.ts`, `*.js`, `*.yaml`, `*.toml`, or any other
  source file.
- `.env` files containing real secrets must be listed in `.gitignore`.
- Rotate credentials immediately if a secret is found in git history.

## Detection

Static analysis (gitleaks, truffleHog) and Semgrep rules scan for high-entropy strings and
known secret patterns. A finding against this policy is always **critical** severity.

## References

- SOC 2 CC6.1 — Logical and physical access controls
- ISO 27001 A.9.4.3 — Password management systems
- NIST SP 800-53 IA-5 — Authenticator management
