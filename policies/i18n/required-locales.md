---
id: I18N-001
domain: i18n
topic: required-locales
severity: medium
controls:
  - ISO27001-A.18.1.4
keywords:
  - locales
  - translations
  - i18n
  - l10n
  - missing-locale
  - catalog
  - gettext
locales:
  - en
  - es
  - fr
  - de
  - ja
  - zh-CN
  - ar
  - pt-BR
---

# Required Locales Policy

The application must ship complete translation catalogs for all locales in the `required-locales`
configuration list before a release.

## Required controls

- Translation catalogs (i18next JSON, `.po`, or equivalent) must exist for every required locale.
- Missing keys across locales trigger findings — a key present in `en` but absent in `es` is a
  violation.
- Empty translations (key maps to `""`) are treated as missing.
- The CI pipeline validates catalog completeness and blocks merges on missing-locale findings.

## Scope

The `required-locales` list is configured in `compliance.toml` and may differ between projects.
This policy defines the minimum set; projects may extend it.

## References

- ISO 27001 A.18.1.4 — Privacy and protection of personally identifiable information
