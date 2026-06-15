---
id: I18N-004
domain: i18n
topic: locale-formatting
severity: low
controls: []
keywords:
  - date
  - number
  - currency
  - locale
  - formatting
  - intl
locales:
  - en
---

# Locale Formatting Policy

Dates, numbers, and currencies must use locale-aware formatting.

- Use the Intl API or equivalent locale-aware library.
- Never hardcode date/number format strings.
- Test with multiple locales including RTL languages.
