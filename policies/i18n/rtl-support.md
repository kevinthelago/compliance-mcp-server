---
id: I18N-003
domain: i18n
topic: rtl-support
severity: medium
controls: []
keywords:
  - rtl
  - right-to-left
  - arabic
  - hebrew
  - bidi
  - direction
  - logical-properties
  - css
locales:
  - ar
  - he
  - fa
---

# RTL Layout Support Policy

When a required locale uses right-to-left (RTL) text direction (Arabic, Hebrew, Farsi),
the UI must use CSS logical properties instead of physical directional properties.

## Required controls

- Use `margin-inline-start` / `margin-inline-end` instead of `margin-left` / `margin-right`.
- Use `padding-inline-*`, `border-inline-*` instead of physical equivalents.
- Do not hardcode `text-align: left` — use `text-align: start`.
- The root `<html>` element must set `dir="rtl"` when an RTL locale is active.
- RTL violations are detected by the i18n lens via tinycss2 CSS analysis.

## Scope

Only applies to projects whose `required-locales` config includes at least one RTL locale.

## References

- MDN — CSS Logical Properties and Values
