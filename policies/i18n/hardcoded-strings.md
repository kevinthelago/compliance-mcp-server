---
id: I18N-002
domain: i18n
topic: hardcoded-strings
severity: medium
controls: []
keywords:
  - hardcoded
  - strings
  - literals
  - jsx
  - labels
  - i18n
  - translation-key
locales: []
---

# Hardcoded User-Facing String Policy

User-facing text (labels, button text, titles, placeholder text, alt text, error messages) must
not be hardcoded in source files. All UI strings must be managed through the translation catalog.

## Required controls

- All JSX text nodes, `label`, `placeholder`, `title`, and `alt` attribute values that contain
  natural-language text must be replaced with catalog keys (e.g. `t("button.submit")`).
- The i18n lens detects hardcoded strings via tree-sitter AST analysis.
- New UI components must be scaffolded with catalog keys from the start; retrofitting is allowed
  only when the component is refactored.
- A configurable ignore-list may exclude non-UI strings (enum values, log keys, test fixtures).

## References

- No specific control — internal engineering standard.
