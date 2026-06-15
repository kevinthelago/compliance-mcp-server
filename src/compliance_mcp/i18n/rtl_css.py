"""I18N-4: Flag physical directional CSS properties when RTL locales are required.

Uses tinycss2 for CSS parsing. Only runs when the configured required_locales
include at least one RTL locale (Arabic, Hebrew, Farsi, etc.). Suggests logical
property equivalents as replacements.
"""

from __future__ import annotations

from pathlib import Path

try:
    import tinycss2  # type: ignore[import]

    _TINYCSS2_AVAILABLE = True
except ImportError:  # pragma: no cover
    _TINYCSS2_AVAILABLE = False

try:
    from compliance_mcp.models import Finding, ScanContext, Severity  # type: ignore[import]
except ImportError:
    from compliance_mcp.i18n._types import (  # type: ignore[assignment]
        Finding,
        ScanContext,
        Severity,
    )


# --------------------------------------------------------------------------- #
# Constants                                                                    #
# --------------------------------------------------------------------------- #

_RTL_LOCALES = frozenset({"ar", "he", "fa", "ur", "ps", "dv", "yi", "ji", "iw"})

# Physical directional properties → suggested logical replacement
_PHYSICAL_PROPS: dict[str, str] = {
    "margin-left": "margin-inline-start",
    "margin-right": "margin-inline-end",
    "padding-left": "padding-inline-start",
    "padding-right": "padding-inline-end",
    "border-left": "border-inline-start",
    "border-right": "border-inline-end",
    "border-left-width": "border-inline-start-width",
    "border-right-width": "border-inline-end-width",
    "border-left-color": "border-inline-start-color",
    "border-right-color": "border-inline-end-color",
    "border-left-style": "border-inline-start-style",
    "border-right-style": "border-inline-end-style",
    "border-top-left-radius": "border-start-start-radius",
    "border-top-right-radius": "border-start-end-radius",
    "border-bottom-left-radius": "border-end-start-radius",
    "border-bottom-right-radius": "border-end-end-radius",
    "left": "inset-inline-start",
    "right": "inset-inline-end",
}

# Properties whose VALUES (not names) may indicate directionality
_DIRECTIONAL_VALUE_PROPS = frozenset({"float", "text-align", "background-position"})
_DIRECTIONAL_VALUES = frozenset({"left", "right"})


def _has_rtl_locale(required_locales: list[str]) -> bool:
    return any(lc.lower().split("_")[0].split("-")[0] in _RTL_LOCALES for lc in required_locales)


# --------------------------------------------------------------------------- #
# CSS parsing                                                                  #
# --------------------------------------------------------------------------- #


def _tokens_to_text(tokens: list) -> str:
    """Convert a list of tinycss2 tokens to a plain string using serialize()."""
    return "".join(t.serialize() for t in tokens).strip()


def _scan_css_file(path: Path) -> list[Finding]:
    """Parse *path* as CSS and return RTL-related findings."""
    if not _TINYCSS2_AVAILABLE:
        return []  # pragma: no cover

    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    findings: list[Finding] = []

    rules = tinycss2.parse_stylesheet(source, skip_comments=True, skip_whitespace=True)

    for rule in rules:
        if rule.type != "qualified-rule":
            continue

        declarations = tinycss2.parse_declaration_list(
            rule.content, skip_comments=True, skip_whitespace=True
        )

        for decl in declarations:
            if decl.type != "declaration":
                continue

            prop_name = decl.name.lower()
            value_text = _tokens_to_text(decl.value).lower()

            # Physical property name match
            if prop_name in _PHYSICAL_PROPS:
                logical = _PHYSICAL_PROPS[prop_name]
                findings.append(
                    Finding(
                        rule_id="i18n/rtl-physical-property",
                        path=str(path),
                        line=getattr(decl, "source_line", 0),
                        col=getattr(decl, "source_column", 0),
                        severity=Severity.WARNING,
                        message=f"Physical CSS property '{prop_name}' breaks RTL layouts",
                        detail=(
                            f"'{prop_name}' uses a physical direction. "
                            f"Replace with the logical property '{logical}' for RTL support."
                        ),
                        suggestion=f"Use '{logical}' instead of '{prop_name}'.",
                    )
                )

            # Directional value (float: left/right, text-align: left/right)
            elif prop_name in _DIRECTIONAL_VALUE_PROPS:
                first_word = value_text.split()[0] if value_text.split() else ""
                if first_word in _DIRECTIONAL_VALUES:
                    if prop_name == "text-align":
                        suggestion = (
                            "Use 'text-align: start' or 'text-align: end' instead of "
                            f"'text-align: {first_word}' for RTL support."
                        )
                    elif prop_name == "float":
                        suggestion = (
                            f"Avoid 'float: {first_word}'; "
                            "use flexbox or CSS logical properties instead."
                        )
                    else:
                        suggestion = (
                            f"Consider logical values instead of '{prop_name}: {first_word}'."
                        )
                    findings.append(
                        Finding(
                            rule_id="i18n/rtl-physical-value",
                            path=str(path),
                            line=getattr(decl, "source_line", 0),
                            col=getattr(decl, "source_column", 0),
                            severity=Severity.WARNING,
                            message=(
                                f"'{prop_name}: {first_word}' uses a physical direction "
                                "and breaks RTL layouts"
                            ),
                            detail=suggestion,
                            suggestion=suggestion,
                        )
                    )

    return findings


# --------------------------------------------------------------------------- #
# Public entry point                                                           #
# --------------------------------------------------------------------------- #


def check_rtl_css(
    ctx: ScanContext,
    config: dict,
) -> list[Finding]:
    """Scan CSS files for physical directional properties.

    Only runs when ``config['required_locales']`` contains an RTL locale.
    Returns an empty list otherwise.
    """
    required_locales: list[str] = config.get("required_locales", [])

    if not _has_rtl_locale(required_locales):
        return []

    findings: list[Finding] = []
    for file_path in ctx.files:
        if file_path.suffix.lower() in (".css", ".scss", ".less"):
            findings.extend(_scan_css_file(file_path))

    return findings
