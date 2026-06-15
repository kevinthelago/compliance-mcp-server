"""I18N-3: Check i18n catalog coverage across required locales.

Supports:
- i18next JSON files (flat or namespace-nested)
- gettext .po files (via polib)

If no catalogs are found under *ctx.root*, emits a single INFO finding and
returns — the check is not applicable.
"""

from __future__ import annotations

import json
from pathlib import Path

try:
    import polib  # type: ignore[import]

    _POLIB_AVAILABLE = True
except ImportError:  # pragma: no cover
    _POLIB_AVAILABLE = False

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

_DEFAULT_CATALOG_DIRS = ("locales", "translations", "i18n", "locale")
_RTL_LOCALES = frozenset({"ar", "he", "fa", "ur", "ps", "dv", "yi", "ji", "iw"})


# --------------------------------------------------------------------------- #
# Catalog discovery & parsing                                                  #
# --------------------------------------------------------------------------- #


def _flatten_json(obj: object, prefix: str = "") -> dict[str, str]:
    """Recursively flatten a nested JSON dict into dotted keys."""
    result: dict[str, str] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                result.update(_flatten_json(v, full_key))
            else:
                result[full_key] = str(v) if v is not None else ""
    return result


def _locale_from_path(path: Path, catalog_root: Path) -> str | None:
    """Infer the locale code from *path* relative to *catalog_root*.

    Handles patterns:
    - ``locales/en.json``        → "en"
    - ``locales/en/translation.json`` → "en"
    - ``locale/en/LC_MESSAGES/messages.po`` → "en"
    """
    try:
        rel = path.relative_to(catalog_root)
    except ValueError:
        return None

    parts = rel.parts
    if not parts:
        return None

    # First component that looks like a locale code
    first = parts[0]
    # Strip file extension from stem if it's a file (e.g. "en.json" → "en")
    if "." in first:
        first = first.rsplit(".", 1)[0]

    # Accept 2- or 5-char locale codes (en, fr, en_US, zh_Hans)
    if 2 <= len(first) <= 5:
        return first.replace("-", "_").split("_")[0].lower()

    # Second component if first was a generic namespace dir
    if len(parts) > 1:
        second = parts[1]
        if "." in second:
            second = second.rsplit(".", 1)[0]
        if 2 <= len(second) <= 5:
            return second.replace("-", "_").split("_")[0].lower()

    return None


def _load_json_catalog(path: Path) -> dict[str, str]:
    """Parse an i18next JSON file, returning a flat {key: value} dict."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return _flatten_json(raw)


def _load_po_catalog(path: Path) -> dict[str, str]:
    """Parse a gettext .po file, returning a {msgid: msgstr} dict."""
    if not _POLIB_AVAILABLE:
        return {}
    try:
        po = polib.pofile(str(path))
    except OSError:
        return {}
    return {entry.msgid: entry.msgstr for entry in po if not entry.obsolete}


def _discover_catalogs(
    root: Path,
    catalog_dir_names: tuple[str, ...],
) -> dict[str, dict[str, str]]:
    """Return a mapping ``locale → {key: value}`` by scanning *root* for catalogs."""
    catalogs: dict[str, dict[str, str]] = {}

    for dir_name in catalog_dir_names:
        catalog_root = root / dir_name
        if not catalog_root.is_dir():
            continue

        # i18next JSON
        for json_path in sorted(catalog_root.rglob("*.json")):
            locale = _locale_from_path(json_path, catalog_root)
            if locale is None:
                continue
            data = _load_json_catalog(json_path)
            if data:
                if locale not in catalogs:
                    catalogs[locale] = {}
                catalogs[locale].update(data)

        # gettext .po
        for po_path in sorted(catalog_root.rglob("*.po")):
            locale = _locale_from_path(po_path, catalog_root)
            if locale is None:
                continue
            data = _load_po_catalog(po_path)
            if data:
                if locale not in catalogs:
                    catalogs[locale] = {}
                catalogs[locale].update(data)

    return catalogs


# --------------------------------------------------------------------------- #
# Public entry point                                                           #
# --------------------------------------------------------------------------- #


def check_catalog_coverage(
    ctx: ScanContext,
    config: dict,
) -> list[Finding]:
    """Check i18n catalog coverage and return coverage-gap findings.

    Config keys consumed:
    - ``required_locales``: list[str] — locales that must have complete catalogs
    - ``catalog_dirs``: list[str] — directory names to search (default: standard set)
    """
    required_locales: list[str] = [lc.lower() for lc in config.get("required_locales", ["en"])]
    catalog_dir_names: tuple[str, ...] = tuple(
        config.get("catalog_dirs", list(_DEFAULT_CATALOG_DIRS))
    )

    catalogs = _discover_catalogs(ctx.root, catalog_dir_names)

    if not catalogs:
        return [
            Finding(
                rule_id="i18n/catalog-not-found",
                path=str(ctx.root),
                line=0,
                severity=Severity.INFO,
                message="No i18n catalogs found — catalog coverage check not applicable",
                detail=(
                    f"Searched for directories: {', '.join(catalog_dir_names)}. "
                    "Add a 'locales/' directory with locale JSON files or gettext .po files."
                ),
            )
        ]

    findings: list[Finding] = []

    # Base locale for key comparison — first required locale or "en"
    base_locale = required_locales[0] if required_locales else "en"
    base_keys = set(catalogs.get(base_locale, {}).keys())

    # 1. Missing locale catalogs
    for locale in required_locales:
        if locale not in catalogs:
            findings.append(
                Finding(
                    rule_id="i18n/missing-locale",
                    path=str(ctx.root),
                    line=0,
                    severity=Severity.ERROR,
                    message=f"Required locale '{locale}' has no catalog",
                    detail=(
                        f"Create a catalog for '{locale}' in one of: {', '.join(catalog_dir_names)}"
                    ),
                )
            )

    # 2. Missing or empty keys per non-base locale
    for locale in required_locales:
        if locale == base_locale or locale not in catalogs:
            continue
        locale_keys = set(catalogs[locale].keys())
        locale_values = catalogs[locale]

        missing = base_keys - locale_keys
        empty = {k for k in (base_keys & locale_keys) if not locale_values.get(k, "").strip()}

        for key in sorted(missing):
            findings.append(
                Finding(
                    rule_id="i18n/missing-key",
                    path=str(ctx.root),
                    line=0,
                    severity=Severity.WARNING,
                    message=f"Key '{key}' missing in locale '{locale}'",
                    detail=f"Add translation for '{key}' in the '{locale}' catalog.",
                )
            )

        for key in sorted(empty):
            findings.append(
                Finding(
                    rule_id="i18n/empty-translation",
                    path=str(ctx.root),
                    line=0,
                    severity=Severity.WARNING,
                    message=f"Key '{key}' has empty translation in locale '{locale}'",
                    detail=(
                        f"Provide a non-empty translation for '{key}' in the '{locale}' catalog."
                    ),
                )
            )

    # 3. Empty translations in the base locale itself
    if base_locale in catalogs:
        for key, val in sorted(catalogs[base_locale].items()):
            if not val.strip():
                findings.append(
                    Finding(
                        rule_id="i18n/empty-translation",
                        path=str(ctx.root),
                        line=0,
                        severity=Severity.WARNING,
                        message=f"Key '{key}' has empty translation in base locale '{base_locale}'",
                        detail=(
                            f"Provide a non-empty translation for '{key}' "
                            f"in the '{base_locale}' catalog."
                        ),
                    )
                )

    return findings
