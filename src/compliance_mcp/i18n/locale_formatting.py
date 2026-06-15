"""I18N-2: Flag non-locale-aware date, number, and currency formatting.

Uses regex heuristics on raw source text — no AST required. The patterns are
conservative: they match only the most common non-locale patterns and are
intentionally skewed toward false-negatives over false-positives.
"""

from __future__ import annotations

import re
from pathlib import Path

try:
    from compliance_mcp.models import Finding, ScanContext, Severity  # type: ignore[import]
except ImportError:
    from compliance_mcp.i18n._types import (  # type: ignore[assignment]
        Finding,
        ScanContext,
        Severity,
    )


# --------------------------------------------------------------------------- #
# Patterns                                                                     #
# --------------------------------------------------------------------------- #

# JS/TS patterns that produce non-locale-aware output
_JS_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(r"\btoDateString\s*\(\s*\)"),
        "i18n/non-locale-date",
        "Date.toDateString() is not locale-aware; use toLocaleDateString() or Intl.DateTimeFormat",
    ),
    (
        re.compile(r"\btoTimeString\s*\(\s*\)"),
        "i18n/non-locale-date",
        "Date.toTimeString() is not locale-aware; use toLocaleTimeString() or Intl.DateTimeFormat",
    ),
    (
        re.compile(r"\btoUTCString\s*\(\s*\)"),
        "i18n/non-locale-date",
        "Date.toUTCString() is not locale-aware; use Intl.DateTimeFormat with timeZone",
    ),
    (
        # number.toString() used in display context (heuristic: assigned to a variable
        # called text/label/display/value ending in displayed/formatted)
        re.compile(
            r"(?:price|amount|total|cost|fee|balance|count|num(?:ber)?)\.toString\s*\(\s*\)"
        ),
        "i18n/non-locale-number",
        "Numeric .toString() is not locale-aware; use toLocaleString() or Intl.NumberFormat",
    ),
    (
        # Currency concatenation: "$" + amount, amount + " USD"
        re.compile(r'["\'][$€£¥₹]\s*["\']\s*\+\s*\w'),
        "i18n/non-locale-currency",
        "Currency symbol concatenation is not locale-aware; "
        "use Intl.NumberFormat with style:'currency'",
    ),
    (
        re.compile(r'\w\s*\+\s*["\']\s*(?:USD|EUR|GBP|JPY|CAD)["\']'),
        "i18n/non-locale-currency",
        "Currency code concatenation is not locale-aware; "
        "use Intl.NumberFormat with style:'currency'",
    ),
]

# Python patterns that produce non-locale-aware output
_PY_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (
        # str() wrapping a date/datetime variable
        re.compile(
            r"\bstr\s*\(\s*(?:date|datetime|time|dt|d|t|created_at|updated_at|timestamp)\b"
        ),
        "i18n/non-locale-date",
        "str() on a date/datetime is not locale-aware; use babel.dates.format_date() or similar",
    ),
    (
        # f-string with a date variable: f"{date}" or f"{dt}"
        re.compile(
            r'f["\'].*\{(?:date|datetime|time|dt|d|created_at|updated_at|timestamp)\b[^}]*\}'
        ),
        "i18n/non-locale-date",
        "Formatting a date in an f-string is not locale-aware; use a locale-aware formatter",
    ),
    (
        # strftime without locale argument
        re.compile(r"\.strftime\s*\("),
        "i18n/non-locale-date",
        ".strftime() is not locale-aware; use babel.dates.format_datetime() for localized output",
    ),
    (
        # str() on a price/amount/number variable
        re.compile(
            r"\bstr\s*\(\s*(?:price|amount|total|cost|fee|balance|num(?:ber)?|count)\b"
        ),
        "i18n/non-locale-number",
        "str() on a number is not locale-aware; use babel.numbers.format_number() or similar",
    ),
    (
        # f-string with a price/amount variable
        re.compile(
            r'f["\'].*\{(?:price|amount|total|cost|fee|balance)\b[^}]*\}'
        ),
        "i18n/non-locale-number",
        "Formatting a number/currency in an f-string is not locale-aware; "
        "use a locale-aware formatter",
    ),
]

_TEST_PATH_RE = re.compile(
    r"(?:\.test\.|\.spec\.|_test\.(py|js|ts|jsx|tsx)$|[/\\]__tests__[/\\])",
    re.IGNORECASE,
)


# --------------------------------------------------------------------------- #
# Implementation                                                               #
# --------------------------------------------------------------------------- #


def _scan_source(
    path: Path,
    lines: list[str],
    patterns: list[tuple[re.Pattern[str], str, str]],
) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(lines, start=1):
        for pat, rule_id, detail in patterns:
            m = pat.search(line)
            if m:
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        path=str(path),
                        line=lineno,
                        col=m.start(),
                        severity=Severity.WARNING,
                        message="Non-locale-aware formatting detected",
                        detail=detail,
                        suggestion=detail.split(";", 1)[-1].strip() if ";" in detail else detail,
                    )
                )
                break  # one finding per line per file is enough for this heuristic
    return findings


def check_locale_formatting(
    ctx: ScanContext,
    framework: object = None,  # noqa: ARG001 — reserved for future framework-specific rules
) -> list[Finding]:
    """Scan *ctx.files* for non-locale-aware date/number/currency formatting."""
    findings: list[Finding] = []

    for file_path in ctx.files:
        if _TEST_PATH_RE.search(str(file_path).replace("\\", "/")):
            continue

        ext = file_path.suffix.lower()

        if ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
            try:
                lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            findings.extend(_scan_source(file_path, lines, _JS_PATTERNS))

        elif ext == ".py":
            try:
                lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            findings.extend(_scan_source(file_path, lines, _PY_PATTERNS))

    return findings
