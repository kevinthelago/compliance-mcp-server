"""Tests for I18N-2: non-locale-aware date/number/currency formatting."""

from __future__ import annotations

from pathlib import Path

from compliance_mcp.i18n._types import ScanContext, Severity
from compliance_mcp.i18n.locale_formatting import check_locale_formatting

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "i18n"
JSX_FILE = FIXTURE_DIR / "react_component.jsx"
PY_FILE = FIXTURE_DIR / "python_view.py"


# ---------------------------------------------------------------------------
# JS/JSX fixture
# ---------------------------------------------------------------------------


def test_jsx_toDateString_flagged():
    ctx = ScanContext(root=FIXTURE_DIR, files=[JSX_FILE], config={})
    findings = check_locale_formatting(ctx)
    rule_ids = [f.rule_id for f in findings]
    assert "i18n/non-locale-date" in rule_ids


def test_jsx_toTimeString_flagged():
    ctx = ScanContext(root=FIXTURE_DIR, files=[JSX_FILE], config={})
    findings = check_locale_formatting(ctx)
    assert any("toTimeString" in (f.detail or "") for f in findings)


# ---------------------------------------------------------------------------
# Python fixture
# ---------------------------------------------------------------------------


def test_py_strftime_flagged():
    ctx = ScanContext(root=FIXTURE_DIR, files=[PY_FILE], config={})
    findings = check_locale_formatting(ctx)
    rule_ids = [f.rule_id for f in findings]
    assert "i18n/non-locale-date" in rule_ids


def test_py_str_date_flagged():
    ctx = ScanContext(root=FIXTURE_DIR, files=[PY_FILE], config={})
    findings = check_locale_formatting(ctx)
    # str(dt) or f-string with date should be flagged
    assert any(f.rule_id == "i18n/non-locale-date" for f in findings)


# ---------------------------------------------------------------------------
# Currency patterns (inline)
# ---------------------------------------------------------------------------


def test_js_currency_concat_flagged(tmp_path):
    f = tmp_path / "price.js"
    f.write_text('const label = "$" + price;', encoding="utf-8")
    ctx = ScanContext(root=tmp_path, files=[f], config={})
    findings = check_locale_formatting(ctx)
    assert any(f.rule_id == "i18n/non-locale-currency" for f in findings)


def test_js_currency_code_flagged(tmp_path):
    f = tmp_path / "price.js"
    f.write_text('const label = amount + " USD";', encoding="utf-8")
    ctx = ScanContext(root=tmp_path, files=[f], config={})
    findings = check_locale_formatting(ctx)
    assert any(f.rule_id == "i18n/non-locale-currency" for f in findings)


def test_js_number_tostring_flagged(tmp_path):
    f = tmp_path / "fmt.js"
    f.write_text("const display = price.toString();", encoding="utf-8")
    ctx = ScanContext(root=tmp_path, files=[f], config={})
    findings = check_locale_formatting(ctx)
    assert any(f.rule_id == "i18n/non-locale-number" for f in findings)


# ---------------------------------------------------------------------------
# Test files excluded
# ---------------------------------------------------------------------------


def test_test_file_skipped(tmp_path):
    f = tmp_path / "helpers.test.js"
    f.write_text("const d = new Date().toDateString();", encoding="utf-8")
    ctx = ScanContext(root=tmp_path, files=[f], config={})
    findings = check_locale_formatting(ctx)
    assert findings == []


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


def test_findings_severity_warning():
    ctx = ScanContext(root=FIXTURE_DIR, files=[JSX_FILE], config={})
    findings = check_locale_formatting(ctx)
    assert all(f.severity == Severity.WARNING for f in findings)


# ---------------------------------------------------------------------------
# No false positives on already-locale-aware code
# ---------------------------------------------------------------------------


def test_locale_aware_js_not_flagged(tmp_path):
    f = tmp_path / "ok.js"
    f.write_text(
        "const d = new Intl.DateTimeFormat(locale).format(date);",
        encoding="utf-8",
    )
    ctx = ScanContext(root=tmp_path, files=[f], config={})
    findings = check_locale_formatting(ctx)
    assert not any(f.rule_id == "i18n/non-locale-date" for f in findings)
