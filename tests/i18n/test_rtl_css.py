"""Tests for I18N-4: RTL physical CSS property detection."""

from __future__ import annotations

from pathlib import Path

import pytest

from compliance_mcp.i18n._types import ScanContext, Severity
from compliance_mcp.i18n.rtl_css import (
    _has_rtl_locale,
    _scan_css_file,
    check_rtl_css,
)

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "i18n"
CSS_FILE = FIXTURE_DIR / "styles.css"


# ---------------------------------------------------------------------------
# _has_rtl_locale
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "locales, expected",
    [
        (["en", "ar"], True),
        (["en", "he"], True),
        (["en", "fa"], True),
        (["en", "ur"], True),
        (["en", "fr"], False),
        ([], False),
        (["en"], False),
    ],
)
def test_has_rtl_locale(locales, expected):
    assert _has_rtl_locale(locales) == expected


# ---------------------------------------------------------------------------
# _scan_css_file — fixture
# ---------------------------------------------------------------------------


def test_margin_left_flagged():
    findings = _scan_css_file(CSS_FILE)
    props = [f.message for f in findings]
    assert any("margin-left" in p for p in props)


def test_margin_right_flagged():
    findings = _scan_css_file(CSS_FILE)
    props = [f.message for f in findings]
    assert any("margin-right" in p for p in props)


def test_padding_left_flagged():
    findings = _scan_css_file(CSS_FILE)
    props = [f.message for f in findings]
    assert any("padding-left" in p for p in props)


def test_text_align_left_flagged():
    findings = _scan_css_file(CSS_FILE)
    rule_ids = [f.rule_id for f in findings]
    assert "i18n/rtl-physical-value" in rule_ids
    msgs = [f.message for f in findings if f.rule_id == "i18n/rtl-physical-value"]
    assert any("text-align" in m for m in msgs)


def test_float_left_flagged():
    findings = _scan_css_file(CSS_FILE)
    msgs = [f.message for f in findings if f.rule_id == "i18n/rtl-physical-value"]
    assert any("float" in m for m in msgs)


def test_border_radius_flagged():
    findings = _scan_css_file(CSS_FILE)
    props = [f.message for f in findings]
    assert any("border-top-left-radius" in p or "border-top-right-radius" in p for p in props)


def test_left_positioning_flagged():
    findings = _scan_css_file(CSS_FILE)
    msgs = [f.message for f in findings if f.rule_id == "i18n/rtl-physical-property"]
    assert any("left" in m for m in msgs)


def test_logical_props_not_flagged():
    findings = _scan_css_file(CSS_FILE)
    msgs = [f.message for f in findings]
    assert not any("margin-inline-start" in m for m in msgs)
    assert not any("padding-inline-end" in m for m in msgs)


def test_text_align_center_not_flagged():
    findings = _scan_css_file(CSS_FILE)
    msgs = [f.message for f in findings]
    assert not any("text-align: center" in m for m in msgs)


def test_severity_is_warning():
    findings = _scan_css_file(CSS_FILE)
    assert all(f.severity == Severity.WARNING for f in findings)


def test_suggestion_present():
    findings = _scan_css_file(CSS_FILE)
    # All findings should have a non-empty suggestion
    assert all(f.suggestion for f in findings)


# ---------------------------------------------------------------------------
# check_rtl_css — requires RTL locale in config
# ---------------------------------------------------------------------------


def test_no_rtl_locale_returns_empty():
    ctx = ScanContext(root=FIXTURE_DIR, files=[CSS_FILE], config={})
    config = {"required_locales": ["en", "fr"]}
    findings = check_rtl_css(ctx, config)
    assert findings == []


def test_with_rtl_locale_returns_findings():
    ctx = ScanContext(root=FIXTURE_DIR, files=[CSS_FILE], config={})
    config = {"required_locales": ["en", "ar"]}
    findings = check_rtl_css(ctx, config)
    assert len(findings) > 0


def test_no_required_locales_returns_empty():
    ctx = ScanContext(root=FIXTURE_DIR, files=[CSS_FILE], config={})
    config = {}
    findings = check_rtl_css(ctx, config)
    assert findings == []


# ---------------------------------------------------------------------------
# Inline CSS
# ---------------------------------------------------------------------------


def test_inline_css_physical_props(tmp_path):
    css = tmp_path / "styles.css"
    css.write_text(
        ".btn { padding-left: 10px; padding-right: 10px; }",
        encoding="utf-8",
    )
    ctx = ScanContext(root=tmp_path, files=[css], config={})
    findings = check_rtl_css(ctx, {"required_locales": ["en", "he"]})
    props = [f.message for f in findings]
    assert any("padding-left" in p for p in props)
    assert any("padding-right" in p for p in props)


def test_already_logical_css_clean(tmp_path):
    css = tmp_path / "styles.css"
    css.write_text(
        ".btn { padding-inline-start: 10px; margin-inline-end: 4px; }",
        encoding="utf-8",
    )
    ctx = ScanContext(root=tmp_path, files=[css], config={})
    findings = check_rtl_css(ctx, {"required_locales": ["en", "ar"]})
    assert findings == []
