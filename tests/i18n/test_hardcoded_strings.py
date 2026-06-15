"""Tests for I18N-1: hardcoded string detection."""

from __future__ import annotations

from pathlib import Path

import pytest

from compliance_mcp.i18n._types import ScanContext, Severity
from compliance_mcp.i18n.framework_detection import FrameworkInfo
from compliance_mcp.i18n.hardcoded_strings import (
    _is_boring,
    _to_catalog_key,
    check_hardcoded_strings,
)

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "i18n"
JSX_FILE = FIXTURE_DIR / "react_component.jsx"
PY_FILE = FIXTURE_DIR / "python_view.py"


# ---------------------------------------------------------------------------
# Unit tests for helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "s, expected",
    [
        ("", True),
        ("a", True),
        ("x", True),  # single char
        ("https://example.com", True),  # URL
        ("SOME_CONSTANT", True),  # ALL_CAPS (3+ chars)
        ("42", True),  # numeric
        ("app.title", True),  # dotted identifier
        ("Hello world", False),
        ("Sign in", False),
        ("Enter your email", False),
    ],
)
def test_is_boring(s, expected):
    assert _is_boring(s) == expected


@pytest.mark.parametrize(
    "s, expected_contains",
    [
        ("Hello world", "hello_world"),
        ("Enter your email address", "enter_your_email_address"),
        ("Sign in to your account", "sign_in_to_your_account"),
    ],
)
def test_to_catalog_key(s, expected_contains):
    assert _to_catalog_key(s) == expected_contains


# ---------------------------------------------------------------------------
# JSX fixture tests
# ---------------------------------------------------------------------------


def _jsx_findings():
    framework = FrameworkInfo(js_framework="react", has_jsx=True, has_tsx=True)
    ctx = ScanContext(root=FIXTURE_DIR, files=[JSX_FILE], config={})
    return check_hardcoded_strings(ctx, framework, {})


def test_jsx_text_flagged():
    findings = _jsx_findings()
    literals = [f.extra["literal"] for f in findings]
    assert any("Welcome to our application" in lit for lit in literals)
    assert any("Please sign in to continue" in lit for lit in literals)


def test_jsx_placeholder_flagged():
    findings = _jsx_findings()
    literals = [f.extra["literal"] for f in findings]
    assert any("Enter your email address" in lit for lit in literals)
    assert any("Enter your password" in lit for lit in literals)


def test_jsx_alt_flagged():
    findings = _jsx_findings()
    literals = [f.extra["literal"] for f in findings]
    assert any("Company logo" in lit for lit in literals)


def test_jsx_aria_label_flagged():
    findings = _jsx_findings()
    literals = [f.extra["literal"] for f in findings]
    assert any("Sign in to your account" in lit for lit in literals)


def test_jsx_console_log_not_flagged():
    findings = _jsx_findings()
    literals = [f.extra["literal"] for f in findings]
    assert not any("Debug" in lit for lit in literals)


def test_jsx_high_confidence_severity():
    findings = _jsx_findings()
    high = [f for f in findings if f.extra.get("confidence") == "high"]
    assert all(f.severity == Severity.WARNING for f in high)


def test_jsx_suggested_key_present():
    findings = _jsx_findings()
    assert all("suggested_key" in f.extra for f in findings)


def test_test_file_skipped(tmp_path):
    test_jsx = tmp_path / "button.test.jsx"
    test_jsx.write_text("<button>Submit</button>", encoding="utf-8")
    ctx = ScanContext(root=tmp_path, files=[test_jsx], config={})
    framework = FrameworkInfo()
    findings = check_hardcoded_strings(ctx, framework, {})
    assert findings == []


# ---------------------------------------------------------------------------
# Python fixture tests
# ---------------------------------------------------------------------------


def _py_findings():
    framework = FrameworkInfo(py_framework=None)
    ctx = ScanContext(root=FIXTURE_DIR, files=[PY_FILE], config={})
    return check_hardcoded_strings(ctx, framework, {})


def test_py_raise_flagged():
    findings = _py_findings()
    literals = [f.extra["literal"] for f in findings]
    assert any("Age must be a positive number" in lit for lit in literals)


def test_py_raise_medium_confidence():
    findings = _py_findings()
    medium = [f for f in findings if "Age must be a positive number" in f.extra.get("literal", "")]
    assert medium and medium[0].extra["confidence"] == "medium"


def test_py_logger_not_flagged():
    findings = _py_findings()
    literals = [f.extra["literal"] for f in findings]
    assert not any("Debug: processing started" in lit for lit in literals)


# ---------------------------------------------------------------------------
# ignore_strings config
# ---------------------------------------------------------------------------


def test_ignore_strings_respected(tmp_path):
    jsx = tmp_path / "comp.jsx"
    jsx.write_text("<div>Hello world</div>", encoding="utf-8")
    ctx = ScanContext(root=tmp_path, files=[jsx], config={})
    framework = FrameworkInfo(has_jsx=True)
    findings_before = check_hardcoded_strings(ctx, framework, {})
    findings_after = check_hardcoded_strings(ctx, framework, {"ignore_strings": ["Hello world"]})
    literals_after = [f.extra["literal"] for f in findings_after]
    assert not any("Hello world" in lit for lit in literals_after)
    # Without ignore list, it should be flagged
    literals_before = [f.extra["literal"] for f in findings_before]
    assert any("Hello world" in lit for lit in literals_before)


# ---------------------------------------------------------------------------
# TypeScript / TSX
# ---------------------------------------------------------------------------


def test_tsx_flagged(tmp_path):
    tsx = tmp_path / "comp.tsx"
    tsx.write_text(
        'export default function A() { return <input placeholder="Enter name" />; }',
        encoding="utf-8",
    )
    ctx = ScanContext(root=tmp_path, files=[tsx], config={})
    framework = FrameworkInfo(has_tsx=True)
    findings = check_hardcoded_strings(ctx, framework, {})
    literals = [f.extra.get("literal", "") for f in findings]
    assert any("Enter name" in lit for lit in literals)


def test_ts_plain_file_no_crash(tmp_path):
    ts = tmp_path / "util.ts"
    ts.write_text('export const greeting = "Hello there";', encoding="utf-8")
    ctx = ScanContext(root=tmp_path, files=[ts], config={})
    framework = FrameworkInfo()
    findings = check_hardcoded_strings(ctx, framework, {})
    # May or may not flag — just must not crash
    assert isinstance(findings, list)
