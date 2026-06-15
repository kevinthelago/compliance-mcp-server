"""Tests for I18N-5: I18nLens integration."""

from __future__ import annotations

from pathlib import Path

from compliance_mcp.i18n._types import ScanContext, Severity
from compliance_mcp.lenses.i18n import I18nLens, _apply_severity_policy

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "i18n"


def _make_ctx(files=None, config=None):
    return ScanContext(
        root=FIXTURE_DIR,
        files=files or list(FIXTURE_DIR.glob("*")),
        config=config or {},
    )


# ---------------------------------------------------------------------------
# Lens metadata
# ---------------------------------------------------------------------------


def test_lens_name():
    assert I18nLens.name == "i18n"


def test_lens_is_instantiable():
    lens = I18nLens()
    assert lens.name == "i18n"


# ---------------------------------------------------------------------------
# run() returns a list of Finding
# ---------------------------------------------------------------------------


def test_run_returns_list():
    ctx = _make_ctx(config={"i18n": {"required_locales": ["en", "ar"]}})
    lens = I18nLens()
    result = lens.run(ctx)
    assert isinstance(result, list)


def test_run_finds_hardcoded_strings():
    ctx = _make_ctx(
        files=[FIXTURE_DIR / "react_component.jsx"],
        config={"i18n": {}},
    )
    lens = I18nLens()
    result = lens.run(ctx)
    rule_ids = {f.rule_id for f in result}
    assert "i18n/hardcoded-string" in rule_ids


def test_run_finds_locale_formatting():
    ctx = _make_ctx(
        files=[FIXTURE_DIR / "react_component.jsx"],
        config={"i18n": {}},
    )
    lens = I18nLens()
    result = lens.run(ctx)
    rule_ids = {f.rule_id for f in result}
    assert "i18n/non-locale-date" in rule_ids


def test_run_finds_catalog_gaps():
    ctx = _make_ctx(
        files=[],
        config={"i18n": {"required_locales": ["en", "es"], "catalog_dirs": ["locales"]}},
    )
    lens = I18nLens()
    result = lens.run(ctx)
    rule_ids = {f.rule_id for f in result}
    assert "i18n/missing-key" in rule_ids


def test_run_finds_rtl_issues():
    ctx = _make_ctx(
        files=[FIXTURE_DIR / "styles.css"],
        config={"i18n": {"required_locales": ["en", "ar"]}},
    )
    lens = I18nLens()
    result = lens.run(ctx)
    rule_ids = {f.rule_id for f in result}
    assert "i18n/rtl-physical-property" in rule_ids or "i18n/rtl-physical-value" in rule_ids


# ---------------------------------------------------------------------------
# Severity policy — low confidence downgraded to INFO
# ---------------------------------------------------------------------------


def test_low_confidence_downgraded_to_info(tmp_path):
    from compliance_mcp.i18n._types import Finding

    f = Finding(
        rule_id="i18n/hardcoded-string",
        path="x.js",
        line=1,
        severity=Severity.WARNING,
        extra={"confidence": "low"},
    )
    result = _apply_severity_policy(f, {})
    assert result.severity == Severity.INFO


def test_high_confidence_not_downgraded():
    from compliance_mcp.i18n._types import Finding

    f = Finding(
        rule_id="i18n/hardcoded-string",
        path="x.js",
        line=1,
        severity=Severity.WARNING,
        extra={"confidence": "high"},
    )
    result = _apply_severity_policy(f, {})
    assert result.severity == Severity.WARNING


def test_elevate_heuristics_preserves_severity():
    from compliance_mcp.i18n._types import Finding

    f = Finding(
        rule_id="i18n/hardcoded-string",
        path="x.js",
        line=1,
        severity=Severity.WARNING,
        extra={"confidence": "low"},
    )
    result = _apply_severity_policy(f, {"elevate_heuristics": True})
    assert result.severity == Severity.WARNING


def test_run_low_confidence_findings_are_info():
    ctx = _make_ctx(
        files=[FIXTURE_DIR / "react_component.jsx"],
        config={"i18n": {}},
    )
    lens = I18nLens()
    result = lens.run(ctx)
    low = [f for f in result if f.extra.get("confidence") == "low"]
    assert all(f.severity == Severity.INFO for f in low)


# ---------------------------------------------------------------------------
# Framework detection is called (smoke test)
# ---------------------------------------------------------------------------


def test_run_with_package_json(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text(
        '{"dependencies": {"react": "18.0.0", "i18next": "23.0.0"}}',
        encoding="utf-8",
    )
    jsx = tmp_path / "comp.jsx"
    jsx.write_text("<div>Hello world</div>", encoding="utf-8")

    ctx = ScanContext(root=tmp_path, files=[jsx], config={"i18n": {}})
    lens = I18nLens()
    result = lens.run(ctx)
    assert isinstance(result, list)
    # Should flag the hardcoded JSX text
    rule_ids = {f.rule_id for f in result}
    assert "i18n/hardcoded-string" in rule_ids


# ---------------------------------------------------------------------------
# Empty scan context — should not crash
# ---------------------------------------------------------------------------


def test_run_no_files_no_crash(tmp_path):
    ctx = ScanContext(root=tmp_path, files=[], config={})
    lens = I18nLens()
    result = lens.run(ctx)
    # Just a "not applicable" catalog finding or empty
    assert isinstance(result, list)
