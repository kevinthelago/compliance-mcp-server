"""Tests for I18N-3: catalog coverage check."""

from __future__ import annotations

from pathlib import Path

from compliance_mcp.i18n._types import ScanContext, Severity
from compliance_mcp.i18n.catalog_coverage import (
    _flatten_json,
    _load_json_catalog,
    _load_po_catalog,
    _locale_from_path,
    check_catalog_coverage,
)

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "i18n"


# ---------------------------------------------------------------------------
# _flatten_json
# ---------------------------------------------------------------------------


def test_flatten_flat():
    assert _flatten_json({"a": "1", "b": "2"}) == {"a": "1", "b": "2"}


def test_flatten_nested():
    result = _flatten_json({"ns": {"key": "val"}})
    assert "ns.key" in result
    assert result["ns.key"] == "val"


def test_flatten_deeply_nested():
    result = _flatten_json({"a": {"b": {"c": "d"}}})
    assert result == {"a.b.c": "d"}


# ---------------------------------------------------------------------------
# _locale_from_path
# ---------------------------------------------------------------------------


def test_locale_from_json_filename():
    p = Path("locales/en.json")
    root = Path("locales")
    assert _locale_from_path(p, root) == "en"


def test_locale_from_po_path():
    p = Path("locale/es/LC_MESSAGES/messages.po")
    root = Path("locale")
    assert _locale_from_path(p, root) == "es"


def test_locale_from_subdirectory():
    p = Path("translations/fr/common.json")
    root = Path("translations")
    assert _locale_from_path(p, root) == "fr"


# ---------------------------------------------------------------------------
# _load_json_catalog
# ---------------------------------------------------------------------------


def test_load_json_catalog_en():
    path = FIXTURE_DIR / "locales" / "en.json"
    result = _load_json_catalog(path)
    assert result["greeting"] == "Hello"
    assert result["farewell"] == "Goodbye"


def test_load_json_catalog_es():
    path = FIXTURE_DIR / "locales" / "es.json"
    result = _load_json_catalog(path)
    assert result["greeting"] == "Hola"
    assert "farewell" not in result


def test_load_json_bad_file(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json", encoding="utf-8")
    result = _load_json_catalog(bad)
    assert result == {}


# ---------------------------------------------------------------------------
# _load_po_catalog
# ---------------------------------------------------------------------------


def test_load_po_catalog_en():
    path = FIXTURE_DIR / "locale" / "en" / "LC_MESSAGES" / "messages.po"
    result = _load_po_catalog(path)
    assert result.get("Hello") == "Hello"
    assert result.get("Goodbye") == "Goodbye"


def test_load_po_catalog_es():
    path = FIXTURE_DIR / "locale" / "es" / "LC_MESSAGES" / "messages.po"
    result = _load_po_catalog(path)
    assert result.get("Hello") == "Hola"
    assert result.get("Goodbye") == ""  # empty translation


# ---------------------------------------------------------------------------
# check_catalog_coverage — JSON catalogs
# ---------------------------------------------------------------------------


def test_no_catalogs_returns_not_applicable(tmp_path):
    ctx = ScanContext(root=tmp_path, files=[], config={})
    findings = check_catalog_coverage(ctx, {})
    assert len(findings) == 1
    assert findings[0].rule_id == "i18n/catalog-not-found"
    assert findings[0].severity == Severity.INFO


def test_missing_locale_reported():
    ctx = ScanContext(root=FIXTURE_DIR, files=[], config={})
    config = {
        "required_locales": ["en", "es", "de"],
        "catalog_dirs": ["locales"],
    }
    findings = check_catalog_coverage(ctx, config)
    rule_ids = {f.rule_id for f in findings}
    assert "i18n/missing-locale" in rule_ids
    missing_msgs = [f.message for f in findings if f.rule_id == "i18n/missing-locale"]
    assert any("de" in m for m in missing_msgs)


def test_missing_key_reported():
    ctx = ScanContext(root=FIXTURE_DIR, files=[], config={})
    config = {
        "required_locales": ["en", "es"],
        "catalog_dirs": ["locales"],
    }
    findings = check_catalog_coverage(ctx, config)
    rule_ids = {f.rule_id for f in findings}
    assert "i18n/missing-key" in rule_ids
    missing_key_msgs = [f.message for f in findings if f.rule_id == "i18n/missing-key"]
    assert any("farewell" in m for m in missing_key_msgs)


def test_missing_key_es_severity():
    ctx = ScanContext(root=FIXTURE_DIR, files=[], config={})
    config = {"required_locales": ["en", "es"], "catalog_dirs": ["locales"]}
    findings = check_catalog_coverage(ctx, config)
    missing = [f for f in findings if f.rule_id == "i18n/missing-key"]
    assert all(f.severity == Severity.WARNING for f in missing)


# ---------------------------------------------------------------------------
# check_catalog_coverage — PO catalogs
# ---------------------------------------------------------------------------


def test_po_empty_translation_reported():
    ctx = ScanContext(root=FIXTURE_DIR, files=[], config={})
    config = {
        "required_locales": ["en", "es"],
        "catalog_dirs": ["locale"],
    }
    findings = check_catalog_coverage(ctx, config)
    rule_ids = {f.rule_id for f in findings}
    assert "i18n/empty-translation" in rule_ids
    empty_msgs = [f.message for f in findings if f.rule_id == "i18n/empty-translation"]
    assert any("Goodbye" in m or "es" in m for m in empty_msgs)


# ---------------------------------------------------------------------------
# Inline JSON catalog tests
# ---------------------------------------------------------------------------


def test_custom_catalog_dir(tmp_path):
    tr_dir = tmp_path / "translations"
    tr_dir.mkdir()
    (tr_dir / "en.json").write_text(
        '{"title": "Hello", "body": "World"}', encoding="utf-8"
    )
    (tr_dir / "fr.json").write_text('{"title": "Bonjour"}', encoding="utf-8")

    ctx = ScanContext(root=tmp_path, files=[], config={})
    config = {"required_locales": ["en", "fr"], "catalog_dirs": ["translations"]}
    findings = check_catalog_coverage(ctx, config)
    rule_ids = {f.rule_id for f in findings}
    assert "i18n/missing-key" in rule_ids


def test_complete_catalogs_no_gap_findings(tmp_path):
    loc_dir = tmp_path / "locales"
    loc_dir.mkdir()
    (loc_dir / "en.json").write_text('{"a": "A", "b": "B"}', encoding="utf-8")
    (loc_dir / "es.json").write_text('{"a": "Aa", "b": "Bb"}', encoding="utf-8")

    ctx = ScanContext(root=tmp_path, files=[], config={})
    config = {"required_locales": ["en", "es"], "catalog_dirs": ["locales"]}
    findings = check_catalog_coverage(ctx, config)
    rule_ids = {f.rule_id for f in findings}
    assert "i18n/missing-key" not in rule_ids
    assert "i18n/missing-locale" not in rule_ids
    assert "i18n/empty-translation" not in rule_ids
