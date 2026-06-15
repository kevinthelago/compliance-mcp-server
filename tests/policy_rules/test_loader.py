"""Tests for the YAML rule loader (PAC-1)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from compliance_mcp.policy_rules.loader import load_rules
from compliance_mcp.policy_rules.schema import AssertionType


def _write_rules(tmp_path: Path, filename: str, content: object) -> Path:
    p = tmp_path / filename
    p.write_text(yaml.dump(content), encoding="utf-8")
    return p


class TestLoadRules:
    def test_loads_valid_rules(self, tmp_path: Path) -> None:
        _write_rules(
            tmp_path,
            "rules.yaml",
            [
                {
                    "id": "require-license",
                    "description": "LICENSE must exist",
                    "severity": "high",
                    "controls": ["OSS-1.1"],
                    "domain": "documentation",
                    "target": "LICENSE*",
                    "assertion": {"type": "file-present"},
                }
            ],
        )
        rules = load_rules(tmp_path)
        assert len(rules) == 1
        assert rules[0].id == "require-license"
        assert rules[0].severity == "high"
        assert rules[0].controls == ["OSS-1.1"]

    def test_skips_malformed_rule_keeps_valid(self, tmp_path: Path) -> None:
        _write_rules(
            tmp_path,
            "rules.yaml",
            [
                {"id": "bad-rule"},  # missing required 'target' and 'assertion'
                {
                    "id": "good-rule",
                    "target": "LICENSE",
                    "assertion": {"type": "file-present"},
                },
            ],
        )
        rules = load_rules(tmp_path)
        assert len(rules) == 1
        assert rules[0].id == "good-rule"

    def test_skips_non_list_file(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        p = tmp_path / "bad.yaml"
        p.write_text("id: single-item\n", encoding="utf-8")
        rules = load_rules(tmp_path)
        assert rules == []
        assert "must contain a YAML list" in caplog.text

    def test_skips_unparseable_file(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        p = tmp_path / "corrupt.yaml"
        p.write_text("{ invalid yaml: [", encoding="utf-8")
        rules = load_rules(tmp_path)
        assert rules == []

    def test_returns_empty_for_missing_dir(self, tmp_path: Path) -> None:
        rules = load_rules(tmp_path / "nonexistent")
        assert rules == []

    def test_loads_multiple_files_sorted(self, tmp_path: Path) -> None:
        _write_rules(
            tmp_path,
            "b_rules.yaml",
            [{"id": "rule-b", "target": "B", "assertion": {"type": "file-present"}}],
        )
        _write_rules(
            tmp_path,
            "a_rules.yaml",
            [{"id": "rule-a", "target": "A", "assertion": {"type": "file-present"}}],
        )
        rules = load_rules(tmp_path)
        assert [r.id for r in rules] == ["rule-a", "rule-b"]

    def test_all_assertion_types_parse(self, tmp_path: Path) -> None:
        _write_rules(
            tmp_path,
            "all.yaml",
            [
                {"id": "fp", "target": "X", "assertion": {"type": "file-present"}},
                {"id": "fa", "target": "X", "assertion": {"type": "file-absent"}},
                {
                    "id": "cm",
                    "target": "X",
                    "assertion": {"type": "content-matches", "pattern": "foo"},
                },
                {
                    "id": "cnm",
                    "target": "X",
                    "assertion": {"type": "content-not-matches", "pattern": "foo"},
                },
                {
                    "id": "sp",
                    "target": "X",
                    "assertion": {"type": "structured-path", "path": "key", "exists": True},
                },
            ],
        )
        rules = load_rules(tmp_path)
        types = [r.assertion.type for r in rules]
        assert AssertionType.FILE_PRESENT in types
        assert AssertionType.FILE_ABSENT in types
        assert AssertionType.CONTENT_MATCHES in types
        assert AssertionType.CONTENT_NOT_MATCHES in types
        assert AssertionType.STRUCTURED_PATH in types

    def test_assertion_missing_pattern_is_invalid(self, tmp_path: Path) -> None:
        _write_rules(
            tmp_path,
            "bad.yaml",
            [{"id": "no-pattern", "target": "X", "assertion": {"type": "content-matches"}}],
        )
        rules = load_rules(tmp_path)
        assert rules == []

    def test_structured_path_requires_check(self, tmp_path: Path) -> None:
        _write_rules(
            tmp_path,
            "bad.yaml",
            [
                # missing exists/equals/matches
                {
                    "id": "no-check",
                    "target": "X",
                    "assertion": {"type": "structured-path", "path": "foo"},
                }
            ],
        )
        rules = load_rules(tmp_path)
        assert rules == []

    def test_loads_project_starter_ruleset(self, rules_dir: Path) -> None:
        rules = load_rules(rules_dir)
        ids = [r.id for r in rules]
        assert "require-license" in ids
        assert "require-security-md" in ids
        assert "no-committed-env" in ids
        assert "ci-runs-tests" in ids
