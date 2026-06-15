"""Tests for assertion primitives (PAC-2)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from compliance_mcp.models.finding import Lens, Severity
from compliance_mcp.policy_rules.assertions import evaluate
from compliance_mcp.policy_rules.schema import Rule


def _make_rule(
    rule_id: str,
    target: str,
    assertion_dict: dict,
    *,
    severity: str = "high",
    domain: str = "configuration",
    controls: list[str] | None = None,
) -> Rule:
    return Rule.model_validate(
        {
            "id": rule_id,
            "description": f"Test rule {rule_id}",
            "severity": severity,
            "controls": controls or [],
            "domain": domain,
            "target": target,
            "assertion": assertion_dict,
        }
    )


# ── file-present ──────────────────────────────────────────────────────────────


class TestFilePresent:
    def test_passes_when_file_exists(self, tmp_path: Path) -> None:
        (tmp_path / "LICENSE").write_text("MIT")
        rule = _make_rule("require-license", "LICENSE*", {"type": "file-present"})
        assert evaluate(rule, tmp_path) == []

    def test_violation_when_file_absent(self, tmp_path: Path) -> None:
        rule = _make_rule("require-license", "LICENSE*", {"type": "file-present"})
        findings = evaluate(rule, tmp_path)
        assert len(findings) == 1
        assert findings[0].rule_id == "pac.require-license"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].lens == Lens.CUSTOM

    def test_finding_file_path_is_dot(self, tmp_path: Path) -> None:
        rule = _make_rule("r", "MISSING", {"type": "file-present"})
        findings = evaluate(rule, tmp_path)
        assert findings[0].file_path == "."

    def test_control_refs_propagated(self, tmp_path: Path) -> None:
        rule = _make_rule("r", "X", {"type": "file-present"}, controls=["OSS-1.1"])
        findings = evaluate(rule, tmp_path)
        assert "OSS-1.1" in findings[0].control_refs

    def test_glob_matches_multiple_candidates(self, tmp_path: Path) -> None:
        (tmp_path / "LICENSE.md").write_text("MIT")
        rule = _make_rule("r", "LICENSE*", {"type": "file-present"})
        assert evaluate(rule, tmp_path) == []


# ── file-absent ───────────────────────────────────────────────────────────────


class TestFileAbsent:
    def test_passes_when_no_match(self, tmp_path: Path) -> None:
        rule = _make_rule("no-env", "**/.env", {"type": "file-absent"})
        assert evaluate(rule, tmp_path) == []

    def test_violation_for_each_match(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("SECRET=x")
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / ".env").write_text("KEY=y")
        rule = _make_rule("no-env", "**/.env", {"type": "file-absent"})
        findings = evaluate(rule, tmp_path)
        assert len(findings) == 2
        paths = {f.file_path for f in findings}
        assert ".env" in paths
        assert "subdir/.env" in paths

    def test_finding_severity_from_rule(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("x")
        rule = _make_rule("no-env", "**/.env", {"type": "file-absent"}, severity="critical")
        findings = evaluate(rule, tmp_path)
        assert findings[0].severity == Severity.CRITICAL


# ── content-matches ───────────────────────────────────────────────────────────


class TestContentMatches:
    def test_passes_when_pattern_found(self, tmp_path: Path) -> None:
        (tmp_path / "Dockerfile").write_text("FROM ubuntu\nUSER nonroot\n")
        rule = _make_rule(
            "non-root",
            "Dockerfile",
            {"type": "content-matches", "pattern": r"^USER\s+(?!root\b)", "flags": "MULTILINE"},
        )
        assert evaluate(rule, tmp_path) == []

    def test_violation_when_pattern_absent(self, tmp_path: Path) -> None:
        (tmp_path / "Dockerfile").write_text("FROM ubuntu\n")
        rule = _make_rule(
            "non-root",
            "Dockerfile",
            {"type": "content-matches", "pattern": r"^USER\s+", "flags": "MULTILINE"},
        )
        findings = evaluate(rule, tmp_path)
        assert len(findings) == 1
        assert "Dockerfile" in findings[0].file_path

    def test_multiline_flag_works(self, tmp_path: Path) -> None:
        (tmp_path / "Dockerfile").write_text("RUN echo hi\nUSER app\n")
        rule = _make_rule(
            "r",
            "Dockerfile",
            {"type": "content-matches", "pattern": r"^USER\s+app", "flags": "MULTILINE"},
        )
        assert evaluate(rule, tmp_path) == []

    def test_no_target_files_produces_no_findings(self, tmp_path: Path) -> None:
        rule = _make_rule("r", "Dockerfile", {"type": "content-matches", "pattern": "foo"})
        assert evaluate(rule, tmp_path) == []

    def test_invalid_regex_skips_rule(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        (tmp_path / "f.txt").write_text("hello")
        rule = _make_rule("r", "f.txt", {"type": "content-matches", "pattern": "[invalid"})
        findings = evaluate(rule, tmp_path)
        assert findings == []

    def test_ignorecase_flag(self, tmp_path: Path) -> None:
        (tmp_path / "f.txt").write_text("Hello World")
        rule = _make_rule(
            "r", "f.txt", {"type": "content-matches", "pattern": "hello", "flags": "IGNORECASE"}
        )
        assert evaluate(rule, tmp_path) == []


# ── content-not-matches ───────────────────────────────────────────────────────


class TestContentNotMatches:
    def test_passes_when_pattern_absent(self, tmp_path: Path) -> None:
        (tmp_path / "f.py").write_text("import os\n")
        rule = _make_rule("r", "f.py", {"type": "content-not-matches", "pattern": "eval("})
        assert evaluate(rule, tmp_path) == []

    def test_violation_when_pattern_present(self, tmp_path: Path) -> None:
        (tmp_path / "f.py").write_text("x = eval(input())\n")
        rule = _make_rule("r", "f.py", {"type": "content-not-matches", "pattern": r"eval\("})
        findings = evaluate(rule, tmp_path)
        assert len(findings) == 1

    def test_line_start_is_line_of_match(self, tmp_path: Path) -> None:
        (tmp_path / "f.py").write_text("# ok\n# also ok\neval(x)\n")
        rule = _make_rule("r", "f.py", {"type": "content-not-matches", "pattern": r"eval\("})
        findings = evaluate(rule, tmp_path)
        assert findings[0].line_start == 3

    def test_no_target_files_produces_no_findings(self, tmp_path: Path) -> None:
        rule = _make_rule("r", "missing.py", {"type": "content-not-matches", "pattern": "x"})
        assert evaluate(rule, tmp_path) == []


# ── structured-path ───────────────────────────────────────────────────────────


class TestStructuredPath:
    def _json_file(self, tmp_path: Path, content: dict, name: str = "pkg.json") -> Path:
        p = tmp_path / name
        p.write_text(json.dumps(content))
        return p

    def _yaml_file(self, tmp_path: Path, content: dict, name: str = "cfg.yaml") -> Path:
        p = tmp_path / name
        p.write_text(yaml.dump(content))
        return p

    def _toml_file(self, tmp_path: Path, content: str, name: str = "cfg.toml") -> Path:
        p = tmp_path / name
        p.write_text(content)
        return p

    # exists=True
    def test_exists_passes_when_present(self, tmp_path: Path) -> None:
        self._json_file(tmp_path, {"license": "MIT"}, "package.json")
        rule = _make_rule(
            "lic",
            "package.json",
            {"type": "structured-path", "path": "license", "exists": True},
        )
        assert evaluate(rule, tmp_path) == []

    def test_exists_violation_when_absent(self, tmp_path: Path) -> None:
        self._json_file(tmp_path, {"name": "my-pkg"}, "package.json")
        rule = _make_rule(
            "lic",
            "package.json",
            {"type": "structured-path", "path": "license", "exists": True},
        )
        findings = evaluate(rule, tmp_path)
        assert len(findings) == 1
        assert "license" in findings[0].message

    # exists=False
    def test_not_exists_passes_when_absent(self, tmp_path: Path) -> None:
        self._json_file(tmp_path, {"name": "pkg"}, "package.json")
        rule = _make_rule(
            "r",
            "package.json",
            {"type": "structured-path", "path": "private", "exists": False},
        )
        assert evaluate(rule, tmp_path) == []

    def test_not_exists_violation_when_present(self, tmp_path: Path) -> None:
        self._json_file(tmp_path, {"private": True}, "package.json")
        rule = _make_rule(
            "r",
            "package.json",
            {"type": "structured-path", "path": "private", "exists": False},
        )
        findings = evaluate(rule, tmp_path)
        assert len(findings) == 1

    # equals
    def test_equals_passes(self, tmp_path: Path) -> None:
        self._json_file(tmp_path, {"version": "1.0.0"}, "package.json")
        rule = _make_rule(
            "r",
            "package.json",
            {"type": "structured-path", "path": "version", "equals": "1.0.0"},
        )
        assert evaluate(rule, tmp_path) == []

    def test_equals_violation(self, tmp_path: Path) -> None:
        self._json_file(tmp_path, {"version": "2.0.0"}, "package.json")
        rule = _make_rule(
            "r",
            "package.json",
            {"type": "structured-path", "path": "version", "equals": "1.0.0"},
        )
        findings = evaluate(rule, tmp_path)
        assert len(findings) == 1

    # matches (regex on string value)
    def test_matches_passes(self, tmp_path: Path) -> None:
        self._json_file(tmp_path, {"license": "Apache-2.0"}, "package.json")
        rule = _make_rule(
            "r",
            "package.json",
            {"type": "structured-path", "path": "license", "matches": r"^(MIT|Apache-2\.0)$"},
        )
        assert evaluate(rule, tmp_path) == []

    def test_matches_violation(self, tmp_path: Path) -> None:
        self._json_file(tmp_path, {"license": "UNLICENSED"}, "package.json")
        rule = _make_rule(
            "r",
            "package.json",
            {"type": "structured-path", "path": "license", "matches": r"^(MIT|Apache-2\.0)$"},
        )
        findings = evaluate(rule, tmp_path)
        assert len(findings) == 1

    # YAML and TOML parsing
    def test_yaml_file_parsed(self, tmp_path: Path) -> None:
        self._yaml_file(tmp_path, {"key": "value"}, "cfg.yaml")
        rule = _make_rule(
            "r",
            "cfg.yaml",
            {"type": "structured-path", "path": "key", "exists": True},
        )
        assert evaluate(rule, tmp_path) == []

    def test_toml_file_parsed(self, tmp_path: Path) -> None:
        self._toml_file(tmp_path, '[tool]\nname = "myapp"\n', "cfg.toml")
        rule = _make_rule(
            "r",
            "cfg.toml",
            {"type": "structured-path", "path": "tool.name", "exists": True},
        )
        assert evaluate(rule, tmp_path) == []

    # unsupported type → rule-error diagnostic
    def test_unsupported_file_type_emits_info_diagnostic(self, tmp_path: Path) -> None:
        (tmp_path / "binary.bin").write_bytes(b"\x00\x01\x02")
        rule = _make_rule(
            "r",
            "binary.bin",
            {"type": "structured-path", "path": "x", "exists": True},
        )
        findings = evaluate(rule, tmp_path)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "[rule-error]" in findings[0].message

    # corrupt JSON → rule-error diagnostic
    def test_corrupt_json_emits_info_diagnostic(self, tmp_path: Path) -> None:
        (tmp_path / "bad.json").write_text("{not valid json}")
        rule = _make_rule(
            "r",
            "bad.json",
            {"type": "structured-path", "path": "x", "exists": True},
        )
        findings = evaluate(rule, tmp_path)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    # invalid JMESPath → skips rule entirely
    def test_invalid_jmespath_skips_rule(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        self._json_file(tmp_path, {"x": 1}, "f.json")
        rule = _make_rule(
            "r",
            "f.json",
            {"type": "structured-path", "path": "x[invalid", "exists": True},
        )
        findings = evaluate(rule, tmp_path)
        assert findings == []
