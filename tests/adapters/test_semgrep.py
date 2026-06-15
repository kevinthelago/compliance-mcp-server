"""Tests for adapters/semgrep.py — SEC-2."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from compliance_mcp.adapters.base import AdapterResult, RunStatus
from compliance_mcp.adapters.semgrep import parse_sarif, scan
from compliance_mcp.models.finding import Domain, Lens, Severity


@pytest.fixture()
def target(tmp_path: Path) -> Path:
    return tmp_path


class TestParseSarif:
    """Unit tests that parse SARIF fixtures directly (no binary needed)."""

    def test_parses_two_findings_from_fixture(self, sarif_text: str, target: Path) -> None:
        findings = parse_sarif(sarif_text, target)
        assert len(findings) == 2

    def test_error_level_maps_to_high(self, sarif_text: str, target: Path) -> None:
        findings = parse_sarif(sarif_text, target)
        sql_finding = next(f for f in findings if "sql" in f.rule_id.lower())
        assert sql_finding.severity == Severity.HIGH

    def test_warning_level_maps_to_medium(self, sarif_text: str, target: Path) -> None:
        findings = parse_sarif(sarif_text, target)
        cred_finding = next(f for f in findings if "credential" in f.rule_id.lower())
        assert cred_finding.severity == Severity.MEDIUM

    def test_finding_fields_populated(self, sarif_text: str, target: Path) -> None:
        findings = parse_sarif(sarif_text, target)
        f = findings[0]
        assert f.lens == Lens.OWASP
        assert f.domain == Domain.VULNERABILITY
        assert f.file_path
        assert f.line_start >= 1
        assert f.rule_id
        assert f.title
        assert f.fingerprint  # computed, non-empty

    def test_finding_has_message(self, sarif_text: str, target: Path) -> None:
        findings = parse_sarif(sarif_text, target)
        assert all(f.message for f in findings)

    def test_invalid_sarif_returns_empty(self, target: Path) -> None:
        findings = parse_sarif("not json at all", target)
        assert findings == []

    def test_empty_sarif_returns_empty(self, target: Path) -> None:
        empty_sarif = json.dumps({"version": "2.1.0", "runs": []})
        findings = parse_sarif(empty_sarif, target)
        assert findings == []

    def test_result_without_location_is_skipped(self, target: Path) -> None:
        sarif = json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "Semgrep", "rules": []}},
                        "results": [
                            {
                                "ruleId": "some.rule",
                                "message": {"text": "issue"},
                                "level": "error",
                                "locations": [],
                            }
                        ],
                    }
                ],
            }
        )
        findings = parse_sarif(sarif, target)
        assert findings == []

    def test_fingerprints_are_stable_and_unique(self, sarif_text: str, target: Path) -> None:
        findings1 = parse_sarif(sarif_text, target)
        findings2 = parse_sarif(sarif_text, target)
        fps1 = [f.fingerprint for f in findings1]
        fps2 = [f.fingerprint for f in findings2]
        assert fps1 == fps2
        assert len(set(fps1)) == len(fps1), "fingerprints must be unique across findings"


class TestScan:
    """Tests for scan() that stub the subprocess layer."""

    def test_missing_binary_returns_not_run(self, target: Path) -> None:
        with patch(
            "compliance_mcp.adapters.semgrep.run_subprocess",
            return_value=AdapterResult(status=RunStatus.NOT_RUN),
        ):
            result, findings = scan(target)
        assert result.status == RunStatus.NOT_RUN
        assert findings == []

    def test_errored_run_returns_errored(self, target: Path) -> None:
        with patch(
            "compliance_mcp.adapters.semgrep.run_subprocess",
            return_value=AdapterResult(status=RunStatus.ERRORED, stderr="some error"),
        ):
            result, findings = scan(target)
        assert result.status == RunStatus.ERRORED
        assert findings == []

    def test_ok_returns_findings(self, target: Path, sarif_text: str) -> None:
        with patch(
            "compliance_mcp.adapters.semgrep.run_subprocess",
            return_value=AdapterResult(status=RunStatus.OK, stdout=sarif_text, returncode=0),
        ):
            result, findings = scan(target)
        assert result.status == RunStatus.OK
        assert len(findings) == 2

    def test_findings_status_returns_findings(self, target: Path, sarif_text: str) -> None:
        """Exit code 1 = 'findings found' — normal FINDINGS outcome."""
        with patch(
            "compliance_mcp.adapters.semgrep.run_subprocess",
            return_value=AdapterResult(status=RunStatus.FINDINGS, stdout=sarif_text, returncode=1),
        ):
            result, findings = scan(target)
        assert result.status == RunStatus.FINDINGS
        assert len(findings) == 2

    def test_policies_dir_included_in_args(self, target: Path, tmp_path: Path) -> None:
        policies_dir = tmp_path / "policies" / "semgrep"
        policies_dir.mkdir(parents=True)

        captured_args: list[list[str]] = []

        def mock_run(cmd: list[str], **kwargs: object) -> AdapterResult:
            captured_args.append(cmd)
            return AdapterResult(status=RunStatus.OK, stdout='{"version":"2.1.0","runs":[]}')

        with patch("compliance_mcp.adapters.semgrep.run_subprocess", side_effect=mock_run):
            scan(target, policies_dir=policies_dir)

        assert captured_args
        assert "--config" in captured_args[0]
        assert str(policies_dir) in captured_args[0]
