"""Tests for adapters/gitleaks.py — SEC-3."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from compliance_mcp.adapters.base import AdapterResult, RunStatus
from compliance_mcp.adapters.gitleaks import parse_json, scan
from compliance_mcp.models.finding import Domain, Lens, Severity


@pytest.fixture()
def target(tmp_path: Path) -> Path:
    return tmp_path


class TestParseJson:
    """Unit tests that parse the JSON fixture directly (no binary needed)."""

    def test_parses_two_findings_from_fixture(self, gitleaks_text: str) -> None:
        findings = parse_json(gitleaks_text)
        assert len(findings) == 2

    def test_aws_key_finding_fields(self, gitleaks_text: str) -> None:
        findings = parse_json(gitleaks_text)
        aws = next(f for f in findings if "aws" in f.rule_id.lower())
        assert aws.severity == Severity.CRITICAL
        assert aws.lens == Lens.CUSTOM
        assert aws.domain == Domain.DATA_PROTECTION
        assert aws.rule_id == "gitleaks.aws-access-token"
        assert aws.file_path
        assert aws.line_start >= 1

    def test_generic_api_key_finding_fields(self, gitleaks_text: str) -> None:
        findings = parse_json(gitleaks_text)
        api = next(f for f in findings if "api" in f.rule_id.lower())
        assert api.severity == Severity.CRITICAL
        assert api.rule_id.startswith("gitleaks.")

    def test_fingerprints_are_stable_and_unique(self, gitleaks_text: str) -> None:
        findings1 = parse_json(gitleaks_text)
        findings2 = parse_json(gitleaks_text)
        fps1 = [f.fingerprint for f in findings1]
        fps2 = [f.fingerprint for f in findings2]
        assert fps1 == fps2
        assert len(set(fps1)) == len(fps1)

    def test_invalid_json_returns_empty(self) -> None:
        findings = parse_json("not json")
        assert findings == []

    def test_empty_array_returns_empty(self) -> None:
        findings = parse_json("[]")
        assert findings == []

    def test_item_without_rule_id_is_skipped(self) -> None:
        bad = '[{"Description":"oops","StartLine":1}]'
        findings = parse_json(bad)
        assert findings == []

    def test_message_contains_description(self, gitleaks_text: str) -> None:
        findings = parse_json(gitleaks_text)
        assert all(f.message for f in findings)

    def test_secret_value_is_redacted_in_message(self, gitleaks_text: str) -> None:
        findings = parse_json(gitleaks_text)
        for f in findings:
            assert "AKIA" not in f.message, "actual secret value must not appear in message"


class TestScan:
    """Tests for scan() that stub the subprocess layer."""

    def test_missing_binary_returns_not_run(self, target: Path) -> None:
        with patch(
            "compliance_mcp.adapters.gitleaks.run_subprocess",
            return_value=AdapterResult(status=RunStatus.NOT_RUN),
        ):
            result, findings = scan(target)
        assert result.status == RunStatus.NOT_RUN
        assert findings == []

    def test_errored_run_returns_errored(self, target: Path) -> None:
        with patch(
            "compliance_mcp.adapters.gitleaks.run_subprocess",
            return_value=AdapterResult(status=RunStatus.ERRORED, stderr="boom"),
        ):
            result, findings = scan(target)
        assert result.status == RunStatus.ERRORED
        assert findings == []

    def test_ok_means_no_secrets(self, target: Path) -> None:
        with patch(
            "compliance_mcp.adapters.gitleaks.run_subprocess",
            return_value=AdapterResult(status=RunStatus.OK, stdout="[]", returncode=0),
        ):
            result, findings = scan(target)
        assert result.status == RunStatus.OK
        assert findings == []

    def test_findings_status_means_secrets_found(self, target: Path, gitleaks_text: str) -> None:
        with patch(
            "compliance_mcp.adapters.gitleaks.run_subprocess",
            return_value=AdapterResult(
                status=RunStatus.FINDINGS, stdout=gitleaks_text, returncode=1
            ),
        ):
            result, findings = scan(target)
        assert result.status == RunStatus.FINDINGS
        assert len(findings) == 2
