"""Tests for the Trivy adapter (SUP-2)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from compliance_mcp.adapters.base import AdapterResult, RunStatus
from compliance_mcp.adapters.trivy import TrivyAdapter, _parse_trivy_json
from compliance_mcp.models.finding import Domain, Lens, Severity

# ── _parse_trivy_json unit tests ──────────────────────────────────────────────


def test_parse_trivy_json_count(trivy_fixture_json: str) -> None:
    findings = _parse_trivy_json(trivy_fixture_json, target=".")
    assert len(findings) == 3


def test_parse_trivy_json_cve_id(trivy_fixture_json: str) -> None:
    findings = _parse_trivy_json(trivy_fixture_json, target=".")
    rule_ids = {f.rule_id for f in findings}
    assert "cve.CVE-2023-32681" in rule_ids
    assert "cve.CVE-2024-99999" in rule_ids
    assert "cve.CVE-2024-12345" in rule_ids


def test_parse_trivy_json_file_path(trivy_fixture_json: str) -> None:
    findings = _parse_trivy_json(trivy_fixture_json, target=".")
    paths = {f.file_path for f in findings}
    assert "requirements.txt" in paths
    assert "package.json" in paths


def test_parse_trivy_json_severity_from_cvss(trivy_fixture_json: str) -> None:
    findings = _parse_trivy_json(trivy_fixture_json, target=".")
    by_id = {f.rule_id: f for f in findings}
    # CVE-2024-12345 has V3Score 9.8 → CRITICAL
    assert by_id["cve.CVE-2024-12345"].severity == Severity.CRITICAL
    # CVE-2024-99999 has V3Score 8.8 → HIGH
    assert by_id["cve.CVE-2024-99999"].severity == Severity.HIGH
    # CVE-2023-32681 has V3Score 6.1 → MEDIUM
    assert by_id["cve.CVE-2023-32681"].severity == Severity.MEDIUM


def test_parse_trivy_json_domain_and_lens(trivy_fixture_json: str) -> None:
    findings = _parse_trivy_json(trivy_fixture_json, target=".")
    for f in findings:
        assert f.domain == Domain.SUPPLY_CHAIN
        assert f.lens == Lens.CUSTOM


def test_parse_trivy_json_suggestion_with_fix(trivy_fixture_json: str) -> None:
    findings = _parse_trivy_json(trivy_fixture_json, target=".")
    by_id = {f.rule_id: f for f in findings}
    assert "2.31.0" in by_id["cve.CVE-2023-32681"].suggestion


def test_parse_trivy_json_no_fix() -> None:
    data = json.dumps({
        "SchemaVersion": 2,
        "Results": [{
            "Target": "go.sum",
            "Class": "lang-pkgs",
            "Type": "gomod",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2099-0001",
                "PkgName": "some-lib",
                "InstalledVersion": "1.0.0",
                "FixedVersion": "",
                "Severity": "LOW",
                "Title": "Minor issue",
                "Description": "A low severity issue.",
            }],
        }],
    })
    findings = _parse_trivy_json(data, target=".")
    assert findings[0].suggestion == "No fix available yet."


def test_parse_trivy_json_fallback_severity_no_cvss() -> None:
    data = json.dumps({
        "SchemaVersion": 2,
        "Results": [{
            "Target": "Cargo.lock",
            "Class": "lang-pkgs",
            "Type": "cargo",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2099-0002",
                "PkgName": "rust-lib",
                "InstalledVersion": "0.1.0",
                "Severity": "CRITICAL",
                "Title": "Serious issue",
                "Description": ".",
            }],
        }],
    })
    findings = _parse_trivy_json(data, target=".")
    assert findings[0].severity == Severity.CRITICAL


def test_parse_trivy_json_invalid_json() -> None:
    findings = _parse_trivy_json("not json", target=".")
    assert findings == []


def test_parse_trivy_json_no_vulnerabilities() -> None:
    data = json.dumps({
        "SchemaVersion": 2,
        "Results": [{"Target": "requirements.txt", "Class": "lang-pkgs", "Type": "pip"}],
    })
    findings = _parse_trivy_json(data, target=".")
    assert findings == []


def test_parse_trivy_json_fingerprint_stable(trivy_fixture_json: str) -> None:
    f1 = _parse_trivy_json(trivy_fixture_json, target=".")
    f2 = _parse_trivy_json(trivy_fixture_json, target=".")
    fps1 = {f.fingerprint for f in f1}
    fps2 = {f.fingerprint for f in f2}
    assert fps1 == fps2


# ── TrivyAdapter integration (binary stubbed) ─────────────────────────────────


def test_trivy_adapter_not_run_when_binary_absent() -> None:
    adapter = TrivyAdapter()
    with patch("compliance_mcp.adapters.base.shutil.which", return_value=None):
        result, findings = adapter.run(Path("."))
    assert result.status == RunStatus.NOT_RUN
    assert findings == []


def test_trivy_adapter_returns_findings_on_success(trivy_fixture_json: str) -> None:
    adapter = TrivyAdapter()
    fake_result = AdapterResult(
        status=RunStatus.FINDINGS,
        stdout=trivy_fixture_json,
        returncode=1,
    )
    with patch("compliance_mcp.adapters.trivy.run_subprocess", return_value=fake_result):
        result, findings = adapter.run(Path("."))
    assert result.status == RunStatus.FINDINGS
    assert len(findings) == 3


def test_trivy_adapter_degraded_on_db_update_failure(trivy_fixture_json: str) -> None:
    """When DB update fails, retry with --skip-db-update and mark degraded."""
    adapter = TrivyAdapter()
    initial_error = AdapterResult(
        status=RunStatus.ERRORED,
        stderr="failed to fetch vulnerability DB: db update error: network timeout",
        returncode=1,
    )
    degraded_success = AdapterResult(
        status=RunStatus.FINDINGS,
        stdout=trivy_fixture_json,
        returncode=1,
    )
    call_count = 0

    def fake_run(cmd: list[str], **kwargs: object) -> AdapterResult:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return initial_error
        return degraded_success

    with patch("compliance_mcp.adapters.trivy.run_subprocess", side_effect=fake_run):
        result, findings = adapter.run(Path("."))

    assert result.degraded is True
    assert len(findings) == 3
    assert call_count == 2


def test_trivy_adapter_error_returns_empty() -> None:
    adapter = TrivyAdapter()
    fake_result = AdapterResult(
        status=RunStatus.ERRORED,
        stderr="fatal: unknown error",
        returncode=2,
    )
    with patch("compliance_mcp.adapters.trivy.run_subprocess", return_value=fake_result):
        result, findings = adapter.run(Path("."))
    assert result.status == RunStatus.ERRORED
    assert findings == []
