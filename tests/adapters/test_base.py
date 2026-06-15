"""Tests for adapters/base.py — SEC-1.

These tests verify the module-level run_subprocess() function, RunStatus enum,
severity helpers (cvss_to_severity, native_to_severity), and AdapterResult.
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from compliance_mcp.adapters.base import (
    RunStatus,
    cvss_to_severity,
    native_to_severity,
    run_subprocess,
)
from compliance_mcp.models.finding import Severity


class TestRunSubprocessBinaryAbsent:
    def test_missing_binary_returns_not_run(self) -> None:
        result = run_subprocess(["this-binary-does-not-exist-12345"])
        assert result.status == RunStatus.NOT_RUN

    def test_not_run_has_empty_output(self) -> None:
        result = run_subprocess(["this-binary-does-not-exist-12345"])
        assert result.stdout == ""
        assert result.stderr == ""


class TestRunSubprocessSuccess:
    def test_zero_exit_is_ok(self) -> None:
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = "output"
        proc.stderr = ""
        with (
            patch("compliance_mcp.adapters.base.subprocess.run", return_value=proc),
            patch("compliance_mcp.adapters.base.shutil.which", return_value="/usr/bin/fake"),
        ):
            result = run_subprocess(["fake"])
        assert result.status == RunStatus.OK
        assert result.stdout == "output"

    def test_findings_exit_code_is_findings(self) -> None:
        proc = MagicMock()
        proc.returncode = 1
        proc.stdout = "findings"
        proc.stderr = ""
        with (
            patch("compliance_mcp.adapters.base.subprocess.run", return_value=proc),
            patch("compliance_mcp.adapters.base.shutil.which", return_value="/usr/bin/fake"),
        ):
            result = run_subprocess(["fake"], findings_exit_codes=frozenset({1}))
        assert result.status == RunStatus.FINDINGS

    def test_nonzero_non_findings_exit_is_errored(self) -> None:
        proc = MagicMock()
        proc.returncode = 2
        proc.stdout = ""
        proc.stderr = "fatal error"
        with (
            patch("compliance_mcp.adapters.base.subprocess.run", return_value=proc),
            patch("compliance_mcp.adapters.base.shutil.which", return_value="/usr/bin/fake"),
        ):
            result = run_subprocess(["fake"], findings_exit_codes=frozenset({1}))
        assert result.status == RunStatus.ERRORED

    def test_stdout_and_stderr_captured(self) -> None:
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = "hello"
        proc.stderr = "warn"
        with (
            patch("compliance_mcp.adapters.base.subprocess.run", return_value=proc),
            patch("compliance_mcp.adapters.base.shutil.which", return_value="/usr/bin/fake"),
        ):
            result = run_subprocess(["fake"])
        assert result.stdout == "hello"
        assert result.stderr == "warn"


class TestRunSubprocessErrors:
    def test_timeout_returns_errored(self) -> None:
        with (
            patch(
                "compliance_mcp.adapters.base.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd=["fake"], timeout=1),
            ),
            patch("compliance_mcp.adapters.base.shutil.which", return_value="/usr/bin/fake"),
        ):
            result = run_subprocess(["fake"], timeout=1)
        assert result.status == RunStatus.ERRORED
        assert "timeout" in result.stderr.lower()

    def test_oserror_returns_errored(self) -> None:
        with (
            patch(
                "compliance_mcp.adapters.base.subprocess.run",
                side_effect=OSError("permission denied"),
            ),
            patch("compliance_mcp.adapters.base.shutil.which", return_value="/usr/bin/fake"),
        ):
            result = run_subprocess(["fake"])
        assert result.status == RunStatus.ERRORED
        assert "permission denied" in result.stderr


class TestCvssToSeverity:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (9.5, Severity.CRITICAL),
            (9.0, Severity.CRITICAL),
            (8.9, Severity.HIGH),
            (7.0, Severity.HIGH),
            (6.9, Severity.MEDIUM),
            (4.0, Severity.MEDIUM),
            (3.9, Severity.LOW),
            (0.1, Severity.LOW),
            (0.0, Severity.INFO),
        ],
    )
    def test_cvss_score_maps_correctly(self, score: float, expected: Severity) -> None:
        assert cvss_to_severity(score) == expected


class TestNativeToSeverity:
    @pytest.mark.parametrize(
        ("native", "expected"),
        [
            ("critical", Severity.CRITICAL),
            ("CRITICAL", Severity.CRITICAL),
            ("high", Severity.HIGH),
            ("medium", Severity.MEDIUM),
            ("moderate", Severity.MEDIUM),
            ("low", Severity.LOW),
            ("info", Severity.INFO),
            ("informational", Severity.INFO),
            ("unknown", Severity.INFO),
            ("negligible", Severity.INFO),
            ("something-weird", Severity.INFO),
        ],
    )
    def test_native_label_maps_correctly(self, native: str, expected: Severity) -> None:
        assert native_to_severity(native) == expected
