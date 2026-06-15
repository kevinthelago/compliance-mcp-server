"""Tests for lenses/security.py — SEC-4."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from compliance_mcp.adapters.base import AdapterResult, RunStatus
from compliance_mcp.lenses.security import SecurityLens
from compliance_mcp.models.finding import Domain, Finding, Lens, Severity
from compliance_mcp.scan.lens import LensResult, LensStatus


def _make_finding(**kwargs: object) -> Finding:
    defaults: dict[str, object] = {
        "lens": Lens.OWASP,
        "domain": Domain.VULNERABILITY,
        "severity": Severity.HIGH,
        "title": "Test finding",
        "rule_id": "test.rule",
        "file_path": "test.py",
        "line_start": 1,
    }
    defaults.update(kwargs)
    return Finding(**defaults)  # type: ignore[arg-type]


@pytest.fixture()
def lens() -> SecurityLens:
    return SecurityLens()


@pytest.fixture()
def target(tmp_path: Path) -> Path:
    return tmp_path


class TestSecurityLensProtocol:
    def test_has_name_security(self, lens: SecurityLens) -> None:
        assert lens.name == "security"

    def test_has_domain_security(self, lens: SecurityLens) -> None:
        assert lens.domain == "security"

    def test_applicable_always_true(self, lens: SecurityLens, target: Path) -> None:
        assert lens.applicable(target) is True

    def test_run_returns_lens_result(self, lens: SecurityLens, target: Path) -> None:
        with (
            patch(
                "compliance_mcp.lenses.security.semgrep_scan",
                return_value=(AdapterResult(status=RunStatus.NOT_RUN), []),
            ),
            patch(
                "compliance_mcp.lenses.security.gitleaks_scan",
                return_value=(AdapterResult(status=RunStatus.NOT_RUN), []),
            ),
        ):
            result = lens.run(target)
        assert isinstance(result, LensResult)

    def test_run_result_has_status(self, lens: SecurityLens, target: Path) -> None:
        with (
            patch(
                "compliance_mcp.lenses.security.semgrep_scan",
                return_value=(AdapterResult(status=RunStatus.NOT_RUN), []),
            ),
            patch(
                "compliance_mcp.lenses.security.gitleaks_scan",
                return_value=(AdapterResult(status=RunStatus.NOT_RUN), []),
            ),
        ):
            result = lens.run(target)
        assert result.status in (LensStatus.RAN, LensStatus.NOT_RUN, LensStatus.ERRORED)


class TestSecurityLensDegradation:
    def test_semgrep_not_run_still_returns_gitleaks_findings(
        self, lens: SecurityLens, target: Path
    ) -> None:
        gl_finding = _make_finding(lens=Lens.CUSTOM, domain=Domain.DATA_PROTECTION)
        with (
            patch(
                "compliance_mcp.lenses.security.semgrep_scan",
                return_value=(AdapterResult(status=RunStatus.NOT_RUN), []),
            ),
            patch(
                "compliance_mcp.lenses.security.gitleaks_scan",
                return_value=(AdapterResult(status=RunStatus.OK), [gl_finding]),
            ),
        ):
            result = lens.run(target)
        assert gl_finding in result.findings
        assert result.status == LensStatus.RAN

    def test_gitleaks_not_run_still_returns_semgrep_findings(
        self, lens: SecurityLens, target: Path
    ) -> None:
        sg_finding = _make_finding()
        with (
            patch(
                "compliance_mcp.lenses.security.semgrep_scan",
                return_value=(AdapterResult(status=RunStatus.OK), [sg_finding]),
            ),
            patch(
                "compliance_mcp.lenses.security.gitleaks_scan",
                return_value=(AdapterResult(status=RunStatus.NOT_RUN), []),
            ),
        ):
            result = lens.run(target)
        assert sg_finding in result.findings

    def test_both_not_run_returns_not_run_status(self, lens: SecurityLens, target: Path) -> None:
        with (
            patch(
                "compliance_mcp.lenses.security.semgrep_scan",
                return_value=(AdapterResult(status=RunStatus.NOT_RUN), []),
            ),
            patch(
                "compliance_mcp.lenses.security.gitleaks_scan",
                return_value=(AdapterResult(status=RunStatus.NOT_RUN), []),
            ),
        ):
            result = lens.run(target)
        assert result.status == LensStatus.NOT_RUN
        assert result.findings == []

    def test_both_ran_aggregates_findings(self, lens: SecurityLens, target: Path) -> None:
        sg = _make_finding(title="SAST finding")
        gl = _make_finding(
            lens=Lens.CUSTOM,
            domain=Domain.DATA_PROTECTION,
            title="Secret",
            rule_id="gitleaks.aws",
            severity=Severity.CRITICAL,
        )
        with (
            patch(
                "compliance_mcp.lenses.security.semgrep_scan",
                return_value=(AdapterResult(status=RunStatus.OK), [sg]),
            ),
            patch(
                "compliance_mcp.lenses.security.gitleaks_scan",
                return_value=(AdapterResult(status=RunStatus.FINDINGS), [gl]),
            ),
        ):
            result = lens.run(target)
        assert len(result.findings) == 2
        assert sg in result.findings
        assert gl in result.findings

    def test_run_never_raises(self, lens: SecurityLens, target: Path) -> None:
        with (
            patch(
                "compliance_mcp.lenses.security.semgrep_scan",
                side_effect=RuntimeError("unexpected"),
            ),
            patch(
                "compliance_mcp.lenses.security.gitleaks_scan",
                return_value=(AdapterResult(status=RunStatus.NOT_RUN), []),
            ),
        ):
            try:
                lens.run(target)
            except RuntimeError:
                pytest.fail("SecurityLens.run() propagated an unexpected RuntimeError")

    def test_diagnostics_populated_when_scanners_absent(
        self, lens: SecurityLens, target: Path
    ) -> None:
        with (
            patch(
                "compliance_mcp.lenses.security.semgrep_scan",
                return_value=(AdapterResult(status=RunStatus.NOT_RUN), []),
            ),
            patch(
                "compliance_mcp.lenses.security.gitleaks_scan",
                return_value=(AdapterResult(status=RunStatus.NOT_RUN), []),
            ),
        ):
            result = lens.run(target)
        assert result.diagnostics
        assert "semgrep" in result.diagnostics
        assert "gitleaks" in result.diagnostics
