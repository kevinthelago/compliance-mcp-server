"""Tests for the markdown report renderer — GR-3."""

from __future__ import annotations

from compliance_mcp.gate.baseline import BaselineEntry, BaselineResult
from compliance_mcp.gate.evaluator import GateDecision, GateResult
from compliance_mcp.models.finding import Domain, Finding, Lens, Severity
from compliance_mcp.report.renderer import render_report, render_report_json


def _finding(
    severity: Severity = Severity.HIGH,
    domain: Domain = Domain.VULNERABILITY,
    rule_id: str = "soc2.CC6.1",
    file_path: str = "src/auth.py",
    line_start: int = 10,
    idx: int = 0,
    fingerprint: str = "",
) -> Finding:
    kwargs = dict(
        lens=Lens.SOC2,
        domain=domain,
        rule_id=rule_id,
        file_path=file_path,
        line_start=line_start,
        severity=severity,
        title=f"Test finding {idx}",
        message=f"Message {idx}",
        suggestion=f"Fix {idx}",
        control_refs=["CC6.1"],
    )
    if fingerprint:
        kwargs["fingerprint"] = fingerprint
    return Finding(**kwargs)


def _gate(
    decision: GateDecision = GateDecision.PASS,
    blocking: list[Finding] | None = None,
) -> GateResult:
    return GateResult(
        decision=decision,
        rationale="Test rationale",
        blocking_findings=blocking or [],
        counts_by_severity={s.value: 0 for s in Severity},
    )


class TestRenderReport:
    def test_returns_string(self) -> None:
        report = render_report(findings=[], gate_result=_gate())
        assert isinstance(report, str)
        assert len(report) > 0

    def test_pass_badge_present(self) -> None:
        report = render_report(findings=[], gate_result=_gate(GateDecision.PASS))
        assert "PASS" in report

    def test_block_badge_present(self) -> None:
        f = _finding(Severity.CRITICAL)
        report = render_report(findings=[f], gate_result=_gate(GateDecision.BLOCK, [f]))
        assert "BLOCK" in report

    def test_inconclusive_badge_present(self) -> None:
        report = render_report(findings=[], gate_result=_gate(GateDecision.INCONCLUSIVE))
        assert "INCONCLUSIVE" in report

    def test_project_path_in_report(self) -> None:
        report = render_report(findings=[], gate_result=_gate(), project_path="/my/project")
        assert "/my/project" in report

    def test_finding_rendered(self) -> None:
        f = _finding(Severity.HIGH, rule_id="soc2.CC6.1", file_path="src/login.py")
        report = render_report(findings=[f], gate_result=_gate())
        assert "soc2.CC6.1" in report
        assert "src/login.py" in report

    def test_not_run_lenses_section(self) -> None:
        report = render_report(
            findings=[],
            gate_result=_gate(),
            lenses_run=["gdpr"],
            lenses_skipped=["soc2", "hipaa"],
        )
        assert "soc2" in report
        assert "hipaa" in report

    def test_deterministic_ordering(self) -> None:
        findings = [_finding(Severity.HIGH, idx=i, line_start=i + 1) for i in range(5)]
        g = _gate()
        r1 = render_report(findings=findings, gate_result=g)
        r2 = render_report(findings=findings, gate_result=g)
        assert r1 == r2

    def test_write_to_file(self, tmp_path) -> None:
        out = tmp_path / "report.md"
        report = render_report(findings=[], gate_result=_gate(), output_path=out)
        assert out.exists()
        assert out.read_text(encoding="utf-8") == report

    def test_baseline_section_rendered(self) -> None:
        fp = "a" * 64
        f = _finding(fingerprint=fp)
        baseline_result = BaselineResult(
            accepted=[f],
            active=[],
            stale_entries=[BaselineEntry(fingerprint="b" * 64, reason="Old")],
        )
        report = render_report(
            findings=[f],
            gate_result=_gate(),
            baseline_result=baseline_result,
        )
        assert "Suppression" in report
        assert "Stale" in report


class TestRenderReportJson:
    def test_returns_valid_json(self) -> None:
        import json

        content = render_report_json(findings=[], gate_result=_gate())
        data = json.loads(content)
        assert "gate" in data
        assert "findings" in data

    def test_findings_in_json(self) -> None:
        import json

        f = _finding(Severity.HIGH)
        content = render_report_json(findings=[f], gate_result=_gate())
        data = json.loads(content)
        assert len(data["findings"]) == 1
        assert data["findings"][0]["severity"] == "high"


class TestSnapshotReport:
    """Snapshot test — catches accidental template changes."""

    def test_snapshot(self, snapshot) -> None:
        fp = "snap" + "0" * 60
        f = Finding(
            lens=Lens.SOC2,
            domain=Domain.ACCESS_CONTROL,
            rule_id="soc2.CC6.1",
            file_path="src/auth/login.py",
            line_start=42,
            severity=Severity.HIGH,
            title="Missing MFA enforcement",
            message="Multi-factor auth not required for admin routes",
            suggestion="Enable MFA in the auth middleware",
            control_refs=["SOC2 CC6.1", "ISO 27001 A.9.4.2"],
            fingerprint=fp,
        )
        gate = GateResult(
            decision=GateDecision.BLOCK,
            rationale="Gate blocked: 1 finding(s) at or above the 'medium' severity threshold.",
            blocking_findings=[f],
            counts_by_severity={"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            counts_by_domain={"access_control": {"high": 1}},
        )
        report = render_report(
            findings=[f],
            gate_result=gate,
            project_path="/project",
            lenses_run=["soc2"],
            lenses_skipped=["hipaa"],
        )
        assert report == snapshot
