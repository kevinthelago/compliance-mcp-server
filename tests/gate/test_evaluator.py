"""Tests for the gate evaluator — GR-1."""

from __future__ import annotations

from compliance_mcp.gate.evaluator import GateDecision, evaluate
from compliance_mcp.models.finding import Domain, Finding, Lens, Severity


def _f(
    severity: Severity,
    domain: Domain = Domain.VULNERABILITY,
    idx: int = 0,
) -> Finding:
    return Finding(
        lens=Lens.SOC2,
        domain=domain,
        rule_id=f"soc2.rule-{idx}",
        file_path=f"src/file_{idx}.py",
        line_start=idx + 1,
        severity=severity,
        title=f"Finding {idx}",
    )


class TestInconclusive:
    def test_no_lenses_ran_is_inconclusive(self) -> None:
        result = evaluate([], ran=False)
        assert result.decision == GateDecision.INCONCLUSIVE

    def test_ran_false_with_findings_still_inconclusive(self) -> None:
        result = evaluate([_f(Severity.CRITICAL)], ran=False)
        assert result.decision == GateDecision.INCONCLUSIVE

    def test_ran_true_empty_findings_passes(self) -> None:
        result = evaluate([], ran=True)
        assert result.decision == GateDecision.PASS


class TestBlock:
    def test_critical_blocks_at_medium_threshold(self) -> None:
        result = evaluate([_f(Severity.CRITICAL)], block_threshold=Severity.MEDIUM)
        assert result.decision == GateDecision.BLOCK
        assert len(result.blocking_findings) == 1

    def test_high_blocks_at_medium_threshold(self) -> None:
        result = evaluate([_f(Severity.HIGH)], block_threshold=Severity.MEDIUM)
        assert result.decision == GateDecision.BLOCK

    def test_medium_blocks_at_medium_threshold(self) -> None:
        result = evaluate([_f(Severity.MEDIUM)], block_threshold=Severity.MEDIUM)
        assert result.decision == GateDecision.BLOCK

    def test_low_does_not_block_at_medium_threshold(self) -> None:
        result = evaluate([_f(Severity.LOW)], block_threshold=Severity.MEDIUM)
        assert result.decision == GateDecision.PASS

    def test_critical_blocks_at_high_threshold(self) -> None:
        result = evaluate([_f(Severity.CRITICAL)], block_threshold=Severity.HIGH)
        assert result.decision == GateDecision.BLOCK

    def test_medium_does_not_block_at_high_threshold(self) -> None:
        result = evaluate([_f(Severity.MEDIUM)], block_threshold=Severity.HIGH)
        assert result.decision == GateDecision.PASS

    def test_critical_threshold_only_critical_blocks(self) -> None:
        findings = [_f(Severity.HIGH, idx=0), _f(Severity.CRITICAL, idx=1)]
        result = evaluate(findings, block_threshold=Severity.CRITICAL)
        assert result.decision == GateDecision.BLOCK
        assert len(result.blocking_findings) == 1
        assert result.blocking_findings[0].severity == Severity.CRITICAL

    def test_rationale_mentions_count(self) -> None:
        result = evaluate([_f(Severity.CRITICAL)], block_threshold=Severity.MEDIUM)
        assert "1" in result.rationale


class TestPass:
    def test_no_findings_passes(self) -> None:
        result = evaluate([])
        assert result.decision == GateDecision.PASS

    def test_info_finding_passes_at_medium_threshold(self) -> None:
        result = evaluate([_f(Severity.INFO)], block_threshold=Severity.MEDIUM)
        assert result.decision == GateDecision.PASS


class TestCounts:
    def test_counts_by_severity(self) -> None:
        findings = [
            _f(Severity.CRITICAL, idx=0),
            _f(Severity.HIGH, idx=1),
            _f(Severity.MEDIUM, idx=2),
            _f(Severity.LOW, idx=3),
        ]
        result = evaluate(findings, block_threshold=Severity.CRITICAL)
        assert result.counts_by_severity["critical"] == 1
        assert result.counts_by_severity["high"] == 1
        assert result.counts_by_severity["medium"] == 1
        assert result.counts_by_severity["low"] == 1

    def test_counts_by_domain(self) -> None:
        findings = [
            _f(Severity.HIGH, domain=Domain.ACCESS_CONTROL, idx=0),
            _f(Severity.MEDIUM, domain=Domain.DATA_PROTECTION, idx=1),
        ]
        result = evaluate(findings, block_threshold=Severity.CRITICAL)
        assert result.counts_by_domain["access_control"]["high"] == 1
        assert result.counts_by_domain["data_protection"]["medium"] == 1

    def test_zero_counts_present_for_all_severities(self) -> None:
        result = evaluate([_f(Severity.HIGH)])
        for sev in Severity:
            assert sev.value in result.counts_by_severity
