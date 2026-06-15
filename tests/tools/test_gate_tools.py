"""Integration tests for compliance_gate and generate_report tools — GR-4."""

from __future__ import annotations

import json

import pytest

from compliance_mcp.gate.evaluator import GateDecision
from compliance_mcp.models.finding import Domain, Finding, Lens, Severity
from compliance_mcp.registry import _REGISTRY
from compliance_mcp.tools.gate import compliance_gate, generate_report

# ---------------------------------------------------------------------------
# Stub lens factories
# ---------------------------------------------------------------------------


def _stub_lens(findings: list[Finding] | None = None, *, raises: bool = False):
    """Return an async lens runner that returns *findings* (or raises if raises=True)."""

    async def _runner(project_path: str, settings) -> list[Finding]:
        if raises:
            raise RuntimeError("Stub lens exploded")
        return list(findings or [])

    return _runner


def _make_finding(severity: Severity, idx: int = 0) -> Finding:
    return Finding(
        lens=Lens.SOC2,
        domain=Domain.VULNERABILITY,
        rule_id=f"soc2.rule-{idx}",
        file_path=f"src/file_{idx}.py",
        line_start=idx + 1,
        severity=severity,
        title=f"Finding {idx}",
    )


@pytest.fixture(autouse=True)
def _clear_registry():
    _REGISTRY.clear()
    yield
    _REGISTRY.clear()


# ---------------------------------------------------------------------------
# compliance_gate tests
# ---------------------------------------------------------------------------


class TestComplianceGate:
    @pytest.mark.asyncio
    async def test_no_lenses_returns_inconclusive(self, tmp_path) -> None:
        result = await compliance_gate(str(tmp_path))
        assert result["decision"] == GateDecision.INCONCLUSIVE
        assert result["passed"] is False

    @pytest.mark.asyncio
    async def test_clean_scan_passes(self, tmp_path) -> None:
        _REGISTRY[Lens.SOC2] = _stub_lens([])
        result = await compliance_gate(str(tmp_path), lenses=["soc2"])
        assert result["passed"] is True
        assert result["decision"] == GateDecision.PASS

    @pytest.mark.asyncio
    async def test_blocking_finding_fails_gate(self, tmp_path) -> None:
        crit = _make_finding(Severity.CRITICAL)
        _REGISTRY[Lens.SOC2] = _stub_lens([crit])
        result = await compliance_gate(str(tmp_path), lenses=["soc2"])
        assert result["passed"] is False
        assert result["decision"] == GateDecision.BLOCK
        assert len(result["new_findings"]) == 1

    @pytest.mark.asyncio
    async def test_low_finding_passes_at_medium_threshold(self, tmp_path) -> None:
        low = _make_finding(Severity.LOW)
        _REGISTRY[Lens.SOC2] = _stub_lens([low])
        result = await compliance_gate(str(tmp_path), lenses=["soc2"], severity_threshold="medium")
        assert result["passed"] is True

    @pytest.mark.asyncio
    async def test_erroring_lens_counted_as_skipped(self, tmp_path) -> None:
        _REGISTRY[Lens.SOC2] = _stub_lens(raises=True)
        result = await compliance_gate(str(tmp_path), lenses=["soc2"])
        # Errored lens → no ran lenses → inconclusive
        assert result["decision"] == GateDecision.INCONCLUSIVE

    @pytest.mark.asyncio
    async def test_baseline_suppresses_blocking_finding(self, tmp_path) -> None:
        crit = _make_finding(Severity.CRITICAL)
        _REGISTRY[Lens.SOC2] = _stub_lens([crit])

        baseline_file = tmp_path / "baseline.json"
        baseline_file.write_text(json.dumps([crit.fingerprint]))

        result = await compliance_gate(
            str(tmp_path),
            lenses=["soc2"],
            baseline_file=str(baseline_file),
        )
        assert result["passed"] is True
        assert result["suppressed"] == 1

    @pytest.mark.asyncio
    async def test_unknown_lens_raises(self, tmp_path) -> None:
        with pytest.raises(ValueError, match="Unknown lens"):
            await compliance_gate(str(tmp_path), lenses=["totally-unknown-lens"])

    @pytest.mark.asyncio
    async def test_result_has_required_keys(self, tmp_path) -> None:
        result = await compliance_gate(str(tmp_path))
        assert "passed" in result
        assert "decision" in result
        assert "new_findings" in result
        assert "suppressed" in result


# ---------------------------------------------------------------------------
# generate_report tests
# ---------------------------------------------------------------------------


class TestGenerateReport:
    @pytest.mark.asyncio
    async def test_markdown_format(self, tmp_path) -> None:
        result = await generate_report(str(tmp_path), output_format="markdown")
        assert result["format"] == "markdown"
        assert "#" in result["content"]

    @pytest.mark.asyncio
    async def test_md_alias(self, tmp_path) -> None:
        result = await generate_report(str(tmp_path), output_format="md")
        assert result["format"] == "markdown"

    @pytest.mark.asyncio
    async def test_json_format(self, tmp_path) -> None:
        result = await generate_report(str(tmp_path), output_format="json")
        assert result["format"] == "json"
        data = json.loads(result["content"])
        assert "gate" in data
        assert "findings" in data

    @pytest.mark.asyncio
    async def test_unknown_format_raises(self, tmp_path) -> None:
        with pytest.raises(ValueError, match="Unsupported report format"):
            await generate_report(str(tmp_path), output_format="pdf")

    @pytest.mark.asyncio
    async def test_error_message_lists_supported_formats(self, tmp_path) -> None:
        with pytest.raises(ValueError, match="markdown"):
            await generate_report(str(tmp_path), output_format="html")

    @pytest.mark.asyncio
    async def test_finding_appears_in_report(self, tmp_path) -> None:
        high = _make_finding(Severity.HIGH)
        _REGISTRY[Lens.SOC2] = _stub_lens([high])
        result = await generate_report(str(tmp_path), output_format="markdown", lenses=["soc2"])
        assert high.rule_id in result["content"]

    @pytest.mark.asyncio
    async def test_report_content_is_string(self, tmp_path) -> None:
        result = await generate_report(str(tmp_path))
        assert isinstance(result["content"], str)
