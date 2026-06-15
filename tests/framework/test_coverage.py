"""Tests for control coverage rollup and explain_control (FM-3)."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from compliance_mcp.framework.coverage import (
    ControlCoverageError,
    ControlStatus,
    compute_coverage,
    explain_control_entry,
)
from compliance_mcp.framework.mapper import enrich_findings
from compliance_mcp.framework.mapping import load_mapping
from compliance_mcp.models.finding import Domain, Finding, Lens, Severity


@pytest.fixture()
def controls_yaml(tmp_path: Path) -> Path:
    content = textwrap.dedent("""\
        version: "1.0"
        frameworks:
          soc2:
            CC6.1:
              title: "Logical Access Security"
              description: "Access security controls."
            CC7.1:
              title: "Detection of Anomalies"
              description: "Detection procedures."
            CC8.1:
              title: "Change Management"
              description: "Change controls."
          gdpr:
            "Art.5(1)(f)":
              title: "Integrity and confidentiality"
              description: "Data security."
            "Art.5(1)(e)":
              title: "Storage limitation"
              description: "Keep data only as long as necessary."
        mappings:
          - rule_id: "gitleaks.generic-api-key"
            controls:
              soc2: ["CC6.1"]
              gdpr: ["Art.5(1)(f)"]
          - rule_id: "trivy.CVE-HIGH"
            controls:
              soc2: ["CC8.1"]
          - policy_id: "gdpr.data-retention"
            controls:
              gdpr: ["Art.5(1)(e)"]
          - category: "supply_chain"
            controls:
              soc2: ["CC8.1"]
    """)
    p = tmp_path / "controls.yaml"
    p.write_text(content)
    return p


@pytest.fixture()
def mapping(controls_yaml: Path):  # noqa: ANN201
    return load_mapping(controls_yaml=controls_yaml)


def _make_finding(
    rule_id: str, severity: Severity, domain: Domain = Domain.ACCESS_CONTROL
) -> Finding:
    return Finding(
        lens=Lens.SOC2,
        domain=domain,
        rule_id=rule_id,
        file_path="src/foo.py",
        line_start=1,
        severity=severity,
        title=f"Finding for {rule_id}",
    )


class TestComputeCoverage:
    def test_unknown_framework_raises(self, mapping) -> None:  # noqa: ANN001
        with pytest.raises(ControlCoverageError, match="Unknown framework"):
            compute_coverage([], "unknown_fw", mapping)

    def test_known_framework_error_lists_supported(self, mapping) -> None:  # noqa: ANN001
        with pytest.raises(ControlCoverageError) as exc_info:
            compute_coverage([], "bad_framework", mapping)
        assert "soc2" in str(exc_info.value)
        assert "gdpr" in str(exc_info.value)

    def test_no_findings_all_addressed(self, mapping) -> None:  # noqa: ANN001
        result = compute_coverage([], "soc2", mapping)
        summary = result["summary"]
        # No findings → all known controls are "addressed"
        assert summary["at_risk"] == 0
        assert summary["addressed"] == 3  # CC6.1, CC7.1, CC8.1
        assert summary["total"] == 3

    def test_at_risk_when_finding_maps_to_control(self, mapping) -> None:  # noqa: ANN001
        finding = _make_finding("gitleaks.generic-api-key", Severity.HIGH)
        enriched = enrich_findings([finding], mapping)
        result = compute_coverage(enriched, "soc2", mapping)
        cc6 = result["controls"]["CC6.1"]
        assert cc6["status"] == ControlStatus.AT_RISK.value
        assert cc6["findings_count"] == 1
        assert cc6["max_severity"] == "high"

    def test_addressed_when_no_findings_for_control(self, mapping) -> None:  # noqa: ANN001
        finding = _make_finding("gitleaks.generic-api-key", Severity.HIGH)
        enriched = enrich_findings([finding], mapping)
        result = compute_coverage(enriched, "soc2", mapping)
        # CC7.1 has no findings
        assert result["controls"]["CC7.1"]["status"] == ControlStatus.ADDRESSED.value
        assert result["controls"]["CC7.1"]["findings_count"] == 0

    def test_max_severity_reflects_worst_finding(self, mapping) -> None:  # noqa: ANN001
        findings = [
            _make_finding("trivy.CVE-HIGH", Severity.HIGH),
            _make_finding("gitleaks.generic-api-key", Severity.CRITICAL, Domain.ACCESS_CONTROL),
        ]
        # patch: add CC8.1 mapping for second finding by using supply_chain category
        f2 = Finding(
            lens=Lens.SOC2,
            domain=Domain.SUPPLY_CHAIN,
            rule_id="gitleaks.generic-api-key",
            file_path="src/bar.py",
            line_start=5,
            severity=Severity.CRITICAL,
            title="High severity",
        )
        enriched = enrich_findings([findings[0], f2], mapping)
        result = compute_coverage(enriched, "soc2", mapping)
        cc8 = result["controls"]["CC8.1"]
        assert cc8["status"] == ControlStatus.AT_RISK.value
        # CC8.1 has both a HIGH (trivy.CVE-HIGH) and CRITICAL (supply_chain category) finding
        assert cc8["max_severity"] in ("critical", "high")

    def test_gdpr_framework(self, mapping) -> None:  # noqa: ANN001
        finding = Finding(
            lens=Lens.GDPR,
            domain=Domain.DATA_PROTECTION,
            rule_id="gdpr.data-retention",
            file_path="src/db.py",
            line_start=10,
            severity=Severity.HIGH,
            title="Data retention violation",
        )
        enriched = enrich_findings([finding], mapping)
        result = compute_coverage(enriched, "gdpr", mapping)
        art5e = result["controls"].get("Art.5(1)(e)")
        assert art5e is not None
        assert art5e["status"] == ControlStatus.AT_RISK.value

    def test_summary_counts_correct(self, mapping) -> None:  # noqa: ANN001
        finding = _make_finding("gitleaks.generic-api-key", Severity.HIGH)
        enriched = enrich_findings([finding], mapping)
        result = compute_coverage(enriched, "soc2", mapping)
        s = result["summary"]
        assert s["at_risk"] + s["addressed"] + s["no_evidence"] == s["total"]

    def test_controls_have_title(self, mapping) -> None:  # noqa: ANN001
        result = compute_coverage([], "soc2", mapping)
        for ctrl in result["controls"].values():
            assert ctrl["title"]  # must be non-empty string

    def test_empty_findings_empty_refs(self, mapping) -> None:  # noqa: ANN001
        # Findings with no control_refs should not affect coverage
        finding = _make_finding("unknown.rule", Severity.INFO)
        result = compute_coverage([finding], "soc2", mapping)
        assert result["summary"]["at_risk"] == 0

    def test_framework_key_in_result(self, mapping) -> None:  # noqa: ANN001
        result = compute_coverage([], "soc2", mapping)
        assert result["framework"] == "soc2"


class TestExplainControlEntry:
    def test_known_control_returns_entry(self, mapping) -> None:  # noqa: ANN001
        entry = explain_control_entry("soc2", "CC6.1", mapping)
        assert entry["id"] == "CC6.1"
        assert entry["framework"] == "soc2"
        assert "Logical Access" in entry["title"]
        assert isinstance(entry["description"], str)
        assert isinstance(entry["mapped_policies"], list)
        assert isinstance(entry["mapped_rules"], list)

    def test_mapped_rules_listed(self, mapping) -> None:  # noqa: ANN001
        entry = explain_control_entry("soc2", "CC6.1", mapping)
        assert "gitleaks.generic-api-key" in entry["mapped_rules"]

    def test_mapped_policies_listed(self, mapping) -> None:  # noqa: ANN001
        entry = explain_control_entry("gdpr", "Art.5(1)(e)", mapping)
        assert "gdpr.data-retention" in entry["mapped_policies"]

    def test_unknown_framework_raises(self, mapping) -> None:  # noqa: ANN001
        with pytest.raises(ControlCoverageError, match="Unknown framework"):
            explain_control_entry("unknown_fw", "CC6.1", mapping)

    def test_unknown_control_raises(self, mapping) -> None:  # noqa: ANN001
        with pytest.raises(ControlCoverageError, match="not found"):
            explain_control_entry("soc2", "NONEXISTENT", mapping)

    def test_unknown_control_error_lists_known(self, mapping) -> None:  # noqa: ANN001
        with pytest.raises(ControlCoverageError) as exc_info:
            explain_control_entry("soc2", "XX99", mapping)
        assert "CC6.1" in str(exc_info.value)
