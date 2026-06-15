"""Tests for the finding control-mapper (FM-2)."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from compliance_mcp.framework.mapper import enrich_finding, enrich_findings
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
            CC8.1:
              title: "Change Management"
          gdpr:
            "Art.5(1)(f)":
              title: "Integrity and confidentiality"
            "Art.5(1)(e)":
              title: "Storage limitation"
        mappings:
          - rule_id: "gitleaks.generic-api-key"
            controls:
              soc2: ["CC6.1"]
              gdpr: ["Art.5(1)(f)"]
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


def make_finding(**kwargs: object) -> Finding:
    defaults = dict(
        lens=Lens.SOC2,
        domain=Domain.ACCESS_CONTROL,
        rule_id="test.rule",
        file_path="src/foo.py",
        line_start=1,
        severity=Severity.MEDIUM,
        title="Test finding",
    )
    defaults.update(kwargs)
    return Finding(**defaults)  # type: ignore[arg-type]


class TestEnrichFinding:
    def test_known_rule_id_gets_refs(self, mapping) -> None:  # noqa: ANN001
        finding = make_finding(rule_id="gitleaks.generic-api-key")
        enriched = enrich_finding(finding, mapping)
        assert "soc2:CC6.1" in enriched.control_refs
        assert "gdpr:Art.5(1)(f)" in enriched.control_refs

    def test_unknown_rule_id_preserved_without_refs(self, mapping) -> None:  # noqa: ANN001
        finding = make_finding(rule_id="completely.unknown")
        enriched = enrich_finding(finding, mapping)
        # Category fallback: domain=access_control is not in controls.yaml category map
        # so no refs added
        assert enriched.rule_id == "completely.unknown"
        assert enriched.fingerprint == finding.fingerprint

    def test_domain_category_fallback(self, mapping) -> None:  # noqa: ANN001
        finding = make_finding(
            rule_id="some.tool.finding",
            domain=Domain.SUPPLY_CHAIN,
        )
        enriched = enrich_finding(finding, mapping)
        assert "soc2:CC8.1" in enriched.control_refs

    def test_policy_id_derived_from_rule_id(self, mapping) -> None:  # noqa: ANN001
        # rule_id="gdpr.data-retention" → policy_id lookup succeeds
        finding = make_finding(
            lens=Lens.GDPR,
            rule_id="gdpr.data-retention",
            domain=Domain.DATA_PROTECTION,
        )
        enriched = enrich_finding(finding, mapping)
        assert "gdpr:Art.5(1)(e)" in enriched.control_refs

    def test_existing_control_refs_preserved(self, mapping) -> None:  # noqa: ANN001
        finding = make_finding(
            rule_id="gitleaks.generic-api-key",
            control_refs=["soc2:CC9.1"],  # pre-existing ref
        )
        enriched = enrich_finding(finding, mapping)
        assert "soc2:CC9.1" in enriched.control_refs
        assert "soc2:CC6.1" in enriched.control_refs

    def test_refs_are_deduplicated(self, mapping) -> None:  # noqa: ANN001
        finding = make_finding(
            rule_id="gitleaks.generic-api-key",
            control_refs=["soc2:CC6.1"],  # duplicate of what rule_id maps to
        )
        enriched = enrich_finding(finding, mapping)
        assert enriched.control_refs.count("soc2:CC6.1") == 1

    def test_fingerprint_unchanged_after_enrichment(self, mapping) -> None:  # noqa: ANN001
        finding = make_finding(rule_id="gitleaks.generic-api-key")
        enriched = enrich_finding(finding, mapping)
        assert enriched.fingerprint == finding.fingerprint

    def test_no_match_returns_same_object(self, mapping) -> None:  # noqa: ANN001
        finding = make_finding(rule_id="no.match.here", domain=Domain.OTHER)
        result = enrich_finding(finding, mapping)
        # No refs from mapping, no existing refs — same object returned
        assert result is finding

    def test_refs_are_sorted(self, mapping) -> None:  # noqa: ANN001
        finding = make_finding(rule_id="gitleaks.generic-api-key")
        enriched = enrich_finding(finding, mapping)
        assert enriched.control_refs == sorted(enriched.control_refs)


class TestEnrichFindings:
    def test_empty_list_returns_empty(self, mapping) -> None:  # noqa: ANN001
        assert enrich_findings([], mapping) == []

    def test_all_findings_preserved(self, mapping) -> None:  # noqa: ANN001
        findings = [
            make_finding(rule_id="gitleaks.generic-api-key"),
            make_finding(rule_id="no.match.rule", domain=Domain.OTHER),
        ]
        enriched = enrich_findings(findings, mapping)
        assert len(enriched) == 2

    def test_unmapped_finding_not_dropped(self, mapping) -> None:  # noqa: ANN001
        findings = [
            make_finding(rule_id="no.match.rule", domain=Domain.OTHER),
        ]
        enriched = enrich_findings(findings, mapping)
        assert len(enriched) == 1
        assert enriched[0].control_refs == []

    def test_order_preserved(self, mapping) -> None:  # noqa: ANN001
        findings = [make_finding(rule_id=f"tool.rule{i}", line_start=i + 1) for i in range(5)]
        enriched = enrich_findings(findings, mapping)
        fps = [f.fingerprint for f in enriched]
        original_fps = [f.fingerprint for f in findings]
        assert fps == original_fps
