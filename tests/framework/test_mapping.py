"""Tests for the control-mapping table loader (FM-1)."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from compliance_mcp.framework.mapping import (
    SUPPORTED_FRAMEWORKS,
    load_mapping,
)


@pytest.fixture()
def controls_yaml(tmp_path: Path) -> Path:
    """Write a minimal controls.yaml fixture and return its path."""
    content = textwrap.dedent("""\
        version: "1.0"
        frameworks:
          soc2:
            CC6.1:
              title: "Logical Access Security"
              description: "Controls for logical access."
            CC8.1:
              title: "Change Management"
              description: "Controls for change management."
          gdpr:
            "Art.5(1)(f)":
              title: "Integrity and confidentiality"
              description: "Data security requirements."
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
    yaml_file = tmp_path / "controls.yaml"
    yaml_file.write_text(content)
    return yaml_file


@pytest.fixture()
def policy_dir(tmp_path: Path) -> Path:
    """Create a minimal policies directory with one markdown file."""
    pol_dir = tmp_path / "policies"
    pol_dir.mkdir()
    md = pol_dir / "gdpr-data-retention.md"
    md.write_text(
        textwrap.dedent("""\
        ---
        id: gdpr.data-retention
        controls:
          gdpr:
            - "Art.17"
        ---
        # Data Retention Policy
        Keep data only as long as necessary.
    """)
    )
    return pol_dir


class TestLoadMapping:
    def test_loads_framework_definitions(self, controls_yaml: Path) -> None:
        mapping = load_mapping(controls_yaml=controls_yaml)
        ctrl = mapping.get_control("soc2", "CC6.1")
        assert ctrl is not None
        assert ctrl.title == "Logical Access Security"
        assert ctrl.framework == "soc2"

    def test_loads_rule_id_mapping(self, controls_yaml: Path) -> None:
        mapping = load_mapping(controls_yaml=controls_yaml)
        result = mapping.lookup(rule_id="gitleaks.generic-api-key")
        assert "CC6.1" in result.get("soc2", [])
        assert "Art.5(1)(f)" in result.get("gdpr", [])

    def test_loads_policy_id_mapping(self, controls_yaml: Path) -> None:
        mapping = load_mapping(controls_yaml=controls_yaml)
        result = mapping.lookup(policy_id="gdpr.data-retention")
        assert "Art.5(1)(e)" in result.get("gdpr", [])

    def test_loads_category_mapping(self, controls_yaml: Path) -> None:
        mapping = load_mapping(controls_yaml=controls_yaml)
        result = mapping.lookup(category="supply_chain")
        assert "CC8.1" in result.get("soc2", [])

    def test_framework_filter(self, controls_yaml: Path) -> None:
        mapping = load_mapping(controls_yaml=controls_yaml)
        result = mapping.lookup(rule_id="gitleaks.generic-api-key", framework="soc2")
        assert "soc2" in result
        assert "gdpr" not in result

    def test_missing_yaml_does_not_crash(self, tmp_path: Path) -> None:
        mapping = load_mapping(controls_yaml=tmp_path / "nonexistent.yaml")
        assert mapping.supported_frameworks() == []

    def test_malformed_entry_skipped_with_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        bad_yaml = tmp_path / "controls.yaml"
        bad_yaml.write_text(
            textwrap.dedent("""\
            version: "1.0"
            frameworks:
              soc2:
                CC6.1:
                  title: "Good control"
            mappings:
              - {}
              - rule_id: "ok.rule"
                controls:
                  soc2: ["CC6.1"]
        """)
        )
        import logging

        with caplog.at_level(logging.WARNING):
            mapping = load_mapping(controls_yaml=bad_yaml)
        result = mapping.lookup(rule_id="ok.rule")
        assert "CC6.1" in result.get("soc2", [])

    def test_frontmatter_controls_merged(self, controls_yaml: Path, policy_dir: Path) -> None:
        mapping = load_mapping(controls_yaml=controls_yaml, policies_dir=policy_dir)
        # Policy frontmatter adds Art.17 for gdpr.data-retention
        result = mapping.lookup(policy_id="gdpr.data-retention")
        gdpr_controls = result.get("gdpr", [])
        assert "Art.5(1)(e)" in gdpr_controls  # from yaml
        assert "Art.17" in gdpr_controls  # from frontmatter

    def test_supported_frameworks_from_yaml(self, controls_yaml: Path) -> None:
        mapping = load_mapping(controls_yaml=controls_yaml)
        assert "soc2" in mapping.supported_frameworks()
        assert "gdpr" in mapping.supported_frameworks()

    def test_get_unknown_control_returns_none(self, controls_yaml: Path) -> None:
        mapping = load_mapping(controls_yaml=controls_yaml)
        assert mapping.get_control("soc2", "NONEXISTENT") is None

    def test_controls_for_framework(self, controls_yaml: Path) -> None:
        mapping = load_mapping(controls_yaml=controls_yaml)
        defs = mapping.controls_for_framework("soc2")
        assert "CC6.1" in defs
        assert "CC8.1" in defs

    def test_policies_for_control(self, controls_yaml: Path) -> None:
        mapping = load_mapping(controls_yaml=controls_yaml)
        pols = mapping.policies_for_control("gdpr", "Art.5(1)(e)")
        assert "gdpr.data-retention" in pols

    def test_rules_for_control(self, controls_yaml: Path) -> None:
        mapping = load_mapping(controls_yaml=controls_yaml)
        rules = mapping.rules_for_control("soc2", "CC6.1")
        assert "gitleaks.generic-api-key" in rules

    def test_lookup_returns_empty_for_unknown_key(self, controls_yaml: Path) -> None:
        mapping = load_mapping(controls_yaml=controls_yaml)
        result = mapping.lookup(rule_id="unknown.rule.xyz")
        assert result == {}

    def test_starter_controls_yaml_parses(self) -> None:
        """The shipped controls.yaml must parse with no errors."""
        yaml_path = Path("policies/mappings/controls.yaml")
        if not yaml_path.exists():
            pytest.skip("controls.yaml not found; run from repo root")
        mapping = load_mapping(controls_yaml=yaml_path)
        # Must have all five frameworks defined
        fws = set(mapping.supported_frameworks())
        assert SUPPORTED_FRAMEWORKS.issubset(fws)

    def test_lookup_unions_all_keys(self, controls_yaml: Path) -> None:
        """When multiple keys are given, results should be unioned."""
        mapping = load_mapping(controls_yaml=controls_yaml)
        result = mapping.lookup(
            rule_id="gitleaks.generic-api-key",
            policy_id="gdpr.data-retention",
            category="supply_chain",
        )
        # rule_id contributes CC6.1 (soc2) and Art.5(1)(f) (gdpr)
        # policy_id contributes Art.5(1)(e) (gdpr)
        # category contributes CC8.1 (soc2)
        assert "CC6.1" in result.get("soc2", [])
        assert "CC8.1" in result.get("soc2", [])
        assert "Art.5(1)(f)" in result.get("gdpr", [])
        assert "Art.5(1)(e)" in result.get("gdpr", [])
