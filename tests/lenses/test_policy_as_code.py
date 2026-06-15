"""Integration tests for the PolicyAsCodeLens (PAC-3)."""

from __future__ import annotations

from pathlib import Path

from compliance_mcp.lenses.policy_as_code import PolicyAsCodeLens
from compliance_mcp.models.finding import Lens, Severity


class TestPolicyAsCodeLens:
    def test_compliant_repo_produces_no_findings(
        self, compliant_repo: Path, rules_dir: Path
    ) -> None:
        lens = PolicyAsCodeLens(rules_dir=rules_dir)
        findings = lens.scan(compliant_repo)
        assert findings == [], "Expected no findings for compliant_repo; got: " + ", ".join(
            f"{f.rule_id} @ {f.file_path}" for f in findings
        )

    def test_noncompliant_repo_has_violations(
        self, noncompliant_repo: Path, rules_dir: Path
    ) -> None:
        lens = PolicyAsCodeLens(rules_dir=rules_dir)
        findings = lens.scan(noncompliant_repo)
        assert findings, "Expected findings for noncompliant_repo, got none"

    def test_noncompliant_repo_missing_license(
        self, noncompliant_repo: Path, rules_dir: Path
    ) -> None:
        lens = PolicyAsCodeLens(rules_dir=rules_dir)
        findings = lens.scan(noncompliant_repo)
        ids = [f.rule_id for f in findings]
        assert "pac.require-license" in ids

    def test_noncompliant_repo_missing_security_md(
        self, noncompliant_repo: Path, rules_dir: Path
    ) -> None:
        lens = PolicyAsCodeLens(rules_dir=rules_dir)
        findings = lens.scan(noncompliant_repo)
        ids = [f.rule_id for f in findings]
        assert "pac.require-security-md" in ids

    def test_noncompliant_repo_env_file_flagged(
        self, noncompliant_repo: Path, rules_dir: Path
    ) -> None:
        lens = PolicyAsCodeLens(rules_dir=rules_dir)
        findings = lens.scan(noncompliant_repo)
        ids = [f.rule_id for f in findings]
        assert "pac.no-committed-env" in ids

    def test_noncompliant_repo_package_json_missing_license(
        self, noncompliant_repo: Path, rules_dir: Path
    ) -> None:
        lens = PolicyAsCodeLens(rules_dir=rules_dir)
        findings = lens.scan(noncompliant_repo)
        ids = [f.rule_id for f in findings]
        assert "pac.package-json-license" in ids

    def test_noncompliant_repo_dockerfile_root_user(
        self, noncompliant_repo: Path, rules_dir: Path
    ) -> None:
        lens = PolicyAsCodeLens(rules_dir=rules_dir)
        findings = lens.scan(noncompliant_repo)
        ids = [f.rule_id for f in findings]
        assert "pac.dockerfile-non-root" in ids

    def test_noncompliant_repo_dockerfile_unpinned_base(
        self, noncompliant_repo: Path, rules_dir: Path
    ) -> None:
        lens = PolicyAsCodeLens(rules_dir=rules_dir)
        findings = lens.scan(noncompliant_repo)
        ids = [f.rule_id for f in findings]
        assert "pac.dockerfile-pinned-base" in ids

    def test_all_findings_use_custom_lens(self, noncompliant_repo: Path, rules_dir: Path) -> None:
        lens = PolicyAsCodeLens(rules_dir=rules_dir)
        findings = lens.scan(noncompliant_repo)
        assert all(f.lens == Lens.CUSTOM for f in findings)

    def test_findings_have_stable_fingerprints(
        self, noncompliant_repo: Path, rules_dir: Path
    ) -> None:
        lens = PolicyAsCodeLens(rules_dir=rules_dir)
        run1 = lens.scan(noncompliant_repo)
        run2 = lens.scan(noncompliant_repo)
        fps1 = {f.fingerprint for f in run1}
        fps2 = {f.fingerprint for f in run2}
        assert fps1 == fps2

    def test_fingerprints_are_unique(self, noncompliant_repo: Path, rules_dir: Path) -> None:
        lens = PolicyAsCodeLens(rules_dir=rules_dir)
        findings = lens.scan(noncompliant_repo)
        fps = [f.fingerprint for f in findings]
        assert len(fps) == len(set(fps)), "Duplicate fingerprints found"

    def test_empty_rules_dir_returns_no_findings(self, tmp_path: Path) -> None:
        rules_dir = tmp_path / "empty_rules"
        rules_dir.mkdir()
        lens = PolicyAsCodeLens(rules_dir=rules_dir)
        assert lens.scan(tmp_path) == []

    def test_rules_property_returns_loaded_rules(self, rules_dir: Path) -> None:
        lens = PolicyAsCodeLens(rules_dir=rules_dir)
        assert len(lens.rules) > 0

    def test_custom_rules_evaluated(self, tmp_path: Path) -> None:
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "custom.yaml").write_text(
            "- id: need-readme\n"
            "  description: README.md must exist\n"
            "  severity: medium\n"
            "  target: README.md\n"
            "  assertion:\n"
            "    type: file-present\n"
        )
        repo = tmp_path / "repo"
        repo.mkdir()
        lens = PolicyAsCodeLens(rules_dir=rules_dir)
        findings = lens.scan(repo)
        assert len(findings) == 1
        assert findings[0].rule_id == "pac.need-readme"

    def test_severity_info_excluded_from_high_findings(
        self, noncompliant_repo: Path, rules_dir: Path
    ) -> None:
        lens = PolicyAsCodeLens(rules_dir=rules_dir)
        findings = lens.scan(noncompliant_repo)
        high_or_above = [f for f in findings if f.severity >= Severity.HIGH]
        assert high_or_above, "Expected at least one high/critical finding"
