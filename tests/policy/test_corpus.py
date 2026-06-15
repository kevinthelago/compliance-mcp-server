"""PA-1: Tests for the policy corpus loader."""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

from compliance_mcp.models.finding import Severity
from compliance_mcp.policy.corpus import load_corpus
from compliance_mcp.policy.models import PolicyDomain

if TYPE_CHECKING:
    import pathlib


def _write_policy(path: pathlib.Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content), encoding="utf-8")


class TestLoadCorpus:
    def test_loads_valid_policy(self, tmp_policy_dir: pathlib.Path) -> None:
        _write_policy(
            tmp_policy_dir / "security" / "test.md",
            """\
            ---
            id: TEST-001
            domain: security
            topic: test-topic
            severity: high
            controls:
              - SOC2-CC6.1
            keywords:
              - test
            locales: []
            ---

            Policy body text.
            """,
        )

        rules = load_corpus(tmp_policy_dir)

        assert len(rules) == 1
        rule = rules[0]
        assert rule.id == "TEST-001"
        assert rule.domain == PolicyDomain.SECURITY
        assert rule.topic == "test-topic"
        assert rule.severity == Severity.HIGH
        assert "SOC2-CC6.1" in rule.controls
        assert "test" in rule.keywords
        assert "Policy body text." in rule.body

    def test_skips_invalid_policy_and_loads_rest(self, tmp_policy_dir: pathlib.Path) -> None:
        _write_policy(
            tmp_policy_dir / "ok.md",
            """\
            ---
            id: OK-001
            domain: security
            topic: ok
            ---
            """,
        )
        # missing required 'domain'
        _write_policy(
            tmp_policy_dir / "bad.md",
            """\
            ---
            id: BAD-001
            topic: no-domain-here
            ---
            """,
        )

        rules = load_corpus(tmp_policy_dir)

        ids = [r.id for r in rules]
        assert "OK-001" in ids
        assert "BAD-001" not in ids

    def test_empty_directory_returns_empty_list(self, tmp_policy_dir: pathlib.Path) -> None:
        tmp_policy_dir.mkdir(parents=True, exist_ok=True)
        assert load_corpus(tmp_policy_dir) == []

    def test_defaults_severity_to_medium(self, tmp_policy_dir: pathlib.Path) -> None:
        _write_policy(
            tmp_policy_dir / "test.md",
            """\
            ---
            id: DEF-001
            domain: policy
            topic: default-severity
            ---
            """,
        )

        rules = load_corpus(tmp_policy_dir)
        assert rules[0].severity == Severity.MEDIUM


class TestRealCorpus:
    """Integration: the shipped corpus must parse with zero validation errors."""

    def test_real_corpus_loads(self, policy_dir: pathlib.Path) -> None:
        rules = load_corpus(policy_dir)
        assert len(rules) > 0, "shipped corpus must contain at least one rule"

    def test_real_corpus_all_domains_have_coverage(self, policy_dir: pathlib.Path) -> None:
        rules = load_corpus(policy_dir)
        domains_present = {r.domain for r in rules}
        expected = {
            PolicyDomain.SECURITY,
            PolicyDomain.SUPPLY_CHAIN,
            PolicyDomain.POLICY,
            PolicyDomain.I18N,
        }
        missing = expected - domains_present
        assert not missing, f"no policies found for domains: {missing}"

    def test_credential_storage_rule_present(self, policy_dir: pathlib.Path) -> None:
        rules = load_corpus(policy_dir)
        credential_rules = [r for r in rules if r.topic == "credential-storage"]
        assert credential_rules, "a credential-storage rule must exist in the corpus"
        rule = credential_rules[0]
        assert rule.controls, "credential-storage rule must cite at least one control"
        assert rule.severity == Severity.CRITICAL
