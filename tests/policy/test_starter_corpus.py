"""PA-4: Starter corpus completeness tests."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from compliance_mcp.models.finding import Severity
from compliance_mcp.policy.corpus import load_corpus
from compliance_mcp.policy.models import PolicyDomain

if TYPE_CHECKING:
    import pathlib


class TestStarterCorpus:
    def test_every_required_domain_has_coverage(self, policy_dir: pathlib.Path) -> None:
        rules = load_corpus(policy_dir)
        assert rules, "corpus must not be empty"

        domains_covered = {r.domain for r in rules}
        required = {
            PolicyDomain.SECURITY, PolicyDomain.SUPPLY_CHAIN, PolicyDomain.POLICY, PolicyDomain.I18N
        }
        missing = required - domains_covered
        assert not missing, f"domains with no policies: {[d.value for d in missing]}"

    def test_each_domain_has_multiple_rules(self, policy_dir: pathlib.Path) -> None:
        rules = load_corpus(policy_dir)
        by_domain: dict[str, list] = {}
        for r in rules:
            by_domain.setdefault(r.domain.value, []).append(r)

        for domain_val, domain_rules in by_domain.items():
            assert len(domain_rules) >= 2, (
                f"domain '{domain_val}' has only {len(domain_rules)} rule(s); need ≥ 2"
            )

    def test_credential_storage_rule_cites_control(self, policy_dir: pathlib.Path) -> None:
        rules = load_corpus(policy_dir)
        cred_rules = [r for r in rules if r.topic == "credential-storage"]
        assert cred_rules, "credential-storage rule must be present"
        rule = cred_rules[0]
        assert rule.controls, "credential-storage rule must cite at least one control"
        assert rule.severity == Severity.CRITICAL

    def test_zero_validation_errors(self, policy_dir: pathlib.Path) -> None:
        """All shipped policies parse without validation errors."""
        warning_messages: list[str] = []

        class ListHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                warning_messages.append(record.getMessage())

        handler = ListHandler()
        corpus_logger = logging.getLogger("compliance_mcp.policy.corpus")
        corpus_logger.addHandler(handler)
        try:
            load_corpus(policy_dir)
        finally:
            corpus_logger.removeHandler(handler)

        validation_warnings = [m for m in warning_messages if "invalid policy" in m.lower()]
        assert not validation_warnings, (
            "corpus has validation errors:\n" + "\n".join(validation_warnings)
        )

    def test_all_rules_have_required_fields(self, policy_dir: pathlib.Path) -> None:
        rules = load_corpus(policy_dir)
        for rule in rules:
            assert rule.id, f"rule missing id: {rule}"
            assert rule.domain, f"rule missing domain: {rule.id}"
            assert rule.topic, f"rule missing topic: {rule.id}"
