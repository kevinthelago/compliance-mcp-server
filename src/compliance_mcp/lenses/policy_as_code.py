"""Policy-as-code lens: evaluates YAML-declared org rules against a repository.

The lens is intentionally framework-agnostic.  Rules express *what* to check
(file present/absent, regex match, structured-path assertion) and tag findings
with control references so the framework-mapping layer can enrich them into
SOC2 / ISO 27001 / etc. controls.

Usage
-----
    from pathlib import Path
    from compliance_mcp.lenses.policy_as_code import PolicyAsCodeLens

    lens = PolicyAsCodeLens(rules_dir=Path("policies/rules"))
    findings = lens.scan(Path("/path/to/repo"))
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from compliance_mcp.policy_rules.assertions import evaluate
from compliance_mcp.policy_rules.loader import load_rules

if TYPE_CHECKING:
    from compliance_mcp.models.finding import Finding
    from compliance_mcp.policy_rules.schema import Rule

logger = logging.getLogger(__name__)

_DEFAULT_RULES_DIR = Path("policies/rules")


class PolicyAsCodeLens:
    """Evaluates a YAML ruleset against a repository directory.

    Args:
        rules_dir: Directory containing ``*.yaml`` rule files.
                   Defaults to ``policies/rules`` relative to the working directory.
    """

    def __init__(self, rules_dir: Path = _DEFAULT_RULES_DIR) -> None:
        self._rules_dir = rules_dir
        self._rules: list[Rule] = load_rules(rules_dir)
        logger.debug("PolicyAsCodeLens loaded %d rule(s) from '%s'", len(self._rules), rules_dir)

    @property
    def rules(self) -> list[Rule]:
        """The loaded rules (read-only view)."""
        return list(self._rules)

    def scan(self, repo_root: Path) -> list[Finding]:
        """Evaluate all rules against *repo_root*.

        Args:
            repo_root: Absolute path to the repository being scanned.

        Returns:
            All findings (violations) across every rule.  An empty list means
            the repository satisfies all loaded rules.
        """
        findings: list[Finding] = []
        for rule in self._rules:
            rule_findings = evaluate(rule, repo_root)
            findings.extend(rule_findings)
            if rule_findings:
                logger.debug("Rule '%s' produced %d finding(s)", rule.id, len(rule_findings))
        return findings
