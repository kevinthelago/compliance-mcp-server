"""In-memory index built from a loaded PolicyRule corpus."""

from __future__ import annotations

import re
from collections import defaultdict

from compliance_mcp.policy.models import PolicyDomain, PolicyRule


def _tokenize(text: str) -> set[str]:
    """Lowercase word tokens, length ≥ 3, from a string."""
    return {w for w in re.findall(r"[a-z0-9]+", text.lower()) if len(w) >= 3}


class PolicyIndex:
    """Immutable index over a corpus of PolicyRules for fast structured lookup.

    Call :meth:`build` to create from a list of rules; the index is
    read-only after construction and safe to share across threads.
    """

    def __init__(
        self,
        rules: list[PolicyRule],
        by_domain: dict[str, list[PolicyRule]],
        by_topic: dict[str, list[PolicyRule]],
        by_control: dict[str, list[PolicyRule]],
        tokens: dict[str, set[str]],
        all_topics: list[str],
    ) -> None:
        self._rules = rules
        self._by_domain = by_domain
        self._by_topic = by_topic
        self._by_control = by_control
        self._tokens = tokens
        self._all_topics = all_topics

    @classmethod
    def build(cls, rules: list[PolicyRule]) -> PolicyIndex:
        """Build an index from a corpus list."""
        by_domain: dict[str, list[PolicyRule]] = defaultdict(list)
        by_topic: dict[str, list[PolicyRule]] = defaultdict(list)
        by_control: dict[str, list[PolicyRule]] = defaultdict(list)
        tokens: dict[str, set[str]] = {}
        all_topics: list[str] = []

        for rule in rules:
            by_domain[rule.domain.value].append(rule)
            by_topic[rule.topic.lower()].append(rule)
            for ctrl in rule.controls:
                by_control[ctrl.upper()].append(rule)
            rule_tokens = (
                _tokenize(rule.topic)
                | _tokenize(" ".join(rule.keywords))
                | _tokenize(rule.body[:500])
            )
            tokens[rule.id] = rule_tokens
            if rule.topic not in all_topics:
                all_topics.append(rule.topic)

        return cls(rules, dict(by_domain), dict(by_topic), dict(by_control), tokens, all_topics)

    @property
    def rules(self) -> list[PolicyRule]:
        return list(self._rules)

    @property
    def all_topics(self) -> list[str]:
        return list(self._all_topics)

    def by_domain(self, domain: PolicyDomain | str) -> list[PolicyRule]:
        key = domain.value if isinstance(domain, PolicyDomain) else domain
        return list(self._by_domain.get(key, []))

    def by_topic(self, topic: str) -> list[PolicyRule]:
        return list(self._by_topic.get(topic.lower(), []))

    def by_control(self, control: str) -> list[PolicyRule]:
        return list(self._by_control.get(control.upper(), []))
