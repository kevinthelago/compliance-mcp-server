"""Structured-lookup engine over a PolicyIndex.

Ranking: metadata-tag match first (domain + topic exact), then keyword/token overlap.
A no-match returns an explicit empty result with nearest-topic suggestions.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from compliance_mcp.policy.index import PolicyIndex, _tokenize
from compliance_mcp.policy.models import PolicyDomain, PolicyRule


@dataclass
class QueryResult:
    """Result of a policy engine query."""

    matches: list[PolicyRule] = field(default_factory=list)
    nearest_topics: list[str] = field(default_factory=list)
    degraded: bool = False
    degraded_reason: str = ""


class PolicyEngine:
    """Deterministic lookup engine that runs against a :class:`PolicyIndex`.

    Instantiate once at server start with a built index, then call :meth:`query`
    repeatedly — it is stateless and thread-safe.
    """

    def __init__(self, index: PolicyIndex) -> None:
        self._index = index

    @classmethod
    def from_corpus(cls, rules: list[PolicyRule]) -> PolicyEngine:
        return cls(PolicyIndex.build(rules))

    def query(
        self,
        domain: PolicyDomain | str | None = None,
        topic: str | None = None,
        query: str | None = None,
        framework: str | None = None,
    ) -> QueryResult:
        """Return matching policies ordered by relevance.

        Stage 1 — metadata filter: restrict by ``domain`` and/or exact ``topic``.
        Stage 2 — keyword overlap: rank remaining candidates by token overlap with
        the free-text ``query``; break ties by rule id (deterministic).
        ``framework`` is passed through and used to filter by controls prefix when
        supplied (e.g. "SOC2", "ISO27001").
        """
        if not self._index.rules:
            return QueryResult(
                degraded=True, degraded_reason="policy corpus is empty or not loaded"
            )

        candidates: list[PolicyRule] = list(self._index.rules)

        # Stage 1a — domain filter
        if domain is not None:
            d_key = domain.value if isinstance(domain, PolicyDomain) else str(domain)
            candidates = [r for r in candidates if r.domain.value == d_key]

        # Stage 1b — topic exact match
        if topic is not None:
            topic_lower = topic.lower()
            topic_matches = [r for r in candidates if r.topic.lower() == topic_lower]
            if topic_matches:
                candidates = topic_matches

        # Stage 1c — framework/control prefix filter
        if framework is not None:
            fw_upper = framework.upper()
            fw_filtered = [
                r for r in candidates if any(c.upper().startswith(fw_upper) for c in r.controls)
            ]
            if fw_filtered:
                candidates = fw_filtered

        # Stage 2 — keyword overlap ranking
        if query:
            query_tokens = _tokenize(query)
            if topic:
                query_tokens |= _tokenize(topic)

            def score(rule: PolicyRule) -> tuple[int, str]:
                rule_tokens = self._index._tokens.get(rule.id, set())
                overlap = len(query_tokens & rule_tokens)
                return (-overlap, rule.id)

            candidates.sort(key=score)
        else:
            candidates.sort(key=lambda r: r.id)

        if candidates:
            return QueryResult(matches=candidates)

        suggestions = self._nearest_topics(topic or query or "")
        return QueryResult(matches=[], nearest_topics=suggestions)

    def get_by_id(self, policy_id: str) -> PolicyRule | None:
        """Return the rule with the given id, or None if not found."""
        for rule in self._index.rules:
            if rule.id == policy_id:
                return rule
        return None

    def list_all(
        self,
        domain: PolicyDomain | str | None = None,
        lens_value: str | None = None,
        locale: str | None = None,
    ) -> dict[str, list[PolicyRule]]:
        """Return all rules grouped by domain, with optional filters.

        ``lens_value`` is ignored for now (policy rules are not scoped to a Lens);
        ``locale`` filters rules that list the given locale in their ``locales`` field
        or that have an empty locales list (universal).
        """
        rules = list(self._index.rules)

        if domain is not None:
            d_key = domain.value if isinstance(domain, PolicyDomain) else str(domain)
            rules = [r for r in rules if r.domain.value == d_key]

        if locale is not None:
            rules = [r for r in rules if not r.locales or locale in r.locales]

        result: dict[str, list[PolicyRule]] = {}
        for rule in rules:
            result.setdefault(rule.domain.value, []).append(rule)
        return result

    def _nearest_topics(self, hint: str, top_n: int = 3) -> list[str]:
        """Return up to *top_n* topic names most similar to *hint* by token overlap."""
        hint_tokens = _tokenize(hint)
        if not hint_tokens:
            return self._index.all_topics[:top_n]

        scored: list[tuple[int, str]] = []
        for topic in self._index.all_topics:
            topic_tokens = _tokenize(topic)
            scored.append((-len(hint_tokens & topic_tokens), topic))
        scored.sort()
        return [t for _, t in scored[:top_n]]
