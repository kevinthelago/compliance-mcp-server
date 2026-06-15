"""PA-2: Tests for the corpus index and structured-lookup engine."""

from __future__ import annotations

from typing import TYPE_CHECKING

from compliance_mcp.models.finding import Severity
from compliance_mcp.policy.corpus import load_corpus
from compliance_mcp.policy.engine import PolicyEngine
from compliance_mcp.policy.models import PolicyDomain, PolicyRule

if TYPE_CHECKING:
    import pathlib


def _make_rule(**kwargs: object) -> PolicyRule:
    defaults: dict[str, object] = {
        "id": "X-001",
        "domain": PolicyDomain.SECURITY,
        "topic": "test-topic",
        "severity": Severity.MEDIUM,
        "controls": [],
        "keywords": [],
        "locales": [],
        "body": "",
    }
    defaults.update(kwargs)
    return PolicyRule.model_validate(defaults)


class TestPolicyEngine:
    def _engine(self, rules: list[PolicyRule]) -> PolicyEngine:
        return PolicyEngine.from_corpus(rules)

    def test_query_by_domain(self) -> None:
        sec = _make_rule(id="S-001", domain=PolicyDomain.SECURITY, topic="auth")
        sc = _make_rule(id="SC-001", domain=PolicyDomain.SUPPLY_CHAIN, topic="license")
        engine = self._engine([sec, sc])

        result = engine.query(domain=PolicyDomain.SECURITY)
        assert len(result.matches) == 1
        assert result.matches[0].id == "S-001"

    def test_query_by_topic_exact_match(self) -> None:
        r1 = _make_rule(id="A-001", domain=PolicyDomain.SECURITY, topic="credential-storage")
        r2 = _make_rule(id="A-002", domain=PolicyDomain.SECURITY, topic="access-control")
        engine = self._engine([r1, r2])

        result = engine.query(topic="credential-storage")
        assert len(result.matches) == 1
        assert result.matches[0].id == "A-001"

    def test_query_keyword_ranking(self) -> None:
        r_high = _make_rule(
            id="H-001",
            domain=PolicyDomain.SECURITY,
            topic="secrets",
            keywords=["credentials", "passwords", "tokens"],
        )
        r_low = _make_rule(
            id="L-001",
            domain=PolicyDomain.SECURITY,
            topic="networking",
            keywords=["firewall", "port"],
        )
        engine = self._engine([r_low, r_high])

        result = engine.query(query="credentials tokens passwords")
        assert result.matches[0].id == "H-001", "higher overlap rule must rank first"

    def test_no_match_returns_nearest_topics(self) -> None:
        r = _make_rule(id="X-001", domain=PolicyDomain.SECURITY, topic="access-control")
        engine = self._engine([r])

        result = engine.query(domain=PolicyDomain.POLICY, topic="nonexistent-topic-xyz")
        assert result.matches == []
        assert isinstance(result.nearest_topics, list)

    def test_empty_corpus_returns_degraded(self) -> None:
        engine = self._engine([])
        result = engine.query()
        assert result.degraded is True
        reason = result.degraded_reason.lower()
        assert "empty" in reason or "not loaded" in reason

    def test_deterministic_ordering_no_query(self) -> None:
        rules = [
            _make_rule(id=f"R-{i:03d}", domain=PolicyDomain.SECURITY, topic=f"topic-{i}")
            for i in range(5)
        ]
        import random

        shuffled = rules[:]
        random.shuffle(shuffled)
        engine1 = self._engine(rules)
        engine2 = self._engine(shuffled)

        r1 = [r.id for r in engine1.query().matches]
        r2 = [r.id for r in engine2.query().matches]
        assert r1 == r2, "ordering must be deterministic regardless of input order"

    def test_list_all_groups_by_domain(self) -> None:
        sec = _make_rule(id="S-001", domain=PolicyDomain.SECURITY, topic="t1")
        sc = _make_rule(id="SC-001", domain=PolicyDomain.SUPPLY_CHAIN, topic="t2")
        engine = self._engine([sec, sc])

        grouped = engine.list_all()
        assert "security" in grouped
        assert "supply_chain" in grouped

    def test_list_all_filtered_by_domain(self) -> None:
        sec = _make_rule(id="S-001", domain=PolicyDomain.SECURITY, topic="t1")
        sc = _make_rule(id="SC-001", domain=PolicyDomain.SUPPLY_CHAIN, topic="t2")
        engine = self._engine([sec, sc])

        grouped = engine.list_all(domain=PolicyDomain.SECURITY)
        assert list(grouped.keys()) == ["security"]
        assert len(grouped["security"]) == 1

    def test_framework_filter(self) -> None:
        soc2_rule = _make_rule(
            id="S-001", domain=PolicyDomain.SECURITY, topic="t1", controls=["SOC2-CC6.1"]
        )
        iso_rule = _make_rule(
            id="I-001", domain=PolicyDomain.SECURITY, topic="t2", controls=["ISO27001-A.9"]
        )
        engine = self._engine([soc2_rule, iso_rule])

        result = engine.query(framework="SOC2")
        assert len(result.matches) == 1
        assert result.matches[0].id == "S-001"

    def test_get_by_id(self) -> None:
        r = _make_rule(id="FIND-001", domain=PolicyDomain.SECURITY, topic="test")
        engine = self._engine([r])
        found = engine.get_by_id("FIND-001")
        assert found is not None
        assert found.id == "FIND-001"

    def test_get_by_id_missing_returns_none(self) -> None:
        engine = self._engine([])
        assert engine.get_by_id("NOPE") is None

    def test_list_all_locale_filter(self) -> None:
        universal = _make_rule(id="U-001", domain=PolicyDomain.I18N, topic="t1", locales=[])
        rtl_only = _make_rule(
            id="R-001", domain=PolicyDomain.I18N, topic="t2", locales=["ar", "he"]
        )
        en_only = _make_rule(id="E-001", domain=PolicyDomain.I18N, topic="t3", locales=["en"])
        engine = self._engine([universal, rtl_only, en_only])

        grouped_ar = engine.list_all(locale="ar")
        ids = [r.id for rules in grouped_ar.values() for r in rules]
        assert "U-001" in ids, "universal rule must appear for any locale"
        assert "R-001" in ids, "ar rule must appear when filtering for ar"
        assert "E-001" not in ids, "en-only rule must not appear when filtering for ar"


class TestRealCorpusEngine:
    def test_query_credential_storage(self, policy_dir: pathlib.Path) -> None:
        rules = load_corpus(policy_dir)
        engine = PolicyEngine.from_corpus(rules)

        result = engine.query(topic="credential-storage")
        assert result.matches, "should find credential-storage policy"
        assert result.matches[0].controls, "result must have controls"

    def test_query_free_text_secrets(self, policy_dir: pathlib.Path) -> None:
        rules = load_corpus(policy_dir)
        engine = PolicyEngine.from_corpus(rules)

        result = engine.query(query="secrets api keys passwords")
        assert result.matches

    def test_no_match_returns_suggestions(self, policy_dir: pathlib.Path) -> None:
        rules = load_corpus(policy_dir)
        engine = PolicyEngine.from_corpus(rules)

        result = engine.query(query="xyzzy-completely-unknown-topic-abc123")
        assert isinstance(result.matches, list)
