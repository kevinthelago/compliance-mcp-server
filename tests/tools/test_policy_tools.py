"""PA-3: Tests for query_policy and list_policies tools.

Tests call the engine/tool functions directly (not via MCP transport) to keep
the suite fast and hermetic.  The server import sets up the FastMCP instance but
we only invoke the underlying callables.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from compliance_mcp.tools.policy import _get_engine, configure

if TYPE_CHECKING:
    import pathlib


@pytest.fixture(autouse=True)
def reset_engine(policy_dir: pathlib.Path) -> None:
    """Point the tool module at the real corpus for each test, then reset."""
    configure(policy_dir)
    yield
    configure(None)


class TestQueryPolicy:
    """Tests via the engine directly (bypasses MCP transport for speed)."""

    def test_get_by_id_returns_rule(self, policy_dir: pathlib.Path) -> None:
        configure(policy_dir)
        engine = _get_engine()
        rule = engine.get_by_id("SEC-001")
        assert rule is not None
        assert rule.id == "SEC-001"
        assert rule.topic == "credential-storage"

    def test_get_by_id_unknown_returns_none(self, policy_dir: pathlib.Path) -> None:
        configure(policy_dir)
        engine = _get_engine()
        assert engine.get_by_id("DOES-NOT-EXIST-999") is None

    def test_credential_storage_has_controls(self, policy_dir: pathlib.Path) -> None:
        configure(policy_dir)
        engine = _get_engine()
        rule = engine.get_by_id("SEC-001")
        assert rule is not None
        assert rule.controls, "credential-storage must cite at least one control"

    def test_locale_filter_universal_rule_always_matches(self, policy_dir: pathlib.Path) -> None:
        configure(policy_dir)
        engine = _get_engine()
        # SEC-001 has empty locales → universal
        rule = engine.get_by_id("SEC-001")
        assert rule is not None
        assert rule.locales == []

    def test_query_by_domain_security(self, policy_dir: pathlib.Path) -> None:
        configure(policy_dir)
        engine = _get_engine()
        result = engine.query(domain="security")
        assert result.matches
        assert all(r.domain.value == "security" for r in result.matches)

    def test_query_by_topic(self, policy_dir: pathlib.Path) -> None:
        configure(policy_dir)
        engine = _get_engine()
        result = engine.query(topic="credential-storage")
        assert result.matches
        assert result.matches[0].id == "SEC-001"

    def test_query_free_text_secrets(self, policy_dir: pathlib.Path) -> None:
        configure(policy_dir)
        engine = _get_engine()
        result = engine.query(query="credentials passwords api keys secrets")
        assert result.matches

    def test_unknown_domain_returns_no_matches(self, policy_dir: pathlib.Path) -> None:
        configure(policy_dir)
        engine = _get_engine()
        result = engine.query(domain="invalid-domain-xyz")
        assert result.matches == []

    def test_no_match_returns_nearest_topics(self, policy_dir: pathlib.Path) -> None:
        configure(policy_dir)
        engine = _get_engine()
        result = engine.query(query="xyzzy-completely-unknown-topic-abc123xyz")
        assert isinstance(result.matches, list)
        assert isinstance(result.nearest_topics, list)

    def test_empty_corpus_returns_degraded(self, tmp_policy_dir: pathlib.Path) -> None:
        tmp_policy_dir.mkdir(parents=True, exist_ok=True)
        configure(tmp_policy_dir)
        engine = _get_engine()
        result = engine.query()
        assert result.degraded is True

    def test_query_by_framework_soc2(self, policy_dir: pathlib.Path) -> None:
        configure(policy_dir)
        engine = _get_engine()
        result = engine.query(framework="SOC2")
        assert result.matches
        for match in result.matches:
            assert any(c.startswith("SOC2") for c in match.controls)


class TestListPolicies:
    def test_list_all_returns_rules(self, policy_dir: pathlib.Path) -> None:
        configure(policy_dir)
        engine = _get_engine()
        grouped = engine.list_all()
        total = sum(len(v) for v in grouped.values())
        assert total > 0

    def test_list_filtered_by_domain(self, policy_dir: pathlib.Path) -> None:
        configure(policy_dir)
        engine = _get_engine()
        grouped = engine.list_all(domain="security")
        assert list(grouped.keys()) == ["security"]

    def test_list_all_groups_by_domain(self, policy_dir: pathlib.Path) -> None:
        configure(policy_dir)
        engine = _get_engine()
        grouped = engine.list_all()
        assert "security" in grouped
        assert "supply_chain" in grouped

    def test_locale_filter_universal(self, policy_dir: pathlib.Path) -> None:
        configure(policy_dir)
        engine = _get_engine()
        # Universal rules (empty locales) should always appear
        grouped_all = engine.list_all()
        grouped_locale = engine.list_all(locale="en")
        total_all = sum(len(v) for v in grouped_all.values())
        total_locale = sum(len(v) for v in grouped_locale.values())
        # All universal rules must be included
        assert total_locale > 0
        assert total_locale <= total_all

    def test_locale_filter_rtl(self, policy_dir: pathlib.Path) -> None:
        configure(policy_dir)
        engine = _get_engine()
        # rtl-support.md lists ar, he, fa
        grouped = engine.list_all(locale="ar")
        i18n_rules = grouped.get("i18n", [])
        rtl_ids = [r.id for r in i18n_rules]
        assert "I18N-003" in rtl_ids, "RTL rule must appear when filtering for 'ar'"

    def test_each_rule_has_id(self, policy_dir: pathlib.Path) -> None:
        configure(policy_dir)
        engine = _get_engine()
        grouped = engine.list_all()
        for rules in grouped.values():
            for r in rules:
                assert r.id
