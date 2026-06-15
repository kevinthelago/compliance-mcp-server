"""query_policy and list_policies tool implementations.

Implements the stubs registered in `compliance_mcp.server` by importing the
server's FastMCP instance and re-decorating with matching signatures.

The corpus index is loaded lazily on first call and shared with the
framework-mapping stream via ``_get_engine()``.
"""

from __future__ import annotations

import pathlib
from typing import Any

from compliance_mcp.policy.corpus import load_corpus
from compliance_mcp.policy.engine import PolicyEngine
from compliance_mcp.policy.models import PolicyDomain, PolicyRule
from compliance_mcp.server import mcp

# ---------------------------------------------------------------------------
# Module-level engine — lazily initialised and importable by other streams.
# ---------------------------------------------------------------------------
_engine: PolicyEngine | None = None
_policy_dir: pathlib.Path | None = None


def configure(policy_dir: pathlib.Path | str | None = None) -> None:
    """Point the policy tools at a custom policy directory (testing / config)."""
    global _policy_dir, _engine
    _policy_dir = pathlib.Path(policy_dir) if policy_dir is not None else None
    _engine = None


def _get_engine() -> PolicyEngine:
    """Return (and lazily construct) the shared engine.

    Exported so the framework-mapping stream can share the loaded index:
        from compliance_mcp.tools.policy import _get_engine
    """
    global _engine
    if _engine is None:
        rules = load_corpus(_policy_dir)
        _engine = PolicyEngine.from_corpus(rules)
    return _engine


# ---------------------------------------------------------------------------
# Tool implementations — signatures match server-core stubs exactly
# ---------------------------------------------------------------------------


@mcp.tool()
async def query_policy(
    policy_id: str,
    locale: str | None = None,
) -> dict[str, Any]:
    """Retrieve the full text of a policy document by its identifier.

    Args:
        policy_id: Unique policy identifier, e.g. ``SEC-001``.
        locale: BCP-47 language tag; if supplied, the rule must either list
            this locale or have an empty locales list (universal).

    Returns:
        A dict with ``id``, ``domain``, ``topic``, ``severity``, ``controls``,
        ``locales``, and ``body`` keys, or ``{"error": ...}`` when not found.
    """
    engine = _get_engine()
    rule = engine.get_by_id(policy_id)

    if rule is None:
        return {"error": f"policy '{policy_id}' not found"}

    if locale is not None and rule.locales and locale not in rule.locales:
        return {"error": f"policy '{policy_id}' does not cover locale '{locale}'"}

    return _rule_to_dict(rule)


@mcp.tool()
async def list_policies(
    domain: str | None = None,
    lens: str | None = None,
    locale: str | None = None,
) -> list[dict[str, Any]]:
    """List all available policies, optionally filtered.

    Args:
        domain: Filter by policy domain (``security``, ``supply_chain``,
            ``license``, ``i18n``, ``policy``).
        lens: Ignored for now — policy docs are not scoped to a specific lens.
        locale: Filter to rules that cover this BCP-47 locale (or are universal).

    Returns:
        List of policy summary dicts (``id``, ``domain``, ``topic``, ``severity``,
        ``controls``, ``locales``).
    """
    engine = _get_engine()

    policy_domain: PolicyDomain | None = None
    if domain is not None:
        try:
            policy_domain = PolicyDomain(domain)
        except ValueError:
            valid = [d.value for d in PolicyDomain]
            return [{"error": f"unknown domain '{domain}'; valid values: {valid}"}]

    grouped = engine.list_all(domain=policy_domain, locale=locale)

    return [
        _rule_to_summary(rule)
        for rules in sorted(grouped.values(), key=lambda rs: rs[0].domain.value if rs else "")
        for rule in rules
    ]


def _rule_to_dict(rule: PolicyRule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "domain": rule.domain.value,
        "topic": rule.topic,
        "severity": rule.severity.value,
        "controls": rule.controls,
        "locales": rule.locales,
        "body": rule.body,
    }


def _rule_to_summary(rule: PolicyRule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "domain": rule.domain.value,
        "topic": rule.topic,
        "severity": rule.severity.value,
        "controls": rule.controls,
        "locales": rule.locales,
    }
