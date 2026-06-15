"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from compliance_mcp.models.finding import Domain, Finding, Lens, Severity

_FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def minimal_finding() -> Finding:
    return Finding(
        lens=Lens.GDPR,
        domain=Domain.DATA_PROTECTION,
        rule_id="gdpr.data-retention",
        file_path="src/db/user_repo.py",
        line_start=42,
        severity=Severity.HIGH,
        title="Unlimited data retention",
    )


@pytest.fixture()
def supply_chain_fixtures() -> Path:
    return _FIXTURES / "supply_chain"


@pytest.fixture()
def cyclonedx_fixture_json(supply_chain_fixtures: Path) -> str:
    return (supply_chain_fixtures / "cyclonedx_fixture.json").read_text()


@pytest.fixture()
def trivy_fixture_json(supply_chain_fixtures: Path) -> str:
    return (supply_chain_fixtures / "trivy_fixture.json").read_text()


@pytest.fixture
def compliant_repo() -> Path:
    """Path to a fixture repo that satisfies all core rules."""
    return _FIXTURES / "policy_as_code" / "compliant_repo"


@pytest.fixture
def noncompliant_repo() -> Path:
    """Path to a fixture repo that violates several core rules."""
    return _FIXTURES / "policy_as_code" / "noncompliant_repo"


@pytest.fixture
def rules_dir() -> Path:
    """Path to the project's starter ruleset."""
    return Path(__file__).parent.parent / "policies" / "rules"
