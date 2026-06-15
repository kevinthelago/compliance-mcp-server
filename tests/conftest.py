"""Shared pytest fixtures."""

from __future__ import annotations

import pathlib

import pytest

from compliance_mcp.models.finding import Domain, Finding, Lens, Severity


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
def policy_dir() -> pathlib.Path:
    """Return the path to the real policy corpus."""
    return pathlib.Path(__file__).parent.parent / "policies"


@pytest.fixture()
def tmp_policy_dir(tmp_path: pathlib.Path) -> pathlib.Path:
    """Return a temporary directory for synthetic policy files."""
    return tmp_path / "policies"
