"""Shared pytest fixtures for policy-as-code tests."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "policy_as_code"


@pytest.fixture
def compliant_repo() -> Path:
    """Path to a fixture repo that satisfies all core rules."""
    return FIXTURES_DIR / "compliant_repo"


@pytest.fixture
def noncompliant_repo() -> Path:
    """Path to a fixture repo that violates several core rules."""
    return FIXTURES_DIR / "noncompliant_repo"


@pytest.fixture
def rules_dir() -> Path:
    """Path to the project's starter ruleset."""
    return Path(__file__).parent.parent / "policies" / "rules"
