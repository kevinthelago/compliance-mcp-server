"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "supply_chain"


@pytest.fixture()
def supply_chain_fixtures() -> Path:
    return FIXTURES_DIR


@pytest.fixture()
def cyclonedx_fixture_json(supply_chain_fixtures: Path) -> str:
    return (supply_chain_fixtures / "cyclonedx_fixture.json").read_text()


@pytest.fixture()
def trivy_fixture_json(supply_chain_fixtures: Path) -> str:
    return (supply_chain_fixtures / "trivy_fixture.json").read_text()
