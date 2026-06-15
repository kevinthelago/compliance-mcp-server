"""Integration test fixtures."""

from __future__ import annotations

import pathlib

import pytest


@pytest.fixture(scope="session")
def sample_repo() -> pathlib.Path:
    return pathlib.Path(__file__).parent.parent / "fixtures" / "sample_repo"
