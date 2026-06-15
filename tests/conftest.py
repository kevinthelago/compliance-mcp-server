"""Shared pytest fixtures."""

from __future__ import annotations

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
