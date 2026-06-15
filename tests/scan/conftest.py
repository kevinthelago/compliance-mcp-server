"""Shared fixtures for the scan package tests."""

from __future__ import annotations

from pathlib import Path

from compliance_mcp.models.finding import Domain, Finding, Lens, Severity
from compliance_mcp.scan.lens import LensProtocol, LensResult


def make_finding(
    *,
    title: str = "Test finding",
    severity: Severity = Severity.MEDIUM,
    file_path: str = "src/foo.py",
    lens: Lens = Lens.GDPR,
    domain: Domain = Domain.DATA_PROTECTION,
    message: str = "",
) -> Finding:
    # Embed title in rule_id so distinct titles → distinct fingerprints.
    rule_id = f"test.{title.lower().replace(' ', '-')}"
    return Finding(
        lens=lens,
        domain=domain,
        rule_id=rule_id,
        file_path=file_path,
        line_start=10,
        severity=severity,
        title=title,
        message=message,
    )


class StubLens:
    """Configurable synchronous lens for use in tests."""

    def __init__(
        self,
        name: str = "stub",
        domain: Domain = Domain.DATA_PROTECTION,
        *,
        findings: list[Finding] | None = None,
        applicable: bool = True,
        raise_on_run: Exception | None = None,
        missing_binary: bool = False,
    ) -> None:
        self._name = name
        self._domain = domain
        self._findings = findings or []
        self._applicable = applicable
        self._raise_on_run = raise_on_run
        self._missing_binary = missing_binary

    @property
    def name(self) -> str:
        return self._name

    @property
    def domain(self) -> Domain:
        return self._domain

    def applicable(self, target: Path) -> bool:
        if self._missing_binary:
            return False
        return self._applicable

    def run(self, target: Path) -> LensResult:
        if self._raise_on_run is not None:
            raise self._raise_on_run
        return LensResult.ran(self._findings)


# Verify StubLens satisfies the protocol at import time.
assert isinstance(StubLens(), LensProtocol)
