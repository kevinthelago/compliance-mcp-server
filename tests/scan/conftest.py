"""Shared test fixtures for the scan package."""
from __future__ import annotations

from pathlib import Path

from compliance_mcp.models import Domain, Finding, Lens, Severity
from compliance_mcp.scan.lens import LensProtocol, LensResult


def make_finding(
    *,
    title: str = "Test finding",
    severity: Severity = Severity.MEDIUM,
    file_path: str | None = "src/foo.py",
    source: str = "test",
    lens: Lens = Lens.SECURITY,
    domain: Domain = Domain.SECURITY,
    policy_id: str | None = None,
) -> Finding:
    return Finding(
        lens=lens,
        domain=domain,
        severity=severity,
        title=title,
        message=f"Message for {title}",
        file_path=file_path,
        source=source,
        policy_id=policy_id,
        fingerprint=Finding.make_fingerprint(
            lens=lens,
            domain=domain,
            file_path=file_path,
            location=None,
            policy_id=policy_id,
            title=title,
        ),
    )


class StubLens:
    """A stub lens that returns a fixed list of findings."""

    def __init__(
        self,
        name: str = "stub",
        domain: Domain = Domain.SECURITY,
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
