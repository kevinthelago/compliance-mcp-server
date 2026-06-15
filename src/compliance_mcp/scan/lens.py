"""Lens protocol contract — all lens implementations must satisfy this interface.

Five lens streams build against this; any change must be coordinated with the director.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

from compliance_mcp.models import Domain, Finding


class LensStatus(enum.StrEnum):
    """Outcome of a single lens run."""

    RAN = "ran"
    NOT_RUN = "not-run"      # binary absent; never launched
    ERRORED = "errored"      # launched but raised or timed out


@dataclass
class LensResult:
    """Result produced by one lens."""

    status: LensStatus
    findings: list[Finding] = field(default_factory=list)
    # Human-readable context for NOT_RUN or ERRORED; None when RAN.
    diagnostics: str | None = None

    @classmethod
    def ran(cls, findings: list[Finding]) -> LensResult:
        return cls(status=LensStatus.RAN, findings=findings)

    @classmethod
    def not_run(cls, reason: str) -> LensResult:
        return cls(status=LensStatus.NOT_RUN, diagnostics=reason)

    @classmethod
    def errored(cls, reason: str) -> LensResult:
        return cls(status=LensStatus.ERRORED, diagnostics=reason)


@runtime_checkable
class LensProtocol(Protocol):
    """Structural protocol every lens must satisfy.

    Lens implementations live under src/compliance_mcp/lenses/ and self-register
    via the registry decorator at import time.
    """

    @property
    def name(self) -> str:
        """Unique, stable identifier used in run summaries and config."""
        ...

    @property
    def domain(self) -> Domain:
        """Primary domain this lens covers (maps to Finding.domain)."""
        ...

    def applicable(self, target: Path) -> bool:
        """Return True if this lens should run against *target*.

        May check for config flags, binary presence, or file patterns.
        A lens returning False is recorded as NOT_RUN, not ERRORED.
        """
        ...

    def run(self, target: Path) -> LensResult:
        """Execute the lens against *target* and return findings.

        Must not raise — catch all exceptions and return LensResult.errored().
        Timeout enforcement is the orchestrator's responsibility.
        """
        ...
