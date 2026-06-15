"""Lens Protocol and LensResult — the contract all scanner lenses implement (SO-1)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Protocol, runtime_checkable

from compliance_mcp.models.finding import Finding


class LensStatus(StrEnum):
    RAN = "ran"
    NOT_RUN = "not_run"
    ERRORED = "errored"


@dataclass
class LensResult:
    """Result produced by a single lens run."""

    status: LensStatus
    findings: list[Finding] = field(default_factory=list)
    diagnostics: str | None = None

    @classmethod
    def ran(cls, findings: list[Finding]) -> LensResult:
        return cls(status=LensStatus.RAN, findings=findings)

    @classmethod
    def not_run(cls, reason: str = "") -> LensResult:
        return cls(status=LensStatus.NOT_RUN, diagnostics=reason or None)

    @classmethod
    def errored(cls, reason: str) -> LensResult:
        return cls(status=LensStatus.ERRORED, diagnostics=reason)


@runtime_checkable
class LensProtocol(Protocol):
    """Duck-typed protocol every scanner lens satisfies."""

    @property
    def name(self) -> str: ...

    @property
    def domain(self) -> str: ...

    def applicable(self, target: Path) -> bool: ...

    def run(self, target: Path) -> LensResult: ...
