"""Stub types for server-core Finding/ScanContext/Lens — replaced at integration time."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Protocol, runtime_checkable

try:
    from compliance_mcp.lenses import Lens  # type: ignore[import]
    from compliance_mcp.models import Finding, ScanContext, Severity  # type: ignore[import]
except ImportError:

    class Severity(StrEnum):  # type: ignore[no-redef]
        ERROR = "error"
        WARNING = "warning"
        INFO = "info"

    @dataclass
    class Finding:  # type: ignore[no-redef]
        rule_id: str
        path: str
        line: int
        col: int = 0
        severity: Severity = Severity.WARNING
        message: str = ""
        detail: str = ""
        suggestion: str = ""
        extra: dict = field(default_factory=dict)

    @dataclass
    class ScanContext:  # type: ignore[no-redef]
        root: Path
        files: list[Path]
        config: dict = field(default_factory=dict)

    @runtime_checkable
    class Lens(Protocol):  # type: ignore[no-redef]
        name: str

        def run(self, ctx: ScanContext) -> list[Finding]:
            ...


__all__ = ["Finding", "Lens", "ScanContext", "Severity"]
