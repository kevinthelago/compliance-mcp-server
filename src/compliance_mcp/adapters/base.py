"""Shared subprocess adapter base (SEC-1).

Centralises subprocess execution with timeout, exit-code interpretation, and
stdout/stderr capture.  All scanner adapters call `run_subprocess` rather than
shelling out directly.

Exit-code semantics
-------------------
Exit 0            → OK (ran, no findings or tool-specific success)
Exit 1 (default)  → FINDINGS (ran and found issues — most scanners use this)
Binary absent     → NOT_RUN (shutil.which returns None before launch)
OSError / timeout → ERRORED (launch failure or runaway process)

Adapters may override the `findings_exit_codes` set to widen the FINDINGS range
(e.g. Trivy uses 1 for "vulns found" but 2+ for fatal errors).
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from enum import StrEnum

from compliance_mcp.models.finding import Severity


class RunStatus(StrEnum):
    OK = "ok"
    FINDINGS = "findings"
    NOT_RUN = "not_run"
    ERRORED = "errored"


@dataclass
class AdapterResult:
    """Raw result from a subprocess invocation."""

    status: RunStatus
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    degraded: bool = False
    degraded_reason: str = ""


def run_subprocess(
    cmd: list[str],
    *,
    timeout: int = 60,
    cwd: str | None = None,
    findings_exit_codes: frozenset[int] = frozenset({1}),
) -> AdapterResult:
    """Run *cmd* and return an :class:`AdapterResult`.

    The first element of *cmd* is the binary name; if ``shutil.which`` cannot
    locate it the call returns NOT_RUN immediately without launching a process.
    """
    binary = cmd[0]
    if not shutil.which(binary):
        return AdapterResult(status=RunStatus.NOT_RUN)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
    except subprocess.TimeoutExpired:
        return AdapterResult(status=RunStatus.ERRORED, stderr=f"timeout after {timeout}s")
    except OSError as exc:
        return AdapterResult(status=RunStatus.ERRORED, stderr=str(exc))

    if proc.returncode == 0:
        status = RunStatus.OK
    elif proc.returncode in findings_exit_codes:
        status = RunStatus.FINDINGS
    else:
        status = RunStatus.ERRORED

    return AdapterResult(
        status=status,
        stdout=proc.stdout,
        stderr=proc.stderr,
        returncode=proc.returncode,
    )


# ── Severity helpers ──────────────────────────────────────────────────────────

_CVSS_SEVERITY: list[tuple[float, Severity]] = [
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
]


def cvss_to_severity(score: float) -> Severity:
    """Map a CVSS v3 score to a :class:`Severity` value."""
    for threshold, sev in _CVSS_SEVERITY:
        if score >= threshold:
            return sev
    return Severity.INFO


_NATIVE_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
    "negligible": Severity.INFO,
}


def native_to_severity(native: str) -> Severity:
    """Map a scanner's native severity label to a :class:`Severity` value."""
    return _NATIVE_MAP.get(native.lower(), Severity.INFO)
