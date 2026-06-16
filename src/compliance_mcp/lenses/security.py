"""Security lens — composes Semgrep (SAST) and gitleaks (secrets) scanning (SEC-4).

Implements the :class:`~compliance_mcp.scan.lens.LensProtocol` from lens-protocol
contract. The lens registers itself at import time for auto-discovery.

Degradation model
-----------------
A missing binary degrades that sub-scanner only — the lens still runs and
returns whatever findings the available scanner(s) produced.  The lens never
raises; missing or errored sub-scanners are logged and skipped.
"""

from __future__ import annotations

import logging
from pathlib import Path

from compliance_mcp.adapters.base import RunStatus
from compliance_mcp.adapters.gitleaks import scan as gitleaks_scan
from compliance_mcp.adapters.semgrep import scan as semgrep_scan
from compliance_mcp.models.finding import Finding
from compliance_mcp.scan.lens import LensResult, LensStatus

log = logging.getLogger(__name__)

_POLICIES_DIR = Path(__file__).resolve().parents[3] / "policies" / "semgrep"


class SecurityLens:
    """Compliance security lens: runs Semgrep + gitleaks and aggregates findings."""

    name = "security"
    domain = "security"

    def applicable(self, target: Path) -> bool:
        """Always applicable — any project may have security issues."""
        return True

    def run(self, target: Path) -> LensResult:
        """Scan *target* with Semgrep and gitleaks; return aggregated LensResult.

        Never raises — missing or errored sub-scanners are degraded gracefully.
        """
        policies_dir = _POLICIES_DIR if _POLICIES_DIR.is_dir() else None
        findings: list[Finding] = []
        diagnostics_parts: list[str] = []
        ran_count = 0

        # --- Semgrep (SAST) ---
        try:
            semgrep_result, semgrep_findings = semgrep_scan(target, policies_dir=policies_dir)
            if semgrep_result.status == RunStatus.NOT_RUN:
                diagnostics_parts.append("semgrep binary not found — SAST scan skipped")
                log.warning("security lens: semgrep not found")
            elif semgrep_result.status == RunStatus.ERRORED:
                diagnostics_parts.append(f"semgrep failed: {semgrep_result.stderr[:100]}")
                log.error("security lens: semgrep error: %s", semgrep_result.stderr[:100])
            else:
                findings.extend(semgrep_findings)
                ran_count += 1
                log.info("security lens: semgrep found %d finding(s)", len(semgrep_findings))
        except Exception as exc:
            diagnostics_parts.append(f"semgrep adapter error: {exc}")
            log.exception("security lens: semgrep adapter raised unexpectedly")

        # --- gitleaks (secrets) ---
        try:
            gl_result, gl_findings = gitleaks_scan(target)
            if gl_result.status == RunStatus.NOT_RUN:
                diagnostics_parts.append("gitleaks binary not found — secrets scan skipped")
                log.warning("security lens: gitleaks not found")
            elif gl_result.status == RunStatus.ERRORED:
                diagnostics_parts.append(f"gitleaks failed: {gl_result.stderr[:100]}")
                log.error("security lens: gitleaks error: %s", gl_result.stderr[:100])
            else:
                findings.extend(gl_findings)
                ran_count += 1
                log.info("security lens: gitleaks found %d finding(s)", len(gl_findings))
        except Exception as exc:
            diagnostics_parts.append(f"gitleaks adapter error: {exc}")
            log.exception("security lens: gitleaks adapter raised unexpectedly")

        status = LensStatus.NOT_RUN if ran_count == 0 and diagnostics_parts else LensStatus.RAN

        return LensResult(
            status=status,
            findings=findings,
            diagnostics="; ".join(diagnostics_parts) if diagnostics_parts else None,
        )
