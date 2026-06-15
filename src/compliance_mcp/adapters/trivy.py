"""Trivy adapter — CVE findings from filesystem scan (SUP-2).

Runs ``trivy fs --format json --quiet <target>`` and maps each vulnerability to a
:class:`~compliance_mcp.models.finding.Finding`.

Offline / stale-DB handling
----------------------------
When Trivy cannot update its vulnerability database (exit code 1 with a
``--skip-db-update`` retry succeeds), the scan continues with the cached DB and
the returned :class:`~compliance_mcp.adapters.base.AdapterResult` is marked
``degraded=True``.

Finding field mapping
---------------------
======================  =========================================================
Finding field           Source
======================  =========================================================
``rule_id``             ``"cve.{VulnerabilityID}"``
``file_path``           Result ``Target`` (the manifest file, e.g. requirements.txt)
``line_start``          Always 1 (manifests have no meaningful line for a package)
``severity``            CVSS V3 score via :func:`cvss_to_severity`, or native label
``title``               ``"{CVE_ID}: {Title}"``
``message``             ``Description``
``suggestion``          ``"Upgrade to {FixedVersion}"`` (or "No fix available")
``control_refs``        Empty (enriched later by the framework mapper)
======================  =========================================================
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from compliance_mcp.adapters.base import (
    AdapterResult,
    RunStatus,
    cvss_to_severity,
    native_to_severity,
    run_subprocess,
)
from compliance_mcp.models.finding import Domain, Finding, Lens, Severity

log = logging.getLogger(__name__)

# Trivy exits 1 when it finds vulnerabilities, 2+ for fatal errors
_TRIVY_FINDINGS_CODES = frozenset({1})

# Pattern that appears in stderr when the DB update fails
_DB_UPDATE_FAIL = "db update error"


def _parse_trivy_json(raw_json: str, target: str) -> list[Finding]:
    """Parse Trivy JSON report into a list of :class:`Finding` objects."""
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        log.error("failed to parse Trivy JSON output: %s", exc)
        return []

    findings: list[Finding] = []
    for result in data.get("Results", []):
        file_path = result.get("Target", target)
        for vuln in result.get("Vulnerabilities") or []:
            cve_id = vuln.get("VulnerabilityID", "UNKNOWN")
            pkg_name = vuln.get("PkgName", "unknown")
            installed = vuln.get("InstalledVersion", "")
            fixed = vuln.get("FixedVersion", "")
            native_sev = vuln.get("Severity", "UNKNOWN")
            title_text = vuln.get("Title", cve_id)
            description = vuln.get("Description", "")
            primary_url = vuln.get("PrimaryURL", "")

            # Prefer CVSS v3 score for severity; fall back to native label
            cvss_score: float | None = None
            for source_data in vuln.get("CVSS", {}).values():
                score = source_data.get("V3Score")
                if isinstance(score, (int, float)) and (cvss_score is None or score > cvss_score):
                    cvss_score = float(score)

            severity: Severity = (
                cvss_to_severity(cvss_score) if cvss_score is not None
                else native_to_severity(native_sev)
            )

            suggestion = f"Upgrade to {fixed}" if fixed else "No fix available yet."

            msg_parts = [description]
            if primary_url:
                msg_parts.append(f"See: {primary_url}")
            message = "  ".join(p for p in msg_parts if p)

            findings.append(
                Finding(
                    lens=Lens.CUSTOM,
                    domain=Domain.SUPPLY_CHAIN,
                    rule_id=f"cve.{cve_id}",
                    file_path=file_path,
                    line_start=1,
                    severity=severity,
                    title=f"{cve_id}: {title_text} ({pkg_name}@{installed})",
                    message=message,
                    suggestion=suggestion,
                )
            )
    return findings


class TrivyAdapter:
    """Wraps Trivy filesystem scan and maps output to Findings.

    Parameters
    ----------
    timeout:
        Max seconds to wait for Trivy (default 120).
    """

    def __init__(self, *, timeout: int = 120) -> None:
        self._timeout = timeout

    def _build_cmd(self, target: Path, *, skip_db_update: bool = False) -> list[str]:
        cmd = [
            "trivy",
            "fs",
            "--format", "json",
            "--quiet",
        ]
        if skip_db_update:
            cmd.append("--skip-db-update")
        cmd.append(str(target))
        return cmd

    def run(self, target: Path) -> tuple[AdapterResult, list[Finding]]:
        """Run Trivy against *target* and return *(AdapterResult, findings)*.

        On offline/stale-DB failure, retries with ``--skip-db-update`` and
        marks the result degraded.
        """
        result = run_subprocess(
            self._build_cmd(target),
            timeout=self._timeout,
            findings_exit_codes=_TRIVY_FINDINGS_CODES,
        )

        if result.status == RunStatus.NOT_RUN:
            return result, []

        # Detect offline DB failure and retry with cached DB
        if result.status == RunStatus.ERRORED and _DB_UPDATE_FAIL in result.stderr.lower():
            log.warning("Trivy DB update failed; retrying with --skip-db-update (degraded)")
            retry = run_subprocess(
                self._build_cmd(target, skip_db_update=True),
                timeout=self._timeout,
                findings_exit_codes=_TRIVY_FINDINGS_CODES,
            )
            retry.degraded = True
            retry.degraded_reason = "vulnerability DB is stale; could not reach update server"
            result = retry

        if result.status == RunStatus.ERRORED:
            log.error("Trivy failed (rc=%d): %s", result.returncode, result.stderr[:200])
            return result, []

        findings = _parse_trivy_json(result.stdout, str(target))
        return result, findings
