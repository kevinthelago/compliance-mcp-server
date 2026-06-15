"""Semgrep adapter — SAST via SARIF output (SEC-2).

Runs ``semgrep --sarif --config <policy> <target>`` and parses the SARIF 2.1.0
report into :class:`~compliance_mcp.models.finding.Finding` objects.

Exit-code semantics
-------------------
Exit 0  → scan ran, no findings
Exit 1  → scan ran, findings present (both are RunStatus.FINDINGS / OK)
Exit 2+ → semgrep internal error → RunStatus.ERRORED
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from compliance_mcp.adapters.base import AdapterResult, RunStatus, run_subprocess
from compliance_mcp.models.finding import Domain, Finding, Lens, Severity

log = logging.getLogger(__name__)

# Semgrep levels → Severity
_SARIF_LEVEL_MAP: dict[str, Severity] = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.INFO,
    "none": Severity.INFO,
}

# Exit codes that indicate semgrep ran normally (with or without findings)
_SEMGREP_OK_CODES = frozenset({0, 1})


def _sarif_level_to_severity(level: str) -> Severity:
    return _SARIF_LEVEL_MAP.get(level.lower(), Severity.MEDIUM)


def parse_sarif(sarif_text: str, target: Path) -> list[Finding]:
    """Parse a SARIF 2.1.0 JSON string into a list of Findings.

    Returns an empty list on parse error or empty runs.
    """
    try:
        data = json.loads(sarif_text)
    except json.JSONDecodeError as exc:
        log.error("failed to parse semgrep SARIF output: %s", exc)
        return []

    findings: list[Finding] = []
    for run in data.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        rules: dict[str, dict] = {r["id"]: r for r in driver.get("rules", [])}

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            level = result.get("level", "warning")
            severity = _sarif_level_to_severity(level)

            # Message
            message = result.get("message", {}).get("text", "")

            # Rule metadata for title
            rule_meta = rules.get(rule_id, {})
            title = (
                rule_meta.get("name")
                or rule_meta.get("shortDescription", {}).get("text")
                or rule_id
            )

            # Location — SARIF requires at least one location for a finding
            locations = result.get("locations", [])
            if not locations:
                log.debug("skipping semgrep result without location: %s", rule_id)
                continue

            loc = locations[0]
            phys = loc.get("physicalLocation", {})
            artifact_uri = phys.get("artifactLocation", {}).get("uri", "")
            region = phys.get("region", {})
            line_start = max(1, region.get("startLine", 1))
            line_end = region.get("endLine")

            # Resolve URI against target for display; keep relative
            file_path = artifact_uri or str(target)

            findings.append(
                Finding(
                    lens=Lens.OWASP,
                    domain=Domain.VULNERABILITY,
                    rule_id=rule_id,
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end if line_end and line_end >= line_start else None,
                    severity=severity,
                    title=title,
                    message=message,
                )
            )

    return findings


def scan(
    target: Path,
    *,
    policies_dir: Path | None = None,
    timeout: int = 300,
) -> tuple[AdapterResult, list[Finding]]:
    """Run semgrep against *target* and return *(AdapterResult, findings)*.

    Parameters
    ----------
    target:
        Directory or file to scan.
    policies_dir:
        Optional extra ``--config`` directory for custom rules.
    timeout:
        Max seconds to wait for semgrep (default 300).
    """
    cmd = ["semgrep", "--sarif", "--config", "p/default"]
    if policies_dir and policies_dir.is_dir():
        cmd += ["--config", str(policies_dir)]
    cmd.append(str(target))

    result = run_subprocess(cmd, timeout=timeout, findings_exit_codes=frozenset({1}))

    if result.status == RunStatus.NOT_RUN:
        return result, []

    # Semgrep exit 2+ signals a fatal internal error
    if result.status == RunStatus.ERRORED:
        log.error("semgrep failed (rc=%d): %s", result.returncode, result.stderr[:200])
        return result, []

    findings = parse_sarif(result.stdout, target)
    return result, findings
