"""gitleaks adapter — secret scanning via JSON output (SEC-3).

Runs ``gitleaks detect --source <target> -f json`` and parses findings into
:class:`~compliance_mcp.models.finding.Finding` objects.

Exit-code semantics
-------------------
Exit 0  → scan ran, no secrets found → RunStatus.OK
Exit 1  → scan ran, secrets found → RunStatus.FINDINGS
Exit 2+ → gitleaks internal error → RunStatus.ERRORED
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from compliance_mcp.adapters.base import AdapterResult, RunStatus, run_subprocess
from compliance_mcp.models.finding import Domain, Finding, Lens, Severity

log = logging.getLogger(__name__)

_GITLEAKS_FINDINGS_CODES = frozenset({1})


def parse_json(json_text: str) -> list[Finding]:
    """Parse gitleaks JSON output into a list of Findings.

    Returns an empty list on parse error or empty results.
    """
    try:
        items = json.loads(json_text)
    except json.JSONDecodeError as exc:
        log.error("failed to parse gitleaks JSON output: %s", exc)
        return []

    if not isinstance(items, list):
        return []

    findings: list[Finding] = []
    for item in items:
        rule_id_raw = item.get("RuleID") or item.get("ruleID") or item.get("rule_id")
        if not rule_id_raw:
            log.debug("skipping gitleaks item without RuleID: %s", item)
            continue

        description = item.get("Description") or item.get("description") or rule_id_raw
        file_path = item.get("File") or item.get("file") or ""
        line_start = max(1, item.get("StartLine") or item.get("start_line") or 1)
        line_end_raw = item.get("EndLine") or item.get("end_line")
        line_end = int(line_end_raw) if line_end_raw and int(line_end_raw) >= line_start else None
        secret_match = item.get("Secret") or item.get("secret") or ""

        message = description
        if secret_match:
            # Redact the actual secret value — show only the rule and context
            message = f"{description} (match redacted for security)"

        findings.append(
            Finding(
                lens=Lens.CUSTOM,
                domain=Domain.DATA_PROTECTION,
                rule_id=f"gitleaks.{rule_id_raw}",
                file_path=file_path or "unknown",
                line_start=line_start,
                line_end=line_end,
                severity=Severity.CRITICAL,
                title=f"Secret detected: {description}",
                message=message,
                suggestion="Remove the secret from source code and rotate the credential.",
            )
        )

    return findings


def scan(
    target: Path,
    *,
    timeout: int = 120,
) -> tuple[AdapterResult, list[Finding]]:
    """Run gitleaks against *target* and return *(AdapterResult, findings)*.

    Parameters
    ----------
    target:
        Directory to scan for leaked secrets.
    timeout:
        Max seconds to wait for gitleaks (default 120).
    """
    cmd = [
        "gitleaks",
        "detect",
        "--source",
        str(target),
        "-f",
        "json",
        "--no-banner",
        "--exit-code",
        "1",
    ]

    result = run_subprocess(cmd, timeout=timeout, findings_exit_codes=_GITLEAKS_FINDINGS_CODES)

    if result.status == RunStatus.NOT_RUN:
        return result, []

    if result.status == RunStatus.ERRORED:
        log.error("gitleaks failed (rc=%d): %s", result.returncode, result.stderr[:200])
        return result, []

    # exit 0 → no secrets; exit 1 → secrets found (both are successful scans)
    findings = parse_json(result.stdout)
    return result, findings
