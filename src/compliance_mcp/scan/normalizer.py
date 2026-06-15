"""Finding normalizer — deduplicate by fingerprint and rank by severity then file path."""
from __future__ import annotations

from compliance_mcp.models import Finding, Severity

# Severity ordering: lower value = higher priority in the ranked output.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def normalize_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate *findings* by fingerprint, then rank by severity then file path.

    When two findings share a fingerprint the first one encountered is kept
    (preserves lens-registration order for stable output).

    Ordering is deterministic for identical inputs.
    """
    seen: dict[str, Finding] = {}
    for finding in findings:
        if finding.fingerprint not in seen:
            seen[finding.fingerprint] = finding

    deduped = list(seen.values())
    deduped.sort(key=_sort_key)
    return deduped


def _sort_key(finding: Finding) -> tuple[int, str, str]:
    severity_rank = _SEVERITY_RANK.get(finding.severity, 99)
    file_key = finding.file_path or ""
    # tertiary: title for full determinism when severity + file_path match
    return (severity_rank, file_key, finding.title)
