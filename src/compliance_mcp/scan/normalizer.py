"""Finding normalizer — deduplication and severity-ranked ordering (SO-3)."""

from __future__ import annotations

from compliance_mcp.models.finding import Finding


def normalize_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate by fingerprint (first occurrence wins) and sort by severity desc."""
    seen: dict[str, Finding] = {}
    for f in findings:
        if f.fingerprint not in seen:
            seen[f.fingerprint] = f

    return sorted(seen.values(), key=_sort_key)


def _sort_key(f: Finding) -> tuple[int, str, str]:
    return (-f.severity.rank, f.file_path, f.title)
