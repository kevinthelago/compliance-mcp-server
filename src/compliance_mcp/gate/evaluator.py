"""Gate evaluator — pass / block / inconclusive decision from a set of findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from compliance_mcp.models.finding import Finding, Severity


class GateDecision(StrEnum):
    PASS = "pass"  # noqa: S105
    BLOCK = "block"
    # No lenses ran — cannot assert compliance either way
    INCONCLUSIVE = "inconclusive"


@dataclass
class GateResult:
    decision: GateDecision
    rationale: str
    # Findings at or above the blocking threshold
    blocking_findings: list[Finding] = field(default_factory=list)
    # {severity_value: count} over ALL active findings
    counts_by_severity: dict[str, int] = field(default_factory=dict)
    # {domain_value: {severity_value: count}}
    counts_by_domain: dict[str, dict[str, int]] = field(default_factory=dict)


def evaluate(
    findings: list[Finding],
    block_threshold: Severity = Severity.MEDIUM,
    ran: bool = True,
) -> GateResult:
    """
    Evaluate a list of active (non-suppressed) findings.

    Args:
        findings: Active findings from the current scan (baseline-suppressed).
        block_threshold: Minimum severity that causes a block (inclusive, by rank).
            Defaults to MEDIUM (matches the default config ``severity_threshold``).
        ran: Whether at least one lens ran successfully. If False the result is
            INCONCLUSIVE regardless of findings.

    Returns:
        GateResult with decision, rationale, counts, and blocking findings list.
    """
    if not ran:
        return GateResult(
            decision=GateDecision.INCONCLUSIVE,
            rationale=(
                "No lenses ran successfully. "
                "Cannot determine compliance status — treating as inconclusive."
            ),
        )

    counts_severity: dict[str, int] = {s.value: 0 for s in Severity}
    counts_domain: dict[str, dict[str, int]] = {}
    blocking: list[Finding] = []

    for finding in findings:
        sev_val = finding.severity.value
        dom_val = finding.domain.value

        counts_severity[sev_val] = counts_severity.get(sev_val, 0) + 1

        if dom_val not in counts_domain:
            counts_domain[dom_val] = {s.value: 0 for s in Severity}
        counts_domain[dom_val][sev_val] = counts_domain[dom_val].get(sev_val, 0) + 1

        # Block when finding severity is >= threshold (by rank: higher rank = more severe)
        if finding.severity >= block_threshold:
            blocking.append(finding)

    if blocking:
        return GateResult(
            decision=GateDecision.BLOCK,
            rationale=(
                f"Gate blocked: {len(blocking)} finding(s) at or above "
                f"the {block_threshold.value!r} severity threshold."
            ),
            blocking_findings=blocking,
            counts_by_severity=counts_severity,
            counts_by_domain=counts_domain,
        )

    return GateResult(
        decision=GateDecision.PASS,
        rationale="All findings are below the blocking severity threshold.",
        counts_by_severity=counts_severity,
        counts_by_domain=counts_domain,
    )
