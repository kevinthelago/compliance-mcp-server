"""Markdown report renderer — Jinja2-based, deterministic ordering."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from compliance_mcp.models.finding import Domain, Finding, Severity

if TYPE_CHECKING:
    from compliance_mcp.gate.baseline import BaselineResult
    from compliance_mcp.gate.evaluator import GateResult

_TEMPLATES_DIR = Path(__file__).parent / "templates"

# Canonical severity order — most to least severe
_SEVERITY_ORDER: list[str] = [s.value for s in Severity]

# Canonical domain order for grouping
_DOMAIN_ORDER: list[str] = [d.value for d in Domain]

_SUPPORTED_FORMATS: frozenset[str] = frozenset(["markdown", "md"])


def render_report(
    findings: list[Finding],
    gate_result: GateResult,
    project_path: str = "",
    baseline_result: BaselineResult | None = None,
    output_path: Path | None = None,
    include_passed: bool = False,
    lenses_run: list[str] | None = None,
    lenses_skipped: list[str] | None = None,
) -> str:
    """
    Render a Markdown compliance report.

    Args:
        findings: All active (non-suppressed) findings from the scan.
        gate_result: The gate decision to summarise.
        project_path: The scanned project path (display only).
        baseline_result: Optional suppression summary (accepted + stale).
        output_path: If given, write the report to disk (UTF-8) in addition to
            returning it.
        include_passed: Include domains with zero findings.
        lenses_run: Names of lenses that ran successfully.
        lenses_skipped: Names of lenses that did not run or errored.

    Returns:
        Rendered Markdown string.
    """
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        undefined=StrictUndefined,
        autoescape=False,  # noqa: S701 — generating Markdown, not HTML
        keep_trailing_newline=True,
    )
    env.filters["sev_emoji"] = _sev_emoji
    env.filters["decision_badge"] = _decision_badge

    template = env.get_template("report.md.j2")

    # Group findings by domain → severity, deterministic sort within each bucket
    by_domain_sev: dict[str, dict[str, list[Finding]]] = {}
    for f in findings:
        by_domain_sev.setdefault(f.domain.value, {}).setdefault(f.severity.value, []).append(f)

    for dom in by_domain_sev:
        for sev in by_domain_sev[dom]:
            by_domain_sev[dom][sev].sort(key=lambda f: (f.file_path, f.line_start, f.rule_id))

    # Re-order by canonical domain + severity
    ordered: dict[str, dict[str, list[Finding]]] = {}
    for dom in _DOMAIN_ORDER:
        if dom in by_domain_sev:
            ordered[dom] = {
                sev: by_domain_sev[dom][sev] for sev in _SEVERITY_ORDER if sev in by_domain_sev[dom]
            }

    rendered = template.render(
        project_path=project_path,
        gate=gate_result,
        by_domain_sev=ordered,
        baseline=baseline_result,
        severity_order=_SEVERITY_ORDER,
        domain_order=_DOMAIN_ORDER,
        include_passed=include_passed,
        lenses_run=sorted(lenses_run or []),
        lenses_skipped=sorted(lenses_skipped or []),
    )

    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")

    return rendered


def render_report_json(
    findings: list[Finding],
    gate_result: GateResult,
    project_path: str = "",
    baseline_result: BaselineResult | None = None,
    include_passed: bool = False,
) -> str:
    """Render a structured JSON compliance report."""
    payload: dict[str, Any] = {
        "project_path": project_path,
        "gate": {
            "decision": gate_result.decision.value,
            "rationale": gate_result.rationale,
            "counts_by_severity": gate_result.counts_by_severity,
        },
        "findings": [
            {
                "fingerprint": f.fingerprint,
                "lens": f.lens.value,
                "domain": f.domain.value,
                "severity": f.severity.value,
                "rule_id": f.rule_id,
                "title": f.title,
                "file_path": f.file_path,
                "line_start": f.line_start,
                "line_end": f.line_end,
                "message": f.message,
                "suggestion": f.suggestion,
                "control_refs": f.control_refs,
            }
            for f in sorted(findings, key=lambda f: (f.severity.rank, f.file_path, f.line_start))
        ],
    }
    if baseline_result is not None:
        payload["baseline"] = {
            "suppressed_count": len(baseline_result.accepted),
            "stale_count": len(baseline_result.stale_entries),
        }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _sev_emoji(sev: str) -> str:
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(
        sev, "❓"
    )


def _decision_badge(decision: str) -> str:
    return {
        "pass": "✅ PASS",
        "block": "❌ BLOCK",
        "inconclusive": "⚠️ INCONCLUSIVE",
    }.get(decision, decision.upper())
