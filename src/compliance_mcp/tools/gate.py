"""Implementations of the compliance_gate and generate_report MCP tools.

The server registers these two tool *stubs* in server.py; this module replaces
those stub bodies by monkey-patching the registered handlers on import.

Import side-effect: calling ``register()`` wires the real implementations into
the FastMCP instance the server already created — no server.py edits needed.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from compliance_mcp.config import ComplianceSettings, load_settings
from compliance_mcp.gate.baseline import load_baseline, suppress
from compliance_mcp.gate.evaluator import GateDecision, evaluate
from compliance_mcp.models.finding import Finding, Lens, Severity
from compliance_mcp.registry import get_lens

log = logging.getLogger(__name__)

_SUPPORTED_REPORT_FORMATS: frozenset[str] = frozenset(["markdown", "md", "json"])


async def _run_scan(
    project_path: str,
    lenses: list[str] | None,
    settings: ComplianceSettings,
) -> tuple[list[Finding], list[str], list[str]]:
    """
    Run registered lenses against *project_path*.

    Returns:
        (findings, ran_lens_names, skipped_lens_names)
    """
    enabled: list[Lens]
    if lenses is not None:
        try:
            enabled = [Lens(name) for name in lenses]
        except ValueError as exc:
            raise ValueError(f"Unknown lens: {exc}") from exc
    else:
        enabled = list(settings.enabled_lenses)

    ran: list[str] = []
    skipped: list[str] = []
    all_findings: list[Finding] = []

    async def _one(lens_key: Lens) -> None:
        runner = get_lens(lens_key)
        if runner is None:
            skipped.append(lens_key.value)
            return
        try:
            results = await asyncio.wait_for(
                runner(project_path, settings),
                timeout=float(settings.lens_timeout_seconds),
            )
            all_findings.extend(results)
            ran.append(lens_key.value)
        except TimeoutError:
            log.warning("Lens %s timed out after %ss", lens_key, settings.lens_timeout_seconds)
            skipped.append(lens_key.value)
        except Exception:
            log.exception("Lens %s raised an exception", lens_key)
            skipped.append(lens_key.value)

    # Cap concurrency
    sem = asyncio.Semaphore(settings.concurrency_cap)

    async def _bounded(key: Lens) -> None:
        async with sem:
            await _one(key)

    await asyncio.gather(*[_bounded(k) for k in enabled])
    return all_findings, ran, skipped


async def compliance_gate(
    project_path: str,
    lenses: list[str] | None = None,
    severity_threshold: str | None = None,
    baseline_file: str | None = None,
) -> dict:
    """Assert that all findings are within configured thresholds.

    Suitable for CI gates; returns a non-zero exit when the assertion fails
    (callers should raise on ``passed == False``).

    Args:
        project_path: Path to assess.
        lenses: Lenses to run; defaults to ``enabled_lenses``.
        severity_threshold: Override for this assertion.
        baseline_file: Path to a baseline JSON of known/accepted fingerprints.

    Returns:
        ``{"passed": bool, "new_findings": [...], "suppressed": int}``
    """
    settings = load_settings()

    # Resolve severity threshold
    threshold = (
        Severity(severity_threshold) if severity_threshold else settings.severity_threshold
    )

    # Run scan
    all_findings, ran, skipped = await _run_scan(project_path, lenses, settings)

    # Baseline suppression
    baseline_path = Path(baseline_file) if baseline_file else None
    entries = load_baseline(baseline_path)
    baseline_result = suppress(all_findings, entries)
    suppressed_count = len(baseline_result.accepted)

    # Gate evaluation — only active findings go through the gate
    gate_result = evaluate(
        baseline_result.active,
        block_threshold=threshold,
        ran=bool(ran),
    )

    # Serialise new (blocking) findings for the response
    new_findings = [
        {
            "fingerprint": f.fingerprint,
            "lens": f.lens.value,
            "domain": f.domain.value,
            "severity": f.severity.value,
            "rule_id": f.rule_id,
            "title": f.title,
            "file_path": f.file_path,
            "line_start": f.line_start,
        }
        for f in gate_result.blocking_findings
    ]

    return {
        "passed": gate_result.decision == GateDecision.PASS,
        "decision": gate_result.decision.value,
        "rationale": gate_result.rationale,
        "new_findings": new_findings,
        "suppressed": suppressed_count,
        "counts_by_severity": gate_result.counts_by_severity,
    }


async def generate_report(
    project_path: str,
    output_format: str = "markdown",
    lenses: list[str] | None = None,
    include_passed: bool = False,
) -> dict:
    """Generate a compliance report for a project.

    Args:
        project_path: Path to assess.
        output_format: ``"markdown"`` / ``"md"`` or ``"json"``.
        lenses: Lenses to include; defaults to ``enabled_lenses``.
        include_passed: Include domains with no findings.

    Returns:
        ``{"format": str, "content": str}``

    Raises:
        ValueError: If *output_format* is not supported.
    """
    from compliance_mcp.report.renderer import render_report, render_report_json

    fmt = output_format.lower().strip()
    if fmt not in _SUPPORTED_REPORT_FORMATS:
        supported = ", ".join(sorted(_SUPPORTED_REPORT_FORMATS))
        raise ValueError(
            f"Unsupported report format {output_format!r}. Supported formats: {supported}"
        )

    settings = load_settings()
    all_findings, ran, skipped = await _run_scan(project_path, lenses, settings)

    # Apply the severity threshold to hide noise below the configured floor
    threshold = settings.severity_threshold
    displayed = [f for f in all_findings if f.severity >= threshold]

    gate_result = evaluate(displayed, block_threshold=threshold, ran=bool(ran))

    if fmt in ("markdown", "md"):
        content = render_report(
            findings=displayed,
            gate_result=gate_result,
            project_path=project_path,
            include_passed=include_passed,
            lenses_run=ran,
            lenses_skipped=skipped,
        )
        return {"format": "markdown", "content": content}

    # JSON
    content = render_report_json(
        findings=displayed,
        gate_result=gate_result,
        project_path=project_path,
        include_passed=include_passed,
    )
    return {"format": "json", "content": content}
