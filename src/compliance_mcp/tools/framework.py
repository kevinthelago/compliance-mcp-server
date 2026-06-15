"""MCP tool implementations for framework coverage — FM-3.

Registers ``control_coverage`` and ``explain_control`` on the FastMCP instance
imported from the server module, overriding the placeholder stubs.

Integration note
----------------
This module must be imported *after* ``compliance_mcp.server`` so that ``mcp``
is already constructed.  Add ``import compliance_mcp.tools.framework`` (or a
``discover_tools()`` call that covers it) in ``compliance_mcp/tools/__init__.py``
or in the server startup function.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from compliance_mcp.framework.coverage import (
    ControlCoverageError,
    compute_coverage,
    explain_control_entry,
    findings_to_coverage_format,
)
from compliance_mcp.framework.mapper import enrich_findings
from compliance_mcp.framework.mapping import SUPPORTED_FRAMEWORKS, ControlMapping, load_mapping
from compliance_mcp.models.finding import Finding
from compliance_mcp.server import mcp

logger = logging.getLogger(__name__)

# Module-level singleton — loaded once on first use
_mapping: ControlMapping | None = None


def _get_mapping() -> ControlMapping:
    global _mapping  # noqa: PLW0603
    if _mapping is None:
        _mapping = load_mapping()
    return _mapping


def _deserialize_findings(raw: Any) -> list[Finding]:  # noqa: ANN401
    """Convert a JSON-serializable findings list (from scan_project) to Finding objects."""
    if isinstance(raw, str):
        raw = json.loads(raw)
    if not isinstance(raw, list):
        raise ValueError(f"findings must be a JSON array, got {type(raw).__name__}")
    return [Finding.model_validate(item) for item in raw]


@mcp.tool()
async def control_coverage(  # type: ignore[misc]
    project_path: str,
    lens: str,
    findings_json: str | None = None,
) -> dict:
    """Report control coverage for a compliance framework.

    When *findings_json* is supplied it is used directly (the JSON array
    returned by ``scan_project``).  When omitted the tool returns a degraded
    result indicating that a scan result is required — the full scan-then-cover
    flow is implemented by the gate-reporting stream.

    Args:
        project_path: Path to the project being assessed (informational).
        lens: Compliance framework key: ``soc2``, ``iso27001``, ``hipaa``,
              ``pci_dss``, or ``gdpr``.
        findings_json: Optional JSON string — the ``findings`` array from
                       ``scan_project``.  When present, findings are enriched
                       with control refs and coverage is computed.

    Returns:
        ``{
            "framework": str,
            "controls": {
                "<control_id>": {
                    "status": "addressed" | "at_risk" | "no_evidence",
                    "title": str,
                    "findings_count": int,
                    "max_severity": str | None,
                }
            },
            "summary": {
                "addressed": int,
                "at_risk": int,
                "no_evidence": int,
                "total": int,
            }
        }``
        or an ``{"error": str, "supported_frameworks": [...]}`` dict when the
        framework is unknown.
    """
    framework = lens.lower()

    try:
        mapping = _get_mapping()
    except Exception as exc:
        logger.exception("Failed to load control mapping")
        return {"error": f"Failed to load control mapping: {exc}"}

    if framework not in SUPPORTED_FRAMEWORKS:
        return {
            "error": f"Unknown framework {framework!r}",
            "supported_frameworks": sorted(SUPPORTED_FRAMEWORKS),
        }

    if findings_json is None:
        logger.info("control_coverage called without findings_json for %s", project_path)
        return {
            "framework": framework,
            "degraded": True,
            "reason": (
                "No findings provided. Pass findings_json (the 'findings' array "
                "from scan_project) to compute coverage."
            ),
            "supported_frameworks": sorted(SUPPORTED_FRAMEWORKS),
        }

    try:
        raw_findings = _deserialize_findings(findings_json)
    except (ValueError, Exception) as exc:
        return {"error": f"Invalid findings_json: {exc}"}

    enriched = enrich_findings(raw_findings, mapping)
    result = compute_coverage(enriched, framework, mapping)
    result["project_path"] = project_path
    result["enriched_findings"] = findings_to_coverage_format(enriched)
    return result


@mcp.tool()
async def explain_control(  # type: ignore[misc]
    control_id: str,
    lens: str,
) -> dict:
    """Return the description and mapped policies for a single control.

    Args:
        control_id: Framework-scoped control identifier, e.g. ``CC6.1``
                    (SOC 2) or ``Art.5(1)(f)`` (GDPR).
        lens: Compliance framework key: ``soc2``, ``iso27001``, ``hipaa``,
              ``pci_dss``, or ``gdpr``.

    Returns:
        ``{
            "id": str,
            "framework": str,
            "title": str,
            "description": str,
            "mapped_policies": [str, ...],
            "mapped_rules": [str, ...],
        }``
        or ``{"error": str, "supported_frameworks": [...]}`` when the framework
        or control is unknown.
    """
    framework = lens.lower()

    try:
        mapping = _get_mapping()
    except Exception as exc:
        logger.exception("Failed to load control mapping")
        return {"error": f"Failed to load control mapping: {exc}"}

    try:
        return explain_control_entry(framework, control_id, mapping)
    except ControlCoverageError as exc:
        return {
            "error": str(exc),
            "supported_frameworks": sorted(SUPPORTED_FRAMEWORKS),
        }
