"""FastMCP server entry point.

Registers all 8 compliance tools with stable signatures so downstream streams
can implement them without touching this file.  Tool *implementations* live under
`compliance_mcp/tools/`; each implementation module imports the server's `mcp`
instance via `from compliance_mcp.server import mcp`.

stdout is the MCP protocol stream — never write to it directly.  All diagnostic
output goes to stderr via `compliance_mcp.logging`.
"""

from __future__ import annotations

import sys

from fastmcp import FastMCP

from compliance_mcp.config import ComplianceSettings, load_settings
from compliance_mcp.logging import configure_logging, get_logger
from compliance_mcp.registry import discover_lenses

configure_logging()
logger = get_logger(__name__)

mcp: FastMCP = FastMCP("compliance-mcp-server")


# ---------------------------------------------------------------------------
# Tool stubs — stable signatures; implementations replace the body
# ---------------------------------------------------------------------------


@mcp.tool()
async def query_policy(
    policy_id: str,
    locale: str | None = None,
) -> dict:
    """Retrieve the full text of a policy document by its identifier.

    Args:
        policy_id: Unique policy identifier, e.g. ``gdpr.data-retention``.
        locale: BCP-47 language tag; defaults to the first required locale.

    Returns:
        A dict with ``id``, ``title``, ``body``, and ``locale`` keys.
    """
    raise NotImplementedError("query_policy not yet implemented — awaiting tools stream")


@mcp.tool()
async def list_policies(
    domain: str | None = None,
    lens: str | None = None,
    locale: str | None = None,
) -> list[dict]:
    """List all available policies, optionally filtered.

    Args:
        domain: Filter by :class:`~compliance_mcp.models.finding.Domain` value.
        lens: Filter by :class:`~compliance_mcp.models.finding.Lens` value.
        locale: Filter by locale code.

    Returns:
        List of policy summary dicts (``id``, ``title``, ``domain``, ``lens``).
    """
    raise NotImplementedError("list_policies not yet implemented — awaiting tools stream")


@mcp.tool()
async def scan_project(
    project_path: str,
    lenses: list[str] | None = None,
    severity_threshold: str | None = None,
) -> dict:
    """Run enabled compliance lenses against an entire project tree.

    Args:
        project_path: Absolute or workspace-relative path to scan.
        lenses: Subset of lenses to run; defaults to ``enabled_lenses`` from config.
        severity_threshold: Override the config threshold for this call.

    Returns:
        ``{"findings": [...], "summary": {"total": int, "by_severity": {...}}}``
    """
    raise NotImplementedError("scan_project not yet implemented — awaiting tools stream")


@mcp.tool()
async def scan_diff(
    diff: str,
    base_ref: str | None = None,
    lenses: list[str] | None = None,
) -> dict:
    """Run compliance lenses against a unified diff (pre-commit or CI gate).

    Args:
        diff: Unified diff text (output of ``git diff``).
        base_ref: Git ref the diff is against, for context.
        lenses: Subset of lenses to run; defaults to ``enabled_lenses``.

    Returns:
        ``{"findings": [...], "summary": {...}}``
    """
    raise NotImplementedError("scan_diff not yet implemented — awaiting tools stream")


@mcp.tool()
async def control_coverage(
    project_path: str,
    lens: str,
) -> dict:
    """Report which controls are satisfied and which are missing for a project.

    Args:
        project_path: Path to the project to assess.
        lens: The compliance framework to evaluate against.

    Returns:
        ``{"met": [...], "missing": [...], "coverage_pct": float}``
    """
    raise NotImplementedError("control_coverage not yet implemented — awaiting tools stream")


@mcp.tool()
async def explain_control(
    control_id: str,
    lens: str,
) -> dict:
    """Return the full text, rationale, and implementation guidance for a control.

    Args:
        control_id: Framework-scoped control identifier, e.g. ``soc2.CC6.1``.
        lens: The compliance framework the control belongs to.

    Returns:
        ``{"id": str, "title": str, "body": str, "guidance": str, "refs": [...]}``
    """
    raise NotImplementedError("explain_control not yet implemented — awaiting tools stream")


@mcp.tool()
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
    raise NotImplementedError("compliance_gate not yet implemented — awaiting tools stream")


@mcp.tool()
async def generate_report(
    project_path: str,
    output_format: str = "markdown",
    lenses: list[str] | None = None,
    include_passed: bool = False,
) -> dict:
    """Generate a compliance report for a project.

    Args:
        project_path: Path to assess.
        output_format: ``"markdown"`` or ``"json"``.
        lenses: Lenses to include; defaults to ``enabled_lenses``.
        include_passed: Include controls with no findings.

    Returns:
        ``{"format": str, "content": str}``
    """
    raise NotImplementedError("generate_report not yet implemented — awaiting tools stream")


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------


def _startup(settings: ComplianceSettings) -> None:
    logger.info("Compliance MCP Server starting up")
    logger.info("Corpus path: %s", settings.corpus_path)
    logger.info("Enabled lenses: %s", [lns.value for lns in settings.enabled_lenses])
    logger.info("Severity threshold: %s", settings.severity_threshold)
    discover_lenses()
    logger.info("Registered lenses: %s (of %s enabled)", 0, len(settings.enabled_lenses))


def main() -> None:
    try:
        settings = load_settings()
    except Exception as exc:
        print(f"[compliance-mcp] FATAL: invalid configuration — {exc}", file=sys.stderr)
        sys.exit(1)

    _startup(settings)
    mcp.run()


if __name__ == "__main__":
    main()
