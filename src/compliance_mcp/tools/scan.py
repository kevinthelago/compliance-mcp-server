"""scan_project and scan_diff MCP tool implementations."""
from __future__ import annotations

import logging
from pathlib import Path

from compliance_mcp.config import get_config
from compliance_mcp.models import Finding
from compliance_mcp.registry import get_lenses
from compliance_mcp.scan.diff import DiffResolutionError, resolve_diff_target
from compliance_mcp.scan.normalizer import normalize_findings
from compliance_mcp.scan.orchestrator import LensRunRecord, ScanOrchestrator, ScanSummary

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Response shapes (plain dicts; serialised by FastMCP as JSON)
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _finding_to_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "lens": f.lens.value,
        "domain": f.domain.value,
        "severity": f.severity.value,
        "title": f.title,
        "message": f.message,
        "file_path": f.file_path,
        "location": (
            {"line": f.location.line, "col": f.location.col} if f.location else None
        ),
        "policy_id": f.policy_id,
        "controls": f.controls,
        "remediation": f.remediation,
        "source": f.source,
        "fingerprint": f.fingerprint,
    }


def _record_to_dict(r: LensRunRecord) -> dict:
    return {
        "lens": r.name,
        "status": r.status.value,
        "finding_count": r.finding_count,
        "diagnostics": r.diagnostics,
    }


def _build_response(summary: ScanSummary, normalized: list[Finding]) -> dict:
    return {
        "findings": [_finding_to_dict(f) for f in normalized],
        "run_summary": {
            "total_findings": len(normalized),
            "lenses_ran": summary.ran_count,
            "lenses_not_run": summary.not_run_count,
            "lenses_errored": summary.errored_count,
            "lens_details": [_record_to_dict(r) for r in summary.lens_records],
        },
    }


# ---------------------------------------------------------------------------
# Validation helper
# ---------------------------------------------------------------------------

def _validate_project_path(path: str) -> tuple[Path | None, dict | None]:
    """Return (resolved_path, None) or (None, error_dict)."""
    p = Path(path)
    if not p.exists():
        return None, {
            "error": "path_not_found",
            "detail": f"Path does not exist: {path}",
        }
    if not p.is_dir():
        return None, {
            "error": "path_not_directory",
            "detail": f"Path is not a directory: {path}",
        }
    return p.resolve(), None


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def scan_project(path: str, lenses: list[str] | None = None) -> dict:
    """Run all enabled lenses against a project directory.

    Args:
        path: Absolute or relative path to the project root.
        lenses: Optional list of lens names to restrict the run to.
                If omitted, all applicable registered lenses run.

    Returns:
        A dict with ``findings`` (normalised, ranked) and ``run_summary``.
    """
    project_path, err = _validate_project_path(path)
    if err:
        return err

    cfg = get_config()
    all_lenses = get_lenses()
    if lenses is not None:
        requested = set(lenses)
        all_lenses = [lens for lens in all_lenses if lens.name in requested]

    orc = ScanOrchestrator(
        all_lenses,
        concurrency=cfg.concurrency,
        timeout=cfg.lens_timeout,
    )
    summary = orc.run(project_path)  # type: ignore[arg-type]
    normalized = normalize_findings(summary.findings)
    return _build_response(summary, normalized)


def scan_diff(
    path: str,
    base_ref: str | None = None,
    changed_paths: list[str] | None = None,
) -> dict:
    """Scan only files changed relative to a base git ref or an explicit file list.

    Args:
        path: Absolute or relative path to the project root (must be a git repo
              when *base_ref* is used).
        base_ref: Git ref (branch, tag, SHA) to diff against. If supplied, *path*
                  must be inside a git repository.
        changed_paths: Explicit list of file paths relative to *path* to scan.
                       Takes priority over *base_ref*.

    Returns:
        A dict with ``findings`` and ``run_summary``, same shape as scan_project.
    """
    project_path, err = _validate_project_path(path)
    if err:
        return err

    try:
        diff_files = resolve_diff_target(
            project_path,  # type: ignore[arg-type]
            base_ref=base_ref,
            changed_paths=changed_paths,
        )
    except DiffResolutionError as exc:
        return {"error": "diff_resolution_failed", "detail": str(exc)}

    if not diff_files and (base_ref is not None or changed_paths is not None):
        return {
            "findings": [],
            "run_summary": {
                "total_findings": 0,
                "lenses_ran": 0,
                "lenses_not_run": 0,
                "lenses_errored": 0,
                "lens_details": [],
                "note": "no changed files detected",
            },
        }

    cfg = get_config()
    all_lenses = get_lenses()

    # When we have specific diff files, run each lens against the project root
    # but the lenses' applicable() check still gates whether they run.
    # Lenses that support file-level filtering should inspect diff_files internally;
    # for now we pass the project root so all lenses can run and we filter results.
    scan_target = project_path

    orc = ScanOrchestrator(
        all_lenses,
        concurrency=cfg.concurrency,
        timeout=cfg.lens_timeout,
    )
    summary = orc.run(scan_target)  # type: ignore[arg-type]

    # Filter findings to changed files only.
    diff_strs = {str(p) for p in diff_files}
    diff_rels = {p.relative_to(project_path).as_posix() for p in diff_files}  # type: ignore[union-attr]

    filtered = [
        f for f in summary.findings
        if f.file_path is None
        or f.file_path in diff_strs
        or f.file_path in diff_rels
        or (project_path / f.file_path).resolve() in diff_files  # type: ignore[operator]
    ]

    normalized = normalize_findings(filtered)
    return _build_response(summary, normalized)


# ---------------------------------------------------------------------------
# Registration hook — called by server.py during startup
# ---------------------------------------------------------------------------

def register(mcp) -> None:  # noqa: ANN001  (mcp: FastMCP)
    """Register scan tools onto the FastMCP server instance."""
    mcp.tool()(scan_project)
    mcp.tool()(scan_diff)
