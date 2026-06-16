"""scan_project and scan_diff MCP tool implementations (SO-5)."""

from __future__ import annotations

from pathlib import Path

from compliance_mcp.config import load_settings
from compliance_mcp.models.finding import Finding
from compliance_mcp.scan.diff import DiffResolutionError, resolve_diff_target
from compliance_mcp.scan.normalizer import normalize_findings
from compliance_mcp.scan.orchestrator import LensRunRecord, ScanOrchestrator, ScanSummary


def get_lenses():  # noqa: ANN201
    """Return all registered LensProtocol implementations.

    Builds the built-in scanner set (security, supply-chain, policy-as-code,
    i18n).  A scanner that fails to construct is skipped, not fatal.  Patched in
    tests to substitute deterministic stub lenses.
    """
    from compliance_mcp.scan.builtin import build_default_lenses

    return build_default_lenses(load_settings())


# ---------------------------------------------------------------------------
# Response serialisation
# ---------------------------------------------------------------------------


def _finding_to_dict(f: Finding) -> dict:
    return {
        "lens": f.lens.value,
        "domain": f.domain.value,
        "severity": f.severity.value,
        "title": f.title,
        "message": f.message,
        "file_path": f.file_path,
        "rule_id": f.rule_id,
        "line_start": f.line_start,
        "line_end": f.line_end,
        "suggestion": f.suggestion,
        "control_refs": f.control_refs,
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
# Validation
# ---------------------------------------------------------------------------


def _validate_project_path(path: str) -> tuple[Path | None, dict | None]:
    p = Path(path)
    if not p.exists():
        return None, {"error": "path_not_found", "detail": f"Path does not exist: {path}"}
    if not p.is_dir():
        return None, {"error": "path_not_directory", "detail": f"Not a directory: {path}"}
    return p.resolve(), None


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def scan_project(path: str, lenses: list[str] | None = None) -> dict:
    """Run all applicable lenses against a project directory.

    Args:
        path: Absolute or relative path to the project root.
        lenses: Optional lens names to restrict the run. All applicable if omitted.

    Returns:
        Dict with ``findings`` (normalised, ranked) and ``run_summary``.
    """
    project_path, err = _validate_project_path(path)
    if err:
        return err

    cfg = load_settings()
    all_lenses = get_lenses()
    if lenses is not None:
        requested = set(lenses)
        all_lenses = [lens for lens in all_lenses if lens.name in requested]

    orc = ScanOrchestrator(
        all_lenses,
        concurrency=cfg.concurrency_cap,
        timeout=float(cfg.lens_timeout_seconds),
    )
    summary = orc.run(project_path)
    normalized = normalize_findings(summary.findings)
    return _build_response(summary, normalized)


def scan_diff(
    path: str,
    base_ref: str | None = None,
    changed_paths: list[str] | None = None,
) -> dict:
    """Scan only files changed relative to a base git ref or an explicit file list.

    Args:
        path: Absolute or relative path to the project root.
        base_ref: Git ref to diff against (requires git repo at *path*).
        changed_paths: Explicit file paths relative to *path* (takes priority).

    Returns:
        Dict with ``findings`` and ``run_summary``, same shape as scan_project.
    """
    project_path, err = _validate_project_path(path)
    if err:
        return err

    try:
        diff_files = resolve_diff_target(
            project_path,
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

    cfg = load_settings()
    all_lenses = get_lenses()
    orc = ScanOrchestrator(
        all_lenses,
        concurrency=cfg.concurrency_cap,
        timeout=float(cfg.lens_timeout_seconds),
    )
    summary = orc.run(project_path)

    diff_set = {str(p) for p in diff_files}
    diff_rels = {p.relative_to(project_path).as_posix() for p in diff_files}

    filtered = [
        f
        for f in summary.findings
        if f.file_path in diff_set
        or f.file_path in diff_rels
        or str((project_path / f.file_path).resolve()) in diff_set
    ]

    normalized = normalize_findings(filtered)
    return _build_response(summary, normalized)


# ---------------------------------------------------------------------------
# Registration hook
# ---------------------------------------------------------------------------


def register(mcp) -> None:  # noqa: ANN001
    """Register scan tools on a FastMCP instance, overriding the server stubs."""
    mcp.tool()(scan_project)
    mcp.tool()(scan_diff)
