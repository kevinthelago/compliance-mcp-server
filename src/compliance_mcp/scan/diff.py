"""Diff resolution — determine which files to scan for scan_diff."""
from __future__ import annotations

import subprocess
from pathlib import Path


class DiffResolutionError(Exception):
    """Raised when changed files cannot be determined from the git history."""


def resolve_diff_target(
    project_path: Path,
    *,
    base_ref: str | None = None,
    changed_paths: list[str] | None = None,
) -> list[Path]:
    """Return the set of changed file paths to scan.

    Priority:
    1. If *changed_paths* is given, use it directly (paths are relative to *project_path*).
    2. If *base_ref* is given, ask git for files changed between *base_ref* and HEAD.
    3. If neither is given, return an empty list (caller should scan the whole project).

    Args:
        project_path: Absolute path to the repository root.
        base_ref: Git ref (branch, tag, SHA) to diff against.
        changed_paths: Explicit list of changed file paths (relative to *project_path*).

    Returns:
        List of absolute Path objects for changed files that exist on disk.
        Paths that no longer exist (deleted files) are omitted.

    Raises:
        DiffResolutionError: If git reports a non-zero exit code or is unavailable.
    """
    if changed_paths is not None:
        return _from_explicit(project_path, changed_paths)

    if base_ref is not None:
        return _from_git(project_path, base_ref)

    return []


def _from_explicit(project_path: Path, paths: list[str]) -> list[Path]:
    """Resolve an explicit path list; filter to existing files."""
    result: list[Path] = []
    for rel in paths:
        p = (project_path / rel).resolve()
        if p.exists():
            result.append(p)
    return result


def _from_git(project_path: Path, base_ref: str) -> list[Path]:
    """Use `git diff --name-only` to find files changed since *base_ref*."""
    try:
        proc = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMRT", base_ref, "HEAD"],
            cwd=project_path,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError as exc:
        raise DiffResolutionError("git binary not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise DiffResolutionError("git diff timed out") from exc

    if proc.returncode != 0:
        raise DiffResolutionError(
            f"git diff failed (exit {proc.returncode}): {proc.stderr.strip()}"
        )

    changed: list[Path] = []
    for line in proc.stdout.splitlines():
        rel = line.strip()
        if not rel:
            continue
        p = (project_path / rel).resolve()
        if p.exists():
            changed.append(p)
    return changed
