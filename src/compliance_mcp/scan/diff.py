"""Diff resolution — resolve changed file paths for scan_diff (SO-4)."""

from __future__ import annotations

import subprocess
from pathlib import Path


class DiffResolutionError(Exception):
    """Raised when changed-file resolution fails."""


def resolve_diff_target(
    project_path: Path,
    *,
    base_ref: str | None = None,
    changed_paths: list[str] | None = None,
) -> list[Path]:
    """Return the list of existing changed files under *project_path*.

    Priority: *changed_paths* > *base_ref* > empty list.
    """
    if changed_paths is not None:
        return _resolve_explicit(project_path, changed_paths)

    if base_ref is not None:
        return _resolve_git(project_path, base_ref)

    return []


def _resolve_explicit(project_path: Path, changed_paths: list[str]) -> list[Path]:
    result: list[Path] = []
    for rel in changed_paths:
        resolved = (project_path / rel).resolve()
        if resolved.exists():
            result.append(resolved)
    return result


def _resolve_git(project_path: Path, base_ref: str) -> list[Path]:
    try:
        cmd = ["git", "diff", "--name-only", base_ref]  # noqa: S607
        proc = subprocess.run(
            cmd,
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

    result: list[Path] = []
    for line in proc.stdout.splitlines():
        rel = line.strip()
        if not rel:
            continue
        resolved = (project_path / rel).resolve()
        if resolved.exists():
            result.append(resolved)
    return result
