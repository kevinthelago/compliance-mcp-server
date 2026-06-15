"""Tests for diff resolution (SO-4)."""
from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from compliance_mcp.scan.diff import DiffResolutionError, resolve_diff_target


class TestExplicitChangedPaths:
    def test_returns_existing_files(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("x")
        (tmp_path / "b.py").write_text("y")
        result = resolve_diff_target(tmp_path, changed_paths=["a.py", "b.py"])
        assert set(result) == {(tmp_path / "a.py").resolve(), (tmp_path / "b.py").resolve()}

    def test_skips_deleted_files(self, tmp_path: Path) -> None:
        (tmp_path / "exists.py").write_text("x")
        result = resolve_diff_target(tmp_path, changed_paths=["exists.py", "gone.py"])
        assert len(result) == 1
        assert result[0].name == "exists.py"

    def test_empty_changed_paths_returns_empty(self, tmp_path: Path) -> None:
        result = resolve_diff_target(tmp_path, changed_paths=[])
        assert result == []

    def test_changed_paths_takes_priority_over_base_ref(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("x")
        # base_ref is also supplied; changed_paths should win (no git call needed)
        with patch("subprocess.run") as mock_run:
            result = resolve_diff_target(
                tmp_path, base_ref="HEAD~1", changed_paths=["a.py"]
            )
        mock_run.assert_not_called()
        assert len(result) == 1


class TestGitDiff:
    def _make_git_proc(self, stdout: str, returncode: int = 0) -> MagicMock:
        proc = MagicMock()
        proc.returncode = returncode
        proc.stdout = stdout
        proc.stderr = ""
        return proc

    def test_returns_changed_files_from_git(self, tmp_path: Path) -> None:
        (tmp_path / "changed.py").write_text("code")
        git_output = "changed.py\n"
        with patch("subprocess.run", return_value=self._make_git_proc(git_output)):
            result = resolve_diff_target(tmp_path, base_ref="main")
        assert len(result) == 1
        assert result[0].name == "changed.py"

    def test_skips_deleted_files_from_git(self, tmp_path: Path) -> None:
        git_output = "deleted_file.py\n"
        with patch("subprocess.run", return_value=self._make_git_proc(git_output)):
            result = resolve_diff_target(tmp_path, base_ref="main")
        assert result == []

    def test_git_nonzero_exit_raises(self, tmp_path: Path) -> None:
        proc = MagicMock(returncode=128, stdout="", stderr="fatal: bad revision")
        with patch("subprocess.run", return_value=proc):
            with pytest.raises(DiffResolutionError, match="git diff failed"):
                resolve_diff_target(tmp_path, base_ref="bad-ref")

    def test_git_not_found_raises(self, tmp_path: Path) -> None:
        with patch("subprocess.run", side_effect=FileNotFoundError):
            with pytest.raises(DiffResolutionError, match="git binary not found"):
                resolve_diff_target(tmp_path, base_ref="main")

    def test_git_timeout_raises(self, tmp_path: Path) -> None:
        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="git", timeout=30)
        ):
            with pytest.raises(DiffResolutionError, match="timed out"):
                resolve_diff_target(tmp_path, base_ref="main")

    def test_multiple_files_returned(self, tmp_path: Path) -> None:
        for name in ("a.py", "b.py", "c.rs"):
            (tmp_path / name).write_text("x")
        git_output = "a.py\nb.py\nc.rs\n"
        with patch("subprocess.run", return_value=self._make_git_proc(git_output)):
            result = resolve_diff_target(tmp_path, base_ref="HEAD~3")
        assert len(result) == 3

    def test_blank_lines_ignored(self, tmp_path: Path) -> None:
        (tmp_path / "only.py").write_text("x")
        git_output = "\nonly.py\n\n"
        with patch("subprocess.run", return_value=self._make_git_proc(git_output)):
            result = resolve_diff_target(tmp_path, base_ref="main")
        assert len(result) == 1


class TestNoArgsGiven:
    def test_no_args_returns_empty(self, tmp_path: Path) -> None:
        result = resolve_diff_target(tmp_path)
        assert result == []
