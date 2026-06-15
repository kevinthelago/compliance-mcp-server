"""Integration tests for scan_project and scan_diff tools (SO-5)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from compliance_mcp.models.finding import Severity
from compliance_mcp.tools.scan import scan_diff, scan_project
from tests.scan.conftest import StubLens, make_finding


def _patch_lenses(lenses):
    return patch("compliance_mcp.tools.scan.get_lenses", return_value=lenses)


# ---------------------------------------------------------------------------
# scan_project
# ---------------------------------------------------------------------------


class TestScanProjectValidation:
    def test_nonexistent_path_returns_error(self) -> None:
        result = scan_project("/no/such/path/xyz")
        assert result["error"] == "path_not_found"
        assert "detail" in result

    def test_file_path_returns_error(self, tmp_path: Path) -> None:
        f = tmp_path / "file.py"
        f.write_text("x")
        result = scan_project(str(f))
        assert result["error"] == "path_not_directory"

    def test_valid_directory_does_not_error(self, tmp_path: Path) -> None:
        with _patch_lenses([]):
            result = scan_project(str(tmp_path))
        assert "error" not in result
        assert "findings" in result
        assert "run_summary" in result


class TestScanProjectFindings:
    def test_returns_findings_from_lens(self, tmp_path: Path) -> None:
        f = make_finding(title="vuln", severity=Severity.HIGH, file_path="a.py")
        lens = StubLens(name="sec", findings=[f])
        with _patch_lenses([lens]):
            result = scan_project(str(tmp_path))
        assert len(result["findings"]) == 1
        assert result["findings"][0]["title"] == "vuln"
        assert result["findings"][0]["severity"] == "high"

    def test_findings_are_normalised(self, tmp_path: Path) -> None:
        f1 = make_finding(title="dup", severity=Severity.MEDIUM, file_path="a.py")
        f2 = make_finding(title="dup", severity=Severity.MEDIUM, file_path="a.py")
        assert f1.fingerprint == f2.fingerprint
        lens = StubLens(name="sec", findings=[f1, f2])
        with _patch_lenses([lens]):
            result = scan_project(str(tmp_path))
        assert len(result["findings"]) == 1

    def test_run_summary_counts(self, tmp_path: Path) -> None:
        good = StubLens(name="good", findings=[make_finding()])
        absent = StubLens(name="absent", applicable=False)
        broken = StubLens(name="broken", raise_on_run=RuntimeError("fail"))
        with _patch_lenses([good, absent, broken]):
            result = scan_project(str(tmp_path))
        rs = result["run_summary"]
        assert rs["lenses_ran"] == 1
        assert rs["lenses_not_run"] == 1
        assert rs["lenses_errored"] == 1

    def test_findings_ranked_by_severity(self, tmp_path: Path) -> None:
        findings = [
            make_finding(title="low", severity=Severity.LOW, file_path="a.py"),
            make_finding(title="critical", severity=Severity.CRITICAL, file_path="b.py"),
        ]
        lens = StubLens(name="all", findings=findings)
        with _patch_lenses([lens]):
            result = scan_project(str(tmp_path))
        severities = [f["severity"] for f in result["findings"]]
        assert severities[0] == "critical"
        assert severities[1] == "low"

    def test_lens_filter_restricts_to_named_lenses(self, tmp_path: Path) -> None:
        lens_a = StubLens(name="lens-a", findings=[make_finding(title="a")])
        lens_b = StubLens(name="lens-b", findings=[make_finding(title="b")])
        with _patch_lenses([lens_a, lens_b]):
            result = scan_project(str(tmp_path), lenses=["lens-a"])
        titles = [f["title"] for f in result["findings"]]
        assert "a" in titles
        assert "b" not in titles

    def test_empty_findings_returns_empty_list(self, tmp_path: Path) -> None:
        with _patch_lenses([StubLens(name="clean", findings=[])]):
            result = scan_project(str(tmp_path))
        assert result["findings"] == []
        assert result["run_summary"]["total_findings"] == 0


# ---------------------------------------------------------------------------
# scan_diff
# ---------------------------------------------------------------------------


class TestScanDiffValidation:
    def test_nonexistent_path_returns_error(self) -> None:
        result = scan_diff("/no/such/xyz")
        assert result["error"] == "path_not_found"

    def test_file_path_returns_error(self, tmp_path: Path) -> None:
        f = tmp_path / "file.py"
        f.write_text("x")
        result = scan_diff(str(f))
        assert result["error"] == "path_not_directory"


class TestScanDiffExplicitPaths:
    def test_changed_paths_filters_findings(self, tmp_path: Path) -> None:
        (tmp_path / "in_diff.py").write_text("x")
        (tmp_path / "not_in_diff.py").write_text("y")

        findings = [
            make_finding(title="in", file_path="in_diff.py"),
            make_finding(title="out", file_path="not_in_diff.py"),
        ]
        lens = StubLens(name="sec", findings=findings)
        with _patch_lenses([lens]):
            result = scan_diff(str(tmp_path), changed_paths=["in_diff.py"])
        titles = [f["title"] for f in result["findings"]]
        assert "in" in titles
        assert "out" not in titles

    def test_no_changed_files_returns_empty_with_note(self, tmp_path: Path) -> None:
        with _patch_lenses([]):
            result = scan_diff(str(tmp_path), changed_paths=[])
        assert result["findings"] == []
        assert "note" in result["run_summary"]


class TestScanDiffGitBaseRef:
    def test_git_error_returns_error_dict(self, tmp_path: Path) -> None:
        proc = MagicMock(returncode=128, stdout="", stderr="fatal: bad ref")
        with patch("subprocess.run", return_value=proc), _patch_lenses([]):
            result = scan_diff(str(tmp_path), base_ref="bad-ref")
        assert result["error"] == "diff_resolution_failed"
        assert "detail" in result

    def test_base_ref_resolves_changed_files(self, tmp_path: Path) -> None:
        (tmp_path / "changed.py").write_text("code")
        (tmp_path / "unchanged.py").write_text("code")

        proc = MagicMock(returncode=0, stdout="changed.py\n", stderr="")
        with patch("subprocess.run", return_value=proc):
            findings = [
                make_finding(title="found", file_path="changed.py"),
                make_finding(title="not-found", file_path="unchanged.py"),
            ]
            lens = StubLens(name="sec", findings=findings)
            with _patch_lenses([lens]):
                result = scan_diff(str(tmp_path), base_ref="main")
        titles = [f["title"] for f in result["findings"]]
        assert "found" in titles
        assert "not-found" not in titles
