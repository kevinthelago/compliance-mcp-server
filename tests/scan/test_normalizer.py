"""Tests for the finding normalizer (SO-3)."""

from __future__ import annotations

from compliance_mcp.models.finding import Severity
from compliance_mcp.scan.normalizer import normalize_findings
from tests.scan.conftest import make_finding


class TestDedupe:
    def test_empty_list_returns_empty(self) -> None:
        assert normalize_findings([]) == []

    def test_no_duplicates_unchanged_count(self) -> None:
        findings = [
            make_finding(title="A", file_path="a.py"),
            make_finding(title="B", file_path="b.py"),
        ]
        result = normalize_findings(findings)
        assert len(result) == 2

    def test_duplicate_fingerprint_deduplicated(self) -> None:
        f1 = make_finding(title="Dup", file_path="foo.py")
        f2 = make_finding(title="Dup", file_path="foo.py")  # same fingerprint
        assert f1.fingerprint == f2.fingerprint
        result = normalize_findings([f1, f2])
        assert len(result) == 1

    def test_first_occurrence_kept_on_duplicate(self) -> None:
        f1 = make_finding(title="Dup", file_path="foo.py", message="from lens-a")
        f2 = make_finding(title="Dup", file_path="foo.py", message="from lens-b")
        result = normalize_findings([f1, f2])
        assert result[0].message == "from lens-a"

    def test_different_fingerprints_both_kept(self) -> None:
        f1 = make_finding(title="X", file_path="a.py")
        f2 = make_finding(title="Y", file_path="a.py")
        assert f1.fingerprint != f2.fingerprint
        result = normalize_findings([f1, f2])
        assert len(result) == 2


class TestOrdering:
    def test_sorted_by_severity_critical_first(self) -> None:
        findings = [
            make_finding(title="low", severity=Severity.LOW),
            make_finding(title="critical", severity=Severity.CRITICAL),
            make_finding(title="high", severity=Severity.HIGH),
        ]
        result = normalize_findings(findings)
        assert result[0].severity == Severity.CRITICAL
        assert result[1].severity == Severity.HIGH
        assert result[2].severity == Severity.LOW

    def test_same_severity_sorted_by_file_path(self) -> None:
        findings = [
            make_finding(title="T1", severity=Severity.HIGH, file_path="z/file.py"),
            make_finding(title="T2", severity=Severity.HIGH, file_path="a/file.py"),
        ]
        result = normalize_findings(findings)
        assert result[0].file_path == "a/file.py"
        assert result[1].file_path == "z/file.py"

    def test_ordering_deterministic_for_identical_inputs(self) -> None:
        findings = [
            make_finding(title=f"F{i}", severity=Severity.MEDIUM, file_path="x.py")
            for i in range(5)
        ]
        r1 = normalize_findings(list(findings))
        r2 = normalize_findings(list(findings))
        assert [f.title for f in r1] == [f.title for f in r2]

    def test_full_severity_order(self) -> None:
        all_severities = [
            Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL
        ]
        findings = [
            make_finding(title=sev.value, severity=sev, file_path=f"{i}.py")
            for i, sev in enumerate(all_severities)
        ]
        result = normalize_findings(findings)
        expected_order = [
            Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
        ]
        assert [f.severity for f in result] == expected_order


class TestDedupeAndOrder:
    def test_dedupe_then_order(self) -> None:
        f_high_dup1 = make_finding(title="high-dup", severity=Severity.HIGH, file_path="a.py")
        f_high_dup2 = make_finding(title="high-dup", severity=Severity.HIGH, file_path="a.py")
        f_critical = make_finding(title="crit", severity=Severity.CRITICAL, file_path="b.py")
        findings = [f_high_dup1, f_high_dup2, f_critical]
        result = normalize_findings(findings)
        assert len(result) == 2
        assert result[0].severity == Severity.CRITICAL
        assert result[1].severity == Severity.HIGH
