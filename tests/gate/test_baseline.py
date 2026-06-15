"""Tests for baseline suppression — GR-2."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from compliance_mcp.gate.baseline import BaselineEntry, load_baseline, suppress

if TYPE_CHECKING:
    from pathlib import Path
from compliance_mcp.models.finding import Domain, Finding, Lens, Severity


def _f(fingerprint: str, sev: Severity = Severity.HIGH) -> Finding:
    return Finding(
        lens=Lens.SOC2,
        domain=Domain.VULNERABILITY,
        rule_id="soc2.test",
        file_path="src/test.py",
        line_start=1,
        severity=sev,
        title="Test",
        fingerprint=fingerprint,
    )


class TestLoadBaseline:
    def test_none_path_returns_empty(self) -> None:
        assert load_baseline(None) == []

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        assert load_baseline(tmp_path / "nonexistent.json") == []

    def test_simple_string_list(self, tmp_path: Path) -> None:
        p = tmp_path / "baseline.json"
        p.write_text(json.dumps(["fp0001", "fp0002"]))
        entries = load_baseline(p)
        assert len(entries) == 2
        assert entries[0].fingerprint == "fp0001"
        assert entries[1].fingerprint == "fp0002"

    def test_annotated_format(self, tmp_path: Path) -> None:
        p = tmp_path / "baseline.json"
        p.write_text(
            json.dumps(
                [
                    {"fingerprint": "fp0001", "reason": "Known FP"},
                    {"fingerprint": "fp0002", "reason": "Tracked in SEC-42"},
                ]
            )
        )
        entries = load_baseline(p)
        assert len(entries) == 2
        assert entries[0].reason == "Known FP"

    def test_mixed_format(self, tmp_path: Path) -> None:
        p = tmp_path / "baseline.json"
        p.write_text(
            json.dumps(["plain-fp", {"fingerprint": "annotated-fp", "reason": "test"}])
        )
        entries = load_baseline(p)
        assert len(entries) == 2
        assert entries[0].fingerprint == "plain-fp"

    def test_entry_missing_fingerprint_skipped(self, tmp_path: Path) -> None:
        p = tmp_path / "baseline.json"
        p.write_text(json.dumps([{"reason": "no fingerprint"}, {"fingerprint": "valid-fp"}]))
        entries = load_baseline(p)
        assert len(entries) == 1
        assert entries[0].fingerprint == "valid-fp"

    def test_non_list_input_returns_empty(self, tmp_path: Path) -> None:
        p = tmp_path / "baseline.json"
        p.write_text(json.dumps({"fingerprints": ["fp1"]}))
        assert load_baseline(p) == []


class TestSuppress:
    def test_matching_fingerprint_accepted(self) -> None:
        fp = "a" * 64  # full sha256
        finding = _f(fp, Severity.CRITICAL)
        baseline = [BaselineEntry(fingerprint=fp)]
        result = suppress([finding], baseline)
        assert finding in result.accepted
        assert finding not in result.active
        assert result.stale_entries == []

    def test_non_matching_fingerprint_active(self) -> None:
        finding = _f("a" * 64)
        baseline = [BaselineEntry(fingerprint="b" * 64)]
        result = suppress([finding], baseline)
        assert finding in result.active
        assert finding not in result.accepted

    def test_stale_entry_detected(self) -> None:
        baseline = [BaselineEntry(fingerprint="ghost" + "0" * 59, reason="Old issue")]
        result = suppress([], baseline)
        assert len(result.stale_entries) == 1

    def test_matched_entry_not_stale(self) -> None:
        fp = "c" * 64
        finding = _f(fp)
        baseline = [BaselineEntry(fingerprint=fp)]
        result = suppress([finding], baseline)
        assert result.stale_entries == []

    def test_mixed_findings(self) -> None:
        fp_acc = "a" * 64
        fp_act = "b" * 64
        fp_stale = "c" * 64

        findings = [_f(fp_acc), _f(fp_act)]
        baseline = [
            BaselineEntry(fingerprint=fp_acc, reason="Accepted"),
            BaselineEntry(fingerprint=fp_stale, reason="Stale"),
        ]
        result = suppress(findings, baseline)
        assert len(result.accepted) == 1
        assert result.accepted[0].fingerprint == fp_acc
        assert len(result.active) == 1
        assert result.active[0].fingerprint == fp_act
        assert len(result.stale_entries) == 1
        assert result.stale_entries[0].fingerprint == fp_stale

    def test_empty_baseline_all_active(self) -> None:
        findings = [_f("a" * 64), _f("b" * 64)]
        result = suppress(findings, [])
        assert len(result.active) == 2
        assert result.accepted == []
        assert result.stale_entries == []

    def test_empty_findings_all_stale(self) -> None:
        baseline = [BaselineEntry(fingerprint="a" * 64), BaselineEntry(fingerprint="b" * 64)]
        result = suppress([], baseline)
        assert result.active == []
        assert result.accepted == []
        assert len(result.stale_entries) == 2
