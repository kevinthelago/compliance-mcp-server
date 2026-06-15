"""Tests for ScanOrchestrator (SO-2)."""
from __future__ import annotations

import time
from pathlib import Path

from compliance_mcp.models import Domain
from compliance_mcp.scan.lens import LensResult, LensStatus
from compliance_mcp.scan.orchestrator import ScanOrchestrator
from tests.scan.conftest import StubLens, make_finding

TARGET = Path("/tmp/project")


class TestScanOrchestratorBasic:
    def test_empty_lenses_returns_empty_summary(self) -> None:
        orc = ScanOrchestrator([], concurrency=2, timeout=5.0)
        summary = orc.run(TARGET)
        assert summary.findings == []
        assert summary.lens_records == []

    def test_single_lens_ran(self) -> None:
        f = make_finding(title="A")
        lens = StubLens(findings=[f])
        orc = ScanOrchestrator([lens], concurrency=1, timeout=5.0)
        summary = orc.run(TARGET)
        assert summary.findings == [f]
        assert len(summary.lens_records) == 1
        assert summary.lens_records[0].status == LensStatus.RAN
        assert summary.lens_records[0].finding_count == 1

    def test_not_applicable_lens_is_not_run(self) -> None:
        lens = StubLens(applicable=False)
        orc = ScanOrchestrator([lens], timeout=5.0)
        summary = orc.run(TARGET)
        assert summary.findings == []
        assert summary.lens_records[0].status == LensStatus.NOT_RUN

    def test_missing_binary_is_not_run(self) -> None:
        lens = StubLens(missing_binary=True)
        orc = ScanOrchestrator([lens], timeout=5.0)
        summary = orc.run(TARGET)
        assert summary.lens_records[0].status == LensStatus.NOT_RUN

    def test_run_summary_counts(self) -> None:
        lenses = [
            StubLens(name="good", findings=[make_finding()]),
            StubLens(name="absent", applicable=False),
            StubLens(name="broken", raise_on_run=RuntimeError("fail")),
        ]
        orc = ScanOrchestrator(lenses, concurrency=3, timeout=5.0)
        summary = orc.run(TARGET)
        assert summary.ran_count == 1
        assert summary.not_run_count == 1
        assert summary.errored_count == 1


class TestParallelRun:
    def test_multiple_lenses_all_produce_findings(self) -> None:
        lenses = [
            StubLens(name=f"lens-{i}", findings=[make_finding(title=f"F{i}")])
            for i in range(4)
        ]
        orc = ScanOrchestrator(lenses, concurrency=4, timeout=5.0)
        summary = orc.run(TARGET)
        assert len(summary.findings) == 4
        assert summary.ran_count == 4

    def test_results_in_lens_order(self) -> None:
        """Finding order must follow lens registration order, not completion order."""
        import threading

        barrier = threading.Barrier(3)

        class OrderedStub:
            def __init__(self, idx: int, delay: float) -> None:
                self._idx = idx
                self._delay = delay

            @property
            def name(self) -> str:
                return f"lens-{self._idx}"

            @property
            def domain(self) -> Domain:
                return Domain.SECURITY

            def applicable(self, target: Path) -> bool:
                return True

            def run(self, target: Path) -> LensResult:
                barrier.wait()
                time.sleep(self._delay)
                return LensResult.ran([make_finding(title=f"finding-{self._idx}")])

        # lens-0 is slowest, lens-2 is fastest — order must still be 0,1,2
        lenses = [OrderedStub(0, 0.05), OrderedStub(1, 0.02), OrderedStub(2, 0.0)]
        orc = ScanOrchestrator(lenses, concurrency=3, timeout=5.0)
        summary = orc.run(TARGET)
        titles = [f.title for f in summary.findings]
        assert titles == ["finding-0", "finding-1", "finding-2"]


class TestFaultIsolation:
    def test_errored_lens_does_not_block_others(self) -> None:
        f = make_finding(title="clean")
        lenses = [
            StubLens(name="bad", raise_on_run=ValueError("explode")),
            StubLens(name="good", findings=[f]),
        ]
        orc = ScanOrchestrator(lenses, concurrency=2, timeout=5.0)
        summary = orc.run(TARGET)
        assert any(r.status == LensStatus.ERRORED for r in summary.lens_records)
        assert f in summary.findings

    def test_errored_lens_record_has_diagnostics(self) -> None:
        lenses = [StubLens(name="bad", raise_on_run=RuntimeError("oops"))]
        orc = ScanOrchestrator(lenses, timeout=5.0)
        summary = orc.run(TARGET)
        record = summary.lens_records[0]
        assert record.status == LensStatus.ERRORED
        assert record.diagnostics is not None
        assert "oops" in record.diagnostics


class TestTimeout:
    def test_slow_lens_is_timed_out_and_others_complete(self) -> None:
        import threading

        ready = threading.Event()

        class SlowLens:
            @property
            def name(self) -> str:
                return "slow"

            @property
            def domain(self) -> Domain:
                return Domain.SECURITY

            def applicable(self, target: Path) -> bool:
                return True

            def run(self, target: Path) -> LensResult:
                ready.set()
                time.sleep(10)
                return LensResult.ran([])

        f = make_finding(title="fast-finding")
        fast = StubLens(name="fast", findings=[f])
        slow = SlowLens()

        orc = ScanOrchestrator([slow, fast], concurrency=2, timeout=0.3)
        summary = orc.run(TARGET)

        slow_record = next(r for r in summary.lens_records if r.name == "slow")
        assert slow_record.status == LensStatus.ERRORED
        assert "timed out" in (slow_record.diagnostics or "")

        fast_record = next(r for r in summary.lens_records if r.name == "fast")
        assert fast_record.status == LensStatus.RAN
        assert f in summary.findings
