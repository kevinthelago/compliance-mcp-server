"""Tests for LensProtocol, LensResult, and LensStatus (SO-1)."""

from __future__ import annotations

from pathlib import Path

from compliance_mcp.scan.lens import LensProtocol, LensResult, LensStatus
from tests.scan.conftest import StubLens, make_finding


class TestLensStatus:
    def test_values_are_strings(self) -> None:
        assert LensStatus.RAN == "ran"
        assert LensStatus.NOT_RUN == "not_run"
        assert LensStatus.ERRORED == "errored"

    def test_is_str(self) -> None:
        assert isinstance(LensStatus.RAN, str)


class TestLensResult:
    def test_ran_factory(self) -> None:
        f = make_finding()
        result = LensResult.ran([f])
        assert result.status == LensStatus.RAN
        assert result.findings == [f]
        assert result.diagnostics is None

    def test_ran_empty(self) -> None:
        result = LensResult.ran([])
        assert result.status == LensStatus.RAN
        assert result.findings == []

    def test_not_run_factory(self) -> None:
        result = LensResult.not_run("tool not found")
        assert result.status == LensStatus.NOT_RUN
        assert result.findings == []
        assert result.diagnostics == "tool not found"

    def test_not_run_no_reason(self) -> None:
        result = LensResult.not_run()
        assert result.status == LensStatus.NOT_RUN
        assert result.diagnostics is None

    def test_errored_factory(self) -> None:
        result = LensResult.errored("connection refused")
        assert result.status == LensStatus.ERRORED
        assert result.findings == []
        assert result.diagnostics == "connection refused"


class TestLensProtocol:
    def test_stub_satisfies_protocol(self) -> None:
        assert isinstance(StubLens(), LensProtocol)

    def test_stub_name(self) -> None:
        assert StubLens(name="myscanner").name == "myscanner"

    def test_stub_applicable_true(self, tmp_path: Path) -> None:
        assert StubLens().applicable(tmp_path) is True

    def test_stub_applicable_false(self, tmp_path: Path) -> None:
        assert StubLens(applicable=False).applicable(tmp_path) is False

    def test_stub_run_returns_findings(self, tmp_path: Path) -> None:
        f = make_finding(title="found")
        result = StubLens(findings=[f]).run(tmp_path)
        assert result.status == LensStatus.RAN
        assert f in result.findings
