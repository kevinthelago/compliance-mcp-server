"""Tests for the Lens protocol and LensResult contract (SO-1)."""
from __future__ import annotations

from pathlib import Path

import pytest

from compliance_mcp.models import Domain
from compliance_mcp.scan.lens import LensProtocol, LensResult, LensStatus
from tests.scan.conftest import StubLens, make_finding


class TestLensStatus:
    def test_values_are_strings(self) -> None:
        assert LensStatus.RAN == "ran"
        assert LensStatus.NOT_RUN == "not-run"
        assert LensStatus.ERRORED == "errored"


class TestLensResult:
    def test_ran_factory(self) -> None:
        f = make_finding()
        result = LensResult.ran([f])
        assert result.status == LensStatus.RAN
        assert result.findings == [f]
        assert result.diagnostics is None

    def test_not_run_factory(self) -> None:
        result = LensResult.not_run("binary missing")
        assert result.status == LensStatus.NOT_RUN
        assert result.findings == []
        assert result.diagnostics == "binary missing"

    def test_errored_factory(self) -> None:
        result = LensResult.errored("timeout after 30s")
        assert result.status == LensStatus.ERRORED
        assert result.findings == []
        assert result.diagnostics == "timeout after 30s"

    def test_ran_with_empty_findings(self) -> None:
        result = LensResult.ran([])
        assert result.status == LensStatus.RAN
        assert result.findings == []


class TestLensProtocol:
    def test_stub_lens_satisfies_protocol(self) -> None:
        lens = StubLens()
        assert isinstance(lens, LensProtocol)

    def test_protocol_is_runtime_checkable(self) -> None:
        # Non-lens object must NOT satisfy protocol
        class Impostor:
            pass

        assert not isinstance(Impostor(), LensProtocol)

    def test_stub_lens_name_and_domain(self) -> None:
        lens = StubLens(name="my-lens", domain=Domain.SUPPLY_CHAIN)
        assert lens.name == "my-lens"
        assert lens.domain == Domain.SUPPLY_CHAIN

    def test_applicable_returns_bool(self) -> None:
        target = Path("/tmp/project")
        assert StubLens(applicable=True).applicable(target) is True
        assert StubLens(applicable=False).applicable(target) is False

    def test_missing_binary_not_applicable(self) -> None:
        lens = StubLens(missing_binary=True)
        assert lens.applicable(Path("/tmp")) is False

    def test_run_returns_findings(self) -> None:
        f = make_finding()
        lens = StubLens(findings=[f])
        result = lens.run(Path("/tmp"))
        assert result.status == LensStatus.RAN
        assert f in result.findings

    def test_run_propagates_via_raise(self) -> None:
        lens = StubLens(raise_on_run=RuntimeError("boom"))
        with pytest.raises(RuntimeError, match="boom"):
            lens.run(Path("/tmp"))

    def test_object_without_domain_not_protocol(self) -> None:
        class NoDomain:
            @property
            def name(self) -> str:
                return "x"

            def applicable(self, target: Path) -> bool:
                return True

            def run(self, target: Path) -> LensResult:
                return LensResult.ran([])

        assert not isinstance(NoDomain(), LensProtocol)
