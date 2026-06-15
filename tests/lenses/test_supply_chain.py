"""Tests for the supply-chain lens (SUP-4).

All scanner binaries (syft, trivy) are stubbed — no real tools required.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from compliance_mcp.adapters.base import AdapterResult, RunStatus
from compliance_mcp.adapters.syft import SBOM, Package, SyftAdapter
from compliance_mcp.adapters.trivy import TrivyAdapter
from compliance_mcp.lenses.supply_chain import SupplyChainLens
from compliance_mcp.models.finding import Domain, Lens, Severity
from compliance_mcp.scan.lens import LensStatus

POLICY_DIR = Path(__file__).parent.parent.parent / "policies" / "licenses"
SAMPLE_PROJECT = Path(__file__).parent.parent / "fixtures" / "supply_chain" / "sample_project"


# ── Helpers ───────────────────────────────────────────────────────────────────


def make_sbom(packages: list[dict]) -> SBOM:
    return SBOM(
        target=".",
        packages=[
            Package(
                name=p["name"],
                version=p.get("version", "1.0"),
                purl=None,
                licenses=p.get("licenses", []),
            )
            for p in packages
        ],
    )


def make_syft_adapter(sbom: SBOM | None = None, *, status: RunStatus = RunStatus.OK) -> MagicMock:
    adapter = MagicMock(spec=SyftAdapter)
    result = AdapterResult(status=status, stdout="", returncode=0)
    adapter.run.return_value = (result, sbom)
    return adapter


def make_trivy_adapter(findings: list = [], *, status: RunStatus = RunStatus.OK) -> MagicMock:
    adapter = MagicMock(spec=TrivyAdapter)
    result = AdapterResult(status=status, stdout="", returncode=0)
    adapter.run.return_value = (result, findings)
    return adapter


# ── Lens metadata ─────────────────────────────────────────────────────────────


def test_lens_name() -> None:
    lens = SupplyChainLens(policy_dir=POLICY_DIR)
    assert lens.name == "supply-chain"


def test_lens_domain() -> None:
    lens = SupplyChainLens(policy_dir=POLICY_DIR)
    assert lens.domain == "supply_chain"


def test_lens_applicable_to_directory(tmp_path: Path) -> None:
    lens = SupplyChainLens(policy_dir=POLICY_DIR)
    assert lens.applicable(tmp_path) is True


def test_lens_not_applicable_to_file(tmp_path: Path) -> None:
    f = tmp_path / "file.txt"
    f.write_text("content")
    lens = SupplyChainLens(policy_dir=POLICY_DIR)
    assert lens.applicable(f) is False


# ── Both scanners absent ──────────────────────────────────────────────────────


def test_both_absent_returns_not_run(tmp_path: Path) -> None:
    syft = make_syft_adapter(status=RunStatus.NOT_RUN)
    trivy = make_trivy_adapter(status=RunStatus.NOT_RUN)
    lens = SupplyChainLens(policy_dir=POLICY_DIR, syft_adapter=syft, trivy_adapter=trivy)
    result = lens.run(tmp_path)
    assert result.status == LensStatus.NOT_RUN
    assert result.findings == []


# ── Denied-license + known-CVE fixture scenario ───────────────────────────────


def test_denied_license_produces_finding(tmp_path: Path) -> None:
    sbom = make_sbom([
        {"name": "gpl-lib", "version": "1.0.0", "licenses": ["GPL-3.0-only"]},
        {"name": "safe-lib", "version": "2.0.0", "licenses": ["MIT"]},
    ])
    syft = make_syft_adapter(sbom=sbom)
    trivy = make_trivy_adapter()
    lens = SupplyChainLens(policy_dir=POLICY_DIR, syft_adapter=syft, trivy_adapter=trivy)
    result = lens.run(tmp_path)

    assert result.status == LensStatus.RAN
    denied = [f for f in result.findings if "GPL-3.0-only" in (f.message or f.title)]
    assert len(denied) >= 1
    assert denied[0].severity == Severity.HIGH


def test_known_cve_produces_finding(tmp_path: Path, trivy_fixture_json: str) -> None:
    from compliance_mcp.adapters.trivy import _parse_trivy_json

    cve_findings = _parse_trivy_json(trivy_fixture_json, target=str(tmp_path))
    syft = make_syft_adapter()  # no SBOM
    trivy = make_trivy_adapter(findings=cve_findings)
    lens = SupplyChainLens(policy_dir=POLICY_DIR, syft_adapter=syft, trivy_adapter=trivy)
    result = lens.run(tmp_path)

    assert result.status == LensStatus.RAN
    cve_rules = [f for f in result.findings if f.rule_id.startswith("cve.")]
    assert len(cve_rules) == 3


def test_combined_sbom_and_cve(tmp_path: Path, trivy_fixture_json: str) -> None:
    """Fixture scenario: denied-license dep AND known-CVE dep — both surface."""
    from compliance_mcp.adapters.trivy import _parse_trivy_json

    sbom = make_sbom([
        {"name": "gpl-lib", "version": "1.0.0", "licenses": ["GPL-3.0-only"]},
    ])
    cve_findings = _parse_trivy_json(trivy_fixture_json, target=str(tmp_path))
    syft = make_syft_adapter(sbom=sbom)
    trivy = make_trivy_adapter(findings=cve_findings)
    lens = SupplyChainLens(policy_dir=POLICY_DIR, syft_adapter=syft, trivy_adapter=trivy)
    result = lens.run(tmp_path)

    assert result.status == LensStatus.RAN
    license_findings = [f for f in result.findings if f.rule_id.startswith("license.")]
    cve_findings_out = [f for f in result.findings if f.rule_id.startswith("cve.")]
    assert len(license_findings) >= 1
    assert len(cve_findings_out) == 3


# ── Partial availability ──────────────────────────────────────────────────────


def test_syft_absent_trivy_present(tmp_path: Path, trivy_fixture_json: str) -> None:
    from compliance_mcp.adapters.trivy import _parse_trivy_json

    cve_findings = _parse_trivy_json(trivy_fixture_json, target=str(tmp_path))
    syft = make_syft_adapter(status=RunStatus.NOT_RUN)
    trivy = make_trivy_adapter(findings=cve_findings)
    lens = SupplyChainLens(policy_dir=POLICY_DIR, syft_adapter=syft, trivy_adapter=trivy)
    result = lens.run(tmp_path)

    assert result.status == LensStatus.RAN
    assert result.diagnostics is not None
    assert "syft" in result.diagnostics.lower()
    assert len([f for f in result.findings if f.rule_id.startswith("cve.")]) == 3


def test_trivy_absent_syft_present(tmp_path: Path) -> None:
    sbom = make_sbom([{"name": "gpl-lib", "version": "1.0.0", "licenses": ["GPL-3.0-only"]}])
    syft = make_syft_adapter(sbom=sbom)
    trivy = make_trivy_adapter(status=RunStatus.NOT_RUN)
    lens = SupplyChainLens(policy_dir=POLICY_DIR, syft_adapter=syft, trivy_adapter=trivy)
    result = lens.run(tmp_path)

    assert result.status == LensStatus.RAN
    assert result.diagnostics is not None
    assert "trivy" in result.diagnostics.lower()
    assert any(f.rule_id.startswith("license.") for f in result.findings)


def test_trivy_degraded_is_still_ran(tmp_path: Path) -> None:
    syft = make_syft_adapter()
    trivy = make_trivy_adapter()
    trivy.run.return_value = (
        AdapterResult(status=RunStatus.FINDINGS, degraded=True, degraded_reason="stale DB"),
        [],
    )
    lens = SupplyChainLens(policy_dir=POLICY_DIR, syft_adapter=syft, trivy_adapter=trivy)
    result = lens.run(tmp_path)

    assert result.status == LensStatus.RAN
    assert result.diagnostics is not None
    assert "degraded" in result.diagnostics.lower()


# ── SBOM generated once ───────────────────────────────────────────────────────


def test_syft_called_once(tmp_path: Path) -> None:
    syft = make_syft_adapter()
    trivy = make_trivy_adapter()
    lens = SupplyChainLens(policy_dir=POLICY_DIR, syft_adapter=syft, trivy_adapter=trivy)
    lens.run(tmp_path)
    syft.run.assert_called_once_with(tmp_path)


# ── All findings tagged correctly ─────────────────────────────────────────────


def test_all_findings_have_supply_chain_domain(tmp_path: Path, trivy_fixture_json: str) -> None:
    from compliance_mcp.adapters.trivy import _parse_trivy_json

    sbom = make_sbom([{"name": "gpl-lib", "version": "1.0.0", "licenses": ["GPL-3.0-only"]}])
    cve_findings = _parse_trivy_json(trivy_fixture_json, target=str(tmp_path))
    syft = make_syft_adapter(sbom=sbom)
    trivy = make_trivy_adapter(findings=cve_findings)
    lens = SupplyChainLens(policy_dir=POLICY_DIR, syft_adapter=syft, trivy_adapter=trivy)
    result = lens.run(tmp_path)

    for f in result.findings:
        assert f.domain == Domain.SUPPLY_CHAIN
        assert f.lens == Lens.CUSTOM
