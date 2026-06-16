"""INT-5: End-to-end test of the *real* wired server — no stub runners.

The pre-existing ``test_e2e`` module patches deterministic stub runners into the
registry.  This module instead exercises the genuine integration seam
(:mod:`compliance_mcp.scan.builtin`): the real scanner lenses wired into both the
orchestrator engine (``scan_project``) and the registry engine
(``compliance_gate`` / ``generate_report``).

Scanner binaries (semgrep, gitleaks, syft, trivy) are not required — the
security and supply-chain lenses degrade to ``not_run`` when their binaries are
absent, while the pure-Python policy-as-code and i18n lenses still produce real
findings against the planted violations in ``sample_repo``.
"""

from __future__ import annotations

import pathlib

import pytest

from compliance_mcp.models.finding import Finding, Severity
from compliance_mcp.scan.lens import LensProtocol

SAMPLE_REPO = pathlib.Path(__file__).parent.parent / "fixtures" / "sample_repo"


@pytest.fixture
def restore_registry():
    """Snapshot and restore the global lens registry around a test."""
    from compliance_mcp import registry as _reg

    original = dict(_reg._REGISTRY)
    try:
        yield _reg
    finally:
        _reg._REGISTRY.clear()
        _reg._REGISTRY.update(original)


# ---------------------------------------------------------------------------
# build_default_lenses — every scanner conforms to LensProtocol
# ---------------------------------------------------------------------------


def test_build_default_lenses_returns_all_scanners():
    from compliance_mcp.scan.builtin import build_default_lenses

    lenses = build_default_lenses()
    names = {lens.name for lens in lenses}
    assert {"security", "supply-chain", "policy-as-code", "i18n"} <= names


def test_default_lenses_conform_to_protocol():
    from compliance_mcp.scan.builtin import build_default_lenses

    for lens in build_default_lenses():
        assert isinstance(lens, LensProtocol), f"{lens.name} does not satisfy LensProtocol"


# ---------------------------------------------------------------------------
# scan_project — orchestrator engine produces real findings
# ---------------------------------------------------------------------------


def test_scan_project_produces_real_findings():
    """scan_project over sample_repo surfaces real policy-as-code + i18n findings."""
    from compliance_mcp.tools.scan import scan_project

    result = scan_project(str(SAMPLE_REPO))
    assert result["run_summary"]["total_findings"] > 0, "real scan produced no findings"

    statuses = {r["lens"]: r["status"] for r in result["run_summary"]["lens_details"]}
    # Pure-Python lenses must actually run (no external binary required).
    assert statuses.get("policy-as-code") == "ran"
    assert statuses.get("i18n") == "ran"


def test_scan_project_degrades_without_binaries():
    """Security/supply-chain degrade (not errored) when their binaries are absent."""
    from compliance_mcp.tools.scan import scan_project

    result = scan_project(str(SAMPLE_REPO))
    statuses = {r["lens"]: r["status"] for r in result["run_summary"]["lens_details"]}
    # When the binaries ARE installed these run; when absent they degrade — never errored.
    assert statuses.get("security") in {"ran", "not_run"}
    assert statuses.get("supply-chain") in {"ran", "not_run"}


def test_scan_project_findings_are_valid_findings():
    """Every serialised finding round-trips required Finding fields."""
    from compliance_mcp.tools.scan import scan_project

    result = scan_project(str(SAMPLE_REPO))
    for f in result["findings"]:
        assert f["rule_id"]
        assert f["file_path"]
        assert f["line_start"] >= 1
        assert f["severity"] in {s.value for s in Severity}


# ---------------------------------------------------------------------------
# i18n adapter — stub findings translate to real Finding objects
# ---------------------------------------------------------------------------


def test_i18n_adapter_emits_real_findings():
    from compliance_mcp.scan.builtin import I18nScannerLens

    lens = I18nScannerLens()
    result = lens.run(SAMPLE_REPO)
    assert result.status.value == "ran"
    for f in result.findings:
        assert isinstance(f, Finding)  # real model, not the i18n stub type
        assert f.line_start >= 1


# ---------------------------------------------------------------------------
# compliance_gate — registry engine with real runners blocks on real findings
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_default_runners_populates_registry(restore_registry):
    from compliance_mcp.models.finding import Lens
    from compliance_mcp.scan.builtin import register_default_runners

    restore_registry._REGISTRY.clear()
    count = register_default_runners()
    assert count == 3
    assert restore_registry.get_lens(Lens.SOC2) is not None


@pytest.mark.asyncio
async def test_compliance_gate_blocks_with_real_scanners(restore_registry):
    from compliance_mcp.scan.builtin import register_default_runners
    from compliance_mcp.tools.gate import compliance_gate

    restore_registry._REGISTRY.clear()
    register_default_runners()

    result = await compliance_gate(str(SAMPLE_REPO))
    assert result["decision"] == "block", f"expected block, got {result['decision']}"
    assert result["new_findings"], "gate blocked but reported no findings"


@pytest.mark.asyncio
async def test_generate_report_with_real_scanners(restore_registry):
    from compliance_mcp.scan.builtin import register_default_runners
    from compliance_mcp.tools.gate import generate_report

    restore_registry._REGISTRY.clear()
    register_default_runners()

    result = await generate_report(str(SAMPLE_REPO), output_format="markdown")
    assert result["content"].strip()
    assert any(w in result["content"].upper() for w in ("BLOCK", "PASS", "INCONCLUSIVE"))


# ---------------------------------------------------------------------------
# load_tools — the real implementations replace the NotImplementedError stubs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_load_tools_replaces_stubs():
    """After load_tools, the server's registered tools are the real callables."""
    from compliance_mcp.server import mcp
    from compliance_mcp.tools import load_tools

    load_tools(mcp)
    tool_names = {t.name for t in await mcp.list_tools()}
    expected = {
        "query_policy",
        "list_policies",
        "scan_project",
        "scan_diff",
        "control_coverage",
        "explain_control",
        "compliance_gate",
        "generate_report",
    }
    assert expected <= tool_names
