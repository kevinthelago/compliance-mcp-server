"""INT-2: End-to-end integration test.

Verifies the compliance_gate → generate_report pipeline using stub lens
runners patched into the module-level registry. Scanner binaries are NOT
required.

The sample_repo fixture has planted violations (committed .env, root
Dockerfile, SQL-injection-prone app.py) that stub runners surface as
deterministic findings across multiple compliance domains.
"""

from __future__ import annotations

import pathlib

import pytest

from compliance_mcp.models.finding import Domain, Finding, Lens, Severity

SAMPLE_REPO = pathlib.Path(__file__).parent.parent / "fixtures" / "sample_repo"


# ---------------------------------------------------------------------------
# Stub lens runners — async functions matching the LensRunner protocol:
#   async def run(project_path: str, config: ComplianceSettings) -> list[Finding]
# ---------------------------------------------------------------------------


async def _gdpr_stub(project_path: str, config) -> list[Finding]:  # noqa: ANN001
    """Surfaces data-protection and access-control findings from the sample repo."""
    return [
        Finding(
            lens=Lens.GDPR,
            domain=Domain.DATA_PROTECTION,
            rule_id="gdpr.data-protection.secrets-in-env",
            file_path=".env",
            line_start=1,
            severity=Severity.HIGH,
            title="Secrets committed to version control",
            message=".env file with credentials is tracked in git",
            suggestion="Add .env to .gitignore and rotate all secrets",
            control_refs=["GDPR Art. 32(1)(b)", "GDPR Art. 5(1)(f)"],
        ),
        Finding(
            lens=Lens.GDPR,
            domain=Domain.ACCESS_CONTROL,
            rule_id="gdpr.access-control.hardcoded-credentials",
            file_path="app.py",
            line_start=3,
            severity=Severity.CRITICAL,
            title="Hardcoded credentials in source",
            message="API key is hardcoded in application source code",
            suggestion="Use environment variables or a secrets manager",
            control_refs=["GDPR Art. 32(1)(b)"],
        ),
    ]


async def _soc2_stub(project_path: str, config) -> list[Finding]:  # noqa: ANN001
    """Surfaces vulnerability and configuration findings from the sample repo."""
    return [
        Finding(
            lens=Lens.SOC2,
            domain=Domain.VULNERABILITY,
            rule_id="soc2.vuln.sql-injection",
            file_path="app.py",
            line_start=7,
            severity=Severity.CRITICAL,
            title="SQL injection via string interpolation",
            message="f-string used to build SQL query — untrusted input flows to DB",
            suggestion="Use parameterised queries",
            control_refs=["SOC2-CC6.1", "OWASP-A03"],
        ),
        Finding(
            lens=Lens.SOC2,
            domain=Domain.CONFIGURATION,
            rule_id="soc2.config.dockerfile-runs-as-root",
            file_path="Dockerfile",
            line_start=1,
            severity=Severity.HIGH,
            title="Dockerfile runs as root",
            message="No USER directive found — container executes as root",
            suggestion="Add USER <non-root> after the last COPY/RUN",
            control_refs=["SOC2-CC6.6"],
        ),
    ]


async def _iso27001_stub(project_path: str, config) -> list[Finding]:  # noqa: ANN001
    """Surfaces supply-chain and documentation findings from the sample repo."""
    target = pathlib.Path(project_path)
    findings: list[Finding] = [
        Finding(
            lens=Lens.ISO27001,
            domain=Domain.SUPPLY_CHAIN,
            rule_id="iso27001.supply-chain.unpinned-dependency",
            file_path="package.json",
            line_start=1,
            severity=Severity.MEDIUM,
            title="Unpinned dependency",
            message="lodash uses a range specifier (^4.17.21); pin to an exact version",
            suggestion='Pin to an exact version, e.g. "4.17.21"',
            control_refs=["ISO27001-A.15.1.1"],
        ),
    ]
    if not any((target / name).exists() for name in ("README.md", "README.rst", "README")):
        findings.append(
            Finding(
                lens=Lens.ISO27001,
                domain=Domain.DOCUMENTATION,
                rule_id="iso27001.docs.missing-readme",
                file_path=".",
                line_start=1,
                severity=Severity.LOW,
                title="Missing README",
                message="No README file found in the repository root",
                suggestion="Add a README.md describing the project",
                control_refs=["ISO27001-A.12.1.1"],
            )
        )
    return findings


_STUB_RUNNERS = {
    Lens.GDPR: _gdpr_stub,
    Lens.SOC2: _soc2_stub,
    Lens.ISO27001: _iso27001_stub,
}


# ---------------------------------------------------------------------------
# Fixture — patch/restore the module-level _REGISTRY for each test
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def patch_registry():
    """Replace the module-level _REGISTRY with stubs; restore after each test."""
    from compliance_mcp import registry as _reg

    original = dict(_reg._REGISTRY)
    _reg._REGISTRY.clear()
    _reg._REGISTRY.update(_STUB_RUNNERS)
    yield
    _reg._REGISTRY.clear()
    _reg._REGISTRY.update(original)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_sample_repo_exists():
    """The sample_repo fixture directory must exist."""
    assert SAMPLE_REPO.exists(), f"sample_repo fixture missing at {SAMPLE_REPO}"
    assert SAMPLE_REPO.is_dir()


def test_sample_repo_has_planted_violations():
    """Planted violation files must be present in sample_repo."""
    assert (SAMPLE_REPO / ".env").exists(), "Missing .env fixture (planted committed secrets)"
    assert (SAMPLE_REPO / "Dockerfile").exists(), "Missing Dockerfile fixture (root container)"
    assert (SAMPLE_REPO / "app.py").exists(), "Missing app.py fixture (SQL injection)"
    assert (SAMPLE_REPO / "package.json").exists(), "Missing package.json fixture (supply chain)"


@pytest.mark.asyncio
async def test_compliance_gate_returns_result():
    """compliance_gate over sample_repo must return a structured result dict."""
    from compliance_mcp.tools.gate import compliance_gate

    result = await compliance_gate(str(SAMPLE_REPO))
    assert "decision" in result, f"compliance_gate missing 'decision': {result}"
    assert result["decision"] in ("pass", "block", "inconclusive")


@pytest.mark.asyncio
async def test_compliance_gate_blocks():
    """compliance_gate must return decision='block' when high-severity findings exist."""
    from compliance_mcp.tools.gate import compliance_gate

    result = await compliance_gate(str(SAMPLE_REPO))
    assert result["decision"] == "block", (
        f"Expected gate to block but got '{result['decision']}'. "
        f"Rationale: {result.get('rationale')}"
    )


@pytest.mark.asyncio
async def test_compliance_gate_blocking_findings_present():
    """new_findings must be non-empty when the gate blocks."""
    from compliance_mcp.tools.gate import compliance_gate

    result = await compliance_gate(str(SAMPLE_REPO))
    assert result["new_findings"], "gate blocked but new_findings list is empty"


@pytest.mark.asyncio
async def test_compliance_gate_rationale_mentions_block():
    """Gate rationale must reference the blocking condition."""
    from compliance_mcp.tools.gate import compliance_gate

    result = await compliance_gate(str(SAMPLE_REPO))
    rationale = result.get("rationale", "")
    assert any(word in rationale.lower() for word in ("critical", "high", "medium", "block")), (
        f"Rationale does not mention severity or block decision: {rationale!r}"
    )


@pytest.mark.asyncio
async def test_compliance_gate_covers_multiple_domains():
    """Stub runners must produce findings in at least three compliance domains."""
    from compliance_mcp.tools.gate import compliance_gate

    result = await compliance_gate(str(SAMPLE_REPO))
    domains_found = {f["domain"] for f in result["new_findings"]}
    assert len(domains_found) >= 3, f"Expected findings in ≥3 domains; got: {domains_found}"


@pytest.mark.asyncio
async def test_compliance_gate_high_severity_blocking():
    """Critical/high findings from planted violations must appear in new_findings."""
    from compliance_mcp.tools.gate import compliance_gate

    result = await compliance_gate(str(SAMPLE_REPO))
    high_or_above = [f for f in result["new_findings"] if f["severity"] in ("critical", "high")]
    assert high_or_above, (
        "No critical/high findings in new_findings — planted violations not detected"
    )


@pytest.mark.asyncio
async def test_compliance_gate_gdpr_lens_only():
    """Running only the gdpr lens returns findings from that stub only."""
    from compliance_mcp.tools.gate import compliance_gate

    result = await compliance_gate(str(SAMPLE_REPO), lenses=["gdpr"])
    # GDPR stub produces CRITICAL and HIGH findings → must block
    assert result["decision"] == "block"
    for f in result["new_findings"]:
        assert f["lens"] == "gdpr", f"Expected only gdpr findings; got {f['lens']}"


@pytest.mark.asyncio
async def test_supply_chain_domain_present():
    """ISO27001 stub must surface a supply_chain domain finding."""
    from compliance_mcp.tools.gate import compliance_gate

    result = await compliance_gate(str(SAMPLE_REPO), lenses=["iso27001"])
    domains = {f["domain"] for f in result["new_findings"]}
    assert "supply_chain" in domains, (
        f"Expected supply_chain domain from ISO27001 stub; domains found: {domains}"
    )


@pytest.mark.asyncio
async def test_compliance_gate_pass_when_threshold_above_findings():
    """compliance_gate must return 'pass' when all findings are below the threshold."""
    from compliance_mcp import registry as _reg
    from compliance_mcp.tools.gate import compliance_gate

    async def _low_only_stub(project_path: str, config) -> list[Finding]:  # noqa: ANN001
        return [
            Finding(
                lens=Lens.GDPR,
                domain=Domain.DOCUMENTATION,
                rule_id="test.low.only",
                file_path="README.md",
                line_start=1,
                severity=Severity.LOW,
                title="Minor documentation gap",
                message="Low-severity issue only",
                control_refs=[],
            )
        ]

    _reg._REGISTRY.clear()
    _reg._REGISTRY[Lens.GDPR] = _low_only_stub
    result = await compliance_gate(str(SAMPLE_REPO), lenses=["gdpr"], severity_threshold="critical")
    assert result["decision"] == "pass", (
        f"Expected 'pass' for low-only findings below critical threshold, got '{result['decision']}'"
    )


@pytest.mark.asyncio
async def test_compliance_gate_inconclusive_when_no_lenses_registered():
    """compliance_gate must return 'inconclusive' when no lens runners exist."""
    from compliance_mcp import registry as _reg
    from compliance_mcp.tools.gate import compliance_gate

    _reg._REGISTRY.clear()
    result = await compliance_gate(str(SAMPLE_REPO))
    assert result["decision"] == "inconclusive", (
        f"Expected 'inconclusive' for empty registry, got '{result['decision']}'"
    )


@pytest.mark.asyncio
async def test_generate_report_returns_markdown():
    """generate_report must return a non-empty markdown string."""
    from compliance_mcp.tools.gate import generate_report

    result = await generate_report(str(SAMPLE_REPO), output_format="markdown")
    assert "content" in result, f"generate_report missing 'content' key: {result}"
    content = result["content"]
    assert isinstance(content, str) and content.strip(), "report content is empty"
    assert result["format"] in ("markdown", "md")


@pytest.mark.asyncio
async def test_report_cites_gate_decision():
    """The generated report must include the gate decision."""
    from compliance_mcp.tools.gate import generate_report

    result = await generate_report(str(SAMPLE_REPO), output_format="markdown")
    content = result["content"]
    assert any(word in content.upper() for word in ("BLOCK", "PASS", "INCONCLUSIVE")), (
        "Report does not cite the gate decision"
    )


@pytest.mark.asyncio
async def test_report_cites_control_refs():
    """The generated report must mention at least one control reference from stub findings."""
    from compliance_mcp.tools.gate import generate_report

    result = await generate_report(str(SAMPLE_REPO), output_format="markdown")
    content = result["content"]
    expected_controls = ["SOC2-CC6.1", "GDPR Art. 32", "ISO27001"]
    found = [ctrl for ctrl in expected_controls if ctrl in content]
    assert found, (
        f"Report does not cite any expected controls. Checked: {expected_controls}\n"
        f"Report snippet:\n{content[:800]}"
    )


@pytest.mark.asyncio
async def test_report_mentions_finding_titles():
    """The generated report must include finding titles from stub runners."""
    from compliance_mcp.tools.gate import generate_report

    result = await generate_report(str(SAMPLE_REPO), output_format="markdown")
    content = result["content"]
    assert any(
        phrase in content
        for phrase in ("Hardcoded credentials", "SQL injection", "Secrets committed")
    ), f"Report does not mention expected finding titles. Snippet:\n{content[:800]}"


@pytest.mark.asyncio
async def test_generate_report_json_format():
    """generate_report with format='json' must return JSON-parseable content."""
    import json

    from compliance_mcp.tools.gate import generate_report

    result = await generate_report(str(SAMPLE_REPO), output_format="json")
    assert result["format"] == "json"
    parsed = json.loads(result["content"])
    assert isinstance(parsed, dict), "JSON report must be a JSON object"
