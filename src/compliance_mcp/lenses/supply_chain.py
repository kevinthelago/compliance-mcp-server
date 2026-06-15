"""Supply-chain lens — composes Syft SBOM + Trivy CVEs + license evaluation (SUP-4).

The SBOM is generated exactly once by :class:`SyftAdapter` and fed to both:
  - :class:`TrivyAdapter` for CVE scanning (Trivy reads the project itself, not
    the SBOM directly, but runs in parallel with Syft)
  - :class:`LicenseEvaluator` which consumes the SBOM package list

Lens status aggregation
-----------------------
======================  =====================================================
Condition               LensStatus
======================  =====================================================
Both Syft + Trivy run   RAN (even if Trivy is degraded)
Only one sub-scanner    RAN (with diagnostics noting the absent binary)
Both absent / errored   NOT_RUN
======================  =====================================================
"""

from __future__ import annotations

import logging
from pathlib import Path

from compliance_mcp.adapters.base import RunStatus
from compliance_mcp.adapters.syft import SyftAdapter
from compliance_mcp.adapters.trivy import TrivyAdapter
from compliance_mcp.licenses.evaluator import LicenseEvaluator
from compliance_mcp.models.finding import Finding
from compliance_mcp.scan.lens import LensResult, LensStatus

log = logging.getLogger(__name__)

_DEFAULT_POLICY_DIR = Path(__file__).parent.parent.parent.parent.parent / "policies" / "licenses"


class SupplyChainLens:
    """Implements the LensProtocol for supply-chain scanning.

    Parameters
    ----------
    policy_dir:
        Directory containing ``allow.yaml``, ``deny.yaml``, and ``review.yaml``.
        Defaults to ``<repo-root>/policies/licenses/``.
    syft_adapter:
        Custom :class:`SyftAdapter` instance (useful for testing).
    trivy_adapter:
        Custom :class:`TrivyAdapter` instance (useful for testing).
    emit_sbom:
        When True, write ``sbom.cdx.json`` to the scan target directory.
    """

    name = "supply-chain"
    domain = "supply_chain"

    def __init__(
        self,
        *,
        policy_dir: Path | None = None,
        syft_adapter: SyftAdapter | None = None,
        trivy_adapter: TrivyAdapter | None = None,
        emit_sbom: bool = False,
    ) -> None:
        self._policy_dir = policy_dir or _DEFAULT_POLICY_DIR
        self._syft = syft_adapter or SyftAdapter(emit_artifact=emit_sbom)
        self._trivy = trivy_adapter or TrivyAdapter()
        self._evaluator = LicenseEvaluator(self._policy_dir)

    def applicable(self, target: Path) -> bool:
        """Always applicable — supply-chain scanning works on any directory."""
        return target.is_dir()

    def run(self, target: Path) -> LensResult:
        """Run the full supply-chain analysis against *target*.

        1. Generate SBOM with Syft (packages + licenses)
        2. Scan for CVEs with Trivy (runs against the project directly)
        3. Evaluate licenses via the SBOM package list
        4. Aggregate findings and status
        """
        all_findings: list[Finding] = []
        diagnostics_parts: list[str] = []
        ran_count = 0

        # ── Step 1: SBOM via Syft ────────────────────────────────────────────
        syft_result, sbom = self._syft.run(target)

        if syft_result.status == RunStatus.NOT_RUN:
            diagnostics_parts.append("syft binary not found — SBOM and license scan skipped")
            log.warning("supply-chain lens: syft not found")
        elif syft_result.status == RunStatus.ERRORED:
            diagnostics_parts.append(f"syft failed: {syft_result.stderr[:100]}")
            log.error("supply-chain lens: syft error: %s", syft_result.stderr[:100])
        else:
            ran_count += 1

        # ── Step 2: CVEs via Trivy ───────────────────────────────────────────
        trivy_result, cve_findings = self._trivy.run(target)

        if trivy_result.status == RunStatus.NOT_RUN:
            diagnostics_parts.append("trivy binary not found — CVE scan skipped")
            log.warning("supply-chain lens: trivy not found")
        elif trivy_result.status == RunStatus.ERRORED:
            diagnostics_parts.append(f"trivy failed: {trivy_result.stderr[:100]}")
            log.error("supply-chain lens: trivy error: %s", trivy_result.stderr[:100])
        else:
            if trivy_result.degraded:
                diagnostics_parts.append(f"trivy degraded: {trivy_result.degraded_reason}")
            ran_count += 1
            all_findings.extend(cve_findings)

        # ── Step 3: License evaluation from SBOM ────────────────────────────
        if sbom is not None:
            packages = sbom.as_package_dicts()
            license_findings = self._evaluator.evaluate(packages, target=str(target))
            all_findings.extend(license_findings)

        # ── Aggregate status ─────────────────────────────────────────────────
        status = LensStatus.NOT_RUN if ran_count == 0 else LensStatus.RAN

        diagnostics = "; ".join(diagnostics_parts) if diagnostics_parts else None

        return LensResult(
            status=status,
            findings=all_findings,
            diagnostics=diagnostics,
        )
