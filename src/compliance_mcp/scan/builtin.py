"""Built-in lens wiring — the integration seam between the scanner lenses and
the two execution engines (orchestrator + registry).

Two engines historically grew in parallel and were never connected:

* the **orchestrator** engine (:mod:`compliance_mcp.scan.orchestrator`) runs
  synchronous :class:`~compliance_mcp.scan.lens.LensProtocol` scanners and backs
  ``scan_project`` / ``scan_diff``;
* the **registry** engine (:mod:`compliance_mcp.registry`) runs async runners
  keyed by :class:`~compliance_mcp.models.finding.Lens` (a *framework*) and backs
  ``compliance_gate`` / ``generate_report``.

This module makes every real scanner conform to ``LensProtocol`` (adapting the
policy-as-code and i18n lenses, which were written against different contracts)
and registers them with *both* engines so a wired server actually scans.

Framework → scanner assignment for the registry is 1-to-1 per scanner so the
default ``enabled_lenses`` (``gdpr``/``soc2``/``iso27001``) runs every scanner
exactly once, with no double-counted findings.  Each scanner still tags its own
findings with its true ``Finding.lens`` (e.g. ``owasp`` for Semgrep); the
framework key only selects *which* scanners run.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from compliance_mcp.config import ComplianceSettings
from compliance_mcp.i18n._types import ScanContext
from compliance_mcp.i18n._types import Severity as StubSeverity
from compliance_mcp.lenses.i18n import I18nLens
from compliance_mcp.lenses.policy_as_code import PolicyAsCodeLens
from compliance_mcp.lenses.security import SecurityLens
from compliance_mcp.lenses.supply_chain import SupplyChainLens
from compliance_mcp.models.finding import Domain, Finding, Lens, Severity
from compliance_mcp.registry import lens as _register_lens
from compliance_mcp.scan.lens import LensProtocol, LensResult, LensStatus

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

log = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[3]

# Source-file extensions the i18n lens cares about, and directories never worth
# walking into.  Keeps the file gather bounded on real projects.
_I18N_EXTENSIONS = frozenset(
    {".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".html", ".css", ".py"}
)
_SKIP_DIRS = frozenset(
    {".git", "node_modules", "dist", "build", ".venv", "venv", "__pycache__", ".tox"}
)
_MAX_I18N_FILES = 5000

# Stub-severity (error/warning/info) → real Severity.
_STUB_SEVERITY_MAP = {
    StubSeverity.ERROR: Severity.HIGH,
    StubSeverity.WARNING: Severity.MEDIUM,
    StubSeverity.INFO: Severity.INFO,
}


def _gather_source_files(root: Path) -> list[Path]:
    """Collect i18n-relevant source files under *root*, skipping vendored dirs."""
    files: list[Path] = []
    for path in root.rglob("*"):
        if len(files) >= _MAX_I18N_FILES:
            log.warning("i18n scan: file cap (%d) reached — truncating", _MAX_I18N_FILES)
            break
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and path.suffix in _I18N_EXTENSIONS:
            files.append(path)
    return files


class I18nScannerLens:
    """Adapt :class:`~compliance_mcp.lenses.i18n.I18nLens` to ``LensProtocol``.

    The underlying lens emits stub-typed findings against a ``ScanContext``;
    this adapter builds that context from a target directory and translates each
    stub finding into a real :class:`~compliance_mcp.models.finding.Finding`.
    """

    name = "i18n"
    domain = "i18n"

    def __init__(self, settings: ComplianceSettings | None = None) -> None:
        self._lens = I18nLens()
        self._required_locales = list(settings.required_locales) if settings else ["en"]

    def applicable(self, target: Path) -> bool:
        return target.is_dir()

    def run(self, target: Path) -> LensResult:
        try:
            files = _gather_source_files(target)
            ctx = ScanContext(
                root=target,
                files=files,
                config={"i18n": {"required_locales": self._required_locales}},
            )
            stub_findings = self._lens.run(ctx)
        except Exception as exc:  # noqa: BLE001 — degrade, never break the scan
            log.exception("i18n lens raised unexpectedly")
            return LensResult.errored(f"i18n lens error: {exc}")

        findings = [self._to_finding(f) for f in stub_findings]
        return LensResult.ran(findings)

    @staticmethod
    def _to_finding(stub: object) -> Finding:
        severity = _STUB_SEVERITY_MAP.get(getattr(stub, "severity", None), Severity.INFO)
        rule_id = getattr(stub, "rule_id", "") or "i18n/unknown"
        message = getattr(stub, "message", "") or ""
        detail = getattr(stub, "detail", "") or ""
        return Finding(
            lens=Lens.CUSTOM,
            domain=Domain.OTHER,
            rule_id=rule_id,
            file_path=str(getattr(stub, "path", "") or "."),
            line_start=max(1, int(getattr(stub, "line", 1) or 1)),
            severity=severity,
            title=(message or rule_id)[:200],
            message=detail or message,
            suggestion=getattr(stub, "suggestion", "") or "",
        )


class PolicyAsCodeScannerLens:
    """Adapt :class:`~compliance_mcp.lenses.policy_as_code.PolicyAsCodeLens`
    (which exposes ``scan()`` and already emits real ``Finding`` objects) to
    ``LensProtocol``."""

    name = "policy-as-code"
    domain = "policy"

    def __init__(self, rules_dir: Path | None = None) -> None:
        self._lens = PolicyAsCodeLens(rules_dir=rules_dir or (_REPO_ROOT / "policies" / "rules"))

    def applicable(self, target: Path) -> bool:
        return target.is_dir()

    def run(self, target: Path) -> LensResult:
        try:
            findings = self._lens.scan(target)
        except Exception as exc:  # noqa: BLE001
            log.exception("policy-as-code lens raised unexpectedly")
            return LensResult.errored(f"policy-as-code lens error: {exc}")
        return LensResult.ran(findings)


def build_default_lenses(settings: ComplianceSettings | None = None) -> list[LensProtocol]:
    """Construct every built-in scanner as a ``LensProtocol`` instance.

    A scanner that fails to construct (missing policy dir, bad ruleset, …) is
    logged and skipped rather than aborting the whole scan — consistent with the
    lens degradation model.
    """
    builders: list[tuple[str, Callable[[], LensProtocol]]] = [
        ("security", SecurityLens),
        ("supply-chain", SupplyChainLens),
        ("policy-as-code", PolicyAsCodeScannerLens),
        ("i18n", lambda: I18nScannerLens(settings)),
    ]
    lenses: list[LensProtocol] = []
    for name, build in builders:
        try:
            lenses.append(build())
        except Exception:  # noqa: BLE001
            log.exception("Failed to construct lens '%s' — skipping", name)
    return lenses


# Framework → scanner names.  1-to-1 coverage so the default enabled set runs
# every scanner exactly once.  Scanners not listed under any enabled framework
# simply do not run.
_FRAMEWORK_LENSES: dict[Lens, tuple[str, ...]] = {
    Lens.GDPR: ("i18n",),
    Lens.SOC2: ("security", "policy-as-code"),
    Lens.ISO27001: ("supply-chain",),
}


def _make_runner(
    lenses: list[LensProtocol],
) -> Callable[[str, ComplianceSettings], Awaitable[list[Finding]]]:
    async def _runner(project_path: str, settings: ComplianceSettings) -> list[Finding]:  # noqa: ARG001
        target = Path(project_path)
        findings: list[Finding] = []
        for lens in lenses:
            if not lens.applicable(target):
                continue
            result = await asyncio.to_thread(lens.run, target)
            if result.status == LensStatus.RAN:
                findings.extend(result.findings)
        return findings

    return _runner


def register_default_runners(settings: ComplianceSettings | None = None) -> int:
    """Register async runners into the lens registry for ``compliance_gate`` /
    ``generate_report``.

    Returns the number of framework runners registered.  Idempotent: registering
    the same framework twice just overwrites the prior runner.
    """
    all_lenses = {lens.name: lens for lens in build_default_lenses(settings)}
    count = 0
    for framework, names in _FRAMEWORK_LENSES.items():
        selected = [all_lenses[n] for n in names if n in all_lenses]
        if not selected:
            continue
        runner = _make_runner(selected)
        _register_lens(framework)(runner)
        count += 1
    return count
