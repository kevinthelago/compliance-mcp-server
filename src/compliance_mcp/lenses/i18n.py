"""I18N-5: I18nLens — compose all i18n/l10n sub-checks into a single Lens.

Registers as a Lens against the scan-orchestration Lens protocol (SO-1).
Falls back to a stub protocol during parallel development before server-core
and scan-orchestration streams have merged.
"""

from __future__ import annotations

from compliance_mcp.i18n.catalog_coverage import check_catalog_coverage
from compliance_mcp.i18n.framework_detection import FrameworkInfo, detect_framework
from compliance_mcp.i18n.hardcoded_strings import check_hardcoded_strings
from compliance_mcp.i18n.locale_formatting import check_locale_formatting
from compliance_mcp.i18n.rtl_css import check_rtl_css

try:
    from compliance_mcp.lenses import register  # type: ignore[import]
    from compliance_mcp.models import Finding, ScanContext, Severity  # type: ignore[import]

    _HAS_REAL_LENS = True
except ImportError:
    from compliance_mcp.i18n._types import (  # type: ignore[assignment]
        Finding,
        ScanContext,
        Severity,
    )

    _HAS_REAL_LENS = False

    def register(cls: type) -> type:  # type: ignore[misc]
        """No-op decorator — replaced when scan-orchestration lands."""
        return cls


# Severity threshold below which heuristic findings are downgraded to INFO
_HEURISTIC_DOWNGRADE_CONFIDENCES = frozenset({"low"})


class I18nLens:
    """Lens that checks a codebase for i18n/l10n issues.

    Sub-checks (all four run in sequence):
    - I18N-1: hardcoded user-facing string literals
    - I18N-2: non-locale-aware date/number/currency formatting
    - I18N-3: i18n catalog coverage across required locales
    - I18N-4: physical directional CSS properties (RTL)
    """

    name = "i18n"

    def run(self, ctx: ScanContext) -> list[Finding]:
        i18n_config: dict = ctx.config.get("i18n", {})
        framework: FrameworkInfo = detect_framework(ctx.root)

        raw: list[Finding] = []
        raw.extend(check_hardcoded_strings(ctx, framework, i18n_config))
        raw.extend(check_locale_formatting(ctx, framework))
        raw.extend(check_catalog_coverage(ctx, i18n_config))
        raw.extend(check_rtl_css(ctx, i18n_config))

        return [_apply_severity_policy(f, i18n_config) for f in raw]


def _apply_severity_policy(finding: Finding, config: dict) -> Finding:
    """Downgrade low-confidence heuristic findings to INFO unless policy elevates them.

    The ``i18n.elevate_heuristics`` config key (bool, default False) overrides
    this behaviour and preserves the original severity.
    """
    if config.get("elevate_heuristics", False):
        return finding

    confidence = finding.extra.get("confidence", "")
    if confidence in _HEURISTIC_DOWNGRADE_CONFIDENCES:
        # Return a new Finding with INFO severity
        return Finding(
            rule_id=finding.rule_id,
            path=finding.path,
            line=finding.line,
            col=finding.col,
            severity=Severity.INFO,
            message=finding.message,
            detail=finding.detail,
            suggestion=finding.suggestion,
            extra=finding.extra,
        )
    return finding


# Register the lens so that the scan orchestrator can discover it
if _HAS_REAL_LENS:  # pragma: no cover
    register(I18nLens)
