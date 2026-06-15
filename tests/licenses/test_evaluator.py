"""Tests for the license evaluator (SUP-3)."""

from __future__ import annotations

from pathlib import Path

import pytest

from compliance_mcp.licenses.evaluator import LicenseEvaluator, LicenseVerdict
from compliance_mcp.models.finding import Domain, Lens, Severity

POLICY_DIR = Path(__file__).parent.parent.parent / "policies" / "licenses"


@pytest.fixture()
def evaluator() -> LicenseEvaluator:
    return LicenseEvaluator(POLICY_DIR)


# ── Verdict tests ─────────────────────────────────────────────────────────────


def test_allowed_mit(evaluator: LicenseEvaluator) -> None:
    verdict = evaluator.judge("lib", "1.0", "MIT")
    assert verdict.verdict == LicenseVerdict.ALLOWED


def test_allowed_apache(evaluator: LicenseEvaluator) -> None:
    verdict = evaluator.judge("lib", "1.0", "Apache-2.0")
    assert verdict.verdict == LicenseVerdict.ALLOWED


def test_allowed_bsd3(evaluator: LicenseEvaluator) -> None:
    verdict = evaluator.judge("lib", "1.0", "BSD-3-Clause")
    assert verdict.verdict == LicenseVerdict.ALLOWED


def test_denied_gpl3(evaluator: LicenseEvaluator) -> None:
    verdict = evaluator.judge("lib", "1.0", "GPL-3.0-only")
    assert verdict.verdict == LicenseVerdict.DENIED
    assert "GPL-3.0-only" in verdict.matched_licenses


def test_denied_agpl(evaluator: LicenseEvaluator) -> None:
    verdict = evaluator.judge("lib", "1.0", "AGPL-3.0-only")
    assert verdict.verdict == LicenseVerdict.DENIED


def test_denied_gpl2(evaluator: LicenseEvaluator) -> None:
    verdict = evaluator.judge("lib", "1.0", "GPL-2.0-or-later")
    assert verdict.verdict == LicenseVerdict.DENIED


def test_review_lgpl21(evaluator: LicenseEvaluator) -> None:
    verdict = evaluator.judge("lib", "1.0", "LGPL-2.1-only")
    assert verdict.verdict == LicenseVerdict.REVIEW


def test_review_epl2(evaluator: LicenseEvaluator) -> None:
    verdict = evaluator.judge("lib", "1.0", "EPL-2.0")
    assert verdict.verdict == LicenseVerdict.REVIEW


def test_unknown_proprietary(evaluator: LicenseEvaluator) -> None:
    verdict = evaluator.judge("lib", "1.0", "Proprietary")
    assert verdict.verdict == LicenseVerdict.UNKNOWN


def test_unknown_empty(evaluator: LicenseEvaluator) -> None:
    verdict = evaluator.judge("lib", "1.0", "")
    assert verdict.verdict == LicenseVerdict.UNKNOWN


def test_unknown_noassertion(evaluator: LicenseEvaluator) -> None:
    verdict = evaluator.judge("lib", "1.0", "NOASSERTION")
    assert verdict.verdict == LicenseVerdict.UNKNOWN


# ── Compound expression tests ─────────────────────────────────────────────────


def test_compound_or_both_allowed(evaluator: LicenseEvaluator) -> None:
    verdict = evaluator.judge("lib", "1.0", "MIT OR Apache-2.0")
    assert verdict.verdict == LicenseVerdict.ALLOWED


def test_compound_or_one_denied(evaluator: LicenseEvaluator) -> None:
    # Conservative: if ANY alternative is denied, the package is denied
    verdict = evaluator.judge("lib", "1.0", "GPL-3.0-only OR MIT")
    assert verdict.verdict == LicenseVerdict.DENIED


def test_compound_and_one_review(evaluator: LicenseEvaluator) -> None:
    verdict = evaluator.judge("lib", "1.0", "MIT AND LGPL-2.1-only")
    assert verdict.verdict == LicenseVerdict.REVIEW


# ── Alias normalisation tests ─────────────────────────────────────────────────


def test_alias_apache_20(evaluator: LicenseEvaluator) -> None:
    verdict = evaluator.judge("lib", "1.0", "Apache 2.0")
    assert verdict.verdict == LicenseVerdict.ALLOWED


def test_alias_mit_license(evaluator: LicenseEvaluator) -> None:
    verdict = evaluator.judge("lib", "1.0", "MIT License")
    assert verdict.verdict == LicenseVerdict.ALLOWED


def test_alias_gpl2(evaluator: LicenseEvaluator) -> None:
    verdict = evaluator.judge("lib", "1.0", "gpl2")
    assert verdict.verdict == LicenseVerdict.DENIED


# ── evaluate() method tests ───────────────────────────────────────────────────


def test_evaluate_returns_findings_for_denied(evaluator: LicenseEvaluator) -> None:
    packages = [{"name": "bad-lib", "version": "1.0", "license": "GPL-3.0-only"}]
    findings = evaluator.evaluate(packages, target=".")
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].domain == Domain.SUPPLY_CHAIN
    assert findings[0].lens == Lens.CUSTOM


def test_evaluate_returns_findings_for_review(evaluator: LicenseEvaluator) -> None:
    packages = [{"name": "review-lib", "version": "1.0", "license": "LGPL-2.1-only"}]
    findings = evaluator.evaluate(packages, target=".")
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_evaluate_returns_findings_for_unknown(evaluator: LicenseEvaluator) -> None:
    packages = [{"name": "mystery-lib", "version": "1.0", "license": "Proprietary"}]
    findings = evaluator.evaluate(packages, target=".")
    assert len(findings) == 1
    assert findings[0].rule_id == "license.unknown"


def test_evaluate_no_findings_for_allowed(evaluator: LicenseEvaluator) -> None:
    packages = [{"name": "safe-lib", "version": "1.0", "license": "MIT"}]
    findings = evaluator.evaluate(packages, target=".")
    assert findings == []


def test_evaluate_mixed_packages(evaluator: LicenseEvaluator) -> None:
    packages = [
        {"name": "safe", "version": "1.0", "license": "MIT"},
        {"name": "bad", "version": "1.0", "license": "GPL-3.0-only"},
        {"name": "needs-review", "version": "1.0", "license": "LGPL-2.1-only"},
        {"name": "unknown", "version": "1.0", "license": "Proprietary"},
    ]
    findings = evaluator.evaluate(packages)
    assert len(findings) == 3
    severities = {f.severity for f in findings}
    assert Severity.HIGH in severities
    assert Severity.MEDIUM in severities


def test_evaluate_fingerprint_stable(evaluator: LicenseEvaluator) -> None:
    packages = [{"name": "bad-lib", "version": "1.0", "license": "GPL-3.0-only"}]
    f1 = evaluator.evaluate(packages)
    f2 = evaluator.evaluate(packages)
    assert f1[0].fingerprint == f2[0].fingerprint


def test_evaluate_configurable_denied_severity() -> None:
    evaluator = LicenseEvaluator(POLICY_DIR, denied_severity=Severity.CRITICAL)
    packages = [{"name": "bad-lib", "version": "1.0", "license": "GPL-3.0-only"}]
    findings = evaluator.evaluate(packages)
    assert findings[0].severity == Severity.CRITICAL


def test_evaluate_configurable_unknown_severity() -> None:
    evaluator = LicenseEvaluator(POLICY_DIR, unknown_severity=Severity.LOW)
    packages = [{"name": "mystery-lib", "version": "1.0", "license": "Proprietary"}]
    findings = evaluator.evaluate(packages)
    assert findings[0].severity == Severity.LOW
