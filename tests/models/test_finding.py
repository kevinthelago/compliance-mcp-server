"""Tests for Finding model and enums (SC-2)."""

from __future__ import annotations

import pytest

from compliance_mcp.models.finding import Domain, Finding, Lens, Severity


class TestSeverity:
    def test_rank_order(self):
        assert Severity.CRITICAL.rank > Severity.HIGH.rank
        assert Severity.HIGH.rank > Severity.MEDIUM.rank
        assert Severity.MEDIUM.rank > Severity.LOW.rank
        assert Severity.LOW.rank > Severity.INFO.rank

    def test_ge_comparison(self):
        assert Severity.HIGH >= Severity.MEDIUM
        assert Severity.MEDIUM >= Severity.MEDIUM
        assert not (Severity.LOW >= Severity.HIGH)

    def test_string_values(self):
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"


class TestFinding:
    def test_fingerprint_is_computed(self, minimal_finding: Finding):
        assert len(minimal_finding.fingerprint) == 64  # SHA-256 hex

    def test_fingerprint_is_deterministic(self, minimal_finding: Finding):
        f2 = Finding(
            lens=Lens.GDPR,
            domain=Domain.DATA_PROTECTION,
            rule_id="gdpr.data-retention",
            file_path="src/db/user_repo.py",
            line_start=42,
            severity=Severity.HIGH,
            title="Unlimited data retention",
        )
        assert minimal_finding.fingerprint == f2.fingerprint

    def test_fingerprint_changes_with_identity_field(self, minimal_finding: Finding):
        different_rule = Finding(
            lens=Lens.GDPR,
            domain=Domain.DATA_PROTECTION,
            rule_id="gdpr.different-rule",
            file_path="src/db/user_repo.py",
            line_start=42,
            severity=Severity.HIGH,
            title="Something else",
        )
        assert minimal_finding.fingerprint != different_rule.fingerprint

    def test_fingerprint_stable_across_message_changes(self, minimal_finding: Finding):
        """Presentation fields must NOT affect the fingerprint."""
        with_message = Finding(
            lens=minimal_finding.lens,
            domain=minimal_finding.domain,
            rule_id=minimal_finding.rule_id,
            file_path=minimal_finding.file_path,
            line_start=minimal_finding.line_start,
            severity=minimal_finding.severity,
            title=minimal_finding.title,
            message="A completely different message",
            suggestion="A different suggestion",
        )
        assert minimal_finding.fingerprint == with_message.fingerprint

    def test_fingerprint_changes_with_line(self, minimal_finding: Finding):
        different_line = Finding(
            **{
                **minimal_finding.model_dump(exclude={"fingerprint"}),
                "line_start": 99,
            }
        )
        assert minimal_finding.fingerprint != different_line.fingerprint

    def test_fingerprint_normalises_path_separators(self):
        """Windows-style paths are normalised to POSIX before hashing."""
        f_posix = Finding(
            lens=Lens.SOC2,
            domain=Domain.ACCESS_CONTROL,
            rule_id="soc2.CC6.1",
            file_path="src/auth/login.py",
            line_start=1,
            severity=Severity.MEDIUM,
            title="Missing MFA",
        )
        f_win = Finding(
            lens=Lens.SOC2,
            domain=Domain.ACCESS_CONTROL,
            rule_id="soc2.CC6.1",
            file_path="src\\auth\\login.py",
            line_start=1,
            severity=Severity.MEDIUM,
            title="Missing MFA",
        )
        # PurePosixPath normalises backslashes to forward slashes on all platforms
        # so fingerprints should match
        assert f_posix.fingerprint == f_win.fingerprint

    def test_model_is_frozen(self, minimal_finding: Finding):
        with pytest.raises((TypeError, AttributeError, ValueError)):
            minimal_finding.severity = Severity.CRITICAL  # type: ignore[misc]

    def test_control_refs_default_empty(self, minimal_finding: Finding):
        assert minimal_finding.control_refs == []

    def test_lens_enum_values(self):
        assert Lens.GDPR == "gdpr"
        assert Lens.SOC2 == "soc2"
        assert Lens.ISO27001 == "iso27001"

    def test_domain_enum_values(self):
        assert Domain.DATA_PROTECTION == "data_protection"
        assert Domain.ACCESS_CONTROL == "access_control"
