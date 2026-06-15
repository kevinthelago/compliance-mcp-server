"""Tests for config loading (SC-3)."""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from compliance_mcp.config import load_settings
from compliance_mcp.models.finding import Lens, Severity


class TestLoadSettings:
    def test_defaults_without_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.chdir(tmp_path)
        s = load_settings()
        assert Lens.GDPR in s.enabled_lenses
        assert s.severity_threshold == Severity.MEDIUM
        assert s.concurrency_cap == 8

    def test_loads_from_toml(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        toml = textwrap.dedent("""\
            [compliance]
            enabled_lenses = ["hipaa", "pci_dss"]
            severity_threshold = "critical"
            concurrency_cap = 4
        """)
        (tmp_path / "compliance.toml").write_text(toml)
        monkeypatch.chdir(tmp_path)
        s = load_settings()
        assert Lens.HIPAA in s.enabled_lenses
        assert Lens.PCI_DSS in s.enabled_lenses
        assert s.severity_threshold == Severity.CRITICAL
        assert s.concurrency_cap == 4

    def test_env_overrides_toml(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        toml = textwrap.dedent("""\
            [compliance]
            severity_threshold = "low"
        """)
        (tmp_path / "compliance.toml").write_text(toml)
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COMPLIANCE_SEVERITY_THRESHOLD", "critical")
        s = load_settings()
        assert s.severity_threshold == Severity.CRITICAL

    def test_invalid_lens_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        toml = textwrap.dedent("""\
            [compliance]
            enabled_lenses = ["not_a_real_lens"]
        """)
        (tmp_path / "compliance.toml").write_text(toml)
        monkeypatch.chdir(tmp_path)
        with pytest.raises((ValueError, Exception)):
            load_settings()

    def test_concurrency_cap_lower_bound(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        toml = textwrap.dedent("""\
            [compliance]
            concurrency_cap = 0
        """)
        (tmp_path / "compliance.toml").write_text(toml)
        monkeypatch.chdir(tmp_path)
        with pytest.raises((ValueError, Exception)):
            load_settings()

    def test_custom_config_file(self, tmp_path: Path):
        cfg = tmp_path / "custom.toml"
        cfg.write_text('[compliance]\nseverity_threshold = "high"\n')
        s = load_settings(config_file=cfg)
        assert s.severity_threshold == Severity.HIGH
