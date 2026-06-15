"""Tests for the Syft adapter (SUP-1)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from compliance_mcp.adapters.base import AdapterResult, RunStatus
from compliance_mcp.adapters.syft import SyftAdapter, parse_cyclonedx

# ── parse_cyclonedx unit tests ────────────────────────────────────────────────


def test_parse_cyclonedx_packages(cyclonedx_fixture_json: str) -> None:
    sbom = parse_cyclonedx(cyclonedx_fixture_json, target=".")
    assert len(sbom.packages) == 5
    names = {p.name for p in sbom.packages}
    assert "requests" in names
    assert "gpl-lib" in names


def test_parse_cyclonedx_license_id(cyclonedx_fixture_json: str) -> None:
    sbom = parse_cyclonedx(cyclonedx_fixture_json, target=".")
    requests = next(p for p in sbom.packages if p.name == "requests")
    assert "Apache-2.0" in requests.licenses


def test_parse_cyclonedx_license_name(cyclonedx_fixture_json: str) -> None:
    sbom = parse_cyclonedx(cyclonedx_fixture_json, target=".")
    unknown = next(p for p in sbom.packages if p.name == "unknown-lib")
    assert "Proprietary" in unknown.licenses


def test_parse_cyclonedx_license_expression(cyclonedx_fixture_json: str) -> None:
    sbom = parse_cyclonedx(cyclonedx_fixture_json, target=".")
    multi = next(p for p in sbom.packages if p.name == "multi-license-lib")
    assert "MIT OR Apache-2.0" in multi.licenses


def test_parse_cyclonedx_purl(cyclonedx_fixture_json: str) -> None:
    sbom = parse_cyclonedx(cyclonedx_fixture_json, target=".")
    requests = next(p for p in sbom.packages if p.name == "requests")
    assert requests.purl == "pkg:pypi/requests@2.28.0"


def test_parse_cyclonedx_invalid_json() -> None:
    sbom = parse_cyclonedx("not json at all", target=".")
    assert sbom.packages == []


def test_parse_cyclonedx_empty_components() -> None:
    data = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []})
    sbom = parse_cyclonedx(data, target=".")
    assert sbom.packages == []


def test_sbom_as_package_dicts(cyclonedx_fixture_json: str) -> None:
    sbom = parse_cyclonedx(cyclonedx_fixture_json, target=".")
    dicts = sbom.as_package_dicts()
    assert all(isinstance(d, dict) for d in dicts)
    assert all("name" in d and "version" in d and "license" in d for d in dicts)


def test_sbom_as_package_dicts_joins_multiple_licenses() -> None:
    data = json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {
                    "name": "dual",
                    "version": "1.0",
                    "purl": "pkg:pypi/dual@1.0",
                    "licenses": [
                        {"license": {"id": "MIT"}},
                        {"license": {"id": "Apache-2.0"}},
                    ],
                }
            ],
        }
    )
    sbom = parse_cyclonedx(data, target=".")
    pkg_dicts = sbom.as_package_dicts()
    assert pkg_dicts[0]["license"] == "MIT OR Apache-2.0"


# ── SyftAdapter integration (binary stubbed) ──────────────────────────────────


def test_syft_adapter_not_run_when_binary_absent() -> None:
    adapter = SyftAdapter()
    with patch("compliance_mcp.adapters.base.shutil.which", return_value=None):
        result, sbom = adapter.run(Path("."))
    assert result.status == RunStatus.NOT_RUN
    assert sbom is None


def test_syft_adapter_returns_sbom_on_success(cyclonedx_fixture_json: str) -> None:
    adapter = SyftAdapter()
    fake_result = AdapterResult(
        status=RunStatus.OK,
        stdout=cyclonedx_fixture_json,
        returncode=0,
    )
    with patch("compliance_mcp.adapters.syft.run_subprocess", return_value=fake_result):
        result, sbom = adapter.run(Path("."))
    assert result.status == RunStatus.OK
    assert sbom is not None
    assert len(sbom.packages) == 5


def test_syft_adapter_errored_returns_none() -> None:
    adapter = SyftAdapter()
    fake_result = AdapterResult(
        status=RunStatus.ERRORED,
        stderr="syft crashed",
        returncode=2,
    )
    with patch("compliance_mcp.adapters.syft.run_subprocess", return_value=fake_result):
        result, sbom = adapter.run(Path("."))
    assert result.status == RunStatus.ERRORED
    assert sbom is None


def test_syft_adapter_emit_artifact(tmp_path: Path, cyclonedx_fixture_json: str) -> None:
    adapter = SyftAdapter(emit_artifact=True)
    fake_result = AdapterResult(
        status=RunStatus.OK,
        stdout=cyclonedx_fixture_json,
        returncode=0,
    )
    with patch("compliance_mcp.adapters.syft.run_subprocess", return_value=fake_result):
        adapter.run(tmp_path)
    artifact = tmp_path / "sbom.cdx.json"
    assert artifact.exists()
    assert json.loads(artifact.read_text())["bomFormat"] == "CycloneDX"
