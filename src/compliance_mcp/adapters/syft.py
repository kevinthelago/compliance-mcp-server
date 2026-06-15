"""Syft adapter — SBOM generation via CycloneDX JSON (SUP-1).

Runs ``syft <target> -o cyclonedx-json`` and parses the output into an
in-process :class:`SBOM` object that both the CVE pipeline (Trivy) and the
license evaluator can consume.

CycloneDX ``licenses`` array variants handled
---------------------------------------------
``{"license": {"id": "<spdx-id>"}}``        — preferred SPDX identifier
``{"license": {"name": "<free text>"}}``     — non-SPDX name (treated as-is)
``{"expression": "<compound-expression>"}``  — SPDX compound expression
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from compliance_mcp.adapters.base import AdapterResult, RunStatus, run_subprocess

log = logging.getLogger(__name__)


@dataclass
class Package:
    """A single software component from the SBOM."""

    name: str
    version: str
    purl: str | None
    licenses: list[str]


@dataclass
class SBOM:
    """Parsed CycloneDX software bill of materials."""

    target: str
    packages: list[Package] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    def as_package_dicts(self) -> list[dict[str, str]]:
        """Return packages as simple dicts for the license evaluator."""
        result = []
        for pkg in self.packages:
            license_str = " OR ".join(pkg.licenses) if pkg.licenses else ""
            result.append({"name": pkg.name, "version": pkg.version, "license": license_str})
        return result


def _extract_licenses(component: dict) -> list[str]:
    """Extract a flat list of license strings from a CycloneDX component dict."""
    licenses: list[str] = []
    for entry in component.get("licenses", []):
        if "expression" in entry:
            licenses.append(entry["expression"])
        elif "license" in entry:
            lic = entry["license"]
            if "id" in lic:
                licenses.append(lic["id"])
            elif "name" in lic:
                name = lic["name"]
                if name and name.upper() not in {"NOASSERTION", "NONE"}:
                    licenses.append(name)
    return licenses


def parse_cyclonedx(raw_json: str, target: str) -> SBOM:
    """Parse a CycloneDX JSON string into an :class:`SBOM`."""
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        log.error("failed to parse Syft CycloneDX output: %s", exc)
        return SBOM(target=target)

    packages: list[Package] = []
    for component in data.get("components", []):
        name = component.get("name", "")
        version = component.get("version", "")
        purl = component.get("purl")
        licenses = _extract_licenses(component)
        if name:
            packages.append(Package(name=name, version=version, purl=purl, licenses=licenses))

    return SBOM(target=target, packages=packages, raw=data)


class SyftAdapter:
    """Generates an SBOM for *target* using Syft.

    Parameters
    ----------
    timeout:
        Max seconds to wait for Syft (default 120 — SBOM generation is slow).
    emit_artifact:
        When True, write the CycloneDX JSON to *target*/sbom.cdx.json.
    """

    def __init__(self, *, timeout: int = 120, emit_artifact: bool = False) -> None:
        self._timeout = timeout
        self._emit_artifact = emit_artifact

    def run(self, target: Path) -> tuple[AdapterResult, SBOM | None]:
        """Run Syft against *target* and return *(AdapterResult, SBOM | None)*.

        Returns ``(result, None)`` when the binary is absent or Syft crashes.
        """
        result = run_subprocess(
            ["syft", str(target), "-o", "cyclonedx-json"],
            timeout=self._timeout,
        )

        if result.status == RunStatus.NOT_RUN:
            return result, None

        if result.status == RunStatus.ERRORED:
            log.error("Syft failed (rc=%d): %s", result.returncode, result.stderr[:200])
            return result, None

        # Syft exits 0 even when it finds packages; treat OK and FINDINGS the same
        sbom = parse_cyclonedx(result.stdout, str(target))

        if self._emit_artifact:
            artifact = Path(target) / "sbom.cdx.json"
            try:
                artifact.write_text(result.stdout, encoding="utf-8")
                log.info("SBOM written to %s", artifact)
            except OSError as exc:
                log.warning("could not write SBOM artifact: %s", exc)

        return result, sbom
