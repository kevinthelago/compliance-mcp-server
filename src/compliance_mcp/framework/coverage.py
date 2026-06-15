"""Control coverage rollup for regulatory frameworks.

Given a list of enriched findings and a target framework, produces a per-control
status report:

- **addressed**: the control appears in the mapping catalogue and no finding
  references it (no active violations).
- **at_risk**: ≥1 finding has a ``control_refs`` entry for this control.
- **no_evidence**: the control is not referenced in the mapping catalogue at all
  (neither findings nor mapping rules cover it, so we have no data).

"Addressed" means *we know about this control* (it is in controls.yaml) *and
found no violations* — not that it was actively verified to pass.
"""

from __future__ import annotations

from enum import StrEnum

from compliance_mcp.framework.mapping import SUPPORTED_FRAMEWORKS, ControlMapping
from compliance_mcp.models.finding import Finding


class ControlStatus(StrEnum):
    ADDRESSED = "addressed"
    AT_RISK = "at_risk"
    NO_EVIDENCE = "no_evidence"


class ControlCoverageError(ValueError):
    """Raised when an unknown framework is requested."""


def _parse_ref(ref: str) -> tuple[str, str] | None:
    """Split ``"framework:control_id"`` into ``(framework, control_id)``.

    Returns None for malformed refs.
    """
    parts = ref.split(":", 1)
    if len(parts) != 2:
        return None
    return parts[0], parts[1]


def compute_coverage(
    findings: list[Finding],
    framework: str,
    mapping: ControlMapping,
) -> dict:
    """Compute per-control coverage for *framework* over *findings*.

    Parameters
    ----------
    findings:
        Enriched findings (after :func:`~compliance_mcp.framework.mapper.enrich_findings`).
    framework:
        One of ``soc2``, ``iso27001``, ``hipaa``, ``pci_dss``, ``gdpr``.
    mapping:
        Loaded :class:`~compliance_mcp.framework.mapping.ControlMapping`.

    Returns
    -------
    dict
        ``{
          "framework": str,
          "controls": {
            "<control_id>": {
              "status": "addressed" | "at_risk" | "no_evidence",
              "title": str,
              "findings_count": int,
              "max_severity": str | None,
            }
          },
          "summary": {
            "addressed": int,
            "at_risk": int,
            "no_evidence": int,
            "total": int,
          }
        }``

    Raises
    ------
    ControlCoverageError
        If *framework* is not in the supported list.
    """
    if framework not in SUPPORTED_FRAMEWORKS:
        raise ControlCoverageError(
            f"Unknown framework {framework!r}. Supported frameworks: {sorted(SUPPORTED_FRAMEWORKS)}"
        )

    # Index findings by control_id for this framework
    violations: dict[str, list[Finding]] = {}
    for finding in findings:
        for ref in finding.control_refs:
            parsed = _parse_ref(ref)
            if parsed is None:
                continue
            ref_fw, ctrl_id = parsed
            if ref_fw == framework:
                violations.setdefault(ctrl_id, []).append(finding)

    # Build per-control report from the catalogue
    ctrl_defs = mapping.controls_for_framework(framework)
    controls_report: dict[str, dict] = {}

    for ctrl_id, ctrl_def in sorted(ctrl_defs.items()):
        ctrl_findings = violations.get(ctrl_id, [])
        if ctrl_findings:
            max_sev = max(ctrl_findings, key=lambda f: f.severity.rank).severity
            status = ControlStatus.AT_RISK
        else:
            max_sev = None
            status = ControlStatus.ADDRESSED

        controls_report[ctrl_id] = {
            "status": status.value,
            "title": ctrl_def.title,
            "findings_count": len(ctrl_findings),
            "max_severity": max_sev.value if max_sev else None,
        }

    # Controls referenced in findings but NOT in the catalogue → no_evidence
    catalogue_ids = set(ctrl_defs)
    for ctrl_id in violations:
        if ctrl_id not in catalogue_ids:
            ctrl_findings = violations[ctrl_id]
            max_sev = max(ctrl_findings, key=lambda f: f.severity.rank).severity
            controls_report[ctrl_id] = {
                "status": ControlStatus.AT_RISK.value,
                "title": ctrl_id,
                "findings_count": len(ctrl_findings),
                "max_severity": max_sev.value,
            }

    # Summary counts
    counts = {
        ControlStatus.ADDRESSED.value: 0,
        ControlStatus.AT_RISK.value: 0,
        ControlStatus.NO_EVIDENCE.value: 0,
    }
    for entry in controls_report.values():
        counts[entry["status"]] += 1

    return {
        "framework": framework,
        "controls": controls_report,
        "summary": {
            "addressed": counts[ControlStatus.ADDRESSED.value],
            "at_risk": counts[ControlStatus.AT_RISK.value],
            "no_evidence": counts[ControlStatus.NO_EVIDENCE.value],
            "total": len(controls_report),
        },
    }


def explain_control_entry(
    framework: str,
    control_id: str,
    mapping: ControlMapping,
) -> dict:
    """Return the description and mapped policies/rules for one control.

    Parameters
    ----------
    framework:
        One of the supported framework keys.
    control_id:
        The control identifier, e.g. ``CC6.1`` or ``Art.5(1)(f)``.
    mapping:
        Loaded :class:`~compliance_mcp.framework.mapping.ControlMapping`.

    Returns
    -------
    dict
        ``{
          "id": str,
          "framework": str,
          "title": str,
          "description": str,
          "mapped_policies": [str, ...],
          "mapped_rules": [str, ...],
        }``

    Raises
    ------
    ControlCoverageError
        If *framework* is unknown or *control_id* is not found.
    """
    if framework not in SUPPORTED_FRAMEWORKS:
        raise ControlCoverageError(
            f"Unknown framework {framework!r}. Supported frameworks: {sorted(SUPPORTED_FRAMEWORKS)}"
        )

    ctrl_def = mapping.get_control(framework, control_id)
    if ctrl_def is None:
        known = sorted(mapping.controls_for_framework(framework))
        raise ControlCoverageError(
            f"Control {control_id!r} not found in framework {framework!r}. Known controls: {known}"
        )

    return {
        "id": control_id,
        "framework": framework,
        "title": ctrl_def.title,
        "description": ctrl_def.description,
        "mapped_policies": mapping.policies_for_control(framework, control_id),
        "mapped_rules": mapping.rules_for_control(framework, control_id),
    }


def findings_to_coverage_format(findings: list[Finding]) -> list[dict]:
    """Serialize findings to a JSON-safe list for tool return values."""
    return [
        {
            "rule_id": f.rule_id,
            "lens": f.lens.value,
            "domain": f.domain.value,
            "severity": f.severity.value,
            "title": f.title,
            "file_path": f.file_path,
            "line_start": f.line_start,
            "control_refs": f.control_refs,
            "fingerprint": f.fingerprint,
        }
        for f in findings
    ]
