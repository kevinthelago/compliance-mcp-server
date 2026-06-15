"""Finding control-mapper — enriches findings with regulatory control references.

Enrichment is *additive*: a finding that maps to no controls is preserved exactly
as-is (never dropped). Findings that do map gain ``control_refs`` entries in the
format ``"<FRAMEWORK>:<control_id>"``, e.g. ``"soc2:CC6.1"``.

The mapper matches against three keys in priority order:
  1. ``finding.rule_id``  (most specific)
  2. ``finding.policy_id`` (via ``rule_id`` prefix convention ``<domain>.<slug>``)
  3. ``finding.domain``  (broadest fallback — maps to a ``category``)

``Finding`` is a frozen Pydantic model, so enrichment returns new instances.
"""

from __future__ import annotations

from compliance_mcp.framework.mapping import ControlMapping
from compliance_mcp.models.finding import Finding


def _derive_policy_id(finding: Finding) -> str | None:
    """Infer a policy_id from the rule_id if it looks like ``<domain>.<slug>``.

    Lenses that emit a rule_id of the form ``gdpr.data-retention`` can also be
    matched via their policy_id (``gdpr.data-retention``), so callers do not need
    to duplicate the mapping entry.
    """
    # rule_id values like "gitleaks.private-key" use "gitleaks" as a tool prefix,
    # not a policy domain — only treat it as a policy_id when the prefix matches
    # a known compliance domain.
    known_domains = {"gdpr", "soc2", "iso27001", "hipaa", "pci_dss", "owasp"}
    parts = finding.rule_id.split(".", 1)
    if len(parts) == 2 and parts[0] in known_domains:
        return finding.rule_id
    return None


def enrich_finding(finding: Finding, mapping: ControlMapping) -> Finding:
    """Return a copy of *finding* with ``control_refs`` populated.

    If the finding already has ``control_refs`` set, new references are appended
    (deduplication is applied).  If no controls match, the original finding is
    returned unchanged.
    """
    # Aggregate control references across all frameworks
    refs_set: set[str] = set(finding.control_refs)

    # 1. Match by rule_id
    rule_controls = mapping.lookup(rule_id=finding.rule_id)
    for framework, ctrl_ids in rule_controls.items():
        for cid in ctrl_ids:
            refs_set.add(f"{framework}:{cid}")

    # 2. Match by derived policy_id (only if distinct from rule_id lookup)
    policy_id = _derive_policy_id(finding)
    if policy_id:
        policy_controls = mapping.lookup(policy_id=policy_id)
        for framework, ctrl_ids in policy_controls.items():
            for cid in ctrl_ids:
                refs_set.add(f"{framework}:{cid}")

    # 3. Match by domain (category fallback)
    category_controls = mapping.lookup(category=finding.domain.value)
    for framework, ctrl_ids in category_controls.items():
        for cid in ctrl_ids:
            refs_set.add(f"{framework}:{cid}")

    new_refs = sorted(refs_set)
    if new_refs == sorted(finding.control_refs):
        return finding

    return finding.model_copy(update={"control_refs": new_refs})


def enrich_findings(findings: list[Finding], mapping: ControlMapping) -> list[Finding]:
    """Enrich all findings in *findings* with control references.

    Unmapped findings are preserved without modification.  The order of the
    input list is preserved.
    """
    return [enrich_finding(f, mapping) for f in findings]
