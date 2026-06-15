"""Control-mapping table loader.

Loads two sources into a unified lookup:
  1. ``policies/mappings/controls.yaml`` — explicit rule_id / policy_id / category → controls
  2. Policy frontmatter ``controls`` field — per-policy direct control citations

The lookup API accepts any combination of rule_id, policy_id, and category and
returns the union of matching control IDs for the requested framework.

Priority when multiple keys match the same entry:
  rule_id (most specific) > policy_id > category (broadest)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import frontmatter
import yaml

logger = logging.getLogger(__name__)

# Canonical framework keys used throughout the codebase
SUPPORTED_FRAMEWORKS: frozenset[str] = frozenset(
    {
        "soc2",
        "iso27001",
        "hipaa",
        "pci_dss",
        "gdpr",
    }
)


class ControlDef:
    """Metadata for a single regulatory control."""

    __slots__ = ("control_id", "framework", "title", "description")

    def __init__(
        self,
        control_id: str,
        framework: str,
        title: str,
        description: str = "",
    ) -> None:
        self.control_id = control_id
        self.framework = framework
        self.title = title
        self.description = description

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.control_id,
            "framework": self.framework,
            "title": self.title,
            "description": self.description,
        }


class ControlMapping:
    """In-memory index of all rule/policy/category → control mappings.

    Attributes
    ----------
    _definitions:
        ``{framework: {control_id: ControlDef}}`` — the complete control catalogue.
    _by_rule_id:
        ``{rule_id: {framework: [control_id, ...]}}``
    _by_policy_id:
        ``{policy_id: {framework: [control_id, ...]}}``
    _by_category:
        ``{category: {framework: [control_id, ...]}}``
    """

    def __init__(self) -> None:
        self._definitions: dict[str, dict[str, ControlDef]] = {}
        self._by_rule_id: dict[str, dict[str, list[str]]] = {}
        self._by_policy_id: dict[str, dict[str, list[str]]] = {}
        self._by_category: dict[str, dict[str, list[str]]] = {}

    # ------------------------------------------------------------------
    # Public query API
    # ------------------------------------------------------------------

    def supported_frameworks(self) -> list[str]:
        """Return the list of frameworks with at least one control defined."""
        return sorted(self._definitions)

    def controls_for_framework(self, framework: str) -> dict[str, ControlDef]:
        """Return all control definitions for *framework*, keyed by control_id."""
        return self._definitions.get(framework, {})

    def get_control(self, framework: str, control_id: str) -> ControlDef | None:
        """Return the ControlDef for a specific control, or None if unknown."""
        return self._definitions.get(framework, {}).get(control_id)

    def lookup(
        self,
        *,
        rule_id: str | None = None,
        policy_id: str | None = None,
        category: str | None = None,
        framework: str | None = None,
    ) -> dict[str, list[str]]:
        """Return ``{framework: [control_id, ...]}`` for the given keys.

        All non-None keys are consulted; results are unioned across keys.
        When *framework* is given, only that framework's controls are returned.
        """
        result: dict[str, set[str]] = {}

        def _merge(source: dict[str, list[str]]) -> None:
            for fw, ids in source.items():
                if framework and fw != framework:
                    continue
                result.setdefault(fw, set()).update(ids)

        if rule_id and rule_id in self._by_rule_id:
            _merge(self._by_rule_id[rule_id])
        if policy_id and policy_id in self._by_policy_id:
            _merge(self._by_policy_id[policy_id])
        if category and category in self._by_category:
            _merge(self._by_category[category])

        return {fw: sorted(ids) for fw, ids in result.items()}

    def policies_for_control(self, framework: str, control_id: str) -> list[str]:
        """Return all policy_ids that cite *control_id* in *framework*."""
        results: list[str] = []
        for pid, fw_map in self._by_policy_id.items():
            if control_id in fw_map.get(framework, []):
                results.append(pid)
        return sorted(results)

    def rules_for_control(self, framework: str, control_id: str) -> list[str]:
        """Return all rule_ids that map to *control_id* in *framework*."""
        results: list[str] = []
        for rid, fw_map in self._by_rule_id.items():
            if control_id in fw_map.get(framework, []):
                results.append(rid)
        return sorted(results)

    # ------------------------------------------------------------------
    # Internal builders
    # ------------------------------------------------------------------

    def _add_definition(  # noqa: PLR0913
        self, framework: str, control_id: str, title: str, description: str = ""
    ) -> None:
        self._definitions.setdefault(framework, {})[control_id] = ControlDef(
            control_id=control_id,
            framework=framework,
            title=title,
            description=description,
        )

    def _add_rule_mapping(self, rule_id: str, framework: str, control_ids: list[str]) -> None:
        fw_map = self._by_rule_id.setdefault(rule_id, {})
        existing = fw_map.setdefault(framework, [])
        for cid in control_ids:
            if cid not in existing:
                existing.append(cid)

    def _add_policy_mapping(self, policy_id: str, framework: str, control_ids: list[str]) -> None:
        fw_map = self._by_policy_id.setdefault(policy_id, {})
        existing = fw_map.setdefault(framework, [])
        for cid in control_ids:
            if cid not in existing:
                existing.append(cid)

    def _add_category_mapping(self, category: str, framework: str, control_ids: list[str]) -> None:
        fw_map = self._by_category.setdefault(category, {})
        existing = fw_map.setdefault(framework, [])
        for cid in control_ids:
            if cid not in existing:
                existing.append(cid)


def _load_controls_yaml(path: Path, mapping: ControlMapping) -> None:
    """Parse controls.yaml and populate *mapping* in place."""
    if not path.is_file():
        logger.warning("controls.yaml not found at %s — framework mapping will be empty", path)
        return

    with open(path, encoding="utf-8") as fh:
        data: dict[str, Any] = yaml.safe_load(fh) or {}

    # 1. Load framework control definitions
    for framework, controls in (data.get("frameworks") or {}).items():
        if not isinstance(controls, dict):
            logger.warning("Skipping malformed framework entry: %s", framework)
            continue
        for ctrl_id, ctrl_data in controls.items():
            if not isinstance(ctrl_data, dict):
                logger.warning("Skipping malformed control %s.%s", framework, ctrl_id)
                continue
            mapping._add_definition(
                framework=str(framework),
                control_id=str(ctrl_id),
                title=str(ctrl_data.get("title", "")),
                description=str(ctrl_data.get("description", "")),
            )

    # 2. Load rule/policy/category mappings
    for idx, entry in enumerate(data.get("mappings") or []):
        if not isinstance(entry, dict):
            logger.warning("Skipping malformed mapping entry at index %d", idx)
            continue

        controls_block: dict[str, list[str]] = entry.get("controls") or {}
        if not isinstance(controls_block, dict):
            logger.warning("Skipping mapping entry %d: 'controls' must be a dict", idx)
            continue

        rule_id: str | None = entry.get("rule_id")
        policy_id: str | None = entry.get("policy_id")
        category: str | None = entry.get("category")

        if not any([rule_id, policy_id, category]):
            logger.warning(
                "Mapping entry %d has no rule_id, policy_id, or category — skipping", idx
            )
            continue

        for framework, ctrl_ids in controls_block.items():
            if not isinstance(ctrl_ids, list):
                logger.warning(
                    "Mapping entry %d, framework %s: control list must be a list",
                    idx,
                    framework,
                )
                continue
            valid_ids = [str(c) for c in ctrl_ids if c]
            if rule_id:
                mapping._add_rule_mapping(str(rule_id), str(framework), valid_ids)
            if policy_id:
                mapping._add_policy_mapping(str(policy_id), str(framework), valid_ids)
            if category:
                mapping._add_category_mapping(str(category), str(framework), valid_ids)


def _load_policy_frontmatter(policies_dir: Path, mapping: ControlMapping) -> None:
    """Read ``controls`` from each policy .md file and merge into *mapping*."""
    if not policies_dir.is_dir():
        logger.debug("Policies directory not found at %s — skipping frontmatter load", policies_dir)
        return

    for md_file in sorted(policies_dir.rglob("*.md")):
        try:
            post = frontmatter.load(str(md_file))
        except Exception:
            logger.warning("Failed to parse frontmatter in %s — skipping", md_file)
            continue

        policy_id: str | None = post.get("id") or post.get("policy_id")
        controls_fm: dict[str, list[str]] | None = post.get("controls")

        if not policy_id or not isinstance(controls_fm, dict):
            continue

        for framework, ctrl_ids in controls_fm.items():
            if not isinstance(ctrl_ids, list):
                logger.warning(
                    "Policy %s: controls.%s must be a list — skipping", policy_id, framework
                )
                continue
            valid_ids = [str(c) for c in ctrl_ids if c]
            mapping._add_policy_mapping(str(policy_id), str(framework), valid_ids)


def load_mapping(
    controls_yaml: Path | None = None,
    policies_dir: Path | None = None,
) -> ControlMapping:
    """Build and return a populated :class:`ControlMapping`.

    Parameters
    ----------
    controls_yaml:
        Path to ``controls.yaml``; defaults to ``policies/mappings/controls.yaml``
        relative to the current working directory.
    policies_dir:
        Root of the policy corpus directory (``*.md`` files with frontmatter);
        defaults to ``policies/`` relative to cwd.
    """
    yaml_path = controls_yaml or Path("policies/mappings/controls.yaml")
    pol_dir = policies_dir or Path("policies")

    mapping = ControlMapping()
    _load_controls_yaml(yaml_path, mapping)
    _load_policy_frontmatter(pol_dir, mapping)
    return mapping
