"""Load declarative rules from YAML files.

Convention: every *.yaml file in the rules directory must contain a YAML list of
rule objects.  A single malformed rule is skipped with a warning so that one bad
entry never silences the rest of the ruleset.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import yaml
from pydantic import ValidationError

from compliance_mcp.policy_rules.schema import Rule

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


def load_rules(rules_dir: Path) -> list[Rule]:
    """Load all *.yaml rule files from *rules_dir*.

    Args:
        rules_dir: Directory containing rule YAML files.

    Returns:
        List of validated Rule objects; malformed entries are skipped.
    """
    if not rules_dir.is_dir():
        logger.warning("Rules directory '%s' does not exist; returning empty ruleset", rules_dir)
        return []

    rules: list[Rule] = []
    for path in sorted(rules_dir.glob("*.yaml")):
        _load_file(path, rules)
    return rules


def _load_file(path: Path, rules: list[Rule]) -> None:
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except Exception as exc:
        logger.warning("Failed to parse rule file '%s': %s — skipping", path, exc)
        return

    if not isinstance(data, list):
        logger.warning("Rule file '%s' must contain a YAML list at the top level — skipping", path)
        return

    for item in data:
        if not isinstance(item, dict):
            logger.warning("Non-dict entry in '%s': %r — skipping", path, item)
            continue
        try:
            rules.append(Rule.model_validate(item))
        except ValidationError as exc:
            rule_id = item.get("id", "<unknown>")
            logger.warning("Malformed rule '%s' in '%s': %s — skipping", rule_id, path, exc)
