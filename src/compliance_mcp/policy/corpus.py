"""Policy corpus loader — reads policies/**/*.md via python-frontmatter."""
from __future__ import annotations

import logging
import pathlib

import frontmatter
import pydantic

from compliance_mcp.policy.models import PolicyRule

logger = logging.getLogger(__name__)

_DEFAULT_POLICY_DIR = pathlib.Path(__file__).parent.parent.parent.parent / "policies"


def load_corpus(policy_dir: pathlib.Path | str | None = None) -> list[PolicyRule]:
    """Load all policy markdown files under *policy_dir* and return validated rules.

    Files that fail schema validation are skipped with a logged warning so that one
    bad file never prevents the rest of the corpus from loading.
    """
    base = pathlib.Path(policy_dir) if policy_dir is not None else _DEFAULT_POLICY_DIR
    rules: list[PolicyRule] = []

    for md_path in sorted(base.rglob("*.md")):
        try:
            post = frontmatter.load(str(md_path))
        except Exception as exc:
            logger.warning("failed to parse %s: %s", md_path, exc)
            continue

        metadata = dict(post.metadata)
        metadata["body"] = post.content

        try:
            rule = PolicyRule.model_validate(metadata)
        except pydantic.ValidationError as exc:
            logger.warning("invalid policy frontmatter in %s: %s", md_path, exc)
            continue

        rules.append(rule)

    return rules
