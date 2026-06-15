"""Pydantic model for a policy rule loaded from a markdown file.

`PolicyDomain` is a corpus-organisation concept distinct from `Finding.Domain`
(which classifies scan findings by category).  Policy documents are authored
in one of these five areas; the corpus loader and index use this enum.
"""
from __future__ import annotations

from enum import StrEnum

import pydantic

from compliance_mcp.models.finding import Severity


class PolicyDomain(StrEnum):
    """Top-level organisational domain for a policy document."""

    SECURITY = "security"
    SUPPLY_CHAIN = "supply_chain"
    LICENSE = "license"
    I18N = "i18n"
    POLICY = "policy"


class PolicyRule(pydantic.BaseModel):
    """A single compliance policy rule parsed from a policies/*.md file.

    The frontmatter fields map to this model; the markdown body becomes ``body``.
    """

    id: str
    domain: PolicyDomain
    topic: str
    controls: list[str] = []
    severity: Severity = Severity.MEDIUM
    locales: list[str] = []
    keywords: list[str] = []
    body: str = ""

    model_config = pydantic.ConfigDict(populate_by_name=True)
