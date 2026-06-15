"""Pydantic schema for policy-as-code rules."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, model_validator


class AssertionType(StrEnum):
    FILE_PRESENT = "file-present"
    FILE_ABSENT = "file-absent"
    CONTENT_MATCHES = "content-matches"
    CONTENT_NOT_MATCHES = "content-not-matches"
    STRUCTURED_PATH = "structured-path"


class Assertion(BaseModel):
    """Declarative assertion attached to a Rule."""

    type: AssertionType

    # content-matches / content-not-matches
    pattern: str | None = None
    flags: str = Field(
        default="", description="Space-separated re flag names, e.g. 'MULTILINE IGNORECASE'"
    )

    # structured-path (jmespath over JSON / YAML / TOML)
    path: str | None = Field(default=None, description="JMESPath expression to evaluate")
    exists: bool | None = Field(
        default=None, description="Assert the path exists (True) or is absent (False)"
    )
    equals: Any = Field(default=None, description="Assert the path value equals this literal")
    matches: str | None = Field(
        default=None, description="Assert the path value as string matches this regex"
    )

    @model_validator(mode="after")
    def _validate_assertion_fields(self) -> Assertion:
        t = self.type
        if (
            t in (AssertionType.CONTENT_MATCHES, AssertionType.CONTENT_NOT_MATCHES)
            and self.pattern is None
        ):
            raise ValueError(f"assertion type '{t}' requires 'pattern'")
        if t == AssertionType.STRUCTURED_PATH and self.path is None:
            raise ValueError("assertion type 'structured-path' requires 'path'")
        if (
            t == AssertionType.STRUCTURED_PATH
            and self.exists is None
            and self.equals is None
            and self.matches is None
        ):
            raise ValueError(
                "structured-path assertion requires at least one of: exists, equals, matches"
            )
        return self


class Rule(BaseModel):
    """A single declarative compliance rule loaded from YAML."""

    id: str = Field(..., min_length=1, description="Unique rule identifier within the ruleset")
    description: str = Field(
        default="", description="Human-readable description of what the rule checks"
    )
    severity: str = Field(
        default="medium",
        description="Severity level: critical | high | medium | low | info",
    )
    controls: list[str] = Field(
        default_factory=list,
        description="Control references propagated to Finding.control_refs (e.g. 'SOC2-CC6.1')",
    )
    domain: str = Field(
        default="other",
        description="Finding domain: one of the Domain enum values (e.g. 'configuration')",
    )
    target: str = Field(..., min_length=1, description="Glob pattern relative to the repo root")
    assertion: Assertion
