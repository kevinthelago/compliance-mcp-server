"""Core Finding model and classification enums.

Fingerprint contract
--------------------
`Finding.fingerprint` is a deterministic, content-addressed SHA-256 hex digest
derived from the fields that identify *which* violation was found, excluding
mutable presentation fields (message, suggestion).  It is stable across runs and
used for deduplication and baseline suppression.

Fingerprint inputs (in canonical order):
  lens | domain | rule_id | file_path (POSIX, relative) | line_start
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from pathlib import PurePosixPath

from pydantic import BaseModel, Field, model_validator


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]

    def __ge__(self, other: Severity) -> bool:  # type: ignore[override]
        return self.rank >= other.rank


class Lens(StrEnum):
    """First-class compliance framework identifiers."""

    GDPR = "gdpr"
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    OWASP = "owasp"
    CUSTOM = "custom"


class Domain(StrEnum):
    """Broad category a finding belongs to."""

    ACCESS_CONTROL = "access_control"
    DATA_PROTECTION = "data_protection"
    AUDIT_LOGGING = "audit_logging"
    NETWORK_SECURITY = "network_security"
    VULNERABILITY = "vulnerability"
    CONFIGURATION = "configuration"
    DOCUMENTATION = "documentation"
    INCIDENT_RESPONSE = "incident_response"
    SUPPLY_CHAIN = "supply_chain"
    OTHER = "other"


class Finding(BaseModel):
    """A single compliance finding emitted by a lens."""

    model_config = {"frozen": True}

    # Identity fields — drive the fingerprint
    lens: Lens
    domain: Domain
    rule_id: str = Field(..., description="Lens-scoped rule identifier, e.g. 'gdpr.data-retention'")
    file_path: str = Field(
        ..., description="Relative POSIX path to the file containing the finding"
    )
    line_start: int = Field(..., ge=1)
    line_end: int | None = Field(default=None, ge=1)

    # Classification
    severity: Severity
    title: str = Field(..., min_length=1)

    # Presentation fields — excluded from fingerprint intentionally
    message: str = Field(default="")
    suggestion: str = Field(default="")
    control_refs: list[str] = Field(default_factory=list, description="e.g. ['GDPR Art. 5(1)(e)']")

    # Computed
    fingerprint: str = Field(default="", description="Deterministic SHA-256 of identity fields")

    @model_validator(mode="after")
    def _compute_fingerprint(self) -> Finding:
        if self.fingerprint:
            return self
        canonical = "|".join(
            [
                self.lens.value,
                self.domain.value,
                self.rule_id,
                str(PurePosixPath(self.file_path)),
                str(self.line_start),
            ]
        )
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        # bypass frozen model to set computed field
        object.__setattr__(self, "fingerprint", digest)
        return self
