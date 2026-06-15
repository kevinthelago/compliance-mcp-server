import hashlib
import uuid

import pydantic

from compliance_mcp.models.enums import Domain, Lens, Severity


class Location(pydantic.BaseModel):
    line: int | None = None
    col: int | None = None


class Finding(pydantic.BaseModel):
    id: str = pydantic.Field(default_factory=lambda: str(uuid.uuid4()))
    lens: Lens
    domain: Domain
    severity: Severity
    title: str
    message: str
    file_path: str | None = None
    location: Location | None = None
    policy_id: str | None = None
    controls: list[str] = []
    remediation: str | None = None
    source: str
    fingerprint: str

    @staticmethod
    def make_fingerprint(
        lens: Lens,
        domain: Domain,
        file_path: str | None,
        location: Location | None,
        policy_id: str | None,
        title: str,
    ) -> str:
        line_str = str(location.line) if (location and location.line is not None) else ""
        last_slot = policy_id if policy_id is not None else title
        raw = "|".join([
            lens.value,
            domain.value,
            file_path or "",
            line_str,
            last_slot,
        ])
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    model_config = pydantic.ConfigDict(populate_by_name=True)
