"""Server configuration loaded from compliance.toml and COMPLIANCE_* env vars.

Resolution order (highest wins):
  1. COMPLIANCE_* environment variables
  2. compliance.toml (next to cwd, or path given by COMPLIANCE_CONFIG_FILE)
  3. Built-in defaults
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator, model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from compliance_mcp.models.finding import Lens, Severity


class _TomlSource(PydanticBaseSettingsSource):
    """Lowest-priority source: reads [compliance] from compliance.toml."""

    def __init__(self, settings_cls: type, config_file: Path | None = None) -> None:
        super().__init__(settings_cls)
        self._config_file = config_file

    def get_field_value(self, field: Any, field_name: str) -> tuple[Any, str, bool]:  # noqa: ANN401
        data = self._load()
        value = data.get(field_name)
        return value, field_name, value is not None

    def __call__(self) -> dict[str, Any]:
        return self._load()

    def _load(self) -> dict[str, Any]:
        path = self._config_file or Path("compliance.toml")
        if not path.is_file():
            return {}
        with open(path, "rb") as fh:
            raw = tomllib.load(fh)
        return raw.get("compliance", {})


class ComplianceSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="COMPLIANCE_",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    corpus_path: Path = Field(
        default=Path("compliance_corpus"),
        description="Directory that holds policy documents.",
    )
    enabled_lenses: list[Lens] = Field(
        default_factory=lambda: [Lens.GDPR, Lens.SOC2, Lens.ISO27001],
        description="Which lenses to load and run.",
    )
    severity_threshold: Severity = Field(
        default=Severity.MEDIUM,
        description="Minimum severity level to surface in results.",
    )
    required_locales: list[str] = Field(
        default_factory=lambda: ["en"],
        description="Locale codes that policy documents must cover.",
    )
    concurrency_cap: int = Field(
        default=8,
        ge=1,
        le=64,
        description="Maximum number of lens workers running in parallel.",
    )
    lens_timeout_seconds: int = Field(
        default=60,
        ge=1,
        description="Per-lens wall-clock timeout before it is forcibly cancelled.",
    )

    @field_validator("enabled_lenses", mode="before")
    @classmethod
    def _coerce_lenses(cls, v: object) -> object:
        if isinstance(v, str):
            return [s.strip() for s in v.split(",") if s.strip()]
        return v

    @field_validator("required_locales", mode="before")
    @classmethod
    def _coerce_locales(cls, v: object) -> object:
        if isinstance(v, str):
            return [s.strip() for s in v.split(",") if s.strip()]
        return v

    @model_validator(mode="after")
    def _validate_corpus_accessible(self) -> ComplianceSettings:
        if not self.corpus_path.exists():
            print(
                f"[compliance-mcp] WARNING: corpus_path '{self.corpus_path}' does not exist.",
                file=sys.stderr,
            )
        return self

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # env_settings wins over toml; toml wins over defaults
        toml_source = _TomlSource(settings_cls, config_file=_ACTIVE_CONFIG_FILE)
        return (env_settings, toml_source)


# Module-level slot so _TomlSource can pick up the path without init_settings hacks
_ACTIVE_CONFIG_FILE: Path | None = None


def load_settings(config_file: Path | None = None) -> ComplianceSettings:
    """Load and validate settings; raise ValidationError on bad config (fail fast)."""
    global _ACTIVE_CONFIG_FILE  # noqa: PLW0603
    _ACTIVE_CONFIG_FILE = config_file
    try:
        return ComplianceSettings()
    finally:
        _ACTIVE_CONFIG_FILE = None
