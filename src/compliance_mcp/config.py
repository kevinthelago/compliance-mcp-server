"""Configuration via pydantic-settings — reads compliance.toml and env vars."""
from __future__ import annotations

from pathlib import Path

import pydantic_settings
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, TomlConfigSettingsSource


class ComplianceConfig(BaseSettings):
    model_config = pydantic_settings.SettingsConfigDict(
        toml_file="compliance.toml",
        env_prefix="COMPLIANCE_",
        extra="ignore",
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (init_settings, env_settings, TomlConfigSettingsSource(settings_cls))

    corpus_path: Path = Path("policies")
    enabled_lenses: list[str] = []
    concurrency: int = 4
    lens_timeout: float = 120.0
    severity_thresholds: dict[str, str] = {}
    required_locales: list[str] = []


_config: ComplianceConfig | None = None


def get_config() -> ComplianceConfig:
    global _config
    if _config is None:
        _config = ComplianceConfig()
    return _config
