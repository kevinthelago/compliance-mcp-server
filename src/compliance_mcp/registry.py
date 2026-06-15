"""Lens registry — self-registration via decorator + pkgutil auto-discovery.

Usage in a lens module
----------------------
    from compliance_mcp.registry import lens

    @lens("gdpr")
    async def run(project_path: str, config: ComplianceSettings) -> list[Finding]:
        ...

Auto-discovery
--------------
Call `discover_lenses()` at startup; it imports every module under
`compliance_mcp.lenses.*` via pkgutil so their `@lens` decorators fire without
any shared `__init__.py` needing to be edited.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Awaitable, Callable

from compliance_mcp.logging import get_logger
from compliance_mcp.models.finding import Finding, Lens

logger = get_logger(__name__)

# LensRunner type: (project_path, config) -> list[Finding]
LensRunner = Callable[..., Awaitable[list[Finding]]]

_REGISTRY: dict[Lens, LensRunner] = {}


def lens(lens_id: str | Lens) -> Callable[[LensRunner], LensRunner]:
    """Decorator that registers an async lens runner under *lens_id*."""

    def decorator(fn: LensRunner) -> LensRunner:
        key = Lens(lens_id) if isinstance(lens_id, str) else lens_id
        if key in _REGISTRY:
            logger.warning("Lens %s already registered — overwriting with %s", key, fn.__qualname__)
        _REGISTRY[key] = fn
        logger.debug("Registered lens: %s → %s", key, fn.__qualname__)
        return fn

    return decorator


def get_lens(lens_id: Lens) -> LensRunner | None:
    return _REGISTRY.get(lens_id)


def registered_lenses() -> list[Lens]:
    return list(_REGISTRY)


def discover_lenses() -> None:
    """Import every module under `compliance_mcp.lenses` so decorators run."""
    import compliance_mcp.lenses as _lenses_pkg  # noqa: PLC0415

    pkg_path = _lenses_pkg.__path__  # type: ignore[attr-defined]
    pkg_name = _lenses_pkg.__name__

    for _finder, mod_name, _is_pkg in pkgutil.iter_modules(pkg_path):
        full_name = f"{pkg_name}.{mod_name}"
        try:
            importlib.import_module(full_name)
            logger.debug("Discovered lens module: %s", full_name)
        except Exception:
            logger.exception("Failed to import lens module %s — skipping", full_name)
