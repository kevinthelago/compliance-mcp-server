"""Lens registry — lenses self-register via @register_lens; orchestrator discovers them."""
from __future__ import annotations

import importlib
import pkgutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from compliance_mcp.scan.lens import LensProtocol

_registry: list[LensProtocol] = []


def register_lens(lens: LensProtocol) -> LensProtocol:
    """Register a lens instance. Called by each lens module at import time."""
    _registry.append(lens)
    return lens


def get_lenses() -> list[LensProtocol]:
    """Return all registered lenses (triggers auto-discovery on first call)."""
    _discover_lenses()
    return list(_registry)


_discovered = False


def _discover_lenses() -> None:
    global _discovered
    if _discovered:
        return
    _discovered = True
    import compliance_mcp.lenses as lenses_pkg
    for _finder, name, _ispkg in pkgutil.iter_modules(lenses_pkg.__path__):
        importlib.import_module(f"compliance_mcp.lenses.{name}")
