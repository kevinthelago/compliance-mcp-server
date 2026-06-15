"""Scan orchestration — Lens protocol, orchestrator, normalizer, diff resolution."""

from compliance_mcp.scan.diff import DiffResolutionError, resolve_diff_target
from compliance_mcp.scan.lens import LensProtocol, LensResult, LensStatus
from compliance_mcp.scan.normalizer import normalize_findings
from compliance_mcp.scan.orchestrator import LensRunRecord, ScanOrchestrator, ScanSummary

__all__ = [
    "DiffResolutionError",
    "LensProtocol",
    "LensResult",
    "LensRunRecord",
    "LensStatus",
    "ScanOrchestrator",
    "ScanSummary",
    "normalize_findings",
    "resolve_diff_target",
]
