"""Scan orchestrator — runs applicable lenses in parallel with timeout + fault isolation."""
from __future__ import annotations

import concurrent.futures
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from compliance_mcp.models import Finding
from compliance_mcp.scan.lens import LensProtocol, LensResult, LensStatus

logger = logging.getLogger(__name__)


@dataclass
class LensRunRecord:
    """Per-lens outcome recorded in the run summary."""

    name: str
    status: LensStatus
    finding_count: int
    diagnostics: str | None = None


@dataclass
class ScanSummary:
    """Aggregate result of one orchestrator run."""

    findings: list[Finding] = field(default_factory=list)
    lens_records: list[LensRunRecord] = field(default_factory=list)

    @property
    def ran_count(self) -> int:
        return sum(1 for r in self.lens_records if r.status == LensStatus.RAN)

    @property
    def not_run_count(self) -> int:
        return sum(1 for r in self.lens_records if r.status == LensStatus.NOT_RUN)

    @property
    def errored_count(self) -> int:
        return sum(1 for r in self.lens_records if r.status == LensStatus.ERRORED)


class ScanOrchestrator:
    """Runs registered lenses in parallel; isolates failures; enforces per-lens timeouts.

    Args:
        lenses: Ordered list of lens instances to consider.
        concurrency: Max lenses running simultaneously.
        timeout: Per-lens wall-clock timeout in seconds.
    """

    def __init__(
        self,
        lenses: list[LensProtocol],
        *,
        concurrency: int = 4,
        timeout: float = 120.0,
    ) -> None:
        self._lenses = lenses
        self._concurrency = max(1, concurrency)
        self._timeout = timeout

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self, target: Path) -> ScanSummary:
        """Run all applicable lenses against *target* and return the aggregated summary."""
        applicable, not_run_records = self._partition_lenses(target)

        if not applicable:
            logger.info("No lenses applicable for %s", target)

        lens_records: list[LensRunRecord] = list(not_run_records)
        all_findings: list[Finding] = []

        if applicable:
            results = self._run_parallel(applicable, target)
            for lens, result in zip(applicable, results):
                lens_records.append(LensRunRecord(
                    name=lens.name,
                    status=result.status,
                    finding_count=len(result.findings),
                    diagnostics=result.diagnostics,
                ))
                all_findings.extend(result.findings)

        return ScanSummary(findings=all_findings, lens_records=lens_records)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _partition_lenses(
        self, target: Path
    ) -> tuple[list[LensProtocol], list[LensRunRecord]]:
        """Split lenses into applicable ones and not-run records."""
        applicable: list[LensProtocol] = []
        not_run: list[LensRunRecord] = []
        for lens in self._lenses:
            try:
                is_applicable = lens.applicable(target)
            except Exception as exc:
                logger.warning("lens %r applicable() raised: %s", lens.name, exc)
                not_run.append(LensRunRecord(
                    name=lens.name,
                    status=LensStatus.NOT_RUN,
                    finding_count=0,
                    diagnostics=f"applicable() raised: {exc}",
                ))
                continue

            if is_applicable:
                applicable.append(lens)
            else:
                not_run.append(LensRunRecord(
                    name=lens.name,
                    status=LensStatus.NOT_RUN,
                    finding_count=0,
                    diagnostics="lens not applicable (binary absent or disabled)",
                ))
        return applicable, not_run

    def _run_parallel(
        self, lenses: list[LensProtocol], target: Path
    ) -> list[LensResult]:
        """Execute lenses concurrently; results are in the same order as *lenses*."""
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self._concurrency
        ) as executor:
            # Record submission time per lens to enforce per-lens timeout.
            submitted_at = time.monotonic()
            futures: list[concurrent.futures.Future[LensResult]] = [
                executor.submit(self._safe_run, lens, target)
                for lens in lenses
            ]

            results: list[LensResult] = []
            for future, lens in zip(futures, lenses):
                elapsed = time.monotonic() - submitted_at
                remaining = max(0.0, self._timeout - elapsed)
                try:
                    result = future.result(timeout=remaining if remaining > 0 else 0.001)
                except concurrent.futures.TimeoutError:
                    logger.warning("Lens %r timed out after %.1fs", lens.name, self._timeout)
                    future.cancel()
                    result = LensResult.errored(f"timed out after {self._timeout:.0f}s")
                except Exception as exc:
                    logger.warning("Lens %r result retrieval error: %s", lens.name, exc)
                    result = LensResult.errored(f"unexpected error: {exc}")
                results.append(result)

        return results

    @staticmethod
    def _safe_run(lens: LensProtocol, target: Path) -> LensResult:
        """Call lens.run(); convert any exception to LensResult.errored()."""
        try:
            return lens.run(target)
        except Exception as exc:
            logger.warning("Lens %r raised: %s", lens.name, exc)
            return LensResult.errored(str(exc))
