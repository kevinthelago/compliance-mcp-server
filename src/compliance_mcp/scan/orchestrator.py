"""Scan orchestrator — runs lenses in parallel via a thread pool (SO-2)."""

from __future__ import annotations

import concurrent.futures
from dataclasses import dataclass, field
from pathlib import Path

from compliance_mcp.models.finding import Finding
from compliance_mcp.scan.lens import LensProtocol, LensResult, LensStatus


@dataclass
class LensRunRecord:
    name: str
    status: LensStatus
    finding_count: int
    diagnostics: str | None = None


@dataclass
class ScanSummary:
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
    """Run a list of lenses concurrently, collecting findings in registration order."""

    def __init__(
        self,
        lenses: list[LensProtocol],
        *,
        concurrency: int = 8,
        timeout: float = 60.0,
    ) -> None:
        self._lenses = list(lenses)
        self._concurrency = concurrency
        self._timeout = timeout

    def run(self, target: Path) -> ScanSummary:
        if not self._lenses:
            return ScanSummary()

        applicable_flags = [(lens, lens.applicable(target)) for lens in self._lenses]
        runnable = [lens for lens, flag in applicable_flags if flag]

        future_to_lens: dict[concurrent.futures.Future[LensResult], LensProtocol] = {}
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=self._concurrency)

        for lens in runnable:
            future_to_lens[executor.submit(lens.run, target)] = lens

        done: set[concurrent.futures.Future[LensResult]] = set()
        not_done: set[concurrent.futures.Future[LensResult]] = set()

        if future_to_lens:
            done, not_done = concurrent.futures.wait(
                list(future_to_lens), timeout=self._timeout
            )

        for f in not_done:
            f.cancel()
        executor.shutdown(wait=False)

        # Map lens name → result
        results: dict[str, LensResult] = {}
        for future, lens in future_to_lens.items():
            if future in not_done:
                results[lens.name] = LensResult.errored(
                    f"lens timed out after {self._timeout}s"
                )
            else:
                try:
                    results[lens.name] = future.result()
                except Exception as exc:  # noqa: BLE001
                    results[lens.name] = LensResult.errored(str(exc))

        # Collect in registration order
        all_findings: list[Finding] = []
        records: list[LensRunRecord] = []

        for lens, is_applicable in applicable_flags:
            if not is_applicable:
                records.append(
                    LensRunRecord(
                        name=lens.name,
                        status=LensStatus.NOT_RUN,
                        finding_count=0,
                        diagnostics="lens not applicable to this target",
                    )
                )
            else:
                result = results[lens.name]
                records.append(
                    LensRunRecord(
                        name=lens.name,
                        status=result.status,
                        finding_count=len(result.findings),
                        diagnostics=result.diagnostics,
                    )
                )
                all_findings.extend(result.findings)

        return ScanSummary(findings=all_findings, lens_records=records)
