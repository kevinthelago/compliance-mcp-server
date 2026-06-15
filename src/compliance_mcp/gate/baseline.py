"""Baseline suppression — accept known findings by fingerprint to skip the gate."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from compliance_mcp.models.finding import Finding

log = logging.getLogger(__name__)


@dataclass
class BaselineEntry:
    """A single suppressed fingerprint with an optional reason string."""

    fingerprint: str
    reason: str = ""


@dataclass
class BaselineResult:
    """Outcome of applying baseline suppression to a set of findings."""

    # Findings whose fingerprint is in the baseline (not sent to the gate)
    accepted: list[Finding] = field(default_factory=list)
    # Remaining findings that should be evaluated by the gate
    active: list[Finding] = field(default_factory=list)
    # Baseline entries that no longer match any current finding
    stale_entries: list[BaselineEntry] = field(default_factory=list)


def load_baseline(path: Path | None = None) -> list[BaselineEntry]:
    """
    Load a JSON baseline file.

    Accepted formats::

        # Simple list of fingerprint strings
        ["abc123...", "def456..."]

        # Annotated format with reasons
        [
          {"fingerprint": "abc123...", "reason": "Tracked in SEC-42"},
          {"fingerprint": "def456...", "reason": "False positive — confirmed by security"},
          "plain-fingerprint-string"          # plain strings are also accepted
        ]

    Missing or empty file returns an empty list.
    """
    if path is None:
        return []

    if not path.exists():
        return []

    raw: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        log.warning("baseline file %s must be a JSON array — ignored", path)
        return []

    entries: list[BaselineEntry] = []
    for i, item in enumerate(raw):
        if isinstance(item, str):
            entries.append(BaselineEntry(fingerprint=item))
        elif isinstance(item, dict):
            fp = item.get("fingerprint")
            if not fp:
                log.warning("baseline entry %d missing 'fingerprint' — skipped", i)
                continue
            entries.append(BaselineEntry(fingerprint=str(fp), reason=str(item.get("reason", ""))))
        else:
            log.warning(
                "baseline entry %d has unexpected type %s — skipped", i, type(item).__name__
            )

    return entries


def suppress(
    findings: list[Finding],
    baseline: list[BaselineEntry],
) -> BaselineResult:
    """
    Partition findings into accepted (baseline-suppressed) and active.

    Stale entries are those whose fingerprint appears in the baseline but not in
    the current scan — they may indicate a fixed issue or a drifted fingerprint.
    """
    fp_to_entry: dict[str, BaselineEntry] = {e.fingerprint: e for e in baseline}
    accepted: list[Finding] = []
    active: list[Finding] = []
    matched: set[str] = set()

    for finding in findings:
        if finding.fingerprint in fp_to_entry:
            accepted.append(finding)
            matched.add(finding.fingerprint)
        else:
            active.append(finding)

    stale = [e for e in baseline if e.fingerprint not in matched]
    if stale:
        log.info(
            "Stale baseline entries (no matching finding in current scan): %s",
            ", ".join(e.fingerprint for e in stale),
        )

    return BaselineResult(accepted=accepted, active=active, stale_entries=stale)
