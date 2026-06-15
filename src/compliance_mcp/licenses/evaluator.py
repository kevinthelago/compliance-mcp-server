"""License evaluator (SUP-3).

Loads allow/deny/review policy from ``policies/licenses/`` and judges each
package's SPDX license expression.

Judgment logic
--------------
1. Parse the raw license string into an SPDX expression via
   ``license_expression.get_spdx_licensing()``.  Unknown / non-SPDX strings
   are treated as UNKNOWN symbols.
2. Walk the expression leaf symbols.
3. Any leaf in the **deny** list  →  DENIED  (severity configurable, default HIGH)
4. Any leaf in the **review** list (and none denied) → REVIEW  (MEDIUM)
5. All leaves in the **allow** list → ALLOWED
6. A leaf in none of the lists → UNKNOWN  (severity configurable, default MEDIUM)
7. An expression that cannot be parsed at all → UNKNOWN

For OR-joined expressions the conservative rule applies: if *any* alternative is
denied, the package is denied (use the safest path).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

import yaml
from license_expression import ExpressionError, LicenseExpression, get_spdx_licensing

from compliance_mcp.models.finding import Domain, Finding, Lens, Severity

log = logging.getLogger(__name__)

_SPDX = get_spdx_licensing()

# Common non-SPDX aliases → canonical SPDX identifiers
_ALIASES: dict[str, str] = {
    "apache 2.0": "Apache-2.0",
    "apache2": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "gpl2": "GPL-2.0-only",
    "gpl-2": "GPL-2.0-only",
    "gpl v2": "GPL-2.0-only",
    "gnu gpl v2": "GPL-2.0-only",
    "gpl3": "GPL-3.0-only",
    "gpl-3": "GPL-3.0-only",
    "gpl v3": "GPL-3.0-only",
    "gnu gpl v3": "GPL-3.0-only",
    "lgpl": "LGPL-2.1-or-later",
    "lgpl2": "LGPL-2.0-only",
    "lgpl-2.1": "LGPL-2.1-only",
    "mit license": "MIT",
    "mit/x11": "MIT",
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "new bsd": "BSD-3-Clause",
    "simplified bsd": "BSD-2-Clause",
    "isc license": "ISC",
    "mozilla public license 2.0": "MPL-2.0",
    "cc0": "CC0-1.0",
    "public domain": "Unlicense",
    "psf": "PSF-2.0",
    "python software foundation license": "PSF-2.0",
}


def _normalize(raw: str) -> str:
    """Apply alias substitution before SPDX parsing."""
    return _ALIASES.get(raw.strip().lower(), raw.strip())


def _parse_expression(raw: str) -> LicenseExpression | None:
    """Return a parsed SPDX expression, or None on parse failure."""
    normalized = _normalize(raw)
    try:
        return _SPDX.parse(normalized, validate=False)
    except ExpressionError:
        return None


def _leaf_ids(expr: LicenseExpression) -> list[str]:
    """Return all leaf license symbol ids from *expr*."""
    return [str(s.key) for s in expr.symbols]


class LicenseVerdict(StrEnum):
    ALLOWED = "allowed"
    DENIED = "denied"
    REVIEW = "review"
    UNKNOWN = "unknown"


@dataclass
class PackageVerdict:
    name: str
    version: str
    license_expression: str
    verdict: LicenseVerdict
    matched_licenses: list[str]


class LicenseEvaluator:
    """Loads policy files and judges package licenses against them.

    Parameters
    ----------
    policy_dir:
        Directory containing ``allow.yaml``, ``deny.yaml``, and ``review.yaml``.
    denied_severity:
        Severity to assign denied-license findings (default: HIGH).
    unknown_severity:
        Severity to assign unknown-license findings (default: MEDIUM).
    """

    def __init__(
        self,
        policy_dir: Path,
        *,
        denied_severity: Severity = Severity.HIGH,
        unknown_severity: Severity = Severity.MEDIUM,
    ) -> None:
        self._denied_severity = denied_severity
        self._unknown_severity = unknown_severity
        self._allow: frozenset[str] = frozenset()
        self._deny: frozenset[str] = frozenset()
        self._review: frozenset[str] = frozenset()
        self._load_policy(policy_dir)

    # ── Policy loading ────────────────────────────────────────────────────────

    def _load_policy(self, policy_dir: Path) -> None:
        self._allow = self._load_list(policy_dir / "allow.yaml")
        self._deny = self._load_list(policy_dir / "deny.yaml")
        self._review = self._load_list(policy_dir / "review.yaml")

    @staticmethod
    def _load_list(path: Path) -> frozenset[str]:
        if not path.is_file():
            log.warning("license policy file not found: %s", path)
            return frozenset()
        with open(path) as fh:
            data = yaml.safe_load(fh) or {}
        raw: list[str] = data.get("licenses", [])
        return frozenset(raw)

    # ── Judgment ─────────────────────────────────────────────────────────────

    def judge(self, name: str, version: str, license_str: str) -> PackageVerdict:
        """Judge a single package's license expression."""
        if not license_str or license_str.strip().lower() in {"", "noassertion", "none"}:
            return PackageVerdict(
                name=name,
                version=version,
                license_expression=license_str,
                verdict=LicenseVerdict.UNKNOWN,
                matched_licenses=[],
            )

        expr = _parse_expression(license_str)
        if expr is None:
            return PackageVerdict(
                name=name,
                version=version,
                license_expression=license_str,
                verdict=LicenseVerdict.UNKNOWN,
                matched_licenses=[license_str],
            )

        leaves = _leaf_ids(expr)
        denied = [lk for lk in leaves if lk in self._deny]
        review = [lk for lk in leaves if lk in self._review]
        classified = self._allow | self._deny | self._review
        unknown = [lk for lk in leaves if lk not in classified]

        if denied:
            verdict = LicenseVerdict.DENIED
            matched = denied
        elif review:
            verdict = LicenseVerdict.REVIEW
            matched = review
        elif unknown:
            verdict = LicenseVerdict.UNKNOWN
            matched = unknown
        else:
            verdict = LicenseVerdict.ALLOWED
            matched = leaves

        return PackageVerdict(
            name=name,
            version=version,
            license_expression=license_str,
            verdict=verdict,
            matched_licenses=matched,
        )

    def evaluate(
        self,
        packages: list[dict[str, str]],
        target: str = ".",
    ) -> list[Finding]:
        """Evaluate a list of packages and return license Findings.

        Each dict in *packages* must have keys ``name``, ``version``, and
        ``license`` (SPDX expression or identifier).  ``target`` is used as
        the ``file_path`` in the emitted Findings.
        """
        findings: list[Finding] = []
        for pkg in packages:
            name = pkg.get("name", "unknown")
            version = pkg.get("version", "")
            license_str = pkg.get("license", "")

            verdict = self.judge(name, version, license_str)

            if verdict.verdict == LicenseVerdict.ALLOWED:
                continue

            if verdict.verdict == LicenseVerdict.DENIED:
                severity = self._denied_severity
                rule_id = f"license.denied.{'.'.join(verdict.matched_licenses)}"
                title = f"Denied license in {name}@{version}: {license_str}"
                message = (
                    f"Package {name}@{version} uses license '{license_str}' which "
                    f"matches denied identifiers: {', '.join(verdict.matched_licenses)}"
                )
                suggestion = "Replace this dependency or obtain a commercial exception."
            elif verdict.verdict == LicenseVerdict.REVIEW:
                severity = Severity.MEDIUM
                rule_id = f"license.review.{'.'.join(verdict.matched_licenses)}"
                title = f"License requires review in {name}@{version}: {license_str}"
                message = (
                    f"Package {name}@{version} uses license '{license_str}' which "
                    f"requires legal review: {', '.join(verdict.matched_licenses)}"
                )
                suggestion = "Consult legal before shipping this dependency."
            else:  # UNKNOWN
                severity = self._unknown_severity
                rule_id = "license.unknown"
                title = f"Unknown license in {name}@{version}: {license_str!r}"
                message = (
                    f"Package {name}@{version} has an unrecognised license '{license_str}'. "
                    "Add it to allow.yaml, deny.yaml, or review.yaml."
                )
                suggestion = "Identify the license and add it to the appropriate policy list."

            findings.append(
                Finding(
                    lens=Lens.CUSTOM,
                    domain=Domain.SUPPLY_CHAIN,
                    rule_id=rule_id,
                    file_path=target,
                    line_start=1,
                    severity=severity,
                    title=title,
                    message=message,
                    suggestion=suggestion,
                )
            )
        return findings
