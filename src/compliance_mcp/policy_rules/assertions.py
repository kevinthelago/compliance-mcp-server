"""Assertion primitives for the policy-as-code lens.

Each public function accepts a Rule and a repo root Path and returns a list of
Findings (violations).  An empty list means the rule passed.

Supported assertion types
--------------------------
- file-present       : target glob must match ≥1 file.
- file-absent        : target glob must match 0 files.
- content-matches    : every matched file must contain the regex.
- content-not-matches: no matched file may contain the regex.
- structured-path    : evaluate a JMESPath expression over JSON / YAML / TOML.

Error contract
--------------
A bad file type for structured-path emits a rule-error diagnostic (severity=info)
rather than raising.  All other errors (unreadable file, bad regex) are logged and
skipped — the lens never crashes on a single bad file.
"""

from __future__ import annotations

import json
import logging
import re
import tomllib
from typing import TYPE_CHECKING, Any

import jmespath
import yaml

from compliance_mcp.models.finding import Domain, Finding, Lens, Severity
from compliance_mcp.policy_rules.schema import AssertionType, Rule

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

# ── helpers ───────────────────────────────────────────────────────────────────


def _severity(s: str) -> Severity:
    try:
        return Severity(s.lower())
    except ValueError:
        logger.warning("Unknown severity '%s'; defaulting to 'medium'", s)
        return Severity.MEDIUM


def _domain(d: str) -> Domain:
    try:
        return Domain(d.lower())
    except ValueError:
        return Domain.OTHER


def _make_finding(
    rule: Rule,
    file_path: str,
    *,
    line_start: int = 1,
    severity: Severity | None = None,
    message: str = "",
    suggestion: str = "",
) -> Finding:
    return Finding(
        lens=Lens.CUSTOM,
        domain=_domain(rule.domain),
        rule_id=f"pac.{rule.id}",
        file_path=file_path,
        line_start=line_start,
        severity=severity if severity is not None else _severity(rule.severity),
        title=rule.description or rule.id,
        control_refs=rule.controls,
        message=message,
        suggestion=suggestion,
    )


def _compile_flags(flags_str: str) -> int:
    """Parse space-separated re flag names into a combined int flag."""
    value = 0
    for token in flags_str.upper().split():
        attr = getattr(re, token, None)
        if isinstance(attr, int):
            value |= attr
        else:
            logger.warning("Unknown regex flag '%s'; ignoring", token)
    return value


def _glob(repo_root: Path, pattern: str) -> list[Path]:
    return sorted(repo_root.glob(pattern))


# ── assertion implementations ─────────────────────────────────────────────────


def _file_present(rule: Rule, repo_root: Path) -> list[Finding]:
    if _glob(repo_root, rule.target):
        return []
    return [
        _make_finding(
            rule,
            ".",
            message=f"No file matching '{rule.target}' found in the repository",
        )
    ]


def _file_absent(rule: Rule, repo_root: Path) -> list[Finding]:
    findings = []
    for path in _glob(repo_root, rule.target):
        rel = path.relative_to(repo_root).as_posix()
        findings.append(
            _make_finding(rule, rel, message=f"'{rel}' must not be committed to the repository")
        )
    return findings


def _content_matches(rule: Rule, repo_root: Path) -> list[Finding]:
    try:
        compiled = re.compile(rule.assertion.pattern, _compile_flags(rule.assertion.flags))  # type: ignore[arg-type]
    except re.error as exc:
        logger.warning("Invalid regex in rule '%s': %s — skipping rule", rule.id, exc)
        return []

    findings = []
    for path in _glob(repo_root, rule.target):
        rel = path.relative_to(repo_root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read '%s': %s — skipping file", path, exc)
            continue
        if not compiled.search(text):
            findings.append(
                _make_finding(
                    rule,
                    rel,
                    message=f"Pattern '{rule.assertion.pattern}' not found in '{rel}'",
                )
            )
    return findings


def _content_not_matches(rule: Rule, repo_root: Path) -> list[Finding]:
    try:
        compiled = re.compile(rule.assertion.pattern, _compile_flags(rule.assertion.flags))  # type: ignore[arg-type]
    except re.error as exc:
        logger.warning("Invalid regex in rule '%s': %s — skipping rule", rule.id, exc)
        return []

    findings = []
    for path in _glob(repo_root, rule.target):
        rel = path.relative_to(repo_root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read '%s': %s — skipping file", path, exc)
            continue
        match = compiled.search(text)
        if match:
            line_start = text[: match.start()].count("\n") + 1
            findings.append(
                _make_finding(
                    rule,
                    rel,
                    line_start=line_start,
                    message=f"Forbidden pattern '{rule.assertion.pattern}' found in '{rel}'",
                )
            )
    return findings


def _parse_structured(path: Path) -> tuple[Any, str | None]:
    """Parse a structured file into a Python object.

    Returns:
        (data, None)          on success.
        (None, error_message) when the file type is unsupported or parsing fails.
    """
    suffix = path.suffix.lower()
    try:
        if suffix == ".json":
            data = json.loads(path.read_bytes())
        elif suffix in (".yaml", ".yml"):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        elif suffix == ".toml":
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        else:
            return None, f"Unsupported file type '{suffix}' for structured-path assertion"
    except Exception as exc:
        return None, f"Failed to parse '{path.name}': {exc}"
    return data, None


def _structured_path(rule: Rule, repo_root: Path) -> list[Finding]:
    try:
        jpath = jmespath.compile(rule.assertion.path)  # type: ignore[arg-type]
    except jmespath.exceptions.JMESPathError as exc:
        logger.warning("Invalid JMESPath in rule '%s': %s — skipping rule", rule.id, exc)
        return []

    findings = []
    a = rule.assertion

    for path in _glob(repo_root, rule.target):
        rel = path.relative_to(repo_root).as_posix()
        data, err = _parse_structured(path)

        if err:
            # Rule-error diagnostic: unsupported type or parse failure
            findings.append(
                _make_finding(
                    rule,
                    rel,
                    severity=Severity.INFO,
                    message=f"[rule-error] {err}",
                )
            )
            continue

        value = jpath.search(data)

        # Evaluate the configured sub-assertion(s)
        violation = False
        reason = ""

        if a.exists is not None:
            present = value is not None
            if a.exists and not present:
                violation = True
                reason = f"Field '{a.path}' not found in '{rel}'"
            elif not a.exists and present:
                violation = True
                reason = f"Field '{a.path}' must not be present in '{rel}'"

        if not violation and a.equals is not None and value != a.equals:
            violation = True
            reason = f"Field '{a.path}' expected {a.equals!r}, got {value!r} in '{rel}'"

        if not violation and a.matches is not None:
            str_val = str(value) if value is not None else ""
            if not re.search(a.matches, str_val):
                violation = True
                reason = f"Field '{a.path}' value {value!r} does not match '{a.matches}' in '{rel}'"

        if violation:
            findings.append(_make_finding(rule, rel, message=reason))

    return findings


# ── public entry point ────────────────────────────────────────────────────────

_DISPATCH = {
    AssertionType.FILE_PRESENT: _file_present,
    AssertionType.FILE_ABSENT: _file_absent,
    AssertionType.CONTENT_MATCHES: _content_matches,
    AssertionType.CONTENT_NOT_MATCHES: _content_not_matches,
    AssertionType.STRUCTURED_PATH: _structured_path,
}


def evaluate(rule: Rule, repo_root: Path) -> list[Finding]:
    """Evaluate *rule* against *repo_root* and return any findings (violations)."""
    handler = _DISPATCH.get(rule.assertion.type)
    if handler is None:
        logger.warning("Unknown assertion type '%s' in rule '%s'", rule.assertion.type, rule.id)
        return []
    return handler(rule, repo_root)
