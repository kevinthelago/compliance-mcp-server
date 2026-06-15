"""I18N-1: Flag hardcoded user-facing string literals in JS/TS/JSX and Python.

Uses tree-sitter for JS/TS/JSX AST analysis and Python's built-in `ast` module
for Python files. Only flags strings that appear in user-visible positions
(JSX text, specific HTML-like attributes, exception messages, etc.).
"""

from __future__ import annotations

import ast
import re
from collections.abc import Generator
from pathlib import Path
from typing import Any

from .framework_detection import FrameworkInfo

try:
    from compliance_mcp.models import Finding, ScanContext, Severity  # type: ignore[import]
except ImportError:
    from compliance_mcp.i18n._types import (  # type: ignore[assignment]
        Finding,
        ScanContext,
        Severity,
    )


# --------------------------------------------------------------------------- #
# Configuration                                                                #
# --------------------------------------------------------------------------- #

_USER_FACING_ATTRS = frozenset(
    {
        "label",
        "placeholder",
        "alt",
        "title",
        "aria-label",
        "aria-description",
        "tooltip",
        "description",
        "helpertext",
        "helper-text",
        "error",
        "success",
        "hint",
        "caption",
        "legend",
        "message",
        "buttontext",
        "button-text",
        "submittext",
        "submit-text",
        "emptymessage",
        "empty-message",
        "nodata",
        "no-data",
        "nooptionstext",
        "loadingtext",
        "confirmtext",
        "canceltext",
    }
)

_NON_I18N_CALL_NAMES = frozenset(
    {
        "console",
        "logger",
        "logging",
        "log",
        "warn",
        "debug",
        "error",
        "info",
        "require",
        "import",
        "test",
        "describe",
        "it",
        "expect",
        "assert",
        "setTimeout",
        "setInterval",
        "emit",
    }
)

# Strings matching these patterns are boring (not user-facing)
_BORING_RE = re.compile(
    r"^(?:"
    r"https?://"  # URLs
    r"|[./\\@]"  # paths / imports
    r"|\d[\d.,\s]*$"  # numeric
    r"|[A-Z_]{3,}$"  # ALL_CAPS constants
    r"|#[0-9a-fA-F]{3,8}$"  # CSS hex colors
    r"|rgb\("  # CSS rgb
    r"|rgba\("  # CSS rgba
    r"|[\w-]+\.[\w-]+"  # dotted identifiers (app.key, margin.left)
    r")"
)

# A string that looks like a CSS/HTML class name, identifier, or code key
_CODE_IDENT_RE = re.compile(r"^[a-z][a-z0-9\-_]*$")

# Match test FILES by name pattern — deliberately does NOT match "tests/" directory
# names so that fixture files under tests/ are not skipped.
_TEST_FILE_RE = re.compile(
    r"(?:\.test\.|\.spec\.|_test\.(py|js|ts|jsx|tsx)$|(?:^|[/\\])test_[^/\\]+\.(py|js|ts)$|[/\\]__tests__[/\\])",
    re.IGNORECASE,
)

# Python callable names that typically carry user-visible messages
_PY_USER_FACING_CALLS = frozenset(
    {
        "Exception",
        "ValueError",
        "TypeError",
        "RuntimeError",
        "PermissionError",
        "NotImplementedError",
        "ValidationError",
        "HTTPException",
        "flash",
        "messages",
        "abort",
        "render_template",
        "gettext",
        "_",
        "ngettext",
        "lazy_gettext",
        "pgettext",
    }
)


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def _is_boring(s: str) -> bool:
    """Return True if *s* is clearly not a user-facing localizable string."""
    s = s.strip()
    if len(s) < 2:
        return True
    if _BORING_RE.match(s):
        return True
    return bool(_CODE_IDENT_RE.match(s))


def _to_catalog_key(text: str) -> str:
    """Generate a suggested i18n catalog key from *text*."""
    s = text.lower().strip()
    s = re.sub(r"[^a-z0-9\s]", "", s)
    s = re.sub(r"\s+", "_", s).strip("_")
    return (s[:50] or "string").rstrip("_")


def _is_test_file(path: Path) -> bool:
    # Match against path string for directory patterns, but use file name for named patterns
    path_str = str(path).replace("\\", "/")
    return bool(_TEST_FILE_RE.search(path_str))


def _make_finding(
    path: Path,
    line: int,
    col: int,
    literal: str,
    confidence: str,
    severity: Severity,
) -> Finding:
    key = _to_catalog_key(literal)
    return Finding(
        rule_id="i18n/hardcoded-string",
        path=str(path),
        line=line,
        col=col,
        severity=severity,
        message=f'Hardcoded string "{literal[:60]}" may need i18n',
        detail=(
            f"confidence={confidence}; "
            f"suggested key: {key!r}"
        ),
        suggestion=f"Replace with t('{key}') or equivalent catalog lookup.",
        extra={"literal": literal, "suggested_key": key, "confidence": confidence},
    )


# --------------------------------------------------------------------------- #
# JS/TS/JSX analysis via tree-sitter                                          #
# --------------------------------------------------------------------------- #

try:
    import tree_sitter_javascript as _tsjs
    import tree_sitter_typescript as _tsts
    from tree_sitter import Language, Parser

    _JS_LANGUAGE = Language(_tsjs.language())
    _TS_LANGUAGE = Language(_tsts.language_typescript())
    _TSX_LANGUAGE = Language(_tsts.language_tsx())
    _JS_PARSER = Parser(_JS_LANGUAGE)
    _TS_PARSER = Parser(_TS_LANGUAGE)
    _TSX_PARSER = Parser(_TSX_LANGUAGE)
    _TREE_SITTER_AVAILABLE = True
except Exception:  # pragma: no cover â€” tree-sitter unavailable in some envs
    _TREE_SITTER_AVAILABLE = False


def _iter_nodes(node: object, wanted: frozenset[str]) -> Generator[Any, None, None]:
    """Recursively yield all descendant AST nodes whose type is in *wanted*."""
    if node.type in wanted:  # type: ignore[attr-defined]
        yield node
    for child in node.children:  # type: ignore[attr-defined]
        yield from _iter_nodes(child, wanted)


def _get_parser_for(path: Path) -> tuple[Any, Any]:
    """Return the appropriate tree-sitter (Parser, Language) for *path*, or None."""
    if not _TREE_SITTER_AVAILABLE:
        return None, None
    ext = path.suffix.lower()
    if ext in (".tsx",):
        return _TSX_PARSER, _TSX_LANGUAGE
    if ext in (".ts",):
        return _TS_PARSER, _TS_LANGUAGE
    if ext in (".js", ".jsx", ".mjs", ".cjs"):
        return _JS_PARSER, _JS_LANGUAGE
    return None, None


def _is_inside_non_i18n_call(node: object) -> bool:
    """Check if *node* is a direct argument of a known non-i18n call (e.g. console.log)."""
    parent = getattr(node, "parent", None)
    if parent is None:
        return False
    # Walk up to find a call_expression ancestor
    cursor = parent
    depth = 0
    while cursor is not None and depth < 6:
        if cursor.type in ("call_expression", "new_expression"):
            fn_node = cursor.children[0] if cursor.children else None
            if fn_node is not None:
                fn_text = (fn_node.text or b"").decode("utf8", errors="replace")
                parts = fn_text.split(".")
                if parts[0] in _NON_I18N_CALL_NAMES:
                    return True
            break
        cursor = getattr(cursor, "parent", None)
        depth += 1
    return False


def _analyze_js_file(
    path: Path,
    source: bytes,
    ignore_list: list[str],
) -> list[Finding]:
    """Extract user-facing hardcoded strings from a JS/TS/JSX file."""
    parser, language = _get_parser_for(path)
    if parser is None:
        return []

    tree = parser.parse(source)
    findings: list[Finding] = []
    ignore_set = {s.lower() for s in ignore_list}

    for node in _iter_nodes(tree.root_node, frozenset({"jsx_text", "jsx_attribute"})):
        if node.type == "jsx_text":
            text = (node.text or b"").decode("utf8", errors="replace")
            text = text.strip()
            if not text or _is_boring(text) or text.lower() in ignore_set:
                continue
            if _is_inside_non_i18n_call(node):
                continue
            line = node.start_point[0] + 1
            col = node.start_point[1]
            findings.append(_make_finding(path, line, col, text, "high", Severity.WARNING))

        elif node.type == "jsx_attribute":
            # Check if this is a user-facing attribute
            attr_name = ""
            string_value = ""
            string_node = None
            for child in node.children:
                if child.type == "property_identifier":
                    attr_name = (child.text or b"").decode("utf8", errors="replace").lower()
                elif child.type == "string":
                    string_node = child
                    for frag in child.children:
                        if frag.type == "string_fragment":
                            string_value = (frag.text or b"").decode("utf8", errors="replace")
                            break

            normalized = attr_name.replace("-", "").lower()
            is_user_facing = attr_name in _USER_FACING_ATTRS or normalized in {
                a.replace("-", "") for a in _USER_FACING_ATTRS
            }
            if not is_user_facing or not string_value:
                continue
            if _is_boring(string_value) or string_value.lower() in ignore_set:
                continue
            if string_node is not None:
                line = string_node.start_point[0] + 1
                col = string_node.start_point[1]
            else:
                line = node.start_point[0] + 1
                col = node.start_point[1]
            findings.append(
                _make_finding(path, line, col, string_value, "high", Severity.WARNING)
            )

    return findings


# --------------------------------------------------------------------------- #
# Python analysis via stdlib ast                                               #
# --------------------------------------------------------------------------- #


class _PyStringVisitor(ast.NodeVisitor):
    """AST visitor that collects user-facing string literals in Python source."""

    def __init__(self, path: Path, ignore_set: set[str]) -> None:
        self._path = path
        self._ignore_set = ignore_set
        self._findings: list[Finding] = []
        # Track whether we're inside a non-i18n context
        self._skip_depth = 0

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _record(self, s: str, lineno: int, col: int, confidence: str) -> None:
        if _is_boring(s) or s.lower() in self._ignore_set:
            return
        # Require at least one space (looks like a phrase) for LOW confidence
        if confidence == "low" and " " not in s:
            return
        sev = Severity.WARNING if confidence in ("high", "medium") else Severity.INFO
        self._findings.append(_make_finding(self._path, lineno, col, s, confidence, sev))

    # ------------------------------------------------------------------ #
    # Visitors                                                             #
    # ------------------------------------------------------------------ #

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        # Identify the callee name
        func = node.func
        callee: str | None = None
        if isinstance(func, ast.Name):
            callee = func.id
        elif isinstance(func, ast.Attribute):
            callee = func.attr

        if callee in _NON_I18N_CALL_NAMES:
            # Don't descend into console.log / logging.debug etc.
            return

        if callee in _PY_USER_FACING_CALLS:
            # Positional string args of these callables are user-facing (MEDIUM)
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    self._record(arg.value, arg.lineno, arg.col_offset, "medium")
            # Keyword arg "detail" or "message" in HTTPException/ValidationError
            for kw in node.keywords:
                if kw.arg in ("detail", "message", "description") and isinstance(
                    kw.value, ast.Constant
                ):
                    v = kw.value
                    if isinstance(v.value, str):
                        self._record(v.value, v.lineno, v.col_offset, "medium")

        self.generic_visit(node)

    def visit_Raise(self, node: ast.Raise) -> None:  # noqa: N802
        # raise Exception("message") — the string is user-facing at MEDIUM confidence
        if node.exc is not None and isinstance(node.exc, ast.Call):
            for arg in node.exc.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    self._record(arg.value, arg.lineno, arg.col_offset, "medium")
            for kw in node.exc.keywords:
                if kw.arg in ("detail", "message") and isinstance(kw.value, ast.Constant):
                    v = kw.value
                    if isinstance(v.value, str):
                        self._record(v.value, v.lineno, v.col_offset, "medium")
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:  # noqa: N802
        # Generic string constant â€” LOW confidence only if it looks like a sentence
        if isinstance(node.value, str) and " " in node.value:
            self._record(node.value, node.lineno, node.col_offset, "low")
        # Note: we don't call generic_visit here because Constant has no children


def _analyze_py_file(path: Path, source: str, ignore_list: list[str]) -> list[Finding]:
    """Extract user-facing hardcoded strings from a Python source file."""
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return []

    ignore_set = {s.lower() for s in ignore_list}
    visitor = _PyStringVisitor(path, ignore_set)
    visitor.visit(tree)
    return visitor._findings


# --------------------------------------------------------------------------- #
# Public entry point                                                           #
# --------------------------------------------------------------------------- #


def check_hardcoded_strings(
    ctx: ScanContext,
    framework: FrameworkInfo,
    config: dict,
) -> list[Finding]:
    """Scan *ctx.files* for hardcoded user-facing string literals.

    Returns a list of Finding objects. Respects the ``i18n.ignore_strings``
    config key (list of strings to skip).
    """
    ignore_list: list[str] = config.get("ignore_strings", [])
    findings: list[Finding] = []

    for file_path in ctx.files:
        if _is_test_file(file_path):
            continue

        ext = file_path.suffix.lower()

        if ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
            try:
                source = file_path.read_bytes()
            except OSError:
                continue
            findings.extend(_analyze_js_file(file_path, source, ignore_list))

        elif ext == ".py":
            try:
                source = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(_analyze_py_file(file_path, source, ignore_list))

    return findings
