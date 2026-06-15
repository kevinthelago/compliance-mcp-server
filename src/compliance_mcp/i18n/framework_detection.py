"""I18N-5 (partial): Detect the JavaScript/Python framework used in a project.

Framework context is used by the hardcoded-strings check to select appropriate
AST heuristics — e.g. React projects include TSX files and JSX expressions that
plain JS projects do not have.
"""

from __future__ import annotations

import json
from pathlib import Path


class FrameworkInfo:
    """Result of framework detection."""

    def __init__(
        self,
        js_framework: str | None = None,
        py_framework: str | None = None,
        has_jsx: bool = False,
        has_tsx: bool = False,
        i18n_library: str | None = None,
    ) -> None:
        self.js_framework = js_framework  # "react", "vue", "angular", "next", "svelte", None
        self.py_framework = py_framework  # "django", "flask", "fastapi", None
        self.has_jsx = has_jsx
        self.has_tsx = has_tsx
        self.i18n_library = i18n_library  # "i18next", "react-intl", "vue-i18n", "gettext", None

    def __repr__(self) -> str:
        return (
            f"FrameworkInfo(js={self.js_framework!r}, py={self.py_framework!r}, "
            f"jsx={self.has_jsx}, tsx={self.has_tsx}, i18n={self.i18n_library!r})"
        )


_JS_FRAMEWORK_DEPS: dict[str, list[str]] = {
    "next": ["next"],
    "react": ["react", "react-dom"],
    "vue": ["vue", "@vue/core"],
    "angular": ["@angular/core"],
    "svelte": ["svelte"],
    "solid": ["solid-js"],
    "nuxt": ["nuxt"],
}

_JS_I18N_DEPS: dict[str, list[str]] = {
    "i18next": ["i18next", "react-i18next", "i18next-browser-languagedetector"],
    "react-intl": ["react-intl", "formatjs"],
    "vue-i18n": ["vue-i18n"],
    "lingui": ["@lingui/core", "@lingui/react"],
    "next-intl": ["next-intl"],
}

_PY_FRAMEWORK_DEPS: dict[str, list[str]] = {
    "django": ["django", "Django"],
    "flask": ["flask", "Flask"],
    "fastapi": ["fastapi", "FastAPI"],
}


def detect_framework(root: Path) -> FrameworkInfo:
    """Detect JS and Python frameworks in use under *root*."""
    info = FrameworkInfo()

    # --- JavaScript: inspect package.json ---------------------------------
    pkg_json = root / "package.json"
    if pkg_json.exists():
        try:
            pkg = json.loads(pkg_json.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pkg = {}

        all_deps: set[str] = set()
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            all_deps.update(pkg.get(section, {}).keys())

        # Detect JS framework (check next before react — Next is a superset)
        for fw, markers in _JS_FRAMEWORK_DEPS.items():
            if any(m in all_deps for m in markers):
                info.js_framework = fw
                break

        # Detect i18n library
        for lib, markers in _JS_I18N_DEPS.items():
            if any(m in all_deps for m in markers):
                info.i18n_library = lib
                break

        # JSX/TSX presence
        info.has_jsx = info.js_framework in ("react", "next", "solid")
        info.has_tsx = info.has_jsx  # assume TSX where JSX is expected

    # Check actual file extensions if no package.json clue
    if not info.has_jsx:
        info.has_jsx = any(root.rglob("*.jsx"))
    if not info.has_tsx:
        info.has_tsx = any(root.rglob("*.tsx"))

    # --- Python: inspect requirements.txt or pyproject.toml ---------------
    req_txt = root / "requirements.txt"
    if req_txt.exists():
        try:
            reqs = req_txt.read_text(encoding="utf-8").lower()
        except OSError:
            reqs = ""
        for fw, markers in _PY_FRAMEWORK_DEPS.items():
            if any(m.lower() in reqs for m in markers):
                info.py_framework = fw
                break

    if info.py_framework is None:
        pyproject = root / "pyproject.toml"
        if pyproject.exists():
            try:
                content = pyproject.read_text(encoding="utf-8").lower()
            except OSError:
                content = ""
            for fw, markers in _PY_FRAMEWORK_DEPS.items():
                if any(m.lower() in content for m in markers):
                    info.py_framework = fw
                    break

    # Django uses gettext by default
    if info.py_framework == "django" and info.i18n_library is None:
        info.i18n_library = "gettext"

    return info
