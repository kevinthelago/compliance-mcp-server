"""Internationalization (i18n) compliance lens — sub-checks and public API."""

from .catalog_coverage import check_catalog_coverage
from .framework_detection import FrameworkInfo, detect_framework
from .hardcoded_strings import check_hardcoded_strings
from .locale_formatting import check_locale_formatting
from .rtl_css import check_rtl_css

__all__ = [
    "FrameworkInfo",
    "check_catalog_coverage",
    "check_hardcoded_strings",
    "check_locale_formatting",
    "check_rtl_css",
    "detect_framework",
]
