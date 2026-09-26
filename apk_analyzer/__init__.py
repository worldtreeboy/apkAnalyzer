"""Reusable modules for APK Analyzer.

:mod:`apkAnalyzer` remains the supported executable. Device access, decompile
caching, manifest and static scanning, runtime checks, Frida tooling, and the
interactive menu live in this package. The launcher binds those functions into
its own module namespace so existing imports and monkeypatches keep working.
"""

from .version import TOOL_VERSION


__version__ = TOOL_VERSION
__all__ = ["TOOL_VERSION", "__version__"]
