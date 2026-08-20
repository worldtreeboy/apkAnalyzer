"""Reusable modules for APK Analyzer.

The legacy :mod:`apkAnalyzer` module remains the supported executable and
compatibility surface while implementation details are moved here gradually.
"""

from .version import TOOL_VERSION


__version__ = TOOL_VERSION
__all__ = ["TOOL_VERSION", "__version__"]
