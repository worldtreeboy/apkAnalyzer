"""Framework and native SDK detection.

Imported by apkAnalyzer.py, which binds these functions into the
launcher module so existing imports and monkeypatches keep working.
"""

import subprocess
import sys
import os
import stat
import hashlib
import posixpath
import re
import time
import shlex
import shutil
import lzma
import tempfile
import json
import argparse
import urllib.request
import urllib.parse
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime

from . import archive as archive_mod
from . import code_scan as code_scan_mod
from . import cli as cli_mod
from . import inputs as input_mod
from . import process as process_mod
from . import secrets as secrets_mod
from . import resources as resource_mod
from .process import (
    CommandOutputLimitExceeded,
    RuntimeCheckUnavailable,
    command_failed as _process_command_failed,
    is_error_output as _process_is_error_output,
    parse_android_ps as _parse_android_ps,
    require_runtime_command as _process_require_runtime_command,
    run_command as _process_run_command,
    run_command_capture as _process_run_command_capture,
)
from .reporting import (
    ReportCollector,
    now_iso as _now_iso,
    report,
)
from .safety import (
    MAX_XML_BYTES,
    _PACKAGE_RE,
    is_link_or_reparse_stat as _is_link_or_reparse_stat,
    is_valid_package as _is_valid_package,
    parse_sdk_level as _parse_sdk_level,
    safe_parse_xml as _safe_parse_xml,
    terminal_safe as _terminal_safe,
)
from .static_rules import (
    analyze_clipboard_writes as _analyze_clipboard_writes,
    analyze_pending_intents as _analyze_pending_intents,
    classify_deep_link as _classify_deep_link,
)
from .ui import (
    C,
    banner,
    clear,
    configure_windows_streams as _configure_windows_streams,
    info_line,
    pass_fail,
    pause,
    section,
    status_line,
    warn_line,
)
from .version import TOOL_VERSION

# ─── Native SDK signatures (matched against .so filenames in lib/) ────────────

NATIVE_SDK_SIGNATURES = {
    "VKey VGuard":    ["libvguard.so", "libchecks.so", "libvosWrapperEx.so"],
    "Zimperium":      ["libzdefend.so", "libz9.so"],
    "Promon SHIELD":  ["libshield.so"],
    "DexGuard":       ["libdexguard.so"],
    "Frida Gadget":   ["libfrida-gadget.so"],
}

def detect_framework(decompiled_dir):
    """Detect app framework and native SDKs.

    Priority: Flutter > React Native > Xamarin > Unity > Cordova > Kotlin > Java
    Each check collects its own indicators; only the winning framework's
    indicators are returned to avoid misleading mixed details.

    Returns dict with keys:
        framework: str
        native_sdks: list of (sdk_name, [matched .so files])
        details: list of indicator files/dirs found
    """
    # ── Collect native libs ─────────────────────────────────────────────
    so_files = _scan_native_libs(decompiled_dir)
    so_names = {name for name, _ in so_files}
    so_map = {}
    for name, rel in so_files:
        so_map.setdefault(name, []).append(rel)

    analysis_roots = list(_iter_decompiled_roots(decompiled_dir))
    smali_roots = _safe_smali_roots(decompiled_dir)

    def directory_indicator(parts):
        for analysis_root in analysis_roots:
            path = _safe_relative_path(analysis_root, parts)
            if path is not None:
                return os.path.relpath(path, decompiled_dir).replace(os.sep, "/") + "/"
        return None

    def file_indicator(parts):
        for analysis_root in analysis_roots:
            path = _safe_relative_path(
                analysis_root, parts, final_kind="file"
            )
            if path is not None:
                return os.path.relpath(path, decompiled_dir).replace(os.sep, "/")
        return None

    framework = None
    details = []

    # ── Flutter ──────────────────────────────────────────────────────────
    fl = []
    if "libflutter.so" in so_map:
        fl.append(so_map["libflutter.so"][0])
    if "libapp.so" in so_map:
        fl.append(so_map["libapp.so"][0])
    indicator = directory_indicator(("assets", "flutter_assets"))
    if indicator:
        fl.append(indicator)
    for smali_root, display_root in smali_roots:
        if _safe_relative_path(smali_root, ("io", "flutter")):
            fl.append(f"{display_root}/io/flutter/")
            break
    if fl:
        framework = "Flutter"
        details = fl

    # ── React Native ─────────────────────────────────────────────────────
    if not framework:
        rn = []
        rn_libs = {"libreactnativejni.so", "libreactnative.so", "libhermes.so",
                    "libjsc.so", "libhermestooling.so"}
        for name in rn_libs & so_names:
            rn.append(so_map[name][0])
        indicator = file_indicator(("assets", "index.android.bundle"))
        if indicator:
            rn.append(indicator)
        for smali_root, display_root in smali_roots:
            if _safe_relative_path(
                    smali_root, ("com", "facebook", "react")):
                rn.append(f"{display_root}/com/facebook/react/")
                break
        if rn:
            framework = "React Native"
            details = rn

    # ── Xamarin ──────────────────────────────────────────────────────────
    if not framework:
        xm = []
        xm_libs = {"libmonodroid.so", "libmonosgen-2.0.so", "libxamarin-app.so",
                    "libxamarin-debug-app-helper.so"}
        for name in xm_libs & so_names:
            xm.append(so_map[name][0])
        for parts in (("assemblies",), ("unknown", "assemblies")):
            indicator = directory_indicator(parts)
            if indicator:
                xm.append(indicator)
        if xm:
            framework = "Xamarin"
            details = xm

    # ── Unity ────────────────────────────────────────────────────────────
    if not framework:
        un = []
        unity_definitive = {"libunity.so", "libil2cpp.so"}
        unity_supporting = {"libmain.so", "libgameassembly.so"}
        for name in (unity_definitive | unity_supporting) & so_names:
            un.append(so_map[name][0])
        indicator = directory_indicator(("assets", "bin", "Data"))
        if indicator:
            un.append(indicator)
        # Need a definitive lib OR 2+ supporting indicators
        if unity_definitive & so_names or len(un) >= 2:
            framework = "Unity"
            details = un

    # ── Cordova / Ionic ──────────────────────────────────────────────────
    if not framework:
        cd = []
        indicator = directory_indicator(("assets", "www"))
        if indicator:
            cd.append(indicator)
            cordova_script = file_indicator(("assets", "www", "cordova.js"))
            if cordova_script:
                cd.append(cordova_script)
        for smali_root, display_root in smali_roots:
            if _safe_relative_path(
                    smali_root, ("org", "apache", "cordova")):
                cd.append(f"{display_root}/org/apache/cordova/")
                break
        if cd:
            framework = "Cordova"
            details = cd

    # ── Kotlin ───────────────────────────────────────────────────────────
    if not framework:
        for smali_root, display_root in smali_roots:
            if _safe_relative_path(smali_root, ("kotlin",)):
                framework = "Kotlin"
                details = [f"{display_root}/kotlin/"]
                break

    # ── Default ──────────────────────────────────────────────────────────
    if not framework:
        framework = "Java"

    # ── Native SDK detection (always run) ───────────────────────────────
    native_sdks = []
    for sdk_name, signatures in NATIVE_SDK_SIGNATURES.items():
        matched = [s for s in signatures if s in so_names]
        if matched:
            native_sdks.append((sdk_name, matched))

    return {
        "framework": framework,
        "native_sdks": native_sdks,
        "details": details,
    }

def _print_framework_info(fw_info):
    """Print detected framework and native SDK info."""
    fw = fw_info["framework"]
    details = fw_info["details"]
    native_sdks = fw_info["native_sdks"]

    fw_labels = {
        "Flutter": "Flutter (Dart)",
        "React Native": "React Native (JavaScript)",
        "Xamarin": "Xamarin (.NET)",
        "Unity": "Unity (C#/IL2CPP)",
        "Cordova": "Cordova/Ionic (Web)",
        "Kotlin": "Kotlin/JVM",
        "Java": "Java (Native Android)",
    }
    label = fw_labels.get(fw, fw)

    print(f"\n  {C.YELLOW}{C.BOLD}── Framework Detection ──{C.RST}")
    print(f"  {C.BOLD}Framework Detected:{C.RST} {C.GREEN}{label}{C.RST}")
    if details:
        safe_details = [_safe_evidence_path(item) for item in details]
        print(f"  {C.DIM}Indicators: {', '.join(safe_details)}{C.RST}")
    if native_sdks:
        sdk_parts = []
        for sdk_name, matched_files in native_sdks:
            sdk_parts.append(f"{sdk_name} ({', '.join(matched_files)})")
        print(f"  {C.MAGENTA}Native SDKs: {', '.join(sdk_parts)}{C.RST}")
    print()

_FLUTTER_GROUPS = {
    "Flutter Security Plugins",
}
_RN_GROUPS = {
    "React Native Security",
}

KEYWORD_SEARCH_MAX_MATCHES = 20_000
KEYWORD_SEARCH_MAX_MATCHES_PER_GROUP = 2_000
KEYWORD_SEARCH_MAX_LINE_CHARS = 512


def _search_decompiled(decompiled_dir, keyword_groups, framework=None,
                       include_coverage=False, max_file_bytes=None,
                       max_total_bytes=None):
    """Search decompiled directory for keyword groups (case-insensitive).
    Each candidate is read once with the shared non-symlink byte budgets.

    keyword_groups: list of (group_name, [keywords])
    framework: optional detected framework name — used to skip irrelevant
               framework-specific groups and to extend file extensions.
    By default returns the legacy ``(results, scanned_file_count)`` pair.
    ``include_coverage=True`` appends the reusable coverage result.
    """
    extensions = {
        '.smali', '.xml', '.json', '.properties', '.txt', '.cfg', '.conf',
        '.yml', '.yaml', '.js',
    }
    if framework == "React Native":
        extensions.add('.bundle')

    # Filter out framework-specific groups that don't match the detected framework
    skip_groups = set()
    if framework != "Flutter":
        skip_groups |= _FLUTTER_GROUPS
    if framework != "React Native":
        skip_groups |= _RN_GROUPS

    # Build flat lookup for all keywords across all groups
    all_keywords = []  # (kw_lower, kw_orig, group_name)
    for group_name, keywords in keyword_groups:
        if group_name in skip_groups:
            continue
        for kw in keywords:
            all_keywords.append((kw.lower(), kw, group_name))

    results = {gn: [] for gn, _ in keyword_groups}
    match_count = 0
    result_budget_exhausted = False

    def consume(relative, content):
        nonlocal match_count, result_budget_exhausted
        if result_budget_exhausted:
            return False

        complete = True
        for line_no, line in enumerate(content.splitlines(), 1):
            line_lower = line.lower()
            for keyword_lower, keyword_original, group_name in all_keywords:
                if keyword_lower not in line_lower:
                    continue
                if (match_count >= KEYWORD_SEARCH_MAX_MATCHES
                        or len(results[group_name])
                        >= KEYWORD_SEARCH_MAX_MATCHES_PER_GROUP):
                    complete = False
                    if match_count >= KEYWORD_SEARCH_MAX_MATCHES:
                        result_budget_exhausted = True
                        return False
                    continue
                display_line = _terminal_safe(line.strip())
                if len(display_line) > KEYWORD_SEARCH_MAX_LINE_CHARS:
                    display_line = (
                        display_line[:KEYWORD_SEARCH_MAX_LINE_CHARS - 3]
                        + "..."
                    )
                results[group_name].append(
                    (relative, line_no, display_line, keyword_original)
                )
                match_count += 1
        return complete

    coverage = code_scan_mod.scan_tree(
        decompiled_dir,
        consume,
        extensions=tuple(sorted(extensions)),
        max_file_bytes=(STATIC_CODE_MAX_FILE_BYTES if max_file_bytes is None
                        else max_file_bytes),
        max_total_bytes=(STATIC_CODE_MAX_TOTAL_BYTES if max_total_bytes is None
                         else max_total_bytes),
        chunk_bytes=STATIC_CODE_CHUNK_BYTES,
    )
    output = (results, len(coverage.scanned))
    if include_coverage:
        return output + (coverage,)
    return output


__all__ = [
    'NATIVE_SDK_SIGNATURES',
    'detect_framework',
    '_print_framework_info',
    '_FLUTTER_GROUPS',
    '_RN_GROUPS',
    'KEYWORD_SEARCH_MAX_MATCHES',
    'KEYWORD_SEARCH_MAX_MATCHES_PER_GROUP',
    'KEYWORD_SEARCH_MAX_LINE_CHARS',
    '_search_decompiled',
]
