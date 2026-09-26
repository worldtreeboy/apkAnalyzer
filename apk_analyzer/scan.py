"""Static security scan and its check catalog.

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
    analyze_broadcast_sends as _analyze_broadcast_sends,
    analyze_clipboard_writes as _analyze_clipboard_writes,
    analyze_pending_intents as _analyze_pending_intents,
    analyze_webview_settings as _analyze_webview_settings,
    classify_backup_xml as _classify_backup_xml,
    classify_deep_link as _classify_deep_link,
    combine_backup_policy as _combine_backup_policy,
    correlate_permission_apis as _correlate_permission_apis,
    match_permission_apis as _match_permission_apis,
    webview_setting_severity as _webview_setting_severity,
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
from .version import (
    CURRENT_PLAY_TARGET_SDK,
    EXISTING_APP_TARGET_SDK_FLOOR,
    TOOL_VERSION,
)


# ─── OWASP MASVS v2.0 Mapping & Severity for Security Checks ─────────────────

SECURITY_CHECKS = {
    "debuggable": {
        "severity": "CRITICAL",
        "masvs": "MASVS-RESILIENCE-1",
        "cwe": "CWE-489",
        "title": "Application is Debuggable",
        "remediation": "Set android:debuggable='false' in release builds",
    },
    "allow_backup": {
        "severity": "HIGH",
        "masvs": "MASVS-STORAGE-1",
        "cwe": "CWE-530",
        "title": "Backup Enabled Without Restrictions",
        "remediation": "Set android:allowBackup='false' or define backup rules",
    },
    "exported_components": {
        "severity": "HIGH",
        "masvs": "MASVS-PLATFORM-1",
        "cwe": "CWE-926",
        "title": "Exported Components Without Protection",
        "remediation": "Set android:exported='false' or add permission checks",
    },
    "dangerous_permissions": {
        "severity": "INFO",
        "masvs": "MASVS-PLATFORM-1",
        "cwe": "CWE-250",
        "title": "Dangerous Permissions Requested",
        "remediation": "Review necessity and request dangerous permissions only at runtime",
    },
    "permission_without_api": {
        "severity": "MEDIUM",
        "masvs": "MASVS-PLATFORM-1",
        "cwe": "CWE-250",
        "title": "Dangerous Permission Without Mapped API",
        "remediation": (
            "Remove dangerous permissions whose mapped platform API is "
            "absent, or keep the code that uses them"
        ),
    },
    "api_without_permission": {
        "severity": "HIGH",
        "masvs": "MASVS-PLATFORM-1",
        "cwe": "CWE-250",
        "title": "Platform API Without Declared Permission",
        "remediation": (
            "Declare the permission that covers each mapped platform API, "
            "including a permission that lives only in a feature split"
        ),
    },
    "cleartext_traffic": {
        "severity": "HIGH",
        "masvs": "MASVS-NETWORK-1",
        "cwe": "CWE-319",
        "title": "Cleartext Traffic Allowed",
        "remediation": "Set android:usesCleartextTraffic='false' and enforce HTTPS",
    },
    "network_security_config": {
        "severity": "MEDIUM",
        "masvs": "MASVS-NETWORK-1",
        "cwe": "CWE-295",
        "title": "Missing or Weak Network Security Config",
        "remediation": "Define a network_security_config.xml with certificate pinning",
    },
    "deeplinks": {
        "severity": "MEDIUM",
        "masvs": "MASVS-PLATFORM-2",
        "cwe": "CWE-939",
        "title": "Deeplink / URI Scheme Hijacking Risk",
        "remediation": "Validate all deeplink parameters; use App Links with autoVerify",
    },
    "hardcoded_secrets": {
        "severity": "CRITICAL",
        "masvs": "MASVS-STORAGE-1",
        "cwe": "CWE-798",
        "title": "Hardcoded Secrets Detected",
        "remediation": "Store secrets in Android Keystore or server-side; never in source",
    },
    "webview_js_interface": {
        "severity": "HIGH",
        "masvs": "MASVS-PLATFORM-2",
        "cwe": "CWE-749",
        "title": "WebView JavaScript Interface Exposed",
        "remediation": "Restrict addJavascriptInterface to SDK >= 17; validate JS inputs",
    },
    "webview_insecure_settings": {
        "severity": "HIGH",
        "masvs": "MASVS-PLATFORM-2",
        "cwe": "CWE-749",
        "title": "Insecure WebView Settings",
        "remediation": (
            "Disable file and universal file access, WebView debugging, "
            "and MIXED_CONTENT_ALWAYS_ALLOW in release builds"
        ),
    },
    "debug_logging": {
        "severity": "MEDIUM",
        "masvs": "MASVS-STORAGE-1",
        "cwe": "CWE-532",
        "title": "Debug / Verbose Logging in Production",
        "remediation": "Remove Log.d()/Log.v() calls or use ProGuard to strip them",
    },
    "unprotected_broadcasts": {
        "severity": "MEDIUM",
        "masvs": "MASVS-PLATFORM-1",
        "cwe": "CWE-927",
        "title": "Unprotected Broadcast Receivers",
        "remediation": "Use LocalBroadcastManager or add permission to sendBroadcast()",
    },
    "flag_secure": {
        "severity": "LOW",
        "masvs": "MASVS-RESILIENCE-2",
        "cwe": "CWE-200",
        "title": "FLAG_SECURE Not Set (Screenshot Protection)",
        "remediation": "Set FLAG_SECURE on sensitive Activities to block screenshots",
    },
    "clipboard_exposure": {
        "severity": "MEDIUM",
        "masvs": "MASVS-STORAGE-2",
        "cwe": "CWE-200",
        "title": "Clipboard Data Exposure Risk",
        "remediation": ("Set ClipDescription.EXTRA_IS_SENSITIVE=true in the "
                        "ClipDescription extras and clear sensitive clipboard data promptly"),
    },
    "keyboard_cache": {
        "severity": "LOW",
        "masvs": "MASVS-STORAGE-2",
        "cwe": "CWE-524",
        "title": "Keyboard Cache Not Disabled",
        "remediation": "Use textNoSuggestions / flagNoPersonalizedLearning on sensitive fields",
    },
    "tapjacking": {
        "severity": "MEDIUM",
        "masvs": "MASVS-PLATFORM-2",
        "cwe": "CWE-1021",
        "title": "Tapjacking / Overlay Attack Vulnerability",
        "remediation": "Set filterTouchesWhenObscured='true' on sensitive Views",
    },
    "sdk_version": {
        "severity": "MEDIUM",
        "masvs": "MASVS-CODE-1",
        "cwe": "CWE-1104",
        "title": "Outdated SDK Version Targeted",
        "remediation": (
            "Raise minSdkVersion to 23+ and targetSdkVersion to "
            f"{CURRENT_PLAY_TARGET_SDK}+ for new Play uploads. "
            f"{EXISTING_APP_TARGET_SDK_FLOOR}+ keeps an already-published "
            "phone app visible to new users."
        ),
    },
    "pending_intent_mutable": {
        "severity": "HIGH",
        "masvs": "MASVS-PLATFORM-1",
        "cwe": "CWE-927",
        "title": "PendingIntent Without Immutability Flag",
        "remediation": "Use FLAG_IMMUTABLE for PendingIntents unless mutability is required",
    },
    "task_hijacking": {
        "severity": "HIGH",
        "masvs": "MASVS-PLATFORM-1",
        "cwe": "CWE-200",
        "title": "Task Hijacking (StrandHogg) Risk",
        "remediation": "Set taskAffinity='' (empty) and launchMode='singleInstance'",
    },
    "apk_signing": {
        "severity": "HIGH",
        "masvs": "MASVS-RESILIENCE-2",
        "cwe": "CWE-347",
        "title": "Weak APK Signing Scheme",
        "remediation": "Sign with v2/v3 scheme; v1-only is vulnerable to Janus (CVE-2017-13156)",
    },
}

# Severity color mapping for security scan output
_SEVERITY_COLORS = {
    "CRITICAL": C.RED,
    "HIGH":     C.RED,
    "MEDIUM":   C.YELLOW,
    "LOW":      C.BLUE,
}

def _severity_tag(check_key):
    """Return a colored severity tag with MASVS/CWE ref string for a given check key."""
    info = SECURITY_CHECKS.get(check_key, {})
    sev = info.get("severity", "MEDIUM")
    masvs = info.get("masvs", "")
    cwe = info.get("cwe", "")
    color = _SEVERITY_COLORS.get(sev, C.YELLOW)
    return f"{color}[{sev}]{C.RST}", f"{C.DIM}({masvs} | {cwe}){C.RST}"

def _finding_line(check_key, label, detail="", severity=None):
    """Print a FAIL finding with severity, MASVS category, and CWE ID."""
    info = SECURITY_CHECKS.get(check_key, {})
    sev = severity or info.get("severity", "MEDIUM")
    masvs = info.get("masvs", "")
    cwe = info.get("cwe", "")
    color = _SEVERITY_COLORS.get(sev, C.YELLOW)
    sev_tag = f"{color}[{sev}]{C.RST}"
    ref_tag = f"{C.DIM}({masvs} | {cwe}){C.RST}"
    extra = f" {C.DIM}-- {detail}{C.RST}" if detail else ""
    print(f"  {sev_tag} {label}  {ref_tag}{extra}")


def _static_secret_window_has_match(content, final_window):
    """Ignore matches ending at an artificial chunk boundary until look-ahead."""
    for match in _iter_secret_matches(content, per_pattern_limit=1):
        if final_window or match.end() < len(content):
            return True
    return False


def _scan_static_secret_tree(decompiled_dir, max_file_bytes=None,
                             max_total_bytes=None, chunk_bytes=None,
                             overlap_chars=None):
    """Scan likely-text files using the legacy structured regex engine."""
    return secrets_mod.scan_tree(
        decompiled_dir,
        _static_secret_window_has_match,
        extensions=STATIC_SECRET_EXTENSIONS,
        max_file_bytes=(STATIC_SECRET_MAX_FILE_BYTES if max_file_bytes is None
                        else max_file_bytes),
        max_total_bytes=(STATIC_SECRET_MAX_TOTAL_BYTES if max_total_bytes is None
                         else max_total_bytes),
        chunk_bytes=(STATIC_SECRET_CHUNK_BYTES if chunk_bytes is None
                     else chunk_bytes),
        overlap_chars=(STATIC_SECRET_CHUNK_OVERLAP_CHARS
                       if overlap_chars is None else overlap_chars),
    )


def _find_static_secret_files(decompiled_dir):
    """Compatibility wrapper returning secret-bearing relative paths only."""
    return _scan_static_secret_tree(decompiled_dir).matches


def _classify_static_secret_files(decompiled_dir, relative_paths):
    """Split secret-bearing paths by live-key shape and library ownership.

    A second bounded read is limited to files that already matched. Generic
    ``password=`` assignments stay medium confidence. Known live shapes stay
    high confidence even when they sit in an SDK tree.
    """
    groups = {
        "live_app": [],
        "live_sdk": [],
        "generic_app": [],
        "generic_sdk": [],
    }
    root = os.path.abspath(os.fspath(decompiled_dir))
    for relative in relative_paths:
        state = {"live": False}

        def matcher(text, final_window, observed=state):
            found = False
            for match in _iter_secret_matches(text):
                if not final_window and match.end() >= len(text):
                    continue
                found = True
                value, _span = _secret_value_and_span(match)
                if _is_live_secret_value(value):
                    observed["live"] = True
            return found

        secrets_mod.scan_file(
            os.path.join(root, relative),
            matcher,
            max_bytes=STATIC_SECRET_MAX_FILE_BYTES,
            chunk_bytes=STATIC_SECRET_CHUNK_BYTES,
            overlap_chars=STATIC_SECRET_CHUNK_OVERLAP_CHARS,
        )
        sdk_path = _is_sdk_static_path(relative)
        if state["live"]:
            key = "live_sdk" if sdk_path else "live_app"
        else:
            key = "generic_sdk" if sdk_path else "generic_app"
        groups[key].append(relative)
    return groups


_BACKUP_LEVEL_ORDER = ("open", "databases_excluded", "private_excluded")


def _worst_backup_level(levels):
    present = [level for level in levels if level]
    if not present:
        return "open"
    return min(present, key=_BACKUP_LEVEL_ORDER.index)


def _load_backup_document(decompiled_dir, reference, min_level, package,
                          document_key):
    """Return ``(level, broken)`` for one manifest backup-rules reference."""
    if not reference:
        return None, False
    if not str(reference).lstrip().startswith("@"):
        return None, True
    resolution = _resolve_resource_variants(
        decompiled_dir,
        reference,
        expected_type="xml",
        min_sdk=min_level or 1,
        local_package=package,
    )
    paths = list(resolution.get("paths") or ())
    if not paths:
        return None, True
    levels = []
    for path in paths:
        try:
            root = _safe_parse_xml(path).getroot()
        except (ET.ParseError, OSError, ValueError):
            return None, True
        classified = _classify_backup_xml(root)
        level = classified.get(document_key) if classified else None
        if not level:
            return None, True
        levels.append(level)
    return _worst_backup_level(levels), False


def _assess_backup_rules(decompiled_dir, manifest, min_level, target_level):
    """Return open, excluded, or unknown for the applicable API ranges."""
    package = manifest.get("package")
    full_level, full_broken = _load_backup_document(
        decompiled_dir,
        manifest.get("full_backup_content"),
        min_level,
        package,
        "full",
    )
    extraction_level, extraction_broken = _load_backup_document(
        decompiled_dir,
        manifest.get("data_extraction_rules"),
        min_level,
        package,
        "extraction",
    )
    return _combine_backup_policy(
        min_level,
        target_level,
        full_level,
        extraction_level,
        full_broken=full_broken,
        extraction_broken=extraction_broken,
    )


def _secret_finding_evidence(groups):
    """Return severity, confidence, location, and path list for one secret set."""
    if groups["live_app"] or groups["live_sdk"]:
        app_files = groups["live_app"]
        return {
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "where": (
                "app code" if app_files else "SDK/library paths only"
            ),
            "files": app_files or groups["live_sdk"],
            "live": True,
        }
    if groups["generic_app"]:
        return {
            "severity": "MEDIUM",
            "confidence": "MEDIUM",
            "where": "app code; value did not match a known live-key shape",
            "files": groups["generic_app"],
            "live": False,
        }
    return {
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "where": (
            "SDK/library paths only; value did not match a known "
            "live-key shape"
        ),
        "files": groups["generic_sdk"],
        "live": False,
    }


def _safe_evidence_path(path, limit=240):
    """Render an APK-controlled path without leaking credential-like names."""
    single_line = _terminal_safe(path).replace("\r", " ").replace("\n", " ")
    return _redact_secret_text(single_line).strip()[:limit]


def _safe_coverage_metadata(value):
    """Redact APK-controlled paths/reasons before serializing coverage data."""
    if isinstance(value, str):
        return _safe_evidence_path(value, 1000)
    if isinstance(value, list):
        return [_safe_coverage_metadata(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_safe_coverage_metadata(item) for item in value)
    if isinstance(value, dict):
        return {
            key: _safe_coverage_metadata(item)
            for key, item in value.items()
        }
    return value


def _print_static_secret_coverage(scan_result):
    """Print bounded details explaining an incomplete static secret scan."""
    if scan_result.coverage_complete:
        return
    print(
        f"    {C.DIM}Coverage: {scan_result.incomplete_reason()}; "
        f"{scan_result.bytes_scanned} bytes scanned "
        f"(limits: {scan_result.per_file_byte_budget} per file, "
        f"{scan_result.total_byte_budget} total){C.RST}"
    )
    categories = (
        ("unreadable", scan_result.unreadable),
        ("oversized/partial", scan_result.oversized),
        ("partial", [path for path in scan_result.partial
                     if path not in set(scan_result.oversized)]),
        ("skipped", scan_result.skipped),
    )
    shown = 0
    for category, paths in categories:
        for rel_path in paths:
            safe_path = _safe_evidence_path(rel_path)
            print(f"    {C.DIM}{category}: {safe_path}{C.RST}")
            shown += 1
            if shown >= 5:
                return


def _print_static_code_coverage(scan_result):
    """Print bounded details explaining an incomplete smali/XML scan."""
    if scan_result.coverage_complete:
        return
    print(
        f"    {C.DIM}Coverage: {scan_result.incomplete_reason()}; "
        f"{scan_result.bytes_scanned} bytes scanned "
        f"(limits: {scan_result.per_file_byte_budget} per file, "
        f"{scan_result.total_byte_budget} total){C.RST}"
    )
    oversized = set(scan_result.oversized)
    categories = (
        ("unreadable", scan_result.unreadable),
        ("oversized/partial", scan_result.oversized),
        ("partial", [path for path in scan_result.partial
                     if path not in oversized]),
        ("skipped", scan_result.skipped),
        ("analysis-limited", scan_result.analysis_limited),
    )
    shown = 0
    for category, paths in categories:
        for rel_path in paths:
            safe_path = _safe_evidence_path(rel_path)
            print(f"    {C.DIM}{category}: {safe_path}{C.RST}")
            shown += 1
            if shown >= 5:
                return


def _scan_static_code_tree(decompiled_dir, max_file_bytes=None,
                           max_total_bytes=None, chunk_bytes=None):
    """Collect smali/XML signals while preserving bounded coverage state."""
    signals = {
        "jsinterface_found": False,
        "webview_settings": [],
        "pending_invocations": [],
        "broadcast_sends": [],
        "flag_secure_found": False,
        "clip_usage": 0,
        "clip_protection": 0,
        "clip_unprotected_writes": 0,
        "clip_unprotected_files": [],
        "log_hits": {},
        "pw_fields": 0,
        "nosuggest": 0,
        "has_filter_touches": False,
        "permission_api_hits": {},
    }
    log_keywords = {
        "Java": ['Landroid/util/Log;->v(', 'Landroid/util/Log;->d('],
        "Kotlin": ['Timber;->d(', 'Timber;->v('],
        "Flutter": ['debugPrint', 'kDebugMode'],
        "React Native": ['console.log', 'console.debug'],
    }

    def consume(relative, content):
        lower_name = relative.lower()
        is_smali = lower_name.endswith('.smali')
        is_xml = lower_name.endswith('.xml')

        if is_smali:
            if ('addJavascriptInterface' in content
                    and not signals["jsinterface_found"]):
                signals["jsinterface_found"] = True
            for setting in _analyze_webview_settings(content):
                setting["file"] = relative
                signals["webview_settings"].append(setting)
            for pending in _analyze_pending_intents(content):
                pending["file"] = relative
                signals["pending_invocations"].append(pending)
            for send in _analyze_broadcast_sends(content):
                send["file"] = relative
                signals["broadcast_sends"].append(send)
            if ('FLAG_SECURE' in content or 'setFlags(8192' in content):
                signals["flag_secure_found"] = True

            file_clip_writes = _analyze_clipboard_writes(content)
            if file_clip_writes:
                protected = sum(
                    1 for write in file_clip_writes if write["sensitive"]
                )
                unprotected = len(file_clip_writes) - protected
                signals["clip_usage"] += len(file_clip_writes)
                signals["clip_protection"] += protected
                signals["clip_unprotected_writes"] += unprotected
                if unprotected:
                    signals["clip_unprotected_files"].append(relative)

            for framework, keywords in log_keywords.items():
                call_count = 0
                for keyword in keywords:
                    call_count += content.count(keyword)
                if call_count:
                    signals["log_hits"][framework] = (
                        signals["log_hits"].get(framework, 0) + call_count
                    )
            if 'filterTouchesWhenObscured' in content:
                signals["has_filter_touches"] = True

        if is_xml:
            for keyword in (
                    'textPassword', 'textVisiblePassword', 'numberPassword',
                    'textWebPassword'):
                signals["pw_fields"] += content.count(keyword)
            for keyword in (
                    'textNoSuggestions', 'flagNoPersonalizedLearning'):
                signals["nosuggest"] += content.count(keyword)
            if 'filterTouchesWhenObscured' in content:
                signals["has_filter_touches"] = True

        if is_smali or is_xml:
            for rule_id in _match_permission_apis(content):
                signals["permission_api_hits"].setdefault(rule_id, relative)

    result = code_scan_mod.scan_tree(
        decompiled_dir,
        consume,
        extensions=STATIC_CODE_EXTENSIONS,
        max_file_bytes=(STATIC_CODE_MAX_FILE_BYTES if max_file_bytes is None
                        else max_file_bytes),
        max_total_bytes=(STATIC_CODE_MAX_TOTAL_BYTES if max_total_bytes is None
                         else max_total_bytes),
        chunk_bytes=(STATIC_CODE_CHUNK_BYTES if chunk_bytes is None
                     else chunk_bytes),
    )
    return result, signals

def security_scan(pkg, prepared=None, interactive=True, decompiled_dir=None,
                  base_apk=None):
    """Run the static security scan.

    Interactive callers keep using the installed-package path.  Headless
    callers pass the ``PreparedInput`` returned by
    :func:`apk_analyzer.inputs.prepare_local_input`, which keeps this scan free
    of ADB/device dependencies.  The explicit path arguments are retained for
    lightweight integrations and tests, but the command-line entry point never
    bypasses input preparation.
    """
    section("SECURITY SCAN")

    print(f"\n  {C.CYAN}Scanning: {C.BOLD}{pkg}{C.RST}\n")

    passes = 0
    fails = 0
    warns = 0
    inconclusive = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total_checks_run = 0
    total_findings = 0

    def _scan_result(completed):
        """Return stable scan state for CI/automation callers."""
        reported_severities = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
        }
        for finding in report.findings:
            severity = str(finding.get("severity", "")).upper()
            reported_severities[severity] = (
                reported_severities.get(severity, 0) + 1
            )
        return {
            "completed": bool(completed),
            "coverage_complete": not report.inconclusive,
            "passes": passes,
            "fails": fails,
            "warnings": warns,
            "inconclusive": len(report.inconclusive),
            "inconclusive_details": list(report.inconclusive),
            "severity_counts": reported_severities,
            "total_checks": total_checks_run,
            "total_findings": len(report.findings),
            "findings": list(report.findings),
            "decompiled_dir": decompiled_dir,
        }

    prepared_base_apk = base_apk
    if prepared is not None:
        work_dir = os.path.abspath(os.fspath(prepared.work_dir))
        decompiled_dir = os.path.abspath(
            os.fspath(prepared.decompiled_dir)
        )
        prepared_base_apk = os.path.abspath(os.fspath(prepared.base_apk))
        if prepared.input_kind == "aab":
            report.mark_inconclusive(
                "input.aab_module_coverage",
                "bundletool universal output can omit non-fused on-demand "
                "dynamic-feature modules; their manifests and code were not "
                "proven covered",
            )
    elif decompiled_dir is not None:
        decompiled_dir = os.path.abspath(os.fspath(decompiled_dir))
        work_dir = os.path.dirname(decompiled_dir)
        if prepared_base_apk is not None:
            prepared_base_apk = os.path.abspath(
                os.fspath(prepared_base_apk)
            )
    else:
        work_dir, decompiled_dir = _pull_and_decompile(pkg)

    if not decompiled_dir or not os.path.isdir(decompiled_dir):
        report.mark_inconclusive(
            "scan.setup", "No prepared decompile directory was available"
        )
        if interactive:
            pause()
        return _scan_result(False)

    static_secret_scan = _scan_static_secret_tree(decompiled_dir)
    report.app_info["static_secret_scan_coverage"] = (
        _safe_coverage_metadata(static_secret_scan.to_report_dict())
    )
    if not static_secret_scan.coverage_complete:
        report.mark_inconclusive(
            "static_secret_coverage",
            static_secret_scan.incomplete_reason(),
        )

    inconclusive = int(not static_secret_scan.coverage_complete)

    static_code_scan, static_code_signals = _scan_static_code_tree(
        decompiled_dir
    )
    report.app_info["static_code_scan_coverage"] = (
        _safe_coverage_metadata(static_code_scan.to_report_dict())
    )
    code_coverage_complete = static_code_scan.coverage_complete
    if not code_coverage_complete:
        reason = static_code_scan.incomplete_reason()
        report.mark_inconclusive("static_code_coverage", reason)
        inconclusive += 1
        print(
            f"  {C.YELLOW}[INCONCLUSIVE]{C.RST} Static smali/XML "
            f"coverage is incomplete: {reason}."
        )
        _print_static_code_coverage(static_code_scan)

    jsinterface_found = static_code_signals["jsinterface_found"]
    webview_settings = static_code_signals["webview_settings"]
    pending_invocations = static_code_signals["pending_invocations"]
    broadcast_sends = static_code_signals["broadcast_sends"]
    flag_secure_found = static_code_signals["flag_secure_found"]
    clip_usage = static_code_signals["clip_usage"]
    clip_protection = static_code_signals["clip_protection"]
    clip_unprotected_writes = static_code_signals[
        "clip_unprotected_writes"
    ]
    clip_unprotected_files = static_code_signals["clip_unprotected_files"]
    log_hits = static_code_signals["log_hits"]
    pw_fields = static_code_signals["pw_fields"]
    nosuggest = static_code_signals["nosuggest"]
    has_filter_touches = static_code_signals["has_filter_touches"]
    secrets_files = static_secret_scan.matches

    def _record_finding(check_key, description="", extra_detail="",
                        severity=None, confidence="HIGH"):
        """Record a finding, increment severity counter, and add to report."""
        nonlocal total_findings
        total_findings += 1
        info = SECURITY_CHECKS.get(check_key, {})
        sev = severity or info.get("severity", "MEDIUM")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        # Also add to global report collector
        report.add_finding(
            category=info.get("masvs", "General"),
            title=info.get("title", check_key),
            severity=sev,
            confidence=confidence,
            description=description or info.get("title", check_key),
            remediation=info.get("remediation", ""),
            masvs=info.get("masvs", ""),
            cwe=info.get("cwe", ""),
            rule_id=check_key,
        )

    def code_coverage_warning(label):
        warn_line(
            label,
            "INCONCLUSIVE — one or more smali/XML inputs were not fully inspected",
        )

    def run_static_code_checks(allow_passes=True):
        """Report manifest-independent smali/XML checks from one traversal."""
        nonlocal passes, fails, warns, inconclusive, total_checks_run

        def clean_result(label, detail):
            nonlocal passes
            if allow_passes:
                pass_fail(label, True, detail)
                passes += 1
            else:
                info_line(label, detail)

        print(f"\n  {C.YELLOW}{C.BOLD}── WebView Security ──{C.RST}")
        total_checks_run += 1
        if jsinterface_found:
            _finding_line(
                "webview_js_interface",
                "WebView.addJavascriptInterface() used",
                "Verify SDK >= 17 protection",
            )
            fails += 1
            _record_finding(
                "webview_js_interface",
                "WebView.addJavascriptInterface() is used. JS-to-Java "
                "bridge may expose attack surface.",
            )
            print(
                f"    {C.DIM}Risk: JS-to-Java bridge can expose app to "
                f"XSS attacks on SDK < 17{C.RST}"
            )
            if not code_coverage_complete:
                code_coverage_warning("WebView coverage")
        elif not code_coverage_complete:
            code_coverage_warning("WebView JS Interface")
        else:
            clean_result(
                "WebView JS Interface",
                "No addJavascriptInterface() found"
            )

        enabled_webview = [
            item for item in webview_settings if item["state"] == "enabled"
        ]
        disabled_webview = [
            item for item in webview_settings if item["state"] == "disabled"
        ]
        unknown_webview = [
            item for item in webview_settings if item["state"] == "unknown"
        ]
        if enabled_webview:
            setting_names = sorted({
                item["setting"].replace("_", " ")
                for item in enabled_webview
            })
            webview_severity = _webview_setting_severity(enabled_webview)
            _finding_line(
                "webview_insecure_settings",
                f"Insecure WebView setting(s): {len(enabled_webview)}",
                ", ".join(setting_names),
                severity=webview_severity,
            )
            if webview_severity in ("CRITICAL", "HIGH"):
                fails += 1
            else:
                warns += 1
            _record_finding(
                "webview_insecure_settings",
                ("Proven WebView setting call(s): "
                 + ", ".join(setting_names)
                 + f" ({len(enabled_webview)} call(s))."),
                severity=webview_severity,
            )
            for item in enabled_webview[:8]:
                location = _terminal_safe(
                    f"{item.get('file', '<smali>')}:{item['line']}"
                ).replace("\n", " ")
                print(
                    f"    {C.DIM}\u2022 {location}: "
                    f"{item['setting'].replace('_', ' ')}{C.RST}"
                )
        elif disabled_webview and code_coverage_complete and not unknown_webview:
            info_line(
                "WebView settings",
                f"{len(disabled_webview)} call(s) set a restrictive value",
            )
        if unknown_webview:
            info_line(
                "WebView settings",
                (f"{len(unknown_webview)} call(s) used a non-constant "
                 "argument and were not scored"),
            )

        print(f"\n  {C.YELLOW}{C.BOLD}── Pending Intent Security ──{C.RST}")
        total_checks_run += 1
        pending_risky_statuses = {
            "missing_mutability", "conflicting_mutability",
            "mutable_implicit",
        }
        pending_uncertain_statuses = {
            "unknown_flags", "mutable_unknown_intent",
        }
        pending_risky = [
            item for item in pending_invocations
            if item["status"] in pending_risky_statuses
        ]
        pending_uncertain = [
            item for item in pending_invocations
            if item["status"] in pending_uncertain_statuses
        ]
        pending_mutable_explicit = [
            item for item in pending_invocations
            if item["status"] == "mutable_explicit"
        ]
        pending_immutable = [
            item for item in pending_invocations
            if item["status"] == "immutable"
        ]

        if pending_risky:
            status_counts = {
                status: sum(
                    1 for item in pending_risky
                    if item["status"] == status
                )
                for status in sorted(pending_risky_statuses)
                if any(item["status"] == status for item in pending_risky)
            }
            details = ", ".join(
                f"{status.replace('_', ' ')}={count}"
                for status, count in status_counts.items()
            )
            _finding_line(
                "pending_intent_mutable",
                f"Unsafe PendingIntent invocation(s): {len(pending_risky)}",
                details,
            )
            fails += 1
            _record_finding(
                "pending_intent_mutable",
                (f"{len(pending_risky)} PendingIntent invocation(s) are "
                 f"missing valid mutability protection or combine "
                 f"FLAG_MUTABLE with an implicit Intent ({details})."),
            )
            for item in pending_risky[:8]:
                location = _terminal_safe(
                    f"{item.get('file', '<smali>')}:{item['line']}"
                ).replace("\n", " ")
                print(
                    f"    {C.DIM}\u2022 {location}: "
                    f"{item['status'].replace('_', ' ')}{C.RST}"
                )
        if pending_uncertain:
            inconclusive += 1
            warns += 1
            reason = (
                "flags or Intent explicitness could not be resolved for "
                f"{len(pending_uncertain)} PendingIntent invocation(s)"
            )
            report.mark_inconclusive("pending_intent_analysis", reason)
            warn_line("Pending Intent", f"INCONCLUSIVE — {reason}")
        if pending_mutable_explicit:
            info_line(
                "Explicit mutable PendingIntents",
                (f"{len(pending_mutable_explicit)} invocation(s); "
                 "mutability is explicit and component targeting was proven, "
                 "but necessity still requires review"),
            )
        if (pending_invocations
                and len(pending_immutable) == len(pending_invocations)
                and code_coverage_complete):
            clean_result(
                "Pending Intent",
                "Every invocation uses FLAG_IMMUTABLE"
            )
        elif not pending_invocations:
            if code_coverage_complete:
                info_line("Pending Intent", "No PendingIntent usage detected")
            else:
                code_coverage_warning("Pending Intent")
        if pending_invocations and not code_coverage_complete:
            code_coverage_warning("Pending Intent coverage")

        print(f"\n  {C.YELLOW}{C.BOLD}── Broadcast Security ──{C.RST}")
        total_checks_run += 1
        unprotected_sends = [
            item for item in broadcast_sends if not item["protected"]
        ]
        protected_sends = [
            item for item in broadcast_sends if item["protected"]
        ]
        if unprotected_sends:
            unprotected_files = sorted({
                item.get("file", "<smali>") for item in unprotected_sends
            })
            _finding_line(
                "unprotected_broadcasts",
                ("sendBroadcast() without a permission parameter: "
                 f"{len(unprotected_sends)} call(s)"),
            )
            fails += 1
            _record_finding(
                "unprotected_broadcasts",
                (f"{len(unprotected_sends)} sendBroadcast() call(s) in "
                 f"{len(unprotected_files)} file(s) have no permission "
                 "parameter. A permission-protected call in the same file "
                 "does not cover them."),
            )
            for item in unprotected_sends[:8]:
                location = _terminal_safe(
                    f"{item.get('file', '<smali>')}:{item['line']}"
                ).replace("\n", " ")
                print(f"    {C.DIM}\u2022 {location}{C.RST}")
            if protected_sends:
                print(
                    f"    {C.DIM}{len(protected_sends)} other call(s) pass "
                    f"a permission parameter{C.RST}"
                )
            if not code_coverage_complete:
                code_coverage_warning("Broadcast coverage")
        elif protected_sends and code_coverage_complete:
            clean_result(
                "Broadcast security",
                ("All sendBroadcast() calls pass a permission parameter "
                 f"({len(protected_sends)} call(s))")
            )
        elif not code_coverage_complete:
            code_coverage_warning("Broadcast security")
        else:
            info_line("Broadcast security", "No sendBroadcast() usage detected")

        print(f"\n  {C.YELLOW}{C.BOLD}── Screenshot Protection ──{C.RST}")
        total_checks_run += 1
        if flag_secure_found and code_coverage_complete:
            clean_result("FLAG_SECURE", "Screenshot protection detected")
        elif not code_coverage_complete:
            detail = "detected in scanned input; " if flag_secure_found else ""
            warn_line(
                "FLAG_SECURE",
                f"INCONCLUSIVE — {detail}smali/XML coverage was incomplete",
            )
        else:
            info_line(
                "FLAG_SECURE",
                "Not detected; review screens containing sensitive data",
            )

        print(f"\n  {C.YELLOW}{C.BOLD}── Clipboard Data Exposure ──{C.RST}")
        total_checks_run += 1
        if clip_unprotected_files:
            _finding_line(
                "clipboard_exposure",
                ("Clipboard write(s) without "
                 "ClipDescription.EXTRA_IS_SENSITIVE "
                 f"({clip_unprotected_writes} write(s) in "
                 f"{len(clip_unprotected_files)} file(s))"),
            )
            warns += 1
            _record_finding(
                "clipboard_exposure",
                (f"{clip_unprotected_writes} clipboard write(s) in "
                 f"{len(clip_unprotected_files)} file(s) do not set "
                 "ClipDescription.EXTRA_IS_SENSITIVE to true."),
            )
            for clip_file in clip_unprotected_files[:3]:
                print(f"    {C.DIM}{_safe_evidence_path(clip_file)}{C.RST}")
            if clip_protection:
                info_line(
                    "Protected clipboard writes",
                    (f"{clip_protection} write(s) set the documented "
                     "sensitive extra"),
                )
            if not code_coverage_complete:
                code_coverage_warning("Clipboard coverage")
        elif (clip_usage > 0 and clip_protection > 0
              and code_coverage_complete):
            clean_result(
                "Clipboard",
                (f"All {clip_protection} write(s) set "
                 "ClipDescription.EXTRA_IS_SENSITIVE")
            )
        elif not code_coverage_complete:
            code_coverage_warning("Clipboard")
        else:
            clean_result("Clipboard", "No direct clipboard writes detected")

        print(f"\n  {C.YELLOW}{C.BOLD}── Debug / Verbose Logging ──{C.RST}")
        total_checks_run += 1
        if log_hits:
            total = sum(log_hits.values())
            _finding_line(
                "debug_logging",
                f"Debug/verbose log calls found ({total} call(s))",
            )
            warns += 1
            log_detail = ", ".join(
                f"{framework}: {count}"
                for framework, count in log_hits.items()
            )
            _record_finding(
                "debug_logging",
                (f"Debug/verbose log calls found ({total} call(s)): "
                 f"{log_detail}"),
            )
            for framework, count in log_hits.items():
                print(f"    {C.DIM}\u2022 {framework}: {count} call(s){C.RST}")
            if not code_coverage_complete:
                code_coverage_warning("Debug logging coverage")
        elif not code_coverage_complete:
            code_coverage_warning("Debug logging")
        else:
            clean_result(
                "Debug logging",
                "No verbose/debug log calls detected"
            )

        print(f"\n  {C.YELLOW}{C.BOLD}── Keyboard Cache ──{C.RST}")
        total_checks_run += 1
        if pw_fields and code_coverage_complete:
            clean_result(
                "Secure input types",
                f"{pw_fields} password-type field(s) found"
            )
        elif not code_coverage_complete:
            detail = (
                f"{pw_fields} password-type field(s) found; "
                if pw_fields else ""
            )
            warn_line(
                "Secure input types",
                (f"INCONCLUSIVE — {detail}packaged layout coverage was "
                 "incomplete"),
            )
        else:
            info_line(
                "Secure input types",
                "No password fields detected in packaged layouts",
            )
        if nosuggest:
            info_line(
                "textNoSuggestions",
                f"{nosuggest} field(s) disable keyboard learning",
            )
        elif pw_fields:
            info_line(
                "Keyboard learning",
                "Password input types already suppress suggestions",
            )

    def run_tapjacking_check(allow_passes=True):
        nonlocal passes, total_checks_run
        print(f"\n  {C.YELLOW}{C.BOLD}── Tapjacking Protection ──{C.RST}")
        total_checks_run += 1
        if has_filter_touches and code_coverage_complete:
            if allow_passes:
                pass_fail(
                    "Tapjacking", True,
                    "filterTouchesWhenObscured detected",
                )
                passes += 1
            else:
                info_line(
                    "Tapjacking", "filterTouchesWhenObscured detected"
                )
        elif not code_coverage_complete:
            detail = (
                "detected in scanned input; "
                if has_filter_touches else ""
            )
            warn_line(
                "Tapjacking",
                f"INCONCLUSIVE — {detail}smali/XML coverage was incomplete",
            )
        else:
            info_line(
                "Tapjacking",
                ("No global mitigation detected; review sensitive "
                 "confirmation views"),
            )

    # ── Parse AndroidManifest.xml from decompiled dir ────────────────────────
    manifest_expectations = {}
    if prepared is not None:
        manifest_expectations = {
            "expected_split_dirs": prepared.split_decompiled_dirs,
            "expected_apk_count": len(prepared.apk_paths),
        }
    manifest = _parse_manifest(decompiled_dir, **manifest_expectations)
    if not manifest["parsed"]:
        report.mark_inconclusive(
            "manifest.parse", "AndroidManifest.xml could not be parsed safely"
        )
        inconclusive += 1
        print(f"  {C.RED}[!] Could not read AndroidManifest.xml{C.RST}")
        print(f"  {C.YELLOW}[INCONCLUSIVE]{C.RST} Manifest-dependent checks were skipped; bounded code/resource checks will continue.")

        fw_info = detect_framework(decompiled_dir)
        _print_framework_info(fw_info)
        independent_secret_files = static_secret_scan.matches
        print(f"\n  {C.YELLOW}{C.BOLD}── Data Leakage Check ──{C.RST}")
        if independent_secret_files:
            evidence = _secret_finding_evidence(
                _classify_static_secret_files(
                    decompiled_dir, independent_secret_files
                )
            )
            safe_independent_secret_files = [
                _safe_evidence_path(path) for path in evidence["files"]
            ]
            _finding_line(
                "hardcoded_secrets", "Hardcoded secrets",
                (f"{len(evidence['files'])} file(s) in {evidence['where']}"),
                severity=evidence["severity"],
            )
            _record_finding(
                "hardcoded_secrets",
                (
                    "Potential secrets/keys found despite an unreadable "
                    f"manifest ({evidence['where']}): "
                    + ", ".join(safe_independent_secret_files[:5])
                ),
                severity=evidence["severity"],
                confidence=evidence["confidence"],
            )
            for rel_path in safe_independent_secret_files[:5]:
                print(f"    {C.DIM}{rel_path}{C.RST}")
            if not static_secret_scan.coverage_complete:
                print(
                    f"  {C.YELLOW}[INCONCLUSIVE]{C.RST} Additional "
                    "secret-scan coverage was incomplete."
                )
                _print_static_secret_coverage(static_secret_scan)
        elif not static_secret_scan.coverage_complete:
            print(
                f"  {C.YELLOW}[INCONCLUSIVE]{C.RST} Data leakage -- "
                "no secret match was found, but scan coverage was incomplete."
            )
            _print_static_secret_coverage(static_secret_scan)
        else:
            info_line(
                "Manifest-independent secret scan",
                "No matches in fully scanned supported text files",
            )
        run_static_code_checks(allow_passes=False)
        run_tapjacking_check(allow_passes=False)
        if interactive:
            pause()
        return _scan_result(False)

    split_manifest_coverage = manifest.get(
        "split_manifest_coverage",
        {"complete": True, "discovered": 0, "parsed": 0, "issues": []},
    )
    split_manifest_coverage = _safe_coverage_metadata(
        split_manifest_coverage
    )
    report.app_info["split_manifest_coverage"] = dict(
        split_manifest_coverage
    )
    split_manifest_coverage_complete = bool(
        split_manifest_coverage.get("complete", False)
    )
    if not split_manifest_coverage_complete:
        issues = list(split_manifest_coverage.get("issues", []))
        reason = (
            "; ".join(issues[:5])
            or "One or more feature-split manifests could not be verified"
        )
        report.mark_inconclusive("split_manifest_coverage", reason)
        inconclusive += 1
        warns += 1
        warn_line(
            "Feature-split manifests",
            "INCONCLUSIVE — " + _terminal_safe(reason).replace("\n", " ")[:500],
        )

    # ── Framework & Native SDK Detection ─────────────────────────────────────
    fw_info = detect_framework(decompiled_dir)
    _print_framework_info(fw_info)

    # ── 1. Debuggable ────────────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Debuggable Check ──{C.RST}")
    total_checks_run += 1
    debuggable = manifest["debuggable"]
    debuggable_resolution = _manifest_bool_resolution(manifest, "debuggable")
    if debuggable_resolution["state"] == resource_mod.KNOWN and debuggable:
        _finding_line("debuggable", "Debuggable flag", "App is debuggable — allows runtime inspection")
        fails += 1
        _record_finding("debuggable", "android:debuggable is set to true, allowing runtime inspection and debugging.")
    elif debuggable_resolution["state"] == resource_mod.KNOWN:
        pass_fail("Debuggable flag", True, "Not debuggable")
        passes += 1
    elif debuggable_resolution["state"] == resource_mod.CONDITIONAL:
        inconclusive += 1
        report.mark_inconclusive(
            "manifest.debuggable.resource",
            "android:debuggable changes across supported resource configurations",
        )
        warn_line(
            "Debuggable flag",
            "INCONCLUSIVE — @bool value changes across supported configurations",
        )
        warns += 1
    else:
        inconclusive += 1
        report.mark_inconclusive(
            "manifest.debuggable.resource",
            "android:debuggable references a missing or malformed boolean resource",
        )
        warn_line(
            "Debuggable flag",
            "INCONCLUSIVE — referenced boolean is missing or malformed",
        )
        warns += 1

    # Parsed before backup rules so API 31 split full-backup vs extraction.
    raw_min_sdk = manifest["min_sdk"]
    raw_target_sdk = manifest["target_sdk"]
    min_level = _parse_sdk_level(raw_min_sdk)
    target_level = _parse_sdk_level(raw_target_sdk)
    min_sdk = str(min_level) if min_level is not None else "N/A"
    target_sdk = str(target_level) if target_level is not None else "N/A"

    # ── 2. Backup ────────────────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Backup Check ──{C.RST}")
    total_checks_run += 1
    allow_backup = manifest["allow_backup"]
    backup_resolution = _manifest_bool_resolution(manifest, "allow_backup")
    if backup_resolution["state"] == resource_mod.KNOWN and allow_backup:
        backup_policy = _assess_backup_rules(
            decompiled_dir, manifest, min_level, target_level
        )
        if backup_policy == "unknown":
            _finding_line(
                "allow_backup", "allowBackup",
                "Backup is enabled and the referenced rules could not be verified",
            )
            fails += 1
            inconclusive += 1
            report.mark_inconclusive(
                "manifest.backup_rules",
                "android:allowBackup is true, but fullBackupContent or "
                "dataExtractionRules could not be read",
            )
            _record_finding(
                "allow_backup",
                "android:allowBackup is true and the referenced backup "
                "rules could not be verified, so private data is treated "
                "as extractable.",
            )
            warns += 1
        elif backup_policy == "private_excluded":
            _finding_line(
                "allow_backup", "allowBackup",
                "Enabled, but shared preferences, databases, files, and "
                "root are excluded",
                severity="LOW",
            )
            warns += 1
            _record_finding(
                "allow_backup",
                "android:allowBackup is true, but the applicable backup "
                "rules exclude shared preferences, databases, files, and "
                "the app root.",
                severity="LOW",
            )
        elif backup_policy == "databases_excluded":
            _finding_line(
                "allow_backup", "allowBackup",
                "Shared preferences and databases are excluded; other "
                "private files may still be backed up",
                severity="MEDIUM",
            )
            warns += 1
            _record_finding(
                "allow_backup",
                "android:allowBackup is true. Shared preferences and "
                "databases are excluded, but files or the app root can "
                "still be backed up.",
                severity="MEDIUM",
            )
        else:
            detail = (
                "App data can be backed up via adb — data extraction risk"
            )
            if (min_level is None or min_level < 31) and (
                    manifest.get("data_extraction_rules")
                    and not manifest.get("full_backup_content")):
                detail = (
                    "dataExtractionRules do not cover Android 11 and lower; "
                    "those versions still back up private data"
                )
            _finding_line("allow_backup", "allowBackup", detail)
            fails += 1
            _record_finding(
                "allow_backup",
                "android:allowBackup is true and backup rules do not "
                "exclude shared preferences and databases. App data can "
                "be extracted via adb backup.",
            )
    elif backup_resolution["state"] == resource_mod.KNOWN:
        pass_fail("allowBackup", True, "Backup disabled or not set")
        passes += 1
    elif backup_resolution["state"] == resource_mod.CONDITIONAL:
        inconclusive += 1
        report.mark_inconclusive(
            "manifest.allow_backup.resource",
            "android:allowBackup changes across supported resource configurations",
        )
        warn_line(
            "allowBackup",
            "INCONCLUSIVE — @bool value changes across supported configurations",
        )
        warns += 1
    else:
        inconclusive += 1
        report.mark_inconclusive(
            "manifest.allow_backup.resource",
            "android:allowBackup references a missing or malformed boolean resource",
        )
        warn_line(
            "allowBackup",
            "INCONCLUSIVE — referenced boolean is missing or malformed",
        )
        warns += 1

    # ── 3. Exported Components ───────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Exported Components ──{C.RST}")
    total_checks_run += 1

    exposed_components = []
    gated_components = []
    unknown_gated_components = []
    uncertain_exported_components = []

    def classify_component(kind, component, strength):
        if component.get("exposure_state", resource_mod.KNOWN) != resource_mod.KNOWN:
            uncertain_exported_components.append(
                (kind, component["name"], component.get("permission"))
            )
            return
        target = {
            "strong": gated_components,
            "weak": exposed_components,
            "unknown": unknown_gated_components,
        }[strength]
        target.append((kind, component["name"], component.get("permission")))

    for comp in manifest["exported"]["activity"]:
        is_launcher = (
            "android.intent.action.MAIN" in comp.get("actions", [])
            and "android.intent.category.LAUNCHER" in comp.get("categories", [])
        )
        if is_launcher:
            continue
        classify_component(
            "Activity", comp,
            _permission_strength(manifest, comp.get("permission")),
        )
    for bucket, label in (("service", "Service"), ("receiver", "Receiver")):
        for comp in manifest["exported"][bucket]:
            classify_component(
                label, comp,
                _permission_strength(manifest, comp.get("permission")),
            )
    for comp in manifest["exported"]["provider"]:
        strength = _provider_protection_strength(manifest, comp)
        if comp.get("exposure_state", resource_mod.KNOWN) != resource_mod.KNOWN:
            uncertain_exported_components.append(
                ("Provider", comp["name"], None)
            )
        else:
            target = {
                "strong": gated_components,
                "weak": exposed_components,
                "unknown": unknown_gated_components,
            }[strength]
            target.append(("Provider", comp["name"], None))

    if exposed_components:
        total_exported = len(exposed_components)
        _finding_line("exported_components", f"Unprotected exported components: {total_exported}")
        fails += 1
        comp_list = [
            f"{kind}: {_safe_evidence_path(name)}"
            for kind, name, _permission in exposed_components
        ]
        _record_finding("exported_components",
                         f"{total_exported} exported component(s) lack manifest permission protection: "
                         f"{'; '.join(comp_list[:10])}")
        for kind, name, _permission in exposed_components[:20]:
            print(f"    {C.DIM}{kind}: {_safe_evidence_path(name)}{C.RST}")
    elif (not unknown_gated_components
          and not uncertain_exported_components
          and split_manifest_coverage_complete):
        pass_fail("Exported components", True,
                  "Only launcher or permission-gated components are exported")
        passes += 1
    elif (not unknown_gated_components
          and not uncertain_exported_components):
        warn_line(
            "Exported components",
            "INCONCLUSIVE — feature-split manifest coverage is incomplete",
        )
    if gated_components:
        info_line("Permission-gated exports", f"{len(gated_components)} component(s)")
    if unknown_gated_components:
        warns += 1
        warn_line(
            "Unresolved exported-component permissions",
            f"{len(unknown_gated_components)} component(s); protection level could not be verified",
        )
        for kind, name, permission in unknown_gated_components[:10]:
            suffix = (
                f" ({_safe_evidence_path(permission)})" if permission else ""
            )
            print(
                f"    {C.DIM}{kind}: {_safe_evidence_path(name)}"
                f"{suffix}{C.RST}"
            )
    if uncertain_exported_components:
        inconclusive += 1
        report.mark_inconclusive(
            "manifest.exported_components.resource",
            "One or more component enabled/exported resources are conditional or unresolved",
        )
        warns += 1
        warn_line(
            "Conditional exported components",
            (f"INCONCLUSIVE — enabled/exported resources vary or are unresolved "
             f"for {len(uncertain_exported_components)} component(s)"),
        )
        for kind, name, _permission in uncertain_exported_components[:10]:
            print(f"    {C.DIM}{kind}: {_safe_evidence_path(name)}{C.RST}")

    # ── 4. Permissions ───────────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Dangerous Permissions ──{C.RST}")
    total_checks_run += 1
    requested_perms = manifest["permissions"]
    dangerous_requested = requested_perms & DANGEROUS_PERMS
    if dangerous_requested:
        info_line("Dangerous permissions",
                  f"{len(dangerous_requested)} requested (review app necessity)")
        perm_list = ", ".join(dp.replace("android.permission.", "") for dp in sorted(dangerous_requested))
        info = SECURITY_CHECKS["dangerous_permissions"]
        report.add_finding(
            category=info["masvs"], title=info["title"], severity="INFO",
            confidence="HIGH",
            description=f"{len(dangerous_requested)} dangerous permission(s) requested: {perm_list}",
            remediation=info["remediation"], masvs=info["masvs"], cwe=info["cwe"],
        )
        for dp in sorted(dangerous_requested):
            permission_prefix = "android.permission."
            short = (dp[len(permission_prefix):]
                     if dp.startswith(permission_prefix) else dp)
            print(f"    {C.DIM}\u2022 {short}{C.RST}")
    elif split_manifest_coverage_complete:
        pass_fail("Dangerous permissions", True, "No dangerous permissions requested")
        passes += 1
    else:
        warn_line(
            "Dangerous permissions",
            "INCONCLUSIVE — feature-split manifest coverage is incomplete",
        )

    # Unused permissions require complete code coverage. An API with no
    # permission in the merged set stays inconclusive when a split manifest
    # was not fully read, because that split may still declare it.
    print(f"\n  {C.YELLOW}{C.BOLD}── Permission versus Code ──{C.RST}")
    permission_hits = static_code_signals.get("permission_api_hits", {})
    permission_api = _correlate_permission_apis(
        requested_perms,
        permission_hits,
        code_coverage_complete,
        split_manifest_coverage_complete,
        target_level,
    )

    def _short_permission(name):
        prefix = "android.permission."
        text = str(name)
        return text[len(prefix):] if text.startswith(prefix) else text

    def _permission_list(names, limit=12):
        short = [_short_permission(name) for name in names]
        shown = ", ".join(short[:limit])
        if len(short) > limit:
            shown += f" (+{len(short) - limit} more)"
        return shown

    def _missing_permission_phrase(permissions):
        names = [_short_permission(name) for name in permissions]
        if len(names) == 1:
            return (
                f"{names[0]} is not declared in the merged manifest"
            )
        if len(names) == 2:
            return (
                f"neither {names[0]} nor {names[1]} is declared "
                "in the merged manifest"
            )
        listed = ", ".join(names[:-1]) + f", or {names[-1]}"
        return f"none of {listed} is declared in the merged manifest"

    def _missing_sentence(rule):
        evidence = permission_hits.get(rule["id"])
        where = ""
        if evidence:
            where = " in " + _safe_evidence_path(evidence)
        return (
            f"Mapped platform API for {rule['label']} is used{where}, "
            f"but {_missing_permission_phrase(rule['permissions'])}."
        )

    total_checks_run += 1
    unused_permissions = permission_api["unused_permissions"]
    if unused_permissions:
        unused_text = _permission_list(unused_permissions)
        _finding_line(
            "permission_without_api",
            ("Dangerous permission with no mapped API: "
             f"{len(unused_permissions)}"),
            unused_text,
        )
        warns += 1
        _record_finding(
            "permission_without_api",
            (
                f"{len(unused_permissions)} dangerous permission(s) have no "
                f"mapped platform API in the scanned code: {unused_text}. "
                "Reflection, JNI, or code outside this APK can still use "
                "them."
            ),
            confidence="MEDIUM",
        )
        for name in unused_permissions[:12]:
            print(f"    {C.DIM}\u2022 {_short_permission(name)}{C.RST}")
    elif permission_api["unused_inconclusive"]:
        inconclusive += 1
        warns += 1
        reason = (
            "Declared dangerous permission(s) have no mapped platform API "
            "in the scanned portion, but smali/XML coverage is incomplete: "
            + _permission_list(permission_api["unmatched_permissions"])
        )[:600]
        report.mark_inconclusive("permission_without_api", reason)
        warn_line(
            "Dangerous permission with no mapped API",
            "INCONCLUSIVE — " + reason,
        )
    elif code_coverage_complete and split_manifest_coverage_complete:
        pass_fail(
            "Dangerous permission with no mapped API",
            True,
            "No declared dangerous permission lacks a mapped platform API",
        )
        passes += 1
    elif not split_manifest_coverage_complete:
        warn_line(
            "Dangerous permission with no mapped API",
            "INCONCLUSIVE — feature-split manifest coverage is incomplete",
        )
    else:
        warn_line(
            "Dangerous permission with no mapped API",
            "INCONCLUSIVE — smali/XML coverage was incomplete",
        )

    total_checks_run += 1
    missing_rules = permission_api["missing_rules"]
    if missing_rules:
        shown_rules = missing_rules[:12]
        hidden_rules = len(missing_rules) - len(shown_rules)
        sentences = [_missing_sentence(rule) for rule in shown_rules]
        if hidden_rules:
            sentences.append(
                f"{hidden_rules} more mapped API(s) were omitted."
            )
        labels = ", ".join(rule["label"] for rule in shown_rules)
        _finding_line(
            "api_without_permission",
            ("Mapped API with no declared permission: "
             f"{len(missing_rules)}"),
            labels,
        )
        fails += 1
        _record_finding(
            "api_without_permission",
            " ".join(sentences),
            confidence="HIGH",
        )
        for rule in shown_rules:
            evidence = permission_hits.get(rule["id"], "")
            suffix = (
                f" ({_safe_evidence_path(evidence)})" if evidence else ""
            )
            print(f"    {C.DIM}\u2022 {rule['label']}{suffix}{C.RST}")
    elif permission_api["missing_inconclusive"]:
        inconclusive += 1
        warns += 1
        labels = ", ".join(
            rule["label"] for rule in permission_api["uncovered_rules"][:12]
        )
        reason = (
            "Mapped platform API use has no permission in the merged "
            f"manifest ({labels}), but feature-split manifest coverage is "
            "incomplete; the permission may be declared in a split that "
            "was not merged"
        )[:600]
        report.mark_inconclusive("api_without_permission", reason)
        warn_line(
            "Mapped API with no declared permission",
            "INCONCLUSIVE — " + reason,
        )
    elif code_coverage_complete:
        pass_fail(
            "Mapped API with no declared permission",
            True,
            "Mapped platform APIs have a declared permission",
        )
        passes += 1
    else:
        warn_line(
            "Mapped API with no declared permission",
            "INCONCLUSIVE — smali/XML coverage was incomplete",
        )

    # ── 5. SDK Version ───────────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── SDK Version ──{C.RST}")
    total_checks_run += 1
    # Populate report app_info with SDK versions
    report.app_info["min_sdk"] = min_sdk
    report.app_info["target_sdk"] = target_sdk

    sdk_issues = list(manifest.get("sdk_issues", []))
    if min_level is None and not any("minSdkVersion" in item
                                     for item in sdk_issues):
        sdk_issues.append("minSdkVersion could not be resolved safely")
    if target_level is None and not any("targetSdkVersion" in item
                                        for item in sdk_issues):
        sdk_issues.append("targetSdkVersion could not be resolved safely")
    if sdk_issues:
        reason = "; ".join(dict.fromkeys(sdk_issues))[:600]
        report.mark_inconclusive("manifest.sdk", reason)
        inconclusive += 1
        warns += 1
        warn_line("SDK policy", f"INCONCLUSIVE — {reason}")

    sdk_failed = False
    if min_level is not None and min_level < 23:
        _finding_line("sdk_version", "Min SDK", f"minSdk={min_sdk} — targets outdated Android (< 6.0)")
        fails += 1
        sdk_failed = True
        _record_finding("sdk_version",
                         f"minSdkVersion={min_sdk} targets Android < 6.0, missing modern security features.")
    elif min_level is not None:
        pass_fail("Min SDK", True, f"minSdk={min_sdk}")
        passes += 1
    else:
        info_line("Min SDK", "Could not determine")

    if target_level is not None and target_level < CURRENT_PLAY_TARGET_SDK:
        if target_level < EXISTING_APP_TARGET_SDK_FLOOR:
            sdk_detail = (
                f"targetSdk={target_sdk} is below the Play visibility floor "
                f"({EXISTING_APP_TARGET_SDK_FLOOR}) and the update "
                f"requirement ({CURRENT_PLAY_TARGET_SDK})"
            )
        else:
            sdk_detail = (
                f"targetSdk={target_sdk} meets the existing-app floor "
                f"({EXISTING_APP_TARGET_SDK_FLOOR}) but new Play updates "
                f"require {CURRENT_PLAY_TARGET_SDK}+"
            )
        if not sdk_failed:
            _finding_line("sdk_version", "Target SDK", sdk_detail)
            _record_finding(
                "sdk_version",
                f"targetSdkVersion={target_sdk}: {sdk_detail}.",
            )
        else:
            warn_line(f"targetSdk={target_sdk} — {sdk_detail}")
        warns += 1
    elif target_level is not None:
        pass_fail(
            "Target SDK", True,
            f"targetSdk={target_sdk} meets Play's "
            f"{CURRENT_PLAY_TARGET_SDK}+ update requirement",
        )
        passes += 1

    # ── 6. Cleartext Traffic ─────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Network Security ──{C.RST}")
    total_checks_run += 1
    if manifest["has_nsc"]:
        # Network Security Config applies on API 24+.  A v24-only policy fully
        # covers an app whose manifest minSdk is lower because the attribute is
        # ignored by older platforms.
        nsc_min_sdk = (
            max(min_level, 24) if min_level is not None else min_sdk
        )
        nsc_resolution = _resolve_resource_variants(
            decompiled_dir,
            manifest["nsc_ref"],
            expected_type="xml",
            min_sdk=nsc_min_sdk,
            local_package=manifest.get("package"),
        )
        nsc_info = _analyze_nsc_variants(
            decompiled_dir, nsc_resolution, target_sdk=target_sdk
        )
    else:
        nsc_info = {"parsed": False, "pins": [], "cleartext_allowed": False,
                    "cleartext_known": False, "cleartext_conditional": False,
                    "complete": False,
                    "trusts_user_certs": False, "trusts_debug_user_certs": False,
                    "trust_anchors": [], "path": None, "paths": (),
                    "resource_state": resource_mod.UNKNOWN}
    cleartext_source = None
    if manifest["has_nsc"]:
        # Android 7.0+ ignores usesCleartextTraffic when an NSC is present.
        # Do not OR the manifest value into the parsed NSC policy.
        cleartext_resolution = _manifest_bool_resolution(manifest, "cleartext")
        if min_level is not None and min_level <= 22:
            cleartext = True
            cleartext_source = "pre-Android 6 platform behavior"
        elif min_sdk == "23":
            if not manifest["cleartext_explicit"]:
                cleartext = True
                cleartext_source = "Android 6 platform default"
            elif (cleartext_resolution["state"] == resource_mod.KNOWN
                    and manifest["cleartext"] is True):
                cleartext = True
                cleartext_source = "manifest on Android 6"
            elif nsc_info["cleartext_known"] and nsc_info["cleartext_allowed"]:
                cleartext = True
                cleartext_source = (
                    "network security config on some supported configurations"
                    if nsc_info["cleartext_conditional"]
                    else "network security config"
                )
            elif (cleartext_resolution["state"] == resource_mod.KNOWN
                  and manifest["cleartext"] is False
                  and nsc_info["cleartext_known"]):
                cleartext = nsc_info["cleartext_allowed"]
                cleartext_source = "manifest and network security config"
            else:
                cleartext = None
        elif nsc_info["cleartext_known"]:
            cleartext = nsc_info["cleartext_allowed"]
            cleartext_source = (
                "network security config on some supported configurations"
                if nsc_info["cleartext_conditional"]
                else "network security config"
            )
        else:
            cleartext = None
    else:
        cleartext_resolution = _manifest_bool_resolution(manifest, "cleartext")
        if min_level is not None and min_level <= 22:
            # The manifest flag was introduced in API 23; older supported
            # devices do not enforce it.
            cleartext = True
            cleartext_source = "pre-Android 6 platform behavior"
        elif (min_level is not None and min_level <= 27
              and not manifest["cleartext_explicit"]):
            # Android 6-8 predate the target-28 default-deny behavior.  An app
            # that still supports one of those releases has a permissive
            # effective configuration even when its modern target SDK makes
            # the manifest-level default appear false.
            cleartext = True
            cleartext_source = "Android 6-8 platform default"
        elif cleartext_resolution["state"] == resource_mod.KNOWN:
            cleartext = manifest["cleartext"]
            if manifest["cleartext_explicit"]:
                cleartext_source = "manifest"
            else:
                cleartext_source = f"target SDK {target_sdk} platform default"
        else:
            cleartext = None
    if cleartext is not None:
        if cleartext:
            source = cleartext_source or "effective platform policy"
            _finding_line("cleartext_traffic", "Cleartext traffic", f"HTTP allowed by {source}")
            fails += 1
            _record_finding("cleartext_traffic",
                             f"Cleartext HTTP communication is allowed by {source}.")
        else:
            source = cleartext_source or "effective platform policy"
            pass_fail("Cleartext traffic", True, f"Disabled by {source}")
            passes += 1
    else:
        inconclusive += 1
        report.mark_inconclusive(
            "manifest.cleartext.resource",
            "Effective cleartext policy is conditional or has incomplete resource coverage",
        )
        warn_line(
            "Cleartext traffic",
            "INCONCLUSIVE — resource coverage or effective policy is unresolved",
        )
        warns += 1

    # ── 7. Network Security Config ───────────────────────────────────────────
    total_checks_run += 1
    if manifest["has_nsc"]:
        if not nsc_info["complete"]:
            inconclusive += 1
            report.mark_inconclusive(
                "network_security_config.resource",
                "One or more effective network security config resources are missing or invalid",
            )
        if nsc_info["trusts_user_certs"]:
            _finding_line("network_security_config", "Network security config",
                          "Production policy trusts user-installed CAs")
            warns += 1
            _record_finding("network_security_config",
                             "Production network security policy trusts user-installed CA certificates.")
        elif not nsc_info["complete"]:
            warn_line(
                "Network security config",
                "INCONCLUSIVE — one or more effective resource variants are missing or invalid",
            )
            warns += 1
        else:
            pass_fail(
                "Network security config", True,
                "All effective configs parsed; no production user-CA trust",
            )
            passes += 1
    else:
        info_line("Network security config", "Not defined; platform policy applies")

    # ── 8. Secrets in decompiled files ───────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Data Leakage Check ──{C.RST}")
    total_checks_run += 1
    secrets_found = bool(secrets_files)
    if secrets_found:
        evidence = _secret_finding_evidence(
            _classify_static_secret_files(decompiled_dir, secrets_files)
        )
        safe_secret_files = [
            _safe_evidence_path(path) for path in evidence["files"]
        ]
        _finding_line(
            "hardcoded_secrets", "Hardcoded secrets",
            f"{len(evidence['files'])} file(s) in {evidence['where']}",
            severity=evidence["severity"],
        )
        if evidence["severity"] in ("CRITICAL", "HIGH"):
            fails += 1
        else:
            warns += 1
        _record_finding(
            "hardcoded_secrets",
            (f"Potential secrets/keys found in {len(evidence['files'])} "
             f"file(s) ({evidence['where']}): "
             + ", ".join(safe_secret_files[:5])),
            severity=evidence["severity"],
            confidence=evidence["confidence"],
        )
        for sf in safe_secret_files[:5]:
            print(f"    {C.DIM}{sf}{C.RST}")
        if not static_secret_scan.coverage_complete:
            print(
                f"  {C.YELLOW}[INCONCLUSIVE]{C.RST} Additional "
                "secret-scan coverage was incomplete."
            )
            _print_static_secret_coverage(static_secret_scan)
    elif not static_secret_scan.coverage_complete:
        print(
            f"  {C.YELLOW}[INCONCLUSIVE]{C.RST} Data leakage -- "
            "no secret match was found, but scan coverage was incomplete."
        )
        _print_static_secret_coverage(static_secret_scan)
    else:
        pass_fail("Data leakage", True, "No plaintext secrets detected")
        passes += 1

    # ── 9. Deeplink / Intent Filter Hijacking ────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Deeplink Security ──{C.RST}")
    total_checks_run += 1
    deep_link_info = manifest["deeplinks"]
    deep_link_filters = list(deep_link_info.get("filters", []))
    if not deep_link_filters and (
            deep_link_info.get("schemes") or deep_link_info.get("hosts")):
        # Preserve compatibility with callers that provide the pre-v1.6.1
        # manifest shape while treating its missing verification evidence
        # conservatively.
        deep_link_filters = [{
            "component": "unknown",
            "schemes": list(deep_link_info.get("schemes", [])),
            "hosts": list(deep_link_info.get("hosts", [])),
            "paths": [],
            "auto_verify": False,
            "exposure_state": resource_mod.KNOWN,
        }]

    known_link_filters = [
        link for link in deep_link_filters
        if link.get("exposure_state", resource_mod.KNOWN) == resource_mod.KNOWN
    ]
    uncertain_link_filters = [
        link for link in deep_link_filters if link not in known_link_filters
    ]
    classified_links = [
        (link, _classify_deep_link(link)) for link in known_link_filters
    ]
    risky_links = [item for item in classified_links if item[1]["risk"]]
    informational_links = [
        item for item in classified_links if not item[1]["risk"]
    ]

    if risky_links:
        reasons = sorted({
            reason for _link, result in risky_links
            for reason in result["reasons"]
        })
        _finding_line(
            "deeplinks",
            f"Risky externally reachable deeplink filters: {len(risky_links)}",
            "; ".join(reasons[:3]),
        )
        fails += 1
        _record_finding(
            "deeplinks",
            (f"{len(risky_links)} externally reachable deeplink filter(s) "
             f"need hardening: {'; '.join(reasons)}"),
        )
        for link, result in risky_links[:5]:
            schemes = ",".join(link.get("schemes", [])) or "<none>"
            hosts = ",".join(link.get("hosts", [])) or "<none>"
            detail = _terminal_safe(
                f"{link.get('component', 'unknown')}: {schemes}://{hosts} — "
                + "; ".join(result["reasons"])
            ).replace("\n", " ")[:360]
            print(f"    {C.DIM}\u2022 {detail}{C.RST}")
    if informational_links:
        info_line(
            "Verified HTTPS App Links",
            (f"{len(informational_links)} constrained autoVerify filter(s); "
             "assetlinks verification status is not asserted by static analysis"),
        )
        if not risky_links:
            report.add_finding(
                category=SECURITY_CHECKS["deeplinks"]["masvs"],
                title="Externally Reachable Verified App Links",
                severity="INFO", confidence="MEDIUM",
                description=(
                    f"{len(informational_links)} constrained HTTPS App Link "
                    "filter(s) request autoVerify; validate URI parameters and "
                    "deployed assetlinks.json separately."
                ),
                remediation="Validate all parameters accepted by App Link handlers",
                masvs=SECURITY_CHECKS["deeplinks"]["masvs"],
                cwe=SECURITY_CHECKS["deeplinks"]["cwe"],
                rule_id="deeplinks",
            )
    if uncertain_link_filters:
        inconclusive += 1
        warns += 1
        reason = (
            f"{len(uncertain_link_filters)} deeplink filter(s) have conditional "
            "or unresolved enabled/exported resources"
        )
        report.mark_inconclusive("deeplink_exposure", reason)
        warn_line("Deeplink reachability", f"INCONCLUSIVE — {reason}")
    if not deep_link_filters and split_manifest_coverage_complete:
        pass_fail("Deeplinks", True, "No externally reachable deeplink filters found")
        passes += 1
    elif not deep_link_filters:
        warn_line(
            "Deeplinks",
            "INCONCLUSIVE — feature-split manifest coverage is incomplete",
        )

    run_static_code_checks()

    # ── 17. Task Hijacking (taskAffinity) ────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Task Hijacking ──{C.RST}")
    total_checks_run += 1
    task_hijack = manifest["task_affinity"]
    if task_hijack:
        _finding_line("task_hijacking", f"Activities with custom taskAffinity ({len(task_hijack)})", "StrandHogg risk")
        fails += 1
        _record_finding("task_hijacking",
                         f"{len(task_hijack)} activities with custom taskAffinity (StrandHogg risk).")
        for act_name, aff in task_hijack[:5]:
            print(f"    {C.DIM}\u2022 {_safe_evidence_path(act_name)}{C.RST}")
            print(
                f"      {C.DIM}taskAffinity=\""
                f"{_safe_evidence_path(aff)}\"{C.RST}"
            )
    elif split_manifest_coverage_complete:
        pass_fail("Task hijacking", True, "No custom taskAffinity found")
        passes += 1
    else:
        warn_line(
            "Task hijacking",
            "INCONCLUSIVE — feature-split manifest coverage is incomplete",
        )

    run_tapjacking_check()

    # ── 19. APK Signing Scheme ───────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── APK Signing Scheme ──{C.RST}")
    total_checks_run += 1
    # Headless scans must verify the exact validated input rather than finding
    # a same-named, potentially stale APK in the current directory.
    apk_file = prepared_base_apk
    if apk_file is None:
        apk_file = _find_local_apk(pkg)
    if apk_file is None:
        pulled_apk = os.path.join(work_dir, f"{pkg}.apk")
        if os.path.isfile(pulled_apk) and os.path.getsize(pulled_apk) > 0:
            apk_file = pulled_apk

    signing_scope_reason = ""
    if prepared is not None and prepared.input_kind == "aab":
        signing_scope_reason = (
            "bundletool generated the analyzed APK; its debug/generated "
            "signature does not establish source AAB or Play signing"
        )
    elif prepared is not None and len(prepared.apk_paths) > 1:
        signing_scope_reason = (
            "the input contains multiple APKs and the complete split "
            "signature set was not verified"
        )
    elif prepared is None:
        try:
            with open(
                    os.path.join(decompiled_dir, ".apkanalyzer_meta.json"),
                    "r", encoding="utf-8") as metadata_file:
                signing_metadata = json.load(metadata_file)
            if len(signing_metadata.get("remote_apk_paths", [])) > 1:
                signing_scope_reason = (
                    "the installed app uses split APKs but only the cached "
                    "base artifact is available for signing verification"
                )
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    apksigner_command = _resolve_apksigner_command()
    if signing_scope_reason:
        report.mark_inconclusive("apk_signing", signing_scope_reason)
        inconclusive += 1
        warn_line(
            "APK signing", f"INCONCLUSIVE — {signing_scope_reason}"
        )
    elif apk_file and apksigner_command:
        try:
            r = _process_run_command_capture(
                apksigner_command
                + ["verify", "--print-certs", "-v", apk_file],
                timeout=30,
            )
            output = r.stdout + r.stderr
            has_v1 = bool(re.search(r'Verified using v1 scheme.*?:\s*true', output, re.IGNORECASE))
            has_v2 = bool(re.search(r'Verified using v2 scheme.*?:\s*true', output, re.IGNORECASE))
            has_v3 = bool(re.search(r'Verified using v3 scheme.*?:\s*true', output, re.IGNORECASE))
            has_v4 = bool(re.search(r'Verified using v4 scheme.*?:\s*true', output, re.IGNORECASE))

            schemes = []
            if has_v1: schemes.append("v1 (JAR)")
            if has_v2: schemes.append("v2 (APK Sig)")
            if has_v3: schemes.append("v3 (Key Rotation)")
            if has_v4: schemes.append("v4 (Incremental)")

            if r.returncode != 0:
                reason = (
                    "apksigner could not verify the prepared APK "
                    f"(exit code {r.returncode})"
                )
                report.mark_inconclusive("apk_signing", reason)
                inconclusive += 1
                warn_line("APK signing", f"INCONCLUSIVE — {reason}")
            elif schemes:
                info_line("Signing schemes", ", ".join(schemes))
            else:
                reason = "apksigner output did not identify a signing scheme"
                report.mark_inconclusive("apk_signing", reason)
                inconclusive += 1
                warn_line("APK signing", f"INCONCLUSIVE — {reason}")

            if r.returncode == 0 and has_v1 and not has_v2 and not has_v3:
                _finding_line("apk_signing", "APK signing", "v1-only signing — vulnerable to Janus (CVE-2017-13156)")
                fails += 1
                _record_finding("apk_signing",
                                 "APK uses v1 (JAR) signing only, vulnerable to Janus attack (CVE-2017-13156).")
            elif r.returncode == 0 and (has_v2 or has_v3):
                pass_fail("APK signing", True, "Uses v2/v3 signing scheme")
                passes += 1

            # Extract signer info
            if r.returncode == 0:
                for cn_m in re.finditer(r'CN=([^,\n]+)', output):
                    signer_name = _terminal_safe(
                        cn_m.group(1).strip()
                    ).replace("\r", " ").replace("\n", " ")[:240]
                    info_line("Signer", signer_name)
                    break
        except (subprocess.TimeoutExpired, OSError, ValueError,
                CommandOutputLimitExceeded) as exc:
            reason = (
                "apksigner verification failed: "
                f"{_headless_diagnostic(exc, 240)}"
            )
            report.mark_inconclusive("apk_signing", reason)
            inconclusive += 1
            warn_line("APK signing", f"INCONCLUSIVE — {reason}")
    elif not apksigner_command:
        reason = (
            "a safe apksigner executable/JAR is unavailable; APK signing "
            "was not verified"
        )
        report.mark_inconclusive("apk_signing", reason)
        inconclusive += 1
        warn_line("APK signing", f"INCONCLUSIVE — {reason}")
    else:
        reason = "the prepared APK was unavailable for signing verification"
        report.mark_inconclusive("apk_signing", reason)
        inconclusive += 1
        warn_line("APK signing", f"INCONCLUSIVE — {reason}")

    # ── Additional Static Analysis (informational) ───────────────────────────
    # Network Security Config detail: cert pins, cleartext policy, user-CA trust
    _print_nsc_analysis(nsc_info)

    # Known security / anti-tamper libraries detected in the smali class tree
    _print_security_classes(_check_security_classes(decompiled_dir))

    # Security-relevant strings inside native .so libraries (root/frida/SSL/etc.)
    native_scan = _scan_native_strings(decompiled_dir, with_coverage=True)
    if isinstance(native_scan, dict):
        native_str_results = native_scan.get("matches", [])
        native_string_coverage = native_scan.get("coverage", {})
    else:
        # Compatibility for integrations/tests which mock the historical
        # list-valued private helper.
        native_str_results = native_scan
        native_string_coverage = {
            "complete": True,
            "candidate_files": 0,
            "scanned_files": 0,
            "matched_files": len(native_str_results),
        }
    report.app_info["native_string_scan_coverage"] = (
        _safe_coverage_metadata(dict(native_string_coverage))
    )
    native_coverage_complete = bool(
        native_string_coverage.get("complete", False)
    )
    if (native_str_results
            or native_string_coverage.get("candidate_files")
            or not native_coverage_complete):
        print(f"\n  {C.CYAN}{C.BOLD}── NATIVE LIBRARY STRINGS ──{C.RST}")
        if native_str_results or native_coverage_complete:
            _print_native_strings(native_str_results)
    if not native_coverage_complete:
        categories = []
        for key in (
                "discovery_issues", "unreadable", "oversized", "timed_out",
                "tool_errors", "partial"):
            count = len(native_string_coverage.get(key, []))
            if count:
                categories.append(f"{count} {key.replace('_', ' ')}")
        unscanned_count = native_string_coverage.get("unscanned_count", 0)
        if unscanned_count:
            categories.append(f"{unscanned_count} unscanned")
        if native_string_coverage.get("budget_reasons"):
            categories.append("scan budget exhausted")
        reason = ", ".join(categories) or "native string coverage is incomplete"
        report.mark_inconclusive("native_string_coverage", reason)
        inconclusive += 1
        warns += 1
        warn_line(
            "Native library strings",
            f"INCONCLUSIVE — {reason}; positive matches were preserved",
        )

    # ── Risk Summary with MASVS Severity ─────────────────────────────────────
    print(f"\n  {C.CYAN}{'=' * 56}{C.RST}")
    print(f"  {C.BOLD}{C.WHITE}RISK SUMMARY{C.RST}")
    print(f"  {C.CYAN}{'=' * 56}{C.RST}")

    crit = severity_counts["CRITICAL"]
    high = severity_counts["HIGH"]
    med  = severity_counts["MEDIUM"]
    low  = severity_counts["LOW"]

    parts = []
    if crit:
        parts.append(f"{C.RED}{C.BOLD}CRITICAL: {crit}{C.RST}")
    else:
        parts.append(f"{C.DIM}CRITICAL: 0{C.RST}")
    if high:
        parts.append(f"{C.RED}HIGH: {high}{C.RST}")
    else:
        parts.append(f"{C.DIM}HIGH: 0{C.RST}")
    if med:
        parts.append(f"{C.YELLOW}MEDIUM: {med}{C.RST}")
    else:
        parts.append(f"{C.DIM}MEDIUM: 0{C.RST}")
    if low:
        parts.append(f"{C.BLUE}LOW: {low}{C.RST}")
    else:
        parts.append(f"{C.DIM}LOW: 0{C.RST}")

    print(f"  {'  |  '.join(parts)}")
    print(f"  {C.WHITE}Total findings: {total_findings}/{total_checks_run} checks{C.RST}")
    print(
        f"  {C.GREEN}PASS: {passes}{C.RST}  "
        f"{C.RED}FAIL: {fails}{C.RST}  "
        f"{C.YELLOW}WARN: {warns}{C.RST}  "
        f"{C.YELLOW}INCONCLUSIVE: {inconclusive}{C.RST}"
    )

    coverage_suffix = " (INCOMPLETE COVERAGE)" if inconclusive else ""
    if crit > 0:
        print(f"\n  {C.RED}{C.BOLD}Overall: CRITICAL RISK{coverage_suffix}{C.RST}")
    elif high > 0:
        print(f"\n  {C.RED}{C.BOLD}Overall: HIGH RISK{coverage_suffix}{C.RST}")
    elif med > 0:
        print(f"\n  {C.YELLOW}{C.BOLD}Overall: MODERATE RISK{coverage_suffix}{C.RST}")
    elif low > 0:
        print(f"\n  {C.BLUE}{C.BOLD}Overall: LOW RISK{coverage_suffix}{C.RST}")
    elif inconclusive:
        print(
            f"\n  {C.YELLOW}{C.BOLD}Overall: INCONCLUSIVE -- "
            f"one or more static checks had unresolved coverage{C.RST}"
        )
    else:
        print(f"\n  {C.GREEN}{C.BOLD}Overall: MINIMAL RISK{C.RST}")

    if interactive:
        pause()
    return _scan_result(True)

__all__ = [
    'SECURITY_CHECKS',
    '_SEVERITY_COLORS',
    '_severity_tag',
    '_finding_line',
    '_static_secret_window_has_match',
    '_scan_static_secret_tree',
    '_find_static_secret_files',
    '_safe_evidence_path',
    '_safe_coverage_metadata',
    '_print_static_secret_coverage',
    '_print_static_code_coverage',
    '_scan_static_code_tree',
    'security_scan',
    '_classify_static_secret_files',
    '_secret_finding_evidence',
    '_BACKUP_LEVEL_ORDER',
    '_worst_backup_level',
    '_load_backup_document',
    '_assess_backup_rules',
]
