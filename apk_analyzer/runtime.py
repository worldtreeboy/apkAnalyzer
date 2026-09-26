"""ADB runtime security checks.

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

# ─── 12. Runtime Security Check ──────────────────────────────────────────────────

def _runtime_data_check(pkg, launch=True):
    """Launch the app and scan SharedPrefs/databases for runtime secrets."""
    findings = []

    if launch:
        print(f"  {C.DIM}Launching {pkg}...{C.RST}")
        launch_out = adb_shell(
            f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1 2>/dev/null",
            timeout=10,
        )
        _require_app_launch(launch_out)
        print(f"  {C.DIM}Waiting 5 seconds for app to initialize...{C.RST}")
        time.sleep(5)

    # Scan SharedPrefs
    prefs_dir = f"/data/data/{pkg}/shared_prefs"
    quoted_prefs = shlex.quote(prefs_dir)
    files_out = adb_su(
        f"if [ -d {quoted_prefs} ]; then ls {quoted_prefs} 2>/dev/null; fi",
        timeout=10,
    )
    _require_runtime_command(
        files_out, "listing SharedPreferences", partial_findings=findings
    )
    if "No such file" not in files_out:
        for fname in files_out.splitlines():
            fname = fname.strip()
            if not fname or not fname.endswith(".xml"):
                continue
            content = adb_su(f"cat {shlex.quote(f'{prefs_dir}/{fname}')} 2>/dev/null", timeout=10)
            _require_runtime_command(
                content, f"reading SharedPreferences {fname}",
                partial_findings=findings,
            )
            for val in _find_secret_matches(content):
                val_lower = val.lower()
                if re.match(r'eyJ[A-Za-z0-9_-]{10,}', val):
                    sev, slabel = "CRITICAL", "JWT token"
                elif any(kw in val_lower for kw in ('bearer', 'auth_token', 'session_token', 'refresh_token')):
                    sev, slabel = "CRITICAL", "Auth token"
                elif any(kw in val_lower for kw in ('api_key', 'apikey', 'api-key')):
                    sev, slabel = "HIGH", "API key"
                elif any(kw in val_lower for kw in ('password', 'passwd', 'pwd')):
                    sev, slabel = "CRITICAL", "Password"
                elif any(kw in val_lower for kw in ('secret', 'private_key', 'signing_key')):
                    sev, slabel = "HIGH", "Secret/key"
                elif 'AKIA' in val:
                    sev, slabel = "CRITICAL", "AWS Access Key"
                elif val.startswith('AIza'):
                    sev, slabel = "HIGH", "Google API key"
                else:
                    sev, slabel = "MEDIUM", "Potential secret"
                findings.append((sev, slabel, fname, _redact(val[:120])))

            pii_hits = _scan_pii(content)
            for plabel, val in pii_hits:
                findings.append(("MEDIUM", f"PII ({plabel})", fname, _redact(val[:120])))

    # Scan databases
    db_dir = f"/data/data/{pkg}"
    db_files_out = adb_su(
        f"find {shlex.quote(db_dir)} -maxdepth 3 \\( -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' \\) 2>/dev/null",
        timeout=15)
    _require_runtime_command(
        db_files_out, "enumerating application databases",
        partial_findings=findings,
    )
    if db_files_out:
        for dbf in db_files_out.splitlines():
            dbf = dbf.strip()
            if not dbf:
                continue
            dbname = os.path.basename(dbf)
            header = adb_su(f"xxd -l 16 {shlex.quote(dbf)} 2>/dev/null", timeout=5)
            _require_runtime_command(
                header, f"reading database header for {dbname}",
                partial_findings=findings,
            )
            if not header:
                raise RuntimeCheckUnavailable(
                    f"reading database header for {dbname}: no output",
                    partial_findings=findings,
                )
            if not header or "5351 4c69 7465" not in header:
                continue
            tables = adb_su(f"sqlite3 {shlex.quote(dbf)} '.tables' 2>/dev/null", timeout=10)
            _require_runtime_command(
                tables, f"enumerating tables in {dbname}",
                partial_findings=findings,
            )
            if "not found" in tables.lower():
                raise RuntimeCheckUnavailable(
                    f"enumerating tables in {dbname}: sqlite3 is unavailable",
                    partial_findings=findings,
                )
            for table in tables.split()[:10]:
                try:
                    table_ident = _sqlite_identifier(table)
                except ValueError:
                    continue
                sample = _sqlite_read(
                    dbf, f"SELECT * FROM {table_ident} LIMIT 5", timeout=5  # nosec B608
                )
                _require_runtime_command(
                    sample, f"reading {dbname}/{table}",
                    partial_findings=findings,
                )
                for val in _find_secret_matches(sample):
                    findings.append(("HIGH", "Secret in DB", f"{dbname}/{table}",
                                     _redact(val[:120])))
                pii_hits = _scan_pii(sample)
                for plabel, val in pii_hits:
                    findings.append(("MEDIUM", f"PII ({plabel}) in DB",
                                     f"{dbname}/{table}", _redact(val[:120])))

    return findings


def _check_world_readable(pkg):
    """Check for world-readable files in app data directory."""
    findings = []
    out = adb_su(f"find {shlex.quote(f'/data/data/{pkg}')} -perm -o+r -type f 2>/dev/null", timeout=15)
    _require_runtime_command(out, "checking world-readable files")
    if "No such file" in out:
        raise RuntimeCheckUnavailable("application data directory does not exist")
    if out:
        paths = [f.strip() for f in out.splitlines() if f.strip()]
        modes = _batch_stat(paths)
        for fpath in paths:
            perms = modes.get(fpath, "?")
            rel = fpath.replace(f"/data/data/{pkg}/", "")
            findings.append((rel, perms))
    return findings


def _probe_exported_components(pkg):
    """Try launching exported activities for manual access-control review."""
    findings = []

    work_dir, decompiled_dir = _pull_and_decompile(pkg)
    if not decompiled_dir:
        raise RuntimeCheckUnavailable("could not obtain a decompiled APK")

    manifest = _parse_manifest(decompiled_dir)
    if not manifest["parsed"]:
        raise RuntimeCheckUnavailable("could not parse AndroidManifest.xml")

    exported = manifest["exported"]
    activities = exported.get("activity", [])

    for comp in activities:
        name = comp["name"]
        actions = comp.get("actions", [])
        categories = comp.get("categories", [])
        # Skip only a real launcher entry. MAIN without LAUNCHER is still an
        # externally reachable non-launcher activity that should be probed.
        if ("android.intent.action.MAIN" in actions
                and "android.intent.category.LAUNCHER" in categories):
            continue

        stop_out = adb_shell(f"am force-stop {pkg}", timeout=5)
        _require_runtime_command(
            stop_out, f"stopping {pkg}", partial_findings=findings
        )
        time.sleep(0.3)

        cmd = f"am start -n {shlex.quote(f'{pkg}/{name}')}"
        if actions:
            cmd += f" -a {shlex.quote(actions[0])}"
        out = adb_shell(cmd, timeout=10)
        _require_runtime_command(
            out, f"launching exported activity {name}",
            partial_findings=findings,
        )

        if "SecurityException" in out or "not exported" in out.lower():
            findings.append(("PASS", name, "Not actually exported"))
        elif "Error" in out or "Exception" in out:
            findings.append(("INFO", name,
                             "Launch failed or activity crashed; access control was not established"))
        else:
            time.sleep(1)
            focus = adb_shell("dumpsys activity activities | grep mResumedActivity", timeout=5)
            _require_runtime_command(
                focus, "checking resumed activity", partial_findings=findings
            )
            if focus and name.split(".")[-1] in focus:
                findings.append(("MEDIUM", name,
                                 "Externally launchable; authentication requires manual review"))
            else:
                findings.append(("INFO", name, "Sent start but unclear if it rendered"))

    return findings


_NO_CLIPBOARD_BASELINE = object()
_MAX_APP_PROCESS_PIDS = 32
_MAX_LOGCAT_SCAN_BYTES = 16 * 1024 * 1024
_MAX_LOGCAT_FINDINGS = 512


def _read_clipboard_text():
    """Read clipboard text without relying on version-specific Binder codes."""
    dump = adb_su("dumpsys clipboard", timeout=10)
    _require_runtime_command(dump, "reading clipboard")
    if not dump:
        return ""
    if re.search(r"(?:mPrimaryClip|primary clip)\s*[=:]\s*(?:null|none)",
                 dump, re.IGNORECASE):
        return ""
    match = re.search(r'mPrimaryClip=ClipData\{[^}]*\{T:([^}]+)\}', dump)
    if match:
        return match.group(1).strip()
    # Output varies across Android releases. If a clip exists but this build's
    # format is unknown, a clean result cannot be asserted.
    raise RuntimeCheckUnavailable("clipboard output format is unsupported")


def _check_clipboard_leak(pkg, launch=True, baseline=_NO_CLIPBOARD_BASELINE):
    """Monitor clipboard after interacting with the app."""
    findings = []

    if launch:
        baseline = _read_clipboard_text()
        print(f"  {C.DIM}Launching {pkg} for clipboard check...{C.RST}")
        launch_out = adb_shell(
            f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1 2>/dev/null",
            timeout=10,
        )
        _require_app_launch(launch_out, "launching target for clipboard check")
        time.sleep(3)

    clip_text = _read_clipboard_text()

    if baseline is not _NO_CLIPBOARD_BASELINE and clip_text == baseline:
        return findings

    if clip_text and len(clip_text) > 2:
        if _find_secret_matches(clip_text, per_pattern_limit=1):
            findings.append(("HIGH", "Secret in clipboard", _redact(clip_text[:120])))
        pii_hits = _scan_pii(clip_text)
        for plabel, val in pii_hits:
            findings.append(("MEDIUM", f"PII ({plabel}) in clipboard", _redact(val[:120])))
        if not findings:
            label = ("Clipboard changed after launch"
                     if baseline is not _NO_CLIPBOARD_BASELINE
                     else "Clipboard has content (no attribution baseline)")
            findings.append(("INFO", label, _redact(clip_text[:120])))

    return findings


def _resolve_package_process_pids(pkg):
    """Resolve the main and ``:secondary`` PIDs without substring matching."""
    if not _is_valid_package(pkg):
        raise RuntimeCheckUnavailable("invalid package name for process attribution")

    pidof_out = adb_shell(f"pidof {pkg}", timeout=5)
    pidof_pids = []
    pidof_problem = None
    if _command_failed(pidof_out):
        pidof_problem = str(pidof_out)
    else:
        saw_word = False
        seen_pidof = set()
        for match in re.finditer(r"\S+", str(pidof_out or "")):
            saw_word = True
            word = match.group(0)
            if (not word.isascii() or not word.isdigit()
                    or len(word) > 10 or int(word) <= 0
                    or int(word) > 0x7FFFFFFF):
                pidof_pids = []
                pidof_problem = "pidof returned an unexpected format"
                break
            if word in seen_pidof:
                continue
            seen_pidof.add(word)
            if len(pidof_pids) >= _MAX_APP_PROCESS_PIDS:
                pidof_problem = (
                    "pidof returned more processes than the safety limit"
                )
                continue
            pidof_pids.append(word)
        if saw_word and not pidof_pids and pidof_problem is None:
            pidof_problem = "pidof returned an unexpected format"

    ps_problem = None
    ps_result = None
    # Fetch one extra line beyond the parser's limit so truncation is visible;
    # the fixed pipeline contains no APK/package-controlled shell data.
    for command in (
            "ps -A -o PID,NAME | head -n 8193",
            "ps -A | head -n 8193",
            "ps | head -n 8193"):
        ps_out = adb_shell(command, timeout=8)
        if _command_failed(ps_out):
            ps_problem = str(ps_out)
            continue
        parsed = _parse_android_ps(ps_out, pkg)
        if parsed["recognized"]:
            ps_result = parsed
            break
        ps_problem = f"{command} returned an unsupported table format"

    if ps_result is not None and ps_result["pids"]:
        if ps_result["truncated"]:
            return (ps_result["pids"], False,
                    "process table was truncated before attribution completed")
        return ps_result["pids"], True, None

    if pidof_pids:
        reason = ps_problem or "process table did not contain the pidof process"
        return pidof_pids, False, reason

    details = ps_problem or pidof_problem or "target process is not running"
    raise RuntimeCheckUnavailable(
        f"target process is not running or cannot be attributed: {details}"
    )


def _check_logcat_leakage(pkg, launch=True):
    """Capture logcat during app launch and scan for secrets."""
    findings = []

    if launch:
        clear_out = adb_shell("logcat -c", timeout=5)
        _require_runtime_command(clear_out, "clearing logcat")

        print(f"  {C.DIM}Launching {pkg} for logcat capture...{C.RST}")
        launch_out = adb_shell(
            f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1 2>/dev/null",
            timeout=10,
        )
        _require_app_launch(launch_out, "launching target for logcat capture")
        time.sleep(5)

    # Android apps can use named processes such as ``package:remote``. pidof
    # normally resolves only the main process, so corroborate it with a bounded
    # process-table parse before claiming a clean logcat result.
    pids, attribution_complete, attribution_error = (
        _resolve_package_process_pids(pkg)
    )
    log_chunks = []
    captured_bytes = 0
    capture_truncated = False
    for pid in pids:
        logs = adb_shell(f"logcat -d -t 2000 --pid={pid}", timeout=15)
        try:
            _require_runtime_command(logs, f"capturing logcat for PID {pid}")
        except RuntimeCheckUnavailable as exc:
            partial, _truncated = _analyze_logcat_chunks(log_chunks)
            raise RuntimeCheckUnavailable(
                str(exc), partial_findings=partial
            )
        if not logs:
            continue
        if isinstance(logs, bytes):
            logs = logs.decode("utf-8", errors="replace")
        elif not isinstance(logs, str):
            logs = str(logs)
        encoded = logs.encode("utf-8", errors="replace")
        separator_bytes = 1 if log_chunks else 0
        remaining = _MAX_LOGCAT_SCAN_BYTES - captured_bytes
        if len(encoded) + separator_bytes > remaining:
            prefix_bytes = max(0, remaining - separator_bytes)
            if prefix_bytes:
                prefix = encoded[:prefix_bytes].decode(
                    "utf-8", errors="replace"
                )
                # Do not scan a line cut in half by the byte ceiling: a
                # truncated key/value can otherwise be misreported as a real
                # credential. Complete preceding lines remain useful partial
                # findings in the explicit inconclusive result.
                line_end = max(prefix.rfind("\n"), prefix.rfind("\r"))
                if line_end >= 0:
                    log_chunks.append(prefix[:line_end + 1])
            capture_truncated = True
            break
        log_chunks.append(logs)
        captured_bytes += separator_bytes + len(encoded)

    findings, findings_truncated = _analyze_logcat_chunks(log_chunks)
    incomplete_reasons = []
    if capture_truncated:
        incomplete_reasons.append(
            f"logcat exceeded the {_MAX_LOGCAT_SCAN_BYTES}-byte scan limit"
        )
    if findings_truncated:
        incomplete_reasons.append(
            f"logcat exceeded the {_MAX_LOGCAT_FINDINGS}-finding limit"
        )
    if not attribution_complete:
        incomplete_reasons.append(
            f"logcat process attribution is incomplete: {attribution_error}"
        )
    if incomplete_reasons:
        raise RuntimeCheckUnavailable(
            "; ".join(incomplete_reasons), partial_findings=findings
        )

    return findings


def _analyze_logcat_chunks(log_chunks):
    """Scan already-bounded log chunks without building another full-log copy."""
    secret_line_map = {}
    pii_findings = []
    seen_pii = set()
    findings_truncated = False
    line_number = 0
    for chunk in log_chunks:
        for line in chunk.splitlines():
            line = line.strip()
            if not line:
                continue
            line_number += 1
            for val in _find_secret_matches(line, per_pattern_limit=10):
                if any(fp in val.lower() for fp in [
                    'password=*', 'key=com.', 'key=android.',
                    'access_network_state', 'access_wifi_state',
                ]):
                    continue
                if re.match(r'eyJ[A-Za-z0-9_-]{10,}', val):
                    sev, slabel = "CRITICAL", "JWT token"
                elif any(kw in val.lower() for kw in (
                        'bearer', 'auth_token', 'password')):
                    sev, slabel = "HIGH", "Auth credential"
                else:
                    sev, slabel = "MEDIUM", "Potential secret"
                key = hashlib.sha256(
                    val.encode("utf-8", errors="replace")
                ).digest()
                if key in secret_line_map:
                    continue
                if (len(secret_line_map) + len(pii_findings)
                        >= _MAX_LOGCAT_FINDINGS):
                    findings_truncated = True
                    continue
                secret_line_map[key] = (
                    line_number, _redact(val[:120]), sev, slabel
                )

            remaining = (
                _MAX_LOGCAT_FINDINGS - len(secret_line_map)
                - len(pii_findings)
            )
            pii_hits = _scan_pii(
                line, max_hits=_MAX_LOGCAT_FINDINGS + 1
            )
            for plabel, val in pii_hits:
                key = val
                if key in seen_pii:
                    continue
                seen_pii.add(key)
                if remaining <= 0:
                    findings_truncated = True
                    continue
                pii_findings.append((
                    "MEDIUM", f"PII ({plabel})", "logcat",
                    _redact(val[:120]),
                ))
                remaining -= 1

    findings = []
    for line_num, val, sev, slabel in secret_line_map.values():
        findings.append((sev, slabel, f"line {line_num}", val[:80]))
    findings.extend(pii_findings)
    return findings, findings_truncated


def _check_webview_cache(pkg):
    """Look for cached web content in app data."""
    findings = []
    cache_paths = [
        ("app_webview/Cache", "WebView cache"),
        ("app_webview/Cookies", "WebView cookies DB"),
        ("app_webview/Web Data", "WebView web data"),
        ("app_webview/Local Storage", "WebView local storage"),
        ("app_webview/Session Storage", "WebView session storage"),
    ]
    data_dir = f"/data/data/{pkg}"

    for rel_path, cache_label in cache_paths:
        full_path = f"{data_dir}/{rel_path}"
        quoted_path = shlex.quote(full_path)
        out = adb_su(
            f"if [ -f {quoted_path} ]; then "
            f"[ -s {quoted_path} ] && echo EXISTS || echo ABSENT; "
            f"elif [ -d {quoted_path} ]; then "
            f"find {quoted_path} -type f -size +0c -print -quit 2>/dev/null; "
            f"else echo ABSENT; fi",
            timeout=5,
        )
        _require_runtime_command(out, f"checking {cache_label}")
        if out and out != "ABSENT":
            size_out = adb_su(f"du -sh {quoted_path} 2>/dev/null", timeout=5)
            size = size_out.split()[0] if not _is_err(size_out) and size_out.split() else "?"
            findings.append((cache_label, rel_path, size))

    return findings


def runtime_security_check(pkg):
    """Perform dynamic runtime security checks using ADB commands."""
    section("RUNTIME SECURITY ANALYSIS")
    print(f"\n  {C.CYAN}Target: {C.BOLD}{pkg}{C.RST}")
    print(f"  {C.DIM}Running ADB-based runtime checks (no Frida required)...{C.RST}\n")

    total_critical = 0
    total_high = 0
    total_medium = 0
    total_pass = 0
    total_inconclusive = 0

    def mark_inconclusive(label, reason):
        nonlocal total_inconclusive
        total_inconclusive += 1
        detail = _terminal_safe(str(reason)).replace("\n", " ").strip()
        if len(detail) > 180:
            detail = detail[:177] + "..."
        check_id = re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")
        report.mark_inconclusive(
            f"runtime_{check_id}", detail or "required data was unavailable"
        )
        print(f"    {C.YELLOW}[INCONCLUSIVE]{C.RST} {label}"
              f" {C.DIM}-- {detail or 'required data was unavailable'}{C.RST}")

    # A failed transport must stop the scan before any empty helper result can
    # be mistaken for evidence that the app is safe.
    device_probe = adb_shell("getprop ro.build.version.sdk", timeout=10)
    if (_command_failed(device_probe)
            or not str(device_probe or "").strip().isdigit()):
        mark_inconclusive("Device preflight", device_probe or "no SDK response")
        print(f"\n  {C.CYAN}{'='*56}{C.RST}")
        print(f"  {C.BOLD}RUNTIME SECURITY SUMMARY{C.RST}")
        print(f"  {C.RED}{C.BOLD}CRITICAL: 0{C.RST}  {C.RED}HIGH: 0{C.RST}  "
              f"{C.YELLOW}MEDIUM: 0{C.RST}  {C.GREEN}PASS: 0{C.RST}  "
              f"{C.YELLOW}INCONCLUSIVE: {total_inconclusive}{C.RST}")
        print(f"\n  {C.YELLOW}{C.BOLD}Overall: INCONCLUSIVE -- device unavailable; no security conclusion was made{C.RST}")
        pause()
        return

    root_probe = adb_su("id", timeout=10)
    root_ready = not _command_failed(root_probe) and "uid=0" in root_probe

    clipboard_baseline = _NO_CLIPBOARD_BASELINE
    clipboard_baseline_error = None
    if root_ready:
        try:
            clipboard_baseline = _read_clipboard_text()
        except Exception as exc:
            clipboard_baseline_error = exc

    logcat_clear = adb_shell("logcat -c", timeout=5)
    logcat_ready = not _command_failed(logcat_clear)
    logcat_error = logcat_clear if not logcat_ready else None

    print(f"  {C.DIM}Launching {pkg}...{C.RST}")
    launch_out = adb_shell(
        f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1 2>/dev/null",
        timeout=10,
    )
    try:
        _require_app_launch(launch_out)
        launch_ready = True
    except RuntimeCheckUnavailable:
        launch_ready = False
    if launch_ready:
        print(f"  {C.DIM}Waiting 5 seconds for app to initialize...{C.RST}")
        time.sleep(5)

    # ── 1. Data at Rest (Post-Launch) ───────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}-- Data at Rest (Post-Launch) --{C.RST}")
    print(f"  {C.DIM}Scanning application-private storage for runtime secrets...{C.RST}")

    data_available = root_ready
    data_error = None
    data_findings = []
    if not root_ready:
        data_error = "root access is unavailable"
    else:
        try:
            data_findings = _runtime_data_check(pkg, launch=False)
        except Exception as exc:
            data_findings = list(getattr(exc, "partial_findings", []))
            data_available = False
            data_error = exc

    if data_findings:
        for sev, dlabel, source, val in data_findings:
            if sev == "CRITICAL":
                total_critical += 1
                print(f"    {C.RED}{C.BOLD}[CRITICAL]{C.RST} {dlabel} found in {C.WHITE}{source}{C.RST}")
            elif sev == "HIGH":
                total_high += 1
                print(f"    {C.RED}[HIGH]{C.RST} {dlabel} found in {C.WHITE}{source}{C.RST}")
            elif sev == "MEDIUM":
                total_medium += 1
                print(f"    {C.YELLOW}[MEDIUM]{C.RST} {dlabel} found in {C.WHITE}{source}{C.RST}")
            display_val = val if len(val) <= 60 else val[:57] + "..."
            print(f"      {C.DIM}-> {display_val}{C.RST}")
            report.add_finding("Runtime: Data at Rest", f"{dlabel} in {source}",
                               sev, "HIGH", f"Runtime secret found: {display_val}",
                               "Remove secrets from SharedPrefs/databases", "MASVS-STORAGE-1", "CWE-312")
    if not data_available:
        mark_inconclusive("Data-at-rest check", data_error)
    elif not launch_ready:
        mark_inconclusive("Post-launch data coverage", launch_out)
    elif not data_findings:
        total_pass += 1
        print(f"    {C.GREEN}[PASS]{C.RST} No runtime secrets detected in SharedPrefs/databases")

    # ── 2. File Permissions ─────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}-- File Permissions --{C.RST}")
    print(f"  {C.DIM}Checking for world-readable files...{C.RST}")
    perm_available = root_ready
    perm_error = None
    perm_findings = []
    if not root_ready:
        perm_error = "root access is unavailable"
    else:
        try:
            perm_findings = _check_world_readable(pkg)
        except Exception as exc:
            perm_available = False
            perm_error = exc

    if perm_findings:
        total_high += 1
        print(f"    {C.RED}[HIGH]{C.RST} World-readable files found: {C.WHITE}{len(perm_findings)}{C.RST}")
        for rel_path, perms in perm_findings[:10]:
            print(f"      {C.DIM}-> {rel_path} (mode: {perms}){C.RST}")
        if len(perm_findings) > 10:
            print(f"      {C.DIM}... and {len(perm_findings) - 10} more{C.RST}")
        report.add_finding("Runtime: File Permissions", f"World-readable files: {len(perm_findings)}",
                           "HIGH", "HIGH", "Files in app data directory are world-readable",
                           "Set proper file permissions (0600/0660)", "MASVS-STORAGE-2", "CWE-276")
    elif perm_available:
        total_pass += 1
        print(f"    {C.GREEN}[PASS]{C.RST} No world-readable files found")
    else:
        mark_inconclusive("File-permission check", perm_error)

    # ── 3. Exported Component Probing ───────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}-- Exported Components --{C.RST}")
    print(f"  {C.DIM}Probing exported activities for auth bypass...{C.RST}")
    comp_available = True
    comp_error = None
    comp_findings = []
    try:
        comp_findings = _probe_exported_components(pkg)
    except Exception as exc:
        comp_findings = list(getattr(exc, "partial_findings", []))
        comp_available = False
        comp_error = exc

    if comp_findings:
        for sev, cname, detail in comp_findings:
            short_name = cname.rsplit(".", 1)[-1] if "." in cname else cname
            if sev == "MEDIUM":
                total_medium += 1
                print(f"    {C.YELLOW}[MEDIUM]{C.RST} Activity is externally launchable: {C.WHITE}{short_name}{C.RST}")
                print(f"      {C.DIM}-> {cname}{C.RST}")
                report.add_finding("Runtime: Exported Components", f"Externally launchable: {cname}",
                                   "MEDIUM", "HIGH",
                                   f"Exported activity {cname} can be launched externally; authentication was not inferred",
                                   "Manually verify authorization checks or remove the exported flag",
                                   "MASVS-PLATFORM-1", "CWE-926")
            elif sev == "PASS":
                total_pass += 1
                print(f"    {C.GREEN}[PASS]{C.RST} {short_name} {C.DIM}-- {detail}{C.RST}")
            else:
                print(f"    {C.BLUE}[INFO]{C.RST} {short_name} {C.DIM}-- {detail}{C.RST}")
    elif comp_available:
        print(f"    {C.DIM}No non-launcher exported activities to probe{C.RST}")
    else:
        mark_inconclusive("Exported-component probe", comp_error)

    # ── 4. Clipboard Leakage ────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}-- Clipboard Leakage --{C.RST}")
    print(f"  {C.DIM}Checking clipboard after app launch...{C.RST}")
    clip_available = root_ready and launch_ready and clipboard_baseline_error is None
    clip_error = None
    clip_findings = []
    if not root_ready:
        clip_error = "root access is unavailable"
    elif not launch_ready:
        clip_error = f"target launch failed: {launch_out}"
    elif clipboard_baseline_error is not None:
        clip_error = clipboard_baseline_error
    else:
        try:
            clip_findings = _check_clipboard_leak(
                pkg, launch=False, baseline=clipboard_baseline
            )
        except Exception as exc:
            clip_available = False
            clip_error = exc

    if clip_findings:
        for sev, clabel, val in clip_findings:
            if sev == "HIGH":
                total_high += 1
                print(f"    {C.RED}[HIGH]{C.RST} {clabel}")
            elif sev == "MEDIUM":
                total_medium += 1
                print(f"    {C.YELLOW}[MEDIUM]{C.RST} {clabel}")
            else:
                print(f"    {C.BLUE}[INFO]{C.RST} {clabel}")
            display_val = val if len(val) <= 60 else val[:57] + "..."
            print(f"      {C.DIM}-> {display_val}{C.RST}")
            if sev in ("HIGH", "MEDIUM"):
                report.add_finding(
                    "Runtime: Clipboard Leakage", clabel, sev, "MEDIUM",
                    f"Sensitive clipboard content appeared after launch: {display_val}",
                    "Avoid copying sensitive values or clear them promptly",
                    "MASVS-STORAGE-1", "CWE-200",
                )
    elif clip_available:
        total_pass += 1
        print(f"    {C.GREEN}[PASS]{C.RST} No sensitive data found in clipboard")
    else:
        mark_inconclusive("Clipboard check", clip_error)

    # ── 5. Logcat Leakage ───────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}-- Logcat Leakage --{C.RST}")
    print(f"  {C.DIM}Capturing logcat during app launch...{C.RST}")
    log_available = launch_ready and logcat_ready
    log_error = None
    log_findings = []
    if not launch_ready:
        log_error = f"target launch failed: {launch_out}"
    elif not logcat_ready:
        log_error = f"logcat clear failed: {logcat_error}"
    else:
        try:
            log_findings = _check_logcat_leakage(pkg, launch=False)
        except Exception as exc:
            log_findings = list(getattr(exc, "partial_findings", []))
            log_available = False
            log_error = exc

    if log_findings:
        log_crit = sum(1 for s, *_ in log_findings if s == "CRITICAL")
        log_high = sum(1 for s, *_ in log_findings if s == "HIGH")
        log_med = sum(1 for s, *_ in log_findings if s == "MEDIUM")
        total_critical += log_crit
        total_high += log_high
        total_medium += log_med

        total_log_issues = len(log_findings)
        print(f"    {C.YELLOW}[MEDIUM]{C.RST} {total_log_issues} potential secret(s)/PII found in logcat during app launch")
        for sev, llabel, location, val in log_findings[:15]:
            if sev == "CRITICAL":
                tag = f"{C.RED}{C.BOLD}[CRITICAL]{C.RST}"
            elif sev == "HIGH":
                tag = f"{C.RED}[HIGH]{C.RST}"
            else:
                tag = f"{C.YELLOW}[MEDIUM]{C.RST}"
            display_val = val if len(val) <= 60 else val[:57] + "..."
            print(f"      {tag} {llabel} at {location}")
            print(f"        {C.DIM}-> {display_val}{C.RST}")
            report.add_finding("Runtime: Logcat Leakage", f"{llabel} at {location}",
                               sev, "MEDIUM", f"Secret/PII leaked in logcat: {display_val}",
                               "Remove debug logging of sensitive data", "MASVS-STORAGE-1", "CWE-532")
        if len(log_findings) > 15:
            print(f"      {C.DIM}... and {len(log_findings) - 15} more{C.RST}")
    if not log_available:
        mark_inconclusive("Logcat check", log_error)
    elif not log_findings:
        total_pass += 1
        print(f"    {C.GREEN}[PASS]{C.RST} No secrets or PII leaked in logcat during launch")

    # ── 6. WebView Cache ────────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}-- WebView Cache --{C.RST}")
    print(f"  {C.DIM}Checking for WebView cached data...{C.RST}")
    wv_available = root_ready
    wv_error = None
    wv_findings = []
    if not root_ready:
        wv_error = "root access is unavailable"
    else:
        try:
            wv_findings = _check_webview_cache(pkg)
        except Exception as exc:
            wv_available = False
            wv_error = exc

    if wv_findings:
        total_medium += 1
        print(f"    {C.YELLOW}[MEDIUM]{C.RST} WebView cache present")
        for wlabel, wpath, wsize in wv_findings:
            print(f"      {C.DIM}-> {wlabel}: {wpath} ({wsize}){C.RST}")
        report.add_finding("Runtime: WebView Cache", f"WebView cache present ({len(wv_findings)} items)",
                           "MEDIUM", "HIGH", "Cached web data found in app directory",
                           "Clear WebView cache on app exit or use no-cache headers", "MASVS-STORAGE-2", "CWE-524")
    elif wv_available:
        total_pass += 1
        print(f"    {C.GREEN}[PASS]{C.RST} No WebView cache found")
    else:
        mark_inconclusive("WebView-cache check", wv_error)

    cleanup_out = adb_shell(f"am force-stop {pkg}", timeout=5)
    if _command_failed(cleanup_out):
        mark_inconclusive("Runtime cleanup", cleanup_out)

    # ── Summary ─────────────────────────────────────────────────────────────
    print(f"\n  {C.CYAN}{'='*56}{C.RST}")
    print(f"  {C.BOLD}RUNTIME SECURITY SUMMARY{C.RST}")
    print(f"  {C.RED}{C.BOLD}CRITICAL: {total_critical}{C.RST}  "
          f"{C.RED}HIGH: {total_high}{C.RST}  "
          f"{C.YELLOW}MEDIUM: {total_medium}{C.RST}  "
          f"{C.GREEN}PASS: {total_pass}{C.RST}  "
          f"{C.YELLOW}INCONCLUSIVE: {total_inconclusive}{C.RST}")

    if total_critical > 0:
        suffix = " (INCOMPLETE COVERAGE)" if total_inconclusive else ""
        print(f"\n  {C.RED}{C.BOLD}Overall: CRITICAL RISK{suffix} -- secrets exposed at runtime{C.RST}")
    elif total_high > 0:
        suffix = " (INCOMPLETE COVERAGE)" if total_inconclusive else ""
        print(f"\n  {C.RED}{C.BOLD}Overall: HIGH RISK{suffix} -- significant runtime issues found{C.RST}")
    elif total_medium > 0:
        suffix = " (INCOMPLETE COVERAGE)" if total_inconclusive else ""
        print(f"\n  {C.YELLOW}{C.BOLD}Overall: MODERATE RISK{suffix} -- some runtime concerns{C.RST}")
    elif total_inconclusive > 0:
        print(f"\n  {C.YELLOW}{C.BOLD}Overall: INCONCLUSIVE -- one or more required checks did not run{C.RST}")
    else:
        print(f"\n  {C.GREEN}{C.BOLD}Overall: LOW RISK -- runtime checks passed{C.RST}")

    pause()

__all__ = [
    '_runtime_data_check',
    '_check_world_readable',
    '_probe_exported_components',
    '_NO_CLIPBOARD_BASELINE',
    '_MAX_APP_PROCESS_PIDS',
    '_MAX_LOGCAT_SCAN_BYTES',
    '_MAX_LOGCAT_FINDINGS',
    '_read_clipboard_text',
    '_check_clipboard_leak',
    '_resolve_package_process_pids',
    '_check_logcat_leakage',
    '_analyze_logcat_chunks',
    '_check_webview_cache',
    'runtime_security_check',
]
