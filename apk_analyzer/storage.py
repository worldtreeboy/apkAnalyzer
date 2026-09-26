"""Interactive app info, storage audit, shell, and screenshots.

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


def app_analysis(pkg):
    section("APP ANALYSIS")

    print(f"\n  {C.CYAN}Analyzing: {C.BOLD}{pkg}{C.RST}\n")

    # Basic info
    apk_path = get_apk_path(pkg) or "N/A"
    status_line("APK Path", apk_path)

    # Version info
    dumpsys = adb_su(f"dumpsys package {pkg}")
    version_name = "N/A"
    version_code = "N/A"
    target_sdk = "N/A"
    min_sdk = "N/A"
    for line in dumpsys.splitlines():
        line = line.strip()
        if "versionName=" in line and version_name == "N/A":
            version_name = line.split("versionName=")[-1].split()[0]
        if "versionCode=" in line and version_code == "N/A":
            m = re.search(r'versionCode=(\d+)', line)
            if m:
                version_code = m.group(1)
        if "targetSdk=" in line and target_sdk == "N/A":
            m = re.search(r'targetSdk=(\d+)', line)
            if m:
                target_sdk = m.group(1)
        if "minSdk=" in line and min_sdk == "N/A":
            m = re.search(r'minSdk=(\d+)', line)
            if m:
                min_sdk = m.group(1)

    status_line("Version", f"{version_name} (code: {version_code})")
    status_line("Target SDK", target_sdk)
    status_line("Min SDK", min_sdk)

    # Populate report app_info
    report.app_info["version"] = f"{version_name} (code: {version_code})"
    if target_sdk != "N/A":
        report.app_info["target_sdk"] = target_sdk
    if min_sdk != "N/A":
        report.app_info["min_sdk"] = min_sdk

    # Data dir size
    data_size = adb_su(f"du -sh {shlex.quote(f'/data/data/{pkg}')} 2>/dev/null")
    if not _is_err(data_size):
        status_line("Data Size", data_size.split()[0] if data_size.split() else "N/A")

    # Permissions
    print(f"\n  {C.YELLOW}{C.BOLD}── Permissions ──{C.RST}")
    perms = []
    for line in dumpsys.splitlines():
        if "granted=true" in line:
            m = re.search(r'([\w.]+): granted=true', line.strip())
            if m:
                perms.append(m.group(1))
    if perms:
        for p in perms:
            pname = p.split(".")[-1]
            color = C.RED if any(d in pname.upper() for d in [
                "CAMERA", "LOCATION", "MICROPHONE", "SMS", "CALL", "CONTACTS",
                "STORAGE", "READ_EXTERNAL", "WRITE_EXTERNAL"
            ]) else C.WHITE
            print(f"    {color}• {p}{C.RST}")
    else:
        print(f"    {C.DIM}No runtime permissions granted.{C.RST}")

    # Components
    print(f"\n  {C.YELLOW}{C.BOLD}── Components ──{C.RST}")
    # Count from dumpsys
    act_count = len(re.findall(rf'{re.escape(pkg)}/[\w.]+Activity', dumpsys))
    svc_count = len(re.findall(rf'{re.escape(pkg)}/[\w.]+Service', dumpsys))
    rcv_count = len(re.findall(rf'{re.escape(pkg)}/[\w.]+Receiver', dumpsys))
    prov_count = len(re.findall(rf'{re.escape(pkg)}/[\w.]+Provider', dumpsys))
    status_line("Activities", str(act_count))
    status_line("Services", str(svc_count))
    status_line("Receivers", str(rcv_count))
    status_line("Providers", str(prov_count))

    # Extract APK option
    print()
    extract = input(f"  {C.GREEN}Extract APK to local? (y/n) ▸ {C.RST}").strip().lower()
    if extract == "y" and apk_path != "N/A":
        out_dir = os.path.join(os.getcwd(), "extracted_apks")
        os.makedirs(out_dir, exist_ok=True)
        local_path = os.path.join(out_dir, f"{pkg}.apk")
        print(f"  {C.CYAN}Pulling APK...{C.RST}")
        result = adb_pull(apk_path, local_path)
        if (not _is_err(result) and os.path.exists(local_path)
                and os.path.getsize(local_path) > 0):
            size = os.path.getsize(local_path)
            print(f"  {C.GREEN}[✓] Saved: {local_path} ({size // 1024} KB){C.RST}")
        else:
            print(f"  {C.RED}[✗] Pull failed: {result}{C.RST}")

    pause()

def storage_audit(pkg):
    section("STORAGE AUDIT")

    data_dir = f"/data/data/{pkg}"
    print(f"\n  {C.CYAN}Auditing storage: {C.BOLD}{data_dir}{C.RST}\n")

    # Overall size
    size_out = adb_su(f"du -sh {shlex.quote(data_dir)} 2>/dev/null")
    if not _is_err(size_out):
        status_line("Total Size", size_out.split()[0] if size_out.split() else "N/A")

    # List all files recursively (maxdepth + no symlink follow to stay in app dir)
    files_out = adb_su(f"find {shlex.quote(data_dir)} -maxdepth 5 -type f -not -type l 2>/dev/null", timeout=60)
    all_files = [f.strip() for f in files_out.splitlines()
                 if f.strip() and f.startswith(data_dir)]

    sp_files = [f for f in all_files if "/shared_prefs/" in f and f.endswith(".xml")]
    db_files = [f for f in all_files if f.endswith(".db") or f.endswith(".sqlite") or f.endswith(".sqlite3")]
    realm_files = [f for f in all_files if f.endswith(".realm") or f.endswith(".realm.lock")]
    cache_files = [f for f in all_files if "/cache/" in f]
    log_files = [f for f in all_files if f.endswith(".log") or f.endswith(".tmp")]

    status_line("Total Files", str(len(all_files)))
    status_line("SharedPrefs", str(len(sp_files)), C.YELLOW if sp_files else C.GREEN)
    status_line("SQLite DBs", str(len(db_files)), C.YELLOW if db_files else C.GREEN)
    status_line("Realm DBs", str(len(realm_files)), C.YELLOW if realm_files else C.GREEN)
    status_line("Cache Files", str(len(cache_files)))
    status_line("Log/Tmp Files", str(len(log_files)), C.YELLOW if log_files else C.GREEN)

    # SharedPreferences analysis
    # Third-party SDK prefixes to de-prioritize
    sdk_prefixes = ['com.google', 'com.facebook', 'com.firebase', 'com.crashlytics',
                    'com.mixpanel', 'com.amplitude', 'com.appsflyer', 'io.branch',
                    'com.adjust', 'com.segment', 'androidx.', 'WebView', 'chromium']

    if sp_files:
        print(f"\n  {C.YELLOW}{C.BOLD}── SharedPreferences ──{C.RST}")
        secrets_found = 0
        pii_found = 0
        encrypted_prefs = 0

        # Sort: app-specific files first, SDK files last
        def is_sdk_file(f):
            fn = os.path.basename(f).lower()
            return any(sdk.lower() in fn for sdk in sdk_prefixes)
        sp_files_sorted = sorted(sp_files, key=lambda x: (is_sdk_file(x), x))

        # Read all prefs files (and sizes) in a few batched adb calls
        sp_contents, sp_sizes = _batch_read_files(sp_files_sorted)

        for spf in sp_files_sorted:
            fname = _safe_evidence_path(os.path.basename(spf))
            content = sp_contents.get(spf, "")
            fsize = sp_sizes.get(spf, "?")

            # Check for EncryptedSharedPreferences
            is_encrypted = False
            if content and ("__androidx_security_crypto_encrypted" in content or
                           "keyset" in fname.lower() or
                           "__encrypted__" in content):
                is_encrypted = True
                encrypted_prefs += 1

            is_sdk = is_sdk_file(spf)
            sdk_tag = f" {C.DIM}[SDK]{C.RST}" if is_sdk else f" {C.MAGENTA}[APP]{C.RST}"
            enc_tag = f" {C.GREEN}[ENCRYPTED]{C.RST}" if is_encrypted else ""
            print(f"\n    {C.CYAN}📄 {fname}{C.RST} {C.DIM}({fsize} bytes){C.RST}{sdk_tag}{enc_tag}")

            if not _is_err(content) and not is_encrypted:
                # Always show raw XML content (first 10 lines)
                raw_lines = _redact_sensitive_text(content).splitlines()
                preview_count = min(10, len(raw_lines))
                if preview_count > 0:
                    print(f"      {C.WHITE}Content ({len(raw_lines)} lines, showing first {preview_count}):{C.RST}")
                    for rline in raw_lines[:preview_count]:
                        print(f"        {C.DIM}{rline.rstrip()}{C.RST}")
                    if len(raw_lines) > 10:
                        print(f"        {C.DIM}... ({len(raw_lines) - 10} more lines){C.RST}")

                # Extract and highlight key-value pairs
                kv_pairs = []
                # Tags with content: <string name="X">val</string>
                for m in re.finditer(r'<(string|int|long|float|boolean|set)\s+name="([^"]+)"[^>]*>([^<]*)</', content):
                    ktype, kname, kval = m.groups()
                    kv_pairs.append((ktype, kname, kval.strip()))
                # Self-closing tags: <boolean name="X" value="Y" />, <float name="X" value="Y" />
                for m in re.finditer(r'<(boolean|int|long|float)\s+name="([^"]+)"\s+value="([^"]+)"', content):
                    kv_pairs.append((m.group(1), m.group(2), m.group(3)))

                if kv_pairs:
                    sensitive_keys = [
                        # Auth & credentials
                        'token', 'key', 'secret', 'password', 'passwd', 'pwd',
                        'auth', 'session', 'jwt', 'credential', 'pin', 'otp',
                        'login', 'username', 'user_name', 'userid', 'user_id',
                        # PII
                        'email', 'mail', 'phone', 'mobile', 'number', 'address',
                        'name', 'fullname', 'first_name', 'last_name', 'dob',
                        'birth', 'ssn', 'social', 'national_id', 'nric', 'passport',
                        'license', 'gender', 'age', 'ic_number', 'identity',
                        # Financial
                        'account', 'balance', 'credit', 'debit', 'card',
                        'iban', 'routing', 'swift', 'payment', 'bank',
                        'amount', 'transaction', 'wallet',
                        # Crypto / keys
                        'private', 'cert', 'certificate', 'signing',
                        'encryption', 'master', 'api', 'bearer', 'refresh',
                        'access', 'client_id', 'client_secret',
                        # Device / tracking
                        'imei', 'imsi', 'device_id', 'mac_address',
                        'serial', 'fingerprint', 'biometric',
                    ]
                    flagged = [(ktype, kname, kval) for ktype, kname, kval in kv_pairs
                               if any(sk in kname.lower() for sk in sensitive_keys)]
                    if flagged:
                        print(f"      {C.RED}Sensitive Keys Found ({len(flagged)}):{C.RST}")
                        for ktype, kname, kval in flagged[:10]:
                            display_val = _redact(kval[:120])
                            print(f"        {C.RED}⚠ {kname}{C.RST} = {C.RED}{display_val}{C.RST} {C.DIM}({ktype}){C.RST}")

                # Check for secrets
                secret_matches = _find_secret_matches(content, per_pattern_limit=3)
                if secret_matches:
                    secrets_found += 1
                    for value in secret_matches[:3]:
                        print(f"      {C.RED}⚠ Potential secret: {_redact(value[:120])}{C.RST}")

                # Check for PII in values
                pii_hits = _scan_pii(content)
                if pii_hits:
                    pii_found += 1
                    print(f"      {C.RED}PII Detected ({len(pii_hits)}):{C.RST}")
                    for label, val in pii_hits[:8]:
                        print(f"        {C.RED}⚠ {label}: {_redact(val)}{C.RST}")

        if encrypted_prefs > 0:
            print(f"\n    {C.GREEN}Found {encrypted_prefs} EncryptedSharedPreferences file(s).{C.RST}")
        if secrets_found == 0 and pii_found == 0:
            print(f"\n    {C.GREEN}No plaintext secrets or PII detected in SharedPreferences.{C.RST}")
        elif secrets_found == 0:
            print(f"\n    {C.GREEN}No plaintext secrets detected in SharedPreferences.{C.RST}")
        if pii_found > 0:
            print(f"\n    {C.RED}⚠ PII found in {pii_found} SharedPreferences file(s)!{C.RST}")

    # SQLite Database analysis
    # SDK database names to de-prioritize
    sdk_db_names = ['google', 'firebase', 'facebook', 'analytics', 'crashlytics',
                    'com.google', 'gms', 'admob', 'webview', 'chromium']

    if db_files:
        print(f"\n  {C.YELLOW}{C.BOLD}── SQLite Databases ──{C.RST}")

        def is_sdk_db(f):
            fn = os.path.basename(f).lower()
            return any(sdk.lower() in fn for sdk in sdk_db_names)

        # Sort: app-specific DBs first
        db_files_sorted = sorted(db_files, key=lambda x: (is_sdk_db(x), x))

        for dbf in db_files_sorted:
            fname = _safe_evidence_path(os.path.basename(dbf))
            size_info = adb_su(f"ls -la {shlex.quote(dbf)} 2>/dev/null")
            fsize = "?"
            if size_info:
                parts = size_info.split()
                if len(parts) >= 5:
                    fsize = parts[3]

            is_sdk = is_sdk_db(dbf)
            sdk_tag = f" {C.DIM}[SDK]{C.RST}" if is_sdk else f" {C.MAGENTA}[APP]{C.RST}"
            print(f"\n    {C.CYAN}🗄  {fname}{C.RST} {C.DIM}({fsize} bytes){C.RST}{sdk_tag}")

            # Check if encrypted (SQLCipher)
            header = adb_su(f"xxd -l 16 {shlex.quote(dbf)} 2>/dev/null", timeout=5)
            if _is_err(header):
                print(
                    f"      {C.YELLOW}[INCONCLUSIVE] Could not read the "
                    f"database header; encryption and table checks skipped"
                    f"{C.RST}"
                )
                continue
            is_encrypted = header and "5351 4c69 7465" not in header  # "SQLite" magic
            if is_encrypted:
                print(f"      {C.GREEN}[ENCRYPTED - SQLCipher or similar]{C.RST}")
                continue

            tables = adb_su(f"sqlite3 {shlex.quote(dbf)} '.tables' 2>/dev/null", timeout=10)
            if not _is_err(tables) and "not found" not in tables:
                table_list = tables.split()
                safe_tables = _redact_sensitive_text(tables).replace("\n", " ")
                print(f"      Tables ({len(table_list)}): {C.WHITE}{safe_tables[:500]}{C.RST}")

                # For app-specific DBs, show more details
                if not is_sdk:
                    for table in table_list[:5]:  # First 5 tables
                        try:
                            table_ident = _sqlite_identifier(table)
                        except ValueError:
                            continue
                        # Get row count
                        count = _sqlite_read(
                            dbf, f"SELECT COUNT(*) FROM {table_ident}", timeout=5  # nosec B608
                        )
                        count = count.strip() if not _is_err(count) else "?"

                        # Get column names
                        cols = _sqlite_read(
                            dbf, f"PRAGMA table_info({table_ident})", timeout=5
                        )
                        col_names = []
                        if not _is_err(cols):
                            for line in cols.splitlines():
                                parts = line.split("|")
                                if len(parts) >= 2:
                                    col_names.append(parts[1])

                        print(
                            f"      {C.WHITE}→ {_safe_evidence_path(table)}"
                            f"{C.RST} ({_terminal_safe(count)[:40]} rows)"
                        )
                        if col_names:
                            safe_columns = [
                                _safe_evidence_path(name) for name in col_names[:8]
                            ]
                            print(f"        Columns: {C.DIM}{', '.join(safe_columns)}{C.RST}")
                            if len(col_names) > 8:
                                print(f"        {C.DIM}... and {len(col_names) - 8} more columns{C.RST}")

                        # Fetch sample data for PII scanning + display
                        sensitive_tables = ['user', 'account', 'credential', 'token', 'session',
                                            'auth', 'login', 'profile', 'setting', 'config',
                                            'cache', 'payment', 'card', 'address', 'contact',
                                            'transaction', 'order', 'customer', 'member']
                        if (count != "?" and count.isascii()
                                and count.isdigit() and len(count) <= 20
                                and int(count) > 0):
                            sample = _sqlite_read(
                                dbf, f"SELECT * FROM {table_ident} LIMIT 5", timeout=5  # nosec B608
                            )
                            if not _is_err(sample):
                                # Show raw rows for sensitive-looking tables
                                if any(st in table.lower() for st in sensitive_tables):
                                    print(f"        {C.RED}Sample data:{C.RST}")
                                    for row in sample.splitlines()[:3]:
                                        safe_row = _redact_sensitive_text(row)
                                        row_display = safe_row[:100] + "..." if len(safe_row) > 100 else safe_row
                                        print(f"          {C.DIM}{row_display}{C.RST}")
                                # Scan ALL app tables for PII
                                pii_hits = _scan_pii(sample)
                                if pii_hits:
                                    print(f"        {C.RED}⚠ PII in data ({len(pii_hits)}):{C.RST}")
                                    for label, val in pii_hits[:5]:
                                        print(f"          {C.RED}⚠ {label}: {_redact(val)}{C.RST}")

                    if len(table_list) > 5:
                        print(f"      {C.DIM}... and {len(table_list) - 5} more tables{C.RST}")

    # Realm Database analysis
    if realm_files:
        print(f"\n  {C.YELLOW}{C.BOLD}── Realm Databases ──{C.RST}")
        for rf in realm_files:
            fname = _safe_evidence_path(os.path.basename(rf))
            size_info = adb_su(f"ls -la {shlex.quote(rf)} 2>/dev/null")
            fsize = "?"
            if size_info:
                parts = size_info.split()
                if len(parts) >= 5:
                    fsize = parts[3]
            # Check if encrypted by reading header
            header = adb_su(f"xxd -l 8 {shlex.quote(rf)} 2>/dev/null", timeout=5)
            if _is_err(header):
                print(
                    f"    {C.CYAN}🗄  {fname}{C.RST} "
                    f"{C.YELLOW}[INCONCLUSIVE — header unavailable]{C.RST}"
                )
                continue
            is_encrypted = header and "5265 616c 6d" not in header  # "Realm" magic bytes
            enc_tag = f" {C.GREEN}[ENCRYPTED]{C.RST}" if is_encrypted else f" {C.RED}[UNENCRYPTED]{C.RST}"
            print(f"    {C.CYAN}🗄  {fname}{C.RST} {C.DIM}({fsize} bytes){C.RST}{enc_tag}")

    # ── Recursive scan of ALL remaining files ──────────────────────────────
    # Files already inspected above (SharedPrefs, DBs, Realm) are skipped
    inspected = set(sp_files + db_files + realm_files)
    other_files = [f for f in all_files if f not in inspected]

    if other_files:
        print(f"\n  {C.YELLOW}{C.BOLD}── Other Files (files/, cache/, etc.) ──{C.RST}")
        print(f"  {C.DIM}Scanning {len(other_files)} remaining file(s) for sensitive data...{C.RST}")

        highlight_kw = [
            'token', 'key', 'secret', 'password', 'passwd', 'pwd', 'auth',
            'session', 'jwt', 'credential', 'pin', 'otp', 'login', 'username',
            'email', 'mail', 'phone', 'mobile', 'account', 'balance', 'credit',
            'card', 'iban', 'payment', 'bank', 'amount', 'transaction', 'wallet',
            'private', 'cert', 'api', 'bearer', 'refresh', 'access',
            'imei', 'imsi', 'device_id', 'ssn', 'nric', 'passport',
            'address', 'name', 'dob',
            'fingerprint', 'biometric', 'number',
        ]
        other_secrets = 0
        other_pii = 0

        # Read all remaining files in a few batched adb calls
        other_contents, _other_sizes = _batch_read_files(other_files)

        for of in other_files:
            fname = os.path.basename(of)
            rel_path = of.replace(data_dir + "/", "")
            safe_rel_path = _safe_evidence_path(rel_path)
            content = other_contents.get(of, "")

            # Skip binary / empty / error responses
            if _is_err(content):
                continue
            # Basic binary check: if too many non-printable chars, skip
            sample = content[:512]
            non_print = sum(1 for ch in sample if ord(ch) < 32 and ch not in '\n\r\t')
            if non_print > len(sample) * 0.3:
                print(f"\n    {C.CYAN}{safe_rel_path}{C.RST} {C.DIM}[binary, skipped]{C.RST}")
                continue

            lines = _redact_sensitive_text(content).splitlines()
            preview = lines[:5]

            # Check for keyword hits in full content
            content_lower = content.lower()
            hits = [kw for kw in highlight_kw if kw in content_lower]

            # Check SECRET_PATTERNS
            secret_hits = [value[:120] for value in
                           _find_secret_matches(content, per_pattern_limit=2)]

            if secret_hits:
                other_secrets += 1

            hit_tag = ""
            if hits:
                hit_tag = f" {C.RED}[SENSITIVE: {', '.join(hits[:5])}]{C.RST}"
            elif not secret_hits:
                hit_tag = f" {C.DIM}[no keywords]{C.RST}"

            print(f"\n    {C.CYAN}{safe_rel_path}{C.RST} {C.DIM}({len(lines)} lines){C.RST}{hit_tag}")
            for pl in preview:
                line_display = pl.rstrip()
                # Highlight matching keywords in the line
                for kw in hits:
                    pat = re.compile(re.escape(kw), re.IGNORECASE)
                    line_display = pat.sub(f"{C.RED}{C.BOLD}\\g<0>{C.RST}{C.DIM}", line_display)
                print(f"      {C.DIM}{line_display}{C.RST}")
            if len(lines) > 5:
                print(f"      {C.DIM}... ({len(lines) - 5} more lines){C.RST}")

            for sh in secret_hits:
                print(f"      {C.RED}⚠ Potential secret: {_redact(sh)}{C.RST}")

            # Check for PII in content
            pii_hits = _scan_pii(content)
            if pii_hits:
                other_pii += 1
                print(f"      {C.RED}PII Detected ({len(pii_hits)}):{C.RST}")
                for label, val in pii_hits[:5]:
                    print(f"        {C.RED}⚠ {label}: {_redact(val)}{C.RST}")

        if other_secrets == 0 and other_pii == 0:
            print(f"\n    {C.GREEN}No secrets or PII detected in other files.{C.RST}")
        else:
            if other_secrets > 0:
                print(f"\n    {C.RED}⚠ Found potential secrets in {other_secrets} file(s).{C.RST}")
            if other_pii > 0:
                print(f"\n    {C.RED}⚠ Found PII in {other_pii} file(s)!{C.RST}")

    # File Permission Check (world-readable)
    print(f"\n  {C.YELLOW}{C.BOLD}── File Permissions ──{C.RST}")
    world_readable = []
    find_out = adb_su(f"find {shlex.quote(data_dir)} -maxdepth 5 -type f -perm -o+r 2>/dev/null", timeout=30)
    wr_paths = [f.strip() for f in find_out.splitlines()
                if f.strip() and f.startswith(data_dir)]
    wr_modes = _batch_stat(wr_paths)
    for f in wr_paths:
        perms = wr_modes.get(f, "")
        if len(perms) >= 3 and perms[-1] in ['4', '5', '6', '7']:  # world-readable
            world_readable.append((f, perms))
    if world_readable:
        print(f"    {C.RED}⚠ Found {len(world_readable)} world-readable file(s):{C.RST}")
        for wf, perm in world_readable[:10]:
            print(f"      {C.DIM}{os.path.basename(wf)} (mode: {perm}){C.RST}")
        if len(world_readable) > 10:
            print(f"      {C.DIM}... and {len(world_readable) - 10} more{C.RST}")
    else:
        print(f"    {C.GREEN}No world-readable files found (checked {len(all_files)} files).{C.RST}")

    # External storage check
    print(f"\n  {C.YELLOW}{C.BOLD}── External Storage ──{C.RST}")
    ext_dir = f"/sdcard/Android/data/{pkg}"
    ext_out = adb_su(f"ls -la {shlex.quote(ext_dir)} 2>/dev/null")
    if not _is_err(ext_out) and "No such file" not in ext_out:
        ext_size = adb_su(f"du -sh {shlex.quote(ext_dir)} 2>/dev/null")
        status_line("External Dir", ext_size.split()[0] if ext_size and ext_size.split() else "exists")
    else:
        print(f"    {C.DIM}No external storage data found.{C.RST}")

    pause()

# ─── 3. Shell Access ────────────────────────────────────────────────────────────

def shell_access(pkg=None):
    section("SHELL ACCESS (ROOT)")
    print(f"  {C.DIM}Type commands to execute as root. Type 'exit' to return.{C.RST}\n")

    # Start in the app's data directory if a package is selected
    cwd = f"/data/data/{pkg}" if pkg else "/data/local/tmp"

    while True:
        # Show current directory in prompt
        display_cwd = cwd if len(cwd) <= 40 else "..." + cwd[-37:]
        try:
            cmd = input(f"  {C.RED}root@device{C.RST}:{C.BLUE}{display_cwd}{C.RST}# ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not cmd:
            continue
        if cmd.lower() == "exit":
            return

        # Handle cd command specially to update cwd
        if cmd == "cd" or cmd == "cd ~":
            cwd = "/data/local/tmp"
            continue
        elif cmd.startswith("cd "):
            target = cmd[3:].strip().strip('"').strip("'")
            if not target:
                continue
            # Resolve Android paths with POSIX semantics on every host OS.
            if target.startswith("/"):
                new_cwd = posixpath.normpath(target)
            else:
                new_cwd = posixpath.normpath(posixpath.join(cwd, target))
            # Verify directory exists by actually cd-ing into it
            check = adb_su(f'cd {shlex.quote(new_cwd)} && pwd')
            resolved = check.strip().splitlines()[-1].strip() if check else ""
            if resolved.startswith("/"):
                cwd = resolved
            else:
                print(f"  {C.RED}cd: {target}: No such directory{C.RST}\n")
            continue

        # Run command in current directory
        full_cmd = f'cd {shlex.quote(cwd)} && {cmd}'
        output = adb_su(full_cmd, timeout=30)
        if output:
            for line in output.splitlines():
                print(f"  {line}")
        print()

# ─── 4. Screenshot ──────────────────────────────────────────────────────────────

def screenshot():
    section("SCREENSHOT")
    remote_path = "/sdcard/_apkanalyzer_screenshot.png"
    print(f"  {C.CYAN}Capturing screenshot...{C.RST}")
    adb_shell(f"screencap -p {remote_path}")

    out_dir = os.path.join(os.getcwd(), "screenshots")
    os.makedirs(out_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    local_path = os.path.join(out_dir, f"screenshot_{timestamp}.png")

    result = adb_pull(remote_path, local_path)
    adb_shell(f"rm {remote_path}")

    if os.path.exists(local_path):
        size = os.path.getsize(local_path)
        print(f"  {C.GREEN}[✓] Screenshot saved: {local_path} ({size // 1024} KB){C.RST}")
    else:
        print(f"  {C.RED}[✗] Screenshot failed: {result}{C.RST}")

    pause()


__all__ = [
    'app_analysis',
    'storage_audit',
    'shell_access',
    'screenshot',
]
