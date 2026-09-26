"""Interactive component probes and adb-backup extraction.

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

# ─── Testcases for Fun ────────────────────────────────────────────────────────────

# ─── ADB Backup Extraction (allowBackup=true vector) ─────────────────────────────

def _find_symlinked_path_component(path):
    """Return a symlink at or above *path*, including broken symlinks."""
    return archive_mod.find_symlinked_path_component(path)


def _filesystem_is_case_sensitive(directory):
    """Probe the destination filesystem instead of guessing from the host OS."""
    return archive_mod.filesystem_is_case_sensitive(directory)


def _unpack_ab(ab_path, out_dir):
    """Parse an Android .ab backup and extract its tar payload into out_dir.

    Returns (file_count, error_message_or_None). Extraction is bounded and all
    archive entries are confined to out_dir."""
    return archive_mod.unpack_ab(
        ab_path,
        out_dir,
        max_backup_bytes=MAX_BACKUP_BYTES,
        max_backup_payload_bytes=MAX_BACKUP_PAYLOAD_BYTES,
        max_backup_file_bytes=MAX_BACKUP_FILE_BYTES,
        max_backup_files=MAX_BACKUP_FILES,
        case_sensitive_probe=_filesystem_is_case_sensitive,
        symlink_component_finder=_find_symlinked_path_component,
    )


def backup_extraction(pkg):
    """Demonstrate data exfiltration via 'adb backup' when allowBackup=true.

    Runs a (non-root) backup, unpacks the .ab archive, and scans the contents
    for secrets/PII with the existing detection engine. Findings feed the report."""
    section("ADB BACKUP EXTRACTION")
    print(f"\n  {C.CYAN}Target: {C.BOLD}{pkg}{C.RST}")
    print(f"  {C.DIM}Demonstrates the allowBackup=true data-extraction vector (no root needed).{C.RST}\n")

    # ── Fast allowBackup check via dumpsys flags (no decompile) ───────────────
    flags_out = adb_su(f"dumpsys package {pkg} | grep -i flags", timeout=15)
    allow_backup = True
    if not _is_err(flags_out):
        allow_backup = "ALLOW_BACKUP" in flags_out
    if not allow_backup:
        print(f"  {C.YELLOW}[!] allowBackup appears DISABLED for this app.{C.RST}")
        print(f"  {C.DIM}The backup will most likely be empty, but you can still try.{C.RST}")
        try:
            cont = input(f"\n  {C.GREEN}Attempt backup anyway? [y/N] ▸ {C.RST}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            pause()
            return
        if cont != "y":
            pause()
            return
    else:
        print(f"  {C.GREEN}[+] allowBackup is enabled — app data is backup-eligible.{C.RST}")

    out_base = os.path.join(os.getcwd(), "backups")
    os.makedirs(out_base, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ab_path = os.path.join(out_base, f"{pkg}_{ts}.ab")

    # ── Run adb backup (interactive: device shows a confirmation dialog) ──────
    print(f"\n  {C.YELLOW}{C.BOLD}── On the device ──{C.RST}")
    print(f"  {C.WHITE}A backup confirmation will appear on the device screen.{C.RST}")
    print(f"  {C.WHITE}Tap {C.BOLD}\"Back up my data\"{C.RST}{C.WHITE} and leave the password field EMPTY.{C.RST}")
    print(f"  {C.DIM}(Unlock the device first if the screen is off.){C.RST}")
    try:
        input(f"\n  {C.GREEN}Press Enter to start the backup ▸ {C.RST}")
    except (EOFError, KeyboardInterrupt):
        print()
        pause()
        return

    print(f"\n  {C.CYAN}[*] Running: adb backup -f {os.path.basename(ab_path)} -noapk -noshared {pkg}{C.RST}")
    print(f"  {C.DIM}Waiting for on-device confirmation...{C.RST}")
    try:
        backup_result = _process_run_command_capture(
            _adb_base() + ["backup", "-f", ab_path, "-noapk", "-noshared", pkg],
            timeout=180,
        )
        if backup_result.returncode != 0:
            detail = backup_result.stderr or backup_result.stdout
            print(
                f"  {C.RED}[!] adb backup failed (exit "
                f"{backup_result.returncode}): "
                f"{_headless_safe_text(detail or 'no diagnostic', 400)}{C.RST}"
            )
            pause()
            return
    except subprocess.TimeoutExpired:
        print(f"  {C.RED}[!] Backup timed out — confirmation may not have been tapped.{C.RST}")
        pause()
        return
    except (OSError, ValueError, CommandOutputLimitExceeded) as exc:
        print(
            f"  {C.RED}[!] adb backup failed: "
            f"{_headless_diagnostic(exc, 400)}{C.RST}"
        )
        pause()
        return

    if not os.path.exists(ab_path) or os.path.getsize(ab_path) == 0:
        print(f"  {C.RED}[!] No backup data produced (declined, or backup restricted on this device).{C.RST}")
        print(f"  {C.DIM}Note: adb backup is deprecated/limited on Android 12+ and many OEM builds.{C.RST}")
        pause()
        return

    ab_size = os.path.getsize(ab_path)
    print(f"  {C.GREEN}[+] Backup written: {ab_path} ({ab_size // 1024} KB){C.RST}")

    # ── Unpack the .ab ───────────────────────────────────────────────────────
    extract_dir = os.path.join(out_base, f"{pkg}_{ts}_unpacked")
    os.makedirs(extract_dir, exist_ok=True)
    print(f"  {C.DIM}Unpacking backup archive...{C.RST}")
    count, err = _unpack_ab(ab_path, extract_dir)
    if err:
        print(f"  {C.RED}[!] {err}{C.RST}")
        pause()
        return
    if count == 0:
        print(f"  {C.YELLOW}[!] Backup unpacked but contained no files.{C.RST}")
        pause()
        return
    print(f"  {C.GREEN}[+] Extracted {count} file(s) → {extract_dir}{C.RST}")

    # Record the exploitable-backup finding itself
    report.add_finding(
        "Backup: Data Extraction",
        "App data extracted via adb backup",
        "HIGH", "HIGH",
        f"Extracted {count} file(s) from {pkg} using 'adb backup' without root. allowBackup is enabled.",
        "Set android:allowBackup=false, or define dataExtractionRules/fullBackupContent to exclude sensitive data.",
        "MASVS-STORAGE-1", "CWE-530",
    )

    # ── Scan extracted files for secrets / PII ───────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Scanning Extracted Data ──{C.RST}")
    secrets_files = 0
    pii_files = 0
    for root, dirs, files in os.walk(extract_dir):
        for fn in files:
            fpath = os.path.join(root, fn)
            try:
                if os.path.getsize(fpath) > 2_000_000:  # skip very large files
                    continue
                with open(fpath, "r", errors="ignore") as fh:
                    content = fh.read()
            except Exception:
                continue
            if not content:
                continue
            # Binary heuristic: skip files with many non-printable bytes
            sample = content[:512]
            non_print = sum(1 for ch in sample if ord(ch) < 32 and ch not in "\n\r\t")
            if sample and non_print > len(sample) * 0.3:
                continue

            rel = os.path.relpath(fpath, extract_dir)
            safe_rel = _safe_evidence_path(rel)
            secret_hits = [value[:120] for value in
                           _find_secret_matches(content, per_pattern_limit=3)]
            pii_hits = _scan_pii(content)

            if secret_hits or pii_hits:
                print(f"\n    {C.CYAN}{safe_rel}{C.RST}")
            if secret_hits:
                secrets_files += 1
                for sh in secret_hits[:5]:
                    print(f"      {C.RED}⚠ Potential secret: {_redact(sh)}{C.RST}")
                report.add_finding(
                    "Backup: Sensitive Data", f"Secret in backup: {safe_rel}",
                    "HIGH", "MEDIUM",
                    f"Secret pattern found in backed-up file {safe_rel}: {_redact(secret_hits[0])}",
                    "Exclude sensitive files from backup; never store secrets unencrypted in app data.",
                    "MASVS-STORAGE-1", "CWE-312",
                )
            if pii_hits:
                pii_files += 1
                for label, val in pii_hits[:5]:
                    print(f"      {C.RED}⚠ PII ({label}): {_redact(val)}{C.RST}")
                report.add_finding(
                    "Backup: Sensitive Data", f"PII in backup: {safe_rel}",
                    "MEDIUM", "MEDIUM",
                    f"PII ({pii_hits[0][0]}) found in backed-up file {safe_rel}.",
                    "Exclude personal data from backups or encrypt sensitive data at rest.",
                    "MASVS-STORAGE-2", "CWE-359",
                )

    # ── Result ───────────────────────────────────────────────────────────────
    print(f"\n  {C.CYAN}{'═'*50}{C.RST}")
    if secrets_files or pii_files:
        print(f"  {C.RED}{C.BOLD}RESULT: Backup exposes sensitive data{C.RST}")
        print(f"  {C.DIM}Secrets in {secrets_files} file(s), PII in {pii_files} file(s).{C.RST}")
        print(f"  {C.DIM}Anyone with USB/ADB access can extract this without root.{C.RST}")
    else:
        print(f"  {C.GREEN}{C.BOLD}RESULT: Backup succeeded but no obvious secrets/PII found{C.RST}")
        print(f"  {C.DIM}Data still extracted to {extract_dir} — review manually.{C.RST}")
    print(f"  {C.DIM}Findings added to the report (export with [r]).{C.RST}")
    pause()


def fun_testcases(pkg):
    section("TESTCASES FOR FUN")

    while True:
        print(f"\n  {C.CYAN}{C.BOLD}── Test Cases for: {pkg} ──{C.RST}\n")
        print(f"  {C.YELLOW}[1]{C.RST} {C.WHITE}Launch Exported Activities{C.RST}")
        print(f"      {C.DIM}Start each exported activity for manual access-control review{C.RST}")
        print(f"  {C.YELLOW}[2]{C.RST} {C.WHITE}Launch Exported Services{C.RST}")
        print(f"      {C.DIM}Start each exported service{C.RST}")
        print(f"  {C.YELLOW}[3]{C.RST} {C.WHITE}Launch Broadcast Receivers{C.RST}")
        print(f"      {C.DIM}Send empty broadcast to each exported receiver{C.RST}")
        print(f"  {C.YELLOW}[4]{C.RST} {C.WHITE}Query Content Providers{C.RST}")
        print(f"      {C.DIM}Query exported providers for data leakage{C.RST}")
        print(f"  {C.YELLOW}[5]{C.RST} {C.WHITE}Clipboard Spy{C.RST}")
        print(f"      {C.DIM}Read clipboard after user copies sensitive data{C.RST}")
        print(f"  {C.YELLOW}[6]{C.RST} {C.WHITE}Dev/Staging URL Finder{C.RST}")
        print(f"      {C.DIM}Search decompiled code for internal/dev URLs{C.RST}")
        print(f"  {C.YELLOW}[7]{C.RST} {C.WHITE}Repackaging Integrity Check{C.RST}")
        print(f"      {C.DIM}Launch patched APK and check if integrity checks kill it{C.RST}")
        print(f"  {C.YELLOW}[8]{C.RST} {C.WHITE}ADB Backup Extraction{C.RST}")
        print(f"      {C.DIM}Pull & unpack app data via adb backup (allowBackup vector){C.RST}")
        print(f"\n  {C.DIM}[0] Back{C.RST}")

        choice = input(f"\n  {C.GREEN}Select test ▸ {C.RST}").strip()

        if choice == "0":
            return

        # ── Sub-options 1-3 need the manifest ────────────────────────────
        if choice in ("1", "2", "3", "4"):
            work_dir, decompiled_dir = _pull_and_decompile(pkg)
            if not decompiled_dir:
                pause()
                continue
            manifest = _parse_manifest(decompiled_dir)
            if not manifest["parsed"]:
                print(f"  {C.RED}[!] Could not read AndroidManifest.xml{C.RST}")
                pause()
                continue
            exported = manifest["exported"]

        if choice == "1":
            # ── Launch Exported Activities ────────────────────────────────
            print(f"\n  {C.YELLOW}{C.BOLD}── Launching Exported Activities ──{C.RST}\n")
            acts = exported["activity"]
            if not acts:
                print(f"  {C.DIM}No exported activities found.{C.RST}")
            else:
                print(f"  {C.CYAN}Found {len(acts)} exported activit{'y' if len(acts) == 1 else 'ies'}{C.RST}")

                # Show list with actions
                for i, comp in enumerate(acts, 1):
                    action_str = f" {C.DIM}actions: {', '.join(comp['actions'])}{C.RST}" if comp['actions'] else ""
                    print(f"    {C.YELLOW}[{i}]{C.RST} {comp['name']}{action_str}")

                print(f"\n  {C.DIM}[a] Launch all  [0] Back{C.RST}")
                print(f"  {C.DIM}Add extras: append after number, e.g. '1 --es key value --ei num 42'{C.RST}")
                sel = input(f"\n  {C.GREEN}Select ▸ {C.RST}").strip()
                if sel == "0":
                    continue

                targets = []
                extra_args = ""
                if sel.lower().startswith("a"):
                    targets = acts
                    rest = sel[1:].strip()
                    if rest:
                        extra_args = rest
                else:
                    parts = sel.split(maxsplit=1)
                    try:
                        idx = int(parts[0]) - 1
                        if 0 <= idx < len(acts):
                            targets = [acts[idx]]
                        extra_args = parts[1] if len(parts) > 1 else ""
                    except (ValueError, IndexError):
                        print(f"  {C.RED}Invalid selection.{C.RST}")

                for comp in targets:
                    name = comp['name']
                    # Build command: use first action from intent-filter if available
                    cmd = f"am start -n {shlex.quote(f'{pkg}/{name}')}"
                    if comp['actions']:
                        cmd += f" -a {shlex.quote(comp['actions'][0])}"
                    if extra_args:
                        cmd += f" {extra_args}"
                    print(f"\n  {C.DIM}$ {cmd}{C.RST}")
                    out = adb_shell(cmd, timeout=10)
                    if "Error" in out or "Exception" in out:
                        print(f"  {C.RED}[✗]{C.RST} {name}")
                        print(f"      {C.DIM}{out[:200]}{C.RST}")
                    else:
                        print(f"  {C.GREEN}[✓]{C.RST} {name} {C.YELLOW}— externally launchable; review access controls{C.RST}")
                    time.sleep(0.5)
            pause()

        elif choice == "2":
            # ── Launch Exported Services ──────────────────────────────────
            print(f"\n  {C.YELLOW}{C.BOLD}── Launching Exported Services ──{C.RST}\n")
            svcs = exported["service"]
            if not svcs:
                print(f"  {C.DIM}No exported services found.{C.RST}")
            else:
                print(f"  {C.CYAN}Found {len(svcs)} exported service{'s' if len(svcs) != 1 else ''}{C.RST}")

                for i, comp in enumerate(svcs, 1):
                    action_str = f" {C.DIM}actions: {', '.join(comp['actions'])}{C.RST}" if comp['actions'] else ""
                    print(f"    {C.YELLOW}[{i}]{C.RST} {comp['name']}{action_str}")

                print(f"\n  {C.DIM}[a] Launch all  [0] Back{C.RST}")
                print(f"  {C.DIM}Add extras: append after number, e.g. '1 --es key value'{C.RST}")
                sel = input(f"\n  {C.GREEN}Select ▸ {C.RST}").strip()
                if sel == "0":
                    continue

                targets = []
                extra_args = ""
                if sel.lower().startswith("a"):
                    targets = svcs
                    rest = sel[1:].strip()
                    if rest:
                        extra_args = rest
                else:
                    parts = sel.split(maxsplit=1)
                    try:
                        idx = int(parts[0]) - 1
                        if 0 <= idx < len(svcs):
                            targets = [svcs[idx]]
                        extra_args = parts[1] if len(parts) > 1 else ""
                    except (ValueError, IndexError):
                        print(f"  {C.RED}Invalid selection.{C.RST}")

                for comp in targets:
                    name = comp['name']
                    cmd = f"am startservice -n {shlex.quote(f'{pkg}/{name}')}"
                    if comp['actions']:
                        cmd += f" -a {shlex.quote(comp['actions'][0])}"
                    if extra_args:
                        cmd += f" {extra_args}"
                    print(f"\n  {C.DIM}$ {cmd}{C.RST}")
                    out = adb_shell(cmd, timeout=10)
                    if "Error" in out or "Exception" in out:
                        print(f"  {C.RED}[✗]{C.RST} {name}")
                        print(f"      {C.DIM}{out[:200]}{C.RST}")
                    else:
                        print(f"  {C.GREEN}[✓]{C.RST} {name} {C.YELLOW}— started{C.RST}")
                    time.sleep(0.5)
            pause()

        elif choice == "3":
            # ── Launch Broadcast Receivers ────────────────────────────────
            print(f"\n  {C.YELLOW}{C.BOLD}── Sending Broadcasts to Exported Receivers ──{C.RST}\n")
            rcvs = exported["receiver"]
            if not rcvs:
                print(f"  {C.DIM}No exported receivers found.{C.RST}")
            else:
                print(f"  {C.CYAN}Found {len(rcvs)} exported receiver{'s' if len(rcvs) != 1 else ''}{C.RST}")

                for i, comp in enumerate(rcvs, 1):
                    action_str = f" {C.DIM}actions: {', '.join(comp['actions'])}{C.RST}" if comp['actions'] else ""
                    print(f"    {C.YELLOW}[{i}]{C.RST} {comp['name']}{action_str}")

                print(f"\n  {C.DIM}[a] Launch all  [0] Back{C.RST}")
                print(f"  {C.DIM}Add extras: append after number, e.g. '1 --es key value'{C.RST}")
                sel = input(f"\n  {C.GREEN}Select ▸ {C.RST}").strip()
                if sel == "0":
                    continue

                targets = []
                extra_args = ""
                if sel.lower().startswith("a"):
                    targets = rcvs
                    rest = sel[1:].strip()
                    if rest:
                        extra_args = rest
                else:
                    parts = sel.split(maxsplit=1)
                    try:
                        idx = int(parts[0]) - 1
                        if 0 <= idx < len(rcvs):
                            targets = [rcvs[idx]]
                        extra_args = parts[1] if len(parts) > 1 else ""
                    except (ValueError, IndexError):
                        print(f"  {C.RED}Invalid selection.{C.RST}")

                for comp in targets:
                    name = comp['name']
                    cmd = f"am broadcast -n {shlex.quote(f'{pkg}/{name}')}"
                    if comp['actions']:
                        cmd += f" -a {shlex.quote(comp['actions'][0])}"
                    if extra_args:
                        cmd += f" {extra_args}"
                    print(f"\n  {C.DIM}$ {cmd}{C.RST}")
                    out = adb_shell(cmd, timeout=10)
                    if "Error" in out or "Exception" in out:
                        print(f"  {C.RED}[✗]{C.RST} {name}")
                        print(f"      {C.DIM}{out[:200]}{C.RST}")
                    else:
                        result_line = ""
                        for line in out.splitlines():
                            if "result=" in line.lower():
                                result_line = line.strip()
                                break
                        if result_line:
                            print(f"  {C.GREEN}[✓]{C.RST} {name} {C.DIM}— {result_line}{C.RST}")
                        else:
                            print(f"  {C.GREEN}[✓]{C.RST} {name} {C.YELLOW}— broadcast sent{C.RST}")
                    time.sleep(0.5)
            pause()

        elif choice == "4":
            # ── Query Content Providers ───────────────────────────────────
            print(f"\n  {C.YELLOW}{C.BOLD}── Query Exported Content Providers ──{C.RST}\n")
            provs = exported.get("provider", [])
            if not provs:
                print(f"  {C.DIM}No exported content providers found.{C.RST}")
            else:
                print(f"  {C.CYAN}Found {len(provs)} exported provider{'s' if len(provs) != 1 else ''}{C.RST}\n")

                for i, prov in enumerate(provs, 1):
                    perm_tags = []
                    if not prov["read_perm"] and not prov["write_perm"]:
                        perm_tags.append(f"{C.RED}NO PERMISSION{C.RST}")
                    else:
                        if prov["read_perm"]:
                            perm_tags.append(f"{C.DIM}read: {prov['read_perm']}{C.RST}")
                        if prov["write_perm"]:
                            perm_tags.append(f"{C.DIM}write: {prov['write_perm']}{C.RST}")
                    if prov["grant_uri"]:
                        perm_tags.append(f"{C.YELLOW}grantUriPermissions{C.RST}")
                    perm_str = " | ".join(perm_tags) if perm_tags else ""

                    auth_str = ", ".join(prov["authorities"]) if prov["authorities"] else "no authorities"
                    print(f"    {C.YELLOW}[{i}]{C.RST} {prov['name']}")
                    print(f"        {C.DIM}authorities: {auth_str}{C.RST}")
                    if perm_str:
                        print(f"        {perm_str}")
                    if prov.get("path_permissions"):
                        for pp in prov["path_permissions"]:
                            pp_perms = []
                            if pp["read_perm"]:
                                pp_perms.append(f"read: {pp['read_perm']}")
                            if pp["write_perm"]:
                                pp_perms.append(f"write: {pp['write_perm']}")
                            print(f"        {C.DIM}path-permission: {pp['path']} ({', '.join(pp_perms)}){C.RST}")

                print(f"\n  {C.DIM}[a] Query all  [0] Back{C.RST}")
                print(f"  {C.DIM}Append custom path after number, e.g. '1 /users'{C.RST}")
                sel = input(f"\n  {C.GREEN}Select ▸ {C.RST}").strip()
                if sel == "0":
                    pass
                else:
                    targets = []
                    custom_path = ""
                    if sel.lower().startswith("a"):
                        targets = provs
                        rest = sel[1:].strip()
                        if rest:
                            custom_path = rest
                    else:
                        parts = sel.split(maxsplit=1)
                        try:
                            idx = int(parts[0]) - 1
                            if 0 <= idx < len(provs):
                                targets = [provs[idx]]
                            custom_path = parts[1] if len(parts) > 1 else ""
                        except (ValueError, IndexError):
                            print(f"  {C.RED}Invalid selection.{C.RST}")

                    for prov in targets:
                        authorities = prov["authorities"]
                        if not authorities:
                            print(f"\n  {C.DIM}Skipping {prov['name']} (no authorities defined){C.RST}")
                            continue

                        for authority in authorities:
                            uri = f"content://{authority}"
                            if custom_path:
                                uri += custom_path if custom_path.startswith("/") else f"/{custom_path}"

                            print(f"\n  {C.CYAN}Querying: {C.BOLD}{uri}{C.RST}")

                            # Try content query
                            out = adb_shell(
                                f"content query --uri {shlex.quote(uri)}", timeout=15
                            )
                            if not _is_err(out):
                                lines = out.splitlines()
                                if any("Row:" in l for l in lines):
                                    row_count = sum(1 for l in lines if "Row:" in l)
                                    print(f"  {C.RED}[!] DATA EXPOSED{C.RST} — {row_count} row{'s' if row_count != 1 else ''} returned")
                                    for line in lines[:15]:
                                        print(f"      {C.DIM}{line.strip()[:120]}{C.RST}")
                                    if len(lines) > 15:
                                        print(f"      {C.DIM}... ({len(lines) - 15} more lines){C.RST}")
                                elif "No result found" in out:
                                    print(f"  {C.GREEN}[+]{C.RST} No rows returned (empty or requires path)")
                                elif "Permission Denial" in out or "SecurityException" in out:
                                    print(f"  {C.GREEN}[+]{C.RST} Protected — {C.DIM}permission denied{C.RST}")
                                elif "Unknown URI" in out or "UnsupportedOperationException" in out:
                                    print(f"  {C.YELLOW}[-]{C.RST} URI not recognized by provider")
                                else:
                                    print(f"  {C.YELLOW}[-]{C.RST} Response:")
                                    for line in out.splitlines()[:5]:
                                        print(f"      {C.DIM}{line.strip()[:120]}{C.RST}")
                            else:
                                print(f"  {C.DIM}No response or error: {out[:100] if out else '(empty)'}{C.RST}")

                            # Also try common sub-paths if no custom path given
                            if not custom_path:
                                for sub_path in ["", "/", "/*"]:
                                    test_uri = f"content://{authority}{sub_path}" if sub_path else uri
                                    if test_uri == uri:
                                        continue
                                    out2 = adb_shell(
                                        f"content query --uri {shlex.quote(test_uri)}", timeout=10
                                    )
                                    if out2 and "Row:" in out2:
                                        row_count = sum(1 for l in out2.splitlines() if "Row:" in l)
                                        print(f"  {C.RED}[!] DATA EXPOSED at {test_uri}{C.RST} — {row_count} row{'s' if row_count != 1 else ''}")
                                        for line in out2.splitlines()[:5]:
                                            print(f"      {C.DIM}{line.strip()[:120]}{C.RST}")

                        time.sleep(0.3)

                    print(f"\n  {C.CYAN}{'─'*50}{C.RST}")
                    print(f"  {C.DIM}Tip: Providers returning data without permission are a data leakage risk.{C.RST}")
                    print(f"  {C.DIM}Try custom paths like /users, /accounts, /files to enumerate tables.{C.RST}")
            pause()

        elif choice == "5":
            # ── Clipboard Spy ────────────────────────────────────────────
            print(f"\n  {C.YELLOW}{C.BOLD}── Clipboard Spy ──{C.RST}\n")
            print(f"  {C.CYAN}Copy something sensitive in the target app, then press Enter.{C.RST}")
            input(f"  {C.GREEN}▸ Ready? Press Enter to read clipboard... {C.RST}")

            clip = adb_su("service call clipboard 2 i32 1 i32 0", timeout=10)
            clip_text = ""
            if clip and "Parcel" in clip:
                # Try to extract readable text from the parcel response
                parts = re.findall(r"'([^']+)'", clip)
                if parts:
                    clip_text = "".join(parts).replace(".", "").strip()

            # Also try dumpsys as fallback
            if not clip_text:
                dump = adb_su("dumpsys clipboard", timeout=10)
                if dump and "mPrimaryClip" in dump:
                    m = re.search(r'mPrimaryClip=ClipData\{[^}]*\{T:([^}]+)\}', dump)
                    if m:
                        clip_text = m.group(1).strip()
                    else:
                        # Try to find any text content
                        for line in dump.splitlines():
                            if "T:" in line:
                                clip_text = line.strip()
                                break

            print()
            if clip_text:
                print(f"  {C.RED}{C.BOLD}[!] Clipboard content found:{C.RST}")
                print(f"  {C.WHITE}{C.BOLD}{_redact_sensitive_text(clip_text)}{C.RST}")
                print(f"\n  {C.YELLOW}If this contains sensitive data, the app may not be")
                print(f"  clearing the clipboard properly.{C.RST}")
            else:
                print(f"  {C.DIM}No readable clipboard content found.{C.RST}")
                print(f"  {C.DIM}Raw response:{C.RST}")
                print(f"  {C.DIM}{clip[:200] if clip else '(empty)'}{C.RST}")
            pause()

        elif choice == "6":
            # ── Dev/Staging URL Finder ───────────────────────────────────
            print(f"\n  {C.YELLOW}{C.BOLD}── Dev/Staging URL Finder ──{C.RST}\n")
            work_dir, decompiled_dir = _pull_and_decompile(pkg)
            if not decompiled_dir:
                pause()
                continue

            dev_patterns = [
                (r'https?://dev\.', "dev URL"),
                (r'https?://staging\.', "staging URL"),
                (r'https?://test\.', "test URL"),
                (r'https?://uat\.', "UAT URL"),
                (r'https?://qa\.', "QA URL"),
                (r'https?://localhost[:/]', "localhost"),
                (r'https?://127\.0\.0\.1', "loopback (127.0.0.1)"),
                (r'https?://10\.0\.2\.2', "Android emulator host (10.0.2.2)"),
                (r'192\.168\.\d+\.\d+', "private IP (192.168.x.x)"),
                (r'10\.\d+\.\d+\.\d+', "private IP (10.x.x.x)"),
                (r'172\.(1[6-9]|2\d|3[01])\.\d+\.\d+', "private IP (172.16-31.x.x)"),
            ]
            compiled = [(re.compile(p, re.IGNORECASE), label) for p, label in dev_patterns]

            findings = []
            skip_ext = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.bmp',
                        '.mp3', '.mp4', '.ogg', '.wav', '.ttf', '.otf', '.woff',
                        '.woff2', '.eot', '.so', '.dex', '.class', '.jar', '.zip'}

            print(f"  {C.DIM}Scanning decompiled files...{C.RST}")
            for root, dirs, files in os.walk(decompiled_dir):
                for fname in files:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext in skip_ext:
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, 'r', errors='ignore') as f:
                            for line_num, line in enumerate(f, 1):
                                for pat, label in compiled:
                                    m = pat.search(line)
                                    if m:
                                        rel = os.path.relpath(fpath, decompiled_dir)
                                        findings.append((label, m.group(0), rel, line_num))
                    except Exception:
                        continue

            print()
            if findings:
                print(f"  {C.RED}{C.BOLD}[!] Found {len(findings)} dev/internal URL reference{'s' if len(findings) != 1 else ''}:{C.RST}\n")
                seen = set()
                for label, match, rel_path, line_num in findings:
                    key = (match, rel_path, line_num)
                    if key in seen:
                        continue
                    seen.add(key)
                    print(f"  {C.YELLOW}[{label}]{C.RST} {C.WHITE}{match}{C.RST}")
                    print(f"      {C.DIM}{rel_path}:{line_num}{C.RST}")
                print(f"\n  {C.YELLOW}These may indicate leftover dev/staging endpoints")
                print(f"  that could expose internal infrastructure.{C.RST}")
            else:
                print(f"  {C.GREEN}[+] No dev/staging URLs found.{C.RST}")
            pause()

        elif choice == "7":
            # ── Repackaging / Integrity Check ─────────────────────────────
            print(f"\n  {C.YELLOW}{C.BOLD}── Repackaging Integrity Check ──{C.RST}\n")
            print(f"  {C.CYAN}This test checks whether the app detects repackaging/re-signing.{C.RST}")
            print(f"  {C.CYAN}You must have already installed a patched/re-signed APK of:{C.RST}")
            print(f"  {C.WHITE}{C.BOLD}  {pkg}{C.RST}\n")
            print(f"  {C.DIM}The test will:{C.RST}")
            print(f"  {C.DIM}  1. Force-stop the app{C.RST}")
            print(f"  {C.DIM}  2. Launch it via monkey / am start{C.RST}")
            print(f"  {C.DIM}  3. Monitor the process for up to 30 seconds{C.RST}")
            print(f"  {C.DIM}  4. Report whether it survived or was killed{C.RST}")

            try:
                confirm = input(f"\n  {C.GREEN}Is the patched APK installed? [y/N] ▸ {C.RST}").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                pause()
                continue
            if confirm != "y":
                print(f"  {C.DIM}Aborted. Install the patched APK first.{C.RST}")
                pause()
                continue

            # Force-stop to ensure clean start
            print(f"\n  {C.DIM}Force-stopping {pkg}...{C.RST}")
            adb_shell(f"am force-stop {pkg}")
            time.sleep(1)

            # Verify package is installed and get version info
            pkg_info = adb_shell(f"dumpsys package {pkg} | grep versionName")
            if not pkg_info or "versionName" not in pkg_info:
                print(f"  {C.RED}[!] Package {pkg} does not appear to be installed.{C.RST}")
                pause()
                continue
            version = pkg_info.strip().split("=")[-1] if "=" in pkg_info else "unknown"
            print(f"  {C.DIM}Installed version: {version}{C.RST}")

            # Get signing cert fingerprint to confirm it's re-signed
            sig_info = adb_shell(f"dumpsys package {pkg} | grep -A1 'Signing'")
            print(f"  {C.DIM}Signature: {sig_info.strip()[:100] if sig_info else 'N/A'}{C.RST}")

            # Launch the app
            print(f"\n  {C.CYAN}[*] Launching {pkg}...{C.RST}")
            # Try monkey first (most reliable way to launch the default activity)
            launch_out = adb_shell(f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1 2>&1")
            if "No activities found" in (launch_out or ""):
                # Fallback: use am start with launcher intent
                launch_out = adb_shell(
                    f"am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER {pkg}")

            print(f"  {C.DIM}{launch_out[:150] if launch_out else '(launched)'}{C.RST}")
            time.sleep(2)

            # Monitor process survival
            print(f"\n  {C.CYAN}[*] Monitoring process survival...{C.RST}")
            check_interval = 2  # seconds between checks
            total_wait = 30     # total monitoring time
            checks_passed = 0
            process_died = False
            death_time = None
            crash_info = ""

            for elapsed in range(0, total_wait, check_interval):
                time.sleep(check_interval)
                elapsed += check_interval

                # Check if process is running
                ps_out = adb_shell(f"pidof {pkg}")
                pid = ps_out.strip() if not _is_err(ps_out) else ""

                if pid:
                    checks_passed += 1
                    bar_filled = int((elapsed / total_wait) * 20)
                    bar = f"{'█' * bar_filled}{'░' * (20 - bar_filled)}"
                    print(f"\r  {C.GREEN}[ALIVE]{C.RST} {bar} {elapsed}s  PID: {pid}  ", end="", flush=True)
                else:
                    process_died = True
                    death_time = elapsed
                    # Grab crash reason from logcat
                    crash_log = adb_shell(
                        f"logcat -d -t 30 --pid=$(pidof {pkg} 2>/dev/null || echo 0) 2>/dev/null"
                        f" | grep -iE 'kill|exit|fatal|abort|integrity|tamper|signature|died'")
                    if _is_err(crash_log):
                        # Broader search
                        crash_log = adb_shell(
                            f"logcat -d -t 50 | grep -iE '{pkg}.*(kill|exit|fatal|abort|died|crash)'")
                    crash_info = crash_log.strip() if not _is_err(crash_log) else ""
                    print(f"\r  {C.RED}[DEAD]{C.RST}  Process killed after ~{death_time}s" + " " * 20)
                    break

            print()  # newline after progress bar

            # ── Results ──────────────────────────────────────────────────
            print(f"\n  {C.CYAN}{'═'*50}{C.RST}")
            if process_died:
                print(f"  {C.RED}{C.BOLD}RESULT: INTEGRITY CHECK DETECTED{C.RST}")
                print(f"  {C.RED}The app was killed ~{death_time}s after launch.{C.RST}")
                print(f"  {C.DIM}This indicates the app detects repackaging/re-signing{C.RST}")
                print(f"  {C.DIM}and terminates itself (signature verification, integrity check).{C.RST}")

                if crash_info:
                    print(f"\n  {C.YELLOW}Crash/kill indicators from logcat:{C.RST}")
                    for line in crash_info.splitlines()[:10]:
                        print(f"    {C.DIM}{line.strip()[:120]}{C.RST}")

                # Check what kind of integrity mechanism might be in use
                print(f"\n  {C.YELLOW}Possible mechanisms:{C.RST}")
                if death_time <= 5:
                    print(f"  {C.DIM}• Killed within 5s → likely native/JNI signature check in Application.onCreate(){C.RST}")
                    print(f"  {C.DIM}• Could be: VKey VGuard, Promon SHIELD, DexGuard, Play Integrity{C.RST}")
                elif death_time <= 15:
                    print(f"  {C.DIM}• Killed within 15s → likely Java-level signature verification{C.RST}")
                    print(f"  {C.DIM}• Could be: PackageInfo.signatures check, SafetyNet/Play Integrity callback{C.RST}")
                else:
                    print(f"  {C.DIM}• Killed after 15s → likely server-side attestation or delayed check{C.RST}")
                    print(f"  {C.DIM}• Could be: Remote attestation, certificate transparency, server-side sig check{C.RST}")

                print(f"\n  {C.CYAN}Bypass suggestions:{C.RST}")
                print(f"  {C.DIM}• Use Frida to hook PackageInfo.signatures → return original cert{C.RST}")
                print(f"  {C.DIM}• Hook System.exit() and Process.killProcess() to prevent termination{C.RST}")
                print(f"  {C.DIM}• Try the universal bypass script with --no-pause spawn{C.RST}")
            else:
                print(f"  {C.GREEN}{C.BOLD}RESULT: NO INTEGRITY CHECK DETECTED{C.RST}")
                print(f"  {C.GREEN}The app survived {total_wait}s after launch with a patched/re-signed APK.{C.RST}")
                print(f"  {C.DIM}Process checks passed: {checks_passed}/{total_wait // check_interval}{C.RST}")
                print(f"\n  {C.YELLOW}This means:{C.RST}")
                print(f"  {C.DIM}• The app does NOT verify its own signature at runtime{C.RST}")
                print(f"  {C.DIM}• OR the integrity check is deferred (server-side, next API call, etc.){C.RST}")
                print(f"  {C.DIM}• Recommend: also test with the app fully functional (login, API calls){C.RST}")
            pause()

        elif choice == "8":
            # ── ADB Backup Extraction ─────────────────────────────────────
            backup_extraction(pkg)

        else:
            print(f"  {C.RED}Invalid option.{C.RST}")
            time.sleep(0.5)


__all__ = [
    '_find_symlinked_path_component',
    '_filesystem_is_case_sensitive',
    '_unpack_ab',
    'backup_extraction',
    'fun_testcases',
]
