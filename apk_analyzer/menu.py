"""Interactive menu, report export, and command-line entry.

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

# ─── Main Menu ──────────────────────────────────────────────────────────────────

def main_menu(device_info, has_root, selected_pkg):
    clear()
    banner()

    # Device info bar
    print(f"  {C.GREEN}[✓] Connected{C.RST}: {C.WHITE}{device_info['model']}{C.RST} "
          f"{C.DIM}| Android {device_info['android']} | SDK {device_info['sdk']} | {device_info['serial']}{C.RST}")
    if has_root:
        print(f"  {C.RED}[✓] Root Access{C.RST}: {C.GREEN}Confirmed{C.RST}")
    else:
        print(f"  {C.RED}[✗] Root Access{C.RST}: {C.YELLOW}Not available — some features may fail{C.RST}")

    # Selected app bar
    if selected_pkg:
        print(f"  {C.MAGENTA}[✓] Target App{C.RST}: {C.WHITE}{C.BOLD}{selected_pkg}{C.RST}")
    else:
        print(f"  {C.YELLOW}[!] Target App{C.RST}: {C.DIM}None selected{C.RST}")

    print(f"""
  {C.CYAN}╔══════════════════════════════════════════╗
  ║           {C.BOLD}{C.WHITE}M A I N   M E N U{C.RST}{C.CYAN}               ║
  ╠══════════════════════════════════════════╣
  ║                                          ║
  ║  {C.YELLOW}[1]{C.CYAN} App Analysis                        ║
  ║  {C.YELLOW}[2]{C.CYAN} Storage Audit                       ║
  ║  {C.YELLOW}[3]{C.CYAN} Shell Access                        ║
  ║  {C.YELLOW}[4]{C.CYAN} Screenshot                          ║
  ║  {C.YELLOW}[5]{C.CYAN} Security Scan                       ║
  ║  {C.YELLOW}[6]{C.CYAN} Keyboard Cache Detection            ║
  ║      {C.DIM}Check LokiBoard plaintext cache{C.RST}{C.CYAN}     ║
  ║  {C.YELLOW}[7]{C.CYAN} Logcat Live Monitor                 ║
  ║      {C.DIM}Filter logcat output in real-time{C.RST}{C.CYAN}   ║
  ║  {C.YELLOW}[8]{C.CYAN} Frida CodeShare                     ║
  ║  {C.YELLOW}[9]{C.CYAN} Binary Patcher                      ║
  ║      {C.DIM}Frida Gadget or LSPatch (Xposed){C.RST}{C.CYAN}    ║
  ║  {C.YELLOW}[10]{C.CYAN} Frida Server Config                ║
  ║  {C.YELLOW}[11]{C.CYAN} Testcases for Fun                  ║
  ║      {C.DIM}Exported components, clipboard, URLs{C.RST}{C.CYAN} ║
  ║  {C.YELLOW}[12]{C.CYAN} Runtime Security Check              ║
  ║      {C.DIM}ADB-based dynamic analysis checks{C.RST}{C.CYAN}   ║
  ║                                          ║
  ║  {C.YELLOW}[a]{C.CYAN} Switch App                          ║
  ║  {C.YELLOW}[r]{C.CYAN} Export Report                       ║
  ║      {C.DIM}JSON or HTML report of findings{C.RST}{C.CYAN}     ║
  ║  {C.DIM}[0] Exit{C.CYAN}                                ║
  ║                                          ║
  ╚══════════════════════════════════════════╝{C.RST}
""")

def export_report_menu():
    """Interactive menu to export collected findings as JSON or HTML."""
    section("EXPORT REPORT")
    if not report.has_results:
        print(f"\n  {C.YELLOW}[!] No analysis results collected yet.{C.RST}")
        print(f"  {C.DIM}Run a Security Scan (option 5) first to collect results.{C.RST}")
        pause()
        return

    print(f"\n  {C.CYAN}Collected findings: {C.BOLD}{len(report.findings)}{C.RST}\n")
    print(f"  {C.YELLOW}[1]{C.RST} Export as JSON")
    print(f"  {C.YELLOW}[2]{C.RST} Export as HTML")
    print(f"  {C.DIM}[0] Back{C.RST}")

    try:
        choice = input(f"\n  {C.GREEN}Format ▸ {C.RST}").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return

    if choice == "0":
        return

    if choice == "1":
        fmt = "json"
        default_name = f"apkanalyzer_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    elif choice == "2":
        fmt = "html"
        default_name = f"apkanalyzer_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    else:
        print(f"  {C.RED}Invalid selection.{C.RST}")
        pause()
        return

    try:
        path_input = input(f"  {C.GREEN}Output path [{default_name}] ▸ {C.RST}").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return

    out_path = path_input if path_input else default_name

    try:
        if fmt == "json":
            report.export_json(out_path)
        else:
            report.export_html(out_path)
        abs_path = os.path.abspath(out_path)
        print(f"\n  {C.GREEN}[+] Report exported: {abs_path}{C.RST}")
    except Exception as e:
        print(f"\n  {C.RED}[!] Export failed: {e}{C.RST}")

    pause()


def _build_argument_parser():
    """Build both the legacy interactive and headless command interfaces."""
    parser = argparse.ArgumentParser(
        description="APK Analyzer - Android Security Analysis Tool",
        add_help=True,
    )
    parser.add_argument(
        "--report", choices=["json", "html"],
        help="Export the interactive-session report as JSON or HTML",
    )
    parser.add_argument(
        "--output", dest="legacy_output", default="",
        help="Output path for the interactive-session report",
    )

    subparsers = parser.add_subparsers(dest="command")
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a local APK, APK Set, App Bundle, or split-APK directory",
    )
    scan_parser.add_argument(
        "--apk", required=True,
        help="Path to an .apk, .apks, .aab, or split-APK directory",
    )
    scan_parser.add_argument(
        "--format", choices=["json", "html", "sarif"], default="json",
        help="Report format (default: json)",
    )
    scan_parser.add_argument(
        "--output", default="",
        help="Report output path (default: timestamped file in current directory)",
    )
    scan_parser.add_argument(
        "--fail-on", choices=cli_mod.FAIL_ON_LEVELS, default="high",
        help="Return exit code 1 for findings at or above this severity",
    )
    scan_parser.add_argument(
        "--bundletool", default="",
        help="bundletool executable or JAR path (required for .aab input)",
    )
    return parser


def _headless_safe_text(value, limit=1000):
    """Return bounded, single-line, secret-redacted untrusted text."""
    detail = _terminal_safe(value).replace("\r", " ").replace("\n", " ")
    return _redact_secret_text(detail).strip()[:limit]


def _headless_diagnostic(exc, limit=1000):
    """Sanitize an exception without losing its useful failure category."""
    return (
        _headless_safe_text(str(exc), limit)
        or exc.__class__.__name__[:limit]
    )


def _paths_alias(first, second):
    """Return whether two paths resolve to the same filesystem object/name."""
    first_path = os.path.abspath(os.fspath(first))
    second_path = os.path.abspath(os.fspath(second))
    if os.path.exists(first_path) and os.path.exists(second_path):
        try:
            return os.path.samefile(first_path, second_path)
        except OSError:
            pass
    first_key = os.path.normcase(os.path.realpath(first_path))
    second_key = os.path.normcase(os.path.realpath(second_path))
    return first_key == second_key


def _output_overlaps_input(source, output):
    """Return whether a report could replace an existing selected input."""
    if _paths_alias(source, output):
        return True
    source_path = os.path.abspath(os.fspath(source))
    output_path = os.path.abspath(os.fspath(output))
    if not os.path.isdir(source_path) or not os.path.lexists(output_path):
        return False
    source_key = os.path.normcase(os.path.realpath(source_path))
    output_key = os.path.normcase(os.path.realpath(
        output_path
    ))
    if not archive_mod.filesystem_is_case_sensitive(source_path):
        source_key = source_key.casefold()
        output_key = output_key.casefold()
    try:
        return os.path.commonpath((source_key, output_key)) == source_key
    except ValueError:
        # Paths on different Windows drives cannot overlap.
        return False


def _run_headless_scan(args):
    """Prepare, scan, and always export one local input without using ADB."""
    report.reset()
    report.device_info = {"mode": "local-static-analysis"}
    output_path = (
        os.path.abspath(os.fspath(args.output))
        if args.output else cli_mod.default_report_path(args.format)
    )
    scan_complete = False

    source_path = os.path.abspath(os.fspath(args.apk))
    if _output_overlaps_input(source_path, output_path):
        reason = (
            "report output path aliases or is inside the selected input; "
            "refusing to overwrite it"
        )
        report.mark_inconclusive("report.output", reason)
        print(f"  {C.RED}[!] {reason}{C.RST}")
        return cli_mod.EXIT_INCONCLUSIVE

    try:
        apktool_command = _find_apktool()
        if not apktool_command:
            raise input_mod.InputPreparationError(
                "apktool is required for local static analysis"
            )
        bundletool_command = []
        if (os.path.isfile(source_path)
                and os.path.splitext(source_path)[1].lower() == ".aab"):
            bundletool_command = cli_mod.resolve_bundletool_command(
                args.bundletool
            )
        with tempfile.TemporaryDirectory(prefix="apkanalyzer-local-scan-") as work:
            prepared = input_mod.prepare_local_input(
                args.apk,
                work,
                apktool_command,
                bundletool_command=bundletool_command,
            )
            if any(
                    _paths_alias(apk_path, output_path)
                    for apk_path in prepared.apk_paths):
                reason = (
                    "report output path aliases an APK input; refusing to "
                    "overwrite it"
                )
                report.mark_inconclusive("report.output", reason)
                print(f"  {C.RED}[!] {reason}{C.RST}")
                return cli_mod.EXIT_INCONCLUSIVE
            manifest = _parse_manifest(
                prepared.decompiled_dir,
                expected_split_dirs=prepared.split_decompiled_dirs,
                expected_apk_count=len(prepared.apk_paths),
            )
            source_name = _headless_safe_text(
                os.path.basename(os.path.abspath(os.fspath(args.apk))), 240
            )
            target = manifest.get("package") or source_name or "local-input"
            report.target_app = target
            report.app_info.update({
                "input_kind": prepared.input_kind,
                "apk_count": len(prepared.apk_paths),
                "variant_union": bool(prepared.variant_union),
                # Reporting uses only this already redacted basename when an
                # APK-wide SARIF result has no more precise source location.
                "input_artifact": (
                    source_name if prepared.input_kind != "directory" else ""
                ),
            })
            if prepared.input_kind == "aab":
                report.mark_inconclusive(
                    "input.aab_module_coverage",
                    "bundletool universal output can omit non-fused on-demand "
                    "dynamic-feature modules; their manifests and code were "
                    "not proven covered",
                )
            if prepared.variant_union:
                report.mark_inconclusive(
                    "input.variant_union",
                    "Multiple APK variants/splits were analyzed as a union",
                )
            scan_result = security_scan(
                target, prepared=prepared, interactive=False
            )
            scan_complete = bool(
                isinstance(scan_result, dict)
                and scan_result.get("completed")
            )
    except (input_mod.InputPreparationError, ValueError, OSError) as exc:
        reason = _headless_diagnostic(exc)
        report.mark_inconclusive("scan.setup", reason)
        print(f"  {C.RED}[!] Local scan could not be completed: {reason}{C.RST}")
    except Exception as exc:
        # A scanner crash is an incomplete result, never a clean CI pass.  Keep
        # the diagnostic bounded/sanitized and still emit the requested report.
        reason = _headless_diagnostic(exc)
        report.mark_inconclusive("scan.runtime", reason)
        print(f"  {C.RED}[!] Local scan failed: {reason}{C.RST}")

    try:
        exported = cli_mod.export_report(report, args.format, output_path)
        print(
            f"\n  {C.GREEN}[+] Report exported: "
            f"{_headless_safe_text(exported)}{C.RST}"
        )
    except Exception as exc:
        reason = _headless_diagnostic(exc)
        print(f"\n  {C.RED}[!] Report export failed: {reason}{C.RST}")
        return cli_mod.EXIT_INCONCLUSIVE

    return cli_mod.scan_exit_code(
        report, args.fail_on, scan_complete=scan_complete
    )


def _run_interactive(args):
    """Run the legacy device UI and optional post-session report export."""
    main()
    if args.report and report.has_results:
        out_path = args.legacy_output
        if not out_path:
            out_path = (
                "apkanalyzer_report_"
                f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.{args.report}"
            )
        try:
            if args.report == "json":
                report.export_json(out_path)
            else:
                report.export_html(out_path)
            print(
                f"\n  {C.GREEN}[+] Report exported: "
                f"{os.path.abspath(out_path)}{C.RST}"
            )
        except Exception as exc:
            print(f"\n  {C.RED}[!] Report export failed: {exc}{C.RST}")
    return 0


def _entrypoint(argv=None):
    """Dispatch a headless subcommand before any interactive device checks."""
    args = _build_argument_parser().parse_args(argv)
    if args.command == "scan":
        return _run_headless_scan(args)
    return _run_interactive(args)


def main():
    clear()
    banner()
    print(f"  {C.CYAN}Connecting to device...{C.RST}\n")

    if process_mod.safe_which("adb", which=shutil.which) is None:
        print(f"  {C.RED}[✗] adb not found on PATH.{C.RST}")
        print(f"  {C.DIM}Install Android SDK platform-tools and make sure adb is on your PATH.{C.RST}")
        print(f"  {C.DIM}Download: https://developer.android.com/tools/releases/platform-tools{C.RST}")
        sys.exit(1)

    device = check_device()
    if not device:
        print(f"  {C.RED}[✗] No device connected.{C.RST}")
        print(f"  {C.DIM}Make sure USB debugging is enabled and the device is connected.{C.RST}")
        print(f"  {C.DIM}Run 'adb devices' to verify.{C.RST}")
        sys.exit(1)

    has_root = check_root()

    # Populate report with device info
    report.device_info = device

    # ── Frida-server handling ────────────────────────────────────────────
    if has_root:
        if check_frida_server():
            print(f"  {C.GREEN}[+] Frida-server already running{C.RST}")
            try:
                choice = input(f"  {C.YELLOW}Keep running or restart? [K/r] ▸ {C.RST}").strip().lower()
            except (EOFError, KeyboardInterrupt):
                choice = ""
            if choice == "r":
                print(f"  {C.DIM}Restarting frida-server...{C.RST}")
                if start_frida_server(FRIDA_SERVER_PATH):
                    print(f"  {C.GREEN}[+] Frida-server restarted (USB default){C.RST}")
                else:
                    print(f"  {C.YELLOW}[!] Frida-server failed to restart{C.RST}")
        else:
            print(f"  {C.DIM}Starting frida-server...{C.RST}")
            if start_frida_server(FRIDA_SERVER_PATH):
                print(f"  {C.GREEN}[+] Frida-server running (USB default){C.RST}")
            else:
                print(f"  {C.YELLOW}[!] Frida-server failed to start{C.RST}")
                print(f"  {C.DIM}  Push it once: adb push frida-server {FRIDA_SERVER_PATH}{C.RST}")
    print()

    # ── Select target app up front ──────────────────────────────────────
    print(f"  {C.CYAN}Loading installed apps...{C.RST}\n")
    apps = list_third_party_apps()
    selected_pkg = pick_app(apps)
    if not selected_pkg:
        print(f"\n  {C.CYAN}Goodbye.{C.RST}")
        print(f"  {C.DIM}Like this tool? Star it: {C.WHITE}https://github.com/worldtreeboy/apkAnalyzer{C.RST}\n")
        return

    report.reset_app(selected_pkg)

    # Options that require a selected app
    APP_REQUIRED = {"1", "2", "5", "7", "8", "9", "11", "12"}

    while True:
        main_menu(device, has_root, selected_pkg)
        try:
            choice = input(f"  {C.GREEN}Select option ▸ {C.RST}").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {C.CYAN}Goodbye.{C.RST}")
            print(f"  {C.DIM}Like this tool? Star it: {C.WHITE}https://github.com/worldtreeboy/apkAnalyzer{C.RST}\n")
            break

        if choice.lower() == "a":
            apps = list_third_party_apps()
            new_pkg = pick_app(apps)
            if new_pkg:
                selected_pkg = new_pkg
                report.reset_app(new_pkg)
            continue

        if choice.lower() == "r":
            export_report_menu()
            continue

        if choice in APP_REQUIRED and not selected_pkg:
            print(f"  {C.RED}[!] No app selected. Press [a] to pick an app first.{C.RST}")
            time.sleep(1)
            continue

        if choice == "1":
            app_analysis(selected_pkg)
        elif choice == "2":
            storage_audit(selected_pkg)
        elif choice == "3":
            shell_access(selected_pkg)
        elif choice == "4":
            screenshot()
        elif choice == "5":
            security_scan(selected_pkg)
        elif choice == "6":
            keyboard_cache_check()
        elif choice == "7":
            logcat_monitor(selected_pkg)
        elif choice == "8":
            frida_codeshare(selected_pkg)
        elif choice == "9":
            binary_patcher(selected_pkg)
        elif choice == "10":
            frida_server_config()
        elif choice == "11":
            fun_testcases(selected_pkg)
        elif choice == "12":
            runtime_security_check(selected_pkg)
        elif choice == "0":
            print(f"\n  {C.CYAN}Goodbye.{C.RST}")
            print(f"  {C.DIM}Like this tool? Star it: {C.WHITE}https://github.com/worldtreeboy/apkAnalyzer{C.RST}\n")
            break
        else:
            print(f"  {C.RED}Invalid option.{C.RST}")
            time.sleep(0.5)

__all__ = [
    'main_menu',
    'export_report_menu',
    '_build_argument_parser',
    '_headless_safe_text',
    '_headless_diagnostic',
    '_paths_alias',
    '_output_overlaps_input',
    '_run_headless_scan',
    '_run_interactive',
    '_entrypoint',
    'main',
]
