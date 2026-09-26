"""Keyboard, logcat, Frida CodeShare, emulator, and anti-tamper checks.

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

# ─── 6. Keyboard Cache Detection ─────────────────────────────────────────────────

LOKIBOARD_DIR = "/data/media/0/Android/data/com.abifog.lokiboard/files"

def keyboard_cache_check():
    section("KEYBOARD CACHE DETECTION")

    print(f"\n  {C.CYAN}This test checks whether a third-party keyboard (LokiBoard)")
    print(f"  caches user input in plaintext on the device.{C.RST}\n")

    print(f"  {C.YELLOW}{C.BOLD}── Step 1: Type in the app ──{C.RST}")
    print(f"  {C.WHITE}Open the target app and type something using LokiBoard.{C.RST}")
    print(f"  {C.DIM}Make sure LokiBoard is set as the active keyboard.{C.RST}\n")

    try:
        input(f"  {C.GREEN}Press Enter when you have typed something ▸ {C.RST}")
    except (EOFError, KeyboardInterrupt):
        print()
        pause()
        return

    print(f"\n  {C.YELLOW}{C.BOLD}── Step 2: Enter the text you typed ──{C.RST}")
    try:
        search_str = input(f"  {C.GREEN}What did you type? ▸ {C.RST}").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        pause()
        return

    if not search_str:
        print(f"\n  {C.RED}[!] No search string provided.{C.RST}")
        pause()
        return

    print(f"\n  {C.YELLOW}{C.BOLD}── Step 3: Searching keyboard cache ──{C.RST}")
    print(f"  {C.DIM}Scanning: {LOKIBOARD_DIR}/lokiboard_files_*.txt{C.RST}\n")

    # Use adb_su to cat all matching cache files via glob
    content = adb_su(f"cat {LOKIBOARD_DIR}/lokiboard_files_*.txt 2>/dev/null")

    if _is_err(content):
        print(f"  {C.RED}[!] Could not read keyboard cache files.{C.RST}")
        print(f"  {C.DIM}Ensure LokiBoard is installed (com.abifog.lokiboard)")
        print(f"  and the device has root access.{C.RST}")
        pause()
        return

    if not content:
        print(f"  {C.YELLOW}[!] No LokiBoard cache files found or files are empty.{C.RST}")
        pause()
        return

    # Search for user string (case-insensitive)
    all_hits = []
    for i, line in enumerate(content.splitlines(), 1):
        if search_str.lower() in line.lower():
            all_hits.append((i, line.strip()))

    # ── Result ──────────────────────────────────────────────────────────────
    print(f"  {C.CYAN}{'═'*50}{C.RST}")
    if all_hits:
        print(f"  {C.RED}{C.BOLD}RESULT: Keyboard cache LEAKS user input!{C.RST}")
        print(f"  {C.DIM}The string \"{search_str}\" was found in LokiBoard cache.{C.RST}\n")
        for line_no, line_text in all_hits[:10]:
            display = line_text if len(line_text) <= 120 else line_text[:117] + "..."
            print(f"    {C.CYAN}Line {line_no}:{C.RST} {C.DIM}{display}{C.RST}")
        print(f"\n  {C.RED}Sensitive data typed via keyboard is stored in plaintext.{C.RST}")
        print(f"  {C.DIM}Risk: Passwords, PINs, and credentials may be recoverable.{C.RST}")
    else:
        print(f"  {C.GREEN}{C.BOLD}RESULT: String NOT found in keyboard cache{C.RST}")
        print(f"  {C.DIM}\"{search_str}\" was not found in any LokiBoard cache file.{C.RST}")

    pause()

# ─── 7. Logcat Live Monitor ──────────────────────────────────────────────────────

def logcat_monitor(pkg):
    section("LOGCAT LIVE MONITOR")

    print(f"\n  {C.CYAN}This monitors adb logcat in real-time and filters for a search string.")
    print(f"  Target app: {C.BOLD}{pkg}{C.RST}\n")

    print(f"  {C.YELLOW}{C.BOLD}── Enter search string ──{C.RST}")
    print(f"  {C.DIM}Logcat will be filtered for lines containing this text.{C.RST}")
    try:
        search_str = input(f"  {C.GREEN}Search string ▸ {C.RST}").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        pause()
        return

    if not search_str:
        print(f"\n  {C.RED}[!] No search string provided.{C.RST}")
        pause()
        return

    # Clear logcat buffer so we only see new entries
    clear_result = _run_cmd(_adb_base() + ["logcat", "-c"], timeout=5)
    if _command_failed(clear_result):
        print(
            f"\n  {C.RED}[!] Could not clear logcat: "
            f"{_headless_safe_text(clear_result, 300)}{C.RST}"
        )
        pause()
        return

    print(f"\n  {C.GREEN}[+] Streaming logcat{C.RST}")
    print(f"  {C.DIM}Filtering for: \"{search_str}\"{C.RST}")
    print(f"  {C.YELLOW}Press Ctrl+C to stop.{C.RST}\n")
    print(f"  {C.CYAN}{'═'*50}{C.RST}\n")

    search_lower = search_str.lower()
    proc = None
    try:
        proc = subprocess.Popen(
            _adb_base() + ["logcat"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding='utf-8', errors='replace'
        )
        for line in proc.stdout:
            if search_lower in line.lower():
                safe_line = _terminal_safe(line).rstrip()
                highlighted = re.sub(
                    re.escape(search_str),
                    lambda m: f"{C.RED}{C.BOLD}{m.group()}{C.RST}",
                    safe_line,
                    flags=re.IGNORECASE
                )
                print(f"  > {highlighted}")
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"  {C.RED}[!] Logcat failed: {e}{C.RST}")
    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                proc.kill()

    print(f"\n\n  {C.CYAN}{'═'*50}{C.RST}")
    print(f"  {C.DIM}Logcat monitor stopped.{C.RST}")
    pause()

# ─── 8. Frida CodeShare ─────────────────────────────────────────────────────────

SCRIPT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "frida_scripts",
)

def get_local_scripts():
    """Dynamically scan frida_scripts/ directory for .js files."""
    scripts = []
    if not os.path.isdir(SCRIPT_DIR):
        return scripts
    for filename in sorted(os.listdir(SCRIPT_DIR)):
        if filename.endswith(".js"):
            filepath = os.path.join(SCRIPT_DIR, filename)
            # Extract description from first comment block if available
            desc = ""
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read(2000)  # Read first 2KB for header
                    # Look for description in JSDoc or first comment
                    if "* " in content:
                        for line in content.split("\n"):
                            line = line.strip()
                            if line.startswith("* ") and not line.startswith("* @") and not line.startswith("*/"):
                                text = line[2:].strip()
                                if text and not text.startswith("Usage") and len(text) > 10:
                                    desc = text
                                    break
            except Exception:
                pass
            # Generate display name from filename
            name = filename.replace(".js", "").replace("_", " ").replace("-", " ").title()
            scripts.append({
                "name": name,
                "local": filename,
                "desc": desc or f"Local script: {filename}",
            })
    return scripts

# ── CodeShare Scripts (online) ───────────────────────────────────────
CODESHARE_SCRIPTS = [
    # ── SSL Pinning Bypass ──────────────────────────────────────────
    {
        "name": "SSL Bypass — Multi-Unpinning",
        "codeshare": "akabe1/frida-multiple-unpinning",
        "desc": "OkHttp, TrustManager, Flutter, Xamarin, etc.",
        "group": "SSL Pinning Bypass",
    },
    {
        "name": "SSL Bypass — Universal Android",
        "codeshare": "pcipolloni/universal-android-ssl-pinning-bypass-with-frida",
        "desc": "Universal Android SSL unpinning for HTTPS interception",
        "group": "SSL Pinning Bypass",
    },
    {
        "name": "SSL Bypass — Universal v2",
        "codeshare": "sowdust/universal-android-ssl-pinning-bypass-2",
        "desc": "Comprehensive SSL verification bypass for Android",
        "group": "SSL Pinning Bypass",
    },
    {
        "name": "SSL Bypass — Flutter TLS",
        "codeshare": "TheDauntless/disable-flutter-tls-v1",
        "desc": "Disable Flutter TLS verification (DIO SSL Pinning)",
        "group": "SSL Pinning Bypass",
    },
    {
        "name": "SSL Bypass — OkHttp4",
        "codeshare": "kooroshh/ssl-pinning-bypass-okhttp4",
        "desc": "Target OkHttp4 certificate pinning specifically",
        "group": "SSL Pinning Bypass",
    },
    # ── Root Detection Bypass ───────────────────────────────────────
    {
        "name": "Root Bypass — fridantiroot",
        "codeshare": "dzonerzy/fridantiroot",
        "desc": "Bypass common root detection (SafetyNet, RootBeer, etc.)",
        "group": "Root Detection Bypass",
    },
    {
        "name": "Root Bypass — Multi-Library",
        "codeshare": "KishorBal/multiple-root-detection-bypass",
        "desc": "CyberKatze IRoot, Stericson RootShell, JailMonkey, RootBeer",
        "group": "Root Detection Bypass",
    },
    {
        "name": "Root Bypass — RootBeer Specific",
        "codeshare": "ub3rsick/rootbeer-root-detection-bypass",
        "desc": "Targeted bypass for RootBeer library detection",
        "group": "Root Detection Bypass",
    },
    {
        "name": "Root Bypass — Xamarin Apps",
        "codeshare": "Gand3lf/xamarin-antiroot",
        "desc": "Disable root detection in Xamarin-based Android apps",
        "group": "Root Detection Bypass",
    },
    {
        "name": "Root Bypass — freeRASP/Talsec (RN)",
        "codeshare": "sasasec/freerasp-root-detection-bypass",
        "desc": "Bypass freeRASP: root, hooking, developer mode, ADB checks",
        "group": "Root Detection Bypass",
    },
    {
        "name": "Root Bypass — Talsec/RASP (Flutter)",
        "codeshare": "muhammadhikmahhusnuzon/bypass-talsec-rasp-and-root-detection",
        "desc": "Disable Talsec/FreeRASP in Flutter: root, debugger, events",
        "group": "Root Detection Bypass",
    },
    # ── Anti-Debug / Anti-Tamper ────────────────────────────────────
    {
        "name": "Anti-Debug Bypass",
        "codeshare": "aspect-security/anti-debug-bypass",
        "desc": "Bypass anti-debugging checks (ptrace, debugger detection)",
        "group": "Anti-Debug / Anti-Tamper",
    },
    {
        "name": "USB Debug Detection Bypass",
        "codeshare": "meerkati/universal-android-debugging-bypass",
        "desc": "Bypass USB debugging detection (Settings.Secure/Global)",
        "group": "Anti-Debug / Anti-Tamper",
    },
    {
        "name": "Developer Mode Bypass",
        "codeshare": "zionspike/bypass-developermode-check-android",
        "desc": "Run apps despite developer mode being active",
        "group": "Anti-Debug / Anti-Tamper",
    },
    {
        "name": "Anti-Frida Bypass",
        "codeshare": "enovella/anti-frida-bypass",
        "desc": "Libc strstr hook to hide frida/xposed strings",
        "group": "Anti-Debug / Anti-Tamper",
    },
    # ── Multi-Bypass (All-in-One) ───────────────────────────────────
    {
        "name": "Multi-Bypass — SSL + Root + Emulator",
        "codeshare": "fdciabdul/frida-multiple-bypass",
        "desc": "All-in-one: SSL pinning, root detection, emulator bypass",
        "group": "Multi-Bypass (All-in-One)",
    },
    {
        "name": "Multi-Bypass — Root + Emulator + SSL",
        "codeshare": "cubetech126/root-and-emulator-detection-bypass",
        "desc": "Extended fridantiroot + emulator + SSL pinning bypass",
        "group": "Multi-Bypass (All-in-One)",
    },
    {
        "name": "Multi-Bypass — OneRule",
        "codeshare": "h4rithd/onerule-by-h4rithd",
        "desc": "Root, debugger, SSL, network info bypass in one script",
        "group": "Multi-Bypass (All-in-One)",
    },
    # ── Biometric / Auth Bypass ─────────────────────────────────────
    {
        "name": "Biometric Bypass — Universal",
        "codeshare": "ax/universal-android-biometric-bypass",
        "desc": "Universal BiometricPrompt bypass, works on any Android version",
        "group": "Biometric / Auth Bypass",
    },
    {
        "name": "Biometric Bypass — Android 11+",
        "codeshare": "krapgras/android-biometric-bypass-update-android-11",
        "desc": "Biometric authentication bypass updated for Android 11+",
        "group": "Biometric / Auth Bypass",
    },
    # ── Monitoring — Network ────────────────────────────────────────
    {
        "name": "Traffic Interceptor",
        "codeshare": "Linuxinet/frida-traffic-interceptor",
        "desc": "Intercept network traffic, log API calls and WebView URLs",
        "group": "Monitoring — Network",
    },
    {
        "name": "OkHttp3 Interceptor",
        "codeshare": "owen800q/okhttp3-interceptor",
        "desc": "Network interception for OkHttp3 framework",
        "group": "Monitoring — Network",
    },
    {
        "name": "TCP Trace",
        "codeshare": "mame82/android-tcp-trace",
        "desc": "Log Android TCP connections with Java call traces",
        "group": "Monitoring — Network",
    },
    # ── Monitoring — Crypto / KeyStore ──────────────────────────────
    {
        "name": "Crypto Monitor",
        "codeshare": "fadeevab/intercept-android-apk-crypto-operations",
        "desc": "Intercept Java Crypto API calls — reveal keys and plaintext",
        "group": "Monitoring — Crypto",
    },
    {
        "name": "AES Monitor",
        "codeshare": "dzonerzy/aesinfo",
        "desc": "Display AES encryption/decryption activity at runtime",
        "group": "Monitoring — Crypto",
    },
    {
        "name": "KeyStore Extractor",
        "codeshare": "ceres-c/extract-keystore",
        "desc": "Extract KeyStore objects and passwords from Android apps",
        "group": "Monitoring — Crypto",
    },
    # ── Monitoring — Storage ────────────────────────────────────────
    {
        "name": "SharedPrefs Monitor",
        "codeshare": "aspect-security/sharedprefs-monitor",
        "desc": "Hook SharedPreferences read/write operations in real-time",
        "group": "Monitoring — Storage",
    },
    {
        "name": "EncryptedSharedPrefs Inspector",
        "codeshare": "Alkeraithe/encryptedsharedpreferences",
        "desc": "Inspect EncryptedSharedPreferences values before encryption",
        "group": "Monitoring — Storage",
    },
    {
        "name": "SQLite Monitor",
        "codeshare": "nicolo-travi/sqlite-query-monitor",
        "desc": "Monitor all SQLite queries executed by the app",
        "group": "Monitoring — Storage",
    },
    {
        "name": "File System Access Hook",
        "codeshare": "FrenchYeti/android-file-system-access-hook",
        "desc": "Observe file system accesses via java.io.File and libc hooks",
        "group": "Monitoring — Storage",
    },
    {
        "name": "Clipboard Monitor",
        "codeshare": "aspect-security/clipboard-monitor",
        "desc": "Monitor clipboard read/write to detect data leaks",
        "group": "Monitoring — Storage",
    },
    # ── Monitoring — Intents / WebView ──────────────────────────────
    {
        "name": "Intent Intercept",
        "codeshare": "promon-no/intent-intercept",
        "desc": "Intercept and log all intents sent by the application",
        "group": "Monitoring — Intents / WebView",
    },
    {
        "name": "Deep Link Observer",
        "codeshare": "leolashkevych/android-deep-link-observer",
        "desc": "Dump URI data from deep links",
        "group": "Monitoring — Intents / WebView",
    },
    {
        "name": "WebView Debugger",
        "codeshare": "lolicon/debug-webview",
        "desc": "Force setWebContentsDebuggingEnabled(true) on all WebViews",
        "group": "Monitoring — Intents / WebView",
    },
    # ── Tracing / Enumeration ───────────────────────────────────────
    {
        "name": "Android Tracer (raptor)",
        "codeshare": "0xdea/raptor-frida-android-trace",
        "desc": "Full-featured Java and native module tracer",
        "group": "Tracing / Enumeration",
    },
    {
        "name": "JNI Trace",
        "codeshare": "chame1eon/jnitrace",
        "desc": "Trace JNI API calls in Android apps",
        "group": "Tracing / Enumeration",
    },
    {
        "name": "List Loaded Classes",
        "codeshare": "BenGardiner/android-list-loaded-classes",
        "desc": "List all loaded classes in an Android app",
        "group": "Tracing / Enumeration",
    },
    {
        "name": "InMemoryDexClassLoader Dump",
        "codeshare": "cryptax/inmemorydexclassloader-dump",
        "desc": "Dump DEX bytes from InMemoryDexClassLoader (packed apps)",
        "group": "Tracing / Enumeration",
    },
]

def check_frida():
    """Check if frida is installed locally."""
    executable = _safe_native_executable("frida")
    if not executable:
        return False, ""
    try:
        r = _process_run_command_capture(
            [executable, "--version"], timeout=5
        )
        return r.returncode == 0, r.stdout.strip()
    except (subprocess.TimeoutExpired, OSError, ValueError,
            CommandOutputLimitExceeded):
        return False, ""

def check_frida_server():
    """Check if frida-server is running on device."""
    out = adb_su("ps -A 2>/dev/null | grep frida-server")
    if _is_err(out):
        out = adb_su("ps | grep frida-server")
    return bool(out and "frida-server" in out)

FRIDA_SERVER_PATH = "/data/local/tmp/frida-server"

# Global frida connection mode: "-U" (USB default) or "-H ip:port" (custom)
FRIDA_CONN = "-U"


def _frida_connection_args():
    """Return Frida transport args aligned with the selected ADB device."""
    configured = shlex.split(FRIDA_CONN)
    if configured == ["-U"] and ADB_SERIAL:
        return ["-D", ADB_SERIAL]
    return configured


def _valid_host_port(address):
    """Validate a Frida host:port value before using it in a root shell."""
    if not address or address.count(":") < 1:
        return False
    host, port_text = address.rsplit(":", 1)
    if not re.fullmatch(r"[A-Za-z0-9.:[\]_-]+", host):
        return False
    if (not port_text.isascii() or not port_text.isdigit()
            or len(port_text) > 5):
        return False
    return 1 <= int(port_text) <= 65535


def start_frida_server(binary_path, listen_addr=None):
    """Start frida-server on device in background. Returns True if started."""
    if listen_addr and not _valid_host_port(listen_addr):
        return False
    binary_arg = shlex.quote(binary_path)
    # Kill any existing instance first
    adb_su("pkill -f frida-server 2>/dev/null")
    time.sleep(0.5)

    # nohup + redirect so frida-server survives adb shell exit
    # and adb shell returns immediately (no dangling stdout/stderr pipe)
    if listen_addr:
        bg_cmd = f"nohup {binary_arg} -l {shlex.quote(listen_addr)} >/dev/null 2>&1 &"
    else:
        bg_cmd = f"nohup {binary_arg} >/dev/null 2>&1 &"

    # Start in background via su
    adb_su(f"chmod 755 {binary_arg}")
    adb_su(bg_cmd, timeout=10)
    time.sleep(1.5)

    # Verify it started
    return check_frida_server()

def frida_codeshare(pkg):
    section("FRIDA CODESHARE")

    # ── Check local frida ────────────────────────────────────────────────────
    frida_ok, frida_ver = check_frida()

    if frida_ok:
        status_line("Frida (local)", f"v{frida_ver}", C.GREEN)
    else:
        status_line("Frida (local)", "NOT INSTALLED", C.RED)
        print(f"  {C.DIM}  Install: pip install frida-tools{C.RST}")
        print(f"\n  {C.RED}[!] Frida is required. Install with: pip install frida-tools{C.RST}")
        pause()
        return

    # ── Check frida-server on device ─────────────────────────────────────────
    frida_srv = check_frida_server()

    if frida_srv:
        status_line("Frida-server", "Running on device", C.GREEN)
    else:
        status_line("Frida-server", "NOT RUNNING — starting automatically...", C.YELLOW)
        if start_frida_server(FRIDA_SERVER_PATH):
            print(f"  {C.GREEN}[+] Frida-server started{C.RST}")
            frida_srv = True
        else:
            print(f"  {C.RED}[-] Failed to start frida-server{C.RST}")
            print(f"  {C.DIM}  Make sure {FRIDA_SERVER_PATH} exists on the device.{C.RST}")
            print(f"  {C.DIM}  Push it once: adb push frida-server {FRIDA_SERVER_PATH}{C.RST}")

    if not frida_srv:
        warn_line("Frida-server not running — scripts may fail to connect")

    status_line("Frida connect", FRIDA_CONN, C.CYAN)

    # ── Warn on frida client/server version mismatch ─────────────────────────
    if frida_ok and frida_srv:
        srv_ver = adb_su(f"{FRIDA_SERVER_PATH} --version", timeout=10)
        if not _is_err(srv_ver):
            srv_ver = srv_ver.splitlines()[0].strip()
            local_ver = frida_ver.strip()
            if srv_ver and local_ver and srv_ver != local_ver:
                print(f"  {C.YELLOW}[!] Frida version mismatch: client v{local_ver} vs server v{srv_ver}{C.RST}")
                print(f"  {C.DIM}  Connections may fail — use matching frida/frida-server versions.{C.RST}")

    # ── Show script menu ─────────────────────────────────────────────────────
    while True:
        print(f"\n  {C.CYAN}{C.BOLD}── Frida Scripts for: {pkg} ──{C.RST}")

        # Build display list — dynamically scan local scripts + static codeshare
        display_order = []  # list of script dicts in display order
        local_scripts = get_local_scripts()  # Dynamic scan of frida_scripts/
        codeshare_scripts = CODESHARE_SCRIPTS

        idx = 1
        if local_scripts:
            print(f"\n  {C.MAGENTA}{C.BOLD}  Local Scripts (frida_scripts/){C.RST}")
            for script in local_scripts:
                display_order.append(script)
                print(f"  {C.YELLOW}[{idx:2d}]{C.RST} {C.WHITE}{script['name']}{C.RST}")
                print(f"       {C.DIM}{script['desc']}{C.RST}")
                idx += 1
        else:
            print(f"\n  {C.DIM}  No local scripts found in frida_scripts/{C.RST}")

        if codeshare_scripts:
            current_group = None
            for script in codeshare_scripts:
                grp = script.get("group", "Other")
                if grp != current_group:
                    current_group = grp
                    print(f"\n  {C.MAGENTA}{C.BOLD}  {grp}{C.RST}")
                display_order.append(script)
                print(f"  {C.YELLOW}[{idx:2d}]{C.RST} {C.WHITE}{script['name']}{C.RST}")
                print(f"       {C.DIM}{script['desc']}{C.RST}")
                idx += 1

        print(f"\n  {C.YELLOW}[c]{C.RST}  {C.WHITE}Custom codeshare URL{C.RST}")
        print(f"  {C.DIM}[0]  Back{C.RST}")

        choice = input(f"\n  {C.GREEN}Select script ▸ {C.RST}").strip()

        if choice == "0":
            return
        elif choice.lower() == "c":
            cs_path = input(f"  {C.GREEN}Enter codeshare path (author/script) ▸ {C.RST}").strip()
            if not cs_path:
                continue
            selected = {"codeshare": cs_path, "name": cs_path}
        else:
            try:
                sel_idx = int(choice) - 1
                if not (0 <= sel_idx < len(display_order)):
                    print(f"  {C.RED}Invalid selection.{C.RST}")
                    continue
                selected = display_order[sel_idx]
            except ValueError:
                print(f"  {C.RED}Invalid input.{C.RST}")
                continue

        # Spawn or attach
        print(f"\n  {C.CYAN}{C.BOLD}── Launch Mode ──{C.RST}")
        print(f"  {C.YELLOW}[1]{C.RST} Spawn (restart app with Frida)")
        print(f"  {C.YELLOW}[2]{C.RST} Attach (hook into running app)")
        mode = input(f"\n  {C.GREEN}Mode ▸ {C.RST}").strip()
        spawn = mode == "1"

        # Build command depending on local vs codeshare
        frida_conn_args = _frida_connection_args()
        # Build frida command as argument list
        frida_path = _safe_native_executable("frida")
        if not frida_path:
            print(f"  {C.RED}[!] A safe Frida executable was not found.{C.RST}")
            continue
        frida_args = [frida_path]
        if "local" in selected:
            script_path = os.path.join(SCRIPT_DIR, selected["local"])
            if not os.path.exists(script_path):
                print(f"  {C.RED}[!] Script not found: {script_path}{C.RST}")
                continue
            frida_args += frida_conn_args
            if spawn:
                frida_args += ["-f", pkg, "-l", script_path]
            else:
                frida_args += [pkg, "-l", script_path]
        else:
            cs = selected["codeshare"]
            frida_args += ["--codeshare", cs] + frida_conn_args
            if spawn:
                frida_args += ["-f", pkg]
            else:
                frida_args += [pkg]

        print(f"\n  {C.CYAN}Running: {C.BOLD}{' '.join(frida_args)}{C.RST}")
        print(f"  {C.DIM}Press Ctrl+C to stop Frida session{C.RST}\n")

        try:
            completed = subprocess.run(frida_args, check=False)
            if completed.returncode != 0:
                print(
                    f"  {C.YELLOW}[!] Frida exited with status "
                    f"{completed.returncode}.{C.RST}"
                )
        except KeyboardInterrupt:
            print(f"\n  {C.YELLOW}Frida session ended.{C.RST}")
        except OSError as exc:
            print(
                f"\n  {C.RED}[!] Could not start Frida: "
                f"{_headless_diagnostic(exc, 300)}{C.RST}"
            )

        again = input(f"\n  {C.GREEN}Run another script? (y/n) ▸ {C.RST}").strip().lower()
        if again != "y":
            return

# ─── 9. Emulation Detection Check ──────────────────────────────────────────────

EMU_DETECTION_KEYWORDS = [
    ("Emulator String Checks", [
        "google_sdk", "Android SDK built for",
        "Genymotion", "sdk_google", "vbox86p", "vbox86",
        "bluestacks", "Memu", "LDPlayer",
        "sdk_gphone", "NoxPlayer",
        "Droid4X", "iToolAB", "TiantianVM",
    ]),
    ("WSA / Windows Subsystem", [
        "windows_x86_64", "windows_arm64",
        "Windows Subsystem for Android",
        "ro.hardware.windows",
    ]),
    ("AVD / Android Studio", [
        "sdk_gphone64", "sdk_gphone_x86", "sdk_gphone_arm64",
        "emulator64_x86_64", "emulator64_arm64",
        "generic_x86", "generic_x86_64", "generic_arm64",
        "Android Emulator",
    ]),
    ("Telephony Checks", [
        "000000000000000", "15555215554", "15555215556",
    ]),
    ("Emulator Files/Paths", [
        "/dev/socket/qemud", "/dev/qemu_pipe",
        "libc_malloc_debug_qemu", "/sys/qemu_trace",
        "ueventd.android_x86", "/dev/socket/genyd",
    ]),
    ("Goldfish/Ranchu Drivers", [
        "/dev/goldfish_pipe", "init.goldfish", "init.ranchu",
        "fstab.goldfish", "fstab.ranchu",
    ]),
    ("QEMU Detection", [
        "ro.kernel.qemu", "ro.hardware.virtual",
        "init.svc.qemud", "ro.kernel.qemu.gles",
    ]),
    ("Emulator IP Addresses", [
        "10.0.2.15", "10.0.2.2", "10.0.3.2",
        "10.0.3.15",
    ]),
    ("Detection Method Names", [
        "isEmulator", "detectEmulator", "checkEmulator",
        "isRunningOnEmulator", "isVirtualDevice",
    ]),
]

def emulation_detection_check(pkg):
    section("EMULATION DETECTION CHECK")

    print(f"\n  {C.CYAN}Checking emulator detection in: {C.BOLD}{pkg}{C.RST}\n")

    work_dir, decompiled_dir = _pull_and_decompile(pkg)
    if not decompiled_dir:
        pause()
        return

    fw_info = detect_framework(decompiled_dir)
    _print_framework_info(fw_info)

    found_any = False
    found_count = 0
    total_checks = len(EMU_DETECTION_KEYWORDS)

    print(f"\n  {C.YELLOW}{C.BOLD}── Keyword Search ──{C.RST}")

    results, file_count, search_coverage = _search_decompiled(
        decompiled_dir, EMU_DETECTION_KEYWORDS,
        framework=fw_info["framework"], include_coverage=True,
    )
    info_line(
        "Scanned files",
        f"{file_count}/{search_coverage.candidate_files} candidate files",
    )
    if not search_coverage.coverage_complete:
        reason = search_coverage.incomplete_reason()
        report.mark_inconclusive("emulation_keyword_coverage", reason)
        warn_line("Keyword search coverage", f"INCONCLUSIVE — {reason}")
        _print_static_code_coverage(search_coverage)

    for group_name, matches in results.items():
        if matches:
            found_any = True
            found_count += 1
            print(f"\n  {C.GREEN}[FOUND]{C.RST} {C.BOLD}{group_name}{C.RST} — {len(matches)} match(es)")
            seen = set()
            for rel_path, line_no, line_text, keyword in matches:
                key = f"{rel_path}:{line_no}"
                if key not in seen:
                    seen.add(key)
                    print(
                        f"    {C.CYAN}{_safe_evidence_path(rel_path)}:"
                        f"{line_no}{C.RST}"
                    )
                    safe_line = _redact_sensitive_text(line_text).replace(
                        "\n", " "
                    )
                    display = safe_line if len(safe_line) <= 120 else safe_line[:117] + "..."
                    print(f"    {C.DIM}{display}{C.RST}")
                    print(f"    {C.YELLOW}keyword: {keyword}{C.RST}")
        elif search_coverage.coverage_complete:
            print(f"\n  {C.RED}[NOT FOUND]{C.RST} {group_name}")
        else:
            print(
                f"\n  {C.YELLOW}[INCONCLUSIVE]{C.RST} {group_name} "
                "— no match in the inspected subset"
            )

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n  {C.CYAN}{'═'*50}{C.RST}")
    if found_any:
        print(f"  {C.GREEN}{C.BOLD}RESULT: Emulator Detection DETECTED{C.RST}")
        print(f"  {C.DIM}Found {found_count}/{total_checks} indicator categories.{C.RST}")
        if found_count >= 7:
            print(f"  {C.DIM}App has STRONG emulator detection — likely won't run on emulators.{C.RST}")
        elif found_count >= 4:
            print(f"  {C.DIM}App has MODERATE emulator detection — may partially work on emulators.{C.RST}")
        else:
            print(f"  {C.DIM}App has BASIC emulator detection — some emulator checks present.{C.RST}")
        print(f"  {C.DIM}Review file locations above to confirm true/false positives.{C.RST}")
        print(f"  {C.DIM}Bypassing may require Frida, patching, or a physical device.{C.RST}")
    elif search_coverage.coverage_complete:
        print(f"  {C.RED}{C.BOLD}RESULT: Emulator Detection NOT DETECTED{C.RST}")
        print(f"  {C.DIM}This app does not appear to check for emulators.{C.RST}")
    else:
        print(
            f"  {C.YELLOW}{C.BOLD}RESULT: INCONCLUSIVE — emulator "
            f"detection search coverage was incomplete{C.RST}"
        )

    pause()

# ─── 10. Anti-Tamper & Security SDK Detection Check ─────────────────────────────

ANTI_TAMPER_KEYWORDS = [
    ("Anti-Debug Checks", [
        "Debug;->isDebuggerConnected", "TracerPid",
        "/proc/self/status", "ptrace",
        "isDebugInspectorInfoEnabled",
    ]),
    ("Frida Detection", [
        "frida-server", "frida-agent", "LIBFRIDA",
        "frida-gadget", "re.frida.server",
    ]),
    ("VKey VGuard SDK", [
        "com/vkey/android/vtap", "com.vkey.android.vguard",
        "VosWrapper;->", "VosWrapperBase;->",
        "VGuardLifecycleCallback",
    ]),
    ("Zimperium zDefend", [
        "com.zimperium", "zDefend", "ZDefend",
        "z9core", "z9detect", "ZIAMManager",
    ]),
    ("Promon SHIELD", [
        "com.promon.shield", "PromonShield", "ShieldConfig",
        "Lcom/promon/",
    ]),
    ("Guardsquare DexGuard", [
        "DexGuard", "com.guardsquare", "GuardSquare",
        "iXGuard", "ThreatCast",
    ]),
    ("AppSealing", [
        "com.inka.appsealing", "AppSealing", "inkaentworks",
    ]),
    ("Arxan / Digital.ai", [
        "Arxan", "digital.ai", "TransformIT",
        "GuardIT", "EnsureIT",
    ]),
    ("Liapp", [
        "Liapp", "LIAPP", "com.lockincomp", "LockInComp",
    ]),
    ("Talsec freeRASP", [
        "freeRASP", "com.aheaditec.talsec", "ThreatReactor",
    ]),
    ("ByteDance AppShield", [
        "com.bytedance.appshield", "BDShield", "bdshield",
    ]),
    ("LexisNexis ThreatMetrix", [
        "com.lexisnexisrisk.threatmetrix", "TMXProfiling",
        "TMXConfig", "TMXStrongAuth", "TMXStatusResult",
    ]),
    ("BehavioSec SDK", [
        "com.behaviosec", "BehavioSecCollector", "BehavioSecClient",
        "BehavioButtonSDK",
    ]),
    ("VPN Detection", [
        "vpnConnected", "TRANSPORT_VPN",
        "NetworkCapabilities;->hasTransport",
    ]),
    ("Overlay Detection", [
        "canDrawOverlays", "TYPE_APPLICATION_OVERLAY",
    ]),
    ("Sideload Detection", [
        "getInstallerPackageName", "getInstallSourceInfo",
        "com.android.vending",
    ]),
    ("USB Debug Detection", [
        "adb_enabled", "development_settings_enabled",
    ]),
    ("Tamper / Integrity Checks", [
        "PackageInfo;->signatures", "GET_SIGNATURES",
        "checkSignatures", "SigningInfo",
    ]),
    ("Flutter Security Plugins", [
        "freerasp", "flutter_secure_storage",
        "flutter_screenprotector",
    ]),
    ("React Native Security", [
        "react-native-code-push", "CodePush",
        "react-native-integrity",
    ]),
]

def anti_tamper_check(pkg):
    section("ANTI-TAMPER & SDK DETECTION")

    print(f"\n  {C.CYAN}Checking anti-tamper & security SDKs in: {C.BOLD}{pkg}{C.RST}\n")

    work_dir, decompiled_dir = _pull_and_decompile(pkg)
    if not decompiled_dir:
        pause()
        return

    fw_info = detect_framework(decompiled_dir)
    _print_framework_info(fw_info)

    found_any = False
    found_count = 0

    fw = fw_info["framework"]
    skip = set()
    if fw != "Flutter":
        skip |= _FLUTTER_GROUPS
    if fw != "React Native":
        skip |= _RN_GROUPS
    applicable = sum(1 for gn, _ in ANTI_TAMPER_KEYWORDS if gn not in skip)

    print(f"\n  {C.YELLOW}{C.BOLD}── Keyword Search ──{C.RST}")

    results, file_count, search_coverage = _search_decompiled(
        decompiled_dir, ANTI_TAMPER_KEYWORDS,
        framework=fw_info["framework"], include_coverage=True,
    )
    info_line(
        "Scanned files",
        f"{file_count}/{search_coverage.candidate_files} candidate files",
    )
    if not search_coverage.coverage_complete:
        reason = search_coverage.incomplete_reason()
        report.mark_inconclusive("anti_tamper_keyword_coverage", reason)
        warn_line("Keyword search coverage", f"INCONCLUSIVE — {reason}")
        _print_static_code_coverage(search_coverage)

    for group_name, matches in results.items():
        if group_name in skip:
            continue
        if matches:
            found_any = True
            found_count += 1
            print(f"\n  {C.GREEN}[FOUND]{C.RST} {C.BOLD}{group_name}{C.RST} — {len(matches)} match(es)")
            seen = set()
            for rel_path, line_no, line_text, keyword in matches:
                key = f"{rel_path}:{line_no}"
                if key not in seen:
                    seen.add(key)
                    print(
                        f"    {C.CYAN}{_safe_evidence_path(rel_path)}:"
                        f"{line_no}{C.RST}"
                    )
                    safe_line = _redact_sensitive_text(line_text).replace(
                        "\n", " "
                    )
                    display = safe_line if len(safe_line) <= 120 else safe_line[:117] + "..."
                    print(f"    {C.DIM}{display}{C.RST}")
                    print(f"    {C.YELLOW}keyword: {keyword}{C.RST}")
        elif search_coverage.coverage_complete:
            print(f"\n  {C.RED}[NOT FOUND]{C.RST} {group_name}")
        else:
            print(
                f"\n  {C.YELLOW}[INCONCLUSIVE]{C.RST} {group_name} "
                "— no match in the inspected subset"
            )

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n  {C.CYAN}{'═'*50}{C.RST}")
    if found_any:
        print(f"  {C.GREEN}{C.BOLD}RESULT: Anti-Tamper / Security SDKs DETECTED{C.RST}")
        print(f"  {C.DIM}Found {found_count}/{applicable} indicator categories.{C.RST}")
        if found_count >= 7:
            print(f"  {C.DIM}App has HEAVY security SDK integration — multi-layered protection.{C.RST}")
        elif found_count >= 4:
            print(f"  {C.DIM}App has MODERATE security integration — several SDK protections.{C.RST}")
        else:
            print(f"  {C.DIM}App has BASIC security checks — limited SDK protections.{C.RST}")
        print(f"  {C.DIM}Review file locations above to confirm true/false positives.{C.RST}")
        print(f"  {C.DIM}Bypassing may require Frida with the Universal Bypass script.{C.RST}")
    elif search_coverage.coverage_complete:
        print(f"  {C.RED}{C.BOLD}RESULT: Anti-Tamper / Security SDKs NOT DETECTED{C.RST}")
        print(f"  {C.DIM}This app does not appear to use security SDKs or anti-tamper.{C.RST}")
    else:
        print(
            f"  {C.YELLOW}{C.BOLD}RESULT: INCONCLUSIVE — anti-tamper "
            f"search coverage was incomplete{C.RST}"
        )

    pause()


__all__ = [
    'LOKIBOARD_DIR',
    'keyboard_cache_check',
    'logcat_monitor',
    'SCRIPT_DIR',
    'get_local_scripts',
    'CODESHARE_SCRIPTS',
    'check_frida',
    'check_frida_server',
    'FRIDA_SERVER_PATH',
    'FRIDA_CONN',
    '_frida_connection_args',
    '_valid_host_port',
    'start_frida_server',
    'frida_codeshare',
    'EMU_DETECTION_KEYWORDS',
    'emulation_detection_check',
    'ANTI_TAMPER_KEYWORDS',
    'anti_tamper_check',
]
