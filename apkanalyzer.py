#!/usr/bin/env python3
"""
APK Analyzer - Android Security Analysis Tool
Root-based ADB tool for app analysis, storage auditing,
shell access, screenshots, and security scanning.
"""

import subprocess
import sys
import os
import re
import time
import shutil
import lzma
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime

# ─── ANSI Colors ────────────────────────────────────────────────────────────────

class C:
    RST   = "\033[0m"
    BOLD  = "\033[1m"
    DIM   = "\033[2m"
    RED   = "\033[91m"
    GREEN = "\033[92m"
    YELLOW= "\033[93m"
    BLUE  = "\033[94m"
    MAGENTA="\033[95m"
    CYAN  = "\033[96m"
    WHITE = "\033[97m"
    BG_RED   = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_BLUE  = "\033[44m"
    BG_MAG   = "\033[45m"
    BG_CYAN  = "\033[46m"

# ─── ADB Helpers ────────────────────────────────────────────────────────────────

def adb(cmd, timeout=30):
    """Run an adb command and return stdout."""
    try:
        r = subprocess.run(
            f"adb {cmd}", shell=True, capture_output=True,
            text=True, timeout=timeout, encoding='utf-8', errors='replace'
        )
        return r.stdout.strip()
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR] {e}"

def adb_shell(cmd, timeout=30):
    """Run adb shell command (non-root)."""
    return adb(f'shell "{cmd}"', timeout=timeout)

# Root mode: "su" = use su -c, "adbd" = adb shell already root, None = unknown
_root_mode = None

def adb_su(cmd, timeout=30):
    """Run command as root, auto-detecting whether su or adbd-root is available."""
    global _root_mode
    if _root_mode == "adbd":
        return adb_shell(cmd, timeout=timeout)
    # Default: try su -c
    escaped = cmd.replace('"', '\\"')
    return adb(f'shell su -c "{escaped}"', timeout=timeout)


def _shell_su(cmd, timeout=30):
    """Run a compound command as root (handles &&, |, etc.)."""
    global _root_mode
    if _root_mode == "adbd":
        try:
            r = subprocess.run(
                ["adb", "shell", cmd],
                stdin=subprocess.DEVNULL,
                capture_output=True, text=True, timeout=timeout,
                encoding='utf-8', errors='replace'
            )
            return r.stdout.strip()
        except subprocess.TimeoutExpired:
            return "[TIMEOUT]"
        except Exception as e:
            return f"[ERROR] {e}"
    escaped = cmd.replace("'", "'\\''")
    try:
        r = subprocess.run(
            ["adb", "shell", f"su -c '{escaped}'"],
            stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=timeout,
            encoding='utf-8', errors='replace'
        )
        return r.stdout.strip()
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR] {e}"

def adb_pull(remote, local):
    """Pull a file from device."""
    return adb(f'pull "{remote}" "{local}"', timeout=120)

def get_apk_path(pkg):
    """Get APK path for a package, trying root then non-root."""
    for fn in (adb_su, adb_shell):
        out = fn(f"pm path {pkg}")
        if out and "package:" in out:
            # Handle split APKs — take the base.apk or first entry
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("package:"):
                    path = line.replace("package:", "").strip()
                    if "base.apk" in path or path.endswith(".apk"):
                        return path
    return ""

def check_device():
    """Check if a device is connected and return device info."""
    out = adb("devices")
    lines = [l for l in out.splitlines() if "\tdevice" in l]
    if not lines:
        return None
    serial = lines[0].split("\t")[0]
    model = adb_shell("getprop ro.product.model")
    android_ver = adb_shell("getprop ro.build.version.release")
    sdk = adb_shell("getprop ro.build.version.sdk")
    return {"serial": serial, "model": model, "android": android_ver, "sdk": sdk}

def check_root():
    """Check if device has root access (su, adbd-root, or adb root restart)."""
    global _root_mode
    # 1) Try su -c (Magisk / SuperSU / rooted ROMs)
    out = adb('shell su -c "id"', timeout=10)
    if "uid=0" in out:
        _root_mode = "su"
        return True
    # 2) Check if adb shell already runs as root
    out = adb_shell("id", timeout=10)
    if "uid=0" in out:
        _root_mode = "adbd"
        return True
    # 3) Try "adb root" to restart adbd as root (emulators / userdebug builds)
    root_out = adb("root", timeout=15)
    if root_out and "cannot" not in root_out.lower() and "unable" not in root_out.lower():
        time.sleep(2)  # wait for adbd to restart
        # Re-check connection after adbd restart
        out = adb_shell("id", timeout=10)
        if "uid=0" in out:
            _root_mode = "adbd"
            return True
    _root_mode = None
    return False

def list_third_party_apps():
    """List all third-party (user-installed) apps."""
    out = adb_su("pm list packages -3")
    if not out or "error" in out.lower():
        out = adb_shell("pm list packages -3")
    pkgs = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            pkgs.append(line.replace("package:", ""))
    pkgs.sort()
    return pkgs

def pick_app(apps):
    """Display numbered app list and let user pick one."""
    if not apps:
        print(f"\n  {C.RED}[!] No third-party apps found.{C.RST}")
        return None
    print(f"\n  {C.CYAN}{C.BOLD}── Third-Party Apps ({len(apps)}) ──{C.RST}\n")
    for i, pkg in enumerate(apps, 1):
        print(f"  {C.YELLOW}[{i:3d}]{C.RST} {pkg}")
    print(f"\n  {C.DIM}[0] Back{C.RST}")
    while True:
        try:
            choice = input(f"\n  {C.GREEN}Select app ▸ {C.RST}").strip()
            if choice == "0" or choice.lower() == "b":
                return None
            idx = int(choice) - 1
            if 0 <= idx < len(apps):
                return apps[idx]
            print(f"  {C.RED}Invalid selection.{C.RST}")
        except (ValueError, EOFError):
            print(f"  {C.RED}Enter a number.{C.RST}")

# ─── UI Helpers ─────────────────────────────────────────────────────────────────

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def banner():
    b = f"""
  {C.CYAN}{C.BOLD}
   ╔══════════════════════════════════════════════════════════╗
   ║   █████╗ ██████╗ ██████╗                                ║
   ║  ██╔══██╗██╔══██╗██╔══██╗                               ║
   ║  ███████║██║  ██║██████╔╝                               ║
   ║  ██╔══██║██║  ██║██╔══██╗                               ║
   ║  ██║  ██║██████╔╝██████╔╝                               ║
   ║  ╚═╝  ╚═╝╚═════╝ ╚═════╝                               ║
   ║        {C.MAGENTA}A N A L Y Z E R{C.CYAN}                               ║
   ║  {C.DIM}{C.WHITE}Android Security Analysis Tool{C.RST}{C.CYAN}{C.BOLD}                       ║
   ╚══════════════════════════════════════════════════════════╝{C.RST}
"""
    print(b)

def section(title):
    w = 56
    pad = w - len(title) - 4
    print(f"\n  {C.CYAN}╔{'═'*w}╗{C.RST}")
    print(f"  {C.CYAN}║  {C.BOLD}{C.WHITE}{title}{C.RST}{C.CYAN}{' '*pad}║{C.RST}")
    print(f"  {C.CYAN}╚{'═'*w}╝{C.RST}")

def status_line(label, value, color=None):
    color = color or C.WHITE
    print(f"  {C.DIM}│{C.RST} {C.YELLOW}{label:<20}{C.RST} {color}{value}{C.RST}")

def pass_fail(label, passed, detail=""):
    if passed:
        tag = f"{C.GREEN}[PASS]{C.RST}"
    else:
        tag = f"{C.RED}[FAIL]{C.RST}"
    extra = f" {C.DIM}— {detail}{C.RST}" if detail else ""
    print(f"  {tag} {label}{extra}")

def warn_line(label, detail=""):
    extra = f" {C.DIM}— {detail}{C.RST}" if detail else ""
    print(f"  {C.YELLOW}[WARN]{C.RST} {label}{extra}")

def info_line(label, detail=""):
    extra = f" {C.DIM}— {detail}{C.RST}" if detail else ""
    print(f"  {C.BLUE}[INFO]{C.RST} {label}{extra}")

def pause():
    input(f"\n  {C.DIM}Press Enter to continue...{C.RST}")

# ─── Decompile Helpers ──────────────────────────────────────────────────────────

def _pull_and_decompile(pkg):
    """Pull APK from device and decompile with apktool. Returns (work_dir, decompiled_dir) or (None, None).
    Caches the decompiled output — reuses it if the folder already exists."""
    work_dir = os.path.join(os.getcwd(), ".apkanalyzer_tmp")
    decompiled_dir = os.path.join(work_dir, f"{pkg}_decompiled")

    # ── Cache hit — already decompiled ──────────────────────────────────
    if os.path.isdir(decompiled_dir):
        print(f"  {C.GREEN}[+] Using cached decompile: {decompiled_dir}{C.RST}")
        return work_dir, decompiled_dir

    # ── Need to decompile ───────────────────────────────────────────────
    if not shutil.which("apktool"):
        print(f"  {C.RED}[!] apktool is required for this feature.{C.RST}")
        print(f"  {C.DIM}  Install: https://ibotpeaches.github.io/Apktool/{C.RST}")
        return None, None

    os.makedirs(work_dir, exist_ok=True)

    # Check for local APK first
    local_apk = None
    for search_dir in [os.path.join(os.getcwd(), "extracted_apks"),
                       os.path.join(os.getcwd(), "patched_apks"),
                       os.getcwd()]:
        if not os.path.isdir(search_dir):
            continue
        for root, dirs, files in os.walk(search_dir):
            if ".apkanalyzer_tmp" in root or ".apkpatcher_work" in root:
                continue
            for fname in files:
                if fname.endswith(".apk") and pkg in fname:
                    candidate = os.path.join(root, fname)
                    if os.path.getsize(candidate) > 0:
                        local_apk = candidate
                        break
            if local_apk:
                break
        if local_apk:
            break

    if local_apk:
        print(f"  {C.GREEN}[+] Found local APK: {local_apk}{C.RST}")
    else:
        apk_path = get_apk_path(pkg)
        if not apk_path:
            print(f"  {C.RED}[!] Could not locate APK on device or locally.{C.RST}")
            return None, None
        local_apk = os.path.join(work_dir, f"{pkg}.apk")
        print(f"  {C.DIM}Pulling APK from device...{C.RST}")
        adb_pull(apk_path, local_apk)
        if not os.path.exists(local_apk):
            print(f"  {C.RED}[!] Failed to pull APK.{C.RST}")
            return None, None

    print(f"  {C.DIM}Decompiling with apktool...{C.RST}")
    try:
        r = subprocess.run(
            f'apktool d -f -o "{decompiled_dir}" "{local_apk}"',
            shell=True, capture_output=True, text=True, timeout=300,
            encoding='utf-8', errors='replace'
        )
        if r.returncode != 0 or not os.path.exists(decompiled_dir):
            print(f"  {C.RED}[!] apktool failed: {r.stderr[:200] if r.stderr else 'unknown error'}{C.RST}")
            return None, None
    except subprocess.TimeoutExpired:
        print(f"  {C.RED}[!] apktool timed out.{C.RST}")
        return None, None

    print(f"  {C.GREEN}[+] Decompiled successfully (cached for next check){C.RST}")
    return work_dir, decompiled_dir

def _cleanup_work_dir(work_dir):
    """Remove temporary work directory."""
    if work_dir:
        try:
            shutil.rmtree(work_dir, ignore_errors=True)
        except Exception:
            pass

def _scan_native_libs(decompiled_dir):
    """Walk lib/ directory and collect all .so filenames. Returns list of (filename, rel_path)."""
    lib_dir = os.path.join(decompiled_dir, "lib")
    so_files = []
    if os.path.isdir(lib_dir):
        for root, dirs, files in os.walk(lib_dir):
            for f in files:
                if f.endswith(".so"):
                    rel = os.path.relpath(os.path.join(root, f), decompiled_dir)
                    so_files.append((f, rel))
    return so_files

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

    smali_dirs = [d for d in os.listdir(decompiled_dir)
                  if d.startswith("smali") and os.path.isdir(os.path.join(decompiled_dir, d))]

    framework = None
    details = []

    # ── Flutter ──────────────────────────────────────────────────────────
    fl = []
    if "libflutter.so" in so_map:
        fl.append(so_map["libflutter.so"][0])
    if "libapp.so" in so_map:
        fl.append(so_map["libapp.so"][0])
    if os.path.isdir(os.path.join(decompiled_dir, "assets", "flutter_assets")):
        fl.append("assets/flutter_assets/")
    for d in smali_dirs:
        if os.path.isdir(os.path.join(decompiled_dir, d, "io", "flutter")):
            fl.append(f"{d}/io/flutter/")
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
        if os.path.isfile(os.path.join(decompiled_dir, "assets", "index.android.bundle")):
            rn.append("assets/index.android.bundle")
        for d in smali_dirs:
            if os.path.isdir(os.path.join(decompiled_dir, d, "com", "facebook", "react")):
                rn.append(f"{d}/com/facebook/react/")
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
        if os.path.isdir(os.path.join(decompiled_dir, "assemblies")):
            xm.append("assemblies/")
        if os.path.isdir(os.path.join(decompiled_dir, "unknown", "assemblies")):
            xm.append("unknown/assemblies/")
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
        if os.path.isdir(os.path.join(decompiled_dir, "assets", "bin", "Data")):
            un.append("assets/bin/Data/")
        # Need a definitive lib OR 2+ supporting indicators
        if unity_definitive & so_names or len(un) >= 2:
            framework = "Unity"
            details = un

    # ── Cordova / Ionic ──────────────────────────────────────────────────
    if not framework:
        cd = []
        www_dir = os.path.join(decompiled_dir, "assets", "www")
        if os.path.isdir(www_dir):
            cd.append("assets/www/")
            if os.path.isfile(os.path.join(www_dir, "cordova.js")):
                cd.append("assets/www/cordova.js")
        for d in smali_dirs:
            if os.path.isdir(os.path.join(decompiled_dir, d, "org", "apache", "cordova")):
                cd.append(f"{d}/org/apache/cordova/")
                break
        if cd:
            framework = "Cordova"
            details = cd

    # ── Kotlin ───────────────────────────────────────────────────────────
    if not framework:
        for d in smali_dirs:
            if os.path.isdir(os.path.join(decompiled_dir, d, "kotlin")):
                framework = "Kotlin"
                details = [f"{d}/kotlin/"]
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
        print(f"  {C.DIM}Indicators: {', '.join(details)}{C.RST}")
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

def _search_decompiled(decompiled_dir, keyword_groups, framework=None):
    """Search decompiled directory for keyword groups (case-insensitive).
    Single-pass: reads each file once, checks all keywords per line.

    keyword_groups: list of (group_name, [keywords])
    framework: optional detected framework name — used to skip irrelevant
               framework-specific groups and to extend file extensions.
    Returns: (dict of {group_name: [(rel_path, line_no, line_text, keyword)]}, file_count)
    """
    EXTS = {'.smali', '.xml', '.json', '.properties', '.txt', '.cfg', '.conf', '.yml', '.yaml', '.js'}
    if framework == "React Native":
        EXTS.add('.bundle')

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

    # Collect target files
    all_files = []
    for root, dirs, files in os.walk(decompiled_dir):
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in EXTS:
                all_files.append(os.path.join(root, f))

    # Single pass — one read per file, all keywords checked per line
    for fpath in all_files:
        rel = os.path.relpath(fpath, decompiled_dir)
        try:
            with open(fpath, 'r', errors='ignore') as fh:
                for line_no, line in enumerate(fh, 1):
                    line_low = line.lower()
                    for kl, kw_orig, gn in all_keywords:
                        if kl in line_low:
                            results[gn].append((rel, line_no, line.strip(), kw_orig))
        except Exception:
            continue

    return results, len(all_files)

# ─── Manifest Analysis ────────────────────────────────────────────────────────────

_ANDROID_NS = "http://schemas.android.com/apk/res/android"

_DANGEROUS_PERMS = {
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_PHONE_STATE", "android.permission.CAMERA",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS", "android.permission.RECORD_AUDIO",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO",
    "android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.READ_CALL_LOG", "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
}

def _analyze_manifest(decompiled_dir):
    """Parse AndroidManifest.xml for security-relevant attributes."""
    manifest_path = os.path.join(decompiled_dir, "AndroidManifest.xml")
    info = {
        "debuggable": False, "allow_backup": True, "has_nsc": False,
        "cleartext_traffic": None, "exported": [], "dangerous_perms": [],
        "min_sdk": None, "target_sdk": None, "parsed": False,
    }
    if not os.path.isfile(manifest_path):
        return info
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        info["parsed"] = True

        # SDK versions
        uses_sdk = root.find("uses-sdk")
        if uses_sdk is not None:
            info["min_sdk"] = uses_sdk.get(f"{{{_ANDROID_NS}}}minSdkVersion")
            info["target_sdk"] = uses_sdk.get(f"{{{_ANDROID_NS}}}targetSdkVersion")

        # Application attributes
        app = root.find("application")
        if app is not None:
            info["debuggable"] = app.get(f"{{{_ANDROID_NS}}}debuggable") == "true"
            backup = app.get(f"{{{_ANDROID_NS}}}allowBackup")
            info["allow_backup"] = backup != "false"
            info["has_nsc"] = app.get(f"{{{_ANDROID_NS}}}networkSecurityConfig") is not None
            ct = app.get(f"{{{_ANDROID_NS}}}usesCleartextTraffic")
            info["cleartext_traffic"] = ct == "true" if ct else None

            # Exported components
            for tag in ("activity", "service", "receiver", "provider"):
                for comp in app.findall(tag):
                    exported = comp.get(f"{{{_ANDROID_NS}}}exported")
                    name = comp.get(f"{{{_ANDROID_NS}}}name", "?")
                    has_intent_filter = comp.find("intent-filter") is not None
                    if exported == "true" or (exported is None and has_intent_filter):
                        short = name.rsplit(".", 1)[-1] if "." in name else name
                        info["exported"].append((tag, short))

        # Permissions
        for perm in root.findall("uses-permission"):
            name = perm.get(f"{{{_ANDROID_NS}}}name", "")
            if name in _DANGEROUS_PERMS:
                info["dangerous_perms"].append(name.replace("android.permission.", ""))

    except ET.ParseError:
        pass
    return info


def _print_manifest_analysis(info):
    """Display manifest analysis results."""
    if not info["parsed"]:
        print(f"  {C.RED}[!] Could not parse AndroidManifest.xml{C.RST}")
        return

    print(f"\n  {C.CYAN}{C.BOLD}── MANIFEST ANALYSIS ──{C.RST}")

    if info["min_sdk"]:
        print(f"    {C.DIM}Min SDK: {info['min_sdk']}  Target SDK: {info['target_sdk'] or 'N/A'}{C.RST}")

    # Debuggable
    if info["debuggable"]:
        print(f"    {C.RED}[FAIL]{C.RST} android:debuggable = true")
    else:
        print(f"    {C.GREEN}[PASS]{C.RST} android:debuggable = false")

    # Backup
    if info["allow_backup"]:
        print(f"    {C.YELLOW}[WARN]{C.RST} android:allowBackup = true (data extractable via adb backup)")
    else:
        print(f"    {C.GREEN}[PASS]{C.RST} android:allowBackup = false")

    # Network security config
    if info["has_nsc"]:
        print(f"    {C.GREEN}[PASS]{C.RST} networkSecurityConfig declared")
    else:
        print(f"    {C.YELLOW}[WARN]{C.RST} No networkSecurityConfig (relies on platform defaults)")

    # Cleartext
    if info["cleartext_traffic"] is True:
        print(f"    {C.RED}[FAIL]{C.RST} usesCleartextTraffic = true (HTTP allowed)")
    elif info["cleartext_traffic"] is False:
        print(f"    {C.GREEN}[PASS]{C.RST} usesCleartextTraffic = false")

    # Exported components
    exported = info["exported"]
    if exported:
        print(f"    {C.YELLOW}[INFO]{C.RST} {len(exported)} exported component(s)")
        for tag, name in exported[:8]:
            print(f"           {C.DIM}{tag}: {name}{C.RST}")
        if len(exported) > 8:
            print(f"           {C.DIM}... and {len(exported) - 8} more{C.RST}")

    # Dangerous permissions
    perms = info["dangerous_perms"]
    if perms:
        print(f"    {C.YELLOW}[INFO]{C.RST} {len(perms)} dangerous permission(s): {C.DIM}{', '.join(perms[:6])}{C.RST}")
        if len(perms) > 6:
            print(f"           {C.DIM}... and {len(perms) - 6} more{C.RST}")


# ─── Network Security Config ─────────────────────────────────────────────────────

def _analyze_nsc(decompiled_dir):
    """Parse network_security_config.xml for pinning and cleartext policy."""
    info = {"parsed": False, "pins": [], "cleartext_allowed": False,
            "trusts_user_certs": False, "trust_anchors": []}

    # Try common locations
    for rel in ("res/xml/network_security_config.xml",
                "res/xml/network_security_config_debug.xml"):
        nsc_path = os.path.join(decompiled_dir, rel)
        if os.path.isfile(nsc_path):
            break
    else:
        return info

    try:
        tree = ET.parse(nsc_path)
        root = tree.getroot()
        info["parsed"] = True

        # Check base-config cleartext
        for base in root.findall(".//base-config"):
            if base.get("cleartextTrafficPermitted") == "true":
                info["cleartext_allowed"] = True

        # Check domain-config cleartext
        for dc in root.findall(".//domain-config"):
            if dc.get("cleartextTrafficPermitted") == "true":
                domains = [d.text for d in dc.findall("domain") if d.text]
                info["cleartext_allowed"] = True

        # Pin-set entries
        for ps in root.findall(".//pin-set"):
            expiry = ps.get("expiration", "")
            for pin in ps.findall("pin"):
                digest = pin.get("digest", "")
                val = pin.text or ""
                parent_dc = ps.find("..")
                # Get associated domains
                domains = []
                for dc in root.findall(".//domain-config"):
                    if dc.find("pin-set") is ps or any(p.text == val for p in dc.findall(".//pin")):
                        domains = [d.text for d in dc.findall("domain") if d.text]
                info["pins"].append({
                    "digest": digest, "value": val[:20] + "..." if len(val) > 20 else val,
                    "expiry": expiry, "domains": domains,
                })

        # Trust anchors
        for ta in root.findall(".//trust-anchors"):
            for cert in ta.findall("certificates"):
                src = cert.get("src", "")
                info["trust_anchors"].append(src)
                if src == "user":
                    info["trusts_user_certs"] = True

    except ET.ParseError:
        pass
    return info


def _print_nsc_analysis(info):
    """Display network security config analysis."""
    if not info["parsed"]:
        return

    print(f"\n  {C.CYAN}{C.BOLD}── NETWORK SECURITY CONFIG ──{C.RST}")

    if info["pins"]:
        print(f"    {C.GREEN}[FOUND]{C.RST} {len(info['pins'])} certificate pin(s)")
        for p in info["pins"][:4]:
            domain_str = ", ".join(p["domains"][:2]) if p["domains"] else "N/A"
            print(f"           {C.DIM}{p['digest']}:{p['value']} → {domain_str}{C.RST}")
    else:
        print(f"    {C.YELLOW}[WARN]{C.RST} No certificate pins defined in NSC")

    if info["cleartext_allowed"]:
        print(f"    {C.RED}[FAIL]{C.RST} Cleartext (HTTP) traffic allowed")
    else:
        print(f"    {C.GREEN}[PASS]{C.RST} Cleartext traffic not explicitly allowed")

    if info["trusts_user_certs"]:
        print(f"    {C.YELLOW}[WARN]{C.RST} Trusts user-installed certificates")


# ─── Security Class Detection (smali package tree) ───────────────────────────────

SECURITY_PACKAGES = {
    "com/scottyab/rootbeer": "RootBeer",
    "com/vkey/android": "VKey VGuard",
    "com/zimperium": "Zimperium zDefend",
    "com/promon": "Promon SHIELD",
    "com/guardsquare": "GuardSquare DexGuard",
    "com/datatheorem/android/trustkit": "TrustKit",
    "com/aheaditec/talsec": "Talsec freeRASP",
    "com/inka/appsealing": "AppSealing",
    "com/lexisnexisrisk/threatmetrix": "LexisNexis ThreatMetrix",
    "com/behaviosec": "BehavioSec",
    "org/conscrypt": "Conscrypt",
    "de/robv/android/xposed": "Xposed Framework",
    "com/saurik/substrate": "Cydia Substrate",
    "org/lsposed": "LSPosed",
    "com/topjohnwu/magisk": "Magisk",
    "com/squareup/okhttp3": "OkHttp3",
    "retrofit2": "Retrofit2",
    "com/google/android/gms/safetynet": "SafetyNet",
    "com/google/android/play/core/integrity": "Play Integrity",
}

def _check_security_classes(decompiled_dir):
    """Check smali directory tree for known security library packages."""
    found = []
    smali_dirs = [d for d in os.listdir(decompiled_dir)
                  if d.startswith("smali") and os.path.isdir(os.path.join(decompiled_dir, d))]
    seen = set()
    for d in smali_dirs:
        for pkg_path, label in SECURITY_PACKAGES.items():
            if label in seen:
                continue
            full = os.path.join(decompiled_dir, d, pkg_path)
            if os.path.isdir(full):
                # Count smali files to gauge library size
                count = sum(1 for _, _, ff in os.walk(full) for f in ff if f.endswith(".smali"))
                found.append((label, f"{d}/{pkg_path}/", count))
                seen.add(label)
    return found


def _print_security_classes(classes):
    """Display found security class packages."""
    if not classes:
        return
    print(f"\n  {C.CYAN}{C.BOLD}── SECURITY LIBRARIES (class detection) ──{C.RST}")
    for label, path, count in sorted(classes, key=lambda x: -x[2]):
        print(f"    {C.GREEN}[FOUND]{C.RST} {label}  {C.DIM}({path} — {count} classes){C.RST}")


# ─── Native Strings Analysis (Optional) ──────────────────────────────────────────

_NATIVE_STRING_PATTERNS = [
    ("Root Paths", re.compile(r'/system/(?:x?bin|app)/su|/sbin/su|/data/local/su|Superuser\.apk')),
    ("Magisk", re.compile(r'magisk|\.magisk|magiskhide|magiskpolicy', re.IGNORECASE)),
    ("Frida", re.compile(r'frida|LIBFRIDA|frida-server|frida-agent|frida-gadget')),
    ("Xposed", re.compile(r'XposedBridge|xposed|LSPosed|EdXposed')),
    ("Emulator", re.compile(r'goldfish|ranchu|genymotion|bluestacks|nox|qemu', re.IGNORECASE)),
    ("SSL Pins", re.compile(r'sha256/[A-Za-z0-9+/=]{20,}|SPKI|TrustManager')),
    ("Debug/Tamper", re.compile(r'ptrace|TracerPid|/proc/self/(?:maps|status)|isDebuggerConnected')),
]

def _scan_native_strings(decompiled_dir):
    """Run strings on native .so files and search for security indicators."""
    lib_dir = os.path.join(decompiled_dir, "lib")
    if not os.path.isdir(lib_dir):
        return []

    results = []
    for root, dirs, files in os.walk(lib_dir):
        for f in files:
            if not f.endswith(".so"):
                continue
            fpath = os.path.join(root, f)
            rel = os.path.relpath(fpath, decompiled_dir)
            try:
                r = subprocess.run(
                    ["strings", "-n", "8", fpath],
                    capture_output=True, text=True, timeout=30,
                    encoding='utf-8', errors='replace'
                )
                if r.returncode != 0:
                    continue
                lines = r.stdout
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

            file_hits = {}
            for category, pattern in _NATIVE_STRING_PATTERNS:
                matches = pattern.findall(lines)
                if matches:
                    # Deduplicate
                    unique = list(dict.fromkeys(matches))[:5]
                    file_hits[category] = unique

            if file_hits:
                results.append((rel, file_hits))
    return results


def _print_native_strings(results):
    """Display native string analysis results."""
    if not results:
        print(f"    {C.DIM}No security-related strings found in native libraries.{C.RST}")
        return

    for rel, hits in results:
        print(f"\n    {C.BOLD}{rel}{C.RST}")
        for category, strings in hits.items():
            preview = ", ".join(s if len(s) <= 40 else s[:37] + "..." for s in strings[:3])
            more = f" +{len(strings)-3}" if len(strings) > 3 else ""
            print(f"      {C.GREEN}[{category}]{C.RST} {C.DIM}{preview}{more}{C.RST}")


# ─── 1. App Analysis ────────────────────────────────────────────────────────────

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

    # Data dir size
    data_size = adb_su(f"du -sh /data/data/{pkg} 2>/dev/null")
    if data_size and not data_size.startswith("["):
        status_line("Data Size", data_size.split()[0] if data_size.split() else "N/A")

    # Permissions
    print(f"\n  {C.YELLOW}{C.BOLD}── Permissions ──{C.RST}")
    perm_section = False
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
    activities = re.findall(r'^\s+([\w./]+) filter', dumpsys, re.MULTILINE)
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
        if "error" not in result.lower() and "does not exist" not in result.lower():
            size = os.path.getsize(local_path) if os.path.exists(local_path) else 0
            print(f"  {C.GREEN}[✓] Saved: {local_path} ({size // 1024} KB){C.RST}")
        else:
            print(f"  {C.RED}[✗] Pull failed: {result}{C.RST}")

    pause()

# ─── 2. Storage Audit ───────────────────────────────────────────────────────────

SECRET_PATTERNS = [
    # ── Generic secrets ──
    r'(?i)(password|passwd|pwd)\s*[=:]\s*\S+',
    r'(?i)(api[_-]?key|apikey)\s*[=:]\s*\S+',
    r'(?i)(secret[_-]?key|client[_-]?secret|app[_-]?secret)\s*[=:]\s*\S+',
    r'(?i)(access[_-]?key|access[_-]?token)\s*[=:]\s*\S+',
    r'(?i)(private[_-]?key|signing[_-]?key)\s*[=:]\s*\S+',
    r'(?i)(auth[_-]?token|session[_-]?token|refresh[_-]?token)\s*[=:]\s*\S+',
    r'(?i)(encryption[_-]?key|master[_-]?key|db[_-]?password)\s*[=:]\s*\S+',
    r'eyJ[A-Za-z0-9_-]{10,}',  # JWT
    r'(?i)bearer\s+[A-Za-z0-9_.-]+',
    # ── AWS ──
    r'AKIA[0-9A-Z]{16}',  # AWS Access Key ID
    r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*\S+',
    r'(?i)aws[_-]?session[_-]?token\s*[=:]\s*\S+',
    r's3://[a-zA-Z0-9._-]+',  # S3 bucket URL
    # ── Google / Firebase ──
    r'AIza[0-9A-Za-z_-]{35}',  # Google API key
    r'(?i)firebase[_-]?(api[_-]?key|token|secret|url)\s*[=:]\s*\S+',
    r'[0-9]+-[a-z0-9]{32}\.apps\.googleusercontent\.com',  # Google OAuth client ID
    r'(?i)google[_-]?(api[_-]?key|cloud[_-]?key|maps[_-]?key)\s*[=:]\s*\S+',
    # ── Azure ──
    r'(?i)(azure|az)[_-]?(storage[_-]?key|connection[_-]?string|tenant[_-]?id|client[_-]?secret)\s*[=:]\s*\S+',
    r'DefaultEndpointsProtocol=https;AccountName=\S+',  # Azure connection string
    # ── Stripe ──
    r'sk_live_[0-9a-zA-Z]{24,}',  # Stripe secret key
    r'pk_live_[0-9a-zA-Z]{24,}',  # Stripe publishable key
    r'rk_live_[0-9a-zA-Z]{24,}',  # Stripe restricted key
    # ── Twilio ──
    r'SK[0-9a-fA-F]{32}',  # Twilio API key
    r'(?i)twilio[_-]?(auth[_-]?token|api[_-]?key|account[_-]?sid)\s*[=:]\s*\S+',
    # ── SendGrid ──
    r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',  # SendGrid API key
    # ── Slack ──
    r'xox[bprs]-[0-9a-zA-Z-]+',  # Slack token
    r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+',  # Slack webhook
    # ── GitHub ──
    r'gh[ps]_[A-Za-z0-9_]{36,}',  # GitHub PAT
    r'github_pat_[A-Za-z0-9_]{22,}',  # GitHub fine-grained PAT
    # ── Payment / Merchant ──
    r'(?i)(merchant[_-]?id|merchant[_-]?key|payment[_-]?secret)\s*[=:]\s*\S+',
    r'(?i)(paypal|braintree|razorpay)[_-]?(secret|key|token)\s*[=:]\s*\S+',
    # ── Push / Messaging ──
    r'(?i)(fcm[_-]?key|push[_-]?key|gcm[_-]?key|apns[_-]?key)\s*[=:]\s*\S+',
    r'key=[A-Za-z0-9_-]{39}',  # FCM server key format
    # ── OAuth / SSO ──
    r'(?i)(client[_-]?id|client[_-]?secret|oauth[_-]?token)\s*[=:]\s*\S+',
    r'(?i)(redirect[_-]?uri|callback[_-]?url)\s*[=:]\s*http\S+',
    # ── Database ──
    r'(?i)(mongodb|postgres|mysql|redis)://\S+:\S+@\S+',  # DB connection string with creds
    r'(?i)(database[_-]?url|db[_-]?connection)\s*[=:]\s*\S+',
    # ── Private keys / certs ──
    r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
    r'-----BEGIN CERTIFICATE-----',
]

# ── PII / Sensitive Data Value Patterns ────────────────────────────────────────
# Each tuple: (compiled_regex, label) — scans actual content for stored PII
PII_PATTERNS = [
    # Credit / Debit Cards
    (re.compile(r'\b4[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b'), 'Credit Card (Visa)'),
    (re.compile(r'\b5[1-5][0-9]{2}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b'), 'Credit Card (Mastercard)'),
    (re.compile(r'\b3[47][0-9]{2}[\s-]?[0-9]{6}[\s-]?[0-9]{5}\b'), 'Credit Card (AMEX)'),
    (re.compile(r'\b6(?:011|5[0-9]{2})[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b'), 'Credit Card (Discover)'),
    # Singapore NRIC / FIN (S/T/F/G/M + 7 digits + checksum letter)
    (re.compile(r'\b[STFGM]\d{7}[A-Z]\b'), 'NRIC/FIN (SG)'),
    # Malaysia IC (YYMMDD-PP-####)
    (re.compile(r'\b\d{6}-\d{2}-\d{4}\b'), 'IC Number (MY)'),
    # US SSN (###-##-####)
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), 'SSN (US)'),
    # Passport number near keyword
    (re.compile(r'(?i)passport[\s_:="]*[A-Z][A-Z0-9]\d{6,8}\b'), 'Passport Number'),
    # Email addresses
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'), 'Email Address'),
    # Phone with international country code
    (re.compile(r'\+\d{1,3}[\s-]?\d{4,}[\s-]?\d{3,}'), 'Phone Number'),
    # IBAN
    (re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b'), 'IBAN'),
    # Account number preceded by keyword
    (re.compile(r'(?i)(?:account|acct)[_\s.-]*(?:no|num|number|#)?[_\s:="]*\d{8,17}\b'), 'Account Number'),
    # Date of birth near keyword
    (re.compile(r'(?i)(?:dob|date.of.birth|birth.?date)[_\s:="]*\d{1,4}[/.-]\d{1,2}[/.-]\d{1,4}'), 'Date of Birth'),
    # Full name near keyword
    (re.compile(r'(?i)(?:full.?name|customer.?name|card.?holder|account.?holder)[_\s:="]*[A-Z][a-z]+\s+[A-Z][a-z]+'), 'Full Name'),
]

def _scan_pii(content):
    """Scan content for PII patterns. Returns list of (label, matched_value)."""
    hits = []
    seen = set()
    for pattern, label in PII_PATTERNS:
        for m in pattern.finditer(content):
            val = m.group().strip()[:80]
            key = (label, val)
            if key not in seen:
                seen.add(key)
                hits.append((label, val))
    return hits

def storage_audit(pkg):
    section("STORAGE AUDIT")

    data_dir = f"/data/data/{pkg}"
    print(f"\n  {C.CYAN}Auditing storage: {C.BOLD}{data_dir}{C.RST}\n")

    # Overall size
    size_out = adb_su(f"du -sh {data_dir} 2>/dev/null")
    if size_out and not size_out.startswith("["):
        status_line("Total Size", size_out.split()[0] if size_out.split() else "N/A")

    # List all files recursively (maxdepth + no symlink follow to stay in app dir)
    files_out = adb_su(f"find {data_dir} -maxdepth 5 -type f -not -type l 2>/dev/null", timeout=60)
    all_files = [f.strip() for f in files_out.splitlines()
                 if f.strip() and not f.startswith("[") and f.startswith(data_dir)]

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

        for spf in sp_files_sorted:
            fname = os.path.basename(spf)
            content = adb_su(f"cat {spf} 2>/dev/null", timeout=15)
            size_info = adb_su(f"ls -la {spf} 2>/dev/null")
            fsize = "?"
            if size_info:
                parts = size_info.split()
                if len(parts) >= 5:
                    fsize = parts[3]

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

            if content and not content.startswith("[") and not is_encrypted:
                # Always show raw XML content (first 10 lines)
                raw_lines = content.splitlines()
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
                            display_val = kval[:80] + "..." if len(kval) > 80 else kval
                            print(f"        {C.RED}⚠ {kname}{C.RST} = {C.RED}{display_val}{C.RST} {C.DIM}({ktype}){C.RST}")

                # Check for secrets
                for pattern in SECRET_PATTERNS:
                    matches = re.findall(pattern, content)
                    if matches:
                        secrets_found += 1
                        for match in matches[:3]:
                            val = match if isinstance(match, str) else match[0]
                            print(f"      {C.RED}⚠ Potential secret: {val[:60]}...{C.RST}")

                # Check for PII in values
                pii_hits = _scan_pii(content)
                if pii_hits:
                    pii_found += 1
                    print(f"      {C.RED}PII Detected ({len(pii_hits)}):{C.RST}")
                    for label, val in pii_hits[:8]:
                        print(f"        {C.RED}⚠ {label}: {val}{C.RST}")

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
            fname = os.path.basename(dbf)
            size_info = adb_su(f"ls -la {dbf} 2>/dev/null")
            fsize = "?"
            if size_info:
                parts = size_info.split()
                if len(parts) >= 5:
                    fsize = parts[3]

            is_sdk = is_sdk_db(dbf)
            sdk_tag = f" {C.DIM}[SDK]{C.RST}" if is_sdk else f" {C.MAGENTA}[APP]{C.RST}"
            print(f"\n    {C.CYAN}🗄  {fname}{C.RST} {C.DIM}({fsize} bytes){C.RST}{sdk_tag}")

            # Check if encrypted (SQLCipher)
            header = adb_su(f"xxd -l 16 {dbf} 2>/dev/null", timeout=5)
            is_encrypted = header and "5351 4c69 7465" not in header  # "SQLite" magic
            if is_encrypted:
                print(f"      {C.GREEN}[ENCRYPTED - SQLCipher or similar]{C.RST}")
                continue

            tables = adb_su(f"sqlite3 {dbf} '.tables' 2>/dev/null", timeout=10)
            if tables and not tables.startswith("[") and "not found" not in tables:
                table_list = tables.split()
                print(f"      Tables ({len(table_list)}): {C.WHITE}{tables}{C.RST}")

                # For app-specific DBs, show more details
                if not is_sdk:
                    for table in table_list[:5]:  # First 5 tables
                        # Get row count
                        count = adb_su(f"sqlite3 {dbf} 'SELECT COUNT(*) FROM {table}' 2>/dev/null", timeout=5)
                        count = count.strip() if count and not count.startswith("[") else "?"

                        # Get column names
                        cols = adb_su(f"sqlite3 {dbf} 'PRAGMA table_info({table})' 2>/dev/null", timeout=5)
                        col_names = []
                        if cols and not cols.startswith("["):
                            for line in cols.splitlines():
                                parts = line.split("|")
                                if len(parts) >= 2:
                                    col_names.append(parts[1])

                        print(f"      {C.WHITE}→ {table}{C.RST} ({count} rows)")
                        if col_names:
                            print(f"        Columns: {C.DIM}{', '.join(col_names[:8])}{C.RST}")
                            if len(col_names) > 8:
                                print(f"        {C.DIM}... and {len(col_names) - 8} more columns{C.RST}")

                        # Fetch sample data for PII scanning + display
                        sensitive_tables = ['user', 'account', 'credential', 'token', 'session',
                                            'auth', 'login', 'profile', 'setting', 'config',
                                            'cache', 'payment', 'card', 'address', 'contact',
                                            'transaction', 'order', 'customer', 'member']
                        if count != "?" and int(count) > 0:
                            sample = adb_su(f"sqlite3 {dbf} 'SELECT * FROM {table} LIMIT 5' 2>/dev/null", timeout=5)
                            if sample and not sample.startswith("["):
                                # Show raw rows for sensitive-looking tables
                                if any(st in table.lower() for st in sensitive_tables):
                                    print(f"        {C.RED}Sample data:{C.RST}")
                                    for row in sample.splitlines()[:3]:
                                        row_display = row[:100] + "..." if len(row) > 100 else row
                                        print(f"          {C.DIM}{row_display}{C.RST}")
                                # Scan ALL app tables for PII
                                pii_hits = _scan_pii(sample)
                                if pii_hits:
                                    print(f"        {C.RED}⚠ PII in data ({len(pii_hits)}):{C.RST}")
                                    for label, val in pii_hits[:5]:
                                        print(f"          {C.RED}⚠ {label}: {val}{C.RST}")

                    if len(table_list) > 5:
                        print(f"      {C.DIM}... and {len(table_list) - 5} more tables{C.RST}")

    # Realm Database analysis
    if realm_files:
        print(f"\n  {C.YELLOW}{C.BOLD}── Realm Databases ──{C.RST}")
        for rf in realm_files:
            fname = os.path.basename(rf)
            size_info = adb_su(f"ls -la {rf} 2>/dev/null")
            fsize = "?"
            if size_info:
                parts = size_info.split()
                if len(parts) >= 5:
                    fsize = parts[3]
            # Check if encrypted by reading header
            header = adb_su(f"xxd -l 8 {rf} 2>/dev/null", timeout=5)
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

        for of in other_files:
            fname = os.path.basename(of)
            rel_path = of.replace(data_dir + "/", "")
            content = adb_su(f"cat {of} 2>/dev/null", timeout=10)

            # Skip binary / empty / error responses
            if not content or content.startswith("["):
                continue
            # Basic binary check: if too many non-printable chars, skip
            sample = content[:512]
            non_print = sum(1 for ch in sample if ord(ch) < 32 and ch not in '\n\r\t')
            if non_print > len(sample) * 0.3:
                print(f"\n    {C.CYAN}{rel_path}{C.RST} {C.DIM}[binary, skipped]{C.RST}")
                continue

            lines = content.splitlines()
            preview = lines[:5]

            # Check for keyword hits in full content
            content_lower = content.lower()
            hits = [kw for kw in highlight_kw if kw in content_lower]

            # Check SECRET_PATTERNS
            secret_hits = []
            for pattern in SECRET_PATTERNS:
                matches = re.findall(pattern, content)
                if matches:
                    for m in matches[:2]:
                        val = m if isinstance(m, str) else m[0]
                        secret_hits.append(val[:80])

            if secret_hits:
                other_secrets += 1

            hit_tag = ""
            if hits:
                hit_tag = f" {C.RED}[SENSITIVE: {', '.join(hits[:5])}]{C.RST}"
            elif not secret_hits:
                hit_tag = f" {C.DIM}[no keywords]{C.RST}"

            print(f"\n    {C.CYAN}{rel_path}{C.RST} {C.DIM}({len(lines)} lines){C.RST}{hit_tag}")
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
                print(f"      {C.RED}⚠ Potential secret: {sh}{C.RST}")

            # Check for PII in content
            pii_hits = _scan_pii(content)
            if pii_hits:
                other_pii += 1
                print(f"      {C.RED}PII Detected ({len(pii_hits)}):{C.RST}")
                for label, val in pii_hits[:5]:
                    print(f"        {C.RED}⚠ {label}: {val}{C.RST}")

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
    for f in all_files[:100]:  # Check first 100 files
        perms = adb_su(f"stat -c '%a' {f} 2>/dev/null", timeout=5)
        if perms and not perms.startswith("["):
            perms = perms.strip()
            if len(perms) >= 3 and perms[-1] in ['4', '5', '6', '7']:  # world-readable
                world_readable.append((f, perms))
    if world_readable:
        print(f"    {C.RED}⚠ Found {len(world_readable)} world-readable file(s):{C.RST}")
        for wf, perm in world_readable[:10]:
            print(f"      {C.DIM}{os.path.basename(wf)} (mode: {perm}){C.RST}")
        if len(world_readable) > 10:
            print(f"      {C.DIM}... and {len(world_readable) - 10} more{C.RST}")
    else:
        print(f"    {C.GREEN}No world-readable files found (checked {min(len(all_files), 100)} files).{C.RST}")

    # External storage check
    print(f"\n  {C.YELLOW}{C.BOLD}── External Storage ──{C.RST}")
    ext_dir = f"/sdcard/Android/data/{pkg}"
    ext_out = adb_su(f"ls -la {ext_dir} 2>/dev/null")
    if ext_out and "No such file" not in ext_out and not ext_out.startswith("["):
        ext_size = adb_su(f"du -sh {ext_dir} 2>/dev/null")
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
            # Resolve the new path in Python
            if target.startswith("/"):
                new_cwd = os.path.normpath(target)
            else:
                new_cwd = os.path.normpath(f"{cwd}/{target}")
            # Verify directory exists by actually cd-ing into it
            check = _shell_su(f'cd {new_cwd} && pwd')
            if check and not check.startswith('[') and '/' in check:
                cwd = check.strip().splitlines()[-1].strip()
            else:
                print(f"  {C.RED}cd: {target}: No such directory{C.RST}\n")
            continue

        # Run command in current directory (compound cmd needs _shell_su)
        full_cmd = f'cd {cwd} && {cmd}'
        output = _shell_su(full_cmd, timeout=30)
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

# ─── 5. Security Scan ───────────────────────────────────────────────────────────

DANGEROUS_PERMS = {
    "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_PHONE_STATE", "android.permission.CALL_PHONE",
    "android.permission.SEND_SMS", "android.permission.READ_SMS",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR",
    "android.permission.BODY_SENSORS", "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG", "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO", "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.POST_NOTIFICATIONS",
}

def security_scan(pkg):
    section("SECURITY SCAN")

    print(f"\n  {C.CYAN}Scanning: {C.BOLD}{pkg}{C.RST}\n")

    work_dir, decompiled_dir = _pull_and_decompile(pkg)
    if not decompiled_dir:
        pause()
        return

    passes = 0
    fails = 0
    warns = 0

    # ── Read AndroidManifest.xml from decompiled dir ─────────────────────────
    manifest_path = os.path.join(decompiled_dir, "AndroidManifest.xml")
    manifest = ""
    try:
        with open(manifest_path, 'r', errors='ignore') as f:
            manifest = f.read()
    except Exception:
        print(f"  {C.RED}[!] Could not read AndroidManifest.xml{C.RST}")

    # ── Debuggable ───────────────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Debuggable Check ──{C.RST}")
    debuggable = bool(re.search(r'android:debuggable\s*=\s*"true"', manifest, re.IGNORECASE))
    if debuggable:
        pass_fail("Debuggable flag", False, "App is debuggable — allows runtime inspection")
        fails += 1
    else:
        pass_fail("Debuggable flag", True, "Not debuggable")
        passes += 1

    # ── Backup ───────────────────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Backup Check ──{C.RST}")
    backup_match = re.search(r'android:allowBackup\s*=\s*"(true|false)"', manifest, re.IGNORECASE)
    allow_backup = backup_match and backup_match.group(1).lower() == "true"
    if allow_backup:
        pass_fail("allowBackup", False, "App data can be backed up via adb — data extraction risk")
        fails += 1
    else:
        pass_fail("allowBackup", True, "Backup disabled or not set")
        passes += 1

    # ── Exported Components ──────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Exported Components ──{C.RST}")

    exported_acts = []
    exported_svcs = []
    exported_rcvs = []
    exported_provs = []

    comp_map = [
        ("activity", exported_acts),
        ("service", exported_svcs),
        ("receiver", exported_rcvs),
        ("provider", exported_provs),
    ]

    for tag, lst in comp_map:
        for m in re.finditer(
            rf'<{tag}\s[^>]*android:exported\s*=\s*"true"[^>]*android:name\s*=\s*"([^"]+)"',
            manifest, re.IGNORECASE
        ):
            lst.append(m.group(1))
        # Also match when name comes before exported
        for m in re.finditer(
            rf'<{tag}\s[^>]*android:name\s*=\s*"([^"]+)"[^>]*android:exported\s*=\s*"true"',
            manifest, re.IGNORECASE
        ):
            if m.group(1) not in lst:
                lst.append(m.group(1))

    total_exported = len(exported_acts) + len(exported_svcs) + len(exported_rcvs) + len(exported_provs)
    if total_exported > 0:
        warn_line(f"Exported components found: {total_exported}")
        warns += 1
        for a in exported_acts[:5]:
            print(f"    {C.DIM}Activity: {a}{C.RST}")
        for s in exported_svcs[:5]:
            print(f"    {C.DIM}Service: {s}{C.RST}")
        for r in exported_rcvs[:5]:
            print(f"    {C.DIM}Receiver: {r}{C.RST}")
        for p in exported_provs[:5]:
            print(f"    {C.DIM}Provider: {p}{C.RST}")
    else:
        pass_fail("Exported components", True, "None found or all properly protected")
        passes += 1

    # ── Permissions ──────────────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Dangerous Permissions ──{C.RST}")
    requested_perms = set()
    for m in re.finditer(r'<uses-permission\s[^>]*android:name\s*=\s*"([^"]+)"', manifest):
        requested_perms.add(m.group(1))
    dangerous_requested = requested_perms & DANGEROUS_PERMS
    if dangerous_requested:
        warn_line(f"{len(dangerous_requested)} dangerous permissions requested")
        warns += 1
        for dp in sorted(dangerous_requested):
            short = dp.replace("android.permission.", "")
            print(f"    {C.RED}• {short}{C.RST}")
    else:
        pass_fail("Dangerous permissions", True, "No dangerous permissions requested")
        passes += 1

    # ── SDK Version ──────────────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── SDK Version ──{C.RST}")
    # Read apktool.yml for SDK info
    apktool_yml = os.path.join(decompiled_dir, "apktool.yml")
    min_sdk = "N/A"
    target_sdk = "N/A"
    try:
        with open(apktool_yml, 'r', errors='ignore') as f:
            yml = f.read()
        m = re.search(r'minSdkVersion:\s*[\'"]?(\d+)', yml)
        if m:
            min_sdk = m.group(1)
        m = re.search(r'targetSdkVersion:\s*[\'"]?(\d+)', yml)
        if m:
            target_sdk = m.group(1)
    except Exception:
        pass
    # Fallback: check manifest uses-sdk
    if min_sdk == "N/A":
        m = re.search(r'android:minSdkVersion\s*=\s*"(\d+)"', manifest)
        if m:
            min_sdk = m.group(1)
    if target_sdk == "N/A":
        m = re.search(r'android:targetSdkVersion\s*=\s*"(\d+)"', manifest)
        if m:
            target_sdk = m.group(1)

    if min_sdk != "N/A" and int(min_sdk) < 23:
        pass_fail("Min SDK", False, f"minSdk={min_sdk} — targets outdated Android (< 6.0)")
        fails += 1
    elif min_sdk != "N/A":
        pass_fail("Min SDK", True, f"minSdk={min_sdk}")
        passes += 1
    else:
        info_line("Min SDK", "Could not determine")

    if target_sdk != "N/A" and int(target_sdk) < 30:
        warn_line(f"targetSdk={target_sdk} — below recommended level 30+")
        warns += 1
    elif target_sdk != "N/A":
        pass_fail("Target SDK", True, f"targetSdk={target_sdk}")
        passes += 1

    # ── Cleartext Traffic ────────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Network Security ──{C.RST}")
    cleartext_match = re.search(r'android:usesCleartextTraffic\s*=\s*"(true|false)"', manifest, re.IGNORECASE)
    if cleartext_match:
        if cleartext_match.group(1).lower() == "true":
            pass_fail("Cleartext traffic", False, "usesCleartextTraffic=true — HTTP allowed")
            fails += 1
        else:
            pass_fail("Cleartext traffic", True, "Cleartext traffic disabled")
            passes += 1
    else:
        info_line("Cleartext traffic", "Flag not explicitly set in manifest")

    # ── Network Security Config ──────────────────────────────────────────────
    nsc_ref = re.search(r'android:networkSecurityConfig\s*=\s*"@([^"]+)"', manifest)
    nsc_path = os.path.join(decompiled_dir, "res", "xml", "network_security_config.xml")
    if nsc_ref or os.path.exists(nsc_path):
        pass_fail("Network security config", True, "Custom config present")
        passes += 1
        # Check if config allows user CAs (bad for prod)
        if os.path.exists(nsc_path):
            try:
                with open(nsc_path, 'r', errors='ignore') as f:
                    nsc = f.read()
                if "user" in nsc.lower() and "certificates" in nsc.lower():
                    warn_line("Network security config trusts user-installed CAs")
                    warns += 1
            except Exception:
                pass
    else:
        info_line("Network security config", "No custom config found (using platform defaults)")

    # ── Secrets in decompiled files ──────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Data Leakage Check ──{C.RST}")
    secrets_found = False
    secrets_files = []
    for root, dirs, files in os.walk(decompiled_dir):
        for fname in files:
            if fname.endswith(('.xml', '.json', '.properties', '.yml', '.yaml')):
                fpath = os.path.join(root, fname)
                # Skip large files and manifest (already parsed)
                try:
                    if os.path.getsize(fpath) > 500000:
                        continue
                except Exception:
                    continue
                try:
                    with open(fpath, 'r', errors='ignore') as fh:
                        content = fh.read()
                    for pattern in SECRET_PATTERNS:
                        if re.search(pattern, content):
                            rel = os.path.relpath(fpath, decompiled_dir)
                            secrets_files.append(rel)
                            secrets_found = True
                            break
                except Exception:
                    continue
    if secrets_found:
        pass_fail("Hardcoded secrets", False, f"Potential secrets found in {len(secrets_files)} file(s)")
        fails += 1
        for sf in secrets_files[:5]:
            print(f"    {C.DIM}{sf}{C.RST}")
    else:
        pass_fail("Data leakage", True, "No plaintext secrets detected")
        passes += 1

    # ── Deeplink / Intent Filter Hijacking ───────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Deeplink Security ──{C.RST}")
    deeplinks = []
    for m in re.finditer(r'<data\s[^>]*android:scheme\s*=\s*"([^"]+)"[^>]*/?\s*>', manifest, re.IGNORECASE):
        scheme = m.group(1)
        if scheme not in ['http', 'https']:  # Custom schemes
            deeplinks.append(scheme)
    # Also find host-based deeplinks
    for m in re.finditer(r'<data\s[^>]*android:host\s*=\s*"([^"]+)"', manifest, re.IGNORECASE):
        deeplinks.append(m.group(1))
    if deeplinks:
        unique_links = list(set(deeplinks))
        warn_line(f"Found {len(unique_links)} custom deeplink scheme(s)/host(s)")
        warns += 1
        for dl in unique_links[:5]:
            print(f"    {C.DIM}• {dl}{C.RST}")
        print(f"    {C.DIM}Risk: Deeplink hijacking if not validated properly{C.RST}")
    else:
        pass_fail("Deeplinks", True, "No custom deeplink schemes found")
        passes += 1

    # ── WebView JavaScript Interface ─────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── WebView Security ──{C.RST}")
    jsinterface_found = False
    for root, dirs, files in os.walk(decompiled_dir):
        for fname in files:
            if fname.endswith('.smali'):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', errors='ignore') as fh:
                        content = fh.read()
                    if 'addJavascriptInterface' in content:
                        jsinterface_found = True
                        break
                except Exception:
                    continue
        if jsinterface_found:
            break
    if jsinterface_found:
        warn_line("WebView.addJavascriptInterface() used — verify SDK >= 17 protection")
        warns += 1
        print(f"    {C.DIM}Risk: JS-to-Java bridge can expose app to XSS attacks on SDK < 17{C.RST}")
    else:
        pass_fail("WebView JS Interface", True, "No addJavascriptInterface() found")
        passes += 1

    # ── Pending Intent Mutability ────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Pending Intent Security ──{C.RST}")
    mutable_pending = False
    immutable_pending = False
    for root, dirs, files in os.walk(decompiled_dir):
        for fname in files:
            if fname.endswith('.smali'):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', errors='ignore') as fh:
                        content = fh.read()
                    if 'PendingIntent;->get' in content:
                        if 'FLAG_IMMUTABLE' in content or 'FLAG_MUTABLE' in content:
                            immutable_pending = True
                        else:
                            mutable_pending = True
                except Exception:
                    continue
    if mutable_pending and not immutable_pending:
        warn_line("PendingIntent without FLAG_IMMUTABLE/FLAG_MUTABLE (SDK 31+ required)")
        warns += 1
        print(f"    {C.DIM}Risk: PendingIntent hijacking on Android 12+{C.RST}")
    elif immutable_pending:
        pass_fail("Pending Intent", True, "FLAG_IMMUTABLE/FLAG_MUTABLE flags used")
        passes += 1
    else:
        info_line("Pending Intent", "No PendingIntent usage detected")

    # ── Implicit Broadcast ───────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Broadcast Security ──{C.RST}")
    unprotected_broadcasts = 0
    protected_broadcasts = 0
    for root, dirs, files in os.walk(decompiled_dir):
        for fname in files:
            if fname.endswith('.smali'):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', errors='ignore') as fh:
                        content = fh.read()
                    # sendBroadcast(Intent) without permission — single arg
                    if 'sendBroadcast(Landroid/content/Intent;)V' in content:
                        # Check it's not LocalBroadcastManager (safe)
                        if 'LocalBroadcastManager' not in content:
                            unprotected_broadcasts += 1
                    # sendBroadcast(Intent, String) with permission — safe
                    if 'sendBroadcast(Landroid/content/Intent;Ljava/lang/String;)V' in content:
                        protected_broadcasts += 1
                except Exception:
                    continue
    if unprotected_broadcasts > 0:
        warn_line(f"sendBroadcast() without permission in {unprotected_broadcasts} file(s)")
        warns += 1
        print(f"    {C.DIM}Risk: Any app can intercept implicit broadcasts{C.RST}")
        if protected_broadcasts > 0:
            print(f"    {C.DIM}{protected_broadcasts} file(s) use permission-protected broadcasts{C.RST}")
    elif protected_broadcasts > 0:
        pass_fail("Broadcast security", True, f"All broadcasts use permission protection ({protected_broadcasts} file(s))")
        passes += 1
    else:
        info_line("Broadcast security", "No sendBroadcast() usage detected")

    # ── Screenshot Protection (FLAG_SECURE) ─────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Screenshot Protection ──{C.RST}")
    flag_secure_found = False
    for root, dirs, files in os.walk(decompiled_dir):
        for fname in files:
            if fname.endswith('.smali'):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', errors='ignore') as fh:
                        content = fh.read()
                    if 'FLAG_SECURE' in content or 'setFlags(8192' in content:
                        flag_secure_found = True
                        break
                except Exception:
                    continue
        if flag_secure_found:
            break
    if flag_secure_found:
        pass_fail("FLAG_SECURE", True, "Screenshot protection detected")
        passes += 1
    else:
        warn_line("FLAG_SECURE not detected — screenshots may expose sensitive data")
        warns += 1

    # ── Clipboard Data Exposure ─────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Clipboard Data Exposure ──{C.RST}")
    clip_usage = 0
    clip_protection = 0
    clip_files = []
    for root, dirs, files in os.walk(decompiled_dir):
        for fname in files:
            if fname.endswith('.smali'):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', errors='ignore') as fh:
                        content = fh.read()
                    has_clip = any(kw in content for kw in
                                  ('ClipboardManager', 'ClipData', 'setPrimaryClip', 'getPrimaryClip'))
                    if has_clip:
                        clip_usage += 1
                        rel = os.path.relpath(fpath, decompiled_dir)
                        clip_files.append(rel)
                    if 'FLAG_SENSITIVE' in content or 'isSensitive' in content:
                        clip_protection += 1
                except Exception:
                    continue
    if clip_usage > 0 and clip_protection == 0:
        warn_line(f"Clipboard used without FLAG_SENSITIVE protection ({clip_usage} file(s))")
        warns += 1
        for cf in clip_files[:3]:
            print(f"    {C.DIM}{cf}{C.RST}")
    elif clip_usage > 0 and clip_protection > 0:
        pass_fail("Clipboard", True, "Clipboard used with sensitive flag protection")
        passes += 1
    else:
        pass_fail("Clipboard", True, "No direct clipboard operations detected")
        passes += 1

    # ── Debug / Verbose Logging ────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Debug / Verbose Logging ──{C.RST}")
    log_keywords = {
        "Java":   ['Landroid/util/Log;->v(', 'Landroid/util/Log;->d('],
        "Kotlin": ['Timber;->d(', 'Timber;->v('],
        "Flutter": ['debugPrint', 'kDebugMode'],
        "React Native": ['console.log', 'console.debug'],
    }
    log_hits = {}
    for root, dirs, files in os.walk(decompiled_dir):
        for fname in files:
            if fname.endswith('.smali'):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', errors='ignore') as fh:
                        content = fh.read()
                    for framework, kws in log_keywords.items():
                        for kw in kws:
                            if kw in content:
                                log_hits[framework] = log_hits.get(framework, 0) + 1
                except Exception:
                    continue
    if log_hits:
        total = sum(log_hits.values())
        warn_line(f"Debug/verbose log calls found ({total} file(s))")
        warns += 1
        for fw, count in log_hits.items():
            print(f"    {C.DIM}• {fw}: {count} file(s){C.RST}")
    else:
        pass_fail("Debug logging", True, "No verbose/debug log calls detected")
        passes += 1

    # ── Keyboard Cache / Input Types ────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Keyboard Cache ──{C.RST}")
    pw_fields = 0
    nosuggest = 0
    for root, dirs, files in os.walk(decompiled_dir):
        for fname in files:
            if fname.endswith('.xml'):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', errors='ignore') as fh:
                        content = fh.read()
                    for kw in ('textPassword', 'textVisiblePassword', 'numberPassword', 'textWebPassword'):
                        if kw in content:
                            pw_fields += content.count(kw)
                    for kw in ('textNoSuggestions', 'flagNoPersonalizedLearning'):
                        if kw in content:
                            nosuggest += content.count(kw)
                except Exception:
                    continue
    if pw_fields:
        pass_fail("Secure input types", True, f"{pw_fields} password-type field(s) found")
        passes += 1
    else:
        warn_line("No password inputType fields found in layouts")
        warns += 1
    if nosuggest:
        info_line("textNoSuggestions", f"{nosuggest} field(s) disable keyboard learning")
    else:
        warn_line("No textNoSuggestions flag — keyboard may cache sensitive input")
        warns += 1

    # ── Task Hijacking (taskAffinity) ───────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Task Hijacking ──{C.RST}")
    task_hijack = []
    for m in re.finditer(
        r'<activity\s([^>]*?)(?:/>|>)', manifest, re.IGNORECASE | re.DOTALL
    ):
        attrs = m.group(1)
        name_m = re.search(r'android:name\s*=\s*"([^"]+)"', attrs)
        if not name_m:
            continue
        affinity_m = re.search(r'android:taskAffinity\s*=\s*"([^"]*)"', attrs)
        if affinity_m:
            aff = affinity_m.group(1)
            # Empty string taskAffinity is actually a mitigation
            if aff:
                task_hijack.append((name_m.group(1), aff))
    if task_hijack:
        warn_line(f"Activities with custom taskAffinity ({len(task_hijack)}) — StrandHogg risk")
        warns += 1
        for act_name, aff in task_hijack[:5]:
            print(f"    {C.DIM}• {act_name}{C.RST}")
            print(f"      {C.DIM}taskAffinity=\"{aff}\"{C.RST}")
    else:
        pass_fail("Task hijacking", True, "No custom taskAffinity found")
        passes += 1

    # ── Tapjacking Protection ───────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Tapjacking Protection ──{C.RST}")
    has_filter_touches = False
    for root, dirs, files in os.walk(decompiled_dir):
        for fname in files:
            if fname.endswith(('.xml', '.smali')):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', errors='ignore') as fh:
                        content = fh.read()
                    if 'filterTouchesWhenObscured' in content:
                        has_filter_touches = True
                        break
                except Exception:
                    continue
        if has_filter_touches:
            break
    if has_filter_touches:
        pass_fail("Tapjacking", True, "filterTouchesWhenObscured detected")
        passes += 1
    else:
        warn_line("No filterTouchesWhenObscured — app may be vulnerable to tapjacking")
        warns += 1

    # ── APK Signing Scheme ──────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── APK Signing Scheme ──{C.RST}")
    # Locate the APK file
    apk_file = None
    for search_dir in [os.path.join(os.getcwd(), "extracted_apks"),
                       os.path.join(os.getcwd(), "patched_apks"),
                       work_dir, os.getcwd()]:
        if not os.path.isdir(search_dir):
            continue
        for fname in os.listdir(search_dir):
            if fname.endswith(".apk") and pkg in fname:
                candidate = os.path.join(search_dir, fname)
                if os.path.getsize(candidate) > 0:
                    apk_file = candidate
                    break
        if apk_file:
            break

    if apk_file and shutil.which("apksigner"):
        try:
            r = subprocess.run(
                f'apksigner verify --print-certs -v "{apk_file}"',
                shell=True, capture_output=True, text=True, timeout=30,
                encoding='utf-8', errors='replace'
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

            if schemes:
                info_line("Signing schemes", ", ".join(schemes))
            if has_v1 and not has_v2 and not has_v3:
                pass_fail("APK signing", False, "v1-only signing — vulnerable to Janus (CVE-2017-13156)")
                fails += 1
            elif has_v2 or has_v3:
                pass_fail("APK signing", True, "Uses v2/v3 signing scheme")
                passes += 1
            else:
                info_line("APK signing", "Could not determine signing schemes")

            # Extract signer info
            for cn_m in re.finditer(r'CN=([^,\n]+)', output):
                info_line("Signer", cn_m.group(1).strip())
                break
        except Exception:
            info_line("APK signing", "apksigner check failed")
    elif not shutil.which("apksigner"):
        info_line("APK signing", "apksigner not found — skipping (install Android SDK build-tools)")
    else:
        info_line("APK signing", "APK file not found locally — skipping")

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n  {C.CYAN}{'═'*50}{C.RST}")
    print(f"  {C.BOLD}SCAN SUMMARY{C.RST}")
    print(f"  {C.GREEN}PASS: {passes}{C.RST}  {C.RED}FAIL: {fails}{C.RST}  {C.YELLOW}WARN: {warns}{C.RST}")

    if fails == 0 and warns == 0:
        print(f"\n  {C.GREEN}{C.BOLD}Overall: LOW RISK{C.RST}")
    elif fails == 0:
        print(f"\n  {C.YELLOW}{C.BOLD}Overall: MODERATE RISK{C.RST}")
    else:
        print(f"\n  {C.RED}{C.BOLD}Overall: HIGH RISK{C.RST}")

    pause()

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

    # Use _shell_su to cat all matching cache files via glob
    content = _shell_su(f"cat {LOKIBOARD_DIR}/lokiboard_files_*.txt 2>/dev/null")

    if "[ERROR]" in content or "[TIMEOUT]" in content:
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
    subprocess.run(["adb", "logcat", "-c"], capture_output=True, timeout=5)

    print(f"\n  {C.GREEN}[+] Streaming logcat{C.RST}")
    print(f"  {C.DIM}Filtering for: \"{search_str}\"{C.RST}")
    print(f"  {C.YELLOW}Press Ctrl+C to stop.{C.RST}\n")
    print(f"  {C.CYAN}{'═'*50}{C.RST}\n")

    search_lower = search_str.lower()
    try:
        proc = subprocess.Popen(
            ["adb", "logcat"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding='utf-8', errors='replace'
        )
        for line in proc.stdout:
            if search_lower in line.lower():
                highlighted = re.sub(
                    re.escape(search_str),
                    lambda m: f"{C.RED}{C.BOLD}{m.group()}{C.RST}",
                    line.rstrip(),
                    flags=re.IGNORECASE
                )
                print(f"  > {highlighted}")
    except KeyboardInterrupt:
        pass
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            proc.kill()

    print(f"\n\n  {C.CYAN}{'═'*50}{C.RST}")
    print(f"  {C.DIM}Logcat monitor stopped.{C.RST}")
    pause()

# ─── 8. Frida CodeShare ─────────────────────────────────────────────────────────

SCRIPT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frida_scripts")

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
    try:
        r = subprocess.run("frida --version", shell=True, capture_output=True, text=True,
                           timeout=5, encoding='utf-8', errors='replace')
        return r.returncode == 0, r.stdout.strip()
    except Exception:
        return False, ""

def check_frida_server():
    """Check if frida-server is running on device."""
    out = adb_su("ps -A 2>/dev/null | grep frida-server")
    if not out or out.startswith("["):
        out = adb_su("ps | grep frida-server")
    return bool(out and "frida-server" in out)

FRIDA_SERVER_PATH = "/data/local/tmp/frida-server"

# Global frida connection mode: "-U" (USB default) or "-H ip:port" (custom)
FRIDA_CONN = "-U"

def start_frida_server(binary_path, listen_addr=None):
    """Start frida-server on device in background. Returns True if started."""
    # Kill any existing instance first
    adb_su("pkill -f frida-server 2>/dev/null")
    time.sleep(0.5)

    # nohup + redirect so frida-server survives adb shell exit
    # and adb shell returns immediately (no dangling stdout/stderr pipe)
    if listen_addr:
        bg_cmd = f"nohup {binary_path} -l {listen_addr} >/dev/null 2>&1 &"
    else:
        bg_cmd = f"nohup {binary_path} >/dev/null 2>&1 &"

    # Start in background via su
    adb_su(f"chmod 755 {binary_path}")
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
        frida_conn = FRIDA_CONN
        if "local" in selected:
            script_path = os.path.join(SCRIPT_DIR, selected["local"])
            if not os.path.exists(script_path):
                print(f"  {C.RED}[!] Script not found: {script_path}{C.RST}")
                continue
            if spawn:
                cmd = f'frida {frida_conn} -f {pkg} -l "{script_path}"'
            else:
                cmd = f'frida {frida_conn} {pkg} -l "{script_path}"'
        else:
            cs = selected["codeshare"]
            if spawn:
                cmd = f'frida --codeshare {cs} {frida_conn} -f {pkg}'
            else:
                cmd = f'frida --codeshare {cs} {frida_conn} {pkg}'

        print(f"\n  {C.CYAN}Running: {C.BOLD}{cmd}{C.RST}")
        print(f"  {C.DIM}Press Ctrl+C to stop Frida session{C.RST}\n")

        try:
            subprocess.run(cmd, shell=True)
        except KeyboardInterrupt:
            print(f"\n  {C.YELLOW}Frida session ended.{C.RST}")

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

    results, file_count = _search_decompiled(decompiled_dir, EMU_DETECTION_KEYWORDS, framework=fw_info["framework"])
    info_line("Scanned files", f"{file_count} files")

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
                    print(f"    {C.CYAN}{rel_path}:{line_no}{C.RST}")
                    display = line_text if len(line_text) <= 120 else line_text[:117] + "..."
                    print(f"    {C.DIM}{display}{C.RST}")
                    print(f"    {C.YELLOW}keyword: {keyword}{C.RST}")
        else:
            print(f"\n  {C.RED}[NOT FOUND]{C.RST} {group_name}")

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
    else:
        print(f"  {C.RED}{C.BOLD}RESULT: Emulator Detection NOT DETECTED{C.RST}")
        print(f"  {C.DIM}This app does not appear to check for emulators.{C.RST}")

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

    results, file_count = _search_decompiled(decompiled_dir, ANTI_TAMPER_KEYWORDS, framework=fw_info["framework"])
    info_line("Scanned files", f"{file_count} files")

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
                    print(f"    {C.CYAN}{rel_path}:{line_no}{C.RST}")
                    display = line_text if len(line_text) <= 120 else line_text[:117] + "..."
                    print(f"    {C.DIM}{display}{C.RST}")
                    print(f"    {C.YELLOW}keyword: {keyword}{C.RST}")
        else:
            print(f"\n  {C.RED}[NOT FOUND]{C.RST} {group_name}")

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
    else:
        print(f"  {C.RED}{C.BOLD}RESULT: Anti-Tamper / Security SDKs NOT DETECTED{C.RST}")
        print(f"  {C.DIM}This app does not appear to use security SDKs or anti-tamper.{C.RST}")

    pause()

# ─── Testcases for Fun ────────────────────────────────────────────────────────────

def _parse_exported_components(manifest):
    """Parse AndroidManifest.xml and return exported components with their intent-filter actions.

    Returns dict like:
        {"activity": [{"name": ".Foo", "actions": ["android.intent.action.VIEW"]}, ...], ...}
    """
    exported = {"activity": [], "service": [], "receiver": []}
    seen = {"activity": set(), "service": set(), "receiver": set()}

    for tag in exported:
        # Match full component blocks: <tag ...>...</tag>
        for block_m in re.finditer(
            rf'<{tag}\s([^>]*?)>(.*?)</{tag}>',
            manifest, re.IGNORECASE | re.DOTALL
        ):
            attrs, body = block_m.group(1), block_m.group(2)
            # Check exported="true"
            if not re.search(r'android:exported\s*=\s*"true"', attrs, re.IGNORECASE):
                continue
            # Extract name
            name_m = re.search(r'android:name\s*=\s*"([^"]+)"', attrs)
            if not name_m:
                continue
            name = name_m.group(1)
            if name in seen[tag]:
                continue
            seen[tag].add(name)
            # Extract actions from intent-filters
            actions = []
            for action_m in re.finditer(r'<action\s[^>]*android:name\s*=\s*"([^"]+)"', body):
                act = action_m.group(1)
                if act not in actions:
                    actions.append(act)
            exported[tag].append({"name": name, "actions": actions})

        # Also handle self-closing tags: <tag ... /> (no intent-filters possible)
        for m in re.finditer(
            rf'<{tag}\s([^>]*?)/\s*>',
            manifest, re.IGNORECASE
        ):
            attrs = m.group(1)
            if not re.search(r'android:exported\s*=\s*"true"', attrs, re.IGNORECASE):
                continue
            name_m = re.search(r'android:name\s*=\s*"([^"]+)"', attrs)
            if not name_m:
                continue
            name = name_m.group(1)
            if name in seen[tag]:
                continue
            seen[tag].add(name)
            exported[tag].append({"name": name, "actions": []})

    return exported

def fun_testcases(pkg):
    section("TESTCASES FOR FUN")

    while True:
        print(f"\n  {C.CYAN}{C.BOLD}── Test Cases for: {pkg} ──{C.RST}\n")
        print(f"  {C.YELLOW}[1]{C.RST} {C.WHITE}Launch Exported Activities{C.RST}")
        print(f"      {C.DIM}Start each exported activity (auth bypass check){C.RST}")
        print(f"  {C.YELLOW}[2]{C.RST} {C.WHITE}Launch Exported Services{C.RST}")
        print(f"      {C.DIM}Start each exported service{C.RST}")
        print(f"  {C.YELLOW}[3]{C.RST} {C.WHITE}Launch Broadcast Receivers{C.RST}")
        print(f"      {C.DIM}Send empty broadcast to each exported receiver{C.RST}")
        print(f"  {C.YELLOW}[4]{C.RST} {C.WHITE}Clipboard Spy{C.RST}")
        print(f"      {C.DIM}Read clipboard after user copies sensitive data{C.RST}")
        print(f"  {C.YELLOW}[5]{C.RST} {C.WHITE}Dev/Staging URL Finder{C.RST}")
        print(f"      {C.DIM}Search decompiled code for internal/dev URLs{C.RST}")
        print(f"\n  {C.DIM}[0] Back{C.RST}")

        choice = input(f"\n  {C.GREEN}Select test ▸ {C.RST}").strip()

        if choice == "0":
            return

        # ── Sub-options 1-3 need the manifest ────────────────────────────
        if choice in ("1", "2", "3"):
            work_dir, decompiled_dir = _pull_and_decompile(pkg)
            if not decompiled_dir:
                pause()
                continue
            manifest_path = os.path.join(decompiled_dir, "AndroidManifest.xml")
            try:
                with open(manifest_path, 'r', errors='ignore') as f:
                    manifest = f.read()
            except Exception:
                print(f"  {C.RED}[!] Could not read AndroidManifest.xml{C.RST}")
                pause()
                continue
            exported = _parse_exported_components(manifest)

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
                    cmd = f"am start -n {pkg}/{name}"
                    if comp['actions']:
                        cmd += f" -a {comp['actions'][0]}"
                    if extra_args:
                        cmd += f" {extra_args}"
                    print(f"\n  {C.DIM}$ {cmd}{C.RST}")
                    out = adb_shell(cmd, timeout=10)
                    if "Error" in out or "Exception" in out:
                        print(f"  {C.RED}[✗]{C.RST} {name}")
                        print(f"      {C.DIM}{out[:200]}{C.RST}")
                    else:
                        print(f"  {C.GREEN}[✓]{C.RST} {name} {C.YELLOW}— launched (potential auth bypass!){C.RST}")
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
                    cmd = f"am startservice -n {pkg}/{name}"
                    if comp['actions']:
                        cmd += f" -a {comp['actions'][0]}"
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
                    cmd = f"am broadcast -n {pkg}/{name}"
                    if comp['actions']:
                        cmd += f" -a {comp['actions'][0]}"
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
                print(f"  {C.WHITE}{C.BOLD}{clip_text}{C.RST}")
                print(f"\n  {C.YELLOW}If this contains sensitive data, the app may not be")
                print(f"  clearing the clipboard properly.{C.RST}")
            else:
                print(f"  {C.DIM}No readable clipboard content found.{C.RST}")
                print(f"  {C.DIM}Raw response:{C.RST}")
                print(f"  {C.DIM}{clip[:200] if clip else '(empty)'}{C.RST}")
            pause()

        elif choice == "5":
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

        else:
            print(f"  {C.RED}Invalid option.{C.RST}")
            time.sleep(0.5)

# ─── Frida Gadget APK Patcher ────────────────────────────────────────────────────

GADGET_URL = "https://github.com/frida/frida/releases/download/17.6.2/frida-gadget-17.6.2-android-arm64.so.xz"
GADGET_SO_NAME = "libfrida-gadget.so"

LSPATCH_URL = "https://github.com/LSPosed/LSPatch/releases/download/v0.6/jar-v0.6-398-release.jar"
LSPATCH_JAR_NAME = "lspatch.jar"

def _find_apktool():
    """Find apktool — standalone command or java -jar fallback."""
    if shutil.which("apktool"):
        return "apktool"
    for jar_path in [
        os.path.join(os.getcwd(), "apktool.jar"),
        os.path.join(os.path.expanduser("~"), "apktool.jar"),
    ]:
        if os.path.isfile(jar_path):
            if shutil.which("java"):
                return f'java -jar "{jar_path}"'
    return None

def _find_main_activity(manifest_path):
    """Parse AndroidManifest.xml to find the launcher activity."""
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        ns = "http://schemas.android.com/apk/res/android"
        package = root.get("package", "")

        for activity in root.iter("activity"):
            for intent_filter in activity.iter("intent-filter"):
                actions = [a.get(f"{{{ns}}}name") for a in intent_filter.iter("action")]
                categories = [c.get(f"{{{ns}}}name") for c in intent_filter.iter("category")]
                if ("android.intent.action.MAIN" in actions
                        and "android.intent.category.LAUNCHER" in categories):
                    name = activity.get(f"{{{ns}}}name", "")
                    if name.startswith("."):
                        name = package + name
                    elif "." not in name:
                        name = package + "." + name
                    return name
    except Exception as e:
        print(f"  {C.RED}[!] Manifest parse error: {e}{C.RST}")
    return None

def _patch_manifest_for_gadget(manifest_path):
    """Add INTERNET permission and set extractNativeLibs=true."""
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Add INTERNET permission if missing
        if 'android.permission.INTERNET' not in content:
            content = content.replace(
                '<application',
                '<uses-permission android:name="android.permission.INTERNET"/>\n    <application',
                1
            )
            print(f"  {C.GREEN}[+] Added INTERNET permission{C.RST}")

        # Set extractNativeLibs="true" so injected .so gets extracted
        if 'extractNativeLibs="false"' in content:
            content = content.replace('extractNativeLibs="false"', 'extractNativeLibs="true"')
            print(f"  {C.GREEN}[+] Set extractNativeLibs=true{C.RST}")

        with open(manifest_path, "w", encoding="utf-8") as f:
            f.write(content)
        return True
    except Exception as e:
        print(f"  {C.RED}[!] Manifest patch error: {e}{C.RST}")
        return False

def _inject_gadget_loader(smali_path):
    """Inject System.loadLibrary('frida-gadget') into smali class."""
    try:
        with open(smali_path, "r", encoding="utf-8") as f:
            content = f.read()

        load_lines = [
            '    const-string v0, "frida-gadget"',
            '',
            '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V',
        ]

        if ".method static constructor <clinit>()V" in content:
            # Inject into existing <clinit>
            lines = content.split('\n')
            new_lines = []
            in_clinit = False
            injected = False
            for line in lines:
                new_lines.append(line)
                if ".method static constructor <clinit>()V" in line:
                    in_clinit = True
                if in_clinit and not injected:
                    stripped = line.strip()
                    if stripped.startswith(".locals") or stripped.startswith(".registers"):
                        # Ensure at least 1 register
                        parts = stripped.split()
                        if len(parts) == 2 and int(parts[1]) < 1:
                            new_lines[-1] = line.replace(f"{parts[0]} 0", f"{parts[0]} 1")
                        new_lines.extend(load_lines)
                        injected = True
            if injected:
                content = '\n'.join(new_lines)
            else:
                return False

        elif "onCreate(Landroid/os/Bundle;)V" in content:
            # Inject into onCreate
            lines = content.split('\n')
            new_lines = []
            in_oncreate = False
            injected = False
            for line in lines:
                new_lines.append(line)
                if "onCreate(Landroid/os/Bundle;)V" in line and ".method" in line:
                    in_oncreate = True
                if in_oncreate and not injected:
                    stripped = line.strip()
                    if stripped.startswith(".locals") or stripped.startswith(".registers"):
                        parts = stripped.split()
                        if len(parts) == 2:
                            n = int(parts[1])
                            if stripped.startswith(".locals") and n < 1:
                                new_lines[-1] = line.replace(".locals 0", ".locals 1")
                            elif stripped.startswith(".registers") and n < 1:
                                new_lines[-1] = line.replace(".registers 0", ".registers 1")
                        new_lines.extend(load_lines)
                        injected = True
            if injected:
                content = '\n'.join(new_lines)
            else:
                return False
        else:
            # No <clinit> or onCreate — add a new <clinit>
            clinit_block = (
                '\n.method static constructor <clinit>()V\n'
                '    .registers 1\n'
                '\n'
                '    const-string v0, "frida-gadget"\n'
                '\n'
                '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n'
                '\n'
                '    return-void\n'
                '.end method\n'
            )
            if "\n.method " in content:
                idx = content.index("\n.method ") + 1
                content = content[:idx] + clinit_block + "\n" + content[idx:]
            else:
                content += "\n" + clinit_block

        with open(smali_path, "w", encoding="utf-8") as f:
            f.write(content)
        return True
    except Exception as e:
        print(f"  {C.RED}[!] Smali injection error: {e}{C.RST}")
        return False


def frida_gadget_patch(pkg):
    """Patch APK with Frida Gadget for non-root dynamic analysis."""
    section("FRIDA GADGET APK PATCHER")

    # ── Check dependencies ───────────────────────────────────────────────
    apktool_cmd = _find_apktool()
    if not apktool_cmd:
        print(f"  {C.RED}[!] apktool not found.{C.RST}")
        print(f"  {C.DIM}  Install: https://ibotpeaches.github.io/Apktool/{C.RST}")
        print(f"  {C.DIM}  Or place apktool.jar in current directory and ensure java is installed{C.RST}")
        pause()
        return

    signer = None
    if shutil.which("apksigner"):
        signer = "apksigner"
    elif shutil.which("jarsigner"):
        signer = "jarsigner"
    else:
        print(f"  {C.RED}[!] No signing tool found (apksigner or jarsigner).{C.RST}")
        print(f"  {C.DIM}  Install JDK for jarsigner or Android SDK build-tools for apksigner{C.RST}")
        pause()
        return

    if not shutil.which("keytool"):
        print(f"  {C.RED}[!] keytool not found — JDK is required for keystore generation.{C.RST}")
        pause()
        return

    print(f"  {C.GREEN}[+] apktool : {apktool_cmd}{C.RST}")
    print(f"  {C.GREEN}[+] signer  : {signer}{C.RST}")

    # ── Setup directories ────────────────────────────────────────────────
    work_dir = os.path.join(os.getcwd(), ".apkpatcher_work")
    patched_dir = os.path.join(os.getcwd(), "patched_apks")
    gadget_cache = os.path.join(os.getcwd(), ".gadget_cache")
    os.makedirs(work_dir, exist_ok=True)
    os.makedirs(patched_dir, exist_ok=True)
    os.makedirs(gadget_cache, exist_ok=True)

    try:
        # ── Step 1: Download Frida Gadget ────────────────────────────────
        gadget_so = os.path.join(gadget_cache, GADGET_SO_NAME)
        if not os.path.isfile(gadget_so):
            gadget_xz = os.path.join(gadget_cache, "frida-gadget.so.xz")
            print(f"\n  {C.CYAN}[*] Downloading Frida Gadget...{C.RST}")
            print(f"  {C.DIM}{GADGET_URL}{C.RST}")
            try:
                urllib.request.urlretrieve(GADGET_URL, gadget_xz)
            except Exception as e:
                print(f"  {C.RED}[!] Download failed: {e}{C.RST}")
                pause()
                return

            print(f"  {C.DIM}Extracting...{C.RST}")
            try:
                with lzma.open(gadget_xz) as f_in:
                    with open(gadget_so, "wb") as f_out:
                        f_out.write(f_in.read())
                os.remove(gadget_xz)
            except Exception as e:
                print(f"  {C.RED}[!] Extraction failed: {e}{C.RST}")
                pause()
                return
            print(f"  {C.GREEN}[+] Frida Gadget downloaded{C.RST}")
        else:
            print(f"\n  {C.GREEN}[+] Using cached Frida Gadget{C.RST}")

        # ── Step 2: Get APK ──────────────────────────────────────────────
        local_apk = None
        for search_dir in [os.path.join(os.getcwd(), "extracted_apks"), os.getcwd()]:
            if not os.path.isdir(search_dir):
                continue
            for root, dirs, files in os.walk(search_dir):
                if ".apkanalyzer_tmp" in root or ".apkpatcher_work" in root:
                    continue
                for fname in files:
                    if fname.endswith(".apk") and pkg in fname:
                        candidate = os.path.join(root, fname)
                        if os.path.getsize(candidate) > 0:
                            local_apk = candidate
                            break
                if local_apk:
                    break
            if local_apk:
                break

        if local_apk:
            print(f"  {C.GREEN}[+] Found local APK: {local_apk}{C.RST}")
        else:
            apk_path = get_apk_path(pkg)
            if not apk_path:
                print(f"  {C.RED}[!] Could not locate APK for {pkg}{C.RST}")
                pause()
                return
            local_apk = os.path.join(work_dir, f"{pkg}.apk")
            print(f"\n  {C.DIM}Pulling APK from device...{C.RST}")
            adb_pull(apk_path, local_apk)
            if not os.path.exists(local_apk) or os.path.getsize(local_apk) == 0:
                print(f"  {C.RED}[!] Failed to pull APK.{C.RST}")
                pause()
                return

        # ── Step 3: Decompile ────────────────────────────────────────────
        decompiled = os.path.join(work_dir, f"{pkg}_patched")
        if os.path.isdir(decompiled):
            shutil.rmtree(decompiled, ignore_errors=True)

        print(f"  {C.DIM}Decompiling APK...{C.RST}")
        try:
            r = subprocess.run(
                f'{apktool_cmd} d -f -o "{decompiled}" "{local_apk}"',
                shell=True, capture_output=True, text=True, timeout=300,
                encoding='utf-8', errors='replace'
            )
            if r.returncode != 0 or not os.path.isdir(decompiled):
                print(f"  {C.RED}[!] Decompilation failed:{C.RST}")
                print(f"  {C.DIM}{r.stderr[:400] if r.stderr else 'unknown error'}{C.RST}")
                pause()
                return
        except subprocess.TimeoutExpired:
            print(f"  {C.RED}[!] Decompilation timed out.{C.RST}")
            pause()
            return
        print(f"  {C.GREEN}[+] Decompiled successfully{C.RST}")

        # ── Step 4: Find main activity ───────────────────────────────────
        manifest = os.path.join(decompiled, "AndroidManifest.xml")
        if not os.path.isfile(manifest):
            print(f"  {C.RED}[!] AndroidManifest.xml not found{C.RST}")
            pause()
            return

        main_activity = _find_main_activity(manifest)
        if not main_activity:
            print(f"  {C.RED}[!] Could not determine launcher activity{C.RST}")
            pause()
            return
        print(f"  {C.GREEN}[+] Launcher: {main_activity}{C.RST}")

        # ── Step 5: Patch manifest ───────────────────────────────────────
        _patch_manifest_for_gadget(manifest)

        # ── Step 6: Inject gadget loader into smali ──────────────────────
        smali_relative = main_activity.replace(".", os.sep) + ".smali"
        smali_path = None
        for entry in sorted(os.listdir(decompiled)):
            if entry.startswith("smali"):
                candidate = os.path.join(decompiled, entry, smali_relative)
                if os.path.isfile(candidate):
                    smali_path = candidate
                    break

        if not smali_path:
            print(f"  {C.RED}[!] Smali not found for {main_activity}{C.RST}")
            pause()
            return

        print(f"  {C.DIM}Injecting gadget loader...{C.RST}")
        if not _inject_gadget_loader(smali_path):
            print(f"  {C.RED}[!] Failed to inject gadget loader{C.RST}")
            pause()
            return
        print(f"  {C.GREEN}[+] Gadget loader injected into smali{C.RST}")

        # ── Step 7: Copy gadget .so ──────────────────────────────────────
        lib_dir = os.path.join(decompiled, "lib", "arm64-v8a")
        os.makedirs(lib_dir, exist_ok=True)
        shutil.copy2(gadget_so, os.path.join(lib_dir, GADGET_SO_NAME))
        print(f"  {C.GREEN}[+] Copied {GADGET_SO_NAME} → lib/arm64-v8a/{C.RST}")

        # ── Step 8: Rebuild ──────────────────────────────────────────────
        rebuilt_apk = os.path.join(work_dir, f"{pkg}_rebuilt.apk")
        print(f"  {C.DIM}Rebuilding APK...{C.RST}")
        try:
            r = subprocess.run(
                f'{apktool_cmd} b -o "{rebuilt_apk}" "{decompiled}"',
                shell=True, capture_output=True, text=True, timeout=300,
                encoding='utf-8', errors='replace'
            )
            if r.returncode != 0 or not os.path.isfile(rebuilt_apk):
                print(f"  {C.RED}[!] Rebuild failed:{C.RST}")
                print(f"  {C.DIM}{r.stderr[:400] if r.stderr else 'unknown error'}{C.RST}")
                pause()
                return
        except subprocess.TimeoutExpired:
            print(f"  {C.RED}[!] Rebuild timed out.{C.RST}")
            pause()
            return
        print(f"  {C.GREEN}[+] APK rebuilt{C.RST}")

        # ── Step 9: Sign ─────────────────────────────────────────────────
        keystore = os.path.join(gadget_cache, "debug.keystore")
        if not os.path.isfile(keystore):
            print(f"  {C.DIM}Generating debug keystore...{C.RST}")
            subprocess.run(
                f'keytool -genkeypair -v -keystore "{keystore}" '
                f'-alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 '
                f'-storepass android -keypass android '
                f'-dname "CN=Android Debug,O=Android,C=US"',
                shell=True, capture_output=True, text=True, timeout=30
            )

        signed_apk = os.path.join(work_dir, f"{pkg}_signed.apk")
        print(f"  {C.DIM}Signing APK with {signer}...{C.RST}")

        if signer == "apksigner":
            # zipalign first if available
            zipaligned = os.path.join(work_dir, f"{pkg}_aligned.apk")
            if shutil.which("zipalign"):
                subprocess.run(
                    f'zipalign -f 4 "{rebuilt_apk}" "{zipaligned}"',
                    shell=True, capture_output=True, text=True, timeout=60
                )
                to_sign = zipaligned
            else:
                to_sign = rebuilt_apk

            r = subprocess.run(
                f'apksigner sign --ks "{keystore}" --ks-pass pass:android '
                f'--ks-key-alias androiddebugkey --key-pass pass:android '
                f'--out "{signed_apk}" "{to_sign}"',
                shell=True, capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
        else:
            # jarsigner signs in-place
            shutil.copy2(rebuilt_apk, signed_apk)
            r = subprocess.run(
                f'jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 '
                f'-keystore "{keystore}" -storepass android -keypass android '
                f'"{signed_apk}" androiddebugkey',
                shell=True, capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            # zipalign after jarsigner if available
            if shutil.which("zipalign"):
                aligned = os.path.join(work_dir, f"{pkg}_aligned.apk")
                subprocess.run(
                    f'zipalign -f 4 "{signed_apk}" "{aligned}"',
                    shell=True, capture_output=True, text=True, timeout=60
                )
                shutil.move(aligned, signed_apk)

        if r.returncode != 0:
            print(f"  {C.RED}[!] Signing failed:{C.RST}")
            print(f"  {C.DIM}{r.stderr[:400] if r.stderr else r.stdout[:400]}{C.RST}")
            pause()
            return
        print(f"  {C.GREEN}[+] APK signed{C.RST}")

        # ── Step 10: Move to patched_apks/ ───────────────────────────────
        final_name = f"{pkg}_gadget_patched.apk"
        final_path = os.path.join(patched_dir, final_name)
        shutil.move(signed_apk, final_path)

        print(f"\n  {C.GREEN}{C.BOLD}{'='*50}{C.RST}")
        print(f"  {C.GREEN}{C.BOLD}[✓] PATCHED APK READY{C.RST}")
        print(f"  {C.GREEN}{C.BOLD}{'='*50}{C.RST}")
        print(f"  {C.WHITE}{final_path}{C.RST}")
        print(f"\n  {C.CYAN}To install:{C.RST}")
        print(f"  {C.DIM}  adb uninstall {pkg}{C.RST}")
        print(f'  {C.DIM}  adb install "{final_path}"{C.RST}')
        print(f"\n  {C.CYAN}Then launch the app — Frida Gadget will listen on port 27042.{C.RST}")
        print(f"  {C.DIM}  frida {FRIDA_CONN} -n Gadget{C.RST}")

    finally:
        # Clean up work dir
        if os.path.isdir(work_dir):
            shutil.rmtree(work_dir, ignore_errors=True)

    pause()


# ─── LSPatch APK Patcher ─────────────────────────────────────────────────────────

def lspatch_patch(pkg):
    """Patch APK with LSPatch for Xposed/LSPosed module loading."""
    section("LSPATCH APK PATCHER")

    # ── Check dependencies ───────────────────────────────────────────────
    if not shutil.which("java"):
        print(f"  {C.RED}[!] java not found — JDK/JRE is required for LSPatch.{C.RST}")
        print(f"  {C.DIM}  Install a JDK (e.g. openjdk-17-jdk) and ensure java is on PATH{C.RST}")
        pause()
        return

    print(f"  {C.GREEN}[+] java : {shutil.which('java')}{C.RST}")

    # ── Setup directories ────────────────────────────────────────────────
    gadget_cache = os.path.join(os.getcwd(), ".gadget_cache")
    patched_dir = os.path.join(os.getcwd(), "patched_apks")
    os.makedirs(gadget_cache, exist_ok=True)
    os.makedirs(patched_dir, exist_ok=True)

    # ── Download LSPatch jar if not cached ───────────────────────────────
    lspatch_jar = os.path.join(gadget_cache, LSPATCH_JAR_NAME)
    if not os.path.isfile(lspatch_jar):
        print(f"\n  {C.CYAN}[*] Downloading LSPatch jar...{C.RST}")
        print(f"  {C.DIM}{LSPATCH_URL}{C.RST}")
        try:
            urllib.request.urlretrieve(LSPATCH_URL, lspatch_jar)
        except Exception as e:
            print(f"  {C.RED}[!] Download failed: {e}{C.RST}")
            pause()
            return
        print(f"  {C.GREEN}[+] LSPatch jar downloaded{C.RST}")
    else:
        print(f"\n  {C.GREEN}[+] Using cached LSPatch jar{C.RST}")

    # ── Locate APK ───────────────────────────────────────────────────────
    local_apk = None
    for search_dir in [os.path.join(os.getcwd(), "extracted_apks"), os.getcwd()]:
        if not os.path.isdir(search_dir):
            continue
        for root, dirs, files in os.walk(search_dir):
            if ".apkanalyzer_tmp" in root or ".apkpatcher_work" in root:
                continue
            for fname in files:
                if fname.endswith(".apk") and pkg in fname:
                    candidate = os.path.join(root, fname)
                    if os.path.getsize(candidate) > 0:
                        local_apk = candidate
                        break
            if local_apk:
                break
        if local_apk:
            break

    if local_apk:
        print(f"  {C.GREEN}[+] Found local APK: {local_apk}{C.RST}")
    else:
        apk_path = get_apk_path(pkg)
        if not apk_path:
            print(f"  {C.RED}[!] Could not locate APK for {pkg}{C.RST}")
            pause()
            return
        work_dir = os.path.join(os.getcwd(), ".apkpatcher_work")
        os.makedirs(work_dir, exist_ok=True)
        local_apk = os.path.join(work_dir, f"{pkg}.apk")
        print(f"\n  {C.DIM}Pulling APK from device...{C.RST}")
        adb_pull(apk_path, local_apk)
        if not os.path.exists(local_apk) or os.path.getsize(local_apk) == 0:
            print(f"  {C.RED}[!] Failed to pull APK.{C.RST}")
            pause()
            return

    # ── Run LSPatch ──────────────────────────────────────────────────────
    print(f"\n  {C.CYAN}[*] Running LSPatch...{C.RST}")
    print(f"  {C.DIM}  -d (debuggable)  -v (verbose)  -l 2 (sig-bypass level 2){C.RST}")
    try:
        r = subprocess.run(
            f'java -jar "{lspatch_jar}" "{local_apk}" -d -v -l 2 -o "{patched_dir}"',
            shell=True, capture_output=True, text=True, timeout=300,
            encoding='utf-8', errors='replace'
        )
        print(f"  {C.DIM}{r.stdout[-800:] if r.stdout else ''}{C.RST}")
        if r.returncode != 0:
            print(f"  {C.RED}[!] LSPatch failed (exit {r.returncode}):{C.RST}")
            print(f"  {C.DIM}{r.stderr[:600] if r.stderr else 'unknown error'}{C.RST}")
            pause()
            return
    except subprocess.TimeoutExpired:
        print(f"  {C.RED}[!] LSPatch timed out.{C.RST}")
        pause()
        return

    print(f"\n  {C.GREEN}{C.BOLD}{'='*50}{C.RST}")
    print(f"  {C.GREEN}{C.BOLD}[✓] LSPATCH COMPLETE{C.RST}")
    print(f"  {C.GREEN}{C.BOLD}{'='*50}{C.RST}")
    print(f"  {C.WHITE}Output directory: {patched_dir}{C.RST}")
    print(f"\n  {C.CYAN}To install:{C.RST}")
    print(f"  {C.DIM}  adb uninstall {pkg}{C.RST}")
    print(f'  {C.DIM}  adb install "<patched_apk_from_output_dir>"{C.RST}')
    print(f"\n  {C.CYAN}The patched APK can load LSPosed/Xposed modules without root.{C.RST}")
    pause()


# ─── Binary Patcher (sub-menu) ───────────────────────────────────────────────────

def binary_patcher(pkg):
    """Sub-menu: choose between Frida Gadget and LSPatch patching."""
    section("BINARY PATCHER")
    print(f"  {C.CYAN}Choose a patching method:{C.RST}\n")
    print(f"  {C.YELLOW}[1]{C.RST} Frida Gadget  — inject frida-gadget.so (Frida hooking)")
    print(f"  {C.YELLOW}[2]{C.RST} LSPatch       — embed LSPosed/Xposed framework (Xposed modules)")
    print(f"  {C.YELLOW}[0]{C.RST} Back\n")
    ch = input(f"  {C.WHITE}Select [{C.YELLOW}1{C.WHITE}/{C.YELLOW}2{C.WHITE}/{C.YELLOW}0{C.WHITE}]: {C.RST}").strip()
    if ch == "1":
        frida_gadget_patch(pkg)
    elif ch == "2":
        lspatch_patch(pkg)
    else:
        return


# ─── Frida Server Config ─────────────────────────────────────────────────────────

def frida_server_config():
    global FRIDA_CONN
    section("FRIDA SERVER CONFIG")

    print(f"\n  {C.CYAN}Current connection mode: {C.BOLD}{FRIDA_CONN}{C.RST}\n")
    print(f"  {C.YELLOW}[1]{C.RST} USB default (frida -U)")
    print(f"  {C.YELLOW}[2]{C.RST} Custom port (frida -H ip:port)")
    print(f"  {C.YELLOW}[3]{C.RST} Restart frida-server (default)")
    print(f"  {C.YELLOW}[4]{C.RST} Restart frida-server on custom port")
    print(f"  {C.YELLOW}[5]{C.RST} Kill frida-server")
    print(f"  {C.DIM}[0] Back{C.RST}")

    choice = input(f"\n  {C.GREEN}Select ▸ {C.RST}").strip()

    if choice == "1":
        FRIDA_CONN = "-U"
        # Restart on default
        start_frida_server(FRIDA_SERVER_PATH)
        print(f"  {C.GREEN}[+] Connection mode: -U (USB default){C.RST}")

    elif choice == "2":
        addr = input(f"  {C.GREEN}Enter ip:port (e.g. 127.0.0.1:4444) ▸ {C.RST}").strip()
        if addr:
            port = addr.split(":")[-1]
            listen_addr = f"0.0.0.0:{port}"
            if start_frida_server(FRIDA_SERVER_PATH, listen_addr):
                adb(f"forward tcp:{port} tcp:{port}")
                FRIDA_CONN = f"-H {addr}"
                print(f"  {C.GREEN}[+] Frida-server started on {listen_addr}{C.RST}")
                print(f"  {C.GREEN}[+] Connection mode: {FRIDA_CONN}{C.RST}")
                print(f"  {C.DIM}adb forward tcp:{port} tcp:{port}{C.RST}")
            else:
                print(f"  {C.RED}[-] Failed to start frida-server on {listen_addr}{C.RST}")

    elif choice == "3":
        if start_frida_server(FRIDA_SERVER_PATH):
            FRIDA_CONN = "-U"
            print(f"  {C.GREEN}[+] Frida-server restarted (USB default){C.RST}")
        else:
            print(f"  {C.RED}[-] Failed to start frida-server{C.RST}")

    elif choice == "4":
        addr = input(f"  {C.GREEN}Listen address (e.g. 0.0.0.0:4444) ▸ {C.RST}").strip()
        if addr:
            if start_frida_server(FRIDA_SERVER_PATH, addr):
                port = addr.split(":")[-1]
                adb(f"forward tcp:{port} tcp:{port}")
                FRIDA_CONN = f"-H 127.0.0.1:{port}"
                print(f"  {C.GREEN}[+] Frida-server started on {addr}{C.RST}")
                print(f"  {C.GREEN}[+] Connection mode: {FRIDA_CONN}{C.RST}")
                print(f"  {C.DIM}adb forward tcp:{port} tcp:{port}{C.RST}")
            else:
                print(f"  {C.RED}[-] Failed to start frida-server{C.RST}")

    elif choice == "5":
        adb_su("pkill -f frida-server 2>/dev/null")
        print(f"  {C.GREEN}[+] Frida-server killed{C.RST}")

    pause()

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
  ║                                          ║
  ║  {C.YELLOW}[a]{C.CYAN} Switch App                          ║
  ║  {C.DIM}[0] Exit{C.CYAN}                                ║
  ║                                          ║
  ╚══════════════════════════════════════════╝{C.RST}
""")

def main():
    clear()
    banner()
    print(f"  {C.CYAN}Connecting to device...{C.RST}\n")

    device = check_device()
    if not device:
        print(f"  {C.RED}[✗] No device connected.{C.RST}")
        print(f"  {C.DIM}Make sure USB debugging is enabled and the device is connected.{C.RST}")
        print(f"  {C.DIM}Run 'adb devices' to verify.{C.RST}")
        sys.exit(1)

    has_root = check_root()

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
        print(f"\n  {C.CYAN}Goodbye.{C.RST}\n")
        return

    # Options that require a selected app
    APP_REQUIRED = {"1", "2", "5", "7", "8", "9", "11"}

    while True:
        main_menu(device, has_root, selected_pkg)
        try:
            choice = input(f"  {C.GREEN}Select option ▸ {C.RST}").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {C.CYAN}Goodbye.{C.RST}\n")
            break

        if choice.lower() == "a":
            apps = list_third_party_apps()
            new_pkg = pick_app(apps)
            if new_pkg:
                selected_pkg = new_pkg
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
        elif choice == "0":
            print(f"\n  {C.CYAN}Goodbye.{C.RST}\n")
            break
        else:
            print(f"  {C.RED}Invalid option.{C.RST}")
            time.sleep(0.5)

if __name__ == "__main__":
    main()
