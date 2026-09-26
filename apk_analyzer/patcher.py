"""Frida Gadget and LSPatch packaging.

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


GADGET_VERSION = "17.6.2"  # fallback when the local frida version can't be determined
GADGET_SO_NAME = "libfrida-gadget.so"

LSPATCH_URL = "https://github.com/LSPosed/LSPatch/releases/download/v0.6/jar-v0.6-398-release.jar"
LSPATCH_JAR_NAME = "lspatch.jar"
LSPATCH_SHA256 = "c179d884cb5dda151d6066320a2cf3658b4c15160306a0af2bd4c71faf6c3540"


def _file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download_file(url, destination, max_bytes, expected_sha256=None):
    """Download an HTTPS asset with limits, validation, and atomic replace."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("only HTTPS downloads are allowed")

    partial = destination + ".part"
    try:
        if os.path.exists(partial):
            os.remove(partial)
        request = urllib.request.Request(url, headers={"User-Agent": "APK-Analyzer"})
        # The initial and final schemes are both constrained to HTTPS.
        with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310
            final_url = urllib.parse.urlparse(response.geturl())
            if final_url.scheme != "https":
                raise ValueError("download redirected to a non-HTTPS URL")
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > max_bytes:
                raise ValueError("download exceeds size limit")
            digest = hashlib.sha256()
            size = 0
            with open(partial, "xb") as output:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > max_bytes:
                        raise ValueError("download exceeds size limit")
                    digest.update(chunk)
                    output.write(chunk)
        if size == 0:
            raise ValueError("download was empty")
        actual = digest.hexdigest()
        if expected_sha256 and actual.lower() != expected_sha256.lower():
            raise ValueError(f"SHA-256 mismatch (got {actual})")
        os.replace(partial, destination)
        return actual
    finally:
        if os.path.exists(partial):
            os.remove(partial)


def _github_asset_sha256(repository, tag, asset_name):
    """Read a published SHA-256 digest from GitHub release metadata."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        return None
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", tag):
        return None
    api_url = (
        f"https://api.github.com/repos/{repository}/releases/tags/"
        f"{urllib.parse.quote(tag)}"
    )
    request = urllib.request.Request(
        api_url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "APK-Analyzer"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:  # nosec B310
            final = urllib.parse.urlparse(response.geturl())
            if final.scheme != "https" or final.hostname != "api.github.com":
                return None
            data = response.read(10 * 1024 * 1024 + 1)
            if len(data) > 10 * 1024 * 1024:
                return None
        release = json.loads(data.decode("utf-8"))
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError):
        return None
    for asset in release.get("assets", []):
        if asset.get("name") == asset_name:
            digest = asset.get("digest") or ""
            if re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest):
                return digest.split(":", 1)[1].lower()
    return None


def _extract_xz_elf(source, destination, max_bytes=256 * 1024 * 1024):
    """Bounded extraction for a Frida Gadget XZ asset."""
    partial = destination + ".part"
    try:
        if os.path.exists(partial):
            os.remove(partial)
        total = 0
        with lzma.open(source, "rb") as compressed, open(partial, "xb") as output:
            while True:
                chunk = compressed.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError("decompressed Gadget exceeds size limit")
                output.write(chunk)
        with open(partial, "rb") as fh:
            if fh.read(4) != b"\x7fELF":
                raise ValueError("downloaded Gadget is not an ELF library")
        os.replace(partial, destination)
    finally:
        if os.path.exists(partial):
            os.remove(partial)


def _get_frida_gadget(cache_dir, version, arch):
    """Return a validated cached/downloaded Frida Gadget for one ABI."""
    gadget_so = os.path.join(
        cache_dir, f"frida-gadget-{version}-android-{arch}.so"
    )
    if os.path.isfile(gadget_so):
        try:
            with open(gadget_so, "rb") as cached:
                if cached.read(4) == b"\x7fELF":
                    print(f"  {C.GREEN}[+] Using cached Frida Gadget ({arch}){C.RST}")
                    return gadget_so
        except OSError:
            pass
        os.remove(gadget_so)

    asset_name = f"frida-gadget-{version}-android-{arch}.so.xz"
    gadget_url = (f"https://github.com/frida/frida/releases/download/{version}/"
                  f"{asset_name}")
    gadget_xz = gadget_so + ".xz"
    print(f"\n  {C.CYAN}[*] Downloading Frida Gadget (v{version} / {arch})...{C.RST}")
    print(f"  {C.DIM}{gadget_url}{C.RST}")
    expected_sha256 = _github_asset_sha256("frida/frida", version, asset_name)
    if expected_sha256 is None:
        print(f"  {C.YELLOW}[!] GitHub did not publish an asset digest; validating format only.{C.RST}")
    _download_file(
        gadget_url, gadget_xz, max_bytes=128 * 1024 * 1024,
        expected_sha256=expected_sha256,
    )
    try:
        _extract_xz_elf(gadget_xz, gadget_so)
    finally:
        if os.path.exists(gadget_xz):
            os.remove(gadget_xz)
    print(f"  {C.GREEN}[+] Frida Gadget downloaded ({arch}){C.RST}")
    return gadget_so

def _safe_native_executable(name):
    """Resolve a tool that will not be dispatched through a batch shell."""
    executable = process_mod.safe_which(name, which=shutil.which)
    if executable and not executable.lower().endswith((".bat", ".cmd")):
        return executable
    return None


def _safe_java_executable():
    """Return Java only when it has native argv semantics."""
    return _safe_native_executable("java")


def _resolve_apksigner_command():
    """Resolve apksigner without invoking a Windows batch wrapper."""
    executable = process_mod.safe_which("apksigner", which=shutil.which)
    if not executable:
        return None
    if not executable.lower().endswith((".bat", ".cmd")):
        return [executable]
    sibling_jar = os.path.join(
        os.path.dirname(executable), "lib", "apksigner.jar"
    )
    java = _safe_java_executable()
    if java and os.path.isfile(sibling_jar):
        return [java, "-jar", sibling_jar]
    return None


def _find_apktool():
    """Find apktool — standalone command or java -jar fallback.
    Returns a list of args (e.g. ["apktool"] or ["java", "-jar", "/path/to/apktool.jar"])."""
    executable = process_mod.safe_which("apktool", which=shutil.which)
    if executable:
        if not executable.lower().endswith((".bat", ".cmd")):
            return [executable]
        sibling_jar = os.path.join(os.path.dirname(executable), "apktool.jar")
        java = _safe_java_executable()
        if os.path.isfile(sibling_jar) and java:
            return [java, "-jar", sibling_jar]
    # Do not auto-execute an apktool.jar from the current working directory:
    # headless scans are commonly launched inside untrusted project trees.
    # A per-user fallback retains the historical no-PATH convenience without
    # treating APK-adjacent content as executable tooling.
    for jar_path in [
        os.path.join(os.path.expanduser("~"), "apktool.jar"),
    ]:
        if os.path.isfile(jar_path):
            java = _safe_java_executable()
            if java:
                return [java, "-jar", jar_path]
    return None

def _find_main_activity(manifest_path):
    """Parse AndroidManifest.xml to find the launcher activity."""
    try:
        tree = _safe_parse_xml(manifest_path)
        root = tree.getroot()
        ns = _ANDROID_NS
        package = root.get("package", "")

        for activity in list(root.iter("activity")) + list(root.iter("activity-alias")):
            for intent_filter in activity.iter("intent-filter"):
                actions = [a.get(f"{{{ns}}}name") for a in intent_filter.iter("action")]
                categories = [c.get(f"{{{ns}}}name") for c in intent_filter.iter("category")]
                if ("android.intent.action.MAIN" in actions
                        and "android.intent.category.LAUNCHER" in categories):
                    name = (activity.get(f"{{{ns}}}targetActivity")
                            or activity.get(f"{{{ns}}}name", ""))
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
        ET.register_namespace("android", _ANDROID_NS)
        tree = _safe_parse_xml(manifest_path)
        root = tree.getroot()
        ns_name = f"{{{_ANDROID_NS}}}name"

        permissions = {
            node.get(ns_name) for node in root.findall("uses-permission")
        }
        if "android.permission.INTERNET" not in permissions:
            permission = ET.Element("uses-permission")
            permission.set(ns_name, "android.permission.INTERNET")
            app_index = next(
                (i for i, child in enumerate(root) if child.tag == "application"),
                len(root),
            )
            root.insert(app_index, permission)
            print(f"  {C.GREEN}[+] Added INTERNET permission{C.RST}")

        app = root.find("application")
        if app is None:
            raise ValueError("manifest has no application element")
        extract_attr = f"{{{_ANDROID_NS}}}extractNativeLibs"
        if app.get(extract_attr) != "true":
            app.set(extract_attr, "true")
            print(f"  {C.GREEN}[+] Set extractNativeLibs=true{C.RST}")

        tree.write(manifest_path, encoding="utf-8", xml_declaration=True)
        return True
    except (ET.ParseError, OSError, ValueError) as e:
        print(f"  {C.RED}[!] Manifest patch error: {e}{C.RST}")
        return False

def _inject_gadget_loader(smali_path):
    """Inject System.loadLibrary('frida-gadget') into a static initializer."""
    try:
        with open(smali_path, "r", encoding="utf-8") as f:
            content = f.read()

        existing_loader = re.search(
            r"(?ms)^\s*\.method\b[^\r\n]*<clinit>\(\)V\s*$"
            r"(?P<body>.*?)^\s*\.end\s+method\s*$",
            content,
        )
        if (existing_loader
                and re.search(
                    r'(?m)^[ \t]*const-string v0, "frida-gadget"[ \t]*\r?$'
                    r'(?:\n[ \t]*\r?)*\n[ \t]*invoke-static \{v0\},[ \t]*'
                    r'Ljava/lang/System;->loadLibrary\(Ljava/lang/String;\)V[ \t]*\r?$',
                    existing_loader.group("body"),
                )):
            return True

        load_lines = [
            '    const-string v0, "frida-gadget"',
            '',
            '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V',
        ]

        clinit_match = re.search(
            r"(?m)^\s*\.method\b[^\r\n]*<clinit>\(\)V\s*$", content
        )
        if clinit_match:
            # Inject into existing <clinit>
            lines = content.split('\n')
            new_lines = []
            in_clinit = False
            injected = False
            for line in lines:
                new_lines.append(line)
                if re.match(r"^\s*\.method\b[^\r\n]*<clinit>\(\)V\s*$", line):
                    in_clinit = True
                if in_clinit and not injected:
                    frame = re.match(
                        r"^(\s*)\.(locals|registers)\s+(\d+)(.*)$", line
                    )
                    if frame:
                        # Ensure at least 1 register
                        indent, directive, count, suffix = frame.groups()
                        if int(count) < 1:
                            new_lines[-1] = (
                                f"{indent}.{directive} 1{suffix}"
                            )
                        new_lines.extend(load_lines)
                        injected = True
                if in_clinit and line.strip() == ".end method":
                    in_clinit = False
            if injected:
                content = '\n'.join(new_lines)
            else:
                return False
        else:
            # Never grow an instance method's frame: doing so shifts absolute
            # v-register aliases for its parameters. A new static initializer
            # has no parameter registers and is safe for this loader.
            clinit_block = (
                '\n.method static constructor <clinit>()V\n'
                '    .registers 3\n'
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


def _refuse_split_apk_patch(pkg, installed_paths=None):
    """Stop single-APK patchers before writes when the install has splits."""
    if installed_paths is None:
        installed_paths = get_apk_paths(pkg)
    if len(installed_paths) <= 1:
        return False
    print(
        f"  {C.RED}[!] This package uses {len(installed_paths)} installed APK "
        f"artifacts. Single-APK patching would produce an incomplete, "
        f"non-installable result, so no files were changed.{C.RST}"
    )
    print(
        f"  {C.DIM}Split-aware patch/re-sign/install is not implemented yet.{C.RST}"
    )
    pause()
    return True


def _run_patcher_tool(args, timeout, operation):
    """Run a patch/sign tool without letting launch failures escape the menu."""
    try:
        return _process_run_command_capture(
            list(args),
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"  {C.RED}[!] {operation} timed out.{C.RST}")
    except OSError as exc:
        print(f"  {C.RED}[!] Could not start {operation}: {_terminal_safe(exc)}{C.RST}")
    except (ValueError, CommandOutputLimitExceeded) as exc:
        print(f"  {C.RED}[!] {operation} failed safely: {_terminal_safe(exc)}{C.RST}")
    return None


def frida_gadget_patch(pkg):
    """Patch APK with Frida Gadget for non-root dynamic analysis."""
    section("FRIDA GADGET APK PATCHER")

    installed_apk_paths = get_apk_paths(pkg)
    if _refuse_split_apk_patch(pkg, installed_apk_paths):
        return

    # ── Check dependencies ───────────────────────────────────────────────
    apktool_cmd = _find_apktool()
    if not apktool_cmd:
        print(f"  {C.RED}[!] apktool not found.{C.RST}")
        print(f"  {C.DIM}  Install: https://ibotpeaches.github.io/Apktool/{C.RST}")
        print(f"  {C.DIM}  Or place apktool.jar in your home directory and ensure java is installed{C.RST}")
        pause()
        return

    signer = None
    apksigner_command = _resolve_apksigner_command()
    jarsigner_path = _safe_native_executable("jarsigner")
    keytool_path = _safe_native_executable("keytool")
    if apksigner_command:
        signer = "apksigner"
    elif jarsigner_path:
        signer = "jarsigner"
    else:
        print(f"  {C.RED}[!] No signing tool found (apksigner or jarsigner).{C.RST}")
        print(f"  {C.DIM}  Install JDK for jarsigner or Android SDK build-tools for apksigner{C.RST}")
        pause()
        return

    if not keytool_path:
        print(f"  {C.RED}[!] keytool not found — JDK is required for keystore generation.{C.RST}")
        pause()
        return

    print(f"  {C.GREEN}[+] apktool : {' '.join(apktool_cmd)}{C.RST}")
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
        # Detect device ABI → frida release arch
        abi = adb_shell("getprop ro.product.cpu.abi").strip()
        arch_map = {"arm64-v8a": "arm64", "armeabi-v7a": "arm", "armeabi": "arm",
                    "x86": "x86", "x86_64": "x86_64"}
        if abi not in arch_map:
            print(f"  {C.YELLOW}[!] Unrecognized device ABI '{abi or 'unknown'}' — defaulting to arm64.{C.RST}")
            abi = "arm64-v8a"

        # Match the gadget version to the local frida install when possible
        frida_ok, frida_ver = check_frida()
        ver = GADGET_VERSION
        if frida_ok:
            m = re.match(r'\d+\.\d+\.\d+', frida_ver.strip())
            if m:
                ver = m.group()

        # ── Step 2: Get APK ──────────────────────────────────────────────
        local_apk = _find_local_apk(pkg)

        if local_apk:
            print(f"  {C.GREEN}[+] Found local APK: {local_apk}{C.RST}")
        else:
            apk_path = installed_apk_paths[0] if installed_apk_paths else ""
            if not apk_path:
                print(f"  {C.RED}[!] Could not locate APK for {pkg}{C.RST}")
                pause()
                return
            local_apk = os.path.join(work_dir, f"{pkg}.apk")
            print(f"\n  {C.DIM}Pulling APK from device...{C.RST}")
            pull_result = adb_pull(apk_path, local_apk)
            if (_is_err(pull_result) or not os.path.exists(local_apk)
                    or os.path.getsize(local_apk) == 0):
                print(f"  {C.RED}[!] Failed to pull APK.{C.RST}")
                pause()
                return

        try:
            _preflight_apk_artifacts([local_apk], work_dir)
        except (input_mod.InputPreparationError, OSError, ValueError) as exc:
            print(
                f"  {C.RED}[!] APK failed safety validation: "
                f"{_headless_diagnostic(exc, 400)}{C.RST}"
            )
            pause()
            return

        # ── Step 3: Decompile ────────────────────────────────────────────
        decompiled = os.path.join(work_dir, f"{pkg}_patched")
        if os.path.isdir(decompiled):
            shutil.rmtree(decompiled, ignore_errors=True)

        frame_path = os.path.join(work_dir, "apktool_framework")
        os.makedirs(frame_path, exist_ok=True)
        print(f"  {C.DIM}Decompiling APK...{C.RST}")
        r = _run_patcher_tool(
            apktool_cmd + [
                "d", "-f", "--frame-path", frame_path,
                "-o", decompiled, local_apk,
            ],
            300,
            "apktool decompilation",
        )
        if r is None:
            pause()
            return
        if r.returncode != 0 or not os.path.isdir(decompiled):
            print(f"  {C.RED}[!] Decompilation failed:{C.RST}")
            detail = r.stderr or r.stdout or "unknown error"
            print(
                f"  {C.DIM}{_headless_safe_text(detail, 400)}{C.RST}"
            )
            pause()
            return
        print(f"  {C.GREEN}[+] Decompiled successfully{C.RST}")

        # Match Gadget libraries to the APK's ABIs. Adding only the device's
        # primary ABI can make a 32-bit-only APK look 64-bit-capable and crash
        # when Android selects an incomplete native library directory.
        existing_abis = []
        decompiled_lib = os.path.join(decompiled, "lib")
        if os.path.isdir(decompiled_lib):
            existing_abis = [
                entry for entry in sorted(os.listdir(decompiled_lib))
                if entry in arch_map and os.path.isdir(os.path.join(decompiled_lib, entry))
            ]
        target_abis = existing_abis or [abi]
        gadgets = {}
        try:
            for target_abi in target_abis:
                gadgets[target_abi] = _get_frida_gadget(
                    gadget_cache, ver, arch_map[target_abi]
                )
        except (OSError, ValueError, lzma.LZMAError, urllib.error.URLError) as e:
            print(f"  {C.RED}[!] Frida Gadget download/extraction failed: {e}{C.RST}")
            pause()
            return

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
        if not _patch_manifest_for_gadget(manifest):
            pause()
            return

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
        for target_abi, gadget_so in gadgets.items():
            lib_dir = os.path.join(decompiled, "lib", target_abi)
            os.makedirs(lib_dir, exist_ok=True)
            shutil.copy2(gadget_so, os.path.join(lib_dir, GADGET_SO_NAME))
            print(f"  {C.GREEN}[+] Copied {GADGET_SO_NAME} → lib/{target_abi}/{C.RST}")

        # ── Step 8: Rebuild ──────────────────────────────────────────────
        rebuilt_apk = os.path.join(work_dir, f"{pkg}_rebuilt.apk")
        print(f"  {C.DIM}Rebuilding APK...{C.RST}")
        r = _run_patcher_tool(
            apktool_cmd + [
                "b", "--frame-path", frame_path,
                "-o", rebuilt_apk, decompiled,
            ],
            300,
            "apktool rebuild",
        )
        if r is None:
            pause()
            return
        if r.returncode != 0 or not os.path.isfile(rebuilt_apk):
            print(f"  {C.RED}[!] Rebuild failed:{C.RST}")
            detail = r.stderr or r.stdout or "unknown error"
            print(
                f"  {C.DIM}{_headless_safe_text(detail, 400)}{C.RST}"
            )
            pause()
            return
        print(f"  {C.GREEN}[+] APK rebuilt{C.RST}")

        # ── Step 9: Sign ─────────────────────────────────────────────────
        keystore = os.path.join(gadget_cache, "debug.keystore")
        if not os.path.isfile(keystore):
            print(f"  {C.DIM}Generating debug keystore...{C.RST}")
            keytool_result = _run_patcher_tool(
                [keytool_path, "-genkeypair", "-v", "-keystore", keystore,
                 "-alias", "androiddebugkey", "-keyalg", "RSA", "-keysize", "2048",
                 "-validity", "10000", "-storepass", "android", "-keypass", "android",
                 "-dname", "CN=Android Debug,O=Android,C=US"],
                30,
                "keytool",
            )
            if keytool_result is None:
                pause()
                return
            if keytool_result.returncode != 0 or not os.path.isfile(keystore):
                print(f"  {C.RED}[!] Debug keystore generation failed.{C.RST}")
                print(f"  {C.DIM}{_terminal_safe(keytool_result.stderr)[:400]}{C.RST}")
                pause()
                return

        signed_apk = os.path.join(work_dir, f"{pkg}_signed.apk")
        print(f"  {C.DIM}Signing APK with {signer}...{C.RST}")

        if signer == "apksigner":
            # zipalign first if available
            zipaligned = os.path.join(work_dir, f"{pkg}_aligned.apk")
            zipalign_path = _safe_native_executable("zipalign")
            if zipalign_path:
                align_result = _run_patcher_tool(
                    [zipalign_path, "-f", "4", rebuilt_apk, zipaligned],
                    60,
                    "zipalign",
                )
                if align_result is None:
                    pause()
                    return
                if align_result.returncode != 0 or not os.path.isfile(zipaligned):
                    print(f"  {C.RED}[!] zipalign failed before signing.{C.RST}")
                    pause()
                    return
                to_sign = zipaligned
            else:
                to_sign = rebuilt_apk

            r = _run_patcher_tool(
                apksigner_command
                + ["sign", "--ks", keystore, "--ks-pass", "pass:android",
                 "--ks-key-alias", "androiddebugkey", "--key-pass", "pass:android",
                 "--out", signed_apk, to_sign],
                60,
                "apksigner",
            )
            if r is None:
                pause()
                return
        else:
            # jarsigner signs in-place
            shutil.copy2(rebuilt_apk, signed_apk)
            r = _run_patcher_tool(
                [jarsigner_path, "-verbose", "-sigalg", "SHA256withRSA", "-digestalg", "SHA-256",
                 "-keystore", keystore, "-storepass", "android", "-keypass", "android",
                 signed_apk, "androiddebugkey"],
                60,
                "jarsigner",
            )
            if r is None:
                pause()
                return
            # zipalign after jarsigner if available
            zipalign_path = _safe_native_executable("zipalign")
            if zipalign_path:
                aligned = os.path.join(work_dir, f"{pkg}_aligned.apk")
                align_result = _run_patcher_tool(
                    [zipalign_path, "-f", "4", signed_apk, aligned],
                    60,
                    "zipalign",
                )
                if align_result is None:
                    pause()
                    return
                if align_result.returncode != 0 or not os.path.isfile(aligned):
                    print(f"  {C.RED}[!] zipalign failed after signing.{C.RST}")
                    pause()
                    return
                shutil.move(aligned, signed_apk)

        if r.returncode != 0:
            print(f"  {C.RED}[!] Signing failed:{C.RST}")
            print(f"  {C.DIM}{r.stderr[:400] if r.stderr else r.stdout[:400]}{C.RST}")
            pause()
            return
        if not os.path.isfile(signed_apk) or os.path.getsize(signed_apk) == 0:
            print(f"  {C.RED}[!] Signing reported success but produced no APK.{C.RST}")
            pause()
            return
        verify_command = (
            apksigner_command + ["verify", "--verbose", signed_apk]
            if signer == "apksigner"
            else [jarsigner_path, "-verify", signed_apk]
        )
        verify_result = _run_patcher_tool(
            verify_command, 60, f"{signer} verification"
        )
        if verify_result is None or verify_result.returncode != 0:
            print(
                f"  {C.RED}[!] Signed APK verification failed; no output "
                f"artifact was published.{C.RST}"
            )
            pause()
            return
        print(f"  {C.GREEN}[+] APK signed and verified{C.RST}")

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

    installed_apk_paths = get_apk_paths(pkg)
    if _refuse_split_apk_patch(pkg, installed_apk_paths):
        return

    # ── Check dependencies ───────────────────────────────────────────────
    java_path = _safe_java_executable()
    if not java_path:
        print(f"  {C.RED}[!] java not found — JDK/JRE is required for LSPatch.{C.RST}")
        print(f"  {C.DIM}  Install a JDK (e.g. openjdk-17-jdk) and ensure java is on PATH{C.RST}")
        pause()
        return

    print(f"  {C.GREEN}[+] java : {java_path}{C.RST}")

    # ── Setup directories ────────────────────────────────────────────────
    gadget_cache = os.path.join(os.getcwd(), ".gadget_cache")
    patched_dir = os.path.join(os.getcwd(), "patched_apks")
    os.makedirs(gadget_cache, exist_ok=True)
    os.makedirs(patched_dir, exist_ok=True)

    # ── Download LSPatch jar if not cached ───────────────────────────────
    lspatch_jar = os.path.join(gadget_cache, LSPATCH_JAR_NAME)
    if os.path.isfile(lspatch_jar):
        try:
            valid_cache = (_file_sha256(lspatch_jar) == LSPATCH_SHA256
                           and zipfile.is_zipfile(lspatch_jar))
        except OSError:
            valid_cache = False
        if not valid_cache:
            print(f"  {C.YELLOW}[!] Cached LSPatch JAR failed integrity validation; replacing it.{C.RST}")
            os.remove(lspatch_jar)
    if not os.path.isfile(lspatch_jar):
        print(f"\n  {C.CYAN}[*] Downloading LSPatch jar...{C.RST}")
        print(f"  {C.DIM}{LSPATCH_URL}{C.RST}")
        try:
            _download_file(
                LSPATCH_URL, lspatch_jar, max_bytes=32 * 1024 * 1024,
                expected_sha256=LSPATCH_SHA256,
            )
            if not zipfile.is_zipfile(lspatch_jar):
                raise ValueError("downloaded LSPatch asset is not a valid JAR")
        except (OSError, ValueError, urllib.error.URLError) as e:
            print(f"  {C.RED}[!] Download failed: {e}{C.RST}")
            pause()
            return
        print(f"  {C.GREEN}[+] LSPatch jar downloaded{C.RST}")
    else:
        print(f"\n  {C.GREEN}[+] Using cached LSPatch jar{C.RST}")

    # ── Locate APK ───────────────────────────────────────────────────────
    local_apk = _find_local_apk(pkg)

    if local_apk:
        print(f"  {C.GREEN}[+] Found local APK: {local_apk}{C.RST}")
    else:
        apk_path = installed_apk_paths[0] if installed_apk_paths else ""
        if not apk_path:
            print(f"  {C.RED}[!] Could not locate APK for {pkg}{C.RST}")
            pause()
            return
        work_dir = os.path.join(os.getcwd(), ".apkpatcher_work")
        os.makedirs(work_dir, exist_ok=True)
        local_apk = os.path.join(work_dir, f"{pkg}.apk")
        print(f"\n  {C.DIM}Pulling APK from device...{C.RST}")
        pull_result = adb_pull(apk_path, local_apk)
        if (_is_err(pull_result) or not os.path.exists(local_apk)
                or os.path.getsize(local_apk) == 0):
            print(f"  {C.RED}[!] Failed to pull APK.{C.RST}")
            pause()
            return

    # ── Run LSPatch ──────────────────────────────────────────────────────
    print(f"\n  {C.CYAN}[*] Running LSPatch...{C.RST}")
    print(f"  {C.DIM}  -d (debuggable)  -v (verbose)  -l 2 (sig-bypass level 2){C.RST}")
    before_outputs = {}
    try:
        for entry in os.scandir(patched_dir):
            if entry.name.lower().endswith(".apk") and entry.is_file(
                    follow_symlinks=False):
                state = entry.stat(follow_symlinks=False)
                before_outputs[entry.path] = (
                    state.st_size, state.st_mtime_ns
                )
    except OSError as exc:
        print(f"  {C.RED}[!] Could not inspect LSPatch output directory: {_terminal_safe(exc)}{C.RST}")
        pause()
        return
    r = _run_patcher_tool(
        [java_path, "-jar", lspatch_jar, local_apk,
         "-d", "-v", "-l", "2", "-o", patched_dir],
        300,
        "LSPatch",
    )
    if r is None:
        pause()
        return

    produced_apks = []
    try:
        for entry in os.scandir(patched_dir):
            if not (entry.name.lower().endswith(".apk")
                    and entry.is_file(follow_symlinks=False)):
                continue
            state = entry.stat(follow_symlinks=False)
            previous = before_outputs.get(entry.path)
            if state.st_size > 0 and previous != (
                    state.st_size, state.st_mtime_ns):
                produced_apks.append(entry.path)
    except OSError as exc:
        print(f"  {C.RED}[!] Could not validate LSPatch output: {_terminal_safe(exc)}{C.RST}")
        pause()
        return
    if not produced_apks:
        print(
            f"  {C.RED}[!] LSPatch reported success but produced no new "
            f"non-empty APK; completion was not claimed.{C.RST}"
        )
        pause()
        return
    print(f"  {C.DIM}{r.stdout[-800:] if r.stdout else ''}{C.RST}")
    if r.returncode != 0:
        print(f"  {C.RED}[!] LSPatch failed (exit {r.returncode}):{C.RST}")
        print(f"  {C.DIM}{r.stderr[:600] if r.stderr else 'unknown error'}{C.RST}")
        pause()
        return

    print(f"\n  {C.GREEN}{C.BOLD}{'='*50}{C.RST}")
    print(f"  {C.GREEN}{C.BOLD}[✓] LSPATCH COMPLETE{C.RST}")
    print(f"  {C.GREEN}{C.BOLD}{'='*50}{C.RST}")
    for output_apk in produced_apks:
        print(f"  {C.WHITE}{_safe_evidence_path(output_apk, 500)}{C.RST}")
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


__all__ = [
    'GADGET_VERSION',
    'GADGET_SO_NAME',
    'LSPATCH_URL',
    'LSPATCH_JAR_NAME',
    'LSPATCH_SHA256',
    '_file_sha256',
    '_download_file',
    '_github_asset_sha256',
    '_extract_xz_elf',
    '_get_frida_gadget',
    '_safe_native_executable',
    '_safe_java_executable',
    '_resolve_apksigner_command',
    '_find_apktool',
    '_find_main_activity',
    '_patch_manifest_for_gadget',
    '_inject_gadget_loader',
    '_refuse_split_apk_patch',
    '_run_patcher_tool',
    'frida_gadget_patch',
    'lspatch_patch',
    'binary_patcher',
    'frida_server_config',
]
