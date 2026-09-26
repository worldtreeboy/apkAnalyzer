"""Device, ADB, and package selection.

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

def _redact(value, visible=4):
    """Mask a sensitive value while leaving enough context to identify it."""
    text = _terminal_safe(value).strip()
    if not text:
        return ""
    # When the value itself is a scanner match, preserve its key/formatting but
    # never expose fragments of the matched credential.  The helper is defined
    # later in the module, so use a guarded lookup during module initialization.
    secret_redactor = globals().get("_redact_secret_text")
    if secret_redactor is not None:
        redacted = secret_redactor(text)
        if redacted != text:
            return redacted
    # Keep a useful key/label visible for key=value style findings.
    match = re.match(r"(?s)(.*?\s*[=:]\s*)(.*)", text)
    if match:
        prefix, secret = match.groups()
        return prefix + ("[REDACTED]" if secret else "")
    if len(text) <= visible * 2:
        return "*" * len(text)
    return f"{text[:visible]}…{text[-visible:]}"



# ─── ADB Helpers ────────────────────────────────────────────────────────────────

def _run_cmd(args, timeout=30, stdin=None):
    """Run an argument-list command and return output or an error sentinel."""
    # Pass the legacy global explicitly so tests and integrations that
    # monkeypatch ``apkAnalyzer._terminal_safe`` keep working after extraction.
    return _process_run_command(
        args, timeout=timeout, stdin=stdin, sanitizer=_terminal_safe
    )

def adb(cmd, timeout=30):
    """Run an adb command and return stdout.
    cmd can be a string (split by shlex) or a list of arguments."""
    if isinstance(cmd, str):
        args = _adb_base() + shlex.split(cmd)
    else:
        args = _adb_base() + list(cmd)
    return _run_cmd(args, timeout=timeout)

def adb_shell(cmd, timeout=30):
    """Run adb shell command (non-root). cmd is passed as a single shell string to the device."""
    return _run_cmd(_adb_base() + ["shell", cmd], timeout=timeout)

# Root mode: "su" = use su -c, "adbd" = adb shell already root, None = unknown
_root_mode = None

# Selected device serial when multiple devices are connected (None = adb default)
ADB_SERIAL = None

def _adb_base():
    """Base adb command, targeting the selected device when one was picked."""
    executable = process_mod.safe_which("adb", which=shutil.which)
    if executable is None:
        # POSIX exec never implicitly prepends the CWD. On Windows, returning
        # a bare name would undo safe_which and could execute an APK-adjacent
        # adb.exe, so use a deterministic nonexistent absolute path instead.
        executable = (
            "adb" if os.name != "nt" else
            os.path.join(os.path.abspath(os.sep), "__apkanalyzer_adb_missing__")
        )
    return ([executable, "-s", ADB_SERIAL]
            if ADB_SERIAL else [executable])

def _is_err(out):
    """True if a command output is empty or an error sentinel like [ERROR]/[TIMEOUT]."""
    return _process_is_error_output(out)


def _command_failed(out):
    """Return whether a command produced one of ``_run_cmd``'s failure sentinels.

    Unlike :func:`_is_err`, an empty string is not necessarily a failure: many
    successful shell probes intentionally produce no output when they find
    nothing. Runtime checks use this narrower predicate so they can distinguish
    a clean empty result from an unavailable device or failed command.
    """
    return _process_command_failed(out)


def _require_runtime_command(out, operation, require_output=False,
                             partial_findings=None):
    """Validate command output or raise an explicit inconclusive-check error."""
    # Supplying the legacy globals preserves monkeypatch behavior at the old
    # module boundary while the reusable implementation lives in the package.
    return _process_require_runtime_command(
        out,
        operation,
        require_output=require_output,
        partial_findings=partial_findings,
        failure_predicate=_command_failed,
        unavailable_error=RuntimeCheckUnavailable,
    )


def _require_app_launch(out, operation="launching target app"):
    """Reject both transport errors and monkey/am textual launch failures."""
    _require_runtime_command(out, operation, require_output=True)
    lowered = str(out or "").lower()
    failure_markers = (
        "no activities found", "monkey aborted", "unable to resolve intent",
        "activity class does not exist", "error type 3",
    )
    if any(marker in lowered for marker in failure_markers):
        raise RuntimeCheckUnavailable(f"{operation}: {str(out).strip()}")
    injected = re.search(r"Events injected:\s*(\d+)", str(out), re.IGNORECASE)
    injected_count = injected.group(1) if injected is not None else ""
    if (not injected_count or len(injected_count) > 6
            or int(injected_count) < 1):
        raise RuntimeCheckUnavailable(
            f"{operation}: monkey did not confirm an injected launch event"
        )
    return out

def adb_su(cmd, timeout=30):
    """Run command as root, auto-detecting whether su or adbd-root is available."""
    if _root_mode == "adbd":
        return adb_shell(cmd, timeout=timeout)
    # adb joins arguments after `shell`; passing `su`, `-c`, and a compound
    # command separately makes su execute only the first token. Build one
    # remote-shell string and quote the complete command as su's -c argument.
    remote_cmd = f"su -c {shlex.quote(cmd)}"
    return _run_cmd(_adb_base() + ["shell", remote_cmd], timeout=timeout)

def adb_pull(remote, local):
    """Atomically pull a file from the device, never accepting stale output."""
    local_path = os.path.abspath(os.fspath(local))
    local_dir = os.path.dirname(local_path)
    partial = None
    try:
        fd, partial = tempfile.mkstemp(
            prefix=os.path.basename(local_path) + ".",
            suffix=".part",
            dir=local_dir,
        )
        os.close(fd)
        # Reserve a collision-resistant name, then remove the placeholder so
        # success still requires adb itself to create the pulled file.
        os.remove(partial)
        result = _run_cmd(_adb_base() + ["pull", remote, partial], timeout=120)
        failed = result == "[TIMEOUT]" or result.startswith("[ERROR")
        if failed or not os.path.isfile(partial):
            return result if failed else "[ERROR] adb pull produced no file"
        os.replace(partial, local_path)
        partial = None
        return result or "pulled"
    except OSError as e:
        return f"[ERROR] {e}"
    finally:
        if partial and os.path.exists(partial):
            os.remove(partial)


def _find_local_apk(pkg):
    """Find an exact, non-patched APK previously extracted for *pkg*."""
    if not _is_valid_package(pkg):
        return None
    expected = f"{pkg}.apk"
    for search_dir in (os.path.join(os.getcwd(), "extracted_apks"), os.getcwd()):
        candidate = os.path.join(search_dir, expected)
        if os.path.isfile(candidate) and os.path.getsize(candidate) > 0:
            return candidate
    return None

def _validated_pm_apk_paths(output):
    """Return a deterministic, complete set of safe paths from ``pm path``.

    A malformed ``package:`` line invalidates the whole response: accepting the
    remaining lines could silently turn a split install into a base-only scan.
    Paths are later passed to ``adb pull`` as argv entries, but validating them
    here also keeps control characters and ambiguous traversal spellings out of
    cache metadata and terminal output.
    """
    if _is_err(output):
        return []
    paths = []
    saw_package_line = False
    for raw_line in str(output).splitlines():
        line = raw_line.strip()
        if not line.startswith("package:"):
            continue
        saw_package_line = True
        path = line[len("package:"):].strip()
        if (not path or not path.startswith("/") or "\\" in path
                or any(ord(char) < 32 or ord(char) == 127 for char in path)
                or not path.lower().endswith(".apk")
                or posixpath.normpath(path) != path):
            return []
        paths.append(path)
    if not saw_package_line or not paths or len(set(paths)) != len(paths):
        return []
    base_count = sum(
        posixpath.basename(path).lower() == "base.apk" for path in paths
    )
    if len(paths) > 1 and base_count != 1:
        # A split install without exactly one identifiable base cannot be
        # decompiled in a trustworthy module order.
        return []

    # Android conventionally names the install's primary artifact base.apk.
    # Keep it first for callers while sorting every other path for stable cache
    # identities across devices whose ``pm path`` output order is not stable.
    return sorted(
        paths,
        key=lambda path: (
            0 if posixpath.basename(path).lower() == "base.apk" else 1,
            path,
        ),
    )


def get_apk_paths(pkg):
    """Get all installed APK paths for *pkg*, trying root then non-root."""
    if not _is_valid_package(pkg):
        return []
    pkg_arg = shlex.quote(pkg)
    for fn in (adb_su, adb_shell):
        out = fn(f"pm path {pkg_arg}")
        paths = _validated_pm_apk_paths(out)
        if paths:
            return paths
    return []


def get_apk_path(pkg):
    """Compatibility wrapper returning the installed base (or first) APK."""
    paths = get_apk_paths(pkg)
    if paths:
        return paths[0]
    return ""

def check_device():
    """Check if a device is connected and return device info.
    When multiple devices are connected, prompts the user to pick one."""
    global ADB_SERIAL
    out = adb("devices")
    lines = [l for l in out.splitlines() if "\tdevice" in l]
    if not lines:
        return None
    serials = [l.split("\t")[0] for l in lines]
    if len(serials) > 1:
        print(f"\n  {C.YELLOW}[!] Multiple devices connected:{C.RST}\n")
        for i, s in enumerate(serials, 1):
            print(f"  {C.YELLOW}[{i:3d}]{C.RST} {s}")
        print(f"\n  {C.DIM}[0] Exit{C.RST}")
        while True:
            try:
                choice = input(f"\n  {C.GREEN}Select device ▸ {C.RST}").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                sys.exit(0)
            if choice == "0":
                sys.exit(0)
            try:
                idx = int(choice) - 1
            except ValueError:
                print(f"  {C.RED}Enter a number.{C.RST}")
                continue
            if 0 <= idx < len(serials):
                ADB_SERIAL = serials[idx]
                break
            print(f"  {C.RED}Invalid selection.{C.RST}")
    serial = ADB_SERIAL or serials[0]
    model = adb_shell("getprop ro.product.model")
    android_ver = adb_shell("getprop ro.build.version.release")
    sdk = adb_shell("getprop ro.build.version.sdk")
    return {"serial": serial, "model": model, "android": android_ver, "sdk": sdk}

def check_root():
    """Check if device has root access (su, adbd-root, or adb root restart)."""
    global _root_mode
    # 1) Try su -c (Magisk / SuperSU / rooted ROMs)
    out = _run_cmd(_adb_base() + ["shell", "su -c id"], timeout=10)
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
    if _is_err(out):
        out = adb_shell("pm list packages -3")
    pkgs = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            package = line.replace("package:", "", 1)
            if _is_valid_package(package):
                pkgs.append(package)
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
        except ValueError:
            print(f"  {C.RED}Enter a number.{C.RST}")
        except (EOFError, KeyboardInterrupt):
            print()
            return None

# ─── Decompile Helpers ──────────────────────────────────────────────────────────

__all__ = [
    '_redact',
    '_run_cmd',
    'adb',
    'adb_shell',
    '_root_mode',
    'ADB_SERIAL',
    '_adb_base',
    '_is_err',
    '_command_failed',
    '_require_runtime_command',
    '_require_app_launch',
    'adb_su',
    'adb_pull',
    '_find_local_apk',
    '_validated_pm_apk_paths',
    'get_apk_paths',
    'get_apk_path',
    'check_device',
    'check_root',
    'list_third_party_apps',
    'pick_app',
]
