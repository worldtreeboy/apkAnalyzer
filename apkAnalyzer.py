#!/usr/bin/env python3
"""
APK Analyzer - Android Security Analysis Tool
Root-based ADB tool for app analysis, storage auditing,
shell access, screenshots, and security scanning.
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

from apk_analyzer import archive as archive_mod
from apk_analyzer import code_scan as code_scan_mod
from apk_analyzer import cli as cli_mod
from apk_analyzer import inputs as input_mod
from apk_analyzer import process as process_mod
from apk_analyzer import secrets as secrets_mod
from apk_analyzer import resources as resource_mod
from apk_analyzer.process import (
    CommandOutputLimitExceeded,
    RuntimeCheckUnavailable,
    command_failed as _process_command_failed,
    is_error_output as _process_is_error_output,
    parse_android_ps as _parse_android_ps,
    require_runtime_command as _process_require_runtime_command,
    run_command as _process_run_command,
    run_command_capture as _process_run_command_capture,
)
from apk_analyzer.reporting import (
    ReportCollector,
    now_iso as _now_iso,
    report,
)
from apk_analyzer.safety import (
    MAX_XML_BYTES,
    _PACKAGE_RE,
    is_link_or_reparse_stat as _is_link_or_reparse_stat,
    is_valid_package as _is_valid_package,
    parse_sdk_level as _parse_sdk_level,
    safe_parse_xml as _safe_parse_xml,
    terminal_safe as _terminal_safe,
)
from apk_analyzer.static_rules import (
    analyze_clipboard_writes as _analyze_clipboard_writes,
    analyze_pending_intents as _analyze_pending_intents,
    classify_deep_link as _classify_deep_link,
)
from apk_analyzer.ui import (
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
from apk_analyzer.version import TOOL_VERSION


_configure_windows_streams()

# ─── Report Collector ────────────────────────────────────────────────────────────

# Legacy, monkeypatchable aliases. The reusable archive module is the single
# source for production defaults; _unpack_ab forwards these names at call time.
MAX_BACKUP_BYTES = archive_mod.DEFAULT_MAX_BACKUP_BYTES
MAX_BACKUP_PAYLOAD_BYTES = archive_mod.DEFAULT_MAX_BACKUP_PAYLOAD_BYTES
MAX_BACKUP_FILE_BYTES = archive_mod.DEFAULT_MAX_BACKUP_FILE_BYTES
MAX_BACKUP_FILES = archive_mod.DEFAULT_MAX_BACKUP_FILES


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

def _get_version_code(pkg):
    """Query the device's current versionCode for a package ('' if unavailable)."""
    out = adb_shell(f"dumpsys package {pkg}")
    if _is_err(out):
        return ""
    m = re.search(r'versionCode=(\d+)', out)
    return m.group(1) if m else ""


def _get_package_fingerprint(pkg):
    """Return package metadata that changes on update/reinstall."""
    if not _is_valid_package(pkg):
        return {}
    out = adb_shell(f"dumpsys package {shlex.quote(pkg)}", timeout=30)
    if _is_err(out):
        return {}
    patterns = {
        "versionCode": r"versionCode=(\d+)",
        "lastUpdateTime": r"lastUpdateTime=([^\r\n]+)",
        "codePath": r"codePath=([^\r\n]+)",
    }
    fingerprint = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, out)
        if match:
            fingerprint[key] = match.group(1).strip()
    # A versionCode alone is not an update identity: an APK can be replaced in
    # place with the same version.  lastUpdateTime and codePath are both needed
    # to make cache reuse fail closed across reinstalls and staged updates.
    return fingerprint if set(fingerprint) == set(patterns) else {}


_DECOMPILE_CACHE_SCHEMA = 3
_MAX_DECOMPILE_METADATA_BYTES = 64 * 1024
_MAX_CACHE_INTEGRITY_ENTRIES = 500_000
_MAX_CACHE_INTEGRITY_BYTES = 8 * 1024 * 1024 * 1024
_CACHE_INTEGRITY_CHUNK_BYTES = 1024 * 1024


def _device_decompile_metadata(pkg, remote_paths=None, fingerprint=None):
    """Build verifiable cache metadata for the complete installed APK set."""
    if fingerprint is None:
        fingerprint = _get_package_fingerprint(pkg)
    if not fingerprint:
        return {}
    if remote_paths is None:
        remote_paths = get_apk_paths(pkg)
    if not remote_paths:
        return {}
    return {
        "cache_schema": _DECOMPILE_CACHE_SCHEMA,
        "source": "device",
        "package_fingerprint": fingerprint,
        "remote_apk_paths": list(remote_paths),
    }


def _write_decompile_metadata(decompiled_dir, metadata):
    """Atomically store decompile provenance inside an analysis directory."""
    destination = os.path.join(decompiled_dir, ".apkanalyzer_meta.json")
    fd, temporary = tempfile.mkstemp(
        prefix=".apkanalyzer-meta-", suffix=".json", dir=decompiled_dir
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(metadata, output, indent=2, ensure_ascii=False)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary and os.path.exists(temporary):
            os.remove(temporary)


def _read_decompile_metadata(decompiled_dir):
    """Read bounded, non-symlink decompile metadata or return an empty dict."""
    path = os.path.join(decompiled_dir, ".apkanalyzer_meta.json")
    outcome = code_scan_mod.read_file(
        path,
        max_bytes=_MAX_DECOMPILE_METADATA_BYTES,
        chunk_bytes=16 * 1024,
    )
    if not outcome.complete:
        return {}
    try:
        metadata = json.loads(outcome.content)
    except (ValueError, TypeError):
        return {}
    return metadata if isinstance(metadata, dict) else {}


def _decompile_cache_provenance(metadata):
    """Return only the installed-app identity fields from cache metadata."""
    if not isinstance(metadata, dict):
        return {}
    return {
        "cache_schema": metadata.get("cache_schema"),
        "source": metadata.get("source"),
        "package_fingerprint": metadata.get("package_fingerprint"),
        "remote_apk_paths": metadata.get("remote_apk_paths"),
    }


def _cache_stat_signature(path_stat, include_size=True):
    """Return fields that expose replacement or mutation during sealing."""
    signature = (
        stat.S_IFMT(path_stat.st_mode),
        getattr(path_stat, "st_dev", None),
        getattr(path_stat, "st_ino", None),
        getattr(path_stat, "st_mtime_ns", int(path_stat.st_mtime * 1e9)),
    )
    if include_size:
        signature += (path_stat.st_size,)
    return signature


def _is_cache_reparse_point(path_stat):
    attributes = getattr(path_stat, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(path_stat.st_mode) or bool(attributes & reparse_flag)


def _digest_cache_field(digest, marker, relative_path):
    encoded_path = relative_path.replace(os.sep, "/").encode(
        "utf-8", errors="surrogatepass"
    )
    digest.update(marker)
    digest.update(str(len(encoded_path)).encode("ascii"))
    digest.update(b":")
    digest.update(encoded_path)
    digest.update(b"\0")


def _decompile_integrity_seal(decompiled_dir):
    """Hash the complete safe decompile inventory and every file's content.

    The provenance metadata itself is excluded because it stores this seal.
    Symlinks, reparse points, special files, oversized trees, and files that
    change while being read make the cache unverifiable rather than trusted.
    """
    root = os.path.abspath(os.fspath(decompiled_dir))
    root_stat = os.lstat(root)
    if _is_cache_reparse_point(root_stat) or not stat.S_ISDIR(root_stat.st_mode):
        raise ValueError("decompile cache root is not a safe directory")

    digest = hashlib.sha256()
    digest.update(b"apkAnalyzer-decompile-integrity-v1\0")
    file_count = 0
    directory_count = 0
    total_bytes = 0
    directory_states = []
    pending = [("", root)]

    while pending:
        relative_directory, directory = pending.pop()
        before_directory = os.lstat(directory)
        if (_is_cache_reparse_point(before_directory)
                or not stat.S_ISDIR(before_directory.st_mode)):
            raise ValueError("decompile cache contains an unsafe directory")
        directory_states.append((
            directory,
            _cache_stat_signature(before_directory, include_size=False),
        ))
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(list(iterator), key=lambda item: item.name)
        except OSError as exc:
            raise OSError(f"could not enumerate decompile cache: {exc}") from exc

        child_directories = []
        for entry in entries:
            if (not relative_directory
                    and entry.name == ".apkanalyzer_meta.json"):
                continue
            relative_path = (
                entry.name if not relative_directory else
                os.path.join(relative_directory, entry.name)
            )
            entry_stat = entry.stat(follow_symlinks=False)
            if _is_cache_reparse_point(entry_stat):
                raise ValueError(
                    f"decompile cache contains a link: {relative_path!r}"
                )
            if stat.S_ISDIR(entry_stat.st_mode):
                directory_count += 1
                if file_count + directory_count > _MAX_CACHE_INTEGRITY_ENTRIES:
                    raise ValueError("decompile cache contains too many entries")
                _digest_cache_field(digest, b"D", relative_path)
                child_directories.append((relative_path, entry.path))
                continue
            if not stat.S_ISREG(entry_stat.st_mode):
                raise ValueError(
                    f"decompile cache contains a special file: {relative_path!r}"
                )

            file_count += 1
            if file_count + directory_count > _MAX_CACHE_INTEGRITY_ENTRIES:
                raise ValueError("decompile cache contains too many entries")
            if entry_stat.st_size < 0:
                raise ValueError("decompile cache contains an invalid file size")
            total_bytes += entry_stat.st_size
            if total_bytes > _MAX_CACHE_INTEGRITY_BYTES:
                raise ValueError("decompile cache exceeds the integrity size limit")
            _digest_cache_field(digest, b"F", relative_path)
            digest.update(str(entry_stat.st_size).encode("ascii"))
            digest.update(b"\0")

            flags = os.O_RDONLY
            flags |= getattr(os, "O_BINARY", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(entry.path, flags)
            try:
                opened_stat = os.fstat(descriptor)
                if (not stat.S_ISREG(opened_stat.st_mode)
                        or _cache_stat_signature(opened_stat)
                        != _cache_stat_signature(entry_stat)):
                    raise ValueError(
                        f"decompile cache entry changed: {relative_path!r}"
                    )
                bytes_read = 0
                while True:
                    chunk = os.read(descriptor, _CACHE_INTEGRITY_CHUNK_BYTES)
                    if not chunk:
                        break
                    bytes_read += len(chunk)
                    digest.update(chunk)
                after_read = os.fstat(descriptor)
                if (bytes_read != entry_stat.st_size
                        or _cache_stat_signature(after_read)
                        != _cache_stat_signature(opened_stat)):
                    raise ValueError(
                        f"decompile cache entry changed: {relative_path!r}"
                    )
            finally:
                os.close(descriptor)
            if (_cache_stat_signature(os.lstat(entry.path))
                    != _cache_stat_signature(entry_stat)):
                raise ValueError(
                    f"decompile cache entry was replaced: {relative_path!r}"
                )

        # Reverse insertion keeps the traversal deterministic while using a
        # bounded iterative stack rather than Python recursion.
        pending.extend(reversed(child_directories))

    # Inventory changes made while descendants were being hashed must not be
    # captured as a seal for a mixed tree.
    for directory, expected_signature in directory_states:
        current = os.lstat(directory)
        if (_is_cache_reparse_point(current)
                or _cache_stat_signature(current, include_size=False)
                != expected_signature):
            raise ValueError("decompile cache inventory changed while sealing")

    return {
        "algorithm": "sha256",
        "digest": digest.hexdigest(),
        "files": file_count,
        "directories": directory_count,
        "bytes": total_bytes,
    }


def _validate_cached_decompile_integrity(decompiled_dir, metadata):
    expected = metadata.get("decompile_integrity")
    if not isinstance(expected, dict):
        return False, "cached content has no integrity seal"
    try:
        actual = _decompile_integrity_seal(decompiled_dir)
    except (OSError, ValueError) as exc:
        return False, str(exc)
    if actual != expected:
        return False, "cached file inventory or content changed"
    return True, ""


def _validate_cached_base_apk(base_apk, metadata):
    """Verify the pulled base used by signing checks alongside the cache."""
    expected = metadata.get("base_apk_sha256")
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        return False, "cached base APK has no integrity seal"
    try:
        path_stat = os.lstat(base_apk)
        if (_is_cache_reparse_point(path_stat)
                or not stat.S_ISREG(path_stat.st_mode)):
            return False, "cached base APK is unsafe"
        actual = _file_sha256(base_apk)
    except OSError as exc:
        return False, f"cached base APK is unreadable ({type(exc).__name__})"
    if actual != expected:
        return False, "cached base APK content changed"
    return True, ""


def _preflight_apk_artifacts(apk_paths, destination_directory):
    """Validate a complete APK set, including aggregate expansion limits."""
    limits = input_mod.ArchiveLimits()
    if not apk_paths or len(apk_paths) > limits.max_apk_count:
        raise input_mod.InputPreparationError(
            "installed APK set contains an unsupported number of artifacts"
        )
    case_sensitive = archive_mod.filesystem_is_case_sensitive(
        destination_directory
    )
    aggregate_uncompressed = 0
    for apk_path in apk_paths:
        try:
            path_stat = os.lstat(apk_path)
        except OSError as exc:
            raise input_mod.InputPreparationError(
                f"APK artifact is unreadable: {exc}"
            ) from exc
        if (_is_cache_reparse_point(path_stat)
                or not stat.S_ISREG(path_stat.st_mode)):
            raise input_mod.InputPreparationError(
                "APK artifact is not a safe regular file"
            )
        preflight = input_mod.preflight_zip(
            apk_path,
            limits=limits,
            require_apk_manifest=True,
            case_sensitive=case_sensitive,
        )
        aggregate_uncompressed += preflight.uncompressed_bytes
        if aggregate_uncompressed > limits.max_total_bytes:
            raise input_mod.InputPreparationError(
                "installed APK set expands beyond the aggregate safety limit"
            )


def _validate_cached_decompile_layout(decompiled_dir, package, apk_count):
    """Verify that a cached base/split layout is complete and parseable."""
    try:
        apk_count = int(apk_count)
    except (TypeError, ValueError):
        return False, "cached APK count is invalid"
    if apk_count < 1 or apk_count > _MAX_SPLIT_MANIFESTS + 1:
        return False, "cached APK count is outside the supported range"
    try:
        root_mode = os.lstat(decompiled_dir).st_mode
    except OSError:
        return False, "cached decompile directory is unreadable"
    if stat.S_ISLNK(root_mode) or not stat.S_ISDIR(root_mode):
        return False, "cached decompile directory is unsafe"

    expected_roots = [decompiled_dir]
    expected_names = {
        f"split_{index:04d}" for index in range(1, apk_count)
    }
    split_root = os.path.join(decompiled_dir, ".apkanalyzer_splits")
    if expected_names or os.path.lexists(split_root):
        if os.path.islink(split_root) or not os.path.isdir(split_root):
            return False, "cached split directory is missing or unsafe"
        try:
            with os.scandir(split_root) as iterator:
                entries = list(iterator)
        except OSError as exc:
            return False, f"cached split directory is unreadable ({type(exc).__name__})"
        actual_names = set()
        entry_map = {}
        for entry in entries:
            try:
                safe_directory = (
                    not entry.is_symlink()
                    and entry.is_dir(follow_symlinks=False)
                )
            except OSError:
                safe_directory = False
            if not safe_directory:
                return False, f"unsafe cached split entry {entry.name!r}"
            actual_names.add(entry.name)
            entry_map[entry.name] = entry.path
        if actual_names != expected_names:
            return False, (
                "cached split layout does not match the installed APK set"
            )
        expected_roots.extend(entry_map[name] for name in sorted(expected_names))

    for analysis_root in expected_roots:
        manifest_path = os.path.join(analysis_root, "AndroidManifest.xml")
        try:
            manifest_root = _safe_parse_xml(manifest_path).getroot()
        except (ET.ParseError, OSError, ValueError):
            return False, "a cached AndroidManifest.xml is missing or malformed"
        if (manifest_root.tag != "manifest"
                or manifest_root.get("package") != package):
            return False, "a cached manifest package does not match the target"
    return True, ""

def _pull_and_decompile(pkg):
    """Pull and atomically decompile an installed APK set or one local APK."""
    work_dir = os.path.join(os.getcwd(), ".apkanalyzer_tmp")
    decompiled_dir = os.path.join(work_dir, f"{pkg}_decompiled")
    legacy_base_apk = os.path.join(work_dir, f"{pkg}.apk")

    # ── Cache hit — already decompiled ──────────────────────────────────
    if os.path.isdir(decompiled_dir):
        # Invalidate the cache if the app was updated on the device since
        cached_meta = _read_decompile_metadata(decompiled_dir)
        # Reuse requires both device metadata and the complete split-path set.
        # Pre-schema, base-only caches deliberately cannot compare equal.
        current_meta = _device_decompile_metadata(pkg)
        if not current_meta:
            # A transient ADB/device failure must not turn an old decompile into
            # trusted input. Preserve the cache so a later, healthy connection
            # can verify it, but stop this scan as inconclusive.
            print(f"  {C.YELLOW}[!] Could not verify the cached decompile against the installed app; cache was not used.{C.RST}")
            return None, None
        if _decompile_cache_provenance(cached_meta) != current_meta:
            cached_fingerprint = cached_meta.get(
                "package_fingerprint", cached_meta
            )
            if not isinstance(cached_fingerprint, dict):
                cached_fingerprint = {}
            old_vc = cached_fingerprint.get("versionCode", "unknown")
            new_vc = current_meta["package_fingerprint"].get(
                "versionCode", "unknown"
            )
            old_count = len(cached_meta.get("remote_apk_paths", []))
            new_count = len(current_meta["remote_apk_paths"])
            print(f"  {C.YELLOW}[!] Installed APK set changed on device (versionCode {old_vc} → {new_vc}, artifacts {old_count} → {new_count}) — re-decompiling.{C.RST}")
            shutil.rmtree(decompiled_dir, ignore_errors=True)
            try:
                os.remove(legacy_base_apk)
            except OSError:
                pass
        else:
            cache_layout_valid, cache_layout_reason = (
                _validate_cached_decompile_layout(
                    decompiled_dir,
                    pkg,
                    len(current_meta["remote_apk_paths"]),
                )
            )
            cache_integrity_valid = False
            cache_integrity_reason = ""
            cached_base_valid = False
            cached_base_reason = ""
            if cache_layout_valid:
                cache_integrity_valid, cache_integrity_reason = (
                    _validate_cached_decompile_integrity(
                        decompiled_dir, cached_meta
                    )
                )
            if cache_layout_valid and cache_integrity_valid:
                cached_base_valid, cached_base_reason = (
                    _validate_cached_base_apk(legacy_base_apk, cached_meta)
                )
            if not cache_layout_valid:
                print(
                    f"  {C.YELLOW}[!] Cached decompile is incomplete "
                    f"({_terminal_safe(cache_layout_reason)}) — "
                    f"re-decompiling.{C.RST}"
                )
                shutil.rmtree(decompiled_dir, ignore_errors=True)
                try:
                    os.remove(legacy_base_apk)
                except OSError:
                    pass
            elif not cache_integrity_valid or not cached_base_valid:
                integrity_reason = (
                    cache_integrity_reason if not cache_integrity_valid
                    else cached_base_reason
                )
                print(
                    f"  {C.YELLOW}[!] Cached decompile integrity check "
                    f"failed ({_terminal_safe(integrity_reason)}) — "
                    f"re-decompiling.{C.RST}"
                )
                shutil.rmtree(decompiled_dir, ignore_errors=True)
                try:
                    os.remove(legacy_base_apk)
                except OSError:
                    pass
            else:
                # Recheck after hashing the cache, which can be a substantial
                # operation for a large app.  A disconnect or update during
                # validation must not turn old content into a trusted hit.
                confirmed_meta = _device_decompile_metadata(pkg)
                if not confirmed_meta:
                    print(f"  {C.YELLOW}[!] Device state became unavailable while verifying the decompile cache; cache was not used.{C.RST}")
                    return None, None
                if confirmed_meta != current_meta:
                    print(f"  {C.YELLOW}[!] Installed APK set changed while the decompile cache was being verified — re-decompiling.{C.RST}")
                    shutil.rmtree(decompiled_dir, ignore_errors=True)
                    try:
                        os.remove(legacy_base_apk)
                    except OSError:
                        pass
                else:
                    print(f"  {C.GREEN}[+] Using cached decompile: {decompiled_dir}{C.RST}")
                    return work_dir, decompiled_dir

    # ── Need to decompile ───────────────────────────────────────────────
    apktool_cmd = _find_apktool()
    if not apktool_cmd:
        print(f"  {C.RED}[!] apktool is required for this feature.{C.RST}")
        print(f"  {C.DIM}  Install: https://ibotpeaches.github.io/Apktool/{C.RST}")
        return None, None

    os.makedirs(work_dir, exist_ok=True)

    # Prefer the complete installed APK set so scans cannot silently use a
    # stale local copy or omit feature/configuration splits.
    remote_paths = get_apk_paths(pkg)
    local_apks = []
    local_apk = None
    apk_source = "local"
    pull_stage = None
    initial_device_meta = None
    local_source_sha256 = None
    if remote_paths:
        if len(remote_paths) > input_mod.ArchiveLimits().max_apk_count:
            print(f"  {C.RED}[!] Installed APK set contains too many artifacts to analyze safely.{C.RST}")
            return None, None
        initial_fingerprint = _get_package_fingerprint(pkg)
        initial_device_meta = _device_decompile_metadata(
            pkg,
            remote_paths=remote_paths,
            fingerprint=initial_fingerprint,
        )
        confirmed_initial_meta = _device_decompile_metadata(pkg)
        if (not initial_device_meta or not confirmed_initial_meta
                or confirmed_initial_meta != initial_device_meta):
            print(f"  {C.RED}[!] Installed APK state was unavailable or changed before pulling; no artifacts were used.{C.RST}")
            return None, None
        # Never leave an old base where the signing check trusts it if a split
        # refresh subsequently fails partway through.
        try:
            os.remove(legacy_base_apk)
        except FileNotFoundError:
            pass
        except OSError as exc:
            print(f"  {C.RED}[!] Could not clear a stale pulled APK: {_terminal_safe(exc)}{C.RST}")
            return None, None
        try:
            pull_stage = tempfile.mkdtemp(
                prefix=f".{pkg}-pull-", dir=work_dir
            )
        except OSError as exc:
            print(f"  {C.RED}[!] Could not stage installed APK pulls: {_terminal_safe(exc)}{C.RST}")
            return None, None
        print(f"  {C.DIM}Pulling {len(remote_paths)} installed APK artifact(s) from device...{C.RST}")
        for index, remote_path in enumerate(remote_paths):
            local_name = "base.apk" if index == 0 else f"split_{index:04d}.apk"
            candidate = os.path.join(pull_stage, local_name)
            pull_result = adb_pull(remote_path, candidate)
            try:
                valid_pull = (
                    not _is_err(pull_result)
                    and os.path.isfile(candidate)
                    and os.path.getsize(candidate) > 0
                )
            except OSError:
                valid_pull = False
            if not valid_pull:
                shutil.rmtree(pull_stage, ignore_errors=True)
                print(f"  {C.RED}[!] Installed APK set was located but an artifact could not be pulled; refusing to use an unverified local fallback: {_terminal_safe(pull_result)}{C.RST}")
                return None, None
            local_apks.append(candidate)
        confirmed_after_pull = _device_decompile_metadata(pkg)
        if confirmed_after_pull != initial_device_meta:
            shutil.rmtree(pull_stage, ignore_errors=True)
            print(f"  {C.RED}[!] Installed APK state changed or became unavailable while it was being pulled; discarded the staged artifacts.{C.RST}")
            return None, None
        local_apk = local_apks[0]
        apk_source = "device"
    else:
        local_apk = _find_local_apk(pkg)
        if local_apk:
            print(f"  {C.YELLOW}[!] Installed APK path unavailable; using unverified local APK: {local_apk}{C.RST}")
            local_apks = [local_apk]
        else:
            print(f"  {C.RED}[!] Could not locate APK on device or locally.{C.RST}")
            return None, None

    try:
        _preflight_apk_artifacts(
            local_apks,
            pull_stage if pull_stage else work_dir,
        )
        if apk_source == "local":
            local_source_sha256 = _file_sha256(local_apk)
    except (input_mod.InputPreparationError, OSError) as exc:
        if pull_stage:
            shutil.rmtree(pull_stage, ignore_errors=True)
        print(f"  {C.RED}[!] APK validation failed before apktool: {_terminal_safe(exc)}{C.RST}")
        return None, None

    print(f"  {C.DIM}Decompiling with apktool...{C.RST}")
    try:
        apk_inputs = input_mod.ApkInputSet(
            source_path=pkg if apk_source == "device" else local_apk,
            input_kind="device" if apk_source == "device" else "apk",
            apk_paths=tuple(local_apks),
            base_apk=local_apk,
            variant_union=False,
        )
        input_mod.decompile_apk_inputs(
            apk_inputs,
            decompiled_dir,
            apktool_cmd,
            timeout=300,
            runner=subprocess.run,
        )
    except (input_mod.InputPreparationError, OSError) as exc:
        print(f"  {C.RED}[!] APK decompilation failed: {_terminal_safe(exc)}{C.RST}")
        if pull_stage:
            shutil.rmtree(pull_stage, ignore_errors=True)
        return None, None

    # Only a successfully pulled APK may inherit installed-package metadata.
    # Local fallback content gets an explicitly local identity so it can never
    # masquerade as the currently installed build on a later cache check.
    try:
        if apk_source == "device":
            confirmed_after_decompile = _device_decompile_metadata(pkg)
            if confirmed_after_decompile != initial_device_meta:
                raise input_mod.InputPreparationError(
                    "installed APK state changed or became unavailable during "
                    "decompilation"
                )
        elif _file_sha256(local_apk) != local_source_sha256:
            raise input_mod.InputPreparationError(
                "local APK changed during decompilation"
            )

        decompile_integrity = _decompile_integrity_seal(decompiled_dir)
        if apk_source == "device":
            base_apk_sha256 = _file_sha256(local_apk)
            # Sealing hashes every output byte. Check once more afterward so an
            # update occurring while either the outputs or pulled base are
            # hashed cannot be mislabeled with the earlier app identity.
            confirmed_after_seal = _device_decompile_metadata(pkg)
            if confirmed_after_seal != initial_device_meta:
                raise input_mod.InputPreparationError(
                    "installed APK state changed or became unavailable while "
                    "sealing decompile output"
                )
            decompile_meta = {
                "cache_schema": _DECOMPILE_CACHE_SCHEMA,
                "source": "device",
                "package_fingerprint": initial_device_meta[
                    "package_fingerprint"
                ],
                "remote_apk_paths": list(remote_paths),
                "base_apk_sha256": base_apk_sha256,
                "decompile_integrity": decompile_integrity,
            }
        else:
            decompile_meta = {
                "cache_schema": _DECOMPILE_CACHE_SCHEMA,
                "source": "local",
                "sha256": local_source_sha256,
                "decompile_integrity": decompile_integrity,
            }
        _write_decompile_metadata(decompiled_dir, decompile_meta)
        if apk_source == "device":
            # Preserve the base for the signing-scheme check, but only after
            # every installed artifact and every decompile has succeeded.
            os.replace(local_apk, legacy_base_apk)
    except (input_mod.InputPreparationError, OSError, ValueError) as exc:
        shutil.rmtree(decompiled_dir, ignore_errors=True)
        print(f"  {C.RED}[!] Could not finalize the decompile cache: {_terminal_safe(exc)}{C.RST}")
        return None, None
    finally:
        if pull_stage:
            shutil.rmtree(pull_stage, ignore_errors=True)

    print(f"  {C.GREEN}[+] Decompiled successfully (cached for next check){C.RST}")
    return work_dir, decompiled_dir

_MAX_NATIVE_LIB_FILES = 4096
_MAX_SECURITY_CLASS_FILES = 200000
_MAX_NATIVE_STRING_FILE_BYTES = 128 * 1024 * 1024
_MAX_NATIVE_STRING_OUTPUT_BYTES = 16 * 1024 * 1024
_MAX_NATIVE_STRING_FILES = 256
_MAX_NATIVE_STRING_TOTAL_BYTES = 512 * 1024 * 1024
_MAX_NATIVE_STRING_SCAN_SECONDS = 120
_MAX_NATIVE_STRING_TOOL_SECONDS = 10
_MAX_NATIVE_DISCOVERY_ISSUES = 100


def _iter_decompiled_roots(decompiled_dir):
    """Yield the base and safe prepared split roots deterministically."""
    decompiled_dir = os.path.abspath(os.fspath(decompiled_dir))
    yield decompiled_dir
    split_directories, _issues = _split_manifest_directories(decompiled_dir)
    for _relative, split_dir in split_directories:
        yield split_dir


def _iter_safe_regular_files(root, max_files):
    """Yield bounded regular files below *root* without following symlinks."""
    try:
        root_stat = os.lstat(root)
    except OSError:
        return
    if (_is_link_or_reparse_stat(root_stat)
            or not stat.S_ISDIR(root_stat.st_mode)):
        return

    yielded = 0
    for directory, directories, files in os.walk(root, followlinks=False):
        safe_directories = []
        for name in sorted(directories, key=lambda value: (
                value.casefold(), value)):
            path = os.path.join(directory, name)
            try:
                path_stat = os.lstat(path)
            except OSError:
                continue
            if (stat.S_ISDIR(path_stat.st_mode)
                    and not _is_link_or_reparse_stat(path_stat)):
                safe_directories.append(name)
        directories[:] = safe_directories
        for name in sorted(files, key=lambda value: (
                value.casefold(), value)):
            if yielded >= max_files:
                directories[:] = []
                return
            path = os.path.join(directory, name)
            try:
                path_stat = os.lstat(path)
            except OSError:
                continue
            if (stat.S_ISREG(path_stat.st_mode)
                    and not _is_link_or_reparse_stat(path_stat)):
                yielded += 1
                yield path


def _safe_relative_path(root, parts, final_kind="directory"):
    """Return a non-symlink path below *root*, or ``None`` when unsafe."""
    current = os.path.abspath(os.fspath(root))
    for index, part in enumerate(parts):
        current = os.path.join(current, part)
        try:
            path_stat = os.lstat(current)
        except OSError:
            return None
        if _is_link_or_reparse_stat(path_stat):
            return None
        is_final = index == len(parts) - 1
        if not is_final and not stat.S_ISDIR(path_stat.st_mode):
            return None
        if is_final:
            if (final_kind == "directory"
                    and not stat.S_ISDIR(path_stat.st_mode)):
                return None
            if (final_kind == "file"
                    and not stat.S_ISREG(path_stat.st_mode)):
                return None
    return current


def _safe_smali_roots(decompiled_dir):
    """Return ``(path, display_path)`` for base/split smali directories."""
    roots = []
    for analysis_root in _iter_decompiled_roots(decompiled_dir):
        try:
            with os.scandir(analysis_root) as iterator:
                entries = sorted(iterator, key=lambda entry: (
                    entry.name.casefold(), entry.name
                ))
        except OSError:
            continue
        for entry in entries:
            if not entry.name.startswith("smali"):
                continue
            try:
                safe = (not entry.is_symlink()
                        and entry.is_dir(follow_symlinks=False))
            except OSError:
                safe = False
            if safe:
                relative = os.path.relpath(entry.path, decompiled_dir)
                roots.append((entry.path, relative.replace(os.sep, "/")))
    return roots


def _discover_native_libs(decompiled_dir, deadline=None):
    """Return native libraries plus bounded discovery-coverage issues."""
    decompiled_dir = os.path.abspath(os.fspath(decompiled_dir))
    so_files = []
    split_directories, split_issues = _split_manifest_directories(
        decompiled_dir
    )
    issues = []

    def add_issue(issue):
        if len(issues) < _MAX_NATIVE_DISCOVERY_ISSUES - 1:
            issues.append(issue)
        elif len(issues) == _MAX_NATIVE_DISCOVERY_ISSUES - 1:
            issues.append("Additional native discovery issues were omitted")

    for split_issue in split_issues:
        add_issue(f"split layout: {split_issue}")
    limit_reached = False

    def deadline_reached():
        nonlocal limit_reached
        if deadline is None or time.monotonic() < deadline:
            return False
        if not limit_reached:
            add_issue("Native library discovery exceeded scan time limit")
        limit_reached = True
        return True

    analysis_roots = [decompiled_dir] + [
        path for _relative, path in split_directories
    ]
    for analysis_root in analysis_roots:
        if deadline_reached():
            break
        rel_root = os.path.relpath(
            analysis_root, decompiled_dir
        ).replace(os.sep, "/")
        try:
            root_stat = os.lstat(analysis_root)
        except OSError as exc:
            add_issue(f"{rel_root}: {type(exc).__name__}")
            continue
        if (_is_link_or_reparse_stat(root_stat)
                or not stat.S_ISDIR(root_stat.st_mode)):
            add_issue(f"{rel_root}: unsafe analysis root")
            continue
        lib_dir = os.path.join(analysis_root, "lib")
        if not os.path.lexists(lib_dir):
            continue
        rel_lib = os.path.relpath(lib_dir, decompiled_dir).replace(os.sep, "/")
        try:
            lib_stat = os.lstat(lib_dir)
        except OSError as exc:
            add_issue(f"{rel_lib}: {type(exc).__name__}")
            continue
        if (_is_link_or_reparse_stat(lib_stat)
                or not stat.S_ISDIR(lib_stat.st_mode)):
            add_issue(f"{rel_lib}: unsafe native library directory")
            continue

        def walk_error(error):
            path = error.filename or lib_dir
            relative = os.path.relpath(path, decompiled_dir).replace(
                os.sep, "/"
            )
            add_issue(f"{relative}: {type(error).__name__}")

        for directory, directories, files in os.walk(
                lib_dir, onerror=walk_error, followlinks=False):
            if deadline_reached():
                directories[:] = []
                break
            safe_directories = []
            for name in sorted(directories, key=lambda value: (
                    value.casefold(), value)):
                if deadline_reached():
                    break
                path = os.path.join(directory, name)
                relative = os.path.relpath(path, decompiled_dir).replace(
                    os.sep, "/"
                )
                try:
                    path_stat = os.lstat(path)
                except OSError as exc:
                    add_issue(f"{relative}: {type(exc).__name__}")
                    continue
                if (_is_link_or_reparse_stat(path_stat)
                        or not stat.S_ISDIR(path_stat.st_mode)):
                    add_issue(f"{relative}: unsafe native subdirectory")
                    continue
                safe_directories.append(name)
            directories[:] = safe_directories

            for filename in sorted(files, key=lambda value: (
                    value.casefold(), value)):
                if deadline_reached():
                    directories[:] = []
                    break
                if not filename.endswith(".so"):
                    continue
                path = os.path.join(directory, filename)
                relative = os.path.relpath(path, decompiled_dir).replace(
                    os.sep, "/"
                )
                try:
                    path_stat = os.lstat(path)
                except OSError as exc:
                    add_issue(f"{relative}: {type(exc).__name__}")
                    continue
                if (_is_link_or_reparse_stat(path_stat)
                        or not stat.S_ISREG(path_stat.st_mode)):
                    add_issue(f"{relative}: unsafe native library file")
                    continue
                if len(so_files) >= _MAX_NATIVE_LIB_FILES:
                    add_issue(
                        "Native library count exceeds "
                        f"{_MAX_NATIVE_LIB_FILES} file limit"
                    )
                    limit_reached = True
                    directories[:] = []
                    break
                so_files.append((filename, relative))
            if limit_reached:
                break
        if limit_reached:
            break
    # An empty or final directory can consume the remaining budget without
    # reaching another loop guard. Record that gap before returning a
    # potentially misleading complete-no-candidate result.
    deadline_reached()
    return so_files, issues


def _scan_native_libs(decompiled_dir):
    """Collect native libraries from the base and all safe feature splits."""
    return _discover_native_libs(decompiled_dir)[0]

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

# ─── Manifest Analysis ────────────────────────────────────────────────────────────

_ANDROID_NS = "http://schemas.android.com/apk/res/android"

DANGEROUS_PERMS = {
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_PHONE_STATE", "android.permission.CAMERA",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS", "android.permission.RECORD_AUDIO",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO", "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS", "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR", "android.permission.BODY_SENSORS",
    "android.permission.MANAGE_EXTERNAL_STORAGE", "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.NEARBY_WIFI_DEVICES", "android.permission.POST_NOTIFICATIONS",
}


_STRONG_PERMISSION_LEVELS = {
    "signature", "signatureOrSystem", "knownSigner", "internal",
}

_KNOWN_STRONG_PLATFORM_PERMISSIONS = {
    # Representative framework permissions commonly used to protect exported
    # service entry points. Their protection level is defined by Android, not
    # by the application manifest being scanned.
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_AUTOFILL_SERVICE",
    "android.permission.BIND_CARRIER_MESSAGING_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_INCALL_SERVICE",
    "android.permission.BIND_INPUT_METHOD",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.BIND_PRINT_SERVICE",
    "android.permission.BIND_QUICK_SETTINGS_TILE",
    "android.permission.BIND_TELECOM_CONNECTION_SERVICE",
    "android.permission.BIND_VPN_SERVICE",
    "android.permission.BIND_WALLPAPER",
}

_KNOWN_WEAK_PLATFORM_PERMISSIONS = DANGEROUS_PERMS | {
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.BLUETOOTH",
    "android.permission.BLUETOOTH_ADMIN",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.NFC",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.VIBRATE",
    "android.permission.WAKE_LOCK",
}


def _permission_strength(manifest, permission):
    """Return ``strong``, ``weak``, or ``unknown`` for a gate permission."""
    if not permission:
        return "weak"
    level = manifest["declared_permissions"].get(permission)
    if level is not None:
        base_levels = {part.strip() for part in level.split("|")}
        return ("strong" if base_levels & _STRONG_PERMISSION_LEVELS
                else "weak")
    if permission in _KNOWN_STRONG_PLATFORM_PERMISSIONS:
        return "strong"
    if permission in _KNOWN_WEAK_PLATFORM_PERMISSIONS:
        return "weak"
    return "unknown"


def _permission_is_strong(manifest, permission):
    """Return whether this manifest proves that *permission* is strong.

    A permission that is not declared in the analyzed manifest has an unknown
    protection level.  Treating every such name as signature-level hides
    components guarded by normal platform permissions such as INTERNET.
    """
    return _permission_strength(manifest, permission) == "strong"


def _provider_protection_strength(manifest, provider):
    """Return the weakest effective provider/path permission strength."""
    strengths = [
        _permission_strength(manifest, provider.get("read_perm")),
        _permission_strength(manifest, provider.get("write_perm")),
    ]
    for path_permission in provider.get("path_permissions", []):
        for key in ("read_perm", "write_perm"):
            permission = path_permission.get(key)
            if permission is not None:
                strengths.append(_permission_strength(manifest, permission))
    if "weak" in strengths:
        return "weak"
    if strengths and all(strength == "strong" for strength in strengths):
        return "strong"
    return "unknown"


def _provider_is_strongly_protected(manifest, provider):
    """Return whether all provider-wide and path overrides are strong."""
    return _provider_protection_strength(manifest, provider) == "strong"


def _resolve_bool_resource(decompiled_dir, raw_value, default=None, min_sdk=1,
                           local_package=None):
    """Legacy wrapper for conservative manifest boolean resolution."""
    return resource_mod.resolve_boolean(
        decompiled_dir,
        raw_value,
        default=default,
        min_sdk=min_sdk,
        local_package=local_package,
    )


def _resolve_resource_variants(decompiled_dir, resource_ref,
                               expected_type="xml", min_sdk=1,
                               local_package=None):
    """Legacy wrapper returning all effective qualified resource files."""
    return resource_mod.resolve_file_variants(
        decompiled_dir,
        resource_ref,
        expected_type=expected_type,
        min_sdk=min_sdk,
        local_package=local_package,
    )


def _manifest_bool_resolution(manifest, key):
    """Return a normalized resolution, including for older mocked manifests."""
    resolution = manifest.get("attribute_states", {}).get(key)
    if resolution is not None:
        return resolution
    value = manifest.get(key)
    if value is None:
        return resource_mod.unknown_boolean(reason="Manifest boolean is unresolved")
    return resource_mod.known_boolean(value)


_SPLIT_DIRECTORY_NAME = ".apkanalyzer_splits"
_MAX_SPLIT_MANIFESTS = 1024


def _parse_single_manifest(decompiled_dir, inherited=None):
    """Parse one apktool AndroidManifest.xml for manifest-based checks.

    ``inherited`` is the already-parsed base manifest when this is a feature
    split.  Android installs evaluate split components under the base APK's
    SDK and application defaults, so an omitted split ``uses-sdk`` or
    application permission/enabled/taskAffinity must not fall back to SDK 1 or
    an unprotected application.

    Returns a dict with keys:
        parsed (bool), min_sdk, target_sdk (str or None),
        debuggable/allow_backup (bool or None when a resource is unresolved),
        attribute_states (known/conditional/unknown boolean resolutions),
        cleartext (True/False/None), cleartext_explicit (bool),
        has_nsc (bool), nsc_ref (str or None),
        permissions (set of full permission names),
        exported ({"activity"/"service"/"receiver": [{"name", "actions": [...]}],
                   "provider": [{"name", "authorities", "read_perm", "write_perm",
                                 "grant_uri", "path_permissions": [...]}]}),
        deeplinks ({"schemes": [...], "hosts": [...], "filters": [...]}),
        task_affinity (list of (activity_name, affinity) with non-empty affinity)
    Activity/service/receiver aliases use the intent-filter export default.
    Provider defaults follow Android's target-SDK-dependent behavior.
    """
    info = {
        "parsed": False,
        "min_sdk": None, "target_sdk": None,
        "debuggable": False, "allow_backup": True,
        "package": "",
        "manifest_split": "", "manifest_error": "",
        "sdk_issues": [],
        "cleartext": None, "cleartext_explicit": False,
        "has_nsc": False, "nsc_ref": None,
        "attribute_states": {},
        "resource_warnings": [],
        "application_permission": None,
        "application_task_affinity": "",
        "permissions": set(),
        "declared_permissions": {},
        "exported": {"activity": [], "service": [], "receiver": [], "provider": []},
        "deeplinks": {"schemes": [], "hosts": [], "filters": []},
        "task_affinity": [],
    }
    try:
        decompiled_mode = os.lstat(decompiled_dir).st_mode
    except OSError:
        return info
    if (stat.S_ISLNK(decompiled_mode)
            or not stat.S_ISDIR(decompiled_mode)):
        return info
    manifest_path = os.path.join(decompiled_dir, "AndroidManifest.xml")
    if not os.path.isfile(manifest_path):
        return info
    try:
        tree = _safe_parse_xml(manifest_path)
        root = tree.getroot()
    except (ET.ParseError, OSError, ValueError):
        return info
    package = root.get("package", "")
    if root.tag != "manifest" or not _is_valid_package(package):
        return info
    info["package"] = package

    ns = f"{{{_ANDROID_NS}}}"
    split_name = (root.get("split") or root.get(f"{ns}split") or "").strip()
    config_for_split = (
        root.get("configForSplit")
        or root.get(f"{ns}configForSplit")
        or ""
    ).strip()
    is_feature_split = str(
        root.get(f"{ns}isFeatureSplit") or ""
    ).strip().lower() == "true"
    info["manifest_split"] = split_name or config_for_split
    if (inherited is None
            and (split_name or config_for_split or is_feature_split)):
        info["manifest_error"] = (
            "selected APK is a feature/configuration split without its base APK"
        )
        return info
    info["parsed"] = True

    # SDK versions are base-APK policy. A feature split commonly omits
    # uses-sdk entirely; treating that as Android's SDK-1 default changes
    # provider-export and App Link decisions.
    if inherited is not None:
        info["min_sdk"] = inherited.get("min_sdk")
        info["target_sdk"] = inherited.get("target_sdk")
    else:
        uses_sdk = root.find("uses-sdk")
        if uses_sdk is not None:
            info["min_sdk"] = uses_sdk.get(f"{ns}minSdkVersion")
            info["target_sdk"] = uses_sdk.get(f"{ns}targetSdkVersion")
        if info["min_sdk"] is None or info["target_sdk"] is None:
            try:
                with open(os.path.join(decompiled_dir, "apktool.yml"), 'r', errors='ignore') as f:
                    yml = f.read()
                if info["min_sdk"] is None:
                    m = re.search(r'minSdkVersion:\s*[\'"]?(\d+)', yml)
                    if m:
                        info["min_sdk"] = m.group(1)
                if info["target_sdk"] is None:
                    m = re.search(r'targetSdkVersion:\s*[\'"]?(\d+)', yml)
                    if m:
                        info["target_sdk"] = m.group(1)
            except Exception:
                pass

    # Android's platform defaults are minSdkVersion=1 and
    # targetSdkVersion=minSdkVersion.  These defaults affect exported-provider
    # and cleartext behavior, so leaving them unknown changes security results.
    if info["min_sdk"] is None:
        info["min_sdk"] = "1"
    if info["target_sdk"] is None:
        info["target_sdk"] = info["min_sdk"]

    for key, label in (("min_sdk", "minSdkVersion"),
                       ("target_sdk", "targetSdkVersion")):
        raw_sdk = str(info[key])
        if _parse_sdk_level(raw_sdk) is None:
            info["sdk_issues"].append(
                f"{label} is a codename, malformed, or outside the "
                "supported numeric range"
            )
            # Do not retain/report a multi-megabyte attacker-controlled digit
            # string after parsing the bounded manifest.
            info[key] = _terminal_safe(raw_sdk).replace("\n", " ")[:80]

    target_level = _parse_sdk_level(info["target_sdk"])
    default_cleartext = (
        target_level <= 27 if target_level is not None else None
    )
    info["attribute_states"]["debuggable"] = resource_mod.known_boolean(
        False, reason="Android manifest default"
    )
    info["attribute_states"]["allow_backup"] = resource_mod.known_boolean(
        True, reason="Android manifest default"
    )
    info["attribute_states"]["application_enabled"] = resource_mod.known_boolean(
        True, reason="Android manifest default"
    )
    if default_cleartext is None:
        info["attribute_states"]["cleartext"] = resource_mod.unknown_boolean(
            reason="Target SDK is not numeric"
        )
    else:
        info["attribute_states"]["cleartext"] = resource_mod.known_boolean(
            default_cleartext, reason="Target-SDK platform default"
        )
        info["cleartext"] = default_cleartext

    if inherited is not None:
        # These values are not merged back into the base result, but copying
        # them here makes the inheritance contract explicit and supplies the
        # base application-enabled resolution used for split components.
        for key in (
                "debuggable", "allow_backup", "application_enabled",
                "cleartext"):
            inherited_state = inherited.get("attribute_states", {}).get(key)
            if inherited_state is not None:
                info["attribute_states"][key] = dict(inherited_state)
        info["debuggable"] = inherited.get("debuggable")
        info["allow_backup"] = inherited.get("allow_backup")
        info["cleartext"] = inherited.get("cleartext")
        info["cleartext_explicit"] = inherited.get(
            "cleartext_explicit", False
        )
        info["has_nsc"] = inherited.get("has_nsc", False)
        info["nsc_ref"] = inherited.get("nsc_ref")

    # Permissions
    for perm_tag in ("uses-permission", "uses-permission-sdk-23"):
        for perm in root.findall(perm_tag):
            name = perm.get(f"{ns}name", "")
            if name:
                info["permissions"].add(name)
    for declared in root.findall("permission"):
        name = declared.get(f"{ns}name", "")
        if name:
            info["declared_permissions"][name] = (
                declared.get(f"{ns}protectionLevel") or "normal"
            )

    # Application attributes. Split manifests inherit omitted application
    # defaults from the base, but a component-facing explicit enabled,
    # permission, or taskAffinity value is evaluated in the split's own
    # resource directory.
    app = root.find("application")
    if inherited is None:
        app_enabled_resolution = info["attribute_states"][
            "application_enabled"
        ]
        app_permission = None
        app_task_affinity = info["package"]
    else:
        app_enabled_resolution = dict(
            inherited.get("attribute_states", {}).get(
                "application_enabled",
                resource_mod.unknown_boolean(
                    reason="Base application enabled policy is unresolved"
                ),
            )
        )
        app_permission = inherited.get("application_permission")
        app_task_affinity = (
            inherited.get("application_task_affinity")
            or info["package"]
        )
    info["application_permission"] = app_permission
    info["application_task_affinity"] = app_task_affinity
    if app is not None:
        def resolve_app_bool(key, attribute, default):
            resolution = _resolve_bool_resource(
                decompiled_dir,
                app.get(f"{ns}{attribute}"),
                default=default,
                min_sdk=info["min_sdk"],
                local_package=info["package"],
            )
            info["attribute_states"][key] = resolution
            if resolution["state"] != resource_mod.KNOWN:
                info["resource_warnings"].append(
                    f"android:{attribute}: {resolution['reason']}"
                )
            return resolution

        if inherited is None:
            debuggable_resolution = resolve_app_bool(
                "debuggable", "debuggable", False
            )
            backup_resolution = resolve_app_bool(
                "allow_backup", "allowBackup", True
            )
            app_enabled_resolution = resolve_app_bool(
                "application_enabled", "enabled", True
            )
            info["debuggable"] = debuggable_resolution["value"]
            info["allow_backup"] = backup_resolution["value"]
            app_permission = app.get(f"{ns}permission") or None
            app_task_affinity = app.get(f"{ns}taskAffinity")
            if app_task_affinity is None:
                app_task_affinity = info["package"]
            nsc = app.get(f"{ns}networkSecurityConfig")
            if nsc is not None:
                info["has_nsc"] = True
                info["nsc_ref"] = nsc.lstrip("@") or None
            ct = app.get(f"{ns}usesCleartextTraffic")
            if ct is None and default_cleartext is None:
                cleartext_resolution = resource_mod.unknown_boolean(
                    reason="Target SDK is not numeric"
                )
                info["attribute_states"]["cleartext"] = cleartext_resolution
                info["resource_warnings"].append(
                    "android:usesCleartextTraffic: Target SDK is not numeric"
                )
            else:
                cleartext_resolution = resolve_app_bool(
                    "cleartext", "usesCleartextTraffic", default_cleartext
                )
            info["cleartext"] = cleartext_resolution["value"]
            info["cleartext_explicit"] = ct is not None
        else:
            enabled_raw = app.get(f"{ns}enabled")
            if enabled_raw is not None:
                app_enabled_resolution = _resolve_bool_resource(
                    decompiled_dir,
                    enabled_raw,
                    default=None,
                    min_sdk=info["min_sdk"],
                    local_package=info["package"],
                )
                info["attribute_states"][
                    "application_enabled"
                ] = app_enabled_resolution
            permission_raw = app.get(f"{ns}permission")
            if permission_raw is not None:
                app_permission = permission_raw or None
            affinity_raw = app.get(f"{ns}taskAffinity")
            if affinity_raw is not None:
                app_task_affinity = affinity_raw

        info["application_permission"] = app_permission
        info["application_task_affinity"] = app_task_affinity

        # Components
        for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            for comp in app.findall(tag):
                name = comp.get(f"{ns}name")
                component_enabled_resolution = _resolve_bool_resource(
                    decompiled_dir,
                    comp.get(f"{ns}enabled"),
                    default=True,
                    min_sdk=info["min_sdk"],
                    local_package=info["package"],
                )
                if (not name
                        or not resource_mod.may_be_true(app_enabled_resolution)
                        or not resource_mod.may_be_true(component_enabled_resolution)):
                    continue
                bucket = "activity" if tag == "activity-alias" else tag
                if bucket == "activity":
                    affinity = comp.get(f"{ns}taskAffinity")
                    if affinity is None:
                        affinity = app_task_affinity
                    if affinity and affinity != info["package"]:
                        info["task_affinity"].append((name, affinity))

                intent_filters = comp.findall("intent-filter")
                filter_details = []
                for filt in intent_filters:
                    filter_actions = [
                        action.get(f"{ns}name")
                        for action in filt.findall("action")
                        if action.get(f"{ns}name")
                    ]
                    filter_categories = [
                        category.get(f"{ns}name")
                        for category in filt.findall("category")
                        if category.get(f"{ns}name")
                    ]
                    filter_details.append(
                        (filt, filter_actions, filter_categories)
                    )

                exported_attr = comp.get(f"{ns}exported")
                if exported_attr is not None:
                    exported_resolution = _resolve_bool_resource(
                        decompiled_dir,
                        exported_attr,
                        default=False,
                        min_sdk=info["min_sdk"],
                        local_package=info["package"],
                    )
                elif tag == "provider":
                    target = info["target_sdk"]
                    target_level = _parse_sdk_level(target)
                    if target_level is not None:
                        exported_resolution = resource_mod.known_boolean(
                            target_level <= 16,
                            reason="Target-SDK provider export default",
                        )
                    else:
                        exported_resolution = resource_mod.unknown_boolean(
                            reason="Provider export default requires a numeric target SDK"
                        )
                else:
                    exported_resolution = resource_mod.known_boolean(
                        bool(intent_filters),
                        reason="Intent-filter component export default",
                    )
                if not resource_mod.may_be_true(exported_resolution):
                    continue
                exposure_resolution = resource_mod.combine_required_true(
                    app_enabled_resolution,
                    component_enabled_resolution,
                    exported_resolution,
                )

                # A browser-style deep link must be reachable from outside and
                # have VIEW, BROWSABLE, and DEFAULT in the same filter.
                # startActivity/browser resolution applies MATCH_DEFAULT_ONLY;
                # keeping filter boundaries avoids combining unrelated values.
                if bucket == "activity":
                    for filt, filter_actions, filter_categories in filter_details:
                        if ("android.intent.action.VIEW" not in filter_actions
                                or "android.intent.category.BROWSABLE"
                                not in filter_categories
                                or "android.intent.category.DEFAULT"
                                not in filter_categories):
                            continue
                        auto_verify_raw = filt.get(f"{ns}autoVerify")
                        if auto_verify_raw == "true":
                            auto_verify = True
                        elif auto_verify_raw in (None, "false"):
                            auto_verify = False
                        else:
                            auto_verify = None
                        link_filter = {
                            "component": name,
                            "component_type": tag,
                            "auto_verify": auto_verify,
                            "auto_verify_raw": auto_verify_raw,
                            "schemes": [],
                            "hosts": [],
                            "ports": [],
                            "paths": [],
                            "min_sdk": info["min_sdk"],
                            "exposure_state": exposure_resolution["state"],
                        }
                        for data in filt.findall("data"):
                            scheme = data.get(f"{ns}scheme")
                            if scheme:
                                if scheme not in link_filter["schemes"]:
                                    link_filter["schemes"].append(scheme)
                            host = data.get(f"{ns}host")
                            if host:
                                if host not in link_filter["hosts"]:
                                    link_filter["hosts"].append(host)
                            port = data.get(f"{ns}port")
                            if port and port not in link_filter["ports"]:
                                link_filter["ports"].append(port)
                            for path_kind in (
                                    "path", "pathPrefix", "pathPattern",
                                    "pathAdvancedPattern", "pathSuffix"):
                                path_value = data.get(f"{ns}{path_kind}")
                                constraint = {
                                    "kind": path_kind, "value": path_value
                                }
                                if (path_value is not None
                                        and constraint not in link_filter["paths"]):
                                    link_filter["paths"].append(constraint)
                        # URI matching requires a scheme. Host/path-only data
                        # elements must not be promoted into a reachable link.
                        if link_filter["schemes"]:
                            info["deeplinks"]["filters"].append(link_filter)
                            for scheme in link_filter["schemes"]:
                                if scheme not in info["deeplinks"]["schemes"]:
                                    info["deeplinks"]["schemes"].append(scheme)
                            for host in link_filter["hosts"]:
                                if host not in info["deeplinks"]["hosts"]:
                                    info["deeplinks"]["hosts"].append(host)

                if tag == "provider":
                    authorities = comp.get(f"{ns}authorities")
                    component_permission_attr = comp.get(f"{ns}permission")
                    component_permission = (
                        app_permission if component_permission_attr is None
                        else component_permission_attr or None
                    )
                    read_permission_attr = comp.get(f"{ns}readPermission")
                    write_permission_attr = comp.get(f"{ns}writePermission")
                    grant_uri_resolution = _resolve_bool_resource(
                        decompiled_dir,
                        comp.get(f"{ns}grantUriPermissions"),
                        default=False,
                        min_sdk=info["min_sdk"],
                        local_package=info["package"],
                    )
                    prov = {
                        "name": name,
                        "authorities": authorities.split(";") if authorities else [],
                        "read_perm": (
                            component_permission if read_permission_attr is None
                            else read_permission_attr or None
                        ),
                        "write_perm": (
                            component_permission if write_permission_attr is None
                            else write_permission_attr or None
                        ),
                        "grant_uri": grant_uri_resolution["value"],
                        "grant_uri_state": grant_uri_resolution,
                        "exposure_state": exposure_resolution["state"],
                        "exposure_resolution": exposure_resolution,
                        "path_permissions": [],
                    }
                    for pp in comp.findall("path-permission"):
                        path = (pp.get(f"{ns}path") or pp.get(f"{ns}pathPrefix")
                                or pp.get(f"{ns}pathPattern")
                                or pp.get(f"{ns}pathAdvancedPattern")
                                or pp.get(f"{ns}pathSuffix"))
                        generic_permission = pp.get(f"{ns}permission")
                        generic_permission = generic_permission or None
                        path_read_attr = pp.get(f"{ns}readPermission")
                        path_write_attr = pp.get(f"{ns}writePermission")
                        prov["path_permissions"].append({
                            "path": path,
                            "permission": generic_permission,
                            "read_perm": (
                                generic_permission if path_read_attr is None
                                else path_read_attr or None
                            ),
                            "write_perm": (
                                generic_permission if path_write_attr is None
                                else path_write_attr or None
                            ),
                        })
                    info["exported"]["provider"].append(prov)
                else:
                    actions = []
                    categories = []
                    for _filt, filter_actions, filter_categories in filter_details:
                        for act in filter_actions:
                            if act and act not in actions:
                                actions.append(act)
                        for cat in filter_categories:
                            if cat and cat not in categories:
                                categories.append(cat)
                    permission_attr = comp.get(f"{ns}permission")
                    if tag == "activity-alias":
                        component_permission = permission_attr or None
                    else:
                        component_permission = (
                            app_permission if permission_attr is None
                            else permission_attr or None
                        )
                    entry = {
                        "name": name,
                        "actions": actions,
                        "categories": categories,
                        "permission": component_permission,
                        "component_type": tag,
                        "exposure_state": exposure_resolution["state"],
                        "exposure_resolution": exposure_resolution,
                    }
                    if tag == "activity-alias":
                        entry["target_activity"] = comp.get(f"{ns}targetActivity")
                    info["exported"][bucket].append(entry)

    return info


def _split_manifest_directories(decompiled_dir):
    """Return safe split roots and bounded coverage issues.

    Only APK Analyzer's deterministic ``split_NNNN`` layout is accepted. Any
    other entry is evidence that the installed/local artifact set was not
    interpreted exactly as prepared and therefore cannot support an
    absence-based manifest claim.
    """
    split_root = os.path.join(decompiled_dir, _SPLIT_DIRECTORY_NAME)
    if not os.path.lexists(split_root):
        return [], []
    if os.path.islink(split_root) or not os.path.isdir(split_root):
        return [], [f"{_SPLIT_DIRECTORY_NAME} is not a safe directory"]

    try:
        with os.scandir(split_root) as iterator:
            entries = sorted(iterator, key=lambda entry: (
                entry.name.casefold(), entry.name
            ))
    except OSError as exc:
        return [], [
            f"{_SPLIT_DIRECTORY_NAME} is unreadable ({type(exc).__name__})"
        ]

    directories = []
    issues = []
    for entry in entries:
        relative = f"{_SPLIT_DIRECTORY_NAME}/{entry.name}"
        if not re.fullmatch(r"split_[0-9]{4}", entry.name):
            issues.append(f"Unexpected split-layout entry: {relative}")
            continue
        try:
            is_safe_directory = (
                not entry.is_symlink()
                and entry.is_dir(follow_symlinks=False)
            )
        except OSError:
            is_safe_directory = False
        if not is_safe_directory:
            issues.append(f"Unsafe or unreadable split directory: {relative}")
            continue
        if len(directories) >= _MAX_SPLIT_MANIFESTS:
            issues.append(
                f"Split count exceeds {_MAX_SPLIT_MANIFESTS} manifest limit"
            )
            break
        directories.append((relative, entry.path))
    return directories, issues


def _parse_manifest(decompiled_dir, expected_split_dirs=None,
                    expected_apk_count=None):
    """Parse the base manifest and conservatively aggregate feature splits.

    Prepared-input callers should supply both expectation arguments. Device
    caches are anchored automatically to their bounded provenance metadata.
    This prevents a deleted/corrupt split directory from being mistaken for a
    genuine single-APK application.
    """
    base = _parse_single_manifest(decompiled_dir)
    coverage = {
        "complete": True,
        "discovered": 0,
        "parsed": 0,
        "manifests": [],
        "issues": [],
    }
    base["split_manifest_coverage"] = coverage
    if not base["parsed"]:
        coverage["complete"] = False
        coverage["issues"].append(
            base.get("manifest_error")
            or "Base manifest is missing, malformed, oversized, or unsafe"
        )
        return base

    split_directories, discovery_issues = _split_manifest_directories(
        decompiled_dir
    )
    coverage["issues"].extend(discovery_issues)
    coverage["discovered"] = len(split_directories)

    if expected_apk_count is None and expected_split_dirs is None:
        metadata = _read_decompile_metadata(decompiled_dir)
        remote_paths = metadata.get("remote_apk_paths")
        if (metadata.get("source") == "device"
                and isinstance(remote_paths, list)):
            expected_apk_count = len(remote_paths)

    expected_paths = None
    if expected_split_dirs is not None:
        try:
            provided = list(expected_split_dirs)
        except TypeError:
            provided = []
            coverage["issues"].append(
                "Prepared split directory metadata is invalid"
            )
        if len(provided) > _MAX_SPLIT_MANIFESTS:
            coverage["issues"].append(
                "Prepared split directory metadata exceeds the split limit"
            )
            provided = provided[:_MAX_SPLIT_MANIFESTS]
        expected_paths = set()
        for path in provided:
            try:
                expected_paths.add(
                    os.path.normcase(os.path.abspath(os.fspath(path)))
                )
            except (TypeError, ValueError, OSError):
                coverage["issues"].append(
                    "Prepared split directory contains an invalid path"
                )
        discovered_paths = {
            os.path.normcase(os.path.abspath(path))
            for _relative, path in split_directories
        }
        if expected_paths != discovered_paths:
            coverage["issues"].append(
                "Prepared split directories do not match the decompiled layout"
            )

    if expected_apk_count is not None:
        try:
            expected_split_count = int(expected_apk_count) - 1
        except (TypeError, ValueError):
            expected_split_count = -1
        if (expected_split_count < 0
                or expected_split_count > _MAX_SPLIT_MANIFESTS):
            coverage["issues"].append(
                "Prepared APK-count metadata is invalid"
            )
        elif expected_split_count != len(split_directories):
            coverage["issues"].append(
                f"Expected {expected_split_count} split manifest(s), found "
                f"{len(split_directories)}"
            )
        if (expected_paths is not None
                and expected_split_count >= 0
                and expected_split_count != len(expected_paths)):
            coverage["issues"].append(
                "Prepared APK paths and split-directory metadata disagree"
            )
    conflicted_permissions = set()

    for relative, split_dir in split_directories:
        split = _parse_single_manifest(split_dir, inherited=base)
        if not split["parsed"]:
            coverage["issues"].append(
                f"Missing, malformed, oversized, or unsafe manifest: {relative}"
            )
            continue
        if split["package"] != base["package"]:
            coverage["issues"].append(
                f"Package mismatch in {relative}: {split['package']}"
            )
            continue

        coverage["parsed"] += 1
        coverage["manifests"].append(relative)
        base["permissions"].update(split["permissions"])
        for name, level in split["declared_permissions"].items():
            if name in conflicted_permissions:
                continue
            existing = base["declared_permissions"].get(name)
            if existing is not None and existing != level:
                base["declared_permissions"].pop(name, None)
                conflicted_permissions.add(name)
                coverage["issues"].append(
                    f"Conflicting protectionLevel for {name} in {relative}"
                )
            else:
                base["declared_permissions"][name] = level

        for bucket in ("activity", "service", "receiver", "provider"):
            for component in split["exported"][bucket]:
                component = dict(component)
                component["source_split"] = relative
                base["exported"][bucket].append(component)

        for link_filter in split["deeplinks"]["filters"]:
            link_filter = dict(link_filter)
            link_filter["source_split"] = relative
            base["deeplinks"]["filters"].append(link_filter)
        for key in ("schemes", "hosts"):
            for value in split["deeplinks"][key]:
                if value not in base["deeplinks"][key]:
                    base["deeplinks"][key].append(value)
        base["task_affinity"].extend(split["task_affinity"])
        base["resource_warnings"].extend(
            f"{relative}: {warning}"
            for warning in split["resource_warnings"]
        )

    coverage["complete"] = not coverage["issues"]
    return base


def _resolve_resource_path(decompiled_dir, resource_ref, local_package=None):
    """Resolve an apktool resource reference such as @xml/network_config."""
    return resource_mod.resolve_legacy_path(
        decompiled_dir, resource_ref, local_package=local_package
    )


# ─── Network Security Config ─────────────────────────────────────────────────────

def _analyze_nsc(decompiled_dir, nsc_path=None, target_sdk=None):
    """Parse network_security_config.xml for pinning and cleartext policy."""
    info = {"parsed": False, "pins": [], "cleartext_allowed": False,
            "cleartext_known": False,
            "cleartext_conditional": False, "complete": False,
            "trusts_user_certs": False, "trusts_debug_user_certs": False,
            "trust_anchors": [], "path": None, "paths": (),
            "resource_state": resource_mod.UNKNOWN}

    if not nsc_path:
        for rel in ("res/xml/network_security_config.xml",
                    "res/xml/network_security_config_debug.xml"):
            candidate = os.path.join(decompiled_dir, rel)
            if os.path.isfile(candidate):
                nsc_path = candidate
                break
    if not nsc_path or not os.path.isfile(nsc_path):
        return info
    info["path"] = nsc_path
    info["paths"] = (nsc_path,)

    try:
        tree = _safe_parse_xml(nsc_path, max_bytes=2 * 1024 * 1024)
        root = tree.getroot()
        if root.tag != "network-security-config":
            raise ValueError("invalid network security config root")

        def cleartext_value(node, inherited):
            raw = node.get("cleartextTrafficPermitted")
            if raw is None:
                return inherited
            if raw not in ("true", "false"):
                raise ValueError("invalid cleartextTrafficPermitted value")
            return raw == "true"

        target_level = _parse_sdk_level(target_sdk)
        platform_default = (
            target_level <= 27 if target_level is not None else None
        )

        base_configs = root.findall("./base-config")
        if len(base_configs) > 1:
            raise ValueError("multiple base-config elements")
        base_cleartext = (
            cleartext_value(base_configs[0], platform_default)
            if base_configs else platform_default
        )
        any_cleartext = base_cleartext is True

        def visit_domain_config(node, inherited):
            nonlocal any_cleartext
            effective = cleartext_value(node, inherited)
            if effective is True:
                any_cleartext = True
            for child in node.findall("./domain-config"):
                visit_domain_config(child, effective)

        for domain_config in root.findall("./domain-config"):
            visit_domain_config(domain_config, base_cleartext)

        info["cleartext_allowed"] = any_cleartext
        # If any scope explicitly/effectively permits cleartext, the risk is
        # known. Otherwise all scopes are known only when the base/default is.
        info["cleartext_known"] = any_cleartext or base_cleartext is not None

        # Pin-set entries
        for ps in root.findall(".//pin-set"):
            expiry = ps.get("expiration", "")
            for pin in ps.findall("pin"):
                digest = pin.get("digest", "")
                val = pin.text or ""
                # Get associated domains
                domains = []
                for dc in root.findall(".//domain-config"):
                    if dc.find("pin-set") is ps or any(p.text == val for p in dc.findall(".//pin")):
                        domains = [d.text for d in dc.findall("domain") if d.text]
                info["pins"].append({
                    "digest": digest, "value": val[:20] + "..." if len(val) > 20 else val,
                    "expiry": expiry, "domains": domains,
                })

        # Trust anchors in base/domain configs affect production traffic.
        for parent_tag in ("base-config", "domain-config"):
            for parent in root.findall(f".//{parent_tag}"):
                for ta in parent.findall("trust-anchors"):
                    for cert in ta.findall("certificates"):
                        src = cert.get("src", "")
                        info["trust_anchors"].append(src)
                        if src == "user":
                            info["trusts_user_certs"] = True

        # User CAs under debug-overrides are safe in non-debuggable builds and
        # should not be reported as a production trust failure.
        for ta in root.findall("./debug-overrides/trust-anchors"):
            for cert in ta.findall("certificates"):
                src = cert.get("src", "")
                if src == "user":
                    info["trusts_debug_user_certs"] = True

        info["parsed"] = True
        info["complete"] = True
        info["resource_state"] = resource_mod.KNOWN

    except (ET.ParseError, OSError, ValueError):
        pass
    return info


def _analyze_nsc_variants(decompiled_dir, resolution, target_sdk=None):
    """Analyze and conservatively merge all effective qualified NSC files."""
    merged = {"parsed": False, "pins": [], "cleartext_allowed": False,
              "cleartext_known": False, "cleartext_conditional": False,
              "complete": False, "trusts_user_certs": False,
              "trusts_debug_user_certs": False, "trust_anchors": [],
              "path": None, "paths": tuple(resolution.get("paths", ())),
              "resource_state": resolution.get("state", resource_mod.UNKNOWN),
              "resource_reason": resolution.get("reason", "")}
    paths = merged["paths"]
    if paths:
        merged["path"] = paths[0]
    analyses = [
        _analyze_nsc(decompiled_dir, nsc_path=path, target_sdk=target_sdk)
        for path in paths
    ]
    parsed = [analysis for analysis in analyses if analysis["parsed"]]
    merged["parsed"] = bool(parsed)
    merged["complete"] = bool(paths) and len(parsed) == len(paths) and (
        merged["resource_state"] != resource_mod.UNKNOWN
    )

    for analysis in parsed:
        for pin in analysis["pins"]:
            if pin not in merged["pins"]:
                merged["pins"].append(pin)
        for anchor in analysis["trust_anchors"]:
            if anchor not in merged["trust_anchors"]:
                merged["trust_anchors"].append(anchor)
        merged["trusts_user_certs"] = (
            merged["trusts_user_certs"] or analysis["trusts_user_certs"]
        )
        merged["trusts_debug_user_certs"] = (
            merged["trusts_debug_user_certs"]
            or analysis["trusts_debug_user_certs"]
        )

    known_policies = [
        analysis["cleartext_allowed"]
        for analysis in parsed
        if analysis["cleartext_known"]
    ]
    if True in known_policies:
        # A permissive effective variant is a definite exposure even when
        # another variant is missing or malformed.
        merged["cleartext_allowed"] = True
        merged["cleartext_known"] = True
    elif (merged["complete"] and len(known_policies) == len(parsed)
          and parsed):
        merged["cleartext_allowed"] = False
        merged["cleartext_known"] = True
    merged["cleartext_conditional"] = (
        len(set(known_policies)) > 1
        or (not merged["complete"] and bool(known_policies))
    )
    return merged


def _print_nsc_analysis(info):
    """Display network security config analysis."""
    if not info["parsed"]:
        return

    print(f"\n  {C.CYAN}{C.BOLD}── NETWORK SECURITY CONFIG ──{C.RST}")

    if info["pins"]:
        print(f"    {C.GREEN}[FOUND]{C.RST} {len(info['pins'])} certificate pin(s)")
        for p in info["pins"][:4]:
            domain_str = ", ".join(p["domains"][:2]) if p["domains"] else "N/A"
            pin_detail = _terminal_safe(
                f"{p['digest']}:{p['value']} → {domain_str}"
            ).replace("\n", " ")[:500]
            print(f"           {C.DIM}{pin_detail}{C.RST}")
    else:
        print(f"    {C.YELLOW}[WARN]{C.RST} No certificate pins defined in NSC")

    if info["cleartext_allowed"]:
        print(f"    {C.RED}[FAIL]{C.RST} Cleartext (HTTP) traffic allowed")
    elif info.get("cleartext_known"):
        print(f"    {C.GREEN}[PASS]{C.RST} Effective cleartext policy is disabled")
    else:
        print(f"    {C.YELLOW}[WARN]{C.RST} Effective cleartext policy could not be determined")

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
    """Check bounded base/split smali trees for known security packages."""
    found = []
    seen = set()
    remaining = _MAX_SECURITY_CLASS_FILES
    for smali_root, display_root in _safe_smali_roots(decompiled_dir):
        for pkg_path, label in SECURITY_PACKAGES.items():
            if label in seen:
                continue
            full = _safe_relative_path(smali_root, tuple(pkg_path.split("/")))
            if full is None:
                continue
            count = 0
            for path in _iter_safe_regular_files(full, remaining):
                remaining -= 1
                if path.endswith(".smali"):
                    count += 1
            found.append(
                (label, f"{display_root}/{pkg_path}/", count)
            )
            seen.add(label)
            if remaining <= 0:
                return found
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

def _bounded_printable_ascii(data, output_limit):
    """Extract printable runs without constructing unbounded output."""
    parts = []
    used = 0
    truncated = False
    for match in re.finditer(rb"[\x20-\x7e]{8,}", data):
        value = match.group()
        separator = 1 if parts else 0
        remaining = output_limit - used - separator
        if remaining <= 0:
            truncated = True
            break
        if len(value) > remaining:
            value = value[:remaining]
            truncated = True
        parts.append(value.decode("ascii"))
        used += len(value) + separator
        if truncated:
            break
    return "\n".join(parts), truncated


def _run_native_strings_tool(strings_path, library_path, timeout=30):
    """Run ``strings`` with bounded capture and descendant containment."""
    result = _process_run_command_capture(
        [strings_path, "-n", "8", library_path],
        timeout=timeout,
        max_output_bytes=_MAX_NATIVE_STRING_OUTPUT_BYTES,
    )
    return result.returncode, result.stdout, False


def _native_stat_signature(path_stat):
    """Return fields that expose path replacement or in-place mutation."""
    mtime_ns = getattr(path_stat, "st_mtime_ns", None)
    if mtime_ns is None:
        mtime_ns = int(getattr(path_stat, "st_mtime", 0.0) * 1e9)
    ctime_ns = getattr(path_stat, "st_ctime_ns", None)
    if ctime_ns is None:
        ctime_ns = int(getattr(path_stat, "st_ctime", 0.0) * 1e9)
    return (
        path_stat.st_dev,
        path_stat.st_ino,
        path_stat.st_mode,
        path_stat.st_size,
        mtime_ns,
        ctime_ns,
    )


def _read_native_file_bounded(path, initial_stat):
    """Read one native file without following a swapped link/reparse point."""
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    descriptor = os.open(path, flags)
    try:
        opened_stat = os.fstat(descriptor)
        if (not stat.S_ISREG(opened_stat.st_mode)
                or _native_stat_signature(opened_stat)
                != _native_stat_signature(initial_stat)):
            raise OSError("native library changed during open")
        with os.fdopen(descriptor, "rb") as fh:
            descriptor = None
            data = fh.read(_MAX_NATIVE_STRING_FILE_BYTES + 1)
            finished_stat = os.fstat(fh.fileno())
    finally:
        if descriptor is not None:
            os.close(descriptor)

    try:
        final_stat = os.lstat(path)
    except OSError as exc:
        raise OSError("native library changed during read") from exc
    if (_is_link_or_reparse_stat(final_stat)
            or _native_stat_signature(finished_stat)
            != _native_stat_signature(initial_stat)
            or _native_stat_signature(final_stat)
            != _native_stat_signature(initial_stat)):
        raise OSError("native library changed during read")
    return data


def _scan_native_strings(decompiled_dir, with_coverage=False):
    """Search bounded native-library strings and retain coverage evidence.

    The historical list return is preserved unless ``with_coverage`` is true.
    This keeps private integrations compatible while allowing the security
    report to distinguish a complete no-match from a timeout, unreadable
    library, tool failure, unsafe path, or size/output limit.
    """
    started = time.monotonic()
    deadline = started + _MAX_NATIVE_STRING_SCAN_SECONDS
    discovered_tool = process_mod.safe_which(
        "strings", which=shutil.which
    )
    rejected_tool_wrapper = bool(
        discovered_tool
        and discovered_tool.lower().endswith((".bat", ".cmd"))
    )
    # Batch launchers are parsed again by cmd.exe on Windows. An APK-controlled
    # library path must only ever be passed to a native argv-taking executable.
    strings_path = None if rejected_tool_wrapper else discovered_tool
    native_libs, discovery_issues = _discover_native_libs(
        decompiled_dir, deadline=deadline
    )

    results = []
    scanned = []
    unreadable = []
    oversized = []
    timed_out = []
    tool_errors = []
    partial = []
    unscanned = []
    budget_reasons = []
    considered_bytes = 0
    for index, (_filename, rel) in enumerate(native_libs):
        if index >= _MAX_NATIVE_STRING_FILES:
            unscanned.extend(item[1] for item in native_libs[index:])
            budget_reasons.append(
                "Native string candidate count exceeds "
                f"{_MAX_NATIVE_STRING_FILES} file scan limit"
            )
            break
        remaining_seconds = deadline - time.monotonic()
        if remaining_seconds <= 0:
            unscanned.extend(item[1] for item in native_libs[index:])
            budget_reasons.append(
                "Native string scan exceeded "
                f"{_MAX_NATIVE_STRING_SCAN_SECONDS} second limit"
            )
            break
        fpath = os.path.join(decompiled_dir, *rel.split("/"))
        try:
            path_stat = os.lstat(fpath)
        except OSError:
            unreadable.append(rel)
            continue
        if (_is_link_or_reparse_stat(path_stat)
                or not stat.S_ISREG(path_stat.st_mode)):
            unreadable.append(rel)
            continue
        if path_stat.st_size > _MAX_NATIVE_STRING_FILE_BYTES:
            oversized.append(rel)
            continue
        if (considered_bytes + path_stat.st_size
                > _MAX_NATIVE_STRING_TOTAL_BYTES):
            unscanned.extend(item[1] for item in native_libs[index:])
            budget_reasons.append(
                "Native string candidates exceed "
                f"{_MAX_NATIVE_STRING_TOTAL_BYTES} byte total scan limit"
            )
            break
        considered_bytes += path_stat.st_size
        if strings_path:
            try:
                tool_timeout = min(
                    _MAX_NATIVE_STRING_TOOL_SECONDS,
                    max(0.001, remaining_seconds),
                )
                returncode, lines, output_truncated = (
                    _run_native_strings_tool(
                        strings_path, fpath, timeout=tool_timeout
                    )
                )
                if returncode != 0:
                    tool_errors.append(rel)
                    continue
                if output_truncated:
                    partial.append(rel)
            except subprocess.TimeoutExpired:
                timed_out.append(rel)
                continue
            except CommandOutputLimitExceeded:
                partial.append(rel)
                continue
            except (FileNotFoundError, OSError):
                tool_errors.append(rel)
                continue
            try:
                final_stat = os.lstat(fpath)
            except OSError:
                unreadable.append(rel)
                continue
            if (_is_link_or_reparse_stat(final_stat)
                    or _native_stat_signature(final_stat)
                    != _native_stat_signature(path_stat)):
                unreadable.append(rel)
                continue
        else:
            # The Windows/Python fallback bounds both retained input and
            # extracted printable output.
            try:
                data = _read_native_file_bounded(fpath, path_stat)
            except OSError:
                unreadable.append(rel)
                continue
            if len(data) > _MAX_NATIVE_STRING_FILE_BYTES:
                oversized.append(rel)
                continue
            lines, output_truncated = _bounded_printable_ascii(
                data, _MAX_NATIVE_STRING_OUTPUT_BYTES
            )
            if output_truncated:
                partial.append(rel)

        scanned.append(rel)

        file_hits = {}
        for category, pattern in _NATIVE_STRING_PATTERNS:
            unique = []
            seen_matches = set()
            for match in pattern.finditer(lines):
                value = match.group(0)
                if value in seen_matches:
                    continue
                seen_matches.add(value)
                unique.append(value)
                if len(unique) >= 5:
                    break
            if unique:
                file_hits[category] = unique

        if file_hits:
            results.append((rel, file_hits))

    coverage = {
        "complete": not (
            discovery_issues or unreadable or oversized or timed_out
            or tool_errors or partial or unscanned or budget_reasons
        ),
        "candidate_files": len(native_libs),
        "scanned_files": len(scanned),
        "matched_files": len(results),
        "max_files": _MAX_NATIVE_LIB_FILES,
        "max_scan_files": _MAX_NATIVE_STRING_FILES,
        "max_file_bytes": _MAX_NATIVE_STRING_FILE_BYTES,
        "max_total_bytes": _MAX_NATIVE_STRING_TOTAL_BYTES,
        "max_output_bytes": _MAX_NATIVE_STRING_OUTPUT_BYTES,
        "max_scan_seconds": _MAX_NATIVE_STRING_SCAN_SECONDS,
        "considered_bytes": considered_bytes,
        "elapsed_seconds": min(
            _MAX_NATIVE_STRING_SCAN_SECONDS,
            max(0.0, time.monotonic() - started),
        ),
        "strings_tool": "python-fallback" if strings_path is None else "external",
        "rejected_batch_wrapper": rejected_tool_wrapper,
        "discovery_issues": list(discovery_issues[:100]),
        "unreadable": list(unreadable[:100]),
        "oversized": list(oversized[:100]),
        "timed_out": list(timed_out[:100]),
        "tool_errors": list(tool_errors[:100]),
        "partial": list(partial[:100]),
        "unscanned": list(unscanned[:100]),
        "unscanned_count": len(unscanned),
        "budget_reasons": list(budget_reasons),
    }
    scan_result = {"matches": results, "coverage": coverage}
    return scan_result if with_coverage else results


def _print_native_strings(results):
    """Display native string analysis results."""
    if not results:
        print(f"    {C.DIM}No security-related strings found in native libraries.{C.RST}")
        return

    for rel, hits in results:
        safe_rel = _safe_evidence_path(rel, 500)
        print(f"\n    {C.BOLD}{safe_rel}{C.RST}")
        for category, strings in hits.items():
            safe_strings = [
                _terminal_safe(value).replace("\n", " ")
                for value in strings[:3]
            ]
            preview = ", ".join(
                value if len(value) <= 40 else value[:37] + "..."
                for value in safe_strings
            )
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

# ─── 2. Storage Audit ───────────────────────────────────────────────────────────

STATIC_SECRET_CHUNK_BYTES = secrets_mod.DEFAULT_CHUNK_BYTES
STATIC_SECRET_CHUNK_OVERLAP_CHARS = secrets_mod.DEFAULT_OVERLAP_CHARS
STATIC_SECRET_MAX_FILE_BYTES = secrets_mod.DEFAULT_MAX_FILE_BYTES
STATIC_SECRET_MAX_TOTAL_BYTES = secrets_mod.DEFAULT_MAX_TOTAL_BYTES
STATIC_SECRET_EXTENSIONS = secrets_mod.DEFAULT_EXTENSIONS

STATIC_CODE_CHUNK_BYTES = code_scan_mod.DEFAULT_CHUNK_BYTES
STATIC_CODE_MAX_FILE_BYTES = code_scan_mod.DEFAULT_MAX_FILE_BYTES
STATIC_CODE_MAX_TOTAL_BYTES = code_scan_mod.DEFAULT_MAX_TOTAL_BYTES
STATIC_CODE_EXTENSIONS = code_scan_mod.DEFAULT_EXTENSIONS


def _should_scan_static_secrets(path):
    """Return whether a path is a supported likely-text secret source."""
    return secrets_mod.is_candidate(path, STATIC_SECRET_EXTENSIONS)


_SECRET_KEY_PATTERN = (
    r'(?:password|passwd|pwd|api[_-]?key|apikey|secret[_-]?key|'
    r'client[_-]?secret|app[_-]?secret|access[_-]?key|access[_-]?token|'
    r'private[_-]?key|signing[_-]?key|auth[_-]?token|session[_-]?token|'
    r'refresh[_-]?token|encryption[_-]?key|master[_-]?key|db[_-]?password|'
    r'aws[_-]?secret[_-]?access[_-]?key|aws[_-]?session[_-]?token|'
    r'firebase[_-]?(?:api[_-]?key|token|secret)|'
    r'google[_-]?(?:api[_-]?key|cloud[_-]?key|maps[_-]?key)|'
    r'(?:azure|az)[_-]?(?:storage[_-]?key|connection[_-]?string|client[_-]?secret)|'
    r'twilio[_-]?(?:auth[_-]?token|api[_-]?key|account[_-]?sid)|'
    r'merchant[_-]?key|payment[_-]?secret|'
    r'(?:paypal|braintree|razorpay)[_-]?(?:secret|key|token)|'
    r'(?:fcm|push|gcm|apns)[_-]?key|oauth[_-]?token|'
    r'database[_-]?url|db[_-]?connection)'
)

# Capture only the value so redaction can retain JSON/XML/property syntax.  A
# bare assignment remains whitespace-delimited; quoted JSON/XML values have
# dedicated patterns below and may safely contain spaces.
_SECRET_ASSIGNMENT_VALUE = (
    r'(?:"(?P<secret_double>(?:\\.|[^"\\])*)"'
    r"|'(?P<secret_single>(?:\\.|[^'\\])*)'"
    r"|(?P<secret_bare>[^\s,;<>'\"]+))"
)

SECRET_PATTERNS = [
    # Normal JSON and Android SharedPreferences XML representations.
    re.compile(
        rf'"{_SECRET_KEY_PATTERN}"\s*:\s*'
        r'"(?P<secret_json>(?:\\.|[^"\\])*)"',
        re.IGNORECASE,
    ),
    re.compile(
        rf'<string\b(?=[^>]*\bname\s*=\s*["\']{_SECRET_KEY_PATTERN}["\'])'
        r'[^>]*>(?P<secret_xml>[^<]*)</string\s*>',
        re.IGNORECASE,
    ),
    # apktool/smali static String fields keep a JVM type descriptor between
    # the key-like field name and its quoted initializer.
    re.compile(
        rf'(?m)^\s*\.field\b[^\r\n]*\b{_SECRET_KEY_PATTERN}'
        r':Ljava/lang/String;\s*=\s*"(?P<secret_smali>(?:\\.|[^"\\])*)"',
        re.IGNORECASE,
    ),
    # Generic quoted or whitespace-delimited key/value assignments.
    re.compile(
        rf'(?<![\w-]){_SECRET_KEY_PATTERN}\s*[=:]\s*'
        rf'(?!\[*(?:[ZBSCIJFDV]|L[A-Za-z0-9_/$]+;)(?=\s*(?:=|$)))'
        rf'{_SECRET_ASSIGNMENT_VALUE}',
        re.IGNORECASE,
    ),
    re.compile(
        r'(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}'
        r'\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        r'(?![A-Za-z0-9_-])'
    ),  # compact JWT/JWS
    re.compile(r'bearer\s+[A-Za-z0-9_.-]+', re.IGNORECASE),
    # Azure Storage connection strings are credentials only when they carry
    # AccountKey/SAS material; protocol + public account name alone is config.
    re.compile(
        r'DefaultEndpointsProtocol=https;'
        r'(?=[^\s]*(?:AccountKey|SharedAccessSignature)=)[^\s]+',
        re.IGNORECASE,
    ),
    # Stripe.
    re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
    re.compile(r'rk_live_[0-9a-zA-Z]{24,}'),
    # SendGrid.
    re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'),
    # Slack.
    re.compile(r'xox[bprs]-[0-9a-zA-Z-]+'),
    re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+'),
    # GitHub.
    re.compile(r'gh[ps]_[A-Za-z0-9_]{36,}'),
    re.compile(r'github_pat_[A-Za-z0-9_]{22,}'),
    # Legacy FCM server-key syntax.  Boundaries prevent matching the suffix of
    # names such as firebase_api_key.
    re.compile(
        r'(?<![\w-])key=(?P<secret_fcm>[A-Za-z0-9_-]{39})(?![A-Za-z0-9_-])',
        re.IGNORECASE,
    ),
    # Database connection string with a fixed first ':' and '@' delimiter.
    # The disjoint character classes avoid the quadratic backtracking caused
    # by the former ``\S+:\S+@\S+`` expression on colon-heavy malformed input.
    re.compile(
        r'\b(?P<secret_db>(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://'
        r'[^\s/:@]+:[^\s/@]+@[^\s/?#]+(?:[/?#][^\s]*)?)',
        re.IGNORECASE,
    ),
    # Private keys.  Redact the complete block rather than only its BEGIN
    # marker; a truncated block is treated conservatively through EOF.
    re.compile(
        r'(?P<secret_pem>-----BEGIN '
        r'(?P<secret_pem_label>(?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY)-----'
        r'[\s\S]{0,500000}?(?:-----END (?P=secret_pem_label)-----|\Z))'
    ),
]

_SECRET_VALUE_GROUPS = (
    "secret_double", "secret_single", "secret_bare", "secret_json",
    "secret_xml", "secret_smali", "secret_fcm", "secret_db", "secret_pem",
)
_PUBLIC_IDENTIFIER_PATTERNS = (
    # Firebase/Google Android API keys are public identifiers whose security
    # comes from API/application restrictions, not from keeping the value secret.
    re.compile(r'AIza[0-9A-Za-z_-]{35}'),
    # Twilio SK values are API-key SIDs; the separately returned Secret is the
    # credential and does not use this format.
    re.compile(r'SK[0-9a-fA-F]{32}'),
    re.compile(r'AC[0-9a-fA-F]{32}'),  # Twilio Account SID
    re.compile(r'AKIA[0-9A-Z]{16}'),  # AWS access-key ID, not the secret key
)


def _secret_value_and_span(match):
    """Return the credential portion of a secret match and its source span."""
    groups = match.groupdict()
    for name in _SECRET_VALUE_GROUPS:
        value = groups.get(name)
        if value is not None:
            return value, match.span(name)
    return match.group(0), match.span(0)


def _is_public_secret_identifier(value):
    candidate = value.strip()
    return any(pattern.fullmatch(candidate)
               for pattern in _PUBLIC_IDENTIFIER_PATTERNS)


def _is_non_secret_endpoint_config(value):
    """Exclude public Azure endpoint/account metadata without credentials."""
    candidate = value.strip()
    if not candidate.lower().startswith("defaultendpointsprotocol="):
        return False
    return not re.search(
        r'(?:^|;)(?:AccountKey|SharedAccessSignature)=',
        candidate,
        re.IGNORECASE,
    )


def _iter_secret_matches(content, per_pattern_limit=None):
    """Yield non-empty, non-public secret matches with bounded per-rule output."""
    for pattern in SECRET_PATTERNS:
        count = 0
        for match in pattern.finditer(content):
            value, _span = _secret_value_and_span(match)
            if (not value.strip()
                    or _is_public_secret_identifier(value)
                    or _is_non_secret_endpoint_config(value)):
                continue
            yield match
            count += 1
            if per_pattern_limit is not None and count >= per_pattern_limit:
                break


def _find_secret_matches(content, per_pattern_limit=None):
    """Return full regex matches, excluding known public identifiers."""
    return [match.group(0) for match in
            _iter_secret_matches(content, per_pattern_limit)]


def _redact_secret_text(content):
    """Redact complete credential spans while retaining surrounding syntax."""
    spans = []
    for match in _iter_secret_matches(content):
        _value, span = _secret_value_and_span(match)
        if span[0] != span[1]:
            spans.append(span)
    if not spans:
        return content

    merged = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))

    redacted = content
    for start, end in reversed(merged):
        redacted = redacted[:start] + "[REDACTED]" + redacted[end:]
    return redacted


def _sqlite_identifier(name):
    """Quote an SQLite identifier obtained from an untrusted app database."""
    if not name or any(ord(ch) < 32 for ch in name):
        raise ValueError("invalid SQLite identifier")
    return '"' + name.replace('"', '""') + '"'


def _sqlite_read(db_path, query, timeout=5):
    """Run a read-only sqlite3 query without exposing it to the device shell."""
    return adb_su(
        f"sqlite3 {shlex.quote(db_path)} {shlex.quote(query)} 2>/dev/null",
        timeout=timeout,
    )

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

def _scan_pii(content, max_hits=None):
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
                if max_hits is not None and len(hits) >= max_hits:
                    return hits
    return hits


def _redact_sensitive_text(content):
    """Redact detected secrets and PII before showing raw storage previews."""
    redacted = _redact_secret_text(content)
    for pattern, _label in PII_PATTERNS:
        redacted = pattern.sub(lambda match: _redact(match.group(0)), redacted)
    return _terminal_safe(redacted)

def _batch_read_files(paths, per_file_bytes=100000, chunk=30):
    """Read many device files with as few adb round-trips as possible.
    Returns (contents, sizes): {path: content}, {path: size_str}."""
    contents = {}
    sizes = {}
    for i in range(0, len(paths), chunk):
        batch = paths[i:i + chunk]
        marker = "APK" + os.urandom(12).hex()
        file_marker = f"@@@{marker}:FILE:"
        size_marker = f"@@@{marker}:SIZE:"
        quoted = " ".join(shlex.quote(p) for p in batch)
        cmd = (f'for f in {quoted}; do echo "{file_marker}$f"; '
               f'echo "{size_marker}$(wc -c < "$f" 2>/dev/null)"; '
               f'head -c {per_file_bytes} "$f" 2>/dev/null; echo; done')
        out = adb_su(cmd, timeout=60)
        parsed = {}
        cur = None
        for line in out.splitlines():
            if line.startswith(file_marker):
                cur = line[len(file_marker):]
                parsed[cur] = []
            elif line.startswith(size_marker) and cur is not None:
                size = line[len(size_marker):].strip()
                sizes[cur] = size if size.isdigit() else "?"
            elif cur is not None:
                parsed[cur].append(line)
        if not parsed and batch:
            # Odd toybox/shell behavior — fall back to per-file reads
            for p in batch:
                contents[p] = adb_su(f"cat {shlex.quote(p)} 2>/dev/null", timeout=15)
                sizes[p] = "?"
        else:
            for p, lines in parsed.items():
                contents[p] = "\n".join(lines).rstrip("\n")
    return contents, sizes

def _batch_stat(paths, chunk=50):
    """Get permission modes for many device files in a few adb calls.
    Returns {path: mode_str} (e.g. '644')."""
    modes = {}
    for i in range(0, len(paths), chunk):
        batch = paths[i:i + chunk]
        batch_set = set(batch)
        quoted = " ".join(shlex.quote(p) for p in batch)
        out = adb_su(f"stat -c '%a %n' {quoted} 2>/dev/null", timeout=30)
        if _is_err(out):
            continue
        for line in out.splitlines():
            parts = line.split(" ", 1)
            if len(parts) == 2 and parts[1] in batch_set:
                modes[parts[1]] = parts[0]
    return modes

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

# ─── 5. Security Scan ───────────────────────────────────────────────────────────

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
        "remediation": "Raise minSdkVersion to 23+ and targetSdkVersion to 35+",
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

def _finding_line(check_key, label, detail=""):
    """Print a FAIL finding with severity, MASVS category, and CWE ID."""
    sev_tag, ref_tag = _severity_tag(check_key)
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
        "pending_invocations": [],
        "unprotected_broadcasts": 0,
        "protected_broadcasts": 0,
        "flag_secure_found": False,
        "clip_usage": 0,
        "clip_protection": 0,
        "clip_unprotected_writes": 0,
        "clip_unprotected_files": [],
        "log_hits": {},
        "pw_fields": 0,
        "nosuggest": 0,
        "has_filter_touches": False,
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
            for pending in _analyze_pending_intents(content):
                pending["file"] = relative
                signals["pending_invocations"].append(pending)
            if ('sendBroadcast(Landroid/content/Intent;)V' in content
                    and 'LocalBroadcastManager' not in content):
                signals["unprotected_broadcasts"] += 1
            if ('sendBroadcast(Landroid/content/Intent;Ljava/lang/String;)V'
                    in content):
                signals["protected_broadcasts"] += 1
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
                for keyword in keywords:
                    if keyword in content:
                        signals["log_hits"][framework] = (
                            signals["log_hits"].get(framework, 0) + 1
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
    pending_invocations = static_code_signals["pending_invocations"]
    unprotected_broadcasts = static_code_signals["unprotected_broadcasts"]
    protected_broadcasts = static_code_signals["protected_broadcasts"]
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

    def _record_finding(check_key, description="", extra_detail=""):
        """Record a finding, increment severity counter, and add to report."""
        nonlocal total_findings
        total_findings += 1
        info = SECURITY_CHECKS.get(check_key, {})
        sev = info.get("severity", "MEDIUM")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        # Also add to global report collector
        report.add_finding(
            category=info.get("masvs", "General"),
            title=info.get("title", check_key),
            severity=sev,
            confidence="HIGH",
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
        if unprotected_broadcasts > 0:
            _finding_line(
                "unprotected_broadcasts",
                ("sendBroadcast() without permission in "
                 f"{unprotected_broadcasts} file(s)"),
            )
            fails += 1
            _record_finding(
                "unprotected_broadcasts",
                ("sendBroadcast() without permission in "
                 f"{unprotected_broadcasts} file(s). Any app can intercept."),
            )
            print(
                f"    {C.DIM}Risk: Any app can intercept implicit "
                f"broadcasts{C.RST}"
            )
            if protected_broadcasts > 0:
                print(
                    f"    {C.DIM}{protected_broadcasts} file(s) use "
                    f"permission-protected broadcasts{C.RST}"
                )
            if not code_coverage_complete:
                code_coverage_warning("Broadcast coverage")
        elif protected_broadcasts > 0 and code_coverage_complete:
            clean_result(
                "Broadcast security",
                ("All broadcasts use permission protection "
                 f"({protected_broadcasts} file(s))")
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
                f"Debug/verbose log calls found ({total} file(s))",
            )
            warns += 1
            log_detail = ", ".join(
                f"{framework}: {count}"
                for framework, count in log_hits.items()
            )
            _record_finding(
                "debug_logging",
                (f"Debug/verbose log calls found in {total} file(s): "
                 f"{log_detail}"),
            )
            for framework, count in log_hits.items():
                print(f"    {C.DIM}\u2022 {framework}: {count} file(s){C.RST}")
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
        safe_independent_secret_files = [
            _safe_evidence_path(path) for path in independent_secret_files
        ]
        print(f"\n  {C.YELLOW}{C.BOLD}── Data Leakage Check ──{C.RST}")
        if independent_secret_files:
            _finding_line(
                "hardcoded_secrets", "Hardcoded secrets",
                f"Potential secrets found in {len(independent_secret_files)} file(s)",
            )
            info = SECURITY_CHECKS["hardcoded_secrets"]
            report.add_finding(
                category=info["masvs"], title=info["title"],
                severity=info["severity"], confidence="HIGH",
                description=(
                    "Potential secrets/keys found despite an unreadable manifest: "
                    + ", ".join(safe_independent_secret_files[:5])
                ),
                remediation=info["remediation"], masvs=info["masvs"],
                cwe=info["cwe"], rule_id="hardcoded_secrets",
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

    # ── 2. Backup ────────────────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Backup Check ──{C.RST}")
    total_checks_run += 1
    allow_backup = manifest["allow_backup"]
    backup_resolution = _manifest_bool_resolution(manifest, "allow_backup")
    if backup_resolution["state"] == resource_mod.KNOWN and allow_backup:
        _finding_line("allow_backup", "allowBackup", "App data can be backed up via adb — data extraction risk")
        fails += 1
        _record_finding("allow_backup", "android:allowBackup is true. App data can be extracted via adb backup.")
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

    # ── 5. SDK Version ───────────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── SDK Version ──{C.RST}")
    total_checks_run += 1
    # SDK info from the parsed manifest (apktool.yml fallback handled by _parse_manifest)
    raw_min_sdk = manifest["min_sdk"]
    raw_target_sdk = manifest["target_sdk"]
    min_level = _parse_sdk_level(raw_min_sdk)
    target_level = _parse_sdk_level(raw_target_sdk)
    min_sdk = str(min_level) if min_level is not None else "N/A"
    target_sdk = str(target_level) if target_level is not None else "N/A"

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

    if target_level is not None and target_level < 35:
        if not sdk_failed:
            _finding_line("sdk_version", "Target SDK", f"targetSdk={target_sdk} — below current level 35+")
            _record_finding("sdk_version",
                             f"targetSdkVersion={target_sdk} is below current level 35+.")
        else:
            warn_line(f"targetSdk={target_sdk} — below current level 35+")
        warns += 1
    elif target_level is not None:
        pass_fail("Target SDK", True, f"targetSdk={target_sdk}")
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
        safe_secret_files = [
            _safe_evidence_path(path) for path in secrets_files
        ]
        _finding_line("hardcoded_secrets", "Hardcoded secrets", f"Potential secrets found in {len(secrets_files)} file(s)")
        fails += 1
        _record_finding("hardcoded_secrets",
                         f"Potential secrets/keys found in {len(secrets_files)} file(s): {', '.join(safe_secret_files[:5])}")
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

# ─── Frida Gadget APK Patcher ────────────────────────────────────────────────────

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
    if not report.findings:
        print(f"\n  {C.YELLOW}[!] No findings collected yet.{C.RST}")
        print(f"  {C.DIM}Run a Security Scan (option 5) first to collect findings.{C.RST}")
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
    if args.report and report.findings:
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

    report.target_app = selected_pkg

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
                report.target_app = new_pkg
                report.findings.clear()
                report.app_info.clear()
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

if __name__ == "__main__":
    sys.exit(_entrypoint())
