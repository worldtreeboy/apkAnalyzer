"""Installed-APK decompile cache and native-library discovery.

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

__all__ = [
    '_get_version_code',
    '_get_package_fingerprint',
    '_DECOMPILE_CACHE_SCHEMA',
    '_MAX_DECOMPILE_METADATA_BYTES',
    '_MAX_CACHE_INTEGRITY_ENTRIES',
    '_MAX_CACHE_INTEGRITY_BYTES',
    '_CACHE_INTEGRITY_CHUNK_BYTES',
    '_device_decompile_metadata',
    '_write_decompile_metadata',
    '_read_decompile_metadata',
    '_decompile_cache_provenance',
    '_cache_stat_signature',
    '_is_cache_reparse_point',
    '_digest_cache_field',
    '_decompile_integrity_seal',
    '_validate_cached_decompile_integrity',
    '_validate_cached_base_apk',
    '_preflight_apk_artifacts',
    '_validate_cached_decompile_layout',
    '_pull_and_decompile',
    '_MAX_NATIVE_LIB_FILES',
    '_MAX_SECURITY_CLASS_FILES',
    '_MAX_NATIVE_STRING_FILE_BYTES',
    '_MAX_NATIVE_STRING_OUTPUT_BYTES',
    '_MAX_NATIVE_STRING_FILES',
    '_MAX_NATIVE_STRING_TOTAL_BYTES',
    '_MAX_NATIVE_STRING_SCAN_SECONDS',
    '_MAX_NATIVE_STRING_TOOL_SECONDS',
    '_MAX_NATIVE_DISCOVERY_ISSUES',
    '_iter_decompiled_roots',
    '_iter_safe_regular_files',
    '_safe_relative_path',
    '_safe_smali_roots',
    '_discover_native_libs',
    '_scan_native_libs',
]
