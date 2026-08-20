"""Safe local APK, split-APK, APK Set, and App Bundle preparation.

This module contains no ADB or interactive UI code.  Callers provide existing
tool commands as argument lists; every external command is executed without a
host shell and decompilation is staged atomically.
"""

import hashlib
import os
import re
import shutil
import stat
import struct
import subprocess
import tempfile
import time
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass

from .archive import filesystem_is_case_sensitive
from .process import (
    CommandOutputLimitExceeded,
    MAX_COMMAND_OUTPUT_BYTES,
    run_command_capture,
)


DEFAULT_MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_MAX_ZIP_ENTRIES = 20_000
DEFAULT_MAX_CENTRAL_DIRECTORY_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_ZIP_NAME_BYTES = 4 * 1024
DEFAULT_MAX_ZIP_TOTAL_NAME_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_ZIP_PATH_DEPTH = 128
DEFAULT_MAX_ZIP_MEMBER_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_ZIP_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_MAX_COMPRESSION_RATIO = 1_000.0
DEFAULT_MAX_APK_COUNT = 200
DEFAULT_DECOMPILE_TIMEOUT = 900
_ORIGINAL_SUBPROCESS_RUN = subprocess.run

_FILE_MARKER = None
_DIRECTORY_MARKER = object()
_WINDOWS_RESERVED_NAMES = {
    "con", "prn", "aux", "nul",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}


class InputPreparationError(RuntimeError):
    """Raised when local input cannot be analyzed safely or completely."""


@dataclass(frozen=True)
class ArchiveLimits:
    """Bounds applied before apktool or bundletool sees untrusted archives."""

    max_archive_bytes: int = DEFAULT_MAX_ARCHIVE_BYTES
    max_entries: int = DEFAULT_MAX_ZIP_ENTRIES
    max_central_directory_bytes: int = DEFAULT_MAX_CENTRAL_DIRECTORY_BYTES
    max_name_bytes: int = DEFAULT_MAX_ZIP_NAME_BYTES
    max_total_name_bytes: int = DEFAULT_MAX_ZIP_TOTAL_NAME_BYTES
    max_path_depth: int = DEFAULT_MAX_ZIP_PATH_DEPTH
    max_member_bytes: int = DEFAULT_MAX_ZIP_MEMBER_BYTES
    max_total_bytes: int = DEFAULT_MAX_ZIP_TOTAL_BYTES
    max_compression_ratio: float = DEFAULT_MAX_COMPRESSION_RATIO
    max_apk_count: int = DEFAULT_MAX_APK_COUNT


@dataclass(frozen=True)
class ZipPreflight:
    """Metadata produced by a successful bounded ZIP preflight."""

    entries: int
    files: int
    compressed_bytes: int
    uncompressed_bytes: int


@dataclass(frozen=True)
class ApkInputSet:
    """One logical application represented by one or more APK files."""

    source_path: str
    input_kind: str
    apk_paths: tuple
    base_apk: str
    variant_union: bool = False


def _is_link_or_reparse_point(path_stat):
    """Detect POSIX links and Windows junction/reparse-point escapes."""
    if stat.S_ISLNK(path_stat.st_mode):
        return True
    attributes = getattr(path_stat, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def _stat_timestamp_ns(path_stat, name):
    """Return a stable nanosecond timestamp on every supported Python."""
    nanosecond_name = name + "_ns"
    if hasattr(path_stat, nanosecond_name):
        return getattr(path_stat, nanosecond_name)
    return int(getattr(path_stat, name) * 1_000_000_000)


def _snapshot_signature(path_stat):
    """Fields that change if a source is replaced or modified during copy."""
    return (
        getattr(path_stat, "st_dev", None),
        getattr(path_stat, "st_ino", None),
        stat.S_IFMT(path_stat.st_mode),
        path_stat.st_size,
        _stat_timestamp_ns(path_stat, "st_mtime"),
        _stat_timestamp_ns(path_stat, "st_ctime"),
        getattr(path_stat, "st_file_attributes", 0),
    )


def _same_file_identity(first, second):
    """Compare two stat results without following a pathname again."""
    first_identity = (
        getattr(first, "st_dev", None), getattr(first, "st_ino", None)
    )
    second_identity = (
        getattr(second, "st_dev", None), getattr(second, "st_ino", None)
    )
    # CPython may expose zero file indexes on unusual Windows filesystems.
    # In that case the full snapshot signature below still detects ordinary
    # replacements and mutations; do not treat two meaningless zeroes as the
    # sole proof that the path and handle identify the same file.
    if first_identity != (0, 0) or second_identity != (0, 0):
        return first_identity == second_identity
    return _snapshot_signature(first) == _snapshot_signature(second)


def _source_open_flags(directory=False):
    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOINHERIT", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    return flags


def _write_all(file_descriptor, data):
    """Write a complete chunk while handling legal short writes."""
    view = memoryview(data)
    while view:
        written = os.write(file_descriptor, view)
        if written <= 0:
            raise OSError("snapshot write made no progress")
        view = view[written:]


def _snapshot_regular_file(source_path, destination, max_bytes, *,
                           expected_stat=None, source_dir_fd=None,
                           source_name=None):
    """Copy one stable regular file through a no-follow descriptor.

    The destination is created exclusively inside private staging.  The
    pathname/entry and open handle are compared before and after the bounded
    copy so a concurrent symlink swap, replacement, truncation, or append is
    rejected instead of silently changing what a later tool analyzes.
    """
    display_path = os.path.abspath(os.fspath(source_path))
    lookup_name = source_name if source_dir_fd is not None else display_path
    created = False
    copy_complete = False
    source_fd = None
    destination_fd = None
    try:
        if source_dir_fd is None:
            initial_stat = os.lstat(lookup_name)
        else:
            initial_stat = os.stat(
                lookup_name, dir_fd=source_dir_fd, follow_symlinks=False
            )
        if expected_stat is not None:
            if (not _same_file_identity(expected_stat, initial_stat)
                    or _snapshot_signature(expected_stat)
                    != _snapshot_signature(initial_stat)):
                raise InputPreparationError(
                    f"input changed while it was being enumerated: {display_path}"
                )
        if _is_link_or_reparse_point(initial_stat):
            raise InputPreparationError(
                "symlinked or reparse-point APK input is not supported: "
                f"{display_path}"
            )
        if not stat.S_ISREG(initial_stat.st_mode):
            raise InputPreparationError(
                f"APK input is not a regular file: {display_path}"
            )
        if initial_stat.st_size < 0 or initial_stat.st_size > max_bytes:
            raise InputPreparationError(
                f"input exceeds {max_bytes} byte snapshot safety limit"
            )

        if source_dir_fd is None:
            source_fd = os.open(lookup_name, _source_open_flags())
        else:
            source_fd = os.open(
                lookup_name,
                _source_open_flags(),
                dir_fd=source_dir_fd,
            )
        opened_stat = os.fstat(source_fd)
        if (_is_link_or_reparse_point(opened_stat)
                or not stat.S_ISREG(opened_stat.st_mode)
                or not _same_file_identity(initial_stat, opened_stat)
                or _snapshot_signature(initial_stat)
                != _snapshot_signature(opened_stat)):
            raise InputPreparationError(
                f"input changed while it was being opened: {display_path}"
            )

        destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        destination_flags |= getattr(os, "O_BINARY", 0)
        destination_flags |= getattr(os, "O_CLOEXEC", 0)
        destination_flags |= getattr(os, "O_NOINHERIT", 0)
        destination_flags |= getattr(os, "O_NOFOLLOW", 0)
        destination_fd = os.open(destination, destination_flags, 0o600)
        created = True
        if not stat.S_ISREG(os.fstat(destination_fd).st_mode):
            raise InputPreparationError("snapshot destination is not a regular file")

        copied = 0
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            copied += len(chunk)
            if copied > max_bytes:
                raise InputPreparationError(
                    f"input exceeds {max_bytes} byte snapshot safety limit"
                )
            _write_all(destination_fd, chunk)
        os.fsync(destination_fd)

        final_handle_stat = os.fstat(source_fd)
        if source_dir_fd is None:
            final_path_stat = os.lstat(lookup_name)
        else:
            final_path_stat = os.stat(
                lookup_name, dir_fd=source_dir_fd, follow_symlinks=False
            )
        if (copied != opened_stat.st_size
                or _snapshot_signature(final_handle_stat)
                != _snapshot_signature(opened_stat)
                or not _same_file_identity(final_path_stat, opened_stat)
                or _snapshot_signature(final_path_stat)
                != _snapshot_signature(opened_stat)
                or _is_link_or_reparse_point(final_path_stat)):
            raise InputPreparationError(
                f"input changed while it was being snapshotted: {display_path}"
            )
        copy_complete = True
    except InputPreparationError:
        raise
    except OSError as exc:
        raise InputPreparationError(
            f"could not snapshot local input {display_path}: {exc}"
        ) from exc
    finally:
        if destination_fd is not None:
            os.close(destination_fd)
        if source_fd is not None:
            os.close(source_fd)
        if created and not copy_complete:
            try:
                os.unlink(destination)
            except OSError:
                pass

    _make_snapshot_read_only(destination)
    return destination


def _directory_fd_traversal_supported():
    """Whether this runtime can pin directory traversal to open handles."""
    return (
        os.name != "nt"
        and os.open in getattr(os, "supports_dir_fd", set())
        and os.stat in getattr(os, "supports_dir_fd", set())
        and os.scandir in getattr(os, "supports_fd", set())
    )


def _make_snapshot_read_only(path):
    """Protect staged files without creating undeletable Windows artifacts."""
    # On Windows os.chmod(..., S_IRUSR) sets FILE_ATTRIBUTE_READONLY. Python
    # 3.8's TemporaryDirectory/rmtree cannot reliably remove such files, so
    # private unpredictable staging is the protection there. POSIX staging is
    # additionally made owner-readable only.
    if os.name == "nt":
        return
    try:
        os.chmod(path, stat.S_IRUSR)
    except OSError as exc:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise InputPreparationError(
            f"could not make input snapshot read-only: {exc}"
        ) from exc


@dataclass(frozen=True)
class PreparedInput:
    """Decompiled local input ready for the legacy static scanner."""

    source_path: str
    input_kind: str
    apk_paths: tuple
    base_apk: str
    work_dir: str
    decompiled_dir: str
    split_decompiled_dirs: tuple
    variant_union: bool = False


def _member_parts(name):
    """Validate an archive member name and return POSIX path components."""
    if not name or "\x00" in name or "\\" in name:
        raise InputPreparationError(f"unsafe ZIP member path: {name!r}")
    if any(ord(character) < 32 or 127 <= ord(character) < 160
           for character in name):
        raise InputPreparationError(
            "unsafe ZIP member path contains a control character"
        )
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        raise InputPreparationError(f"unsafe ZIP member path: {name!r}")
    trimmed = name[:-1] if name.endswith("/") else name
    if not trimmed:
        raise InputPreparationError(f"unsafe ZIP member path: {name!r}")
    parts = trimmed.split("/")
    if any(part in ("", ".", "..") or ":" in part for part in parts):
        raise InputPreparationError(f"unsafe ZIP member path: {name!r}")
    return parts


def _collision_parts(parts, case_sensitive, windows_paths=False):
    """Normalize names that collide on common extraction filesystems."""
    normalized = [unicodedata.normalize("NFC", part) for part in parts]
    if windows_paths:
        windows_normalized = []
        for part in normalized:
            if (any(ord(character) < 32 for character in part)
                    or any(character in '<>"|?*' for character in part)):
                raise InputPreparationError(
                    f"ZIP member is not representable on Windows: {part!r}"
                )
            trimmed = part.rstrip(" .")
            if not trimmed:
                raise InputPreparationError(
                    f"ZIP member is not representable on Windows: {part!r}"
                )
            device_name = trimmed.split(".", 1)[0].casefold()
            if device_name in _WINDOWS_RESERVED_NAMES:
                raise InputPreparationError(
                    f"ZIP member uses a reserved Windows name: {part!r}"
                )
            windows_normalized.append(trimmed)
        normalized = windows_normalized
    if not case_sensitive:
        normalized = [part.casefold() for part in normalized]
    return normalized


def _register_member_path(trie, parts, name, is_directory):
    """Reject duplicate and file/directory-prefix collisions before writes."""
    node = trie
    for part in parts:
        if _FILE_MARKER in node:
            raise InputPreparationError(
                f"conflicting ZIP member path: {name!r}"
            )
        node = node.setdefault(part, {})
    if is_directory:
        if _FILE_MARKER in node:
            raise InputPreparationError(
                f"conflicting ZIP member path: {name!r}"
            )
        node[_DIRECTORY_MARKER] = True
        return
    if _FILE_MARKER in node:
        raise InputPreparationError(f"duplicate ZIP member path: {name!r}")
    if node:
        raise InputPreparationError(f"conflicting ZIP member path: {name!r}")
    node[_FILE_MARKER] = True


def _preflight_central_directory(path, archive_size, limits):
    """Bound ZIP metadata before ``zipfile`` allocates its full entry list."""
    tail_size = min(archive_size, 65535 + 22)
    try:
        with open(path, "rb") as source:
            source.seek(archive_size - tail_size)
            tail = source.read(tail_size)
    except OSError as exc:
        raise InputPreparationError(f"could not read ZIP metadata: {exc}") from exc

    signature = b"PK\x05\x06"
    offset = tail.rfind(signature)
    eocd = None
    while offset >= 0:
        if offset + 22 <= len(tail):
            values = struct.unpack_from("<4s4H2LH", tail, offset)
            comment_length = values[-1]
            if offset + 22 + comment_length == len(tail):
                eocd = values
                break
        offset = tail.rfind(signature, 0, offset)
    if eocd is None:
        raise InputPreparationError("ZIP end-of-central-directory is missing")

    (_sig, disk_number, central_disk, disk_entries, total_entries,
     central_size, central_offset, _comment_length) = eocd
    if disk_number != 0 or central_disk != 0 or disk_entries != total_entries:
        raise InputPreparationError("multi-disk ZIP archives are not supported")
    # The configured archive/entry limits are all below classic ZIP bounds,
    # so ZIP64 is unnecessary here. Rejecting sentinel metadata avoids opening
    # an attacker-sized central directory just to learn its real dimensions.
    if (total_entries == 0xFFFF or central_size == 0xFFFFFFFF
            or central_offset == 0xFFFFFFFF):
        raise InputPreparationError("ZIP64 metadata exceeds supported limits")
    if total_entries > limits.max_entries:
        raise InputPreparationError("ZIP contains too many entries")
    if central_size > limits.max_central_directory_bytes:
        raise InputPreparationError("ZIP central directory exceeds safety limit")
    eocd_position = archive_size - tail_size + offset
    if central_offset + central_size > eocd_position:
        raise InputPreparationError("ZIP central directory metadata is invalid")


def preflight_zip(path, *, limits=None, require_apk_manifest=False,
                  case_sensitive=True, windows_paths=None):
    """Validate ZIP structure, paths, sizes, ratios, and APK manifest count."""
    limits = limits or ArchiveLimits()
    if windows_paths is None:
        windows_paths = os.name == "nt"
    archive_path = os.path.abspath(os.fspath(path))
    try:
        archive_size = os.path.getsize(archive_path)
    except OSError as exc:
        raise InputPreparationError(f"could not read archive: {exc}") from exc
    if archive_size <= 0:
        raise InputPreparationError("archive is empty")
    if archive_size > limits.max_archive_bytes:
        raise InputPreparationError(
            f"archive exceeds {limits.max_archive_bytes} byte safety limit"
        )

    _preflight_central_directory(archive_path, archive_size, limits)

    entry_count = 0
    file_count = 0
    compressed_total = 0
    uncompressed_total = 0
    manifest_count = 0
    total_name_bytes = 0
    file_trie = {}
    seen_entries = set()
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            for info in archive.infolist():
                entry_count += 1
                if entry_count > limits.max_entries:
                    raise InputPreparationError("ZIP contains too many entries")
                name_bytes = len(
                    info.filename.encode("utf-8", errors="surrogatepass")
                )
                if name_bytes > limits.max_name_bytes:
                    raise InputPreparationError(
                        "ZIP member name exceeds safety limit"
                    )
                total_name_bytes += name_bytes
                if total_name_bytes > limits.max_total_name_bytes:
                    raise InputPreparationError(
                        "ZIP member names exceed aggregate safety limit"
                    )
                parts = _member_parts(info.filename)
                if len(parts) > limits.max_path_depth:
                    raise InputPreparationError(
                        "ZIP member path nesting exceeds safety limit"
                    )
                collision_key = tuple(_collision_parts(
                    parts, case_sensitive, windows_paths=windows_paths
                ))
                entry_key = (collision_key, info.is_dir())
                if entry_key in seen_entries:
                    raise InputPreparationError(
                        f"duplicate ZIP member path: {info.filename!r}"
                    )
                seen_entries.add(entry_key)

                unix_mode = (info.external_attr >> 16) & 0xFFFF
                if unix_mode and stat.S_ISLNK(unix_mode):
                    raise InputPreparationError(
                        f"ZIP symlink entries are not supported: {info.filename!r}"
                    )
                if info.flag_bits & 0x1:
                    raise InputPreparationError(
                        f"encrypted ZIP member is not supported: {info.filename!r}"
                    )
                _register_member_path(
                    file_trie, collision_key, info.filename, info.is_dir()
                )
                if info.is_dir():
                    continue

                file_count += 1
                if info.file_size < 0 or info.file_size > limits.max_member_bytes:
                    raise InputPreparationError(
                        "ZIP member exceeds per-file safety limit: "
                        f"{info.filename!r}"
                    )
                uncompressed_total += info.file_size
                compressed_total += info.compress_size
                if uncompressed_total > limits.max_total_bytes:
                    raise InputPreparationError(
                        "ZIP exceeds total uncompressed safety limit"
                    )
                if info.file_size:
                    if info.compress_size <= 0:
                        raise InputPreparationError(
                            f"invalid compressed size for {info.filename!r}"
                        )
                    ratio = float(info.file_size) / float(info.compress_size)
                    if ratio > limits.max_compression_ratio:
                        raise InputPreparationError(
                            "ZIP member compression ratio exceeds safety limit: "
                            f"{info.filename!r}"
                        )

                # Metadata alone cannot prove that a ZIP member is readable:
                # a damaged payload can retain plausible sizes and paths, and
                # some apktool versions still return success after copying the
                # corrupted bytes.  Stream every bounded member through
                # zipfile so CRC/truncation failures are rejected before any
                # external decoder treats the input as complete.
                bytes_read = 0
                with archive.open(info, "r") as member:
                    while True:
                        chunk = member.read(1024 * 1024)
                        if not chunk:
                            break
                        bytes_read += len(chunk)
                        if bytes_read > info.file_size:
                            raise InputPreparationError(
                                "ZIP member expanded beyond its declared size: "
                                f"{info.filename!r}"
                            )
                if bytes_read != info.file_size:
                    raise InputPreparationError(
                        "ZIP member size does not match its metadata: "
                        f"{info.filename!r}"
                    )
                if info.filename == "AndroidManifest.xml":
                    manifest_count += 1
    except InputPreparationError:
        raise
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, EOFError,
            RuntimeError, zlib.error) as exc:
        raise InputPreparationError(f"invalid or unreadable ZIP: {exc}") from exc

    if file_count == 0:
        raise InputPreparationError("ZIP contains no files")
    if require_apk_manifest and manifest_count != 1:
        raise InputPreparationError(
            "APK must contain exactly one top-level AndroidManifest.xml"
        )
    return ZipPreflight(
        entries=entry_count,
        files=file_count,
        compressed_bytes=compressed_total,
        uncompressed_bytes=uncompressed_total,
    )


def _safe_output_name(member_name, index):
    """Create a collision-resistant flat name for an APK Set member."""
    stem = os.path.basename(member_name)
    safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem)
    if not safe_stem.lower().endswith(".apk"):
        safe_stem += ".apk"
    digest = hashlib.sha256(
        member_name.encode("utf-8", errors="surrogatepass")
    ).hexdigest()[:10]
    return f"{index:04d}_{digest}_{safe_stem}"


def _make_private_snapshot_dir(staging):
    """Create an unpredictable owner-only directory for stable input copies."""
    try:
        staging_stat = os.lstat(staging)
    except OSError as exc:
        raise InputPreparationError(
            f"input staging directory is unreadable: {exc}"
        ) from exc
    if (_is_link_or_reparse_point(staging_stat)
            or not stat.S_ISDIR(staging_stat.st_mode)):
        raise InputPreparationError(
            "input staging path must be a real directory, not a link or "
            "reparse point"
        )
    snapshot_dir = None
    try:
        snapshot_dir = tempfile.mkdtemp(prefix=".input-snapshot-", dir=staging)
        os.chmod(snapshot_dir, stat.S_IRWXU)
        snapshot_stat = os.lstat(snapshot_dir)
    except OSError as exc:
        if snapshot_dir:
            shutil.rmtree(snapshot_dir, ignore_errors=True)
        raise InputPreparationError(
            f"could not create private input staging: {exc}"
        ) from exc
    if (_is_link_or_reparse_point(snapshot_stat)
            or not stat.S_ISDIR(snapshot_stat.st_mode)):
        shutil.rmtree(snapshot_dir, ignore_errors=True)
        raise InputPreparationError("private input staging is not a real directory")
    return snapshot_dir


def _source_contains_staging(source, staging):
    """Reject staging inside a traversed input directory."""
    source_real = os.path.normcase(os.path.realpath(source))
    staging_real = os.path.normcase(os.path.realpath(staging))
    # normcase is a no-op on macOS even on its commonly case-insensitive APFS
    # volumes. Probe the source's parent (not the input itself) and normalize
    # conservatively when it reports case-insensitive behavior.
    source_parent = os.path.dirname(source_real) or source_real
    if not filesystem_is_case_sensitive(source_parent):
        source_real = source_real.casefold()
        staging_real = staging_real.casefold()
    try:
        return os.path.commonpath((source_real, staging_real)) == source_real
    except ValueError:
        return False


def _snapshot_directory_apks_fd(source, snapshot_dir, limits, expected_root):
    """Snapshot APKs while every traversed directory is pinned by an fd."""
    snapshot_apks = os.path.join(snapshot_dir, "directory-apks")
    os.mkdir(snapshot_apks, 0o700)
    staged_paths = []
    original_names = []
    copied_bytes = 0
    root_initial = os.lstat(source)
    root_fd = None

    def visit(directory_fd, relative_parts):
        nonlocal copied_bytes
        try:
            with os.scandir(directory_fd) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError as exc:
            raise InputPreparationError(
                f"input directory is unreadable: {exc}"
            ) from exc
        for entry in entries:
            display_path = os.path.join(source, *(relative_parts + [entry.name]))
            try:
                entry_stat = entry.stat(follow_symlinks=False)
                path_stat = os.lstat(display_path)
            except OSError as exc:
                raise InputPreparationError(
                    f"input directory entry is unreadable: {display_path}"
                ) from exc
            if (_is_link_or_reparse_point(entry_stat)
                    or _is_link_or_reparse_point(path_stat)):
                raise InputPreparationError(
                    "symlinked or reparse-point input entry is not "
                    f"supported: {display_path}"
                )
            if (not _same_file_identity(entry_stat, path_stat)
                    or _snapshot_signature(entry_stat)
                    != _snapshot_signature(path_stat)):
                raise InputPreparationError(
                    "input directory entry changed during traversal: "
                    f"{display_path}"
                )
            if stat.S_ISDIR(entry_stat.st_mode):
                child_fd = None
                try:
                    child_fd = os.open(
                        entry.name,
                        _source_open_flags(directory=True),
                        dir_fd=directory_fd,
                    )
                    opened_stat = os.fstat(child_fd)
                    if (not stat.S_ISDIR(opened_stat.st_mode)
                            or not _same_file_identity(entry_stat, opened_stat)
                            or _snapshot_signature(entry_stat)
                            != _snapshot_signature(opened_stat)
                            or _is_link_or_reparse_point(opened_stat)):
                        raise InputPreparationError(
                            "input directory changed while it was being "
                            f"opened: {display_path}"
                        )
                    visit(child_fd, relative_parts + [entry.name])
                    after_handle = os.fstat(child_fd)
                    after_entry = os.stat(
                        entry.name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                    if (_snapshot_signature(after_handle)
                            != _snapshot_signature(opened_stat)
                            or not _same_file_identity(after_entry, opened_stat)
                            or _snapshot_signature(after_entry)
                            != _snapshot_signature(opened_stat)
                            or _is_link_or_reparse_point(after_entry)):
                        raise InputPreparationError(
                            "input directory changed while it was being "
                            f"snapshotted: {display_path}"
                        )
                except InputPreparationError:
                    raise
                except OSError as exc:
                    raise InputPreparationError(
                        f"could not traverse input directory {display_path}: {exc}"
                    ) from exc
                finally:
                    if child_fd is not None:
                        os.close(child_fd)
                continue
            if not entry.name.lower().endswith(".apk"):
                continue
            if not stat.S_ISREG(entry_stat.st_mode):
                raise InputPreparationError(
                    f"APK input is not a regular file: {display_path}"
                )
            if len(staged_paths) >= limits.max_apk_count:
                raise InputPreparationError(
                    "input directory contains too many APKs"
                )
            if entry_stat.st_size < 0:
                raise InputPreparationError("APK input has an invalid size")
            copied_bytes += entry_stat.st_size
            if copied_bytes > limits.max_archive_bytes:
                raise InputPreparationError(
                    "input directory APKs exceed aggregate snapshot safety limit"
                )
            relative_name = "/".join(relative_parts + [entry.name])
            destination = os.path.join(
                snapshot_apks,
                _safe_output_name(relative_name, len(staged_paths)),
            )
            _snapshot_regular_file(
                display_path,
                destination,
                limits.max_archive_bytes,
                expected_stat=entry_stat,
                source_dir_fd=directory_fd,
                source_name=entry.name,
            )
            staged_paths.append(destination)
            original_names.append(relative_name)

    try:
        if (_is_link_or_reparse_point(root_initial)
                or not stat.S_ISDIR(root_initial.st_mode)):
            raise InputPreparationError(
                "input directory is not a real directory"
            )
        if (not _same_file_identity(expected_root, root_initial)
                or _snapshot_signature(expected_root)
                != _snapshot_signature(root_initial)):
            raise InputPreparationError(
                "input directory changed before it could be snapshotted"
            )
        root_fd = os.open(source, _source_open_flags(directory=True))
        root_opened = os.fstat(root_fd)
        if (not _same_file_identity(root_initial, root_opened)
                or _snapshot_signature(root_initial)
                != _snapshot_signature(root_opened)
                or _is_link_or_reparse_point(root_opened)
                or not stat.S_ISDIR(root_opened.st_mode)):
            raise InputPreparationError(
                "input directory changed while it was being opened"
            )
        visit(root_fd, [])
        root_after_handle = os.fstat(root_fd)
        root_after_path = os.lstat(source)
        if (_snapshot_signature(root_after_handle)
                != _snapshot_signature(root_opened)
                or not _same_file_identity(root_after_path, root_opened)
                or _snapshot_signature(root_after_path)
                != _snapshot_signature(root_opened)
                or _is_link_or_reparse_point(root_after_path)):
            raise InputPreparationError(
                "input directory changed while it was being snapshotted"
            )
    except InputPreparationError:
        raise
    except OSError as exc:
        raise InputPreparationError(
            f"could not snapshot input directory: {exc}"
        ) from exc
    finally:
        if root_fd is not None:
            os.close(root_fd)
    return staged_paths, original_names


def _snapshot_directory_apks_path(source, snapshot_dir, limits, expected_root):
    """Checked path-based fallback for runtimes without directory fds."""
    snapshot_apks = os.path.join(snapshot_dir, "directory-apks")
    os.mkdir(snapshot_apks, 0o700)
    candidates = []
    directory_stats = {}

    def walk_error(exc):
        raise InputPreparationError(f"input directory is unreadable: {exc}")

    for root, dirs, files in os.walk(
            source, followlinks=False, onerror=walk_error):
        try:
            current_stat = os.lstat(root)
        except OSError as exc:
            raise InputPreparationError(
                f"input directory entry is unreadable: {root}"
            ) from exc
        expected = directory_stats.get(root)
        if root == source and expected is None:
            expected = expected_root
        if (_is_link_or_reparse_point(current_stat)
                or not stat.S_ISDIR(current_stat.st_mode)
                or (expected is not None
                    and (not _same_file_identity(expected, current_stat)
                         or _snapshot_signature(expected)
                         != _snapshot_signature(current_stat)))):
            raise InputPreparationError(
                f"input directory changed during traversal: {root}"
            )
        directory_stats[root] = current_stat
        safe_dirs = []
        for name in sorted(dirs):
            child = os.path.join(root, name)
            try:
                child_stat = os.lstat(child)
            except OSError as exc:
                raise InputPreparationError(
                    f"input directory entry is unreadable: {child}"
                ) from exc
            if (_is_link_or_reparse_point(child_stat)
                    or not stat.S_ISDIR(child_stat.st_mode)):
                raise InputPreparationError(
                    "symlinked, reparse-point, or unexpected input directory "
                    f"is not supported: {child}"
                )
            directory_stats[child] = child_stat
            safe_dirs.append(name)
        dirs[:] = safe_dirs
        for name in sorted(files):
            if not name.lower().endswith(".apk"):
                continue
            candidate = os.path.join(root, name)
            try:
                candidate_stat = os.lstat(candidate)
            except OSError as exc:
                raise InputPreparationError(
                    f"APK input is unreadable: {candidate}"
                ) from exc
            if _is_link_or_reparse_point(candidate_stat):
                raise InputPreparationError(
                    "symlinked or reparse-point APK input is not supported: "
                    f"{candidate}"
                )
            if not stat.S_ISREG(candidate_stat.st_mode):
                raise InputPreparationError(
                    f"APK input is not a regular file: {candidate}"
                )
            candidates.append((candidate, candidate_stat))
            if len(candidates) > limits.max_apk_count:
                raise InputPreparationError(
                    "input directory contains too many APKs"
                )

    copied_bytes = 0
    staged_paths = []
    original_names = []
    for candidate, candidate_stat in candidates:
        copied_bytes += candidate_stat.st_size
        if copied_bytes > limits.max_archive_bytes:
            raise InputPreparationError(
                "input directory APKs exceed aggregate snapshot safety limit"
            )
        relative_name = os.path.relpath(candidate, source).replace(os.sep, "/")
        destination = os.path.join(
            snapshot_apks,
            _safe_output_name(relative_name, len(staged_paths)),
        )
        _snapshot_regular_file(
            candidate,
            destination,
            limits.max_archive_bytes,
            expected_stat=candidate_stat,
        )
        staged_paths.append(destination)
        original_names.append(relative_name)

    for directory, expected in directory_stats.items():
        try:
            current = os.lstat(directory)
        except OSError as exc:
            raise InputPreparationError(
                f"input directory changed during snapshot: {directory}"
            ) from exc
        if (_is_link_or_reparse_point(current)
                or not _same_file_identity(expected, current)
                or _snapshot_signature(expected) != _snapshot_signature(current)):
            raise InputPreparationError(
                f"input directory changed during snapshot: {directory}"
            )
    return staged_paths, original_names


def _snapshot_directory_apks(source, snapshot_dir, limits, expected_root):
    if _directory_fd_traversal_supported():
        return _snapshot_directory_apks_fd(
            source, snapshot_dir, limits, expected_root
        )
    return _snapshot_directory_apks_path(
        source, snapshot_dir, limits, expected_root
    )


def _choose_base(apk_paths, original_names=None):
    """Choose a base/universal APK deterministically from a split set."""
    names = list(original_names or [os.path.basename(path) for path in apk_paths])
    priorities = (
        lambda value: value.lower().endswith("/universal.apk")
        or value.lower() == "universal.apk",
        lambda value: value.lower().endswith("/base-master.apk")
        or value.lower() == "base-master.apk",
        lambda value: value.lower().endswith("/base.apk")
        or value.lower() == "base.apk",
    )
    for predicate in priorities:
        matches = [
            path for path, name in zip(apk_paths, names)
            if predicate(name.replace("\\", "/"))
        ]
        if len(matches) > 1:
            raise InputPreparationError(
                "split set contains multiple candidate base APKs"
            )
        if matches:
            return matches[0]
    if len(apk_paths) == 1:
        return apk_paths[0]
    raise InputPreparationError(
        "could not identify a unique base APK in the split set"
    )


def _extract_apks_container(container_path, staging_dir, limits,
                            case_sensitive):
    """Safely extract APK members from a bundletool ``.apks`` container."""
    preflight_zip(
        container_path, limits=limits, case_sensitive=case_sensitive
    )
    os.makedirs(staging_dir, exist_ok=False)
    extracted = []
    original_names = []
    try:
        with zipfile.ZipFile(container_path, "r") as archive:
            candidates = [
                info for info in archive.infolist()
                if not info.is_dir() and info.filename.lower().endswith(".apk")
            ]
            if not candidates:
                raise InputPreparationError("APK Set contains no APK members")
            # Bound the container's actual APK population before preferring a
            # universal artifact. Otherwise thousands of ignored variants can
            # bypass max_apk_count while still being CRC-read in preflight.
            if len(candidates) > limits.max_apk_count:
                raise InputPreparationError("APK Set contains too many APKs")
            universal_candidates = [
                info for info in candidates
                if info.filename.replace("\\", "/").lower().endswith(
                    "/universal.apk"
                ) or info.filename.lower() == "universal.apk"
            ]
            if len(universal_candidates) > 1:
                raise InputPreparationError(
                    "APK Set contains multiple universal APK members"
                )
            nested_uncompressed_total = 0
            for index, info in enumerate(candidates):
                destination = os.path.join(
                    staging_dir, _safe_output_name(info.filename, index)
                )
                with archive.open(info, "r") as source, open(
                        destination, "xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                nested = preflight_zip(
                    destination,
                    limits=limits,
                    require_apk_manifest=True,
                    case_sensitive=case_sensitive,
                )
                nested_uncompressed_total += nested.uncompressed_bytes
                if nested_uncompressed_total > limits.max_total_bytes:
                    raise InputPreparationError(
                        "APK Set expands beyond the aggregate safety limit"
                    )
                _make_snapshot_read_only(destination)
                extracted.append(destination)
                original_names.append(info.filename)
    except InputPreparationError:
        shutil.rmtree(staging_dir, ignore_errors=True)
        raise
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        shutil.rmtree(staging_dir, ignore_errors=True)
        raise InputPreparationError(
            f"could not extract APK Set safely: {exc}"
        ) from exc
    return extracted, original_names


def _validate_aab(path, limits, case_sensitive):
    """Preflight an Android App Bundle and check its defining entries."""
    preflight_zip(path, limits=limits, case_sensitive=case_sensitive)
    try:
        with zipfile.ZipFile(path, "r") as archive:
            names = {info.filename for info in archive.infolist()}
    except (zipfile.BadZipFile, OSError) as exc:
        raise InputPreparationError(f"invalid App Bundle: {exc}") from exc
    if "BundleConfig.pb" not in names:
        raise InputPreparationError("AAB is missing BundleConfig.pb")
    if not any(
        name.endswith("/manifest/AndroidManifest.xml") for name in names
    ):
        raise InputPreparationError("AAB contains no module manifest")


def _run_bounded_tool(args, timeout, operation, runner=subprocess.run):
    """Execute one argument-list tool call with bounded captured diagnostics."""
    try:
        bounded_timeout = max(1, int(timeout))
        if runner is _ORIGINAL_SUBPROCESS_RUN:
            completed = run_command_capture(
                list(args),
                timeout=bounded_timeout,
                max_output_bytes=MAX_COMMAND_OUTPUT_BYTES,
            )
            detail = (completed.stdout + completed.stderr)[-8192:].strip()
        else:
            # Retain the injectable runner used by tests and embedders. The
            # production subprocess.run path above is process-tree contained.
            with tempfile.TemporaryFile(mode="w+b") as output:
                completed = runner(
                    list(args),
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    timeout=bounded_timeout,
                    check=False,
                )
                output.flush()
                output.seek(0, os.SEEK_END)
                size = output.tell()
                if size > MAX_COMMAND_OUTPUT_BYTES:
                    raise CommandOutputLimitExceeded(
                        MAX_COMMAND_OUTPUT_BYTES
                    )
                output.seek(max(0, size - 8192))
                detail = output.read(8192).decode(
                    "utf-8", errors="replace"
                ).strip()
    except subprocess.TimeoutExpired as exc:
        raise InputPreparationError(f"{operation} timed out") from exc
    except CommandOutputLimitExceeded as exc:
        raise InputPreparationError(f"{operation} failed safely: {exc}") from exc
    except (OSError, ValueError) as exc:
        raise InputPreparationError(f"could not start {operation}: {exc}") from exc
    if completed.returncode != 0:
        suffix = f": {detail}" if detail else ""
        raise InputPreparationError(
            f"{operation} failed with exit code {completed.returncode}{suffix}"
        )


def build_apks_from_aab(aab_path, output_path, bundletool_command, *,
                        timeout=DEFAULT_DECOMPILE_TIMEOUT,
                        runner=subprocess.run):
    """Build a universal APK Set from an AAB using an explicit command list."""
    command = list(bundletool_command or [])
    if not command:
        raise InputPreparationError(
            "bundletool is required for .aab input; provide --bundletool"
        )
    if os.path.lexists(output_path):
        raise InputPreparationError("refusing to overwrite APK Set output")
    args = command + [
        "build-apks",
        f"--bundle={os.path.abspath(aab_path)}",
        f"--output={os.path.abspath(output_path)}",
        "--mode=universal",
    ]
    _run_bounded_tool(args, timeout, "bundletool", runner=runner)
    try:
        output_stat = os.lstat(output_path)
    except OSError as exc:
        raise InputPreparationError(
            "bundletool reported success but made no APK Set"
        ) from exc
    if (_is_link_or_reparse_point(output_stat)
            or not stat.S_ISREG(output_stat.st_mode)
            or output_stat.st_size <= 0):
        raise InputPreparationError("bundletool reported success but made no APK Set")
    _make_snapshot_read_only(output_path)


def collect_apk_inputs(source_path, staging_root, *, limits=None,
                       bundletool_command=None, runner=subprocess.run):
    """Snapshot and resolve one local app input to validated private APKs."""
    limits = limits or ArchiveLimits()
    source = os.path.abspath(os.fspath(source_path))
    staging = os.path.abspath(os.fspath(staging_root))
    try:
        source_stat = os.lstat(source)
    except OSError as exc:
        raise InputPreparationError(
            f"input does not exist or is unreadable: {source}"
        ) from exc
    if _is_link_or_reparse_point(source_stat):
        raise InputPreparationError(
            "symlinked or reparse-point local input is not supported"
        )
    is_directory = stat.S_ISDIR(source_stat.st_mode)
    if not is_directory and not stat.S_ISREG(source_stat.st_mode):
        raise InputPreparationError("local input is not a regular file")
    suffix = "" if is_directory else os.path.splitext(source)[1].lower()
    if not is_directory and suffix not in (".apk", ".apks", ".aab"):
        raise InputPreparationError(
            "unsupported input type; expected .apk, .apks, .aab, or a directory"
        )
    if is_directory and _source_contains_staging(source, staging):
        raise InputPreparationError(
            "input staging directory must not be inside the input directory"
        )

    try:
        os.makedirs(staging, mode=0o700, exist_ok=True)
    except OSError as exc:
        raise InputPreparationError(
            f"could not create input staging directory: {exc}"
        ) from exc
    snapshot_dir = _make_private_snapshot_dir(staging)
    try:
        case_sensitive = filesystem_is_case_sensitive(staging)
        if is_directory:
            apk_paths, original_names = _snapshot_directory_apks(
                source, snapshot_dir, limits, source_stat
            )
            if not apk_paths:
                raise InputPreparationError(
                    "input directory contains no APK files"
                )
            aggregate_uncompressed = 0
            for path in apk_paths:
                metadata = preflight_zip(
                    path,
                    limits=limits,
                    require_apk_manifest=True,
                    case_sensitive=case_sensitive,
                )
                aggregate_uncompressed += metadata.uncompressed_bytes
                if aggregate_uncompressed > limits.max_total_bytes:
                    raise InputPreparationError(
                        "split APK set expands beyond the aggregate safety limit"
                    )
            return ApkInputSet(
                source,
                "directory",
                tuple(apk_paths),
                _choose_base(apk_paths, original_names),
                variant_union=len(apk_paths) > 1,
            )

        source_snapshot = os.path.join(snapshot_dir, "source" + suffix)
        _snapshot_regular_file(
            source,
            source_snapshot,
            limits.max_archive_bytes,
            expected_stat=source_stat,
        )
        if suffix == ".apk":
            preflight_zip(
                source_snapshot,
                limits=limits,
                require_apk_manifest=True,
                case_sensitive=case_sensitive,
            )
            return ApkInputSet(
                source, "apk", (source_snapshot,), source_snapshot
            )

        container_path = source_snapshot
        input_kind = "apks"
        if suffix == ".aab":
            _validate_aab(source_snapshot, limits, case_sensitive)
            container_path = os.path.join(
                snapshot_dir, "bundletool-output.apks"
            )
            build_apks_from_aab(
                source_snapshot,
                container_path,
                bundletool_command,
                runner=runner,
            )
            input_kind = "aab"

        extracted_dir = os.path.join(snapshot_dir, "apk-set-members")
        extracted, names = _extract_apks_container(
            container_path, extracted_dir, limits, case_sensitive
        )
        # Keep every nested APK. A container can pair universal.apk with a
        # non-fused/on-demand feature that the universal artifact omits;
        # silently narrowing to universal would miss that module and skip
        # nested APK validation.
        return ApkInputSet(
            source,
            input_kind,
            tuple(extracted),
            _choose_base(extracted, names),
            variant_union=len(extracted) > 1,
        )
    except Exception:
        shutil.rmtree(snapshot_dir, ignore_errors=True)
        raise


def decompile_apk_inputs(apk_input, output_dir, apktool_command, *,
                         timeout=DEFAULT_DECOMPILE_TIMEOUT,
                         runner=subprocess.run):
    """Atomically decompile a base APK and its splits under one analysis root."""
    command = list(apktool_command or [])
    if not command:
        raise InputPreparationError("apktool is required for static analysis")
    destination = os.path.abspath(os.fspath(output_dir))
    if os.path.lexists(destination):
        raise InputPreparationError("refusing to overwrite decompile output")
    parent = os.path.dirname(destination)
    os.makedirs(parent, exist_ok=True)
    stage_root = tempfile.mkdtemp(prefix=".apkanalyzer-decompile-", dir=parent)
    analysis_root = os.path.join(stage_root, "analysis")
    framework_root = os.path.join(stage_root, "framework")
    os.makedirs(framework_root, exist_ok=True)
    split_outputs = []
    ordered = [apk_input.base_apk] + [
        path for path in apk_input.apk_paths if path != apk_input.base_apk
    ]
    deadline = time.monotonic() + max(1, int(timeout))
    try:
        for index, apk_path in enumerate(ordered):
            if index == 0:
                current_output = analysis_root
            else:
                split_root = os.path.join(
                    analysis_root, ".apkanalyzer_splits"
                )
                os.makedirs(split_root, exist_ok=True)
                current_output = os.path.join(split_root, f"split_{index:04d}")
                split_outputs.append(current_output)
            remaining = int(deadline - time.monotonic())
            if remaining <= 0:
                raise InputPreparationError("apktool decompilation timed out")
            _run_bounded_tool(
                command + [
                    "d", "-f", "--frame-path", framework_root,
                    "-o", current_output, apk_path,
                ],
                remaining,
                f"apktool ({os.path.basename(apk_path)})",
                runner=runner,
            )
            if not os.path.isdir(current_output):
                raise InputPreparationError(
                    "apktool reported success but made no decompile directory"
                )
        os.replace(analysis_root, destination)
        relative_splits = tuple(
            os.path.join(
                destination,
                os.path.relpath(path, analysis_root),
            )
            for path in split_outputs
        )
        return relative_splits
    except Exception:
        if os.path.lexists(destination):
            shutil.rmtree(destination, ignore_errors=True)
        raise
    finally:
        shutil.rmtree(stage_root, ignore_errors=True)


def prepare_local_input(source_path, work_dir, apktool_command, *, limits=None,
                        bundletool_command=None,
                        timeout=DEFAULT_DECOMPILE_TIMEOUT,
                        runner=subprocess.run):
    """Validate, materialize, and atomically decompile one local app input."""
    work = os.path.abspath(os.fspath(work_dir))
    os.makedirs(work, exist_ok=True)
    artifacts = os.path.join(work, "artifacts")
    os.makedirs(artifacts, exist_ok=True)
    apk_input = collect_apk_inputs(
        source_path,
        artifacts,
        limits=limits,
        bundletool_command=bundletool_command,
        runner=runner,
    )
    decompiled = os.path.join(work, "decompiled")
    split_dirs = decompile_apk_inputs(
        apk_input,
        decompiled,
        apktool_command,
        timeout=timeout,
        runner=runner,
    )
    return PreparedInput(
        source_path=apk_input.source_path,
        input_kind=apk_input.input_kind,
        apk_paths=apk_input.apk_paths,
        base_apk=apk_input.base_apk,
        work_dir=work,
        decompiled_dir=decompiled,
        split_decompiled_dirs=split_dirs,
        variant_union=apk_input.variant_union,
    )
