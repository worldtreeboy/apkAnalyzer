"""Safe extraction helpers for Android ``.ab`` backup archives."""

import os
import shutil
import stat
import sys
import tarfile
import tempfile
import unicodedata
import zlib


DEFAULT_MAX_BACKUP_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_BACKUP_PAYLOAD_BYTES = 1024 * 1024 * 1024
DEFAULT_MAX_BACKUP_FILE_BYTES = 128 * 1024 * 1024
DEFAULT_MAX_BACKUP_FILES = 100_000


_DARWIN_TRUSTED_SYSTEM_ALIASES = {
    "/tmp": "/private/tmp",
    "/var": "/private/var",
}


def _is_link_or_reparse_point(path):
    """Return whether a path is a symlink, junction, or other reparse point."""
    try:
        path_stat = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(path_stat.st_mode):
        return True
    attributes = getattr(path_stat, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def _is_trusted_darwin_system_alias(path):
    """Return whether *path* is a known macOS root-level system alias.

    Resolve only the immediate target of Apple's fixed aliases. Resolving the
    whole output path would also hide caller-controlled symlink components.
    """
    if sys.platform != "darwin":
        return False

    alias = os.path.abspath(os.fspath(path))
    expected_target = _DARWIN_TRUSTED_SYSTEM_ALIASES.get(alias)
    if expected_target is None:
        return False

    try:
        link_target = os.readlink(alias)
    except OSError:
        return False
    if not os.path.isabs(link_target):
        link_target = os.path.join(os.path.dirname(alias), link_target)
    return os.path.abspath(link_target) == expected_target


def find_symlinked_path_component(path):
    """Return a link/reparse point at or above *path*."""
    cursor = os.path.abspath(os.fspath(path))
    while True:
        if os.path.lexists(cursor) and _is_link_or_reparse_point(cursor):
            if not _is_trusted_darwin_system_alias(cursor):
                return cursor
        parent = os.path.dirname(cursor)
        if parent == cursor:
            return None
        cursor = parent


def filesystem_is_case_sensitive(directory):
    """Probe the destination filesystem instead of guessing from the host OS."""
    probe_path = None
    try:
        fd, probe_path = tempfile.mkstemp(
            prefix=".ApkAnalyzerCaseProbe", dir=directory
        )
        os.close(fd)
        alternate = os.path.join(
            directory, os.path.basename(probe_path).swapcase()
        )
        return not os.path.exists(alternate)
    except OSError:
        # Conservative fallback for the two commonly case-insensitive hosts.
        return os.name != "nt" and sys.platform != "darwin"
    finally:
        if probe_path and os.path.exists(probe_path):
            try:
                os.remove(probe_path)
            except OSError:
                pass


def unpack_ab(
    ab_path,
    out_dir,
    *,
    max_backup_bytes=DEFAULT_MAX_BACKUP_BYTES,
    max_backup_payload_bytes=DEFAULT_MAX_BACKUP_PAYLOAD_BYTES,
    max_backup_file_bytes=DEFAULT_MAX_BACKUP_FILE_BYTES,
    max_backup_files=DEFAULT_MAX_BACKUP_FILES,
    case_sensitive_probe=filesystem_is_case_sensitive,
    symlink_component_finder=find_symlinked_path_component,
):
    """Parse an Android ``.ab`` file and safely extract its tar payload.

    The configurable limits and case-sensitivity probe let the legacy launcher
    preserve its public monkeypatch points while the extraction implementation
    remains independently reusable.

    Returns ``(file_count, error_message_or_None)``.
    """
    created_output_root = None
    try:
        if os.path.getsize(ab_path) > max_backup_bytes:
            return 0, f"backup exceeds {max_backup_bytes} byte safety limit"
        source = open(ab_path, "rb")
    except OSError as exc:
        return 0, f"could not read backup file: {exc}"

    try:
        with source, tempfile.TemporaryFile() as payload_file:
            header = [source.readline(128) for _ in range(4)]
            if header[0] != b"ANDROID BACKUP\n":
                return 0, "not a valid Android backup (missing 'ANDROID BACKUP' header)"
            if any(not line.endswith(b"\n") for line in header):
                return 0, "backup is empty or truncated (on-device confirmation likely declined)"

            compression = header[2].strip()
            if compression not in (b"0", b"1"):
                return 0, "backup has an invalid compression flag"
            encryption = header[3].strip()
            if encryption != b"none":
                enc = encryption.decode("ascii", "replace")
                return 0, (
                    f"backup is encrypted ({enc}); "
                    "password-protected backups are not supported"
                )

            total_payload = 0
            decompressor = zlib.decompressobj() if compression == b"1" else None
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                if decompressor is None:
                    output_chunks = (chunk,)
                else:
                    output_chunks = []
                    pending = chunk
                    while pending:
                        remaining = max_backup_payload_bytes - total_payload
                        if remaining <= 0:
                            return 0, "backup payload exceeds extraction safety limit"
                        output = decompressor.decompress(
                            pending, min(8 * 1024 * 1024, remaining + 1)
                        )
                        output_chunks.append(output)
                        pending = decompressor.unconsumed_tail
                        if len(output) > remaining:
                            return 0, "backup payload exceeds extraction safety limit"
                for output in output_chunks:
                    total_payload += len(output)
                    if total_payload > max_backup_payload_bytes:
                        return 0, "backup payload exceeds extraction safety limit"
                    payload_file.write(output)

            if decompressor is not None:
                remaining = max_backup_payload_bytes - total_payload
                tail = decompressor.flush(remaining + 1)
                total_payload += len(tail)
                if total_payload > max_backup_payload_bytes:
                    return 0, "backup payload exceeds extraction safety limit"
                payload_file.write(tail)
                if not decompressor.eof:
                    return 0, "payload decompression failed: truncated zlib stream"

            if total_payload == 0:
                return 0, (
                    "backup contains no data "
                    "(app disallows backup or returned an empty set)"
                )

            payload_file.seek(0)
            output_root = os.path.abspath(out_dir)
            # A symlink used as (or above) the logical extraction root defeats
            # descendant-only checks: an otherwise safe member would be written
            # outside the directory named by the caller.
            symlink_component = symlink_component_finder(output_root)
            if symlink_component:
                return 0, (
                    "refusing symlinked backup output path component: "
                    f"{symlink_component}"
                )
            output_root_created = not os.path.lexists(output_root)
            os.makedirs(output_root, exist_ok=True)
            if output_root_created:
                created_output_root = output_root
            case_sensitive_output = case_sensitive_probe(output_root)

            def reject_after_output_setup(message):
                if output_root_created:
                    try:
                        os.rmdir(output_root)
                    except OSError:
                        pass
                return 0, message

            with tarfile.open(fileobj=payload_file, mode="r:*") as tar:
                members = []
                destination_trie = {}
                total_size = 0
                for member in tar:
                    if not member.isfile():
                        continue
                    if len(members) >= max_backup_files:
                        return reject_after_output_setup(
                            "backup contains too many files"
                        )
                    if member.size < 0 or member.size > max_backup_file_bytes:
                        return reject_after_output_setup(
                            "backup member exceeds per-file safety limit: "
                            f"{member.name}"
                        )
                    total_size += member.size
                    if total_size > max_backup_payload_bytes:
                        return reject_after_output_setup(
                            "backup members exceed total extraction safety limit"
                        )

                    name = member.name
                    if (
                        not name
                        or name.startswith(("/", "\\"))
                        or "\\" in name
                        or "\x00" in name
                    ):
                        return reject_after_output_setup(
                            f"unsafe backup member path: {name!r}"
                        )
                    parts = name.split("/")
                    if any(part in ("", ".", "..") or ":" in part for part in parts):
                        return reject_after_output_setup(
                            f"unsafe backup member path: {name!r}"
                        )
                    destination = os.path.abspath(os.path.join(output_root, *parts))
                    if os.path.commonpath((output_root, destination)) != output_root:
                        return reject_after_output_setup(
                            f"unsafe backup member path: {name!r}"
                        )
                    # Reject duplicate paths and file/directory prefix conflicts
                    # before writing anything (for example, both ``a`` and
                    # ``a/b``). Case-folding also avoids partial extraction on
                    # Windows-style case-insensitive destinations.
                    trie_node = destination_trie
                    # APFS and HFS+ can collapse canonically equivalent Unicode
                    # names even when their Python strings differ. Normalize
                    # before applying the destination's case behavior so a
                    # collision is rejected before any file is written.
                    normalized_parts = [
                        unicodedata.normalize("NFC", item) for item in parts
                    ]
                    if not case_sensitive_output:
                        normalized_parts = [
                            item.casefold() for item in normalized_parts
                        ]
                    for part in normalized_parts:
                        if None in trie_node:
                            return reject_after_output_setup(
                                f"conflicting backup member path: {name!r}"
                            )
                        trie_node = trie_node.setdefault(part, {})
                    if None in trie_node:
                        return reject_after_output_setup(
                            f"duplicate backup member path: {name!r}"
                        )
                    if trie_node:
                        return reject_after_output_setup(
                            f"conflicting backup member path: {name!r}"
                        )
                    trie_node[None] = True
                    members.append((member, destination))

                # Check every existing path and parent symlink before the first
                # output file is opened, so a late conflict cannot leave a
                # misleading partial extraction behind.
                for _member, destination in members:
                    parent = os.path.dirname(destination)
                    relative_parent = os.path.relpath(parent, output_root)
                    cursor = output_root
                    if relative_parent != ".":
                        for part in relative_parent.split(os.sep):
                            cursor = os.path.join(cursor, part)
                            if (os.path.lexists(cursor)
                                    and _is_link_or_reparse_point(cursor)):
                                return reject_after_output_setup(
                                    f"refusing to extract through symlink: {cursor}"
                                )
                            if os.path.lexists(cursor) and not os.path.isdir(cursor):
                                return reject_after_output_setup(
                                    "backup parent path is not a directory: "
                                    f"{cursor}"
                                )
                    if os.path.lexists(destination):
                        return reject_after_output_setup(
                            "refusing to overwrite existing path: "
                            f"{destination}"
                        )

                count = 0
                created_files = []
                created_directories = [output_root] if output_root_created else []
                try:
                    for member, destination in members:
                        parent = os.path.dirname(destination)
                        relative_parent = os.path.relpath(parent, output_root)
                        cursor = output_root
                        if relative_parent != ".":
                            for part in relative_parent.split(os.sep):
                                cursor = os.path.join(cursor, part)
                                if os.path.lexists(cursor):
                                    if (_is_link_or_reparse_point(cursor)
                                            or not os.path.isdir(cursor)):
                                        raise OSError(
                                            "unsafe backup parent appeared during extraction: "
                                            f"{cursor}"
                                        )
                                else:
                                    os.mkdir(cursor)
                                    created_directories.append(cursor)
                        extracted = tar.extractfile(member)
                        if extracted is None:
                            raise tarfile.ReadError(
                                f"could not read backup member: {member.name}"
                            )
                        try:
                            with extracted, open(destination, "xb") as output:
                                # Record the destination as soon as it exists so
                                # a short write is also removed during rollback.
                                created_files.append(destination)
                                shutil.copyfileobj(
                                    extracted, output, length=1024 * 1024
                                )
                        except Exception:
                            if not extracted.closed:
                                extracted.close()
                            raise
                        count += 1
                except (OSError, tarfile.TarError) as exc:
                    for created_file in reversed(created_files):
                        try:
                            if os.path.lexists(created_file):
                                os.remove(created_file)
                        except OSError:
                            pass
                    for created_directory in reversed(created_directories):
                        try:
                            os.rmdir(created_directory)
                        except OSError:
                            pass
                    return 0, f"backup extraction failed: {exc}"

                return count, None
    except (OSError, tarfile.TarError, zlib.error) as exc:
        if created_output_root:
            try:
                os.rmdir(created_output_root)
            except OSError:
                pass
        return 0, f"backup extraction failed: {exc}"
