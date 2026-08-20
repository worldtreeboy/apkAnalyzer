"""Bounded, coverage-aware traversal for static smali/XML signals.

The rules that consume these files are deliberately kept outside this module.
This module only guarantees that file discovery, reads, and coverage reporting
remain bounded and fail closed when an input cannot be inspected completely.
"""

import os
import stat
from dataclasses import dataclass, field

from .safety import is_link_or_reparse_stat


DEFAULT_CHUNK_BYTES = 256 * 1024
DEFAULT_MAX_FILE_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 512 * 1024 * 1024
DEFAULT_EXTENSIONS = (".smali", ".xml")


@dataclass
class FileReadOutcome:
    """Bounded result of reading one candidate source file."""

    content: str = ""
    opened: bool = False
    complete: bool = False
    bytes_scanned: int = 0
    size: int = 0
    status: str = "complete"
    reason: str = ""


@dataclass
class StaticCodeScanResult:
    """Coverage accounting for one static smali/XML traversal."""

    scanned: list = field(default_factory=list)
    unreadable: list = field(default_factory=list)
    partial: list = field(default_factory=list)
    skipped: list = field(default_factory=list)
    oversized: list = field(default_factory=list)
    analysis_limited: list = field(default_factory=list)
    candidate_files: int = 0
    bytes_scanned: int = 0
    per_file_byte_budget: int = 0
    total_byte_budget: int = 0

    @property
    def coverage_complete(self):
        return not (
            self.unreadable or self.partial or self.skipped
            or self.analysis_limited
        )

    def incomplete_reason(self):
        """Return a bounded summary suitable for terminal/report output."""
        parts = []
        if self.unreadable:
            parts.append(f"{len(self.unreadable)} unreadable")
        if self.partial:
            detail = f"{len(self.partial)} partially scanned"
            if self.oversized:
                detail += (
                    f" ({len(self.oversized)} exceeded the per-file budget)"
                )
            parts.append(detail)
        if self.skipped:
            parts.append(f"{len(self.skipped)} skipped")
        if self.analysis_limited:
            parts.append(f"{len(self.analysis_limited)} analysis-limited")
        return ", ".join(parts) or "complete"

    def to_report_dict(self, path_limit=100):
        """Return bounded, JSON-serializable coverage metadata."""
        path_limit = max(0, int(path_limit))

        def paths(values):
            return list(values[:path_limit])

        return {
            "coverage_complete": self.coverage_complete,
            "candidate_files": self.candidate_files,
            "scanned_files": len(self.scanned),
            "bytes_scanned": self.bytes_scanned,
            "per_file_byte_budget": self.per_file_byte_budget,
            "total_byte_budget": self.total_byte_budget,
            "unreadable_count": len(self.unreadable),
            "partial_count": len(self.partial),
            "skipped_count": len(self.skipped),
            "oversized_count": len(self.oversized),
            "analysis_limited_count": len(self.analysis_limited),
            "unreadable": paths(self.unreadable),
            "partial": paths(self.partial),
            "skipped": paths(self.skipped),
            "oversized": paths(self.oversized),
            "analysis_limited": paths(self.analysis_limited),
        }


def is_candidate(path, extensions=DEFAULT_EXTENSIONS):
    """Return whether *path* has a supported static-code extension."""
    name = os.path.basename(os.fspath(path)).lower()
    normalized = tuple(str(extension).lower() for extension in extensions)
    return bool(normalized) and name.endswith(normalized)


def _validate_limits(max_bytes, chunk_bytes):
    max_bytes = int(max_bytes)
    chunk_bytes = int(chunk_bytes)
    if max_bytes < 0:
        raise ValueError("byte budget must be non-negative")
    if chunk_bytes <= 0:
        raise ValueError("chunk size must be positive")
    return max_bytes, chunk_bytes


def read_file(path, *, max_bytes=DEFAULT_MAX_FILE_BYTES,
              chunk_bytes=DEFAULT_CHUNK_BYTES):
    """Read at most *max_bytes* from one non-symlink regular file.

    Text is decoded with UTF-8 replacement so malformed byte sequences neither
    abort the rest of the scan nor silently disappear.  The returned content
    may be useful even when ``complete`` is false; consumers can retain proven
    positive findings while treating absence as inconclusive.
    """
    max_bytes, chunk_bytes = _validate_limits(max_bytes, chunk_bytes)
    outcome = FileReadOutcome()
    path = os.fspath(path)

    try:
        path_stat = os.lstat(path)
    except OSError as exc:
        outcome.status = "unreadable"
        outcome.reason = type(exc).__name__
        return outcome
    if is_link_or_reparse_stat(path_stat):
        outcome.status = "skipped"
        outcome.reason = "symbolic link"
        return outcome
    if not stat.S_ISREG(path_stat.st_mode):
        outcome.status = "skipped"
        outcome.reason = "not a regular file"
        return outcome

    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    descriptor = None
    try:
        descriptor = os.open(path, flags)
        source_stat = os.fstat(descriptor)
        if not stat.S_ISREG(source_stat.st_mode):
            os.close(descriptor)
            descriptor = None
            outcome.status = "skipped"
            outcome.reason = "not a regular file"
            return outcome
        try:
            same_file = os.path.samestat(path_stat, source_stat)
        except AttributeError:
            same_file = True
        except OSError:
            same_file = False
        if not same_file:
            os.close(descriptor)
            descriptor = None
            outcome.status = "skipped"
            outcome.reason = "file changed during open"
            return outcome
        outcome.size = source_stat.st_size
        source = os.fdopen(descriptor, "rb")
        descriptor = None
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        outcome.status = "unreadable"
        outcome.reason = type(exc).__name__
        return outcome

    chunks = []
    reached_eof = False
    try:
        with source:
            outcome.opened = True
            while outcome.bytes_scanned < max_bytes:
                remaining = max_bytes - outcome.bytes_scanned
                raw = source.read(min(chunk_bytes, remaining))
                if not raw:
                    reached_eof = True
                    break
                chunks.append(raw)
                outcome.bytes_scanned += len(raw)

            # A one-byte probe detects files whose size changed after fstat and
            # exact-budget files without retaining or analysing beyond budget.
            if not reached_eof and outcome.size <= max_bytes:
                reached_eof = not bool(source.read(1))
    except OSError as exc:
        outcome.content = b"".join(chunks).decode(
            "utf-8", errors="replace"
        )
        outcome.status = "unreadable"
        outcome.reason = type(exc).__name__
        return outcome

    outcome.content = b"".join(chunks).decode("utf-8", errors="replace")
    outcome.complete = reached_eof or outcome.bytes_scanned >= outcome.size
    # A file known to exceed the read allowance is partial even if it was
    # truncated or replaced between fstat and the first read.
    if outcome.size > max_bytes:
        outcome.complete = False
    if not outcome.complete:
        outcome.status = "partial"
        outcome.reason = "byte budget exhausted"
    return outcome


def scan_tree(root, consumer, *, extensions=DEFAULT_EXTENSIONS,
              max_file_bytes=DEFAULT_MAX_FILE_BYTES,
              max_total_bytes=DEFAULT_MAX_TOTAL_BYTES,
              chunk_bytes=DEFAULT_CHUNK_BYTES):
    """Traverse candidate files deterministically and call ``consumer``.

    ``consumer(relative_path, content)`` is invoked for every candidate that
    yielded readable bytes, including a bounded prefix of a partial file.
    Consumer failures are recorded as unreadable analysis evidence rather than
    being swallowed or aborting unrelated files. A consumer can return exactly
    ``False`` when its own result budget prevents complete analysis; that path
    is then recorded as analysis-limited.
    """
    max_file_bytes, chunk_bytes = _validate_limits(
        max_file_bytes, chunk_bytes
    )
    max_total_bytes = int(max_total_bytes)
    if max_total_bytes < 0:
        raise ValueError("total byte budget must be non-negative")
    if not callable(consumer):
        raise TypeError("consumer must be callable")

    root = os.path.abspath(os.fspath(root))
    result = StaticCodeScanResult(
        per_file_byte_budget=max_file_bytes,
        total_byte_budget=max_total_bytes,
    )

    def relative(path):
        value = os.path.relpath(path, root)
        return value.replace(os.sep, "/")

    def add_once(target, value):
        if value not in target:
            target.append(value)

    def walk_error(error):
        add_once(result.unreadable, relative(error.filename or root))

    try:
        root_stat = os.lstat(root)
    except OSError:
        result.unreadable.append(".")
        return result
    if is_link_or_reparse_stat(root_stat):
        result.skipped.append(".")
        return result
    if not stat.S_ISDIR(root_stat.st_mode):
        result.skipped.append(".")
        return result

    for directory, directories, files in os.walk(
            root, onerror=walk_error, followlinks=False):
        safe_directories = []
        for name in sorted(directories, key=lambda item: (item.casefold(), item)):
            child = os.path.join(directory, name)
            rel_child = relative(child)
            try:
                child_stat = os.lstat(child)
            except OSError:
                add_once(result.unreadable, rel_child)
                continue
            if is_link_or_reparse_stat(child_stat):
                add_once(result.skipped, rel_child)
                continue
            if not stat.S_ISDIR(child_stat.st_mode):
                add_once(result.skipped, rel_child)
                continue
            safe_directories.append(name)
        directories[:] = safe_directories

        for filename in sorted(files, key=lambda item: (item.casefold(), item)):
            path = os.path.join(directory, filename)
            if not is_candidate(path, extensions):
                continue
            result.candidate_files += 1
            rel_path = relative(path)
            remaining_total = max_total_bytes - result.bytes_scanned
            if remaining_total <= 0 or max_file_bytes <= 0:
                result.skipped.append(rel_path)
                continue

            outcome = read_file(
                path,
                max_bytes=min(max_file_bytes, remaining_total),
                chunk_bytes=chunk_bytes,
            )
            result.bytes_scanned += outcome.bytes_scanned
            if outcome.opened:
                result.scanned.append(rel_path)
                try:
                    consumer_result = consumer(rel_path, outcome.content)
                    if consumer_result is False:
                        add_once(result.analysis_limited, rel_path)
                except Exception as exc:
                    add_once(result.unreadable, rel_path)
                    outcome.status = "unreadable"
                    outcome.reason = f"consumer {type(exc).__name__}"

            if outcome.status == "unreadable":
                add_once(result.unreadable, rel_path)
            elif outcome.status == "skipped":
                add_once(result.skipped, rel_path)
            elif not outcome.complete:
                add_once(result.partial, rel_path)
                # Only the configured per-file cap denotes an oversized file;
                # a smaller effective cap can instead come from total budget.
                if outcome.size > max_file_bytes:
                    add_once(result.oversized, rel_path)

    return result
