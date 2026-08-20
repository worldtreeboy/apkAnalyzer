"""Bounded, coverage-aware scanning of likely-text secret sources."""

import codecs
import os
import stat
from dataclasses import dataclass, field

from .safety import is_link_or_reparse_stat


DEFAULT_CHUNK_BYTES = 256 * 1024
# The legacy scanner examined at most 500,000 characters at once, and its
# private-key pattern permits a 500,000-character body.  Retaining that much
# preceding text prevents supported matches from disappearing at chunk edges.
DEFAULT_OVERLAP_CHARS = 512 * 1024
DEFAULT_MAX_FILE_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 256 * 1024 * 1024
DEFAULT_EXTENSIONS = (
    ".xml", ".json", ".properties", ".yml", ".yaml", ".env", ".ini",
    ".cfg", ".conf", ".config", ".txt", ".js", ".mjs", ".cjs",
    ".ts", ".tsx", ".jsx", ".java", ".kt", ".kts", ".smali",
    ".gradle", ".toml", ".dart", ".html", ".htm", ".pem", ".key",
    ".bundle",
)


@dataclass
class FileScanOutcome:
    """Outcome of scanning one candidate file."""

    matched: bool = False
    opened: bool = False
    complete: bool = False
    bytes_scanned: int = 0
    size: int = 0
    status: str = "complete"
    reason: str = ""


@dataclass
class StaticSecretScanResult:
    """Findings and evidence-coverage accounting for a directory scan."""

    matches: list = field(default_factory=list)
    scanned: list = field(default_factory=list)
    unreadable: list = field(default_factory=list)
    partial: list = field(default_factory=list)
    skipped: list = field(default_factory=list)
    oversized: list = field(default_factory=list)
    candidate_files: int = 0
    bytes_scanned: int = 0
    per_file_byte_budget: int = 0
    total_byte_budget: int = 0

    @property
    def coverage_complete(self):
        return not (self.unreadable or self.partial or self.skipped)

    def incomplete_reason(self):
        """Return a concise reason suitable for console and report metadata."""
        parts = []
        if self.unreadable:
            parts.append(f"{len(self.unreadable)} unreadable")
        if self.partial:
            detail = f"{len(self.partial)} partially scanned"
            if self.oversized:
                detail += f" ({len(self.oversized)} exceeded the per-file budget)"
            parts.append(detail)
        if self.skipped:
            parts.append(f"{len(self.skipped)} skipped")
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
            "matched_files": len(self.matches),
            "bytes_scanned": self.bytes_scanned,
            "per_file_byte_budget": self.per_file_byte_budget,
            "total_byte_budget": self.total_byte_budget,
            "unreadable_count": len(self.unreadable),
            "partial_count": len(self.partial),
            "skipped_count": len(self.skipped),
            "oversized_count": len(self.oversized),
            "unreadable": paths(self.unreadable),
            "partial": paths(self.partial),
            "skipped": paths(self.skipped),
            "oversized": paths(self.oversized),
        }


def is_candidate(path, extensions=DEFAULT_EXTENSIONS):
    """Return whether *path* has a supported likely-text extension."""
    name = os.path.basename(os.fspath(path)).lower()
    normalized = tuple(str(extension).lower() for extension in extensions)
    return bool(normalized) and name.endswith(normalized)


def _validate_limits(max_bytes, chunk_bytes, overlap_chars):
    max_bytes = int(max_bytes)
    chunk_bytes = int(chunk_bytes)
    overlap_chars = int(overlap_chars)
    if max_bytes < 0:
        raise ValueError("byte budget must be non-negative")
    if chunk_bytes <= 0:
        raise ValueError("chunk size must be positive")
    if overlap_chars < 0:
        raise ValueError("overlap must be non-negative")
    return max_bytes, chunk_bytes, overlap_chars


def scan_file(path, matcher, *, max_bytes=DEFAULT_MAX_FILE_BYTES,
              chunk_bytes=DEFAULT_CHUNK_BYTES,
              overlap_chars=DEFAULT_OVERLAP_CHARS):
    """Scan one regular file with bounded reads and overlapping text windows.

    ``matcher`` is called as ``matcher(text, final_window)``.  Callers can
    defer regex matches that end at an artificial chunk boundary until a later
    window supplies look-ahead.  This keeps the file transport reusable while
    the legacy launcher remains the source of its structured regex semantics.
    """
    max_bytes, chunk_bytes, overlap_chars = _validate_limits(
        max_bytes, chunk_bytes, overlap_chars
    )
    outcome = FileScanOutcome()
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
        outcome.size = source_stat.st_size
        source = os.fdopen(descriptor, "rb")
        descriptor = None
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        outcome.status = "unreadable"
        outcome.reason = type(exc).__name__
        return outcome

    decoder = codecs.getincrementaldecoder("utf-8")(errors="ignore")
    carry = ""
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
                outcome.bytes_scanned += len(raw)
                if not outcome.matched:
                    text = carry + decoder.decode(raw, final=False)
                    final_window = outcome.bytes_scanned >= outcome.size
                    try:
                        outcome.matched = bool(matcher(text, final_window))
                    except Exception as exc:
                        outcome.status = "unreadable"
                        outcome.reason = f"matcher {type(exc).__name__}"
                        return outcome
                    carry = text[-overlap_chars:] if overlap_chars else ""

            if not outcome.matched and reached_eof:
                tail = decoder.decode(b"", final=True)
                try:
                    outcome.matched = bool(matcher(carry + tail, True))
                except Exception as exc:
                    outcome.status = "unreadable"
                    outcome.reason = f"matcher {type(exc).__name__}"
                    return outcome
    except OSError as exc:
        outcome.status = "unreadable"
        outcome.reason = type(exc).__name__
        return outcome

    outcome.complete = reached_eof or outcome.bytes_scanned >= outcome.size
    if not outcome.complete:
        outcome.status = "partial"
        outcome.reason = "byte budget exhausted"
    return outcome


def scan_tree(root, matcher, *, extensions=DEFAULT_EXTENSIONS,
              max_file_bytes=DEFAULT_MAX_FILE_BYTES,
              max_total_bytes=DEFAULT_MAX_TOTAL_BYTES,
              chunk_bytes=DEFAULT_CHUNK_BYTES,
              overlap_chars=DEFAULT_OVERLAP_CHARS):
    """Scan a tree and account for every supported candidate not fully read."""
    max_file_bytes, chunk_bytes, overlap_chars = _validate_limits(
        max_file_bytes, chunk_bytes, overlap_chars
    )
    max_total_bytes = int(max_total_bytes)
    if max_total_bytes < 0:
        raise ValueError("total byte budget must be non-negative")

    root = os.path.abspath(os.fspath(root))
    result = StaticSecretScanResult(
        per_file_byte_budget=max_file_bytes,
        total_byte_budget=max_total_bytes,
    )

    def relative(path):
        return os.path.relpath(path, root)

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

    for directory, directories, files in os.walk(root, onerror=walk_error):
        safe_directories = []
        for name in sorted(directories):
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
        # Mutating the list is required to prevent os.walk from descending
        # into an entry that changed type during traversal.
        directories[:] = safe_directories
        files.sort()
        for filename in files:
            path = os.path.join(directory, filename)
            if not is_candidate(path, extensions):
                continue
            result.candidate_files += 1
            rel_path = relative(path)
            remaining_total = max_total_bytes - result.bytes_scanned
            if remaining_total <= 0 or max_file_bytes <= 0:
                result.skipped.append(rel_path)
                continue

            outcome = scan_file(
                path,
                matcher,
                max_bytes=min(max_file_bytes, remaining_total),
                chunk_bytes=chunk_bytes,
                overlap_chars=overlap_chars,
            )
            result.bytes_scanned += outcome.bytes_scanned
            if outcome.opened:
                result.scanned.append(rel_path)
            if outcome.matched:
                result.matches.append(rel_path)

            if outcome.status == "unreadable":
                result.unreadable.append(rel_path)
            elif outcome.status == "skipped":
                result.skipped.append(rel_path)
            elif not outcome.complete:
                result.partial.append(rel_path)
                if outcome.size > max_file_bytes:
                    result.oversized.append(rel_path)

    return result
