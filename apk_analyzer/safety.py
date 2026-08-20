"""Input validation and output-sanitizing helpers.

These helpers do not depend on the interactive application, which keeps them
safe to reuse from future CLI, archive, and reporting modules.
"""

import os
import re
import stat
import xml.etree.ElementTree as ET


MAX_XML_BYTES = 10 * 1024 * 1024

_PACKAGE_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$"
)
_MAX_ANDROID_SDK_LEVEL = 999


def is_link_or_reparse_stat(path_stat):
    """Return whether an ``lstat`` result can redirect filesystem traversal."""
    if stat.S_ISLNK(path_stat.st_mode):
        return True
    attributes = getattr(path_stat, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def terminal_safe(value):
    """Strip terminal control sequences from untrusted device/app output."""
    text = str(value)
    # CSI and OSC sequences can rewrite the terminal or clipboard (OSC 52).
    text = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", "", text)
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = text.replace("\x1b", "")
    # C1 controls include single-byte CSI/OSC/ST forms and must not reach a
    # terminal even when the source did not contain an ESC byte.
    return "".join(
        ch for ch in text
        if ch in "\n\r\t" or (32 <= ord(ch) < 127) or ord(ch) >= 160
    )


def safe_parse_xml(path, max_bytes=MAX_XML_BYTES):
    """Parse an untrusted XML file with size and DTD/entity protections."""
    path = os.fspath(path)
    path_stat = os.lstat(path)
    if (is_link_or_reparse_stat(path_stat)
            or not stat.S_ISREG(path_stat.st_mode)):
        raise ValueError(
            "XML input must be a non-link, non-reparse regular file"
        )

    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    descriptor = os.open(path, flags)
    try:
        source_stat = os.fstat(descriptor)
        if (not stat.S_ISREG(source_stat.st_mode)
                or not os.path.samestat(path_stat, source_stat)):
            raise ValueError("XML input changed during open")
        if source_stat.st_size > max_bytes:
            raise ValueError(
                f"XML file exceeds {max_bytes} byte safety limit"
            )
        with os.fdopen(descriptor, "rb") as fh:
            descriptor = None
            data = fh.read(max_bytes + 1)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(data) > max_bytes:
        raise ValueError(f"XML file exceeds {max_bytes} byte safety limit")
    upper = data.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ValueError("DTD/entity declarations are not allowed")
    # ElementTree is safe here because DTD/entities are rejected and input is
    # bounded.
    return ET.ElementTree(ET.fromstring(data))  # nosec B314


def is_valid_package(package):
    """Return whether *package* is a safe Android application identifier."""
    return bool(_PACKAGE_RE.fullmatch(package or ""))


def parse_sdk_level(value):
    """Return a bounded numeric Android API level, or ``None`` if unresolved."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 1 <= value <= _MAX_ANDROID_SDK_LEVEL else None
    if not isinstance(value, str):
        return None
    # Bound lexical length before int(): Python 3.8 has no decimal-conversion
    # digit limit, and manifest attributes are APK-controlled.
    if not re.fullmatch(r"[0-9]{1,3}", value):
        return None
    parsed = int(value)
    return parsed if 1 <= parsed <= _MAX_ANDROID_SDK_LEVEL else None
