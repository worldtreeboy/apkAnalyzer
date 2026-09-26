"""Secret and PII pattern matching for static and device scans.

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


_LIVE_SECRET_PATTERNS = (
    re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    re.compile(r"rk_live_[0-9a-zA-Z]{24,}"),
    re.compile(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"),
    re.compile(r"xox[bprs]-[0-9A-Za-z-]{10,}"),
    re.compile(
        r"https://hooks\.slack\.com/services/"
        r"T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"
    ),
    re.compile(r"gh[ps]_[A-Za-z0-9_]{36,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{22,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9_.-]{8,}"),
    re.compile(
        r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----"
    ),
    re.compile(
        r"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://"
        r"[^\s/:@]+:[^\s/@]+@"
    ),
    re.compile(r"(?i)(?:AccountKey|SharedAccessSignature)=[^\s;]{8,}"),
    re.compile(r"(?i)(?<![A-Za-z0-9_-])key=[A-Za-z0-9_-]{39}(?![A-Za-z0-9_-])"),
)
_SDK_PATH_MARKERS = (
    "/com/google/",
    "/com/android/",
    "/androidx/",
    "/kotlin/",
    "/kotlinx/",
    "/okhttp3/",
    "/okhttp/",
    "/okio/",
    "/retrofit2/",
    "/com/facebook/",
    "/com/firebase/",
    "/com/crashlytics/",
    "/io/flutter/",
    "/org/apache/",
    "/com/squareup/",
    "/com/adjust/",
    "/com/appsflyer/",
    "/io/branch/",
    "/com/mixpanel/",
    "/com/amplitude/",
    "/com/segment/",
)


def _is_live_secret_value(value):
    """Return whether a matched value has a known live-credential shape."""
    text = str(value or "").strip()
    return any(pattern.search(text) for pattern in _LIVE_SECRET_PATTERNS)


def _is_sdk_static_path(relative):
    """Return whether a decompiled path sits inside a known library tree."""
    padded = "/" + str(relative or "").replace("\\", "/").lower()
    return any(marker in padded for marker in _SDK_PATH_MARKERS)


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

__all__ = [
    'STATIC_SECRET_CHUNK_BYTES',
    'STATIC_SECRET_CHUNK_OVERLAP_CHARS',
    'STATIC_SECRET_MAX_FILE_BYTES',
    'STATIC_SECRET_MAX_TOTAL_BYTES',
    'STATIC_SECRET_EXTENSIONS',
    'STATIC_CODE_CHUNK_BYTES',
    'STATIC_CODE_MAX_FILE_BYTES',
    'STATIC_CODE_MAX_TOTAL_BYTES',
    'STATIC_CODE_EXTENSIONS',
    '_should_scan_static_secrets',
    '_SECRET_KEY_PATTERN',
    '_SECRET_ASSIGNMENT_VALUE',
    'SECRET_PATTERNS',
    '_SECRET_VALUE_GROUPS',
    '_PUBLIC_IDENTIFIER_PATTERNS',
    '_secret_value_and_span',
    '_is_public_secret_identifier',
    '_LIVE_SECRET_PATTERNS',
    '_SDK_PATH_MARKERS',
    '_is_live_secret_value',
    '_is_sdk_static_path',
    '_is_non_secret_endpoint_config',
    '_iter_secret_matches',
    '_find_secret_matches',
    '_redact_secret_text',
    '_sqlite_identifier',
    '_sqlite_read',
    'PII_PATTERNS',
    '_scan_pii',
    '_redact_sensitive_text',
    '_batch_read_files',
    '_batch_stat',
]
