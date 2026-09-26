#!/usr/bin/env python3
"""APK Analyzer - Android Security Analysis Tool.

Run this file for a local static scan or the interactive device workflow.
The implementations live in apk_analyzer and are bound into this module so
imports and monkeypatches of apkAnalyzer keep working.
"""

import types

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
    analyze_broadcast_sends as _analyze_broadcast_sends,
    analyze_clipboard_writes as _analyze_clipboard_writes,
    analyze_pending_intents as _analyze_pending_intents,
    analyze_webview_settings as _analyze_webview_settings,
    classify_backup_xml as _classify_backup_xml,
    classify_deep_link as _classify_deep_link,
    combine_backup_policy as _combine_backup_policy,
    correlate_permission_apis as _correlate_permission_apis,
    match_permission_apis as _match_permission_apis,
    webview_setting_severity as _webview_setting_severity,
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
from apk_analyzer.version import (
    CURRENT_PLAY_TARGET_SDK,
    EXISTING_APP_TARGET_SDK_FLOOR,
    TOOL_VERSION,
)

_configure_windows_streams()

# Legacy, monkeypatchable aliases. The archive module owns the defaults;
# _unpack_ab reads these names from this module at call time.
MAX_BACKUP_BYTES = archive_mod.DEFAULT_MAX_BACKUP_BYTES
MAX_BACKUP_PAYLOAD_BYTES = archive_mod.DEFAULT_MAX_BACKUP_PAYLOAD_BYTES
MAX_BACKUP_FILE_BYTES = archive_mod.DEFAULT_MAX_BACKUP_FILE_BYTES
MAX_BACKUP_FILES = archive_mod.DEFAULT_MAX_BACKUP_FILES

from apk_analyzer import device as _device_mod
from apk_analyzer import decompile as _decompile_mod
from apk_analyzer import framework as _framework_mod
from apk_analyzer import manifest as _manifest_mod
from apk_analyzer import patterns as _patterns_mod
from apk_analyzer import storage as _storage_mod
from apk_analyzer import scan as _scan_mod
from apk_analyzer import checks as _checks_mod
from apk_analyzer import probes as _probes_mod
from apk_analyzer import patcher as _patcher_mod
from apk_analyzer import runtime as _runtime_mod
from apk_analyzer import menu as _menu_mod


_FEATURE_MODULES = (
    _device_mod,
    _decompile_mod,
    _framework_mod,
    _manifest_mod,
    _patterns_mod,
    _storage_mod,
    _scan_mod,
    _checks_mod,
    _probes_mod,
    _patcher_mod,
    _runtime_mod,
    _menu_mod,
)


def _bind_feature_function(function, namespace):
    """Return *function* with lookups resolved in the launcher namespace."""
    if function.__closure__:
        raise RuntimeError(
            "feature function has a closure and cannot be rebound: "
            + function.__name__
        )
    bound = types.FunctionType(
        function.__code__,
        namespace,
        function.__name__,
        function.__defaults__,
        None,
    )
    bound.__kwdefaults__ = function.__kwdefaults__
    bound.__annotations__ = dict(function.__annotations__)
    bound.__qualname__ = function.__qualname__
    bound.__module__ = __name__
    bound.__doc__ = function.__doc__
    return bound


def _bind_feature_modules():
    """Publish feature-module names from this launcher module."""
    namespace = globals()
    for module in _FEATURE_MODULES:
        for name in module.__all__:
            obj = getattr(module, name)
            if (isinstance(obj, types.FunctionType)
                    and obj.__module__ == module.__name__):
                obj = _bind_feature_function(obj, namespace)
                setattr(module, name, obj)
            namespace[name] = obj


_bind_feature_modules()


if __name__ == "__main__":
    sys.exit(_entrypoint())
