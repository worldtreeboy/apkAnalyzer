"""Manifest, permission, network-security, and native-string analysis.

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
        "full_backup_content": None,
        "data_extraction_rules": None,
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
            info["full_backup_content"] = app.get(f"{ns}fullBackupContent")
            info["data_extraction_rules"] = app.get(
                f"{ns}dataExtractionRules"
            )
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



__all__ = [
    '_ANDROID_NS',
    'DANGEROUS_PERMS',
    '_STRONG_PERMISSION_LEVELS',
    '_KNOWN_STRONG_PLATFORM_PERMISSIONS',
    '_KNOWN_WEAK_PLATFORM_PERMISSIONS',
    '_permission_strength',
    '_permission_is_strong',
    '_provider_protection_strength',
    '_provider_is_strongly_protected',
    '_resolve_bool_resource',
    '_resolve_resource_variants',
    '_manifest_bool_resolution',
    '_SPLIT_DIRECTORY_NAME',
    '_MAX_SPLIT_MANIFESTS',
    '_parse_single_manifest',
    '_split_manifest_directories',
    '_parse_manifest',
    '_resolve_resource_path',
    '_analyze_nsc',
    '_analyze_nsc_variants',
    '_print_nsc_analysis',
    'SECURITY_PACKAGES',
    '_check_security_classes',
    '_print_security_classes',
    '_NATIVE_STRING_PATTERNS',
    '_bounded_printable_ascii',
    '_run_native_strings_tool',
    '_native_stat_signature',
    '_read_native_file_bounded',
    '_scan_native_strings',
    '_print_native_strings',
]
