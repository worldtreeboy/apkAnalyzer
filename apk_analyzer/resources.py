"""Conservative Android resource resolution for apktool output.

Android manifest attributes may reference resources whose effective value
changes with the device configuration.  A static analyzer must not pick the
unqualified file and silently treat it as universal.  This module resolves the
version dimension exactly and treats other qualifiers as possible alternatives.

Resolution results use three states:

``known``
    Every supported configuration covered by the decompiled resources has the
    same value (or one file path).
``conditional``
    Coverage is complete, but the effective value/path changes by Android
    version or another resource qualifier.
``unknown``
    A definition is missing, malformed, unsafe to read, or does not cover the
    lowest supported Android version.
"""

import os
import re
import xml.etree.ElementTree as ET

from .safety import MAX_XML_BYTES, parse_sdk_level, safe_parse_xml


KNOWN = "known"
CONDITIONAL = "conditional"
UNKNOWN = "unknown"

_RESOURCE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_RESOURCE_TYPE_RE = re.compile(r"^[A-Za-z0-9_]+$")
_VERSION_QUALIFIER_RE = re.compile(r"^v([0-9]+)$")
_MISSING = object()


def known_boolean(value, reference=None, reason=""):
    """Return a normalized result for a known boolean value."""
    boolean = bool(value)
    return {
        "state": KNOWN,
        "value": boolean,
        "possible_values": (boolean,),
        "reference": reference,
        "reason": reason,
    }


def unknown_boolean(reference=None, reason="Resource value could not be resolved"):
    """Return a normalized fail-safe result for an unresolved boolean."""
    return {
        "state": UNKNOWN,
        "value": None,
        "possible_values": (False, True),
        "reference": reference,
        "reason": reason,
    }


def may_be_true(result):
    """Return whether a boolean resolution can evaluate to true."""
    return True in result.get("possible_values", (False, True))


def combine_required_true(*results):
    """Combine boolean conditions which must all be true.

    Callers should normally discard a component first when one result is known
    false.  The function still handles that case for completeness.
    """
    if any(result.get("state") == KNOWN and not result.get("value")
           for result in results):
        return known_boolean(False, reason="A required condition is false")
    if any(result.get("state") == UNKNOWN for result in results):
        return unknown_boolean(reason="One or more required conditions are unresolved")
    if any(result.get("state") == CONDITIONAL for result in results):
        return {
            "state": CONDITIONAL,
            "value": None,
            "possible_values": (False, True),
            "reference": None,
            "reason": "Required conditions vary by resource qualifier",
        }
    return known_boolean(True)


def parse_reference(resource_ref, expected_type=None, local_package=None):
    """Parse a local Android resource reference.

    Framework and dependency-package resources are intentionally not mapped to
    the app's ``res`` tree.  Returning ``None`` is safer than confusing a
    foreign resource with an identically named local file.
    """
    if not isinstance(resource_ref, str):
        return None
    ref = resource_ref.strip()
    if ref.startswith("@"):
        ref = ref[1:]
    if ref.startswith("+"):
        ref = ref[1:]
    if not ref or ref in ("null", "empty"):
        return None

    package = None
    if ":" in ref:
        package, ref = ref.split(":", 1)
        if not package or package == "android":
            return None
        if local_package is None or package != local_package:
            return None

    parts = ref.split("/", 1)
    if len(parts) != 2 or not all(parts):
        return None
    resource_type, name = parts
    if (not _RESOURCE_TYPE_RE.fullmatch(resource_type)
            or not _RESOURCE_NAME_RE.fullmatch(name)):
        return None
    if expected_type is not None and resource_type != expected_type:
        return None
    return resource_type, name


def _qualifier_info(directory_name, resource_type):
    """Return ``(version, has_other_qualifiers)`` for a resource directory."""
    if directory_name == resource_type:
        return 0, False
    prefix = resource_type + "-"
    if not directory_name.startswith(prefix):
        return None
    parts = directory_name[len(prefix):].split("-")
    if not parts or any(not part for part in parts):
        return None
    versions = []
    for part in parts:
        match = _VERSION_QUALIFIER_RE.fullmatch(part)
        if match:
            version = parse_sdk_level(match.group(1))
            if version is None:
                return None
            versions.append(version)
    if len(versions) > 1:
        return None
    version = versions[0] if versions else 0
    return version, any(not _VERSION_QUALIFIER_RE.fullmatch(part)
                        for part in parts)


def _minimum_sdk(min_sdk):
    parsed = parse_sdk_level(min_sdk)
    if parsed is not None:
        return parsed, False
    return 1, True


def _resource_root(decompiled_dir):
    root = os.path.abspath(os.path.join(os.fspath(decompiled_dir), "res"))
    return root


def _resource_root_is_safe(decompiled_dir, resource_root):
    decompiled_root = os.path.realpath(os.path.abspath(os.fspath(decompiled_dir)))
    try:
        return (not os.path.islink(resource_root)
                and os.path.commonpath(
                    (decompiled_root, os.path.realpath(resource_root))
                ) == decompiled_root)
    except (OSError, ValueError):
        return False


def _is_within(root, path):
    try:
        return os.path.commonpath((os.path.realpath(root), os.path.realpath(path))) == os.path.realpath(root)
    except (OSError, ValueError):
        return False


def _resource_xml_mentions(path, name):
    """Return whether a file may define *name*, or ``None`` if unreadable.

    This avoids making an unrelated malformed values file poison every boolean
    lookup while remaining conservative for oversized or unreadable files.
    """
    try:
        if os.path.getsize(path) > MAX_XML_BYTES:
            return None
        with open(path, "rb") as source:
            data = source.read(MAX_XML_BYTES + 1)
    except OSError:
        return None
    if len(data) > MAX_XML_BYTES:
        return None
    encoded = re.escape(name.encode("utf-8"))
    return bool(re.search(rb"\bname\s*=\s*(['\"])" + encoded + rb"\1", data))


def _iter_value_definitions(decompiled_dir, name):
    """Collect candidate ``<bool>`` definitions and resolution issues."""
    definitions = []
    issues = []
    res_root = _resource_root(decompiled_dir)
    if not _resource_root_is_safe(decompiled_dir, res_root):
        return definitions, ["Resource directory is unsafe to read"]
    try:
        directories = sorted(os.scandir(res_root), key=lambda entry: entry.name)
    except OSError:
        return definitions, ["Resource directory is missing or unreadable"]

    for directory in directories:
        qualifier = _qualifier_info(directory.name, "values")
        if qualifier is None:
            continue
        if directory.is_symlink() or not directory.is_dir(follow_symlinks=False):
            issues.append("A values resource directory is unsafe to read")
            continue
        version, other_qualifiers = qualifier
        try:
            files = sorted(os.scandir(directory.path), key=lambda entry: entry.name)
        except OSError:
            issues.append("A values resource directory is unreadable")
            continue
        for entry in files:
            if not entry.name.endswith(".xml"):
                continue
            if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                issues.append("A values resource file is unsafe to read")
                continue
            if not _is_within(res_root, entry.path):
                issues.append("A values resource escaped the resource directory")
                continue
            try:
                tree = safe_parse_xml(entry.path)
                root = tree.getroot()
            except (ET.ParseError, OSError, ValueError):
                mentioned = _resource_xml_mentions(entry.path, name)
                if mentioned is not False:
                    issues.append("A relevant values resource file is malformed or unreadable")
                continue
            if root.tag != "resources":
                if _resource_xml_mentions(entry.path, name):
                    issues.append("A relevant values resource has an invalid root element")
                continue
            for child in list(root):
                tag = child.tag.rsplit("}", 1)[-1]
                is_bool = tag == "bool"
                is_bool_item = tag == "item" and child.get("type") == "bool"
                if (is_bool or is_bool_item) and child.get("name") == name:
                    raw = "".join(child.itertext()).strip()
                    definitions.append({
                        "version": version,
                        "other_qualifiers": other_qualifiers,
                        "configuration": directory.name,
                        "raw": raw,
                    })
    return definitions, issues


def _effective_definitions(definitions, min_sdk, issues):
    """Select definitions which can be effective on a supported device."""
    version_only = {}
    other = []
    by_configuration = {}
    for definition in definitions:
        by_configuration.setdefault(definition["configuration"], []).append(definition)
        if definition["other_qualifiers"]:
            other.append(definition)
        else:
            version_only.setdefault(definition["version"], []).append(definition)

    for candidates in by_configuration.values():
        if len(candidates) > 1:
            issues.append("A resource is defined more than once for one configuration")

    baseline_versions = [version for version in version_only if version <= min_sdk]
    selected = []
    if baseline_versions:
        selected.extend(version_only[max(baseline_versions)])
    else:
        issues.append("No resource definition covers the minimum supported Android version")
    for version in sorted(version for version in version_only if version > min_sdk):
        selected.extend(version_only[version])
    selected.extend(other)
    return selected


def _resolve_bool_token(decompiled_dir, raw, min_sdk, local_package, seen):
    token = (raw or "").strip()
    if token == "true":
        return {True}, True
    if token == "false":
        return {False}, True
    if token.startswith("@"):
        nested = resolve_boolean(
            decompiled_dir,
            token,
            min_sdk=min_sdk,
            local_package=local_package,
            _seen=seen,
        )
        return set(nested["possible_values"]), nested["state"] != UNKNOWN
    return {False, True}, False


def resolve_boolean(decompiled_dir, raw_value, default=_MISSING, min_sdk=1,
                    local_package=None, _seen=None):
    """Resolve a manifest boolean literal or local ``@bool`` reference.

    ``default`` is used only when the manifest attribute is absent.  A present
    but invalid/missing reference is always ``unknown`` and never falls back to
    the Android attribute default.
    """
    if raw_value is None:
        if default is _MISSING or not isinstance(default, bool):
            return unknown_boolean(reason="No boolean value or default was supplied")
        return known_boolean(default, reason="Android manifest default")

    raw = str(raw_value).strip()
    if raw == "true":
        return known_boolean(True, reference=raw)
    if raw == "false":
        return known_boolean(False, reference=raw)

    parsed = parse_reference(raw, expected_type="bool", local_package=local_package)
    if parsed is None:
        return unknown_boolean(raw, "Boolean value is not a resolvable local @bool reference")
    _resource_type, name = parsed
    key = (local_package, name)
    seen = set() if _seen is None else set(_seen)
    if key in seen:
        return unknown_boolean(raw, "Boolean resource aliases form a cycle")
    seen.add(key)

    minimum, minimum_unknown = _minimum_sdk(min_sdk)
    definitions, issues = _iter_value_definitions(decompiled_dir, name)
    if minimum_unknown:
        issues.append("Minimum SDK is unknown")
    if not definitions:
        issues.append("Boolean resource is missing")
        return unknown_boolean(raw, "; ".join(sorted(set(issues))))

    selected = _effective_definitions(definitions, minimum, issues)
    possible = set()
    complete = True
    for definition in selected:
        values, token_complete = _resolve_bool_token(
            decompiled_dir,
            definition["raw"],
            minimum,
            local_package,
            seen,
        )
        possible.update(values)
        complete = complete and token_complete
    if not selected:
        possible.update((False, True))
        complete = False
    if issues:
        complete = False
    if not complete:
        if not possible:
            possible.update((False, True))
        return {
            "state": UNKNOWN,
            "value": None,
            "possible_values": tuple(sorted(possible)),
            "reference": raw,
            "reason": "; ".join(sorted(set(issues))) or "Boolean resource is malformed",
        }
    if len(possible) == 1:
        value = next(iter(possible))
        return known_boolean(value, reference=raw)
    return {
        "state": CONDITIONAL,
        "value": None,
        "possible_values": tuple(sorted(possible)),
        "reference": raw,
        "reason": "Boolean resource changes across supported configurations",
    }


def resolve_file_variants(decompiled_dir, resource_ref, expected_type="xml",
                          min_sdk=1, local_package=None):
    """Resolve all effective files for a version/configuration resource.

    The returned ``paths`` are safe, regular files inside the decompiled
    resource tree.  ``unknown`` can still contain paths whose contents are
    useful for detecting a definite vulnerability; it means coverage is not
    complete enough to claim a PASS.
    """
    result = {
        "state": UNKNOWN,
        "paths": (),
        "reference": resource_ref,
        "reason": "Resource reference could not be resolved",
    }
    parsed = parse_reference(
        resource_ref, expected_type=expected_type, local_package=local_package
    )
    if parsed is None:
        return result
    resource_type, name = parsed
    filename = name if os.path.splitext(name)[1] else name + ".xml"
    minimum, minimum_unknown = _minimum_sdk(min_sdk)
    issues = ["Minimum SDK is unknown"] if minimum_unknown else []
    candidates = []
    res_root = _resource_root(decompiled_dir)
    if not _resource_root_is_safe(decompiled_dir, res_root):
        result["reason"] = "Resource directory is unsafe to read"
        return result
    try:
        directories = sorted(os.scandir(res_root), key=lambda entry: entry.name)
    except OSError:
        result["reason"] = "Resource directory is missing or unreadable"
        return result

    for directory in directories:
        qualifier = _qualifier_info(directory.name, resource_type)
        if qualifier is None:
            continue
        if directory.is_symlink() or not directory.is_dir(follow_symlinks=False):
            issues.append("A matching resource directory is unsafe to read")
            continue
        path = os.path.join(directory.path, filename)
        if not os.path.lexists(path):
            continue
        if os.path.islink(path) or not os.path.isfile(path) or not _is_within(res_root, path):
            issues.append("A matching resource file is unsafe to read")
            continue
        version, other_qualifiers = qualifier
        candidates.append({
            "version": version,
            "other_qualifiers": other_qualifiers,
            "configuration": directory.name,
            "path": os.path.abspath(path),
        })

    if not candidates:
        result["reason"] = "; ".join(sorted(set(issues + ["Referenced resource file is missing"])))
        return result

    selected = _effective_definitions(candidates, minimum, issues)
    paths = []
    for candidate in selected:
        path = candidate["path"]
        if path not in paths:
            paths.append(path)
    result["paths"] = tuple(paths)
    if issues or not paths:
        result["reason"] = "; ".join(sorted(set(issues))) or "No effective resource file was found"
        return result
    result["state"] = CONDITIONAL if len(paths) > 1 else KNOWN
    result["reason"] = (
        "Resource file changes across supported configurations"
        if len(paths) > 1 else ""
    )
    return result


def resolve_legacy_path(decompiled_dir, resource_ref, local_package=None):
    """Resolve only the unqualified file for the historical single-path API."""
    parsed = parse_reference(resource_ref, local_package=local_package)
    if parsed is None:
        return None
    resource_type, name = parsed
    filename = name if os.path.splitext(name)[1] else name + ".xml"
    res_root = _resource_root(decompiled_dir)
    if not _resource_root_is_safe(decompiled_dir, res_root):
        return None
    path = os.path.abspath(os.path.join(res_root, resource_type, filename))
    if (not _is_within(res_root, path) or os.path.islink(path)):
        return None
    return path


__all__ = [
    "CONDITIONAL",
    "KNOWN",
    "UNKNOWN",
    "combine_required_true",
    "known_boolean",
    "may_be_true",
    "parse_reference",
    "resolve_boolean",
    "resolve_file_variants",
    "resolve_legacy_path",
    "unknown_boolean",
]
