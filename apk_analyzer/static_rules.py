"""Pure, bounded classifiers for static Android security checks.

The helpers in this module intentionally do not read files or update reports.
They accept decoded manifest/smali data and return evidence that the legacy UI
can classify without relying on whole-file substring matches.
"""

import re

from .safety import parse_sdk_level


PENDING_INTENT_FLAG_MUTABLE = 0x02000000
PENDING_INTENT_FLAG_IMMUTABLE = 0x04000000
CLIPBOARD_SENSITIVE_KEY = "android.content.extra.IS_SENSITIVE"

_REGISTER_RE = re.compile(r"^[vp]\d{1,5}$")
_INVOKE_RE = re.compile(
    r"^\s*(invoke-[\w/-]+)\s+\{([^}]*)\},\s+"
    r"(L[^;]+;)->([^\s(]+)\(([^)]*)\)(\S+)"
)
_PENDING_METHODS = {
    "getActivity", "getActivities", "getBroadcast", "getService",
    "getForegroundService",
}
_NON_WRITING_OP_PREFIXES = (
    "return", "if-", "goto", "invoke-", "sput", "iput", "aput",
    "monitor-", "throw", "packed-switch", "sparse-switch",
    "fill-array-data",
)


def _expand_registers(register_text):
    """Expand an invoke register list, including ``v0 .. v4`` ranges."""
    value = register_text.strip()
    if not value or len(value) > 4096:
        return []
    if ".." in value:
        bounds = [part.strip() for part in value.split("..", 1)]
        if len(bounds) != 2:
            return []
        first = re.fullmatch(r"([vp])(\d+)", bounds[0])
        last = re.fullmatch(r"([vp])(\d+)", bounds[1])
        if not first or not last or first.group(1) != last.group(1):
            return []
        if len(first.group(2)) > 5 or len(last.group(2)) > 5:
            return []
        start = int(first.group(2))
        end = int(last.group(2))
        if (start > 65535 or end > 65535
                or end < start or end - start > 255):
            return []
        return [f"{first.group(1)}{number}" for number in range(start, end + 1)]
    registers = [part.strip() for part in value.split(",")]
    return (registers if len(registers) <= 256
            and all(_REGISTER_RE.fullmatch(reg) for reg in registers) else [])


def _split_descriptors(descriptors):
    """Split a Dalvik parameter descriptor into individual types."""
    result = []
    index = 0
    while index < len(descriptors):
        start = index
        while index < len(descriptors) and descriptors[index] == "[":
            index += 1
        if index >= len(descriptors):
            return []
        if descriptors[index] == "L":
            end = descriptors.find(";", index)
            if end < 0:
                return []
            index = end + 1
        elif descriptors[index] in "ZBSCIJFD":
            index += 1
        else:
            return []
        result.append(descriptors[start:index])
    return result


def _parse_invoke(line):
    match = _INVOKE_RE.match(line)
    if not match:
        return None
    opcode, register_text, owner, method, parameters, return_type = match.groups()
    registers = _expand_registers(register_text)
    descriptors = _split_descriptors(parameters)
    if not registers or (parameters and not descriptors):
        return None
    return {
        "opcode": opcode,
        "registers": registers,
        "owner": owner,
        "method": method,
        "parameters": descriptors,
        "return_type": return_type,
        "static": opcode.startswith("invoke-static"),
    }


def _argument_register(invocation, parameter_index):
    """Return the first register word for a Dalvik method parameter."""
    offset = 0 if invocation["static"] else 1
    for index, descriptor in enumerate(invocation["parameters"]):
        if index == parameter_index:
            return (invocation["registers"][offset]
                    if offset < len(invocation["registers"]) else None)
        offset += 2 if descriptor in ("J", "D") else 1
    return None


def _method_lower_bound(lines, index, lookback):
    lower = max(0, index - max(1, int(lookback)))
    for cursor in range(index - 1, lower - 1, -1):
        stripped = lines[cursor].lstrip()
        if stripped.startswith(".method") or stripped.startswith(".end method"):
            return cursor + 1
    return lower


def _is_control_flow_boundary(instruction):
    stripped = instruction.lstrip()
    return (stripped.startswith(":")
            or stripped.startswith("if-")
            or stripped.startswith("goto")
            or stripped.startswith("packed-switch")
            or stripped.startswith("sparse-switch")
            or stripped.startswith(".catch"))


def _instruction_writes_register(instruction, register):
    first_operand = re.match(
        r"([\w/-]+)\s+([vp]\d+)(?:\s*,|$)", instruction
    )
    return bool(
        first_operand and first_operand.group(2) == register
        and not first_operand.group(1).startswith(_NON_WRITING_OP_PREFIXES)
    )


def _parse_literal(value):
    value = value.strip()
    if len(value) > 32:
        return None
    match = re.fullmatch(r"([+-]?(?:0x[0-9a-fA-F]+|\d+))[tTsSlL]?", value)
    if not match:
        return None
    try:
        return int(match.group(1), 0) & 0xFFFFFFFF
    except ValueError:
        return None


def _resolve_int_constant(lines, before_index, register, lower_bound,
                          remaining=32, seen=None):
    """Resolve a local integer through bounded const/move/OR instructions."""
    if remaining <= 0 or not _REGISTER_RE.fullmatch(register or ""):
        return None
    if seen is None:
        seen = set()
    state = (before_index, register)
    if state in seen:
        return None
    seen.add(state)

    for cursor in range(before_index - 1, lower_bound - 1, -1):
        instruction = lines[cursor].split("#", 1)[0].strip()
        if _is_control_flow_boundary(instruction):
            return None
        if not instruction or instruction.startswith("."):
            continue

        field = re.match(
            r"sget(?:-object)?\s+([vp]\d+)\s*,\s*"
            r"Landroid/app/PendingIntent;->(FLAG_IMMUTABLE|FLAG_MUTABLE):I$",
            instruction,
        )
        if field and field.group(1) == register:
            return (PENDING_INTENT_FLAG_IMMUTABLE
                    if field.group(2) == "FLAG_IMMUTABLE"
                    else PENDING_INTENT_FLAG_MUTABLE)

        constant = re.match(
            r"const(?:/(4|16|high16))?\s+([vp]\d+)\s*,\s*([^\s,]+)",
            instruction,
        )
        if constant and constant.group(2) == register:
            value = _parse_literal(constant.group(3))
            if value is None:
                return None
            # baksmali renders const/high16 as the represented full 32-bit
            # value (for example ``0x4000000``), not the encoded 16-bit word.
            return value

        move = re.match(r"move(?:/\w+)?\s+([vp]\d+)\s*,\s*([vp]\d+)$", instruction)
        if move and move.group(1) == register:
            return _resolve_int_constant(
                lines, cursor, move.group(2), lower_bound,
                remaining=remaining - 1, seen=seen,
            )

        binary = re.match(
            r"(or|and|xor)-int\s+([vp]\d+)\s*,\s*([vp]\d+)\s*,\s*([vp]\d+)$",
            instruction,
        )
        if binary and binary.group(2) == register:
            left = _resolve_int_constant(
                lines, cursor, binary.group(3), lower_bound,
                remaining=remaining - 1, seen=set(seen),
            )
            right = _resolve_int_constant(
                lines, cursor, binary.group(4), lower_bound,
                remaining=remaining - 1, seen=set(seen),
            )
            if left is None or right is None:
                return None
            return {"or": left | right, "and": left & right,
                    "xor": left ^ right}[binary.group(1)] & 0xFFFFFFFF

        literal = re.match(
            r"(or|and|xor)-int/lit(?:8|16)\s+([vp]\d+)\s*,\s*"
            r"([vp]\d+)\s*,\s*([^\s,]+)$",
            instruction,
        )
        if literal and literal.group(2) == register:
            left = _resolve_int_constant(
                lines, cursor, literal.group(3), lower_bound,
                remaining=remaining - 1, seen=set(seen),
            )
            right = _parse_literal(literal.group(4))
            if left is None or right is None:
                return None
            return {"or": left | right, "and": left & right,
                    "xor": left ^ right}[literal.group(1)] & 0xFFFFFFFF

        two_address = re.match(
            r"(or|and|xor)-int/2addr\s+([vp]\d+)\s*,\s*([vp]\d+)$",
            instruction,
        )
        if two_address and two_address.group(2) == register:
            left = _resolve_int_constant(
                lines, cursor, register, lower_bound,
                remaining=remaining - 1, seen=set(seen),
            )
            right = _resolve_int_constant(
                lines, cursor, two_address.group(3), lower_bound,
                remaining=remaining - 1, seen=set(seen),
            )
            if left is None or right is None:
                return None
            return {"or": left | right, "and": left & right,
                    "xor": left ^ right}[two_address.group(1)] & 0xFFFFFFFF

        first_operand = re.match(r"([\w/-]+)\s+([vp]\d+)(?:\s*,|$)", instruction)
        if first_operand and first_operand.group(2) == register:
            opcode = first_operand.group(1)
            if not opcode.startswith(_NON_WRITING_OP_PREFIXES):
                # A write we do not model invalidates any older constant.
                return None
    return None


def _previous_instruction(lines, index, lower_bound):
    for cursor in range(index - 1, lower_bound - 1, -1):
        stripped = lines[cursor].strip()
        if stripped and not stripped.startswith((".", ":", "#")):
            return cursor, stripped
    return None, None


def _intent_explicitness(lines, before_index, register, lower_bound):
    """Return ``explicit``, ``implicit``, or ``unknown`` for an Intent value."""
    current = register
    for cursor in range(before_index - 1, lower_bound - 1, -1):
        instruction = lines[cursor].split("#", 1)[0].strip()
        if _is_control_flow_boundary(instruction):
            return "unknown"
        if not instruction or instruction.startswith("."):
            continue
        invocation = _parse_invoke(instruction)
        if invocation and invocation["owner"] == "Landroid/content/Intent;":
            regs = invocation["registers"]
            receiver = regs[0] if regs and not invocation["static"] else None
            if receiver == current and invocation["method"] in {
                    "setClass", "setClassName", "setComponent"}:
                return "explicit"
            if (receiver == current and invocation["method"] == "<init>"):
                params = invocation["parameters"]
                if ("Ljava/lang/Class;" in params
                        or "Landroid/content/ComponentName;" in params):
                    return "explicit"
                return "implicit"

        move = re.match(
            r"move-object(?:/\w+)?\s+([vp]\d+)\s*,\s*([vp]\d+)$",
            instruction,
        )
        if move and move.group(1) == current:
            current = move.group(2)
            continue

        move_result = re.match(r"move-result-object\s+([vp]\d+)$", instruction)
        if move_result and move_result.group(1) == current:
            _prior_index, prior = _previous_instruction(lines, cursor, lower_bound)
            prior_call = _parse_invoke(prior or "")
            if (prior_call and prior_call["owner"] == "Landroid/content/Intent;"
                    and prior_call["method"] in {
                        "setClass", "setClassName", "setComponent"}):
                return "explicit"
            return "unknown"

        first_operand = re.match(r"([\w/-]+)\s+([vp]\d+)(?:\s*,|$)", instruction)
        if first_operand and first_operand.group(2) == current:
            opcode = first_operand.group(1)
            if opcode == "new-instance":
                # A constructor should have been encountered first. Missing it
                # means the bounded evidence is malformed or incomplete.
                return "unknown"
            if not opcode.startswith(_NON_WRITING_OP_PREFIXES):
                return "unknown"
    return "unknown"


def analyze_pending_intents(smali_text, lookback=96):
    """Classify each PendingIntent factory invocation independently.

    Dynamic flag values are returned as ``unknown_flags`` rather than assumed
    safe. Explicitly mutable PendingIntents are distinguished by whether their
    Intent was proven component-explicit in the same bounded method slice.
    """
    lines = str(smali_text or "").splitlines()
    results = []
    for index, line in enumerate(lines):
        invocation = _parse_invoke(line)
        if not invocation or invocation["owner"] != "Landroid/app/PendingIntent;":
            continue
        if invocation["method"] not in _PENDING_METHODS:
            continue
        params = invocation["parameters"]
        if len(params) < 4 or params[1] != "I" or params[3] != "I":
            continue
        flag_register = _argument_register(invocation, 3)
        intent_register = _argument_register(invocation, 2)
        lower = _method_lower_bound(lines, index, lookback)
        flag_value = _resolve_int_constant(lines, index, flag_register, lower)
        intent_kind = _intent_explicitness(
            lines, index, intent_register, lower
        ) if intent_register else "unknown"

        if flag_value is None:
            status = "unknown_flags"
        else:
            immutable = bool(flag_value & PENDING_INTENT_FLAG_IMMUTABLE)
            mutable = bool(flag_value & PENDING_INTENT_FLAG_MUTABLE)
            if immutable and mutable:
                status = "conflicting_mutability"
            elif immutable:
                status = "immutable"
            elif mutable and intent_kind == "explicit":
                status = "mutable_explicit"
            elif mutable and intent_kind == "implicit":
                status = "mutable_implicit"
            elif mutable:
                status = "mutable_unknown_intent"
            else:
                status = "missing_mutability"
        results.append({
            "line": index + 1,
            "method": invocation["method"],
            "status": status,
            "flags": flag_value,
            "intent": intent_kind,
        })
    return results


def _resolve_string_constant(lines, before_index, register, lower_bound):
    current = register
    for cursor in range(before_index - 1, lower_bound - 1, -1):
        instruction = lines[cursor].split("#", 1)[0].strip()
        if _is_control_flow_boundary(instruction):
            return None
        if not instruction or instruction.startswith("."):
            continue
        field = re.match(
            r"sget-object\s+([vp]\d+)\s*,\s*"
            r"Landroid/content/ClipDescription;->EXTRA_IS_SENSITIVE:"
            r"Ljava/lang/String;$",
            instruction,
        )
        if field and field.group(1) == current:
            return CLIPBOARD_SENSITIVE_KEY
        constant = re.match(
            r'const-string(?:/jumbo)?\s+([vp]\d+)\s*,\s*"([^"\\]*(?:\\.[^"\\]*)*)"$',
            instruction,
        )
        if constant and constant.group(1) == current:
            raw = constant.group(2)
            return raw.replace(r"\u002e", ".").replace(r"\u002E", ".")
        move = re.match(
            r"move-object(?:/\w+)?\s+([vp]\d+)\s*,\s*([vp]\d+)$",
            instruction,
        )
        if move and move.group(1) == current:
            current = move.group(2)
            continue
        first_operand = re.match(r"([\w/-]+)\s+([vp]\d+)(?:\s*,|$)", instruction)
        if first_operand and first_operand.group(2) == current:
            if not first_operand.group(1).startswith(_NON_WRITING_OP_PREFIXES):
                return None
    return None


def _description_belongs_to_clip(lines, set_extras_index, description_register,
                                 clip_register, lower_bound):
    for cursor in range(set_extras_index - 1, lower_bound - 1, -1):
        instruction = lines[cursor].split("#", 1)[0].strip()
        if _is_control_flow_boundary(instruction):
            return False
        if instruction == f"move-result-object {description_register}":
            _prior_index, prior = _previous_instruction(lines, cursor, lower_bound)
            call = _parse_invoke(prior or "")
            return bool(
                call and call["owner"] == "Landroid/content/ClipData;"
                and call["method"] == "getDescription"
                and call["registers"] and call["registers"][0] == clip_register
            )
        if _instruction_writes_register(instruction, description_register):
            return False
    return False


def _bundle_sets_sensitive(lines, set_extras_index, bundle_register, lower_bound):
    for cursor in range(set_extras_index - 1, lower_bound - 1, -1):
        instruction = lines[cursor].split("#", 1)[0].strip()
        if _is_control_flow_boundary(instruction):
            return False
        if _instruction_writes_register(instruction, bundle_register):
            return False
        call = _parse_invoke(lines[cursor])
        if not call or call["method"] != "putBoolean":
            continue
        if call["owner"] not in (
                "Landroid/os/PersistableBundle;", "Landroid/os/BaseBundle;"):
            continue
        regs = call["registers"]
        if len(regs) < 3 or regs[0] != bundle_register:
            continue
        key = _resolve_string_constant(lines, cursor, regs[1], lower_bound)
        enabled = _resolve_int_constant(lines, cursor, regs[2], lower_bound)
        if key == CLIPBOARD_SENSITIVE_KEY:
            # Scanning backwards means this is the nearest write to the key;
            # a later false must override an earlier true.
            return enabled == 1
        if key is None:
            # A dynamic key could overwrite the sensitive marker. Without a
            # CFG/value proof, do not walk past it and fabricate protection.
            return False
    return False


def _clipboard_write_is_sensitive(lines, write_index, clip_register, lower_bound):
    for cursor in range(write_index - 1, lower_bound - 1, -1):
        instruction = lines[cursor].split("#", 1)[0].strip()
        if _is_control_flow_boundary(instruction):
            return False
        if _instruction_writes_register(instruction, clip_register):
            return False
        call = _parse_invoke(lines[cursor])
        if (not call or call["owner"] != "Landroid/content/ClipDescription;"
                or call["method"] != "setExtras"):
            continue
        regs = call["registers"]
        if len(regs) < 2:
            continue
        if not _description_belongs_to_clip(
                lines, cursor, regs[0], clip_register, lower_bound):
            continue
        # The nearest setExtras applied to this ClipData wins. Do not search
        # through an unprotected replacement to find stale older evidence.
        return _bundle_sets_sensitive(lines, cursor, regs[1], lower_bound)
    return False


def analyze_clipboard_writes(smali_text, lookback=160):
    """Return only ClipboardManager writes and their proven sensitivity mark."""
    lines = str(smali_text or "").splitlines()
    writes = []
    for index, line in enumerate(lines):
        call = _parse_invoke(line)
        if (not call or call["owner"] != "Landroid/content/ClipboardManager;"
                or call["method"] != "setPrimaryClip"):
            continue
        clip_register = _argument_register(call, 0)
        lower = _method_lower_bound(lines, index, lookback)
        writes.append({
            "line": index + 1,
            "sensitive": bool(clip_register and _clipboard_write_is_sensitive(
                lines, index, clip_register, lower
            )),
        })
    return writes


_WEBVIEW_BOOL_SETTINGS = {
    ("Landroid/webkit/WebSettings;", "setAllowFileAccess"): "file_access",
    ("Landroid/webkit/WebSettings;", "setAllowFileAccessFromFileURLs"): (
        "file_url_access"
    ),
    ("Landroid/webkit/WebSettings;", "setAllowUniversalAccessFromFileURLs"): (
        "universal_file_access"
    ),
    ("Landroid/webkit/WebView;", "setWebContentsDebuggingEnabled"): "debugging",
}
_WEBVIEW_HIGH_SETTINGS = {
    "file_url_access", "universal_file_access", "debugging",
}
# WebSettings.MIXED_CONTENT_ALWAYS_ALLOW is 0. Compatibility mode (2) still
# permits mixed content and is reported with the always-allow finding.
_MIXED_CONTENT_RISKY = {0, 2}
_BROADCAST_METHODS = {"sendBroadcast", "sendBroadcastAsUser"}
_BACKUP_DOMAINS = ("sharedpref", "database", "file", "root")
_BACKUP_LEVEL_ORDER = ("open", "databases_excluded", "private_excluded")


def analyze_webview_settings(smali_text, lookback=64):
    """Classify WebView setting calls whose argument can be proven.

    ``state`` is ``enabled``, ``disabled``, or ``unknown``. Only ``enabled``
    is a finding. A non-constant argument is unknown rather than assumed safe
    or unsafe.
    """
    lines = str(smali_text or "").splitlines()
    results = []
    for index, line in enumerate(lines):
        call = _parse_invoke(line)
        if not call:
            continue
        setting = _WEBVIEW_BOOL_SETTINGS.get((call["owner"], call["method"]))
        if setting is not None and call["parameters"] == ["Z"]:
            register = _argument_register(call, 0)
            lower = _method_lower_bound(lines, index, lookback)
            value = _resolve_int_constant(lines, index, register, lower)
            if value == 1:
                state = "enabled"
            elif value == 0:
                state = "disabled"
            else:
                state = "unknown"
            results.append({
                "line": index + 1,
                "setting": setting,
                "state": state,
            })
            continue
        if (call["owner"] == "Landroid/webkit/WebSettings;"
                and call["method"] == "setMixedContentMode"
                and call["parameters"] == ["I"]):
            register = _argument_register(call, 0)
            lower = _method_lower_bound(lines, index, lookback)
            value = _resolve_int_constant(lines, index, register, lower)
            if value in _MIXED_CONTENT_RISKY:
                state = "enabled"
            elif value == 1:
                state = "disabled"
            else:
                state = "unknown"
            results.append({
                "line": index + 1,
                "setting": "mixed_content",
                "state": state,
                "mode": value,
            })
    return results


def webview_setting_severity(settings):
    """Return HIGH when a proven WebView call is a bridge or debugger switch."""
    enabled = {item["setting"] for item in settings if item["state"] == "enabled"}
    if enabled & _WEBVIEW_HIGH_SETTINGS:
        return "HIGH"
    if enabled:
        return "MEDIUM"
    return None


def analyze_broadcast_sends(smali_text):
    """Classify each Context.sendBroadcast call, not the whole file.

    A String permission parameter counts as protected. LocalBroadcastManager
    sends are in-process and are ignored. The receiver class in smali is often
    the app Activity, so the method descriptor is matched instead of Context.
    """
    lines = str(smali_text or "").splitlines()
    results = []
    for index, line in enumerate(lines):
        call = _parse_invoke(line)
        if not call or call["method"] not in _BROADCAST_METHODS:
            continue
        if "LocalBroadcastManager" in call["owner"]:
            continue
        parameters = call["parameters"]
        if not parameters or parameters[0] != "Landroid/content/Intent;":
            continue
        results.append({
            "line": index + 1,
            "method": call["method"],
            "protected": "Ljava/lang/String;" in parameters,
        })
    return results


def _whole_backup_domain(path):
    return (path or ".").strip() in {".", "", "/", "*", "./"}


def _backup_rules(parent):
    """Return include/exclude rows, or None when the section is absent."""
    if parent is None:
        return None
    rules = []
    for child in list(parent):
        tag = child.tag.split("}")[-1]
        if tag not in ("include", "exclude"):
            continue
        rules.append({
            "op": tag,
            "domain": (child.get("domain") or "").strip().lower(),
            "path": child.get("path"),
        })
    return rules


def _domain_is_backed_up(rules, domain):
    includes = [
        rule for rule in rules
        if rule["op"] == "include" and rule["domain"] == domain
    ]
    excludes = [
        rule for rule in rules
        if rule["op"] == "exclude" and rule["domain"] == domain
    ]
    full_exclude = any(_whole_backup_domain(rule["path"]) for rule in excludes)
    if any(rule["op"] == "include" for rule in rules):
        if not includes or full_exclude:
            return False
        return True
    return not full_exclude


def classify_backup_rules(rules):
    """Return how much private data a rule list still backs up.

    ``open`` means shared preferences or databases can be included.
    ``databases_excluded`` still allows files or the app root.
    ``private_excluded`` excludes shared preferences, databases, files, and root.
    """
    if rules is None:
        return None
    backed = {
        domain: _domain_is_backed_up(rules, domain)
        for domain in _BACKUP_DOMAINS
    }
    if backed["sharedpref"] or backed["database"]:
        return "open"
    if backed["file"] or backed["root"]:
        return "databases_excluded"
    return "private_excluded"


def _worst_backup_level(levels):
    present = [level for level in levels if level]
    if not present:
        return "open"
    return min(present, key=_BACKUP_LEVEL_ORDER.index)


def classify_backup_xml(root):
    """Classify one full-backup or data-extraction document.

    Returns ``full`` and/or ``extraction`` levels. A missing device-transfer
    section inherits cloud-backup, and the reverse. An empty present section
    does not inherit: it backs up everything.
    """
    if root is None:
        return None
    tag = root.tag.split("}")[-1]
    if tag == "full-backup-content":
        return {"full": classify_backup_rules(_backup_rules(root))}
    if tag != "data-extraction-rules":
        return None
    cloud = root.find("cloud-backup")
    device = root.find("device-transfer")
    cloud_rules = _backup_rules(cloud)
    device_rules = _backup_rules(device)
    if cloud_rules is None and device_rules is not None:
        cloud_rules = device_rules
    elif device_rules is None and cloud_rules is not None:
        device_rules = cloud_rules
    elif cloud_rules is None and device_rules is None:
        return {"extraction": "open"}
    return {
        "extraction": _worst_backup_level((
            classify_backup_rules(cloud_rules),
            classify_backup_rules(device_rules),
        )),
    }


def combine_backup_policy(min_level, target_level, full_level, extraction_level,
                          full_broken=False, extraction_broken=False):
    """Combine pre-31 full-backup rules with API 31+ extraction rules.

    A missing document for an applicable API range is unrestricted. An
    unreadable referenced document is ``unknown`` so the caller does not
    treat it as a proven exclusion.
    """
    needs_full = min_level is None or min_level < 31
    needs_extraction = target_level is None or target_level >= 31
    if needs_full and full_broken:
        return "unknown"
    if needs_extraction and extraction_broken:
        return "unknown"
    levels = []
    if needs_full:
        levels.append(full_level or "open")
    if needs_extraction:
        levels.append(extraction_level or "open")
    return _worst_backup_level(levels)


# Markers are case-sensitive smali/XML substrings. Class references use the
# ``;``, ``->``, and ``$`` forms so a longer type (CameraProfile,
# AudioRecordingConfiguration) does not match. Keep SMS and storage markers
# disjoint: one call must not mark a sibling permission as used.
_ACTION_CALL_RE = re.compile(
    r"android\.intent\.action\.CALL(?![A-Za-z0-9_])"
)
_ACTION_INSTALL_PACKAGE_RE = re.compile(
    r"android\.intent\.action\.INSTALL_PACKAGE(?![A-Za-z0-9_])"
)
_ACTION_NEW_OUTGOING_CALL_RE = re.compile(
    r"android\.intent\.action\.NEW_OUTGOING_CALL(?![A-Za-z0-9_])"
)
_SMS_RECEIVED_ACTION_RE = re.compile(
    r"android\.provider\.Telephony\.SMS_RECEIVED(?![A-Za-z0-9_])"
)

PERMISSION_API_RULES = (
    {
        # Background location has no distinct platform call. A foreground
        # location API counts as use, so the background permission is not
        # reported unused when those calls are present.
        "id": "location",
        "label": "location",
        "permissions": (
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
        ),
        "markers": (
            "Landroid/location/LocationManager;->getLastKnownLocation(",
            "Landroid/location/LocationManager;->requestLocationUpdates(",
            "Landroid/location/LocationManager;->requestSingleUpdate(",
            "Landroid/location/LocationManager;->getCurrentLocation(",
            "Lcom/google/android/gms/location/FusedLocationProviderClient;",
            "Lcom/google/android/gms/location/FusedLocationProviderClient;->",
            "Lcom/google/android/gms/location/FusedLocationProviderClient$",
        ),
    },
    {
        "id": "phone_state",
        "label": "phone state",
        "permissions": ("android.permission.READ_PHONE_STATE",),
        "markers": (
            "Landroid/telephony/TelephonyManager;",
            "Landroid/telephony/TelephonyManager;->",
            "Landroid/telephony/TelephonyManager$",
        ),
    },
    {
        "id": "camera",
        "label": "camera",
        "permissions": ("android.permission.CAMERA",),
        "markers": (
            "Landroid/hardware/Camera;",
            "Landroid/hardware/Camera;->",
            "Landroid/hardware/Camera$",
            "Landroid/hardware/camera2/",
        ),
    },
    {
        "id": "contacts",
        "label": "contacts",
        "permissions": (
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
        ),
        "markers": (
            "Landroid/provider/ContactsContract;",
            "Landroid/provider/ContactsContract;->",
            "Landroid/provider/ContactsContract$",
        ),
    },
    {
        # Telephony$Sms$Intents is the receive path and must not satisfy
        # READ_SMS. Send methods are likewise not reads or receives.
        "id": "sms_read",
        "label": "SMS reading",
        "permissions": ("android.permission.READ_SMS",),
        "markers": (
            "Landroid/provider/Telephony$Sms;->",
            "Landroid/provider/Telephony$Sms;",
            "Landroid/provider/Telephony$Sms$Inbox",
            "Landroid/provider/Telephony$Sms$Sent",
            "Landroid/provider/Telephony$Sms$Draft",
            "Landroid/provider/Telephony$Sms$Outbox",
            "Landroid/provider/Telephony$Sms$Conversations",
        ),
    },
    {
        "id": "sms_receive",
        "label": "SMS receiving",
        "permissions": ("android.permission.RECEIVE_SMS",),
        "markers": (
            "Landroid/provider/Telephony$Sms$Intents;->SMS_RECEIVED_ACTION",
            "Landroid/telephony/SmsMessage;->createFromPdu(",
            "Landroid/telephony/gsm/SmsMessage;->createFromPdu(",
        ),
        "patterns": (_SMS_RECEIVED_ACTION_RE,),
    },
    {
        "id": "sms_send",
        "label": "SMS sending",
        "permissions": ("android.permission.SEND_SMS",),
        "markers": (
            "Landroid/telephony/SmsManager;->sendTextMessage(",
            "Landroid/telephony/SmsManager;->sendMultipartTextMessage(",
            "Landroid/telephony/SmsManager;->sendDataMessage(",
            "Landroid/telephony/gsm/SmsManager;->sendTextMessage(",
            "Landroid/telephony/gsm/SmsManager;->sendMultipartTextMessage(",
            "Landroid/telephony/gsm/SmsManager;->sendDataMessage(",
        ),
    },
    {
        "id": "record_audio",
        "label": "audio recording",
        "permissions": ("android.permission.RECORD_AUDIO",),
        "markers": (
            "Landroid/media/AudioRecord;",
            "Landroid/media/AudioRecord;->",
            "Landroid/media/AudioRecord$",
            "Landroid/media/MediaRecorder;->setAudioSource(",
            "Landroid/speech/SpeechRecognizer;",
            "Landroid/speech/SpeechRecognizer;->",
            "Landroid/speech/SpeechRecognizer$",
        ),
    },
    {
        # READ_EXTERNAL_STORAGE still covers media on older targets.
        "id": "media_images",
        "label": "image media",
        "permissions": (
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.READ_EXTERNAL_STORAGE",
        ),
        "markers": (
            "Landroid/provider/MediaStore$Images;",
            "Landroid/provider/MediaStore$Images$",
        ),
    },
    {
        "id": "media_video",
        "label": "video media",
        "permissions": (
            "android.permission.READ_MEDIA_VIDEO",
            "android.permission.READ_EXTERNAL_STORAGE",
        ),
        "markers": (
            "Landroid/provider/MediaStore$Video;",
            "Landroid/provider/MediaStore$Video$",
        ),
    },
    {
        "id": "media_audio",
        "label": "audio media",
        "permissions": (
            "android.permission.READ_MEDIA_AUDIO",
            "android.permission.READ_EXTERNAL_STORAGE",
        ),
        "markers": (
            "Landroid/provider/MediaStore$Audio;",
            "Landroid/provider/MediaStore$Audio$",
        ),
    },
    {
        # Directory APIs are covered by read, write, or all-files access.
        # isExternalStorageManager stays on the manage-only rule below.
        "id": "external_storage",
        "label": "external storage",
        "permissions": (
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.MANAGE_EXTERNAL_STORAGE",
        ),
        "markers": (
            "Landroid/os/Environment;->getExternalStorageDirectory(",
            "Landroid/os/Environment;->getExternalStoragePublicDirectory(",
        ),
    },
    {
        "id": "install_packages",
        "label": "package installation",
        "permissions": ("android.permission.REQUEST_INSTALL_PACKAGES",),
        "markers": (
            "Landroid/content/pm/PackageInstaller;",
            "Landroid/content/pm/PackageInstaller;->",
            "Landroid/content/pm/PackageInstaller$",
            "Landroid/content/Intent;->ACTION_INSTALL_PACKAGE:",
        ),
        "patterns": (_ACTION_INSTALL_PACKAGE_RE,),
    },
    {
        "id": "system_alert",
        "label": "system overlay",
        "permissions": ("android.permission.SYSTEM_ALERT_WINDOW",),
        "markers": (
            "Landroid/view/WindowManager$LayoutParams;->TYPE_APPLICATION_OVERLAY:",
            "Landroid/view/WindowManager$LayoutParams;->TYPE_SYSTEM_ALERT:",
            "Landroid/provider/Settings;->canDrawOverlays(",
        ),
    },
    {
        "id": "call_phone",
        "label": "phone calls",
        "permissions": ("android.permission.CALL_PHONE",),
        "markers": ("Landroid/content/Intent;->ACTION_CALL:",),
        "patterns": (_ACTION_CALL_RE,),
    },
    {
        "id": "call_log",
        "label": "call log",
        "permissions": (
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
        ),
        "markers": (
            "Landroid/provider/CallLog;",
            "Landroid/provider/CallLog;->",
            "Landroid/provider/CallLog$",
        ),
    },
    {
        "id": "outgoing_calls",
        "label": "outgoing calls",
        "permissions": ("android.permission.PROCESS_OUTGOING_CALLS",),
        "markers": ("Landroid/content/Intent;->ACTION_NEW_OUTGOING_CALL:",),
        "patterns": (_ACTION_NEW_OUTGOING_CALL_RE,),
    },
    {
        "id": "calendar",
        "label": "calendar",
        "permissions": (
            "android.permission.READ_CALENDAR",
            "android.permission.WRITE_CALENDAR",
        ),
        "markers": (
            "Landroid/provider/CalendarContract;",
            "Landroid/provider/CalendarContract;->",
            "Landroid/provider/CalendarContract$",
        ),
    },
    {
        # TYPE_HEART_RATE only. SensorManager itself is not body-sensor use.
        "id": "body_sensors",
        "label": "body sensors",
        "permissions": ("android.permission.BODY_SENSORS",),
        "markers": ("Landroid/hardware/Sensor;->TYPE_HEART_RATE:",),
    },
    {
        "id": "manage_storage",
        "label": "all-files access",
        "permissions": ("android.permission.MANAGE_EXTERNAL_STORAGE",),
        "markers": (
            "Landroid/os/Environment;->isExternalStorageManager(",
            "android.settings.MANAGE_APP_ALL_FILES_ACCESS_PERMISSION",
            "Landroid/provider/Settings;->ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION",
        ),
    },
    {
        "id": "nearby_wifi",
        "label": "nearby Wi-Fi",
        "permissions": ("android.permission.NEARBY_WIFI_DEVICES",),
        "min_target": 33,
        "markers": (
            "Landroid/net/wifi/aware/",
            "Landroid/net/wifi/rtt/",
            "Landroid/net/wifi/p2p/",
            "Landroid/net/wifi/WifiNetworkSpecifier;",
            "Landroid/net/wifi/WifiNetworkSpecifier;->",
            "Landroid/net/wifi/WifiNetworkSpecifier$",
        ),
    },
    {
        "id": "post_notifications",
        "label": "notification posting",
        "permissions": ("android.permission.POST_NOTIFICATIONS",),
        "min_target": 33,
        "markers": (
            "Landroid/app/NotificationManager;->notify(",
            "Landroid/app/NotificationManager;->notifyAsPackage(",
            "Landroid/app/NotificationManager;->notifyAsUser(",
            "Landroidx/core/app/NotificationManagerCompat;->notify(",
        ),
    },
)


def _permission_text_matches(rule, text):
    """Return whether one mapped API marker appears in *text*."""
    for marker in rule["markers"]:
        if marker in text:
            return True
    for pattern in rule.get("patterns", ()):
        if pattern.search(text):
            return True
    return False


def match_permission_apis(text):
    """Return rule ids whose mapped platform API appears in *text*.

    The match is a substring/regex scan of one smali or XML document, not a
    proof that the call is reachable.
    """
    if not isinstance(text, str) or not text:
        return []
    return [
        rule["id"] for rule in PERMISSION_API_RULES
        if _permission_text_matches(rule, text)
    ]


def _permission_names(values):
    """Return a set of permission or rule-id strings."""
    if values is None:
        return set()
    if isinstance(values, str):
        values = (values,)
    names = set()
    for item in values:
        text = str(item).strip()
        if text:
            names.add(text)
    return names


def _permission_api_required(rule, target_level):
    """Return whether a missing declaration of *rule* is meaningful.

    Permissions added in API 33 are not required when targetSdk is known and
    lower. An unknown target fails closed and still requires them.
    """
    minimum = rule.get("min_target")
    if minimum is None:
        return True
    if target_level is None:
        return True
    try:
        level = int(target_level)
    except (TypeError, ValueError):
        return True
    return level >= int(minimum)


def correlate_permission_apis(declared_permissions, matched_rule_ids,
                              code_coverage_complete,
                              split_manifest_coverage_complete,
                              target_level=None):
    """Pair dangerous permissions with mapped platform APIs.

    ``unused_permissions`` is an absence claim: it stays empty unless
    smali/XML coverage is complete. ``missing_rules`` is positive evidence
    of an API, but it stays empty when split-manifest coverage is incomplete
    because the permission may exist only in a split that was not merged.
    Callers still withhold a clean pass when the other coverage axis is
    incomplete.

    POST_NOTIFICATIONS and NEARBY_WIFI_DEVICES produce a missing-permission
    result only when targetSdk is unknown or at least 33. A declaration with
    no mapped API is still reported as unused at any target. Dangerous
    permissions that have no rule are never called unused.
    """
    declared = _permission_names(declared_permissions)
    matched = _permission_names(matched_rule_ids)
    rules_for_permission = {}
    for rule in PERMISSION_API_RULES:
        for permission in rule["permissions"]:
            rules_for_permission.setdefault(permission, []).append(rule)

    unmatched = []
    for permission in sorted(rules_for_permission):
        if permission not in declared:
            continue
        covering = rules_for_permission[permission]
        if any(rule["id"] in matched for rule in covering):
            continue
        unmatched.append(permission)

    candidate_rules = []
    for rule in PERMISSION_API_RULES:
        if rule["id"] not in matched:
            continue
        if any(permission in declared for permission in rule["permissions"]):
            continue
        if not _permission_api_required(rule, target_level):
            continue
        candidate_rules.append({
            "id": rule["id"],
            "label": rule["label"],
            "permissions": rule["permissions"],
        })

    code_complete = bool(code_coverage_complete)
    split_complete = bool(split_manifest_coverage_complete)
    return {
        "unused_permissions": list(unmatched) if code_complete else [],
        "unmatched_permissions": list(unmatched),
        "missing_rules": list(candidate_rules) if split_complete else [],
        "uncovered_rules": [] if split_complete else list(candidate_rules),
        "unused_inconclusive": (not code_complete) and bool(unmatched),
        "missing_inconclusive": (
            (not split_complete) and bool(candidate_rules)
        ),
    }


def classify_deep_link(link):
    """Classify one externally reachable deep-link intent filter.

    A constrained, auto-verified HTTPS App Link is informational. Custom
    schemes, unverified web links, HTTP, unresolved/wildcard hosts, and
    unconstrained web paths retain a security finding.
    """
    schemes = [str(value).strip().lower()
               for value in link.get("schemes", []) if str(value).strip()]
    hosts = [str(value).strip().lower()
             for value in link.get("hosts", []) if str(value).strip()]
    paths = list(link.get("paths", []))
    auto_verify = link.get("auto_verify") is True
    reasons = []

    resource_schemes = [scheme for scheme in schemes if scheme.startswith("@")]
    custom = [
        scheme for scheme in schemes
        if scheme not in ("http", "https") and not scheme.startswith("@")
    ]
    web = [scheme for scheme in schemes if scheme in ("http", "https")]
    if custom:
        reasons.append("custom URI schemes can be claimed by another app")
    if resource_schemes:
        reasons.append("resource-valued scheme could not be resolved")
    if web:
        min_sdk = str(link.get("min_sdk", ""))
        min_level = parse_sdk_level(min_sdk)
        if min_level is not None and min_level < 23:
            reasons.append(
                "supported Android versions before API 23 do not enforce App Link verification"
            )
        if "http" in web:
            reasons.append("unencrypted HTTP scheme is accepted")
        if not auto_verify:
            reasons.append("HTTP(S) link is not auto-verified")
        if not hosts:
            reasons.append("HTTP(S) filter has no host constraint")
        elif any(host.startswith("@") or "*" in host for host in hosts):
            reasons.append("HTTP(S) host is wildcarded or unresolved")
        if not paths:
            reasons.append("HTTP(S) filter accepts every path")
        else:
            for path in paths:
                kind = str(path.get("kind", "")) if isinstance(path, dict) else ""
                value = str(path.get("value", "")) if isinstance(path, dict) else str(path)
                if value.startswith("@"):
                    reasons.append("HTTP(S) path constraint is unresolved")
                    break
                broad_path = (
                    not value
                    or (kind == "pathPrefix" and value == "/")
                    or (kind in ("pathPattern", "pathAdvancedPattern")
                        and value in ("*", ".*", "/.*"))
                )
                if broad_path:
                    reasons.append("HTTP(S) path constraint is effectively broad")
                    break
    elif not custom:
        reasons.append("URI scheme could not be determined")

    return {
        "risk": bool(reasons),
        "level": "finding" if reasons else "info",
        "reasons": reasons,
    }
