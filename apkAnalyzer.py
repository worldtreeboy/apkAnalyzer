#!/usr/bin/env python3
"""
APK Analyzer - Android Security Analysis Tool
Root-based ADB tool for app analysis, storage auditing,
shell access, screenshots, and security scanning.
"""

import subprocess
import sys
import os
import hashlib
import posixpath
import re
import time
import shlex
import shutil
import lzma
import zlib
import tarfile
import tempfile
import json
import argparse
import html as html_mod
import urllib.request
import urllib.parse
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


def _configure_windows_streams():
    """Prevent Unicode UI output from crashing under legacy Windows code pages."""
    if os.name != "nt":
        return
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass


_configure_windows_streams()

# ─── ANSI Colors ────────────────────────────────────────────────────────────────

class C:
    RST   = "\033[0m"
    BOLD  = "\033[1m"
    DIM   = "\033[2m"
    RED   = "\033[91m"
    GREEN = "\033[92m"
    YELLOW= "\033[93m"
    BLUE  = "\033[94m"
    MAGENTA="\033[95m"
    CYAN  = "\033[96m"
    WHITE = "\033[97m"
    BG_RED   = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_BLUE  = "\033[44m"
    BG_MAG   = "\033[45m"
    BG_CYAN  = "\033[46m"

# ─── Report Collector ────────────────────────────────────────────────────────────

TOOL_VERSION = "1.6.0"

MAX_XML_BYTES = 10 * 1024 * 1024
MAX_BACKUP_BYTES = 512 * 1024 * 1024
MAX_BACKUP_PAYLOAD_BYTES = 1024 * 1024 * 1024
MAX_BACKUP_FILE_BYTES = 128 * 1024 * 1024
MAX_BACKUP_FILES = 100_000


def _now_iso():
    """Return an unambiguous UTC timestamp for reports and findings."""
    return datetime.now(timezone.utc).isoformat()


def _terminal_safe(value):
    """Strip terminal control sequences from untrusted device/app output."""
    text = str(value)
    # CSI and OSC sequences can rewrite the terminal or clipboard (OSC 52).
    text = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", "", text)
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = text.replace("\x1b", "")
    return "".join(ch for ch in text if ch in "\n\r\t" or ord(ch) >= 32)


def _redact(value, visible=4):
    """Mask a sensitive value while leaving enough context to identify it."""
    text = _terminal_safe(value).strip()
    if not text:
        return ""
    # When the value itself is a scanner match, preserve its key/formatting but
    # never expose fragments of the matched credential.  The helper is defined
    # later in the module, so use a guarded lookup during module initialization.
    secret_redactor = globals().get("_redact_secret_text")
    if secret_redactor is not None:
        redacted = secret_redactor(text)
        if redacted != text:
            return redacted
    # Keep a useful key/label visible for key=value style findings.
    match = re.match(r"(?s)(.*?\s*[=:]\s*)(.*)", text)
    if match:
        prefix, secret = match.groups()
        return prefix + ("[REDACTED]" if secret else "")
    if len(text) <= visible * 2:
        return "*" * len(text)
    return f"{text[:visible]}…{text[-visible:]}"


def _safe_parse_xml(path, max_bytes=MAX_XML_BYTES):
    """Parse an untrusted XML file with size and DTD/entity protections."""
    size = os.path.getsize(path)
    if size > max_bytes:
        raise ValueError(f"XML file exceeds {max_bytes} byte safety limit")
    with open(path, "rb") as fh:
        data = fh.read(max_bytes + 1)
    upper = data.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ValueError("DTD/entity declarations are not allowed")
    # ElementTree is safe here because DTD/entities are rejected and input is bounded.
    return ET.ElementTree(ET.fromstring(data))  # nosec B314


_PACKAGE_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$"
)


def _is_valid_package(package):
    """Return whether *package* is a safe Android application identifier."""
    return bool(_PACKAGE_RE.fullmatch(package or ""))

class ReportCollector:
    """Accumulates findings throughout the session for JSON/HTML export."""

    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    def __init__(self):
        self.device_info = {}
        self.target_app = ""
        self.findings = []
        self.app_info = {}
        self.timestamp = _now_iso()

    def add_finding(self, category, title, severity, confidence, description,
                    remediation="", masvs="", cwe=""):
        # Skip exact duplicates (same category/title/description) so re-running
        # a scan doesn't record the same finding twice
        for f in self.findings:
            if (f["category"] == category and f["title"] == title
                    and f["description"] == description):
                return
        self.findings.append({
            "category": category,
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "description": description,
            "remediation": remediation,
            "masvs": masvs,
            "cwe": cwe,
            "timestamp": _now_iso(),
        })

    def _build_report_dict(self):
        sorted_findings = sorted(
            self.findings,
            key=lambda f: self.SEVERITY_ORDER.get(f["severity"], 99)
        )
        return {
            "tool": "APK Analyzer",
            "version": TOOL_VERSION,
            "generated_at": _now_iso(),
            "device_info": self.device_info,
            "target_app": self.target_app,
            "app_info": self.app_info,
            "summary": {
                "total": len(sorted_findings),
                "critical": sum(1 for f in sorted_findings if f["severity"] == "CRITICAL"),
                "high": sum(1 for f in sorted_findings if f["severity"] == "HIGH"),
                "medium": sum(1 for f in sorted_findings if f["severity"] == "MEDIUM"),
                "low": sum(1 for f in sorted_findings if f["severity"] == "LOW"),
                "info": sum(1 for f in sorted_findings if f["severity"] == "INFO"),
            },
            "findings": sorted_findings,
        }

    def export_json(self, path):
        data = self._build_report_dict()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def export_html(self, path):
        data = self._build_report_dict()
        sev_colors = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#0d6efd",
            "INFO": "#6c757d",
        }
        sev_text_colors = {
            "CRITICAL": "#fff",
            "HIGH": "#fff",
            "MEDIUM": "#212529",
            "LOW": "#fff",
            "INFO": "#fff",
        }

        findings_rows = []
        for i, f in enumerate(data["findings"], 1):
            bg = sev_colors.get(f["severity"], "#6c757d")
            fg = sev_text_colors.get(f["severity"], "#fff")
            esc = html_mod.escape
            remediation_cell = esc(f["remediation"]) if f["remediation"] else "&mdash;"
            ref_parts = []
            if f["masvs"]:
                ref_parts.append(esc(f["masvs"]))
            if f["cwe"]:
                ref_parts.append(esc(f["cwe"]))
            ref_cell = ", ".join(ref_parts) if ref_parts else "&mdash;"
            findings_rows.append(
                f'<tr>'
                f'<td>{i}</td>'
                f'<td><span class="badge" style="background:{bg};color:{fg};">{esc(str(f.get("severity", "")))}</span></td>'
                f'<td>{esc(str(f.get("category", "")))}</td>'
                f'<td><strong>{esc(str(f.get("title", "")))}</strong></td>'
                f'<td>{esc(str(f.get("confidence", "")))}</td>'
                f'<td>{esc(str(f.get("description", "")))}</td>'
                f'<td>{remediation_cell}</td>'
                f'<td class="ref">{ref_cell}</td>'
                f'</tr>'
            )
        rows_html = "\n".join(findings_rows)

        dev = data["device_info"]
        dev_model = html_mod.escape(dev.get("model", "N/A"))
        dev_android = html_mod.escape(dev.get("android", "N/A"))
        dev_sdk = html_mod.escape(dev.get("sdk", "N/A"))
        dev_serial = html_mod.escape(dev.get("serial", "N/A"))
        app_name = html_mod.escape(data["target_app"] or "N/A")
        app_ver = html_mod.escape(data["app_info"].get("version", "N/A"))
        app_target_sdk = html_mod.escape(str(data["app_info"].get("target_sdk", "N/A")))
        app_min_sdk = html_mod.escape(str(data["app_info"].get("min_sdk", "N/A")))
        s = data["summary"]

        page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>APK Analyzer Report &mdash; {app_name}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #f8f9fa; color: #212529; padding: 2rem; line-height: 1.5; }}
  .container {{ max-width: 1200px; margin: auto; }}
  h1 {{ font-size: 1.8rem; margin-bottom: .25rem; }}
  .subtitle {{ color: #6c757d; margin-bottom: 1.5rem; font-size: .9rem; }}
  .card {{ background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.1);
           padding: 1.25rem; margin-bottom: 1.25rem; }}
  .card h2 {{ font-size: 1.1rem; margin-bottom: .75rem; border-bottom: 1px solid #dee2e6;
              padding-bottom: .5rem; }}
  .info-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
                gap: .5rem; }}
  .info-grid dt {{ font-weight: 600; color: #495057; font-size: .85rem; }}
  .info-grid dd {{ margin-bottom: .5rem; }}
  .summary-badges {{ display: flex; gap: .75rem; flex-wrap: wrap; }}
  .summary-badges .sb {{ padding: .4rem .9rem; border-radius: 6px; color: #fff;
                         font-weight: 600; font-size: .95rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
  th, td {{ padding: .6rem .75rem; border-bottom: 1px solid #dee2e6; text-align: left;
            vertical-align: top; }}
  th {{ background: #e9ecef; position: sticky; top: 0; }}
  tr:hover {{ background: #f1f3f5; }}
  .badge {{ display: inline-block; padding: .2rem .55rem; border-radius: 4px;
            font-size: .75rem; font-weight: 700; text-transform: uppercase; }}
  .ref {{ font-size: .78rem; color: #6c757d; }}
  footer {{ text-align: center; color: #adb5bd; font-size: .8rem; margin-top: 2rem; }}
</style>
</head>
<body>
<div class="container">
  <h1>APK Analyzer Report</h1>
  <p class="subtitle">Generated {html_mod.escape(data["generated_at"])} &mdash; v{html_mod.escape(TOOL_VERSION)}</p>

  <div class="card">
    <h2>Device Information</h2>
    <dl class="info-grid">
      <dt>Model</dt><dd>{dev_model}</dd>
      <dt>Android</dt><dd>{dev_android}</dd>
      <dt>SDK</dt><dd>{dev_sdk}</dd>
      <dt>Serial</dt><dd>{dev_serial}</dd>
    </dl>
  </div>

  <div class="card">
    <h2>Target Application</h2>
    <dl class="info-grid">
      <dt>Package</dt><dd>{app_name}</dd>
      <dt>Version</dt><dd>{app_ver}</dd>
      <dt>Target SDK</dt><dd>{app_target_sdk}</dd>
      <dt>Min SDK</dt><dd>{app_min_sdk}</dd>
    </dl>
  </div>

  <div class="card">
    <h2>Summary</h2>
    <div class="summary-badges">
      <span class="sb" style="background:#dc3545;">CRITICAL: {s['critical']}</span>
      <span class="sb" style="background:#fd7e14;">HIGH: {s['high']}</span>
      <span class="sb" style="background:#ffc107;color:#212529;">MEDIUM: {s['medium']}</span>
      <span class="sb" style="background:#0d6efd;">LOW: {s['low']}</span>
      <span class="sb" style="background:#6c757d;">INFO: {s['info']}</span>
      <span class="sb" style="background:#212529;">TOTAL: {s['total']}</span>
    </div>
  </div>

  <div class="card">
    <h2>Findings</h2>
    <table>
      <thead>
        <tr>
          <th>#</th><th>Severity</th><th>Category</th><th>Title</th>
          <th>Confidence</th><th>Description</th><th>Remediation</th><th>Reference</th>
        </tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
  </div>

  <footer>APK Analyzer v{html_mod.escape(TOOL_VERSION)} &mdash; github.com/worldtreeboy/apkAnalyzer</footer>
</div>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as f:
            f.write(page)

# Global singleton report collector
report = ReportCollector()

# ─── ADB Helpers ────────────────────────────────────────────────────────────────

def _run_cmd(args, timeout=30, stdin=None):
    """Run an argument-list command and return output or an error sentinel."""
    try:
        r = subprocess.run(
            args,
            stdin=subprocess.DEVNULL if stdin is None else stdin,
            capture_output=True, text=True, timeout=timeout,
            encoding='utf-8', errors='replace', check=False,
        )
        stdout = _terminal_safe(r.stdout).strip()
        stderr = _terminal_safe(r.stderr).strip()
        if r.returncode != 0:
            detail = stderr or stdout or "no diagnostic output"
            return f"[ERROR {r.returncode}] {detail}"
        return stdout
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except (OSError, ValueError) as e:
        return f"[ERROR] {e}"

def adb(cmd, timeout=30):
    """Run an adb command and return stdout.
    cmd can be a string (split by shlex) or a list of arguments."""
    if isinstance(cmd, str):
        args = _adb_base() + shlex.split(cmd)
    else:
        args = _adb_base() + list(cmd)
    return _run_cmd(args, timeout=timeout)

def adb_shell(cmd, timeout=30):
    """Run adb shell command (non-root). cmd is passed as a single shell string to the device."""
    return _run_cmd(_adb_base() + ["shell", cmd], timeout=timeout)

# Root mode: "su" = use su -c, "adbd" = adb shell already root, None = unknown
_root_mode = None

# Selected device serial when multiple devices are connected (None = adb default)
ADB_SERIAL = None

def _adb_base():
    """Base adb command, targeting the selected device when one was picked."""
    return ["adb", "-s", ADB_SERIAL] if ADB_SERIAL else ["adb"]

def _is_err(out):
    """True if a command output is empty or an error sentinel like [ERROR]/[TIMEOUT]."""
    return (not out or out == "[TIMEOUT]" or out.startswith("[ERROR"))


def _command_failed(out):
    """Return whether a command produced one of ``_run_cmd``'s failure sentinels.

    Unlike :func:`_is_err`, an empty string is not necessarily a failure: many
    successful shell probes intentionally produce no output when they find
    nothing. Runtime checks use this narrower predicate so they can distinguish
    a clean empty result from an unavailable device or failed command.
    """
    return isinstance(out, str) and (
        out == "[TIMEOUT]" or out.startswith("[ERROR")
    )


class RuntimeCheckUnavailable(RuntimeError):
    """Raised when a runtime security check cannot obtain trustworthy data."""

    def __init__(self, message, partial_findings=None):
        super().__init__(message)
        self.partial_findings = list(partial_findings or [])


def _require_runtime_command(out, operation, require_output=False,
                             partial_findings=None):
    """Validate command output or raise an explicit inconclusive-check error."""
    if _command_failed(out) or (require_output and not str(out or "").strip()):
        detail = str(out or "no output").strip()
        raise RuntimeCheckUnavailable(
            f"{operation}: {detail}", partial_findings=partial_findings
        )
    return out


def _require_app_launch(out, operation="launching target app"):
    """Reject both transport errors and monkey/am textual launch failures."""
    _require_runtime_command(out, operation, require_output=True)
    lowered = str(out or "").lower()
    failure_markers = (
        "no activities found", "monkey aborted", "unable to resolve intent",
        "activity class does not exist", "error type 3",
    )
    if any(marker in lowered for marker in failure_markers):
        raise RuntimeCheckUnavailable(f"{operation}: {str(out).strip()}")
    injected = re.search(r"Events injected:\s*(\d+)", str(out), re.IGNORECASE)
    if injected is None or int(injected.group(1)) < 1:
        raise RuntimeCheckUnavailable(
            f"{operation}: monkey did not confirm an injected launch event"
        )
    return out

def adb_su(cmd, timeout=30):
    """Run command as root, auto-detecting whether su or adbd-root is available."""
    if _root_mode == "adbd":
        return adb_shell(cmd, timeout=timeout)
    # adb joins arguments after `shell`; passing `su`, `-c`, and a compound
    # command separately makes su execute only the first token. Build one
    # remote-shell string and quote the complete command as su's -c argument.
    remote_cmd = f"su -c {shlex.quote(cmd)}"
    return _run_cmd(_adb_base() + ["shell", remote_cmd], timeout=timeout)

def adb_pull(remote, local):
    """Atomically pull a file from the device, never accepting stale output."""
    local_path = os.path.abspath(os.fspath(local))
    local_dir = os.path.dirname(local_path)
    partial = None
    try:
        fd, partial = tempfile.mkstemp(
            prefix=os.path.basename(local_path) + ".",
            suffix=".part",
            dir=local_dir,
        )
        os.close(fd)
        # Reserve a collision-resistant name, then remove the placeholder so
        # success still requires adb itself to create the pulled file.
        os.remove(partial)
        result = _run_cmd(_adb_base() + ["pull", remote, partial], timeout=120)
        failed = result == "[TIMEOUT]" or result.startswith("[ERROR")
        if failed or not os.path.isfile(partial):
            return result if failed else "[ERROR] adb pull produced no file"
        os.replace(partial, local_path)
        partial = None
        return result or "pulled"
    except OSError as e:
        return f"[ERROR] {e}"
    finally:
        if partial and os.path.exists(partial):
            os.remove(partial)


def _find_local_apk(pkg):
    """Find an exact, non-patched APK previously extracted for *pkg*."""
    if not _is_valid_package(pkg):
        return None
    expected = f"{pkg}.apk"
    for search_dir in (os.path.join(os.getcwd(), "extracted_apks"), os.getcwd()):
        candidate = os.path.join(search_dir, expected)
        if os.path.isfile(candidate) and os.path.getsize(candidate) > 0:
            return candidate
    return None

def get_apk_path(pkg):
    """Get APK path for a package, trying root then non-root.
    For split APKs, warns and returns the base.apk (or first) path."""
    if not _is_valid_package(pkg):
        return ""
    pkg_arg = shlex.quote(pkg)
    for fn in (adb_su, adb_shell):
        out = fn(f"pm path {pkg_arg}")
        if out and "package:" in out:
            paths = [line.strip().replace("package:", "").strip()
                     for line in out.splitlines()
                     if line.strip().startswith("package:")]
            if not paths:
                continue
            if len(paths) > 1:
                print(f"  {C.YELLOW}[!] App uses split APKs ({len(paths)} splits) — only base.apk will be analyzed/patched.{C.RST}")
            for path in paths:
                if "base.apk" in path:
                    return path
            return paths[0]
    return ""

def check_device():
    """Check if a device is connected and return device info.
    When multiple devices are connected, prompts the user to pick one."""
    global ADB_SERIAL
    out = adb("devices")
    lines = [l for l in out.splitlines() if "\tdevice" in l]
    if not lines:
        return None
    serials = [l.split("\t")[0] for l in lines]
    if len(serials) > 1:
        print(f"\n  {C.YELLOW}[!] Multiple devices connected:{C.RST}\n")
        for i, s in enumerate(serials, 1):
            print(f"  {C.YELLOW}[{i:3d}]{C.RST} {s}")
        print(f"\n  {C.DIM}[0] Exit{C.RST}")
        while True:
            try:
                choice = input(f"\n  {C.GREEN}Select device ▸ {C.RST}").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                sys.exit(0)
            if choice == "0":
                sys.exit(0)
            try:
                idx = int(choice) - 1
            except ValueError:
                print(f"  {C.RED}Enter a number.{C.RST}")
                continue
            if 0 <= idx < len(serials):
                ADB_SERIAL = serials[idx]
                break
            print(f"  {C.RED}Invalid selection.{C.RST}")
    serial = ADB_SERIAL or serials[0]
    model = adb_shell("getprop ro.product.model")
    android_ver = adb_shell("getprop ro.build.version.release")
    sdk = adb_shell("getprop ro.build.version.sdk")
    return {"serial": serial, "model": model, "android": android_ver, "sdk": sdk}

def check_root():
    """Check if device has root access (su, adbd-root, or adb root restart)."""
    global _root_mode
    # 1) Try su -c (Magisk / SuperSU / rooted ROMs)
    out = _run_cmd(_adb_base() + ["shell", "su -c id"], timeout=10)
    if "uid=0" in out:
        _root_mode = "su"
        return True
    # 2) Check if adb shell already runs as root
    out = adb_shell("id", timeout=10)
    if "uid=0" in out:
        _root_mode = "adbd"
        return True
    # 3) Try "adb root" to restart adbd as root (emulators / userdebug builds)
    root_out = adb("root", timeout=15)
    if root_out and "cannot" not in root_out.lower() and "unable" not in root_out.lower():
        time.sleep(2)  # wait for adbd to restart
        # Re-check connection after adbd restart
        out = adb_shell("id", timeout=10)
        if "uid=0" in out:
            _root_mode = "adbd"
            return True
    _root_mode = None
    return False

def list_third_party_apps():
    """List all third-party (user-installed) apps."""
    out = adb_su("pm list packages -3")
    if _is_err(out):
        out = adb_shell("pm list packages -3")
    pkgs = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            package = line.replace("package:", "", 1)
            if _is_valid_package(package):
                pkgs.append(package)
    pkgs.sort()
    return pkgs

def pick_app(apps):
    """Display numbered app list and let user pick one."""
    if not apps:
        print(f"\n  {C.RED}[!] No third-party apps found.{C.RST}")
        return None
    print(f"\n  {C.CYAN}{C.BOLD}── Third-Party Apps ({len(apps)}) ──{C.RST}\n")
    for i, pkg in enumerate(apps, 1):
        print(f"  {C.YELLOW}[{i:3d}]{C.RST} {pkg}")
    print(f"\n  {C.DIM}[0] Back{C.RST}")
    while True:
        try:
            choice = input(f"\n  {C.GREEN}Select app ▸ {C.RST}").strip()
            if choice == "0" or choice.lower() == "b":
                return None
            idx = int(choice) - 1
            if 0 <= idx < len(apps):
                return apps[idx]
            print(f"  {C.RED}Invalid selection.{C.RST}")
        except ValueError:
            print(f"  {C.RED}Enter a number.{C.RST}")
        except (EOFError, KeyboardInterrupt):
            print()
            return None

# ─── UI Helpers ─────────────────────────────────────────────────────────────────

def clear():
    if sys.stdout.isatty():
        print("\033[2J\033[H", end="", flush=True)

def banner():
    b = f"""
  {C.CYAN}{C.BOLD}
   ╔══════════════════════════════════════════════════════════╗
   ║   █████╗ ██████╗ ██████╗                                ║
   ║  ██╔══██╗██╔══██╗██╔══██╗                               ║
   ║  ███████║██║  ██║██████╔╝                               ║
   ║  ██╔══██║██║  ██║██╔══██╗                               ║
   ║  ██║  ██║██████╔╝██████╔╝                               ║
   ║  ╚═╝  ╚═╝╚═════╝ ╚═════╝                               ║
   ║        {C.MAGENTA}A N A L Y Z E R{C.CYAN}                               ║
   ║  {C.DIM}{C.WHITE}Android Security Analysis Tool{C.RST}{C.CYAN}{C.BOLD}                       ║
   ║  {C.DIM}{C.WHITE}github.com/worldtreeboy/apkAnalyzer{C.RST}{C.CYAN}{C.BOLD}                  ║
   ╚══════════════════════════════════════════════════════════╝{C.RST}
"""
    print(b)

def section(title):
    w = 56
    pad = w - len(title) - 4
    print(f"\n  {C.CYAN}╔{'═'*w}╗{C.RST}")
    print(f"  {C.CYAN}║  {C.BOLD}{C.WHITE}{title}{C.RST}{C.CYAN}{' '*pad}║{C.RST}")
    print(f"  {C.CYAN}╚{'═'*w}╝{C.RST}")

def status_line(label, value, color=None):
    color = color or C.WHITE
    print(f"  {C.DIM}│{C.RST} {C.YELLOW}{label:<20}{C.RST} {color}{value}{C.RST}")

def pass_fail(label, passed, detail=""):
    if passed:
        tag = f"{C.GREEN}[PASS]{C.RST}"
    else:
        tag = f"{C.RED}[FAIL]{C.RST}"
    extra = f" {C.DIM}— {detail}{C.RST}" if detail else ""
    print(f"  {tag} {label}{extra}")

def warn_line(label, detail=""):
    extra = f" {C.DIM}— {detail}{C.RST}" if detail else ""
    print(f"  {C.YELLOW}[WARN]{C.RST} {label}{extra}")

def info_line(label, detail=""):
    extra = f" {C.DIM}— {detail}{C.RST}" if detail else ""
    print(f"  {C.BLUE}[INFO]{C.RST} {label}{extra}")

def pause():
    try:
        input(f"\n  {C.DIM}Press Enter to continue...{C.RST}")
    except (EOFError, KeyboardInterrupt):
        print()

# ─── Decompile Helpers ──────────────────────────────────────────────────────────

def _get_version_code(pkg):
    """Query the device's current versionCode for a package ('' if unavailable)."""
    out = adb_shell(f"dumpsys package {pkg}")
    if _is_err(out):
        return ""
    m = re.search(r'versionCode=(\d+)', out)
    return m.group(1) if m else ""


def _get_package_fingerprint(pkg):
    """Return package metadata that changes on update/reinstall."""
    if not _is_valid_package(pkg):
        return {}
    out = adb_shell(f"dumpsys package {shlex.quote(pkg)}", timeout=30)
    if _is_err(out):
        return {}
    patterns = {
        "versionCode": r"versionCode=(\d+)",
        "lastUpdateTime": r"lastUpdateTime=([^\r\n]+)",
        "codePath": r"codePath=([^\r\n]+)",
    }
    fingerprint = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, out)
        if match:
            fingerprint[key] = match.group(1).strip()
    return fingerprint

def _pull_and_decompile(pkg):
    """Pull APK from device and decompile with apktool. Returns (work_dir, decompiled_dir) or (None, None).
    Caches the decompiled output — reuses it if the folder already exists."""
    work_dir = os.path.join(os.getcwd(), ".apkanalyzer_tmp")
    decompiled_dir = os.path.join(work_dir, f"{pkg}_decompiled")

    # ── Cache hit — already decompiled ──────────────────────────────────
    if os.path.isdir(decompiled_dir):
        # Invalidate the cache if the app was updated on the device since
        try:
            with open(os.path.join(decompiled_dir, ".apkanalyzer_meta.json"),
                      "r", encoding="utf-8") as f:
                cached_meta = json.load(f)
        except Exception:
            cached_meta = {}
        if not isinstance(cached_meta, dict):
            cached_meta = {}
        current_meta = _get_package_fingerprint(pkg)
        if not current_meta:
            # A transient ADB/device failure must not turn an old decompile into
            # trusted input. Preserve the cache so a later, healthy connection
            # can verify it, but stop this scan as inconclusive.
            print(f"  {C.YELLOW}[!] Could not verify the cached decompile against the installed app; cache was not used.{C.RST}")
            return None, None
        if cached_meta != current_meta:
            old_vc = cached_meta.get("versionCode", "unknown")
            new_vc = current_meta.get("versionCode", "unknown")
            print(f"  {C.YELLOW}[!] App changed on device (versionCode {old_vc} → {new_vc}) — re-decompiling.{C.RST}")
            shutil.rmtree(decompiled_dir, ignore_errors=True)
        else:
            print(f"  {C.GREEN}[+] Using cached decompile: {decompiled_dir}{C.RST}")
            return work_dir, decompiled_dir

    # ── Need to decompile ───────────────────────────────────────────────
    apktool_cmd = _find_apktool()
    if not apktool_cmd:
        print(f"  {C.RED}[!] apktool is required for this feature.{C.RST}")
        print(f"  {C.DIM}  Install: https://ibotpeaches.github.io/Apktool/{C.RST}")
        return None, None

    os.makedirs(work_dir, exist_ok=True)

    # Prefer the installed APK so scans cannot silently use a stale local copy.
    apk_path = get_apk_path(pkg)
    local_apk = None
    apk_source = "local"
    if apk_path:
        local_apk = os.path.join(work_dir, f"{pkg}.apk")
        print(f"  {C.DIM}Pulling APK from device...{C.RST}")
        pull_result = adb_pull(apk_path, local_apk)
        if _is_err(pull_result) or not os.path.exists(local_apk):
            print(f"  {C.RED}[!] Installed APK was located but could not be pulled; refusing to use an unverified local fallback: {pull_result}{C.RST}")
            return None, None
        apk_source = "device"
    else:
        local_apk = _find_local_apk(pkg)
        if local_apk:
            print(f"  {C.YELLOW}[!] Installed APK path unavailable; using unverified local APK: {local_apk}{C.RST}")
        else:
            print(f"  {C.RED}[!] Could not locate APK on device or locally.{C.RST}")
            return None, None

    print(f"  {C.DIM}Decompiling with apktool...{C.RST}")
    try:
        r = subprocess.run(
            apktool_cmd + ["d", "-f", "-o", decompiled_dir, local_apk],
            capture_output=True, text=True, timeout=300,
            encoding='utf-8', errors='replace'
        )
        if r.returncode != 0 or not os.path.exists(decompiled_dir):
            print(f"  {C.RED}[!] apktool failed: {r.stderr[:200] if r.stderr else 'unknown error'}{C.RST}")
            return None, None
    except subprocess.TimeoutExpired:
        print(f"  {C.RED}[!] apktool timed out.{C.RST}")
        return None, None
    except OSError as e:
        print(f"  {C.RED}[!] Could not start apktool: {e}{C.RST}")
        return None, None

    # Only a successfully pulled APK may inherit installed-package metadata.
    # Local fallback content gets an explicitly local identity so it can never
    # masquerade as the currently installed build on a later cache check.
    try:
        if apk_source == "device":
            decompile_meta = _get_package_fingerprint(pkg)
        else:
            decompile_meta = {
                "source": "local",
                "sha256": _file_sha256(local_apk),
            }
        with open(os.path.join(decompiled_dir, ".apkanalyzer_meta.json"),
                  "w", encoding="utf-8") as f:
            json.dump(decompile_meta, f, indent=2)
    except Exception:
        pass

    print(f"  {C.GREEN}[+] Decompiled successfully (cached for next check){C.RST}")
    return work_dir, decompiled_dir

def _scan_native_libs(decompiled_dir):
    """Walk lib/ directory and collect all .so filenames. Returns list of (filename, rel_path)."""
    lib_dir = os.path.join(decompiled_dir, "lib")
    so_files = []
    if os.path.isdir(lib_dir):
        for root, dirs, files in os.walk(lib_dir):
            for f in files:
                if f.endswith(".so"):
                    rel = os.path.relpath(os.path.join(root, f), decompiled_dir)
                    so_files.append((f, rel))
    return so_files

# ─── Native SDK signatures (matched against .so filenames in lib/) ────────────

NATIVE_SDK_SIGNATURES = {
    "VKey VGuard":    ["libvguard.so", "libchecks.so", "libvosWrapperEx.so"],
    "Zimperium":      ["libzdefend.so", "libz9.so"],
    "Promon SHIELD":  ["libshield.so"],
    "DexGuard":       ["libdexguard.so"],
    "Frida Gadget":   ["libfrida-gadget.so"],
}

def detect_framework(decompiled_dir):
    """Detect app framework and native SDKs.

    Priority: Flutter > React Native > Xamarin > Unity > Cordova > Kotlin > Java
    Each check collects its own indicators; only the winning framework's
    indicators are returned to avoid misleading mixed details.

    Returns dict with keys:
        framework: str
        native_sdks: list of (sdk_name, [matched .so files])
        details: list of indicator files/dirs found
    """
    # ── Collect native libs ─────────────────────────────────────────────
    so_files = _scan_native_libs(decompiled_dir)
    so_names = {name for name, _ in so_files}
    so_map = {}
    for name, rel in so_files:
        so_map.setdefault(name, []).append(rel)

    smali_dirs = [d for d in os.listdir(decompiled_dir)
                  if d.startswith("smali") and os.path.isdir(os.path.join(decompiled_dir, d))]

    framework = None
    details = []

    # ── Flutter ──────────────────────────────────────────────────────────
    fl = []
    if "libflutter.so" in so_map:
        fl.append(so_map["libflutter.so"][0])
    if "libapp.so" in so_map:
        fl.append(so_map["libapp.so"][0])
    if os.path.isdir(os.path.join(decompiled_dir, "assets", "flutter_assets")):
        fl.append("assets/flutter_assets/")
    for d in smali_dirs:
        if os.path.isdir(os.path.join(decompiled_dir, d, "io", "flutter")):
            fl.append(f"{d}/io/flutter/")
            break
    if fl:
        framework = "Flutter"
        details = fl

    # ── React Native ─────────────────────────────────────────────────────
    if not framework:
        rn = []
        rn_libs = {"libreactnativejni.so", "libreactnative.so", "libhermes.so",
                    "libjsc.so", "libhermestooling.so"}
        for name in rn_libs & so_names:
            rn.append(so_map[name][0])
        if os.path.isfile(os.path.join(decompiled_dir, "assets", "index.android.bundle")):
            rn.append("assets/index.android.bundle")
        for d in smali_dirs:
            if os.path.isdir(os.path.join(decompiled_dir, d, "com", "facebook", "react")):
                rn.append(f"{d}/com/facebook/react/")
                break
        if rn:
            framework = "React Native"
            details = rn

    # ── Xamarin ──────────────────────────────────────────────────────────
    if not framework:
        xm = []
        xm_libs = {"libmonodroid.so", "libmonosgen-2.0.so", "libxamarin-app.so",
                    "libxamarin-debug-app-helper.so"}
        for name in xm_libs & so_names:
            xm.append(so_map[name][0])
        if os.path.isdir(os.path.join(decompiled_dir, "assemblies")):
            xm.append("assemblies/")
        if os.path.isdir(os.path.join(decompiled_dir, "unknown", "assemblies")):
            xm.append("unknown/assemblies/")
        if xm:
            framework = "Xamarin"
            details = xm

    # ── Unity ────────────────────────────────────────────────────────────
    if not framework:
        un = []
        unity_definitive = {"libunity.so", "libil2cpp.so"}
        unity_supporting = {"libmain.so", "libgameassembly.so"}
        for name in (unity_definitive | unity_supporting) & so_names:
            un.append(so_map[name][0])
        if os.path.isdir(os.path.join(decompiled_dir, "assets", "bin", "Data")):
            un.append("assets/bin/Data/")
        # Need a definitive lib OR 2+ supporting indicators
        if unity_definitive & so_names or len(un) >= 2:
            framework = "Unity"
            details = un

    # ── Cordova / Ionic ──────────────────────────────────────────────────
    if not framework:
        cd = []
        www_dir = os.path.join(decompiled_dir, "assets", "www")
        if os.path.isdir(www_dir):
            cd.append("assets/www/")
            if os.path.isfile(os.path.join(www_dir, "cordova.js")):
                cd.append("assets/www/cordova.js")
        for d in smali_dirs:
            if os.path.isdir(os.path.join(decompiled_dir, d, "org", "apache", "cordova")):
                cd.append(f"{d}/org/apache/cordova/")
                break
        if cd:
            framework = "Cordova"
            details = cd

    # ── Kotlin ───────────────────────────────────────────────────────────
    if not framework:
        for d in smali_dirs:
            if os.path.isdir(os.path.join(decompiled_dir, d, "kotlin")):
                framework = "Kotlin"
                details = [f"{d}/kotlin/"]
                break

    # ── Default ──────────────────────────────────────────────────────────
    if not framework:
        framework = "Java"

    # ── Native SDK detection (always run) ───────────────────────────────
    native_sdks = []
    for sdk_name, signatures in NATIVE_SDK_SIGNATURES.items():
        matched = [s for s in signatures if s in so_names]
        if matched:
            native_sdks.append((sdk_name, matched))

    return {
        "framework": framework,
        "native_sdks": native_sdks,
        "details": details,
    }

def _print_framework_info(fw_info):
    """Print detected framework and native SDK info."""
    fw = fw_info["framework"]
    details = fw_info["details"]
    native_sdks = fw_info["native_sdks"]

    fw_labels = {
        "Flutter": "Flutter (Dart)",
        "React Native": "React Native (JavaScript)",
        "Xamarin": "Xamarin (.NET)",
        "Unity": "Unity (C#/IL2CPP)",
        "Cordova": "Cordova/Ionic (Web)",
        "Kotlin": "Kotlin/JVM",
        "Java": "Java (Native Android)",
    }
    label = fw_labels.get(fw, fw)

    print(f"\n  {C.YELLOW}{C.BOLD}── Framework Detection ──{C.RST}")
    print(f"  {C.BOLD}Framework Detected:{C.RST} {C.GREEN}{label}{C.RST}")
    if details:
        print(f"  {C.DIM}Indicators: {', '.join(details)}{C.RST}")
    if native_sdks:
        sdk_parts = []
        for sdk_name, matched_files in native_sdks:
            sdk_parts.append(f"{sdk_name} ({', '.join(matched_files)})")
        print(f"  {C.MAGENTA}Native SDKs: {', '.join(sdk_parts)}{C.RST}")
    print()

_FLUTTER_GROUPS = {
    "Flutter Security Plugins",
}
_RN_GROUPS = {
    "React Native Security",
}

def _search_decompiled(decompiled_dir, keyword_groups, framework=None):
    """Search decompiled directory for keyword groups (case-insensitive).
    Single-pass: reads each file once, checks all keywords per line.

    keyword_groups: list of (group_name, [keywords])
    framework: optional detected framework name — used to skip irrelevant
               framework-specific groups and to extend file extensions.
    Returns: (dict of {group_name: [(rel_path, line_no, line_text, keyword)]}, file_count)
    """
    EXTS = {'.smali', '.xml', '.json', '.properties', '.txt', '.cfg', '.conf', '.yml', '.yaml', '.js'}
    if framework == "React Native":
        EXTS.add('.bundle')

    # Filter out framework-specific groups that don't match the detected framework
    skip_groups = set()
    if framework != "Flutter":
        skip_groups |= _FLUTTER_GROUPS
    if framework != "React Native":
        skip_groups |= _RN_GROUPS

    # Build flat lookup for all keywords across all groups
    all_keywords = []  # (kw_lower, kw_orig, group_name)
    for group_name, keywords in keyword_groups:
        if group_name in skip_groups:
            continue
        for kw in keywords:
            all_keywords.append((kw.lower(), kw, group_name))

    results = {gn: [] for gn, _ in keyword_groups}

    # Collect target files
    all_files = []
    for root, dirs, files in os.walk(decompiled_dir):
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in EXTS:
                all_files.append(os.path.join(root, f))

    # Single pass — one read per file, all keywords checked per line
    for fpath in all_files:
        rel = os.path.relpath(fpath, decompiled_dir)
        try:
            with open(fpath, 'r', errors='ignore') as fh:
                for line_no, line in enumerate(fh, 1):
                    line_low = line.lower()
                    for kl, kw_orig, gn in all_keywords:
                        if kl in line_low:
                            results[gn].append((rel, line_no, line.strip(), kw_orig))
        except Exception:
            continue

    return results, len(all_files)

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


def _parse_manifest(decompiled_dir):
    """Parse AndroidManifest.xml (apktool output) once for all manifest-based checks.

    Returns a dict with keys:
        parsed (bool), min_sdk, target_sdk (str or None),
        debuggable (bool), allow_backup (bool, default True),
        cleartext (True/False/None), cleartext_explicit (bool),
        has_nsc (bool), nsc_ref (str or None),
        permissions (set of full permission names),
        exported ({"activity"/"service"/"receiver": [{"name", "actions": [...]}],
                   "provider": [{"name", "authorities", "read_perm", "write_perm",
                                 "grant_uri", "path_permissions": [...]}]}),
        deeplinks ({"schemes": [...], "hosts": [...]}),
        task_affinity (list of (activity_name, affinity) with non-empty affinity)
    Activity/service/receiver aliases use the intent-filter export default.
    Provider defaults follow Android's target-SDK-dependent behavior.
    """
    info = {
        "parsed": False,
        "min_sdk": None, "target_sdk": None,
        "debuggable": False, "allow_backup": True,
        "package": "",
        "cleartext": None, "cleartext_explicit": False,
        "has_nsc": False, "nsc_ref": None,
        "permissions": set(),
        "declared_permissions": {},
        "exported": {"activity": [], "service": [], "receiver": [], "provider": []},
        "deeplinks": {"schemes": [], "hosts": []},
        "task_affinity": [],
    }
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
    info["parsed"] = True
    info["package"] = package

    ns = f"{{{_ANDROID_NS}}}"

    # SDK versions (fall back to apktool.yml when uses-sdk is absent)
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

    # Permissions
    for perm_tag in ("uses-permission", "uses-permission-sdk-23"):
        for perm in root.findall(perm_tag):
            name = perm.get(f"{ns}name", "")
            if name:
                info["permissions"].add(name)
    for declared in root.findall("permission"):
        name = declared.get(f"{ns}name", "")
        if name:
            info["declared_permissions"][name] = declared.get(
                f"{ns}protectionLevel", "normal"
            )

    # Application attributes
    app = root.find("application")
    if app is not None:
        info["debuggable"] = app.get(f"{ns}debuggable") == "true"
        info["allow_backup"] = app.get(f"{ns}allowBackup") != "false"
        app_enabled = app.get(f"{ns}enabled") != "false"
        app_permission = app.get(f"{ns}permission") or None
        app_task_affinity = app.get(f"{ns}taskAffinity")
        if app_task_affinity is None:
            app_task_affinity = info["package"]
        nsc = app.get(f"{ns}networkSecurityConfig")
        if nsc is not None:
            info["has_nsc"] = True
            info["nsc_ref"] = nsc.lstrip("@") or None
        ct = app.get(f"{ns}usesCleartextTraffic")
        if ct is not None:
            info["cleartext"] = ct == "true"
            info["cleartext_explicit"] = True
        elif info["target_sdk"] and str(info["target_sdk"]).isdigit():
            # Platform default changed from true to false for target SDK 28.
            info["cleartext"] = int(info["target_sdk"]) <= 27

        # Components
        for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            for comp in app.findall(tag):
                name = comp.get(f"{ns}name")
                if not name or not app_enabled or comp.get(f"{ns}enabled") == "false":
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
                    is_exported = exported_attr == "true"
                elif tag == "provider":
                    target = info["target_sdk"]
                    is_exported = bool(target and str(target).isdigit()
                                       and int(target) <= 16)
                else:
                    is_exported = bool(intent_filters)
                if not is_exported:
                    continue

                # A browser-style deep link must be reachable from outside and
                # have VIEW and BROWSABLE in the same filter.  Keeping filter
                # boundaries avoids combining unrelated actions/categories.
                if bucket == "activity":
                    for filt, filter_actions, filter_categories in filter_details:
                        if ("android.intent.action.VIEW" not in filter_actions
                                or "android.intent.category.BROWSABLE"
                                not in filter_categories):
                            continue
                        for data in filt.findall("data"):
                            scheme = data.get(f"{ns}scheme")
                            if (scheme and scheme
                                    not in info["deeplinks"]["schemes"]):
                                info["deeplinks"]["schemes"].append(scheme)
                            host = data.get(f"{ns}host")
                            if (host and host
                                    not in info["deeplinks"]["hosts"]):
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
                        "grant_uri": comp.get(f"{ns}grantUriPermissions") == "true",
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
                    }
                    if tag == "activity-alias":
                        entry["target_activity"] = comp.get(f"{ns}targetActivity")
                    info["exported"][bucket].append(entry)

    return info


def _resolve_resource_path(decompiled_dir, resource_ref):
    """Resolve an apktool resource reference such as @xml/network_config."""
    if not resource_ref:
        return None
    ref = resource_ref.strip().lstrip("@")
    if ref.startswith("+"):
        ref = ref[1:]
    if ":" in ref:
        _package, ref = ref.split(":", 1)
    parts = ref.split("/", 1)
    if len(parts) != 2 or not all(parts):
        return None
    resource_type, name = parts
    if not re.fullmatch(r"[A-Za-z0-9_]+", resource_type):
        return None
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        return None
    if not os.path.splitext(name)[1]:
        name += ".xml"
    path = os.path.abspath(os.path.join(decompiled_dir, "res", resource_type, name))
    root = os.path.abspath(decompiled_dir)
    return path if os.path.commonpath((root, path)) == root else None


# ─── Network Security Config ─────────────────────────────────────────────────────

def _analyze_nsc(decompiled_dir, nsc_path=None, target_sdk=None):
    """Parse network_security_config.xml for pinning and cleartext policy."""
    info = {"parsed": False, "pins": [], "cleartext_allowed": False,
            "cleartext_known": False,
            "trusts_user_certs": False, "trusts_debug_user_certs": False,
            "trust_anchors": [], "path": None}

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

        platform_default = None
        if target_sdk is not None and str(target_sdk).isdigit():
            platform_default = int(target_sdk) <= 27

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

    except (ET.ParseError, OSError, ValueError):
        pass
    return info


def _print_nsc_analysis(info):
    """Display network security config analysis."""
    if not info["parsed"]:
        return

    print(f"\n  {C.CYAN}{C.BOLD}── NETWORK SECURITY CONFIG ──{C.RST}")

    if info["pins"]:
        print(f"    {C.GREEN}[FOUND]{C.RST} {len(info['pins'])} certificate pin(s)")
        for p in info["pins"][:4]:
            domain_str = ", ".join(p["domains"][:2]) if p["domains"] else "N/A"
            print(f"           {C.DIM}{p['digest']}:{p['value']} → {domain_str}{C.RST}")
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
    """Check smali directory tree for known security library packages."""
    found = []
    smali_dirs = [d for d in os.listdir(decompiled_dir)
                  if d.startswith("smali") and os.path.isdir(os.path.join(decompiled_dir, d))]
    seen = set()
    for d in smali_dirs:
        for pkg_path, label in SECURITY_PACKAGES.items():
            if label in seen:
                continue
            full = os.path.join(decompiled_dir, d, pkg_path)
            if os.path.isdir(full):
                # Count smali files to gauge library size
                count = sum(1 for _, _, ff in os.walk(full) for f in ff if f.endswith(".smali"))
                found.append((label, f"{d}/{pkg_path}/", count))
                seen.add(label)
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

def _scan_native_strings(decompiled_dir):
    """Run strings on native .so files and search for security indicators.
    Falls back to a pure-Python printable-ASCII extraction when the
    'strings' binary is not available (e.g. stock Windows)."""
    lib_dir = os.path.join(decompiled_dir, "lib")
    if not os.path.isdir(lib_dir):
        return []

    have_strings = shutil.which("strings") is not None

    results = []
    for root, dirs, files in os.walk(lib_dir):
        for f in files:
            if not f.endswith(".so"):
                continue
            fpath = os.path.join(root, f)
            rel = os.path.relpath(fpath, decompiled_dir)
            if have_strings:
                try:
                    r = subprocess.run(
                        ["strings", "-n", "8", fpath],
                        capture_output=True, text=True, timeout=30,
                        encoding='utf-8', errors='replace'
                    )
                    if r.returncode != 0:
                        continue
                    lines = r.stdout
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    continue
            else:
                # Pure-Python fallback: printable-ASCII runs of length >= 8
                try:
                    with open(fpath, 'rb') as fh:
                        data = fh.read()
                except Exception:
                    continue
                lines = "\n".join(
                    m.group().decode('ascii')
                    for m in re.finditer(rb"[\x20-\x7e]{8,}", data)
                )

            file_hits = {}
            for category, pattern in _NATIVE_STRING_PATTERNS:
                matches = pattern.findall(lines)
                if matches:
                    # Deduplicate
                    unique = list(dict.fromkeys(matches))[:5]
                    file_hits[category] = unique

            if file_hits:
                results.append((rel, file_hits))
    return results


def _print_native_strings(results):
    """Display native string analysis results."""
    if not results:
        print(f"    {C.DIM}No security-related strings found in native libraries.{C.RST}")
        return

    for rel, hits in results:
        print(f"\n    {C.BOLD}{rel}{C.RST}")
        for category, strings in hits.items():
            preview = ", ".join(s if len(s) <= 40 else s[:37] + "..." for s in strings[:3])
            more = f" +{len(strings)-3}" if len(strings) > 3 else ""
            print(f"      {C.GREEN}[{category}]{C.RST} {C.DIM}{preview}{more}{C.RST}")


# ─── 1. App Analysis ────────────────────────────────────────────────────────────

def app_analysis(pkg):
    section("APP ANALYSIS")

    print(f"\n  {C.CYAN}Analyzing: {C.BOLD}{pkg}{C.RST}\n")

    # Basic info
    apk_path = get_apk_path(pkg) or "N/A"
    status_line("APK Path", apk_path)

    # Version info
    dumpsys = adb_su(f"dumpsys package {pkg}")
    version_name = "N/A"
    version_code = "N/A"
    target_sdk = "N/A"
    min_sdk = "N/A"
    for line in dumpsys.splitlines():
        line = line.strip()
        if "versionName=" in line and version_name == "N/A":
            version_name = line.split("versionName=")[-1].split()[0]
        if "versionCode=" in line and version_code == "N/A":
            m = re.search(r'versionCode=(\d+)', line)
            if m:
                version_code = m.group(1)
        if "targetSdk=" in line and target_sdk == "N/A":
            m = re.search(r'targetSdk=(\d+)', line)
            if m:
                target_sdk = m.group(1)
        if "minSdk=" in line and min_sdk == "N/A":
            m = re.search(r'minSdk=(\d+)', line)
            if m:
                min_sdk = m.group(1)

    status_line("Version", f"{version_name} (code: {version_code})")
    status_line("Target SDK", target_sdk)
    status_line("Min SDK", min_sdk)

    # Populate report app_info
    report.app_info["version"] = f"{version_name} (code: {version_code})"
    if target_sdk != "N/A":
        report.app_info["target_sdk"] = target_sdk
    if min_sdk != "N/A":
        report.app_info["min_sdk"] = min_sdk

    # Data dir size
    data_size = adb_su(f"du -sh {shlex.quote(f'/data/data/{pkg}')} 2>/dev/null")
    if not _is_err(data_size):
        status_line("Data Size", data_size.split()[0] if data_size.split() else "N/A")

    # Permissions
    print(f"\n  {C.YELLOW}{C.BOLD}── Permissions ──{C.RST}")
    perms = []
    for line in dumpsys.splitlines():
        if "granted=true" in line:
            m = re.search(r'([\w.]+): granted=true', line.strip())
            if m:
                perms.append(m.group(1))
    if perms:
        for p in perms:
            pname = p.split(".")[-1]
            color = C.RED if any(d in pname.upper() for d in [
                "CAMERA", "LOCATION", "MICROPHONE", "SMS", "CALL", "CONTACTS",
                "STORAGE", "READ_EXTERNAL", "WRITE_EXTERNAL"
            ]) else C.WHITE
            print(f"    {color}• {p}{C.RST}")
    else:
        print(f"    {C.DIM}No runtime permissions granted.{C.RST}")

    # Components
    print(f"\n  {C.YELLOW}{C.BOLD}── Components ──{C.RST}")
    # Count from dumpsys
    act_count = len(re.findall(rf'{re.escape(pkg)}/[\w.]+Activity', dumpsys))
    svc_count = len(re.findall(rf'{re.escape(pkg)}/[\w.]+Service', dumpsys))
    rcv_count = len(re.findall(rf'{re.escape(pkg)}/[\w.]+Receiver', dumpsys))
    prov_count = len(re.findall(rf'{re.escape(pkg)}/[\w.]+Provider', dumpsys))
    status_line("Activities", str(act_count))
    status_line("Services", str(svc_count))
    status_line("Receivers", str(rcv_count))
    status_line("Providers", str(prov_count))

    # Extract APK option
    print()
    extract = input(f"  {C.GREEN}Extract APK to local? (y/n) ▸ {C.RST}").strip().lower()
    if extract == "y" and apk_path != "N/A":
        out_dir = os.path.join(os.getcwd(), "extracted_apks")
        os.makedirs(out_dir, exist_ok=True)
        local_path = os.path.join(out_dir, f"{pkg}.apk")
        print(f"  {C.CYAN}Pulling APK...{C.RST}")
        result = adb_pull(apk_path, local_path)
        if (not _is_err(result) and os.path.exists(local_path)
                and os.path.getsize(local_path) > 0):
            size = os.path.getsize(local_path)
            print(f"  {C.GREEN}[✓] Saved: {local_path} ({size // 1024} KB){C.RST}")
        else:
            print(f"  {C.RED}[✗] Pull failed: {result}{C.RST}")

    pause()

# ─── 2. Storage Audit ───────────────────────────────────────────────────────────

STATIC_SECRET_MAX_FILE_BYTES = 500_000
STATIC_SECRET_EXTENSIONS = (
    '.xml', '.json', '.properties', '.yml', '.yaml', '.env', '.ini', '.cfg',
    '.conf', '.config', '.txt', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx',
    '.java', '.kt', '.kts', '.smali', '.gradle', '.toml', '.dart', '.html',
    '.htm', '.pem', '.key',
)


def _should_scan_static_secrets(path):
    """Return whether a likely-text source file is within the scanner cap."""
    if not os.path.basename(path).lower().endswith(STATIC_SECRET_EXTENSIONS):
        return False
    try:
        return os.path.getsize(path) <= STATIC_SECRET_MAX_FILE_BYTES
    except OSError:
        return False


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
    # Azure connection string (legacy rule retained).
    re.compile(r'DefaultEndpointsProtocol=https;AccountName=\S+'),
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


def _iter_secret_matches(content, per_pattern_limit=None):
    """Yield non-empty, non-public secret matches with bounded per-rule output."""
    for pattern in SECRET_PATTERNS:
        count = 0
        for match in pattern.finditer(content):
            value, _span = _secret_value_and_span(match)
            if not value.strip() or _is_public_secret_identifier(value):
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

def _scan_pii(content):
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
    return hits


def _redact_sensitive_text(content):
    """Redact detected secrets and PII before showing raw storage previews."""
    redacted = _redact_secret_text(content)
    for pattern, _label in PII_PATTERNS:
        redacted = pattern.sub(lambda match: _redact(match.group(0)), redacted)
    return redacted

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

def storage_audit(pkg):
    section("STORAGE AUDIT")

    data_dir = f"/data/data/{pkg}"
    print(f"\n  {C.CYAN}Auditing storage: {C.BOLD}{data_dir}{C.RST}\n")

    # Overall size
    size_out = adb_su(f"du -sh {shlex.quote(data_dir)} 2>/dev/null")
    if not _is_err(size_out):
        status_line("Total Size", size_out.split()[0] if size_out.split() else "N/A")

    # List all files recursively (maxdepth + no symlink follow to stay in app dir)
    files_out = adb_su(f"find {shlex.quote(data_dir)} -maxdepth 5 -type f -not -type l 2>/dev/null", timeout=60)
    all_files = [f.strip() for f in files_out.splitlines()
                 if f.strip() and f.startswith(data_dir)]

    sp_files = [f for f in all_files if "/shared_prefs/" in f and f.endswith(".xml")]
    db_files = [f for f in all_files if f.endswith(".db") or f.endswith(".sqlite") or f.endswith(".sqlite3")]
    realm_files = [f for f in all_files if f.endswith(".realm") or f.endswith(".realm.lock")]
    cache_files = [f for f in all_files if "/cache/" in f]
    log_files = [f for f in all_files if f.endswith(".log") or f.endswith(".tmp")]

    status_line("Total Files", str(len(all_files)))
    status_line("SharedPrefs", str(len(sp_files)), C.YELLOW if sp_files else C.GREEN)
    status_line("SQLite DBs", str(len(db_files)), C.YELLOW if db_files else C.GREEN)
    status_line("Realm DBs", str(len(realm_files)), C.YELLOW if realm_files else C.GREEN)
    status_line("Cache Files", str(len(cache_files)))
    status_line("Log/Tmp Files", str(len(log_files)), C.YELLOW if log_files else C.GREEN)

    # SharedPreferences analysis
    # Third-party SDK prefixes to de-prioritize
    sdk_prefixes = ['com.google', 'com.facebook', 'com.firebase', 'com.crashlytics',
                    'com.mixpanel', 'com.amplitude', 'com.appsflyer', 'io.branch',
                    'com.adjust', 'com.segment', 'androidx.', 'WebView', 'chromium']

    if sp_files:
        print(f"\n  {C.YELLOW}{C.BOLD}── SharedPreferences ──{C.RST}")
        secrets_found = 0
        pii_found = 0
        encrypted_prefs = 0

        # Sort: app-specific files first, SDK files last
        def is_sdk_file(f):
            fn = os.path.basename(f).lower()
            return any(sdk.lower() in fn for sdk in sdk_prefixes)
        sp_files_sorted = sorted(sp_files, key=lambda x: (is_sdk_file(x), x))

        # Read all prefs files (and sizes) in a few batched adb calls
        sp_contents, sp_sizes = _batch_read_files(sp_files_sorted)

        for spf in sp_files_sorted:
            fname = os.path.basename(spf)
            content = sp_contents.get(spf, "")
            fsize = sp_sizes.get(spf, "?")

            # Check for EncryptedSharedPreferences
            is_encrypted = False
            if content and ("__androidx_security_crypto_encrypted" in content or
                           "keyset" in fname.lower() or
                           "__encrypted__" in content):
                is_encrypted = True
                encrypted_prefs += 1

            is_sdk = is_sdk_file(spf)
            sdk_tag = f" {C.DIM}[SDK]{C.RST}" if is_sdk else f" {C.MAGENTA}[APP]{C.RST}"
            enc_tag = f" {C.GREEN}[ENCRYPTED]{C.RST}" if is_encrypted else ""
            print(f"\n    {C.CYAN}📄 {fname}{C.RST} {C.DIM}({fsize} bytes){C.RST}{sdk_tag}{enc_tag}")

            if not _is_err(content) and not is_encrypted:
                # Always show raw XML content (first 10 lines)
                raw_lines = _redact_sensitive_text(content).splitlines()
                preview_count = min(10, len(raw_lines))
                if preview_count > 0:
                    print(f"      {C.WHITE}Content ({len(raw_lines)} lines, showing first {preview_count}):{C.RST}")
                    for rline in raw_lines[:preview_count]:
                        print(f"        {C.DIM}{rline.rstrip()}{C.RST}")
                    if len(raw_lines) > 10:
                        print(f"        {C.DIM}... ({len(raw_lines) - 10} more lines){C.RST}")

                # Extract and highlight key-value pairs
                kv_pairs = []
                # Tags with content: <string name="X">val</string>
                for m in re.finditer(r'<(string|int|long|float|boolean|set)\s+name="([^"]+)"[^>]*>([^<]*)</', content):
                    ktype, kname, kval = m.groups()
                    kv_pairs.append((ktype, kname, kval.strip()))
                # Self-closing tags: <boolean name="X" value="Y" />, <float name="X" value="Y" />
                for m in re.finditer(r'<(boolean|int|long|float)\s+name="([^"]+)"\s+value="([^"]+)"', content):
                    kv_pairs.append((m.group(1), m.group(2), m.group(3)))

                if kv_pairs:
                    sensitive_keys = [
                        # Auth & credentials
                        'token', 'key', 'secret', 'password', 'passwd', 'pwd',
                        'auth', 'session', 'jwt', 'credential', 'pin', 'otp',
                        'login', 'username', 'user_name', 'userid', 'user_id',
                        # PII
                        'email', 'mail', 'phone', 'mobile', 'number', 'address',
                        'name', 'fullname', 'first_name', 'last_name', 'dob',
                        'birth', 'ssn', 'social', 'national_id', 'nric', 'passport',
                        'license', 'gender', 'age', 'ic_number', 'identity',
                        # Financial
                        'account', 'balance', 'credit', 'debit', 'card',
                        'iban', 'routing', 'swift', 'payment', 'bank',
                        'amount', 'transaction', 'wallet',
                        # Crypto / keys
                        'private', 'cert', 'certificate', 'signing',
                        'encryption', 'master', 'api', 'bearer', 'refresh',
                        'access', 'client_id', 'client_secret',
                        # Device / tracking
                        'imei', 'imsi', 'device_id', 'mac_address',
                        'serial', 'fingerprint', 'biometric',
                    ]
                    flagged = [(ktype, kname, kval) for ktype, kname, kval in kv_pairs
                               if any(sk in kname.lower() for sk in sensitive_keys)]
                    if flagged:
                        print(f"      {C.RED}Sensitive Keys Found ({len(flagged)}):{C.RST}")
                        for ktype, kname, kval in flagged[:10]:
                            display_val = _redact(kval[:120])
                            print(f"        {C.RED}⚠ {kname}{C.RST} = {C.RED}{display_val}{C.RST} {C.DIM}({ktype}){C.RST}")

                # Check for secrets
                secret_matches = _find_secret_matches(content, per_pattern_limit=3)
                if secret_matches:
                    secrets_found += 1
                    for value in secret_matches[:3]:
                        print(f"      {C.RED}⚠ Potential secret: {_redact(value[:120])}{C.RST}")

                # Check for PII in values
                pii_hits = _scan_pii(content)
                if pii_hits:
                    pii_found += 1
                    print(f"      {C.RED}PII Detected ({len(pii_hits)}):{C.RST}")
                    for label, val in pii_hits[:8]:
                        print(f"        {C.RED}⚠ {label}: {_redact(val)}{C.RST}")

        if encrypted_prefs > 0:
            print(f"\n    {C.GREEN}Found {encrypted_prefs} EncryptedSharedPreferences file(s).{C.RST}")
        if secrets_found == 0 and pii_found == 0:
            print(f"\n    {C.GREEN}No plaintext secrets or PII detected in SharedPreferences.{C.RST}")
        elif secrets_found == 0:
            print(f"\n    {C.GREEN}No plaintext secrets detected in SharedPreferences.{C.RST}")
        if pii_found > 0:
            print(f"\n    {C.RED}⚠ PII found in {pii_found} SharedPreferences file(s)!{C.RST}")

    # SQLite Database analysis
    # SDK database names to de-prioritize
    sdk_db_names = ['google', 'firebase', 'facebook', 'analytics', 'crashlytics',
                    'com.google', 'gms', 'admob', 'webview', 'chromium']

    if db_files:
        print(f"\n  {C.YELLOW}{C.BOLD}── SQLite Databases ──{C.RST}")

        def is_sdk_db(f):
            fn = os.path.basename(f).lower()
            return any(sdk.lower() in fn for sdk in sdk_db_names)

        # Sort: app-specific DBs first
        db_files_sorted = sorted(db_files, key=lambda x: (is_sdk_db(x), x))

        for dbf in db_files_sorted:
            fname = os.path.basename(dbf)
            size_info = adb_su(f"ls -la {shlex.quote(dbf)} 2>/dev/null")
            fsize = "?"
            if size_info:
                parts = size_info.split()
                if len(parts) >= 5:
                    fsize = parts[3]

            is_sdk = is_sdk_db(dbf)
            sdk_tag = f" {C.DIM}[SDK]{C.RST}" if is_sdk else f" {C.MAGENTA}[APP]{C.RST}"
            print(f"\n    {C.CYAN}🗄  {fname}{C.RST} {C.DIM}({fsize} bytes){C.RST}{sdk_tag}")

            # Check if encrypted (SQLCipher)
            header = adb_su(f"xxd -l 16 {shlex.quote(dbf)} 2>/dev/null", timeout=5)
            is_encrypted = header and "5351 4c69 7465" not in header  # "SQLite" magic
            if is_encrypted:
                print(f"      {C.GREEN}[ENCRYPTED - SQLCipher or similar]{C.RST}")
                continue

            tables = adb_su(f"sqlite3 {shlex.quote(dbf)} '.tables' 2>/dev/null", timeout=10)
            if not _is_err(tables) and "not found" not in tables:
                table_list = tables.split()
                print(f"      Tables ({len(table_list)}): {C.WHITE}{tables}{C.RST}")

                # For app-specific DBs, show more details
                if not is_sdk:
                    for table in table_list[:5]:  # First 5 tables
                        try:
                            table_ident = _sqlite_identifier(table)
                        except ValueError:
                            continue
                        # Get row count
                        count = _sqlite_read(
                            dbf, f"SELECT COUNT(*) FROM {table_ident}", timeout=5  # nosec B608
                        )
                        count = count.strip() if not _is_err(count) else "?"

                        # Get column names
                        cols = _sqlite_read(
                            dbf, f"PRAGMA table_info({table_ident})", timeout=5
                        )
                        col_names = []
                        if not _is_err(cols):
                            for line in cols.splitlines():
                                parts = line.split("|")
                                if len(parts) >= 2:
                                    col_names.append(parts[1])

                        print(f"      {C.WHITE}→ {table}{C.RST} ({count} rows)")
                        if col_names:
                            print(f"        Columns: {C.DIM}{', '.join(col_names[:8])}{C.RST}")
                            if len(col_names) > 8:
                                print(f"        {C.DIM}... and {len(col_names) - 8} more columns{C.RST}")

                        # Fetch sample data for PII scanning + display
                        sensitive_tables = ['user', 'account', 'credential', 'token', 'session',
                                            'auth', 'login', 'profile', 'setting', 'config',
                                            'cache', 'payment', 'card', 'address', 'contact',
                                            'transaction', 'order', 'customer', 'member']
                        if count != "?" and count.isdigit() and int(count) > 0:
                            sample = _sqlite_read(
                                dbf, f"SELECT * FROM {table_ident} LIMIT 5", timeout=5  # nosec B608
                            )
                            if not _is_err(sample):
                                # Show raw rows for sensitive-looking tables
                                if any(st in table.lower() for st in sensitive_tables):
                                    print(f"        {C.RED}Sample data:{C.RST}")
                                    for row in sample.splitlines()[:3]:
                                        safe_row = _redact_sensitive_text(row)
                                        row_display = safe_row[:100] + "..." if len(safe_row) > 100 else safe_row
                                        print(f"          {C.DIM}{row_display}{C.RST}")
                                # Scan ALL app tables for PII
                                pii_hits = _scan_pii(sample)
                                if pii_hits:
                                    print(f"        {C.RED}⚠ PII in data ({len(pii_hits)}):{C.RST}")
                                    for label, val in pii_hits[:5]:
                                        print(f"          {C.RED}⚠ {label}: {_redact(val)}{C.RST}")

                    if len(table_list) > 5:
                        print(f"      {C.DIM}... and {len(table_list) - 5} more tables{C.RST}")

    # Realm Database analysis
    if realm_files:
        print(f"\n  {C.YELLOW}{C.BOLD}── Realm Databases ──{C.RST}")
        for rf in realm_files:
            fname = os.path.basename(rf)
            size_info = adb_su(f"ls -la {shlex.quote(rf)} 2>/dev/null")
            fsize = "?"
            if size_info:
                parts = size_info.split()
                if len(parts) >= 5:
                    fsize = parts[3]
            # Check if encrypted by reading header
            header = adb_su(f"xxd -l 8 {shlex.quote(rf)} 2>/dev/null", timeout=5)
            is_encrypted = header and "5265 616c 6d" not in header  # "Realm" magic bytes
            enc_tag = f" {C.GREEN}[ENCRYPTED]{C.RST}" if is_encrypted else f" {C.RED}[UNENCRYPTED]{C.RST}"
            print(f"    {C.CYAN}🗄  {fname}{C.RST} {C.DIM}({fsize} bytes){C.RST}{enc_tag}")

    # ── Recursive scan of ALL remaining files ──────────────────────────────
    # Files already inspected above (SharedPrefs, DBs, Realm) are skipped
    inspected = set(sp_files + db_files + realm_files)
    other_files = [f for f in all_files if f not in inspected]

    if other_files:
        print(f"\n  {C.YELLOW}{C.BOLD}── Other Files (files/, cache/, etc.) ──{C.RST}")
        print(f"  {C.DIM}Scanning {len(other_files)} remaining file(s) for sensitive data...{C.RST}")

        highlight_kw = [
            'token', 'key', 'secret', 'password', 'passwd', 'pwd', 'auth',
            'session', 'jwt', 'credential', 'pin', 'otp', 'login', 'username',
            'email', 'mail', 'phone', 'mobile', 'account', 'balance', 'credit',
            'card', 'iban', 'payment', 'bank', 'amount', 'transaction', 'wallet',
            'private', 'cert', 'api', 'bearer', 'refresh', 'access',
            'imei', 'imsi', 'device_id', 'ssn', 'nric', 'passport',
            'address', 'name', 'dob',
            'fingerprint', 'biometric', 'number',
        ]
        other_secrets = 0
        other_pii = 0

        # Read all remaining files in a few batched adb calls
        other_contents, _other_sizes = _batch_read_files(other_files)

        for of in other_files:
            fname = os.path.basename(of)
            rel_path = of.replace(data_dir + "/", "")
            content = other_contents.get(of, "")

            # Skip binary / empty / error responses
            if _is_err(content):
                continue
            # Basic binary check: if too many non-printable chars, skip
            sample = content[:512]
            non_print = sum(1 for ch in sample if ord(ch) < 32 and ch not in '\n\r\t')
            if non_print > len(sample) * 0.3:
                print(f"\n    {C.CYAN}{rel_path}{C.RST} {C.DIM}[binary, skipped]{C.RST}")
                continue

            lines = _redact_sensitive_text(content).splitlines()
            preview = lines[:5]

            # Check for keyword hits in full content
            content_lower = content.lower()
            hits = [kw for kw in highlight_kw if kw in content_lower]

            # Check SECRET_PATTERNS
            secret_hits = [value[:120] for value in
                           _find_secret_matches(content, per_pattern_limit=2)]

            if secret_hits:
                other_secrets += 1

            hit_tag = ""
            if hits:
                hit_tag = f" {C.RED}[SENSITIVE: {', '.join(hits[:5])}]{C.RST}"
            elif not secret_hits:
                hit_tag = f" {C.DIM}[no keywords]{C.RST}"

            print(f"\n    {C.CYAN}{rel_path}{C.RST} {C.DIM}({len(lines)} lines){C.RST}{hit_tag}")
            for pl in preview:
                line_display = pl.rstrip()
                # Highlight matching keywords in the line
                for kw in hits:
                    pat = re.compile(re.escape(kw), re.IGNORECASE)
                    line_display = pat.sub(f"{C.RED}{C.BOLD}\\g<0>{C.RST}{C.DIM}", line_display)
                print(f"      {C.DIM}{line_display}{C.RST}")
            if len(lines) > 5:
                print(f"      {C.DIM}... ({len(lines) - 5} more lines){C.RST}")

            for sh in secret_hits:
                print(f"      {C.RED}⚠ Potential secret: {_redact(sh)}{C.RST}")

            # Check for PII in content
            pii_hits = _scan_pii(content)
            if pii_hits:
                other_pii += 1
                print(f"      {C.RED}PII Detected ({len(pii_hits)}):{C.RST}")
                for label, val in pii_hits[:5]:
                    print(f"        {C.RED}⚠ {label}: {_redact(val)}{C.RST}")

        if other_secrets == 0 and other_pii == 0:
            print(f"\n    {C.GREEN}No secrets or PII detected in other files.{C.RST}")
        else:
            if other_secrets > 0:
                print(f"\n    {C.RED}⚠ Found potential secrets in {other_secrets} file(s).{C.RST}")
            if other_pii > 0:
                print(f"\n    {C.RED}⚠ Found PII in {other_pii} file(s)!{C.RST}")

    # File Permission Check (world-readable)
    print(f"\n  {C.YELLOW}{C.BOLD}── File Permissions ──{C.RST}")
    world_readable = []
    find_out = adb_su(f"find {shlex.quote(data_dir)} -maxdepth 5 -type f -perm -o+r 2>/dev/null", timeout=30)
    wr_paths = [f.strip() for f in find_out.splitlines()
                if f.strip() and f.startswith(data_dir)]
    wr_modes = _batch_stat(wr_paths)
    for f in wr_paths:
        perms = wr_modes.get(f, "")
        if len(perms) >= 3 and perms[-1] in ['4', '5', '6', '7']:  # world-readable
            world_readable.append((f, perms))
    if world_readable:
        print(f"    {C.RED}⚠ Found {len(world_readable)} world-readable file(s):{C.RST}")
        for wf, perm in world_readable[:10]:
            print(f"      {C.DIM}{os.path.basename(wf)} (mode: {perm}){C.RST}")
        if len(world_readable) > 10:
            print(f"      {C.DIM}... and {len(world_readable) - 10} more{C.RST}")
    else:
        print(f"    {C.GREEN}No world-readable files found (checked {len(all_files)} files).{C.RST}")

    # External storage check
    print(f"\n  {C.YELLOW}{C.BOLD}── External Storage ──{C.RST}")
    ext_dir = f"/sdcard/Android/data/{pkg}"
    ext_out = adb_su(f"ls -la {shlex.quote(ext_dir)} 2>/dev/null")
    if not _is_err(ext_out) and "No such file" not in ext_out:
        ext_size = adb_su(f"du -sh {shlex.quote(ext_dir)} 2>/dev/null")
        status_line("External Dir", ext_size.split()[0] if ext_size and ext_size.split() else "exists")
    else:
        print(f"    {C.DIM}No external storage data found.{C.RST}")

    pause()

# ─── 3. Shell Access ────────────────────────────────────────────────────────────

def shell_access(pkg=None):
    section("SHELL ACCESS (ROOT)")
    print(f"  {C.DIM}Type commands to execute as root. Type 'exit' to return.{C.RST}\n")

    # Start in the app's data directory if a package is selected
    cwd = f"/data/data/{pkg}" if pkg else "/data/local/tmp"

    while True:
        # Show current directory in prompt
        display_cwd = cwd if len(cwd) <= 40 else "..." + cwd[-37:]
        try:
            cmd = input(f"  {C.RED}root@device{C.RST}:{C.BLUE}{display_cwd}{C.RST}# ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not cmd:
            continue
        if cmd.lower() == "exit":
            return

        # Handle cd command specially to update cwd
        if cmd == "cd" or cmd == "cd ~":
            cwd = "/data/local/tmp"
            continue
        elif cmd.startswith("cd "):
            target = cmd[3:].strip().strip('"').strip("'")
            if not target:
                continue
            # Resolve Android paths with POSIX semantics on every host OS.
            if target.startswith("/"):
                new_cwd = posixpath.normpath(target)
            else:
                new_cwd = posixpath.normpath(posixpath.join(cwd, target))
            # Verify directory exists by actually cd-ing into it
            check = adb_su(f'cd {shlex.quote(new_cwd)} && pwd')
            resolved = check.strip().splitlines()[-1].strip() if check else ""
            if resolved.startswith("/"):
                cwd = resolved
            else:
                print(f"  {C.RED}cd: {target}: No such directory{C.RST}\n")
            continue

        # Run command in current directory
        full_cmd = f'cd {shlex.quote(cwd)} && {cmd}'
        output = adb_su(full_cmd, timeout=30)
        if output:
            for line in output.splitlines():
                print(f"  {line}")
        print()

# ─── 4. Screenshot ──────────────────────────────────────────────────────────────

def screenshot():
    section("SCREENSHOT")
    remote_path = "/sdcard/_apkanalyzer_screenshot.png"
    print(f"  {C.CYAN}Capturing screenshot...{C.RST}")
    adb_shell(f"screencap -p {remote_path}")

    out_dir = os.path.join(os.getcwd(), "screenshots")
    os.makedirs(out_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    local_path = os.path.join(out_dir, f"screenshot_{timestamp}.png")

    result = adb_pull(remote_path, local_path)
    adb_shell(f"rm {remote_path}")

    if os.path.exists(local_path):
        size = os.path.getsize(local_path)
        print(f"  {C.GREEN}[✓] Screenshot saved: {local_path} ({size // 1024} KB){C.RST}")
    else:
        print(f"  {C.RED}[✗] Screenshot failed: {result}{C.RST}")

    pause()

# ─── 5. Security Scan ───────────────────────────────────────────────────────────

# ─── OWASP MASVS v2.0 Mapping & Severity for Security Checks ─────────────────

SECURITY_CHECKS = {
    "debuggable": {
        "severity": "CRITICAL",
        "masvs": "MASVS-RESILIENCE-1",
        "cwe": "CWE-489",
        "title": "Application is Debuggable",
        "remediation": "Set android:debuggable='false' in release builds",
    },
    "allow_backup": {
        "severity": "HIGH",
        "masvs": "MASVS-STORAGE-1",
        "cwe": "CWE-530",
        "title": "Backup Enabled Without Restrictions",
        "remediation": "Set android:allowBackup='false' or define backup rules",
    },
    "exported_components": {
        "severity": "HIGH",
        "masvs": "MASVS-PLATFORM-1",
        "cwe": "CWE-926",
        "title": "Exported Components Without Protection",
        "remediation": "Set android:exported='false' or add permission checks",
    },
    "dangerous_permissions": {
        "severity": "INFO",
        "masvs": "MASVS-PLATFORM-1",
        "cwe": "CWE-250",
        "title": "Dangerous Permissions Requested",
        "remediation": "Review necessity and request dangerous permissions only at runtime",
    },
    "cleartext_traffic": {
        "severity": "HIGH",
        "masvs": "MASVS-NETWORK-1",
        "cwe": "CWE-319",
        "title": "Cleartext Traffic Allowed",
        "remediation": "Set android:usesCleartextTraffic='false' and enforce HTTPS",
    },
    "network_security_config": {
        "severity": "MEDIUM",
        "masvs": "MASVS-NETWORK-1",
        "cwe": "CWE-295",
        "title": "Missing or Weak Network Security Config",
        "remediation": "Define a network_security_config.xml with certificate pinning",
    },
    "deeplinks": {
        "severity": "MEDIUM",
        "masvs": "MASVS-PLATFORM-2",
        "cwe": "CWE-939",
        "title": "Deeplink / URI Scheme Hijacking Risk",
        "remediation": "Validate all deeplink parameters; use App Links with autoVerify",
    },
    "hardcoded_secrets": {
        "severity": "CRITICAL",
        "masvs": "MASVS-STORAGE-1",
        "cwe": "CWE-798",
        "title": "Hardcoded Secrets Detected",
        "remediation": "Store secrets in Android Keystore or server-side; never in source",
    },
    "webview_js_interface": {
        "severity": "HIGH",
        "masvs": "MASVS-PLATFORM-2",
        "cwe": "CWE-749",
        "title": "WebView JavaScript Interface Exposed",
        "remediation": "Restrict addJavascriptInterface to SDK >= 17; validate JS inputs",
    },
    "debug_logging": {
        "severity": "MEDIUM",
        "masvs": "MASVS-STORAGE-1",
        "cwe": "CWE-532",
        "title": "Debug / Verbose Logging in Production",
        "remediation": "Remove Log.d()/Log.v() calls or use ProGuard to strip them",
    },
    "unprotected_broadcasts": {
        "severity": "MEDIUM",
        "masvs": "MASVS-PLATFORM-1",
        "cwe": "CWE-927",
        "title": "Unprotected Broadcast Receivers",
        "remediation": "Use LocalBroadcastManager or add permission to sendBroadcast()",
    },
    "flag_secure": {
        "severity": "LOW",
        "masvs": "MASVS-RESILIENCE-2",
        "cwe": "CWE-200",
        "title": "FLAG_SECURE Not Set (Screenshot Protection)",
        "remediation": "Set FLAG_SECURE on sensitive Activities to block screenshots",
    },
    "clipboard_exposure": {
        "severity": "MEDIUM",
        "masvs": "MASVS-STORAGE-2",
        "cwe": "CWE-200",
        "title": "Clipboard Data Exposure Risk",
        "remediation": "Use ClipData.setSensitive(true) on Android 13+; clear clipboard after use",
    },
    "keyboard_cache": {
        "severity": "LOW",
        "masvs": "MASVS-STORAGE-2",
        "cwe": "CWE-524",
        "title": "Keyboard Cache Not Disabled",
        "remediation": "Use textNoSuggestions / flagNoPersonalizedLearning on sensitive fields",
    },
    "tapjacking": {
        "severity": "MEDIUM",
        "masvs": "MASVS-PLATFORM-2",
        "cwe": "CWE-1021",
        "title": "Tapjacking / Overlay Attack Vulnerability",
        "remediation": "Set filterTouchesWhenObscured='true' on sensitive Views",
    },
    "sdk_version": {
        "severity": "MEDIUM",
        "masvs": "MASVS-CODE-1",
        "cwe": "CWE-1104",
        "title": "Outdated SDK Version Targeted",
        "remediation": "Raise minSdkVersion to 23+ and targetSdkVersion to 35+",
    },
    "pending_intent_mutable": {
        "severity": "HIGH",
        "masvs": "MASVS-PLATFORM-1",
        "cwe": "CWE-927",
        "title": "PendingIntent Without Immutability Flag",
        "remediation": "Use FLAG_IMMUTABLE for PendingIntents unless mutability is required",
    },
    "task_hijacking": {
        "severity": "HIGH",
        "masvs": "MASVS-PLATFORM-1",
        "cwe": "CWE-200",
        "title": "Task Hijacking (StrandHogg) Risk",
        "remediation": "Set taskAffinity='' (empty) and launchMode='singleInstance'",
    },
    "apk_signing": {
        "severity": "HIGH",
        "masvs": "MASVS-RESILIENCE-2",
        "cwe": "CWE-347",
        "title": "Weak APK Signing Scheme",
        "remediation": "Sign with v2/v3 scheme; v1-only is vulnerable to Janus (CVE-2017-13156)",
    },
}

# Severity color mapping for security scan output
_SEVERITY_COLORS = {
    "CRITICAL": C.RED,
    "HIGH":     C.RED,
    "MEDIUM":   C.YELLOW,
    "LOW":      C.BLUE,
}

def _severity_tag(check_key):
    """Return a colored severity tag with MASVS/CWE ref string for a given check key."""
    info = SECURITY_CHECKS.get(check_key, {})
    sev = info.get("severity", "MEDIUM")
    masvs = info.get("masvs", "")
    cwe = info.get("cwe", "")
    color = _SEVERITY_COLORS.get(sev, C.YELLOW)
    return f"{color}[{sev}]{C.RST}", f"{C.DIM}({masvs} | {cwe}){C.RST}"

def _finding_line(check_key, label, detail=""):
    """Print a FAIL finding with severity, MASVS category, and CWE ID."""
    sev_tag, ref_tag = _severity_tag(check_key)
    extra = f" {C.DIM}-- {detail}{C.RST}" if detail else ""
    print(f"  {sev_tag} {label}  {ref_tag}{extra}")


def _find_static_secret_files(decompiled_dir):
    """Find bounded text files containing secret patterns without a manifest."""
    matches = []
    for root, _dirs, files in os.walk(decompiled_dir):
        for fname in files:
            path = os.path.join(root, fname)
            if not _should_scan_static_secrets(path):
                continue
            try:
                with open(path, "r", errors="ignore") as source:
                    content = source.read(STATIC_SECRET_MAX_FILE_BYTES + 1)
            except OSError:
                continue
            if _find_secret_matches(content, per_pattern_limit=1):
                matches.append(os.path.relpath(path, decompiled_dir))
    return matches

def security_scan(pkg):
    section("SECURITY SCAN")

    print(f"\n  {C.CYAN}Scanning: {C.BOLD}{pkg}{C.RST}\n")

    work_dir, decompiled_dir = _pull_and_decompile(pkg)
    if not decompiled_dir:
        pause()
        return

    passes = 0
    fails = 0
    warns = 0

    # Severity counters for MASVS risk summary
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total_checks_run = 0
    total_findings = 0

    def _record_finding(check_key, description="", extra_detail=""):
        """Record a finding, increment severity counter, and add to report."""
        nonlocal total_findings
        total_findings += 1
        info = SECURITY_CHECKS.get(check_key, {})
        sev = info.get("severity", "MEDIUM")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        # Also add to global report collector
        report.add_finding(
            category=info.get("masvs", "General"),
            title=info.get("title", check_key),
            severity=sev,
            confidence="HIGH",
            description=description or info.get("title", check_key),
            remediation=info.get("remediation", ""),
            masvs=info.get("masvs", ""),
            cwe=info.get("cwe", ""),
        )

    # ── Parse AndroidManifest.xml from decompiled dir ────────────────────────
    manifest = _parse_manifest(decompiled_dir)
    if not manifest["parsed"]:
        print(f"  {C.RED}[!] Could not read AndroidManifest.xml{C.RST}")
        print(f"  {C.YELLOW}[INCONCLUSIVE]{C.RST} Manifest-dependent checks were skipped; bounded code/resource checks will continue.")

        fw_info = detect_framework(decompiled_dir)
        _print_framework_info(fw_info)
        independent_secret_files = _find_static_secret_files(decompiled_dir)
        print(f"\n  {C.YELLOW}{C.BOLD}── Data Leakage Check ──{C.RST}")
        if independent_secret_files:
            _finding_line(
                "hardcoded_secrets", "Hardcoded secrets",
                f"Potential secrets found in {len(independent_secret_files)} file(s)",
            )
            info = SECURITY_CHECKS["hardcoded_secrets"]
            report.add_finding(
                category=info["masvs"], title=info["title"],
                severity=info["severity"], confidence="HIGH",
                description=(
                    "Potential secrets/keys found despite an unreadable manifest: "
                    + ", ".join(independent_secret_files[:5])
                ),
                remediation=info["remediation"], masvs=info["masvs"],
                cwe=info["cwe"],
            )
            for rel_path in independent_secret_files[:5]:
                print(f"    {C.DIM}{rel_path}{C.RST}")
        else:
            info_line(
                "Manifest-independent secret scan",
                "No matches in bounded supported text files",
            )
        pause()
        return

    # ── Framework & Native SDK Detection ─────────────────────────────────────
    fw_info = detect_framework(decompiled_dir)
    _print_framework_info(fw_info)

    # ── Single-pass scan of the decompiled tree (checks 8, 10-18) ───────────
    # Reads each relevant file exactly once and accumulates every signal,
    # instead of re-walking the whole tree (and re-reading every file) per check.
    jsinterface_found = False
    mutable_pending = False
    immutable_pending = False
    unprotected_broadcasts = 0
    protected_broadcasts = 0
    flag_secure_found = False
    clip_usage = 0
    clip_protection = 0
    clip_unprotected_files = []
    log_hits = {}
    pw_fields = 0
    nosuggest = 0
    has_filter_touches = False
    secrets_files = []

    log_keywords = {
        "Java":   ['Landroid/util/Log;->v(', 'Landroid/util/Log;->d('],
        "Kotlin": ['Timber;->d(', 'Timber;->v('],
        "Flutter": ['debugPrint', 'kDebugMode'],
        "React Native": ['console.log', 'console.debug'],
    }

    for root, dirs, files in os.walk(decompiled_dir):
        for fname in files:
            lower_fname = fname.lower()
            is_smali = lower_fname.endswith('.smali')
            is_xml = lower_fname.endswith('.xml')
            is_secret_ext = lower_fname.endswith(STATIC_SECRET_EXTENSIONS)
            if not (is_smali or is_xml or is_secret_ext):
                continue
            fpath = os.path.join(root, fname)
            # Secret scanning includes the manifest and smali but remains
            # bounded per file.  Other checks retain their existing inputs.
            do_secrets = _should_scan_static_secrets(fpath) if is_secret_ext else False
            if not (is_smali or is_xml or do_secrets):
                continue
            try:
                with open(fpath, 'r', errors='ignore') as fh:
                    content = fh.read()
            except Exception:
                continue

            if do_secrets:
                if _find_secret_matches(content, per_pattern_limit=1):
                    rel = os.path.relpath(fpath, decompiled_dir)
                    secrets_files.append(rel)

            if is_smali:
                # WebView JS interface
                if not jsinterface_found and 'addJavascriptInterface' in content:
                    jsinterface_found = True
                # PendingIntent mutability
                if 'PendingIntent;->get' in content:
                    flag_signals = (
                        'FLAG_IMMUTABLE', 'FLAG_MUTABLE',
                        '0x4000000',  # PendingIntent.FLAG_IMMUTABLE
                        '0x2000000',  # PendingIntent.FLAG_MUTABLE
                    )
                    if any(signal in content for signal in flag_signals):
                        immutable_pending = True
                    else:
                        mutable_pending = True
                # Broadcast security
                if 'sendBroadcast(Landroid/content/Intent;)V' in content:
                    if 'LocalBroadcastManager' not in content:
                        unprotected_broadcasts += 1
                if 'sendBroadcast(Landroid/content/Intent;Ljava/lang/String;)V' in content:
                    protected_broadcasts += 1
                # FLAG_SECURE
                if not flag_secure_found and ('FLAG_SECURE' in content or 'setFlags(8192' in content):
                    flag_secure_found = True
                # Clipboard usage
                uses_clipboard = any(kw in content for kw in
                                     ('ClipboardManager', 'ClipData', 'setPrimaryClip', 'getPrimaryClip'))
                has_clipboard_protection = ('FLAG_SENSITIVE' in content
                                            or 'isSensitive' in content)
                if uses_clipboard:
                    clip_usage += 1
                    relative = os.path.relpath(fpath, decompiled_dir)
                    if has_clipboard_protection:
                        clip_protection += 1
                    else:
                        clip_unprotected_files.append(relative)
                # Debug / verbose logging
                for framework, kws in log_keywords.items():
                    for kw in kws:
                        if kw in content:
                            log_hits[framework] = log_hits.get(framework, 0) + 1
                # Tapjacking
                if not has_filter_touches and 'filterTouchesWhenObscured' in content:
                    has_filter_touches = True

            if is_xml:
                # Keyboard cache / secure input types
                for kw in ('textPassword', 'textVisiblePassword', 'numberPassword', 'textWebPassword'):
                    if kw in content:
                        pw_fields += content.count(kw)
                for kw in ('textNoSuggestions', 'flagNoPersonalizedLearning'):
                    if kw in content:
                        nosuggest += content.count(kw)
                # Tapjacking (also declared in layouts)
                if not has_filter_touches and 'filterTouchesWhenObscured' in content:
                    has_filter_touches = True

    # ── 1. Debuggable ────────────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Debuggable Check ──{C.RST}")
    total_checks_run += 1
    debuggable = manifest["debuggable"]
    if debuggable:
        _finding_line("debuggable", "Debuggable flag", "App is debuggable — allows runtime inspection")
        fails += 1
        _record_finding("debuggable", "android:debuggable is set to true, allowing runtime inspection and debugging.")
    else:
        pass_fail("Debuggable flag", True, "Not debuggable")
        passes += 1

    # ── 2. Backup ────────────────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Backup Check ──{C.RST}")
    total_checks_run += 1
    allow_backup = manifest["allow_backup"]
    if allow_backup:
        _finding_line("allow_backup", "allowBackup", "App data can be backed up via adb — data extraction risk")
        fails += 1
        _record_finding("allow_backup", "android:allowBackup is true. App data can be extracted via adb backup.")
    else:
        pass_fail("allowBackup", True, "Backup disabled or not set")
        passes += 1

    # ── 3. Exported Components ───────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Exported Components ──{C.RST}")
    total_checks_run += 1

    exposed_components = []
    gated_components = []
    unknown_gated_components = []

    def classify_component(kind, component, strength):
        target = {
            "strong": gated_components,
            "weak": exposed_components,
            "unknown": unknown_gated_components,
        }[strength]
        target.append((kind, component["name"], component.get("permission")))

    for comp in manifest["exported"]["activity"]:
        is_launcher = (
            "android.intent.action.MAIN" in comp.get("actions", [])
            and "android.intent.category.LAUNCHER" in comp.get("categories", [])
        )
        if is_launcher:
            continue
        classify_component(
            "Activity", comp,
            _permission_strength(manifest, comp.get("permission")),
        )
    for bucket, label in (("service", "Service"), ("receiver", "Receiver")):
        for comp in manifest["exported"][bucket]:
            classify_component(
                label, comp,
                _permission_strength(manifest, comp.get("permission")),
            )
    for comp in manifest["exported"]["provider"]:
        strength = _provider_protection_strength(manifest, comp)
        target = {
            "strong": gated_components,
            "weak": exposed_components,
            "unknown": unknown_gated_components,
        }[strength]
        target.append(("Provider", comp["name"], None))

    if exposed_components:
        total_exported = len(exposed_components)
        _finding_line("exported_components", f"Unprotected exported components: {total_exported}")
        fails += 1
        comp_list = [f"{kind}: {name}" for kind, name, _permission in exposed_components]
        _record_finding("exported_components",
                         f"{total_exported} exported component(s) lack manifest permission protection: "
                         f"{'; '.join(comp_list[:10])}")
        for kind, name, _permission in exposed_components[:20]:
            print(f"    {C.DIM}{kind}: {name}{C.RST}")
    elif not unknown_gated_components:
        pass_fail("Exported components", True,
                  "Only launcher or permission-gated components are exported")
        passes += 1
    if gated_components:
        info_line("Permission-gated exports", f"{len(gated_components)} component(s)")
    if unknown_gated_components:
        warns += 1
        warn_line(
            "Unresolved exported-component permissions",
            f"{len(unknown_gated_components)} component(s); protection level could not be verified",
        )
        for kind, name, permission in unknown_gated_components[:10]:
            suffix = f" ({permission})" if permission else ""
            print(f"    {C.DIM}{kind}: {name}{suffix}{C.RST}")

    # ── 4. Permissions ───────────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Dangerous Permissions ──{C.RST}")
    total_checks_run += 1
    requested_perms = manifest["permissions"]
    dangerous_requested = requested_perms & DANGEROUS_PERMS
    if dangerous_requested:
        info_line("Dangerous permissions",
                  f"{len(dangerous_requested)} requested (review app necessity)")
        perm_list = ", ".join(dp.replace("android.permission.", "") for dp in sorted(dangerous_requested))
        info = SECURITY_CHECKS["dangerous_permissions"]
        report.add_finding(
            category=info["masvs"], title=info["title"], severity="INFO",
            confidence="HIGH",
            description=f"{len(dangerous_requested)} dangerous permission(s) requested: {perm_list}",
            remediation=info["remediation"], masvs=info["masvs"], cwe=info["cwe"],
        )
        for dp in sorted(dangerous_requested):
            permission_prefix = "android.permission."
            short = (dp[len(permission_prefix):]
                     if dp.startswith(permission_prefix) else dp)
            print(f"    {C.DIM}\u2022 {short}{C.RST}")
    else:
        pass_fail("Dangerous permissions", True, "No dangerous permissions requested")
        passes += 1

    # ── 5. SDK Version ───────────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── SDK Version ──{C.RST}")
    total_checks_run += 1
    # SDK info from the parsed manifest (apktool.yml fallback handled by _parse_manifest)
    min_sdk = manifest["min_sdk"] or "N/A"
    target_sdk = manifest["target_sdk"] or "N/A"
    if min_sdk != "N/A" and not min_sdk.isdigit():
        min_sdk = "N/A"
    if target_sdk != "N/A" and not target_sdk.isdigit():
        target_sdk = "N/A"

    # Populate report app_info with SDK versions
    report.app_info["min_sdk"] = min_sdk
    report.app_info["target_sdk"] = target_sdk

    sdk_failed = False
    if min_sdk != "N/A" and int(min_sdk) < 23:
        _finding_line("sdk_version", "Min SDK", f"minSdk={min_sdk} — targets outdated Android (< 6.0)")
        fails += 1
        sdk_failed = True
        _record_finding("sdk_version",
                         f"minSdkVersion={min_sdk} targets Android < 6.0, missing modern security features.")
    elif min_sdk != "N/A":
        pass_fail("Min SDK", True, f"minSdk={min_sdk}")
        passes += 1
    else:
        info_line("Min SDK", "Could not determine")

    if target_sdk != "N/A" and int(target_sdk) < 35:
        if not sdk_failed:
            _finding_line("sdk_version", "Target SDK", f"targetSdk={target_sdk} — below current level 35+")
            _record_finding("sdk_version",
                             f"targetSdkVersion={target_sdk} is below current level 35+.")
        else:
            warn_line(f"targetSdk={target_sdk} — below current level 35+")
        warns += 1
    elif target_sdk != "N/A":
        pass_fail("Target SDK", True, f"targetSdk={target_sdk}")
        passes += 1

    # ── 6. Cleartext Traffic ─────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Network Security ──{C.RST}")
    total_checks_run += 1
    nsc_path = _resolve_resource_path(decompiled_dir, manifest["nsc_ref"])
    if manifest["has_nsc"]:
        nsc_info = _analyze_nsc(
            decompiled_dir, nsc_path=nsc_path, target_sdk=target_sdk
        )
    else:
        nsc_info = {"parsed": False, "pins": [], "cleartext_allowed": False,
                    "cleartext_known": False,
                    "trusts_user_certs": False, "trusts_debug_user_certs": False,
                    "trust_anchors": [], "path": None}
    cleartext_source = None
    if manifest["has_nsc"]:
        # Android 7.0+ ignores usesCleartextTraffic when an NSC is present.
        # Do not OR the manifest value into the parsed NSC policy.
        if nsc_info["parsed"] and nsc_info["cleartext_known"]:
            cleartext = nsc_info["cleartext_allowed"]
            cleartext_source = "network security config"
            if min_sdk != "N/A" and int(min_sdk) <= 22:
                cleartext = True
                cleartext_source = "pre-Android 6 platform behavior"
            elif (min_sdk == "23" and (
                    manifest["cleartext"] is True
                    or not manifest["cleartext_explicit"])):
                cleartext = True
                cleartext_source = (
                    "manifest on Android 6"
                    if manifest["cleartext_explicit"]
                    else "Android 6 platform default"
                )
        else:
            cleartext = None
    else:
        cleartext = manifest["cleartext"]
        if manifest["cleartext_explicit"]:
            cleartext_source = "manifest"
        else:
            cleartext_source = f"target SDK {target_sdk} platform default"
    if cleartext is not None:
        if cleartext:
            source = cleartext_source or "effective platform policy"
            _finding_line("cleartext_traffic", "Cleartext traffic", f"HTTP allowed by {source}")
            fails += 1
            _record_finding("cleartext_traffic",
                             f"Cleartext HTTP communication is allowed by {source}.")
        else:
            source = cleartext_source or "effective platform policy"
            pass_fail("Cleartext traffic", True, f"Disabled by {source}")
            passes += 1
    else:
        info_line("Cleartext traffic", "Could not determine effective policy")

    # ── 7. Network Security Config ───────────────────────────────────────────
    total_checks_run += 1
    if manifest["has_nsc"]:
        if not nsc_info["parsed"]:
            warn_line("Network security config", "Referenced config is missing or invalid")
            warns += 1
        elif nsc_info["trusts_user_certs"]:
            _finding_line("network_security_config", "Network security config",
                          "Production policy trusts user-installed CAs")
            warns += 1
            _record_finding("network_security_config",
                             "Production network security policy trusts user-installed CA certificates.")
        else:
            pass_fail("Network security config", True, "Custom config parsed; no production user-CA trust")
            passes += 1
    else:
        info_line("Network security config", "Not defined; platform policy applies")

    # ── 8. Secrets in decompiled files ───────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Data Leakage Check ──{C.RST}")
    total_checks_run += 1
    secrets_found = bool(secrets_files)
    if secrets_found:
        _finding_line("hardcoded_secrets", "Hardcoded secrets", f"Potential secrets found in {len(secrets_files)} file(s)")
        fails += 1
        _record_finding("hardcoded_secrets",
                         f"Potential secrets/keys found in {len(secrets_files)} file(s): {', '.join(secrets_files[:5])}")
        for sf in secrets_files[:5]:
            print(f"    {C.DIM}{sf}{C.RST}")
    else:
        pass_fail("Data leakage", True, "No plaintext secrets detected")
        passes += 1

    # ── 9. Deeplink / Intent Filter Hijacking ────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Deeplink Security ──{C.RST}")
    total_checks_run += 1
    deeplinks = manifest["deeplinks"]["schemes"] + manifest["deeplinks"]["hosts"]
    if deeplinks:
        unique_links = list(set(deeplinks))
        _finding_line("deeplinks", f"Found {len(unique_links)} deeplink scheme(s)/host(s)")
        fails += 1
        _record_finding("deeplinks",
                         f"{len(unique_links)} deeplink scheme(s)/host(s): {', '.join(unique_links[:5])}")
        for dl in unique_links[:5]:
            print(f"    {C.DIM}\u2022 {dl}{C.RST}")
        print(f"    {C.DIM}Risk: Deeplink hijacking if not validated properly{C.RST}")
    else:
        pass_fail("Deeplinks", True, "No externally reachable deeplink filters found")
        passes += 1

    # ── 10. WebView JavaScript Interface ─────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── WebView Security ──{C.RST}")
    total_checks_run += 1
    if jsinterface_found:
        _finding_line("webview_js_interface", "WebView.addJavascriptInterface() used", "Verify SDK >= 17 protection")
        fails += 1
        _record_finding("webview_js_interface",
                         "WebView.addJavascriptInterface() is used. JS-to-Java bridge may expose attack surface.")
        print(f"    {C.DIM}Risk: JS-to-Java bridge can expose app to XSS attacks on SDK < 17{C.RST}")
    else:
        pass_fail("WebView JS Interface", True, "No addJavascriptInterface() found")
        passes += 1

    # ── 11. Pending Intent Mutability ────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Pending Intent Security ──{C.RST}")
    total_checks_run += 1
    if mutable_pending:
        _finding_line("pending_intent_mutable", "PendingIntent without FLAG_IMMUTABLE/FLAG_MUTABLE", "SDK 31+ required")
        fails += 1
        _record_finding("pending_intent_mutable",
                         "PendingIntent created without FLAG_IMMUTABLE/FLAG_MUTABLE, risking hijacking on Android 12+.")
        print(f"    {C.DIM}Risk: PendingIntent hijacking on Android 12+{C.RST}")
        if immutable_pending:
            info_line("Other PendingIntents", "Explicit mutability flags also detected")
    elif immutable_pending:
        pass_fail("Pending Intent", True, "FLAG_IMMUTABLE/FLAG_MUTABLE flags used")
        passes += 1
    else:
        info_line("Pending Intent", "No PendingIntent usage detected")

    # ── 12. Implicit Broadcast ───────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Broadcast Security ──{C.RST}")
    total_checks_run += 1
    if unprotected_broadcasts > 0:
        _finding_line("unprotected_broadcasts", f"sendBroadcast() without permission in {unprotected_broadcasts} file(s)")
        fails += 1
        _record_finding("unprotected_broadcasts",
                         f"sendBroadcast() without permission in {unprotected_broadcasts} file(s). Any app can intercept.")
        print(f"    {C.DIM}Risk: Any app can intercept implicit broadcasts{C.RST}")
        if protected_broadcasts > 0:
            print(f"    {C.DIM}{protected_broadcasts} file(s) use permission-protected broadcasts{C.RST}")
    elif protected_broadcasts > 0:
        pass_fail("Broadcast security", True, f"All broadcasts use permission protection ({protected_broadcasts} file(s))")
        passes += 1
    else:
        info_line("Broadcast security", "No sendBroadcast() usage detected")

    # ── 13. Screenshot Protection (FLAG_SECURE) ──────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Screenshot Protection ──{C.RST}")
    total_checks_run += 1
    if flag_secure_found:
        pass_fail("FLAG_SECURE", True, "Screenshot protection detected")
        passes += 1
    else:
        info_line("FLAG_SECURE", "Not detected; review screens containing sensitive data")

    # ── 14. Clipboard Data Exposure ──────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Clipboard Data Exposure ──{C.RST}")
    total_checks_run += 1
    if clip_unprotected_files:
        _finding_line("clipboard_exposure",
                      f"Clipboard used without FLAG_SENSITIVE protection ({len(clip_unprotected_files)} file(s))")
        warns += 1
        _record_finding("clipboard_exposure",
                         f"Clipboard used without FLAG_SENSITIVE protection in "
                         f"{len(clip_unprotected_files)} file(s).")
        for cf in clip_unprotected_files[:3]:
            print(f"    {C.DIM}{cf}{C.RST}")
    elif clip_usage > 0 and clip_protection > 0:
        pass_fail("Clipboard", True, "Clipboard used with sensitive flag protection")
        passes += 1
    else:
        pass_fail("Clipboard", True, "No direct clipboard operations detected")
        passes += 1

    # ── 15. Debug / Verbose Logging ──────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Debug / Verbose Logging ──{C.RST}")
    total_checks_run += 1
    if log_hits:
        total = sum(log_hits.values())
        _finding_line("debug_logging", f"Debug/verbose log calls found ({total} file(s))")
        warns += 1
        log_detail = ", ".join(f"{fw}: {count}" for fw, count in log_hits.items())
        _record_finding("debug_logging",
                         f"Debug/verbose log calls found in {total} file(s): {log_detail}")
        for fw, count in log_hits.items():
            print(f"    {C.DIM}\u2022 {fw}: {count} file(s){C.RST}")
    else:
        pass_fail("Debug logging", True, "No verbose/debug log calls detected")
        passes += 1

    # ── 16. Keyboard Cache / Input Types ─────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Keyboard Cache ──{C.RST}")
    total_checks_run += 1
    if pw_fields:
        pass_fail("Secure input types", True, f"{pw_fields} password-type field(s) found")
        passes += 1
    else:
        info_line("Secure input types", "No password fields detected in packaged layouts")
    if nosuggest:
        info_line("textNoSuggestions", f"{nosuggest} field(s) disable keyboard learning")
    elif pw_fields:
        info_line("Keyboard learning", "Password input types already suppress suggestions")

    # ── 17. Task Hijacking (taskAffinity) ────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Task Hijacking ──{C.RST}")
    total_checks_run += 1
    task_hijack = manifest["task_affinity"]
    if task_hijack:
        _finding_line("task_hijacking", f"Activities with custom taskAffinity ({len(task_hijack)})", "StrandHogg risk")
        fails += 1
        _record_finding("task_hijacking",
                         f"{len(task_hijack)} activities with custom taskAffinity (StrandHogg risk).")
        for act_name, aff in task_hijack[:5]:
            print(f"    {C.DIM}\u2022 {act_name}{C.RST}")
            print(f"      {C.DIM}taskAffinity=\"{aff}\"{C.RST}")
    else:
        pass_fail("Task hijacking", True, "No custom taskAffinity found")
        passes += 1

    # ── 18. Tapjacking Protection ────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Tapjacking Protection ──{C.RST}")
    total_checks_run += 1
    if has_filter_touches:
        pass_fail("Tapjacking", True, "filterTouchesWhenObscured detected")
        passes += 1
    else:
        info_line("Tapjacking", "No global mitigation detected; review sensitive confirmation views")

    # ── 19. APK Signing Scheme ───────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── APK Signing Scheme ──{C.RST}")
    total_checks_run += 1
    # Locate the APK file
    apk_file = _find_local_apk(pkg)
    if apk_file is None:
        pulled_apk = os.path.join(work_dir, f"{pkg}.apk")
        if os.path.isfile(pulled_apk) and os.path.getsize(pulled_apk) > 0:
            apk_file = pulled_apk

    if apk_file and shutil.which("apksigner"):
        try:
            r = subprocess.run(
                ["apksigner", "verify", "--print-certs", "-v", apk_file],
                capture_output=True, text=True, timeout=30,
                encoding='utf-8', errors='replace'
            )
            output = r.stdout + r.stderr
            has_v1 = bool(re.search(r'Verified using v1 scheme.*?:\s*true', output, re.IGNORECASE))
            has_v2 = bool(re.search(r'Verified using v2 scheme.*?:\s*true', output, re.IGNORECASE))
            has_v3 = bool(re.search(r'Verified using v3 scheme.*?:\s*true', output, re.IGNORECASE))
            has_v4 = bool(re.search(r'Verified using v4 scheme.*?:\s*true', output, re.IGNORECASE))

            schemes = []
            if has_v1: schemes.append("v1 (JAR)")
            if has_v2: schemes.append("v2 (APK Sig)")
            if has_v3: schemes.append("v3 (Key Rotation)")
            if has_v4: schemes.append("v4 (Incremental)")

            if schemes:
                info_line("Signing schemes", ", ".join(schemes))
            if has_v1 and not has_v2 and not has_v3:
                _finding_line("apk_signing", "APK signing", "v1-only signing — vulnerable to Janus (CVE-2017-13156)")
                fails += 1
                _record_finding("apk_signing",
                                 "APK uses v1 (JAR) signing only, vulnerable to Janus attack (CVE-2017-13156).")
            elif has_v2 or has_v3:
                pass_fail("APK signing", True, "Uses v2/v3 signing scheme")
                passes += 1
            else:
                info_line("APK signing", "Could not determine signing schemes")

            # Extract signer info
            for cn_m in re.finditer(r'CN=([^,\n]+)', output):
                info_line("Signer", cn_m.group(1).strip())
                break
        except Exception:
            info_line("APK signing", "apksigner check failed")
    elif not shutil.which("apksigner"):
        info_line("APK signing", "apksigner not found — skipping (install Android SDK build-tools)")
    else:
        info_line("APK signing", "APK file not found locally — skipping")

    # ── Additional Static Analysis (informational) ───────────────────────────
    # Network Security Config detail: cert pins, cleartext policy, user-CA trust
    _print_nsc_analysis(nsc_info)

    # Known security / anti-tamper libraries detected in the smali class tree
    _print_security_classes(_check_security_classes(decompiled_dir))

    # Security-relevant strings inside native .so libraries (root/frida/SSL/etc.)
    native_str_results = _scan_native_strings(decompiled_dir)
    if native_str_results:
        print(f"\n  {C.CYAN}{C.BOLD}── NATIVE LIBRARY STRINGS ──{C.RST}")
        _print_native_strings(native_str_results)

    # ── Risk Summary with MASVS Severity ─────────────────────────────────────
    print(f"\n  {C.CYAN}{'=' * 56}{C.RST}")
    print(f"  {C.BOLD}{C.WHITE}RISK SUMMARY{C.RST}")
    print(f"  {C.CYAN}{'=' * 56}{C.RST}")

    crit = severity_counts["CRITICAL"]
    high = severity_counts["HIGH"]
    med  = severity_counts["MEDIUM"]
    low  = severity_counts["LOW"]

    parts = []
    if crit:
        parts.append(f"{C.RED}{C.BOLD}CRITICAL: {crit}{C.RST}")
    else:
        parts.append(f"{C.DIM}CRITICAL: 0{C.RST}")
    if high:
        parts.append(f"{C.RED}HIGH: {high}{C.RST}")
    else:
        parts.append(f"{C.DIM}HIGH: 0{C.RST}")
    if med:
        parts.append(f"{C.YELLOW}MEDIUM: {med}{C.RST}")
    else:
        parts.append(f"{C.DIM}MEDIUM: 0{C.RST}")
    if low:
        parts.append(f"{C.BLUE}LOW: {low}{C.RST}")
    else:
        parts.append(f"{C.DIM}LOW: 0{C.RST}")

    print(f"  {'  |  '.join(parts)}")
    print(f"  {C.WHITE}Total findings: {total_findings}/{total_checks_run} checks{C.RST}")
    print(f"  {C.GREEN}PASS: {passes}{C.RST}  {C.RED}FAIL: {fails}{C.RST}  {C.YELLOW}WARN: {warns}{C.RST}")

    if crit > 0:
        print(f"\n  {C.RED}{C.BOLD}Overall: CRITICAL RISK{C.RST}")
    elif high > 0:
        print(f"\n  {C.RED}{C.BOLD}Overall: HIGH RISK{C.RST}")
    elif med > 0:
        print(f"\n  {C.YELLOW}{C.BOLD}Overall: MODERATE RISK{C.RST}")
    elif low > 0:
        print(f"\n  {C.BLUE}{C.BOLD}Overall: LOW RISK{C.RST}")
    else:
        print(f"\n  {C.GREEN}{C.BOLD}Overall: MINIMAL RISK{C.RST}")

    pause()

# ─── 6. Keyboard Cache Detection ─────────────────────────────────────────────────

LOKIBOARD_DIR = "/data/media/0/Android/data/com.abifog.lokiboard/files"

def keyboard_cache_check():
    section("KEYBOARD CACHE DETECTION")

    print(f"\n  {C.CYAN}This test checks whether a third-party keyboard (LokiBoard)")
    print(f"  caches user input in plaintext on the device.{C.RST}\n")

    print(f"  {C.YELLOW}{C.BOLD}── Step 1: Type in the app ──{C.RST}")
    print(f"  {C.WHITE}Open the target app and type something using LokiBoard.{C.RST}")
    print(f"  {C.DIM}Make sure LokiBoard is set as the active keyboard.{C.RST}\n")

    try:
        input(f"  {C.GREEN}Press Enter when you have typed something ▸ {C.RST}")
    except (EOFError, KeyboardInterrupt):
        print()
        pause()
        return

    print(f"\n  {C.YELLOW}{C.BOLD}── Step 2: Enter the text you typed ──{C.RST}")
    try:
        search_str = input(f"  {C.GREEN}What did you type? ▸ {C.RST}").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        pause()
        return

    if not search_str:
        print(f"\n  {C.RED}[!] No search string provided.{C.RST}")
        pause()
        return

    print(f"\n  {C.YELLOW}{C.BOLD}── Step 3: Searching keyboard cache ──{C.RST}")
    print(f"  {C.DIM}Scanning: {LOKIBOARD_DIR}/lokiboard_files_*.txt{C.RST}\n")

    # Use adb_su to cat all matching cache files via glob
    content = adb_su(f"cat {LOKIBOARD_DIR}/lokiboard_files_*.txt 2>/dev/null")

    if _is_err(content):
        print(f"  {C.RED}[!] Could not read keyboard cache files.{C.RST}")
        print(f"  {C.DIM}Ensure LokiBoard is installed (com.abifog.lokiboard)")
        print(f"  and the device has root access.{C.RST}")
        pause()
        return

    if not content:
        print(f"  {C.YELLOW}[!] No LokiBoard cache files found or files are empty.{C.RST}")
        pause()
        return

    # Search for user string (case-insensitive)
    all_hits = []
    for i, line in enumerate(content.splitlines(), 1):
        if search_str.lower() in line.lower():
            all_hits.append((i, line.strip()))

    # ── Result ──────────────────────────────────────────────────────────────
    print(f"  {C.CYAN}{'═'*50}{C.RST}")
    if all_hits:
        print(f"  {C.RED}{C.BOLD}RESULT: Keyboard cache LEAKS user input!{C.RST}")
        print(f"  {C.DIM}The string \"{search_str}\" was found in LokiBoard cache.{C.RST}\n")
        for line_no, line_text in all_hits[:10]:
            display = line_text if len(line_text) <= 120 else line_text[:117] + "..."
            print(f"    {C.CYAN}Line {line_no}:{C.RST} {C.DIM}{display}{C.RST}")
        print(f"\n  {C.RED}Sensitive data typed via keyboard is stored in plaintext.{C.RST}")
        print(f"  {C.DIM}Risk: Passwords, PINs, and credentials may be recoverable.{C.RST}")
    else:
        print(f"  {C.GREEN}{C.BOLD}RESULT: String NOT found in keyboard cache{C.RST}")
        print(f"  {C.DIM}\"{search_str}\" was not found in any LokiBoard cache file.{C.RST}")

    pause()

# ─── 7. Logcat Live Monitor ──────────────────────────────────────────────────────

def logcat_monitor(pkg):
    section("LOGCAT LIVE MONITOR")

    print(f"\n  {C.CYAN}This monitors adb logcat in real-time and filters for a search string.")
    print(f"  Target app: {C.BOLD}{pkg}{C.RST}\n")

    print(f"  {C.YELLOW}{C.BOLD}── Enter search string ──{C.RST}")
    print(f"  {C.DIM}Logcat will be filtered for lines containing this text.{C.RST}")
    try:
        search_str = input(f"  {C.GREEN}Search string ▸ {C.RST}").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        pause()
        return

    if not search_str:
        print(f"\n  {C.RED}[!] No search string provided.{C.RST}")
        pause()
        return

    # Clear logcat buffer so we only see new entries
    subprocess.run(_adb_base() + ["logcat", "-c"], capture_output=True, timeout=5)

    print(f"\n  {C.GREEN}[+] Streaming logcat{C.RST}")
    print(f"  {C.DIM}Filtering for: \"{search_str}\"{C.RST}")
    print(f"  {C.YELLOW}Press Ctrl+C to stop.{C.RST}\n")
    print(f"  {C.CYAN}{'═'*50}{C.RST}\n")

    search_lower = search_str.lower()
    proc = None
    try:
        proc = subprocess.Popen(
            _adb_base() + ["logcat"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding='utf-8', errors='replace'
        )
        for line in proc.stdout:
            if search_lower in line.lower():
                safe_line = _terminal_safe(line).rstrip()
                highlighted = re.sub(
                    re.escape(search_str),
                    lambda m: f"{C.RED}{C.BOLD}{m.group()}{C.RST}",
                    safe_line,
                    flags=re.IGNORECASE
                )
                print(f"  > {highlighted}")
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"  {C.RED}[!] Logcat failed: {e}{C.RST}")
    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                proc.kill()

    print(f"\n\n  {C.CYAN}{'═'*50}{C.RST}")
    print(f"  {C.DIM}Logcat monitor stopped.{C.RST}")
    pause()

# ─── 8. Frida CodeShare ─────────────────────────────────────────────────────────

SCRIPT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frida_scripts")

def get_local_scripts():
    """Dynamically scan frida_scripts/ directory for .js files."""
    scripts = []
    if not os.path.isdir(SCRIPT_DIR):
        return scripts
    for filename in sorted(os.listdir(SCRIPT_DIR)):
        if filename.endswith(".js"):
            filepath = os.path.join(SCRIPT_DIR, filename)
            # Extract description from first comment block if available
            desc = ""
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read(2000)  # Read first 2KB for header
                    # Look for description in JSDoc or first comment
                    if "* " in content:
                        for line in content.split("\n"):
                            line = line.strip()
                            if line.startswith("* ") and not line.startswith("* @") and not line.startswith("*/"):
                                text = line[2:].strip()
                                if text and not text.startswith("Usage") and len(text) > 10:
                                    desc = text
                                    break
            except Exception:
                pass
            # Generate display name from filename
            name = filename.replace(".js", "").replace("_", " ").replace("-", " ").title()
            scripts.append({
                "name": name,
                "local": filename,
                "desc": desc or f"Local script: {filename}",
            })
    return scripts

# ── CodeShare Scripts (online) ───────────────────────────────────────
CODESHARE_SCRIPTS = [
    # ── SSL Pinning Bypass ──────────────────────────────────────────
    {
        "name": "SSL Bypass — Multi-Unpinning",
        "codeshare": "akabe1/frida-multiple-unpinning",
        "desc": "OkHttp, TrustManager, Flutter, Xamarin, etc.",
        "group": "SSL Pinning Bypass",
    },
    {
        "name": "SSL Bypass — Universal Android",
        "codeshare": "pcipolloni/universal-android-ssl-pinning-bypass-with-frida",
        "desc": "Universal Android SSL unpinning for HTTPS interception",
        "group": "SSL Pinning Bypass",
    },
    {
        "name": "SSL Bypass — Universal v2",
        "codeshare": "sowdust/universal-android-ssl-pinning-bypass-2",
        "desc": "Comprehensive SSL verification bypass for Android",
        "group": "SSL Pinning Bypass",
    },
    {
        "name": "SSL Bypass — Flutter TLS",
        "codeshare": "TheDauntless/disable-flutter-tls-v1",
        "desc": "Disable Flutter TLS verification (DIO SSL Pinning)",
        "group": "SSL Pinning Bypass",
    },
    {
        "name": "SSL Bypass — OkHttp4",
        "codeshare": "kooroshh/ssl-pinning-bypass-okhttp4",
        "desc": "Target OkHttp4 certificate pinning specifically",
        "group": "SSL Pinning Bypass",
    },
    # ── Root Detection Bypass ───────────────────────────────────────
    {
        "name": "Root Bypass — fridantiroot",
        "codeshare": "dzonerzy/fridantiroot",
        "desc": "Bypass common root detection (SafetyNet, RootBeer, etc.)",
        "group": "Root Detection Bypass",
    },
    {
        "name": "Root Bypass — Multi-Library",
        "codeshare": "KishorBal/multiple-root-detection-bypass",
        "desc": "CyberKatze IRoot, Stericson RootShell, JailMonkey, RootBeer",
        "group": "Root Detection Bypass",
    },
    {
        "name": "Root Bypass — RootBeer Specific",
        "codeshare": "ub3rsick/rootbeer-root-detection-bypass",
        "desc": "Targeted bypass for RootBeer library detection",
        "group": "Root Detection Bypass",
    },
    {
        "name": "Root Bypass — Xamarin Apps",
        "codeshare": "Gand3lf/xamarin-antiroot",
        "desc": "Disable root detection in Xamarin-based Android apps",
        "group": "Root Detection Bypass",
    },
    {
        "name": "Root Bypass — freeRASP/Talsec (RN)",
        "codeshare": "sasasec/freerasp-root-detection-bypass",
        "desc": "Bypass freeRASP: root, hooking, developer mode, ADB checks",
        "group": "Root Detection Bypass",
    },
    {
        "name": "Root Bypass — Talsec/RASP (Flutter)",
        "codeshare": "muhammadhikmahhusnuzon/bypass-talsec-rasp-and-root-detection",
        "desc": "Disable Talsec/FreeRASP in Flutter: root, debugger, events",
        "group": "Root Detection Bypass",
    },
    # ── Anti-Debug / Anti-Tamper ────────────────────────────────────
    {
        "name": "Anti-Debug Bypass",
        "codeshare": "aspect-security/anti-debug-bypass",
        "desc": "Bypass anti-debugging checks (ptrace, debugger detection)",
        "group": "Anti-Debug / Anti-Tamper",
    },
    {
        "name": "USB Debug Detection Bypass",
        "codeshare": "meerkati/universal-android-debugging-bypass",
        "desc": "Bypass USB debugging detection (Settings.Secure/Global)",
        "group": "Anti-Debug / Anti-Tamper",
    },
    {
        "name": "Developer Mode Bypass",
        "codeshare": "zionspike/bypass-developermode-check-android",
        "desc": "Run apps despite developer mode being active",
        "group": "Anti-Debug / Anti-Tamper",
    },
    {
        "name": "Anti-Frida Bypass",
        "codeshare": "enovella/anti-frida-bypass",
        "desc": "Libc strstr hook to hide frida/xposed strings",
        "group": "Anti-Debug / Anti-Tamper",
    },
    # ── Multi-Bypass (All-in-One) ───────────────────────────────────
    {
        "name": "Multi-Bypass — SSL + Root + Emulator",
        "codeshare": "fdciabdul/frida-multiple-bypass",
        "desc": "All-in-one: SSL pinning, root detection, emulator bypass",
        "group": "Multi-Bypass (All-in-One)",
    },
    {
        "name": "Multi-Bypass — Root + Emulator + SSL",
        "codeshare": "cubetech126/root-and-emulator-detection-bypass",
        "desc": "Extended fridantiroot + emulator + SSL pinning bypass",
        "group": "Multi-Bypass (All-in-One)",
    },
    {
        "name": "Multi-Bypass — OneRule",
        "codeshare": "h4rithd/onerule-by-h4rithd",
        "desc": "Root, debugger, SSL, network info bypass in one script",
        "group": "Multi-Bypass (All-in-One)",
    },
    # ── Biometric / Auth Bypass ─────────────────────────────────────
    {
        "name": "Biometric Bypass — Universal",
        "codeshare": "ax/universal-android-biometric-bypass",
        "desc": "Universal BiometricPrompt bypass, works on any Android version",
        "group": "Biometric / Auth Bypass",
    },
    {
        "name": "Biometric Bypass — Android 11+",
        "codeshare": "krapgras/android-biometric-bypass-update-android-11",
        "desc": "Biometric authentication bypass updated for Android 11+",
        "group": "Biometric / Auth Bypass",
    },
    # ── Monitoring — Network ────────────────────────────────────────
    {
        "name": "Traffic Interceptor",
        "codeshare": "Linuxinet/frida-traffic-interceptor",
        "desc": "Intercept network traffic, log API calls and WebView URLs",
        "group": "Monitoring — Network",
    },
    {
        "name": "OkHttp3 Interceptor",
        "codeshare": "owen800q/okhttp3-interceptor",
        "desc": "Network interception for OkHttp3 framework",
        "group": "Monitoring — Network",
    },
    {
        "name": "TCP Trace",
        "codeshare": "mame82/android-tcp-trace",
        "desc": "Log Android TCP connections with Java call traces",
        "group": "Monitoring — Network",
    },
    # ── Monitoring — Crypto / KeyStore ──────────────────────────────
    {
        "name": "Crypto Monitor",
        "codeshare": "fadeevab/intercept-android-apk-crypto-operations",
        "desc": "Intercept Java Crypto API calls — reveal keys and plaintext",
        "group": "Monitoring — Crypto",
    },
    {
        "name": "AES Monitor",
        "codeshare": "dzonerzy/aesinfo",
        "desc": "Display AES encryption/decryption activity at runtime",
        "group": "Monitoring — Crypto",
    },
    {
        "name": "KeyStore Extractor",
        "codeshare": "ceres-c/extract-keystore",
        "desc": "Extract KeyStore objects and passwords from Android apps",
        "group": "Monitoring — Crypto",
    },
    # ── Monitoring — Storage ────────────────────────────────────────
    {
        "name": "SharedPrefs Monitor",
        "codeshare": "aspect-security/sharedprefs-monitor",
        "desc": "Hook SharedPreferences read/write operations in real-time",
        "group": "Monitoring — Storage",
    },
    {
        "name": "EncryptedSharedPrefs Inspector",
        "codeshare": "Alkeraithe/encryptedsharedpreferences",
        "desc": "Inspect EncryptedSharedPreferences values before encryption",
        "group": "Monitoring — Storage",
    },
    {
        "name": "SQLite Monitor",
        "codeshare": "nicolo-travi/sqlite-query-monitor",
        "desc": "Monitor all SQLite queries executed by the app",
        "group": "Monitoring — Storage",
    },
    {
        "name": "File System Access Hook",
        "codeshare": "FrenchYeti/android-file-system-access-hook",
        "desc": "Observe file system accesses via java.io.File and libc hooks",
        "group": "Monitoring — Storage",
    },
    {
        "name": "Clipboard Monitor",
        "codeshare": "aspect-security/clipboard-monitor",
        "desc": "Monitor clipboard read/write to detect data leaks",
        "group": "Monitoring — Storage",
    },
    # ── Monitoring — Intents / WebView ──────────────────────────────
    {
        "name": "Intent Intercept",
        "codeshare": "promon-no/intent-intercept",
        "desc": "Intercept and log all intents sent by the application",
        "group": "Monitoring — Intents / WebView",
    },
    {
        "name": "Deep Link Observer",
        "codeshare": "leolashkevych/android-deep-link-observer",
        "desc": "Dump URI data from deep links",
        "group": "Monitoring — Intents / WebView",
    },
    {
        "name": "WebView Debugger",
        "codeshare": "lolicon/debug-webview",
        "desc": "Force setWebContentsDebuggingEnabled(true) on all WebViews",
        "group": "Monitoring — Intents / WebView",
    },
    # ── Tracing / Enumeration ───────────────────────────────────────
    {
        "name": "Android Tracer (raptor)",
        "codeshare": "0xdea/raptor-frida-android-trace",
        "desc": "Full-featured Java and native module tracer",
        "group": "Tracing / Enumeration",
    },
    {
        "name": "JNI Trace",
        "codeshare": "chame1eon/jnitrace",
        "desc": "Trace JNI API calls in Android apps",
        "group": "Tracing / Enumeration",
    },
    {
        "name": "List Loaded Classes",
        "codeshare": "BenGardiner/android-list-loaded-classes",
        "desc": "List all loaded classes in an Android app",
        "group": "Tracing / Enumeration",
    },
    {
        "name": "InMemoryDexClassLoader Dump",
        "codeshare": "cryptax/inmemorydexclassloader-dump",
        "desc": "Dump DEX bytes from InMemoryDexClassLoader (packed apps)",
        "group": "Tracing / Enumeration",
    },
]

def check_frida():
    """Check if frida is installed locally."""
    try:
        r = subprocess.run(["frida", "--version"], capture_output=True, text=True,
                           timeout=5, encoding='utf-8', errors='replace')
        return r.returncode == 0, r.stdout.strip()
    except Exception:
        return False, ""

def check_frida_server():
    """Check if frida-server is running on device."""
    out = adb_su("ps -A 2>/dev/null | grep frida-server")
    if _is_err(out):
        out = adb_su("ps | grep frida-server")
    return bool(out and "frida-server" in out)

FRIDA_SERVER_PATH = "/data/local/tmp/frida-server"

# Global frida connection mode: "-U" (USB default) or "-H ip:port" (custom)
FRIDA_CONN = "-U"


def _valid_host_port(address):
    """Validate a Frida host:port value before using it in a root shell."""
    if not address or address.count(":") < 1:
        return False
    host, port_text = address.rsplit(":", 1)
    if not re.fullmatch(r"[A-Za-z0-9.:[\]_-]+", host):
        return False
    if not port_text.isdigit():
        return False
    return 1 <= int(port_text) <= 65535


def start_frida_server(binary_path, listen_addr=None):
    """Start frida-server on device in background. Returns True if started."""
    if listen_addr and not _valid_host_port(listen_addr):
        return False
    binary_arg = shlex.quote(binary_path)
    # Kill any existing instance first
    adb_su("pkill -f frida-server 2>/dev/null")
    time.sleep(0.5)

    # nohup + redirect so frida-server survives adb shell exit
    # and adb shell returns immediately (no dangling stdout/stderr pipe)
    if listen_addr:
        bg_cmd = f"nohup {binary_arg} -l {shlex.quote(listen_addr)} >/dev/null 2>&1 &"
    else:
        bg_cmd = f"nohup {binary_arg} >/dev/null 2>&1 &"

    # Start in background via su
    adb_su(f"chmod 755 {binary_arg}")
    adb_su(bg_cmd, timeout=10)
    time.sleep(1.5)

    # Verify it started
    return check_frida_server()

def frida_codeshare(pkg):
    section("FRIDA CODESHARE")

    # ── Check local frida ────────────────────────────────────────────────────
    frida_ok, frida_ver = check_frida()

    if frida_ok:
        status_line("Frida (local)", f"v{frida_ver}", C.GREEN)
    else:
        status_line("Frida (local)", "NOT INSTALLED", C.RED)
        print(f"  {C.DIM}  Install: pip install frida-tools{C.RST}")
        print(f"\n  {C.RED}[!] Frida is required. Install with: pip install frida-tools{C.RST}")
        pause()
        return

    # ── Check frida-server on device ─────────────────────────────────────────
    frida_srv = check_frida_server()

    if frida_srv:
        status_line("Frida-server", "Running on device", C.GREEN)
    else:
        status_line("Frida-server", "NOT RUNNING — starting automatically...", C.YELLOW)
        if start_frida_server(FRIDA_SERVER_PATH):
            print(f"  {C.GREEN}[+] Frida-server started{C.RST}")
            frida_srv = True
        else:
            print(f"  {C.RED}[-] Failed to start frida-server{C.RST}")
            print(f"  {C.DIM}  Make sure {FRIDA_SERVER_PATH} exists on the device.{C.RST}")
            print(f"  {C.DIM}  Push it once: adb push frida-server {FRIDA_SERVER_PATH}{C.RST}")

    if not frida_srv:
        warn_line("Frida-server not running — scripts may fail to connect")

    status_line("Frida connect", FRIDA_CONN, C.CYAN)

    # ── Warn on frida client/server version mismatch ─────────────────────────
    if frida_ok and frida_srv:
        srv_ver = adb_su(f"{FRIDA_SERVER_PATH} --version", timeout=10)
        if not _is_err(srv_ver):
            srv_ver = srv_ver.splitlines()[0].strip()
            local_ver = frida_ver.strip()
            if srv_ver and local_ver and srv_ver != local_ver:
                print(f"  {C.YELLOW}[!] Frida version mismatch: client v{local_ver} vs server v{srv_ver}{C.RST}")
                print(f"  {C.DIM}  Connections may fail — use matching frida/frida-server versions.{C.RST}")

    # ── Show script menu ─────────────────────────────────────────────────────
    while True:
        print(f"\n  {C.CYAN}{C.BOLD}── Frida Scripts for: {pkg} ──{C.RST}")

        # Build display list — dynamically scan local scripts + static codeshare
        display_order = []  # list of script dicts in display order
        local_scripts = get_local_scripts()  # Dynamic scan of frida_scripts/
        codeshare_scripts = CODESHARE_SCRIPTS

        idx = 1
        if local_scripts:
            print(f"\n  {C.MAGENTA}{C.BOLD}  Local Scripts (frida_scripts/){C.RST}")
            for script in local_scripts:
                display_order.append(script)
                print(f"  {C.YELLOW}[{idx:2d}]{C.RST} {C.WHITE}{script['name']}{C.RST}")
                print(f"       {C.DIM}{script['desc']}{C.RST}")
                idx += 1
        else:
            print(f"\n  {C.DIM}  No local scripts found in frida_scripts/{C.RST}")

        if codeshare_scripts:
            current_group = None
            for script in codeshare_scripts:
                grp = script.get("group", "Other")
                if grp != current_group:
                    current_group = grp
                    print(f"\n  {C.MAGENTA}{C.BOLD}  {grp}{C.RST}")
                display_order.append(script)
                print(f"  {C.YELLOW}[{idx:2d}]{C.RST} {C.WHITE}{script['name']}{C.RST}")
                print(f"       {C.DIM}{script['desc']}{C.RST}")
                idx += 1

        print(f"\n  {C.YELLOW}[c]{C.RST}  {C.WHITE}Custom codeshare URL{C.RST}")
        print(f"  {C.DIM}[0]  Back{C.RST}")

        choice = input(f"\n  {C.GREEN}Select script ▸ {C.RST}").strip()

        if choice == "0":
            return
        elif choice.lower() == "c":
            cs_path = input(f"  {C.GREEN}Enter codeshare path (author/script) ▸ {C.RST}").strip()
            if not cs_path:
                continue
            selected = {"codeshare": cs_path, "name": cs_path}
        else:
            try:
                sel_idx = int(choice) - 1
                if not (0 <= sel_idx < len(display_order)):
                    print(f"  {C.RED}Invalid selection.{C.RST}")
                    continue
                selected = display_order[sel_idx]
            except ValueError:
                print(f"  {C.RED}Invalid input.{C.RST}")
                continue

        # Spawn or attach
        print(f"\n  {C.CYAN}{C.BOLD}── Launch Mode ──{C.RST}")
        print(f"  {C.YELLOW}[1]{C.RST} Spawn (restart app with Frida)")
        print(f"  {C.YELLOW}[2]{C.RST} Attach (hook into running app)")
        mode = input(f"\n  {C.GREEN}Mode ▸ {C.RST}").strip()
        spawn = mode == "1"

        # Build command depending on local vs codeshare
        frida_conn = FRIDA_CONN
        # Build frida command as argument list
        frida_args = ["frida"]
        if "local" in selected:
            script_path = os.path.join(SCRIPT_DIR, selected["local"])
            if not os.path.exists(script_path):
                print(f"  {C.RED}[!] Script not found: {script_path}{C.RST}")
                continue
            frida_args += shlex.split(frida_conn)
            if spawn:
                frida_args += ["-f", pkg, "-l", script_path]
            else:
                frida_args += [pkg, "-l", script_path]
        else:
            cs = selected["codeshare"]
            frida_args += ["--codeshare", cs] + shlex.split(frida_conn)
            if spawn:
                frida_args += ["-f", pkg]
            else:
                frida_args += [pkg]

        print(f"\n  {C.CYAN}Running: {C.BOLD}{' '.join(frida_args)}{C.RST}")
        print(f"  {C.DIM}Press Ctrl+C to stop Frida session{C.RST}\n")

        try:
            subprocess.run(frida_args)
        except KeyboardInterrupt:
            print(f"\n  {C.YELLOW}Frida session ended.{C.RST}")

        again = input(f"\n  {C.GREEN}Run another script? (y/n) ▸ {C.RST}").strip().lower()
        if again != "y":
            return

# ─── 9. Emulation Detection Check ──────────────────────────────────────────────

EMU_DETECTION_KEYWORDS = [
    ("Emulator String Checks", [
        "google_sdk", "Android SDK built for",
        "Genymotion", "sdk_google", "vbox86p", "vbox86",
        "bluestacks", "Memu", "LDPlayer",
        "sdk_gphone", "NoxPlayer",
        "Droid4X", "iToolAB", "TiantianVM",
    ]),
    ("WSA / Windows Subsystem", [
        "windows_x86_64", "windows_arm64",
        "Windows Subsystem for Android",
        "ro.hardware.windows",
    ]),
    ("AVD / Android Studio", [
        "sdk_gphone64", "sdk_gphone_x86", "sdk_gphone_arm64",
        "emulator64_x86_64", "emulator64_arm64",
        "generic_x86", "generic_x86_64", "generic_arm64",
        "Android Emulator",
    ]),
    ("Telephony Checks", [
        "000000000000000", "15555215554", "15555215556",
    ]),
    ("Emulator Files/Paths", [
        "/dev/socket/qemud", "/dev/qemu_pipe",
        "libc_malloc_debug_qemu", "/sys/qemu_trace",
        "ueventd.android_x86", "/dev/socket/genyd",
    ]),
    ("Goldfish/Ranchu Drivers", [
        "/dev/goldfish_pipe", "init.goldfish", "init.ranchu",
        "fstab.goldfish", "fstab.ranchu",
    ]),
    ("QEMU Detection", [
        "ro.kernel.qemu", "ro.hardware.virtual",
        "init.svc.qemud", "ro.kernel.qemu.gles",
    ]),
    ("Emulator IP Addresses", [
        "10.0.2.15", "10.0.2.2", "10.0.3.2",
        "10.0.3.15",
    ]),
    ("Detection Method Names", [
        "isEmulator", "detectEmulator", "checkEmulator",
        "isRunningOnEmulator", "isVirtualDevice",
    ]),
]

def emulation_detection_check(pkg):
    section("EMULATION DETECTION CHECK")

    print(f"\n  {C.CYAN}Checking emulator detection in: {C.BOLD}{pkg}{C.RST}\n")

    work_dir, decompiled_dir = _pull_and_decompile(pkg)
    if not decompiled_dir:
        pause()
        return

    fw_info = detect_framework(decompiled_dir)
    _print_framework_info(fw_info)

    found_any = False
    found_count = 0
    total_checks = len(EMU_DETECTION_KEYWORDS)

    print(f"\n  {C.YELLOW}{C.BOLD}── Keyword Search ──{C.RST}")

    results, file_count = _search_decompiled(decompiled_dir, EMU_DETECTION_KEYWORDS, framework=fw_info["framework"])
    info_line("Scanned files", f"{file_count} files")

    for group_name, matches in results.items():
        if matches:
            found_any = True
            found_count += 1
            print(f"\n  {C.GREEN}[FOUND]{C.RST} {C.BOLD}{group_name}{C.RST} — {len(matches)} match(es)")
            seen = set()
            for rel_path, line_no, line_text, keyword in matches:
                key = f"{rel_path}:{line_no}"
                if key not in seen:
                    seen.add(key)
                    print(f"    {C.CYAN}{rel_path}:{line_no}{C.RST}")
                    display = line_text if len(line_text) <= 120 else line_text[:117] + "..."
                    print(f"    {C.DIM}{display}{C.RST}")
                    print(f"    {C.YELLOW}keyword: {keyword}{C.RST}")
        else:
            print(f"\n  {C.RED}[NOT FOUND]{C.RST} {group_name}")

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n  {C.CYAN}{'═'*50}{C.RST}")
    if found_any:
        print(f"  {C.GREEN}{C.BOLD}RESULT: Emulator Detection DETECTED{C.RST}")
        print(f"  {C.DIM}Found {found_count}/{total_checks} indicator categories.{C.RST}")
        if found_count >= 7:
            print(f"  {C.DIM}App has STRONG emulator detection — likely won't run on emulators.{C.RST}")
        elif found_count >= 4:
            print(f"  {C.DIM}App has MODERATE emulator detection — may partially work on emulators.{C.RST}")
        else:
            print(f"  {C.DIM}App has BASIC emulator detection — some emulator checks present.{C.RST}")
        print(f"  {C.DIM}Review file locations above to confirm true/false positives.{C.RST}")
        print(f"  {C.DIM}Bypassing may require Frida, patching, or a physical device.{C.RST}")
    else:
        print(f"  {C.RED}{C.BOLD}RESULT: Emulator Detection NOT DETECTED{C.RST}")
        print(f"  {C.DIM}This app does not appear to check for emulators.{C.RST}")

    pause()

# ─── 10. Anti-Tamper & Security SDK Detection Check ─────────────────────────────

ANTI_TAMPER_KEYWORDS = [
    ("Anti-Debug Checks", [
        "Debug;->isDebuggerConnected", "TracerPid",
        "/proc/self/status", "ptrace",
        "isDebugInspectorInfoEnabled",
    ]),
    ("Frida Detection", [
        "frida-server", "frida-agent", "LIBFRIDA",
        "frida-gadget", "re.frida.server",
    ]),
    ("VKey VGuard SDK", [
        "com/vkey/android/vtap", "com.vkey.android.vguard",
        "VosWrapper;->", "VosWrapperBase;->",
        "VGuardLifecycleCallback",
    ]),
    ("Zimperium zDefend", [
        "com.zimperium", "zDefend", "ZDefend",
        "z9core", "z9detect", "ZIAMManager",
    ]),
    ("Promon SHIELD", [
        "com.promon.shield", "PromonShield", "ShieldConfig",
        "Lcom/promon/",
    ]),
    ("Guardsquare DexGuard", [
        "DexGuard", "com.guardsquare", "GuardSquare",
        "iXGuard", "ThreatCast",
    ]),
    ("AppSealing", [
        "com.inka.appsealing", "AppSealing", "inkaentworks",
    ]),
    ("Arxan / Digital.ai", [
        "Arxan", "digital.ai", "TransformIT",
        "GuardIT", "EnsureIT",
    ]),
    ("Liapp", [
        "Liapp", "LIAPP", "com.lockincomp", "LockInComp",
    ]),
    ("Talsec freeRASP", [
        "freeRASP", "com.aheaditec.talsec", "ThreatReactor",
    ]),
    ("ByteDance AppShield", [
        "com.bytedance.appshield", "BDShield", "bdshield",
    ]),
    ("LexisNexis ThreatMetrix", [
        "com.lexisnexisrisk.threatmetrix", "TMXProfiling",
        "TMXConfig", "TMXStrongAuth", "TMXStatusResult",
    ]),
    ("BehavioSec SDK", [
        "com.behaviosec", "BehavioSecCollector", "BehavioSecClient",
        "BehavioButtonSDK",
    ]),
    ("VPN Detection", [
        "vpnConnected", "TRANSPORT_VPN",
        "NetworkCapabilities;->hasTransport",
    ]),
    ("Overlay Detection", [
        "canDrawOverlays", "TYPE_APPLICATION_OVERLAY",
    ]),
    ("Sideload Detection", [
        "getInstallerPackageName", "getInstallSourceInfo",
        "com.android.vending",
    ]),
    ("USB Debug Detection", [
        "adb_enabled", "development_settings_enabled",
    ]),
    ("Tamper / Integrity Checks", [
        "PackageInfo;->signatures", "GET_SIGNATURES",
        "checkSignatures", "SigningInfo",
    ]),
    ("Flutter Security Plugins", [
        "freerasp", "flutter_secure_storage",
        "flutter_screenprotector",
    ]),
    ("React Native Security", [
        "react-native-code-push", "CodePush",
        "react-native-integrity",
    ]),
]

def anti_tamper_check(pkg):
    section("ANTI-TAMPER & SDK DETECTION")

    print(f"\n  {C.CYAN}Checking anti-tamper & security SDKs in: {C.BOLD}{pkg}{C.RST}\n")

    work_dir, decompiled_dir = _pull_and_decompile(pkg)
    if not decompiled_dir:
        pause()
        return

    fw_info = detect_framework(decompiled_dir)
    _print_framework_info(fw_info)

    found_any = False
    found_count = 0

    fw = fw_info["framework"]
    skip = set()
    if fw != "Flutter":
        skip |= _FLUTTER_GROUPS
    if fw != "React Native":
        skip |= _RN_GROUPS
    applicable = sum(1 for gn, _ in ANTI_TAMPER_KEYWORDS if gn not in skip)

    print(f"\n  {C.YELLOW}{C.BOLD}── Keyword Search ──{C.RST}")

    results, file_count = _search_decompiled(decompiled_dir, ANTI_TAMPER_KEYWORDS, framework=fw_info["framework"])
    info_line("Scanned files", f"{file_count} files")

    for group_name, matches in results.items():
        if group_name in skip:
            continue
        if matches:
            found_any = True
            found_count += 1
            print(f"\n  {C.GREEN}[FOUND]{C.RST} {C.BOLD}{group_name}{C.RST} — {len(matches)} match(es)")
            seen = set()
            for rel_path, line_no, line_text, keyword in matches:
                key = f"{rel_path}:{line_no}"
                if key not in seen:
                    seen.add(key)
                    print(f"    {C.CYAN}{rel_path}:{line_no}{C.RST}")
                    display = line_text if len(line_text) <= 120 else line_text[:117] + "..."
                    print(f"    {C.DIM}{display}{C.RST}")
                    print(f"    {C.YELLOW}keyword: {keyword}{C.RST}")
        else:
            print(f"\n  {C.RED}[NOT FOUND]{C.RST} {group_name}")

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n  {C.CYAN}{'═'*50}{C.RST}")
    if found_any:
        print(f"  {C.GREEN}{C.BOLD}RESULT: Anti-Tamper / Security SDKs DETECTED{C.RST}")
        print(f"  {C.DIM}Found {found_count}/{applicable} indicator categories.{C.RST}")
        if found_count >= 7:
            print(f"  {C.DIM}App has HEAVY security SDK integration — multi-layered protection.{C.RST}")
        elif found_count >= 4:
            print(f"  {C.DIM}App has MODERATE security integration — several SDK protections.{C.RST}")
        else:
            print(f"  {C.DIM}App has BASIC security checks — limited SDK protections.{C.RST}")
        print(f"  {C.DIM}Review file locations above to confirm true/false positives.{C.RST}")
        print(f"  {C.DIM}Bypassing may require Frida with the Universal Bypass script.{C.RST}")
    else:
        print(f"  {C.RED}{C.BOLD}RESULT: Anti-Tamper / Security SDKs NOT DETECTED{C.RST}")
        print(f"  {C.DIM}This app does not appear to use security SDKs or anti-tamper.{C.RST}")

    pause()

# ─── Testcases for Fun ────────────────────────────────────────────────────────────

# ─── ADB Backup Extraction (allowBackup=true vector) ─────────────────────────────

def _find_symlinked_path_component(path):
    """Return a symlink at or above *path*, including broken symlinks."""
    cursor = os.path.abspath(os.fspath(path))
    while True:
        if os.path.lexists(cursor) and os.path.islink(cursor):
            return cursor
        parent = os.path.dirname(cursor)
        if parent == cursor:
            return None
        cursor = parent


def _filesystem_is_case_sensitive(directory):
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


def _unpack_ab(ab_path, out_dir):
    """Parse an Android .ab backup and extract its tar payload into out_dir.

    Returns (file_count, error_message_or_None). Extraction is bounded and all
    archive entries are confined to out_dir."""
    try:
        if os.path.getsize(ab_path) > MAX_BACKUP_BYTES:
            return 0, f"backup exceeds {MAX_BACKUP_BYTES} byte safety limit"
        source = open(ab_path, "rb")
    except OSError as e:
        return 0, f"could not read backup file: {e}"

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
                return 0, f"backup is encrypted ({enc}); password-protected backups are not supported"

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
                        remaining = MAX_BACKUP_PAYLOAD_BYTES - total_payload
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
                    if total_payload > MAX_BACKUP_PAYLOAD_BYTES:
                        return 0, "backup payload exceeds extraction safety limit"
                    payload_file.write(output)

            if decompressor is not None:
                remaining = MAX_BACKUP_PAYLOAD_BYTES - total_payload
                tail = decompressor.flush(remaining + 1)
                total_payload += len(tail)
                if total_payload > MAX_BACKUP_PAYLOAD_BYTES:
                    return 0, "backup payload exceeds extraction safety limit"
                payload_file.write(tail)
                if not decompressor.eof:
                    return 0, "payload decompression failed: truncated zlib stream"

            if total_payload == 0:
                return 0, "backup contains no data (app disallows backup or returned an empty set)"

            payload_file.seek(0)
            output_root = os.path.abspath(out_dir)
            # A symlink used as (or above) the logical extraction root defeats
            # descendant-only checks: an otherwise safe member would be written
            # outside the directory named by the caller.
            symlink_component = _find_symlinked_path_component(output_root)
            if symlink_component:
                return 0, (
                    "refusing symlinked backup output path component: "
                    f"{symlink_component}"
                )
            os.makedirs(output_root, exist_ok=True)
            case_sensitive_output = _filesystem_is_case_sensitive(output_root)

            with tarfile.open(fileobj=payload_file, mode="r:*") as tar:
                members = []
                destination_trie = {}
                total_size = 0
                for member in tar:
                    if not member.isfile():
                        continue
                    if len(members) >= MAX_BACKUP_FILES:
                        return 0, "backup contains too many files"
                    if member.size < 0 or member.size > MAX_BACKUP_FILE_BYTES:
                        return 0, f"backup member exceeds per-file safety limit: {member.name}"
                    total_size += member.size
                    if total_size > MAX_BACKUP_PAYLOAD_BYTES:
                        return 0, "backup members exceed total extraction safety limit"

                    name = member.name
                    if (not name or name.startswith(('/', '\\')) or '\\' in name
                            or '\x00' in name):
                        return 0, f"unsafe backup member path: {name!r}"
                    parts = name.split("/")
                    if any(part in ("", ".", "..") or ":" in part for part in parts):
                        return 0, f"unsafe backup member path: {name!r}"
                    destination = os.path.abspath(os.path.join(output_root, *parts))
                    if os.path.commonpath((output_root, destination)) != output_root:
                        return 0, f"unsafe backup member path: {name!r}"
                    # Reject duplicate paths and file/directory prefix conflicts
                    # before writing anything (for example, both ``a`` and
                    # ``a/b``). Case-folding also avoids partial extraction on
                    # Windows-style case-insensitive destinations.
                    trie_node = destination_trie
                    normalized_parts = (
                        parts if case_sensitive_output
                        else [item.casefold() for item in parts]
                    )
                    for part in normalized_parts:
                        if None in trie_node:
                            return 0, f"conflicting backup member path: {name!r}"
                        trie_node = trie_node.setdefault(part, {})
                    if None in trie_node:
                        return 0, f"duplicate backup member path: {name!r}"
                    if trie_node:
                        return 0, f"conflicting backup member path: {name!r}"
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
                            if os.path.lexists(cursor) and os.path.islink(cursor):
                                return 0, f"refusing to extract through symlink: {cursor}"
                            if (os.path.lexists(cursor)
                                    and not os.path.isdir(cursor)):
                                return 0, f"backup parent path is not a directory: {cursor}"
                    if os.path.lexists(destination):
                        return 0, f"refusing to overwrite existing path: {destination}"

                count = 0
                for member, destination in members:
                    parent = os.path.dirname(destination)
                    os.makedirs(parent, exist_ok=True)
                    extracted = tar.extractfile(member)
                    if extracted is None:
                        continue
                    with extracted, open(destination, "xb") as output:
                        shutil.copyfileobj(extracted, output, length=1024 * 1024)
                    count += 1

                return count, None
    except (OSError, tarfile.TarError, zlib.error) as e:
        return 0, f"backup extraction failed: {e}"


def backup_extraction(pkg):
    """Demonstrate data exfiltration via 'adb backup' when allowBackup=true.

    Runs a (non-root) backup, unpacks the .ab archive, and scans the contents
    for secrets/PII with the existing detection engine. Findings feed the report."""
    section("ADB BACKUP EXTRACTION")
    print(f"\n  {C.CYAN}Target: {C.BOLD}{pkg}{C.RST}")
    print(f"  {C.DIM}Demonstrates the allowBackup=true data-extraction vector (no root needed).{C.RST}\n")

    # ── Fast allowBackup check via dumpsys flags (no decompile) ───────────────
    flags_out = adb_su(f"dumpsys package {pkg} | grep -i flags", timeout=15)
    allow_backup = True
    if not _is_err(flags_out):
        allow_backup = "ALLOW_BACKUP" in flags_out
    if not allow_backup:
        print(f"  {C.YELLOW}[!] allowBackup appears DISABLED for this app.{C.RST}")
        print(f"  {C.DIM}The backup will most likely be empty, but you can still try.{C.RST}")
        try:
            cont = input(f"\n  {C.GREEN}Attempt backup anyway? [y/N] ▸ {C.RST}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            pause()
            return
        if cont != "y":
            pause()
            return
    else:
        print(f"  {C.GREEN}[+] allowBackup is enabled — app data is backup-eligible.{C.RST}")

    out_base = os.path.join(os.getcwd(), "backups")
    os.makedirs(out_base, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ab_path = os.path.join(out_base, f"{pkg}_{ts}.ab")

    # ── Run adb backup (interactive: device shows a confirmation dialog) ──────
    print(f"\n  {C.YELLOW}{C.BOLD}── On the device ──{C.RST}")
    print(f"  {C.WHITE}A backup confirmation will appear on the device screen.{C.RST}")
    print(f"  {C.WHITE}Tap {C.BOLD}\"Back up my data\"{C.RST}{C.WHITE} and leave the password field EMPTY.{C.RST}")
    print(f"  {C.DIM}(Unlock the device first if the screen is off.){C.RST}")
    try:
        input(f"\n  {C.GREEN}Press Enter to start the backup ▸ {C.RST}")
    except (EOFError, KeyboardInterrupt):
        print()
        pause()
        return

    print(f"\n  {C.CYAN}[*] Running: adb backup -f {os.path.basename(ab_path)} -noapk -noshared {pkg}{C.RST}")
    print(f"  {C.DIM}Waiting for on-device confirmation...{C.RST}")
    try:
        # No output capture: let the user see adb's prompt; the dialog is on-device.
        subprocess.run(
            _adb_base() + ["backup", "-f", ab_path, "-noapk", "-noshared", pkg],
            timeout=180,
        )
    except subprocess.TimeoutExpired:
        print(f"  {C.RED}[!] Backup timed out — confirmation may not have been tapped.{C.RST}")
        pause()
        return
    except Exception as e:
        print(f"  {C.RED}[!] adb backup failed: {e}{C.RST}")
        pause()
        return

    if not os.path.exists(ab_path) or os.path.getsize(ab_path) == 0:
        print(f"  {C.RED}[!] No backup data produced (declined, or backup restricted on this device).{C.RST}")
        print(f"  {C.DIM}Note: adb backup is deprecated/limited on Android 12+ and many OEM builds.{C.RST}")
        pause()
        return

    ab_size = os.path.getsize(ab_path)
    print(f"  {C.GREEN}[+] Backup written: {ab_path} ({ab_size // 1024} KB){C.RST}")

    # ── Unpack the .ab ───────────────────────────────────────────────────────
    extract_dir = os.path.join(out_base, f"{pkg}_{ts}_unpacked")
    os.makedirs(extract_dir, exist_ok=True)
    print(f"  {C.DIM}Unpacking backup archive...{C.RST}")
    count, err = _unpack_ab(ab_path, extract_dir)
    if err:
        print(f"  {C.RED}[!] {err}{C.RST}")
        pause()
        return
    if count == 0:
        print(f"  {C.YELLOW}[!] Backup unpacked but contained no files.{C.RST}")
        pause()
        return
    print(f"  {C.GREEN}[+] Extracted {count} file(s) → {extract_dir}{C.RST}")

    # Record the exploitable-backup finding itself
    report.add_finding(
        "Backup: Data Extraction",
        "App data extracted via adb backup",
        "HIGH", "HIGH",
        f"Extracted {count} file(s) from {pkg} using 'adb backup' without root. allowBackup is enabled.",
        "Set android:allowBackup=false, or define dataExtractionRules/fullBackupContent to exclude sensitive data.",
        "MASVS-STORAGE-1", "CWE-530",
    )

    # ── Scan extracted files for secrets / PII ───────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}── Scanning Extracted Data ──{C.RST}")
    secrets_files = 0
    pii_files = 0
    for root, dirs, files in os.walk(extract_dir):
        for fn in files:
            fpath = os.path.join(root, fn)
            try:
                if os.path.getsize(fpath) > 2_000_000:  # skip very large files
                    continue
                with open(fpath, "r", errors="ignore") as fh:
                    content = fh.read()
            except Exception:
                continue
            if not content:
                continue
            # Binary heuristic: skip files with many non-printable bytes
            sample = content[:512]
            non_print = sum(1 for ch in sample if ord(ch) < 32 and ch not in "\n\r\t")
            if sample and non_print > len(sample) * 0.3:
                continue

            rel = os.path.relpath(fpath, extract_dir)
            secret_hits = [value[:120] for value in
                           _find_secret_matches(content, per_pattern_limit=3)]
            pii_hits = _scan_pii(content)

            if secret_hits or pii_hits:
                print(f"\n    {C.CYAN}{rel}{C.RST}")
            if secret_hits:
                secrets_files += 1
                for sh in secret_hits[:5]:
                    print(f"      {C.RED}⚠ Potential secret: {_redact(sh)}{C.RST}")
                report.add_finding(
                    "Backup: Sensitive Data", f"Secret in backup: {rel}",
                    "HIGH", "MEDIUM",
                    f"Secret pattern found in backed-up file {rel}: {_redact(secret_hits[0])}",
                    "Exclude sensitive files from backup; never store secrets unencrypted in app data.",
                    "MASVS-STORAGE-1", "CWE-312",
                )
            if pii_hits:
                pii_files += 1
                for label, val in pii_hits[:5]:
                    print(f"      {C.RED}⚠ PII ({label}): {_redact(val)}{C.RST}")
                report.add_finding(
                    "Backup: Sensitive Data", f"PII in backup: {rel}",
                    "MEDIUM", "MEDIUM",
                    f"PII ({pii_hits[0][0]}) found in backed-up file {rel}.",
                    "Exclude personal data from backups or encrypt sensitive data at rest.",
                    "MASVS-STORAGE-2", "CWE-359",
                )

    # ── Result ───────────────────────────────────────────────────────────────
    print(f"\n  {C.CYAN}{'═'*50}{C.RST}")
    if secrets_files or pii_files:
        print(f"  {C.RED}{C.BOLD}RESULT: Backup exposes sensitive data{C.RST}")
        print(f"  {C.DIM}Secrets in {secrets_files} file(s), PII in {pii_files} file(s).{C.RST}")
        print(f"  {C.DIM}Anyone with USB/ADB access can extract this without root.{C.RST}")
    else:
        print(f"  {C.GREEN}{C.BOLD}RESULT: Backup succeeded but no obvious secrets/PII found{C.RST}")
        print(f"  {C.DIM}Data still extracted to {extract_dir} — review manually.{C.RST}")
    print(f"  {C.DIM}Findings added to the report (export with [r]).{C.RST}")
    pause()


def fun_testcases(pkg):
    section("TESTCASES FOR FUN")

    while True:
        print(f"\n  {C.CYAN}{C.BOLD}── Test Cases for: {pkg} ──{C.RST}\n")
        print(f"  {C.YELLOW}[1]{C.RST} {C.WHITE}Launch Exported Activities{C.RST}")
        print(f"      {C.DIM}Start each exported activity for manual access-control review{C.RST}")
        print(f"  {C.YELLOW}[2]{C.RST} {C.WHITE}Launch Exported Services{C.RST}")
        print(f"      {C.DIM}Start each exported service{C.RST}")
        print(f"  {C.YELLOW}[3]{C.RST} {C.WHITE}Launch Broadcast Receivers{C.RST}")
        print(f"      {C.DIM}Send empty broadcast to each exported receiver{C.RST}")
        print(f"  {C.YELLOW}[4]{C.RST} {C.WHITE}Query Content Providers{C.RST}")
        print(f"      {C.DIM}Query exported providers for data leakage{C.RST}")
        print(f"  {C.YELLOW}[5]{C.RST} {C.WHITE}Clipboard Spy{C.RST}")
        print(f"      {C.DIM}Read clipboard after user copies sensitive data{C.RST}")
        print(f"  {C.YELLOW}[6]{C.RST} {C.WHITE}Dev/Staging URL Finder{C.RST}")
        print(f"      {C.DIM}Search decompiled code for internal/dev URLs{C.RST}")
        print(f"  {C.YELLOW}[7]{C.RST} {C.WHITE}Repackaging Integrity Check{C.RST}")
        print(f"      {C.DIM}Launch patched APK and check if integrity checks kill it{C.RST}")
        print(f"  {C.YELLOW}[8]{C.RST} {C.WHITE}ADB Backup Extraction{C.RST}")
        print(f"      {C.DIM}Pull & unpack app data via adb backup (allowBackup vector){C.RST}")
        print(f"\n  {C.DIM}[0] Back{C.RST}")

        choice = input(f"\n  {C.GREEN}Select test ▸ {C.RST}").strip()

        if choice == "0":
            return

        # ── Sub-options 1-3 need the manifest ────────────────────────────
        if choice in ("1", "2", "3", "4"):
            work_dir, decompiled_dir = _pull_and_decompile(pkg)
            if not decompiled_dir:
                pause()
                continue
            manifest = _parse_manifest(decompiled_dir)
            if not manifest["parsed"]:
                print(f"  {C.RED}[!] Could not read AndroidManifest.xml{C.RST}")
                pause()
                continue
            exported = manifest["exported"]

        if choice == "1":
            # ── Launch Exported Activities ────────────────────────────────
            print(f"\n  {C.YELLOW}{C.BOLD}── Launching Exported Activities ──{C.RST}\n")
            acts = exported["activity"]
            if not acts:
                print(f"  {C.DIM}No exported activities found.{C.RST}")
            else:
                print(f"  {C.CYAN}Found {len(acts)} exported activit{'y' if len(acts) == 1 else 'ies'}{C.RST}")

                # Show list with actions
                for i, comp in enumerate(acts, 1):
                    action_str = f" {C.DIM}actions: {', '.join(comp['actions'])}{C.RST}" if comp['actions'] else ""
                    print(f"    {C.YELLOW}[{i}]{C.RST} {comp['name']}{action_str}")

                print(f"\n  {C.DIM}[a] Launch all  [0] Back{C.RST}")
                print(f"  {C.DIM}Add extras: append after number, e.g. '1 --es key value --ei num 42'{C.RST}")
                sel = input(f"\n  {C.GREEN}Select ▸ {C.RST}").strip()
                if sel == "0":
                    continue

                targets = []
                extra_args = ""
                if sel.lower().startswith("a"):
                    targets = acts
                    rest = sel[1:].strip()
                    if rest:
                        extra_args = rest
                else:
                    parts = sel.split(maxsplit=1)
                    try:
                        idx = int(parts[0]) - 1
                        if 0 <= idx < len(acts):
                            targets = [acts[idx]]
                        extra_args = parts[1] if len(parts) > 1 else ""
                    except (ValueError, IndexError):
                        print(f"  {C.RED}Invalid selection.{C.RST}")

                for comp in targets:
                    name = comp['name']
                    # Build command: use first action from intent-filter if available
                    cmd = f"am start -n {shlex.quote(f'{pkg}/{name}')}"
                    if comp['actions']:
                        cmd += f" -a {shlex.quote(comp['actions'][0])}"
                    if extra_args:
                        cmd += f" {extra_args}"
                    print(f"\n  {C.DIM}$ {cmd}{C.RST}")
                    out = adb_shell(cmd, timeout=10)
                    if "Error" in out or "Exception" in out:
                        print(f"  {C.RED}[✗]{C.RST} {name}")
                        print(f"      {C.DIM}{out[:200]}{C.RST}")
                    else:
                        print(f"  {C.GREEN}[✓]{C.RST} {name} {C.YELLOW}— externally launchable; review access controls{C.RST}")
                    time.sleep(0.5)
            pause()

        elif choice == "2":
            # ── Launch Exported Services ──────────────────────────────────
            print(f"\n  {C.YELLOW}{C.BOLD}── Launching Exported Services ──{C.RST}\n")
            svcs = exported["service"]
            if not svcs:
                print(f"  {C.DIM}No exported services found.{C.RST}")
            else:
                print(f"  {C.CYAN}Found {len(svcs)} exported service{'s' if len(svcs) != 1 else ''}{C.RST}")

                for i, comp in enumerate(svcs, 1):
                    action_str = f" {C.DIM}actions: {', '.join(comp['actions'])}{C.RST}" if comp['actions'] else ""
                    print(f"    {C.YELLOW}[{i}]{C.RST} {comp['name']}{action_str}")

                print(f"\n  {C.DIM}[a] Launch all  [0] Back{C.RST}")
                print(f"  {C.DIM}Add extras: append after number, e.g. '1 --es key value'{C.RST}")
                sel = input(f"\n  {C.GREEN}Select ▸ {C.RST}").strip()
                if sel == "0":
                    continue

                targets = []
                extra_args = ""
                if sel.lower().startswith("a"):
                    targets = svcs
                    rest = sel[1:].strip()
                    if rest:
                        extra_args = rest
                else:
                    parts = sel.split(maxsplit=1)
                    try:
                        idx = int(parts[0]) - 1
                        if 0 <= idx < len(svcs):
                            targets = [svcs[idx]]
                        extra_args = parts[1] if len(parts) > 1 else ""
                    except (ValueError, IndexError):
                        print(f"  {C.RED}Invalid selection.{C.RST}")

                for comp in targets:
                    name = comp['name']
                    cmd = f"am startservice -n {shlex.quote(f'{pkg}/{name}')}"
                    if comp['actions']:
                        cmd += f" -a {shlex.quote(comp['actions'][0])}"
                    if extra_args:
                        cmd += f" {extra_args}"
                    print(f"\n  {C.DIM}$ {cmd}{C.RST}")
                    out = adb_shell(cmd, timeout=10)
                    if "Error" in out or "Exception" in out:
                        print(f"  {C.RED}[✗]{C.RST} {name}")
                        print(f"      {C.DIM}{out[:200]}{C.RST}")
                    else:
                        print(f"  {C.GREEN}[✓]{C.RST} {name} {C.YELLOW}— started{C.RST}")
                    time.sleep(0.5)
            pause()

        elif choice == "3":
            # ── Launch Broadcast Receivers ────────────────────────────────
            print(f"\n  {C.YELLOW}{C.BOLD}── Sending Broadcasts to Exported Receivers ──{C.RST}\n")
            rcvs = exported["receiver"]
            if not rcvs:
                print(f"  {C.DIM}No exported receivers found.{C.RST}")
            else:
                print(f"  {C.CYAN}Found {len(rcvs)} exported receiver{'s' if len(rcvs) != 1 else ''}{C.RST}")

                for i, comp in enumerate(rcvs, 1):
                    action_str = f" {C.DIM}actions: {', '.join(comp['actions'])}{C.RST}" if comp['actions'] else ""
                    print(f"    {C.YELLOW}[{i}]{C.RST} {comp['name']}{action_str}")

                print(f"\n  {C.DIM}[a] Launch all  [0] Back{C.RST}")
                print(f"  {C.DIM}Add extras: append after number, e.g. '1 --es key value'{C.RST}")
                sel = input(f"\n  {C.GREEN}Select ▸ {C.RST}").strip()
                if sel == "0":
                    continue

                targets = []
                extra_args = ""
                if sel.lower().startswith("a"):
                    targets = rcvs
                    rest = sel[1:].strip()
                    if rest:
                        extra_args = rest
                else:
                    parts = sel.split(maxsplit=1)
                    try:
                        idx = int(parts[0]) - 1
                        if 0 <= idx < len(rcvs):
                            targets = [rcvs[idx]]
                        extra_args = parts[1] if len(parts) > 1 else ""
                    except (ValueError, IndexError):
                        print(f"  {C.RED}Invalid selection.{C.RST}")

                for comp in targets:
                    name = comp['name']
                    cmd = f"am broadcast -n {shlex.quote(f'{pkg}/{name}')}"
                    if comp['actions']:
                        cmd += f" -a {shlex.quote(comp['actions'][0])}"
                    if extra_args:
                        cmd += f" {extra_args}"
                    print(f"\n  {C.DIM}$ {cmd}{C.RST}")
                    out = adb_shell(cmd, timeout=10)
                    if "Error" in out or "Exception" in out:
                        print(f"  {C.RED}[✗]{C.RST} {name}")
                        print(f"      {C.DIM}{out[:200]}{C.RST}")
                    else:
                        result_line = ""
                        for line in out.splitlines():
                            if "result=" in line.lower():
                                result_line = line.strip()
                                break
                        if result_line:
                            print(f"  {C.GREEN}[✓]{C.RST} {name} {C.DIM}— {result_line}{C.RST}")
                        else:
                            print(f"  {C.GREEN}[✓]{C.RST} {name} {C.YELLOW}— broadcast sent{C.RST}")
                    time.sleep(0.5)
            pause()

        elif choice == "4":
            # ── Query Content Providers ───────────────────────────────────
            print(f"\n  {C.YELLOW}{C.BOLD}── Query Exported Content Providers ──{C.RST}\n")
            provs = exported.get("provider", [])
            if not provs:
                print(f"  {C.DIM}No exported content providers found.{C.RST}")
            else:
                print(f"  {C.CYAN}Found {len(provs)} exported provider{'s' if len(provs) != 1 else ''}{C.RST}\n")

                for i, prov in enumerate(provs, 1):
                    perm_tags = []
                    if not prov["read_perm"] and not prov["write_perm"]:
                        perm_tags.append(f"{C.RED}NO PERMISSION{C.RST}")
                    else:
                        if prov["read_perm"]:
                            perm_tags.append(f"{C.DIM}read: {prov['read_perm']}{C.RST}")
                        if prov["write_perm"]:
                            perm_tags.append(f"{C.DIM}write: {prov['write_perm']}{C.RST}")
                    if prov["grant_uri"]:
                        perm_tags.append(f"{C.YELLOW}grantUriPermissions{C.RST}")
                    perm_str = " | ".join(perm_tags) if perm_tags else ""

                    auth_str = ", ".join(prov["authorities"]) if prov["authorities"] else "no authorities"
                    print(f"    {C.YELLOW}[{i}]{C.RST} {prov['name']}")
                    print(f"        {C.DIM}authorities: {auth_str}{C.RST}")
                    if perm_str:
                        print(f"        {perm_str}")
                    if prov.get("path_permissions"):
                        for pp in prov["path_permissions"]:
                            pp_perms = []
                            if pp["read_perm"]:
                                pp_perms.append(f"read: {pp['read_perm']}")
                            if pp["write_perm"]:
                                pp_perms.append(f"write: {pp['write_perm']}")
                            print(f"        {C.DIM}path-permission: {pp['path']} ({', '.join(pp_perms)}){C.RST}")

                print(f"\n  {C.DIM}[a] Query all  [0] Back{C.RST}")
                print(f"  {C.DIM}Append custom path after number, e.g. '1 /users'{C.RST}")
                sel = input(f"\n  {C.GREEN}Select ▸ {C.RST}").strip()
                if sel == "0":
                    pass
                else:
                    targets = []
                    custom_path = ""
                    if sel.lower().startswith("a"):
                        targets = provs
                        rest = sel[1:].strip()
                        if rest:
                            custom_path = rest
                    else:
                        parts = sel.split(maxsplit=1)
                        try:
                            idx = int(parts[0]) - 1
                            if 0 <= idx < len(provs):
                                targets = [provs[idx]]
                            custom_path = parts[1] if len(parts) > 1 else ""
                        except (ValueError, IndexError):
                            print(f"  {C.RED}Invalid selection.{C.RST}")

                    for prov in targets:
                        authorities = prov["authorities"]
                        if not authorities:
                            print(f"\n  {C.DIM}Skipping {prov['name']} (no authorities defined){C.RST}")
                            continue

                        for authority in authorities:
                            uri = f"content://{authority}"
                            if custom_path:
                                uri += custom_path if custom_path.startswith("/") else f"/{custom_path}"

                            print(f"\n  {C.CYAN}Querying: {C.BOLD}{uri}{C.RST}")

                            # Try content query
                            out = adb_shell(
                                f"content query --uri {shlex.quote(uri)}", timeout=15
                            )
                            if not _is_err(out):
                                lines = out.splitlines()
                                if any("Row:" in l for l in lines):
                                    row_count = sum(1 for l in lines if "Row:" in l)
                                    print(f"  {C.RED}[!] DATA EXPOSED{C.RST} — {row_count} row{'s' if row_count != 1 else ''} returned")
                                    for line in lines[:15]:
                                        print(f"      {C.DIM}{line.strip()[:120]}{C.RST}")
                                    if len(lines) > 15:
                                        print(f"      {C.DIM}... ({len(lines) - 15} more lines){C.RST}")
                                elif "No result found" in out:
                                    print(f"  {C.GREEN}[+]{C.RST} No rows returned (empty or requires path)")
                                elif "Permission Denial" in out or "SecurityException" in out:
                                    print(f"  {C.GREEN}[+]{C.RST} Protected — {C.DIM}permission denied{C.RST}")
                                elif "Unknown URI" in out or "UnsupportedOperationException" in out:
                                    print(f"  {C.YELLOW}[-]{C.RST} URI not recognized by provider")
                                else:
                                    print(f"  {C.YELLOW}[-]{C.RST} Response:")
                                    for line in out.splitlines()[:5]:
                                        print(f"      {C.DIM}{line.strip()[:120]}{C.RST}")
                            else:
                                print(f"  {C.DIM}No response or error: {out[:100] if out else '(empty)'}{C.RST}")

                            # Also try common sub-paths if no custom path given
                            if not custom_path:
                                for sub_path in ["", "/", "/*"]:
                                    test_uri = f"content://{authority}{sub_path}" if sub_path else uri
                                    if test_uri == uri:
                                        continue
                                    out2 = adb_shell(
                                        f"content query --uri {shlex.quote(test_uri)}", timeout=10
                                    )
                                    if out2 and "Row:" in out2:
                                        row_count = sum(1 for l in out2.splitlines() if "Row:" in l)
                                        print(f"  {C.RED}[!] DATA EXPOSED at {test_uri}{C.RST} — {row_count} row{'s' if row_count != 1 else ''}")
                                        for line in out2.splitlines()[:5]:
                                            print(f"      {C.DIM}{line.strip()[:120]}{C.RST}")

                        time.sleep(0.3)

                    print(f"\n  {C.CYAN}{'─'*50}{C.RST}")
                    print(f"  {C.DIM}Tip: Providers returning data without permission are a data leakage risk.{C.RST}")
                    print(f"  {C.DIM}Try custom paths like /users, /accounts, /files to enumerate tables.{C.RST}")
            pause()

        elif choice == "5":
            # ── Clipboard Spy ────────────────────────────────────────────
            print(f"\n  {C.YELLOW}{C.BOLD}── Clipboard Spy ──{C.RST}\n")
            print(f"  {C.CYAN}Copy something sensitive in the target app, then press Enter.{C.RST}")
            input(f"  {C.GREEN}▸ Ready? Press Enter to read clipboard... {C.RST}")

            clip = adb_su("service call clipboard 2 i32 1 i32 0", timeout=10)
            clip_text = ""
            if clip and "Parcel" in clip:
                # Try to extract readable text from the parcel response
                parts = re.findall(r"'([^']+)'", clip)
                if parts:
                    clip_text = "".join(parts).replace(".", "").strip()

            # Also try dumpsys as fallback
            if not clip_text:
                dump = adb_su("dumpsys clipboard", timeout=10)
                if dump and "mPrimaryClip" in dump:
                    m = re.search(r'mPrimaryClip=ClipData\{[^}]*\{T:([^}]+)\}', dump)
                    if m:
                        clip_text = m.group(1).strip()
                    else:
                        # Try to find any text content
                        for line in dump.splitlines():
                            if "T:" in line:
                                clip_text = line.strip()
                                break

            print()
            if clip_text:
                print(f"  {C.RED}{C.BOLD}[!] Clipboard content found:{C.RST}")
                print(f"  {C.WHITE}{C.BOLD}{_redact_sensitive_text(clip_text)}{C.RST}")
                print(f"\n  {C.YELLOW}If this contains sensitive data, the app may not be")
                print(f"  clearing the clipboard properly.{C.RST}")
            else:
                print(f"  {C.DIM}No readable clipboard content found.{C.RST}")
                print(f"  {C.DIM}Raw response:{C.RST}")
                print(f"  {C.DIM}{clip[:200] if clip else '(empty)'}{C.RST}")
            pause()

        elif choice == "6":
            # ── Dev/Staging URL Finder ───────────────────────────────────
            print(f"\n  {C.YELLOW}{C.BOLD}── Dev/Staging URL Finder ──{C.RST}\n")
            work_dir, decompiled_dir = _pull_and_decompile(pkg)
            if not decompiled_dir:
                pause()
                continue

            dev_patterns = [
                (r'https?://dev\.', "dev URL"),
                (r'https?://staging\.', "staging URL"),
                (r'https?://test\.', "test URL"),
                (r'https?://uat\.', "UAT URL"),
                (r'https?://qa\.', "QA URL"),
                (r'https?://localhost[:/]', "localhost"),
                (r'https?://127\.0\.0\.1', "loopback (127.0.0.1)"),
                (r'https?://10\.0\.2\.2', "Android emulator host (10.0.2.2)"),
                (r'192\.168\.\d+\.\d+', "private IP (192.168.x.x)"),
                (r'10\.\d+\.\d+\.\d+', "private IP (10.x.x.x)"),
                (r'172\.(1[6-9]|2\d|3[01])\.\d+\.\d+', "private IP (172.16-31.x.x)"),
            ]
            compiled = [(re.compile(p, re.IGNORECASE), label) for p, label in dev_patterns]

            findings = []
            skip_ext = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.bmp',
                        '.mp3', '.mp4', '.ogg', '.wav', '.ttf', '.otf', '.woff',
                        '.woff2', '.eot', '.so', '.dex', '.class', '.jar', '.zip'}

            print(f"  {C.DIM}Scanning decompiled files...{C.RST}")
            for root, dirs, files in os.walk(decompiled_dir):
                for fname in files:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext in skip_ext:
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, 'r', errors='ignore') as f:
                            for line_num, line in enumerate(f, 1):
                                for pat, label in compiled:
                                    m = pat.search(line)
                                    if m:
                                        rel = os.path.relpath(fpath, decompiled_dir)
                                        findings.append((label, m.group(0), rel, line_num))
                    except Exception:
                        continue

            print()
            if findings:
                print(f"  {C.RED}{C.BOLD}[!] Found {len(findings)} dev/internal URL reference{'s' if len(findings) != 1 else ''}:{C.RST}\n")
                seen = set()
                for label, match, rel_path, line_num in findings:
                    key = (match, rel_path, line_num)
                    if key in seen:
                        continue
                    seen.add(key)
                    print(f"  {C.YELLOW}[{label}]{C.RST} {C.WHITE}{match}{C.RST}")
                    print(f"      {C.DIM}{rel_path}:{line_num}{C.RST}")
                print(f"\n  {C.YELLOW}These may indicate leftover dev/staging endpoints")
                print(f"  that could expose internal infrastructure.{C.RST}")
            else:
                print(f"  {C.GREEN}[+] No dev/staging URLs found.{C.RST}")
            pause()

        elif choice == "7":
            # ── Repackaging / Integrity Check ─────────────────────────────
            print(f"\n  {C.YELLOW}{C.BOLD}── Repackaging Integrity Check ──{C.RST}\n")
            print(f"  {C.CYAN}This test checks whether the app detects repackaging/re-signing.{C.RST}")
            print(f"  {C.CYAN}You must have already installed a patched/re-signed APK of:{C.RST}")
            print(f"  {C.WHITE}{C.BOLD}  {pkg}{C.RST}\n")
            print(f"  {C.DIM}The test will:{C.RST}")
            print(f"  {C.DIM}  1. Force-stop the app{C.RST}")
            print(f"  {C.DIM}  2. Launch it via monkey / am start{C.RST}")
            print(f"  {C.DIM}  3. Monitor the process for up to 30 seconds{C.RST}")
            print(f"  {C.DIM}  4. Report whether it survived or was killed{C.RST}")

            try:
                confirm = input(f"\n  {C.GREEN}Is the patched APK installed? [y/N] ▸ {C.RST}").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                pause()
                continue
            if confirm != "y":
                print(f"  {C.DIM}Aborted. Install the patched APK first.{C.RST}")
                pause()
                continue

            # Force-stop to ensure clean start
            print(f"\n  {C.DIM}Force-stopping {pkg}...{C.RST}")
            adb_shell(f"am force-stop {pkg}")
            time.sleep(1)

            # Verify package is installed and get version info
            pkg_info = adb_shell(f"dumpsys package {pkg} | grep versionName")
            if not pkg_info or "versionName" not in pkg_info:
                print(f"  {C.RED}[!] Package {pkg} does not appear to be installed.{C.RST}")
                pause()
                continue
            version = pkg_info.strip().split("=")[-1] if "=" in pkg_info else "unknown"
            print(f"  {C.DIM}Installed version: {version}{C.RST}")

            # Get signing cert fingerprint to confirm it's re-signed
            sig_info = adb_shell(f"dumpsys package {pkg} | grep -A1 'Signing'")
            print(f"  {C.DIM}Signature: {sig_info.strip()[:100] if sig_info else 'N/A'}{C.RST}")

            # Launch the app
            print(f"\n  {C.CYAN}[*] Launching {pkg}...{C.RST}")
            # Try monkey first (most reliable way to launch the default activity)
            launch_out = adb_shell(f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1 2>&1")
            if "No activities found" in (launch_out or ""):
                # Fallback: use am start with launcher intent
                launch_out = adb_shell(
                    f"am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER {pkg}")

            print(f"  {C.DIM}{launch_out[:150] if launch_out else '(launched)'}{C.RST}")
            time.sleep(2)

            # Monitor process survival
            print(f"\n  {C.CYAN}[*] Monitoring process survival...{C.RST}")
            check_interval = 2  # seconds between checks
            total_wait = 30     # total monitoring time
            checks_passed = 0
            process_died = False
            death_time = None
            crash_info = ""

            for elapsed in range(0, total_wait, check_interval):
                time.sleep(check_interval)
                elapsed += check_interval

                # Check if process is running
                ps_out = adb_shell(f"pidof {pkg}")
                pid = ps_out.strip() if not _is_err(ps_out) else ""

                if pid:
                    checks_passed += 1
                    bar_filled = int((elapsed / total_wait) * 20)
                    bar = f"{'█' * bar_filled}{'░' * (20 - bar_filled)}"
                    print(f"\r  {C.GREEN}[ALIVE]{C.RST} {bar} {elapsed}s  PID: {pid}  ", end="", flush=True)
                else:
                    process_died = True
                    death_time = elapsed
                    # Grab crash reason from logcat
                    crash_log = adb_shell(
                        f"logcat -d -t 30 --pid=$(pidof {pkg} 2>/dev/null || echo 0) 2>/dev/null"
                        f" | grep -iE 'kill|exit|fatal|abort|integrity|tamper|signature|died'")
                    if _is_err(crash_log):
                        # Broader search
                        crash_log = adb_shell(
                            f"logcat -d -t 50 | grep -iE '{pkg}.*(kill|exit|fatal|abort|died|crash)'")
                    crash_info = crash_log.strip() if not _is_err(crash_log) else ""
                    print(f"\r  {C.RED}[DEAD]{C.RST}  Process killed after ~{death_time}s" + " " * 20)
                    break

            print()  # newline after progress bar

            # ── Results ──────────────────────────────────────────────────
            print(f"\n  {C.CYAN}{'═'*50}{C.RST}")
            if process_died:
                print(f"  {C.RED}{C.BOLD}RESULT: INTEGRITY CHECK DETECTED{C.RST}")
                print(f"  {C.RED}The app was killed ~{death_time}s after launch.{C.RST}")
                print(f"  {C.DIM}This indicates the app detects repackaging/re-signing{C.RST}")
                print(f"  {C.DIM}and terminates itself (signature verification, integrity check).{C.RST}")

                if crash_info:
                    print(f"\n  {C.YELLOW}Crash/kill indicators from logcat:{C.RST}")
                    for line in crash_info.splitlines()[:10]:
                        print(f"    {C.DIM}{line.strip()[:120]}{C.RST}")

                # Check what kind of integrity mechanism might be in use
                print(f"\n  {C.YELLOW}Possible mechanisms:{C.RST}")
                if death_time <= 5:
                    print(f"  {C.DIM}• Killed within 5s → likely native/JNI signature check in Application.onCreate(){C.RST}")
                    print(f"  {C.DIM}• Could be: VKey VGuard, Promon SHIELD, DexGuard, Play Integrity{C.RST}")
                elif death_time <= 15:
                    print(f"  {C.DIM}• Killed within 15s → likely Java-level signature verification{C.RST}")
                    print(f"  {C.DIM}• Could be: PackageInfo.signatures check, SafetyNet/Play Integrity callback{C.RST}")
                else:
                    print(f"  {C.DIM}• Killed after 15s → likely server-side attestation or delayed check{C.RST}")
                    print(f"  {C.DIM}• Could be: Remote attestation, certificate transparency, server-side sig check{C.RST}")

                print(f"\n  {C.CYAN}Bypass suggestions:{C.RST}")
                print(f"  {C.DIM}• Use Frida to hook PackageInfo.signatures → return original cert{C.RST}")
                print(f"  {C.DIM}• Hook System.exit() and Process.killProcess() to prevent termination{C.RST}")
                print(f"  {C.DIM}• Try the universal bypass script with --no-pause spawn{C.RST}")
            else:
                print(f"  {C.GREEN}{C.BOLD}RESULT: NO INTEGRITY CHECK DETECTED{C.RST}")
                print(f"  {C.GREEN}The app survived {total_wait}s after launch with a patched/re-signed APK.{C.RST}")
                print(f"  {C.DIM}Process checks passed: {checks_passed}/{total_wait // check_interval}{C.RST}")
                print(f"\n  {C.YELLOW}This means:{C.RST}")
                print(f"  {C.DIM}• The app does NOT verify its own signature at runtime{C.RST}")
                print(f"  {C.DIM}• OR the integrity check is deferred (server-side, next API call, etc.){C.RST}")
                print(f"  {C.DIM}• Recommend: also test with the app fully functional (login, API calls){C.RST}")
            pause()

        elif choice == "8":
            # ── ADB Backup Extraction ─────────────────────────────────────
            backup_extraction(pkg)

        else:
            print(f"  {C.RED}Invalid option.{C.RST}")
            time.sleep(0.5)

# ─── Frida Gadget APK Patcher ────────────────────────────────────────────────────

GADGET_VERSION = "17.6.2"  # fallback when the local frida version can't be determined
GADGET_SO_NAME = "libfrida-gadget.so"

LSPATCH_URL = "https://github.com/LSPosed/LSPatch/releases/download/v0.6/jar-v0.6-398-release.jar"
LSPATCH_JAR_NAME = "lspatch.jar"
LSPATCH_SHA256 = "c179d884cb5dda151d6066320a2cf3658b4c15160306a0af2bd4c71faf6c3540"


def _file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download_file(url, destination, max_bytes, expected_sha256=None):
    """Download an HTTPS asset with limits, validation, and atomic replace."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("only HTTPS downloads are allowed")

    partial = destination + ".part"
    try:
        if os.path.exists(partial):
            os.remove(partial)
        request = urllib.request.Request(url, headers={"User-Agent": "APK-Analyzer"})
        # The initial and final schemes are both constrained to HTTPS.
        with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310
            final_url = urllib.parse.urlparse(response.geturl())
            if final_url.scheme != "https":
                raise ValueError("download redirected to a non-HTTPS URL")
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > max_bytes:
                raise ValueError("download exceeds size limit")
            digest = hashlib.sha256()
            size = 0
            with open(partial, "xb") as output:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > max_bytes:
                        raise ValueError("download exceeds size limit")
                    digest.update(chunk)
                    output.write(chunk)
        if size == 0:
            raise ValueError("download was empty")
        actual = digest.hexdigest()
        if expected_sha256 and actual.lower() != expected_sha256.lower():
            raise ValueError(f"SHA-256 mismatch (got {actual})")
        os.replace(partial, destination)
        return actual
    finally:
        if os.path.exists(partial):
            os.remove(partial)


def _github_asset_sha256(repository, tag, asset_name):
    """Read a published SHA-256 digest from GitHub release metadata."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        return None
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", tag):
        return None
    api_url = (
        f"https://api.github.com/repos/{repository}/releases/tags/"
        f"{urllib.parse.quote(tag)}"
    )
    request = urllib.request.Request(
        api_url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "APK-Analyzer"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:  # nosec B310
            final = urllib.parse.urlparse(response.geturl())
            if final.scheme != "https" or final.hostname != "api.github.com":
                return None
            data = response.read(10 * 1024 * 1024 + 1)
            if len(data) > 10 * 1024 * 1024:
                return None
        release = json.loads(data.decode("utf-8"))
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError):
        return None
    for asset in release.get("assets", []):
        if asset.get("name") == asset_name:
            digest = asset.get("digest") or ""
            if re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest):
                return digest.split(":", 1)[1].lower()
    return None


def _extract_xz_elf(source, destination, max_bytes=256 * 1024 * 1024):
    """Bounded extraction for a Frida Gadget XZ asset."""
    partial = destination + ".part"
    try:
        if os.path.exists(partial):
            os.remove(partial)
        total = 0
        with lzma.open(source, "rb") as compressed, open(partial, "xb") as output:
            while True:
                chunk = compressed.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError("decompressed Gadget exceeds size limit")
                output.write(chunk)
        with open(partial, "rb") as fh:
            if fh.read(4) != b"\x7fELF":
                raise ValueError("downloaded Gadget is not an ELF library")
        os.replace(partial, destination)
    finally:
        if os.path.exists(partial):
            os.remove(partial)


def _get_frida_gadget(cache_dir, version, arch):
    """Return a validated cached/downloaded Frida Gadget for one ABI."""
    gadget_so = os.path.join(
        cache_dir, f"frida-gadget-{version}-android-{arch}.so"
    )
    if os.path.isfile(gadget_so):
        try:
            with open(gadget_so, "rb") as cached:
                if cached.read(4) == b"\x7fELF":
                    print(f"  {C.GREEN}[+] Using cached Frida Gadget ({arch}){C.RST}")
                    return gadget_so
        except OSError:
            pass
        os.remove(gadget_so)

    asset_name = f"frida-gadget-{version}-android-{arch}.so.xz"
    gadget_url = (f"https://github.com/frida/frida/releases/download/{version}/"
                  f"{asset_name}")
    gadget_xz = gadget_so + ".xz"
    print(f"\n  {C.CYAN}[*] Downloading Frida Gadget (v{version} / {arch})...{C.RST}")
    print(f"  {C.DIM}{gadget_url}{C.RST}")
    expected_sha256 = _github_asset_sha256("frida/frida", version, asset_name)
    if expected_sha256 is None:
        print(f"  {C.YELLOW}[!] GitHub did not publish an asset digest; validating format only.{C.RST}")
    _download_file(
        gadget_url, gadget_xz, max_bytes=128 * 1024 * 1024,
        expected_sha256=expected_sha256,
    )
    try:
        _extract_xz_elf(gadget_xz, gadget_so)
    finally:
        if os.path.exists(gadget_xz):
            os.remove(gadget_xz)
    print(f"  {C.GREEN}[+] Frida Gadget downloaded ({arch}){C.RST}")
    return gadget_so

def _find_apktool():
    """Find apktool — standalone command or java -jar fallback.
    Returns a list of args (e.g. ["apktool"] or ["java", "-jar", "/path/to/apktool.jar"])."""
    executable = shutil.which("apktool")
    if executable:
        if os.name != "nt" or not executable.lower().endswith((".bat", ".cmd")):
            return [executable]
        sibling_jar = os.path.join(os.path.dirname(executable), "apktool.jar")
        if os.path.isfile(sibling_jar) and shutil.which("java"):
            return [shutil.which("java"), "-jar", sibling_jar]
    for jar_path in [
        os.path.join(os.getcwd(), "apktool.jar"),
        os.path.join(os.path.expanduser("~"), "apktool.jar"),
    ]:
        if os.path.isfile(jar_path):
            if shutil.which("java"):
                return ["java", "-jar", jar_path]
    return None

def _find_main_activity(manifest_path):
    """Parse AndroidManifest.xml to find the launcher activity."""
    try:
        tree = _safe_parse_xml(manifest_path)
        root = tree.getroot()
        ns = _ANDROID_NS
        package = root.get("package", "")

        for activity in list(root.iter("activity")) + list(root.iter("activity-alias")):
            for intent_filter in activity.iter("intent-filter"):
                actions = [a.get(f"{{{ns}}}name") for a in intent_filter.iter("action")]
                categories = [c.get(f"{{{ns}}}name") for c in intent_filter.iter("category")]
                if ("android.intent.action.MAIN" in actions
                        and "android.intent.category.LAUNCHER" in categories):
                    name = (activity.get(f"{{{ns}}}targetActivity")
                            or activity.get(f"{{{ns}}}name", ""))
                    if name.startswith("."):
                        name = package + name
                    elif "." not in name:
                        name = package + "." + name
                    return name
    except Exception as e:
        print(f"  {C.RED}[!] Manifest parse error: {e}{C.RST}")
    return None

def _patch_manifest_for_gadget(manifest_path):
    """Add INTERNET permission and set extractNativeLibs=true."""
    try:
        ET.register_namespace("android", _ANDROID_NS)
        tree = _safe_parse_xml(manifest_path)
        root = tree.getroot()
        ns_name = f"{{{_ANDROID_NS}}}name"

        permissions = {
            node.get(ns_name) for node in root.findall("uses-permission")
        }
        if "android.permission.INTERNET" not in permissions:
            permission = ET.Element("uses-permission")
            permission.set(ns_name, "android.permission.INTERNET")
            app_index = next(
                (i for i, child in enumerate(root) if child.tag == "application"),
                len(root),
            )
            root.insert(app_index, permission)
            print(f"  {C.GREEN}[+] Added INTERNET permission{C.RST}")

        app = root.find("application")
        if app is None:
            raise ValueError("manifest has no application element")
        extract_attr = f"{{{_ANDROID_NS}}}extractNativeLibs"
        if app.get(extract_attr) != "true":
            app.set(extract_attr, "true")
            print(f"  {C.GREEN}[+] Set extractNativeLibs=true{C.RST}")

        tree.write(manifest_path, encoding="utf-8", xml_declaration=True)
        return True
    except (ET.ParseError, OSError, ValueError) as e:
        print(f"  {C.RED}[!] Manifest patch error: {e}{C.RST}")
        return False

def _inject_gadget_loader(smali_path):
    """Inject System.loadLibrary('frida-gadget') into a static initializer."""
    try:
        with open(smali_path, "r", encoding="utf-8") as f:
            content = f.read()

        existing_loader = re.search(
            r"(?ms)^\s*\.method\b[^\r\n]*<clinit>\(\)V\s*$"
            r"(?P<body>.*?)^\s*\.end\s+method\s*$",
            content,
        )
        if (existing_loader
                and re.search(
                    r'(?m)^[ \t]*const-string v0, "frida-gadget"[ \t]*\r?$'
                    r'(?:\n[ \t]*\r?)*\n[ \t]*invoke-static \{v0\},[ \t]*'
                    r'Ljava/lang/System;->loadLibrary\(Ljava/lang/String;\)V[ \t]*\r?$',
                    existing_loader.group("body"),
                )):
            return True

        load_lines = [
            '    const-string v0, "frida-gadget"',
            '',
            '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V',
        ]

        clinit_match = re.search(
            r"(?m)^\s*\.method\b[^\r\n]*<clinit>\(\)V\s*$", content
        )
        if clinit_match:
            # Inject into existing <clinit>
            lines = content.split('\n')
            new_lines = []
            in_clinit = False
            injected = False
            for line in lines:
                new_lines.append(line)
                if re.match(r"^\s*\.method\b[^\r\n]*<clinit>\(\)V\s*$", line):
                    in_clinit = True
                if in_clinit and not injected:
                    frame = re.match(
                        r"^(\s*)\.(locals|registers)\s+(\d+)(.*)$", line
                    )
                    if frame:
                        # Ensure at least 1 register
                        indent, directive, count, suffix = frame.groups()
                        if int(count) < 1:
                            new_lines[-1] = (
                                f"{indent}.{directive} 1{suffix}"
                            )
                        new_lines.extend(load_lines)
                        injected = True
                if in_clinit and line.strip() == ".end method":
                    in_clinit = False
            if injected:
                content = '\n'.join(new_lines)
            else:
                return False
        else:
            # Never grow an instance method's frame: doing so shifts absolute
            # v-register aliases for its parameters. A new static initializer
            # has no parameter registers and is safe for this loader.
            clinit_block = (
                '\n.method static constructor <clinit>()V\n'
                '    .registers 3\n'
                '\n'
                '    const-string v0, "frida-gadget"\n'
                '\n'
                '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n'
                '\n'
                '    return-void\n'
                '.end method\n'
            )
            if "\n.method " in content:
                idx = content.index("\n.method ") + 1
                content = content[:idx] + clinit_block + "\n" + content[idx:]
            else:
                content += "\n" + clinit_block

        with open(smali_path, "w", encoding="utf-8") as f:
            f.write(content)
        return True
    except Exception as e:
        print(f"  {C.RED}[!] Smali injection error: {e}{C.RST}")
        return False


def frida_gadget_patch(pkg):
    """Patch APK with Frida Gadget for non-root dynamic analysis."""
    section("FRIDA GADGET APK PATCHER")

    # ── Check dependencies ───────────────────────────────────────────────
    apktool_cmd = _find_apktool()
    if not apktool_cmd:
        print(f"  {C.RED}[!] apktool not found.{C.RST}")
        print(f"  {C.DIM}  Install: https://ibotpeaches.github.io/Apktool/{C.RST}")
        print(f"  {C.DIM}  Or place apktool.jar in current directory and ensure java is installed{C.RST}")
        pause()
        return

    signer = None
    if shutil.which("apksigner"):
        signer = "apksigner"
    elif shutil.which("jarsigner"):
        signer = "jarsigner"
    else:
        print(f"  {C.RED}[!] No signing tool found (apksigner or jarsigner).{C.RST}")
        print(f"  {C.DIM}  Install JDK for jarsigner or Android SDK build-tools for apksigner{C.RST}")
        pause()
        return

    if not shutil.which("keytool"):
        print(f"  {C.RED}[!] keytool not found — JDK is required for keystore generation.{C.RST}")
        pause()
        return

    print(f"  {C.GREEN}[+] apktool : {' '.join(apktool_cmd)}{C.RST}")
    print(f"  {C.GREEN}[+] signer  : {signer}{C.RST}")

    # ── Setup directories ────────────────────────────────────────────────
    work_dir = os.path.join(os.getcwd(), ".apkpatcher_work")
    patched_dir = os.path.join(os.getcwd(), "patched_apks")
    gadget_cache = os.path.join(os.getcwd(), ".gadget_cache")
    os.makedirs(work_dir, exist_ok=True)
    os.makedirs(patched_dir, exist_ok=True)
    os.makedirs(gadget_cache, exist_ok=True)

    try:
        # ── Step 1: Download Frida Gadget ────────────────────────────────
        # Detect device ABI → frida release arch
        abi = adb_shell("getprop ro.product.cpu.abi").strip()
        arch_map = {"arm64-v8a": "arm64", "armeabi-v7a": "arm", "armeabi": "arm",
                    "x86": "x86", "x86_64": "x86_64"}
        if abi not in arch_map:
            print(f"  {C.YELLOW}[!] Unrecognized device ABI '{abi or 'unknown'}' — defaulting to arm64.{C.RST}")
            abi = "arm64-v8a"

        # Match the gadget version to the local frida install when possible
        frida_ok, frida_ver = check_frida()
        ver = GADGET_VERSION
        if frida_ok:
            m = re.match(r'\d+\.\d+\.\d+', frida_ver.strip())
            if m:
                ver = m.group()

        # ── Step 2: Get APK ──────────────────────────────────────────────
        local_apk = _find_local_apk(pkg)

        if local_apk:
            print(f"  {C.GREEN}[+] Found local APK: {local_apk}{C.RST}")
        else:
            apk_path = get_apk_path(pkg)
            if not apk_path:
                print(f"  {C.RED}[!] Could not locate APK for {pkg}{C.RST}")
                pause()
                return
            local_apk = os.path.join(work_dir, f"{pkg}.apk")
            print(f"\n  {C.DIM}Pulling APK from device...{C.RST}")
            pull_result = adb_pull(apk_path, local_apk)
            if (_is_err(pull_result) or not os.path.exists(local_apk)
                    or os.path.getsize(local_apk) == 0):
                print(f"  {C.RED}[!] Failed to pull APK.{C.RST}")
                pause()
                return

        # ── Step 3: Decompile ────────────────────────────────────────────
        decompiled = os.path.join(work_dir, f"{pkg}_patched")
        if os.path.isdir(decompiled):
            shutil.rmtree(decompiled, ignore_errors=True)

        print(f"  {C.DIM}Decompiling APK...{C.RST}")
        try:
            r = subprocess.run(
                apktool_cmd + ["d", "-f", "-o", decompiled, local_apk],
                capture_output=True, text=True, timeout=300,
                encoding='utf-8', errors='replace'
            )
            if r.returncode != 0 or not os.path.isdir(decompiled):
                print(f"  {C.RED}[!] Decompilation failed:{C.RST}")
                print(f"  {C.DIM}{r.stderr[:400] if r.stderr else 'unknown error'}{C.RST}")
                pause()
                return
        except subprocess.TimeoutExpired:
            print(f"  {C.RED}[!] Decompilation timed out.{C.RST}")
            pause()
            return
        print(f"  {C.GREEN}[+] Decompiled successfully{C.RST}")

        # Match Gadget libraries to the APK's ABIs. Adding only the device's
        # primary ABI can make a 32-bit-only APK look 64-bit-capable and crash
        # when Android selects an incomplete native library directory.
        existing_abis = []
        decompiled_lib = os.path.join(decompiled, "lib")
        if os.path.isdir(decompiled_lib):
            existing_abis = [
                entry for entry in sorted(os.listdir(decompiled_lib))
                if entry in arch_map and os.path.isdir(os.path.join(decompiled_lib, entry))
            ]
        target_abis = existing_abis or [abi]
        gadgets = {}
        try:
            for target_abi in target_abis:
                gadgets[target_abi] = _get_frida_gadget(
                    gadget_cache, ver, arch_map[target_abi]
                )
        except (OSError, ValueError, lzma.LZMAError, urllib.error.URLError) as e:
            print(f"  {C.RED}[!] Frida Gadget download/extraction failed: {e}{C.RST}")
            pause()
            return

        # ── Step 4: Find main activity ───────────────────────────────────
        manifest = os.path.join(decompiled, "AndroidManifest.xml")
        if not os.path.isfile(manifest):
            print(f"  {C.RED}[!] AndroidManifest.xml not found{C.RST}")
            pause()
            return

        main_activity = _find_main_activity(manifest)
        if not main_activity:
            print(f"  {C.RED}[!] Could not determine launcher activity{C.RST}")
            pause()
            return
        print(f"  {C.GREEN}[+] Launcher: {main_activity}{C.RST}")

        # ── Step 5: Patch manifest ───────────────────────────────────────
        if not _patch_manifest_for_gadget(manifest):
            pause()
            return

        # ── Step 6: Inject gadget loader into smali ──────────────────────
        smali_relative = main_activity.replace(".", os.sep) + ".smali"
        smali_path = None
        for entry in sorted(os.listdir(decompiled)):
            if entry.startswith("smali"):
                candidate = os.path.join(decompiled, entry, smali_relative)
                if os.path.isfile(candidate):
                    smali_path = candidate
                    break

        if not smali_path:
            print(f"  {C.RED}[!] Smali not found for {main_activity}{C.RST}")
            pause()
            return

        print(f"  {C.DIM}Injecting gadget loader...{C.RST}")
        if not _inject_gadget_loader(smali_path):
            print(f"  {C.RED}[!] Failed to inject gadget loader{C.RST}")
            pause()
            return
        print(f"  {C.GREEN}[+] Gadget loader injected into smali{C.RST}")

        # ── Step 7: Copy gadget .so ──────────────────────────────────────
        for target_abi, gadget_so in gadgets.items():
            lib_dir = os.path.join(decompiled, "lib", target_abi)
            os.makedirs(lib_dir, exist_ok=True)
            shutil.copy2(gadget_so, os.path.join(lib_dir, GADGET_SO_NAME))
            print(f"  {C.GREEN}[+] Copied {GADGET_SO_NAME} → lib/{target_abi}/{C.RST}")

        # ── Step 8: Rebuild ──────────────────────────────────────────────
        rebuilt_apk = os.path.join(work_dir, f"{pkg}_rebuilt.apk")
        print(f"  {C.DIM}Rebuilding APK...{C.RST}")
        try:
            r = subprocess.run(
                apktool_cmd + ["b", "-o", rebuilt_apk, decompiled],
                capture_output=True, text=True, timeout=300,
                encoding='utf-8', errors='replace'
            )
            if r.returncode != 0 or not os.path.isfile(rebuilt_apk):
                print(f"  {C.RED}[!] Rebuild failed:{C.RST}")
                print(f"  {C.DIM}{r.stderr[:400] if r.stderr else 'unknown error'}{C.RST}")
                pause()
                return
        except subprocess.TimeoutExpired:
            print(f"  {C.RED}[!] Rebuild timed out.{C.RST}")
            pause()
            return
        print(f"  {C.GREEN}[+] APK rebuilt{C.RST}")

        # ── Step 9: Sign ─────────────────────────────────────────────────
        keystore = os.path.join(gadget_cache, "debug.keystore")
        if not os.path.isfile(keystore):
            print(f"  {C.DIM}Generating debug keystore...{C.RST}")
            keytool_result = subprocess.run(
                ["keytool", "-genkeypair", "-v", "-keystore", keystore,
                 "-alias", "androiddebugkey", "-keyalg", "RSA", "-keysize", "2048",
                 "-validity", "10000", "-storepass", "android", "-keypass", "android",
                 "-dname", "CN=Android Debug,O=Android,C=US"],
                capture_output=True, text=True, timeout=30, check=False,
            )
            if keytool_result.returncode != 0 or not os.path.isfile(keystore):
                print(f"  {C.RED}[!] Debug keystore generation failed.{C.RST}")
                print(f"  {C.DIM}{_terminal_safe(keytool_result.stderr)[:400]}{C.RST}")
                pause()
                return

        signed_apk = os.path.join(work_dir, f"{pkg}_signed.apk")
        print(f"  {C.DIM}Signing APK with {signer}...{C.RST}")

        if signer == "apksigner":
            # zipalign first if available
            zipaligned = os.path.join(work_dir, f"{pkg}_aligned.apk")
            if shutil.which("zipalign"):
                align_result = subprocess.run(
                    ["zipalign", "-f", "4", rebuilt_apk, zipaligned],
                    capture_output=True, text=True, timeout=60, check=False,
                )
                if align_result.returncode != 0 or not os.path.isfile(zipaligned):
                    print(f"  {C.RED}[!] zipalign failed before signing.{C.RST}")
                    pause()
                    return
                to_sign = zipaligned
            else:
                to_sign = rebuilt_apk

            r = subprocess.run(
                ["apksigner", "sign", "--ks", keystore, "--ks-pass", "pass:android",
                 "--ks-key-alias", "androiddebugkey", "--key-pass", "pass:android",
                 "--out", signed_apk, to_sign],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
        else:
            # jarsigner signs in-place
            shutil.copy2(rebuilt_apk, signed_apk)
            r = subprocess.run(
                ["jarsigner", "-verbose", "-sigalg", "SHA256withRSA", "-digestalg", "SHA-256",
                 "-keystore", keystore, "-storepass", "android", "-keypass", "android",
                 signed_apk, "androiddebugkey"],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            # zipalign after jarsigner if available
            if shutil.which("zipalign"):
                aligned = os.path.join(work_dir, f"{pkg}_aligned.apk")
                align_result = subprocess.run(
                    ["zipalign", "-f", "4", signed_apk, aligned],
                    capture_output=True, text=True, timeout=60, check=False,
                )
                if align_result.returncode != 0 or not os.path.isfile(aligned):
                    print(f"  {C.RED}[!] zipalign failed after signing.{C.RST}")
                    pause()
                    return
                shutil.move(aligned, signed_apk)

        if r.returncode != 0:
            print(f"  {C.RED}[!] Signing failed:{C.RST}")
            print(f"  {C.DIM}{r.stderr[:400] if r.stderr else r.stdout[:400]}{C.RST}")
            pause()
            return
        if not os.path.isfile(signed_apk) or os.path.getsize(signed_apk) == 0:
            print(f"  {C.RED}[!] Signing reported success but produced no APK.{C.RST}")
            pause()
            return
        print(f"  {C.GREEN}[+] APK signed{C.RST}")

        # ── Step 10: Move to patched_apks/ ───────────────────────────────
        final_name = f"{pkg}_gadget_patched.apk"
        final_path = os.path.join(patched_dir, final_name)
        shutil.move(signed_apk, final_path)

        print(f"\n  {C.GREEN}{C.BOLD}{'='*50}{C.RST}")
        print(f"  {C.GREEN}{C.BOLD}[✓] PATCHED APK READY{C.RST}")
        print(f"  {C.GREEN}{C.BOLD}{'='*50}{C.RST}")
        print(f"  {C.WHITE}{final_path}{C.RST}")
        print(f"\n  {C.CYAN}To install:{C.RST}")
        print(f"  {C.DIM}  adb uninstall {pkg}{C.RST}")
        print(f'  {C.DIM}  adb install "{final_path}"{C.RST}')
        print(f"\n  {C.CYAN}Then launch the app — Frida Gadget will listen on port 27042.{C.RST}")
        print(f"  {C.DIM}  frida {FRIDA_CONN} -n Gadget{C.RST}")

    finally:
        # Clean up work dir
        if os.path.isdir(work_dir):
            shutil.rmtree(work_dir, ignore_errors=True)

    pause()


# ─── LSPatch APK Patcher ─────────────────────────────────────────────────────────

def lspatch_patch(pkg):
    """Patch APK with LSPatch for Xposed/LSPosed module loading."""
    section("LSPATCH APK PATCHER")

    # ── Check dependencies ───────────────────────────────────────────────
    if not shutil.which("java"):
        print(f"  {C.RED}[!] java not found — JDK/JRE is required for LSPatch.{C.RST}")
        print(f"  {C.DIM}  Install a JDK (e.g. openjdk-17-jdk) and ensure java is on PATH{C.RST}")
        pause()
        return

    print(f"  {C.GREEN}[+] java : {shutil.which('java')}{C.RST}")

    # ── Setup directories ────────────────────────────────────────────────
    gadget_cache = os.path.join(os.getcwd(), ".gadget_cache")
    patched_dir = os.path.join(os.getcwd(), "patched_apks")
    os.makedirs(gadget_cache, exist_ok=True)
    os.makedirs(patched_dir, exist_ok=True)

    # ── Download LSPatch jar if not cached ───────────────────────────────
    lspatch_jar = os.path.join(gadget_cache, LSPATCH_JAR_NAME)
    if os.path.isfile(lspatch_jar):
        try:
            valid_cache = (_file_sha256(lspatch_jar) == LSPATCH_SHA256
                           and zipfile.is_zipfile(lspatch_jar))
        except OSError:
            valid_cache = False
        if not valid_cache:
            print(f"  {C.YELLOW}[!] Cached LSPatch JAR failed integrity validation; replacing it.{C.RST}")
            os.remove(lspatch_jar)
    if not os.path.isfile(lspatch_jar):
        print(f"\n  {C.CYAN}[*] Downloading LSPatch jar...{C.RST}")
        print(f"  {C.DIM}{LSPATCH_URL}{C.RST}")
        try:
            _download_file(
                LSPATCH_URL, lspatch_jar, max_bytes=32 * 1024 * 1024,
                expected_sha256=LSPATCH_SHA256,
            )
            if not zipfile.is_zipfile(lspatch_jar):
                raise ValueError("downloaded LSPatch asset is not a valid JAR")
        except (OSError, ValueError, urllib.error.URLError) as e:
            print(f"  {C.RED}[!] Download failed: {e}{C.RST}")
            pause()
            return
        print(f"  {C.GREEN}[+] LSPatch jar downloaded{C.RST}")
    else:
        print(f"\n  {C.GREEN}[+] Using cached LSPatch jar{C.RST}")

    # ── Locate APK ───────────────────────────────────────────────────────
    local_apk = _find_local_apk(pkg)

    if local_apk:
        print(f"  {C.GREEN}[+] Found local APK: {local_apk}{C.RST}")
    else:
        apk_path = get_apk_path(pkg)
        if not apk_path:
            print(f"  {C.RED}[!] Could not locate APK for {pkg}{C.RST}")
            pause()
            return
        work_dir = os.path.join(os.getcwd(), ".apkpatcher_work")
        os.makedirs(work_dir, exist_ok=True)
        local_apk = os.path.join(work_dir, f"{pkg}.apk")
        print(f"\n  {C.DIM}Pulling APK from device...{C.RST}")
        pull_result = adb_pull(apk_path, local_apk)
        if (_is_err(pull_result) or not os.path.exists(local_apk)
                or os.path.getsize(local_apk) == 0):
            print(f"  {C.RED}[!] Failed to pull APK.{C.RST}")
            pause()
            return

    # ── Run LSPatch ──────────────────────────────────────────────────────
    print(f"\n  {C.CYAN}[*] Running LSPatch...{C.RST}")
    print(f"  {C.DIM}  -d (debuggable)  -v (verbose)  -l 2 (sig-bypass level 2){C.RST}")
    try:
        r = subprocess.run(
            ["java", "-jar", lspatch_jar, local_apk, "-d", "-v", "-l", "2", "-o", patched_dir],
            capture_output=True, text=True, timeout=300,
            encoding='utf-8', errors='replace'
        )
        print(f"  {C.DIM}{r.stdout[-800:] if r.stdout else ''}{C.RST}")
        if r.returncode != 0:
            print(f"  {C.RED}[!] LSPatch failed (exit {r.returncode}):{C.RST}")
            print(f"  {C.DIM}{r.stderr[:600] if r.stderr else 'unknown error'}{C.RST}")
            pause()
            return
    except subprocess.TimeoutExpired:
        print(f"  {C.RED}[!] LSPatch timed out.{C.RST}")
        pause()
        return

    print(f"\n  {C.GREEN}{C.BOLD}{'='*50}{C.RST}")
    print(f"  {C.GREEN}{C.BOLD}[✓] LSPATCH COMPLETE{C.RST}")
    print(f"  {C.GREEN}{C.BOLD}{'='*50}{C.RST}")
    print(f"  {C.WHITE}Output directory: {patched_dir}{C.RST}")
    print(f"\n  {C.CYAN}To install:{C.RST}")
    print(f"  {C.DIM}  adb uninstall {pkg}{C.RST}")
    print(f'  {C.DIM}  adb install "<patched_apk_from_output_dir>"{C.RST}')
    print(f"\n  {C.CYAN}The patched APK can load LSPosed/Xposed modules without root.{C.RST}")
    pause()


# ─── Binary Patcher (sub-menu) ───────────────────────────────────────────────────

def binary_patcher(pkg):
    """Sub-menu: choose between Frida Gadget and LSPatch patching."""
    section("BINARY PATCHER")
    print(f"  {C.CYAN}Choose a patching method:{C.RST}\n")
    print(f"  {C.YELLOW}[1]{C.RST} Frida Gadget  — inject frida-gadget.so (Frida hooking)")
    print(f"  {C.YELLOW}[2]{C.RST} LSPatch       — embed LSPosed/Xposed framework (Xposed modules)")
    print(f"  {C.YELLOW}[0]{C.RST} Back\n")
    ch = input(f"  {C.WHITE}Select [{C.YELLOW}1{C.WHITE}/{C.YELLOW}2{C.WHITE}/{C.YELLOW}0{C.WHITE}]: {C.RST}").strip()
    if ch == "1":
        frida_gadget_patch(pkg)
    elif ch == "2":
        lspatch_patch(pkg)
    else:
        return


# ─── Frida Server Config ─────────────────────────────────────────────────────────

def frida_server_config():
    global FRIDA_CONN
    section("FRIDA SERVER CONFIG")

    print(f"\n  {C.CYAN}Current connection mode: {C.BOLD}{FRIDA_CONN}{C.RST}\n")
    print(f"  {C.YELLOW}[1]{C.RST} USB default (frida -U)")
    print(f"  {C.YELLOW}[2]{C.RST} Custom port (frida -H ip:port)")
    print(f"  {C.YELLOW}[3]{C.RST} Restart frida-server (default)")
    print(f"  {C.YELLOW}[4]{C.RST} Restart frida-server on custom port")
    print(f"  {C.YELLOW}[5]{C.RST} Kill frida-server")
    print(f"  {C.DIM}[0] Back{C.RST}")

    choice = input(f"\n  {C.GREEN}Select ▸ {C.RST}").strip()

    if choice == "1":
        FRIDA_CONN = "-U"
        # Restart on default
        start_frida_server(FRIDA_SERVER_PATH)
        print(f"  {C.GREEN}[+] Connection mode: -U (USB default){C.RST}")

    elif choice == "2":
        addr = input(f"  {C.GREEN}Enter ip:port (e.g. 127.0.0.1:4444) ▸ {C.RST}").strip()
        if addr:
            port = addr.split(":")[-1]
            listen_addr = f"0.0.0.0:{port}"
            if start_frida_server(FRIDA_SERVER_PATH, listen_addr):
                adb(f"forward tcp:{port} tcp:{port}")
                FRIDA_CONN = f"-H {addr}"
                print(f"  {C.GREEN}[+] Frida-server started on {listen_addr}{C.RST}")
                print(f"  {C.GREEN}[+] Connection mode: {FRIDA_CONN}{C.RST}")
                print(f"  {C.DIM}adb forward tcp:{port} tcp:{port}{C.RST}")
            else:
                print(f"  {C.RED}[-] Failed to start frida-server on {listen_addr}{C.RST}")

    elif choice == "3":
        if start_frida_server(FRIDA_SERVER_PATH):
            FRIDA_CONN = "-U"
            print(f"  {C.GREEN}[+] Frida-server restarted (USB default){C.RST}")
        else:
            print(f"  {C.RED}[-] Failed to start frida-server{C.RST}")

    elif choice == "4":
        addr = input(f"  {C.GREEN}Listen address (e.g. 0.0.0.0:4444) ▸ {C.RST}").strip()
        if addr:
            if start_frida_server(FRIDA_SERVER_PATH, addr):
                port = addr.split(":")[-1]
                adb(f"forward tcp:{port} tcp:{port}")
                FRIDA_CONN = f"-H 127.0.0.1:{port}"
                print(f"  {C.GREEN}[+] Frida-server started on {addr}{C.RST}")
                print(f"  {C.GREEN}[+] Connection mode: {FRIDA_CONN}{C.RST}")
                print(f"  {C.DIM}adb forward tcp:{port} tcp:{port}{C.RST}")
            else:
                print(f"  {C.RED}[-] Failed to start frida-server{C.RST}")

    elif choice == "5":
        adb_su("pkill -f frida-server 2>/dev/null")
        print(f"  {C.GREEN}[+] Frida-server killed{C.RST}")

    pause()

# ─── 12. Runtime Security Check ──────────────────────────────────────────────────

def _runtime_data_check(pkg, launch=True):
    """Launch the app and scan SharedPrefs/databases for runtime secrets."""
    findings = []

    if launch:
        print(f"  {C.DIM}Launching {pkg}...{C.RST}")
        launch_out = adb_shell(
            f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1 2>/dev/null",
            timeout=10,
        )
        _require_app_launch(launch_out)
        print(f"  {C.DIM}Waiting 5 seconds for app to initialize...{C.RST}")
        time.sleep(5)

    # Scan SharedPrefs
    prefs_dir = f"/data/data/{pkg}/shared_prefs"
    quoted_prefs = shlex.quote(prefs_dir)
    files_out = adb_su(
        f"if [ -d {quoted_prefs} ]; then ls {quoted_prefs} 2>/dev/null; fi",
        timeout=10,
    )
    _require_runtime_command(
        files_out, "listing SharedPreferences", partial_findings=findings
    )
    if "No such file" not in files_out:
        for fname in files_out.splitlines():
            fname = fname.strip()
            if not fname or not fname.endswith(".xml"):
                continue
            content = adb_su(f"cat {shlex.quote(f'{prefs_dir}/{fname}')} 2>/dev/null", timeout=10)
            _require_runtime_command(
                content, f"reading SharedPreferences {fname}",
                partial_findings=findings,
            )
            for val in _find_secret_matches(content):
                val_lower = val.lower()
                if re.match(r'eyJ[A-Za-z0-9_-]{10,}', val):
                    sev, slabel = "CRITICAL", "JWT token"
                elif any(kw in val_lower for kw in ('bearer', 'auth_token', 'session_token', 'refresh_token')):
                    sev, slabel = "CRITICAL", "Auth token"
                elif any(kw in val_lower for kw in ('api_key', 'apikey', 'api-key')):
                    sev, slabel = "HIGH", "API key"
                elif any(kw in val_lower for kw in ('password', 'passwd', 'pwd')):
                    sev, slabel = "CRITICAL", "Password"
                elif any(kw in val_lower for kw in ('secret', 'private_key', 'signing_key')):
                    sev, slabel = "HIGH", "Secret/key"
                elif 'AKIA' in val:
                    sev, slabel = "CRITICAL", "AWS Access Key"
                elif val.startswith('AIza'):
                    sev, slabel = "HIGH", "Google API key"
                else:
                    sev, slabel = "MEDIUM", "Potential secret"
                findings.append((sev, slabel, fname, _redact(val[:120])))

            pii_hits = _scan_pii(content)
            for plabel, val in pii_hits:
                findings.append(("MEDIUM", f"PII ({plabel})", fname, _redact(val[:120])))

    # Scan databases
    db_dir = f"/data/data/{pkg}"
    db_files_out = adb_su(
        f"find {shlex.quote(db_dir)} -maxdepth 3 \\( -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' \\) 2>/dev/null",
        timeout=15)
    _require_runtime_command(
        db_files_out, "enumerating application databases",
        partial_findings=findings,
    )
    if db_files_out:
        for dbf in db_files_out.splitlines():
            dbf = dbf.strip()
            if not dbf:
                continue
            dbname = os.path.basename(dbf)
            header = adb_su(f"xxd -l 16 {shlex.quote(dbf)} 2>/dev/null", timeout=5)
            _require_runtime_command(
                header, f"reading database header for {dbname}",
                partial_findings=findings,
            )
            if not header:
                raise RuntimeCheckUnavailable(
                    f"reading database header for {dbname}: no output",
                    partial_findings=findings,
                )
            if not header or "5351 4c69 7465" not in header:
                continue
            tables = adb_su(f"sqlite3 {shlex.quote(dbf)} '.tables' 2>/dev/null", timeout=10)
            _require_runtime_command(
                tables, f"enumerating tables in {dbname}",
                partial_findings=findings,
            )
            if "not found" in tables.lower():
                raise RuntimeCheckUnavailable(
                    f"enumerating tables in {dbname}: sqlite3 is unavailable",
                    partial_findings=findings,
                )
            for table in tables.split()[:10]:
                try:
                    table_ident = _sqlite_identifier(table)
                except ValueError:
                    continue
                sample = _sqlite_read(
                    dbf, f"SELECT * FROM {table_ident} LIMIT 5", timeout=5  # nosec B608
                )
                _require_runtime_command(
                    sample, f"reading {dbname}/{table}",
                    partial_findings=findings,
                )
                for val in _find_secret_matches(sample):
                    findings.append(("HIGH", "Secret in DB", f"{dbname}/{table}",
                                     _redact(val[:120])))
                pii_hits = _scan_pii(sample)
                for plabel, val in pii_hits:
                    findings.append(("MEDIUM", f"PII ({plabel}) in DB",
                                     f"{dbname}/{table}", _redact(val[:120])))

    return findings


def _check_world_readable(pkg):
    """Check for world-readable files in app data directory."""
    findings = []
    out = adb_su(f"find {shlex.quote(f'/data/data/{pkg}')} -perm -o+r -type f 2>/dev/null", timeout=15)
    _require_runtime_command(out, "checking world-readable files")
    if "No such file" in out:
        raise RuntimeCheckUnavailable("application data directory does not exist")
    if out:
        paths = [f.strip() for f in out.splitlines() if f.strip()]
        modes = _batch_stat(paths)
        for fpath in paths:
            perms = modes.get(fpath, "?")
            rel = fpath.replace(f"/data/data/{pkg}/", "")
            findings.append((rel, perms))
    return findings


def _probe_exported_components(pkg):
    """Try launching exported activities for manual access-control review."""
    findings = []

    work_dir, decompiled_dir = _pull_and_decompile(pkg)
    if not decompiled_dir:
        raise RuntimeCheckUnavailable("could not obtain a decompiled APK")

    manifest = _parse_manifest(decompiled_dir)
    if not manifest["parsed"]:
        raise RuntimeCheckUnavailable("could not parse AndroidManifest.xml")

    exported = manifest["exported"]
    activities = exported.get("activity", [])

    for comp in activities:
        name = comp["name"]
        actions = comp.get("actions", [])
        categories = comp.get("categories", [])
        # Skip only a real launcher entry. MAIN without LAUNCHER is still an
        # externally reachable non-launcher activity that should be probed.
        if ("android.intent.action.MAIN" in actions
                and "android.intent.category.LAUNCHER" in categories):
            continue

        stop_out = adb_shell(f"am force-stop {pkg}", timeout=5)
        _require_runtime_command(
            stop_out, f"stopping {pkg}", partial_findings=findings
        )
        time.sleep(0.3)

        cmd = f"am start -n {shlex.quote(f'{pkg}/{name}')}"
        if actions:
            cmd += f" -a {shlex.quote(actions[0])}"
        out = adb_shell(cmd, timeout=10)
        _require_runtime_command(
            out, f"launching exported activity {name}",
            partial_findings=findings,
        )

        if "SecurityException" in out or "not exported" in out.lower():
            findings.append(("PASS", name, "Not actually exported"))
        elif "Error" in out or "Exception" in out:
            findings.append(("INFO", name,
                             "Launch failed or activity crashed; access control was not established"))
        else:
            time.sleep(1)
            focus = adb_shell("dumpsys activity activities | grep mResumedActivity", timeout=5)
            _require_runtime_command(
                focus, "checking resumed activity", partial_findings=findings
            )
            if focus and name.split(".")[-1] in focus:
                findings.append(("MEDIUM", name,
                                 "Externally launchable; authentication requires manual review"))
            else:
                findings.append(("INFO", name, "Sent start but unclear if it rendered"))

    return findings


_NO_CLIPBOARD_BASELINE = object()


def _read_clipboard_text():
    """Read clipboard text without relying on version-specific Binder codes."""
    dump = adb_su("dumpsys clipboard", timeout=10)
    _require_runtime_command(dump, "reading clipboard")
    if not dump:
        return ""
    if re.search(r"(?:mPrimaryClip|primary clip)\s*[=:]\s*(?:null|none)",
                 dump, re.IGNORECASE):
        return ""
    match = re.search(r'mPrimaryClip=ClipData\{[^}]*\{T:([^}]+)\}', dump)
    if match:
        return match.group(1).strip()
    # Output varies across Android releases. If a clip exists but this build's
    # format is unknown, a clean result cannot be asserted.
    raise RuntimeCheckUnavailable("clipboard output format is unsupported")


def _check_clipboard_leak(pkg, launch=True, baseline=_NO_CLIPBOARD_BASELINE):
    """Monitor clipboard after interacting with the app."""
    findings = []

    if launch:
        baseline = _read_clipboard_text()
        print(f"  {C.DIM}Launching {pkg} for clipboard check...{C.RST}")
        launch_out = adb_shell(
            f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1 2>/dev/null",
            timeout=10,
        )
        _require_app_launch(launch_out, "launching target for clipboard check")
        time.sleep(3)

    clip_text = _read_clipboard_text()

    if baseline is not _NO_CLIPBOARD_BASELINE and clip_text == baseline:
        return findings

    if clip_text and len(clip_text) > 2:
        if _find_secret_matches(clip_text, per_pattern_limit=1):
            findings.append(("HIGH", "Secret in clipboard", _redact(clip_text[:120])))
        pii_hits = _scan_pii(clip_text)
        for plabel, val in pii_hits:
            findings.append(("MEDIUM", f"PII ({plabel}) in clipboard", _redact(val[:120])))
        if not findings:
            label = ("Clipboard changed after launch"
                     if baseline is not _NO_CLIPBOARD_BASELINE
                     else "Clipboard has content (no attribution baseline)")
            findings.append(("INFO", label, _redact(clip_text[:120])))

    return findings


def _check_logcat_leakage(pkg, launch=True):
    """Capture logcat during app launch and scan for secrets."""
    findings = []

    if launch:
        clear_out = adb_shell("logcat -c", timeout=5)
        _require_runtime_command(clear_out, "clearing logcat")

        print(f"  {C.DIM}Launching {pkg} for logcat capture...{C.RST}")
        launch_out = adb_shell(
            f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1 2>/dev/null",
            timeout=10,
        )
        _require_app_launch(launch_out, "launching target for logcat capture")
        time.sleep(5)

    # Try to get app PID for filtered capture; fall back to unfiltered
    pid_out = adb_shell(f"pidof {pkg}", timeout=5)
    _require_runtime_command(pid_out, "resolving target process ID")
    pids = pid_out.split()
    if not pids or any(not pid.isdigit() for pid in pids):
        raise RuntimeCheckUnavailable(
            "target process is not running; logcat cannot be attributed"
        )
    log_chunks = []
    for pid in pids:
        logs = adb_shell(f"logcat -d -t 2000 --pid={pid}", timeout=15)
        _require_runtime_command(logs, f"capturing logcat for PID {pid}")
        if logs:
            log_chunks.append(logs)
    logs = "\n".join(log_chunks)

    app_logs = []
    for line in logs.splitlines():
        line_stripped = line.strip()
        if line_stripped:
            app_logs.append(line_stripped)

    full_log = "\n".join(app_logs)

    secret_line_map = {}
    for i, line in enumerate(app_logs, 1):
        for val in _find_secret_matches(line):
            if any(fp in val.lower() for fp in [
                'password=*', 'key=com.', 'key=android.',
                'access_network_state', 'access_wifi_state',
            ]):
                continue
            if re.match(r'eyJ[A-Za-z0-9_-]{10,}', val):
                sev, slabel = "CRITICAL", "JWT token"
            elif any(kw in val.lower() for kw in ('bearer', 'auth_token', 'password')):
                sev, slabel = "HIGH", "Auth credential"
            else:
                sev, slabel = "MEDIUM", "Potential secret"
            key = val[:40]
            if key not in secret_line_map:
                secret_line_map[key] = []
            if len(secret_line_map[key]) < 3:
                secret_line_map[key].append((i, _redact(val[:120]), sev, slabel))

    for key, occurrences in secret_line_map.items():
        line_num, val, sev, slabel = occurrences[0]
        findings.append((sev, slabel, f"line {line_num}", val[:80]))

    pii_hits = _scan_pii(full_log)
    seen_pii = set()
    for plabel, val in pii_hits:
        if val not in seen_pii:
            seen_pii.add(val)
            findings.append(("MEDIUM", f"PII ({plabel})", "logcat", _redact(val[:120])))

    return findings


def _check_webview_cache(pkg):
    """Look for cached web content in app data."""
    findings = []
    cache_paths = [
        ("app_webview/Cache", "WebView cache"),
        ("app_webview/Cookies", "WebView cookies DB"),
        ("app_webview/Web Data", "WebView web data"),
        ("app_webview/Local Storage", "WebView local storage"),
        ("app_webview/Session Storage", "WebView session storage"),
    ]
    data_dir = f"/data/data/{pkg}"

    for rel_path, cache_label in cache_paths:
        full_path = f"{data_dir}/{rel_path}"
        quoted_path = shlex.quote(full_path)
        out = adb_su(
            f"if [ -f {quoted_path} ]; then "
            f"[ -s {quoted_path} ] && echo EXISTS || echo ABSENT; "
            f"elif [ -d {quoted_path} ]; then "
            f"find {quoted_path} -type f -size +0c -print -quit 2>/dev/null; "
            f"else echo ABSENT; fi",
            timeout=5,
        )
        _require_runtime_command(out, f"checking {cache_label}")
        if out and out != "ABSENT":
            size_out = adb_su(f"du -sh {quoted_path} 2>/dev/null", timeout=5)
            size = size_out.split()[0] if not _is_err(size_out) and size_out.split() else "?"
            findings.append((cache_label, rel_path, size))

    return findings


def runtime_security_check(pkg):
    """Perform dynamic runtime security checks using ADB commands."""
    section("RUNTIME SECURITY ANALYSIS")
    print(f"\n  {C.CYAN}Target: {C.BOLD}{pkg}{C.RST}")
    print(f"  {C.DIM}Running ADB-based runtime checks (no Frida required)...{C.RST}\n")

    total_critical = 0
    total_high = 0
    total_medium = 0
    total_pass = 0
    total_inconclusive = 0

    def mark_inconclusive(label, reason):
        nonlocal total_inconclusive
        total_inconclusive += 1
        detail = _terminal_safe(str(reason)).replace("\n", " ").strip()
        if len(detail) > 180:
            detail = detail[:177] + "..."
        print(f"    {C.YELLOW}[INCONCLUSIVE]{C.RST} {label}"
              f" {C.DIM}-- {detail or 'required data was unavailable'}{C.RST}")

    # A failed transport must stop the scan before any empty helper result can
    # be mistaken for evidence that the app is safe.
    device_probe = adb_shell("getprop ro.build.version.sdk", timeout=10)
    if (_command_failed(device_probe)
            or not str(device_probe or "").strip().isdigit()):
        mark_inconclusive("Device preflight", device_probe or "no SDK response")
        print(f"\n  {C.CYAN}{'='*56}{C.RST}")
        print(f"  {C.BOLD}RUNTIME SECURITY SUMMARY{C.RST}")
        print(f"  {C.RED}{C.BOLD}CRITICAL: 0{C.RST}  {C.RED}HIGH: 0{C.RST}  "
              f"{C.YELLOW}MEDIUM: 0{C.RST}  {C.GREEN}PASS: 0{C.RST}  "
              f"{C.YELLOW}INCONCLUSIVE: {total_inconclusive}{C.RST}")
        print(f"\n  {C.YELLOW}{C.BOLD}Overall: INCONCLUSIVE -- device unavailable; no security conclusion was made{C.RST}")
        pause()
        return

    root_probe = adb_su("id", timeout=10)
    root_ready = not _command_failed(root_probe) and "uid=0" in root_probe

    clipboard_baseline = _NO_CLIPBOARD_BASELINE
    clipboard_baseline_error = None
    if root_ready:
        try:
            clipboard_baseline = _read_clipboard_text()
        except Exception as exc:
            clipboard_baseline_error = exc

    logcat_clear = adb_shell("logcat -c", timeout=5)
    logcat_ready = not _command_failed(logcat_clear)
    logcat_error = logcat_clear if not logcat_ready else None

    print(f"  {C.DIM}Launching {pkg}...{C.RST}")
    launch_out = adb_shell(
        f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1 2>/dev/null",
        timeout=10,
    )
    try:
        _require_app_launch(launch_out)
        launch_ready = True
    except RuntimeCheckUnavailable:
        launch_ready = False
    if launch_ready:
        print(f"  {C.DIM}Waiting 5 seconds for app to initialize...{C.RST}")
        time.sleep(5)

    # ── 1. Data at Rest (Post-Launch) ───────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}-- Data at Rest (Post-Launch) --{C.RST}")
    print(f"  {C.DIM}Scanning application-private storage for runtime secrets...{C.RST}")

    data_available = root_ready
    data_error = None
    data_findings = []
    if not root_ready:
        data_error = "root access is unavailable"
    else:
        try:
            data_findings = _runtime_data_check(pkg, launch=False)
        except Exception as exc:
            data_findings = list(getattr(exc, "partial_findings", []))
            data_available = False
            data_error = exc

    if data_findings:
        for sev, dlabel, source, val in data_findings:
            if sev == "CRITICAL":
                total_critical += 1
                print(f"    {C.RED}{C.BOLD}[CRITICAL]{C.RST} {dlabel} found in {C.WHITE}{source}{C.RST}")
            elif sev == "HIGH":
                total_high += 1
                print(f"    {C.RED}[HIGH]{C.RST} {dlabel} found in {C.WHITE}{source}{C.RST}")
            elif sev == "MEDIUM":
                total_medium += 1
                print(f"    {C.YELLOW}[MEDIUM]{C.RST} {dlabel} found in {C.WHITE}{source}{C.RST}")
            display_val = val if len(val) <= 60 else val[:57] + "..."
            print(f"      {C.DIM}-> {display_val}{C.RST}")
            report.add_finding("Runtime: Data at Rest", f"{dlabel} in {source}",
                               sev, "HIGH", f"Runtime secret found: {display_val}",
                               "Remove secrets from SharedPrefs/databases", "MASVS-STORAGE-1", "CWE-312")
    if not data_available:
        mark_inconclusive("Data-at-rest check", data_error)
    elif not launch_ready:
        mark_inconclusive("Post-launch data coverage", launch_out)
    elif not data_findings:
        total_pass += 1
        print(f"    {C.GREEN}[PASS]{C.RST} No runtime secrets detected in SharedPrefs/databases")

    # ── 2. File Permissions ─────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}-- File Permissions --{C.RST}")
    print(f"  {C.DIM}Checking for world-readable files...{C.RST}")
    perm_available = root_ready
    perm_error = None
    perm_findings = []
    if not root_ready:
        perm_error = "root access is unavailable"
    else:
        try:
            perm_findings = _check_world_readable(pkg)
        except Exception as exc:
            perm_available = False
            perm_error = exc

    if perm_findings:
        total_high += 1
        print(f"    {C.RED}[HIGH]{C.RST} World-readable files found: {C.WHITE}{len(perm_findings)}{C.RST}")
        for rel_path, perms in perm_findings[:10]:
            print(f"      {C.DIM}-> {rel_path} (mode: {perms}){C.RST}")
        if len(perm_findings) > 10:
            print(f"      {C.DIM}... and {len(perm_findings) - 10} more{C.RST}")
        report.add_finding("Runtime: File Permissions", f"World-readable files: {len(perm_findings)}",
                           "HIGH", "HIGH", "Files in app data directory are world-readable",
                           "Set proper file permissions (0600/0660)", "MASVS-STORAGE-2", "CWE-276")
    elif perm_available:
        total_pass += 1
        print(f"    {C.GREEN}[PASS]{C.RST} No world-readable files found")
    else:
        mark_inconclusive("File-permission check", perm_error)

    # ── 3. Exported Component Probing ───────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}-- Exported Components --{C.RST}")
    print(f"  {C.DIM}Probing exported activities for auth bypass...{C.RST}")
    comp_available = True
    comp_error = None
    comp_findings = []
    try:
        comp_findings = _probe_exported_components(pkg)
    except Exception as exc:
        comp_findings = list(getattr(exc, "partial_findings", []))
        comp_available = False
        comp_error = exc

    if comp_findings:
        for sev, cname, detail in comp_findings:
            short_name = cname.rsplit(".", 1)[-1] if "." in cname else cname
            if sev == "MEDIUM":
                total_medium += 1
                print(f"    {C.YELLOW}[MEDIUM]{C.RST} Activity is externally launchable: {C.WHITE}{short_name}{C.RST}")
                print(f"      {C.DIM}-> {cname}{C.RST}")
                report.add_finding("Runtime: Exported Components", f"Externally launchable: {cname}",
                                   "MEDIUM", "HIGH",
                                   f"Exported activity {cname} can be launched externally; authentication was not inferred",
                                   "Manually verify authorization checks or remove the exported flag",
                                   "MASVS-PLATFORM-1", "CWE-926")
            elif sev == "PASS":
                total_pass += 1
                print(f"    {C.GREEN}[PASS]{C.RST} {short_name} {C.DIM}-- {detail}{C.RST}")
            else:
                print(f"    {C.BLUE}[INFO]{C.RST} {short_name} {C.DIM}-- {detail}{C.RST}")
    elif comp_available:
        print(f"    {C.DIM}No non-launcher exported activities to probe{C.RST}")
    else:
        mark_inconclusive("Exported-component probe", comp_error)

    # ── 4. Clipboard Leakage ────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}-- Clipboard Leakage --{C.RST}")
    print(f"  {C.DIM}Checking clipboard after app launch...{C.RST}")
    clip_available = root_ready and launch_ready and clipboard_baseline_error is None
    clip_error = None
    clip_findings = []
    if not root_ready:
        clip_error = "root access is unavailable"
    elif not launch_ready:
        clip_error = f"target launch failed: {launch_out}"
    elif clipboard_baseline_error is not None:
        clip_error = clipboard_baseline_error
    else:
        try:
            clip_findings = _check_clipboard_leak(
                pkg, launch=False, baseline=clipboard_baseline
            )
        except Exception as exc:
            clip_available = False
            clip_error = exc

    if clip_findings:
        for sev, clabel, val in clip_findings:
            if sev == "HIGH":
                total_high += 1
                print(f"    {C.RED}[HIGH]{C.RST} {clabel}")
            elif sev == "MEDIUM":
                total_medium += 1
                print(f"    {C.YELLOW}[MEDIUM]{C.RST} {clabel}")
            else:
                print(f"    {C.BLUE}[INFO]{C.RST} {clabel}")
            display_val = val if len(val) <= 60 else val[:57] + "..."
            print(f"      {C.DIM}-> {display_val}{C.RST}")
            if sev in ("HIGH", "MEDIUM"):
                report.add_finding(
                    "Runtime: Clipboard Leakage", clabel, sev, "MEDIUM",
                    f"Sensitive clipboard content appeared after launch: {display_val}",
                    "Avoid copying sensitive values or clear them promptly",
                    "MASVS-STORAGE-1", "CWE-200",
                )
    elif clip_available:
        total_pass += 1
        print(f"    {C.GREEN}[PASS]{C.RST} No sensitive data found in clipboard")
    else:
        mark_inconclusive("Clipboard check", clip_error)

    # ── 5. Logcat Leakage ───────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}-- Logcat Leakage --{C.RST}")
    print(f"  {C.DIM}Capturing logcat during app launch...{C.RST}")
    log_available = launch_ready and logcat_ready
    log_error = None
    log_findings = []
    if not launch_ready:
        log_error = f"target launch failed: {launch_out}"
    elif not logcat_ready:
        log_error = f"logcat clear failed: {logcat_error}"
    else:
        try:
            log_findings = _check_logcat_leakage(pkg, launch=False)
        except Exception as exc:
            log_available = False
            log_error = exc

    if log_findings:
        log_crit = sum(1 for s, *_ in log_findings if s == "CRITICAL")
        log_high = sum(1 for s, *_ in log_findings if s == "HIGH")
        log_med = sum(1 for s, *_ in log_findings if s == "MEDIUM")
        total_critical += log_crit
        total_high += log_high
        total_medium += log_med

        total_log_issues = len(log_findings)
        print(f"    {C.YELLOW}[MEDIUM]{C.RST} {total_log_issues} potential secret(s)/PII found in logcat during app launch")
        for sev, llabel, location, val in log_findings[:15]:
            if sev == "CRITICAL":
                tag = f"{C.RED}{C.BOLD}[CRITICAL]{C.RST}"
            elif sev == "HIGH":
                tag = f"{C.RED}[HIGH]{C.RST}"
            else:
                tag = f"{C.YELLOW}[MEDIUM]{C.RST}"
            display_val = val if len(val) <= 60 else val[:57] + "..."
            print(f"      {tag} {llabel} at {location}")
            print(f"        {C.DIM}-> {display_val}{C.RST}")
            report.add_finding("Runtime: Logcat Leakage", f"{llabel} at {location}",
                               sev, "MEDIUM", f"Secret/PII leaked in logcat: {display_val}",
                               "Remove debug logging of sensitive data", "MASVS-STORAGE-1", "CWE-532")
        if len(log_findings) > 15:
            print(f"      {C.DIM}... and {len(log_findings) - 15} more{C.RST}")
    elif log_available:
        total_pass += 1
        print(f"    {C.GREEN}[PASS]{C.RST} No secrets or PII leaked in logcat during launch")
    else:
        mark_inconclusive("Logcat check", log_error)

    # ── 6. WebView Cache ────────────────────────────────────────────────────
    print(f"\n  {C.YELLOW}{C.BOLD}-- WebView Cache --{C.RST}")
    print(f"  {C.DIM}Checking for WebView cached data...{C.RST}")
    wv_available = root_ready
    wv_error = None
    wv_findings = []
    if not root_ready:
        wv_error = "root access is unavailable"
    else:
        try:
            wv_findings = _check_webview_cache(pkg)
        except Exception as exc:
            wv_available = False
            wv_error = exc

    if wv_findings:
        total_medium += 1
        print(f"    {C.YELLOW}[MEDIUM]{C.RST} WebView cache present")
        for wlabel, wpath, wsize in wv_findings:
            print(f"      {C.DIM}-> {wlabel}: {wpath} ({wsize}){C.RST}")
        report.add_finding("Runtime: WebView Cache", f"WebView cache present ({len(wv_findings)} items)",
                           "MEDIUM", "HIGH", "Cached web data found in app directory",
                           "Clear WebView cache on app exit or use no-cache headers", "MASVS-STORAGE-2", "CWE-524")
    elif wv_available:
        total_pass += 1
        print(f"    {C.GREEN}[PASS]{C.RST} No WebView cache found")
    else:
        mark_inconclusive("WebView-cache check", wv_error)

    cleanup_out = adb_shell(f"am force-stop {pkg}", timeout=5)
    if _command_failed(cleanup_out):
        mark_inconclusive("Runtime cleanup", cleanup_out)

    # ── Summary ─────────────────────────────────────────────────────────────
    print(f"\n  {C.CYAN}{'='*56}{C.RST}")
    print(f"  {C.BOLD}RUNTIME SECURITY SUMMARY{C.RST}")
    print(f"  {C.RED}{C.BOLD}CRITICAL: {total_critical}{C.RST}  "
          f"{C.RED}HIGH: {total_high}{C.RST}  "
          f"{C.YELLOW}MEDIUM: {total_medium}{C.RST}  "
          f"{C.GREEN}PASS: {total_pass}{C.RST}  "
          f"{C.YELLOW}INCONCLUSIVE: {total_inconclusive}{C.RST}")

    if total_critical > 0:
        suffix = " (INCOMPLETE COVERAGE)" if total_inconclusive else ""
        print(f"\n  {C.RED}{C.BOLD}Overall: CRITICAL RISK{suffix} -- secrets exposed at runtime{C.RST}")
    elif total_high > 0:
        suffix = " (INCOMPLETE COVERAGE)" if total_inconclusive else ""
        print(f"\n  {C.RED}{C.BOLD}Overall: HIGH RISK{suffix} -- significant runtime issues found{C.RST}")
    elif total_medium > 0:
        suffix = " (INCOMPLETE COVERAGE)" if total_inconclusive else ""
        print(f"\n  {C.YELLOW}{C.BOLD}Overall: MODERATE RISK{suffix} -- some runtime concerns{C.RST}")
    elif total_inconclusive > 0:
        print(f"\n  {C.YELLOW}{C.BOLD}Overall: INCONCLUSIVE -- one or more required checks did not run{C.RST}")
    else:
        print(f"\n  {C.GREEN}{C.BOLD}Overall: LOW RISK -- runtime checks passed{C.RST}")

    pause()


# ─── Main Menu ──────────────────────────────────────────────────────────────────

def main_menu(device_info, has_root, selected_pkg):
    clear()
    banner()

    # Device info bar
    print(f"  {C.GREEN}[✓] Connected{C.RST}: {C.WHITE}{device_info['model']}{C.RST} "
          f"{C.DIM}| Android {device_info['android']} | SDK {device_info['sdk']} | {device_info['serial']}{C.RST}")
    if has_root:
        print(f"  {C.RED}[✓] Root Access{C.RST}: {C.GREEN}Confirmed{C.RST}")
    else:
        print(f"  {C.RED}[✗] Root Access{C.RST}: {C.YELLOW}Not available — some features may fail{C.RST}")

    # Selected app bar
    if selected_pkg:
        print(f"  {C.MAGENTA}[✓] Target App{C.RST}: {C.WHITE}{C.BOLD}{selected_pkg}{C.RST}")
    else:
        print(f"  {C.YELLOW}[!] Target App{C.RST}: {C.DIM}None selected{C.RST}")

    print(f"""
  {C.CYAN}╔══════════════════════════════════════════╗
  ║           {C.BOLD}{C.WHITE}M A I N   M E N U{C.RST}{C.CYAN}               ║
  ╠══════════════════════════════════════════╣
  ║                                          ║
  ║  {C.YELLOW}[1]{C.CYAN} App Analysis                        ║
  ║  {C.YELLOW}[2]{C.CYAN} Storage Audit                       ║
  ║  {C.YELLOW}[3]{C.CYAN} Shell Access                        ║
  ║  {C.YELLOW}[4]{C.CYAN} Screenshot                          ║
  ║  {C.YELLOW}[5]{C.CYAN} Security Scan                       ║
  ║  {C.YELLOW}[6]{C.CYAN} Keyboard Cache Detection            ║
  ║      {C.DIM}Check LokiBoard plaintext cache{C.RST}{C.CYAN}     ║
  ║  {C.YELLOW}[7]{C.CYAN} Logcat Live Monitor                 ║
  ║      {C.DIM}Filter logcat output in real-time{C.RST}{C.CYAN}   ║
  ║  {C.YELLOW}[8]{C.CYAN} Frida CodeShare                     ║
  ║  {C.YELLOW}[9]{C.CYAN} Binary Patcher                      ║
  ║      {C.DIM}Frida Gadget or LSPatch (Xposed){C.RST}{C.CYAN}    ║
  ║  {C.YELLOW}[10]{C.CYAN} Frida Server Config                ║
  ║  {C.YELLOW}[11]{C.CYAN} Testcases for Fun                  ║
  ║      {C.DIM}Exported components, clipboard, URLs{C.RST}{C.CYAN} ║
  ║  {C.YELLOW}[12]{C.CYAN} Runtime Security Check              ║
  ║      {C.DIM}ADB-based dynamic analysis checks{C.RST}{C.CYAN}   ║
  ║                                          ║
  ║  {C.YELLOW}[a]{C.CYAN} Switch App                          ║
  ║  {C.YELLOW}[r]{C.CYAN} Export Report                       ║
  ║      {C.DIM}JSON or HTML report of findings{C.RST}{C.CYAN}     ║
  ║  {C.DIM}[0] Exit{C.CYAN}                                ║
  ║                                          ║
  ╚══════════════════════════════════════════╝{C.RST}
""")

def export_report_menu():
    """Interactive menu to export collected findings as JSON or HTML."""
    section("EXPORT REPORT")
    if not report.findings:
        print(f"\n  {C.YELLOW}[!] No findings collected yet.{C.RST}")
        print(f"  {C.DIM}Run a Security Scan (option 5) first to collect findings.{C.RST}")
        pause()
        return

    print(f"\n  {C.CYAN}Collected findings: {C.BOLD}{len(report.findings)}{C.RST}\n")
    print(f"  {C.YELLOW}[1]{C.RST} Export as JSON")
    print(f"  {C.YELLOW}[2]{C.RST} Export as HTML")
    print(f"  {C.DIM}[0] Back{C.RST}")

    try:
        choice = input(f"\n  {C.GREEN}Format ▸ {C.RST}").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return

    if choice == "0":
        return

    if choice == "1":
        fmt = "json"
        default_name = f"apkanalyzer_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    elif choice == "2":
        fmt = "html"
        default_name = f"apkanalyzer_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    else:
        print(f"  {C.RED}Invalid selection.{C.RST}")
        pause()
        return

    try:
        path_input = input(f"  {C.GREEN}Output path [{default_name}] ▸ {C.RST}").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return

    out_path = path_input if path_input else default_name

    try:
        if fmt == "json":
            report.export_json(out_path)
        else:
            report.export_html(out_path)
        abs_path = os.path.abspath(out_path)
        print(f"\n  {C.GREEN}[+] Report exported: {abs_path}{C.RST}")
    except Exception as e:
        print(f"\n  {C.RED}[!] Export failed: {e}{C.RST}")

    pause()


def main():
    clear()
    banner()
    print(f"  {C.CYAN}Connecting to device...{C.RST}\n")

    if shutil.which("adb") is None:
        print(f"  {C.RED}[✗] adb not found on PATH.{C.RST}")
        print(f"  {C.DIM}Install Android SDK platform-tools and make sure adb is on your PATH.{C.RST}")
        print(f"  {C.DIM}Download: https://developer.android.com/tools/releases/platform-tools{C.RST}")
        sys.exit(1)

    device = check_device()
    if not device:
        print(f"  {C.RED}[✗] No device connected.{C.RST}")
        print(f"  {C.DIM}Make sure USB debugging is enabled and the device is connected.{C.RST}")
        print(f"  {C.DIM}Run 'adb devices' to verify.{C.RST}")
        sys.exit(1)

    has_root = check_root()

    # Populate report with device info
    report.device_info = device

    # ── Frida-server handling ────────────────────────────────────────────
    if has_root:
        if check_frida_server():
            print(f"  {C.GREEN}[+] Frida-server already running{C.RST}")
            try:
                choice = input(f"  {C.YELLOW}Keep running or restart? [K/r] ▸ {C.RST}").strip().lower()
            except (EOFError, KeyboardInterrupt):
                choice = ""
            if choice == "r":
                print(f"  {C.DIM}Restarting frida-server...{C.RST}")
                if start_frida_server(FRIDA_SERVER_PATH):
                    print(f"  {C.GREEN}[+] Frida-server restarted (USB default){C.RST}")
                else:
                    print(f"  {C.YELLOW}[!] Frida-server failed to restart{C.RST}")
        else:
            print(f"  {C.DIM}Starting frida-server...{C.RST}")
            if start_frida_server(FRIDA_SERVER_PATH):
                print(f"  {C.GREEN}[+] Frida-server running (USB default){C.RST}")
            else:
                print(f"  {C.YELLOW}[!] Frida-server failed to start{C.RST}")
                print(f"  {C.DIM}  Push it once: adb push frida-server {FRIDA_SERVER_PATH}{C.RST}")
    print()

    # ── Select target app up front ──────────────────────────────────────
    print(f"  {C.CYAN}Loading installed apps...{C.RST}\n")
    apps = list_third_party_apps()
    selected_pkg = pick_app(apps)
    if not selected_pkg:
        print(f"\n  {C.CYAN}Goodbye.{C.RST}")
        print(f"  {C.DIM}Like this tool? Star it: {C.WHITE}https://github.com/worldtreeboy/apkAnalyzer{C.RST}\n")
        return

    report.target_app = selected_pkg

    # Options that require a selected app
    APP_REQUIRED = {"1", "2", "5", "7", "8", "9", "11", "12"}

    while True:
        main_menu(device, has_root, selected_pkg)
        try:
            choice = input(f"  {C.GREEN}Select option ▸ {C.RST}").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {C.CYAN}Goodbye.{C.RST}")
            print(f"  {C.DIM}Like this tool? Star it: {C.WHITE}https://github.com/worldtreeboy/apkAnalyzer{C.RST}\n")
            break

        if choice.lower() == "a":
            apps = list_third_party_apps()
            new_pkg = pick_app(apps)
            if new_pkg:
                selected_pkg = new_pkg
                report.target_app = new_pkg
                report.findings.clear()
                report.app_info.clear()
            continue

        if choice.lower() == "r":
            export_report_menu()
            continue

        if choice in APP_REQUIRED and not selected_pkg:
            print(f"  {C.RED}[!] No app selected. Press [a] to pick an app first.{C.RST}")
            time.sleep(1)
            continue

        if choice == "1":
            app_analysis(selected_pkg)
        elif choice == "2":
            storage_audit(selected_pkg)
        elif choice == "3":
            shell_access(selected_pkg)
        elif choice == "4":
            screenshot()
        elif choice == "5":
            security_scan(selected_pkg)
        elif choice == "6":
            keyboard_cache_check()
        elif choice == "7":
            logcat_monitor(selected_pkg)
        elif choice == "8":
            frida_codeshare(selected_pkg)
        elif choice == "9":
            binary_patcher(selected_pkg)
        elif choice == "10":
            frida_server_config()
        elif choice == "11":
            fun_testcases(selected_pkg)
        elif choice == "12":
            runtime_security_check(selected_pkg)
        elif choice == "0":
            print(f"\n  {C.CYAN}Goodbye.{C.RST}")
            print(f"  {C.DIM}Like this tool? Star it: {C.WHITE}https://github.com/worldtreeboy/apkAnalyzer{C.RST}\n")
            break
        else:
            print(f"  {C.RED}Invalid option.{C.RST}")
            time.sleep(0.5)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="APK Analyzer - Android Security Analysis Tool",
        add_help=True,
    )
    parser.add_argument("--report", choices=["json", "html"],
                        help="Export report format (json or html)")
    parser.add_argument("--output", default="",
                        help="Output file path for the report")
    args, _unknown = parser.parse_known_args()

    # Store CLI args for post-session auto-export
    _cli_report_format = args.report
    _cli_report_output = args.output

    main()

    # Auto-export report if --report was specified on CLI
    if _cli_report_format and report.findings:
        out_path = _cli_report_output
        if not out_path:
            out_path = f"apkanalyzer_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{_cli_report_format}"
        try:
            if _cli_report_format == "json":
                report.export_json(out_path)
            else:
                report.export_html(out_path)
            print(f"\n  {C.GREEN}[+] Report exported: {os.path.abspath(out_path)}{C.RST}")
        except Exception as e:
            print(f"\n  {C.RED}[!] Report export failed: {e}{C.RST}")
