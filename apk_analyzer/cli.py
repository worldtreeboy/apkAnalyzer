"""Headless CLI policy helpers independent of the interactive launcher."""

import os
import shutil
from datetime import datetime

from .process import safe_which


EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_INCONCLUSIVE = 2

FAIL_ON_LEVELS = ("critical", "high", "medium", "low", "info", "none")
_SEVERITY_RANK = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


def finding_meets_threshold(finding, threshold):
    """Return whether one finding reaches a ``--fail-on`` threshold."""
    normalized = str(threshold).lower()
    if normalized == "none":
        return False
    if normalized not in FAIL_ON_LEVELS:
        raise ValueError(f"unknown fail-on threshold: {threshold}")
    threshold_rank = _SEVERITY_RANK[normalized.upper()]
    # Unknown severities are treated conservatively instead of producing a
    # false-success CI exit code.
    finding_rank = _SEVERITY_RANK.get(
        str(finding.get("severity", "")).upper(), 0
    )
    return finding_rank <= threshold_rank


def scan_exit_code(collector, threshold="high", scan_complete=True):
    """Return deterministic CI status: 0 clean, 1 finding, 2 incomplete."""
    if not scan_complete or getattr(collector, "inconclusive", []):
        return EXIT_INCONCLUSIVE
    if any(
        finding_meets_threshold(finding, threshold)
        for finding in collector.findings
    ):
        return EXIT_FINDINGS
    return EXIT_OK


def default_report_path(report_format, directory=None):
    """Build a timestamped report path for a supported headless format."""
    normalized = str(report_format).lower()
    if normalized not in ("json", "html", "sarif"):
        raise ValueError(f"unsupported report format: {report_format}")
    filename = (
        "apkanalyzer_report_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}_"
        f"{os.getpid()}.{normalized}"
    )
    return os.path.join(directory or os.getcwd(), filename)


def export_report(collector, report_format, output_path):
    """Export one report without format branching in the legacy launcher."""
    normalized = str(report_format).lower()
    exporters = {
        "json": collector.export_json,
        "html": collector.export_html,
        "sarif": collector.export_sarif,
    }
    try:
        exporter = exporters[normalized]
    except KeyError as exc:
        raise ValueError(
            f"unsupported report format: {report_format}"
        ) from exc
    destination = os.path.abspath(os.fspath(output_path))
    parent = os.path.dirname(destination)
    if parent:
        os.makedirs(parent, exist_ok=True)
    exporter(destination)
    return destination


def resolve_bundletool_command(explicit_path=""):
    """Resolve bundletool to an argument list, never a host-shell string."""
    def checked_executable(path):
        resolved = os.fspath(path)
        # On Windows, CreateProcess dispatches .bat/.cmd files through cmd.exe
        # even when Python is called with shell=False.  An APK-controlled `&`
        # in a --bundle path can therefore become a second command.  A native
        # executable (or bundletool JAR launched by java) has true argv
        # boundaries and is the only safe supported form here.
        if (os.name == "nt"
                and os.path.splitext(resolved)[1].lower() in (".bat", ".cmd")):
            raise ValueError(
                "Windows batch wrappers are not supported for bundletool; "
                "provide the bundletool JAR or a native executable"
            )
        return resolved

    if explicit_path:
        candidate = os.path.abspath(os.fspath(explicit_path))
        if os.path.isfile(candidate) and candidate.lower().endswith(".jar"):
            java = safe_which("java", which=shutil.which)
            if not java:
                raise ValueError("Java is required to run the bundletool JAR")
            return [checked_executable(java), "-jar", candidate]
        if os.path.isfile(candidate):
            return [checked_executable(candidate)]
        executable = safe_which(
            os.fspath(explicit_path), which=shutil.which
        )
        if executable:
            return [checked_executable(executable)]
        raise ValueError(f"bundletool was not found: {explicit_path}")
    executable = safe_which("bundletool", which=shutil.which)
    return [checked_executable(executable)] if executable else []
