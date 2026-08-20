"""Finding collection and JSON/HTML/SARIF report rendering.

The legacy :mod:`apkAnalyzer` launcher re-exports this module's public objects
so existing imports continue to work while reporting evolves independently.
"""

import html as html_mod
import json
import os
import re
import tempfile
import urllib.parse
from datetime import datetime, timezone

from .version import TOOL_VERSION


REPORT_SCHEMA_VERSION = "2.0"
_SARIF_FALLBACK_ARTIFACT = "apkAnalyzer.py"


def _fallback_rule_id(category, title):
    """Build a deterministic compatibility ID when a caller has no rule key."""
    value = f"{category}.{title}".lower()
    slug = re.sub(r"[^a-z0-9]+", ".", value).strip(".")
    return f"apkanalyzer.{slug or 'finding'}"


def _sarif_level(severity):
    """Map APK Analyzer severities to SARIF result levels."""
    return {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }.get(str(severity).upper(), "warning")


def _sarif_fallback_uri(data):
    """Return a safe artifact URI for findings without precise locations."""
    artifact = data.get("app_info", {}).get("input_artifact", "")
    if isinstance(artifact, str):
        # ``input_artifact`` is populated by the headless launcher only after
        # terminal sanitization and credential redaction. Keep this final
        # boundary basename-only so a malformed integration value cannot add
        # URI roots or traversal components.
        artifact = artifact.replace("\\", "/").rsplit("/", 1)[-1].strip()
        if (artifact in ("", ".", "..")
                or any(ord(character) < 32 or ord(character) == 127
                       for character in artifact)
                or len(artifact) > 240):
            artifact = ""
    else:
        artifact = ""
    return urllib.parse.quote(
        artifact or _SARIF_FALLBACK_ARTIFACT,
        safe="._-",
    )


def now_iso():
    """Return an unambiguous UTC timestamp for reports and findings."""
    return datetime.now(timezone.utc).isoformat()


def _unicode_safe(value):
    """Recursively replace lone surrogates that UTF-8 reports cannot encode."""
    if isinstance(value, str):
        return "".join(
            "\ufffd" if 0xD800 <= ord(character) <= 0xDFFF else character
            for character in value
        )
    if isinstance(value, list):
        return [_unicode_safe(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_unicode_safe(item) for item in value)
    if isinstance(value, dict):
        return {
            _unicode_safe(key): _unicode_safe(item)
            for key, item in value.items()
        }
    return value


def _atomic_text_write(path, writer):
    """Write a report beside its destination, then atomically replace it."""
    destination = os.path.abspath(os.fspath(path))
    directory = os.path.dirname(destination)
    descriptor = None
    temporary = None
    try:
        descriptor, temporary = tempfile.mkstemp(
            # A destination may already use the filesystem's full NAME_MAX.
            # Repeating that basename in the temporary name makes an otherwise
            # valid report path fail before the atomic replace.
            prefix=".apkanalyzer-report-",
            suffix=".tmp",
            dir=directory,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as output:
            descriptor = None
            writer(output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
        temporary = None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            try:
                os.remove(temporary)
            except OSError:
                pass


class ReportCollector:
    """Accumulates findings throughout the session for JSON/HTML export."""

    SEVERITY_ORDER = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
    }

    def __init__(self):
        self.device_info = {}
        self.target_app = ""
        self.findings = []
        self.app_info = {}
        self.inconclusive = []
        self.timestamp = now_iso()

    def add_finding(self, category, title, severity, confidence, description,
                    remediation="", masvs="", cwe="", rule_id="",
                    locations=None):
        # Skip exact duplicates (same category/title/description) so re-running
        # a scan doesn't record the same finding twice.
        for finding in self.findings:
            if (finding["category"] == category
                    and finding["title"] == title
                    and finding["description"] == description):
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
            "rule_id": rule_id or _fallback_rule_id(category, title),
            "locations": list(locations or []),
            "timestamp": now_iso(),
        })

    def mark_inconclusive(self, check_id, reason):
        """Record unavailable scan evidence without fabricating a finding."""
        item = {
            "check_id": str(check_id),
            "reason": str(reason),
        }
        if item not in self.inconclusive:
            self.inconclusive.append(item)

    def reset(self):
        """Clear session state while retaining this shared collector object."""
        self.device_info.clear()
        self.target_app = ""
        self.findings.clear()
        self.app_info.clear()
        self.inconclusive.clear()
        self.timestamp = now_iso()

    def _build_report_dict(self):
        sorted_findings = sorted(
            self.findings,
            key=lambda finding: self.SEVERITY_ORDER.get(
                finding["severity"], 99
            ),
        )
        return _unicode_safe({
            "schema_version": REPORT_SCHEMA_VERSION,
            "tool": "APK Analyzer",
            "version": TOOL_VERSION,
            "generated_at": now_iso(),
            "device_info": self.device_info,
            "target_app": self.target_app,
            "app_info": self.app_info,
            "summary": {
                "total": len(sorted_findings),
                "critical": sum(
                    1 for finding in sorted_findings
                    if finding["severity"] == "CRITICAL"
                ),
                "high": sum(
                    1 for finding in sorted_findings
                    if finding["severity"] == "HIGH"
                ),
                "medium": sum(
                    1 for finding in sorted_findings
                    if finding["severity"] == "MEDIUM"
                ),
                "low": sum(
                    1 for finding in sorted_findings
                    if finding["severity"] == "LOW"
                ),
                "info": sum(
                    1 for finding in sorted_findings
                    if finding["severity"] == "INFO"
                ),
                "inconclusive": len(self.inconclusive),
            },
            "coverage": {
                "complete": not self.inconclusive,
                "inconclusive": list(self.inconclusive),
            },
            "findings": sorted_findings,
        })

    def export_json(self, path):
        data = self._build_report_dict()
        _atomic_text_write(
            path,
            lambda report_file: json.dump(
                data, report_file, indent=2, ensure_ascii=False
            ),
        )

    def _build_sarif_dict(self):
        """Return a SARIF 2.1.0 document for CI/code-scanning consumers."""
        data = self._build_report_dict()
        fallback_uri = _sarif_fallback_uri(data)
        rule_map = {}
        results = []
        for finding in data["findings"]:
            rule_id = finding["rule_id"]
            if rule_id not in rule_map:
                properties = {
                    "severity": finding["severity"],
                    "confidence": finding["confidence"],
                }
                tags = [
                    value for value in (finding.get("masvs"), finding.get("cwe"))
                    if value
                ]
                if tags:
                    properties["tags"] = tags
                rule = {
                    "id": rule_id,
                    "name": finding["title"],
                    "shortDescription": {"text": finding["title"]},
                    "fullDescription": {"text": finding["description"]},
                    "properties": properties,
                }
                if finding.get("remediation"):
                    rule["help"] = {
                        "text": finding["remediation"],
                        "markdown": finding["remediation"],
                    }
                rule_map[rule_id] = rule

            result = {
                "ruleId": rule_id,
                "level": _sarif_level(finding["severity"]),
                "message": {"text": finding["description"]},
                "properties": {
                    "severity": finding["severity"],
                    "confidence": finding["confidence"],
                    "category": finding["category"],
                },
            }
            sarif_locations = []
            for location in finding.get("locations", []):
                path = str(location.get("path", "")).replace("\\", "/")
                if not path:
                    continue
                physical = {
                    # SARIF artifact locations are URI references. Keep path
                    # separators readable while escaping spaces, Unicode, and
                    # URI metacharacters so GitHub and other consumers do not
                    # reject an otherwise valid report.
                    "artifactLocation": {
                        "uri": urllib.parse.quote(path, safe="/:@")
                    },
                }
                line = location.get("line")
                column = location.get("column")
                if isinstance(line, int) and line > 0:
                    region = {"startLine": line}
                    if isinstance(column, int) and column > 0:
                        region["startColumn"] = column
                    physical["region"] = region
                sarif_locations.append({"physicalLocation": physical})
            if not sarif_locations:
                # GitHub code scanning does not display a SARIF result without
                # at least one location. APK-wide rules often have no honest
                # source line, so attach a file-level artifact rather than
                # inventing a line number or silently dropping the alert.
                sarif_locations.append({
                    "physicalLocation": {
                        "artifactLocation": {"uri": fallback_uri},
                    },
                })
            result["locations"] = sarif_locations
            results.append(result)

        notifications = [
            {
                "level": "warning",
                "message": {
                    "text": (
                        f'{item["check_id"]}: {item["reason"]}'
                    )
                },
                "descriptor": {"id": item["check_id"]},
            }
            for item in data["coverage"]["inconclusive"]
        ]
        invocation = {
            "executionSuccessful": data["coverage"]["complete"],
        }
        if notifications:
            invocation["toolExecutionNotifications"] = notifications

        return {
            "$schema": (
                "https://json.schemastore.org/sarif-2.1.0.json"
            ),
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "APK Analyzer",
                        "version": TOOL_VERSION,
                        "informationUri": (
                            "https://github.com/worldtreeboy/apkAnalyzer"
                        ),
                        "rules": list(rule_map.values()),
                    }
                },
                "invocations": [invocation],
                "results": results,
                "properties": {
                    "targetApp": data["target_app"],
                    "reportSchemaVersion": REPORT_SCHEMA_VERSION,
                },
            }],
        }

    def export_sarif(self, path):
        """Write a SARIF 2.1.0 report."""
        data = self._build_sarif_dict()
        _atomic_text_write(
            path,
            lambda report_file: json.dump(
                data, report_file, indent=2, ensure_ascii=False
            ),
        )

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
        for index, finding in enumerate(data["findings"], 1):
            background = sev_colors.get(finding["severity"], "#6c757d")
            foreground = sev_text_colors.get(finding["severity"], "#fff")
            escape = html_mod.escape
            remediation_cell = (
                escape(finding["remediation"])
                if finding["remediation"] else "&mdash;"
            )
            reference_parts = []
            if finding["masvs"]:
                reference_parts.append(escape(finding["masvs"]))
            if finding["cwe"]:
                reference_parts.append(escape(finding["cwe"]))
            reference_cell = (
                ", ".join(reference_parts) if reference_parts else "&mdash;"
            )
            findings_rows.append(
                f'<tr>'
                f'<td>{index}</td>'
                f'<td><span class="badge" style="background:{background};color:{foreground};">{escape(str(finding.get("severity", "")))}</span></td>'
                f'<td>{escape(str(finding.get("category", "")))}</td>'
                f'<td><strong>{escape(str(finding.get("title", "")))}</strong></td>'
                f'<td>{escape(str(finding.get("confidence", "")))}</td>'
                f'<td>{escape(str(finding.get("description", "")))}</td>'
                f'<td>{remediation_cell}</td>'
                f'<td class="ref">{reference_cell}</td>'
                f'</tr>'
            )
        rows_html = "\n".join(findings_rows)

        device = data["device_info"]
        dev_model = html_mod.escape(device.get("model", "N/A"))
        dev_android = html_mod.escape(device.get("android", "N/A"))
        dev_sdk = html_mod.escape(device.get("sdk", "N/A"))
        dev_serial = html_mod.escape(device.get("serial", "N/A"))
        app_name = html_mod.escape(data["target_app"] or "N/A")
        app_version = html_mod.escape(data["app_info"].get("version", "N/A"))
        app_target_sdk = html_mod.escape(
            str(data["app_info"].get("target_sdk", "N/A"))
        )
        app_min_sdk = html_mod.escape(
            str(data["app_info"].get("min_sdk", "N/A"))
        )
        summary = data["summary"]
        coverage_items = data["coverage"]["inconclusive"]
        if coverage_items:
            coverage_rows = "\n".join(
                "<li><code>{}</code>: {}</li>".format(
                    html_mod.escape(str(item.get("check_id", "unknown"))),
                    html_mod.escape(str(item.get("reason", ""))),
                )
                for item in coverage_items
            )
            coverage_html = (
                '<div class="card coverage-warning">'
                '<h2>Incomplete Coverage</h2>'
                '<p>One or more checks could not obtain all required evidence. '
                'These results must not be interpreted as a clean scan.</p>'
                f'<ul>{coverage_rows}</ul></div>'
            )
        else:
            coverage_html = (
                '<div class="card coverage-complete">'
                '<h2>Coverage</h2><p>All recorded checks completed with their '
                'required evidence.</p></div>'
            )

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
  .coverage-warning {{ border-left: 5px solid #ffc107; }}
  .coverage-complete {{ border-left: 5px solid #198754; }}
  .coverage-warning ul {{ margin: .75rem 0 0 1.25rem; }}
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

  {coverage_html}

  <div class="card">
    <h2>Target Application</h2>
    <dl class="info-grid">
      <dt>Package</dt><dd>{app_name}</dd>
      <dt>Version</dt><dd>{app_version}</dd>
      <dt>Target SDK</dt><dd>{app_target_sdk}</dd>
      <dt>Min SDK</dt><dd>{app_min_sdk}</dd>
    </dl>
  </div>

  <div class="card">
    <h2>Summary</h2>
    <div class="summary-badges">
      <span class="sb" style="background:#dc3545;">CRITICAL: {summary['critical']}</span>
      <span class="sb" style="background:#fd7e14;">HIGH: {summary['high']}</span>
      <span class="sb" style="background:#ffc107;color:#212529;">MEDIUM: {summary['medium']}</span>
      <span class="sb" style="background:#0d6efd;">LOW: {summary['low']}</span>
      <span class="sb" style="background:#6c757d;">INFO: {summary['info']}</span>
      <span class="sb" style="background:#212529;">TOTAL: {summary['total']}</span>
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

        _atomic_text_write(path, lambda report_file: report_file.write(page))


# The interactive launcher keeps sharing this exact instance through its
# compatibility import.
report = ReportCollector()
