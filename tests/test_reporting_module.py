import json
import os
import tempfile
import unittest
import re
from pathlib import Path

import apkAnalyzer as analyzer
from apk_analyzer import reporting


class ReportingModuleTests(unittest.TestCase):
    def test_legacy_module_reexports_reporting_api_and_singleton(self):
        self.assertIs(analyzer.ReportCollector, reporting.ReportCollector)
        self.assertIs(analyzer.report, reporting.report)
        self.assertIs(analyzer._now_iso, reporting.now_iso)
        self.assertEqual(analyzer.TOOL_VERSION, reporting.TOOL_VERSION)

    def test_json_export_preserves_schema_sorting_deduplication_and_unicode(self):
        collector = analyzer.ReportCollector()
        collector.device_info = {
            "model": "Pixel α",
            "android": "14",
            "sdk": "34",
            "serial": "device-1",
        }
        collector.target_app = "com.example.app"
        collector.app_info = {
            "version": "1.2 (code: 3)",
            "target_sdk": 34,
            "min_sdk": 23,
        }
        collector.add_finding(
            "Informational",
            "Later finding",
            "INFO",
            "MEDIUM",
            "Unicode remains intact: 雪",
        )
        collector.add_finding(
            "Configuration",
            "First finding",
            "CRITICAL",
            "HIGH",
            "A critical description",
            "Fix it",
            "MASVS-STORAGE-1",
            "CWE-312",
        )
        collector.add_finding(
            "Configuration",
            "First finding",
            "LOW",
            "LOW",
            "A critical description",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir, "report.json")
            collector.export_json(output)
            data = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(data["tool"], "APK Analyzer")
        self.assertEqual(data["version"], analyzer.TOOL_VERSION)
        self.assertEqual(data["target_app"], "com.example.app")
        self.assertEqual(data["device_info"]["model"], "Pixel α")
        self.assertEqual(data["app_info"]["target_sdk"], 34)
        self.assertEqual(
            data["summary"],
            {
                "total": 2,
                "critical": 1,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 1,
                "inconclusive": 0,
            },
        )
        self.assertEqual(data["schema_version"], "2.0")
        self.assertEqual(data["coverage"], {
            "complete": True,
            "inconclusive": [],
        })
        self.assertEqual(
            [finding["severity"] for finding in data["findings"]],
            ["CRITICAL", "INFO"],
        )
        self.assertEqual(
            data["findings"][1]["description"],
            "Unicode remains intact: 雪",
        )
        self.assertIn("generated_at", data)
        self.assertIn("timestamp", data["findings"][0])

    def test_html_export_escapes_untrusted_fields_and_keeps_report_content(self):
        collector = analyzer.ReportCollector()
        collector.device_info = {
            "model": "<device>",
            "android": "14",
            "sdk": "34",
            "serial": "serial&one",
        }
        collector.target_app = "com.example.<script>"
        collector.app_info = {
            "version": "1&2",
            "target_sdk": 34,
            "min_sdk": 23,
        }
        collector.add_finding(
            "<category>",
            "Unsafe <title>",
            "HIGH",
            "HIGH",
            '<img src=x onerror="alert(1)">',
            "Use A&B",
            "MASVS&REF",
            "CWE-79",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir, "report.html")
            collector.export_html(output)
            rendered = output.read_text(encoding="utf-8")

        self.assertTrue(rendered.startswith("<!DOCTYPE html>"))
        self.assertIn("APK Analyzer Report", rendered)
        self.assertIn("com.example.&lt;script&gt;", rendered)
        self.assertIn("&lt;device&gt;", rendered)
        self.assertIn("serial&amp;one", rendered)
        self.assertIn("Unsafe &lt;title&gt;", rendered)
        self.assertIn(
            "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;",
            rendered,
        )
        self.assertIn("Use A&amp;B", rendered)
        self.assertNotIn('<img src=x onerror="alert(1)">', rendered)
        header = re.search(r"<thead>.*?<tr>(.*?)</tr>", rendered, re.DOTALL)
        row = re.search(r"<tbody>.*?<tr>(.*?)</tr>", rendered, re.DOTALL)
        self.assertIsNotNone(header)
        self.assertIsNotNone(row)
        self.assertEqual(header.group(1).count("<th>"), 8)
        self.assertEqual(row.group(1).count("<td"), 8)

    def test_sarif_export_has_stable_rule_location_and_incomplete_invocation(self):
        collector = analyzer.ReportCollector()
        collector.target_app = "com.example.app"
        collector.add_finding(
            "MASVS-NETWORK-1",
            "Cleartext Traffic Allowed",
            "HIGH",
            "HIGH",
            "Cleartext traffic is enabled.",
            "Disable cleartext traffic.",
            "MASVS-NETWORK-1",
            "CWE-319",
            rule_id="cleartext_traffic",
            locations=[{
                "path": "res/xml/network policy.xml",
                "line": 7,
                "column": 3,
            }],
        )
        collector.mark_inconclusive(
            "static_secret_coverage", "one asset exceeded the byte budget"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir, "report.sarif")
            collector.export_sarif(output)
            data = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(data["version"], "2.1.0")
        run = data["runs"][0]
        self.assertEqual(
            run["tool"]["driver"]["rules"][0]["id"],
            "cleartext_traffic",
        )
        result = run["results"][0]
        self.assertEqual(result["ruleId"], "cleartext_traffic")
        self.assertEqual(result["level"], "error")
        physical = result["locations"][0]["physicalLocation"]
        self.assertEqual(
            physical["artifactLocation"]["uri"],
            "res/xml/network%20policy.xml",
        )
        self.assertEqual(physical["region"], {
            "startLine": 7,
            "startColumn": 3,
        })
        invocation = run["invocations"][0]
        self.assertFalse(invocation["executionSuccessful"])
        self.assertIn(
            "static_secret_coverage",
            invocation["toolExecutionNotifications"][0]["message"]["text"],
        )

    def test_sarif_locationless_production_finding_gets_safe_file_location(self):
        collector = analyzer.ReportCollector()
        raw_secret = "abcdefghijklmnopqrstuvwx"
        collector.app_info["input_artifact"] = analyzer._headless_safe_text(
            f'api_key = "{raw_secret}".apk', 240
        )
        collector.add_finding(
            "MASVS-CODE-1",
            "Production-shaped APK-wide finding",
            "HIGH",
            "HIGH",
            "No individual source line applies.",
            rule_id="production_wide_rule",
        )

        result = collector._build_sarif_dict()["runs"][0]["results"][0]

        self.assertEqual(len(result["locations"]), 1)
        physical = result["locations"][0]["physicalLocation"]
        uri = physical["artifactLocation"]["uri"]
        self.assertNotIn(raw_secret, uri)
        self.assertIn("%5BREDACTED%5D", uri)
        self.assertNotIn("region", physical)

    def test_sarif_locationless_finding_has_stable_launcher_fallback(self):
        collector = analyzer.ReportCollector()
        collector.add_finding(
            "MASVS-CODE-1", "APK-wide finding", "HIGH", "HIGH", "detail",
            rule_id="apk_wide_rule",
        )

        result = collector._build_sarif_dict()["runs"][0]["results"][0]

        uri = result["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]["uri"]
        self.assertEqual(uri, "apkAnalyzer.py")

    def test_html_report_exposes_inconclusive_coverage(self):
        collector = analyzer.ReportCollector()
        collector.mark_inconclusive(
            "static_code_coverage",
            "assets/<unsafe>.xml could not be read",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir, "report.html")
            collector.export_html(output)
            rendered = output.read_text(encoding="utf-8")

        self.assertIn("Incomplete Coverage", rendered)
        self.assertIn("static_code_coverage", rendered)
        self.assertIn("assets/&lt;unsafe&gt;.xml could not be read", rendered)
        self.assertNotIn("assets/<unsafe>.xml", rendered)

    def test_reset_preserves_shared_collector_identity_and_clears_coverage(self):
        collector = analyzer.ReportCollector()
        identity = id(collector)
        collector.target_app = "com.example.app"
        collector.add_finding("Category", "Title", "LOW", "LOW", "text")
        collector.mark_inconclusive("check", "reason")

        collector.reset()

        self.assertEqual(id(collector), identity)
        self.assertEqual(collector.target_app, "")
        self.assertEqual(collector.findings, [])
        self.assertEqual(collector.inconclusive, [])

    def test_failed_export_does_not_corrupt_existing_report(self):
        collector = analyzer.ReportCollector()
        collector.app_info["not_json_serializable"] = {"a", "set"}

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir, "report.json")
            output.write_text("original-report", encoding="utf-8")
            with self.assertRaises(TypeError):
                collector.export_json(output)

            self.assertEqual(
                output.read_text(encoding="utf-8"), "original-report"
            )
            self.assertEqual(
                [path.name for path in Path(temp_dir).iterdir()],
                ["report.json"],
            )

    def test_atomic_export_supports_a_valid_long_destination_name(self):
        if os.name == "nt":
            self.skipTest("Windows legacy total-path limits vary by runner")
        collector = analyzer.ReportCollector()
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir, ("a" * 240) + ".json")
            collector.export_json(output)
            data = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(data["tool"], "APK Analyzer")

    def test_exports_replace_lone_surrogates_from_filesystem_text(self):
        collector = analyzer.ReportCollector()
        collector.target_app = "bad\udcffname"
        collector.add_finding(
            "Input", "Bad path", "LOW", "HIGH", "invalid\udcfftext",
            locations=[{"path": "assets/bad\udcffname.txt", "line": 1}],
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            for report_format in ("json", "html", "sarif"):
                with self.subTest(report_format=report_format):
                    output = Path(temp_dir, f"report.{report_format}")
                    getattr(collector, f"export_{report_format}")(output)
                    rendered = output.read_text(encoding="utf-8")
                    self.assertNotIn("\udcff", rendered)
                    self.assertIn("\ufffd", rendered)


if __name__ == "__main__":
    unittest.main()
