import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from apk_analyzer import cli
from apk_analyzer.reporting import ReportCollector


class CliModuleTests(unittest.TestCase):
    def test_exit_codes_distinguish_findings_and_incomplete_coverage(self):
        collector = ReportCollector()
        self.assertEqual(cli.scan_exit_code(collector, "high"), cli.EXIT_OK)

        collector.add_finding(
            "Network", "Medium issue", "MEDIUM", "HIGH", "description"
        )
        self.assertEqual(cli.scan_exit_code(collector, "high"), cli.EXIT_OK)
        self.assertEqual(
            cli.scan_exit_code(collector, "medium"), cli.EXIT_FINDINGS
        )
        self.assertEqual(cli.scan_exit_code(collector, "none"), cli.EXIT_OK)

        collector.mark_inconclusive("manifest", "could not parse")
        self.assertEqual(
            cli.scan_exit_code(collector, "none"), cli.EXIT_INCONCLUSIVE
        )
        self.assertEqual(
            cli.scan_exit_code(collector, "critical", scan_complete=False),
            cli.EXIT_INCONCLUSIVE,
        )

    def test_unknown_severity_fails_conservatively(self):
        self.assertTrue(cli.finding_meets_threshold(
            {"severity": "future-level"}, "critical"
        ))
        with self.assertRaises(ValueError):
            cli.finding_meets_threshold({"severity": "HIGH"}, "urgent")

    def test_export_report_supports_sarif_and_creates_parent(self):
        collector = ReportCollector()
        collector.add_finding(
            "Code", "Synthetic issue", "LOW", "HIGH", "description",
            rule_id="synthetic_issue",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir, "nested", "report.sarif")
            returned = cli.export_report(collector, "sarif", output)
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(returned, os.path.abspath(output))
            self.assertTrue(os.path.samefile(returned, output))

        self.assertEqual(data["version"], "2.1.0")
        self.assertEqual(
            data["runs"][0]["results"][0]["ruleId"], "synthetic_issue"
        )

    def test_bundletool_jar_path_with_spaces_is_an_argument_list(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            jar = Path(temp_dir, "bundle tool.jar")
            jar.write_bytes(b"jar")
            with mock.patch(
                    "apk_analyzer.cli.shutil.which", return_value="/tools/java"):
                command = cli.resolve_bundletool_command(jar)
            self.assertEqual(
                command, ["/tools/java", "-jar", os.path.abspath(jar)]
            )
            self.assertTrue(os.path.samefile(command[2], jar))

        self.assertNotIn(" ", command[0])
        self.assertIn(" ", command[2])

    def test_windows_bundletool_batch_wrapper_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            wrapper = Path(temp_dir, "bundletool.cmd")
            wrapper.write_text("@echo off\n", encoding="utf-8")
            with mock.patch.object(cli.os, "name", "nt"):
                with self.assertRaisesRegex(ValueError, "batch wrappers"):
                    cli.resolve_bundletool_command(wrapper)

            with mock.patch.object(cli.os, "name", "nt"), mock.patch(
                    "apk_analyzer.cli.safe_which",
                    return_value=r"C:\\tools\\bundletool.bat"):
                with self.assertRaisesRegex(ValueError, "batch wrappers"):
                    cli.resolve_bundletool_command()

    def test_default_report_path_uses_requested_directory_and_extension(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = cli.default_report_path("json", temp_dir)
        self.assertEqual(os.path.dirname(output), temp_dir)
        self.assertTrue(output.endswith(".json"))


if __name__ == "__main__":
    unittest.main()
