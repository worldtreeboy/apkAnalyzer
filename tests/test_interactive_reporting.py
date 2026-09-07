import argparse
import io
import json
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest import mock

import apkAnalyzer as analyzer


class InteractiveReportingTests(unittest.TestCase):
    def test_no_finding_reports_export_from_menu_and_session_flag(self):
        for route in ("menu", "flag"):
            for state in ("clean", "inconclusive"):
                with self.subTest(route=route, state=state), \
                        tempfile.TemporaryDirectory() as tmp:
                    collector = analyzer.ReportCollector()
                    collector.target_app = "com.example.app"
                    if state == "clean":
                        collector.app_info["static_code_scan_coverage"] = {
                            "coverage_complete": True,
                        }
                    else:
                        collector.mark_inconclusive("scan.setup", "No prepared input")
                    output = Path(tmp, "report.json")
                    with mock.patch.object(analyzer, "report", collector), \
                            mock.patch.object(analyzer, "pause"), \
                            mock.patch.object(analyzer, "main"), \
                            mock.patch("builtins.input", side_effect=["1", str(output)]), \
                            redirect_stdout(io.StringIO()):
                        if route == "menu":
                            analyzer.export_report_menu()
                        else:
                            analyzer._run_interactive(argparse.Namespace(
                                report="json", legacy_output=str(output),
                            ))

                    data = json.loads(output.read_text(encoding="utf-8"))
                    self.assertEqual(data["findings"], [])
                    self.assertEqual(data["coverage"]["complete"], state == "clean")

    def test_switching_apps_does_not_retain_old_incomplete_coverage(self):
        collector = analyzer.ReportCollector()
        device = {"serial": "device-1"}
        menu_calls = []

        def show_menu(_device, _root, package):
            menu_calls.append(package)
            if package == "com.example.first":
                collector.app_info["version"] = "old-version"
                collector.mark_inconclusive("old.check", "old app unavailable")
                collector.add_finding("Old", "Old finding", "HIGH", "HIGH", "old")

        patches = {
            "report": collector,
            "clear": mock.Mock(),
            "banner": mock.Mock(),
            "check_device": mock.Mock(return_value=device),
            "check_root": mock.Mock(return_value=False),
            "list_third_party_apps": mock.Mock(return_value=[]),
            "pick_app": mock.Mock(side_effect=["com.example.first", "com.example.second"]),
            "main_menu": mock.Mock(side_effect=show_menu),
        }
        with ExitStack() as stack:
            for name, replacement in patches.items():
                stack.enter_context(mock.patch.object(analyzer, name, replacement))
            stack.enter_context(mock.patch.object(analyzer.process_mod, "safe_which", return_value="adb"))
            stack.enter_context(mock.patch("builtins.input", side_effect=["a", "0"]))
            stack.enter_context(redirect_stdout(io.StringIO()))
            analyzer.main()

        self.assertEqual(menu_calls, ["com.example.first", "com.example.second"])
        self.assertEqual(collector.target_app, "com.example.second")
        self.assertEqual(collector.device_info, device)
        self.assertEqual(collector.findings, [])
        self.assertEqual(collector.app_info, {})
        self.assertEqual(collector.inconclusive, [])


if __name__ == "__main__":
    unittest.main()
