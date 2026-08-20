import os
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

import apkAnalyzer as analyzer
import apk_analyzer
from apk_analyzer import archive, process, safety, ui


class CoreModuleBoundaryTests(unittest.TestCase):
    def test_banner_spells_apk_and_keeps_every_edge_aligned(self):
        output = StringIO()
        with redirect_stdout(output):
            analyzer.banner()

        visible = re.sub(
            r"\x1b\[[0-?]*[ -/]*[@-~]", "", output.getvalue()
        )
        box_lines = [line for line in visible.splitlines() if line.strip()]

        self.assertIn("██████╔╝█████╔╝", visible)
        self.assertIn("apkAnalyzer", visible)
        self.assertEqual(len(box_lines), 11)
        self.assertEqual({len(line) for line in box_lines}, {63})
        self.assertTrue(all(line.startswith("   ") for line in box_lines))
        self.assertTrue(all(
            line[3] in "╔║╚" and line[-1] in "╗║╝"
            for line in box_lines
        ))

    def test_package_and_legacy_launcher_share_one_version_source(self):
        self.assertEqual(analyzer.TOOL_VERSION, apk_analyzer.TOOL_VERSION)
        self.assertEqual(apk_analyzer.__version__, analyzer.TOOL_VERSION)

    def test_archive_defaults_have_one_source_and_legacy_aliases(self):
        self.assertEqual(analyzer.MAX_BACKUP_BYTES,
                         archive.DEFAULT_MAX_BACKUP_BYTES)
        self.assertEqual(analyzer.MAX_BACKUP_PAYLOAD_BYTES,
                         archive.DEFAULT_MAX_BACKUP_PAYLOAD_BYTES)
        self.assertEqual(analyzer.MAX_BACKUP_FILE_BYTES,
                         archive.DEFAULT_MAX_BACKUP_FILE_BYTES)
        self.assertEqual(analyzer.MAX_BACKUP_FILES,
                         archive.DEFAULT_MAX_BACKUP_FILES)

    def test_legacy_safety_names_reexport_package_implementations(self):
        self.assertIs(analyzer._terminal_safe, safety.terminal_safe)
        self.assertIs(analyzer._safe_parse_xml, safety.safe_parse_xml)
        self.assertIs(analyzer._is_valid_package, safety.is_valid_package)
        self.assertIs(analyzer._PACKAGE_RE, safety._PACKAGE_RE)
        self.assertEqual(analyzer.MAX_XML_BYTES, safety.MAX_XML_BYTES)

    def test_legacy_ui_names_reexport_package_implementations(self):
        self.assertIs(analyzer.C, ui.C)
        self.assertIs(analyzer.clear, ui.clear)
        self.assertIs(analyzer.banner, ui.banner)
        self.assertIs(analyzer.section, ui.section)
        self.assertIs(analyzer.status_line, ui.status_line)
        self.assertIs(analyzer.pass_fail, ui.pass_fail)
        self.assertIs(analyzer.warn_line, ui.warn_line)
        self.assertIs(analyzer.info_line, ui.info_line)
        self.assertIs(analyzer.pause, ui.pause)

    def test_legacy_run_command_keeps_terminal_sanitizer_monkeypatch(self):
        completed = subprocess.CompletedProcess(
            ["tool"], 0, stdout="device output", stderr=""
        )
        sanitizer = mock.Mock(return_value="sanitized")
        with mock.patch("apkAnalyzer.subprocess.run", return_value=completed), \
                mock.patch.object(analyzer, "_terminal_safe", sanitizer):
            result = analyzer._run_cmd(["tool"])

        self.assertEqual(result, "sanitized")
        self.assertEqual(sanitizer.call_count, 2)

    def test_runtime_validator_keeps_legacy_failure_monkeypatch(self):
        with mock.patch.object(
                analyzer, "_command_failed", return_value=True
        ) as failed, self.assertRaises(process.RuntimeCheckUnavailable):
            analyzer._require_runtime_command("output", "testing")
        failed.assert_called_once_with("output")

    def test_runtime_exception_is_available_at_both_boundaries(self):
        self.assertIs(analyzer.RuntimeCheckUnavailable,
                      process.RuntimeCheckUnavailable)

    def test_default_frida_transport_targets_selected_adb_device(self):
        with mock.patch.object(analyzer, "FRIDA_CONN", "-U"), \
                mock.patch.object(analyzer, "ADB_SERIAL", "device-serial-2"):
            self.assertEqual(
                analyzer._frida_connection_args(),
                ["-D", "device-serial-2"],
            )

        with mock.patch.object(analyzer, "FRIDA_CONN", "-H 127.0.0.1:27042"), \
                mock.patch.object(analyzer, "ADB_SERIAL", "device-serial-2"):
            self.assertEqual(
                analyzer._frida_connection_args(),
                ["-H", "127.0.0.1:27042"],
            )

    def test_legacy_launcher_finds_package_outside_repository_cwd(self):
        launcher = Path(analyzer.__file__).resolve()
        with tempfile.TemporaryDirectory() as unrelated_cwd:
            completed = subprocess.run(
                [sys.executable, str(launcher), "--help"],
                cwd=unrelated_cwd,
                capture_output=True,
                text=True,
                timeout=30,
                encoding="utf-8",
                errors="replace",
                check=False,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("APK Analyzer - Android Security Analysis Tool",
                      completed.stdout)

    def test_unicode_ui_survives_an_ascii_posix_locale(self):
        if os.name == "nt":
            self.skipTest("POSIX locale behavior is not applicable on Windows")
        launcher_root = str(Path(analyzer.__file__).resolve().parent)
        environment = dict(os.environ)
        environment.update({
            "LC_ALL": "C",
            "LANG": "C",
            "PYTHONUTF8": "0",
            "PYTHONCOERCECLOCALE": "0",
            "PYTHONPATH": launcher_root,
        })
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                "import apkAnalyzer; apkAnalyzer.section('SCAN')",
            ],
            cwd=launcher_root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("SCAN".encode("utf-8"), completed.stdout)


if __name__ == "__main__":
    unittest.main()
