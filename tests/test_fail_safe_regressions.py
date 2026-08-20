import io
import re
import tarfile
import tempfile
import unittest
import zlib
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import apkAnalyzer as analyzer


ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def plain_output(buffer):
    return ANSI_RE.sub("", buffer.getvalue())


def make_backup(path, members):
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
        for name, value in members:
            data = value.encode() if isinstance(value, str) else value
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))

    Path(path).write_bytes(
        b"ANDROID BACKUP\n5\n1\nnone\n"
        + zlib.compress(tar_buffer.getvalue())
    )


class FailSafeRegressionTests(unittest.TestCase):
    def test_textual_monkey_failure_is_not_a_successful_launch(self):
        failures = (
            "** No activities found to run, monkey aborted.",
            "Events injected: 0",
            "Monkey finished",
        )
        for output in failures:
            with self.subTest(output=output), self.assertRaises(
                    analyzer.RuntimeCheckUnavailable):
                analyzer._require_app_launch(output)

        self.assertEqual(
            analyzer._require_app_launch("Events injected: 1"),
            "Events injected: 1",
        )

    def test_adb_pull_success_without_a_created_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp, "existing.apk")
            destination.write_bytes(b"old-apk")

            with mock.patch.object(analyzer, "_run_cmd", return_value="pulled"):
                result = analyzer.adb_pull("/data/app/base.apk", destination)

            self.assertTrue(result.startswith("[ERROR]"))
            self.assertEqual(destination.read_bytes(), b"old-apk")

    def test_security_scan_aborts_a_malformed_manifest_without_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "AndroidManifest.xml").write_text(
                "<manifest><application>", encoding="utf-8"
            )
            output = io.StringIO()
            framework = {
                "framework": "Java",
                "native_sdks": [],
                "details": [],
            }

            with mock.patch.object(
                analyzer, "_pull_and_decompile", return_value=(tmp, tmp)
            ), mock.patch.object(
                analyzer, "detect_framework", return_value=framework
            ) as detect_framework, mock.patch.object(
                analyzer, "_find_local_apk", return_value=None
            ), mock.patch.object(
                analyzer, "pause"
            ), mock.patch.object(
                analyzer, "report", analyzer.ReportCollector()
            ), redirect_stdout(output):
                analyzer.security_scan("com.example.invalid")

        rendered = plain_output(output)
        self.assertIn("Could not read AndroidManifest.xml", rendered)
        self.assertNotIn("[PASS]", rendered)
        detect_framework.assert_called_once_with(tmp)

    def test_malformed_manifest_still_scans_code_for_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "AndroidManifest.xml").write_text(
                "<manifest><application>", encoding="utf-8"
            )
            Path(tmp, "classes.smali").write_text(
                '.field static PASSWORD:Ljava/lang/String; = "synthetic-value"',
                encoding="utf-8",
            )
            output = io.StringIO()
            collector = analyzer.ReportCollector()

            with mock.patch.object(
                analyzer, "_pull_and_decompile", return_value=(tmp, tmp)
            ), mock.patch.object(
                analyzer, "detect_framework", return_value={}
            ), mock.patch.object(
                analyzer, "_print_framework_info"
            ), mock.patch.object(analyzer, "pause"), mock.patch.object(
                analyzer, "report", collector
            ), redirect_stdout(output):
                analyzer.security_scan("com.example.invalid")

        rendered = plain_output(output)
        self.assertIn("Hardcoded secrets", rendered)
        self.assertNotIn("synthetic-value", rendered)
        self.assertTrue(
            any(finding["title"] == "Hardcoded Secrets Detected"
                for finding in collector.findings)
        )

    def test_well_formed_non_manifest_xml_is_not_accepted_as_a_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "AndroidManifest.xml").write_text(
                '<foo package="com.example.fake"/>', encoding="utf-8"
            )

            parsed = analyzer._parse_manifest(tmp)

        self.assertFalse(parsed["parsed"])

    def test_unavailable_device_is_inconclusive_with_zero_runtime_passes(self):
        failures = (
            "[ERROR 1] error: no devices/emulators found",
            "[ERROR 1] error: device unauthorized",
        )

        for failure in failures:
            with self.subTest(failure=failure):
                output = io.StringIO()
                helper_patches = (
                    mock.patch.object(analyzer, "_runtime_data_check", return_value=[]),
                    mock.patch.object(analyzer, "_check_world_readable", return_value=[]),
                    mock.patch.object(analyzer, "_probe_exported_components", return_value=[]),
                    mock.patch.object(analyzer, "_check_clipboard_leak", return_value=[]),
                    mock.patch.object(analyzer, "_check_logcat_leakage", return_value=[]),
                    mock.patch.object(analyzer, "_check_webview_cache", return_value=[]),
                )

                with mock.patch.object(
                    analyzer, "adb_shell", return_value=failure
                ), mock.patch.object(
                    analyzer, "adb_su", return_value=failure
                ), mock.patch.object(
                    analyzer.time, "sleep"
                ), mock.patch.object(
                    analyzer, "pause"
                ), mock.patch.object(
                    analyzer, "report", analyzer.ReportCollector()
                ), helper_patches[0], helper_patches[1], helper_patches[2], \
                        helper_patches[3], helper_patches[4], helper_patches[5], \
                        redirect_stdout(output):
                    analyzer.runtime_security_check("com.example.offline")

                rendered = plain_output(output)
                self.assertIn("INCONCLUSIVE", rendered.upper())
                self.assertRegex(rendered, r"PASS:\s*0\b")
                self.assertNotIn("[PASS]", rendered)
                self.assertNotIn("LOW RISK", rendered.upper())

    def test_unpack_ab_rejects_a_symlink_output_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup = root / "sample.ab"
            outside = root / "outside"
            outside.mkdir()
            output = root / "output"
            try:
                output.symlink_to(outside, target_is_directory=True)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"directory symlinks are unavailable: {exc}")

            relative = Path("apps", "com.example", "f", "config.txt")
            make_backup(backup, [(relative.as_posix(), "must-not-be-written")])

            count, error = analyzer._unpack_ab(backup, output)

            self.assertEqual(count, 0)
            self.assertIsNotNone(error)
            self.assertIn("symlink", error.lower())
            self.assertFalse((outside / relative).exists())

    def test_unpack_ab_rejects_a_symlinked_output_ancestor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup = root / "sample.ab"
            outside = root / "outside"
            outside.mkdir()
            logical = root / "logical"
            logical.mkdir()
            ancestor = logical / "ancestor"
            try:
                ancestor.symlink_to(outside, target_is_directory=True)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"directory symlinks are unavailable: {exc}")

            output = ancestor / "extract"
            relative = Path("apps", "com.example", "f", "config.txt")
            make_backup(backup, [(relative.as_posix(), "must-not-be-written")])

            count, error = analyzer._unpack_ab(backup, output)

            self.assertEqual(count, 0)
            self.assertIsNotNone(error)
            self.assertIn("symlink", error.lower())
            self.assertFalse(output.exists())
            self.assertFalse((outside / "extract" / relative).exists())

    def test_unpack_ab_rejects_duplicates_before_writing_any_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup = root / "duplicate.ab"
            output = root / "output"
            relative = Path("apps", "com.example", "f", "same.txt")
            make_backup(
                backup,
                [(relative.as_posix(), "first"), (relative.as_posix(), "second")],
            )

            count, error = analyzer._unpack_ab(backup, output)

            self.assertEqual(count, 0)
            self.assertIsNotNone(error)
            self.assertIn("duplicate", error.lower())
            self.assertFalse((output / relative).exists())

    def test_unpack_ab_rejects_file_prefix_conflicts_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup = root / "prefix.ab"
            output = root / "output"
            make_backup(
                backup,
                [("apps/x/f/a", "file"), ("apps/x/f/a/child", "child")],
            )

            count, error = analyzer._unpack_ab(backup, output)

            self.assertEqual(count, 0)
            self.assertIn("conflicting", error.lower())
            self.assertFalse((output / "apps" / "x" / "f" / "a").exists())

    def test_unpack_ab_honors_destination_case_sensitivity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup = root / "case.ab"
            output = root / "output"
            make_backup(
                backup,
                [("apps/x/f/A", "upper"), ("apps/x/f/a", "lower")],
            )

            with mock.patch.object(
                analyzer, "_filesystem_is_case_sensitive", return_value=False
            ):
                count, error = analyzer._unpack_ab(backup, output)

            self.assertEqual(count, 0)
            self.assertIn("duplicate", error.lower())
            self.assertFalse((output / "apps" / "x" / "f" / "A").exists())

    def test_runtime_helper_failure_is_not_converted_to_a_pass(self):
        output = io.StringIO()

        def shell(command, timeout=30):
            if command == "getprop ro.build.version.sdk":
                return "35"
            if command.startswith("monkey "):
                return "Events injected: 1"
            return ""

        with mock.patch.object(analyzer, "adb_shell", side_effect=shell), \
                mock.patch.object(analyzer, "adb_su", return_value="uid=0(root)"), \
                mock.patch.object(analyzer, "_read_clipboard_text", return_value=""), \
                mock.patch.object(
                    analyzer, "_runtime_data_check",
                    side_effect=analyzer.RuntimeCheckUnavailable("device disconnected"),
                ), mock.patch.object(
                    analyzer, "_check_world_readable", return_value=[]
                ), mock.patch.object(
                    analyzer, "_probe_exported_components", return_value=[]
                ), mock.patch.object(
                    analyzer, "_check_clipboard_leak", return_value=[]
                ), mock.patch.object(
                    analyzer, "_check_logcat_leakage", return_value=[]
                ), mock.patch.object(
                    analyzer, "_check_webview_cache", return_value=[]
                ), mock.patch.object(analyzer.time, "sleep"), \
                mock.patch.object(analyzer, "pause"), \
                mock.patch.object(analyzer, "report", analyzer.ReportCollector()), \
                redirect_stdout(output):
            analyzer.runtime_security_check("com.example.disconnect")

        rendered = plain_output(output)
        self.assertIn("[INCONCLUSIVE] Data-at-rest check", rendered)
        self.assertNotIn(
            "[PASS] No runtime secrets detected in SharedPrefs/databases", rendered
        )
        self.assertNotIn("Overall: LOW RISK", rendered)

    def test_runtime_data_failure_preserves_earlier_positive_findings(self):
        def root(command, timeout=30):
            if command.startswith("if [ -d "):
                return "prefs.xml"
            if command.startswith("cat "):
                return "password=synthetic-value"
            if command.startswith("find "):
                return "/data/data/com.example.partial/databases/bad.db"
            if command.startswith("xxd "):
                return "[ERROR 127] xxd: not found"
            self.fail(f"unexpected root command: {command}")

        with mock.patch.object(analyzer, "adb_su", side_effect=root):
            with self.assertRaises(analyzer.RuntimeCheckUnavailable) as caught:
                analyzer._runtime_data_check("com.example.partial", launch=False)

        partial = caught.exception.partial_findings
        self.assertEqual(len(partial), 1)
        self.assertEqual(partial[0][1], "Password")
        self.assertNotIn("synthetic-value", partial[0][3])

    def test_logcat_requires_target_pids_and_handles_multiple_processes(self):
        commands = []

        def shell(command, timeout=30):
            commands.append(command)
            if command.startswith("pidof "):
                return "123 456"
            if "--pid=" in command:
                return ""
            self.fail(f"unexpected command: {command}")

        with mock.patch.object(analyzer, "adb_shell", side_effect=shell):
            self.assertEqual(
                analyzer._check_logcat_leakage("com.example.multi", launch=False),
                [],
            )

        self.assertIn("logcat -d -t 2000 --pid=123", commands)
        self.assertIn("logcat -d -t 2000 --pid=456", commands)
        self.assertNotIn("logcat -d -t 2000", commands)

        with mock.patch.object(analyzer, "adb_shell", return_value=""):
            with self.assertRaises(analyzer.RuntimeCheckUnavailable):
                analyzer._check_logcat_leakage("com.example.stopped", launch=False)

    def test_main_action_without_launcher_category_is_still_probed(self):
        manifest = {
            "parsed": True,
            "exported": {
                "activity": [{
                    "name": ".ExternalMain",
                    "actions": ["android.intent.action.MAIN"],
                    "categories": ["android.intent.category.DEFAULT"],
                }]
            },
        }
        commands = []

        def shell(command, timeout=30):
            commands.append(command)
            if command.startswith("dumpsys activity"):
                return "mResumedActivity: com.example/.ExternalMain"
            return ""

        with mock.patch.object(
            analyzer, "_pull_and_decompile", return_value=("/tmp", "/tmp")
        ), mock.patch.object(
            analyzer, "_parse_manifest", return_value=manifest
        ), mock.patch.object(
            analyzer, "adb_shell", side_effect=shell
        ), mock.patch.object(analyzer.time, "sleep"):
            findings = analyzer._probe_exported_components("com.example")

        self.assertTrue(any(command.startswith("am start -n") for command in commands))
        self.assertEqual(findings[0][0], "MEDIUM")

    def test_component_disconnect_preserves_earlier_probe_findings(self):
        manifest = {
            "parsed": True,
            "exported": {
                "activity": [
                    {"name": ".First", "actions": [], "categories": []},
                    {"name": ".Second", "actions": [], "categories": []},
                ]
            },
        }
        stop_count = 0

        def shell(command, timeout=30):
            nonlocal stop_count
            if command.startswith("am force-stop"):
                stop_count += 1
                return "" if stop_count == 1 else "[ERROR 1] device offline"
            if command.startswith("am start"):
                return "Starting: Intent"
            if command.startswith("dumpsys activity"):
                return "mResumedActivity: com.example/.First"
            self.fail(f"unexpected command: {command}")

        with mock.patch.object(
            analyzer, "_pull_and_decompile", return_value=("/tmp", "/tmp")
        ), mock.patch.object(
            analyzer, "_parse_manifest", return_value=manifest
        ), mock.patch.object(
            analyzer, "adb_shell", side_effect=shell
        ), mock.patch.object(analyzer.time, "sleep"):
            with self.assertRaises(analyzer.RuntimeCheckUnavailable) as caught:
                analyzer._probe_exported_components("com.example")

        self.assertEqual(caught.exception.partial_findings[0][1], ".First")


if __name__ == "__main__":
    unittest.main()
