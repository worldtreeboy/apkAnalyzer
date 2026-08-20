import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import apkAnalyzer as analyzer
from apk_analyzer import inputs, process


class BoundedCommandTests(unittest.TestCase):
    def test_windows_executable_lookup_excludes_current_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            current = root / "untrusted-scan-directory"
            trusted = root / "trusted-tools"
            current.mkdir()
            trusted.mkdir()
            (current / "apktool.EXE").write_bytes(b"malicious")
            expected = trusted / "apktool.EXE"
            expected.write_bytes(b"trusted")

            with mock.patch.object(process.os, "name", "nt"), \
                    mock.patch.object(
                        process.os, "getcwd", return_value=str(current)
                    ), mock.patch.dict(
                        process.os.environ,
                        {"PATHEXT": ".EXE", "PATH": ""},
                    ):
                resolved = process.safe_which(
                    "apktool", path=f"{current};{trusted}"
                )

        self.assertEqual(resolved, str(expected))

    def test_windows_executable_lookup_ignores_relative_path_entries(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            current = root / "scan"
            current.mkdir()
            (current / "java.EXE").write_bytes(b"malicious")

            with mock.patch.object(process.os, "name", "nt"), \
                    mock.patch.object(
                        process.os, "getcwd", return_value=str(current)
                    ), mock.patch.dict(
                        process.os.environ,
                        {"PATHEXT": ".EXE", "PATH": ""},
                    ):
                resolved = process.safe_which("java", path=".;tools")

        self.assertIsNone(resolved)

    def test_capture_returns_separate_decoded_streams_and_status(self):
        code = (
            "import os, sys; "
            "os.write(1, b'hello\\xff'); "
            "os.write(2, b'problem'); "
            "sys.exit(7)"
        )
        result = process.run_command_capture(
            [sys.executable, "-c", code], max_output_bytes=1024
        )

        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, "hello�")
        self.assertEqual(result.stderr, "problem")

    def test_combined_stdout_and_stderr_limit_returns_error_sentinel(self):
        code = (
            "import os; "
            "os.write(1, b'a' * 80); "
            "os.write(2, b'b' * 80)"
        )
        result = process.run_command(
            [sys.executable, "-c", code], max_output_bytes=128
        )

        self.assertEqual(
            result,
            "[ERROR] command output exceeded 128-byte safety limit",
        )

    def test_exact_output_limit_is_accepted(self):
        code = "import os; os.write(1, b'x' * 128)"
        result = process.run_command(
            [sys.executable, "-c", code], max_output_bytes=128
        )

        self.assertEqual(result, "x" * 128)

    def test_output_limit_stops_a_tool_that_would_otherwise_hang(self):
        code = (
            "import os, time; "
            "os.write(1, b'x' * 129); "
            "time.sleep(60)"
        )
        started = time.monotonic()
        result = process.run_command(
            [sys.executable, "-c", code],
            timeout=10,
            max_output_bytes=128,
        )

        self.assertEqual(
            result,
            "[ERROR] command output exceeded 128-byte safety limit",
        )
        self.assertLess(time.monotonic() - started, 3)

    def test_legacy_completed_process_mock_is_still_supported(self):
        completed = subprocess.CompletedProcess(
            ["tool"], 3, stdout="out", stderr="diagnostic"
        )
        with mock.patch("apk_analyzer.process.subprocess.run",
                        return_value=completed):
            result = process.run_command(["tool"], max_output_bytes=128)

        self.assertEqual(result, "[ERROR 3] diagnostic")

    def test_mocked_oversized_output_is_not_sanitized_or_returned(self):
        completed = subprocess.CompletedProcess(
            ["tool"], 0, stdout="s" * 129, stderr=""
        )
        sanitizer = mock.Mock(side_effect=AssertionError("must not receive output"))
        with mock.patch("apk_analyzer.process.subprocess.run",
                        return_value=completed):
            result = process.run_command(
                ["tool"], sanitizer=sanitizer, max_output_bytes=128
            )

        self.assertEqual(
            result,
            "[ERROR] command output exceeded 128-byte safety limit",
        )
        sanitizer.assert_not_called()


class ProcessTreeContainmentTests(unittest.TestCase):
    def test_apktool_timeout_kills_child_before_delayed_write(self):
        if os.name not in ("nt", "posix"):
            self.skipTest("process-tree containment is platform-specific")
        with tempfile.TemporaryDirectory() as temp_dir:
            ready = Path(temp_dir, "descendant started.txt")
            marker = Path(temp_dir, "descendant survived.txt")
            child_code = (
                "import pathlib, sys, time; "
                "pathlib.Path(sys.argv[1]).write_text('started'); "
                "time.sleep(1.6); "
                "pathlib.Path(sys.argv[2]).write_text('survived')"
            )
            parent_code = (
                "import pathlib, subprocess, sys, time; "
                "subprocess.Popen([sys.executable, '-c', sys.argv[1], "
                "sys.argv[2], sys.argv[3]]); "
                "ready = pathlib.Path(sys.argv[2]); "
                "\nwhile not ready.exists():\n time.sleep(0.01)\n"
                "time.sleep(60)"
            )

            with self.assertRaisesRegex(
                    inputs.InputPreparationError, "apktool timed out"):
                inputs._run_bounded_tool(
                    [
                        sys.executable,
                        "-c",
                        parent_code,
                        child_code,
                        str(ready),
                        str(marker),
                    ],
                    timeout=1,
                    operation="apktool",
                )

            self.assertTrue(ready.exists(), "the fixture child never started")
            # Wait past the child's scheduled write. A direct-process-only
            # timeout lets this marker appear after the exception is raised.
            time.sleep(0.9)
            self.assertFalse(
                marker.exists(),
                "the timed-out tool left a descendant running",
            )


class ProcessTableLimitTests(unittest.TestCase):
    @staticmethod
    def _table(count):
        rows = ["PID NAME"]
        rows.extend(
            f"{index} com.example.app:p{index}" for index in range(1, count + 1)
        )
        return "\n".join(rows)

    def test_exact_pid_limit_is_complete(self):
        parsed = process.parse_android_ps(
            self._table(32), "com.example.app"
        )

        self.assertEqual(len(parsed["pids"]), 32)
        self.assertFalse(parsed["truncated"])

    def test_additional_pid_marks_result_truncated(self):
        parsed = process.parse_android_ps(
            self._table(33), "com.example.app"
        )

        self.assertEqual(len(parsed["pids"]), 32)
        self.assertTrue(parsed["truncated"])

    def test_oversized_pid_token_does_not_raise(self):
        parsed = process.parse_android_ps(
            "PID NAME\n" + "9" * 10000 + " com.example.app",
            "com.example.app",
        )

        self.assertTrue(parsed["recognized"])
        self.assertEqual(parsed["pids"], [])


class LogcatLimitTests(unittest.TestCase):
    def test_logcat_byte_limit_is_inconclusive_and_preserves_findings(self):
        commands = []

        def shell(command, timeout=30):
            commands.append(command)
            if command.startswith("pidof "):
                return "101 202"
            if command.startswith("ps -A -o PID,NAME"):
                return (
                    "PID NAME\n"
                    "101 com.example.app\n"
                    "202 com.example.app:remote"
                )
            if command.endswith("--pid=101"):
                return 'password="synthetic-secret-value"\n' + "x" * 200
            if command.endswith("--pid=202"):
                return ""
            self.fail(f"unexpected command: {command}")

        with mock.patch.object(analyzer, "adb_shell", side_effect=shell), \
                mock.patch.object(analyzer, "_MAX_LOGCAT_SCAN_BYTES", 128):
            with self.assertRaises(analyzer.RuntimeCheckUnavailable) as caught:
                analyzer._check_logcat_leakage(
                    "com.example.app", launch=False
                )

        self.assertIn("128-byte scan limit", str(caught.exception))
        self.assertTrue(caught.exception.partial_findings)
        self.assertEqual(
            caught.exception.partial_findings[0][1], "Auth credential"
        )
        self.assertNotIn(
            "synthetic-secret-value", repr(caught.exception.partial_findings)
        )
        self.assertNotIn("logcat -d -t 2000 --pid=202", commands)

    def test_finding_limit_is_explicit_instead_of_allocating_unbounded_list(self):
        logs = [
            "a1@example.com\n"
            "a2@example.com\n"
            "a3@example.com"
        ]
        with mock.patch.object(analyzer, "_MAX_LOGCAT_FINDINGS", 2):
            findings, truncated = analyzer._analyze_logcat_chunks(logs)

        self.assertEqual(len(findings), 2)
        self.assertTrue(truncated)


if __name__ == "__main__":
    unittest.main()
