import argparse
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import apkAnalyzer as analyzer
from apk_analyzer import cli
from apk_analyzer import inputs


class HeadlessCliIntegrationTests(unittest.TestCase):
    def _args(self, apk, output, **overrides):
        values = {
            "apk": apk,
            "format": "json",
            "output": output,
            "fail_on": "high",
            "bundletool": "",
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def test_parser_supports_headless_and_preserves_legacy_flags(self):
        parser = analyzer._build_argument_parser()
        headless = parser.parse_args([
            "scan", "--apk", "app with spaces.apk", "--format", "sarif",
            "--output", "result.sarif", "--fail-on", "medium",
            "--bundletool", "bundle tool.jar",
        ])
        self.assertEqual(headless.command, "scan")
        self.assertEqual(headless.apk, "app with spaces.apk")
        self.assertEqual(headless.format, "sarif")
        self.assertEqual(headless.fail_on, "medium")
        self.assertEqual(headless.bundletool, "bundle tool.jar")

        legacy = parser.parse_args([
            "--report", "html", "--output", "legacy report.html"
        ])
        self.assertIsNone(legacy.command)
        self.assertEqual(legacy.report, "html")
        self.assertEqual(legacy.legacy_output, "legacy report.html")

    def test_clean_local_scan_exports_empty_report_and_cleans_workdir(self):
        captured = {}

        def fake_prepare(source, work, apktool_command, **kwargs):
            captured["source"] = source
            captured["work"] = work
            captured["apktool"] = apktool_command
            captured["bundletool"] = kwargs["bundletool_command"]
            decompiled = os.path.join(work, "decompiled")
            os.makedirs(decompiled)
            base_apk = os.path.join(work, "validated base.apk")
            Path(base_apk).write_bytes(b"validated")
            return inputs.PreparedInput(
                source_path=os.path.abspath(source),
                input_kind="apk",
                apk_paths=(base_apk,),
                base_apk=base_apk,
                work_dir=work,
                decompiled_dir=decompiled,
                split_decompiled_dirs=(),
            )

        def fake_scan(target, **kwargs):
            self.assertEqual(target, "com.example.local")
            self.assertFalse(kwargs["interactive"])
            self.assertEqual(
                kwargs["prepared"].base_apk,
                os.path.join(captured["work"], "validated base.apk"),
            )
            return {"completed": True}

        with tempfile.TemporaryDirectory() as temp_dir:
            source = os.path.join(temp_dir, "input ; name.apk")
            output = os.path.join(temp_dir, "empty report.json")
            with mock.patch.object(
                    analyzer, "_find_apktool", return_value=["apktool"]), \
                    mock.patch.object(
                        analyzer.cli_mod, "resolve_bundletool_command",
                        return_value=[]) as resolve_bundletool, \
                    mock.patch.object(
                        analyzer.input_mod, "prepare_local_input",
                        side_effect=fake_prepare), \
                    mock.patch.object(
                        analyzer, "_parse_manifest",
                        return_value={"parsed": True,
                                      "package": "com.example.local"}), \
                    mock.patch.object(
                        analyzer, "security_scan", side_effect=fake_scan), \
                    mock.patch.object(
                        analyzer, "check_device",
                        side_effect=AssertionError("ADB must not be used")), \
                    mock.patch.object(
                        analyzer, "_pull_and_decompile",
                        side_effect=AssertionError("device pull must not run")):
                exit_code = analyzer._run_headless_scan(
                    self._args(source, output)
                )
            payload = json.loads(Path(output).read_text(encoding="utf-8"))
            work = captured["work"]

        self.assertEqual(exit_code, cli.EXIT_OK)
        self.assertEqual(payload["target_app"], "com.example.local")
        self.assertEqual(payload["summary"]["total"], 0)
        self.assertTrue(payload["coverage"]["complete"])
        self.assertFalse(os.path.exists(work))
        self.assertEqual(captured["apktool"], ["apktool"])
        self.assertEqual(captured["bundletool"], [])
        resolve_bundletool.assert_not_called()

    def test_threshold_finding_returns_one(self):
        def fake_prepare(source, work, _apktool_command, **_kwargs):
            decompiled = os.path.join(work, "decompiled")
            os.makedirs(decompiled)
            base_apk = os.path.join(work, "base.apk")
            Path(base_apk).write_bytes(b"apk")
            return inputs.PreparedInput(
                source, "apk", (base_apk,), base_apk, work, decompiled, ()
            )

        def fake_scan(_target, **_kwargs):
            analyzer.report.add_finding(
                "Code", "High issue", "HIGH", "HIGH", "description",
                rule_id="test.high",
            )
            return {"completed": True}

        with tempfile.TemporaryDirectory() as temp_dir, \
                mock.patch.object(
                    analyzer, "_find_apktool", return_value=["apktool"]), \
                mock.patch.object(
                    analyzer.input_mod, "prepare_local_input",
                    side_effect=fake_prepare), \
                mock.patch.object(
                    analyzer, "_parse_manifest",
                    return_value={"parsed": True,
                                  "package": "com.example.app"}), \
                mock.patch.object(
                    analyzer, "security_scan", side_effect=fake_scan):
            output = os.path.join(temp_dir, "report.json")
            exit_code = analyzer._run_headless_scan(
                self._args("input.apk", output)
            )

        self.assertEqual(exit_code, cli.EXIT_FINDINGS)

    def test_aab_universal_scan_reports_incomplete_module_coverage(self):
        def fake_prepare(source, work, _apktool_command, **_kwargs):
            decompiled = os.path.join(work, "decompiled")
            os.makedirs(decompiled)
            base_apk = os.path.join(work, "universal.apk")
            Path(base_apk).write_bytes(b"apk")
            return inputs.PreparedInput(
                source, "aab", (base_apk,), base_apk, work, decompiled, ()
            )

        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
                analyzer, "_find_apktool", return_value=["apktool"]), \
                mock.patch.object(
                    analyzer.input_mod, "prepare_local_input",
                    side_effect=fake_prepare), \
                mock.patch.object(
                    analyzer, "_parse_manifest",
                    return_value={"parsed": True,
                                  "package": "com.example.bundle"}), \
                mock.patch.object(
                    analyzer, "security_scan",
                    return_value={"completed": True}):
            output = os.path.join(temp_dir, "aab.json")
            exit_code = analyzer._run_headless_scan(
                self._args("input.aab", output)
            )
            payload = json.loads(Path(output).read_text(encoding="utf-8"))

        self.assertEqual(exit_code, cli.EXIT_INCONCLUSIVE)
        self.assertTrue(any(
            item["check_id"] == "input.aab_module_coverage"
            for item in payload["coverage"]["inconclusive"]
        ))

    def test_setup_failure_still_exports_and_returns_inconclusive(self):
        with tempfile.TemporaryDirectory() as temp_dir, \
                mock.patch.object(
                    analyzer, "_find_apktool", return_value=["apktool"]), \
                mock.patch.object(
                    analyzer.input_mod, "prepare_local_input",
                    side_effect=inputs.InputPreparationError(
                        "malformed archive\nwith detail")), \
                mock.patch.object(analyzer, "security_scan") as scan:
            output = os.path.join(temp_dir, "failed.json")
            exit_code = analyzer._run_headless_scan(
                self._args("broken.apk", output, fail_on="none")
            )
            payload = json.loads(Path(output).read_text(encoding="utf-8"))

        self.assertEqual(exit_code, cli.EXIT_INCONCLUSIVE)
        self.assertEqual(payload["summary"]["total"], 0)
        self.assertFalse(payload["coverage"]["complete"])
        self.assertEqual(
            payload["coverage"]["inconclusive"][0]["check_id"],
            "scan.setup",
        )
        scan.assert_not_called()

    def test_report_cannot_overwrite_the_input_apk(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir, "do not corrupt.apk")
            original = b"original-apk-bytes"
            source.write_bytes(original)
            with mock.patch.object(
                    analyzer, "_find_apktool") as find_apktool, \
                    mock.patch.object(
                        analyzer.input_mod, "prepare_local_input") as prepare:
                exit_code = analyzer._run_headless_scan(
                    self._args(str(source), str(source))
                )

            self.assertEqual(exit_code, cli.EXIT_INCONCLUSIVE)
            self.assertEqual(source.read_bytes(), original)
            find_apktool.assert_not_called()
            prepare.assert_not_called()

    def test_report_cannot_overwrite_an_apk_inside_input_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir, "split-set")
            source.mkdir()
            base = source / "base.apk"
            original = b"original-apk-bytes"
            base.write_bytes(original)
            with mock.patch.object(
                    analyzer, "_find_apktool") as find_apktool, \
                    mock.patch.object(
                        analyzer.input_mod, "prepare_local_input") as prepare:
                exit_code = analyzer._run_headless_scan(
                    self._args(str(source), str(base))
                )

            self.assertEqual(exit_code, cli.EXIT_INCONCLUSIVE)
            self.assertEqual(base.read_bytes(), original)
            find_apktool.assert_not_called()
            prepare.assert_not_called()

    def test_new_default_report_name_is_allowed_inside_input_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir, "split-set")
            source.mkdir()
            output = source / "apkanalyzer_report_new.json"

            self.assertFalse(
                analyzer._output_overlaps_input(str(source), str(output))
            )

    def test_existing_input_overlap_honors_case_insensitive_filesystem(self):
        with mock.patch.object(
                analyzer, "_paths_alias", return_value=False), \
                mock.patch.object(analyzer.os.path, "isdir", return_value=True), \
                mock.patch.object(analyzer.os.path, "lexists", return_value=True), \
                mock.patch.object(
                    analyzer.os.path, "realpath", side_effect=lambda value: value
                ), mock.patch.object(
                    analyzer.archive_mod, "filesystem_is_case_sensitive",
                    return_value=False,
                ):
            overlaps = analyzer._output_overlaps_input(
                "/Volumes/Work/Splits",
                "/Volumes/Work/splits/base.apk",
            )

        self.assertTrue(overlaps)

    def test_rejected_directory_symlink_is_not_replaced_by_report(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links are unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            real_source = Path(temp_dir, "real-input")
            real_source.mkdir()
            source_link = Path(temp_dir, "input-link")
            try:
                source_link.symlink_to(real_source, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symbolic links are unavailable: {exc}")

            with mock.patch.object(
                    analyzer, "_find_apktool") as find_apktool:
                exit_code = analyzer._run_headless_scan(
                    self._args(str(source_link), str(source_link))
                )

            self.assertEqual(exit_code, cli.EXIT_INCONCLUSIVE)
            self.assertTrue(source_link.is_symlink())
            self.assertTrue(real_source.is_dir())
            find_apktool.assert_not_called()

    def test_headless_diagnostics_are_single_line_and_secret_redacted(self):
        synthetic = "api_key = \"abcdefghijklmnopqrstuvwx\"\nnext line"
        rendered = analyzer._headless_diagnostic(RuntimeError(synthetic))
        self.assertNotIn("\n", rendered)
        self.assertNotIn("abcdefghijklmnopqrstuvwx", rendered)
        self.assertIn("[REDACTED]", rendered)

    def test_noninteractive_security_scan_never_pulls_or_pauses(self):
        with tempfile.TemporaryDirectory() as temp_dir, \
                mock.patch.object(
                    analyzer, "_pull_and_decompile",
                    side_effect=AssertionError("must not pull")), \
                mock.patch.object(
                    analyzer, "pause",
                    side_effect=AssertionError("must not pause")), \
                mock.patch.object(
                    analyzer, "_parse_manifest",
                    return_value={"parsed": False}), \
                mock.patch.object(analyzer, "detect_framework") as framework, \
                mock.patch.object(analyzer, "_print_framework_info"):
            framework.return_value = {}
            result = analyzer.security_scan(
                "com.example.invalid",
                interactive=False,
                decompiled_dir=temp_dir,
            )

        self.assertFalse(result["completed"])
        self.assertGreaterEqual(result["inconclusive"], 1)


if __name__ == "__main__":
    unittest.main()
