import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import apkAnalyzer as analyzer
from apk_analyzer import code_scan


ANDROID_NS = "http://schemas.android.com/apk/res/android"


def write_safe_manifest(root):
    manifest = Path(root, "AndroidManifest.xml")
    manifest.write_text(
        f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ANDROID_NS}" package="com.example.coverage">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/>
  <application android:debuggable="false" android:allowBackup="false"
               android:usesCleartextTraffic="false"/>
</manifest>''',
        encoding="utf-8",
    )
    return manifest


def run_security_scan(root, collector, sanitize=True):
    output = io.StringIO()
    with mock.patch.object(
        analyzer, "_pull_and_decompile", return_value=(root, root)
    ), mock.patch.object(
        analyzer, "detect_framework", return_value={}
    ), mock.patch.object(
        analyzer, "_print_framework_info"
    ), mock.patch.object(
        analyzer, "_find_local_apk", return_value=None
    ), mock.patch.object(
        analyzer, "_print_security_classes"
    ), mock.patch.object(
        analyzer, "_check_security_classes", return_value=[]
    ), mock.patch.object(
        analyzer, "_scan_native_strings", return_value=[]
    ), mock.patch.object(
        analyzer, "pause"
    ), mock.patch.object(
        analyzer, "report", collector
    ), redirect_stdout(output):
        analyzer.security_scan("com.example.coverage")
    rendered = output.getvalue()
    return analyzer._terminal_safe(rendered) if sanitize else rendered


class StaticCodeModuleTests(unittest.TestCase):
    def test_oversized_file_yields_prefix_to_consumer_and_is_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "large.smali").write_bytes(
                b"addJavascriptInterface\n" + (b"x" * 100)
            )
            consumed = []

            result = code_scan.scan_tree(
                tmp,
                lambda path, content: consumed.append((path, content)),
                max_file_bytes=32,
                max_total_bytes=1024,
                chunk_bytes=7,
            )

        self.assertEqual(result.bytes_scanned, 32)
        self.assertEqual(result.partial, ["large.smali"])
        self.assertEqual(result.oversized, ["large.smali"])
        self.assertFalse(result.coverage_complete)
        self.assertEqual(consumed[0][0], "large.smali")
        self.assertIn("addJavascriptInterface", consumed[0][1])

    def test_total_budget_accounts_for_complete_partial_and_skipped_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("a.smali", "b.xml", "c.smali"):
                Path(tmp, name).write_bytes(b"x" * 40)
            consumed = []

            result = code_scan.scan_tree(
                tmp,
                lambda path, content: consumed.append((path, len(content))),
                max_file_bytes=100,
                max_total_bytes=60,
                chunk_bytes=9,
            )

        self.assertEqual(result.bytes_scanned, 60)
        self.assertEqual(result.scanned, ["a.smali", "b.xml"])
        self.assertEqual(result.partial, ["b.xml"])
        self.assertEqual(result.skipped, ["c.smali"])
        self.assertEqual(result.oversized, [])
        self.assertEqual(consumed, [("a.smali", 40), ("b.xml", 20)])
        self.assertFalse(result.coverage_complete)

    def test_unreadable_candidate_is_not_silently_omitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            blocked = Path(tmp, "blocked.smali")
            blocked.write_text("ordinary code", encoding="utf-8")
            real_open = os.open

            def deny_blocked(path, flags, *args, **kwargs):
                if os.path.abspath(os.fspath(path)) == str(blocked):
                    raise PermissionError("synthetic denial")
                return real_open(path, flags, *args, **kwargs)

            with mock.patch.object(
                    code_scan.os, "open", side_effect=deny_blocked):
                result = code_scan.scan_tree(tmp, lambda _path, _text: None)

        self.assertEqual(result.unreadable, ["blocked.smali"])
        self.assertEqual(result.scanned, [])
        self.assertFalse(result.coverage_complete)

    def test_symlinked_file_and_directory_are_explicitly_skipped(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links are unavailable")
        with tempfile.TemporaryDirectory() as tmp, \
                tempfile.TemporaryDirectory() as external:
            Path(external, "external.smali").write_text(
                "addJavascriptInterface", encoding="utf-8"
            )
            try:
                Path(tmp, "linked.smali").symlink_to(
                    Path(external, "external.smali")
                )
                Path(tmp, "linked-tree").symlink_to(
                    external, target_is_directory=True
                )
            except OSError as exc:
                self.skipTest(f"symbolic links are unavailable: {exc}")

            consumed = []
            result = code_scan.scan_tree(
                tmp, lambda path, _text: consumed.append(path)
            )

        self.assertEqual(consumed, [])
        self.assertEqual(
            result.skipped, ["linked-tree", "linked.smali"]
        )
        self.assertFalse(result.coverage_complete)

    def test_invalid_utf8_is_replaced_without_losing_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "invalid.xml").write_bytes(b"before\xffafter")
            consumed = []
            result = code_scan.scan_tree(
                tmp, lambda _path, content: consumed.append(content)
            )

        self.assertTrue(result.coverage_complete)
        self.assertEqual(consumed, ["before\ufffdafter"])


class StaticCodeSecurityScanTests(unittest.TestCase):
    def test_apk_controlled_clipboard_path_cannot_emit_terminal_controls(self):
        dangerous_name = "evil\x1b]52;c;U1lOVEhFVElD\x07.smali"
        with tempfile.TemporaryDirectory() as tmp:
            write_safe_manifest(tmp)
            Path(tmp, dangerous_name).write_text(
                "invoke-virtual {v0, v1}, "
                "Landroid/content/ClipboardManager;->setPrimaryClip"
                "(Landroid/content/ClipData;)V\n",
                encoding="utf-8",
            )
            collector = analyzer.ReportCollector()
            rendered = run_security_scan(tmp, collector, sanitize=False)

        self.assertIn("Clipboard write(s)", rendered)
        self.assertNotIn("\x1b]52", rendered)
        self.assertNotIn("\x07", rendered)

    def test_missing_signing_evidence_is_inconclusive_not_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_safe_manifest(tmp)
            collector = analyzer.ReportCollector()
            with mock.patch.object(analyzer.shutil, "which", return_value=None):
                run_security_scan(tmp, collector)

        self.assertTrue(any(
            item["check_id"] == "apk_signing"
            for item in collector.inconclusive
        ))

    def test_malformed_manifest_keeps_pending_intent_and_logging_findings(self):
        pending_signature = (
            "Landroid/app/PendingIntent;->getActivity("
            "Landroid/content/Context;ILandroid/content/Intent;I)"
            "Landroid/app/PendingIntent;"
        )
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "AndroidManifest.xml").write_text(
                "<manifest><application>", encoding="utf-8"
            )
            Path(tmp, "Risk.smali").write_text(
                f'''.method public create()V
    new-instance v2, Landroid/content/Intent;
    invoke-direct {{v2}}, Landroid/content/Intent;-><init>()V
    const/4 v3, 0x0
    invoke-static {{v0, v1, v2, v3}}, {pending_signature}
    invoke-static {{v4, v5}}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
.end method
''',
                encoding="utf-8",
            )
            collector = analyzer.ReportCollector()
            rendered = run_security_scan(tmp, collector)

        self.assertIn("Could not read AndroidManifest.xml", rendered)
        self.assertIn("Unsafe PendingIntent invocation(s): 1", rendered)
        self.assertIn("Debug/verbose log calls found", rendered)
        self.assertNotIn("[PASS]", rendered)
        self.assertTrue(any(
            finding["rule_id"] == "pending_intent_mutable"
            for finding in collector.findings
        ))
        self.assertTrue(any(
            finding["rule_id"] == "debug_logging"
            for finding in collector.findings
        ))

    def test_total_budget_preserves_finding_but_suppresses_clean_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_safe_manifest(tmp)
            finding_source = Path(tmp, "a.smali")
            finding_source.write_text(
                "invoke-virtual {v0}, "
                "Landroid/webkit/WebView;->addJavascriptInterface"
                "(Ljava/lang/Object;Ljava/lang/String;)V\n"
                + ("x" * 80),
                encoding="utf-8",
            )
            Path(tmp, "b.smali").write_text(
                "ordinary code that will not be completely inspected",
                encoding="utf-8",
            )
            # AndroidManifest.xml and a.smali are complete; b.smali is only
            # partially read. This proves positive evidence is retained while
            # absence-based results are no longer called PASS.
            total_budget = (
                manifest.stat().st_size + finding_source.stat().st_size + 8
            )
            collector = analyzer.ReportCollector()

            with mock.patch.object(
                analyzer, "STATIC_CODE_MAX_TOTAL_BYTES", total_budget
            ), mock.patch.object(
                analyzer, "STATIC_CODE_MAX_FILE_BYTES", 1024 * 1024
            ):
                rendered = run_security_scan(tmp, collector)

        self.assertIn("WebView.addJavascriptInterface() used", rendered)
        self.assertIn("Static smali/XML coverage is incomplete", rendered)
        self.assertNotIn(
            "[PASS] WebView JS Interface -- No addJavascriptInterface() found",
            rendered,
        )
        self.assertNotIn(
            "[PASS] Debug logging -- No verbose/debug log calls detected",
            rendered,
        )
        self.assertTrue(any(
            finding["rule_id"] == "webview_js_interface"
            for finding in collector.findings
        ))
        self.assertTrue(any(
            item["check_id"] == "static_code_coverage"
            for item in collector.inconclusive
        ))
        coverage = collector.app_info["static_code_scan_coverage"]
        self.assertFalse(coverage["coverage_complete"])
        self.assertEqual(coverage["partial"], ["b.smali"])

    def test_symlinked_smali_makes_all_absence_claims_inconclusive(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links are unavailable")
        with tempfile.TemporaryDirectory() as tmp, \
                tempfile.TemporaryDirectory() as external:
            write_safe_manifest(tmp)
            Path(external, "hidden.smali").write_text(
                "Landroid/util/Log;->d(", encoding="utf-8"
            )
            try:
                Path(tmp, "linked-code").symlink_to(
                    external, target_is_directory=True
                )
            except OSError as exc:
                self.skipTest(f"symbolic links are unavailable: {exc}")
            collector = analyzer.ReportCollector()
            rendered = run_security_scan(tmp, collector)

        self.assertIn("smali/XML coverage was incomplete", rendered)
        self.assertNotIn("[PASS] Debug logging", rendered)
        self.assertIn("linked-code", collector.app_info[
            "static_code_scan_coverage"
        ]["skipped"])


class BoundedKeywordSearchTests(unittest.TestCase):
    def test_oversized_keyword_source_preserves_prefix_hit_and_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "Huge.smali").write_text(
                "TracerPid\n" + ("x" * 200), encoding="utf-8"
            )

            results, scanned, coverage = analyzer._search_decompiled(
                tmp,
                [("Anti-Debug", ["TracerPid"])],
                include_coverage=True,
                max_file_bytes=32,
                max_total_bytes=1024,
            )

        self.assertEqual(scanned, 1)
        self.assertEqual(len(results["Anti-Debug"]), 1)
        self.assertEqual(coverage.partial, ["Huge.smali"])
        self.assertEqual(coverage.oversized, ["Huge.smali"])
        self.assertFalse(coverage.coverage_complete)

    def test_symlinked_keyword_tree_cannot_report_not_detected(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links are unavailable")
        with tempfile.TemporaryDirectory() as tmp, \
                tempfile.TemporaryDirectory() as external:
            Path(external, "Hidden.smali").write_text(
                "isEmulator", encoding="utf-8"
            )
            try:
                Path(tmp, "linked-code").symlink_to(
                    external, target_is_directory=True
                )
            except OSError as exc:
                self.skipTest(f"symbolic links are unavailable: {exc}")

            output = io.StringIO()
            collector = analyzer.ReportCollector()
            framework = {
                "framework": "Java", "native_sdks": [], "details": [],
            }
            with mock.patch.object(
                analyzer, "_pull_and_decompile", return_value=(tmp, tmp)
            ), mock.patch.object(
                analyzer, "detect_framework", return_value=framework
            ), mock.patch.object(
                analyzer, "_print_framework_info"
            ), mock.patch.object(
                analyzer, "pause"
            ), mock.patch.object(
                analyzer, "report", collector
            ), redirect_stdout(output):
                analyzer.emulation_detection_check("com.example.coverage")

        rendered = analyzer._terminal_safe(output.getvalue())
        self.assertIn("RESULT: INCONCLUSIVE", rendered)
        self.assertNotIn("RESULT: Emulator Detection NOT DETECTED", rendered)
        self.assertIn(
            "emulation_keyword_coverage",
            {item["check_id"] for item in collector.inconclusive},
        )

    def test_result_cap_is_coverage_incomplete_not_silent_truncation(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "Many.smali").write_text(
                "needle\nneedle\n", encoding="utf-8"
            )
            with mock.patch.object(
                    analyzer, "KEYWORD_SEARCH_MAX_MATCHES", 1):
                results, _scanned, coverage = analyzer._search_decompiled(
                    tmp,
                    [("Group", ["needle"])],
                    include_coverage=True,
                )

        self.assertEqual(len(results["Group"]), 1)
        self.assertEqual(coverage.analysis_limited, ["Many.smali"])
        self.assertFalse(coverage.coverage_complete)


if __name__ == "__main__":
    unittest.main()
