import io
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import apkAnalyzer as analyzer


ANDROID_NS = "http://schemas.android.com/apk/res/android"
PACKAGE = "com.example.splitcoverage"


def _write_base(root):
    Path(root, "AndroidManifest.xml").write_text(
        f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ANDROID_NS}" package="{PACKAGE}">
  <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="35"/>
  <permission android:name="{PACKAGE}.BASE_GATE"
              android:protectionLevel="signature"/>
  <application android:debuggable="false" android:allowBackup="false"
               android:usesCleartextTraffic="false"
               android:permission="{PACKAGE}.BASE_GATE"/>
</manifest>''',
        encoding="utf-8",
    )


def _split_root(root, number=1):
    result = Path(root, ".apkanalyzer_splits", f"split_{number:04d}")
    result.mkdir(parents=True)
    return result


def _run_scan(root, collector, native_scan=None):
    if native_scan is None:
        native_scan = []
    output = io.StringIO()
    with mock.patch.object(
        analyzer, "_pull_and_decompile", return_value=(root, root)
    ), mock.patch.object(
        analyzer, "_find_local_apk", return_value=None
    ), mock.patch.object(
        analyzer, "_print_security_classes"
    ), mock.patch.object(
        analyzer, "_scan_native_strings", return_value=native_scan
    ), mock.patch.object(
        analyzer, "pause"
    ), mock.patch.object(
        analyzer, "report", collector
    ), redirect_stdout(output):
        analyzer.security_scan(PACKAGE)
    return analyzer._terminal_safe(output.getvalue())


class SplitManifestAggregationTests(unittest.TestCase):
    def test_lone_feature_split_is_not_treated_as_a_complete_base(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "AndroidManifest.xml").write_text(
                f'''<manifest xmlns:android="{ANDROID_NS}"
                    package="{PACKAGE}" split="feature_payments"
                    android:isFeatureSplit="true">
  <application/>
</manifest>''',
                encoding="utf-8",
            )
            parsed = analyzer._parse_manifest(
                tmp, expected_split_dirs=(), expected_apk_count=1
            )

        self.assertFalse(parsed["parsed"])
        self.assertEqual(parsed["manifest_split"], "feature_payments")
        self.assertFalse(parsed["split_manifest_coverage"]["complete"])
        self.assertTrue(any(
            "without its base APK" in issue
            for issue in parsed["split_manifest_coverage"]["issues"]
        ))

    def test_feature_security_evidence_is_aggregated_with_base_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_base(tmp)
            # This resource exists only in the base. A split-local reference
            # must not silently resolve by reaching outside the split root.
            base_values = Path(tmp, "res", "values")
            base_values.mkdir(parents=True)
            Path(base_values, "bools.xml").write_text(
                '<resources><bool name="base_exported">true</bool></resources>',
                encoding="utf-8",
            )

            split = _split_root(tmp)
            split_values = Path(split, "res", "values")
            split_values.mkdir(parents=True)
            Path(split_values, "bools.xml").write_text(
                '<resources><bool name="feature_exported">true</bool></resources>',
                encoding="utf-8",
            )
            Path(split, "AndroidManifest.xml").write_text(
                f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ANDROID_NS}" package="{PACKAGE}">
  <uses-permission android:name="android.permission.CAMERA"/>
  <permission android:name="{PACKAGE}.FEATURE_GATE"
              android:protectionLevel="signature"/>
  <application>
    <service android:name=".InheritedGate" android:exported="true"/>
    <service android:name=".FeatureService" android:exported="true"
             android:permission=""/>
    <service android:name=".LocalResourceService"
             android:exported="@bool/feature_exported"
             android:permission=""/>
    <service android:name=".BaseResourceService"
             android:exported="@bool/base_exported"
             android:permission=""/>
    <activity android:name=".FeatureLink" android:exported="true"
              android:permission="" android:taskAffinity="shared.feature">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="feature" android:host="open.example"/>
      </intent-filter>
    </activity>
  </application>
</manifest>''',
                encoding="utf-8",
            )
            native = Path(split, "lib", "arm64-v8a")
            native.mkdir(parents=True)
            Path(native, "libfrida-gadget.so").write_bytes(b"not-a-real-elf")
            security_class = Path(
                split, "smali_classes2", "com", "scottyab", "rootbeer"
            )
            security_class.mkdir(parents=True)
            Path(security_class, "RootBeer.smali").write_text(
                ".class public Lcom/scottyab/rootbeer/RootBeer;",
                encoding="utf-8",
            )

            parsed = analyzer._parse_manifest(tmp)
            framework = analyzer.detect_framework(tmp)
            classes = analyzer._check_security_classes(tmp)

        self.assertTrue(parsed["split_manifest_coverage"]["complete"])
        self.assertEqual(parsed["split_manifest_coverage"]["parsed"], 1)
        self.assertIn("android.permission.CAMERA", parsed["permissions"])
        self.assertEqual(
            parsed["declared_permissions"][f"{PACKAGE}.FEATURE_GATE"],
            "signature",
        )
        services = {
            item["name"]: item for item in parsed["exported"]["service"]
        }
        # Missing split attributes inherit the base SDK/application policy.
        self.assertEqual(
            services[".InheritedGate"]["permission"],
            f"{PACKAGE}.BASE_GATE",
        )
        self.assertEqual(
            services[".LocalResourceService"]["exposure_state"],
            analyzer.resource_mod.KNOWN,
        )
        self.assertEqual(
            services[".BaseResourceService"]["exposure_state"],
            analyzer.resource_mod.UNKNOWN,
        )
        self.assertEqual(parsed["deeplinks"]["filters"][0]["min_sdk"], "28")
        self.assertIn((".FeatureLink", "shared.feature"), parsed["task_affinity"])
        self.assertIn(("Frida Gadget", ["libfrida-gadget.so"]), framework["native_sdks"])
        self.assertTrue(any(label == "RootBeer" for label, _path, _count in classes))

    def test_feature_only_findings_reach_the_security_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_base(tmp)
            split = _split_root(tmp)
            Path(split, "AndroidManifest.xml").write_text(
                f'''<manifest xmlns:android="{ANDROID_NS}" package="{PACKAGE}">
  <uses-permission android:name="android.permission.CAMERA"/>
  <application>
    <service android:name=".FeatureService" android:exported="true"
             android:permission=""/>
    <activity android:name=".FeatureLink" android:exported="true"
              android:permission="" android:taskAffinity="shared.feature">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="feature" android:host="open.example"/>
      </intent-filter>
    </activity>
  </application>
</manifest>''',
                encoding="utf-8",
            )
            collector = analyzer.ReportCollector()
            rendered = _run_scan(tmp, collector)

        self.assertIn("FeatureService", rendered)
        self.assertIn("CAMERA", rendered)
        self.assertIn("feature://open.example", rendered)
        self.assertIn("FeatureLink", rendered)
        rule_ids = {finding["rule_id"] for finding in collector.findings}
        self.assertIn("exported_components", rule_ids)
        self.assertIn("deeplinks", rule_ids)
        self.assertIn("task_hijacking", rule_ids)

    def test_malformed_split_is_explicitly_inconclusive_and_suppresses_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_base(tmp)
            split = _split_root(tmp)
            Path(split, "AndroidManifest.xml").write_text(
                "<manifest><application>", encoding="utf-8"
            )
            parsed = analyzer._parse_manifest(tmp)
            collector = analyzer.ReportCollector()
            rendered = _run_scan(tmp, collector)

        coverage = parsed["split_manifest_coverage"]
        self.assertFalse(coverage["complete"])
        self.assertEqual(coverage["discovered"], 1)
        self.assertEqual(coverage["parsed"], 0)
        self.assertTrue(any(
            item["check_id"] == "split_manifest_coverage"
            for item in collector.inconclusive
        ))
        self.assertNotIn("[PASS] Exported components", rendered)
        self.assertNotIn("[PASS] Dangerous permissions", rendered)
        self.assertNotIn("[PASS] Deeplinks", rendered)
        self.assertNotIn("[PASS] Task hijacking", rendered)
        self.assertIn("feature-split manifest coverage is incomplete", rendered)

    def test_mismatched_split_package_is_not_merged(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_base(tmp)
            split = _split_root(tmp)
            Path(split, "AndroidManifest.xml").write_text(
                f'''<manifest xmlns:android="{ANDROID_NS}"
                    package="com.example.different">
  <uses-permission android:name="android.permission.CAMERA"/>
</manifest>''',
                encoding="utf-8",
            )
            parsed = analyzer._parse_manifest(tmp)

        self.assertFalse(parsed["split_manifest_coverage"]["complete"])
        self.assertNotIn("android.permission.CAMERA", parsed["permissions"])

    def test_prepared_expectations_prevent_missing_split_false_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_base(tmp)
            expected = Path(
                tmp, ".apkanalyzer_splits", "split_0001"
            )
            parsed = analyzer._parse_manifest(
                tmp,
                expected_split_dirs=(str(expected),),
                expected_apk_count=2,
            )

        self.assertFalse(parsed["split_manifest_coverage"]["complete"])
        self.assertTrue(any(
            "Expected 1 split manifest" in issue
            for issue in parsed["split_manifest_coverage"]["issues"]
        ))

    def test_device_metadata_anchors_manifest_discovery_to_expected_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_base(tmp)
            Path(tmp, ".apkanalyzer_meta.json").write_text(
                '''{
  "cache_schema": 2,
  "source": "device",
  "remote_apk_paths": ["/base.apk", "/split.apk"]
}''',
                encoding="utf-8",
            )
            parsed = analyzer._parse_manifest(tmp)

        self.assertFalse(parsed["split_manifest_coverage"]["complete"])


class SplitTraversalSafetyTests(unittest.TestCase):
    def test_symlinked_split_native_and_smali_trees_are_not_followed(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links are unavailable")
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            _write_base(tmp)
            split = _split_root(tmp)
            Path(split, "AndroidManifest.xml").write_text(
                f'<manifest xmlns:android="{ANDROID_NS}" package="{PACKAGE}"/>',
                encoding="utf-8",
            )
            outside_lib = Path(outside, "lib")
            outside_lib.mkdir()
            Path(outside_lib, "libfrida-gadget.so").write_bytes(b"outside")
            outside_smali = Path(outside, "smali")
            Path(outside_smali, "com", "scottyab", "rootbeer").mkdir(
                parents=True
            )
            try:
                Path(split, "lib").symlink_to(outside_lib, target_is_directory=True)
                Path(split, "smali").symlink_to(
                    outside_smali, target_is_directory=True
                )
            except OSError as exc:
                self.skipTest(f"symbolic links are unavailable: {exc}")

            libs = analyzer._scan_native_libs(tmp)
            classes = analyzer._check_security_classes(tmp)

        self.assertEqual(libs, [])
        self.assertEqual(classes, [])

    def test_native_string_coverage_preserves_matches_before_oversized_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_base(tmp)
            native = Path(tmp, "lib", "arm64-v8a")
            native.mkdir(parents=True)
            Path(native, "a_match.so").write_bytes(
                b"prefix-frida-server-suffix"
            )
            Path(native, "z_large.so").write_bytes(b"x" * 80)
            with mock.patch.object(
                analyzer.shutil, "which", return_value=None
            ), mock.patch.object(
                analyzer, "_MAX_NATIVE_STRING_FILE_BYTES", 40
            ):
                scan = analyzer._scan_native_strings(
                    tmp, with_coverage=True
                )

        self.assertFalse(scan["coverage"]["complete"])
        self.assertEqual(
            scan["coverage"]["oversized"], ["lib/arm64-v8a/z_large.so"]
        )
        self.assertEqual(scan["matches"][0][0], "lib/arm64-v8a/a_match.so")
        self.assertIn("Frida", scan["matches"][0][1])

    def test_native_strings_timeout_is_coverage_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_base(tmp)
            native = Path(tmp, "lib", "arm64-v8a")
            native.mkdir(parents=True)
            Path(native, "libsample.so").write_bytes(b"ordinary-native-data")
            with mock.patch.object(
                analyzer.shutil, "which", return_value="/tools/strings"
            ), mock.patch.object(
                analyzer,
                "_run_native_strings_tool",
                side_effect=subprocess.TimeoutExpired(["strings"], 30),
            ):
                scan = analyzer._scan_native_strings(
                    tmp, with_coverage=True
                )

        self.assertFalse(scan["coverage"]["complete"])
        self.assertEqual(
            scan["coverage"]["timed_out"], ["lib/arm64-v8a/libsample.so"]
        )

    def test_native_strings_output_is_bounded_and_marked_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_base(tmp)
            native = Path(tmp, "lib", "arm64-v8a")
            native.mkdir(parents=True)
            Path(native, "libsample.so").write_bytes(
                b"frida-server\n" + b"x" * 100
            )
            with mock.patch.object(
                analyzer.shutil, "which", return_value=None
            ), mock.patch.object(
                analyzer, "_MAX_NATIVE_STRING_OUTPUT_BYTES", 32
            ):
                scan = analyzer._scan_native_strings(
                    tmp, with_coverage=True
                )

        self.assertFalse(scan["coverage"]["complete"])
        self.assertEqual(
            scan["coverage"]["partial"], ["lib/arm64-v8a/libsample.so"]
        )
        self.assertIn("Frida", scan["matches"][0][1])

    def test_native_string_file_budget_preserves_hits_and_marks_remainder(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_base(tmp)
            native = Path(tmp, "lib", "arm64-v8a")
            native.mkdir(parents=True)
            Path(native, "a_match.so").write_bytes(b"frida-server-found")
            Path(native, "z_unscanned.so").write_bytes(b"ordinary-data")
            with mock.patch.object(
                analyzer.shutil, "which", return_value=None
            ), mock.patch.object(
                analyzer, "_MAX_NATIVE_STRING_FILES", 1
            ):
                scan = analyzer._scan_native_strings(
                    tmp, with_coverage=True
                )

        self.assertFalse(scan["coverage"]["complete"])
        self.assertEqual(scan["coverage"]["scanned_files"], 1)
        self.assertEqual(
            scan["coverage"]["unscanned"],
            ["lib/arm64-v8a/z_unscanned.so"],
        )
        self.assertIn("Frida", scan["matches"][0][1])

    def test_native_string_total_byte_budget_stops_before_next_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_base(tmp)
            native = Path(tmp, "lib", "arm64-v8a")
            native.mkdir(parents=True)
            Path(native, "a_match.so").write_bytes(b"frida-server")
            Path(native, "z_unscanned.so").write_bytes(b"ordinary-data")
            with mock.patch.object(
                analyzer.shutil, "which", return_value=None
            ), mock.patch.object(
                analyzer, "_MAX_NATIVE_STRING_TOTAL_BYTES", 20
            ):
                scan = analyzer._scan_native_strings(
                    tmp, with_coverage=True
                )

        self.assertFalse(scan["coverage"]["complete"])
        self.assertEqual(scan["coverage"]["considered_bytes"], 12)
        self.assertEqual(
            scan["coverage"]["unscanned"],
            ["lib/arm64-v8a/z_unscanned.so"],
        )
        self.assertIn("byte total scan limit", scan["coverage"]["budget_reasons"][0])
        self.assertIn("Frida", scan["matches"][0][1])

    def test_native_string_global_deadline_preserves_prior_hits(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_base(tmp)
            native = Path(tmp, "lib", "arm64-v8a")
            native.mkdir(parents=True)
            first = Path(native, "a_match.so")
            second = Path(native, "z_unscanned.so")
            first.write_bytes(b"frida-server")
            second.write_bytes(b"ordinary-data")
            libraries = [
                (first.name, "lib/arm64-v8a/a_match.so"),
                (second.name, "lib/arm64-v8a/z_unscanned.so"),
            ]
            with mock.patch.object(
                analyzer.shutil, "which", return_value=None
            ), mock.patch.object(
                analyzer, "_discover_native_libs", return_value=(libraries, [])
            ), mock.patch.object(
                analyzer, "_MAX_NATIVE_STRING_SCAN_SECONDS", 1
            ), mock.patch.object(
                analyzer.time, "monotonic", side_effect=[0.0, 0.1, 2.0, 2.0]
            ):
                scan = analyzer._scan_native_strings(
                    tmp, with_coverage=True
                )

        self.assertFalse(scan["coverage"]["complete"])
        self.assertEqual(
            scan["coverage"]["unscanned"],
            ["lib/arm64-v8a/z_unscanned.so"],
        )
        self.assertIn("second limit", scan["coverage"]["budget_reasons"][0])
        self.assertIn("Frida", scan["matches"][0][1])

    def test_native_strings_rejects_batch_wrapper_and_uses_safe_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_base(tmp)
            native = Path(tmp, "lib", "arm64-v8a")
            native.mkdir(parents=True)
            Path(native, "libsample.so").write_bytes(b"frida-server")
            with mock.patch.object(
                analyzer.shutil, "which", return_value=r"C:\\tools\\strings.CMD"
            ), mock.patch.object(
                analyzer, "_run_native_strings_tool"
            ) as run_tool:
                scan = analyzer._scan_native_strings(
                    tmp, with_coverage=True
                )

        run_tool.assert_not_called()
        self.assertTrue(scan["coverage"]["rejected_batch_wrapper"])
        self.assertEqual(scan["coverage"]["strings_tool"], "python-fallback")
        self.assertIn("Frida", scan["matches"][0][1])

    def test_native_strings_tool_uses_contained_bounded_capture(self):
        completed = subprocess.CompletedProcess(
            ["strings"], 0, "frida-server", ""
        )
        with mock.patch.object(
            analyzer, "_process_run_command_capture", return_value=completed
        ) as run_capture:
            result = analyzer._run_native_strings_tool(
                "/tools/strings", "/tmp/lib sample.so", timeout=3
            )

        self.assertEqual(result, (0, "frida-server", False))
        run_capture.assert_called_once_with(
            ["/tools/strings", "-n", "8", "/tmp/lib sample.so"],
            timeout=3,
            max_output_bytes=analyzer._MAX_NATIVE_STRING_OUTPUT_BYTES,
        )

    def test_native_discovery_rejects_reparse_point_library(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_base(tmp)
            native = Path(tmp, "lib", "arm64-v8a")
            native.mkdir(parents=True)
            library = Path(native, "libredirect.so")
            library.write_bytes(b"ordinary-data")
            original_lstat = analyzer.os.lstat
            reparse_flag = getattr(analyzer.stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

            def fake_lstat(path):
                result = original_lstat(path)
                if os.path.abspath(os.fspath(path)) == os.path.abspath(str(library)):
                    return mock.Mock(
                        st_mode=result.st_mode,
                        st_file_attributes=reparse_flag,
                    )
                return result

            with mock.patch.object(analyzer.os, "lstat", side_effect=fake_lstat):
                libraries, issues = analyzer._discover_native_libs(tmp)

        self.assertEqual(libraries, [])
        self.assertTrue(any("unsafe native library file" in item for item in issues))

    def test_native_string_gap_marks_security_report_inconclusive(self):
        native_scan = {
            "matches": [],
            "coverage": {
                "complete": False,
                "candidate_files": 1,
                "scanned_files": 0,
                "matched_files": 0,
                "oversized": ["lib/arm64-v8a/large.so"],
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            _write_base(tmp)
            collector = analyzer.ReportCollector()
            rendered = _run_scan(tmp, collector, native_scan=native_scan)

        self.assertIn("Native library strings", rendered)
        self.assertIn("INCONCLUSIVE", rendered)
        self.assertNotIn(
            "No security-related strings found in native libraries", rendered
        )
        self.assertTrue(any(
            item["check_id"] == "native_string_coverage"
            for item in collector.inconclusive
        ))


if __name__ == "__main__":
    unittest.main()
