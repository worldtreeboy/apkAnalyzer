import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import apkAnalyzer as analyzer
from apk_analyzer import resources


ANDROID_NS = "http://schemas.android.com/apk/res/android"


def write_manifest(root, application, min_sdk="23", target_sdk="35"):
    Path(root, "AndroidManifest.xml").write_text(
        f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ANDROID_NS}" package="com.example.app">
  <uses-sdk android:minSdkVersion="{min_sdk}"
            android:targetSdkVersion="{target_sdk}"/>
  {application}
</manifest>''',
        encoding="utf-8",
    )


def write_bool(root, directory, name, value):
    values = Path(root, "res", directory)
    values.mkdir(parents=True, exist_ok=True)
    Path(values, "bools.xml").write_text(
        f'<resources><bool name="{name}">{value}</bool></resources>',
        encoding="utf-8",
    )


def write_nsc(root, directory, cleartext):
    xml = Path(root, "res", directory)
    xml.mkdir(parents=True, exist_ok=True)
    Path(xml, "policy.xml").write_text(
        '<network-security-config><base-config '
        f'cleartextTrafficPermitted="{str(cleartext).lower()}"/>'
        '</network-security-config>',
        encoding="utf-8",
    )


def run_security_scan(root):
    output = io.StringIO()
    collector = analyzer.ReportCollector()
    with mock.patch.object(
        analyzer, "_pull_and_decompile", return_value=(root, root)
    ), mock.patch.object(
        analyzer, "_print_framework_info"
    ), mock.patch.object(
        analyzer, "detect_framework", return_value={}
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
        analyzer.security_scan("com.example.app")
    return analyzer._terminal_safe(output.getvalue()), collector


class BooleanResourceResolutionTests(unittest.TestCase):
    def test_manifest_resolves_true_and_false_bool_references(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '''<application android:debuggable="@bool/debug_build"
                    android:allowBackup="@bool/backup_enabled"/>''',
            )
            values = Path(tmp, "res", "values")
            values.mkdir(parents=True)
            Path(values, "security.xml").write_text(
                '''<resources>
  <bool name="debug_build">true</bool>
  <item type="bool" name="backup_enabled">false</item>
</resources>''',
                encoding="utf-8",
            )

            manifest = analyzer._parse_manifest(tmp)

        self.assertIs(manifest["debuggable"], True)
        self.assertIs(manifest["allow_backup"], False)
        self.assertEqual(
            manifest["attribute_states"]["debuggable"]["state"],
            resources.KNOWN,
        )
        self.assertEqual(
            manifest["attribute_states"]["allow_backup"]["state"],
            resources.KNOWN,
        )

    def test_missing_bool_reference_is_unknown_not_attribute_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '<application android:debuggable="@bool/not_present"/>',
            )
            manifest = analyzer._parse_manifest(tmp)

        self.assertIsNone(manifest["debuggable"])
        self.assertEqual(
            manifest["attribute_states"]["debuggable"]["state"],
            resources.UNKNOWN,
        )

    def test_version_qualified_bool_conflict_is_conditional(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '''<application android:debuggable="@bool/debug_build">
  <service android:name=".Sync" android:enabled="@bool/service_enabled"
           android:exported="@bool/service_exported"/>
</application>''',
            )
            values = Path(tmp, "res", "values")
            values.mkdir(parents=True)
            Path(values, "security.xml").write_text(
                '''<resources>
  <bool name="debug_build">false</bool>
  <bool name="service_enabled">true</bool>
  <bool name="service_exported">false</bool>
</resources>''',
                encoding="utf-8",
            )
            qualified = Path(tmp, "res", "values-v28")
            qualified.mkdir(parents=True)
            Path(qualified, "security.xml").write_text(
                '''<resources>
  <bool name="debug_build">true</bool>
  <bool name="service_exported">true</bool>
</resources>''',
                encoding="utf-8",
            )

            manifest = analyzer._parse_manifest(tmp)

        debug_state = manifest["attribute_states"]["debuggable"]
        self.assertEqual(debug_state["state"], resources.CONDITIONAL)
        self.assertEqual(debug_state["possible_values"], (False, True))
        service = manifest["exported"]["service"][0]
        self.assertEqual(service["name"], ".Sync")
        self.assertEqual(service["exposure_state"], resources.CONDITIONAL)

    def test_application_and_component_enabled_references_are_resolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '''<application android:enabled="@bool/app_enabled">
  <service android:name=".Disabled" android:enabled="@bool/service_enabled"
           android:exported="true"/>
</application>''',
            )
            values = Path(tmp, "res", "values")
            values.mkdir(parents=True)
            Path(values, "enabled.xml").write_text(
                '''<resources>
  <bool name="app_enabled">true</bool>
  <bool name="service_enabled">false</bool>
</resources>''',
                encoding="utf-8",
            )

            manifest = analyzer._parse_manifest(tmp)

        self.assertEqual(manifest["exported"]["service"], [])
        self.assertEqual(
            manifest["attribute_states"]["application_enabled"]["state"],
            resources.KNOWN,
        )

    def test_cleartext_bool_reference_is_not_compared_as_a_literal_string(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '<application android:usesCleartextTraffic="@bool/http_allowed"/>',
            )
            write_bool(tmp, "values", "http_allowed", "false")
            manifest = analyzer._parse_manifest(tmp)

        self.assertIs(manifest["cleartext"], False)
        self.assertTrue(manifest["cleartext_explicit"])
        self.assertEqual(
            manifest["attribute_states"]["cleartext"]["state"],
            resources.KNOWN,
        )

    def test_highest_version_at_or_below_minimum_is_the_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_bool(tmp, "values", "flag", "false")
            write_bool(tmp, "values-v24", "flag", "true")
            result = resources.resolve_boolean(
                tmp, "@bool/flag", default=False, min_sdk="28"
            )

        self.assertEqual(result["state"], resources.KNOWN)
        self.assertIs(result["value"], True)

    def test_relevant_malformed_values_file_is_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            values = Path(tmp, "res", "values")
            values.mkdir(parents=True)
            Path(values, "bools.xml").write_text(
                '<resources><bool name="flag">false', encoding="utf-8"
            )
            result = resources.resolve_boolean(
                tmp, "@bool/flag", default=True, min_sdk="23"
            )

        self.assertEqual(result["state"], resources.UNKNOWN)
        self.assertIsNone(result["value"])

    def test_scan_does_not_pass_an_unresolved_debuggable_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '<application android:debuggable="@bool/not_present" '
                'android:allowBackup="false"/>',
            )
            rendered, collector = run_security_scan(tmp)

        self.assertIn("[WARN] Debuggable flag", rendered)
        self.assertIn("INCONCLUSIVE", rendered)
        self.assertNotIn("[PASS] Debuggable flag", rendered)
        self.assertIn(
            "manifest.debuggable.resource",
            {item["check_id"] for item in collector.inconclusive},
        )

    def test_scan_does_not_pass_a_version_conditional_debuggable_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '<application android:debuggable="@bool/debug_build" '
                'android:allowBackup="false"/>',
            )
            write_bool(tmp, "values", "debug_build", "false")
            write_bool(tmp, "values-v28", "debug_build", "true")
            rendered, collector = run_security_scan(tmp)

        self.assertIn("[WARN] Debuggable flag", rendered)
        self.assertIn("changes across supported configurations", rendered)
        self.assertNotIn("[PASS] Debuggable flag", rendered)
        self.assertIn(
            "manifest.debuggable.resource",
            {item["check_id"] for item in collector.inconclusive},
        )

    def test_modern_target_does_not_hide_old_supported_cleartext_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '<application android:allowBackup="false"/>',
                min_sdk="24",
                target_sdk="35",
            )
            rendered, _collector = run_security_scan(tmp)

        self.assertIn("HTTP allowed by Android 6-8 platform default", rendered)
        self.assertNotIn("[PASS] Cleartext traffic", rendered)


class XmlResourceResolutionTests(unittest.TestCase):
    def test_version_qualified_nsc_policies_are_all_analyzed(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '<application android:networkSecurityConfig="@xml/policy"/>',
                min_sdk="24",
            )
            write_nsc(tmp, "xml", False)
            write_nsc(tmp, "xml-v28", True)

            resolution = analyzer._resolve_resource_variants(
                tmp,
                "@xml/policy",
                expected_type="xml",
                min_sdk=24,
                local_package="com.example.app",
            )
            policy = analyzer._analyze_nsc_variants(
                tmp, resolution, target_sdk="35"
            )

        self.assertEqual(resolution["state"], resources.CONDITIONAL)
        self.assertEqual(len(resolution["paths"]), 2)
        self.assertTrue(policy["complete"])
        self.assertTrue(policy["cleartext_known"])
        self.assertTrue(policy["cleartext_allowed"])
        self.assertTrue(policy["cleartext_conditional"])

    def test_v24_only_nsc_covers_platforms_where_nsc_is_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_nsc(tmp, "xml-v24", False)
            resolution = analyzer._resolve_resource_variants(
                tmp, "@xml/policy", min_sdk=24
            )

        self.assertEqual(resolution["state"], resources.KNOWN)
        self.assertEqual(len(resolution["paths"]), 1)

    def test_missing_nsc_is_inconclusive_and_never_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '<application android:networkSecurityConfig="@xml/missing"/>',
            )
            rendered, collector = run_security_scan(tmp)

        self.assertIn("[WARN] Network security config", rendered)
        self.assertIn("INCONCLUSIVE", rendered)
        self.assertNotIn("[PASS] Network security config", rendered)
        self.assertNotIn("[PASS] Cleartext traffic", rendered)
        self.assertIn(
            "network_security_config.resource",
            {item["check_id"] for item in collector.inconclusive},
        )

    def test_scan_reports_permissive_xml_v_policy_not_default_false_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '<application android:networkSecurityConfig="@xml/policy"/>',
                min_sdk="24",
            )
            write_nsc(tmp, "xml", False)
            write_nsc(tmp, "xml-v28", True)
            rendered, _collector = run_security_scan(tmp)

        self.assertIn("Cleartext traffic", rendered)
        self.assertIn("HTTP allowed by network security config", rendered)
        self.assertNotIn("[PASS] Cleartext traffic", rendered)


if __name__ == "__main__":
    unittest.main()
