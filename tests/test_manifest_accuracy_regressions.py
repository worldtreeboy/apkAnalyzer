import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import apkAnalyzer as analyzer


ANDROID_NS = "http://schemas.android.com/apk/res/android"


def write_manifest(root, body, uses_sdk=""):
    Path(root, "AndroidManifest.xml").write_text(
        f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ANDROID_NS}" package="com.example.app">
  {uses_sdk}
  {body}
</manifest>''',
        encoding="utf-8",
    )


class ManifestAccuracyRegressionTests(unittest.TestCase):
    def test_omitted_sdk_values_use_android_platform_defaults(self):
        cases = (
            ("", "1", "1"),
            ('<uses-sdk android:minSdkVersion="23"/>', "23", "23"),
            ('<uses-sdk android:targetSdkVersion="35"/>', "1", "35"),
        )
        for uses_sdk, expected_min, expected_target in cases:
            with self.subTest(uses_sdk=uses_sdk), tempfile.TemporaryDirectory() as tmp:
                write_manifest(tmp, "<application/>", uses_sdk)
                parsed = analyzer._parse_manifest(tmp)
                self.assertEqual(parsed["min_sdk"], expected_min)
                self.assertEqual(parsed["target_sdk"], expected_target)

    def test_component_permissions_preserve_missing_and_explicit_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '''
<permission android:name="com.example.app.SIGNATURE"
            android:protectionLevel="signature"/>
<application android:permission="com.example.app.SIGNATURE">
  <activity android:name=".Target"/>
  <activity-alias android:name=".Alias" android:targetActivity=".Target"
                  android:exported="true"/>
  <service android:name=".Inherited" android:exported="true"/>
  <service android:name=".Cleared" android:exported="true"
           android:permission=""/>
  <provider android:name=".InheritedProvider"
            android:authorities="com.example.inherited"
            android:exported="true"/>
  <provider android:name=".ClearedProvider"
            android:authorities="com.example.cleared"
            android:exported="true" android:permission=""/>
  <provider android:name=".ReadClearedProvider"
            android:authorities="com.example.readcleared"
            android:exported="true" android:readPermission=""/>
</application>''',
                '<uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/>',
            )
            parsed = analyzer._parse_manifest(tmp)

        activities = {item["name"]: item for item in parsed["exported"]["activity"]}
        services = {item["name"]: item for item in parsed["exported"]["service"]}
        providers = {item["name"]: item for item in parsed["exported"]["provider"]}

        self.assertIsNone(activities[".Alias"]["permission"])
        self.assertEqual(
            services[".Inherited"]["permission"], "com.example.app.SIGNATURE"
        )
        self.assertIsNone(services[".Cleared"]["permission"])
        self.assertEqual(
            providers[".InheritedProvider"]["read_perm"],
            "com.example.app.SIGNATURE",
        )
        self.assertEqual(
            providers[".InheritedProvider"]["write_perm"],
            "com.example.app.SIGNATURE",
        )
        self.assertIsNone(providers[".ClearedProvider"]["read_perm"])
        self.assertIsNone(providers[".ClearedProvider"]["write_perm"])
        self.assertIsNone(providers[".ReadClearedProvider"]["read_perm"])
        self.assertEqual(
            providers[".ReadClearedProvider"]["write_perm"],
            "com.example.app.SIGNATURE",
        )

    def test_unknown_and_normal_permissions_are_not_strong(self):
        manifest = {
            "declared_permissions": {
                "com.example.NORMAL": "normal",
                "com.example.DANGEROUS": "dangerous",
                "com.example.SIGNATURE": "signature|privileged",
                "com.example.INTERNAL": "internal",
            }
        }

        self.assertFalse(
            analyzer._permission_is_strong(manifest, "android.permission.INTERNET")
        )
        self.assertFalse(
            analyzer._permission_is_strong(manifest, "com.example.NORMAL")
        )
        self.assertFalse(
            analyzer._permission_is_strong(manifest, "com.example.DANGEROUS")
        )
        self.assertTrue(
            analyzer._permission_is_strong(manifest, "com.example.SIGNATURE")
        )
        self.assertTrue(
            analyzer._permission_is_strong(manifest, "com.example.INTERNAL")
        )
        self.assertEqual(
            analyzer._permission_strength(
                manifest, "android.permission.BIND_ACCESSIBILITY_SERVICE"
            ),
            "strong",
        )
        self.assertEqual(
            analyzer._permission_strength(manifest, "com.dependency.UNKNOWN"),
            "unknown",
        )

    def test_generic_weak_path_permission_prevents_provider_from_passing(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '''
<permission android:name="com.example.app.SIGNATURE"
            android:protectionLevel="signature"/>
<permission android:name="com.example.app.NORMAL"
            android:protectionLevel="normal"/>
<application>
  <provider android:name=".Provider" android:authorities="com.example.provider"
            android:exported="true" android:permission="com.example.app.SIGNATURE">
    <path-permission android:pathPrefix="/public"
                     android:permission="com.example.app.NORMAL"/>
  </provider>
</application>''',
                '<uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/>',
            )
            parsed = analyzer._parse_manifest(tmp)

        provider = parsed["exported"]["provider"][0]
        path_permission = provider["path_permissions"][0]
        self.assertEqual(path_permission["permission"], "com.example.app.NORMAL")
        self.assertEqual(path_permission["read_perm"], "com.example.app.NORMAL")
        self.assertEqual(path_permission["write_perm"], "com.example.app.NORMAL")
        self.assertFalse(
            analyzer._provider_is_strongly_protected(parsed, provider)
        )

    def test_deeplinks_require_exported_view_and_browsable_same_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '''
<application>
  <activity android:name=".Valid" android:exported="true">
    <intent-filter>
      <action android:name="android.intent.action.VIEW"/>
      <category android:name="android.intent.category.BROWSABLE"/>
      <data android:scheme="https"/>
      <data android:scheme="valid" android:host="valid.example"/>
    </intent-filter>
  </activity>
  <activity android:name=".Private" android:exported="false">
    <intent-filter>
      <action android:name="android.intent.action.VIEW"/>
      <category android:name="android.intent.category.BROWSABLE"/>
      <data android:scheme="private" android:host="private.example"/>
    </intent-filter>
  </activity>
  <activity android:name=".SplitFilter" android:exported="true">
    <intent-filter>
      <action android:name="android.intent.action.VIEW"/>
      <data android:scheme="split" android:host="split.example"/>
    </intent-filter>
    <intent-filter>
      <category android:name="android.intent.category.BROWSABLE"/>
    </intent-filter>
  </activity>
  <activity android:name=".WrongAction" android:exported="true">
    <intent-filter>
      <action android:name="com.example.INTERNAL"/>
      <category android:name="android.intent.category.BROWSABLE"/>
      <data android:scheme="wrong" android:host="wrong.example"/>
    </intent-filter>
  </activity>
</application>''',
                '<uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/>',
            )
            parsed = analyzer._parse_manifest(tmp)

        self.assertEqual(parsed["deeplinks"]["schemes"], ["https", "valid"])
        self.assertEqual(parsed["deeplinks"]["hosts"], ["valid.example"])

    def test_activity_inherits_application_task_affinity(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '''
<application android:taskAffinity="shared.affinity">
  <activity android:name=".Inherited"/>
  <activity android:name=".Cleared" android:taskAffinity=""/>
  <activity android:name=".PackageDefault"
            android:taskAffinity="com.example.app"/>
</application>''',
                '<uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/>',
            )
            parsed = analyzer._parse_manifest(tmp)

        self.assertEqual(
            parsed["task_affinity"], [(".Inherited", "shared.affinity")]
        )

    def test_nsc_cleartext_policy_overrides_manifest_on_android_7_plus(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '''<application android:usesCleartextTraffic="true"
                    android:networkSecurityConfig="@xml/policy"/>''',
                '<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="35"/>',
            )
            xml_dir = Path(tmp, "res", "xml")
            xml_dir.mkdir(parents=True)
            policy = xml_dir / "policy.xml"
            policy.write_text(
                '<network-security-config><base-config '
                'cleartextTrafficPermitted="false"/></network-security-config>',
                encoding="utf-8",
            )

            parsed = analyzer._parse_manifest(tmp)
            nsc = analyzer._analyze_nsc(tmp, str(policy), target_sdk="35")
            self.assertTrue(nsc["parsed"])
            self.assertTrue(nsc["cleartext_known"])
            self.assertFalse(nsc["cleartext_allowed"])

            output = io.StringIO()
            with mock.patch.object(
                analyzer, "_pull_and_decompile", return_value=(tmp, tmp)
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
            ), mock.patch.object(analyzer, "pause"), mock.patch.object(
                analyzer, "report", analyzer.ReportCollector()
            ), redirect_stdout(output):
                analyzer.security_scan("com.example.app")

        rendered = analyzer._terminal_safe(output.getvalue())
        self.assertIn("Disabled by network security config", rendered)
        self.assertNotIn("HTTP allowed by manifest", rendered)

    def test_android_6_omitted_cleartext_ignores_nsc_deny(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '''<application
                    android:networkSecurityConfig="@xml/policy"/>''',
                '<uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/>',
            )
            xml_dir = Path(tmp, "res", "xml")
            xml_dir.mkdir(parents=True)
            (xml_dir / "policy.xml").write_text(
                '<network-security-config><base-config '
                'cleartextTrafficPermitted="false"/></network-security-config>',
                encoding="utf-8",
            )

            parsed = analyzer._parse_manifest(tmp)
            self.assertFalse(parsed["cleartext"])
            self.assertFalse(parsed["cleartext_explicit"])

            output = io.StringIO()
            with mock.patch.object(
                analyzer, "_pull_and_decompile", return_value=(tmp, tmp)
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
            ), mock.patch.object(analyzer, "pause"), mock.patch.object(
                analyzer, "report", analyzer.ReportCollector()
            ), redirect_stdout(output):
                analyzer.security_scan("com.example.app")

        rendered = analyzer._terminal_safe(output.getvalue())
        self.assertIn("HTTP allowed by Android 6 platform default", rendered)
        self.assertNotIn("Disabled by network security config", rendered)

    def test_nsc_omitted_cleartext_uses_target_dependent_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = Path(tmp, "policy.xml")
            policy.write_text(
                "<network-security-config/>", encoding="utf-8"
            )

            legacy = analyzer._analyze_nsc(tmp, str(policy), target_sdk="27")
            modern = analyzer._analyze_nsc(tmp, str(policy), target_sdk="28")

        self.assertTrue(legacy["cleartext_allowed"])
        self.assertTrue(legacy["cleartext_known"])
        self.assertFalse(modern["cleartext_allowed"])
        self.assertTrue(modern["cleartext_known"])


if __name__ == "__main__":
    unittest.main()
