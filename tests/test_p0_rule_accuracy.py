import tempfile
import unittest
from pathlib import Path
from unittest import mock

import apkAnalyzer as analyzer
from apk_analyzer import process, static_rules


ANDROID_NS = "http://schemas.android.com/apk/res/android"
PENDING_SIGNATURE = (
    "Landroid/app/PendingIntent;->getActivity("
    "Landroid/content/Context;ILandroid/content/Intent;I)"
    "Landroid/app/PendingIntent;"
)


class PendingIntentRuleTests(unittest.TestCase):
    def test_each_invocation_uses_its_own_traced_flags(self):
        smali = f"""
.method public test()V
    new-instance v2, Landroid/content/Intent;
    invoke-direct {{v2}}, Landroid/content/Intent;-><init>()V
    const v9, 0x4000000
    const v3, 0x4000000
    invoke-static {{v0, v1, v2, v3}}, {PENDING_SIGNATURE}
    const/4 v3, 0x0
    invoke-static {{v0, v1, v2, v3}}, {PENDING_SIGNATURE}
.end method
"""

        results = static_rules.analyze_pending_intents(smali)

        self.assertEqual(
            [result["status"] for result in results],
            ["immutable", "missing_mutability"],
        )

    def test_dynamic_flags_are_inconclusive_not_assumed_safe(self):
        smali = f"""
.method public create(I)V
    new-instance v2, Landroid/content/Intent;
    invoke-direct {{v2}}, Landroid/content/Intent;-><init>()V
    invoke-static {{v0, v1, v2, p1}}, {PENDING_SIGNATURE}
.end method
"""

        result = static_rules.analyze_pending_intents(smali)[0]

        self.assertEqual(result["status"], "unknown_flags")
        self.assertIsNone(result["flags"])

    def test_mutable_implicit_and_explicit_intents_are_distinguished(self):
        implicit = f"""
.method public implicit()V
    new-instance v2, Landroid/content/Intent;
    invoke-direct {{v2}}, Landroid/content/Intent;-><init>()V
    const v3, 0x2000000
    invoke-static {{v0, v1, v2, v3}}, {PENDING_SIGNATURE}
.end method
"""
        explicit = f"""
.method public explicit()V
    new-instance v2, Landroid/content/Intent;
    const-class v6, Lcom/example/Target;
    invoke-direct {{v2, v0, v6}}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
    const/high16 v3, 0x2000000
    invoke-static {{v0, v1, v2, v3}}, {PENDING_SIGNATURE}
.end method
"""

        self.assertEqual(
            static_rules.analyze_pending_intents(implicit)[0]["status"],
            "mutable_implicit",
        )
        self.assertEqual(
            static_rules.analyze_pending_intents(explicit)[0]["status"],
            "mutable_explicit",
        )

    def test_baksmali_const_high16_uses_the_rendered_full_value(self):
        smali = f"""
.method public create()V
    new-instance v2, Landroid/content/Intent;
    invoke-direct {{v2}}, Landroid/content/Intent;-><init>()V
    const/high16 v3, 0x4000000
    invoke-static {{v0, v1, v2, v3}}, {PENDING_SIGNATURE}
.end method
"""
        self.assertEqual(
            static_rules.analyze_pending_intents(smali)[0]["status"],
            "immutable",
        )

    def test_branch_skipped_constant_is_not_assumed_to_reach_call(self):
        smali = f"""
.method public create(Z)V
    new-instance v2, Landroid/content/Intent;
    invoke-direct {{v2}}, Landroid/content/Intent;-><init>()V
    if-eqz p1, :call
    const v3, 0x4000000
  :call
    invoke-static {{v0, v1, v2, v3}}, {PENDING_SIGNATURE}
.end method
"""
        self.assertEqual(
            static_rules.analyze_pending_intents(smali)[0]["status"],
            "unknown_flags",
        )

    def test_legacy_entrypoint_uses_modular_pending_analyzer(self):
        self.assertIs(analyzer._analyze_pending_intents,
                      static_rules.analyze_pending_intents)


class ClipboardRuleTests(unittest.TestCase):
    def test_read_only_clipboard_access_is_not_an_exposure(self):
        smali = """
.method public read()V
    invoke-virtual {v0}, Landroid/content/ClipboardManager;->getPrimaryClip()Landroid/content/ClipData;
    move-result-object v1
.end method
"""
        self.assertEqual(static_rules.analyze_clipboard_writes(smali), [])

    def test_wrong_flag_name_does_not_protect_a_clipboard_write(self):
        smali = """
.method public write()V
    const-string v7, "FLAG_SENSITIVE"
    invoke-virtual {v0, v1}, Landroid/content/ClipboardManager;->setPrimaryClip(Landroid/content/ClipData;)V
.end method
"""
        self.assertFalse(
            static_rules.analyze_clipboard_writes(smali)[0]["sensitive"]
        )

    def test_documented_sensitive_extra_protects_the_written_clip(self):
        smali = """
.method public write()V
    invoke-virtual {v1}, Landroid/content/ClipData;->getDescription()Landroid/content/ClipDescription;
    move-result-object v2
    new-instance v3, Landroid/os/PersistableBundle;
    invoke-direct {v3}, Landroid/os/PersistableBundle;-><init>()V
    sget-object v4, Landroid/content/ClipDescription;->EXTRA_IS_SENSITIVE:Ljava/lang/String;
    const/4 v5, 0x1
    invoke-virtual {v3, v4, v5}, Landroid/os/PersistableBundle;->putBoolean(Ljava/lang/String;Z)V
    invoke-virtual {v2, v3}, Landroid/content/ClipDescription;->setExtras(Landroid/os/PersistableBundle;)V
    invoke-virtual {v0, v1}, Landroid/content/ClipboardManager;->setPrimaryClip(Landroid/content/ClipData;)V
.end method
"""
        self.assertTrue(
            static_rules.analyze_clipboard_writes(smali)[0]["sensitive"]
        )

    def test_sensitive_extra_set_to_false_is_not_protection(self):
        smali = """
.method public write()V
    invoke-virtual {v1}, Landroid/content/ClipData;->getDescription()Landroid/content/ClipDescription;
    move-result-object v2
    new-instance v3, Landroid/os/PersistableBundle;
    invoke-direct {v3}, Landroid/os/PersistableBundle;-><init>()V
    const-string v4, "android.content.extra.IS_SENSITIVE"
    const/4 v5, 0x0
    invoke-virtual {v3, v4, v5}, Landroid/os/PersistableBundle;->putBoolean(Ljava/lang/String;Z)V
    invoke-virtual {v2, v3}, Landroid/content/ClipDescription;->setExtras(Landroid/os/PersistableBundle;)V
    invoke-virtual {v0, v1}, Landroid/content/ClipboardManager;->setPrimaryClip(Landroid/content/ClipData;)V
.end method
"""
        self.assertFalse(
            static_rules.analyze_clipboard_writes(smali)[0]["sensitive"]
        )

    def test_nearest_false_sensitive_value_overrides_an_earlier_true(self):
        smali = """
.method public write()V
    invoke-virtual {v1}, Landroid/content/ClipData;->getDescription()Landroid/content/ClipDescription;
    move-result-object v2
    new-instance v3, Landroid/os/PersistableBundle;
    invoke-direct {v3}, Landroid/os/PersistableBundle;-><init>()V
    const-string v4, "android.content.extra.IS_SENSITIVE"
    const/4 v5, 0x1
    invoke-virtual {v3, v4, v5}, Landroid/os/PersistableBundle;->putBoolean(Ljava/lang/String;Z)V
    const/4 v5, 0x0
    invoke-virtual {v3, v4, v5}, Landroid/os/PersistableBundle;->putBoolean(Ljava/lang/String;Z)V
    invoke-virtual {v2, v3}, Landroid/content/ClipDescription;->setExtras(Landroid/os/PersistableBundle;)V
    invoke-virtual {v0, v1}, Landroid/content/ClipboardManager;->setPrimaryClip(Landroid/content/ClipData;)V
.end method
"""
        self.assertFalse(
            static_rules.analyze_clipboard_writes(smali)[0]["sensitive"]
        )

    def test_reused_clip_register_does_not_inherit_stale_protection(self):
        smali = """
.method public write()V
    invoke-virtual {v1}, Landroid/content/ClipData;->getDescription()Landroid/content/ClipDescription;
    move-result-object v2
    new-instance v3, Landroid/os/PersistableBundle;
    invoke-direct {v3}, Landroid/os/PersistableBundle;-><init>()V
    const-string v4, "android.content.extra.IS_SENSITIVE"
    const/4 v5, 0x1
    invoke-virtual {v3, v4, v5}, Landroid/os/PersistableBundle;->putBoolean(Ljava/lang/String;Z)V
    invoke-virtual {v2, v3}, Landroid/content/ClipDescription;->setExtras(Landroid/os/PersistableBundle;)V
    invoke-static {v6, v7}, Landroid/content/ClipData;->newPlainText(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Landroid/content/ClipData;
    move-result-object v1
    invoke-virtual {v0, v1}, Landroid/content/ClipboardManager;->setPrimaryClip(Landroid/content/ClipData;)V
.end method
"""
        self.assertFalse(
            static_rules.analyze_clipboard_writes(smali)[0]["sensitive"]
        )


class DeepLinkRuleTests(unittest.TestCase):
    def test_manifest_preserves_verification_and_uri_constraints(self):
        manifest = f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ANDROID_NS}" package="com.example.links">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/>
  <application>
    <activity android:name=".Links" android:exported="true">
      <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <data android:scheme="https"/>
        <data android:host="links.example" android:pathPrefix="/account"/>
      </intent-filter>
    </activity>
  </application>
</manifest>'''
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "AndroidManifest.xml").write_text(manifest, encoding="utf-8")
            parsed = analyzer._parse_manifest(tmp)

        link = parsed["deeplinks"]["filters"][0]
        self.assertTrue(link["auto_verify"])
        self.assertEqual(link["schemes"], ["https"])
        self.assertEqual(link["hosts"], ["links.example"])
        self.assertEqual(
            link["paths"], [{"kind": "pathPrefix", "value": "/account"}]
        )
        self.assertEqual(static_rules.classify_deep_link(link)["level"], "info")

    def test_custom_unverified_and_broad_web_links_remain_findings(self):
        cases = (
            {
                "schemes": ["example"], "hosts": [], "paths": [],
                "auto_verify": False,
            },
            {
                "schemes": ["https"], "hosts": ["links.example"],
                "paths": [{"kind": "pathPrefix", "value": "/account"}],
                "auto_verify": False,
            },
            {
                "schemes": ["https"], "hosts": ["links.example"],
                "paths": [], "auto_verify": True,
            },
        )
        for link in cases:
            with self.subTest(link=link):
                result = static_rules.classify_deep_link(link)
                self.assertTrue(result["risk"])
                self.assertEqual(result["level"], "finding")

    def test_app_links_supported_below_api_23_remain_a_finding(self):
        link = {
            "schemes": ["https"], "hosts": ["links.example"],
            "paths": [{"kind": "pathPrefix", "value": "/account"}],
            "auto_verify": True, "min_sdk": "21",
        }
        result = static_rules.classify_deep_link(link)
        self.assertTrue(result["risk"])
        self.assertTrue(any("API 23" in reason for reason in result["reasons"]))

    def test_host_only_filter_is_not_promoted_to_a_deep_link(self):
        manifest = f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ANDROID_NS}" package="com.example.links">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/>
  <application>
    <activity android:name=".Links" android:exported="true">
      <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <data android:host="links.example" android:pathPrefix="/account"/>
      </intent-filter>
    </activity>
  </application>
</manifest>'''
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "AndroidManifest.xml").write_text(manifest, encoding="utf-8")
            parsed = analyzer._parse_manifest(tmp)

        self.assertEqual(parsed["deeplinks"]["filters"], [])
        self.assertEqual(parsed["deeplinks"]["hosts"], [])

    def test_filter_without_default_category_is_not_reachable_deep_link(self):
        manifest = f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ANDROID_NS}" package="com.example.links">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/>
  <application>
    <activity android:name=".Links" android:exported="true">
      <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https" android:host="links.example"
              android:pathPrefix="/account"/>
      </intent-filter>
    </activity>
  </application>
</manifest>'''
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "AndroidManifest.xml").write_text(manifest, encoding="utf-8")
            parsed = analyzer._parse_manifest(tmp)

        self.assertEqual(parsed["deeplinks"]["filters"], [])


class LogcatAttributionTests(unittest.TestCase):
    def test_ps_parser_matches_main_and_colon_processes_only(self):
        output = """USER PID PPID VSZ RSS WCHAN ADDR S NAME
u0_a1 101 1 0 0 0 0 S com.example.app
u0_a1 202 1 0 0 0 0 S com.example.app:remote
u0_a2 303 1 0 0 0 0 S com.example.app.evil
u0_a2 404 1 0 0 0 0 S other.com.example.app
"""
        parsed = process.parse_android_ps(output, "com.example.app")
        self.assertTrue(parsed["recognized"])
        self.assertEqual(parsed["pids"], ["101", "202"])

    def test_logcat_captures_secondary_package_processes(self):
        commands = []

        def shell(command, timeout=30):
            commands.append(command)
            if command.startswith("pidof "):
                return "101"
            if command.startswith("ps -A -o PID,NAME"):
                return "PID NAME\n101 com.example.app\n202 com.example.app:remote"
            if command.startswith("logcat -d"):
                return ""
            self.fail(f"unexpected command: {command}")

        with mock.patch.object(analyzer, "adb_shell", side_effect=shell):
            findings = analyzer._check_logcat_leakage(
                "com.example.app", launch=False
            )

        self.assertEqual(findings, [])
        self.assertIn("logcat -d -t 2000 --pid=101", commands)
        self.assertIn("logcat -d -t 2000 --pid=202", commands)

    def test_pidof_without_a_parseable_process_table_is_inconclusive(self):
        def shell(command, timeout=30):
            if command.startswith("pidof "):
                return "101"
            if command.startswith("ps"):
                return "[ERROR 1] unsupported"
            if command.startswith("logcat -d"):
                return ""
            self.fail(f"unexpected command: {command}")

        with mock.patch.object(analyzer, "adb_shell", side_effect=shell):
            with self.assertRaises(analyzer.RuntimeCheckUnavailable):
                analyzer._check_logcat_leakage(
                    "com.example.app", launch=False
                )


if __name__ == "__main__":
    unittest.main()
