import io
import tempfile
import textwrap
import unittest
import xml.etree.ElementTree as ET
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import apkAnalyzer as analyzer
from apk_analyzer.manifest import DANGEROUS_PERMS
from apk_analyzer.static_rules import (
    PERMISSION_API_RULES,
    analyze_broadcast_sends,
    analyze_webview_settings,
    classify_backup_xml,
    combine_backup_policy,
    correlate_permission_apis,
    match_permission_apis,
)
from apk_analyzer.version import CURRENT_PLAY_TARGET_SDK


ANDROID_NS = "http://schemas.android.com/apk/res/android"


def write_manifest(root, body, target_sdk=None):
    if target_sdk is None:
        target_sdk = CURRENT_PLAY_TARGET_SDK
    Path(root, "AndroidManifest.xml").write_text(
        f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ANDROID_NS}" package="com.example.sharp">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="{target_sdk}"/>
  {body}
</manifest>''',
        encoding="utf-8",
    )


def run_scan(root, collector):
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
        analyzer.security_scan("com.example.sharp")
    return analyzer._terminal_safe(output.getvalue())


class BroadcastAndLogCallTests(unittest.TestCase):
    def test_permission_protected_call_does_not_cover_another_call(self):
        smali = textwrap.dedent("""\
            .method public send()V
                invoke-virtual {p0, v0}, Lcom/example/Main;->sendBroadcast(Landroid/content/Intent;)V
                invoke-virtual {p0, v0, v1}, Lcom/example/Main;->sendBroadcast(Landroid/content/Intent;Ljava/lang/String;)V
                invoke-virtual {v2, v0}, Landroidx/localbroadcastmanager/content/LocalBroadcastManager;->sendBroadcast(Landroid/content/Intent;)V
            .end method
            """)
        sends = analyze_broadcast_sends(smali)
        self.assertEqual(
            [item["protected"] for item in sends],
            [False, True],
        )

    def test_two_log_calls_are_counted_separately(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '<application android:debuggable="false" '
                'android:allowBackup="false" '
                'android:usesCleartextTraffic="false"/>',
            )
            Path(tmp, "Log.smali").write_text(
                "invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I\n"
                "invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I\n",
                encoding="utf-8",
            )
            collector = analyzer.ReportCollector()
            rendered = run_scan(tmp, collector)

        self.assertIn("Debug/verbose log calls found (2 call(s))", rendered)
        finding = next(
            item for item in collector.findings
            if item["rule_id"] == "debug_logging"
        )
        self.assertIn("2 call(s)", finding["description"])


class WebViewSettingTests(unittest.TestCase):
    def test_proven_debug_flag_is_a_finding_and_false_is_not(self):
        enabled = textwrap.dedent("""\
            .method public on()V
                const/4 v0, 0x1
                invoke-static {v0}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V
            .end method
            """)
        disabled = textwrap.dedent("""\
            .method public off()V
                const/4 v0, 0x0
                invoke-static {v0}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V
            .end method
            """)
        enabled_calls = analyze_webview_settings(enabled)
        disabled_calls = analyze_webview_settings(disabled)
        self.assertEqual(enabled_calls[0]["state"], "enabled")
        self.assertEqual(enabled_calls[0]["setting"], "debugging")
        self.assertEqual(disabled_calls[0]["state"], "disabled")

    def test_scan_reports_universal_file_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '<application android:debuggable="false" '
                'android:allowBackup="false" '
                'android:usesCleartextTraffic="false"/>',
            )
            Path(tmp, "Web.smali").write_text(textwrap.dedent("""\
                .method public configure()V
                    const/4 v1, 0x1
                    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V
                .end method
                """), encoding="utf-8")
            collector = analyzer.ReportCollector()
            rendered = run_scan(tmp, collector)

        self.assertIn("Insecure WebView setting(s): 1", rendered)
        finding = next(
            item for item in collector.findings
            if item["rule_id"] == "webview_insecure_settings"
        )
        self.assertEqual(finding["severity"], "HIGH")
        self.assertIn("universal file access", finding["description"])


class BackupRuleTests(unittest.TestCase):
    def test_database_exclusion_is_not_an_open_backup(self):
        root = ET.fromstring("""\
<data-extraction-rules>
  <cloud-backup>
    <exclude domain="sharedpref" path="."/>
    <exclude domain="database" path="."/>
    <exclude domain="file" path="."/>
    <exclude domain="root" path="."/>
  </cloud-backup>
</data-extraction-rules>
""")
        self.assertEqual(
            classify_backup_xml(root)["extraction"],
            "private_excluded",
        )
        self.assertEqual(
            combine_backup_policy(23, 36, "open", "private_excluded"),
            "open",
        )
        self.assertEqual(
            combine_backup_policy(31, 36, None, "private_excluded"),
            "private_excluded",
        )

    def test_rules_that_exclude_private_data_lower_the_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '<application android:debuggable="false" '
                'android:allowBackup="true" '
                'android:fullBackupContent="@xml/backup_rules" '
                'android:dataExtractionRules="@xml/data_extraction_rules" '
                'android:usesCleartextTraffic="false"/>',
            )
            rules = Path(tmp, "res", "xml")
            rules.mkdir(parents=True)
            rules.joinpath("backup_rules.xml").write_text(
                "<full-backup-content>"
                '<exclude domain="sharedpref" path="."/>'
                '<exclude domain="database" path="."/>'
                '<exclude domain="file" path="."/>'
                '<exclude domain="root" path="."/>'
                "</full-backup-content>",
                encoding="utf-8",
            )
            rules.joinpath("data_extraction_rules.xml").write_text(
                "<data-extraction-rules><cloud-backup>"
                '<exclude domain="sharedpref" path="."/>'
                '<exclude domain="database" path="."/>'
                '<exclude domain="file" path="."/>'
                '<exclude domain="root" path="."/>'
                "</cloud-backup></data-extraction-rules>",
                encoding="utf-8",
            )
            collector = analyzer.ReportCollector()
            rendered = run_scan(tmp, collector)

        finding = next(
            item for item in collector.findings
            if item["rule_id"] == "allow_backup"
        )
        self.assertEqual(finding["severity"], "LOW")
        self.assertNotIn("[HIGH] allowBackup", rendered)


class SecretConfidenceTests(unittest.TestCase):
    def test_generic_assignment_is_medium_and_live_key_is_critical(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '<application android:debuggable="false" '
                'android:allowBackup="false" '
                'android:usesCleartextTraffic="false"/>',
            )
            Path(tmp, "Config.txt").write_text(
                "api_key=not-a-live-token\n", encoding="utf-8"
            )
            collector = analyzer.ReportCollector()
            run_scan(tmp, collector)
        generic = next(
            item for item in collector.findings
            if item["rule_id"] == "hardcoded_secrets"
        )
        self.assertEqual(generic["severity"], "MEDIUM")
        self.assertEqual(generic["confidence"], "MEDIUM")

        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '<application android:debuggable="false" '
                'android:allowBackup="false" '
                'android:usesCleartextTraffic="false"/>',
            )
            Path(tmp, "Billing.txt").write_text(
                "sk_live_" + ("a" * 24) + "\n", encoding="utf-8"
            )
            Path(tmp, "smali", "com", "google", "sample").mkdir(parents=True)
            Path(
                tmp, "smali", "com", "google", "sample", "Sdk.txt"
            ).write_text("password=library-sample\n", encoding="utf-8")
            collector = analyzer.ReportCollector()
            run_scan(tmp, collector)
        live = next(
            item for item in collector.findings
            if item["rule_id"] == "hardcoded_secrets"
        )
        self.assertEqual(live["severity"], "CRITICAL")
        self.assertEqual(live["confidence"], "HIGH")
        self.assertIn("app code", live["description"])


class TargetSdkConstantTests(unittest.TestCase):
    def test_play_update_bar_is_the_single_constant(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '<application android:debuggable="false" '
                'android:allowBackup="false" '
                'android:usesCleartextTraffic="false"/>',
            )
            # Rewrite the manifest the helper wrote so this case is one below the bar.
            manifest = Path(tmp, "AndroidManifest.xml")
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    f'targetSdkVersion="{CURRENT_PLAY_TARGET_SDK}"',
                    f'targetSdkVersion="{CURRENT_PLAY_TARGET_SDK - 1}"',
                ),
                encoding="utf-8",
            )
            collector = analyzer.ReportCollector()
            rendered = run_scan(tmp, collector)

        self.assertIn(
            f"require {CURRENT_PLAY_TARGET_SDK}+",
            rendered,
        )
        self.assertTrue(any(
            item["rule_id"] == "sdk_version" for item in collector.findings
        ))


SAFE_APP = (
    '<application android:debuggable="false" '
    'android:allowBackup="false" '
    'android:usesCleartextTraffic="false"/>'
)
CAMERA_SMALI = (
    "invoke-virtual {v0, v1, v2, v3}, "
    "Landroid/hardware/camera2/CameraManager;->openCamera("
    "Ljava/lang/String;Landroid/hardware/camera2/CameraDevice$StateCallback;"
    "Landroid/os/Handler;)V\n"
)
NOTIFY_SMALI = (
    "invoke-virtual {v0, v1, v2}, "
    "Landroid/app/NotificationManager;->notify("
    "ILandroid/app/Notification;)V\n"
)
LOCATION_SMALI = (
    "invoke-virtual {v0, v1}, "
    "Landroid/location/LocationManager;->getLastKnownLocation("
    "Ljava/lang/String;)Landroid/location/Location;\n"
)
SEND_SMS_SMALI = (
    "invoke-virtual {v0, v1, v2, v3, v4, v5}, "
    "Landroid/telephony/SmsManager;->sendTextMessage("
    "Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;"
    "Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V\n"
)


def write_smali(root, name, text):
    Path(root, name).write_text(text, encoding="utf-8")


def write_split(root, number, body):
    split = Path(root, ".apkanalyzer_splits", f"split_{number:04d}")
    split.mkdir(parents=True)
    Path(split, "AndroidManifest.xml").write_text(
        f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ANDROID_NS}" package="com.example.sharp">
  {body}
</manifest>''',
        encoding="utf-8",
    )
    return split


def rule_ids(result, key):
    return [item["id"] for item in result[key]]


class PermissionApiRuleTests(unittest.TestCase):
    def test_every_dangerous_permission_has_a_mapped_api(self):
        mapped = set()
        ids = []
        for rule in PERMISSION_API_RULES:
            ids.append(rule["id"])
            mapped.update(rule["permissions"])
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(mapped, set(DANGEROUS_PERMS))
        gated = {
            rule["id"]: rule["min_target"]
            for rule in PERMISSION_API_RULES if "min_target" in rule
        }
        self.assertEqual(
            gated,
            {"nearby_wifi": 33, "post_notifications": 33},
        )

    def test_sms_apis_do_not_cover_each_other(self):
        send = SEND_SMS_SMALI
        read = "sget-object v0, Landroid/provider/Telephony$Sms;->CONTENT_URI:Landroid/net/Uri;"
        receive = 'const-string v0, "android.provider.Telephony.SMS_RECEIVED"'
        intents = (
            "sget-object v0, Landroid/provider/Telephony$Sms$Intents;"
            "->SMS_RECEIVED_ACTION:Ljava/lang/String;"
        )
        self.assertEqual(match_permission_apis(send), ["sms_send"])
        self.assertEqual(match_permission_apis(read), ["sms_read"])
        self.assertEqual(match_permission_apis(receive), ["sms_receive"])
        self.assertEqual(match_permission_apis(intents), ["sms_receive"])
        self.assertEqual(
            match_permission_apis(
                "Landroid/telephony/SmsManager;->sendMultipartTextMessage("
            ),
            ["sms_send"],
        )
        self.assertEqual(
            match_permission_apis(
                "Landroid/telephony/SmsMessage;->createFromPdu([B)Landroid/telephony/SmsMessage;"
            ),
            ["sms_receive"],
        )

    def test_similar_platform_types_are_not_permission_use(self):
        self.assertEqual(
            match_permission_apis(
                "sget v0, Landroid/hardware/CameraProfile;->QUALITY_HIGH:I"
            ),
            [],
        )
        self.assertEqual(
            match_permission_apis(
                "invoke-static {v0}, Landroid/hardware/Camera;->open(I)Landroid/hardware/Camera;"
            ),
            ["camera"],
        )
        self.assertEqual(
            match_permission_apis(
                "check-cast v0, Landroid/media/AudioRecordingConfiguration;"
            ),
            [],
        )
        self.assertEqual(
            match_permission_apis(
                "new-instance v0, Landroid/media/AudioRecord;"
            ),
            ["record_audio"],
        )
        sensor_manager = (
            "invoke-virtual {v0, v1}, Landroid/hardware/SensorManager;"
            "->getDefaultSensor(I)Landroid/hardware/Sensor;"
        )
        heart = "sget v0, Landroid/hardware/Sensor;->TYPE_HEART_RATE:I"
        self.assertEqual(match_permission_apis(sensor_manager), [])
        self.assertEqual(match_permission_apis(heart), ["body_sensors"])
        self.assertEqual(
            match_permission_apis(
                'const-string v0, "android.intent.action.CALL_BUTTON"'
            ),
            [],
        )
        self.assertEqual(
            match_permission_apis(
                'const-string v0, "android.intent.action.CALL"'
            ),
            ["call_phone"],
        )

    def test_shared_groups_and_storage_rules_stay_separate(self):
        images = (
            "sget-object v0, Landroid/provider/MediaStore$Images$Media;"
            "->EXTERNAL_CONTENT_URI:Landroid/net/Uri;"
        )
        self.assertEqual(match_permission_apis(images), ["media_images"])
        covered = correlate_permission_apis(
            {"android.permission.READ_EXTERNAL_STORAGE"},
            match_permission_apis(images),
            True, True, 36,
        )
        self.assertEqual(covered["unused_permissions"], [])
        self.assertEqual(covered["missing_rules"], [])

        video_gap = correlate_permission_apis(
            {"android.permission.READ_MEDIA_IMAGES"},
            match_permission_apis(
                "sget-object v0, Landroid/provider/MediaStore$Video$Media;"
                "->EXTERNAL_CONTENT_URI:Landroid/net/Uri;"
            ),
            True, True, 36,
        )
        self.assertEqual(
            video_gap["unused_permissions"],
            ["android.permission.READ_MEDIA_IMAGES"],
        )
        self.assertEqual(rule_ids(video_gap, "missing_rules"), ["media_video"])

        directory = (
            "invoke-static {v0}, Landroid/os/Environment;"
            "->getExternalStorageDirectory()Ljava/io/File;"
        )
        managed = correlate_permission_apis(
            {"android.permission.MANAGE_EXTERNAL_STORAGE"},
            match_permission_apis(directory),
            True, True, 36,
        )
        self.assertEqual(managed["unused_permissions"], [])
        self.assertEqual(managed["missing_rules"], [])

        all_files = (
            "invoke-static {}, Landroid/os/Environment;"
            "->isExternalStorageManager()Z"
        )
        read_only = correlate_permission_apis(
            {"android.permission.READ_EXTERNAL_STORAGE"},
            match_permission_apis(all_files),
            True, True, 36,
        )
        self.assertEqual(
            read_only["unused_permissions"],
            ["android.permission.READ_EXTERNAL_STORAGE"],
        )
        self.assertEqual(
            rule_ids(read_only, "missing_rules"),
            ["manage_storage"],
        )

    def test_background_location_shares_the_location_api(self):
        matched = match_permission_apis(LOCATION_SMALI)
        background_only = correlate_permission_apis(
            {"android.permission.ACCESS_BACKGROUND_LOCATION"},
            matched, True, True, 36,
        )
        self.assertEqual(background_only["unused_permissions"], [])
        self.assertEqual(background_only["missing_rules"], [])

        missing = correlate_permission_apis(set(), matched, True, True, 36)
        self.assertEqual(rule_ids(missing, "missing_rules"), ["location"])
        self.assertIn(
            "android.permission.ACCESS_FINE_LOCATION",
            missing["missing_rules"][0]["permissions"],
        )
        self.assertIn(
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            missing["missing_rules"][0]["permissions"],
        )

        declared = correlate_permission_apis(
            {"android.permission.ACCESS_BACKGROUND_LOCATION"},
            (), True, True, 36,
        )
        self.assertEqual(
            declared["unused_permissions"],
            ["android.permission.ACCESS_BACKGROUND_LOCATION"],
        )

    def test_unmapped_permissions_are_not_called_unused(self):
        result = correlate_permission_apis(
            {"android.permission.INTERNET", "com.example.CUSTOM"},
            (), True, True, 36,
        )
        self.assertEqual(result["unused_permissions"], [])
        self.assertEqual(result["missing_rules"], [])

    def test_api_33_permissions_follow_target_sdk(self):
        cases = (
            (NOTIFY_SMALI, "android.permission.POST_NOTIFICATIONS",
             "post_notifications"),
            ("Landroid/net/wifi/aware/WifiAwareManager;",
             "android.permission.NEARBY_WIFI_DEVICES", "nearby_wifi"),
        )
        for text, permission, rule_id in cases:
            matched = match_permission_apis(text)
            low = correlate_permission_apis(set(), matched, True, True, 32)
            self.assertEqual(low["missing_rules"], [], rule_id)
            required = correlate_permission_apis(
                set(), matched, True, True, 33
            )
            self.assertEqual(rule_ids(required, "missing_rules"), [rule_id])
            unknown = correlate_permission_apis(
                set(), matched, True, True, None
            )
            self.assertEqual(rule_ids(unknown, "missing_rules"), [rule_id])
            unused = correlate_permission_apis(
                {permission}, (), True, True, 32
            )
            self.assertEqual(unused["unused_permissions"], [permission])

    def test_coverage_flags_suppress_only_the_absence_they_own(self):
        incomplete_code = correlate_permission_apis(
            {"android.permission.CAMERA"},
            ["sms_send"],
            False, True, 36,
        )
        self.assertEqual(incomplete_code["unused_permissions"], [])
        self.assertTrue(incomplete_code["unused_inconclusive"])
        self.assertEqual(
            incomplete_code["unmatched_permissions"],
            ["android.permission.CAMERA"],
        )
        self.assertEqual(
            rule_ids(incomplete_code, "missing_rules"),
            ["sms_send"],
        )
        self.assertFalse(incomplete_code["missing_inconclusive"])

        incomplete_split = correlate_permission_apis(
            {"android.permission.CAMERA"},
            ["sms_send"],
            True, False, 36,
        )
        self.assertEqual(
            incomplete_split["unused_permissions"],
            ["android.permission.CAMERA"],
        )
        self.assertEqual(incomplete_split["missing_rules"], [])
        self.assertTrue(incomplete_split["missing_inconclusive"])
        self.assertEqual(
            rule_ids(incomplete_split, "uncovered_rules"),
            ["sms_send"],
        )


class PermissionApiScanTests(unittest.TestCase):
    def test_camera_api_without_permission_is_a_high_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(tmp, SAFE_APP)
            write_smali(tmp, "Camera.smali", CAMERA_SMALI)
            collector = analyzer.ReportCollector()
            rendered = run_scan(tmp, collector)

        finding = next(
            item for item in collector.findings
            if item["rule_id"] == "api_without_permission"
        )
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["confidence"], "HIGH")
        self.assertIn("Mapped platform API", finding["description"])
        self.assertIn("CAMERA", finding["description"])
        self.assertIn("merged manifest", finding["description"])
        self.assertIn("Camera.smali", finding["description"])
        self.assertIn("[HIGH] Mapped API with no declared permission", rendered)
        self.assertFalse(any(
            item["rule_id"] == "permission_without_api"
            for item in collector.findings
        ))

    def test_camera_permission_without_api_is_medium(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '<uses-permission android:name="android.permission.CAMERA"/>'
                + SAFE_APP,
            )
            collector = analyzer.ReportCollector()
            rendered = run_scan(tmp, collector)

        finding = next(
            item for item in collector.findings
            if item["rule_id"] == "permission_without_api"
        )
        self.assertEqual(finding["severity"], "MEDIUM")
        self.assertEqual(finding["confidence"], "MEDIUM")
        self.assertIn("no mapped platform API", finding["description"])
        self.assertIn("CAMERA", finding["description"])
        self.assertIn(
            "[MEDIUM] Dangerous permission with no mapped API",
            rendered,
        )
        self.assertFalse(any(
            item["rule_id"] == "api_without_permission"
            for item in collector.findings
        ))

    def test_declared_permission_and_api_are_not_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '<uses-permission android:name="android.permission.CAMERA"/>'
                + SAFE_APP,
            )
            write_smali(tmp, "Camera.smali", CAMERA_SMALI)
            collector = analyzer.ReportCollector()
            rendered = run_scan(tmp, collector)

        ids = {item["rule_id"] for item in collector.findings}
        self.assertNotIn("permission_without_api", ids)
        self.assertNotIn("api_without_permission", ids)
        self.assertIn("[PASS] Dangerous permission with no mapped API", rendered)
        self.assertIn("[PASS] Mapped API with no declared permission", rendered)

    def test_permission_declared_only_in_a_parsed_split_covers_the_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(tmp, SAFE_APP)
            write_split(
                tmp, 1,
                '<uses-permission android:name="android.permission.CAMERA"/>',
            )
            write_smali(tmp, "Camera.smali", CAMERA_SMALI)
            collector = analyzer.ReportCollector()
            rendered = run_scan(tmp, collector)

        ids = {item["rule_id"] for item in collector.findings}
        self.assertNotIn("api_without_permission", ids)
        self.assertNotIn("permission_without_api", ids)
        self.assertIn("CAMERA", rendered)
        self.assertIn("[PASS] Mapped API with no declared permission", rendered)

    def test_unmerged_split_does_not_become_a_missing_permission(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(tmp, SAFE_APP)
            split = Path(tmp, ".apkanalyzer_splits", "split_0001")
            split.mkdir(parents=True)
            Path(split, "AndroidManifest.xml").write_text(
                "<manifest><application>", encoding="utf-8"
            )
            write_smali(tmp, "Camera.smali", CAMERA_SMALI)
            collector = analyzer.ReportCollector()
            rendered = run_scan(tmp, collector)

        self.assertFalse(any(
            item["rule_id"] == "api_without_permission"
            for item in collector.findings
        ))
        self.assertTrue(any(
            item["check_id"] == "api_without_permission"
            for item in collector.inconclusive
        ))
        self.assertIn("was not merged", rendered)
        self.assertNotIn(
            "[HIGH] Mapped API with no declared permission",
            rendered,
        )

    def test_permission_seen_in_a_partial_merge_can_still_be_unused(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(tmp, SAFE_APP)
            broken = Path(tmp, ".apkanalyzer_splits", "split_0001")
            broken.mkdir(parents=True)
            Path(broken, "AndroidManifest.xml").write_text(
                "<manifest><application>", encoding="utf-8"
            )
            write_split(
                tmp, 2,
                '<uses-permission android:name="android.permission.CAMERA"/>',
            )
            collector = analyzer.ReportCollector()
            rendered = run_scan(tmp, collector)

        finding = next(
            item for item in collector.findings
            if item["rule_id"] == "permission_without_api"
        )
        self.assertIn("CAMERA", finding["description"])
        self.assertIn("no mapped platform API", finding["description"])
        self.assertIn(
            "[MEDIUM] Dangerous permission with no mapped API",
            rendered,
        )
        self.assertFalse(any(
            item["rule_id"] == "api_without_permission"
            for item in collector.findings
        ))

    def test_incomplete_code_does_not_call_a_permission_unused(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '<uses-permission android:name="android.permission.CAMERA"/>'
                + SAFE_APP,
            )
            collector = analyzer.ReportCollector()
            with mock.patch.object(analyzer, "STATIC_CODE_MAX_FILE_BYTES", 64):
                rendered = run_scan(tmp, collector)

        self.assertFalse(any(
            item["rule_id"] == "permission_without_api"
            for item in collector.findings
        ))
        self.assertTrue(any(
            item["check_id"] == "permission_without_api"
            for item in collector.inconclusive
        ))
        self.assertIn("smali/XML coverage is incomplete", rendered)
        self.assertNotIn(
            "[MEDIUM] Dangerous permission with no mapped API",
            rendered,
        )

    def test_notification_permission_depends_on_target_sdk(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(tmp, SAFE_APP, target_sdk=32)
            write_smali(tmp, "Notify.smali", NOTIFY_SMALI)
            low = analyzer.ReportCollector()
            run_scan(tmp, low)
        self.assertFalse(any(
            item["rule_id"] == "api_without_permission"
            for item in low.findings
        ))

        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(tmp, SAFE_APP)
            write_smali(tmp, "Notify.smali", NOTIFY_SMALI)
            high = analyzer.ReportCollector()
            run_scan(tmp, high)
        finding = next(
            item for item in high.findings
            if item["rule_id"] == "api_without_permission"
        )
        self.assertIn("POST_NOTIFICATIONS", finding["description"])

    def test_location_finding_names_the_whole_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(tmp, SAFE_APP)
            write_smali(tmp, "Location.smali", LOCATION_SMALI)
            collector = analyzer.ReportCollector()
            run_scan(tmp, collector)
        finding = next(
            item for item in collector.findings
            if item["rule_id"] == "api_without_permission"
        )
        self.assertIn("ACCESS_FINE_LOCATION", finding["description"])
        self.assertIn("ACCESS_COARSE_LOCATION", finding["description"])
        self.assertIn("ACCESS_BACKGROUND_LOCATION", finding["description"])

    def test_manifest_receiver_counts_as_sms_api_use(self):
        body = (
            '<uses-permission android:name="android.permission.RECEIVE_SMS"/>'
            '<application android:debuggable="false" '
            'android:allowBackup="false" '
            'android:usesCleartextTraffic="false">'
            '<receiver android:name=".Sms" android:exported="false">'
            '<intent-filter>'
            '<action android:name="android.provider.Telephony.SMS_RECEIVED"/>'
            '</intent-filter></receiver></application>'
        )
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(tmp, body)
            collector = analyzer.ReportCollector()
            run_scan(tmp, collector)
        self.assertFalse(any(
            item["rule_id"] == "permission_without_api"
            for item in collector.findings
        ))

    def test_two_missing_apis_share_one_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(tmp, SAFE_APP)
            write_smali(tmp, "Both.smali", CAMERA_SMALI + SEND_SMS_SMALI)
            collector = analyzer.ReportCollector()
            run_scan(tmp, collector)
        findings = [
            item for item in collector.findings
            if item["rule_id"] == "api_without_permission"
        ]
        self.assertEqual(len(findings), 1)
        self.assertIn("CAMERA", findings[0]["description"])
        self.assertIn("SEND_SMS", findings[0]["description"])


if __name__ == "__main__":
    unittest.main()
