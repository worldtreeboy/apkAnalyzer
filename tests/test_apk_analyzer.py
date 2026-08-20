import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest import mock

import apkAnalyzer as analyzer


ANDROID_NS = "http://schemas.android.com/apk/res/android"


def write_manifest(root, body, target_sdk="28", package="com.example.app"):
    manifest = Path(root, "AndroidManifest.xml")
    manifest.write_text(
        f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ANDROID_NS}" package="{package}">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="{target_sdk}"/>
  {body}
</manifest>''',
        encoding="utf-8",
    )
    return manifest


def make_backup(path, members, compressed=True):
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
        for name, value in members:
            data = value.encode() if isinstance(value, str) else value
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    payload = tar_buffer.getvalue()
    if compressed:
        payload = zlib.compress(payload)
    Path(path).write_bytes(
        b"ANDROID BACKUP\n5\n" + (b"1\n" if compressed else b"0\n")
        + b"none\n" + payload
    )


class CommandTests(unittest.TestCase):
    def tearDown(self):
        analyzer.ADB_SERIAL = None
        analyzer._root_mode = None

    def test_root_command_is_one_quoted_remote_shell_argument(self):
        analyzer.ADB_SERIAL = "serial-1"
        analyzer._root_mode = "su"
        with mock.patch.object(analyzer, "_run_cmd", return_value="ok") as run:
            result = analyzer.adb_su('cd /data/local/tmp && printf "one two\\n"')
        self.assertEqual(result, "ok")
        args = run.call_args.args[0]
        self.assertEqual(os.path.basename(args[0]), "adb")
        self.assertEqual(args[1:4], ["-s", "serial-1", "shell"])
        self.assertEqual(
            args[4],
            "su -c 'cd /data/local/tmp && printf \"one two\\n\"'",
        )

    def test_adbd_root_does_not_add_su(self):
        analyzer._root_mode = "adbd"
        with mock.patch.object(analyzer, "_run_cmd", return_value="ok") as run:
            analyzer.adb_su("pwd")
        args = run.call_args.args[0]
        self.assertEqual(os.path.basename(args[0]), "adb")
        self.assertEqual(args[1:], ["shell", "pwd"])

    def test_run_cmd_surfaces_stderr_and_exit_status(self):
        completed = subprocess.CompletedProcess(
            ["tool"], 7, stdout="", stderr="failure\x1b[31m"
        )
        with mock.patch("apkAnalyzer.subprocess.run", return_value=completed):
            result = analyzer._run_cmd(["tool"])
        self.assertEqual(result, "[ERROR 7] failure")

    def test_terminal_controls_are_removed(self):
        value = "safe\x1b]52;c;ZXZpbA==\x07text\x1b[31m!\x1b[0m"
        self.assertEqual(analyzer._terminal_safe(value), "safetext!")

    def test_error_detection_does_not_reject_json_arrays(self):
        self.assertFalse(analyzer._is_err('[{"valid": true}]'))
        self.assertTrue(analyzer._is_err("[ERROR 1] denied"))

    def test_adb_pull_accepts_empty_stdout_when_file_was_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp, "app.apk")

            def fake_run(args, timeout=30, stdin=None):
                Path(args[-1]).write_bytes(b"apk")
                return ""

            with mock.patch.object(analyzer, "_run_cmd", side_effect=fake_run):
                result = analyzer.adb_pull("/data/app/base.apk", destination)
            self.assertEqual(result, "pulled")
            self.assertEqual(destination.read_bytes(), b"apk")

    def test_adb_pull_does_not_replace_existing_file_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp, "app.apk")
            destination.write_bytes(b"old")
            with mock.patch.object(analyzer, "_run_cmd", return_value="[ERROR 1] denied"):
                result = analyzer.adb_pull("/data/app/base.apk", destination)
            self.assertTrue(result.startswith("[ERROR"))
            self.assertEqual(destination.read_bytes(), b"old")

    def test_interactive_shell_tracks_android_working_directory(self):
        commands = []

        def fake_su(command, timeout=30):
            commands.append(command)
            if command.startswith("cd /data/local/tmp && pwd"):
                return "/data/local/tmp"
            return ""

        user_input = iter(("cd /data/local/tmp", "pwd", "exit"))
        with mock.patch("builtins.input", side_effect=lambda _prompt: next(user_input)), \
                mock.patch.object(analyzer, "adb_su", side_effect=fake_su), \
                mock.patch("builtins.print"):
            analyzer.shell_access("com.example.app")

        self.assertEqual(commands[0], "cd /data/local/tmp && pwd")
        self.assertEqual(commands[1], "cd /data/local/tmp && pwd")


class ManifestTests(unittest.TestCase):
    def test_manifest_defaults_aliases_permissions_and_disabled_components(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '''<permission android:name="com.example.NORMAL" android:protectionLevel="normal"/>
<uses-permission-sdk-23 android:name="android.permission.CAMERA"/>
<application android:permission="com.example.NORMAL">
  <activity android:name=".Main">
    <intent-filter>
      <action android:name="android.intent.action.MAIN"/>
      <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
  </activity>
  <activity-alias android:name=".Alias" android:targetActivity=".Main" android:exported="true"/>
  <service android:name=".Disabled" android:enabled="false" android:exported="true"/>
  <provider android:name=".Provider" android:authorities="com.example.provider"/>
</application>''',
            )
            info = analyzer._parse_manifest(tmp)

        self.assertTrue(info["parsed"])
        self.assertFalse(info["cleartext"])
        self.assertFalse(info["cleartext_explicit"])
        self.assertIn("android.permission.CAMERA", info["permissions"])
        self.assertEqual(info["declared_permissions"]["com.example.NORMAL"], "normal")
        self.assertEqual(len(info["exported"]["provider"]), 0)
        self.assertEqual(len(info["exported"]["service"]), 0)
        self.assertEqual(len(info["exported"]["activity"]), 2)
        alias = next(c for c in info["exported"]["activity"] if c["name"] == ".Alias")
        self.assertEqual(alias["target_activity"], ".Main")

    def test_provider_default_is_exported_only_for_legacy_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '<application><provider android:name=".Provider" '
                'android:authorities="com.example.provider"/></application>',
                target_sdk="16",
            )
            info = analyzer._parse_manifest(tmp)
        self.assertEqual(len(info["exported"]["provider"]), 1)
        self.assertTrue(info["cleartext"])

    def test_custom_network_config_is_resolved_and_debug_ca_is_not_production_ca(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_manifest(
                tmp,
                '<application android:networkSecurityConfig="@xml/custom_policy"/>',
            )
            xml_dir = Path(tmp, "res", "xml")
            xml_dir.mkdir(parents=True)
            policy = xml_dir / "custom_policy.xml"
            policy.write_text(
                '''<network-security-config>
  <base-config><trust-anchors><certificates src="system"/></trust-anchors></base-config>
  <debug-overrides><trust-anchors><certificates src="user"/></trust-anchors></debug-overrides>
</network-security-config>''',
                encoding="utf-8",
            )
            info = analyzer._parse_manifest(tmp)
            resolved = analyzer._resolve_resource_path(tmp, info["nsc_ref"])
            policy_info = analyzer._analyze_nsc(tmp, resolved)
        self.assertEqual(resolved, str(policy))
        self.assertTrue(policy_info["parsed"])
        self.assertFalse(policy_info["trusts_user_certs"])
        self.assertTrue(policy_info["trusts_debug_user_certs"])

    def test_dtd_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "AndroidManifest.xml").write_text(
                '<!DOCTYPE x [<!ENTITY y "z">]><manifest/>', encoding="utf-8"
            )
            self.assertFalse(analyzer._parse_manifest(tmp)["parsed"])

    def test_launcher_alias_resolves_to_target_and_manifest_patch_is_structural(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_manifest(
                tmp,
                '''<application android:extractNativeLibs="false">
  <activity android:name=".Real"/>
  <activity-alias android:name=".Launcher" android:targetActivity=".Real">
    <intent-filter>
      <action android:name="android.intent.action.MAIN"/>
      <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
  </activity-alias>
</application>''',
            )
            self.assertEqual(analyzer._find_main_activity(manifest), "com.example.app.Real")
            self.assertTrue(analyzer._patch_manifest_for_gadget(manifest))
            tree = analyzer._safe_parse_xml(manifest)
            root = tree.getroot()
        ns = f"{{{ANDROID_NS}}}"
        self.assertEqual(root.find("application").get(f"{ns}extractNativeLibs"), "true")
        permissions = [p.get(f"{ns}name") for p in root.findall("uses-permission")]
        self.assertEqual(permissions.count("android.permission.INTERNET"), 1)


class DetectionTests(unittest.TestCase):
    def test_secret_matches_return_full_value_and_skip_public_identifiers(self):
        content = (
            "password = hunter2\n"
            "pk_live_123456789012345678901234\n"
            "-----BEGIN CERTIFICATE-----\n"
        )
        matches = analyzer._find_secret_matches(content)
        self.assertIn("password = hunter2", matches)
        self.assertFalse(any("pk_live" in item for item in matches))
        self.assertFalse(any("CERTIFICATE" in item for item in matches))

    def test_redaction_does_not_return_secret(self):
        redacted = analyzer._redact("password=super-secret-value")
        self.assertNotIn("super-secret-value", redacted)
        self.assertTrue(redacted.startswith("password="))

    def test_storage_preview_redacts_secrets_and_pii(self):
        preview = analyzer._redact_sensitive_text(
            "password=hunter2 email=user@example.com"
        )
        self.assertNotIn("hunter2", preview)
        self.assertNotIn("user@example.com", preview)

    def test_sqlite_identifier_escaping(self):
        self.assertEqual(analyzer._sqlite_identifier('odd"name'), '"odd""name"')
        with self.assertRaises(ValueError):
            analyzer._sqlite_identifier("bad\nname")

    def test_clipboard_check_does_not_clear_after_an_external_launch(self):
        with mock.patch.object(analyzer, "adb_su", return_value="") as adb_su:
            analyzer._check_clipboard_leak("com.example.app", launch=False)
        commands = [call.args[0] for call in adb_su.call_args_list]
        self.assertFalse(any("clipboard 5" in command for command in commands))


class BackupTests(unittest.TestCase):
    def test_extracts_normal_compressed_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            backup = Path(tmp, "sample.ab")
            output = Path(tmp, "out")
            make_backup(backup, [("apps/com.example/f/config.txt", "hello")])
            count, error = analyzer._unpack_ab(backup, output)
            self.assertIsNone(error)
            self.assertEqual(count, 1)
            self.assertEqual(
                Path(output, "apps", "com.example", "f", "config.txt").read_text(),
                "hello",
            )

    def test_rejects_posix_and_windows_path_traversal(self):
        for unsafe_name in ("../escape.txt", "folder/..\\escape.txt", "/absolute.txt"):
            with self.subTest(unsafe_name=unsafe_name), tempfile.TemporaryDirectory() as tmp:
                backup = Path(tmp, "sample.ab")
                output = Path(tmp, "out")
                make_backup(backup, [(unsafe_name, "bad")])
                count, error = analyzer._unpack_ab(backup, output)
                self.assertEqual(count, 0)
                self.assertIn("unsafe backup member path", error)
                self.assertFalse(Path(tmp, "escape.txt").exists())

    def test_honors_per_file_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            backup = Path(tmp, "sample.ab")
            make_backup(backup, [("large.txt", b"12345")])
            with mock.patch.object(analyzer, "MAX_BACKUP_FILE_BYTES", 4):
                count, error = analyzer._unpack_ab(backup, Path(tmp, "out"))
            self.assertEqual(count, 0)
            self.assertIn("per-file safety limit", error)


class PatcherTests(unittest.TestCase):
    def test_github_release_digest_is_read_for_exact_asset(self):
        digest = "a" * 64
        response = mock.MagicMock()
        response.geturl.return_value = (
            "https://api.github.com/repos/frida/frida/releases/tags/17.0.0"
        )
        response.read.return_value = json.dumps({
            "assets": [{"name": "gadget.xz", "digest": f"sha256:{digest}"}]
        }).encode()
        response.__enter__.return_value = response
        with mock.patch("apkAnalyzer.urllib.request.urlopen", return_value=response):
            actual = analyzer._github_asset_sha256(
                "frida/frida", "17.0.0", "gadget.xz"
            )
        self.assertEqual(actual, digest)

    def test_oncreate_register_injection_reserves_a_real_local(self):
        source = '''.class public Lcom/example/Main;
.super Landroid/app/Activity;

.method protected onCreate(Landroid/os/Bundle;)V
    .registers 2
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    return-void
.end method
'''
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "Main.smali")
            path.write_text(source, encoding="utf-8")
            self.assertTrue(analyzer._inject_gadget_loader(path))
            first = path.read_text(encoding="utf-8")
            self.assertIn(".registers 3", first)
            self.assertIn('const-string v0, "frida-gadget"', first)
            self.assertTrue(analyzer._inject_gadget_loader(path))
            second = path.read_text(encoding="utf-8")
            self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
