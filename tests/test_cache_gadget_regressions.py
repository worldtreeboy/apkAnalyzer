import io
import json
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import apkAnalyzer as analyzer


def _write_test_apk(path, marker=b"test-apk"):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", b"binary-manifest")
        archive.writestr("assets/marker.bin", marker)


class DecompileCacheRegressionTests(unittest.TestCase):
    def test_unavailable_fingerprint_preserves_but_does_not_reuse_cache(self):
        package = "com.example.cached"
        with tempfile.TemporaryDirectory() as tmp:
            decompiled = Path(
                tmp, ".apkanalyzer_tmp", f"{package}_decompiled"
            )
            decompiled.mkdir(parents=True)
            metadata = {
                "versionCode": "1",
                "lastUpdateTime": "2026-01-01 00:00:00",
                "codePath": "/data/app/com.example.cached",
            }
            Path(decompiled, ".apkanalyzer_meta.json").write_text(
                json.dumps(metadata), encoding="utf-8"
            )
            Path(decompiled, "AndroidManifest.xml").write_text(
                "<manifest/>", encoding="utf-8"
            )

            output = io.StringIO()
            with mock.patch.object(
                analyzer.os, "getcwd", return_value=tmp
            ), mock.patch.object(
                analyzer, "_get_package_fingerprint", return_value={}
            ), mock.patch.object(
                analyzer, "_find_apktool"
            ) as find_apktool, mock.patch.object(
                analyzer.shutil, "rmtree"
            ) as rmtree, redirect_stdout(output):
                result = analyzer._pull_and_decompile(package)

            self.assertEqual(result, (None, None))
            self.assertTrue(decompiled.is_dir())
            self.assertIn("cache was not used", output.getvalue())
            find_apktool.assert_not_called()
            rmtree.assert_not_called()

    def test_failed_installed_v2_pull_does_not_fall_back_to_stale_local_v1(self):
        package = "com.example.updated"
        device_meta = {
            "versionCode": "2",
            "lastUpdateTime": "2026-08-20 12:00:00",
            "codePath": "/data/app/com.example.updated-v2",
        }
        with tempfile.TemporaryDirectory() as tmp:
            stale_apk = Path(tmp, "extracted_apks", f"{package}.apk")
            stale_apk.parent.mkdir()
            stale_apk.write_bytes(b"stale-version-1")

            output = io.StringIO()
            with mock.patch.object(
                analyzer.os, "getcwd", return_value=tmp
            ), mock.patch.object(
                analyzer, "_find_apktool", return_value=["apktool"]
            ), mock.patch.object(
                analyzer, "get_apk_paths",
                return_value=["/data/app/com.example.updated-v2/base.apk"]
            ), mock.patch.object(
                analyzer, "adb_pull", return_value="[ERROR 1] device offline"
            ), mock.patch.object(
                analyzer, "_find_local_apk", return_value=str(stale_apk)
            ) as find_local, mock.patch.object(
                analyzer, "_get_package_fingerprint", return_value=device_meta
            ) as fingerprint, mock.patch.object(
                analyzer.subprocess, "run"
            ) as run, redirect_stdout(output):
                result = analyzer._pull_and_decompile(package)

            self.assertEqual(result, (None, None))
            self.assertIn("refusing to use an unverified local fallback",
                          output.getvalue())
            self.assertEqual(stale_apk.read_bytes(), b"stale-version-1")
            find_local.assert_not_called()
            self.assertGreaterEqual(fingerprint.call_count, 1)
            run.assert_not_called()

    def test_local_fallback_cache_metadata_is_local_not_device_metadata(self):
        package = "com.example.local"
        device_meta = {
            "versionCode": "2",
            "lastUpdateTime": "2026-08-20 12:00:00",
            "codePath": "/data/app/com.example.local-v2",
        }
        with tempfile.TemporaryDirectory() as tmp:
            local_apk = Path(tmp, "extracted_apks", f"{package}.apk")
            local_apk.parent.mkdir()
            _write_test_apk(local_apk, b"local-version-1")

            def fake_apktool(args, **_kwargs):
                output_dir = Path(args[args.index("-o") + 1])
                output_dir.mkdir(parents=True)
                return mock.Mock(returncode=0, stdout="", stderr="")

            with mock.patch.object(
                analyzer.os, "getcwd", return_value=tmp
            ), mock.patch.object(
                analyzer, "_find_apktool", return_value=["apktool"]
            ), mock.patch.object(
                analyzer, "get_apk_paths", return_value=[]
            ), mock.patch.object(
                analyzer, "_find_local_apk", return_value=str(local_apk)
            ), mock.patch.object(
                analyzer, "_get_package_fingerprint", return_value=device_meta
            ) as fingerprint, mock.patch.object(
                analyzer.subprocess, "run", side_effect=fake_apktool
            ):
                _work_dir, decompiled = analyzer._pull_and_decompile(package)

            metadata = json.loads(
                Path(decompiled, ".apkanalyzer_meta.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(metadata["source"], "local")
            self.assertEqual(len(metadata["sha256"]), 64)
            self.assertNotEqual(metadata, device_meta)
            fingerprint.assert_not_called()


class GadgetInjectionRegressionTests(unittest.TestCase):
    def _patch(self, source):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "Main.smali")
            path.write_text(source, encoding="utf-8")
            self.assertTrue(analyzer._inject_gadget_loader(path))
            first = path.read_text(encoding="utf-8")
            self.assertTrue(analyzer._inject_gadget_loader(path))
            second = path.read_text(encoding="utf-8")
        self.assertEqual(first, second)
        return first

    def test_register_oncreate_is_preserved_and_loader_uses_new_clinit(self):
        on_create = '''.method protected onCreate(Landroid/os/Bundle;)V
    .registers 2
    invoke-super {v0, v1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    return-void
.end method'''
        source = f'''.class public Lcom/example/Main;
.super Landroid/app/Activity;

{on_create}
'''

        patched = self._patch(source)

        self.assertIn(on_create, patched)
        self.assertIn(".method static constructor <clinit>()V", patched)
        self.assertIn('const-string v0, "frida-gadget"', patched)

    def test_locals_oncreate_is_preserved_and_loader_uses_new_clinit(self):
        on_create = '''.method protected onCreate(Landroid/os/Bundle;)V
    .locals 0
    invoke-super {v0, v1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    return-void
.end method'''
        source = f'''.class public Lcom/example/Main;
.super Landroid/app/Activity;

{on_create}
'''

        patched = self._patch(source)

        self.assertIn(on_create, patched)
        self.assertIn(".method static constructor <clinit>()V", patched)

    def test_existing_clinit_is_used_without_touching_oncreate(self):
        on_create = '''.method protected onCreate(Landroid/os/Bundle;)V
    .registers 2
    invoke-super {v0, v1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    return-void
.end method'''
        source = f'''.class public Lcom/example/Main;
.super Landroid/app/Activity;

.method static constructor <clinit>()V
    .registers 0  # preserve inline comment
    return-void
.end method

{on_create}
'''

        patched = self._patch(source)

        self.assertIn(on_create, patched)
        self.assertEqual(patched.count("<clinit>()V"), 1)
        self.assertIn(".registers 1  # preserve inline comment", patched)
        clinit = patched.split("<clinit>()V", 1)[1].split(".end method", 1)[0]
        self.assertIn('const-string v0, "frida-gadget"', clinit)

    def test_unrelated_gadget_string_does_not_suppress_loader_injection(self):
        source = '''.class public Lcom/example/Main;
.super Landroid/app/Activity;

.method private detector()V
    .registers 1
    const-string v0, "frida-gadget"
    return-void
.end method
'''

        patched = self._patch(source)

        self.assertIn(".method static constructor <clinit>()V", patched)
        clinit = patched.split("<clinit>()V", 1)[1].split(".end method", 1)[0]
        self.assertIn("Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V", clinit)

    def test_mismatched_loader_register_does_not_count_as_injected(self):
        source = '''.class public Lcom/example/Main;
.super Landroid/app/Activity;

.method static constructor <clinit>()V
    .registers 2
    const-string v0, "frida-gadget"
    const-string v1, "different-library"
    invoke-static {v1}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    return-void
.end method
'''

        patched = self._patch(source)

        clinit = patched.split("<clinit>()V", 1)[1].split(".end method", 1)[0]
        self.assertIn(
            "invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V",
            clinit,
        )

    def test_overwritten_loader_register_does_not_count_as_injected(self):
        source = '''.class public Lcom/example/Main;
.super Landroid/app/Activity;

.method static constructor <clinit>()V
    .registers 1
    const-string v0, "frida-gadget"
    const-string v0, "different-library"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    return-void
.end method
'''

        patched = self._patch(source)

        self.assertGreaterEqual(patched.count('const-string v0, "frida-gadget"'), 2)


if __name__ == "__main__":
    unittest.main()
