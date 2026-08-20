import io
import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import apkAnalyzer as analyzer


PACKAGE = "com.example.split"
FINGERPRINT = {
    "versionCode": "7",
    "lastUpdateTime": "2026-08-20 12:00:00",
    "codePath": "/data/app/com.example.split",
}
BASE_REMOTE = "/data/app/com.example.split/base.apk"
FEATURE_REMOTE = "/data/app/com.example.split/split_feature_chat.apk"


class InstalledApkPathTests(unittest.TestCase):
    def test_zero_paths_returns_empty_set(self):
        with mock.patch.object(analyzer, "adb_su", return_value=""), \
                mock.patch.object(
                    analyzer, "adb_shell", return_value="[ERROR 1] unknown package"
                ):
            self.assertEqual(analyzer.get_apk_paths(PACKAGE), [])
            self.assertEqual(analyzer.get_apk_path(PACKAGE), "")

    def test_single_path_is_returned_and_compatibility_wrapper_uses_it(self):
        with mock.patch.object(
            analyzer, "adb_su", return_value=f"package:{BASE_REMOTE}\n"
        ), mock.patch.object(analyzer, "adb_shell") as shell:
            self.assertEqual(analyzer.get_apk_paths(PACKAGE), [BASE_REMOTE])
            self.assertEqual(analyzer.get_apk_path(PACKAGE), BASE_REMOTE)
            shell.assert_not_called()

    def test_multiple_paths_are_base_first_and_otherwise_deterministic(self):
        config = "/data/app/com.example.split/split_config.arm64_v8a.apk"
        output = (
            f"package:{FEATURE_REMOTE}\n"
            f"package:{config}\n"
            f"package:{BASE_REMOTE}\n"
        )
        with mock.patch.object(analyzer, "adb_su", return_value=output), \
                mock.patch.object(analyzer, "adb_shell"):
            self.assertEqual(
                analyzer.get_apk_paths(PACKAGE),
                [BASE_REMOTE, config, FEATURE_REMOTE],
            )

    def test_malformed_root_response_is_not_partially_accepted(self):
        malformed = (
            f"package:{BASE_REMOTE}\n"
            "package:/data/app/com.example.split/../outside.apk\n"
        )
        with mock.patch.object(analyzer, "adb_su", return_value=malformed), \
                mock.patch.object(
                    analyzer, "adb_shell", return_value=f"package:{BASE_REMOTE}\n"
                ):
            self.assertEqual(analyzer.get_apk_paths(PACKAGE), [BASE_REMOTE])

    def test_partial_package_fingerprint_is_not_trusted_for_cache_identity(self):
        incomplete = "versionCode=7 minSdk=23 targetSdk=35\n"
        with mock.patch.object(analyzer, "adb_shell", return_value=incomplete):
            self.assertEqual(analyzer._get_package_fingerprint(PACKAGE), {})


class DeviceSplitDecompileTests(unittest.TestCase):
    @staticmethod
    def _apktool_runner(calls):
        def run(args, **_kwargs):
            calls.append(list(args))
            output_dir = Path(args[args.index("-o") + 1])
            output_dir.mkdir(parents=True)
            Path(output_dir, "AndroidManifest.xml").write_text(
                f'<manifest package="{PACKAGE}"/>', encoding="utf-8"
            )
            smali = Path(output_dir, "smali", "Example.smali")
            smali.parent.mkdir()
            smali.write_text(".class public LExample;\n", encoding="utf-8")
            asset = Path(output_dir, "assets", "config.json")
            asset.parent.mkdir()
            asset.write_text('{"safe": true}\n', encoding="utf-8")
            return SimpleNamespace(returncode=0)

        return run

    @staticmethod
    def _successful_pull(remote, local):
        with zipfile.ZipFile(local, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("AndroidManifest.xml", b"binary-manifest")
            archive.writestr(
                "assets/source.txt", ("pulled:" + remote).encode("utf-8")
            )
        return "pulled"

    @staticmethod
    def _write_crc_corrupted_apk(path):
        marker = b"payload-marker-for-crc"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("AndroidManifest.xml", b"binary-manifest")
            archive.writestr("assets/payload.bin", marker)
        raw = bytearray(Path(path).read_bytes())
        offset = raw.index(marker)
        raw[offset] ^= 0x01
        Path(path).write_bytes(raw)

    @staticmethod
    def _write_traversal_apk(path):
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("AndroidManifest.xml", b"binary-manifest")
            archive.writestr("../escaped.txt", b"escape")

    @staticmethod
    def _write_ratio_bomb_apk(path):
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("AndroidManifest.xml", b"binary-manifest")
            archive.writestr("assets/bomb.bin", b"A" * (2 * 1024 * 1024))

    def test_split_output_layout_and_cache_metadata(self):
        calls = []
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            analyzer.os, "getcwd", return_value=tmp
        ), mock.patch.object(
            analyzer, "_find_apktool", return_value=["apktool"]
        ), mock.patch.object(
            analyzer, "get_apk_paths", return_value=[BASE_REMOTE, FEATURE_REMOTE]
        ), mock.patch.object(
            analyzer, "adb_pull", side_effect=self._successful_pull
        ), mock.patch.object(
            analyzer, "_get_package_fingerprint", return_value=FINGERPRINT
        ), mock.patch.object(
            analyzer.subprocess,
            "run",
            side_effect=self._apktool_runner(calls),
        ):
            work_dir, decompiled = analyzer._pull_and_decompile(PACKAGE)

            self.assertEqual(len(calls), 2)
            self.assertTrue(Path(decompiled, "AndroidManifest.xml").is_file())
            self.assertTrue(
                Path(
                    decompiled,
                    ".apkanalyzer_splits",
                    "split_0001",
                    "AndroidManifest.xml",
                ).is_file()
            )
            metadata = json.loads(
                Path(decompiled, ".apkanalyzer_meta.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(metadata["cache_schema"], 3)
            self.assertEqual(metadata["package_fingerprint"], FINGERPRINT)
            self.assertEqual(
                metadata["remote_apk_paths"], [BASE_REMOTE, FEATURE_REMOTE]
            )
            self.assertRegex(metadata["base_apk_sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(
                metadata["decompile_integrity"]["digest"],
                r"^[0-9a-f]{64}$",
            )
            self.assertTrue(Path(work_dir, f"{PACKAGE}.apk").is_file())
            self.assertFalse(
                any(
                    entry.name.startswith(f".{PACKAGE}-pull-")
                    for entry in Path(work_dir).iterdir()
                )
            )

    def test_mid_pull_failure_cleans_stage_and_never_decompiles_or_falls_back(self):
        calls = []

        def pull(remote, local):
            calls.append(remote)
            if remote == BASE_REMOTE:
                Path(local).write_bytes(b"base")
                return "pulled"
            return "[ERROR 1] device disconnected"

        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp, ".apkanalyzer_tmp")
            work.mkdir()
            Path(work, f"{PACKAGE}.apk").write_bytes(b"stale-pulled-base")
            stale_local = Path(tmp, "extracted_apks", f"{PACKAGE}.apk")
            stale_local.parent.mkdir()
            stale_local.write_bytes(b"stale-local")
            with mock.patch.object(
                analyzer.os, "getcwd", return_value=tmp
            ), mock.patch.object(
                analyzer, "_find_apktool", return_value=["apktool"]
            ), mock.patch.object(
                analyzer,
                "get_apk_paths",
                return_value=[BASE_REMOTE, FEATURE_REMOTE],
            ), mock.patch.object(
                analyzer, "adb_pull", side_effect=pull
            ), mock.patch.object(
                analyzer, "_get_package_fingerprint", return_value=FINGERPRINT
            ), mock.patch.object(
                analyzer, "_find_local_apk", return_value=str(stale_local)
            ) as find_local, mock.patch.object(
                analyzer.subprocess, "run"
            ) as run:
                result = analyzer._pull_and_decompile(PACKAGE)

            self.assertEqual(result, (None, None))
            self.assertEqual(calls, [BASE_REMOTE, FEATURE_REMOTE])
            self.assertFalse(Path(work, f"{PACKAGE}.apk").exists())
            self.assertFalse(Path(work, f"{PACKAGE}_decompiled").exists())
            self.assertEqual(stale_local.read_bytes(), b"stale-local")
            self.assertFalse(
                any(
                    entry.name.startswith(f".{PACKAGE}-pull-")
                    for entry in work.iterdir()
                )
            )
            find_local.assert_not_called()
            run.assert_not_called()

    def test_changed_split_set_invalidates_base_only_cache(self):
        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp, ".apkanalyzer_tmp")
            decompiled = Path(work, f"{PACKAGE}_decompiled")
            decompiled.mkdir(parents=True)
            Path(decompiled, "old-marker").write_text("old", encoding="utf-8")
            Path(decompiled, ".apkanalyzer_meta.json").write_text(
                json.dumps(
                    {
                        "cache_schema": 3,
                        "source": "device",
                        "package_fingerprint": FINGERPRINT,
                        "remote_apk_paths": [BASE_REMOTE],
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.object(
                analyzer.os, "getcwd", return_value=tmp
            ), mock.patch.object(
                analyzer, "_find_apktool", return_value=["apktool"]
            ), mock.patch.object(
                analyzer,
                "get_apk_paths",
                return_value=[BASE_REMOTE, FEATURE_REMOTE],
            ), mock.patch.object(
                analyzer, "adb_pull", side_effect=self._successful_pull
            ), mock.patch.object(
                analyzer, "_get_package_fingerprint", return_value=FINGERPRINT
            ), mock.patch.object(
                analyzer.subprocess,
                "run",
                side_effect=self._apktool_runner(calls),
            ):
                _work_dir, new_decompiled = analyzer._pull_and_decompile(PACKAGE)

            self.assertEqual(len(calls), 2)
            self.assertFalse(Path(new_decompiled, "old-marker").exists())
            metadata = json.loads(
                Path(new_decompiled, ".apkanalyzer_meta.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                metadata["remote_apk_paths"], [BASE_REMOTE, FEATURE_REMOTE]
            )

    def test_matching_metadata_does_not_hide_a_missing_cached_split(self):
        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp, ".apkanalyzer_tmp")
            decompiled = Path(work, f"{PACKAGE}_decompiled")
            decompiled.mkdir(parents=True)
            Path(decompiled, "AndroidManifest.xml").write_text(
                f'<manifest package="{PACKAGE}"/>', encoding="utf-8"
            )
            Path(decompiled, "old-marker").write_text("old", encoding="utf-8")
            Path(decompiled, ".apkanalyzer_meta.json").write_text(
                json.dumps(
                    {
                        "cache_schema": 3,
                        "source": "device",
                        "package_fingerprint": FINGERPRINT,
                        "remote_apk_paths": [BASE_REMOTE, FEATURE_REMOTE],
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.object(
                analyzer.os, "getcwd", return_value=tmp
            ), mock.patch.object(
                analyzer, "_find_apktool", return_value=["apktool"]
            ), mock.patch.object(
                analyzer,
                "get_apk_paths",
                return_value=[BASE_REMOTE, FEATURE_REMOTE],
            ), mock.patch.object(
                analyzer, "adb_pull", side_effect=self._successful_pull
            ), mock.patch.object(
                analyzer, "_get_package_fingerprint", return_value=FINGERPRINT
            ), mock.patch.object(
                analyzer.subprocess,
                "run",
                side_effect=self._apktool_runner(calls),
            ), redirect_stdout(io.StringIO()) as output:
                _work_dir, new_decompiled = analyzer._pull_and_decompile(PACKAGE)

            self.assertEqual(len(calls), 2)
            self.assertIn("Cached decompile is incomplete", output.getvalue())
            self.assertFalse(Path(new_decompiled, "old-marker").exists())
            self.assertTrue(
                Path(
                    new_decompiled,
                    ".apkanalyzer_splits",
                    "split_0001",
                    "AndroidManifest.xml",
                ).is_file()
            )

    def test_unchanged_sealed_cache_is_reused_without_apktool_or_pull(self):
        calls = []
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            analyzer.os, "getcwd", return_value=tmp
        ), mock.patch.object(
            analyzer, "_find_apktool", return_value=["apktool"]
        ), mock.patch.object(
            analyzer, "get_apk_paths", return_value=[BASE_REMOTE, FEATURE_REMOTE]
        ), mock.patch.object(
            analyzer, "adb_pull", side_effect=self._successful_pull
        ) as pull, mock.patch.object(
            analyzer, "_get_package_fingerprint", return_value=FINGERPRINT
        ), mock.patch.object(
            analyzer.subprocess,
            "run",
            side_effect=self._apktool_runner(calls),
        ), redirect_stdout(io.StringIO()) as output:
            first = analyzer._pull_and_decompile(PACKAGE)
            second = analyzer._pull_and_decompile(PACKAGE)

        self.assertEqual(first, second)
        self.assertEqual(len(calls), 2)
        self.assertEqual(pull.call_count, 2)
        self.assertIn("Using cached decompile", output.getvalue())

    def test_modified_or_deleted_cached_content_forces_fresh_decompile(self):
        mutations = {
            "modified smali": lambda root: Path(
                root, "smali", "Example.smali"
            ).write_text("tampered\n", encoding="utf-8"),
            "deleted asset": lambda root: Path(
                root, "assets", "config.json"
            ).unlink(),
            "modified signing APK": lambda root: Path(
                root
            ).parent.joinpath(f"{PACKAGE}.apk").write_bytes(b"tampered"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                calls = []
                with mock.patch.object(
                    analyzer.os, "getcwd", return_value=tmp
                ), mock.patch.object(
                    analyzer, "_find_apktool", return_value=["apktool"]
                ), mock.patch.object(
                    analyzer,
                    "get_apk_paths",
                    return_value=[BASE_REMOTE, FEATURE_REMOTE],
                ), mock.patch.object(
                    analyzer, "adb_pull", side_effect=self._successful_pull
                ), mock.patch.object(
                    analyzer, "_get_package_fingerprint", return_value=FINGERPRINT
                ), mock.patch.object(
                    analyzer.subprocess,
                    "run",
                    side_effect=self._apktool_runner(calls),
                ):
                    _work, decompiled = analyzer._pull_and_decompile(PACKAGE)
                    mutate(decompiled)
                    with redirect_stdout(io.StringIO()) as output:
                        _work, refreshed = analyzer._pull_and_decompile(PACKAGE)

                self.assertEqual(len(calls), 4)
                self.assertIn("integrity check failed", output.getvalue())
                self.assertTrue(
                    Path(refreshed, "smali", "Example.smali").is_file()
                )
                self.assertTrue(
                    Path(refreshed, "assets", "config.json").is_file()
                )

    def test_pulled_crc_path_and_ratio_failures_never_reach_apktool(self):
        writers = {
            "CRC corruption": self._write_crc_corrupted_apk,
            "path traversal": self._write_traversal_apk,
            "compression bomb": self._write_ratio_bomb_apk,
        }
        for label, writer in writers.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                def pull(_remote, local):
                    writer(local)
                    return "pulled"

                with mock.patch.object(
                    analyzer.os, "getcwd", return_value=tmp
                ), mock.patch.object(
                    analyzer, "_find_apktool", return_value=["apktool"]
                ), mock.patch.object(
                    analyzer, "get_apk_paths", return_value=[BASE_REMOTE]
                ), mock.patch.object(
                    analyzer, "adb_pull", side_effect=pull
                ), mock.patch.object(
                    analyzer, "_get_package_fingerprint", return_value=FINGERPRINT
                ), mock.patch.object(
                    analyzer.subprocess, "run"
                ) as run, redirect_stdout(io.StringIO()) as output:
                    result = analyzer._pull_and_decompile(PACKAGE)

                self.assertEqual(result, (None, None))
                self.assertIn("APK validation failed", output.getvalue())
                run.assert_not_called()
                work = Path(tmp, ".apkanalyzer_tmp")
                self.assertFalse(Path(work, f"{PACKAGE}_decompiled").exists())
                self.assertFalse(
                    any(
                        child.name.startswith(f".{PACKAGE}-pull-")
                        for child in work.iterdir()
                    )
                )

    def test_path_change_after_pull_discards_artifacts_before_apktool(self):
        changed_paths = [BASE_REMOTE, FEATURE_REMOTE]
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            analyzer.os, "getcwd", return_value=tmp
        ), mock.patch.object(
            analyzer, "_find_apktool", return_value=["apktool"]
        ), mock.patch.object(
            analyzer,
            "get_apk_paths",
            side_effect=[[BASE_REMOTE], [BASE_REMOTE], changed_paths],
        ), mock.patch.object(
            analyzer, "adb_pull", side_effect=self._successful_pull
        ), mock.patch.object(
            analyzer, "_get_package_fingerprint", return_value=FINGERPRINT
        ), mock.patch.object(
            analyzer.subprocess, "run"
        ) as run, redirect_stdout(io.StringIO()) as output:
            result = analyzer._pull_and_decompile(PACKAGE)

        self.assertEqual(result, (None, None))
        self.assertIn("changed or became unavailable", output.getvalue())
        run.assert_not_called()
        work = Path(tmp, ".apkanalyzer_tmp")
        self.assertFalse(Path(work, f"{PACKAGE}_decompiled").exists())

    def test_fingerprint_change_or_disconnect_after_decompile_discards_output(self):
        updated = dict(FINGERPRINT, lastUpdateTime="2026-08-20 13:00:00")
        for label, final_fingerprint in (
            ("in-place update", updated),
            ("disconnect", {}),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                calls = []
                fingerprints = [
                    FINGERPRINT,
                    FINGERPRINT,
                    FINGERPRINT,
                    final_fingerprint,
                ]
                with mock.patch.object(
                    analyzer.os, "getcwd", return_value=tmp
                ), mock.patch.object(
                    analyzer, "_find_apktool", return_value=["apktool"]
                ), mock.patch.object(
                    analyzer, "get_apk_paths", return_value=[BASE_REMOTE]
                ), mock.patch.object(
                    analyzer, "adb_pull", side_effect=self._successful_pull
                ), mock.patch.object(
                    analyzer,
                    "_get_package_fingerprint",
                    side_effect=fingerprints,
                ), mock.patch.object(
                    analyzer.subprocess,
                    "run",
                    side_effect=self._apktool_runner(calls),
                ), redirect_stdout(io.StringIO()) as output:
                    result = analyzer._pull_and_decompile(PACKAGE)

                self.assertEqual(result, (None, None))
                self.assertEqual(len(calls), 1)
                self.assertIn("Could not finalize", output.getvalue())
                work = Path(tmp, ".apkanalyzer_tmp")
                self.assertFalse(Path(work, f"{PACKAGE}_decompiled").exists())
                self.assertFalse(Path(work, f"{PACKAGE}.apk").exists())

    def test_invalid_local_fallback_is_rejected_before_apktool(self):
        with tempfile.TemporaryDirectory() as tmp:
            local_apk = Path(tmp, "extracted_apks", f"{PACKAGE}.apk")
            local_apk.parent.mkdir()
            local_apk.write_bytes(b"not-a-zip")
            with mock.patch.object(
                analyzer.os, "getcwd", return_value=tmp
            ), mock.patch.object(
                analyzer, "_find_apktool", return_value=["apktool"]
            ), mock.patch.object(
                analyzer, "get_apk_paths", return_value=[]
            ), mock.patch.object(
                analyzer, "_find_local_apk", return_value=str(local_apk)
            ), mock.patch.object(
                analyzer.subprocess, "run"
            ) as run, redirect_stdout(io.StringIO()) as output:
                result = analyzer._pull_and_decompile(PACKAGE)

        self.assertEqual(result, (None, None))
        self.assertIn("APK validation failed", output.getvalue())
        run.assert_not_called()


class SplitPatcherSafetyTests(unittest.TestCase):
    def test_both_single_apk_patchers_refuse_splits_before_writes(self):
        for patcher in (analyzer.frida_gadget_patch, analyzer.lspatch_patch):
            with self.subTest(patcher=patcher.__name__), \
                    tempfile.TemporaryDirectory() as tmp, mock.patch.object(
                        analyzer.os, "getcwd", return_value=tmp
                    ), mock.patch.object(
                        analyzer,
                        "get_apk_paths",
                        return_value=[BASE_REMOTE, FEATURE_REMOTE],
                    ), mock.patch.object(
                        analyzer, "pause"
                    ), mock.patch.object(
                        analyzer, "_find_apktool"
                    ) as find_apktool, mock.patch.object(
                        analyzer.shutil, "which"
                    ) as which, redirect_stdout(io.StringIO()) as output:
                patcher(PACKAGE)
                self.assertIn("no files were changed", output.getvalue())
                self.assertEqual(list(Path(tmp).iterdir()), [])
                find_apktool.assert_not_called()
                which.assert_not_called()

    def test_patcher_tool_timeout_and_launch_error_are_contained(self):
        errors = (
            subprocess.TimeoutExpired(["keytool"], 30),
            OSError("executable disappeared"),
        )
        for error in errors:
            with self.subTest(error=type(error).__name__), mock.patch.object(
                analyzer.subprocess, "run", side_effect=error
            ), redirect_stdout(io.StringIO()) as output:
                result = analyzer._run_patcher_tool(
                    ["keytool", "--version"], 30, "keytool"
                )
            self.assertIsNone(result)
            self.assertIn("keytool", output.getvalue())

    def test_frida_keytool_timeout_returns_cleanly_and_removes_workdir(self):
        with tempfile.TemporaryDirectory() as tmp:
            local_apk = Path(tmp, f"{PACKAGE}.apk")
            with zipfile.ZipFile(local_apk, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"manifest")
            gadget = Path(tmp, "gadget.so")
            gadget.write_bytes(b"\x7fELF")

            def which(name):
                if name in ("apksigner", "keytool"):
                    return f"/tools/{name}"
                return None

            def run(args, **_kwargs):
                if args[0] == "apktool" and "d" in args:
                    output_dir = Path(args[args.index("-o") + 1])
                    Path(output_dir, "smali", "com", "example").mkdir(
                        parents=True
                    )
                    Path(output_dir, "AndroidManifest.xml").write_text(
                        "<manifest/>", encoding="utf-8"
                    )
                    Path(
                        output_dir, "smali", "com", "example", "Main.smali"
                    ).write_text(".class public Lcom/example/Main;", encoding="utf-8")
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                if args[0] == "apktool" and "b" in args:
                    Path(args[args.index("-o") + 1]).write_bytes(b"rebuilt")
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                if os.path.basename(args[0]) == "keytool":
                    raise subprocess.TimeoutExpired(args, 30)
                raise AssertionError(f"unexpected command: {args!r}")

            with mock.patch.object(
                analyzer.os, "getcwd", return_value=tmp
            ), mock.patch.object(
                analyzer, "get_apk_paths", return_value=[]
            ), mock.patch.object(
                analyzer, "_find_apktool", return_value=["apktool"]
            ), mock.patch.object(
                analyzer.shutil, "which", side_effect=which
            ), mock.patch.object(
                analyzer, "adb_shell", return_value="arm64-v8a"
            ), mock.patch.object(
                analyzer, "check_frida", return_value=(False, "")
            ), mock.patch.object(
                analyzer, "_find_local_apk", return_value=str(local_apk)
            ), mock.patch.object(
                analyzer, "_get_frida_gadget", return_value=str(gadget)
            ), mock.patch.object(
                analyzer, "_find_main_activity", return_value="com.example.Main"
            ), mock.patch.object(
                analyzer, "_patch_manifest_for_gadget", return_value=True
            ), mock.patch.object(
                analyzer, "_inject_gadget_loader", return_value=True
            ), mock.patch.object(
                analyzer.subprocess, "run", side_effect=run
            ), mock.patch.object(
                analyzer, "pause"
            ), redirect_stdout(io.StringIO()) as output:
                analyzer.frida_gadget_patch(PACKAGE)

            self.assertIn("keytool timed out", output.getvalue())
            self.assertFalse(Path(tmp, ".apkpatcher_work").exists())
            self.assertFalse(Path(tmp, "patched_apks", f"{PACKAGE}_gadget_patched.apk").exists())


if __name__ == "__main__":
    unittest.main()
