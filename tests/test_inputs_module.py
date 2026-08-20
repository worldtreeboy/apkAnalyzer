import io
import os
import subprocess
import tempfile
import types
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

from apk_analyzer import inputs


def write_apk(path, extra=None, compression=zipfile.ZIP_STORED):
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        for name, value in (extra or {}).items():
            archive.writestr(name, value)


def apk_bytes(extra=None):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        for name, value in (extra or {}).items():
            archive.writestr(name, value)
    return output.getvalue()


class InputModuleTests(unittest.TestCase):
    def test_rejects_windows_reparse_point_directory_before_descent(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            junction = source / "junction"
            junction.mkdir(parents=True)
            write_apk(junction / "outside.apk")
            real_lstat = os.lstat
            reparse_flag = getattr(
                inputs.stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
            )

            def simulated_lstat(path, *args, **kwargs):
                result = real_lstat(path, *args, **kwargs)
                absolute_path = None
                if not args and not kwargs and not isinstance(path, int):
                    absolute_path = os.path.abspath(os.fspath(path))
                if absolute_path == str(junction):
                    return types.SimpleNamespace(
                        st_mode=result.st_mode,
                        st_file_attributes=reparse_flag,
                    )
                return result

            with mock.patch.object(
                    inputs.os, "lstat", side_effect=simulated_lstat):
                with self.assertRaisesRegex(
                        inputs.InputPreparationError, "reparse-point"):
                    inputs.collect_apk_inputs(source, root / "stage")

    def test_rejects_symlinked_file_root_and_nested_directory(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links are unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            real_apk = root / "real.apk"
            write_apk(real_apk)
            linked_apk = root / "linked.apk"
            linked_root = root / "linked-root"
            real_dir = root / "real-dir"
            real_dir.mkdir()
            nested_real = root / "nested-real"
            nested_real.mkdir()
            write_apk(nested_real / "split.apk")
            try:
                linked_apk.symlink_to(real_apk)
                linked_root.symlink_to(real_dir, target_is_directory=True)
                (real_dir / "linked-child").symlink_to(
                    nested_real, target_is_directory=True
                )
            except OSError as exc:
                self.skipTest(f"symbolic links are unavailable: {exc}")

            for source in (linked_apk, linked_root, real_dir):
                with self.subTest(source=source), self.assertRaisesRegex(
                        inputs.InputPreparationError, "symlinked"):
                    inputs.collect_apk_inputs(source, root / (source.name + "-stage"))

    def test_rejects_symlinked_staging_before_filesystem_probe_or_write(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links are unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "input.apk"
            outside = root / "outside"
            outside.mkdir()
            staging = root / "staging-link"
            write_apk(source)
            try:
                staging.symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symbolic links are unavailable: {exc}")

            with mock.patch.object(
                    inputs, "filesystem_is_case_sensitive") as probe:
                with self.assertRaisesRegex(
                        inputs.InputPreparationError, "staging.*link"):
                    inputs.collect_apk_inputs(source, staging)

            probe.assert_not_called()
            self.assertEqual(list(outside.iterdir()), [])

    def test_preflight_rejects_traversal_duplicates_symlinks_and_bombs(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            traversal = root / "traversal.apk"
            with zipfile.ZipFile(traversal, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"manifest")
                archive.writestr("../outside", b"bad")
            with self.assertRaisesRegex(
                    inputs.InputPreparationError, "unsafe ZIP member"):
                inputs.preflight_zip(traversal, require_apk_manifest=True)

            duplicate = root / "duplicate.apk"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(duplicate, "w") as archive:
                    archive.writestr("AndroidManifest.xml", b"one")
                    archive.writestr("AndroidManifest.xml", b"two")
            with self.assertRaisesRegex(
                    inputs.InputPreparationError, "duplicate"):
                inputs.preflight_zip(duplicate, require_apk_manifest=True)

            symlink = root / "symlink.apk"
            with zipfile.ZipFile(symlink, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"manifest")
                link = zipfile.ZipInfo("assets/link")
                link.create_system = 3
                link.external_attr = 0o120777 << 16
                archive.writestr(link, b"target")
            with self.assertRaisesRegex(
                    inputs.InputPreparationError, "symlink"):
                inputs.preflight_zip(symlink, require_apk_manifest=True)

            bomb = root / "bomb.apk"
            write_apk(
                bomb,
                {"assets/zeros": b"0" * (1024 * 1024)},
                compression=zipfile.ZIP_DEFLATED,
            )
            strict = inputs.ArchiveLimits(max_compression_ratio=10.0)
            with self.assertRaisesRegex(
                    inputs.InputPreparationError, "compression ratio"):
                inputs.preflight_zip(
                    bomb, limits=strict, require_apk_manifest=True
                )

    def test_preflight_rejects_terminal_controls_in_member_names(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            apk = Path(temp_dir, "terminal-control.apk")
            write_apk(
                apk,
                {"unknown/evil\x1b]52;c;payload\x07.smali": b"code"},
            )

            with self.assertRaisesRegex(
                    inputs.InputPreparationError, "control character"):
                inputs.preflight_zip(apk, require_apk_manifest=True)

    def test_preflight_rejects_crc_corrupted_member_payload(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            apk = Path(temp_dir, "corrupted.apk")
            marker = b"unique-payload-for-crc-regression"
            write_apk(apk, {"assets/payload.bin": marker})

            contents = bytearray(apk.read_bytes())
            payload_offset = contents.index(marker)
            contents[payload_offset] ^= 0x01
            apk.write_bytes(contents)

            with self.assertRaisesRegex(
                    inputs.InputPreparationError, "invalid or unreadable ZIP"):
                inputs.preflight_zip(apk, require_apk_manifest=True)

    def test_preflight_bounds_central_directory_and_member_names(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            apk = root / "metadata.apk"
            write_apk(apk, {"assets/value.txt": b"value"})
            tiny_central = inputs.ArchiveLimits(
                max_central_directory_bytes=8
            )
            with self.assertRaisesRegex(
                    inputs.InputPreparationError, "central directory"):
                inputs.preflight_zip(
                    apk, limits=tiny_central, require_apk_manifest=True
                )

            long_name = root / "long-name.apk"
            write_apk(long_name, {"assets/" + ("a" * 5000): b"value"})
            with self.assertRaisesRegex(
                    inputs.InputPreparationError, "name exceeds"):
                inputs.preflight_zip(
                    long_name, require_apk_manifest=True
                )

    def test_preflight_honors_destination_case_sensitivity(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            apk = Path(temp_dir, "case.apk")
            write_apk(apk, {"assets/A": b"one", "assets/a": b"two"})

            inputs.preflight_zip(
                apk, require_apk_manifest=True, case_sensitive=True
            )
            with self.assertRaisesRegex(
                    inputs.InputPreparationError, "duplicate"):
                inputs.preflight_zip(
                    apk, require_apk_manifest=True, case_sensitive=False
                )

    def test_preflight_rejects_explicit_file_directory_conflicts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            for entries in (
                (("AndroidManifest.xml", b"manifest"), ("assets/a", b"x"),
                 ("assets/a/", b"")),
                (("AndroidManifest.xml", b"manifest"), ("assets/a/", b""),
                 ("assets/a", b"x")),
            ):
                apk = Path(temp_dir, "conflict.apk")
                with zipfile.ZipFile(apk, "w") as archive:
                    for name, value in entries:
                        archive.writestr(name, value)
                with self.assertRaisesRegex(
                        inputs.InputPreparationError, "conflicting"):
                    inputs.preflight_zip(apk, require_apk_manifest=True)

    def test_preflight_models_windows_name_collisions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            trailing = Path(temp_dir, "trailing.apk")
            write_apk(trailing, {"assets/name": b"one", "assets/name.": b"two"})
            with self.assertRaisesRegex(
                    inputs.InputPreparationError, "duplicate"):
                inputs.preflight_zip(
                    trailing,
                    require_apk_manifest=True,
                    case_sensitive=False,
                    windows_paths=True,
                )

            reserved = Path(temp_dir, "reserved.apk")
            write_apk(reserved, {"assets/CON.txt": b"bad"})
            with self.assertRaisesRegex(
                    inputs.InputPreparationError, "reserved Windows"):
                inputs.preflight_zip(
                    reserved,
                    require_apk_manifest=True,
                    case_sensitive=False,
                    windows_paths=True,
                )

    def test_collects_directory_splits_and_chooses_base(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "input with spaces"
            source.mkdir()
            base = source / "base.apk"
            split = source / "split_config.arm64_v8a.apk"
            write_apk(base)
            write_apk(split, {"lib/arm64-v8a/libsample.so": b"elf"})

            result = inputs.collect_apk_inputs(source, root / "stage")
            self.assertEqual(result.input_kind, "directory")
            self.assertEqual(result.source_path, str(source))
            self.assertIn(result.base_apk, result.apk_paths)
            self.assertEqual(len(result.apk_paths), 2)
            self.assertTrue(all(
                str(root / "stage") in path for path in result.apk_paths
            ))
            self.assertTrue(all(
                path not in (str(base), str(split))
                for path in result.apk_paths
            ))
            self.assertTrue(result.variant_union)

    def test_direct_apk_replacement_after_preflight_cannot_reach_apktool(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "selected app.apk"
            write_apk(source, {"assets/marker.txt": b"original"})
            seen_apk_paths = []

            def apktool_runner(args, **kwargs):
                source.write_bytes(b"external replacement")
                apk_path = args[-1]
                seen_apk_paths.append(apk_path)
                self.assertNotEqual(apk_path, str(source))
                with zipfile.ZipFile(apk_path) as archive:
                    self.assertEqual(
                        archive.read("assets/marker.txt"), b"original"
                    )
                output = Path(args[args.index("-o") + 1])
                output.mkdir(parents=True)
                return subprocess.CompletedProcess(args, 0)

            prepared = inputs.prepare_local_input(
                source,
                root / "work",
                ["apktool"],
                runner=apktool_runner,
            )

            self.assertEqual(prepared.source_path, str(source))
            self.assertEqual(prepared.apk_paths, tuple(seen_apk_paths))
            self.assertTrue(Path(prepared.base_apk).is_file())
            self.assertTrue(prepared.decompiled_dir.endswith("decompiled"))

    def test_directory_apks_are_snapshotted_before_any_apktool_call(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "splits"
            source.mkdir()
            base = source / "base.apk"
            feature = source / "feature.apk"
            write_apk(base, {"assets/marker.txt": b"base-original"})
            write_apk(feature, {"assets/marker.txt": b"feature-original"})
            seen = []

            def apktool_runner(args, **kwargs):
                if not seen:
                    base.write_bytes(b"replaced base")
                    feature.write_bytes(b"replaced feature")
                apk_path = args[-1]
                seen.append(apk_path)
                self.assertNotIn(apk_path, (str(base), str(feature)))
                with zipfile.ZipFile(apk_path) as archive:
                    self.assertIn(
                        archive.read("assets/marker.txt"),
                        (b"base-original", b"feature-original"),
                    )
                output = Path(args[args.index("-o") + 1])
                output.mkdir(parents=True)
                return subprocess.CompletedProcess(args, 0)

            prepared = inputs.prepare_local_input(
                source,
                root / "work",
                ["apktool"],
                runner=apktool_runner,
            )

            self.assertEqual(len(seen), 2)
            self.assertEqual(set(prepared.apk_paths), set(seen))
            self.assertEqual(prepared.source_path, str(source))

    def test_apks_uses_snapshot_if_original_is_replaced_after_preflight(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "selected.apks"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr(
                    "universal.apk",
                    apk_bytes({"assets/marker.txt": b"original"}),
                )
            original_preflight = inputs.preflight_zip
            replaced = False

            def preflight_then_replace(path, **kwargs):
                nonlocal replaced
                result = original_preflight(path, **kwargs)
                if (not replaced
                        and os.path.basename(os.fspath(path)) == "source.apks"):
                    source.write_bytes(b"external replacement")
                    replaced = True
                return result

            with mock.patch.object(
                    inputs, "preflight_zip", side_effect=preflight_then_replace):
                result = inputs.collect_apk_inputs(source, root / "stage")

            self.assertTrue(replaced)
            self.assertNotEqual(result.apk_paths[0], str(source))
            with zipfile.ZipFile(result.apk_paths[0]) as archive:
                self.assertEqual(
                    archive.read("assets/marker.txt"), b"original"
                )

    def test_rejects_path_replacement_between_lstat_and_open(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "race.apk"
            replacement = root / "replacement.apk"
            write_apk(source, {"assets/value": b"first"})
            write_apk(replacement, {"assets/value": b"second"})
            real_open = os.open
            swapped = False

            def racing_open(path, flags, *args, **kwargs):
                nonlocal swapped
                if (not swapped
                        and os.path.abspath(os.fspath(path)) == str(source)):
                    os.replace(replacement, source)
                    swapped = True
                return real_open(path, flags, *args, **kwargs)

            with mock.patch.object(inputs.os, "open", side_effect=racing_open):
                with self.assertRaisesRegex(
                        inputs.InputPreparationError, "changed.*opened"):
                    inputs.collect_apk_inputs(source, root / "stage")

            self.assertTrue(swapped)
            self.assertEqual(
                list((root / "stage").glob(".input-snapshot-*")), []
            )

    def test_rejects_directory_root_replacement_before_snapshot(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "selected"
            replacement = root / "replacement"
            displaced = root / "displaced"
            source.mkdir()
            replacement.mkdir()
            write_apk(source / "base.apk", {"assets/value": b"selected"})
            write_apk(
                replacement / "base.apk", {"assets/value": b"replacement"}
            )
            real_make_private = inputs._make_private_snapshot_dir
            swapped = False

            def make_private_then_swap(staging):
                nonlocal swapped
                snapshot = real_make_private(staging)
                os.replace(source, displaced)
                os.replace(replacement, source)
                swapped = True
                return snapshot

            with mock.patch.object(
                    inputs,
                    "_make_private_snapshot_dir",
                    side_effect=make_private_then_swap):
                with self.assertRaisesRegex(
                        inputs.InputPreparationError,
                        "directory changed before"):
                    inputs.collect_apk_inputs(source, root / "stage")

            self.assertTrue(swapped)
            self.assertEqual(
                list((root / "stage").glob(".input-snapshot-*")), []
            )

    def test_windows_snapshot_protection_does_not_set_readonly_attribute(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir, "snapshot.apk")
            artifact.write_bytes(b"value")
            with mock.patch.object(inputs.os, "name", "nt"), \
                    mock.patch.object(inputs.os, "chmod") as chmod:
                inputs._make_snapshot_read_only(artifact)
            chmod.assert_not_called()

    def test_path_fallback_also_snapshots_directory_apks(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "splits"
            source.mkdir()
            original = source / "base.apk"
            write_apk(original, {"assets/value": b"stable"})

            with mock.patch.object(
                    inputs,
                    "_directory_fd_traversal_supported",
                    return_value=False):
                result = inputs.collect_apk_inputs(source, root / "stage")

            self.assertEqual(result.source_path, str(source))
            self.assertNotEqual(result.base_apk, str(original))
            with zipfile.ZipFile(result.base_apk) as archive:
                self.assertEqual(archive.read("assets/value"), b"stable")

    def test_multi_apk_directory_requires_a_recognizable_unique_base(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "renamed-splits"
            source.mkdir()
            write_apk(source / "aaa-feature-renamed.apk")
            write_apk(source / "zzz-base-renamed.apk")

            with self.assertRaisesRegex(
                    inputs.InputPreparationError, "unique base APK"):
                inputs.collect_apk_inputs(source, root / "stage")

    def test_apks_prefers_universal_and_rejects_bad_nested_apk(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            container = root / "sample.apks"
            with zipfile.ZipFile(container, "w") as archive:
                archive.writestr("splits/base-master.apk", apk_bytes())
                archive.writestr("universal/universal.apk", apk_bytes({
                    "classes.dex": b"dex",
                }))

            result = inputs.collect_apk_inputs(container, root / "stage")
            self.assertEqual(result.input_kind, "apks")
            self.assertEqual(len(result.apk_paths), 2)
            self.assertIn(result.base_apk, result.apk_paths)
            with zipfile.ZipFile(result.base_apk) as base_archive:
                self.assertIn("classes.dex", base_archive.namelist())
            self.assertTrue(result.variant_union)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            container = root / "bad.apks"
            with zipfile.ZipFile(container, "w") as archive:
                archive.writestr("splits/base-master.apk", b"not a zip")
            with self.assertRaises(inputs.InputPreparationError):
                inputs.collect_apk_inputs(container, root / "stage")
            self.assertFalse((root / "stage" / "apk-set-members").exists())

    def test_apks_counts_ignored_variants_before_universal_selection(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            container = root / "too-many.apks"
            with zipfile.ZipFile(container, "w") as archive:
                archive.writestr("universal/universal.apk", apk_bytes())
                archive.writestr("variants/other.apk", apk_bytes())

            limits = inputs.ArchiveLimits(max_apk_count=1)
            with self.assertRaisesRegex(
                    inputs.InputPreparationError, "too many APKs"):
                inputs.collect_apk_inputs(
                    container, root / "stage", limits=limits
                )

    def test_decompile_is_argument_list_split_aware_and_atomic(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base = root / "base app.apk"
            split = root / "feature;name.apk"
            write_apk(base)
            write_apk(split)
            apk_input = inputs.ApkInputSet(
                str(root), "directory", (str(base), str(split)), str(base), True
            )
            calls = []

            def successful_runner(args, **kwargs):
                calls.append(args)
                output = Path(args[args.index("-o") + 1])
                output.mkdir(parents=True)
                (output / "AndroidManifest.xml").write_text(
                    "<manifest/>", encoding="utf-8"
                )
                return subprocess.CompletedProcess(args, 0)

            destination = root / "decoded output"
            split_dirs = inputs.decompile_apk_inputs(
                apk_input,
                destination,
                ["java", "-jar", "/tools/apk tool.jar"],
                runner=successful_runner,
            )

            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[0][-1], str(base))
            self.assertEqual(calls[1][-1], str(split))
            self.assertIn("--frame-path", calls[0])
            self.assertEqual(
                calls[0][calls[0].index("--frame-path") + 1],
                calls[1][calls[1].index("--frame-path") + 1],
            )
            self.assertTrue(destination.is_dir())
            self.assertEqual(len(split_dirs), 1)
            self.assertTrue(Path(split_dirs[0]).is_dir())

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base = root / "base.apk"
            split = root / "split.apk"
            write_apk(base)
            write_apk(split)
            apk_input = inputs.ApkInputSet(
                str(root), "directory", (str(base), str(split)), str(base), True
            )
            call_count = 0

            def failing_runner(args, **kwargs):
                nonlocal call_count
                call_count += 1
                output = Path(args[args.index("-o") + 1])
                output.mkdir(parents=True)
                return subprocess.CompletedProcess(args, 0 if call_count == 1 else 7)

            destination = root / "decoded"
            with self.assertRaisesRegex(
                    inputs.InputPreparationError, "exit code 7"):
                inputs.decompile_apk_inputs(
                    apk_input, destination, ["apktool"], runner=failing_runner
                )
            self.assertFalse(destination.exists())
            self.assertEqual(
                list(root.glob(".apkanalyzer-decompile-*")), []
            )

    def test_decompile_timeout_is_explicit_and_leaves_no_partial_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            apk = root / "base.apk"
            write_apk(apk)
            apk_input = inputs.ApkInputSet(
                str(apk), "apk", (str(apk),), str(apk)
            )

            def timeout_runner(args, **kwargs):
                raise subprocess.TimeoutExpired(args, kwargs["timeout"])

            destination = root / "decoded"
            with self.assertRaisesRegex(
                    inputs.InputPreparationError, "timed out"):
                inputs.decompile_apk_inputs(
                    apk_input,
                    destination,
                    ["apktool"],
                    runner=timeout_runner,
                )

            self.assertFalse(destination.exists())
            self.assertEqual(
                list(root.glob(".apkanalyzer-decompile-*")), []
            )

    def test_aab_requires_bundletool_and_passes_paths_as_arguments(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            aab = root / "app bundle.aab"
            with zipfile.ZipFile(aab, "w") as archive:
                archive.writestr("BundleConfig.pb", b"config")
                archive.writestr(
                    "base/manifest/AndroidManifest.xml", b"manifest"
                )

            with self.assertRaisesRegex(
                    inputs.InputPreparationError, "bundletool is required"):
                inputs.collect_apk_inputs(aab, root / "missing-tool")

            calls = []

            def bundletool_runner(args, **kwargs):
                calls.append(args)
                source_argument = next(
                    value for value in args if value.startswith("--bundle=")
                ).split("=", 1)[1]
                self.assertNotEqual(source_argument, str(aab))
                with zipfile.ZipFile(source_argument) as snapshot:
                    self.assertIn("BundleConfig.pb", snapshot.namelist())
                # _validate_aab has completed before bundletool runs. Replacing
                # the external selection here must not change the tool input.
                aab.write_bytes(b"external replacement")
                output_arg = next(
                    value for value in args if value.startswith("--output=")
                )
                output = Path(output_arg.split("=", 1)[1])
                with zipfile.ZipFile(output, "w") as archive:
                    archive.writestr("universal.apk", apk_bytes())
                return subprocess.CompletedProcess(args, 0)

            result = inputs.collect_apk_inputs(
                aab,
                root / "with tool",
                bundletool_command=["java", "-jar", "/tools/bundle tool.jar"],
                runner=bundletool_runner,
            )

            self.assertEqual(result.input_kind, "aab")
            self.assertEqual(len(result.apk_paths), 1)
            self.assertEqual(calls[0][:3], [
                "java", "-jar", "/tools/bundle tool.jar",
            ])
            bundle_argument = next(
                value for value in calls[0] if value.startswith("--bundle=")
            ).split("=", 1)[1]
            self.assertNotEqual(bundle_argument, str(aab))
            self.assertTrue(bundle_argument.startswith(str(root / "with tool")))


if __name__ == "__main__":
    unittest.main()
