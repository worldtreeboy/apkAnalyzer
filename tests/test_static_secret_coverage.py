import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import apkAnalyzer as analyzer
from apk_analyzer import secrets


ANDROID_NS = "http://schemas.android.com/apk/res/android"


def write_safe_manifest(root):
    Path(root, "AndroidManifest.xml").write_text(
        f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ANDROID_NS}" package="com.example.coverage">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/>
  <application android:debuggable="false" android:allowBackup="false"
               android:usesCleartextTraffic="false"/>
</manifest>''',
        encoding="utf-8",
    )


def run_security_scan(root, collector):
    output = io.StringIO()
    patches = (
        mock.patch.object(
            analyzer, "_pull_and_decompile", return_value=(root, root)
        ),
        mock.patch.object(analyzer, "detect_framework", return_value={}),
        mock.patch.object(analyzer, "_print_framework_info"),
        mock.patch.object(analyzer, "_find_local_apk", return_value=None),
        mock.patch.object(analyzer, "_print_security_classes"),
        mock.patch.object(analyzer, "_check_security_classes", return_value=[]),
        mock.patch.object(analyzer, "_scan_native_strings", return_value=[]),
        mock.patch.object(analyzer, "pause"),
        mock.patch.object(analyzer, "report", collector),
    )
    with patches[0], patches[1], patches[2], patches[3], patches[4], \
            patches[5], patches[6], patches[7], patches[8], \
            redirect_stdout(output):
        analyzer.security_scan("com.example.coverage")
    return analyzer._terminal_safe(output.getvalue())


class StaticSecretCoverageTests(unittest.TestCase):
    def test_credential_like_filename_is_redacted_from_output_and_report(self):
        filename_secret = "synthetic-filename-credential-123456"
        with tempfile.TemporaryDirectory() as tmp:
            write_safe_manifest(tmp)
            Path(tmp, f"password={filename_secret}.txt").write_text(
                "api_key=synthetic-content-credential-654321",
                encoding="utf-8",
            )
            collector = analyzer.ReportCollector()
            rendered = run_security_scan(tmp, collector)

        self.assertNotIn(filename_secret, rendered)
        self.assertTrue(collector.findings)
        self.assertTrue(all(
            filename_secret not in finding["description"]
            for finding in collector.findings
        ))

    def test_credential_like_coverage_path_is_redacted_in_json(self):
        filename_secret = "abcdefghijklmnopqrstuvwx"
        with tempfile.TemporaryDirectory() as tmp:
            write_safe_manifest(tmp)
            Path(tmp, f"api_key={filename_secret}.txt").write_text(
                "ordinary content", encoding="utf-8"
            )
            collector = analyzer.ReportCollector()
            with mock.patch.object(
                    analyzer, "STATIC_SECRET_MAX_FILE_BYTES", 0):
                run_security_scan(tmp, collector)
            output = Path(tmp, "coverage.json")
            collector.export_json(output)
            rendered = output.read_text(encoding="utf-8")

        self.assertNotIn(filename_secret, rendered)
        self.assertIn("[REDACTED]", rendered)

    def test_large_react_native_bundle_match_crosses_chunk_boundary(self):
        chunk_bytes = 128 * 1024
        secret = b"password=synthetic-boundary-credential\n"
        # Begin the key four bytes before the boundary. Neither independent
        # chunk contains the whole assignment, so overlap is required.
        prefix = (b"x" * (chunk_bytes - 5)) + b"\n"
        minimum_size = 500_001
        suffix = b"x" * (minimum_size - len(prefix) - len(secret) + 1)

        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp, "index.android.bundle")
            bundle.write_bytes(prefix + secret + suffix)
            file_size = bundle.stat().st_size

            result = analyzer._scan_static_secret_tree(
                tmp,
                chunk_bytes=chunk_bytes,
                overlap_chars=128,
            )

        self.assertGreater(file_size, 500_000)
        self.assertEqual(result.matches, ["index.android.bundle"])
        self.assertTrue(result.coverage_complete)
        self.assertEqual(result.bytes_scanned, file_size)

    def test_public_identifier_split_at_boundary_is_not_a_secret(self):
        chunk_bytes = 64
        public_key = b"AIza" + (b"A" * 35)
        assignment = b"google_api_key=" + public_key + b"\n"
        # End the first read within the value. The scanner must wait for the
        # rest of the identifier before applying the public-ID exclusion.
        prefix_size = chunk_bytes - len(b"google_api_key=AIzaAAAA")
        payload = (b"x" * (prefix_size - 1)) + b"\n" + assignment

        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "config.bundle").write_bytes(payload)
            result = analyzer._scan_static_secret_tree(
                tmp,
                chunk_bytes=chunk_bytes,
                overlap_chars=64,
            )

        self.assertEqual(result.matches, [])
        self.assertTrue(result.coverage_complete)

    def test_per_file_budget_is_partial_and_never_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "large.bundle").write_bytes(
                b"x" * 80 + b"\npassword=outside-budget\n" + b"x" * 80
            )

            result = analyzer._scan_static_secret_tree(
                tmp,
                max_file_bytes=64,
                max_total_bytes=1024,
                chunk_bytes=32,
                overlap_chars=32,
            )

        self.assertEqual(result.matches, [])
        self.assertEqual(result.partial, ["large.bundle"])
        self.assertEqual(result.oversized, ["large.bundle"])
        self.assertEqual(result.bytes_scanned, 64)
        self.assertFalse(result.coverage_complete)

    def test_total_budget_accounts_for_partial_and_skipped_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("a.txt", "b.txt", "c.txt"):
                Path(root, name).write_bytes(b"x" * 64)

            result = analyzer._scan_static_secret_tree(
                tmp,
                max_file_bytes=100,
                max_total_bytes=80,
                chunk_bytes=16,
                overlap_chars=16,
            )

        self.assertEqual(result.bytes_scanned, 80)
        self.assertEqual(result.scanned, ["a.txt", "b.txt"])
        self.assertEqual(result.partial, ["b.txt"])
        self.assertEqual(result.skipped, ["c.txt"])
        self.assertEqual(result.oversized, [])
        self.assertFalse(result.coverage_complete)

    def test_unreadable_candidate_is_exposed(self):
        with tempfile.TemporaryDirectory() as tmp:
            blocked = Path(tmp, "blocked.bundle")
            blocked.write_text("ordinary text", encoding="utf-8")
            real_open = os.open

            def deny_blocked(path, flags, *args, **kwargs):
                if os.path.abspath(os.fspath(path)) == str(blocked):
                    raise PermissionError("synthetic denial")
                return real_open(path, flags, *args, **kwargs)

            with mock.patch.object(secrets.os, "open", side_effect=deny_blocked):
                result = analyzer._scan_static_secret_tree(tmp)

        self.assertEqual(result.unreadable, ["blocked.bundle"])
        self.assertFalse(result.coverage_complete)
        self.assertEqual(result.to_report_dict()["unreadable_count"], 1)

    def test_missing_root_is_incomplete_instead_of_empty_clean_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp, "missing-decompile")
            result = analyzer._scan_static_secret_tree(missing)

        self.assertEqual(result.unreadable, ["."])
        self.assertFalse(result.coverage_complete)

    def test_symlinked_candidate_directory_is_explicitly_skipped(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links are unavailable")
        with tempfile.TemporaryDirectory() as tmp, \
                tempfile.TemporaryDirectory() as external:
            Path(external, "index.bundle").write_text(
                "password=synthetic-external-value", encoding="utf-8"
            )
            linked = Path(tmp, "assets")
            try:
                linked.symlink_to(external, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symbolic links are unavailable: {exc}")

            result = analyzer._scan_static_secret_tree(tmp)

        self.assertEqual(result.matches, [])
        self.assertEqual(result.skipped, ["assets"])
        self.assertFalse(result.coverage_complete)

    def test_unreadable_candidate_makes_data_leakage_inconclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_safe_manifest(tmp)
            blocked = Path(tmp, "blocked.bundle")
            blocked.write_text("ordinary text", encoding="utf-8")
            real_open = os.open

            def deny_blocked(path, flags, *args, **kwargs):
                if os.path.abspath(os.fspath(path)) == str(blocked):
                    raise PermissionError("synthetic denial")
                return real_open(path, flags, *args, **kwargs)

            collector = analyzer.ReportCollector()
            with mock.patch.object(
                    secrets.os, "open", side_effect=deny_blocked):
                rendered = run_security_scan(tmp, collector)

        self.assertIn("[INCONCLUSIVE] Data leakage", rendered)
        self.assertNotIn("[PASS] Data leakage", rendered)
        self.assertIn("Overall: INCONCLUSIVE", rendered)
        self.assertIn(
            {"check_id": "static_secret_coverage", "reason": "1 unreadable"},
            collector.inconclusive,
        )

    def test_total_budget_skip_makes_data_leakage_inconclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_safe_manifest(tmp)
            Path(tmp, "index.bundle").write_text(
                "ordinary text", encoding="utf-8"
            )
            collector = analyzer.ReportCollector()
            with mock.patch.object(
                    analyzer, "STATIC_SECRET_MAX_TOTAL_BYTES", 0):
                rendered = run_security_scan(tmp, collector)

        self.assertIn("[INCONCLUSIVE] Data leakage", rendered)
        self.assertNotIn("[PASS] Data leakage", rendered)
        self.assertIn("skipped", rendered)
        self.assertFalse(
            collector.app_info["static_secret_scan_coverage"]
            ["coverage_complete"]
        )


if __name__ == "__main__":
    unittest.main()
