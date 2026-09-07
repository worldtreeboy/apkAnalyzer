"""Ordinary file edits must not be reported as complete static coverage."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from apk_analyzer import code_scan, secrets


def read_secrets(path, **kwargs):
    return secrets.scan_file(path, lambda _text, _final: False, **kwargs)


class FileReadConsistencyTests(unittest.TestCase):
    readers = (code_scan.read_file, read_secrets)

    def test_unchanged_empty_and_exact_budget_files_are_complete(self):
        for reader in self.readers:
            for content in (b"", b"ordinary text"):
                with self.subTest(reader=reader.__name__, content=content), \
                        tempfile.TemporaryDirectory() as tmp:
                    path = Path(tmp, "source.txt")
                    path.write_bytes(content)
                    outcome = reader(path, max_bytes=len(content), chunk_bytes=3)
                    self.assertTrue(outcome.complete)
                    self.assertEqual(outcome.bytes_scanned, len(content))

    def test_changed_files_are_partial_even_when_the_read_reaches_eof(self):
        original = b"original text\n"
        for reader in self.readers:
            for replacement in (b"", b"modified text\n", original * 2):
                for budget in (len(original), len(original) * 3):
                    with self.subTest(reader=reader.__name__,
                                      replacement=replacement, budget=budget), \
                            tempfile.TemporaryDirectory() as tmp:
                        path = Path(tmp, "source.txt")
                        path.write_bytes(original)
                        real_fstat = os.fstat
                        edited = False

                        def edit_after_initial_stat(descriptor):
                            nonlocal edited
                            snapshot = real_fstat(descriptor)
                            if not edited:
                                edited = True
                                path.write_bytes(replacement)
                                # Ensure same-size edits are observable even
                                # on filesystems with coarse timestamp clocks.
                                changed_time = snapshot.st_mtime + 10
                                os.utime(path, (changed_time, changed_time))
                            return snapshot

                        with mock.patch.object(
                                os, "fstat", side_effect=edit_after_initial_stat):
                            outcome = reader(path, max_bytes=budget, chunk_bytes=3)

                        self.assertFalse(outcome.complete)
                        self.assertEqual(outcome.status, "partial")
                        self.assertLessEqual(outcome.bytes_scanned, budget)

    def test_tree_coverage_records_changed_file_as_partial(self):
        for module in (code_scan, secrets):
            with self.subTest(module=module.__name__), \
                    tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp, "source.txt")
                path.write_bytes(b"initial")
                real_fstat = os.fstat
                edited = False

                def edit_after_initial_stat(descriptor):
                    nonlocal edited
                    snapshot = real_fstat(descriptor)
                    if not edited:
                        edited = True
                        path.write_bytes(b"longer ordinary text")
                    return snapshot

                callback = (
                    (lambda _path, _text: None) if module is code_scan else
                    (lambda _text, _final: False)
                )
                with mock.patch.object(os, "fstat", side_effect=edit_after_initial_stat):
                    result = module.scan_tree(tmp, callback, extensions=(".txt",))

                self.assertFalse(result.coverage_complete)
                self.assertEqual(result.partial, ["source.txt"])

    def test_opened_file_must_match_the_discovered_file(self):
        for reader in self.readers:
            with self.subTest(reader=reader.__name__), \
                    tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp, "source.txt")
                path.write_bytes(b"ordinary text")
                with mock.patch.object(os.path, "samestat", return_value=False):
                    outcome = reader(path)
                self.assertFalse(outcome.opened)
                self.assertFalse(outcome.complete)
                self.assertEqual(outcome.status, "skipped")
                self.assertEqual(outcome.bytes_scanned, 0)

    def test_final_stat_failure_retains_evidence_but_is_incomplete(self):
        for module in (code_scan, secrets):
            with self.subTest(module=module.__name__), \
                    tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp, "source.txt")
                path.write_bytes(b"ordinary text")
                initial_stat = path.stat()
                with mock.patch.object(
                        os, "fstat", side_effect=[initial_stat, OSError("unavailable")]):
                    if module is code_scan:
                        outcome = module.read_file(path)
                    else:
                        outcome = module.scan_file(path, lambda _text, _final: True)
                self.assertFalse(outcome.complete)
                self.assertEqual(outcome.status, "unreadable")
                if module is code_scan:
                    self.assertEqual(outcome.content, "ordinary text")
                else:
                    self.assertTrue(outcome.matched)

    def test_final_secret_window_is_delivered_with_zero_overlap_at_exact_budget(self):
        for overlap in (0, 4):
            with self.subTest(overlap=overlap), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp, "source.txt")
                text = "ordinary café"
                content = text.encode("utf-8")
                path.write_bytes(content)
                windows = []

                def match_at_eof(window, final):
                    windows.append((window, final))
                    return final and window.endswith("café")

                outcome = secrets.scan_file(
                    path, match_at_eof, max_bytes=len(content),
                    chunk_bytes=len(content), overlap_chars=overlap,
                )

                self.assertTrue(outcome.matched)
                self.assertTrue(outcome.complete)
                self.assertEqual(windows[-1], (text, True))


if __name__ == "__main__":
    unittest.main()
