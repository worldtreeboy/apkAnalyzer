import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from apk_analyzer import safety


class XmlSafetyTests(unittest.TestCase):
    def test_regular_unicode_xml_is_supported_across_encodings(self):
        for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
            with self.subTest(encoding=encoding), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp, "values.xml")
                path.write_bytes(
                    '<resources><string name="label">雪</string></resources>'
                    .encode(encoding)
                )
                root = safety.safe_parse_xml(path).getroot()
                self.assertEqual(root.find("string").text, "雪")

    def test_doctype_is_rejected_across_encodings(self):
        for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
            with self.subTest(encoding=encoding), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp, "values.xml")
                path.write_bytes('<!DOCTYPE resources><resources/>'.encode(encoding))
                with self.assertRaisesRegex(ValueError, "DTD/entity"):
                    safety.safe_parse_xml(path)

    def test_declaration_like_literal_text_is_not_a_doctype(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "values.xml")
            path.write_text(
                '<resources><!-- documentation: <!DOCTYPE resources> -->'
                '<string name="example"><![CDATA[<!ENTITY example>]]></string>'
                '</resources>', encoding="utf-8",
            )
            root = safety.safe_parse_xml(path).getroot()
            self.assertEqual(root.find("string").text, "<!ENTITY example>")

    def test_size_limit_is_still_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "values.xml")
            path.write_text("<resources/>", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "byte safety limit"):
                safety.safe_parse_xml(path, max_bytes=4)

    def test_xml_changed_during_read_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "values.xml")
            path.write_bytes(b"<resources/>")
            real_fstat = os.fstat
            edited = False

            def edit_after_initial_stat(descriptor):
                nonlocal edited
                snapshot = real_fstat(descriptor)
                if not edited:
                    edited = True
                    path.write_bytes(b"<resources><bool name='enabled'>true</bool></resources>")
                return snapshot

            with mock.patch.object(os, "fstat", side_effect=edit_after_initial_stat):
                with self.assertRaisesRegex(ValueError, "changed during read"):
                    safety.safe_parse_xml(path)


if __name__ == "__main__":
    unittest.main()
