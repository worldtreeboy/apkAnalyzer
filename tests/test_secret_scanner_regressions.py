import tempfile
import time
import unittest
from pathlib import Path

import apkAnalyzer as analyzer


class SecretScannerRegressionTests(unittest.TestCase):
    def test_json_secret_with_spaces_is_detected_and_fully_redacted(self):
        content = '{"password": "correct horse battery staple"}'

        matches = analyzer._find_secret_matches(content)
        self.assertEqual(matches, ['"password": "correct horse battery staple"'])

        preview = analyzer._redact_sensitive_text(content)
        finding = analyzer._redact(matches[0])
        for fragment in ("correct", "horse", "battery", "staple"):
            self.assertNotIn(fragment, preview)
            self.assertNotIn(fragment, finding)
        self.assertEqual(preview, '{"password": "[REDACTED]"}')

    def test_shared_preferences_xml_secret_is_detected_and_fully_redacted(self):
        content = (
            '<map><string name="auth_token">'
            'violet apple river delta'
            '</string></map>'
        )

        matches = analyzer._find_secret_matches(content)
        self.assertEqual(
            matches,
            ['<string name="auth_token">violet apple river delta</string>'],
        )

        preview = analyzer._redact_sensitive_text(content)
        finding = analyzer._redact(matches[0])
        for fragment in ("violet", "apple", "river", "delta"):
            self.assertNotIn(fragment, preview)
            self.assertNotIn(fragment, finding)
        self.assertEqual(
            preview,
            '<map><string name="auth_token">[REDACTED]</string></map>',
        )

    def test_smali_string_field_redacts_initializer_not_type_descriptor(self):
        content = (
            '.field public static final API_KEY:Ljava/lang/String; = '
            '"synthetic-secret-value"'
        )

        self.assertEqual(analyzer._find_secret_matches(content), [content])
        redacted = analyzer._redact_sensitive_text(content)
        self.assertIn('API_KEY:Ljava/lang/String; = "[REDACTED]"', redacted)
        self.assertNotIn("synthetic-secret-value", redacted)

        non_string_fields = (
            ".field public static API_KEY:I = 7",
            ".field public static API_KEY:[Ljava/lang/String;",
        )
        for declaration in non_string_fields:
            with self.subTest(declaration=declaration):
                self.assertEqual(analyzer._find_secret_matches(declaration), [])

    def test_public_google_keys_and_twilio_sids_are_not_secret_matches(self):
        google_android_key = "AIza" + ("A" * 35)
        twilio_key_sid = "SK" + ("a" * 32)
        content = (
            f'{{"firebase_api_key": "{google_android_key}", '
            f'"twilio_api_key": "{twilio_key_sid}"}}\n'
            f'google_api_key={google_android_key}\n'
            f'twilio_api_key={twilio_key_sid}\n'
            f'key={google_android_key}'
        )

        self.assertEqual(analyzer._find_secret_matches(content), [])
        self.assertEqual(analyzer._redact_sensitive_text(content), content)

        actual_credential = "twilio_auth_token=" + ("b" * 32)
        self.assertEqual(
            analyzer._find_secret_matches(actual_credential),
            [actual_credential],
        )

    def test_public_account_identifiers_and_non_jwt_json_are_not_secrets(self):
        content = (
            "aws_access_key=AKIA" + ("A" * 16) + "\n"
            "twilio_account_sid=AC" + ("b" * 32) + "\n"
            "eyJ" + ("c" * 20)
        )

        self.assertEqual(analyzer._find_secret_matches(content), [])

        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.synthetic_signature"
        self.assertEqual(analyzer._find_secret_matches(jwt), [jwt])

    def test_azure_account_endpoint_without_key_is_not_a_secret(self):
        public_config = (
            "DefaultEndpointsProtocol=https;"
            "AccountName=publicstorage;EndpointSuffix=core.windows.net"
        )
        assigned_public = f'azure_connection_string="{public_config}"'
        self.assertEqual(analyzer._find_secret_matches(public_config), [])
        self.assertEqual(analyzer._find_secret_matches(assigned_public), [])

        credential = (
            "DefaultEndpointsProtocol=https;AccountName=publicstorage;"
            "AccountKey=synthetic-storage-secret-material;"
            "EndpointSuffix=core.windows.net"
        )
        self.assertTrue(analyzer._find_secret_matches(credential))
        self.assertNotIn(
            "synthetic-storage-secret-material",
            analyzer._redact_secret_text(credential),
        )

    def test_database_url_rule_is_linear_on_colon_heavy_malformed_input(self):
        valid = "mongodb://sample-user:sample-pass@example.invalid/app"
        self.assertIn(valid, analyzer._find_secret_matches(valid))

        malformed = "mongodb://" + ("segment:" * 15_000)
        started = time.perf_counter()
        self.assertEqual(analyzer._find_secret_matches(malformed), [])
        elapsed = time.perf_counter() - started
        self.assertLess(elapsed, 1.5)

    def test_complete_private_key_block_is_redacted(self):
        synthetic_body = "c3ludGhldGljLWtleS1tYXRlcmlhbA=="
        content = (
            "before\n"
            "-----BEGIN PRIVATE KEY-----\n"
            f"{synthetic_body}\n"
            "-----END PRIVATE KEY-----\n"
            "after"
        )

        matches = analyzer._find_secret_matches(content)
        self.assertEqual(len(matches), 1)
        redacted = analyzer._redact_sensitive_text(content)
        self.assertEqual(redacted, "before\n[REDACTED]\nafter")
        self.assertNotIn(synthetic_body, redacted)

        truncated = (
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
            f"{synthetic_body}"
        )
        self.assertEqual(
            analyzer._redact_sensitive_text(truncated), "[REDACTED]"
        )

    def test_static_secret_sources_include_manifest_smali_and_text_assets(self):
        names = (
            "AndroidManifest.xml",
            "classes.smali",
            "bundle.js",
            "index.bundle",
            "environment.env",
            "private.pem",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in names:
                path = root / name
                path.write_text("password=sample-value", encoding="utf-8")
                self.assertTrue(
                    analyzer._should_scan_static_secrets(path),
                    name,
                )

            unsupported = root / "image.png"
            unsupported.write_bytes(b"password=sample-value")
            self.assertFalse(analyzer._should_scan_static_secrets(unsupported))

            oversized = root / "oversized.smali"
            oversized.write_bytes(b"x" * 500_001)
            self.assertTrue(analyzer._should_scan_static_secrets(oversized))


if __name__ == "__main__":
    unittest.main()
