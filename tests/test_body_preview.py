import gzip
import unittest

from proxy_router.util import body_preview_for_record


class BodyPreviewForRecordTests(unittest.TestCase):
    def test_decodes_gzip_json_preview_before_redaction(self):
        body = gzip.compress(b'{"token":"secret-value","ok":true}')

        preview = body_preview_for_record(
            body,
            content_type="application/json",
            content_encoding="gzip",
            total_bytes=len(body),
        )

        self.assertTrue(preview["decoded"])
        self.assertEqual(preview["content_encoding"], "gzip")
        self.assertIn('"token":"<redacted>"', preview["text"])
        self.assertIn('"ok":true', preview["text"])

    def test_unsupported_encoded_text_body_is_omitted(self):
        preview = body_preview_for_record(
            b"not actually encoded",
            content_type="application/json",
            content_encoding="made-up",
        )

        self.assertIsNone(preview["text"])
        self.assertIn("unsupported content-encoding", preview["omitted_reason"])

    def test_binary_looking_textual_body_is_omitted(self):
        preview = body_preview_for_record(
            b"\x00\x01\x02\x03\x04\x05\x06\x07" * 16,
            content_type="application/json",
        )

        self.assertIsNone(preview["text"])
        self.assertEqual(preview["omitted_reason"], "binary content")


if __name__ == "__main__":
    unittest.main()
