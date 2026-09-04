"""TOTP verified against the RFC 6238 Appendix B test vectors."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fyers_client.totp import (
    TotpError,
    decode_secret,
    generate_totp,
    seconds_remaining,
)

# RFC 6238 Appendix B: ASCII secret "12345678901234567890" in base32.
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
RFC_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


class TestRfc6238Vectors(unittest.TestCase):
    def test_eight_digit_vectors(self):
        for timestamp, expected in RFC_VECTORS:
            with self.subTest(t=timestamp):
                self.assertEqual(
                    generate_totp(RFC_SECRET, digits=8, at=timestamp), expected
                )

    def test_six_digit_codes_are_the_trailing_six(self):
        for timestamp, expected in RFC_VECTORS:
            with self.subTest(t=timestamp):
                self.assertEqual(
                    generate_totp(RFC_SECRET, digits=6, at=timestamp), expected[-6:]
                )

    def test_code_is_stable_within_a_window_and_changes_across_it(self):
        # 1111111110 and 1111111111 share window 37037037; 1111111109 is the
        # last second of the preceding one.
        self.assertEqual(
            generate_totp(RFC_SECRET, at=1111111110),
            generate_totp(RFC_SECRET, at=1111111111),
        )
        self.assertNotEqual(
            generate_totp(RFC_SECRET, at=1111111109),
            generate_totp(RFC_SECRET, at=1111111110),
        )


class TestSecretDecoding(unittest.TestCase):
    def test_tolerates_spaces_lowercase_and_missing_padding(self):
        canonical = decode_secret(RFC_SECRET)
        messy = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq"
        self.assertEqual(decode_secret(messy), canonical)
        self.assertEqual(decode_secret("GEZDGNBVGY3TQOJQ"), b"12345678901234567890"[:10])

    def test_rejects_empty_and_non_base32(self):
        for bad in ("", "   ", "not-base32-!!"):
            with self.assertRaises(TotpError):
                decode_secret(bad)

    def test_rejects_a_six_digit_code_mistaken_for_a_secret(self):
        with self.assertRaises(TotpError):
            decode_secret("419285")


class TestWindow(unittest.TestCase):
    def test_seconds_remaining_tracks_the_period(self):
        self.assertAlmostEqual(seconds_remaining(30, at=1000.0), 20.0, places=6)
        self.assertAlmostEqual(seconds_remaining(30, at=1019.5), 0.5, places=6)


if __name__ == "__main__":
    unittest.main(verbosity=2)
