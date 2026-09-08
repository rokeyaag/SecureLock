"""Automated tests for OTP generation, expiration, rate limiting, and verification.
"""

import os
import sys
import unittest
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.otp_manager import create_otp, verify_otp, cancel_otp
from core.email_service import mask_email


class TestOTPManager(unittest.TestCase):
    def test_otp_creation_and_successful_verification(self):
        vault_path = "C:\\test\\secret.slock"
        recovery_secret = "SLOCK-RECOV-SECRET-KEY"

        # 1. Create OTP
        otp_code = create_otp(vault_path, recovery_secret, "user@example.com")
        self.assertEqual(len(otp_code), 6)
        self.assertTrue(otp_code.isdigit())

        # 2. Verify with correct OTP
        valid, secret, msg = verify_otp(vault_path, otp_code)
        self.assertTrue(valid)
        self.assertEqual(secret, recovery_secret)

        # 3. OTP should be single-use (cannot be used again)
        valid_again, _, _ = verify_otp(vault_path, otp_code)
        self.assertFalse(valid_again)

    def test_wrong_otp_and_rate_limiting(self):
        vault_path = "C:\\test\\ratelimit.slock"
        recovery_secret = "SLOCK-RECOV-RATELIMIT"

        otp_code = create_otp(vault_path, recovery_secret)

        # Try 5 wrong codes
        for attempt in range(1, 6):
            valid, _, msg = verify_otp(vault_path, "000000")
            self.assertFalse(valid)

        # 6th attempt should be blocked due to rate limit
        valid, _, msg = verify_otp(vault_path, otp_code)
        self.assertFalse(valid)
        self.assertIn("সীমা", msg)

    def test_mask_email(self):
        self.assertEqual(mask_email("john@gmail.com"), "j**n@gmail.com")
        self.assertEqual(mask_email("a@b.com"), "a*@b.com")
        self.assertEqual(mask_email("rahim@outlook.com"), "r***m@outlook.com")


if __name__ == "__main__":
    unittest.main()
