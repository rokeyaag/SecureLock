"""Automated tests for envelope encryption, password recovery, and reset features.
"""

import os
import sys
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.crypto import (
    encrypt_folder,
    decrypt_folder,
    reset_vault_password,
    peek_vault_info,
    InvalidPasswordError,
    InvalidRecoveryKeyError,
)
from core.quick_lock import (
    quick_lock_folder,
    quick_unlock_folder,
    quick_reset_password,
)


class TestFolderLockerRecovery(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="slock_rec_test_")
        self.sample_folder = os.path.join(self.test_dir, "ConfidentialFolder")
        os.makedirs(os.path.join(self.sample_folder, "nested"), exist_ok=True)

        self.file1 = os.path.join(self.sample_folder, "doc.txt")
        with open(self.file1, "w", encoding="utf-8") as f:
            f.write("Important private documents and sensitive information.")

        self.file2 = os.path.join(self.sample_folder, "nested", "sample.bin")
        self.binary_data = os.urandom(1024 * 64)  # 64 KB
        with open(self.file2, "wb") as f:
            f.write(self.binary_data)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_envelope_encryption_and_password_reset(self):
        initial_pwd = "InitialSecretPassword123"
        rec_key = "SLOCK-TEST-1234-ABCD-5678"

        # 1. Encrypt with recovery key
        vault_path, used_key = encrypt_folder(
            folder_path=self.sample_folder,
            password=initial_pwd,
            recovery_key=rec_key,
            delete_original=True,
        )
        self.assertTrue(os.path.isfile(vault_path))
        self.assertEqual(used_key, rec_key)

        # 2. Check metadata
        meta = peek_vault_info(vault_path)
        self.assertEqual(meta["folder_name"], "ConfidentialFolder")
        self.assertTrue(meta["has_recovery"])

        # 3. Verify wrong password fails
        with self.assertRaises(InvalidPasswordError):
            decrypt_folder(vault_path, password="WrongPassword!", delete_vault=False)

        # 4. Reset password using recovery key
        new_pwd = "NewlyResetPassword789"
        success = reset_vault_password(vault_path, rec_key, new_pwd)
        self.assertTrue(success)

        # 5. Old password must now fail
        with self.assertRaises(InvalidPasswordError):
            decrypt_folder(vault_path, password=initial_pwd, delete_vault=False)

        # 6. New password unlocks successfully
        restored = decrypt_folder(vault_path, password=new_pwd, destination_dir=self.test_dir, delete_vault=False)
        self.assertTrue(os.path.isdir(restored))

        with open(os.path.join(restored, "doc.txt"), "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), "Important private documents and sensitive information.")

        with open(os.path.join(restored, "nested", "sample.bin"), "rb") as f:
            self.assertEqual(f.read(), self.binary_data)

        shutil.rmtree(restored, ignore_errors=True)

        # 7. Test direct unlock with recovery key alone (without any password)
        restored2 = decrypt_folder(
            vault_path,
            recovery_secret=rec_key,
            destination_dir=self.test_dir,
            delete_vault=True
        )
        self.assertTrue(os.path.isdir(restored2))
        self.assertFalse(os.path.exists(vault_path))

    def test_security_question_recovery(self):
        pwd = "NormalUserPassword"
        question = "What is your childhood pet name?"
        answer = "Tommy"

        vault_path, _ = encrypt_folder(
            folder_path=self.sample_folder,
            password=pwd,
            security_question=question,
            security_answer=answer,
            delete_original=True,
        )

        meta = peek_vault_info(vault_path)
        self.assertEqual(meta["security_question"], question)

        # Wrong answer fails
        with self.assertRaises(InvalidRecoveryKeyError):
            decrypt_folder(vault_path, recovery_secret="Fluffy", delete_vault=False)

        # Correct answer unlocks (case-insensitive)
        restored = decrypt_folder(vault_path, recovery_secret="tommy", destination_dir=self.test_dir, delete_vault=True)
        self.assertTrue(os.path.isdir(restored))

    def test_quick_lock_reset_and_recovery(self):
        pwd = "OldQuickPassword"
        rec_key = "SLOCK-QUICK-RECOV-1234"

        locked_path, _ = quick_lock_folder(
            folder_path=self.sample_folder,
            password=pwd,
            recovery_key=rec_key,
        )

        # Reset password
        new_pwd = "BrandNewQuickPassword"
        reset_success = quick_reset_password(locked_path, rec_key, new_pwd)
        self.assertTrue(reset_success)

        # Unlock with new password
        restored = quick_unlock_folder(locked_path, password=new_pwd)
        self.assertTrue(os.path.isdir(restored))


if __name__ == "__main__":
    unittest.main()
