"""Cryptographic core for SecureLock.
Implements military-grade AES-256-GCM encryption with Envelope Encryption (DEK wrapping),
PBKDF2 key derivation, and dual-slot Emergency Recovery Key / Email / Security Question support.
"""

import os
import sys
import struct
import shutil
import tempfile
import zipfile
import secrets
from typing import Callable, Optional, Tuple, Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

MAGIC_BYTES = b"SLOCK3"
SALT_SIZE = 16
NONCE_BASE_SIZE = 4
NONCE_SIZE = 12
CHUNK_SIZE = 1024 * 1024  # 1MB per chunk
PBKDF2_ITERATIONS = 100_000

AAD_DEK_PWD = b"SLOCK_DEK_PWD"
AAD_DEK_REC = b"SLOCK_DEK_REC"


class CryptoError(Exception):
    """Base exception for crypto operations."""
    pass


class InvalidPasswordError(CryptoError):
    """Raised when password is incorrect or file is tampered."""
    pass


class InvalidRecoveryKeyError(CryptoError):
    """Raised when recovery code or security answer is incorrect."""
    pass


class InvalidVaultFileError(CryptoError):
    """Raised when file format is not a valid SecureLock vault."""
    pass


def generate_recovery_key() -> str:
    """Generates a human-friendly high-entropy emergency recovery key."""
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    blocks = ["".join(secrets.choice(chars) for _ in range(4)) for _ in range(4)]
    return "SLOCK-" + "-".join(blocks)


def normalize_recovery_key(key: str) -> str:
    """Normalizes recovery key for whitespace and casing."""
    return key.strip().upper().replace(" ", "")


def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 256-bit (32 bytes) encryption key from password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def _zip_directory(source_dir: str, zip_path: str, progress_callback: Optional[Callable[[float, str], None]] = None) -> int:
    """Compress source_dir into zip_path, returning total uncompressed bytes."""
    file_list = []
    total_uncompressed_bytes = 0

    for root, dirs, files in os.walk(source_dir):
        for file in files:
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, source_dir)
            try:
                size = os.path.getsize(full_path)
            except OSError:
                size = 0
            file_list.append((full_path, rel_path, size))
            total_uncompressed_bytes += size

    total_files = len(file_list)
    processed_files = 0

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for full_path, rel_path, size in file_list:
            if progress_callback and total_files > 0:
                pct = (processed_files / total_files) * 45.0
                progress_callback(pct, f"Archiving & compressing files ({processed_files}/{total_files})...")
            try:
                zipf.write(full_path, rel_path)
            except Exception as e:
                print(f"Warning: skipping {full_path}: {e}", file=sys.stderr)
            processed_files += 1

    return total_uncompressed_bytes


def encrypt_folder(
    folder_path: str,
    password: str,
    recovery_key: Optional[str] = None,
    recovery_email: Optional[str] = None,
    security_question: Optional[str] = None,
    security_answer: Optional[str] = None,
    output_vault_path: Optional[str] = None,
    delete_original: bool = True,
    progress_callback: Optional[Callable[[float, str], None]] = None,
) -> Tuple[str, str]:
    """
    Encrypts a folder into a .slock AES-256-GCM vault container using envelope encryption.
    Returns (vault_path, recovery_key_used).
    """
    folder_path = os.path.abspath(folder_path)
    if not os.path.isdir(folder_path):
        raise ValueError(f"Target is not a valid directory: {folder_path}")

    folder_name = os.path.basename(folder_path.rstrip("\\/"))
    if not folder_name:
        folder_name = "SecuredFolder"

    if output_vault_path is None:
        parent_dir = os.path.dirname(folder_path)
        output_vault_path = os.path.join(parent_dir, f"{folder_name}.slock")

    # Generate master Data Encryption Key (DEK)
    dek = os.urandom(32)
    dek_cipher = AESGCM(dek)

    # 1. Wrap DEK with User Password (Slot 0)
    salt_pwd = os.urandom(SALT_SIZE)
    nonce_pwd = os.urandom(NONCE_SIZE)
    kek_pwd = derive_key(password, salt_pwd)
    wrapped_dek_pwd = AESGCM(kek_pwd).encrypt(nonce_pwd, dek, AAD_DEK_PWD)

    # 2. Wrap DEK with Recovery Option (Slot 1)
    has_recovery = 0
    salt_rec = b"\x00" * SALT_SIZE
    nonce_rec = b"\x00" * NONCE_SIZE
    wrapped_dek_rec = b""

    final_recovery_key = recovery_key
    if not final_recovery_key and not security_answer:
        final_recovery_key = generate_recovery_key()

    recovery_secret = None
    if final_recovery_key:
        recovery_secret = normalize_recovery_key(final_recovery_key)
    elif security_answer:
        recovery_secret = security_answer.strip().lower()

    if recovery_secret:
        has_recovery = 1
        salt_rec = os.urandom(SALT_SIZE)
        nonce_rec = os.urandom(NONCE_SIZE)
        kek_rec = derive_key(recovery_secret, salt_rec)
        wrapped_dek_rec = AESGCM(kek_rec).encrypt(nonce_rec, dek, AAD_DEK_REC)

    # Prepare metadata fields
    question_bytes = (security_question.strip().encode("utf-8")) if security_question else b""
    if len(question_bytes) > 65535:
        question_bytes = question_bytes[:65535]

    email_bytes = (recovery_email.strip().encode("utf-8")) if recovery_email else b""
    if len(email_bytes) > 65535:
        email_bytes = email_bytes[:65535]

    encoded_name = folder_name.encode("utf-8")
    if len(encoded_name) > 65535:
        encoded_name = encoded_name[:65535]

    nonce_base = os.urandom(NONCE_BASE_SIZE)

    temp_zip = None
    temp_vault = None
    try:
        if progress_callback:
            progress_callback(5.0, "Preparing files for encryption...")

        temp_zip_fd, temp_zip = tempfile.mkstemp(prefix="slock_tmp_", suffix=".zip")
        os.close(temp_zip_fd)

        _zip_directory(folder_path, temp_zip, progress_callback)
        zip_size = os.path.getsize(temp_zip)

        if progress_callback:
            progress_callback(50.0, "Encrypting archive with AES-256-GCM...")

        temp_vault_fd, temp_vault = tempfile.mkstemp(prefix="slock_out_", suffix=".slock")
        os.close(temp_vault_fd)

        with open(temp_zip, "rb") as fin, open(temp_vault, "wb") as fout:
            # Construct SLOCK3 Header:
            # MAGIC (6) + NONCE_BASE (4)
            # Slot 0: SALT_PWD (16) + NONCE_PWD (12) + WRAPPED_LEN (2) + WRAPPED_DATA (N)
            # Slot 1: HAS_REC (1) + SALT_REC (16) + NONCE_REC (12) + WRAPPED_LEN (2) + WRAPPED_DATA (N)
            # META: Q_LEN (2) + Q_BYTES + EMAIL_LEN (2) + EMAIL_BYTES + NAME_LEN (2) + NAME_BYTES + CHUNK_SIZE (4)
            header = (
                MAGIC_BYTES +
                nonce_base +
                salt_pwd +
                nonce_pwd +
                struct.pack(">H", len(wrapped_dek_pwd)) +
                wrapped_dek_pwd +
                struct.pack(">B", has_recovery) +
                salt_rec +
                nonce_rec +
                struct.pack(">H", len(wrapped_dek_rec)) +
                wrapped_dek_rec +
                struct.pack(">H", len(question_bytes)) +
                question_bytes +
                struct.pack(">H", len(email_bytes)) +
                email_bytes +
                struct.pack(">H", len(encoded_name)) +
                encoded_name +
                struct.pack(">I", CHUNK_SIZE)
            )
            fout.write(header)

            chunk_idx = 0
            bytes_read = 0

            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    if chunk_idx == 0:
                        is_last = 1
                        nonce = nonce_base + struct.pack(">Q", chunk_idx)
                        aad = struct.pack(">QB", chunk_idx, is_last)
                        ciphertext = dek_cipher.encrypt(nonce, b"", aad)
                        fout.write(struct.pack(">QBI", chunk_idx, is_last, len(ciphertext)))
                        fout.write(ciphertext)
                    break

                bytes_read += len(chunk)
                next_byte = fin.read(1)
                if next_byte:
                    fin.seek(-1, os.SEEK_CUR)
                    is_last = 0
                else:
                    is_last = 1

                nonce = nonce_base + struct.pack(">Q", chunk_idx)
                aad = struct.pack(">QB", chunk_idx, is_last)
                ciphertext = dek_cipher.encrypt(nonce, chunk, aad)

                fout.write(struct.pack(">QBI", chunk_idx, is_last, len(ciphertext)))
                fout.write(ciphertext)

                chunk_idx += 1

                if progress_callback and zip_size > 0:
                    pct = 50.0 + (bytes_read / zip_size) * 45.0
                    progress_callback(pct, f"Encrypting data blocks ({int(bytes_read / (1024 * 1024))} MB)...")

                if is_last:
                    break

        if progress_callback:
            progress_callback(95.0, "Verifying vault file integrity...")

        if os.path.exists(output_vault_path):
            os.remove(output_vault_path)
        shutil.move(temp_vault, output_vault_path)
        temp_vault = None

        if delete_original:
            if progress_callback:
                progress_callback(98.0, "Securely removing unencrypted folder...")
            shutil.rmtree(folder_path, ignore_errors=False)

        if progress_callback:
            progress_callback(100.0, "Folder successfully locked!")

        return output_vault_path, final_recovery_key or ""

    finally:
        if temp_zip and os.path.exists(temp_zip):
            try:
                os.remove(temp_zip)
            except OSError:
                pass
        if temp_vault and os.path.exists(temp_vault):
            try:
                os.remove(temp_vault)
            except OSError:
                pass


def peek_vault_info(vault_path: str) -> Dict[str, Any]:
    """Reads vault header and returns metadata including security question and email if set."""
    if not os.path.isfile(vault_path):
        raise FileNotFoundError(f"Vault file not found: {vault_path}")

    with open(vault_path, "rb") as f:
        magic = f.read(6)
        if magic == MAGIC_BYTES:
            _ = f.read(4)  # nonce_base
            # Slot 0
            _ = f.read(16 + 12)
            len_pwd = struct.unpack(">H", f.read(2))[0]
            _ = f.read(len_pwd)
            # Slot 1
            has_rec = struct.unpack(">B", f.read(1))[0]
            _ = f.read(16 + 12)
            len_rec = struct.unpack(">H", f.read(2))[0]
            _ = f.read(len_rec)
            # Question
            q_len = struct.unpack(">H", f.read(2))[0]
            question = f.read(q_len).decode("utf-8", errors="replace")
            # Email
            email_len = struct.unpack(">H", f.read(2))[0]
            email = f.read(email_len).decode("utf-8", errors="replace")
            # Folder name
            name_len = struct.unpack(">H", f.read(2))[0]
            folder_name = f.read(name_len).decode("utf-8", errors="replace")

            return {
                "version": 3,
                "folder_name": folder_name,
                "has_recovery": bool(has_rec),
                "security_question": question,
                "recovery_email": email,
            }
        else:
            raise InvalidVaultFileError("Not a valid SecureLock vault file or unsupported version.")


def unwrap_dek(
    vault_file,
    password: Optional[str] = None,
    recovery_secret: Optional[str] = None
) -> Tuple[bytes, bytes, str, int]:
    """
    Unwraps and returns (DEK, nonce_base, folder_name, data_offset).
    Can unwrap using either password OR recovery_secret.
    """
    vault_file.seek(0)
    magic = vault_file.read(6)
    if magic != MAGIC_BYTES:
        raise InvalidVaultFileError("Invalid vault format or legacy version.")

    nonce_base = vault_file.read(NONCE_BASE_SIZE)

    # Read Slot 0 (Password)
    salt_pwd = vault_file.read(SALT_SIZE)
    nonce_pwd = vault_file.read(NONCE_SIZE)
    len_pwd = struct.unpack(">H", vault_file.read(2))[0]
    wrapped_dek_pwd = vault_file.read(len_pwd)

    # Read Slot 1 (Recovery)
    has_rec = struct.unpack(">B", vault_file.read(1))[0]
    salt_rec = vault_file.read(SALT_SIZE)
    nonce_rec = vault_file.read(NONCE_SIZE)
    len_rec = struct.unpack(">H", vault_file.read(2))[0]
    wrapped_dek_rec = vault_file.read(len_rec)

    # Read Question, Email & Name
    q_len = struct.unpack(">H", vault_file.read(2))[0]
    _ = vault_file.read(q_len)
    email_len = struct.unpack(">H", vault_file.read(2))[0]
    _ = vault_file.read(email_len)
    name_len = struct.unpack(">H", vault_file.read(2))[0]
    folder_name = vault_file.read(name_len).decode("utf-8", errors="replace")
    chunk_size = struct.unpack(">I", vault_file.read(4))[0]

    data_offset = vault_file.tell()
    dek = None

    if password is not None:
        kek_pwd = derive_key(password, salt_pwd)
        try:
            dek = AESGCM(kek_pwd).decrypt(nonce_pwd, wrapped_dek_pwd, AAD_DEK_PWD)
        except Exception:
            if recovery_secret is None:
                raise InvalidPasswordError("Incorrect password! Access denied.")

    if dek is None and recovery_secret is not None:
        if not has_rec or len_rec == 0:
            raise InvalidRecoveryKeyError("No recovery option was configured for this vault.")

        norm_key = normalize_recovery_key(recovery_secret)
        kek_rec = derive_key(norm_key, salt_rec)
        try:
            dek = AESGCM(kek_rec).decrypt(nonce_rec, wrapped_dek_rec, AAD_DEK_REC)
        except Exception:
            kek_answer = derive_key(recovery_secret.strip().lower(), salt_rec)
            try:
                dek = AESGCM(kek_answer).decrypt(nonce_rec, wrapped_dek_rec, AAD_DEK_REC)
            except Exception as e:
                raise InvalidRecoveryKeyError("Invalid recovery key or incorrect security answer!") from e

    if dek is None:
        raise InvalidPasswordError("Unable to decrypt vault with provided credentials.")

    return dek, nonce_base, folder_name, data_offset


def reset_vault_password(vault_path: str, recovery_secret: str, new_password: str) -> bool:
    """
    Instantly resets the password of a vault file in-place using the recovery secret.
    """
    if not os.path.isfile(vault_path):
        raise FileNotFoundError(f"Vault file not found: {vault_path}")

    with open(vault_path, "r+b") as f:
        dek, _, _, _ = unwrap_dek(f, recovery_secret=recovery_secret)

        new_salt_pwd = os.urandom(SALT_SIZE)
        new_nonce_pwd = os.urandom(NONCE_SIZE)
        new_kek_pwd = derive_key(new_password, new_salt_pwd)
        new_wrapped_dek_pwd = AESGCM(new_kek_pwd).encrypt(new_nonce_pwd, dek, AAD_DEK_PWD)

        f.seek(10)
        f.write(new_salt_pwd)
        f.write(new_nonce_pwd)
        f.write(struct.pack(">H", len(new_wrapped_dek_pwd)))
        f.write(new_wrapped_dek_pwd)
        f.flush()

    return True


def decrypt_folder(
    vault_path: str,
    password: Optional[str] = None,
    recovery_secret: Optional[str] = None,
    destination_dir: Optional[str] = None,
    delete_vault: bool = True,
    progress_callback: Optional[Callable[[float, str], None]] = None,
) -> str:
    """
    Decrypts a .slock vault file back into its original folder using password or recovery secret.
    Returns the restored folder path.
    """
    vault_path = os.path.abspath(vault_path)
    if not os.path.isfile(vault_path):
        raise FileNotFoundError(f"Vault file not found: {vault_path}")

    vault_size = os.path.getsize(vault_path)

    if progress_callback:
        progress_callback(5.0, "Validating vault container...")

    temp_zip = None
    try:
        with open(vault_path, "rb") as fin:
            if progress_callback:
                progress_callback(15.0, "Verifying credentials & unwrapping master key...")

            dek, nonce_base, orig_folder_name, data_offset = unwrap_dek(
                fin,
                password=password,
                recovery_secret=recovery_secret
            )

            dek_cipher = AESGCM(dek)
            fin.seek(data_offset)

            temp_zip_fd, temp_zip = tempfile.mkstemp(prefix="slock_dec_", suffix=".zip")
            os.close(temp_zip_fd)

            expected_idx = 0
            with open(temp_zip, "wb") as fout:
                while True:
                    chunk_meta = fin.read(13)
                    if not chunk_meta:
                        break
                    if len(chunk_meta) < 13:
                        raise InvalidVaultFileError("Unexpected end of file while reading chunk header.")

                    idx, is_last, payload_len = struct.unpack(">QBI", chunk_meta)
                    if idx != expected_idx:
                        raise InvalidVaultFileError(f"Chunk sequence mismatch: expected {expected_idx}, got {idx}")

                    ciphertext = fin.read(payload_len)
                    if len(ciphertext) < payload_len:
                        raise InvalidVaultFileError("Incomplete chunk data: file may be truncated.")

                    nonce = nonce_base + struct.pack(">Q", idx)
                    aad = struct.pack(">QB", idx, is_last)

                    try:
                        plaintext = dek_cipher.decrypt(nonce, ciphertext, aad)
                    except Exception as e:
                        raise CryptoError("Corrupted data: AES-GCM authentication failed.") from e

                    fout.write(plaintext)
                    expected_idx += 1

                    if progress_callback and vault_size > 0:
                        cur_pos = fin.tell()
                        pct = 15.0 + (cur_pos / vault_size) * 55.0
                        progress_callback(pct, f"Decrypting blocks ({int(cur_pos / (1024 * 1024))} MB)...")

                    if is_last:
                        break

        if destination_dir is None:
            destination_dir = os.path.dirname(vault_path)

        target_folder = os.path.join(destination_dir, orig_folder_name)

        if progress_callback:
            progress_callback(75.0, f"Extracting files into '{orig_folder_name}'...")

        if os.path.exists(target_folder):
            counter = 1
            while os.path.exists(f"{target_folder} ({counter})"):
                counter += 1
            target_folder = f"{target_folder} ({counter})"

        os.makedirs(target_folder, exist_ok=True)

        with zipfile.ZipFile(temp_zip, "r") as zipf:
            total_members = len(zipf.infolist())
            for idx, member in enumerate(zipf.infolist()):
                target_path = os.path.abspath(os.path.join(target_folder, member.filename))
                if not target_path.startswith(os.path.abspath(target_folder)):
                    raise CryptoError(f"Dangerous path traversal detected in archive: {member.filename}")

                zipf.extract(member, target_folder)

                if progress_callback and total_members > 0:
                    pct = 75.0 + (idx / total_members) * 20.0
                    progress_callback(pct, f"Extracting file {idx + 1}/{total_members}...")

        if delete_vault:
            if progress_callback:
                progress_callback(98.0, "Cleaning up encrypted vault file...")
            try:
                os.remove(vault_path)
            except OSError:
                pass

        if progress_callback:
            progress_callback(100.0, "Folder successfully unlocked & restored!")

        return target_folder

    finally:
        if temp_zip and os.path.exists(temp_zip):
            try:
                os.remove(temp_zip)
            except OSError:
                pass
