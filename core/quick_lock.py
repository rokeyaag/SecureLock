"""Quick Lock module for instant locking of large folders on Windows.
Supports password verification, recovery key, recovery email, security question, and instant password reset.
"""

import os
import sys
import subprocess
import hashlib
import json
import ctypes
from typing import Optional, Tuple, Dict, Any

LOCK_CLSID = "{2559a1f2-21d7-11d4-bdaf-00c04f60b9f0}"
METADATA_FILENAME = ".slock_meta.json"


def _hash_secret(secret: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
    """Generates PBKDF2-SHA256 hex digest and salt."""
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, 100_000)
    return dk.hex(), salt.hex()


def _verify_secret(secret: str, stored_hash: str, salt_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, 100_000)
    return dk.hex() == stored_hash


def _run_attrib(args: list) -> bool:
    """Sets or clears attributes instantly using direct Windows Kernel32 API."""
    if sys.platform != "win32" or not args:
        return True
    try:
        target_path = os.path.abspath(args[-1])
        FILE_ATTRIBUTE_NORMAL = 0x80
        FILE_ATTRIBUTE_HIDDEN = 0x02
        FILE_ATTRIBUTE_SYSTEM = 0x04

        is_hide = any("+h" in arg or "+s" in arg for arg in args)
        if is_hide:
            ctypes.windll.kernel32.SetFileAttributesW(target_path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)
        else:
            ctypes.windll.kernel32.SetFileAttributesW(target_path, FILE_ATTRIBUTE_NORMAL)
        return True
    except Exception:
        try:
            # Fallback with safety timeout
            subprocess.run(
                ["attrib"] + args,
                check=False,
                capture_output=True,
                timeout=1.5,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            return True
        except Exception:
            return False


def quick_lock_folder(
    folder_path: str,
    password: str,
    recovery_key: Optional[str] = None,
    recovery_email: Optional[str] = None,
    security_question: Optional[str] = None,
    security_answer: Optional[str] = None,
) -> Tuple[str, str]:
    """
    Instantly locks a folder on Windows.
    Appends CLSID mask and applies system+hidden attributes.
    Returns (locked_path, recovery_key_used).
    """
    folder_path = os.path.abspath(folder_path)
    if not os.path.isdir(folder_path):
        raise ValueError(f"Path is not a directory: {folder_path}")

    folder_dir = os.path.dirname(folder_path)
    folder_name = os.path.basename(folder_path)

    pwd_hash, salt_pwd = _hash_secret(password)

    from core.crypto import generate_recovery_key, normalize_recovery_key
    final_rec_key = recovery_key
    if not final_rec_key and not security_answer:
        final_rec_key = generate_recovery_key()

    rec_hash = None
    rec_salt = None
    if final_rec_key:
        rec_hash, rec_salt = _hash_secret(normalize_recovery_key(final_rec_key))
    elif security_answer:
        rec_hash, rec_salt = _hash_secret(security_answer.strip().lower())

    meta = {
        "version": 2,
        "type": "quick_lock",
        "original_name": folder_name,
        "password_hash": pwd_hash,
        "salt": salt_pwd,
        "has_recovery": bool(rec_hash),
        "recovery_hash": rec_hash,
        "recovery_salt": rec_salt,
        "security_question": security_question or "",
        "recovery_email": recovery_email or "",
        "recovery_key_backup": final_rec_key or "",
    }

    meta_path = os.path.join(folder_path, METADATA_FILENAME)
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f)

    _run_attrib(["+h", "+s", meta_path])

    locked_name = f"{folder_name}.{LOCK_CLSID}"
    locked_path = os.path.join(folder_dir, locked_name)

    if os.path.exists(locked_path):
        raise FileExistsError(f"Locked folder destination already exists: {locked_path}")

    os.rename(folder_path, locked_path)
    _run_attrib(["+h", "+s", locked_path])

    return locked_path, final_rec_key or ""


def peek_quick_lock_meta(locked_path: str) -> Dict[str, Any]:
    """Reads metadata from quick-locked folder."""
    _run_attrib(["-h", "-s", locked_path])
    meta_path = os.path.join(locked_path, METADATA_FILENAME)
    _run_attrib(["-h", "-s", meta_path])

    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        return meta
    finally:
        _run_attrib(["+h", "+s", meta_path])
        _run_attrib(["+h", "+s", locked_path])


def quick_reset_password(locked_path: str, recovery_secret: str, new_password: str) -> bool:
    """Resets password of quick-locked folder using recovery key or security answer."""
    locked_path = os.path.abspath(locked_path)
    _run_attrib(["-h", "-s", locked_path])
    meta_path = os.path.join(locked_path, METADATA_FILENAME)
    _run_attrib(["-h", "-s", meta_path])

    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        rec_hash = meta.get("recovery_hash")
        rec_salt = meta.get("recovery_salt")

        if not rec_hash or not rec_salt:
            raise ValueError("No recovery option configured for this folder.")

        from core.crypto import normalize_recovery_key
        matched = _verify_secret(normalize_recovery_key(recovery_secret), rec_hash, rec_salt)
        if not matched:
            matched = _verify_secret(recovery_secret.strip().lower(), rec_hash, rec_salt)

        if not matched:
            raise ValueError("Invalid recovery key or security answer!")

        new_pwd_hash, new_salt = _hash_secret(new_password)
        meta["password_hash"] = new_pwd_hash
        meta["salt"] = new_salt

        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f)

        return True
    finally:
        _run_attrib(["+h", "+s", meta_path])
        _run_attrib(["+h", "+s", locked_path])


def quick_unlock_folder(
    locked_path: str,
    password: Optional[str] = None,
    recovery_secret: Optional[str] = None
) -> str:
    """
    Unlocks a quick-locked folder using password or recovery secret.
    Returns restored original folder path.
    """
    locked_path = os.path.abspath(locked_path)
    if not os.path.exists(locked_path):
        raise FileNotFoundError(f"Locked folder not found: {locked_path}")

    _run_attrib(["-h", "-s", locked_path])

    meta_path = os.path.join(locked_path, METADATA_FILENAME)
    _run_attrib(["-h", "-s", meta_path])

    if not os.path.exists(meta_path):
        _run_attrib(["+h", "+s", locked_path])
        raise ValueError("Invalid locked folder: missing SecureLock metadata.")

    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    stored_pwd_hash = meta.get("password_hash")
    salt_pwd = meta.get("salt")
    rec_hash = meta.get("recovery_hash")
    rec_salt = meta.get("recovery_salt")
    orig_name = meta.get("original_name")

    authenticated = False

    if password and stored_pwd_hash and salt_pwd:
        if _verify_secret(password, stored_pwd_hash, salt_pwd):
            authenticated = True

    if not authenticated and recovery_secret and rec_hash and rec_salt:
        from core.crypto import normalize_recovery_key
        if _verify_secret(normalize_recovery_key(recovery_secret), rec_hash, rec_salt):
            authenticated = True
        elif _verify_secret(recovery_secret.strip().lower(), rec_hash, rec_salt):
            authenticated = True

    if not authenticated:
        _run_attrib(["+h", "+s", meta_path])
        _run_attrib(["+h", "+s", locked_path])
        raise ValueError("Incorrect password or recovery key! Access denied.")

    _run_attrib(["-h", "-s", meta_path])
    try:
        os.remove(meta_path)
    except OSError:
        pass

    folder_dir = os.path.dirname(locked_path)
    restored_path = os.path.join(folder_dir, orig_name)

    if os.path.exists(restored_path):
        counter = 1
        while os.path.exists(f"{restored_path} ({counter})"):
            counter += 1
        restored_path = f"{restored_path} ({counter})"

    os.rename(locked_path, restored_path)
    _run_attrib(["-h", "-s", restored_path])

    return restored_path
