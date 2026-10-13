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
            import stat
            try:
                os.chmod(target_path, stat.S_IWRITE)
            except Exception:
                pass
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


def _close_explorer_for_path(target_path: str, close_all: bool = False):
    """Automatically closes any Windows File Explorer windows that are viewing target_path or Home tab."""
    if sys.platform != "win32" or not target_path:
        return
    try:
        norm = os.path.abspath(target_path).replace("\\", "/").rstrip("/").lower()
        target_url = f"file:///{norm}"
        base_name = os.path.basename(norm).lower()
        if close_all:
            ps_script = (
                "$shell = New-Object -ComObject Shell.Application\n"
                "foreach ($win in $shell.Windows()) {\n"
                "    try { $win.Quit() } catch {}\n"
                "}\n"
            )
        else:
            ps_script = (
                "$shell = New-Object -ComObject Shell.Application\n"
                f"$target = '{target_url}'\n"
                f"$baseName = '{base_name}'\n"
                "foreach ($win in $shell.Windows()) {\n"
                "    try {\n"
                "        $loc = if ($win.LocationURL) { $win.LocationURL.TrimEnd('/').ToLower() } else { '' }\n"
                "        $name = if ($win.LocationName) { $win.LocationName.ToLower() } else { '' }\n"
                "        if ($loc.Contains($baseName) -or $loc -eq $target -or $name -eq $baseName -or $name -eq 'home' -or $loc -eq '') {\n"
                "            $win.Quit()\n"
                "        }\n"
                "    } catch {}\n"
                "}\n"
            )
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True,
            timeout=2.5,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
    except Exception:
        pass


def quick_lock_folder(
    folder_path: str,
    password: str,
    recovery_key: Optional[str] = None,
    recovery_email: Optional[str] = None,
    security_question: Optional[str] = None,
    security_answer: Optional[str] = None,
) -> Tuple[str, str]:
    """
    Instantly locks a folder or file on Windows.
    Appends CLSID mask and applies system+hidden attributes.
    Returns (locked_path, recovery_key_used).
    """
    target_path = os.path.abspath(folder_path)
    if not os.path.exists(target_path):
        raise ValueError(f"Path does not exist: {target_path}")

    drive, rest = os.path.splitdrive(target_path)
    if not rest.strip("\\/"):
        raise ValueError("Cannot lock an entire drive root (e.g., C:\\ or D:\\). Please select a specific folder or file inside the drive.")

    is_file = os.path.isfile(target_path)
    folder_dir = os.path.dirname(target_path)
    folder_name = os.path.basename(target_path.rstrip("\\/"))
    if not folder_name:
        raise ValueError("Invalid name.")

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
        "is_file": is_file,
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

    if is_file:
        meta_path = os.path.join(folder_dir, f".{folder_name}.slock_meta.json")
    else:
        meta_path = os.path.join(target_path, METADATA_FILENAME)

    # Bulletproof handling: force normal attributes before attempting write/delete
    if sys.platform == "win32":
        try:
            ctypes.windll.kernel32.SetFileAttributesW(meta_path, 0x80)  # FILE_ATTRIBUTE_NORMAL
        except Exception:
            pass

    if os.path.exists(meta_path):
        _run_attrib(["-h", "-s", meta_path])
        import stat
        try:
            os.chmod(meta_path, stat.S_IWRITE | stat.S_IREAD)
        except Exception:
            pass
        try:
            os.remove(meta_path)
        except Exception:
            pass

    try:
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f)
    except PermissionError:
        if sys.platform == "win32":
            try:
                ctypes.windll.kernel32.SetFileAttributesW(meta_path, 0x80)
            except Exception:
                pass
        _run_attrib(["-h", "-s", meta_path])
        import stat
        try:
            os.chmod(meta_path, stat.S_IWRITE | stat.S_IREAD)
        except Exception:
            pass
        try:
            os.remove(meta_path)
        except Exception:
            pass
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f)

    _run_attrib(["+h", "+s", meta_path])

    locked_name = f"{folder_name}.{LOCK_CLSID}"
    locked_path = os.path.join(folder_dir, locked_name)

    if os.path.exists(locked_path):
        raise FileExistsError(f"Locked destination already exists: {locked_path}")

    # Automatically close any Windows Explorer windows viewing this folder or Home tab
    _close_explorer_for_path(target_path, close_all=False)

    # Retry mechanism with handle garbage collection for Windows locks
    import time
    import gc
    renamed = False
    last_err = None
    for attempt in range(6):
        try:
            gc.collect()
            os.rename(target_path, locked_path)
            renamed = True
            break
        except (PermissionError, OSError) as e:
            last_err = e
            # On retry attempt >= 1, close all explorer windows to release any handles
            if attempt >= 1:
                _close_explorer_for_path(target_path, close_all=True)
            time.sleep(0.4)

    if not renamed:
        try:
            if os.path.exists(meta_path):
                _run_attrib(["-h", "-s", meta_path])
                os.remove(meta_path)
        except Exception:
            pass
        raise PermissionError(
            f"Cannot lock '{folder_name}'. It or a file inside is currently open in Windows Explorer "
            f"or another program. Please close any open explorer windows or applications using it and try again."
        ) from last_err

    _run_attrib(["+h", "+s", locked_path])

    return locked_path, final_rec_key or ""


def _get_meta_path(locked_path: str) -> str:
    """Finds metadata path for either a locked folder or a locked file."""
    # First check directory style
    dir_meta = os.path.join(locked_path, METADATA_FILENAME)
    if os.path.exists(dir_meta):
        return dir_meta
    # Check file style
    folder_dir = os.path.dirname(locked_path)
    clean_base = os.path.basename(locked_path).replace(f".{LOCK_CLSID}", "")
    file_meta = os.path.join(folder_dir, f".{clean_base}.slock_meta.json")
    if os.path.exists(file_meta):
        return file_meta
    return dir_meta


def peek_quick_lock_meta(locked_path: str) -> Dict[str, Any]:
    """Reads metadata from quick-locked folder or file."""
    _run_attrib(["-h", "-s", locked_path])
    meta_path = _get_meta_path(locked_path)
    _run_attrib(["-h", "-s", meta_path])

    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        return meta
    finally:
        _run_attrib(["+h", "+s", meta_path])
        _run_attrib(["+h", "+s", locked_path])


def quick_reset_password(locked_path: str, recovery_secret: str, new_password: str) -> bool:
    """Resets password of quick-locked folder or file using recovery key or security answer."""
    locked_path = os.path.abspath(locked_path)
    _run_attrib(["-h", "-s", locked_path])
    meta_path = _get_meta_path(locked_path)
    _run_attrib(["-h", "-s", meta_path])

    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        rec_hash = meta.get("recovery_hash")
        rec_salt = meta.get("recovery_salt")

        if not rec_hash or not rec_salt:
            raise ValueError("No recovery option configured for this item.")

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
    Unlocks a quick-locked folder or file using password or recovery secret.
    Returns restored original path.
    """
    locked_path = os.path.abspath(locked_path)
    if not os.path.exists(locked_path):
        raise FileNotFoundError(f"Locked item not found: {locked_path}")

    _run_attrib(["-h", "-s", locked_path])

    meta_path = _get_meta_path(locked_path)
    _run_attrib(["-h", "-s", meta_path])

    if not os.path.exists(meta_path):
        _run_attrib(["+h", "+s", locked_path])
        raise ValueError("Invalid locked item: missing SecureLock metadata.")

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
        base, ext = os.path.splitext(orig_name)
        while os.path.exists(os.path.join(folder_dir, f"{base} ({counter}){ext}")):
            counter += 1
        restored_path = os.path.join(folder_dir, f"{base} ({counter}){ext}")

    _close_explorer_for_path(locked_path, close_all=False)

    import time
    import gc
    unlocked = False
    last_err = None
    for attempt in range(6):
        try:
            gc.collect()
            os.rename(locked_path, restored_path)
            unlocked = True
            break
        except (PermissionError, OSError) as e:
            last_err = e
            if attempt >= 1:
                _close_explorer_for_path(locked_path, close_all=True)
            time.sleep(0.4)

    if not unlocked:
        _run_attrib(["+h", "+s", locked_path])
        raise PermissionError(
            f"Cannot unlock '{orig_name}'. The locked item is in use by Windows Explorer or another app. "
            f"Please close any open explorer windows and try again."
        ) from last_err

    _run_attrib(["-h", "-s", restored_path])

    return restored_path
