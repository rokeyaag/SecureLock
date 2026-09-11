"""OTP Management Service.
Generates, tracks, and verifies time-limited 6-digit one-time passwords for password reset.
Persists sessions across restarts and allows unexpired codes within window.
"""

import os
import json
import time
import secrets
from typing import Dict, Any, Optional, Tuple

OTP_EXPIRY_SECONDS = 600  # 10 minutes
MAX_ATTEMPTS = 5

CONFIG_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "SecureLock")
OTP_CACHE_FILE = os.path.join(CONFIG_DIR, "otp_sessions.json")


def _load_sessions() -> Dict[str, Dict[str, Any]]:
    if not os.path.isfile(OTP_CACHE_FILE):
        return {}
    try:
        with open(OTP_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            now = time.time()
            return {k: v for k, v in data.items() if v.get("expires_at", 0) > now}
    except Exception:
        return {}


def _save_sessions(sessions: Dict[str, Dict[str, Any]]) -> None:
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        now = time.time()
        active = {k: v for k, v in sessions.items() if v.get("expires_at", 0) > now}
        with open(OTP_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(active, f, indent=2)
    except Exception:
        pass


def generate_otp_code() -> str:
    """Generates a secure 6-digit random numeric OTP string."""
    return f"{secrets.randbelow(900000) + 100000}"


def create_otp(vault_path: str, recovery_secret: str, recipient_email: str = "") -> str:
    """
    Creates and stores an OTP mapped to the vault path and recovery secret.
    If an active OTP was generated less than 60s ago and not expired, reuses it.
    Also retains recent valid codes so any unexpired code received by email is accepted.
    Returns the 6-digit OTP code.
    """
    sessions = _load_sessions()
    path_key = vault_path.lower()
    existing = sessions.get(path_key)
    now = time.time()

    # If active OTP was created less than 60s ago and not expired, reuse it
    if existing and (now - existing.get("created_at", 0) < 60) and (now < existing.get("expires_at", 0)):
        return existing["otp_code"]

    otp_code = generate_otp_code()
    prev_codes = []
    if existing:
        prev_codes = [existing["otp_code"]] + existing.get("previous_codes", [])
        prev_codes = prev_codes[:5]

    sessions[path_key] = {
        "otp_code": otp_code,
        "previous_codes": prev_codes,
        "recovery_secret": recovery_secret,
        "recipient_email": recipient_email,
        "created_at": now,
        "expires_at": now + OTP_EXPIRY_SECONDS,
        "attempts": 0,
    }
    _save_sessions(sessions)
    return otp_code


def verify_otp(vault_path: str, entered_code: str) -> Tuple[bool, Optional[str], str]:
    """
    Verifies the entered OTP for the vault.
    Accepts the current OTP or any previous valid unexpired OTP from this session.
    Returns (is_valid: bool, recovery_secret: Optional[str], message: str).
    """
    sessions = _load_sessions()
    path_key = vault_path.lower()
    record = sessions.get(path_key)

    if not record:
        return False, None, "No active OTP session found! Please click 'Send OTP' first."

    # Check expiration
    if time.time() > record["expires_at"]:
        sessions.pop(path_key, None)
        _save_sessions(sessions)
        return False, None, "OTP has expired! Please request a new code."

    # Rate limiting
    record["attempts"] = record.get("attempts", 0) + 1
    if record["attempts"] > MAX_ATTEMPTS:
        sessions.pop(path_key, None)
        _save_sessions(sessions)
        return False, None, "Maximum verification attempts exceeded! Please request a new OTP."

    entered_clean = entered_code.strip()
    valid_codes = [record["otp_code"]] + record.get("previous_codes", [])

    matched = any(secrets.compare_digest(entered_clean, c) for c in valid_codes)
    if matched:
        recovery_secret = record["recovery_secret"]
        sessions.pop(path_key, None)  # Invalidate immediately upon successful use
        _save_sessions(sessions)
        return True, recovery_secret, "OTP verified successfully!"
    else:
        _save_sessions(sessions)
        remaining = MAX_ATTEMPTS - record["attempts"]
        return False, None, f"Invalid OTP code! Remaining attempts: {remaining}."


def cancel_otp(vault_path: str) -> None:
    """Cancels active OTP for a vault."""
    sessions = _load_sessions()
    path_key = vault_path.lower()
    if path_key in sessions:
        sessions.pop(path_key, None)
        _save_sessions(sessions)
