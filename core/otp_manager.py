"""OTP Management Service.
Generates, tracks, and verifies time-limited 6-digit one-time passwords for password reset.
"""

import time
import secrets
from typing import Dict, Any, Optional, Tuple

OTP_EXPIRY_SECONDS = 600  # 10 minutes
MAX_ATTEMPTS = 5

# In-memory session store
_active_otps: Dict[str, Dict[str, Any]] = {}


def generate_otp_code() -> str:
    """Generates a secure 6-digit random numeric OTP string."""
    return f"{secrets.randbelow(900000) + 100000}"


def create_otp(vault_path: str, recovery_secret: str, recipient_email: str = "") -> str:
    """
    Creates and stores an OTP mapped to the vault path and recovery secret.
    Returns the 6-digit OTP code.
    """
    path_key = vault_path.lower()
    otp_code = generate_otp_code()
    _active_otps[path_key] = {
        "otp_code": otp_code,
        "recovery_secret": recovery_secret,
        "recipient_email": recipient_email,
        "created_at": time.time(),
        "expires_at": time.time() + OTP_EXPIRY_SECONDS,
        "attempts": 0,
    }
    return otp_code


def verify_otp(vault_path: str, entered_code: str) -> Tuple[bool, Optional[str], str]:
    """
    Verifies the entered OTP for the vault.
    Returns (is_valid: bool, recovery_secret: Optional[str], message: str).
    """
    path_key = vault_path.lower()
    record = _active_otps.get(path_key)

    if not record:
        return False, None, "No active OTP session found! Please click 'Send OTP' first."

    # Check expiration
    if time.time() > record["expires_at"]:
        del _active_otps[path_key]
        return False, None, "OTP has expired! Please request a new code."

    # Rate limiting
    record["attempts"] += 1
    if record["attempts"] > MAX_ATTEMPTS:
        del _active_otps[path_key]
        return False, None, "Maximum verification attempts exceeded! Please request a new OTP."

    # Constant-time comparison
    if secrets.compare_digest(entered_code.strip(), record["otp_code"]):
        recovery_secret = record["recovery_secret"]
        del _active_otps[path_key]  # Invalidate immediately upon successful use
        return True, recovery_secret, "OTP verified successfully!"
    else:
        remaining = MAX_ATTEMPTS - record["attempts"]
        return False, None, f"Invalid OTP code! Remaining attempts: {remaining}."


def cancel_otp(vault_path: str) -> None:
    """Cancels active OTP for a vault."""
    path_key = vault_path.lower()
    _active_otps.pop(path_key, None)
