"""Vault Registry to track and manage all locked folders and containers.
"""

import os
import json
import uuid
import datetime
from typing import List, Dict, Any, Optional

REGISTRY_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "SecureLock")
REGISTRY_FILE = os.path.join(REGISTRY_DIR, "registry.json")


def _ensure_registry_dir():
    os.makedirs(REGISTRY_DIR, exist_ok=True)


def load_vaults() -> List[Dict[str, Any]]:
    """Loads all vault records and updates status based on disk existence."""
    _ensure_registry_dir()
    if not os.path.isfile(REGISTRY_FILE):
        return []

    try:
        with open(REGISTRY_FILE, "r", encoding="utf-8") as f:
            vaults = json.load(f)
            if not isinstance(vaults, list):
                return []
    except Exception:
        return []

    updated = False
    for v in vaults:
        lpath = v.get("locked_path", "")
        exists = os.path.exists(lpath)
        if v.get("exists") != exists:
            v["exists"] = exists
            updated = True

    if updated:
        save_vaults(vaults)

    return vaults


def save_vaults(vaults: List[Dict[str, Any]]) -> None:
    """Saves the vault list to disk."""
    _ensure_registry_dir()
    with open(REGISTRY_FILE, "w", encoding="utf-8") as f:
        json.dump(vaults, f, indent=2)


def add_vault(
    name: str,
    lock_type: str,
    original_path: str,
    locked_path: str,
    size_bytes: int = 0,
    has_recovery: bool = False,
    security_question: str = "",
    recovery_email: str = "",
    recovery_key: str = "",
) -> Dict[str, Any]:
    """Adds a new locked vault record."""
    vaults = load_vaults()
    vaults = [v for v in vaults if os.path.abspath(v.get("locked_path", "")) != os.path.abspath(locked_path)]

    record = {
        "id": str(uuid.uuid4()),
        "name": name,
        "type": lock_type,
        "original_path": os.path.abspath(original_path),
        "locked_path": os.path.abspath(locked_path),
        "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "size_bytes": size_bytes,
        "has_recovery": has_recovery,
        "security_question": security_question,
        "recovery_email": recovery_email,
        "recovery_key": recovery_key,
        "exists": True,
    }
    vaults.append(record)
    save_vaults(vaults)
    return record


def remove_vault_by_path(locked_path: str) -> None:
    """Removes a vault record by locked path."""
    vaults = load_vaults()
    target = os.path.abspath(locked_path)
    vaults = [v for v in vaults if os.path.abspath(v.get("locked_path", "")) != target]
    save_vaults(vaults)


def get_vault_by_path(path: str) -> Optional[Dict[str, Any]]:
    """Finds a vault record matching the path."""
    vaults = load_vaults()
    target = os.path.abspath(path)
    for v in vaults:
        if os.path.abspath(v.get("locked_path", "")) == target or os.path.abspath(v.get("original_path", "")) == target:
            return v
    return None
