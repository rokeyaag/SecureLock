"""Command Line Interface for SecureLock.
Allows locking, unlocking, and resetting passwords directly from PowerShell or Command Prompt.
"""

import os
import sys
import argparse
import getpass
from core.crypto import (
    encrypt_folder,
    decrypt_folder,
    reset_vault_password,
    InvalidPasswordError,
    InvalidRecoveryKeyError,
)
from core.quick_lock import (
    quick_lock_folder,
    quick_unlock_folder,
    quick_reset_password,
)
from core.vault_registry import load_vaults, add_vault, remove_vault_by_path


def run_cli():
    parser = argparse.ArgumentParser(
        description="SecureLock - Advanced Windows Folder Locker & Vault CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Lock Command
    lock_parser = subparsers.add_parser("lock", help="Lock and secure a folder")
    lock_parser.add_argument("folder", help="Path to the folder to lock")
    lock_parser.add_argument("-p", "--password", help="Password for locking")
    lock_parser.add_argument("-r", "--recovery-key", help="Custom emergency recovery key (auto-generated if omitted)")
    lock_parser.add_argument("-q", "--question", help="Security question (optional)")
    lock_parser.add_argument("-a", "--answer", help="Security question answer (optional)")
    lock_parser.add_argument(
        "-m", "--mode", choices=["aes", "quick"], default="aes",
        help="Lock mode: 'aes' (AES-256 Envelope encryption, default) or 'quick' (instant ACL hide)"
    )
    lock_parser.add_argument("--keep-original", action="store_true", help="Do not delete original folder after AES encryption")

    # Unlock Command
    unlock_parser = subparsers.add_parser("unlock", help="Unlock a secured folder or vault")
    unlock_parser.add_argument("target", help="Path to the .slock vault or quick-locked folder")
    unlock_parser.add_argument("-p", "--password", help="Password for unlocking")
    unlock_parser.add_argument("-r", "--recovery-key", help="Emergency recovery key or security answer")
    unlock_parser.add_argument("-d", "--dest", help="Destination directory to restore folder (default: same folder)")

    # Reset Password Command
    reset_parser = subparsers.add_parser("reset-password", help="Reset password of a locked vault using recovery key")
    reset_parser.add_argument("target", help="Path to the .slock vault or quick-locked folder")
    reset_parser.add_argument("-r", "--recovery-key", help="Emergency recovery key or security answer")
    reset_parser.add_argument("-n", "--new-password", help="New password to set")

    # List Command
    subparsers.add_parser("list", help="List currently registered locked vaults")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "lock":
        folder_path = os.path.abspath(args.folder)
        if not os.path.isdir(folder_path):
            print(f"Error: Folder '{folder_path}' does not exist or is not a directory.")
            sys.exit(1)

        password = args.password
        if not password:
            password = getpass.getpass("Enter password to lock: ")
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                print("Error: Passwords do not match.")
                sys.exit(1)

        print(f"Locking folder: {folder_path} (Mode: {args.mode.upper()})...")
        try:
            if args.mode == "aes":
                def cli_progress(pct, msg):
                    print(f"[{int(pct):3d}%] {msg}")

                locked_path, rec_key = encrypt_folder(
                    folder_path=folder_path,
                    password=password,
                    recovery_key=args.recovery_key,
                    security_question=args.question,
                    security_answer=args.answer,
                    delete_original=not args.keep_original,
                    progress_callback=cli_progress,
                )
                lock_type = "aes256"
            else:
                locked_path, rec_key = quick_lock_folder(
                    folder_path=folder_path,
                    password=password,
                    recovery_key=args.recovery_key,
                    security_question=args.question,
                    security_answer=args.answer,
                )
                lock_type = "quick_lock"

            add_vault(
                name=os.path.basename(folder_path),
                lock_type=lock_type,
                original_path=folder_path,
                locked_path=locked_path,
                size_bytes=os.path.getsize(locked_path) if os.path.isfile(locked_path) else 0,
                has_recovery=True,
                security_question=args.question or "",
            )

            print(f"\n[SUCCESS] Folder locked successfully!")
            print(f"Saved to: {locked_path}")
            print(f"Emergency Recovery Key: {rec_key}")
            print("IMPORTANT: Save this recovery key in a safe place to reset your password if forgotten!")

        except Exception as e:
            print(f"\n[ERROR] Failed to lock folder: {e}")
            sys.exit(1)

    elif args.command == "unlock":
        target_path = os.path.abspath(args.target)
        if not os.path.exists(target_path):
            print(f"Error: Target '{target_path}' does not exist.")
            sys.exit(1)

        password = args.password
        recovery_secret = args.recovery_key

        if not password and not recovery_secret:
            password = getpass.getpass("Enter password (or leave blank to enter recovery key): ")
            if not password:
                recovery_secret = input("Enter Emergency Recovery Key / Answer: ")

        print(f"Unlocking: {target_path}...")
        try:
            is_slock = os.path.isfile(target_path) and target_path.lower().endswith(".slock")
            if is_slock:
                def cli_progress(pct, msg):
                    print(f"[{int(pct):3d}%] {msg}")

                restored_path = decrypt_folder(
                    vault_path=target_path,
                    password=password if password else None,
                    recovery_secret=recovery_secret if recovery_secret else None,
                    destination_dir=args.dest,
                    delete_vault=True,
                    progress_callback=cli_progress,
                )
            else:
                restored_path = quick_unlock_folder(
                    target_path,
                    password=password if password else None,
                    recovery_secret=recovery_secret if recovery_secret else None,
                )

            remove_vault_by_path(target_path)
            print(f"\n[SUCCESS] Folder unlocked successfully!\nRestored to: {restored_path}")

        except (InvalidPasswordError, InvalidRecoveryKeyError) as e:
            print(f"\n[ERROR] Authentication failed: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"\n[ERROR] Failed to unlock: {e}")
            sys.exit(1)

    elif args.command == "reset-password":
        target_path = os.path.abspath(args.target)
        if not os.path.exists(target_path):
            print(f"Error: Target '{target_path}' does not exist.")
            sys.exit(1)

        rec_key = args.recovery_key
        if not rec_key:
            rec_key = input("Enter Emergency Recovery Key / Security Answer: ")

        new_password = args.new_password
        if not new_password:
            new_password = getpass.getpass("Enter new password: ")
            confirm = getpass.getpass("Confirm new password: ")
            if new_password != confirm:
                print("Error: Passwords do not match.")
                sys.exit(1)

        print(f"Resetting password for: {target_path}...")
        try:
            is_slock = os.path.isfile(target_path) and target_path.lower().endswith(".slock")
            if is_slock:
                reset_vault_password(target_path, rec_key, new_password)
            else:
                quick_reset_password(target_path, rec_key, new_password)

            print("\n[SUCCESS] Password has been reset successfully!")
            print("You can now unlock the vault using your new password.")
        except Exception as e:
            print(f"\n[ERROR] Password reset failed: {e}")
            sys.exit(1)

    elif args.command == "list":
        vaults = load_vaults()
        if not vaults:
            print("No locked vaults currently recorded.")
            return

        print(f"{'NAME':<18} {'TYPE':<10} {'DATE':<20} {'EXISTS':<8} {'RECOVERY':<10} {'PATH'}")
        print("-" * 85)
        for v in vaults:
            exists = "YES" if v.get("exists") else "NO"
            rec = "ENABLED" if v.get("has_recovery") else "NO"
            print(f"{v.get('name', 'Unknown')[:16]:<18} {v.get('type', ''):<10} {v.get('created_at', ''):<20} {exists:<8} {rec:<10} {v.get('locked_path', '')}")


if __name__ == "__main__":
    run_cli()
