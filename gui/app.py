"""Main GUI Application for SecureLock (v3.0).
A secure, modern Windows Folder Locker with AES-256-GCM Envelope Encryption,
Quick Lock, and complete Email OTP Password Reset capabilities.
"""

import os
import sys
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.crypto import (
    encrypt_folder,
    decrypt_folder,
    reset_vault_password,
    generate_recovery_key,
    peek_vault_info,
    InvalidPasswordError,
    InvalidRecoveryKeyError,
    InvalidVaultFileError,
)
from core.quick_lock import (
    quick_lock_folder,
    quick_unlock_folder,
    quick_reset_password,
    peek_quick_lock_meta,
)
from core.vault_registry import (
    load_vaults,
    add_vault,
    remove_vault_by_path,
    get_vault_by_path,
)
from core.email_service import (
    get_email_config,
    save_email_config,
    test_smtp_connection,
    send_otp_email,
    mask_email,
)
from core.otp_manager import (
    create_otp,
    verify_otp,
    cancel_otp,
)
from gui.components import (
    BG_DARK,
    BG_CARD,
    BG_INPUT,
    BORDER_COLOR,
    BORDER_YELLOW,
    BORDER_RED,
    PRIMARY_COLOR,
    PRIMARY_HOVER,
    ACCENT_YELLOW,
    YELLOW_LIGHT,
    YELLOW_BTN,
    YELLOW_BTN_HOVER,
    SUCCESS_COLOR,
    DANGER_COLOR,
    WARNING_COLOR,
    TEXT_BLACK,
    TEXT_DARK,
    TEXT_WHITE,
    TEXT_MUTED,
    TEXT_SUBTLE,
    PasswordEntry,
    evaluate_password_strength,
)


class EmailSettingsDialog(tk.Toplevel):
    """Dialog to configure sender SMTP settings for OTP delivery."""
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Email OTP Configuration (SMTP Settings)")
        self.geometry("520x460")
        self.resizable(False, False)
        self.configure(bg=BG_CARD)
        self.transient(parent)
        self.grab_set()

        self._build_ui()
        self._center_window(parent)

    def _center_window(self, parent):
        self.update_idletasks()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        px, py = parent.winfo_x(), parent.winfo_y()
        w, h = self.winfo_width(), self.winfo_height()
        self.geometry(f"+{px + (pw - w)//2}+{py + (ph - h)//2}")

    def _build_ui(self):
        pad = tk.Frame(self, bg=BG_CARD, padx=25, pady=20)
        pad.pack(fill=tk.BOTH, expand=True)

        tk.Label(
            pad,
            text="⚙️ Email OTP Sender Settings",
            font=("Segoe UI Bold", 13),
            fg=PRIMARY_COLOR,
            bg=BG_CARD,
        ).pack(anchor="w")

        tk.Label(
            pad,
            text="Configure your sender email to transmit password reset OTP codes:",
            font=("Segoe UI", 9),
            fg=TEXT_MUTED,
            bg=BG_CARD,
        ).pack(anchor="w", pady=(2, 12))

        cfg = get_email_config()

        # Sender Email
        tk.Label(pad, text="Sender Email (Gmail / Outlook / SMTP):", font=("Segoe UI Semibold", 9), fg=TEXT_BLACK, bg=BG_CARD).pack(anchor="w")
        self.entry_sender = tk.Entry(pad, bg=BG_INPUT, fg=TEXT_BLACK, insertbackground=TEXT_BLACK, relief=tk.FLAT, font=("Segoe UI", 10), highlightbackground=BORDER_COLOR, highlightthickness=1)
        self.entry_sender.pack(fill=tk.X, ipady=5, pady=(3, 10))
        self.entry_sender.insert(0, cfg.get("sender_email", ""))

        # App Password
        tk.Label(pad, text="App Password (16-character code):", font=("Segoe UI Semibold", 9), fg=TEXT_BLACK, bg=BG_CARD).pack(anchor="w")
        self.entry_pwd = PasswordEntry(pad)
        self.entry_pwd.pack(fill=tk.X, pady=(3, 10))
        self.entry_pwd.set(cfg.get("sender_password", ""))

        # Server & Port Row
        row = tk.Frame(pad, bg=BG_CARD)
        row.pack(fill=tk.X, pady=(0, 10))

        col1 = tk.Frame(row, bg=BG_CARD)
        col1.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        tk.Label(col1, text="SMTP Server:", font=("Segoe UI", 8), fg=TEXT_MUTED, bg=BG_CARD).pack(anchor="w")
        self.entry_server = tk.Entry(col1, bg=BG_INPUT, fg=TEXT_BLACK, relief=tk.FLAT, font=("Segoe UI", 9), highlightbackground=BORDER_COLOR, highlightthickness=1)
        self.entry_server.pack(fill=tk.X, ipady=4, pady=(2, 0))
        self.entry_server.insert(0, cfg.get("smtp_server", "smtp.gmail.com"))

        col2 = tk.Frame(row, bg=BG_CARD)
        col2.pack(side=tk.LEFT, fill=tk.X, expand=False, padx=(8, 0))
        tk.Label(col2, text="Port:", font=("Segoe UI", 8), fg=TEXT_MUTED, bg=BG_CARD).pack(anchor="w")
        self.entry_port = tk.Entry(col2, bg=BG_INPUT, fg=TEXT_BLACK, relief=tk.FLAT, font=("Segoe UI", 9), width=8, highlightbackground=BORDER_COLOR, highlightthickness=1)
        self.entry_port.pack(fill=tk.X, ipady=4, pady=(2, 0))
        self.entry_port.insert(0, str(cfg.get("smtp_port", 587)))

        # Help Tip Box
        tip_box = tk.Frame(pad, bg=YELLOW_LIGHT, highlightbackground=BORDER_YELLOW, highlightthickness=1, padx=10, pady=8)
        tip_box.pack(fill=tk.X, pady=(0, 15))
        tip_text = "💡 Gmail Setup: Enable 2-Step Verification in your Google Account > Security, generate an 'App Password', and paste that 16-character code here."
        tk.Label(tip_box, text=tip_text, font=("Segoe UI", 8), fg=WARNING_COLOR, bg=YELLOW_LIGHT, justify=tk.LEFT, wraplength=440).pack(anchor="w")

        # Action Buttons
        btn_box = tk.Frame(pad, bg=BG_CARD)
        btn_box.pack(fill=tk.X)

        self.btn_test = tk.Button(
            btn_box,
            text="🧪 Test Connection",
            command=self._test_connection,
            bg=YELLOW_BTN,
            fg=TEXT_BLACK,
            activebackground=YELLOW_BTN_HOVER,
            activeforeground=TEXT_BLACK,
            font=("Segoe UI Bold", 9),
            relief=tk.FLAT,
            padx=12,
            pady=6,
            cursor="hand2",
            bd=0,
        )
        self.btn_test.pack(side=tk.LEFT)

        btn_save = tk.Button(
            btn_box,
            text="💾 Save Settings",
            command=self._save_settings,
            bg=PRIMARY_COLOR,
            fg=TEXT_WHITE,
            activebackground=PRIMARY_HOVER,
            activeforeground=TEXT_WHITE,
            font=("Segoe UI Bold", 9),
            relief=tk.FLAT,
            padx=16,
            pady=6,
            cursor="hand2",
            bd=0,
        )
        btn_save.pack(side=tk.RIGHT)

    def _test_connection(self):
        sender = self.entry_sender.get().strip()
        pwd = self.entry_pwd.get().strip()
        server = self.entry_server.get().strip()
        port = self.entry_port.get().strip()

        if not sender or not pwd:
            messagebox.showerror("Validation Error", "Please enter both sender email and App Password!", parent=self)
            return

        cfg = {
            "smtp_server": server,
            "smtp_port": int(port) if port.isdigit() else 587,
            "sender_email": sender,
            "sender_password": pwd,
            "use_tls": True,
        }

        self.btn_test.config(state=tk.DISABLED, text="Testing Connection...")
        self.update_idletasks()

        def test_worker():
            success, msg = test_smtp_connection(cfg)
            self.after(0, lambda: self._on_test_result(success, msg))

        threading.Thread(target=test_worker, daemon=True).start()

    def _on_test_result(self, success, msg):
        self.btn_test.config(state=tk.NORMAL, text="🧪 Test Connection")
        if success:
            messagebox.showinfo("Success", msg, parent=self)
        else:
            messagebox.showerror("Connection Failed", msg, parent=self)

    def _save_settings(self):
        sender = self.entry_sender.get().strip()
        pwd = self.entry_pwd.get().strip()
        server = self.entry_server.get().strip()
        port = int(self.entry_port.get().strip()) if self.entry_port.get().strip().isdigit() else 587

        save_email_config(sender, pwd, server, port, True)
        messagebox.showinfo("Saved", "Email configuration saved successfully!", parent=self)
        self.destroy()


class ResetPasswordDialog(tk.Toplevel):
    """Modal dialog for resetting password via Email OTP or Recovery Key."""
    def __init__(self, parent, target_path: str, on_success_cb):
        super().__init__(parent)
        self.target_path = target_path
        self.on_success_cb = on_success_cb

        self.title("Password Recovery & Reset")
        self.geometry("560x570")
        self.minsize(540, 520)
        self.configure(bg=BG_CARD)
        self.transient(parent)
        self.grab_set()

        self._load_metadata()
        self._build_ui()
        self._center_window(parent)

    def _center_window(self, parent):
        self.update_idletasks()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        px, py = parent.winfo_x(), parent.winfo_y()
        w, h = self.winfo_width(), self.winfo_height()
        self.geometry(f"+{px + (pw - w)//2}+{py + (ph - h)//2}")

    def _load_metadata(self):
        self.security_question = ""
        self.recovery_email = ""
        self.recovery_key = ""
        self.folder_name = os.path.basename(self.target_path)
        self.is_slock = os.path.isfile(self.target_path) and self.target_path.lower().endswith(".slock")

        # Check in registry first for cached recovery key/email
        vault_record = get_vault_by_path(self.target_path)
        if vault_record:
            self.recovery_email = vault_record.get("recovery_email", "")
            self.recovery_key = vault_record.get("recovery_key", "")
            self.security_question = vault_record.get("security_question", "")

        try:
            if self.is_slock:
                meta = peek_vault_info(self.target_path)
                if not self.security_question:
                    self.security_question = meta.get("security_question", "")
                if not self.recovery_email:
                    self.recovery_email = meta.get("recovery_email", "")
            else:
                meta = peek_quick_lock_meta(self.target_path)
                if not self.security_question:
                    self.security_question = meta.get("security_question", "")
                if not self.recovery_email:
                    self.recovery_email = meta.get("recovery_email", "")
                if not self.recovery_key:
                    self.recovery_key = meta.get("recovery_key_backup", "")
        except Exception:
            pass

    def _build_ui(self):
        pad_frame = tk.Frame(self, bg=BG_CARD, padx=25, pady=18)
        pad_frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(
            pad_frame,
            text="🔑 Password Recovery & Reset",
            font=("Segoe UI Bold", 13),
            fg=PRIMARY_COLOR,
            bg=BG_CARD,
        ).pack(anchor="w")

        tk.Label(
            pad_frame,
            text=f"Target: {self.folder_name}",
            font=("Segoe UI Semibold", 9),
            fg=TEXT_DARK,
            bg=BG_CARD,
        ).pack(anchor="w", pady=(2, 10))

        # Email OTP Card
        otp_card = tk.LabelFrame(
            pad_frame,
            text=" 📧 Method 1: Email OTP Verification (Recommended) ",
            font=("Segoe UI Semibold", 9),
            bg=YELLOW_LIGHT,
            fg=WARNING_COLOR,
            padx=12,
            pady=10,
            relief=tk.FLAT,
            highlightbackground=BORDER_YELLOW,
            highlightthickness=1,
        )
        otp_card.pack(fill=tk.X, pady=(0, 10))

        if self.recovery_email:
            masked = mask_email(self.recovery_email)
            tk.Label(
                otp_card,
                text=f"Registered Recovery Email: {masked}",
                font=("Segoe UI Semibold", 9),
                fg=TEXT_BLACK,
                bg=YELLOW_LIGHT,
            ).pack(anchor="w")
        else:
            tk.Label(
                otp_card,
                text="No recovery email was attached. Enter destination email below:",
                font=("Segoe UI", 8),
                fg=TEXT_MUTED,
                bg=YELLOW_LIGHT,
            ).pack(anchor="w")
            self.entry_adhoc_email = tk.Entry(otp_card, bg=BG_CARD, fg=TEXT_BLACK, relief=tk.FLAT, font=("Segoe UI", 9), highlightbackground=BORDER_COLOR, highlightthickness=1)
            self.entry_adhoc_email.pack(fill=tk.X, ipady=3, pady=(2, 6))

        # Send OTP row
        send_row = tk.Frame(otp_card, bg=YELLOW_LIGHT, pady=4)
        send_row.pack(fill=tk.X)

        self.btn_send_otp = tk.Button(
            send_row,
            text="📩 Send 6-Digit OTP",
            command=self._send_otp_to_email,
            bg=PRIMARY_COLOR,
            fg=TEXT_WHITE,
            activebackground=PRIMARY_HOVER,
            activeforeground=TEXT_WHITE,
            font=("Segoe UI Bold", 9),
            relief=tk.FLAT,
            padx=12,
            pady=5,
            cursor="hand2",
            bd=0,
        )
        self.btn_send_otp.pack(side=tk.LEFT)

        self.lbl_otp_sent_info = tk.Label(send_row, text="", font=("Segoe UI Bold", 8), fg=WARNING_COLOR, bg=YELLOW_LIGHT)
        self.lbl_otp_sent_info.pack(side=tk.LEFT, padx=10)

        # OTP input row
        otp_in_row = tk.Frame(otp_card, bg=YELLOW_LIGHT, pady=4)
        otp_in_row.pack(fill=tk.X)
        tk.Label(otp_in_row, text="Enter OTP Code:", font=("Segoe UI Semibold", 9), fg=TEXT_BLACK, bg=YELLOW_LIGHT).pack(side=tk.LEFT)
        self.entry_otp_code = tk.Entry(
            otp_in_row,
            bg=BG_CARD,
            fg=TEXT_BLACK,
            insertbackground=TEXT_BLACK,
            relief=tk.FLAT,
            font=("Consolas Bold", 13),
            width=10,
            justify="center",
            highlightbackground=BORDER_COLOR,
            highlightthickness=1,
        )
        self.entry_otp_code.pack(side=tk.LEFT, padx=10, ipady=3)

        # Fallback Key Entry (collapsible/subtle)
        fallback_frame = tk.Frame(pad_frame, bg=BG_CARD, pady=4)
        fallback_frame.pack(fill=tk.X)
        tk.Label(
            fallback_frame,
            text="Or enter Backup Recovery Key (Optional / Offline):",
            font=("Segoe UI", 8),
            fg=TEXT_MUTED,
            bg=BG_CARD,
        ).pack(anchor="w")

        self.entry_recovery_fallback = tk.Entry(
            fallback_frame,
            bg=BG_INPUT,
            fg=TEXT_BLACK,
            insertbackground=TEXT_BLACK,
            relief=tk.FLAT,
            font=("Segoe UI", 9),
            highlightbackground=BORDER_COLOR,
            highlightthickness=1,
        )
        self.entry_recovery_fallback.pack(fill=tk.X, ipady=3, pady=(2, 8))

        # New Password Inputs
        tk.Label(
            pad_frame,
            text="Enter New Password:",
            font=("Segoe UI Semibold", 9),
            fg=TEXT_BLACK,
            bg=BG_CARD,
        ).pack(anchor="w")

        self.entry_new_pwd = PasswordEntry(pad_frame)
        self.entry_new_pwd.pack(fill=tk.X, pady=(2, 6))

        tk.Label(
            pad_frame,
            text="Confirm New Password:",
            font=("Segoe UI Semibold", 9),
            fg=TEXT_BLACK,
            bg=BG_CARD,
        ).pack(anchor="w")

        self.entry_confirm_pwd = PasswordEntry(pad_frame)
        self.entry_confirm_pwd.pack(fill=tk.X, pady=(2, 10))

        # Action Buttons
        btn_box = tk.Frame(pad_frame, bg=BG_CARD)
        btn_box.pack(fill=tk.X)

        self.btn_reset = tk.Button(
            btn_box,
            text="✅ Verify OTP & Reset Password",
            command=self._do_verify_and_reset,
            bg=YELLOW_BTN,
            fg=TEXT_BLACK,
            activebackground=YELLOW_BTN_HOVER,
            activeforeground=TEXT_BLACK,
            font=("Segoe UI Bold", 10),
            relief=tk.FLAT,
            pady=8,
            cursor="hand2",
            bd=0,
        )
        self.btn_reset.pack(fill=tk.X, pady=(0, 6))

        btn_cancel = tk.Button(
            btn_box,
            text="Cancel",
            command=self.destroy,
            bg=BG_CARD,
            fg=TEXT_MUTED,
            activebackground="#F3F4F6",
            activeforeground=TEXT_BLACK,
            font=("Segoe UI", 9),
            relief=tk.FLAT,
            pady=4,
            cursor="hand2",
            bd=1,
        )
        btn_cancel.pack(fill=tk.X)

    def _send_otp_to_email(self):
        target_email = self.recovery_email
        if not target_email and hasattr(self, "entry_adhoc_email"):
            target_email = self.entry_adhoc_email.get().strip()

        if not target_email or "@" not in target_email:
            messagebox.showerror("Invalid Email", "Please enter a valid recovery email address!", parent=self)
            return

        cfg = get_email_config()
        if not cfg.get("is_configured"):
            ans = messagebox.askyesno(
                "Email Settings Required",
                "No sender email has been configured yet!\n\nWould you like to configure Email Settings now?",
                parent=self,
            )
            if ans:
                EmailSettingsDialog(self)
            return

        rec_secret = self.recovery_key or "SLOCK-KEY-AUTO"
        otp_code = create_otp(self.target_path, rec_secret, target_email)

        self.btn_send_otp.config(state=tk.DISABLED, text="Sending OTP...")
        self.lbl_otp_sent_info.config(text="Please wait...", fg=WARNING_COLOR)

        def send_worker():
            success, msg = send_otp_email(
                recipient_email=target_email,
                otp_code=otp_code,
                folder_name=self.folder_name,
                recovery_key=self.recovery_key if self.recovery_key else None,
            )
            self.after(0, lambda: self._on_otp_sent(success, msg))

        threading.Thread(target=send_worker, daemon=True).start()

    def _on_otp_sent(self, success, msg):
        self.btn_send_otp.config(state=tk.NORMAL, text="🔄 Resend OTP")
        if success:
            self.lbl_otp_sent_info.config(text="✅ OTP sent! Check your inbox.", fg=SUCCESS_COLOR)
            self.entry_otp_code.focus_set()
            messagebox.showinfo("OTP Sent", msg, parent=self)
        else:
            self.lbl_otp_sent_info.config(text="❌ Delivery Failed!", fg=DANGER_COLOR)
            messagebox.showerror("Delivery Failed", msg, parent=self)

    def _do_verify_and_reset(self):
        otp_code = self.entry_otp_code.get().strip()
        fallback_secret = self.entry_recovery_fallback.get().strip()
        new_pwd = self.entry_new_pwd.get()
        confirm_pwd = self.entry_confirm_pwd.get()

        if not new_pwd:
            messagebox.showerror("Validation Error", "Please enter a new password!", parent=self)
            return

        if new_pwd != confirm_pwd:
            messagebox.showerror("Validation Error", "Passwords do not match! Please check again.", parent=self)
            return

        recovery_secret_to_use = None

        # Check OTP first if provided
        if otp_code:
            valid, rec_secret, msg = verify_otp(self.target_path, otp_code)
            if not valid:
                messagebox.showerror("Verification Failed", msg, parent=self)
                return
            recovery_secret_to_use = rec_secret

        # Fallback to recovery key if OTP was not entered
        if not recovery_secret_to_use and fallback_secret:
            recovery_secret_to_use = fallback_secret

        if not recovery_secret_to_use:
            messagebox.showerror("Missing Code", "Please enter the OTP from your email or your backup recovery key!", parent=self)
            return

        # Perform password reset
        try:
            if self.is_slock:
                reset_vault_password(self.target_path, recovery_secret_to_use, new_pwd)
            else:
                quick_reset_password(self.target_path, recovery_secret_to_use, new_pwd)

            messagebox.showinfo(
                "Success",
                "Congratulations! Identity verified and password reset successfully.\nYou can now unlock the vault using your new password.",
                parent=self,
            )
            self.destroy()
            self.on_success_cb(new_pwd)

        except (InvalidRecoveryKeyError, ValueError) as e:
            messagebox.showerror("Recovery Failed", f"Invalid recovery key or security answer!\n{e}", parent=self)
        except Exception as e:
            messagebox.showerror("Error", f"Password reset failed: {e}", parent=self)


def install_system_shortcuts() -> tuple[bool, str]:
    """Installs SecureLock to Local AppData and creates Desktop and Start Menu shortcuts."""
    try:
        local_appdata = os.environ.get("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local"))
        install_dir = os.path.join(local_appdata, "Programs", "SecureLock")
        os.makedirs(install_dir, exist_ok=True)
        exe_target = os.path.join(install_dir, "SecureLock.exe")

        is_frozen = getattr(sys, "frozen", False)
        current_exe = sys.executable if is_frozen else os.path.abspath(sys.argv[0])

        if is_frozen:
            if os.path.abspath(current_exe).lower() != os.path.abspath(exe_target).lower():
                try:
                    import shutil
                    shutil.copy2(current_exe, exe_target)
                    target_to_link = exe_target
                    work_dir = install_dir
                except Exception:
                    target_to_link = current_exe
                    work_dir = os.path.dirname(current_exe)
            else:
                target_to_link = exe_target
                work_dir = install_dir
        else:
            target_to_link = sys.executable
            work_dir = os.path.dirname(os.path.abspath(__file__))

        # Copy icon to install directory if available
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        icon_source = os.path.join(base_dir, "assets", "icon.ico")
        icon_target = os.path.join(install_dir, "icon.ico")
        if os.path.exists(icon_source):
            try:
                import shutil
                shutil.copy2(icon_source, icon_target)
                icon_path_for_link = icon_target
            except Exception:
                icon_path_for_link = icon_source
        elif os.path.exists(icon_target):
            icon_path_for_link = icon_target
        else:
            icon_path_for_link = target_to_link

        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        desktop_shortcut = os.path.join(desktop, "SecureLock.lnk")

        roaming_appdata = os.environ.get("APPDATA", os.path.expanduser("~\\AppData\\Roaming"))
        start_menu = os.path.join(roaming_appdata, "Microsoft", "Windows", "Start Menu", "Programs")
        start_shortcut = os.path.join(start_menu, "SecureLock.lnk")

        args = "" if is_frozen else f'"{os.path.abspath(os.path.join(work_dir, "..", "main.py"))}"'

        ps_script = f"""
        $ws = New-Object -ComObject WScript.Shell
        $s1 = $ws.CreateShortcut('{desktop_shortcut}')
        $s1.TargetPath = '{target_to_link}'
        $s1.Arguments = '{args}'
        $s1.WorkingDirectory = '{work_dir}'
        $s1.IconLocation = '{icon_path_for_link}'
        $s1.Description = 'SecureLock - Windows Folder Locker & Vault'
        $s1.Save()

        $s2 = $ws.CreateShortcut('{start_shortcut}')
        $s2.TargetPath = '{target_to_link}'
        $s2.Arguments = '{args}'
        $s2.WorkingDirectory = '{work_dir}'
        $s2.IconLocation = '{icon_path_for_link}'
        $s2.Description = 'SecureLock - Windows Folder Locker & Vault'
        $s2.Save()
        """
        creation_flag = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW
        subprocess.run(["powershell", "-NoProfile", "-Command", ps_script], check=True, creationflags=creation_flag)
        return True, target_to_link
    except Exception as e:
        return False, str(e)


class SecureLockApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SecureLock v3.0 - Windows Folder Locker & Vault")
        self.geometry("800x720")
        self.minsize(760, 680)
        self.configure(bg=BG_DARK)

        self._load_app_icon()
        self._setup_styles()
        self._build_header()
        self._build_tabs()
        self._build_status_bar()

        self.refresh_vaults_list()
        self.after(1000, self._check_first_run_shortcut)

    def _load_app_icon(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        ico_path = os.path.join(base_dir, "assets", "icon.ico")
        if os.path.exists(ico_path):
            try:
                self.iconbitmap(ico_path)
            except Exception:
                pass
        png_path = os.path.join(base_dir, "assets", "icon_48.png")
        if os.path.exists(png_path):
            try:
                self._app_icon_photo = tk.PhotoImage(file=png_path)
                self.iconphoto(True, self._app_icon_photo)
            except Exception:
                pass

    def _check_first_run_shortcut(self):
        try:
            desktop = os.path.join(os.path.expanduser("~"), "Desktop")
            shortcut_path = os.path.join(desktop, "SecureLock.lnk")
            if not os.path.exists(shortcut_path):
                ans = messagebox.askyesno(
                    "SecureLock Setup",
                    "Welcome to SecureLock!\n\nWould you like to install SecureLock shortcuts on your Desktop and Start Menu for quick access?",
                    parent=self,
                )
                if ans:
                    self._install_desktop_shortcuts()
        except Exception:
            pass

    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(
            "TNotebook",
            background=BG_DARK,
            borderwidth=0,
            tabmargins=[15, 6, 15, 0],
        )
        style.configure(
            "TNotebook.Tab",
            background="#E2E8F0",
            foreground=TEXT_BLACK,
            font=("Segoe UI Bold", 10),
            padding=[20, 10],
            borderwidth=0,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", PRIMARY_COLOR), ("active", "#FDE68A")],
            foreground=[("selected", TEXT_WHITE), ("active", TEXT_BLACK)],
        )

        style.configure(
            "Horizontal.TProgressbar",
            troughcolor="#E2E8F0",
            background=PRIMARY_COLOR,
            thickness=8,
            borderwidth=0,
        )

        style.configure(
            "Treeview",
            background="#FFFFFF",
            foreground=TEXT_BLACK,
            fieldbackground="#FFFFFF",
            borderwidth=1,
            rowheight=32,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Treeview.Heading",
            background="#FEF3C7",
            foreground=TEXT_BLACK,
            font=("Segoe UI Bold", 9),
            borderwidth=1,
            relief=tk.FLAT,
        )
        style.map("Treeview", background=[("selected", PRIMARY_COLOR)], foreground=[("selected", TEXT_WHITE)])

    def _build_header(self):
        header_frame = tk.Frame(self, bg=PRIMARY_COLOR, pady=12, padx=22)
        header_frame.pack(fill=tk.X)

        left_header = tk.Frame(header_frame, bg=PRIMARY_COLOR)
        left_header.pack(side=tk.LEFT)

        # Show 48x48 brand logo if available
        self._logo_photo = None
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        logo_path = os.path.join(base_dir, "assets", "icon_48.png")
        if os.path.exists(logo_path):
            try:
                self._logo_photo = tk.PhotoImage(file=logo_path)
                lbl_logo = tk.Label(left_header, image=self._logo_photo, bg=PRIMARY_COLOR)
                lbl_logo.pack(side=tk.LEFT, padx=(0, 12))
            except Exception:
                pass

        titles_box = tk.Frame(left_header, bg=PRIMARY_COLOR)
        titles_box.pack(side=tk.LEFT)

        title_label = tk.Label(
            titles_box,
            text="SecureLock",
            font=("Segoe UI Black", 18),
            fg=TEXT_WHITE,
            bg=PRIMARY_COLOR,
        )
        title_label.pack(anchor="w")

        subtitle_label = tk.Label(
            titles_box,
            text="Advanced Folder Locker • AES-256 Envelope Encryption • Email OTP Recovery",
            font=("Segoe UI Semibold", 9),
            fg="#FEF08A",
            bg=PRIMARY_COLOR,
        )
        subtitle_label.pack(anchor="w", pady=(1, 0))

        # Right Action Buttons
        right_actions = tk.Frame(header_frame, bg=PRIMARY_COLOR)
        right_actions.pack(side=tk.RIGHT, pady=4)

        btn_install_shortcuts = tk.Button(
            right_actions,
            text="📌 Setup PC Shortcut",
            command=self._install_desktop_shortcuts,
            bg=YELLOW_BTN,
            fg=TEXT_BLACK,
            activebackground=YELLOW_BTN_HOVER,
            activeforeground=TEXT_BLACK,
            font=("Segoe UI Bold", 9),
            relief=tk.FLAT,
            padx=12,
            pady=6,
            cursor="hand2",
            bd=0,
        )
        btn_install_shortcuts.pack(side=tk.LEFT, padx=(0, 8))

        btn_email_settings = tk.Button(
            right_actions,
            text="⚙️ Email Settings",
            command=self._open_email_settings,
            bg="#FFFFFF",
            fg=TEXT_BLACK,
            activebackground="#F3F4F6",
            activeforeground=TEXT_BLACK,
            font=("Segoe UI Bold", 9),
            relief=tk.FLAT,
            padx=12,
            pady=6,
            cursor="hand2",
            bd=0,
        )
        btn_email_settings.pack(side=tk.LEFT)

    def _install_desktop_shortcuts(self):
        success, msg = install_system_shortcuts()
        if success:
            messagebox.showinfo(
                "Setup Completed",
                f"SecureLock was successfully set up on this PC!\n\n"
                f"Desktop and Start Menu shortcuts have been created.\nProgram: {msg}",
                parent=self,
            )
        else:
            messagebox.showerror("Setup Error", f"Could not create shortcuts: {msg}", parent=self)

    def _open_email_settings(self):
        EmailSettingsDialog(self)

    def _build_tabs(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=(8, 10))

        self.tab_lock = tk.Frame(self.notebook, bg=BG_CARD, padx=25, pady=15)
        self.notebook.add(self.tab_lock, text=" 🔒 Lock Folder ")
        self._init_lock_tab()

        self.tab_unlock = tk.Frame(self.notebook, bg=BG_CARD, padx=25, pady=15)
        self.notebook.add(self.tab_unlock, text=" 🔓 Unlock Folder ")
        self._init_unlock_tab()

        self.tab_vaults = tk.Frame(self.notebook, bg=BG_CARD, padx=25, pady=15)
        self.notebook.add(self.tab_vaults, text=" 📂 Locked Vaults ")
        self._init_vaults_tab()

        self.tab_help = tk.Frame(self.notebook, bg=BG_CARD, padx=25, pady=15)
        self.notebook.add(self.tab_help, text=" ℹ️ Help & Tips ")
        self._init_help_tab()

    # =========================================================================
    # TAB 1: LOCK FOLDER
    # =========================================================================
    def _init_lock_tab(self):
        # 1. Folder Selection
        lbl_step1 = tk.Label(
            self.tab_lock,
            text="1. Select Folder to Lock:",
            font=("Segoe UI Bold", 10),
            fg=TEXT_BLACK,
            bg=BG_CARD,
        )
        lbl_step1.pack(anchor="w")

        folder_box = tk.Frame(self.tab_lock, bg=BG_CARD, pady=4)
        folder_box.pack(fill=tk.X)

        self.lock_folder_path_var = tk.StringVar()
        self.entry_lock_path = tk.Entry(
            folder_box,
            textvariable=self.lock_folder_path_var,
            bg=BG_INPUT,
            fg=TEXT_BLACK,
            insertbackground=TEXT_BLACK,
            relief=tk.FLAT,
            font=("Segoe UI", 10),
            highlightbackground=BORDER_COLOR,
            highlightthickness=1,
        )
        self.entry_lock_path.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=6, padx=(0, 10))

        btn_browse_lock = tk.Button(
            folder_box,
            text="📁 Browse Folder...",
            command=self._browse_folder_to_lock,
            bg=YELLOW_BTN,
            fg=TEXT_BLACK,
            activebackground=YELLOW_BTN_HOVER,
            activeforeground=TEXT_BLACK,
            font=("Segoe UI Bold", 9),
            relief=tk.FLAT,
            padx=14,
            pady=5,
            cursor="hand2",
            bd=0,
        )
        btn_browse_lock.pack(side=tk.RIGHT)

        # 2. Security Mode
        lbl_step2 = tk.Label(
            self.tab_lock,
            text="2. Security Mode:",
            font=("Segoe UI Bold", 10),
            fg=TEXT_BLACK,
            bg=BG_CARD,
        )
        lbl_step2.pack(anchor="w", pady=(6, 2))

        self.lock_mode_var = tk.StringVar(value="aes256")
        mode_box = tk.Frame(self.tab_lock, bg=YELLOW_LIGHT, highlightbackground=BORDER_YELLOW, highlightthickness=1, padx=10, pady=5)
        mode_box.pack(fill=tk.X, pady=(0, 6))

        rb_aes = tk.Radiobutton(
            mode_box,
            text="🛡️ AES-256 Envelope Encryption (Recommended - Military Grade)",
            variable=self.lock_mode_var,
            value="aes256",
            bg=YELLOW_LIGHT,
            fg=TEXT_BLACK,
            activebackground=YELLOW_LIGHT,
            activeforeground=TEXT_BLACK,
            selectcolor="#FFFFFF",
            font=("Segoe UI Semibold", 9),
        )
        rb_aes.pack(anchor="w")

        rb_quick = tk.Radiobutton(
            mode_box,
            text="⚡ Instant Quick Lock (Fast Lock for Large Files/Games)",
            variable=self.lock_mode_var,
            value="quick_lock",
            bg=YELLOW_LIGHT,
            fg=TEXT_BLACK,
            activebackground=YELLOW_LIGHT,
            activeforeground=TEXT_BLACK,
            selectcolor="#FFFFFF",
            font=("Segoe UI Semibold", 9),
        )
        rb_quick.pack(anchor="w", pady=(2, 0))

        # 3. Password Input
        lbl_step3 = tk.Label(
            self.tab_lock,
            text="3. Set Password:",
            font=("Segoe UI Bold", 10),
            fg=TEXT_BLACK,
            bg=BG_CARD,
        )
        lbl_step3.pack(anchor="w")

        pwd_frame = tk.Frame(self.tab_lock, bg=BG_CARD)
        pwd_frame.pack(fill=tk.X, pady=3)

        col1 = tk.Frame(pwd_frame, bg=BG_CARD)
        col1.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        tk.Label(col1, text="Password:", font=("Segoe UI", 9), fg=TEXT_MUTED, bg=BG_CARD).pack(anchor="w")
        self.lock_pwd_entry = PasswordEntry(col1)
        self.lock_pwd_entry.pack(fill=tk.X, pady=(2, 0))
        self.lock_pwd_entry.bind_change(self._on_password_typing)

        col2 = tk.Frame(pwd_frame, bg=BG_CARD)
        col2.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 0))
        tk.Label(col2, text="Confirm Password:", font=("Segoe UI", 9), fg=TEXT_MUTED, bg=BG_CARD).pack(anchor="w")
        self.lock_confirm_entry = PasswordEntry(col2)
        self.lock_confirm_entry.pack(fill=tk.X, pady=(2, 0))

        self.lbl_strength = tk.Label(self.tab_lock, text="Password Strength: Waiting for input...", font=("Segoe UI", 8), fg=TEXT_MUTED, bg=BG_CARD)
        self.lbl_strength.pack(anchor="w", pady=(1, 6))

        # 4. Recovery & Email OTP Card
        rec_card = tk.LabelFrame(
            self.tab_lock,
            text=" 📧 Emergency Recovery & Email OTP Options ",
            font=("Segoe UI Semibold", 9),
            bg=YELLOW_LIGHT,
            fg=WARNING_COLOR,
            padx=12,
            pady=8,
            relief=tk.FLAT,
            highlightbackground=BORDER_YELLOW,
            highlightthickness=1,
        )
        rec_card.pack(fill=tk.X, pady=(0, 8))

        # Recovery Email Input
        tk.Label(rec_card, text="Recovery Email (OTP will be sent here if password is forgotten):", font=("Segoe UI Semibold", 8), fg=TEXT_BLACK, bg=YELLOW_LIGHT).pack(anchor="w")
        self.entry_recovery_email = tk.Entry(
            rec_card,
            bg="#FFFFFF",
            fg=TEXT_BLACK,
            insertbackground=TEXT_BLACK,
            relief=tk.FLAT,
            font=("Segoe UI", 9),
            highlightbackground=BORDER_YELLOW,
            highlightthickness=1,
        )
        self.entry_recovery_email.pack(fill=tk.X, ipady=4, pady=(2, 6))

        # Auto Recovery Key
        self.current_rec_key = generate_recovery_key()
        rec_key_row = tk.Frame(rec_card, bg=YELLOW_LIGHT)
        rec_key_row.pack(fill=tk.X)

        tk.Label(rec_key_row, text="Backup Recovery Key:", font=("Segoe UI", 8), fg=TEXT_DARK, bg=YELLOW_LIGHT).pack(side=tk.LEFT)
        self.lbl_rec_code = tk.Label(
            rec_key_row,
            text=self.current_rec_key,
            font=("Consolas Bold", 9),
            fg="#92400E",
            bg="#FEF3C7",
            padx=6,
            pady=2,
        )
        self.lbl_rec_code.pack(side=tk.LEFT, padx=6)

        btn_copy_code = tk.Button(
            rec_key_row,
            text="📋 Copy Code",
            command=self._copy_recovery_code,
            bg=YELLOW_BTN,
            fg=TEXT_BLACK,
            activebackground=YELLOW_BTN_HOVER,
            activeforeground=TEXT_BLACK,
            font=("Segoe UI Bold", 8),
            relief=tk.FLAT,
            padx=6,
            pady=1,
            cursor="hand2",
            bd=0,
        )
        btn_copy_code.pack(side=tk.LEFT)

        # Lock Action Button
        self.btn_execute_lock = tk.Button(
            self.tab_lock,
            text="🔒 Lock Folder Now",
            command=self._start_lock_thread,
            bg=PRIMARY_COLOR,
            fg=TEXT_WHITE,
            activebackground=PRIMARY_HOVER,
            activeforeground=TEXT_WHITE,
            font=("Segoe UI Bold", 11),
            relief=tk.FLAT,
            pady=8,
            cursor="hand2",
            bd=0,
        )
        self.btn_execute_lock.pack(fill=tk.X, pady=(4, 6))

        self.lock_progress = ttk.Progressbar(self.tab_lock, style="Horizontal.TProgressbar", mode="determinate")
        self.lock_progress.pack(fill=tk.X, pady=(0, 4))

        self.lbl_lock_status = tk.Label(
            self.tab_lock,
            text="Ready to lock.",
            font=("Segoe UI", 9),
            fg=TEXT_DARK,
            bg=BG_CARD,
        )
        self.lbl_lock_status.pack(anchor="w")

    def _copy_recovery_code(self):
        self.clipboard_clear()
        self.clipboard_append(self.current_rec_key)
        messagebox.showinfo("Copied", f"Recovery key copied to clipboard:\n{self.current_rec_key}")

    def _browse_folder_to_lock(self):
        folder = filedialog.askdirectory(title="Select Folder to Lock")
        if folder:
            self.lock_folder_path_var.set(os.path.normpath(folder))

    def _on_password_typing(self, event=None):
        pwd = self.lock_pwd_entry.get()
        score, text, color = evaluate_password_strength(pwd)
        self.lbl_strength.config(text=f"Password Strength: {text}", fg=color)

    def _start_lock_thread(self):
        folder_path = self.lock_folder_path_var.get().strip()
        pwd = self.lock_pwd_entry.get()
        confirm_pwd = self.lock_confirm_entry.get()
        mode = self.lock_mode_var.get()
        rec_email = self.entry_recovery_email.get().strip()
        rec_key = self.current_rec_key

        if not folder_path:
            messagebox.showerror("Error", "Please select a folder to lock!")
            return

        if not os.path.isdir(folder_path):
            messagebox.showerror("Error", "The selected folder was not found!")
            return

        if not pwd:
            messagebox.showerror("Error", "Please enter a password!")
            return

        if pwd != confirm_pwd:
            messagebox.showerror("Error", "Passwords do not match! Please retype.")
            return

        email_hint = f"\nRecovery Email: {rec_email}" if rec_email else ""
        confirm = messagebox.askyesno(
            "Confirm Action",
            f"Are you sure you want to lock this folder?\n\nFolder: {folder_path}\nSecurity Mode: {'AES-256 Envelope Encryption' if mode == 'aes256' else 'Instant Quick Lock'}{email_hint}\n\nEmergency Recovery Key: {rec_key}",
        )
        if not confirm:
            return

        self.btn_execute_lock.config(state=tk.DISABLED, text="Locking Folder (Processing...)...")
        self.lock_progress["value"] = 0

        threading.Thread(
            target=self._lock_worker,
            args=(folder_path, pwd, mode, rec_key, rec_email),
            daemon=True
        ).start()

    def _lock_worker(self, folder_path, pwd, mode, rec_key, rec_email):
        try:
            folder_name = os.path.basename(folder_path.rstrip("\\/"))
            size_bytes = 0
            for root, _, files in os.walk(folder_path):
                for f in files:
                    try:
                        size_bytes += os.path.getsize(os.path.join(root, f))
                    except OSError:
                        pass

            if mode == "aes256":
                def update_cb(pct, msg):
                    self.after(0, lambda: self._update_lock_ui(pct, msg))

                locked_path, used_rec_key = encrypt_folder(
                    folder_path=folder_path,
                    password=pwd,
                    recovery_key=rec_key,
                    recovery_email=rec_email,
                    delete_original=True,
                    progress_callback=update_cb,
                )
            else:
                self.after(0, lambda: self._update_lock_ui(50, "Applying Windows CLSID & attribute protections..."))
                locked_path, used_rec_key = quick_lock_folder(
                    folder_path=folder_path,
                    password=pwd,
                    recovery_key=rec_key,
                    recovery_email=rec_email,
                )
                self.after(0, lambda: self._update_lock_ui(100, "Folder locked instantly!"))

            add_vault(
                name=folder_name,
                lock_type=mode,
                original_path=folder_path,
                locked_path=locked_path,
                size_bytes=size_bytes,
                has_recovery=True,
                recovery_email=rec_email,
                recovery_key=used_rec_key,
            )

            self.after(0, lambda: self._on_lock_success(locked_path, mode, used_rec_key, rec_email))

        except Exception as e:
            self.after(0, lambda: self._on_lock_error(str(e)))

    def _update_lock_ui(self, pct, msg):
        self.lock_progress["value"] = pct
        self.lbl_lock_status.config(text=msg, fg=TEXT_WHITE)

    def _on_lock_success(self, locked_path, mode, rec_key, rec_email):
        self.btn_execute_lock.config(state=tk.NORMAL, text="🔒 Lock Folder Now")
        self.lbl_lock_status.config(text="✅ Folder locked successfully!", fg=SUCCESS_COLOR)

        self.lock_folder_path_var.set("")
        self.lock_pwd_entry.clear()
        self.lock_confirm_entry.clear()
        self.lbl_strength.config(text="Password Strength: Waiting for input...", fg=TEXT_MUTED)

        self.current_rec_key = generate_recovery_key()
        self.lbl_rec_code.config(text=self.current_rec_key)
        self.refresh_vaults_list()

        email_note = f"\nRecovery Email: {rec_email} (OTP will be sent here for resets)" if rec_email else ""
        msg = (
            f"Congratulations! The folder has been securely locked.\n\n"
            f"Locked Location: {locked_path}\n"
            f"Emergency Recovery Key: {rec_key}{email_note}\n\n"
            f"*If you ever forget your password, go to 'Unlock Folder' and click 'Forgot Password?' to reset via Email OTP."
        )
        messagebox.showinfo("Lock Successful", msg)

    def _on_lock_error(self, err_msg):
        self.btn_execute_lock.config(state=tk.NORMAL, text="🔒 Lock Folder Now")
        self.lbl_lock_status.config(text=f"❌ Error: {err_msg}", fg=DANGER_COLOR)
        messagebox.showerror("Lock Failed", f"An error occurred while locking the folder:\n{err_msg}")

    # =========================================================================
    # TAB 2: UNLOCK FOLDER
    # =========================================================================
    def _init_unlock_tab(self):
        lbl_step1 = tk.Label(
            self.tab_unlock,
            text="1. Select Locked Vault or Folder:",
            font=("Segoe UI Bold", 10),
            fg=TEXT_BLACK,
            bg=BG_CARD,
        )
        lbl_step1.pack(anchor="w")

        box = tk.Frame(self.tab_unlock, bg=BG_CARD, pady=6)
        box.pack(fill=tk.X)

        self.unlock_target_var = tk.StringVar()
        self.entry_unlock_path = tk.Entry(
            box,
            textvariable=self.unlock_target_var,
            bg=BG_INPUT,
            fg=TEXT_BLACK,
            insertbackground=TEXT_BLACK,
            relief=tk.FLAT,
            font=("Segoe UI", 10),
            highlightbackground=BORDER_COLOR,
            highlightthickness=1,
        )
        self.entry_unlock_path.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=6, padx=(0, 10))

        btn_browse_slock = tk.Button(
            box,
            text="📂 Browse Locked File...",
            command=self._browse_locked_item,
            bg=YELLOW_BTN,
            fg=TEXT_BLACK,
            activebackground=YELLOW_BTN_HOVER,
            activeforeground=TEXT_BLACK,
            font=("Segoe UI Bold", 9),
            relief=tk.FLAT,
            padx=14,
            pady=5,
            cursor="hand2",
            bd=0,
        )
        btn_browse_slock.pack(side=tk.RIGHT)

        pwd_header_row = tk.Frame(self.tab_unlock, bg=BG_CARD)
        pwd_header_row.pack(fill=tk.X, pady=(12, 4))

        lbl_step2 = tk.Label(
            pwd_header_row,
            text="2. Enter Password:",
            font=("Segoe UI Bold", 10),
            fg=TEXT_BLACK,
            bg=BG_CARD,
        )
        lbl_step2.pack(side=tk.LEFT)

        btn_forgot_pwd = tk.Button(
            pwd_header_row,
            text="❓ Forgot Password? (Email OTP / Recovery Key)",
            command=self._open_forgot_password_dialog,
            bg=BG_CARD,
            fg=PRIMARY_COLOR,
            activebackground=BG_CARD,
            activeforeground=PRIMARY_HOVER,
            font=("Segoe UI Bold", 9, "underline"),
            relief=tk.FLAT,
            bd=0,
            cursor="hand2",
        )
        btn_forgot_pwd.pack(side=tk.RIGHT)

        self.unlock_pwd_entry = PasswordEntry(self.tab_unlock)
        self.unlock_pwd_entry.pack(fill=tk.X, pady=(0, 12))

        lbl_dest = tk.Label(
            self.tab_unlock,
            text="3. Restore Destination (Optional):",
            font=("Segoe UI Bold", 10),
            fg=TEXT_BLACK,
            bg=BG_CARD,
        )
        lbl_dest.pack(anchor="w")

        dest_box = tk.Frame(self.tab_unlock, bg=BG_CARD, pady=4)
        dest_box.pack(fill=tk.X)

        self.unlock_dest_var = tk.StringVar()
        self.entry_dest_path = tk.Entry(
            dest_box,
            textvariable=self.unlock_dest_var,
            bg=BG_INPUT,
            fg=TEXT_BLACK,
            insertbackground=TEXT_BLACK,
            relief=tk.FLAT,
            font=("Segoe UI", 10),
            highlightbackground=BORDER_COLOR,
            highlightthickness=1,
        )
        self.entry_dest_path.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=6, padx=(0, 10))

        btn_browse_dest = tk.Button(
            dest_box,
            text="📁 Select Folder...",
            command=self._browse_destination_folder,
            bg="#FFFFFF",
            fg=TEXT_BLACK,
            activebackground="#F3F4F6",
            activeforeground=TEXT_BLACK,
            font=("Segoe UI Semibold", 9),
            relief=tk.FLAT,
            padx=12,
            pady=5,
            cursor="hand2",
            bd=1,
            highlightbackground=BORDER_COLOR,
        )
        btn_browse_dest.pack(side=tk.RIGHT)

        hint_dest = tk.Label(
            self.tab_unlock,
            text="   *Leave blank to restore next to the locked container.",
            font=("Segoe UI", 8),
            fg=TEXT_MUTED,
            bg=BG_CARD,
        )
        hint_dest.pack(anchor="w", pady=(0, 12))

        self.btn_execute_unlock = tk.Button(
            self.tab_unlock,
            text="🔓 Unlock & Restore Folder",
            command=self._start_unlock_thread,
            bg=YELLOW_BTN,
            fg=TEXT_BLACK,
            activebackground=YELLOW_BTN_HOVER,
            activeforeground=TEXT_BLACK,
            font=("Segoe UI Bold", 11),
            relief=tk.FLAT,
            pady=10,
            cursor="hand2",
            bd=0,
        )
        self.btn_execute_unlock.pack(fill=tk.X, pady=(0, 10))

        self.unlock_progress = ttk.Progressbar(self.tab_unlock, style="Horizontal.TProgressbar", mode="determinate")
        self.unlock_progress.pack(fill=tk.X, pady=(0, 6))

        self.lbl_unlock_status = tk.Label(
            self.tab_unlock,
            text="Ready to unlock.",
            font=("Segoe UI", 9),
            fg=TEXT_DARK,
            bg=BG_CARD,
        )
        self.lbl_unlock_status.pack(anchor="w")

        self.last_restored_folder = None
        self.btn_open_restored = tk.Button(
            self.tab_unlock,
            text="📂 Open Restored Folder in File Explorer",
            command=self._open_restored_in_explorer,
            bg=PRIMARY_COLOR,
            fg=TEXT_WHITE,
            activebackground=PRIMARY_HOVER,
            activeforeground=TEXT_WHITE,
            font=("Segoe UI Semibold", 9),
            relief=tk.FLAT,
            pady=6,
            cursor="hand2",
            bd=0,
        )

    def _open_forgot_password_dialog(self):
        target = self.unlock_target_var.get().strip()
        if not target:
            messagebox.showinfo("Notice", "Please select a locked file or folder first!")
            return

        if not os.path.exists(target):
            messagebox.showerror("Error", "The selected locked container was not found!")
            return

        def on_reset_or_unlock(new_pwd=None):
            if new_pwd:
                self.unlock_pwd_entry.set(new_pwd)
                self.lbl_unlock_status.config(text="✅ Password reset successfully! Click Unlock to continue.", fg=SUCCESS_COLOR)

        ResetPasswordDialog(self, target, on_reset_or_unlock)

    def _browse_locked_item(self):
        file_selected = filedialog.askopenfilename(
            title="Select Locked Vault File (.slock)",
            filetypes=[("SecureLock Vaults", "*.slock"), ("All Files", "*.*")],
        )
        if file_selected:
            self.unlock_target_var.set(os.path.normpath(file_selected))
            return

        folder_selected = filedialog.askdirectory(title="Or Select Quick-Locked Folder")
        if folder_selected:
            self.unlock_target_var.set(os.path.normpath(folder_selected))

    def _browse_destination_folder(self):
        folder = filedialog.askdirectory(title="Select Restore Destination Directory")
        if folder:
            self.unlock_dest_var.set(os.path.normpath(folder))

    def _start_unlock_thread(self):
        target = self.unlock_target_var.get().strip()
        pwd = self.unlock_pwd_entry.get()
        dest = self.unlock_dest_var.get().strip() or None

        if not target:
            messagebox.showerror("Error", "Please select a file or folder to unlock!")
            return

        if not os.path.exists(target):
            messagebox.showerror("Error", "The selected file or folder was not found!")
            return

        if not pwd:
            messagebox.showerror("Error", "Please enter password! (Or click 'Forgot Password?' to recover)")
            return

        self.btn_execute_unlock.config(state=tk.DISABLED, text="Decrypting & Restoring...")
        self.unlock_progress["value"] = 0
        self.btn_open_restored.pack_forget()

        threading.Thread(
            target=self._unlock_worker,
            args=(target, pwd, dest),
            daemon=True
        ).start()

    def _unlock_worker(self, target, pwd, dest):
        try:
            is_slock = os.path.isfile(target) and target.lower().endswith(".slock")

            if is_slock:
                def update_cb(pct, msg):
                    self.after(0, lambda: self._update_unlock_ui(pct, msg))

                restored_path = decrypt_folder(
                    vault_path=target,
                    password=pwd,
                    destination_dir=dest,
                    delete_vault=True,
                    progress_callback=update_cb,
                )
            else:
                self.after(0, lambda: self._update_unlock_ui(50, "Restoring Windows permissions & attributes..."))
                restored_path = quick_unlock_folder(target, password=pwd)
                self.after(0, lambda: self._update_unlock_ui(100, "Folder unlocked successfully!"))

            remove_vault_by_path(target)
            self.after(0, lambda: self._on_unlock_success(restored_path))

        except (InvalidPasswordError, InvalidRecoveryKeyError):
            self.after(0, lambda: self._on_unlock_error("Invalid password!\nIf you forgot your password, click 'Forgot Password?' to reset via Email OTP or Recovery Key."))
        except InvalidVaultFileError as ve:
            self.after(0, lambda: self._on_unlock_error(f"The vault file is corrupted or in an unrecognized format: {ve}"))
        except Exception as e:
            self.after(0, lambda: self._on_unlock_error(str(e)))

    def _update_unlock_ui(self, pct, msg):
        self.unlock_progress["value"] = pct
        self.lbl_unlock_status.config(text=msg, fg=TEXT_WHITE)

    def _on_unlock_success(self, restored_path):
        self.btn_execute_unlock.config(state=tk.NORMAL, text="🔓 Unlock & Restore Folder")
        self.lbl_unlock_status.config(text=f"✅ Successfully unlocked: {restored_path}", fg=SUCCESS_COLOR)

        self.last_restored_folder = restored_path
        self.btn_open_restored.pack(fill=tk.X, pady=(8, 0))

        self.unlock_target_var.set("")
        self.unlock_pwd_entry.clear()
        self.refresh_vaults_list()

        messagebox.showinfo(
            "Unlock Successful",
            f"Your folder has been successfully unlocked and restored!\n\nLocation: {restored_path}",
        )

    def _on_unlock_error(self, err_msg):
        self.btn_execute_unlock.config(state=tk.NORMAL, text="🔓 Unlock & Restore Folder")
        self.lbl_unlock_status.config(text=f"❌ Error: {err_msg}", fg=DANGER_COLOR)
        messagebox.showerror("Unlock Failed", err_msg)

    def _open_restored_in_explorer(self):
        if self.last_restored_folder and os.path.exists(self.last_restored_folder):
            subprocess.run(["explorer", os.path.abspath(self.last_restored_folder)])

    # =========================================================================
    # TAB 3: LOCKED VAULTS MANAGER
    # =========================================================================
    def _init_vaults_tab(self):
        top_bar = tk.Frame(self.tab_vaults, bg=BG_CARD)
        top_bar.pack(fill=tk.X, pady=(0, 10))

        tk.Label(
            top_bar,
            text="Currently Locked Folders & Vaults:",
            font=("Segoe UI Bold", 10),
            fg=TEXT_BLACK,
            bg=BG_CARD,
        ).pack(side=tk.LEFT)

        btn_refresh = tk.Button(
            top_bar,
            text="🔄 Refresh",
            command=self.refresh_vaults_list,
            bg=YELLOW_BTN,
            fg=TEXT_BLACK,
            activebackground=YELLOW_BTN_HOVER,
            activeforeground=TEXT_BLACK,
            font=("Segoe UI Bold", 9),
            relief=tk.FLAT,
            padx=12,
            pady=4,
            cursor="hand2",
            bd=0,
        )
        btn_refresh.pack(side=tk.RIGHT)

        columns = ("name", "type", "date", "status", "email", "path")
        self.tree = ttk.Treeview(self.tab_vaults, columns=columns, show="headings", height=12)
        self.tree.heading("name", text="Folder Name")
        self.tree.heading("type", text="Lock Mode")
        self.tree.heading("date", text="Date Locked")
        self.tree.heading("status", text="Status")
        self.tree.heading("email", text="Recovery Email")
        self.tree.heading("path", text="Locked File Location")

        self.tree.column("name", width=130, anchor="w")
        self.tree.column("type", width=80, anchor="center")
        self.tree.column("date", width=120, anchor="center")
        self.tree.column("status", width=60, anchor="center")
        self.tree.column("email", width=140, anchor="w")
        self.tree.column("path", width=200, anchor="w")

        self.tree.pack(fill=tk.BOTH, expand=True)

        action_bar = tk.Frame(self.tab_vaults, bg=BG_CARD, pady=10)
        action_bar.pack(fill=tk.X)

        btn_unlock_sel = tk.Button(
            action_bar,
            text="🔓 Unlock Selected",
            command=self._action_unlock_selected,
            bg=PRIMARY_COLOR,
            fg=TEXT_WHITE,
            activebackground=PRIMARY_HOVER,
            activeforeground=TEXT_WHITE,
            font=("Segoe UI Bold", 9),
            relief=tk.FLAT,
            padx=14,
            pady=6,
            cursor="hand2",
            bd=0,
        )
        btn_unlock_sel.pack(side=tk.LEFT, padx=(0, 10))

        btn_forgot_sel = tk.Button(
            action_bar,
            text="📧 Email OTP Reset",
            command=self._action_forgot_selected,
            bg=YELLOW_BTN,
            fg=TEXT_BLACK,
            activebackground=YELLOW_BTN_HOVER,
            activeforeground=TEXT_BLACK,
            font=("Segoe UI Bold", 9),
            relief=tk.FLAT,
            padx=12,
            pady=6,
            cursor="hand2",
            bd=0,
        )
        btn_forgot_sel.pack(side=tk.LEFT, padx=(0, 10))

        btn_show_in_dir = tk.Button(
            action_bar,
            text="📁 Show in Explorer",
            command=self._action_show_in_explorer,
            bg="#FFFFFF",
            fg=TEXT_BLACK,
            activebackground="#F3F4F6",
            activeforeground=TEXT_BLACK,
            font=("Segoe UI Semibold", 9),
            relief=tk.FLAT,
            padx=12,
            pady=6,
            cursor="hand2",
            bd=1,
            highlightbackground=BORDER_COLOR,
        )
        btn_show_in_dir.pack(side=tk.LEFT)

    def refresh_vaults_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        vaults = load_vaults()
        for v in vaults:
            lock_type_label = "AES-256" if v.get("type") == "aes256" else "Quick Lock"
            exists_label = "Active" if v.get("exists") else "Missing"
            email_display = mask_email(v.get("recovery_email", "")) if v.get("recovery_email") else "None"
            self.tree.insert(
                "",
                tk.END,
                values=(
                    v.get("name", "Unknown"),
                    lock_type_label,
                    v.get("created_at", "-"),
                    exists_label,
                    email_display,
                    v.get("locked_path", "-"),
                ),
            )

    def _action_unlock_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Select Vault", "Please select a locked folder from the list!")
            return

        values = self.tree.item(selected[0], "values")
        locked_path = values[5]
        self.unlock_target_var.set(locked_path)
        self.notebook.select(self.tab_unlock)
        self.unlock_pwd_entry.entry.focus_set()

    def _action_forgot_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Select Vault", "Please select a locked folder from the list!")
            return

        values = self.tree.item(selected[0], "values")
        locked_path = values[5]
        self.unlock_target_var.set(locked_path)
        self._open_forgot_password_dialog()

    def _action_show_in_explorer(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Select Vault", "Please select a locked folder from the list!")
            return

        values = self.tree.item(selected[0], "values")
        locked_path = values[5]
        if os.path.exists(locked_path):
            folder_dir = os.path.dirname(locked_path)
            subprocess.run(["explorer", folder_dir])
        else:
            messagebox.showwarning("Warning", "The file could not be found at its recorded location!")

    # =========================================================================
    # TAB 4: HELP & TIPS
    # =========================================================================
    def _init_help_tab(self):
        help_text = tk.Text(
            self.tab_help,
            bg="#FFFFFF",
            fg=TEXT_BLACK,
            insertbackground=TEXT_BLACK,
            font=("Segoe UI", 10),
            relief=tk.FLAT,
            padx=15,
            pady=15,
            wrap=tk.WORD,
        )
        help_text.pack(fill=tk.BOTH, expand=True)

        content = """🔰 SecureLock - Security, Email OTP & Recovery Guide:

1. Email OTP Configuration:
   • Click the "⚙️ Email Settings" button at the top-right of the window.
   • Configure your sender email (Gmail / Outlook) and 16-character App Password.
   • When locking any folder, enter your personal email address in the Recovery Email field.

2. How to Recover & Reset Forgotten Passwords:
   • Go to the "Unlock Folder" tab, select your locked container (.slock file or folder).
   • Click the "❓ Forgot Password? (Email OTP / Recovery Key)" button.
   • Click "📩 Send 6-Digit OTP". SecureLock will instantly dispatch a secure verification code to your registered email.
   • Enter the OTP code, type your desired new password, and click "Verify & Reset Password".
   • Your password is updated in milliseconds using zero-re-encryption envelope security!

3. Offline Recovery (No Internet Required):
   • When locking a folder, SecureLock generates a unique Emergency Recovery Key (e.g. SLOCK-XXXX-XXXX-XXXX-XXXX).
   • Store this key in a secure offline location (e.g. password manager or notebook).
   • Even without internet or an email server, you can instantly reset your password or unlock directly using this key.

4. AES-256 vs Quick Lock:
   • AES-256 Envelope Encryption: Military-grade cryptographic protection. Files are encrypted with AES-256-GCM.
   • Quick Lock: Instant Windows shell and permission hiding. Perfect for massive game folders, video libraries, or fast concealment.
"""
        help_text.insert(tk.END, content)
        help_text.config(state=tk.DISABLED)

    def _build_status_bar(self):
        status_bar = tk.Frame(self, bg="#F1F5F9", height=28, padx=15, highlightbackground=BORDER_COLOR, highlightthickness=1)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        lbl_engine = tk.Label(
            status_bar,
            text="🔒 Engine: AES-256-GCM Envelope Cipher | Email OTP & Dual-Slot Key Recovery",
            font=("Segoe UI Semibold", 8),
            fg=TEXT_MUTED,
            bg="#F1F5F9",
        )
        lbl_engine.pack(side=tk.LEFT, pady=4)

        lbl_version = tk.Label(
            status_bar,
            text="SecureLock v3.0 (English Edition)",
            font=("Segoe UI Bold", 8),
            fg=PRIMARY_COLOR,
            bg="#F1F5F9",
        )
        lbl_version.pack(side=tk.RIGHT, pady=4)


def launch():
    app = SecureLockApp()
    app.mainloop()


if __name__ == "__main__":
    launch()
