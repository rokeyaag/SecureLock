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
    PRIMARY_COLOR,
    PRIMARY_HOVER,
    SUCCESS_COLOR,
    DANGER_COLOR,
    WARNING_COLOR,
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
        self.title("ইমেইল সেটিংস কনফিগারেশন (Email OTP Settings)")
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
            text="⚙️ ইমেইল ওটিপি (OTP) প্রেরক সেটিংস",
            font=("Segoe UI Bold", 13),
            fg=TEXT_WHITE,
            bg=BG_CARD,
        ).pack(anchor="w")

        tk.Label(
            pad,
            text="পাসওয়ার্ড রিসেট ওটিপি পাঠানোর জন্য প্রেরক ইমেইল কনফিগার করুন:",
            font=("Segoe UI", 9),
            fg=TEXT_MUTED,
            bg=BG_CARD,
        ).pack(anchor="w", pady=(2, 12))

        cfg = get_email_config()

        # Sender Email
        tk.Label(pad, text="প্রেরক ইমেইল (Sender Gmail / Outlook):", font=("Segoe UI Semibold", 9), fg=TEXT_WHITE, bg=BG_CARD).pack(anchor="w")
        self.entry_sender = tk.Entry(pad, bg=BG_INPUT, fg=TEXT_WHITE, insertbackground=TEXT_WHITE, relief=tk.FLAT, font=("Segoe UI", 10), highlightbackground=BORDER_COLOR, highlightthickness=1)
        self.entry_sender.pack(fill=tk.X, ipady=5, pady=(3, 10))
        self.entry_sender.insert(0, cfg.get("sender_email", ""))

        # App Password
        tk.Label(pad, text="অ্যাপ পাসওয়ার্ড (App Password - 16 অক্ষরের কোড):", font=("Segoe UI Semibold", 9), fg=TEXT_WHITE, bg=BG_CARD).pack(anchor="w")
        self.entry_pwd = PasswordEntry(pad)
        self.entry_pwd.pack(fill=tk.X, pady=(3, 10))
        self.entry_pwd.set(cfg.get("sender_password", ""))

        # Server & Port Row
        row = tk.Frame(pad, bg=BG_CARD)
        row.pack(fill=tk.X, pady=(0, 10))

        col1 = tk.Frame(row, bg=BG_CARD)
        col1.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        tk.Label(col1, text="SMTP সার্ভার:", font=("Segoe UI", 8), fg=TEXT_MUTED, bg=BG_CARD).pack(anchor="w")
        self.entry_server = tk.Entry(col1, bg=BG_INPUT, fg=TEXT_WHITE, relief=tk.FLAT, font=("Segoe UI", 9), highlightbackground=BORDER_COLOR, highlightthickness=1)
        self.entry_server.pack(fill=tk.X, ipady=4, pady=(2, 0))
        self.entry_server.insert(0, cfg.get("smtp_server", "smtp.gmail.com"))

        col2 = tk.Frame(row, bg=BG_CARD)
        col2.pack(side=tk.LEFT, fill=tk.X, expand=False, padx=(8, 0))
        tk.Label(col2, text="পোর্ট (Port):", font=("Segoe UI", 8), fg=TEXT_MUTED, bg=BG_CARD).pack(anchor="w")
        self.entry_port = tk.Entry(col2, bg=BG_INPUT, fg=TEXT_WHITE, relief=tk.FLAT, font=("Segoe UI", 9), width=8, highlightbackground=BORDER_COLOR, highlightthickness=1)
        self.entry_port.pack(fill=tk.X, ipady=4, pady=(2, 0))
        self.entry_port.insert(0, str(cfg.get("smtp_port", 587)))

        # Help Tip Box
        tip_box = tk.Frame(pad, bg=BG_INPUT, highlightbackground=BORDER_COLOR, highlightthickness=1, padx=10, pady=8)
        tip_box.pack(fill=tk.X, pady=(0, 15))
        tip_text = "💡 Gmail ব্যবহারের নিয়ম: Google Account > Security > 2-Step Verification চালু করে 'App Passwords' তৈরি করে সেই ১৬ অক্ষরের কোডটি দিন।"
        tk.Label(tip_box, text=tip_text, font=("Segoe UI", 8), fg=WARNING_COLOR, bg=BG_INPUT, justify=tk.LEFT, wraplength=440).pack(anchor="w")

        # Action Buttons
        btn_box = tk.Frame(pad, bg=BG_CARD)
        btn_box.pack(fill=tk.X)

        self.btn_test = tk.Button(
            btn_box,
            text="🧪 টেস্ট কানেকশন (Test Connection)",
            command=self._test_connection,
            bg=BG_INPUT,
            fg=TEXT_WHITE,
            activebackground=BORDER_COLOR,
            activeforeground=TEXT_WHITE,
            font=("Segoe UI", 9),
            relief=tk.FLAT,
            padx=12,
            pady=6,
            cursor="hand2",
            bd=1,
        )
        self.btn_test.pack(side=tk.LEFT)

        btn_save = tk.Button(
            btn_box,
            text="💾 সেটিংস সেভ করুন (Save)",
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
            messagebox.showerror("ত্রুটি", "অনুগ্রহ করে প্রেরক ইমেইল ও অ্যাপ পাসওয়ার্ড লিখুন!", parent=self)
            return

        cfg = {
            "smtp_server": server,
            "smtp_port": int(port) if port.isdigit() else 587,
            "sender_email": sender,
            "sender_password": pwd,
            "use_tls": True,
        }

        self.btn_test.config(state=tk.DISABLED, text="টেস্ট করা হচ্ছে...")
        self.update_idletasks()

        def test_worker():
            success, msg = test_smtp_connection(cfg)
            self.after(0, lambda: self._on_test_result(success, msg))

        threading.Thread(target=test_worker, daemon=True).start()

    def _on_test_result(self, success, msg):
        self.btn_test.config(state=tk.NORMAL, text="🧪 টেস্ট কানেকশন (Test Connection)")
        if success:
            messagebox.showinfo("সফল", msg, parent=self)
        else:
            messagebox.showerror("টেস্ট ব্যর্থ", msg, parent=self)

    def _save_settings(self):
        sender = self.entry_sender.get().strip()
        pwd = self.entry_pwd.get().strip()
        server = self.entry_server.get().strip()
        port = int(self.entry_port.get().strip()) if self.entry_port.get().strip().isdigit() else 587

        save_email_config(sender, pwd, server, port, True)
        messagebox.showinfo("সফল", "ইমেইল কনফিগারেশন সফলভাবে সংরক্ষিত হয়েছে!", parent=self)
        self.destroy()


class ResetPasswordDialog(tk.Toplevel):
    """Modal dialog for resetting password via Email OTP or Recovery Key."""
    def __init__(self, parent, target_path: str, on_success_cb):
        super().__init__(parent)
        self.target_path = target_path
        self.on_success_cb = on_success_cb

        self.title("পাসওয়ার্ড রিকভারি ও রিসেট (Password Recovery & Reset)")
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
            text="🔑 পাসওয়ার্ড উদ্ধার ও নতুন পাসওয়ার্ড রিসেট",
            font=("Segoe UI Bold", 13),
            fg=TEXT_WHITE,
            bg=BG_CARD,
        ).pack(anchor="w")

        tk.Label(
            pad_frame,
            text=f"টার্গেট ফোল্ডার: {self.folder_name}",
            font=("Segoe UI", 9),
            fg=PRIMARY_COLOR,
            bg=BG_CARD,
        ).pack(anchor="w", pady=(2, 10))

        # Email OTP Card
        otp_card = tk.LabelFrame(
            pad_frame,
            text=" 📧 পদ্ধতি ১: ইমেইল OTP ভেরিফিকেশন (Email OTP - Recommended) ",
            font=("Segoe UI Semibold", 9),
            bg=BG_INPUT,
            fg=SUCCESS_COLOR,
            padx=12,
            pady=10,
            relief=tk.FLAT,
            highlightbackground=BORDER_COLOR,
            highlightthickness=1,
        )
        otp_card.pack(fill=tk.X, pady=(0, 10))

        if self.recovery_email:
            masked = mask_email(self.recovery_email)
            tk.Label(
                otp_card,
                text=f"রেজিস্টার্ড রিকভারি ইমেইল: {masked}",
                font=("Segoe UI Semibold", 9),
                fg=TEXT_WHITE,
                bg=BG_INPUT,
            ).pack(anchor="w")
        else:
            tk.Label(
                otp_card,
                text="কোনো রিকভারি ইমেইল যুক্ত করা ছিল না। তবে নিচে প্রেরণের জন্য ইমেইল দিতে পারেন:",
                font=("Segoe UI", 8),
                fg=TEXT_MUTED,
                bg=BG_INPUT,
            ).pack(anchor="w")
            self.entry_adhoc_email = tk.Entry(otp_card, bg=BG_CARD, fg=TEXT_WHITE, relief=tk.FLAT, font=("Segoe UI", 9), highlightbackground=BORDER_COLOR, highlightthickness=1)
            self.entry_adhoc_email.pack(fill=tk.X, ipady=3, pady=(2, 6))

        # Send OTP row
        send_row = tk.Frame(otp_card, bg=BG_INPUT, pady=4)
        send_row.pack(fill=tk.X)

        self.btn_send_otp = tk.Button(
            send_row,
            text="📩 ইমেইলে ৬ সংখ্যার OTP পাঠান (Send OTP)",
            command=self._send_otp_to_email,
            bg=PRIMARY_COLOR,
            fg=TEXT_WHITE,
            activebackground=PRIMARY_HOVER,
            activeforeground=TEXT_WHITE,
            font=("Segoe UI Semibold", 9),
            relief=tk.FLAT,
            padx=12,
            pady=5,
            cursor="hand2",
            bd=0,
        )
        self.btn_send_otp.pack(side=tk.LEFT)

        self.lbl_otp_sent_info = tk.Label(send_row, text="", font=("Segoe UI", 8), fg=WARNING_COLOR, bg=BG_INPUT)
        self.lbl_otp_sent_info.pack(side=tk.LEFT, padx=10)

        # OTP input row
        otp_in_row = tk.Frame(otp_card, bg=BG_INPUT, pady=4)
        otp_in_row.pack(fill=tk.X)
        tk.Label(otp_in_row, text="ইমেইলে প্রাপ্ত OTP কোড লিখুন:", font=("Segoe UI", 9), fg=TEXT_WHITE, bg=BG_INPUT).pack(side=tk.LEFT)
        self.entry_otp_code = tk.Entry(
            otp_in_row,
            bg=BG_CARD,
            fg=SUCCESS_COLOR,
            insertbackground=TEXT_WHITE,
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
            text="অথবা ব্যাকআপ রিকভারি কোড / উত্তর লিখুন (ঐচ্ছিক):",
            font=("Segoe UI", 8),
            fg=TEXT_MUTED,
            bg=BG_CARD,
        ).pack(anchor="w")

        self.entry_recovery_fallback = tk.Entry(
            fallback_frame,
            bg=BG_INPUT,
            fg=TEXT_WHITE,
            insertbackground=TEXT_WHITE,
            relief=tk.FLAT,
            font=("Segoe UI", 9),
            highlightbackground=BORDER_COLOR,
            highlightthickness=1,
        )
        self.entry_recovery_fallback.pack(fill=tk.X, ipady=3, pady=(2, 8))

        # New Password Inputs
        tk.Label(
            pad_frame,
            text="নতুন পাসওয়ার্ড দিন (New Password):",
            font=("Segoe UI Semibold", 9),
            fg=TEXT_WHITE,
            bg=BG_CARD,
        ).pack(anchor="w")

        self.entry_new_pwd = PasswordEntry(pad_frame)
        self.entry_new_pwd.pack(fill=tk.X, pady=(2, 6))

        tk.Label(
            pad_frame,
            text="নতুন পাসওয়ার্ড নিশ্চিত করুন (Confirm Password):",
            font=("Segoe UI Semibold", 9),
            fg=TEXT_WHITE,
            bg=BG_CARD,
        ).pack(anchor="w")

        self.entry_confirm_pwd = PasswordEntry(pad_frame)
        self.entry_confirm_pwd.pack(fill=tk.X, pady=(2, 10))

        # Action Buttons
        btn_box = tk.Frame(pad_frame, bg=BG_CARD)
        btn_box.pack(fill=tk.X)

        self.btn_reset = tk.Button(
            btn_box,
            text="✅ OTP যাচাই ও পাসওয়ার্ড রিসেট করুন (Verify & Reset Password)",
            command=self._do_verify_and_reset,
            bg=SUCCESS_COLOR,
            fg=TEXT_WHITE,
            activebackground="#16a34a",
            activeforeground=TEXT_WHITE,
            font=("Segoe UI Bold", 10),
            relief=tk.FLAT,
            pady=8,
            cursor="hand2",
            bd=0,
        )
        self.btn_reset.pack(fill=tk.X, pady=(0, 6))

        btn_cancel = tk.Button(
            btn_box,
            text="❌ বাতিল (Cancel)",
            command=self.destroy,
            bg=BG_INPUT,
            fg=TEXT_MUTED,
            activebackground=BORDER_COLOR,
            activeforeground=TEXT_WHITE,
            font=("Segoe UI", 9),
            relief=tk.FLAT,
            pady=4,
            cursor="hand2",
            bd=0,
        )
        btn_cancel.pack(fill=tk.X)

    def _send_otp_to_email(self):
        target_email = self.recovery_email
        if not target_email and hasattr(self, "entry_adhoc_email"):
            target_email = self.entry_adhoc_email.get().strip()

        if not target_email or "@" not in target_email:
            messagebox.showerror("ত্রুটি", "একটি সঠিক রিকভারি ইমেইল অ্যাড্রেস প্রয়োজন!", parent=self)
            return

        cfg = get_email_config()
        if not cfg.get("is_configured"):
            ans = messagebox.askyesno(
                "ইমেইল সেটিংস প্রয়োজন",
                "ইমেইল পাঠানোর জন্য এখনও কোনো প্রেরক ইমেইল কনফিগার করা হয়নি!\n\nআপনি কি এখনই 'Email Settings' কনফিগার করতে চান?",
                parent=self,
            )
            if ans:
                EmailSettingsDialog(self)
            return

        rec_secret = self.recovery_key or "SLOCK-KEY-AUTO"
        otp_code = create_otp(self.target_path, rec_secret, target_email)

        self.btn_send_otp.config(state=tk.DISABLED, text="ইমেইল পাঠানো হচ্ছে...")
        self.lbl_otp_sent_info.config(text="অপেক্ষা করুন...", fg=WARNING_COLOR)

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
        self.btn_send_otp.config(state=tk.NORMAL, text="🔄 পুনরায় OTP পাঠান (Resend)")
        if success:
            self.lbl_otp_sent_info.config(text="✅ OTP পাঠানো হয়েছে! ইনবক্স চেক করুন।", fg=SUCCESS_COLOR)
            self.entry_otp_code.focus_set()
            messagebox.showinfo("ইমেইল পাঠানো সম্পন্ন", msg, parent=self)
        else:
            self.lbl_otp_sent_info.config(text="❌ ব্যর্থ!", fg=DANGER_COLOR)
            messagebox.showerror("ইমেইল প্রেরণ ব্যর্থ", msg, parent=self)

    def _do_verify_and_reset(self):
        otp_code = self.entry_otp_code.get().strip()
        fallback_secret = self.entry_recovery_fallback.get().strip()
        new_pwd = self.entry_new_pwd.get()
        confirm_pwd = self.entry_confirm_pwd.get()

        if not new_pwd:
            messagebox.showerror("ত্রুটি", "অনুগ্রহ করে একটি নতুন পাসওয়ার্ড লিখুন!", parent=self)
            return

        if new_pwd != confirm_pwd:
            messagebox.showerror("ত্রুটি", "দুই ঘরের নতুন পাসওয়ার্ড মেলেনি!", parent=self)
            return

        recovery_secret_to_use = None

        # Check OTP first if provided
        if otp_code:
            valid, rec_secret, msg = verify_otp(self.target_path, otp_code)
            if not valid:
                messagebox.showerror("OTP ভেরিফিকেশন ব্যর্থ", msg, parent=self)
                return
            recovery_secret_to_use = rec_secret

        # Fallback to recovery key if OTP was not entered
        if not recovery_secret_to_use and fallback_secret:
            recovery_secret_to_use = fallback_secret

        if not recovery_secret_to_use:
            messagebox.showerror("ত্রুটি", "অনুগ্রহ করে ইমেইলে প্রাপ্ত OTP কোডটি লিখুন অথবা ব্যাকআপ রিকভারি কোড দিন!", parent=self)
            return

        # Perform password reset
        try:
            if self.is_slock:
                reset_vault_password(self.target_path, recovery_secret_to_use, new_pwd)
            else:
                quick_reset_password(self.target_path, recovery_secret_to_use, new_pwd)

            messagebox.showinfo(
                "সফল",
                "অভিনন্দন! OTP সফলভাবে যাচাই হয়েছে এবং নতুন পাসওয়ার্ড সেট হয়েছে।\nএখন থেকে এই নতুন পাসওয়ার্ড দিয়ে আনলক করতে পারবেন।",
                parent=self,
            )
            self.destroy()
            self.on_success_cb(new_pwd)

        except (InvalidRecoveryKeyError, ValueError) as e:
            messagebox.showerror("রিকভারি ব্যর্থ", f"ভুল রিকভারি কোড বা সিকিউরিটি উত্তর!\n{e}", parent=self)
        except Exception as e:
            messagebox.showerror("ত্রুটি", f"পাসওয়ার্ড রিসেট ব্যর্থ: {e}", parent=self)


class SecureLockApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SecureLock v3.0 - Windows Folder Locker & Vault")
        self.geometry("800x720")
        self.minsize(760, 680)
        self.configure(bg=BG_DARK)

        self._setup_styles()
        self._build_header()
        self._build_tabs()
        self._build_status_bar()

        self.refresh_vaults_list()

    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(
            "TNotebook",
            background=BG_DARK,
            borderwidth=0,
            tabmargins=[15, 5, 15, 0],
        )
        style.configure(
            "TNotebook.Tab",
            background=BG_CARD,
            foreground=TEXT_MUTED,
            font=("Segoe UI Semibold", 10),
            padding=[18, 9],
            borderwidth=0,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", PRIMARY_COLOR), ("active", BG_INPUT)],
            foreground=[("selected", TEXT_WHITE), ("active", TEXT_WHITE)],
        )

        style.configure(
            "Horizontal.TProgressbar",
            troughcolor=BG_INPUT,
            background=PRIMARY_COLOR,
            thickness=8,
            borderwidth=0,
        )

        style.configure(
            "Treeview",
            background=BG_CARD,
            foreground=TEXT_WHITE,
            fieldbackground=BG_CARD,
            borderwidth=0,
            rowheight=32,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Treeview.Heading",
            background=BG_INPUT,
            foreground=TEXT_WHITE,
            font=("Segoe UI Semibold", 9),
            borderwidth=0,
            relief=tk.FLAT,
        )
        style.map("Treeview", background=[("selected", PRIMARY_COLOR)], foreground=[("selected", TEXT_WHITE)])

    def _build_header(self):
        header_frame = tk.Frame(self, bg=BG_DARK, pady=10, padx=25)
        header_frame.pack(fill=tk.X)

        left_header = tk.Frame(header_frame, bg=BG_DARK)
        left_header.pack(side=tk.LEFT)

        title_label = tk.Label(
            left_header,
            text="🔒 SecureLock",
            font=("Segoe UI Black", 20),
            fg=TEXT_WHITE,
            bg=BG_DARK,
        )
        title_label.pack(anchor="w")

        subtitle_label = tk.Label(
            left_header,
            text="উইন্ডোজ ফোল্ডার লকার ও ভল্ট (AES-256 Envelope Encryption ও Email OTP পাসওয়ার্ড রিসেট)",
            font=("Segoe UI", 10),
            fg=TEXT_MUTED,
            bg=BG_DARK,
        )
        subtitle_label.pack(anchor="w", pady=(2, 0))

        # Email Settings Button on Top Right
        btn_email_settings = tk.Button(
            header_frame,
            text="⚙️ Email Settings",
            command=self._open_email_settings,
            bg=BG_INPUT,
            fg=TEXT_WHITE,
            activebackground=BORDER_COLOR,
            activeforeground=TEXT_WHITE,
            font=("Segoe UI Semibold", 9),
            relief=tk.FLAT,
            padx=12,
            pady=6,
            cursor="hand2",
            bd=1,
        )
        btn_email_settings.pack(side=tk.RIGHT, pady=5)

    def _open_email_settings(self):
        EmailSettingsDialog(self)

    def _build_tabs(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=(5, 10))

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
            text="1. লক করার ফোল্ডার নির্বাচন করুন (Select Folder to Lock):",
            font=("Segoe UI Semibold", 10),
            fg=TEXT_WHITE,
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
            fg=TEXT_WHITE,
            insertbackground=TEXT_WHITE,
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
            bg=PRIMARY_COLOR,
            fg=TEXT_WHITE,
            activebackground=PRIMARY_HOVER,
            activeforeground=TEXT_WHITE,
            font=("Segoe UI Semibold", 9),
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
            text="2. লকিং মোড (Security Mode):",
            font=("Segoe UI Semibold", 10),
            fg=TEXT_WHITE,
            bg=BG_CARD,
        )
        lbl_step2.pack(anchor="w", pady=(6, 2))

        self.lock_mode_var = tk.StringVar(value="aes256")
        mode_box = tk.Frame(self.tab_lock, bg=BG_INPUT, highlightbackground=BORDER_COLOR, highlightthickness=1, padx=10, pady=5)
        mode_box.pack(fill=tk.X, pady=(0, 6))

        rb_aes = tk.Radiobutton(
            mode_box,
            text="🛡️ AES-256 Envelope Encryption (Recommended - সর্বোচ্চ সামরিক নিরাপত্তা)",
            variable=self.lock_mode_var,
            value="aes256",
            bg=BG_INPUT,
            fg=TEXT_WHITE,
            activebackground=BG_INPUT,
            activeforeground=TEXT_WHITE,
            selectcolor=BG_DARK,
            font=("Segoe UI Semibold", 9),
        )
        rb_aes.pack(anchor="w")

        rb_quick = tk.Radiobutton(
            mode_box,
            text="⚡ Instant Quick Lock (তাৎক্ষণিক লক - বড় সাইজের ফাইলের জন্য)",
            variable=self.lock_mode_var,
            value="quick_lock",
            bg=BG_INPUT,
            fg=TEXT_WHITE,
            activebackground=BG_INPUT,
            activeforeground=TEXT_WHITE,
            selectcolor=BG_DARK,
            font=("Segoe UI Semibold", 9),
        )
        rb_quick.pack(anchor="w", pady=(2, 0))

        # 3. Password Input
        lbl_step3 = tk.Label(
            self.tab_lock,
            text="3. পাসওয়ার্ড সেট করুন (Set Password):",
            font=("Segoe UI Semibold", 10),
            fg=TEXT_WHITE,
            bg=BG_CARD,
        )
        lbl_step3.pack(anchor="w")

        pwd_frame = tk.Frame(self.tab_lock, bg=BG_CARD)
        pwd_frame.pack(fill=tk.X, pady=3)

        col1 = tk.Frame(pwd_frame, bg=BG_CARD)
        col1.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        tk.Label(col1, text="পাসওয়ার্ড (Password):", font=("Segoe UI", 9), fg=TEXT_MUTED, bg=BG_CARD).pack(anchor="w")
        self.lock_pwd_entry = PasswordEntry(col1)
        self.lock_pwd_entry.pack(fill=tk.X, pady=(2, 0))
        self.lock_pwd_entry.bind_change(self._on_password_typing)

        col2 = tk.Frame(pwd_frame, bg=BG_CARD)
        col2.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 0))
        tk.Label(col2, text="কনফার্ম পাসওয়ার্ড (Confirm):", font=("Segoe UI", 9), fg=TEXT_MUTED, bg=BG_CARD).pack(anchor="w")
        self.lock_confirm_entry = PasswordEntry(col2)
        self.lock_confirm_entry.pack(fill=tk.X, pady=(2, 0))

        self.lbl_strength = tk.Label(self.tab_lock, text="পাসওয়ার্ডের শক্তি: অপেক্ষা করা হচ্ছে...", font=("Segoe UI", 8), fg=TEXT_MUTED, bg=BG_CARD)
        self.lbl_strength.pack(anchor="w", pady=(1, 6))

        # 4. Recovery & Email OTP Card
        rec_card = tk.LabelFrame(
            self.tab_lock,
            text=" 📧 জরুরি রিকভারি ইমেইল ও OTP অপশন (Email OTP & Recovery) ",
            font=("Segoe UI Semibold", 9),
            bg=BG_INPUT,
            fg=WARNING_COLOR,
            padx=12,
            pady=8,
            relief=tk.FLAT,
            highlightbackground=BORDER_COLOR,
            highlightthickness=1,
        )
        rec_card.pack(fill=tk.X, pady=(0, 8))

        # Recovery Email Input
        tk.Label(rec_card, text="আপনার ব্যক্তিগত রিকভারি ইমেইল (পাসওয়ার্ড ভুলে গেলে ওটিপি যাবে):", font=("Segoe UI Semibold", 8), fg=TEXT_WHITE, bg=BG_INPUT).pack(anchor="w")
        self.entry_recovery_email = tk.Entry(
            rec_card,
            bg=BG_CARD,
            fg=TEXT_WHITE,
            insertbackground=TEXT_WHITE,
            relief=tk.FLAT,
            font=("Segoe UI", 9),
            highlightbackground=BORDER_COLOR,
            highlightthickness=1,
        )
        self.entry_recovery_email.pack(fill=tk.X, ipady=4, pady=(2, 6))

        # Auto Recovery Key
        self.current_rec_key = generate_recovery_key()
        rec_key_row = tk.Frame(rec_card, bg=BG_INPUT)
        rec_key_row.pack(fill=tk.X)

        tk.Label(rec_key_row, text="ব্যাকআপ কোড:", font=("Segoe UI", 8), fg=TEXT_MUTED, bg=BG_INPUT).pack(side=tk.LEFT)
        self.lbl_rec_code = tk.Label(
            rec_key_row,
            text=self.current_rec_key,
            font=("Consolas Bold", 9),
            fg=SUCCESS_COLOR,
            bg=BG_DARK,
            padx=6,
            pady=2,
        )
        self.lbl_rec_code.pack(side=tk.LEFT, padx=6)

        btn_copy_code = tk.Button(
            rec_key_row,
            text="📋 Copy Code",
            command=self._copy_recovery_code,
            bg=PRIMARY_COLOR,
            fg=TEXT_WHITE,
            activebackground=PRIMARY_HOVER,
            activeforeground=TEXT_WHITE,
            font=("Segoe UI", 8),
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
            text="🔒 ফোল্ডার লক করুন (Lock Folder Now)",
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
            text="প্রস্তুত (Ready to lock).",
            font=("Segoe UI", 9),
            fg=TEXT_MUTED,
            bg=BG_CARD,
        )
        self.lbl_lock_status.pack(anchor="w")

    def _copy_recovery_code(self):
        self.clipboard_clear()
        self.clipboard_append(self.current_rec_key)
        messagebox.showinfo("কপি সম্পন্ন", f"রিকভারি কোড ক্লিপবোর্ডে কপি করা হয়েছে:\n{self.current_rec_key}")

    def _browse_folder_to_lock(self):
        folder = filedialog.askdirectory(title="লক করার জন্য ফোল্ডার বাছাই করুন (Select Folder to Lock)")
        if folder:
            self.lock_folder_path_var.set(os.path.normpath(folder))

    def _on_password_typing(self, event=None):
        pwd = self.lock_pwd_entry.get()
        score, text, color = evaluate_password_strength(pwd)
        self.lbl_strength.config(text=f"পাসওয়ার্ডের শক্তি: {text}", fg=color)

    def _start_lock_thread(self):
        folder_path = self.lock_folder_path_var.get().strip()
        pwd = self.lock_pwd_entry.get()
        confirm_pwd = self.lock_confirm_entry.get()
        mode = self.lock_mode_var.get()
        rec_email = self.entry_recovery_email.get().strip()
        rec_key = self.current_rec_key

        if not folder_path:
            messagebox.showerror("ত্রুটি", "অনুগ্রহ করে লক করার ফোল্ডারটি সিলেক্ট করুন!")
            return

        if not os.path.isdir(folder_path):
            messagebox.showerror("ত্রুটি", "বাছাইকৃত ফোল্ডারটি খুঁজে পাওয়া যায়নি!")
            return

        if not pwd:
            messagebox.showerror("ত্রুটি", "অনুগ্রহ করে একটি পাসওয়ার্ড লিখুন!")
            return

        if pwd != confirm_pwd:
            messagebox.showerror("ত্রুটি", "দুই ঘরের পাসওয়ার্ড মেলেনি! আবার টাইপ করুন।")
            return

        email_hint = f"\nরিকভারি ইমেইল: {rec_email}" if rec_email else ""
        confirm = messagebox.askyesno(
            "নিশ্চিতকরণ",
            f"আপনি কি নিশ্চিত যে এই ফোল্ডারটি লক করতে চান?\n\nফোল্ডার: {folder_path}\nপদ্ধতি: {'AES-256 এনক্রিপশন' if mode == 'aes256' else 'কুইক লক'}{email_hint}\n\nজরুরি রিকভারি কোড: {rec_key}",
        )
        if not confirm:
            return

        self.btn_execute_lock.config(state=tk.DISABLED, text="লক করা হচ্ছে (Processing...)...")
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
                self.after(0, lambda: self._update_lock_ui(50, "Windows CLSID ও এট্রিবিউট প্রটেকশন প্রয়োগ করা হচ্ছে..."))
                locked_path, used_rec_key = quick_lock_folder(
                    folder_path=folder_path,
                    password=pwd,
                    recovery_key=rec_key,
                    recovery_email=rec_email,
                )
                self.after(0, lambda: self._update_lock_ui(100, "তাৎক্ষণিকভাবে লক সম্পন্ন হয়েছে!"))

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
        self.btn_execute_lock.config(state=tk.NORMAL, text="🔒 ফোল্ডার লক করুন (Lock Folder Now)")
        self.lbl_lock_status.config(text="✅ সফলভাবে ফোল্ডার লক সম্পন্ন হয়েছে!", fg=SUCCESS_COLOR)

        self.lock_folder_path_var.set("")
        self.lock_pwd_entry.clear()
        self.lock_confirm_entry.clear()
        self.lbl_strength.config(text="পাসওয়ার্ডের শক্তি: অপেক্ষা করা হচ্ছে...", fg=TEXT_MUTED)

        self.current_rec_key = generate_recovery_key()
        self.lbl_rec_code.config(text=self.current_rec_key)
        self.refresh_vaults_list()

        email_note = f"\nরিকভারি ইমেইল: {rec_email} (পাসওয়ার্ড ভুলে গেলে ওটিপি যাবে)" if rec_email else ""
        msg = (
            f"অভিনন্দন! ফোল্ডারটি সফলভাবে লক করা হয়েছে।\n\n"
            f"অবস্থান: {locked_path}\n"
            f"জরুরি রিকভারি কোড: {rec_key}{email_note}\n\n"
            f"*পাসওয়ার্ড ভুলে গেলে 'Unlock Folder' ট্যাবে 'Forgot Password?' বাটনে ইমেইল OTP দিয়ে রিসেট করতে পারবেন।"
        )
        messagebox.showinfo("সাফল্য (Success)", msg)

    def _on_lock_error(self, err_msg):
        self.btn_execute_lock.config(state=tk.NORMAL, text="🔒 ফোল্ডার লক করুন (Lock Folder Now)")
        self.lbl_lock_status.config(text=f"❌ ত্রুটি: {err_msg}", fg=DANGER_COLOR)
        messagebox.showerror("লক ব্যর্থ হয়েছে", f"ফোল্ডার লক করার সময় সমস্যা হয়েছে:\n{err_msg}")

    # =========================================================================
    # TAB 2: UNLOCK FOLDER
    # =========================================================================
    def _init_unlock_tab(self):
        lbl_step1 = tk.Label(
            self.tab_unlock,
            text="1. লক করা ফাইল বা ফোল্ডার নির্বাচন করুন (Select Locked Vault / Folder):",
            font=("Segoe UI Semibold", 10),
            fg=TEXT_WHITE,
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
            fg=TEXT_WHITE,
            insertbackground=TEXT_WHITE,
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
            bg=PRIMARY_COLOR,
            fg=TEXT_WHITE,
            activebackground=PRIMARY_HOVER,
            activeforeground=TEXT_WHITE,
            font=("Segoe UI Semibold", 9),
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
            text="2. আনলক করার পাসওয়ার্ড লিখুন (Enter Password):",
            font=("Segoe UI Semibold", 10),
            fg=TEXT_WHITE,
            bg=BG_CARD,
        )
        lbl_step2.pack(side=tk.LEFT)

        btn_forgot_pwd = tk.Button(
            pwd_header_row,
            text="❓ পাসওয়ার্ড ভুলে গেছেন? (Forgot Password / Email OTP)",
            command=self._open_forgot_password_dialog,
            bg=BG_CARD,
            fg=WARNING_COLOR,
            activebackground=BG_CARD,
            activeforeground=TEXT_WHITE,
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
            text="3. আনলক করে কোথায় সেভ করবেন (Restore Destination - ঐচ্ছিক):",
            font=("Segoe UI Semibold", 10),
            fg=TEXT_WHITE,
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
            fg=TEXT_WHITE,
            insertbackground=TEXT_WHITE,
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
            bg=BG_INPUT,
            fg=TEXT_WHITE,
            activebackground=BORDER_COLOR,
            activeforeground=TEXT_WHITE,
            font=("Segoe UI", 9),
            relief=tk.FLAT,
            padx=12,
            pady=5,
            cursor="hand2",
            bd=1,
        )
        btn_browse_dest.pack(side=tk.RIGHT)

        hint_dest = tk.Label(
            self.tab_unlock,
            text="   *খালি রাখলে লক করা ফাইলের পাশেই স্বয়ংক্রিয়ভাবে ফোল্ডারটি আনলক হবে।",
            font=("Segoe UI", 8),
            fg=TEXT_MUTED,
            bg=BG_CARD,
        )
        hint_dest.pack(anchor="w", pady=(0, 12))

        self.btn_execute_unlock = tk.Button(
            self.tab_unlock,
            text="🔓 ফোল্ডার আনলক করুন (Unlock & Restore Folder)",
            command=self._start_unlock_thread,
            bg=SUCCESS_COLOR,
            fg=TEXT_WHITE,
            activebackground="#16a34a",
            activeforeground=TEXT_WHITE,
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
            text="প্রস্তুত (Ready to unlock).",
            font=("Segoe UI", 9),
            fg=TEXT_MUTED,
            bg=BG_CARD,
        )
        self.lbl_unlock_status.pack(anchor="w")

        self.last_restored_folder = None
        self.btn_open_restored = tk.Button(
            self.tab_unlock,
            text="📂 আনলক করা ফোল্ডারটি এক্সপ্লোরারে খুলুন (Open in File Explorer)",
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
            messagebox.showinfo("নোটিশ", "অনুগ্রহ করে প্রথমে লক করা ফাইল বা ফোল্ডারটি সিলেক্ট করুন!")
            return

        if not os.path.exists(target):
            messagebox.showerror("ত্রুটি", "লক করা ফাইল বা ফোল্ডারটি পাওয়া যায়নি!")
            return

        def on_reset_or_unlock(new_pwd=None):
            if new_pwd:
                self.unlock_pwd_entry.set(new_pwd)
                self.lbl_unlock_status.config(text="✅ পাসওয়ার্ড রিসেট হয়েছে! এখন আনলক বাটনে ক্লিক করুন।", fg=SUCCESS_COLOR)

        ResetPasswordDialog(self, target, on_reset_or_unlock)

    def _browse_locked_item(self):
        file_selected = filedialog.askopenfilename(
            title="লক করা ভল্ট ফাইল সিলেক্ট করুন (.slock)",
            filetypes=[("SecureLock Vaults", "*.slock"), ("All Files", "*.*")],
        )
        if file_selected:
            self.unlock_target_var.set(os.path.normpath(file_selected))
            return

        folder_selected = filedialog.askdirectory(title="অথবা কুইক-লক করা ফোল্ডার সিলেক্ট করুন")
        if folder_selected:
            self.unlock_target_var.set(os.path.normpath(folder_selected))

    def _browse_destination_folder(self):
        folder = filedialog.askdirectory(title="যেখানে আনলক করতে চান সেই লোকেশন বাছাই করুন")
        if folder:
            self.unlock_dest_var.set(os.path.normpath(folder))

    def _start_unlock_thread(self):
        target = self.unlock_target_var.get().strip()
        pwd = self.unlock_pwd_entry.get()
        dest = self.unlock_dest_var.get().strip() or None

        if not target:
            messagebox.showerror("ত্রুটি", "অনুগ্রহ করে আনলক করার ফাইল বা ফোল্ডার নির্বাচন করুন!")
            return

        if not os.path.exists(target):
            messagebox.showerror("ত্রুটি", "নির্বাচিত ফাইল বা ফোল্ডারটি পাওয়া যায়নি!")
            return

        if not pwd:
            messagebox.showerror("ত্রুটি", "অনুগ্রহ করে পাসওয়ার্ড দিন! (পাসওয়ার্ড ভুলে গেলে 'Forgot Password?' বাটনে ক্লিক করুন)")
            return

        self.btn_execute_unlock.config(state=tk.DISABLED, text="আনলক করা হচ্ছে (Decrypting...)...")
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
                self.after(0, lambda: self._update_unlock_ui(50, "Windows পারমিশন ও এট্রিবিউট রিস্টোর করা হচ্ছে..."))
                restored_path = quick_unlock_folder(target, password=pwd)
                self.after(0, lambda: self._update_unlock_ui(100, "ফোল্ডার সফলভাবে আনলক হয়েছে!"))

            remove_vault_by_path(target)
            self.after(0, lambda: self._on_unlock_success(restored_path))

        except (InvalidPasswordError, InvalidRecoveryKeyError):
            self.after(0, lambda: self._on_unlock_error("ভুল পাসওয়ার্ড!\nপাসওয়ার্ড ভুলে গেলে 'Forgot Password?' বাটনে ক্লিক করে ইমেইল OTP দিয়ে রিসেট করুন।"))
        except InvalidVaultFileError as ve:
            self.after(0, lambda: self._on_unlock_error(f"ভল্ট ফাইলটি ক্ষতিগ্রস্ত বা সঠিক ফরম্যাটে নেই: {ve}"))
        except Exception as e:
            self.after(0, lambda: self._on_unlock_error(str(e)))

    def _update_unlock_ui(self, pct, msg):
        self.unlock_progress["value"] = pct
        self.lbl_unlock_status.config(text=msg, fg=TEXT_WHITE)

    def _on_unlock_success(self, restored_path):
        self.btn_execute_unlock.config(state=tk.NORMAL, text="🔓 ফোল্ডার আনলক করুন (Unlock & Restore Folder)")
        self.lbl_unlock_status.config(text=f"✅ সফলভাবে আনলক হয়েছে: {restored_path}", fg=SUCCESS_COLOR)

        self.last_restored_folder = restored_path
        self.btn_open_restored.pack(fill=tk.X, pady=(8, 0))

        self.unlock_target_var.set("")
        self.unlock_pwd_entry.clear()
        self.refresh_vaults_list()

        messagebox.showinfo(
            "আনলক সফল",
            f"আপনার ফোল্ডার সফলভাবে আনলক ও রিস্টোর করা হয়েছে!\n\nলোকেশন: {restored_path}",
        )

    def _on_unlock_error(self, err_msg):
        self.btn_execute_unlock.config(state=tk.NORMAL, text="🔓 ফোল্ডার আনলক করুন (Unlock & Restore Folder)")
        self.lbl_unlock_status.config(text=f"❌ ত্রুটি: {err_msg}", fg=DANGER_COLOR)
        messagebox.showerror("আনলক ব্যর্থ হয়েছে", err_msg)

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
            text="বর্তমানে লক করা ফোল্ডারের তালিকা (Currently Locked Folders):",
            font=("Segoe UI Semibold", 10),
            fg=TEXT_WHITE,
            bg=BG_CARD,
        ).pack(side=tk.LEFT)

        btn_refresh = tk.Button(
            top_bar,
            text="🔄 Refresh",
            command=self.refresh_vaults_list,
            bg=BG_INPUT,
            fg=TEXT_WHITE,
            font=("Segoe UI", 9),
            relief=tk.FLAT,
            padx=10,
            pady=3,
            cursor="hand2",
            bd=1,
        )
        btn_refresh.pack(side=tk.RIGHT)

        columns = ("name", "type", "date", "status", "email", "path")
        self.tree = ttk.Treeview(self.tab_vaults, columns=columns, show="headings", height=12)
        self.tree.heading("name", text="ফোল্ডারের নাম")
        self.tree.heading("type", text="লক মোড")
        self.tree.heading("date", text="লক করার সময়")
        self.tree.heading("status", text="স্ট্যাটাস")
        self.tree.heading("email", text="রিকভারি ইমেইল")
        self.tree.heading("path", text="লক করা ফাইলের অবস্থান")

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
            text="🔓 আনলক করুন (Unlock Selected)",
            command=self._action_unlock_selected,
            bg=SUCCESS_COLOR,
            fg=TEXT_WHITE,
            activebackground="#16a34a",
            activeforeground=TEXT_WHITE,
            font=("Segoe UI Semibold", 9),
            relief=tk.FLAT,
            padx=14,
            pady=6,
            cursor="hand2",
            bd=0,
        )
        btn_unlock_sel.pack(side=tk.LEFT, padx=(0, 10))

        btn_forgot_sel = tk.Button(
            action_bar,
            text="📧 ইমেইল OTP রিসেট (Forgot Password)",
            command=self._action_forgot_selected,
            bg=BG_INPUT,
            fg=WARNING_COLOR,
            activebackground=BORDER_COLOR,
            activeforeground=TEXT_WHITE,
            font=("Segoe UI Semibold", 9),
            relief=tk.FLAT,
            padx=12,
            pady=6,
            cursor="hand2",
            bd=1,
        )
        btn_forgot_sel.pack(side=tk.LEFT, padx=(0, 10))

        btn_show_in_dir = tk.Button(
            action_bar,
            text="📁 ফোল্ডারে প্রদর্শন করুন (Show in Explorer)",
            command=self._action_show_in_explorer,
            bg=BG_INPUT,
            fg=TEXT_WHITE,
            font=("Segoe UI", 9),
            relief=tk.FLAT,
            padx=12,
            pady=6,
            cursor="hand2",
            bd=1,
        )
        btn_show_in_dir.pack(side=tk.LEFT)

    def refresh_vaults_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        vaults = load_vaults()
        for v in vaults:
            lock_type_label = "AES-256" if v.get("type") == "aes256" else "Quick Lock"
            exists_label = "সক্রিয়" if v.get("exists") else "পাওয়া যায়নি"
            email_display = mask_email(v.get("recovery_email", "")) if v.get("recovery_email") else "দেওয়া হয়নি"
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
            messagebox.showinfo("বাছাই করুন", "তালিকা থেকে একটি লক করা ফোল্ডার নির্বাচন করুন!")
            return

        values = self.tree.item(selected[0], "values")
        locked_path = values[5]
        self.unlock_target_var.set(locked_path)
        self.notebook.select(self.tab_unlock)
        self.unlock_pwd_entry.entry.focus_set()

    def _action_forgot_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("বাছাই করুন", "তালিকা থেকে একটি লক করা ফোল্ডার নির্বাচন করুন!")
            return

        values = self.tree.item(selected[0], "values")
        locked_path = values[5]
        self.unlock_target_var.set(locked_path)
        self._open_forgot_password_dialog()

    def _action_show_in_explorer(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("বাছাই করুন", "তালিকা থেকে একটি লক করা ফোল্ডার নির্বাচন করুন!")
            return

        values = self.tree.item(selected[0], "values")
        locked_path = values[5]
        if os.path.exists(locked_path):
            folder_dir = os.path.dirname(locked_path)
            subprocess.run(["explorer", folder_dir])
        else:
            messagebox.showwarning("সতর্কতা", "ফাইলটি তার আগের অবস্থানে পাওয়া যায়নি!")

    # =========================================================================
    # TAB 4: HELP & TIPS
    # =========================================================================
    def _init_help_tab(self):
        help_text = tk.Text(
            self.tab_help,
            bg=BG_INPUT,
            fg=TEXT_WHITE,
            insertbackground=TEXT_WHITE,
            font=("Segoe UI", 10),
            relief=tk.FLAT,
            padx=15,
            pady=15,
            wrap=tk.WORD,
        )
        help_text.pack(fill=tk.BOTH, expand=True)

        content = """🔰 SecureLock ইমেইল ওটিপি ও পাসওয়ার্ড রিসেট নির্দেশিকা:

1. ইমেইল ওটিপি (Email OTP Setup):
   • সফটওয়্যারের ওপর থাকা "⚙️ Email Settings" বাটনে ক্লিক করে আপনার প্রেরক ইমেইল ও অ্যাপ পাসওয়ার্ড সেট করুন।
   • ফোল্ডার লক করার সময় আপনার নিজস্ব ব্যক্তিগত ইমেইল দিন।

2. পাসওয়ার্ড ভুলে গেলে ওটিপি পাওয়া ও রিসেট করার নিয়ম:
   • 'Unlock Folder' ট্যাবে গিয়ে লক করা ফাইল সিলেক্ট করে "❓ পাসওয়ার্ড ভুলে গেছেন?" বাটনে ক্লিক করুন।
   • "📩 ইমেইলে OTP পাঠান" বাটনে ক্লিক করুন। সাথে সাথে আপনার ইনবক্সে ৬ সংখ্যার ওটিপি কোড চলে যাবে।
   • কোডটি ও আপনার নতুন পছন্দসই পাসওয়ার্ড লিখে 'Verify & Reset Password' বাটনে ক্লিক করলেই আপনার পাসওয়ার্ড পরিবর্তন হয়ে যাবে!

3. ইন্টারনেট ছাড়া অফলাইন রিকভারি:
   • ইন্টারনেট বা ইমেইল না থাকলে লক করার সময় দেওয়া ব্যাকআপ রিকভারি কোড দিয়েও সাথে সাথে পাসওয়ার্ড রিসেট করা যায়।
"""
        help_text.insert(tk.END, content)
        help_text.config(state=tk.DISABLED)

    def _build_status_bar(self):
        status_bar = tk.Frame(self, bg=BG_INPUT, height=26, padx=15)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        lbl_engine = tk.Label(
            status_bar,
            text="🔒 Engine: AES-256-GCM Envelope Cipher | Email OTP & Dual-Slot Key Recovery",
            font=("Segoe UI", 8),
            fg=TEXT_MUTED,
            bg=BG_INPUT,
        )
        lbl_engine.pack(side=tk.LEFT, pady=4)

        lbl_version = tk.Label(
            status_bar,
            text="SecureLock v3.0 (Email OTP Edition)",
            font=("Segoe UI Semibold", 8),
            fg=TEXT_MUTED,
            bg=BG_INPUT,
        )
        lbl_version.pack(side=tk.RIGHT, pady=4)


def launch():
    app = SecureLockApp()
    app.mainloop()


if __name__ == "__main__":
    launch()
