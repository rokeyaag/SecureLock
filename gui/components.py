"""Reusable GUI components and styling helpers for SecureLock.
"""

import tkinter as tk
from tkinter import ttk
import re

# Theme Colors
BG_DARK = "#181825"
BG_CARD = "#1e1e2e"
BG_INPUT = "#252538"
BORDER_COLOR = "#363654"
PRIMARY_COLOR = "#3d7bf0"
PRIMARY_HOVER = "#2b63cb"
SUCCESS_COLOR = "#22c55e"
DANGER_COLOR = "#ef4444"
WARNING_COLOR = "#f59e0b"
TEXT_WHITE = "#f8fafc"
TEXT_MUTED = "#94a3b8"
TEXT_SUBTLE = "#64748b"


def evaluate_password_strength(password: str) -> tuple[int, str, str]:
    """
    Evaluates password strength.
    Returns (score [0-3], description, color_hex).
    """
    if not password:
        return 0, "No password", TEXT_MUTED
    if len(password) < 6:
        return 1, "Weak (Too short)", DANGER_COLOR

    score = 1
    if len(password) >= 8:
        score += 1
    if re.search(r"\d", password) and re.search(r"[a-zA-Z]", password):
        score += 1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1

    if score <= 2:
        return 1, "Weak", DANGER_COLOR
    elif score == 3:
        return 2, "Moderate", WARNING_COLOR
    else:
        return 3, "Strong (Recommended)", SUCCESS_COLOR


class PasswordEntry(tk.Frame):
    """Custom password input field with integrated Show/Hide toggle."""
    def __init__(self, parent, placeholder="", **kwargs):
        super().__init__(parent, bg=BG_CARD, **kwargs)
        self.show_password = False

        self.entry_frame = tk.Frame(self, bg=BG_INPUT, highlightbackground=BORDER_COLOR, highlightthickness=1)
        self.entry_frame.pack(fill=tk.X, expand=True)

        self.entry = tk.Entry(
            self.entry_frame,
            show="●",
            bg=BG_INPUT,
            fg=TEXT_WHITE,
            insertbackground=TEXT_WHITE,
            relief=tk.FLAT,
            font=("Segoe UI", 10),
        )
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 5), pady=8)

        self.toggle_btn = tk.Button(
            self.entry_frame,
            text="👁",
            command=self.toggle_show,
            bg=BG_INPUT,
            fg=TEXT_MUTED,
            activebackground=BG_INPUT,
            activeforeground=TEXT_WHITE,
            relief=tk.FLAT,
            bd=0,
            cursor="hand2",
            font=("Segoe UI", 11),
            width=3,
        )
        self.toggle_btn.pack(side=tk.RIGHT, padx=(0, 6), pady=4)

    def toggle_show(self):
        self.show_password = not self.show_password
        if self.show_password:
            self.entry.config(show="")
            self.toggle_btn.config(text="🙈", fg=PRIMARY_COLOR)
        else:
            self.entry.config(show="●")
            self.toggle_btn.config(text="👁", fg=TEXT_MUTED)

    def get(self) -> str:
        return self.entry.get()

    def set(self, text: str):
        self.entry.delete(0, tk.END)
        self.entry.insert(0, text)

    def clear(self):
        self.entry.delete(0, tk.END)

    def bind_change(self, callback):
        self.entry.bind("<KeyRelease>", callback)
