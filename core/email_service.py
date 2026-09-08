"""Email transmission service for sending OTP and password reset notices.
Uses standard Python smtplib with TLS support.
"""

import os
import json
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Tuple, Dict, Any, Optional

CONFIG_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "SecureLock")
CONFIG_FILE = os.path.join(CONFIG_DIR, "email_config.json")


def _ensure_dir():
    os.makedirs(CONFIG_DIR, exist_ok=True)


def get_email_config() -> Dict[str, Any]:
    """Loads email SMTP configuration."""
    _ensure_dir()
    default_cfg = {
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "sender_email": "",
        "sender_password": "",
        "use_tls": True,
        "is_configured": False,
    }
    if not os.path.isfile(CONFIG_FILE):
        return default_cfg

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            cfg = json.load(f)
            default_cfg.update(cfg)
            return default_cfg
    except Exception:
        return default_cfg


def save_email_config(
    sender_email: str,
    sender_password: str,
    smtp_server: str = "smtp.gmail.com",
    smtp_port: int = 587,
    use_tls: bool = True,
) -> None:
    """Saves email SMTP configuration."""
    _ensure_dir()
    cfg = {
        "smtp_server": smtp_server.strip(),
        "smtp_port": int(smtp_port),
        "sender_email": sender_email.strip(),
        "sender_password": sender_password.strip(),
        "use_tls": bool(use_tls),
        "is_configured": bool(sender_email.strip() and sender_password.strip()),
    }
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def test_smtp_connection(config: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
    """Tests connection and login to the SMTP server."""
    if config is None:
        config = get_email_config()

    server = config.get("smtp_server", "").strip()
    port = int(config.get("smtp_port", 587))
    sender = config.get("sender_email", "").strip()
    pwd = config.get("sender_password", "").strip()
    use_tls = config.get("use_tls", True)

    if not server or not sender or not pwd:
        return False, "Incomplete configuration! Please enter both sender email and app password."

    try:
        if port == 465:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(server, port, context=context, timeout=12) as smtp:
                smtp.login(sender, pwd)
        else:
            with smtplib.SMTP(server, port, timeout=12) as smtp:
                if use_tls:
                    context = ssl.create_default_context()
                    smtp.starttls(context=context)
                smtp.login(sender, pwd)

        return True, "SMTP connection and login test succeeded!"
    except smtplib.SMTPAuthenticationError:
        return False, "Authentication failed! Check your email and App Password. (For Gmail, a 16-character App Password is required)."
    except Exception as e:
        return False, f"Connection failed: {str(e)}"


def send_otp_email(
    recipient_email: str,
    otp_code: str,
    folder_name: str,
    recovery_key: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Sends a styled OTP email to the recipient.
    Returns (success: bool, message: str).
    """
    config = get_email_config()
    if not config.get("is_configured"):
        return False, "Email sender is not configured! Please open 'Email Settings' to set up your sender credentials."

    server = config.get("smtp_server")
    port = int(config.get("smtp_port", 587))
    sender = config.get("sender_email")
    pwd = config.get("sender_password")
    use_tls = config.get("use_tls", True)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"🔐 SecureLock - Password Reset OTP Code: {otp_code}"
    msg["From"] = f"SecureLock Security <{sender}>"
    msg["To"] = recipient_email

    text_content = f"""SecureLock Password Reset OTP

Target Folder: {folder_name}
Your 6-Digit One-Time Verification Code (OTP):

[ {otp_code} ]

This code is valid for the next 10 minutes.
If you did not initiate this request, you can safely ignore this email.
"""
    if recovery_key:
        text_content += f"\nEmergency Backup Recovery Key: {recovery_key}\n"

    recovery_html = ""
    if recovery_key:
        recovery_html = f"""
        <div style="margin-top: 15px; padding: 12px; background: #252538; border-radius: 6px; font-family: monospace; color: #a6e3a1; font-size: 13px;">
            <b>Emergency Backup Key:</b> {recovery_key}
        </div>
        """

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
    </head>
    <body style="margin: 0; padding: 20px; background-color: #11111b; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #cdd6f4;">
        <div style="max-width: 520px; margin: 0 auto; background: #1e1e2e; border: 1px solid #313244; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.5);">
            <div style="background: #3d7bf0; padding: 18px 25px; text-align: center;">
                <h2 style="margin: 0; color: #ffffff; font-size: 20px;">🔒 SecureLock Security</h2>
                <p style="margin: 3px 0 0 0; color: #dbeafe; font-size: 13px;">Folder Password Reset Verification</p>
            </div>
            <div style="padding: 25px;">
                <p style="margin-top: 0; font-size: 15px;">Hello,</p>
                <p style="font-size: 14px; color: #a6adc8;">
                    You requested to reset the password for your secured folder <b>"{folder_name}"</b>. Use the one-time code below:
                </p>
                <div style="text-align: center; margin: 25px 0;">
                    <span style="display: inline-block; padding: 12px 30px; font-size: 30px; font-weight: bold; letter-spacing: 6px; color: #ffffff; background: #181825; border: 2px solid #89b4fa; border-radius: 8px;">
                        {otp_code}
                    </span>
                </div>
                <p style="font-size: 13px; color: #f38ba8; text-align: center; margin-bottom: 5px;">
                    ⚠️ This verification code will expire in <b>10 minutes</b>.
                </p>
                {recovery_html}
                <hr style="border: 0; border-top: 1px solid #313244; margin: 25px 0 15px 0;">
                <p style="font-size: 12px; color: #6c7086; margin: 0; text-align: center;">
                    If you did not request this code, no action is needed. Your files remain completely secure.
                </p>
            </div>
        </div>
    </body>
    </html>
    """

    part1 = MIMEText(text_content, "plain", "utf-8")
    part2 = MIMEText(html_content, "html", "utf-8")
    msg.attach(part1)
    msg.attach(part2)

    try:
        if port == 465:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(server, port, context=context, timeout=15) as smtp:
                smtp.login(sender, pwd)
                smtp.sendmail(sender, [recipient_email], msg.as_string())
        else:
            with smtplib.SMTP(server, port, timeout=15) as smtp:
                if use_tls:
                    context = ssl.create_default_context()
                    smtp.starttls(context=context)
                smtp.login(sender, pwd)
                smtp.sendmail(sender, [recipient_email], msg.as_string())

        return True, f"A 6-digit OTP code was successfully sent to {recipient_email}!"
    except smtplib.SMTPAuthenticationError:
        return False, "SMTP authentication failed! Please verify your sender email and App Password in Email Settings."
    except Exception as e:
        return False, f"Failed to deliver email: {str(e)}"


def mask_email(email: str) -> str:
    """Masks an email for privacy display, e.g. j***e@gmail.com."""
    email = email.strip()
    if "@" not in email:
        return email
    name, domain = email.split("@", 1)
    if len(name) <= 2:
        return f"{name[:1]}*@{domain}" if len(name) > 0 else email
    masked_name = name[0] + "*" * (len(name) - 2) + name[-1]
    return f"{masked_name}@{domain}"
