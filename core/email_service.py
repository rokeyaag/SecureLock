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
        return False, "ইমেইল বা পাসওয়ার্ড তথ্য অসম্পূর্ণ!"

    try:
        if port == 465:
            # SSL port
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(server, port, context=context, timeout=12) as smtp:
                smtp.login(sender, pwd)
        else:
            # Standard TLS port (587, 25)
            with smtplib.SMTP(server, port, timeout=12) as smtp:
                if use_tls:
                    context = ssl.create_default_context()
                    smtp.starttls(context=context)
                smtp.login(sender, pwd)

        return True, "ইমেইল সার্ভারের সাথে সফলভাবে সংযোগ স্থাপিত হয়েছে!"
    except smtplib.SMTPAuthenticationError:
        return False, "লগইন ব্যর্থ হয়েছে! সঠিক ইমেইল ও App Password প্রদান করুন। (Gmail ব্যবহার করলে App Password আবশ্যক)"
    except Exception as e:
        return False, f"সংযোগ ব্যর্থ: {str(e)}"


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
        return False, "ইমেইল সেটিংস কনফিগার করা হয়নি! অনুগ্রহ করে উপরের '⚙️ Email Settings' থেকে আপনার প্রেরক ইমেইল সেট করুন।"

    server = config.get("smtp_server")
    port = int(config.get("smtp_port", 587))
    sender = config.get("sender_email")
    pwd = config.get("sender_password")
    use_tls = config.get("use_tls", True)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"🔐 SecureLock - পাসওয়ার্ড রিসেট OTP কোড: {otp_code}"
    msg["From"] = f"SecureLock Security <{sender}>"
    msg["To"] = recipient_email

    # Plain text version
    text_content = f"""SecureLock Password Reset OTP

আপনার ফোল্ডার: {folder_name}
পাসওয়ার্ড রিসেট করার জন্য ৬ সংখ্যার ওয়ান-টাইম ওটিপি (OTP):

[ {otp_code} ]

এই কোডটি আগামী ১০ মিনিট কার্যকর থাকবে।
আপনি যদি এই অনুরোধ না করে থাকেন, তবে এই ইমেইলটি উপেক্ষা করুন।
"""
    if recovery_key:
        text_content += f"\nজরুরি ব্যাকআপ রিকভারি কোড: {recovery_key}\n"

    # HTML version
    recovery_html = ""
    if recovery_key:
        recovery_html = f"""
        <div style="margin-top: 15px; padding: 12px; background: #252538; border-radius: 6px; font-family: monospace; color: #a6e3a1;">
            <b>জরুরি ব্যাকআপ রিকভারি কোড:</b> {recovery_key}
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
                <p style="margin: 3px 0 0 0; color: #dbeafe; font-size: 13px;">ফোল্ডার পাসওয়ার্ড রিসেট ভেরিফিকেশন</p>
            </div>
            <div style="padding: 25px;">
                <p style="margin-top: 0; font-size: 15px;">প্রিয় ব্যবহারকারী,</p>
                <p style="font-size: 14px; color: #a6adc8;">
                    আপনার লক করা ফোল্ডার <b>"{folder_name}"</b>-এর পাসওয়ার্ড রিসেট করার জন্য নিচে একটি ওটিপি (OTP) পাঠানো হয়েছে:
                </p>
                <div style="text-align: center; margin: 25px 0;">
                    <span style="display: inline-block; padding: 12px 30px; font-size: 30px; font-weight: bold; letter-spacing: 6px; color: #ffffff; background: #181825; border: 2px solid #89b4fa; border-radius: 8px;">
                        {otp_code}
                    </span>
                </div>
                <p style="font-size: 13px; color: #f38ba8; text-align: center; margin-bottom: 5px;">
                    ⚠️ এই ওটিপি কোডটি আগামী <b>১০ মিনিট</b> পর্যন্ত কার্যকর থাকবে।
                </p>
                {recovery_html}
                <hr style="border: 0; border-top: 1px solid #313244; margin: 25px 0 15px 0;">
                <p style="font-size: 12px; color: #6c7086; margin: 0; text-align: center;">
                    আপনি যদি নিজে এই রিকোয়েস্ট না করে থাকেন, তবে কারো সাথে এই কোড শেয়ার করবেন না।
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

        return True, f"সফলভাবে {recipient_email} ঠিকানায় ৬ সংখ্যার OTP পাঠানো হয়েছে!"
    except smtplib.SMTPAuthenticationError:
        return False, "প্রেরক ইমেইলে লগইন ব্যর্থ হয়েছে! অনুগ্রহ করে Email Settings-এ গিয়ে সঠিক App Password দিন।"
    except Exception as e:
        return False, f"ইমেইল পাঠাতে সমস্যা হয়েছে: {str(e)}"


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
