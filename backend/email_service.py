import os
import smtplib
import logging
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
import requests

from backend.config import (
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USER,
    SMTP_PASSWORD,
    SMTP_FROM_EMAIL,
    SMTP_FROM_NAME,
    SMTP_USE_TLS,
    SMTP_USE_SSL,
    RESEND_API_KEY,
    EMAIL_DEV_MODE,
)

logger = logging.getLogger("tracegate.email")

# In-memory outbox strictly for testing environments (TESTING="1" or EMAIL_DEV_MODE=true)
OUTBOX: List[Dict[str, Any]] = []


def is_email_configured() -> bool:
    """
    Check if email delivery is configured either through standard SMTP,
    an email API provider (Resend), or explicitly enabled test/dev mode.
    Returns False when production mode has no SMTP host or API key configured.
    """
    if os.getenv("TESTING") == "1":
        return True
    if EMAIL_DEV_MODE:
        return True
    if RESEND_API_KEY and len(RESEND_API_KEY) > 5:
        return True
    return bool(SMTP_HOST and SMTP_HOST.strip())


def get_outbox() -> List[Dict[str, Any]]:
    """Retrieve in-memory outbox items (for testing)."""
    return OUTBOX


def clear_outbox() -> None:
    """Clear in-memory outbox (for test suite isolation)."""
    OUTBOX.clear()


def get_last_otp_for_email(email: str) -> Optional[str]:
    """Retrieve the latest OTP sent to a specific email from the test outbox."""
    clean_target = email.strip().lower()
    for item in reversed(OUTBOX):
        if item.get("to_email", "").strip().lower() == clean_target:
            return item.get("otp")
    return None


def verify_smtp_connection() -> Tuple[bool, str]:
    """
    Diagnostic helper to test SMTP host connectivity and authentication
    without dispatching an actual email. Returns (success: bool, message: str).
    """
    if not SMTP_HOST:
        return False, "SMTP host is not configured (SMTP_HOST is empty)."

    try:
        if SMTP_USE_SSL or SMTP_PORT == 465:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=12)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=12)
            server.ehlo()
            if SMTP_USE_TLS:
                server.starttls()
                server.ehlo()

        if SMTP_USER and SMTP_PASSWORD:
            server.login(SMTP_USER, SMTP_PASSWORD)

        server.quit()
        return True, f"Successfully connected and authenticated to {SMTP_HOST}:{SMTP_PORT}."
    except smtplib.SMTPAuthenticationError:
        return False, "SMTP authentication failed. Verify SMTP_USER and SMTP_PASSWORD (e.g. Gmail App Password)."
    except smtplib.SMTPConnectError:
        return False, f"Could not connect to SMTP server at {SMTP_HOST}:{SMTP_PORT}."
    except TimeoutError:
        return False, f"Connection to {SMTP_HOST}:{SMTP_PORT} timed out."
    except Exception as e:
        return False, f"SMTP connection error: {type(e).__name__}"


def _build_email_content(otp: str) -> Tuple[str, str]:
    """
    Construct both high-contrast HTML and plain text email content for the 6-digit OTP.
    """
    plain_text = f"""Tracegate Security Verification Code

Hello,

We received a request to reset your password for your Tracegate account.
Your 6-digit verification code is:

{otp}

This code expires in 10 minutes and can only be used once.

If you did not request this password reset, please ignore this email or review your account security immediately.

Tracegate Automated Security Platform
Automated message — please do not reply.
"""

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tracegate Verification Code</title>
</head>
<body style="margin: 0; padding: 0; background-color: #0b0f19; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #f1f5f9;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #0b0f19; padding: 40px 15px;">
        <tr>
            <td align="center">
                <table role="presentation" width="100%" style="max-width: 520px; background-color: #111827; border: 1px solid #1f2937; border-radius: 12px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.5);">
                    <!-- Header -->
                    <tr>
                        <td style="padding: 28px 32px 20px 32px; border-bottom: 1px solid #1f2937; background: linear-gradient(180deg, #161f33 0%, #111827 100%);">
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                <tr>
                                    <td>
                                        <div style="display: inline-block; vertical-align: middle;">
                                            <span style="font-size: 20px; font-weight: 800; letter-spacing: 1px; color: #38bdf8;">TRACE<span style="color: #6366f1;">GATE</span></span>
                                            <span style="display: block; font-size: 11px; color: #94a3b8; letter-spacing: 0.5px; margin-top: 2px;">Vulnerability Remediation & Security Intelligence</span>
                                        </div>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    <!-- Main Body -->
                    <tr>
                        <td style="padding: 32px;">
                            <h1 style="margin: 0 0 16px 0; font-size: 20px; font-weight: 700; color: #f8fafc;">Password Reset Verification</h1>
                            <p style="margin: 0 0 24px 0; font-size: 14px; line-height: 22px; color: #cbd5e1;">
                                A password reset request was initiated for your Tracegate account. Use the 6-digit verification code below to complete the reset process:
                            </p>
                            <!-- OTP Box -->
                            <div style="background-color: #0b0f19; border: 1px solid #0284c7; border-radius: 8px; padding: 20px; text-align: center; margin-bottom: 24px;">
                                <div style="font-family: 'Courier New', Courier, monospace; font-size: 34px; font-weight: 800; letter-spacing: 8px; color: #38bdf8; text-shadow: 0 0 12px rgba(56, 189, 248, 0.4);">
                                    {otp}
                                </div>
                                <div style="margin-top: 8px; font-size: 12px; color: #94a3b8;">
                                    ⏱️ Valid for 10 minutes &bull; Single-use only
                                </div>
                            </div>
                            <!-- Security Notice -->
                            <div style="background-color: rgba(239, 68, 68, 0.08); border-left: 3px solid #ef4444; padding: 12px 16px; border-radius: 4px; margin-bottom: 24px;">
                                <p style="margin: 0; font-size: 12px; line-height: 18px; color: #fca5a5;">
                                    <strong>Security Notice:</strong> If you did not request this verification code, someone else may have entered your email address. Your account remains secure and no changes were made.
                                </p>
                            </div>
                            <p style="margin: 0; font-size: 13px; line-height: 20px; color: #94a3b8;">
                                Never share this code with anyone. Tracegate administrators will never ask for your verification code or password.
                            </p>
                        </td>
                    </tr>
                    <!-- Footer -->
                    <tr>
                        <td style="padding: 20px 32px; background-color: #0b0f19; border-top: 1px solid #1f2937; text-align: center;">
                            <p style="margin: 0; font-size: 11px; color: #64748b; line-height: 16px;">
                                This is an automated security transmission sent by Tracegate Platform.<br>
                                Please do not reply to this email.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
"""
    return plain_text, html_content


def _send_via_resend(to_email: str, subject: str, plain_text: str, html_content: str) -> bool:
    """Deliver email via Resend transactional HTTP API."""
    try:
        from_address = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>" if "@" in SMTP_FROM_EMAIL else f"Tracegate Security <onboarding@resend.dev>"
        headers = {
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
        }
        payload = {
            "from": from_address,
            "to": [to_email],
            "subject": subject,
            "text": plain_text,
            "html": html_content,
        }
        resp = requests.post("https://api.resend.com/emails", headers=headers, json=payload, timeout=12)
        if resp.status_code in (200, 201):
            logger.info(f"Password reset verification email delivered via Resend API to: {to_email}")
            return True
        else:
            logger.error(f"Resend API error ({resp.status_code}): {resp.text[:120]}")
            return False
    except Exception as e:
        logger.error(f"Resend delivery exception: {type(e).__name__}")
        return False


def send_password_reset_email(to_email: str, otp: str) -> bool:
    """
    Send a 6-digit password reset verification OTP to ANY user's registered email address.
    Strictly avoids logging OTP values, passwords, or credentials.
    """
    if not is_email_configured():
        logger.warning("Attempted to send password reset email but email delivery is not configured.")
        return False

    clean_email = to_email.strip().lower()
    if not clean_email or "@" not in clean_email:
        logger.error("Invalid recipient email address.")
        return False

    subject = "Tracegate Password Reset Verification Code"
    plain_text, html_content = _build_email_content(otp)

    # 1. Capture in test / development outbox strictly when explicitly enabled or testing
    if os.getenv("TESTING") == "1" or EMAIL_DEV_MODE:
        OUTBOX.append({
            "to_email": clean_email,
            "subject": subject,
            "body": plain_text,
            "otp": otp,
            "sent_at": datetime.now().isoformat()
        })
        logger.info(f"Password reset verification email dispatched to recipient: {clean_email}")
        return True

    # 2. Resend API delivery (if configured and no SMTP host override)
    if RESEND_API_KEY and not SMTP_HOST:
        return _send_via_resend(clean_email, subject, plain_text, html_content)

    # 3. Standard SMTP Delivery
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        from_header = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>" if SMTP_FROM_EMAIL else "Tracegate Security <noreply@tracegate.io>"
        msg["From"] = from_header
        msg["To"] = clean_email

        # Attach plain text fallback, then HTML version
        msg.attach(MIMEText(plain_text, "plain", "utf-8"))
        msg.attach(MIMEText(html_content, "html", "utf-8"))

        if SMTP_USE_SSL or SMTP_PORT == 465:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15)
            server.ehlo()
            if SMTP_USE_TLS:
                server.starttls()
                server.ehlo()

        if SMTP_USER and SMTP_PASSWORD:
            server.login(SMTP_USER, SMTP_PASSWORD)

        sender = SMTP_FROM_EMAIL if SMTP_FROM_EMAIL else SMTP_USER
        server.sendmail(sender, [clean_email], msg.as_string())
        server.quit()
        logger.info(f"Password reset verification email delivered via SMTP to: {clean_email}")
        return True
    except smtplib.SMTPAuthenticationError:
        logger.error("SMTP delivery failed: Authentication rejected. Please verify SMTP_USER and SMTP_PASSWORD.")
        return False
    except smtplib.SMTPConnectError:
        logger.error(f"SMTP delivery failed: Could not establish connection to {SMTP_HOST}:{SMTP_PORT}.")
        return False
    except TimeoutError:
        logger.error(f"SMTP delivery failed: Connection timed out connecting to {SMTP_HOST}:{SMTP_PORT}.")
        return False
    except Exception as e:
        # Safe logging: never leak credentials, passwords, or OTP secrets
        logger.error(f"Failed to deliver verification email to recipient ({clean_email}): {type(e).__name__}")
        return False
