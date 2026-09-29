import os
import io
import base64
import hashlib
import secrets
from typing import List, Optional
import pyotp
import qrcode
from cryptography.fernet import Fernet

# Derive a consistent encryption key for 2FA secrets at rest
# Uses server environment variable TRACEGATE_2FA_KEY if set, otherwise derives from application secret
_ENV_KEY = os.environ.get("TRACEGATE_2FA_KEY") or "tracegate-2fa-encryption-salt-2026-secure"
_FERNET_KEY = base64.urlsafe_b64encode(hashlib.sha256(_ENV_KEY.encode("utf-8")).digest())
_cipher = Fernet(_FERNET_KEY)

ISSUER_NAME = "Tracegate"

def encrypt_secret(raw_secret: str) -> str:
    """Encrypt a base32 TOTP secret at rest using authenticated Fernet encryption."""
    if not raw_secret:
        raise ValueError("Cannot encrypt empty secret.")
    return _cipher.encrypt(raw_secret.encode("utf-8")).decode("utf-8")

def decrypt_secret(encrypted_secret: str) -> str:
    """Decrypt an encrypted base32 TOTP secret."""
    if not encrypted_secret:
        raise ValueError("Cannot decrypt empty ciphertext.")
    return _cipher.decrypt(encrypted_secret.encode("utf-8")).decode("utf-8")

def generate_totp_secret() -> str:
    """Generate a high-entropy, cryptographically random base32 TOTP secret."""
    return pyotp.random_base32(length=32)

def get_provisioning_uri(secret: str, account_name: str, issuer: str = ISSUER_NAME, issuer_name: Optional[str] = None) -> str:
    """
    Generate standard RFC 6238 authenticator enrollment URI.
    Compatible with Google Authenticator, Microsoft Authenticator, and Authy.
    Format: otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30
    """
    eff_issuer = issuer_name or issuer or ISSUER_NAME
    totp = pyotp.TOTP(secret, interval=30, digits=6)
    return totp.provisioning_uri(name=account_name, issuer_name=eff_issuer)

def generate_qr_code_data_url(provisioning_uri: str) -> str:
    """Generate a clean QR code PNG image encoded as a base64 data URL."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=2,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0f172a", back_color="#ffffff")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64_png = base64.b64encode(buf.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{b64_png}"

def verify_totp_code(secret: str, code: str) -> bool:
    """
    Verify a 6-digit TOTP code against the secret.
    Enforces valid_window=1 (allows 1 step before / 1 step after = +/- 30s)
    to accommodate normal client-server clock drift.
    """
    if not secret or not code:
        return False
    clean_code = str(code).strip().replace(" ", "").replace("-", "")
    if not clean_code.isdigit() or len(clean_code) != 6:
        return False
    try:
        totp = pyotp.TOTP(secret, interval=30, digits=6)
        return bool(totp.verify(clean_code, valid_window=1))
    except Exception:
        return False

def generate_recovery_codes(count: int = 10) -> List[str]:
    """
    Generate cryptographically secure one-time recovery codes.
    Formatted in 3 groups of 4 characters: XXXX-XXXX-XXXX.
    Characters exclude ambiguous symbols (I, O, 0, 1) for error-free manual typing.
    """
    charset = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    codes = []
    for _ in range(count):
        part1 = "".join(secrets.choice(charset) for _ in range(4))
        part2 = "".join(secrets.choice(charset) for _ in range(4))
        part3 = "".join(secrets.choice(charset) for _ in range(4))
        codes.append(f"{part1}-{part2}-{part3}")
    return codes

def normalize_recovery_code(code: str) -> str:
    """Normalize recovery code input for robust hash comparison."""
    return str(code).strip().upper().replace(" ", "").replace("-", "")

def hash_recovery_code(code: str) -> str:
    """Compute SHA-256 hash of normalized recovery code for storage."""
    norm = normalize_recovery_code(code)
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()
