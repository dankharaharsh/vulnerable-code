import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from project root or backend folder
env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

DEFAULT_GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
DEFAULT_OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")

# Supported file limits
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
ALLOWED_MIME_TYPES = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/jpg": "jpg",
    "image/webp": "webp",
}

def get_active_provider() -> str:
    explicit = os.getenv("AI_PROVIDER")
    if explicit:
        return explicit.lower()
    if GEMINI_API_KEY:
        return "gemini"
    if OPENAI_API_KEY:
        return "openai"
    return "simulation"

# Email / SMTP Configuration (Production & Development)
SMTP_HOST = (os.getenv("SMTP_HOST") or os.getenv("EMAIL_HOST") or os.getenv("MAIL_HOST") or "").strip()
SMTP_USER = (os.getenv("SMTP_USER") or os.getenv("SMTP_USERNAME") or os.getenv("EMAIL_USER") or os.getenv("MAIL_USERNAME") or "").strip()
SMTP_PASSWORD = (os.getenv("SMTP_PASSWORD") or os.getenv("SMTP_PASS") or os.getenv("EMAIL_PASSWORD") or os.getenv("MAIL_PASSWORD") or "").strip()
_port_raw = (os.getenv("SMTP_PORT") or os.getenv("EMAIL_PORT") or os.getenv("MAIL_PORT") or "").strip()

# SSL / TLS auto-negotiation
_ssl_env = (os.getenv("SMTP_USE_SSL") or os.getenv("EMAIL_USE_SSL") or "").strip().lower()
SMTP_USE_SSL = _ssl_env in ("true", "1", "yes")

if _port_raw:
    try:
        SMTP_PORT = int(_port_raw)
    except ValueError:
        SMTP_PORT = 465 if SMTP_USE_SSL else 587
else:
    SMTP_PORT = 465 if SMTP_USE_SSL else 587

# If port 465 is specified, SSL is implied
if SMTP_PORT == 465:
    SMTP_USE_SSL = True

_tls_env = (os.getenv("SMTP_USE_TLS") or os.getenv("EMAIL_USE_TLS") or "").strip().lower()
if _tls_env:
    SMTP_USE_TLS = _tls_env in ("true", "1", "yes")
else:
    # Use STARTTLS for port 587/25/2525 unless SSL is active
    SMTP_USE_TLS = not SMTP_USE_SSL

SMTP_FROM_EMAIL = (
    os.getenv("SMTP_FROM_EMAIL")
    or os.getenv("EMAIL_FROM")
    or os.getenv("MAIL_FROM")
    or (SMTP_USER if "@" in SMTP_USER else "noreply@tracegate.io")
).strip()
SMTP_FROM_NAME = (os.getenv("SMTP_FROM_NAME") or os.getenv("EMAIL_FROM_NAME") or "Tracegate Security").strip()

# Optional third-party transactional email API keys
RESEND_API_KEY = (os.getenv("RESEND_API_KEY") or "").strip()

# EMAIL_DEV_MODE strictly defaults to False so real email delivery is attempted for any user.
# In automated test suites, the test harness sets TESTING=1 or EMAIL_DEV_MODE=true.
EMAIL_DEV_MODE = os.getenv("EMAIL_DEV_MODE", "false").strip().lower() in ("true", "1", "yes")

