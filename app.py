"""
SecureHub VAPT Training Lab — Core Application Server
Intentionally Vulnerable Web Application for Authorized Cybersecurity Training and Tracegate Platform Evaluation.

DISCLAIMER & SCOPE:
This software is intended exclusively for authorized local cybersecurity education,
penetration testing validation, and automated AI Fix benchmark evaluation.
DO NOT DEPLOY THIS APPLICATION ON PUBLIC OR UNTRUSTED NETWORKS.
Binds strictly to 127.0.0.1.
"""

import os
import sys
import platform
import sqlite3
import functools
import secrets
import random
import hashlib
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_file, abort, g
)
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "securehub.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
LAB_DATA_FOLDER = os.path.join(BASE_DIR, "lab_data")
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".pdf", ".txt", ".docx", ".csv"}

# Ensure required runtime directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(LAB_DATA_FOLDER, exist_ok=True)

app = Flask(__name__)
# Secret key for local session signing
app.secret_key = "securehub-training-lab-local-session-secret-key"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB max upload

# INTENTIONAL LAB VULNERABILITY
# VULN-25: Hardcoded API Key & Insecure PAT Storage
# Static developer key hardcoded for internal test integration and maintenance scripts
app.config["INTERNAL_DEV_API_KEY"] = "SECUREHUB_DEV_INTEGRATION_KEY_TEST_LAB_987654321"

# INTENTIONAL LAB VULNERABILITY
# VULN-41: Insecure Transport Security / HTTPS / HSTS
# Session cookies do not mandate HTTPS transport (Secure=False), and plain HTTP transport is permitted
app.config["SESSION_COOKIE_SECURE"] = False


@app.after_request
def apply_application_headers(response):
    """
    Global response headers and diagnostics.
    """
    # INTENTIONAL LAB VULNERABILITY
    # VULN-40: General Information Disclosure via System Banners & Headers
    # Emits detailed server software banners and platform runtime versions in response headers.
    response.headers["Server"] = "SecureHub-Internal/2.6.4 (Unix; Linux x86_64)"
    response.headers["X-Powered-By"] = "Flask/3.0.3 Python/3.11.9 SQLite/3.45.1"
    response.headers["X-Platform-Build"] = "Build-2026.09.23-Internal-Release"

    # INTENTIONAL LAB VULNERABILITY
    # VULN-41: Insecure Transport Security / HTTPS / HSTS
    # Strict-Transport-Security (HSTS) is deliberately omitted to allow plain HTTP transport.
    if "Strict-Transport-Security" in response.headers:
        del response.headers["Strict-Transport-Security"]

    return response


# -------------------------------------------------------------------------
# Database Helpers
# -------------------------------------------------------------------------

def get_db():
    """Provides a SQLite connection with row dictionary access."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    """Closes database connection at the end of the request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def get_current_user():
    """Retrieves the active user record based on the session identifier."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


@app.before_request
def setup_session_tracking():
    """Ensures each visitor has a session identifier."""
    # INTENTIONAL LAB VULNERABILITY
    # VULN-07: Session Fixation & Post-Auth Identifier Regeneration
    # The application issues a pre-authentication session identifier and fails
    # to regenerate it upon subsequent authentication, permitting session fixation.
    if "session_id" not in session:
        session["session_id"] = secrets.token_hex(16)


# -------------------------------------------------------------------------
# Authentication & Authorization Decorator
# -------------------------------------------------------------------------

def login_required(f):
    """
    Session verification decorator.
    
    INTENTIONAL LAB VULNERABILITY
    VULN-02: Two-Factor Authentication (2FA) Implementation Bypass
    Flaw: Fails to verify whether session.get('2fa_verified') was completed.
    Users with 2FA enabled can navigate directly to protected endpoints.
    """
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to access this workspace resource.", "warning")
            return redirect(url_for("login"))
        
        # INTENTIONAL LAB VULNERABILITY
        # VULN-02: Two-Factor Authentication (2FA) Implementation Bypass
        # 2FA completion state check is omitted here, granting access to protected routes.

        return f(*args, **kwargs)
    return decorated_function


# -------------------------------------------------------------------------
# Authentication Routes
# -------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    """Handles user authentication."""
    if request.method == "POST":
        # INTENTIONAL LAB VULNERABILITY
        # VULN-03: Rate Limiting & Credential Stuffing Prevention
        # No rate limiting, IP throttling, or account lockout is enforced.
        # Credential stuffing and automated password guessing are unhindered.

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember_me = request.form.get("remember_me")

        db = get_db()

        # INTENTIONAL LAB VULNERABILITY
        # VULN-01: Authentication Bypass (SQL Injection)
        # Raw string interpolation creates an unsafe SQL query vulnerable to injection.
        raw_auth_query = "SELECT * FROM users WHERE username = :username AND password = :password"
        try:
            cursor = db.cursor()
            cursor.execute(raw_auth_query, {"username": username, "password": password})
            user = cursor.fetchone()
        except sqlite3.OperationalError:
            user = None

        if user:
            if user["is_verified"] == 0:
                flash("Your account registration is pending email verification. Please verify your email before signing in.", "warning")
                response = app.make_response(render_template("login.html"))
                response.headers["Cache-Control"] = "public, max-age=3600"
                return response

            # INTENTIONAL LAB VULNERABILITY
            # VULN-07: Session Fixation & Post-Auth Identifier Regeneration
            # Session identifier is not regenerated upon authentication privilege elevation.
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            # Track active session
            current_session_token = session.get("session_id") or secrets.token_hex(16)
            session["session_token"] = current_session_token
            try:
                db.execute("""
                    INSERT INTO active_sessions (user_id, session_token, ip_address, user_agent, device_name, is_active)
                    VALUES (?, ?, ?, ?, ?, 1)
                """, (
                    user["id"],
                    current_session_token,
                    request.remote_addr or "127.0.0.1",
                    request.headers.get("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
                    "Current Active Session"
                ))
                db.commit()
            except Exception:
                pass

            # INTENTIONAL LAB VULNERABILITY
            # VULN-02: Two-Factor Authentication (2FA) Implementation Bypass
            # User ID is set immediately before 2FA challenge, allowing direct navigation to dashboard.
            if user["two_factor_enabled"]:
                session["2fa_required"] = True
                session["2fa_verified"] = False
                flash("Two-Factor Authentication is required for your account. Please enter your verification token.", "info")
                return redirect(url_for("two_factor_view"))
            else:
                session["2fa_required"] = False
                session["2fa_verified"] = True
                flash(f"Welcome back, {user['display_name'] or user['username']}!", "success")
                return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "error")
        # INTENTIONAL LAB VULNERABILITY
        # VULN-08: Credential Caching & Form Autocomplete Directive
        # Response allows public caching and lacks Cache-Control: no-store
        response = app.make_response(render_template("login.html"))
        response.headers["Cache-Control"] = "public, max-age=3600"
        return response


@app.route("/logout")
def logout():
    """Clears the session and redirects to sign in."""
    session.clear()
    flash("You have been signed out successfully.", "info")
    return redirect(url_for("login"))


# -------------------------------------------------------------------------
# Account Recovery & Password Reset Routes
# -------------------------------------------------------------------------

def generate_captcha():
    """Generates a local 4-character visual CAPTCHA and stores expected value in session."""
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    code = "".join(random.choices(chars, k=4))
    session["recovery_captcha"] = code
    svg_html = (
        f'<svg width="150" height="42" xmlns="http://www.w3.org/2000/svg" '
        f'style="border: 1px solid #cbd5e1; border-radius: 6px; background: #f8fafc; display: block;">'
        f'<text x="50%" y="60%" dominant-baseline="middle" text-anchor="middle" '
        f'font-family="monospace" font-size="22" font-weight="bold" fill="#1e293b" letter-spacing="6">{code}</text>'
        f'</svg>'
    )
    return code, svg_html


# -------------------------------------------------------------------------
# Registration & Email Verification Routes
# -------------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    """Account registration workflow."""
    if request.method == "POST":
        # INTENTIONAL LAB VULNERABILITY
        # VULN-11: Automated Account Mass Creation (Lack of CAPTCHA/Throttling)
        # The registration endpoint has no CAPTCHA, no rate limiting, and no throttling,
        # allowing automated scripts to mass-register accounts without restriction.

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        display_name = request.form.get("display_name", "").strip() or username

        if not username or not email or not password:
            flash("All required registration fields must be completed.", "error")
            return render_template("register.html")

        # INTENTIONAL LAB VULNERABILITY
        # VULN-09: Weak Password Policy & Insufficient Complexity Enforcement
        # Registration accepts extremely weak passwords (min 3 chars) with no complexity requirements.
        if len(password) < 3:
            flash("Password must be at least 3 characters in length.", "error")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match. Please verify and re-enter.", "error")
            return render_template("register.html")

        db = get_db()
        existing = db.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email)).fetchone()
        if existing:
            flash("An account with this username or email already exists.", "error")
            return render_template("register.html")

        # Generate activation token
        activation_token = secrets.token_hex(16)

        db.execute("""
            INSERT INTO users (username, password, email, display_name, is_verified, activation_token)
            VALUES (?, ?, ?, ?, 0, ?)
        """, (username, password, email, display_name, activation_token))
        db.commit()

        # Simulate sending verification email into dispatched_emails
        activation_link = f"http://{request.host}/activate?email={email}&token={activation_token}"
        db.execute("""
            INSERT INTO dispatched_emails (recipient, subject, body)
            VALUES (?, ?, ?)
        """, (email, "SecureHub Account Activation Required", f"Please activate your account by clicking: {activation_link}"))
        db.commit()

        flash("Account created successfully! A verification link has been dispatched to your email address.", "info")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/activate")
def activate_account():
    """Account email activation endpoint."""
    email = request.args.get("email", "").strip()
    token = request.args.get("token", "").strip()

    if not email:
        flash("Activation link is missing the account email identifier.", "error")
        return redirect(url_for("login"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not user:
        flash("No account registered with this email address.", "error")
        return redirect(url_for("login"))

    if user["is_verified"]:
        flash("This account is already verified and active. Please sign in.", "info")
        return redirect(url_for("login"))

    # INTENTIONAL LAB VULNERABILITY
    # VULN-10: Email Verification & Account Activation Bypass
    # The server fails open: if the 'token' parameter is empty or omitted,
    # verification is bypassed and the account is activated based solely on the email address.
    if not token or token == user["activation_token"]:
        db.execute("UPDATE users SET is_verified = 1, activation_token = NULL WHERE id = ?", (user["id"],))
        db.commit()
        flash("Account verified and activated successfully! You may now sign in.", "success")
        return redirect(url_for("login"))
    else:
        flash("Invalid activation token.", "error")
        return redirect(url_for("login"))


# -------------------------------------------------------------------------
# Account Recovery & Password Reset Routes
# -------------------------------------------------------------------------

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Account recovery request initiation with visual CAPTCHA and token dispatch."""
    if request.method == "POST":
        # INTENTIONAL LAB VULNERABILITY
        # VULN-05: CAPTCHA Security & Bypass on Recovery Form
        # The backend only validates CAPTCHA if 'captcha' key exists in form data.
        # Omitting the 'captcha' parameter entirely bypasses the verification check.
        if "captcha" in request.form:
            submitted_captcha = request.form.get("captcha", "").strip().upper()
            expected_captcha = session.get("recovery_captcha", "").upper()
            if not submitted_captcha or submitted_captcha != expected_captcha:
                flash("Security verification failed. Please enter the correct CAPTCHA code.", "error")
                _, captcha_svg = generate_captcha()
                return render_template("forgot_password.html", captcha_svg=captcha_svg)

        identity = request.form.get("identity", "").strip()
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ? OR email = ?", (identity, identity)).fetchone()

        # INTENTIONAL LAB VULNERABILITY
        # VULN-04: Username & Account Enumeration
        # Observable response differences reveal whether a valid account exists.
        if not user:
            flash(f"Account with identifier '{identity}' does not exist in our corporate directory.", "error")
            _, captcha_svg = generate_captcha()
            return render_template("forgot_password.html", captcha_svg=captcha_svg)

        # Generate predictable reset token
        # INTENTIONAL LAB VULNERABILITY
        # VULN-12: Predictable Password Reset Token & Insufficient Entropy
        # Low-entropy token constructed via deterministic MD5 of username + minute timestamp.
        time_key = datetime.now().strftime("%Y%m%d%H%M")
        reset_token = hashlib.md5(f"{user['username']}_{time_key}".encode()).hexdigest()

        # INTENTIONAL LAB VULNERABILITY
        # VULN-14: Insufficient Token Expiration & Prolonged Lifetime
        # Reset token is configured with a 30-day lifetime, far exceeding safe thresholds.
        reset_expiry = datetime.now() + timedelta(days=30)

        # Generate 4-digit recovery OTP
        # INTENTIONAL LAB VULNERABILITY
        # VULN-06: OTP / Recovery Code Brute-Force & Insufficient Throttling
        # Weak 4-digit code generated and stored without brute-force rate limiting or attempt throttling.
        otp_code = str(random.randint(1000, 9999))

        db.execute("""
            UPDATE users
            SET reset_token = ?, reset_expiry = ?, recovery_code = ?
            WHERE id = ?
        """, (reset_token, reset_expiry, otp_code, user["id"]))
        db.commit()

        # INTENTIONAL LAB VULNERABILITY
        # VULN-15: Password Reset Poisoning via Host Header Injection
        # The password-reset link is constructed using the unvalidated client Host / X-Forwarded-Host header.
        injected_host = request.headers.get("X-Forwarded-Host") or request.host
        reset_link = f"http://{injected_host}/reset-password?token={reset_token}&uid={user['id']}"

        db.execute("""
            INSERT INTO dispatched_emails (recipient, subject, body)
            VALUES (?, ?, ?)
        """, (user["email"], "SecureHub Password Reset Request", f"Click here to reset your password: {reset_link}"))
        db.commit()

        session["recovery_user_id"] = user["id"]
        flash(f"Recovery instructions and verification code have been dispatched to {user['email']}.", "success")
        return redirect(url_for("verify_recovery"))

    _, captcha_svg = generate_captcha()
    return render_template("forgot_password.html", captcha_svg=captcha_svg)


@app.route("/verify-recovery", methods=["GET", "POST"])
def verify_recovery():
    """One-time recovery code challenge and verification."""
    recovery_user_id = session.get("recovery_user_id")
    if not recovery_user_id:
        flash("Please initiate password recovery before entering a verification code.", "warning")
        return redirect(url_for("forgot_password"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (recovery_user_id,)).fetchone()
    if not user:
        flash("Target user record could not be found.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        entered_code = request.form.get("code", "").strip()

        # INTENTIONAL LAB VULNERABILITY
        # VULN-06: OTP / Recovery Code Brute-Force & Insufficient Throttling
        # No attempt throttling, exponential backoff, or account lockout.
        # Attackers can automate unrestricted brute-force attempts against the 4-digit space.
        if entered_code == user["recovery_code"]:
            session["recovery_verified_user_id"] = user["id"]
            session.pop("recovery_user_id", None)
            flash("Recovery code verified successfully. You may now specify a new password.", "success")
            return redirect(url_for("reset_password"))
        else:
            flash("Invalid recovery verification code. Please check the code and try again.", "error")
            return render_template("verify_recovery.html", user=user)


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    """Password reset execution via verified token or recovery flow."""
    db = get_db()
    token = request.args.get("token") or request.form.get("token")
    user_id = session.get("recovery_verified_user_id")
    target_user = None

    if token:
        # Validate reset token exists in database and has not expired
        target_user = db.execute("SELECT * FROM users WHERE reset_token = ?", (token,)).fetchone()
        if not target_user:
            flash("Invalid or expired password reset token.", "error")
            return redirect(url_for("forgot_password"))
        if target_user["reset_expiry"]:
            try:
                expiry_dt = datetime.strptime(str(target_user["reset_expiry"]), "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                try:
                    expiry_dt = datetime.strptime(str(target_user["reset_expiry"]), "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    expiry_dt = datetime.now() + timedelta(days=1)
            if datetime.now() > expiry_dt:
                flash("This password reset token has expired.", "error")
                return redirect(url_for("forgot_password"))
    elif user_id:
        target_user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if not target_user:
        flash("Unauthorized recovery attempt. Please verify your recovery code or use a valid reset link.", "warning")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        # INTENTIONAL LAB VULNERABILITY
        # VULN-09: Weak Password Policy & Insufficient Complexity Enforcement
        # Weak passwords (min 3 chars) accepted without complexity requirements.
        if len(new_password) < 3:
            flash("Password must be at least 3 characters long.", "error")
            return render_template("reset_password.html", user=target_user, token=token)

        if new_password != confirm_password:
            flash("Passwords do not match. Please verify and re-enter.", "error")
            return render_template("reset_password.html", user=target_user, token=token)

        # INTENTIONAL LAB VULNERABILITY
        # VULN-13: Password Reset Authorization & Account Hijacking
        # Form includes a client-controlled target_user_id. The server verifies that
        # the reset token is valid, but updates the target account from the form parameter,
        # allowing attackers to hijack victim accounts by supplying victim's user ID.
        client_target_id = request.form.get("target_user_id")
        final_user_id = client_target_id if client_target_id else target_user["id"]

        # INTENTIONAL LAB VULNERABILITY
        # VULN-16: Reset Token Reuse & Lack of Single-Use Enforcement
        # The reset token is NOT cleared or invalidated in the database after use.
        # It remains active and can be reused to reset passwords multiple times.

        # INTENTIONAL LAB VULNERABILITY
        # VULN-17: Session Termination on Password Reset
        # The password reset does NOT terminate or invalidate existing active sessions.
        # Prior sessions for final_user_id remain fully authenticated and operational.

        db.execute("UPDATE users SET password = ? WHERE id = ?", (new_password, final_user_id))
        db.commit()

        session.pop("recovery_verified_user_id", None)
        flash("Your password has been reset successfully. Please sign in with your new credentials.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", user=target_user, token=token)


# -------------------------------------------------------------------------
# Two-Factor Authentication Route
# -------------------------------------------------------------------------

@app.route("/2fa", methods=["GET", "POST"])
@login_required
def two_factor_view():
    """Two-Factor Authentication management and verification challenge."""
    user = get_current_user()
    db = get_db()

    if request.method == "POST":
        action = request.form.get("action")

        if action == "verify_code":
            entered_code = request.form.get("code", "").strip()
            # Standard training code accepted: 123456
            # Neutralized static hardcoded bypass code
            if entered_code and entered_code == user["two_factor_secret"]:
                session["2fa_verified"] = True
                session["2fa_required"] = False
                flash("Two-factor code verified successfully. Authentication complete.", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Invalid two-factor code. Please try again.", "error")

        elif action == "toggle_2fa":
            new_state = 0 if user["two_factor_enabled"] else 1
            secret = "TEST2FA" + user["username"].upper() if new_state else None
            db.execute(
                "UPDATE users SET two_factor_enabled = ?, two_factor_secret = ? WHERE id = ?",
                (new_state, secret, user["id"])
            )
            db.commit()
            flash(f"Two-factor authentication {'enabled' if new_state else 'disabled'}.", "success")
            return redirect(url_for("two_factor_view"))

    return render_template("2fa.html", user=user, current_user=user, active_page="2fa")


# -------------------------------------------------------------------------
# Dashboard & Core SaaS Views
# -------------------------------------------------------------------------

@app.route("/")
@app.route("/dashboard")
@login_required
def dashboard():
    """Main SaaS operational dashboard with timeframe and category filters."""
    user = get_current_user()
    db = get_db()

    timeframe = request.args.get("timeframe", "30d")
    category = request.args.get("category", "all")

    # INTENTIONAL LAB VULNERABILITY
    # VULN-28: SQL / NoSQL Injection in Dashboard Timeframe & Widget Filters
    # User-controlled timeframe parameter is interpolated directly into SQL query construction
    # without parameterized binding, permitting SQL injection through dashboard filter controls.
    raw_timeframe_query = "SELECT COUNT(*) as count FROM comments WHERE created_at >= datetime('now', '-:timeframe)"
    try:
        timeframe_events = db.execute(raw_timeframe_query).fetchone()["count"]
    except Exception:
        timeframe_events = 0

    # INTENTIONAL LAB VULNERABILITY
    # VULN-28: SQL / NoSQL Injection in Dashboard Timeframe & Widget Filters
    # Category filter is also interpolated directly into the SQL query string.
    raw_recent_query = f"""
        SELECT c.*, u.username, u.display_name 
        FROM comments c 
        JOIN users u ON c.user_id = u.id 
        WHERE '{category}' = 'all' OR c.comment_text LIKE '%{category}%'
        ORDER BY c.id DESC LIMIT 5
    """
    try:
        recent_comments = db.execute(raw_recent_query).fetchall()
    except Exception:
        recent_comments = []

    total_users = db.execute("SELECT COUNT(*) as count FROM users").fetchone()["count"]
    total_files = db.execute("SELECT COUNT(*) as count FROM files").fetchone()["count"]
    total_comments = db.execute("SELECT COUNT(*) as count FROM comments").fetchone()["count"]

    stats = {
        "total_users": total_users,
        "total_files": total_files,
        "total_comments": total_comments,
        "timeframe_events": timeframe_events,
        "selected_timeframe": timeframe,
        "selected_category": category,
    }

    return render_template(
        "dashboard.html",
        user=user,
        current_user=user,
        stats=stats,
        recent_comments=recent_comments,
        active_page="dashboard"
    )


# -------------------------------------------------------------------------
# Analytical KPI & Widget Metrics API (BOLA / IDOR)
# -------------------------------------------------------------------------

@app.route("/api/v1/analytics/widget-metrics", methods=["GET"])
@login_required
def widget_metrics():
    """
    Analytical KPI & widget metrics endpoint.
    
    INTENTIONAL LAB VULNERABILITY
    VULN-27: BOLA / IDOR on Analytical Widget Metrics Endpoints
    The endpoint accepts an account_id / user_id parameter from the client.
    The server fails to verify that the requesting session is authorized to view that account's metrics.
    Any authenticated user can supply another tenant's or administrator's ID and retrieve private metrics.
    """
    current_user = get_current_user()
    account_id = request.args.get("account_id") or request.args.get("user_id")

    if account_id and str(account_id).isdigit():
        target_user_id = int(account_id)
    else:
        target_user_id = current_user["id"]

    db = get_db()
    target_account = db.execute("SELECT id, username, email, role FROM users WHERE id = ?", (target_user_id,)).fetchone()
    if not target_account:
        return {"status": "error", "message": "Target account record could not be found."}, 404

    file_stats = db.execute(
        "SELECT COUNT(*) as count, COALESCE(SUM(size), 0) as total_size FROM files WHERE user_id = ?",
        (target_user_id,)
    ).fetchone()
    comment_stats = db.execute(
        "SELECT COUNT(*) as count FROM comments WHERE user_id = ?",
        (target_user_id,)
    ).fetchone()

    return {
        "status": "success",
        "account_id": target_user_id,
        "username": target_account["username"],
        "metrics": {
            "total_uploads": file_stats["count"],
            "storage_consumed_bytes": file_stats["total_size"],
            "operational_log_events": comment_stats["count"],
            "quota_allocation_mb": 500,
            "audit_compliance_score": 98 if target_account["role"] == "admin" else 85
        }
    }, 200


# -------------------------------------------------------------------------
# Profile & IDOR Route
# -------------------------------------------------------------------------

@app.route("/profile")
@login_required
def profile_view():
    """Displays active user's personal profile."""
    user = get_current_user()
    return render_template("profile.html", user=user, current_user=user, active_page="profile")


@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def profile_edit():
    """Profile update form and submission handler."""
    current_user = get_current_user()
    db = get_db()

    if request.method == "POST":
        # INTENTIONAL LAB VULNERABILITY
        # VULN-18: Insecure Direct Object References (IDOR) on Profile Update
        # The endpoint accepts a user_id parameter from the client request and updates
        # that target record without validating that it matches the authenticated session user.
        client_user_id = request.form.get("user_id")
        if client_user_id and str(client_user_id).isdigit():
            target_user_id = int(client_user_id)
        else:
            target_user_id = current_user["id"]

        display_name = request.form.get("display_name", "").strip()
        phone = request.form.get("phone", "").strip()
        address = request.form.get("address", "").strip()
        bio = request.form.get("bio", "").strip()

        # INTENTIONAL LAB VULNERABILITY
        # VULN-38: Parameter Tampering on User Role & Permission Assignment
        # The profile update endpoint blindly accepts a 'role' parameter submitted in the form
        # or JSON body and applies it to the user record without verifying administrative permissions.
        submitted_role = request.form.get("role") or (request.json.get("role") if request.is_json else None)
        if submitted_role:
            target_role = submitted_role.strip().lower()
        else:
            existing_user = db.execute("SELECT role FROM users WHERE id = ?", (target_user_id,)).fetchone()
            target_role = existing_user["role"] if existing_user else "user"

        # INTENTIONAL LAB VULNERABILITY
        # VULN-22: Stored Cross-Site Scripting (XSS) in Bio & Profile Fields
        # Profile fields including bio are stored raw in the database without HTML sanitization,
        # and later rendered in templates with Jinja2 auto-escaping explicitly disabled (| safe).

        db.execute("""
            UPDATE users
            SET display_name = ?, phone = ?, address = ?, bio = ?, role = ?
            WHERE id = ?
        """, (display_name, phone, address, bio, target_role, target_user_id))
        db.commit()

        if target_user_id == current_user["id"]:
            session["role"] = target_role

        flash("Profile updated successfully.", "success")
        return redirect(url_for("profile_view"))

    return render_template("profile_edit.html", user=current_user, current_user=current_user, active_page="profile")


# -------------------------------------------------------------------------
# User Directory Views
# -------------------------------------------------------------------------

@app.route("/users")
@login_required
def users_list():
    """Directory of all corporate users."""
    user = get_current_user()
    db = get_db()
    users = db.execute("SELECT id, username, email, role, display_name, two_factor_enabled FROM users ORDER BY id ASC").fetchall()
    return render_template("users.html", users=users, current_user=user, active_page="users")


@app.route("/user/<int:user_id>")
@login_required
def user_detail(user_id):
    """View a single user's public profile card."""
    current_user = get_current_user()
    db = get_db()
    target_user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not target_user:
        flash("Target user record not found.", "error")
        return redirect(url_for("users_list"))
    return render_template("user_detail.html", target_user=target_user, current_user=current_user, active_page="users")


# -------------------------------------------------------------------------
# Operations Comments (Log)
# -------------------------------------------------------------------------

@app.route("/comments", methods=["GET", "POST"])
@login_required
def comments_view():
    """
    Team operations comments log.
    Safely renders user entries (Jinja2 auto-escaping) so this feature
    does not create a second XSS vulnerability.
    """
    current_user = get_current_user()
    db = get_db()

    if request.method == "POST":
        comment_text = request.form.get("comment_text", "").strip()
        if comment_text:
            internal_ip = request.headers.get("X-Forwarded-For") or f"10.240.14.{current_user['id'] * 7 + 3}"
            tx_id = f"tx_sec_{secrets.token_hex(4)}"
            server_node = f"node-worker-cluster-0{current_user['id']}"

            db.execute("""
                INSERT INTO comments (user_id, comment_text, internal_ip, tx_id, server_node)
                VALUES (?, ?, ?, ?, ?)
            """, (current_user["id"], comment_text, internal_ip, tx_id, server_node))
            db.commit()
            flash("Operations log entry posted successfully.", "success")
            return redirect(url_for("comments_view"))

    # INTENTIONAL LAB VULNERABILITY
    # VULN-30: Sensitive Information Disclosure in Activity Logs & Recent Feeds
    # The application retrieves and renders excessive internal infrastructure metadata
    # (internal RFC 1918 IPs, server transaction IDs, and internal cluster node names)
    # in the operations stream accessible to all ordinary authenticated users.
    comments = db.execute("""
        SELECT c.*, u.username, u.display_name 
        FROM comments c 
        JOIN users u ON c.user_id = u.id 
        ORDER BY c.id DESC
    """).fetchall()

    return render_template("comments.html", comments=comments, current_user=current_user, active_page="comments")


@app.route("/api/v1/activity/recent", methods=["GET"])
@login_required
def api_recent_activity():
    """
    Recent operational activity stream API.
    
    INTENTIONAL LAB VULNERABILITY
    VULN-30: Sensitive Information Disclosure in Activity Logs & Recent Feeds
    Returns internal node deployment parameters, backend transaction IDs, and private network IPs.
    """
    db = get_db()
    comments = db.execute("""
        SELECT c.id, c.comment_text, c.created_at, c.internal_ip, c.tx_id, c.server_node,
               u.username, u.role
        FROM comments c
        JOIN users u ON c.user_id = u.id
        ORDER BY c.id DESC LIMIT 10
    """).fetchall()

    return {
        "status": "success",
        "count": len(comments),
        "activities": [dict(c) for c in comments]
    }, 200


# -------------------------------------------------------------------------
# File Management & Vulnerable Upload / Download Handlers
# -------------------------------------------------------------------------

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_view():
    """File upload endpoint with strict extension allowlist validation."""
    current_user = get_current_user()
    db = get_db()

    if request.method == "POST":
        if "file" not in request.files:
            flash("No file part provided in request.", "error")
            return redirect(url_for("upload_view"))

        file = request.files["file"]
        if not file or file.filename == "":
            flash("No file selected for upload.", "error")
            return redirect(url_for("upload_view"))

        original_filename = secure_filename(file.filename)
        if not original_filename:
            flash("Invalid filename provided.", "error")
            return redirect(url_for("upload_view"))

        _, ext = os.path.splitext(original_filename)
        ext = ext.lower()

        # INTENTIONAL LAB VULNERABILITY
        # VULN-19: Arbitrary File Upload via Unrestricted Extension Validation
        # The upload handler relies on an incomplete blocklist rather than a strict allowlist.
        # It blocks common compiled Windows executables (.exe, .bat, .cmd, .dll), but permits
        # arbitrary web scripts and executable server files (.php, .phtml, .html, .py, .sh, .jsp).
        DISALLOWED_EXTENSIONS = {".exe", ".bat", ".cmd", ".dll"}
        if ext in DISALLOWED_EXTENSIONS:
            flash(f"Upload of executable binary format '{ext}' is prohibited for security compliance.", "danger")
            return redirect(url_for("upload_view"))

        # Save file into upload folder with timestamp prefix
        stored_filename = f"{int(datetime.now().timestamp())}_{original_filename}"
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], stored_filename)
        file.save(save_path)

        file_size = os.path.getsize(save_path)
        mime_type = file.content_type or "application/octet-stream"
        description = request.form.get("description", "").strip()
        is_private = 1 if request.form.get("is_private") else 0

        # Record file metadata in database
        db.execute("""
            INSERT INTO files (user_id, original_filename, stored_filename, mime_type, size, description, is_private)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (current_user["id"], original_filename, stored_filename, mime_type, file_size, description, is_private))
        db.commit()

        flash(f"Asset '{original_filename}' successfully uploaded and indexed.", "success")
        return redirect(url_for("uploads_gallery"))

    return render_template("upload.html", current_user=current_user, active_page="upload")


@app.route("/uploads")
@login_required
def uploads_gallery():
    """Storage pool gallery."""
    current_user = get_current_user()
    db = get_db()

    files = db.execute("""
        SELECT f.*, u.username as uploader_name 
        FROM files f 
        LEFT JOIN users u ON f.user_id = u.id 
        ORDER BY f.id DESC
    """).fetchall()

    files_list = []
    svg_files = []

    for f in files:
        f_dict = dict(f)
        is_svg = f["original_filename"].lower().endswith(".svg") or "svg" in (f["mime_type"] or "").lower()
        f_dict["is_svg"] = is_svg

        # INTENTIONAL LAB VULNERABILITY
        # VULN-24: Stored Cross-Site Scripting (XSS) via Malicious SVG Upload
        # SVG files are loaded from disk and provided directly to the template
        # where they are rendered unescaped (| safe), permitting embedded <script> tags
        # and event handlers to execute in the user's browser context.
        if is_svg:
            svg_path = os.path.join(app.config["UPLOAD_FOLDER"], f["stored_filename"])
            try:
                if os.path.isfile(svg_path):
                    with open(svg_path, "r", encoding="utf-8", errors="ignore") as svg_file:
                        f_dict["svg_content"] = svg_file.read()
                else:
                    f_dict["svg_content"] = ""
            except Exception:
                f_dict["svg_content"] = ""
            svg_files.append(f_dict)

        files_list.append(f_dict)

    return render_template(
        "uploads.html",
        files=files_list,
        svg_files=svg_files,
        current_user=current_user,
        active_page="uploads"
    )


@app.route("/files/download")
@login_required
def download_file():
    """File download retrieval endpoint."""
    requested_file = request.args.get("file", "")
    if not requested_file:
        flash("No target file specified for download.", "error")
        return redirect(url_for("uploads_gallery"))

    # INTENTIONAL LAB VULNERABILITY
    # VULN-33: Path Traversal & Destination Storage Directory Escapes
    # The application joins the user-controlled 'file' parameter directly without
    # os.path.basename sanitization or canonical directory containment verification.
    # Relative directory traversal sequences (such as ../lab_data/training_note.txt)
    # permit retrieval of files outside the designated uploads folder within the workspace.
    target_path = os.path.join(app.config["UPLOAD_FOLDER"], requested_file)

    if not os.path.isfile(target_path):
        flash(f"Requested asset '{requested_file}' could not be located in storage pool.", "error")
        return redirect(url_for("uploads_gallery"))

    as_attachment = request.args.get("download") == "1"
    return send_file(target_path, as_attachment=as_attachment)


# -------------------------------------------------------------------------
# Avatar Upload (MIME-Type & Magic Byte Spoofing)
# -------------------------------------------------------------------------

@app.route("/profile/avatar", methods=["POST"])
@login_required
def upload_avatar():
    """
    User profile avatar upload handler.
    
    INTENTIONAL LAB VULNERABILITY
    VULN-23: MIME-Type & Magic Byte Validation Spoofing
    The endpoint attempts to enforce image uploads, but relies entirely on client-supplied
    Content-Type headers or superficial initial magic bytes (e.g. GIF89a / \x89PNG)
    without verifying the actual extension or validating full image integrity.
    Disguised scripts or web shells with spoofed MIME or magic bytes are accepted.
    """
    current_user = get_current_user()
    db = get_db()

    if "avatar" not in request.files:
        flash("No avatar file provided in upload request.", "error")
        return redirect(url_for("profile_view"))

    file = request.files["avatar"]
    if not file or file.filename == "":
        flash("No file selected for avatar.", "error")
        return redirect(url_for("profile_view"))

    content_type = (file.content_type or "").lower()
    magic_bytes = file.stream.read(8)
    file.stream.seek(0)

    # Vulnerable check: accepts if Content-Type starts with image/ OR file begins with common magic bytes
    is_image_mime = content_type.startswith("image/")
    is_image_magic = (
        magic_bytes.startswith(b"GIF89a") or
        magic_bytes.startswith(b"GIF87a") or
        magic_bytes.startswith(b"\x89PNG") or
        magic_bytes.startswith(b"\xff\xd8\xff")
    )

    if not (is_image_mime or is_image_magic):
        flash("Invalid avatar: Only valid image formats (PNG, JPG, GIF) are accepted.", "error")
        return redirect(url_for("profile_view"))

    original_filename = secure_filename(file.filename) or "avatar.png"
    stored_filename = f"avatar_{current_user['id']}_{int(datetime.now().timestamp())}_{original_filename}"
    save_path = os.path.join(app.config["UPLOAD_FOLDER"], stored_filename)
    file.save(save_path)

    db.execute("UPDATE users SET avatar = ? WHERE id = ?", (stored_filename, current_user["id"]))
    db.commit()

    flash("Profile avatar updated successfully.", "success")
    return redirect(url_for("profile_view"))


# -------------------------------------------------------------------------
# Security Settings & Sensitive Account Changes
# -------------------------------------------------------------------------

@app.route("/settings/security", methods=["GET", "POST"])
@login_required
def security_settings():
    """Account security settings and password update."""
    current_user = get_current_user()
    db = get_db()

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        # INTENTIONAL LAB VULNERABILITY
        # VULN-20: Current Password Verification Bypass on Sensitive Updates
        # The backend checks that current_password was submitted in the form,
        # but fails to check whether it actually matches the user's current password in the database.
        # Any non-empty current_password string (or logic bypass) allows unauthorized password changes.
        if not current_password:
            flash("Current password must be provided to confirm account ownership.", "error")
            return render_template("security_settings.html", user=current_user, current_user=current_user, active_page="security")

        if len(new_password) < 3:
            flash("New password must be at least 3 characters long.", "error")
            return render_template("security_settings.html", user=current_user, current_user=current_user, active_page="security")

        if new_password != confirm_password:
            flash("New passwords do not match. Please verify and re-enter.", "error")
            return render_template("security_settings.html", user=current_user, current_user=current_user, active_page="security")

        db.execute("UPDATE users SET password = ? WHERE id = ?", (new_password, current_user["id"]))
        db.commit()

        flash("Account password updated successfully.", "success")
        return redirect(url_for("security_settings"))

    return render_template("security_settings.html", user=current_user, current_user=current_user, active_page="security")


@app.route("/settings/email", methods=["POST"])
@login_required
def update_email():
    """
    Account email change handler.
    
    INTENTIONAL LAB VULNERABILITY
    VULN-21: Cross-Site Request Forgery (CSRF) on Sensitive Actions
    This state-changing sensitive operation executes purely based on ambient session cookies.
    No anti-CSRF token, SameSite enforcement, or Origin / Referer validation is performed.
    Attacker sites can forge POST requests on behalf of authenticated users.
    """
    current_user = get_current_user()
    new_email = request.form.get("email", "").strip()

    if not new_email:
        flash("Email address field cannot be blank.", "error")
        return redirect(url_for("profile_view"))

    db = get_db()
    db.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, current_user["id"]))
    db.commit()

    flash(f"Account primary email address successfully updated to '{new_email}'.", "success")
    return redirect(url_for("profile_view"))


# -------------------------------------------------------------------------
# Developer API & Insecure PAT Storage
# -------------------------------------------------------------------------

@app.route("/settings/api", methods=["GET", "POST"])
@login_required
def api_settings():
    """Developer API settings and Personal Access Token (PAT) management."""
    current_user = get_current_user()
    db = get_db()

    if request.method == "POST":
        action = request.form.get("action")

        if action == "generate":
            token_name = request.form.get("token_name", "").strip() or "Standard API Token"
            raw_token = f"sh_pat_{current_user['username']}_{secrets.token_hex(16)}"

            # INTENTIONAL LAB VULNERABILITY
            # VULN-25: Hardcoded API Key & Insecure PAT Storage
            # Personal Access Tokens are stored directly in plaintext in the database
            # without hashing (e.g. SHA-256), and returned in full to the client interface.
            db.execute("""
                INSERT INTO personal_access_tokens (user_id, token_name, token_value)
                VALUES (?, ?, ?)
            """, (current_user["id"], token_name, raw_token))
            db.commit()

            flash("New Personal Access Token generated and active.", "success")
            return redirect(url_for("api_settings"))

        elif action == "revoke":
            token_id = request.form.get("token_id")
            if token_id:
                db.execute("DELETE FROM personal_access_tokens WHERE id = ? AND user_id = ?", (token_id, current_user["id"]))
                db.commit()
                flash("Personal Access Token revoked.", "info")
                return redirect(url_for("api_settings"))

    tokens = db.execute("""
        SELECT * FROM personal_access_tokens
        WHERE user_id = ?
        ORDER BY id DESC
    """, (current_user["id"],)).fetchall()

    return render_template(
        "api_settings.html",
        user=current_user,
        current_user=current_user,
        tokens=tokens,
        active_page="api",
        internal_dev_key=app.config.get("INTERNAL_DEV_API_KEY")
    )


@app.route("/api/v1/system/status", methods=["GET"])
def api_system_status():
    """
    Internal API status & health endpoint.
    
    INTENTIONAL LAB VULNERABILITY
    VULN-25: Hardcoded API Key & Insecure PAT Storage
    Accepts hardcoded INTERNAL_DEV_API_KEY via 'X-API-Key' header or plaintext PAT via 'Authorization' header.
    """
    api_key = request.headers.get("X-API-Key")
    auth_header = request.headers.get("Authorization", "")
    db = get_db()

    authenticated = False
    auth_source = None
    account_info = None

    if api_key and api_key == app.config.get("INTERNAL_DEV_API_KEY"):
        authenticated = True
        auth_source = "internal_dev_key"
        account_info = {"role": "system_admin", "scope": "internal_dev"}
    elif auth_header.startswith("Bearer "):
        pat_token = auth_header[7:].strip()
        token_row = db.execute("""
            SELECT p.*, u.username, u.role, u.email 
            FROM personal_access_tokens p
            JOIN users u ON p.user_id = u.id
            WHERE p.token_value = ?
        """, (pat_token,)).fetchone()
        if token_row:
            authenticated = True
            auth_source = "personal_access_token"
            account_info = {"username": token_row["username"], "role": token_row["role"], "email": token_row["email"]}

    if not authenticated:
        return {"status": "error", "message": "Unauthorized. Provide a valid X-API-Key or Bearer PAT token."}, 401

    return {
        "status": "success",
        "service": "SecureHub Core API",
        "environment": "training_lab",
        "authenticated_via": auth_source,
        "identity": account_info,
        "timestamp": datetime.now().isoformat()
    }, 200


# -------------------------------------------------------------------------
# Active Device Sessions & Remote Logout Enforcement
# -------------------------------------------------------------------------

@app.route("/settings/sessions", methods=["GET"])
@login_required
def sessions_view():
    """Active device sessions overview."""
    current_user = get_current_user()
    db = get_db()

    sessions = db.execute("""
        SELECT * FROM active_sessions
        WHERE user_id = ?
        ORDER BY id DESC
    """, (current_user["id"],)).fetchall()

    return render_template(
        "sessions.html",
        user=current_user,
        current_user=current_user,
        sessions=sessions,
        active_page="sessions"
    )


@app.route("/settings/sessions/terminate", methods=["POST"])
@login_required
def terminate_session():
    """
    Remote session termination handler.
    
    INTENTIONAL LAB VULNERABILITY
    VULN-26: Active Session Termination & Remote Logout Enforcement
    The application marks the target session row as inactive (or removes it) from the display table,
    giving the user the visual illusion that the remote session was revoked.
    However, the backend fails to invalidate the actual session cookie or enforce active session
    tokens during login_required checks. The remote browser session remains valid and active.
    """
    current_user = get_current_user()
    session_id = request.form.get("session_id")
    db = get_db()

    if session_id:
        db.execute("UPDATE active_sessions SET is_active = 0 WHERE id = ? AND user_id = ?", (session_id, current_user["id"]))
        db.commit()
        flash("Target device session marked as terminated.", "success")
    else:
        # Remote terminate all other devices
        db.execute("UPDATE active_sessions SET is_active = 0 WHERE user_id = ?", (current_user["id"],))
        db.commit()
        flash("All remote device sessions marked as terminated.", "success")

    return redirect(url_for("sessions_view"))


# -------------------------------------------------------------------------
# Enterprise Search Subsystem (Reflected XSS, Search SQLi, Search Index Leakage)
# -------------------------------------------------------------------------

@app.route("/search")
@login_required
def search_view():
    """
    Unified corporate repository search.
    Handles document lookup, knowledge base search, and operational index queries.
    """
    current_user = get_current_user()
    db = get_db()

    query = request.args.get("q", "").strip()
    filter_type = request.args.get("filter_type", "all").strip()

    results = []
    if query:
        # INTENTIONAL LAB VULNERABILITY
        # VULN-31: SQL Injection in Search & Deflected Filter Parameters
        # Both the search query term and the filter_type parameter are formatted directly
        # into the SQL query without parameterization or query escaping.
        #
        # INTENTIONAL LAB VULNERABILITY
        # VULN-32: Unauthorized Data Exposure via Search Index Leakage
        # The search index retrieval fails to enforce document access control or ownership boundaries.
        # Confidential administrator documents (is_private = 1) are returned to ordinary users.
        raw_search_query = f"""
            SELECT f.id, f.original_filename as title, f.stored_filename, f.mime_type, f.size,
                   f.description, f.is_private, f.created_at, u.username as owner
            FROM files f
            JOIN users u ON f.user_id = u.id
            WHERE (f.original_filename LIKE '%{query}%' OR f.description LIKE '%{query}%')
        """
        if filter_type and filter_type != "all":
            raw_search_query += f" AND f.mime_type = '{filter_type}'"
        raw_search_query += " ORDER BY f.id DESC"
        try:
            cursor = db.cursor()
            cursor.execute(raw_search_query)
            results = cursor.fetchall()
        except sqlite3.OperationalError as e:
            results = []
            flash(f"Search index syntax error: {e}", "warning")

    # INTENTIONAL LAB VULNERABILITY
    # VULN-29: Reflected Cross-Site Scripting (XSS) in Search Results
    # The search query string 'query' is passed to search.html where it is rendered unescaped (| safe)
    # into the search summary header ("Showing results for: {{ query | safe }}").
    return render_template(
        "search.html",
        user=current_user,
        current_user=current_user,
        query=query,
        filter_type=filter_type,
        results=results,
        active_page="search"
    )



# -------------------------------------------------------------------------
# System Diagnostics & Telemetry
# -------------------------------------------------------------------------

@app.route("/system/info", methods=["GET"])
def system_info():
    """
    Public system diagnostics endpoint.
    
    INTENTIONAL LAB VULNERABILITY
    VULN-40: General Information Disclosure via System Banners & Headers
    Exposes sensitive environment and server infrastructure configuration details
    including runtime interpreter, SQLite engine version, internal filesystem paths, and loaded route maps.
    """
    return {
        "status": "operational",
        "app_name": "SecureHub VAPT Training Lab",
        "app_version": "2.6.4",
        "build_date": "2026-09-23",
        "server_banner": "SecureHub-Internal/2.6.4 (Unix; Linux x86_64)",
        "python_version": sys.version,
        "platform": platform.platform(),
        "sqlite_version": sqlite3.sqlite_version,
        "database_path": DATABASE_PATH,
        "upload_folder": UPLOAD_FOLDER,
        "active_endpoints": [str(rule) for rule in app.url_map.iter_rules()]
    }


# -------------------------------------------------------------------------
# Administration Management Console
# -------------------------------------------------------------------------

@app.route("/admin", methods=["GET"])
@login_required
def admin_dashboard():
    """
    Administrative overview console.
    
    INTENTIONAL LAB VULNERABILITY
    VULN-37: Vertical Privilege Escalation on Administrative Functions
    The administrative dashboard view allows any authenticated user without role verification.
    """
    current_user = get_current_user()
    db = get_db()
    total_users = db.execute("SELECT COUNT(*) as count FROM users").fetchone()["count"]
    total_orders = db.execute("SELECT COUNT(*) as count FROM orders").fetchone()["count"]
    total_files = db.execute("SELECT COUNT(*) as count FROM files").fetchone()["count"]
    recent_logs = db.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 5").fetchall()

    return render_template(
        "admin.html",
        current_user=current_user,
        user=current_user,
        total_users=total_users,
        total_orders=total_orders,
        total_files=total_files,
        recent_logs=recent_logs,
        active_page="admin"
    )


@app.route("/admin/system/backup", methods=["POST"])
@login_required
def admin_system_backup():
    """
    Privileged system database snapshot and backup routine.
    
    INTENTIONAL LAB VULNERABILITY
    VULN-37: Vertical Privilege Escalation on Administrative Functions
    This critical administrative endpoint lacks server-side authorization checks (such as
    verifying if current_user['role'] == 'admin'). Any authenticated standard user can execute it.
    """
    current_user = get_current_user()
    db = get_db()
    backup_filename = f"securehub_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    
    # Record backup action in audit logs
    db.execute("""
        INSERT INTO audit_logs (event_type, actor_username, details, ip_address)
        VALUES (?, ?, ?, ?)
    """, ("SYSTEM_BACKUP_INITIATED", current_user["username"], f"Administrative database snapshot {backup_filename} generated.", request.remote_addr or "127.0.0.1"))
    db.commit()

    if request.is_json:
        return {"status": "success", "message": f"Backup snapshot '{backup_filename}' generated successfully.", "backup_file": backup_filename}

    flash(f"System configuration backup '{backup_filename}' initiated successfully.", "success")
    return redirect(url_for("admin_dashboard"))


# -------------------------------------------------------------------------
# Security Audit Trail Management
# -------------------------------------------------------------------------

@app.route("/audit-logs", methods=["GET"])
@login_required
def audit_logs_view():
    """
    Displays the security audit trail.
    """
    current_user = get_current_user()
    db = get_db()
    logs = db.execute("SELECT * FROM audit_logs ORDER BY id DESC").fetchall()
    return render_template(
        "audit_logs.html",
        current_user=current_user,
        user=current_user,
        logs=logs,
        active_page="audit_logs"
    )


@app.route("/audit-logs/delete", methods=["POST"])
@login_required
def audit_log_delete():
    """
    Removes an audit trail entry.
    
    INTENTIONAL LAB VULNERABILITY
    VULN-39: Audit Trail Event Log Tampering / Deletion
    Audit logs should be append-only and strictly tamper-evident. The server permits any
    authenticated user to delete audit event entries by ID without role checking or immutability enforcement.
    """
    current_user = get_current_user()
    db = get_db()
    
    log_id = request.form.get("log_id")
    if not log_id and request.is_json:
        log_id = request.json.get("log_id")

    if not log_id:
        flash("Audit log ID is required.", "error")
        return redirect(url_for("audit_logs_view"))

    target_log = db.execute("SELECT * FROM audit_logs WHERE id = ?", (log_id,)).fetchone()
    if not target_log:
        flash("Audit log entry not found.", "warning")
        return redirect(url_for("audit_logs_view"))

    db.execute("DELETE FROM audit_logs WHERE id = ?", (log_id,))
    db.commit()

    if request.is_json:
        return {"status": "success", "message": f"Audit record #{log_id} permanently deleted."}

    flash(f"Audit log #{log_id} ({target_log['event_type']}) deleted successfully.", "success")
    return redirect(url_for("audit_logs_view"))


# -------------------------------------------------------------------------
# Store & Commerce Management
# -------------------------------------------------------------------------

@app.route("/store", methods=["GET"])
@login_required
def store_catalog():
    """
    Service store and license catalog.
    """
    current_user = get_current_user()
    db = get_db()
    products = db.execute("SELECT * FROM products ORDER BY id ASC").fetchall()
    cart_items = session.get("cart", [])
    cart_count = sum(item.get("quantity", 0) for item in cart_items)
    
    return render_template(
        "store.html",
        current_user=current_user,
        user=current_user,
        products=products,
        cart_count=cart_count,
        active_page="store"
    )


@app.route("/store/cart", methods=["GET"])
@login_required
def store_cart():
    """
    Cart overview with applied discounts and itemized totals.
    """
    current_user = get_current_user()
    cart_items = session.get("cart", [])
    
    subtotal = sum(item.get("subtotal", 0.0) for item in cart_items)
    voucher = session.get("voucher")
    discount = 0.0
    if voucher:
        discount = float(voucher.get("discount", 0.0))
    
    total = max(0.0, round(subtotal - discount, 2)) if subtotal > 0 else round(subtotal - discount, 2)

    return render_template(
        "cart.html",
        current_user=current_user,
        user=current_user,
        cart_items=cart_items,
        subtotal=subtotal,
        voucher=voucher,
        discount=discount,
        total=total,
        active_page="store"
    )


@app.route("/store/cart/add", methods=["POST"])
@login_required
def store_cart_add():
    """
    Adds a product to the cart.
    """
    product_id = request.form.get("product_id")
    quantity_raw = request.form.get("quantity", 1)
    try:
        quantity = int(quantity_raw)
    except (ValueError, TypeError):
        quantity = 1

    db = get_db()
    product = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    if not product:
        flash("Product not found.", "error")
        return redirect(url_for("store_catalog"))

    cart = session.get("cart", [])
    existing = next((item for item in cart if item["product_id"] == product["id"]), None)
    if existing:
        existing["quantity"] += quantity
        existing["subtotal"] = round(existing["quantity"] * existing["unit_price"], 2)
    else:
        cart.append({
            "product_id": product["id"],
            "name": product["name"],
            "sku": product["sku"],
            "unit_price": product["price"],
            "quantity": quantity,
            "subtotal": round(quantity * product["price"], 2)
        })

    session["cart"] = cart
    session.modified = True
    flash(f"Added '{product['name']}' to cart.", "success")
    return redirect(url_for("store_cart"))


@app.route("/store/cart/update", methods=["POST"])
@login_required
def store_cart_update():
    """
    Updates the quantity of an item in the cart.
    
    INTENTIONAL LAB VULNERABILITY
    VULN-35: Negative Quantity & Integer Underflow Logic Flaws
    The handler parses quantity = int(request.form.get('quantity')) without validating
    that quantity > 0. Submitting negative quantities (e.g. -5) creates negative line subtotals,
    permitting an attacker to arbitrarily reduce or manipulate the overall cart total.
    """
    product_id = request.form.get("product_id")
    try:
        product_id = int(product_id)
        quantity = int(request.form.get("quantity", 1))
    except (ValueError, TypeError):
        flash("Invalid quantity parameter.", "error")
        return redirect(url_for("store_cart"))

    cart = session.get("cart", [])
    updated = False
    for item in cart:
        if item["product_id"] == product_id:
            # Flaw: No check that quantity >= 0 or quantity > 0
            item["quantity"] = quantity
            item["subtotal"] = round(item["quantity"] * item["unit_price"], 2)
            updated = True
            break

    if not updated and product_id:
        db = get_db()
        product = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
        if product:
            cart.append({
                "product_id": product["id"],
                "name": product["name"],
                "sku": product["sku"],
                "unit_price": product["price"],
                "quantity": quantity,
                "subtotal": round(quantity * product["price"], 2)
            })

    session["cart"] = cart
    session.modified = True
    flash("Cart quantity updated.", "info")
    return redirect(url_for("store_cart"))


@app.route("/store/cart/apply-voucher", methods=["POST"])
@login_required
def store_apply_voucher():
    """
    Applies a promotional voucher discount to the cart.
    
    INTENTIONAL LAB VULNERABILITY
    VULN-36: Promo Voucher Replay & Concurrent Race Conditions
    The validation checks whether times_used < max_uses, but the application does not atomically
    consume or mark the voucher used upon checkout, nor does it track single-use per user.
    Consequently, single-use vouchers can be replayed repeatedly across multiple orders.
    """
    voucher_code = request.form.get("voucher_code", "").strip().upper()
    if not voucher_code:
        flash("Please enter a voucher code.", "warning")
        return redirect(url_for("store_cart"))

    db = get_db()
    voucher = db.execute("SELECT * FROM vouchers WHERE code = ? AND is_active = 1", (voucher_code,)).fetchone()
    
    if not voucher:
        flash("Invalid or expired promotional code.", "error")
        return redirect(url_for("store_cart"))

    # Flaw: Checks times_used < max_uses, but checkout does not atomically increment or persist usage!
    if voucher["times_used"] >= voucher["max_uses"]:
        flash("This voucher has reached its redemption limit.", "error")
        return redirect(url_for("store_cart"))

    session["voucher"] = {
        "code": voucher["code"],
        "discount": voucher["discount_amount"]
    }
    session.modified = True
    flash(f"Promotional voucher '{voucher['code']}' applied! (${voucher['discount_amount']:.2f} discount)", "success")
    return redirect(url_for("store_cart"))


@app.route("/store/checkout", methods=["POST"])
@login_required
def store_checkout():
    """
    Completes order checkout and persists transaction record.
    
    INTENTIONAL LAB VULNERABILITY
    VULN-34: Price & Currency Manipulation via Parameter Tampering
    The checkout handler trusts client-submitted parameters ('price', 'unit_price', 'total', 'currency')
    directly from the request body or form payload instead of computing authoritative prices
    from the products database table.
    """
    current_user = get_current_user()
    db = get_db()
    cart = session.get("cart", [])

    if not cart and not request.form.get("product_id") and not (request.is_json and request.json.get("product_id")):
        flash("Your cart is empty.", "warning")
        return redirect(url_for("store_catalog"))

    # Check for direct price/currency overrides from client request
    client_currency = request.form.get("currency") or (request.json.get("currency") if request.is_json else None) or "USD"
    client_total_override = request.form.get("total") or (request.json.get("total") if request.is_json else None)
    client_unit_price = request.form.get("unit_price") or request.form.get("price") or (request.json.get("unit_price") or request.json.get("price") if request.is_json else None)

    # If single-item direct checkout was triggered:
    direct_product_id = request.form.get("product_id") or (request.json.get("product_id") if request.is_json else None)
    if direct_product_id and not cart:
        prod = db.execute("SELECT * FROM products WHERE id = ?", (direct_product_id,)).fetchone()
        if prod:
            unit_p = float(client_unit_price) if client_unit_price is not None else prod["price"]
            qty = int(request.form.get("quantity") or (request.json.get("quantity") if request.is_json else 1))
            cart = [{
                "product_id": prod["id"],
                "name": prod["name"],
                "sku": prod["sku"],
                "unit_price": unit_p,
                "quantity": qty,
                "subtotal": round(unit_p * qty, 2)
            }]

    # If client supplied custom unit_price override for existing cart:
    if client_unit_price is not None and cart:
        tampered_price = float(client_unit_price)
        for item in cart:
            item["unit_price"] = tampered_price
            item["subtotal"] = round(tampered_price * item["quantity"], 2)

    subtotal = sum(item["subtotal"] for item in cart)
    voucher = session.get("voucher")
    discount = float(voucher.get("discount", 0.0)) if voucher else 0.0

    if client_total_override is not None:
        final_total = float(client_total_override)
    else:
        final_total = round(subtotal - discount, 2)

    order_number = f"ORD-{secrets.token_hex(4).upper()}"
    
    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO orders (order_number, user_id, subtotal, discount, total, currency, status)
        VALUES (?, ?, ?, ?, ?, ?, 'Completed')
    """, (order_number, current_user["id"], subtotal, discount, final_total, client_currency))
    order_id = cursor.lastrowid

    for item in cart:
        cursor.execute("""
            INSERT INTO order_items (order_id, product_id, product_name, unit_price, quantity, subtotal)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (order_id, item["product_id"], item["name"], item["unit_price"], item["quantity"], item["subtotal"]))

    # VULN-36: Single-use vouchers are not consumed/inactivated upon checkout
    db.commit()

    # Clear session cart and voucher
    session["cart"] = []
    session.pop("voucher", None)
    session.modified = True

    # Record order in audit logs
    db.execute("""
        INSERT INTO audit_logs (event_type, actor_username, details, ip_address)
        VALUES (?, ?, ?, ?)
    """, ("ORDER_PLACED", current_user["username"], f"Order {order_number} completed. Total: {final_total} {client_currency}", request.remote_addr or "127.0.0.1"))
    db.commit()

    if request.is_json:
        return {
            "status": "success",
            "order_number": order_number,
            "order_id": order_id,
            "total": final_total,
            "currency": client_currency,
            "subtotal": subtotal,
            "discount": discount
        }

    flash(f"Order {order_number} placed successfully! Total charged: {final_total:.2f} {client_currency}", "success")
    return redirect(url_for("store_orders"))


@app.route("/store/orders", methods=["GET"])
@login_required
def store_orders():
    """
    View user's order history.
    """
    current_user = get_current_user()
    db = get_db()
    
    if current_user["role"] == "admin":
        orders = db.execute("SELECT o.*, u.username FROM orders o JOIN users u ON o.user_id = u.id ORDER BY o.id DESC").fetchall()
    else:
        orders = db.execute("SELECT o.*, u.username FROM orders o JOIN users u ON o.user_id = u.id WHERE o.user_id = ? ORDER BY o.id DESC", (current_user["id"],)).fetchall()

    return render_template(
        "orders.html",
        current_user=current_user,
        user=current_user,
        orders=orders,
        active_page="orders"
    )


# -------------------------------------------------------------------------
# Application Entry Point
# -------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 70)
    print(" SecureHub VAPT Training Lab — Authorized Local Environment")
    print(" Target: http://127.0.0.1:5000")
    print(" WARNING: Intentionally vulnerable for local training & Tracegate testing.")
    print("=" * 70)
    app.run(host="127.0.0.1", port=5000, debug=False)
