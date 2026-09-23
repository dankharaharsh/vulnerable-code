import re
import uuid
from pathlib import Path
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
        if client_user_id and str(session.get('user_id')) != str(client_user_id) and session.get('role') != 'admin':
            flash('Unauthorized: access denied to modify another user profile.', 'danger')
            return redirect(url_for('profile_view'))
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
        ALLOWED_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.pdf'}
        if ext not in ALLOWED_EXTENSIONS:
            flash(f"Security Alert: Upload format '{ext}' is prohibited. Allowed: png, jpg, jpeg, pdf.", 'danger')
            return redirect(url_for('upload_view'))

        # Save file into upload folder with timestamp prefix
        stored_filename = f"{uuid.uuid4().hex}{ext}"
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
                        raw_svg = svg_file.read()
                        # Defensive SVG sanitization: strip active script elements and event handlers
                        clean_svg = re.sub(r'<script[\s\S]*?</script>', '', raw_svg, flags=re.IGNORECASE)
                        clean_svg = re.sub(r'\bon\w+\s*=\s*["\'][^"\']*["\']', '', clean_svg, flags=re.IGNORECASE)
                        f_dict['svg_content'] = clean_svg
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
    # Defensive path canonicalization and directory boundary containment
    base_dir = Path(app.config['UPLOAD_FOLDER']).resolve()
    target_path = (base_dir / requested_file).resolve()
    if base_dir not in target_path.parents and target_path != base_dir:
        flash('Security Alert: Directory traversal attempt detected.', 'danger')
        return redirect(url_for('uploads_gallery'))
    target_path = str(target_path)