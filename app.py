import re
from pathlib import Path
import uuid
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
import sqlite3
import functools
from datetime import datetime
from flask import (
    make_response,
    Flask, render_template, request, redirect, url_for,
    session, flash, send_file, abort, g
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "securehub.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
LAB_DATA_FOLDER = os.path.join(BASE_DIR, "lab_data")

# Ensure required runtime directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(LAB_DATA_FOLDER, exist_ok=True)

app = Flask(__name__)
# Secret key for local session signing
app.secret_key = "securehub-training-lab-local-session-secret-key"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB max upload


# -------------------------------------------------------------------------
# Database Helpers
# -------------------------------------------------------------------------

def get_db():
    # Tracegate Defensive Guard: Enforce authentication boundary
    if not session.get('user_id') and not session.get('authenticated'):
        return redirect(url_for('login'))
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


# -------------------------------------------------------------------------
# Authentication & Authorization Decorator
# -------------------------------------------------------------------------

def login_required(f):
    """
    Session verification decorator.
    
    VULN-005 (CWE-288): Two-Factor Authentication (2FA) Implementation Bypass
    Flaw: This decorator only checks whether 'user_id' exists in session.
    It fails to verify whether two-factor authentication ('2fa_verified')
    was actually completed by users with 'two_factor_enabled' = 1.
    As a result, a user can navigate directly to any protected endpoint
    without completing the second authentication factor.
    """
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to access this workspace resource.", "warning")
            return redirect(url_for("login"))
        
        # VULNERABLE LOGIC: Missing enforcement of 2FA completion state!
        # An AI fix should verify:
        # if session.get('2fa_required') and not session.get('2fa_verified'):
        #     return redirect(url_for('two_factor_view'))

        return f(*args, **kwargs)
    return decorated_function


# -------------------------------------------------------------------------
# Authentication Routes
# -------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Handles user authentication.
    
    Contains:
    - VULN-001 (CWE-524): Insecure Credential Caching & Autocomplete configuration.
    - VULN-002 (CWE-204): Distinguishable responses revealing valid vs invalid accounts.
    - VULN-004 (CWE-287): SQL Injection in authentication query construction.
    """
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember_me = request.form.get("remember_me")

        db = get_db()

        # -----------------------------------------------------------------
        # VULN-004 (CWE-287): Authentication Bypass via SQL Injection
        # Unsafe string concatenation allows malicious input (e.g. admin' --)
        # to manipulate query structure and bypass password verification.
        # AI Fix: Use parameterized query:
        # cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        # -----------------------------------------------------------------
        raw_auth_query = "SELECT * FROM users WHERE username = :username AND password = :password"
        
        try:
            cursor = db.cursor()
            cursor.execute(raw_auth_query, {"username": username, "password": password})
            user = cursor.fetchone()
        except sqlite3.OperationalError:
            # Fallback if arbitrary syntax breaks query
            user = None

        if user:
            # Set active session credentials
            if user.get('two_factor_enabled'):
                session['pending_2fa_user_id'] = user['id']
                session['2fa_required'] = True
                session['2fa_verified'] = False
                flash('Two-Factor Authentication is required for your account.', 'info')
                return redirect(url_for('two_factor_view'))
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            # Handle 2FA routing
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

        # -----------------------------------------------------------------
        # VULN-002 (CWE-204): Account & Username Enumeration
        # Distinguishable error messages allow attackers to verify whether
        # a given username exists in the system directory.
        # AI Fix: Return a uniform response: "Invalid username or password."
        # -----------------------------------------------------------------
        account_lookup = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        flash('Invalid username or password.', 'error')
        response = make_response(render_template("login.html"))
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        return response

    # VULN-001 (CWE-524): Note that the login page lacks Cache-Control: no-store
    response = make_response(render_template("login.html"))
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/logout")
def logout():
    """Clears the session and redirects to sign in."""
    session.clear()
    flash("You have been signed out successfully.", "info")
    return redirect(url_for("login"))


# -------------------------------------------------------------------------
# Two-Factor Authentication Route
# -------------------------------------------------------------------------

@app.route("/2fa", methods=["GET", "POST"])
@login_required
def two_factor_view():
    """
    Two-Factor Authentication management and verification challenge.
    
    Part of VULN-005 (CWE-288): 2FA Implementation Bypass.
    """
    user = get_current_user()
    db = get_db()

    if request.method == "POST":
        action = request.form.get("action")

        if action == "verify_code":
            entered_code = request.form.get("code", "").strip()
            # Standard training code accepted: 123456
            if entered_code == "123456" or entered_code == user["two_factor_secret"]:
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
    """Main SaaS operational dashboard."""
    user = get_current_user()
    db = get_db()

    total_users = db.execute("SELECT COUNT(*) as count FROM users").fetchone()["count"]
    total_files = db.execute("SELECT COUNT(*) as count FROM files").fetchone()["count"]
    total_comments = db.execute("SELECT COUNT(*) as count FROM comments").fetchone()["count"]

    recent_comments = db.execute("""
        SELECT c.*, u.username, u.display_name 
        FROM comments c 
        JOIN users u ON c.user_id = u.id 
        ORDER BY c.id DESC LIMIT 5
    """).fetchall()

    stats = {
        "total_users": total_users,
        "total_files": total_files,
        "total_comments": total_comments,
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
    """
    Profile update form and submission handler.
    
    VULN-008 (CWE-639): Insecure Direct Object References (IDOR) / BOLA
    The endpoint accepts a user_id from client form data and executes an
    update against that record without checking if user_id matches session['user_id']
    or if the requesting user has administrative privileges.
    AI Fix: Derive identity from session['user_id'] or perform server authorization check:
    target_user_id = session['user_id']
    """
    current_user = get_current_user()
    db = get_db()

    if request.method == "POST":
        # VULNERABLE LOGIC: Trusting client-supplied user_id instead of session identity
        target_user_id = request.form.get("user_id")
        display_name = request.form.get("display_name", "").strip()
        phone = request.form.get("phone", "").strip()
        address = request.form.get("address", "").strip()
        bio = request.form.get("bio", "").strip()

        # Update profile for target_user_id directly
        db.execute("""
            UPDATE users
            SET display_name = ?, phone = ?, address = ?, bio = ?
            WHERE id = ?
        """, (display_name, phone, address, bio, target_user_id))
        db.commit()

        flash(f"Profile record #{target_user_id} updated successfully.", "success")
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
            db.execute(
                "INSERT INTO comments (user_id, comment_text) VALUES (?, ?)",
                (current_user["id"], comment_text)
            )
            db.commit()
            flash("Operations log entry posted successfully.", "success")
            return redirect(url_for("comments_view"))

    comments = db.execute("""
        SELECT c.*, u.username, u.display_name 
        FROM comments c 
        JOIN users u ON c.user_id = u.id 
        ORDER BY c.id DESC
    """).fetchall()

    return render_template("comments.html", comments=comments, current_user=current_user, active_page="comments")


# -------------------------------------------------------------------------
# File Management & Vulnerable Upload / Download Handlers
# -------------------------------------------------------------------------

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_view():
    """
    File upload endpoint.
    
    VULN-007 (CWE-434): Arbitrary File Upload via Unrestricted Extension Validation
    The server relies on an inadequate extension blocklist (only rejecting .exe and .bat)
    rather than a strict allowlist. It accepts unsafe file extensions such as .php, .svg,
    .html, .sh, or script documents, and preserves original extensions on the filesystem.
    AI Fix: Enforce a strict allowlist of extensions, validate MIME types and magic bytes,
    and generate safe pseudo-random filenames.
    """
    current_user = get_current_user()
    db = get_db()

    if request.method == "POST":
        if "file" not in request.files:
            flash("No file part provided in request.", "error")
            return redirect(url_for("upload_view"))

        file = request.files["file"]
        if file.filename == "":
            flash("No file selected for upload.", "error")
            return redirect(url_for("upload_view"))

        original_filename = file.filename
        _, ext = os.path.splitext(original_filename)
        ext = ext.lower()

        # -----------------------------------------------------------------
        # VULNERABLE LOGIC: Weak extension blocklist instead of strict allowlist
        # -----------------------------------------------------------------
        ALLOWED_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.pdf'}
        if ext not in ALLOWED_EXTENSIONS:
            flash(f"Security Alert: Upload format '{ext}' is prohibited. Allowed: png, jpg, jpeg, pdf.", 'danger')
            return redirect(url_for('upload_view'))

        # Save file into upload folder with user-provided filename
        stored_filename = f"{uuid.uuid4().hex}{ext}"
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], stored_filename)
        file.save(save_path)

        file_size = os.path.getsize(save_path)
        mime_type = file.content_type or "application/octet-stream"

        # Record file metadata in database
        db.execute("""
            INSERT INTO files (user_id, original_filename, stored_filename, mime_type, size)
            VALUES (?, ?, ?, ?, ?)
        """, (current_user["id"], original_filename, stored_filename, mime_type, file_size))
        db.commit()

        flash(f"Asset '{original_filename}' successfully uploaded and indexed.", "success")
        return redirect(url_for("uploads_gallery"))

    return render_template("upload.html", current_user=current_user, active_page="upload")


@app.route("/uploads")
@login_required
def uploads_gallery():
    """
    Storage pool gallery and SVG renderer.
    
    VULN-003 (CWE-79): Stored Cross-Site Scripting (XSS) via SVG Upload
    Uploaded SVG files are read from storage and provided directly to the
    template, which renders the SVG content unsafely with the |safe filter
    without script sanitization or Content Security Policy.
    AI Fix: Sanitize SVG XML content or serve it strictly as a non-executable attachment.
    """
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
        is_svg = f["original_filename"].lower().endswith(".svg") or "svg" in f["mime_type"].lower()
        f_dict["is_svg"] = is_svg
        files_list.append(f_dict)

        if is_svg:
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], f["stored_filename"])
            if os.path.exists(file_path):
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as svg_file:
                        raw_svg = svg_file.read()
                        # Defensive SVG sanitization: strip active script elements and event handlers
                        clean_svg = re.sub(r'<script[\s\S]*?</script>', '', raw_svg, flags=re.IGNORECASE)
                        clean_svg = re.sub(r'\bon\w+\s*=\s*["\'][^"\']*["\']', '', clean_svg, flags=re.IGNORECASE)
                        f_dict['svg_content'] = clean_svg
                        svg_files.append(f_dict)
                except Exception:
                    pass

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
    """
    File download retrieval endpoint.
    
    VULN-006: Path Traversal / Destination Storage Directory Escape
    The endpoint constructs the filesystem path directly using os.path.join(UPLOAD_FOLDER, filename)
    without canonicalization or verifying that the target remains inside UPLOAD_FOLDER.
    Attackers can pass traversal sequences (e.g. ?file=../../lab_data/training_note.txt)
    to read safe training artifacts outside the upload repository.
    AI Fix:
    base_dir = os.path.realpath(app.config['UPLOAD_FOLDER'])
    target_path = os.path.realpath(os.path.join(base_dir, requested_file))
    if not target_path.startswith(base_dir + os.path.sep):
        abort(403, "Directory traversal prohibited")
    """
    requested_file = request.args.get("file", "")
    if not requested_file:
        flash("No target file specified for download.", "error")
        return redirect(url_for("uploads_gallery"))

    # -----------------------------------------------------------------
    # VULNERABLE LOGIC: Unsafe path construction without canonicalization
    # -----------------------------------------------------------------
    # Defensive path canonicalization and directory boundary containment
    base_dir = Path(app.config['UPLOAD_FOLDER']).resolve()
    target_path = (base_dir / requested_file).resolve()
    if base_dir not in target_path.parents and target_path != base_dir:
        flash('Security Alert: Directory traversal attempt detected.', 'danger')
        return redirect(url_for('uploads_gallery'))
    target_path = str(target_path)
    if os.path.exists(target_path):
        return send_file(target_path, as_attachment=True)
    else:
        flash(f"Requested asset '{requested_file}' could not be located in storage pool.", "error")
        return redirect(url_for("uploads_gallery"))


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