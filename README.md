# SecureHub VAPT Training Lab

```text
=============================================================================
THIS APPLICATION IS INTENTIONALLY VULNERABLE.
USE ONLY FOR AUTHORIZED LOCAL SECURITY TRAINING.
DO NOT DEPLOY THIS APPLICATION TO THE PUBLIC INTERNET.
=============================================================================
```

**SecureHub VAPT Training Lab** is a server-rendered web application built for local cybersecurity training, penetration testing exercises, and benchmarking the **Tracegate Platform** (Screenshot Analysis, VAPT Checklist Generation, Finding Verification, PoC Collection, DOCX Reporting, and AI Fix Before/After Code Remediation).

---

## 1. Safety & Operational Scope

- **Binding Address:** Strictly `127.0.0.1:5000` (Localhost only).
- **Data Safety:** All accounts, passwords, emails, and phone numbers are completely synthetic dummy training values.
- **Path Traversal Scope:** Restricted to safe, local lab training artifacts (`lab_data/training_note.txt`). No system-level credentials or sensitive OS paths are exposed or targeted.
- **File Upload Scope:** Demonstrates improper extension filtering and active vector rendering without hosting live executable payloads.

---

## 2. Technology Stack

- **Backend:** Python 3 (Flask 3.x)
- **Database:** SQLite 3 (`securehub.db`)
- **Frontend:** Server-rendered HTML5, responsive SaaS CSS (`static/css/style.css`), vanilla JavaScript (`static/js/app.js`)
- **File Storage:** Local filesystem (`uploads/`)

---

## 3. Project Structure

```text
securehub-vapt-lab/
├── app.py                      # Flask backend, routing, authentication, and vulnerable handlers
├── reset_lab.py                # Standalone CLI reset script (rebuilds DB, seeds users & files)
├── test_lab.py                 # Automated verification test suite for all 8 vulnerabilities
├── requirements.txt            # Python dependencies
├── README.md                   # Complete lab documentation and vulnerability mapping
├── lab_data/
│   └── training_note.txt       # Safe target file for Path Traversal testing
├── uploads/                    # Local asset storage directory
│   ├── sample_report.txt       # Seed sample document
│   └── sample_diagram.svg      # Seed vector diagram
├── static/
│   ├── css/
│   │   └── style.css           # Modern SaaS stylesheet (navy/slate theme, cards, tables, badges)
│   └── js/
│       └── app.js              # Client UI helper scripts
└── templates/
    ├── base.html               # Base layout with navbar, alerts, footer, and branding
    ├── login.html              # VULN-001 (autocomplete), VULN-002 (enumeration), VULN-004 (SQLi)
    ├── dashboard.html          # Main operational dashboard with metrics & activity logs
    ├── profile.html            # Profile viewer
    ├── profile_edit.html       # VULN-008 (IDOR on profile update)
    ├── users.html              # Team member directory
    ├── user_detail.html        # Individual user public profile card
    ├── comments.html           # Operations discussion log (safely escaped)
    ├── 2fa.html                # VULN-005 (2FA challenge and management)
    ├── upload.html             # VULN-007 (Arbitrary file upload form)
    └── uploads.html            # VULN-003 (Stored SVG XSS direct vector rendering)
```

---

## 4. Setup & Running Instructions

### Prerequisites
- Python 3.10+
- pip

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Initialize / Reset Lab Environment
Always initialize or restore the database and files before running tests:
```bash
python reset_lab.py
```

### 3. Start the Web Application
```bash
python app.py
```
Open your browser and navigate to:
```text
http://127.0.0.1:5000
```

### 4. Run Automated Vulnerability Verification Suite
Execute the test suite to verify that all 8 vulnerabilities are active and exploitable:
```bash
python test_lab.py
```

---

## 5. Seed Test Credentials

| Username | Password | Role | 2FA Status | Purpose / Test Target |
|---|---|---|---|---|
| `alice` | `alice123` | Standard User | Enabled (`TEST2FAALICE`) | 2FA Implementation Bypass (VULN-005), IDOR Source (VULN-008) |
| `bob` | `bob123` | Standard User | Disabled | IDOR Target Profile (VULN-008), Path Traversal (VULN-006) |
| `charlie` | `charlie123` | Standard User | Disabled | SVG XSS Upload (VULN-003), Arbitrary Upload (VULN-007) |
| `admin` | `admin123` | Administrator | Disabled | SQL Injection Auth Bypass (VULN-004) |

---

## 6. Route Directory

| Route | Methods | Purpose |
|---|---|---|
| `/login` | GET, POST | User sign-in interface (VULN-001, VULN-002, VULN-004) |
| `/logout` | GET | Clears active session and redirects to `/login` |
| `/dashboard` | GET | Main SaaS operations dashboard and metrics |
| `/profile` | GET | View current user's profile information |
| `/profile/edit` | GET, POST | Modify profile details (VULN-008 IDOR) |
| `/users` | GET | Corporate team member directory |
| `/user/<id>` | GET | Public profile card for specific user ID |
| `/comments` | GET, POST | Operations discussion board (safely escaped) |
| `/2fa` | GET, POST | Multi-factor verification and settings (VULN-005) |
| `/upload` | GET, POST | Upload digital media and documents (VULN-007) |
| `/uploads` | GET | Storage browser and SVG vector renderer (VULN-003) |
| `/files/download` | GET | File retrieval endpoint (VULN-006 Path Traversal) |

---

## 7. Security Finding Map & Vulnerability Inventory

### VULN-001: Credential Caching & Form Autocomplete Directive
- **Identifier:** `VULN-001`
- **CWE:** CWE-524 (Information Exposure through Caching)
- **Source File:** `templates/login.html` (lines ~26-44) and `app.py` (`login()`)
- **Intentional Representation:** Form and sensitive input fields explicitly enable browser autocomplete (`autocomplete="on"`), and authentication routes lack `Cache-Control: no-store` headers.
- **Proof of Concept:** Inspect page source of `/login`. Observe `<form autocomplete="on">` and `<input type="password" autocomplete="on">`.
- **Expected AI Fix Target:** Replace with `autocomplete="off"` / `autocomplete="current-password"`, and add `Cache-Control: no-store, no-cache, must-revalidate` response header.

---

### VULN-002: Username & Account Enumeration
- **Identifier:** `VULN-002`
- **CWE:** CWE-204 (Observable Response Discrepancy)
- **Source File:** `app.py` (`login()` lines ~138-150)
- **Intentional Representation:** Login endpoint issues distinct flash error messages:
  - Existing user + wrong password: `"Incorrect password for user."`
  - Non-existent user + wrong password: `"Account with this username does not exist."`
- **Proof of Concept:**
  - Submit `bob` with password `wrong` -> Response includes `"Incorrect password for user."`
  - Submit `ghostuser` with password `wrong` -> Response includes `"Account with this username does not exist."`
- **Expected AI Fix Target:** Return a uniform error message: `"Invalid username or password."`

---

### VULN-003: Stored Cross-Site Scripting (XSS) via SVG Upload
- **Identifier:** `VULN-003`
- **CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)
- **Source File:** `app.py` (`uploads_gallery()`) and `templates/uploads.html` (lines ~80-100)
- **Intentional Representation:** Uploaded `.svg` files are read from the filesystem and injected raw into the DOM via Jinja's `| safe` filter: `{{ svg.svg_content | safe }}` without sanitization or CSP.
- **Proof of Concept:**
  1. Upload an SVG file containing:
     ```xml
     <svg xmlns="http://www.w3.org/2000/svg"><script>alert('TRACEGATE-XSS-VERIFIED')</script></svg>
     ```
  2. Navigate to `/uploads`.
  3. The JavaScript executes inline when the SVG gallery renders.
- **Expected AI Fix Target:** Sanitize SVG XML content (stripping `<script>` and event handlers), enforce `Content-Security-Policy: default-src 'self'`, or serve SVGs strictly as non-inline attachments.

---

### VULN-004: Authentication Bypass via SQL Injection
- **Identifier:** `VULN-004`
- **CWE:** CWE-287 (Improper Authentication) / CWE-89 (SQL Injection)
- **Source File:** `app.py` (`login()` lines ~105-120)
- **Intentional Representation:** Raw string formatting constructs the authentication query:
  ```python
  raw_auth_query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
  ```
- **Proof of Concept:**
  1. Navigate to `/login`.
  2. In Username enter: `admin' --`
  3. In Password enter any arbitrary text.
  4. Submit form. The database authenticates the session immediately as `admin` without verifying password.
- **Expected AI Fix Target:** Use parameterized SQL queries:
  ```python
  cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
  ```

---

### VULN-005: Two-Factor Authentication (2FA) Implementation Bypass
- **Identifier:** `VULN-005`
- **CWE:** CWE-288 (Authentication Bypass Using an Alternate Path or Channel)
- **Source File:** `app.py` (`@login_required` decorator and `login()` route)
- **Intentional Representation:** Upon password verification for accounts with 2FA enabled (e.g. `alice`), the server populates `session['user_id']` immediately before prompting for the 2FA code at `/2fa`. However, `@login_required` only checks `if 'user_id' not in session:` and fails to check `session['2fa_verified']`.
- **Proof of Concept:**
  1. Sign in as `alice` / `alice123`.
  2. The application redirects to `/2fa`.
  3. Instead of entering the 2FA code, directly change browser URL to `/dashboard` or `/profile`.
  4. Access is granted without completing the second authentication factor.
- **Expected AI Fix Target:** Maintain a temporary pre-authentication state (`session['pre_auth_user_id']`), and strictly require `session['2fa_verified'] == True` in `@login_required` before granting access to protected routes.

---

### VULN-006: Path Traversal / Destination Storage Directory Escape
- **Identifier:** `VULN-006`
- **CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **Source File:** `app.py` (`download_file()` lines ~360-380)
- **Intentional Representation:** Query parameter `?file=` is joined directly to the upload directory path:
  ```python
  target_path = os.path.join(app.config["UPLOAD_FOLDER"], requested_file)
  ```
  without verifying canonical containment.
- **Proof of Concept:**
  1. Authenticate with any user account.
  2. Request:
     ```text
     /files/download?file=../lab_data/training_note.txt
     ```
  3. The server downloads the confidential training document outside the upload repository.
- **Expected AI Fix Target:** Resolve canonical paths using `os.path.realpath()` and verify target path starts with `os.path.realpath(app.config['UPLOAD_FOLDER']) + os.path.sep`.

---

### VULN-007: Arbitrary File Upload via Unrestricted Extension Validation
- **Identifier:** `VULN-007`
- **CWE:** CWE-434 (Unrestricted Upload of File with Dangerous Type)
- **Source File:** `app.py` (`upload_view()` lines ~275-305)
- **Intentional Representation:** Server-side upload handler relies on an incomplete blocklist (`.exe`, `.bat`, `.cmd`, `.dll`) rather than a strict allowlist. It accepts `.php`, `.phtml`, `.svg`, `.html`, `.py`, `.sh`, `.config` extensions and retains original extensions in storage.
- **Proof of Concept:**
  1. Authenticate and navigate to `/upload`.
  2. Choose a file named `audit_tool.php` or `config.json`.
  3. Upload succeeds and file is stored in `uploads/` and indexed in the storage pool.
- **Expected AI Fix Target:** Enforce strict allowlist of permitted extensions (`.png`, `.jpg`, `.jpeg`, `.gif`, `.pdf`, `.txt`), validate MIME types and file headers, and assign randomized storage filenames.

---

### VULN-008: Insecure Direct Object References (IDOR) on Profile Update
- **Identifier:** `VULN-008`
- **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)
- **Source File:** `app.py` (`profile_edit()` lines ~200-220) & `templates/profile_edit.html`
- **Intentional Representation:** The profile edit form submits a client-controlled hidden `user_id` field. The backend updates the record matching `request.form.get('user_id')` without verifying session identity or role.
- **Proof of Concept:**
  1. Sign in as `alice` (`user_id = 1`).
  2. Navigate to `/profile/edit`.
  3. Change the hidden field `<input name="user_id" value="2">` (target: Bob Brown).
  4. Submit form. Bob's profile (`display_name`, `phone`, `address`, `bio`) is updated by Alice.
- **Expected AI Fix Target:** Disregard client-supplied `user_id` and update strictly by `session['user_id']`, or perform server-side ownership authorization before persisting changes.

---

## 8. Tracegate Integration & AI Fix Workflow

This repository is optimized for Tracegate's end-to-end automated and manual penetration testing workflow:

```text
1. Run vulnerable application locally (python app.py)
2. Capture screenshots of core modules:
   - Login (/login)
   - Dashboard (/dashboard)
   - Profile (/profile)
   - Two-Factor Authentication (/2fa)
   - Asset Upload (/upload)
   - Storage Pool (/uploads)
   - Team Directory (/users)
3. Generate Tracegate VAPT Checklist
4. Perform authorized test & record PoC evidence
5. Save Security Finding (VULN-001 through VULN-008)
6. Trigger AI Fix in Tracegate:
   - Connect repository
   - Select vulnerability and affected source file
   - Analyze vulnerable code block
   - Review proposed BEFORE / AFTER unified diff
7. Apply fix via dedicated branch:
   - Branch: tracegate/fix/VULN-XXX (never overwrite main/master)
   - Verify source file Git SHA before committing
8. Run python test_lab.py to confirm vulnerability remediation
```
