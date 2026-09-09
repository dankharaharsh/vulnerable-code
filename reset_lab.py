"""
SecureHub VAPT Training Lab — Environment & Database Reset Utility
Run strictly from the local CLI:
    python reset_lab.py
"""

import os
import shutil
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "securehub.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
LAB_DATA_FOLDER = os.path.join(BASE_DIR, "lab_data")
TRAINING_NOTE_PATH = os.path.join(LAB_DATA_FOLDER, "training_note.txt")


def reset_environment():
    print("[*] Resetting SecureHub VAPT Training Lab environment...")

    # 1. Reset Database File
    if os.path.exists(DATABASE_PATH):
        try:
            os.remove(DATABASE_PATH)
            print(f"[+] Removed existing database: {DATABASE_PATH}")
        except Exception as e:
            print(f"[-] Error removing database: {e}")

    # 2. Reset Uploads Directory
    if os.path.exists(UPLOAD_FOLDER):
        shutil.rmtree(UPLOAD_FOLDER)
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    print(f"[+] Recreated clean upload directory: {UPLOAD_FOLDER}")

    # 3. Ensure Lab Data Directory & Training Target File
    os.makedirs(LAB_DATA_FOLDER, exist_ok=True)
    training_note_content = """[CONFIDENTIAL TRAINING ASSET]
Tracegate Cybersecurity VAPT Training Lab - Path Traversal Verification Target
Document ID: SEC-TRG-2026-NOTE-001
Classification: Safe Local Training Artifact

Congratulations! You have successfully retrieved this confidential training note through
Path Traversal / Destination Storage Directory Escape vulnerability demonstration.

Key Verification Token: TRACEGATE{path_traversal_lab_verified_cwe22}
Owner: SecureHub Operations Directorate (Simulated Environment)
Purpose: Tracegate Automated & Manual Penetration Testing Benchmark
"""
    with open(TRAINING_NOTE_PATH, "w", encoding="utf-8") as f:
        f.write(training_note_content)
    print(f"[+] Seeded path traversal target file: {TRAINING_NOTE_PATH}")

    # 4. Seed Initial Starter Files in uploads/
    sample_report_path = os.path.join(UPLOAD_FOLDER, "sample_report.txt")
    with open(sample_report_path, "w", encoding="utf-8") as f:
        f.write("SecureHub System Health Report\nGenerated on: 2026-09-09\nStatus: Normal operations\nActive nodes: 4\nStorage pool: 12% utilized\n")

    sample_svg_path = os.path.join(UPLOAD_FOLDER, "sample_diagram.svg")
    sample_svg_content = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 120" width="100%" height="80">
  <rect width="400" height="120" rx="8" fill="#f1f5f9" stroke="#cbd5e1" stroke-width="2"/>
  <circle cx="50" cy="60" r="24" fill="#2563eb"/>
  <text x="50" y="66" font-family="sans-serif" font-size="16" font-weight="bold" fill="#ffffff" text-anchor="middle">SH</text>
  <text x="90" y="55" font-family="sans-serif" font-size="16" font-weight="bold" fill="#1e293b">SecureHub Architecture</text>
  <text x="90" y="75" font-family="sans-serif" font-size="12" fill="#64748b">Verified Operations Node — Baseline Vector</text>
</svg>"""
    with open(sample_svg_path, "w", encoding="utf-8") as f:
        f.write(sample_svg_content)
    print("[+] Created starter upload files (sample_report.txt, sample_diagram.svg)")

    # 5. Initialize SQLite Database Schema & Seed Data
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    print("[*] Initializing database tables...")

    # Users Table
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            display_name TEXT,
            phone TEXT,
            address TEXT,
            bio TEXT,
            two_factor_enabled INTEGER DEFAULT 0,
            two_factor_secret TEXT
        )
    """)

    # Comments Table
    cursor.execute("""
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            comment_text TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Files Table
    cursor.execute("""
        CREATE TABLE files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            size INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Seed Users
    # Note: passwords stored in plaintext for local educational lab simplicity
    users_seed = [
        (
            1, "alice", "alice123", "alice@training.local", "user",
            "Alice Anderson", "+1 (555) 012-3456",
            "100 Tech Blvd, Suite 201, Silicon Valley",
            "Senior Cloud Security Analyst responsible for infrastructure audits and identity governance.",
            1, "TEST2FAALICE"
        ),
        (
            2, "bob", "bob123", "bob@training.local", "user",
            "Bob Brown", "+1 (555) 014-7890",
            "450 Corporate Row, Building B, Austin, TX",
            "DevOps and Operations Specialist managing automated deployment pipelines.",
            0, None
        ),
        (
            3, "charlie", "charlie123", "charlie@training.local", "user",
            "Charlie Carter", "+1 (555) 018-4321",
            "77 Innovation Way, Seattle, WA",
            "Quality Assurance Engineer focused on system integration and regression suites.",
            0, None
        ),
        (
            4, "admin", "admin123", "admin@training.local", "admin",
            "System Administrator", "+1 (555) 019-9999",
            "SecureHub HQ, Server Room Alpha",
            "Enterprise Root Administrator with global oversight of SecureHub infrastructure.",
            0, None
        )
    ]

    cursor.executemany("""
        INSERT INTO users (id, username, password, email, role, display_name, phone, address, bio, two_factor_enabled, two_factor_secret)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, users_seed)
    print(f"[+] Seeded {len(users_seed)} test user accounts.")

    # Seed Comments
    comments_seed = [
        (4, "System maintenance completed for cluster node 01. All health metrics optimal."),
        (2, "Updated container registry credentials for staging environments."),
        (1, "Quarterly access reviews completed. No anomalies detected in tenant spaces.")
    ]
    cursor.executemany("""
        INSERT INTO comments (user_id, comment_text)
        VALUES (?, ?)
    """, comments_seed)
    print(f"[+] Seeded {len(comments_seed)} operational comments.")

    # Seed Starter Files Metadata
    files_seed = [
        (4, "sample_report.txt", "sample_report.txt", "text/plain", os.path.getsize(sample_report_path)),
        (1, "sample_diagram.svg", "sample_diagram.svg", "image/svg+xml", os.path.getsize(sample_svg_path))
    ]
    cursor.executemany("""
        INSERT INTO files (user_id, original_filename, stored_filename, mime_type, size)
        VALUES (?, ?, ?, ?, ?)
    """, files_seed)
    print(f"[+] Seeded {len(files_seed)} starter file metadata records.")

    conn.commit()
    conn.close()

    print("[SUCCESS] SecureHub VAPT Training Lab has been fully initialized and reset.")
    print("Test Accounts:")
    print("  - alice   / alice123 (2FA Enabled, Secret: TEST2FAALICE)")
    print("  - bob     / bob123   (Standard User)")
    print("  - charlie / charlie123 (Standard User)")
    print("  - admin   / admin123 (System Administrator)")


if __name__ == "__main__":
    reset_environment()
