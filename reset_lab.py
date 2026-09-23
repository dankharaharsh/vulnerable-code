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

    # Seed Private / Confidential Corporate Documents for Search Index Leakage testing
    confidential_audit_path = os.path.join(UPLOAD_FOLDER, "confidential_q3_financial_audit.docx")
    with open(confidential_audit_path, "w", encoding="utf-8") as f:
        f.write("CONFIDENTIAL INTERNAL FINANCIAL AUDIT REPORT - SECUREHUB Q3 2026 - RESTRICTED TO BOARD OF DIRECTORS ONLY.\nAsset Reserves: $42,500,000\nInternal Account ID: SH-CORP-VAULT-991\n")

    internal_matrix_path = os.path.join(UPLOAD_FOLDER, "infrastructure_access_matrix_internal.txt")
    with open(internal_matrix_path, "w", encoding="utf-8") as f:
        f.write("INTERNAL INFRASTRUCTURE ACCESS MATRIX - PRODUCTION NODES\nNode 01: 10.240.0.1 (Root SSH Access via Bastion)\nNode 02: 10.240.12.88 (Worker Fabric)\nNode 03: 10.240.4.15 (Audit Vault)\n")

    print("[+] Created starter upload files (sample_report.txt, sample_diagram.svg, confidential_q3_financial_audit.docx, infrastructure_access_matrix_internal.txt)")

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
            two_factor_secret TEXT,
            recovery_code TEXT,
            recovery_expiry TIMESTAMP,
            is_verified INTEGER DEFAULT 1,
            activation_token TEXT,
            reset_token TEXT,
            reset_expiry TIMESTAMP,
            session_version INTEGER DEFAULT 1,
            avatar TEXT DEFAULT 'default_avatar.png'
        )
    """)

    # Comments Table
    cursor.execute("""
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            comment_text TEXT NOT NULL,
            internal_ip TEXT DEFAULT '10.240.14.22',
            tx_id TEXT DEFAULT 'tx_sec_00918',
            server_node TEXT DEFAULT 'node-us-east-cluster-01',
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
            description TEXT DEFAULT '',
            is_private INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Dispatched Emails (Simulated local spool for verification links and reset tokens)
    cursor.execute("""
        CREATE TABLE dispatched_emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient TEXT NOT NULL,
            subject TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Personal Access Tokens Table (Plaintext storage)
    cursor.execute("""
        CREATE TABLE personal_access_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_name TEXT NOT NULL,
            token_value TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Active Sessions Table (Device & session tracking)
    cursor.execute("""
        CREATE TABLE active_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token TEXT NOT NULL,
            ip_address TEXT DEFAULT '127.0.0.1',
            user_agent TEXT DEFAULT 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            device_name TEXT DEFAULT 'Desktop Workstation',
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Products Table
    cursor.execute("""
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            sku TEXT UNIQUE NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            category TEXT DEFAULT 'Services',
            inventory INTEGER DEFAULT 100
        )
    """)

    # Orders Table
    cursor.execute("""
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_number TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            subtotal REAL NOT NULL,
            discount REAL DEFAULT 0.0,
            total REAL NOT NULL,
            currency TEXT DEFAULT 'USD',
            status TEXT DEFAULT 'Completed',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Order Items Table
    cursor.execute("""
        CREATE TABLE order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            product_name TEXT NOT NULL,
            unit_price REAL NOT NULL,
            quantity INTEGER NOT NULL,
            subtotal REAL NOT NULL,
            FOREIGN KEY (order_id) REFERENCES orders(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )
    """)

    # Vouchers Table
    cursor.execute("""
        CREATE TABLE vouchers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            discount_amount REAL NOT NULL,
            discount_type TEXT DEFAULT 'fixed',
            times_used INTEGER DEFAULT 0,
            max_uses INTEGER DEFAULT 1,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Audit Logs Table
    cursor.execute("""
        CREATE TABLE audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            actor_username TEXT NOT NULL,
            details TEXT NOT NULL,
            ip_address TEXT DEFAULT '127.0.0.1',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

    # Seed Comments (Includes technical metadata for VULN-30 demonstration)
    comments_seed = [
        (4, "System maintenance completed for cluster node 01. All health metrics optimal.", "10.240.0.1", "tx_sec_99182_root", "node-core-alpha-01"),
        (2, "Updated container registry credentials for staging environments.", "10.240.12.88", "tx_sec_88102_ops", "node-worker-beta-04"),
        (1, "Quarterly access reviews completed. No anomalies detected in tenant spaces.", "10.240.4.15", "tx_sec_77219_sec", "node-audit-gamma-02")
    ]
    cursor.executemany("""
        INSERT INTO comments (user_id, comment_text, internal_ip, tx_id, server_node)
        VALUES (?, ?, ?, ?, ?)
    """, comments_seed)
    print(f"[+] Seeded {len(comments_seed)} operational comments with internal metadata.")

    # Seed Starter Files Metadata (Includes confidential records for VULN-32 Search Index Leakage)
    files_seed = [
        (4, "sample_report.txt", "sample_report.txt", "text/plain", os.path.getsize(sample_report_path), "System Health Report", 0),
        (1, "sample_diagram.svg", "sample_diagram.svg", "image/svg+xml", os.path.getsize(sample_svg_path), "Architecture Vector Diagram", 0),
        (4, "confidential_q3_financial_audit.docx", "confidential_q3_financial_audit.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", os.path.getsize(confidential_audit_path), "Confidential Board Financial Audit & Reserves", 1),
        (4, "infrastructure_access_matrix_internal.txt", "infrastructure_access_matrix_internal.txt", "text/plain", os.path.getsize(internal_matrix_path), "Internal Production Nodes SSH Access Matrix", 1)
    ]
    cursor.executemany("""
        INSERT INTO files (user_id, original_filename, stored_filename, mime_type, size, description, is_private)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, files_seed)
    print(f"[+] Seeded {len(files_seed)} starter file metadata records (including private admin documents).")

    # Seed Personal Access Tokens (Plaintext for training lab demonstration)
    pat_seed = [
        (2, "CLI Deploy Token", "sh_pat_bob_live_deploy_token_991823"),
        (4, "Master Automation Key", "sh_pat_admin_root_sync_access_449012")
    ]
    cursor.executemany("""
        INSERT INTO personal_access_tokens (user_id, token_name, token_value)
        VALUES (?, ?, ?)
    """, pat_seed)
    print(f"[+] Seeded {len(pat_seed)} personal access tokens.")

    # Seed Active Sessions
    sessions_seed = [
        (1, "sess_alice_win_chrome_9012", "192.168.1.105", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0", "Workstation Chrome - Current", 1),
        (2, "sess_bob_mac_safari_3411", "192.168.1.110", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15", "MacBook Pro - Remote", 1),
        (2, "sess_bob_mobile_ios_8812", "10.0.4.55", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) Mobile", "Corporate iPhone", 1)
    ]
    cursor.executemany("""
        INSERT INTO active_sessions (user_id, session_token, ip_address, user_agent, device_name, is_active)
        VALUES (?, ?, ?, ?, ?, ?)
    """, sessions_seed)
    print(f"[+] Seeded {len(sessions_seed)} active device session records.")

    # Seed Products
    products_seed = [
        (1, "SecureHub Cloud Storage Pack (500GB)", "SKU-STG-500", "Additional resilient object storage quota with multi-region replication.", 49.99, "Infrastructure", 250),
        (2, "Dedicated Audit Node License", "SKU-AUDIT-NODE", "Single-tenant immutable telemetry and compliance log node.", 199.00, "Compliance", 50),
        (3, "Enterprise Priority 24/7 SLA Support", "SKU-SLA-ENT", "Direct 15-minute SLA dispatch response for production clusters.", 499.00, "Support", 20),
        (4, "Advanced Threat Intelligence Feed Subscription", "SKU-TI-FEED", "Automated daily threat signatures and zero-day advisory ingestion.", 129.50, "Security", 100)
    ]
    cursor.executemany("""
        INSERT INTO products (id, name, sku, description, price, category, inventory)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, products_seed)
    print(f"[+] Seeded {len(products_seed)} store products.")

    # Seed Vouchers
    vouchers_seed = [
        (1, "SAVE50", 50.00, "fixed", 0, 1, 1),
        (2, "WELCOME2026", 20.00, "fixed", 0, 5, 1),
        (3, "VIPENTERPRISE", 100.00, "fixed", 0, 1, 1)
    ]
    cursor.executemany("""
        INSERT INTO vouchers (id, code, discount_amount, discount_type, times_used, max_uses, is_active)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, vouchers_seed)
    print(f"[+] Seeded {len(vouchers_seed)} promo vouchers.")

    # Seed Audit Logs
    audit_logs_seed = [
        ("AUTH_LOGIN_SUCCESS", "admin", "User admin authenticated successfully from administrative workstation.", "10.240.0.1"),
        ("ROLE_UPDATE", "admin", "User bob granted access to staging deployment pipeline.", "10.240.0.1"),
        ("CONFIG_BACKUP_INITIATED", "admin", "Automated routine backup scheduled snapshot completed.", "127.0.0.1"),
        ("PROFILE_UPDATE", "alice", "Alice updated contact phone number and communication preferences.", "192.168.1.105"),
        ("FILE_UPLOAD", "charlie", "Uploaded compliance verification spreadsheet draft.", "192.168.1.120")
    ]
    cursor.executemany("""
        INSERT INTO audit_logs (event_type, actor_username, details, ip_address)
        VALUES (?, ?, ?, ?)
    """, audit_logs_seed)
    print(f"[+] Seeded {len(audit_logs_seed)} initial audit logs.")

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
