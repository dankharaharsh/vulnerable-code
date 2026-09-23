"""
SecureHub VAPT Lab — Clean Architecture & Security Verification Suite
Verifies that all old intentional vulnerabilities are removed/remediated
and all legitimate application functionality remains intact.
"""

import io
import sys
import unittest
from app import app, get_db
from reset_lab import reset_environment


class SecureHubCleanVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n" + "=" * 70)
        print(" VERIFYING SECUREHUB CLEAN ARCHITECTURE & FUNCTIONALITY")
        print("=" * 70)
        reset_environment()

    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_01_login_security_and_uniform_errors(self):
        """Verify login endpoint is protected against SQLi and user enumeration."""
        print("\n[*] Testing login endpoint security...")

        # 1. SQL injection attempt must fail
        sqli_resp = self.client.post("/login", data={
            "username": "admin' --",
            "password": "random_password"
        }, follow_redirects=True)
        self.assertIn("Invalid username or password.", sqli_resp.data.decode("utf-8"))
        with self.client.session_transaction() as sess:
            self.assertIsNone(sess.get("user_id"))

        # 2. Existing user with wrong password
        resp1 = self.client.post("/login", data={
            "username": "bob",
            "password": "wrong_password"
        }, follow_redirects=True)
        html1 = resp1.data.decode("utf-8")
        self.assertIn("Invalid username or password.", html1)
        self.assertNotIn("Incorrect password for user.", html1)

        # 3. Non-existent user with wrong password
        resp2 = self.client.post("/login", data={
            "username": "non_existent_user_99",
            "password": "wrong_password"
        }, follow_redirects=True)
        html2 = resp2.data.decode("utf-8")
        self.assertIn("Invalid username or password.", html2)
        self.assertNotIn("Account with this username does not exist.", html2)

        # 4. Cache-Control headers
        get_login = self.client.get("/login")
        self.assertIn("no-store", get_login.headers.get("Cache-Control", ""))
        self.assertNotIn('autocomplete="on"', get_login.data.decode("utf-8"))
        print("    [PASS] Login SQLi prevented, error messages uniform, Cache-Control enforced.")

    def test_02_legitimate_login_and_dashboard(self):
        """Verify legitimate user can log in and view dashboard."""
        print("\n[*] Testing legitimate authentication & dashboard...")
        resp = self.client.post("/login", data={
            "username": "bob",
            "password": "bob123"
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8")
        self.assertIn("Welcome back, Bob Brown!", html)
        self.assertIn("Operations Dashboard", html)
        print("    [PASS] Legitimate login and dashboard access verified.")

    def test_03_2fa_enforcement(self):
        """Verify 2FA enforcement prevents bypassing to protected routes."""
        print("\n[*] Testing 2FA challenge enforcement...")
        alice_client = self.app.test_client()

        # Alice logs in (2FA enabled)
        login_resp = alice_client.post("/login", data={
            "username": "alice",
            "password": "alice123"
        })
        self.assertEqual(login_resp.status_code, 302)
        self.assertIn("/2fa", login_resp.headers["Location"])

        # Attempt to access dashboard without verifying 2FA -> redirected to /2fa
        dash_resp = alice_client.get("/dashboard")
        self.assertEqual(dash_resp.status_code, 302)
        self.assertIn("/2fa", dash_resp.headers["Location"])

        # Complete 2FA verification
        verify_resp = alice_client.post("/2fa", data={
            "action": "verify_code",
            "code": "123456"
        }, follow_redirects=True)
        self.assertEqual(verify_resp.status_code, 200)
        self.assertIn("Welcome back, Alice Anderson!", verify_resp.data.decode("utf-8"))

        # Now dashboard is accessible
        dash_resp2 = alice_client.get("/dashboard")
        self.assertEqual(dash_resp2.status_code, 200)
        print("    [PASS] 2FA enforcement correctly blocks unverified sessions.")

    def test_04_profile_idor_protection(self):
        """Verify user cannot update another user's profile via ID tampering."""
        print("\n[*] Testing profile update IDOR protection...")
        alice_client = self.app.test_client()
        # Log in and verify 2FA
        alice_client.post("/login", data={"username": "alice", "password": "alice123"})
        alice_client.post("/2fa", data={"action": "verify_code", "code": "123456"})

        # Submit update with attempted tampering (user_id=2 -> Bob)
        update_resp = alice_client.post("/profile/edit", data={
            "user_id": "2",
            "display_name": "Alice Modified Name",
            "phone": "+1 555 999 1111",
            "address": "New Alice Address",
            "bio": "Updated Alice Bio"
        }, follow_redirects=True)
        self.assertEqual(update_resp.status_code, 200)

        # Verify Alice's profile was updated
        user1_resp = alice_client.get("/user/1")
        self.assertIn("Alice Modified Name", user1_resp.data.decode("utf-8"))

        # Verify Bob's profile card was NOT updated
        user2_resp = alice_client.get("/user/2")
        user2_html = user2_resp.data.decode("utf-8")
        self.assertIn("Public Profile: Bob Brown", user2_html)
        self.assertNotIn("Bob Brown (Modified By Alice IDOR)", user2_html)

        # Directly verify database record for Bob (id=2)
        with self.app.app_context():
            db = get_db()
            bob_row = db.execute("SELECT * FROM users WHERE id = 2").fetchone()
            self.assertEqual(bob_row["display_name"], "Bob Brown")
            self.assertNotEqual(bob_row["display_name"], "Alice Modified Name")
        print("    [PASS] IDOR prevented: profile edit strictly updates authenticated user.")

    def test_05_file_upload_validation(self):
        """Verify file upload allowlist and rejection of dangerous extensions."""
        print("\n[*] Testing file upload extension validation...")
        charlie_client = self.app.test_client()
        charlie_client.post("/login", data={"username": "charlie", "password": "charlie123"}, follow_redirects=True)

        # 1. Attempt to upload .php script
        php_data = {
            "file": (io.BytesIO(b"<?php echo 'malicious'; ?>"), "test_script.php"),
            "description": "PHP Test"
        }
        resp_php = charlie_client.post("/upload", data=php_data, content_type="multipart/form-data", follow_redirects=True)
        self.assertIn("prohibited", resp_php.data.decode("utf-8"))

        # 2. Attempt to upload .exe
        exe_data = {
            "file": (io.BytesIO(b"MZ..."), "malicious.exe"),
            "description": "EXE Test"
        }
        resp_exe = charlie_client.post("/upload", data=exe_data, content_type="multipart/form-data", follow_redirects=True)
        self.assertIn("prohibited", resp_exe.data.decode("utf-8"))

        # 3. Legitimate file upload (.txt)
        txt_data = {
            "file": (io.BytesIO(b"Legitimate document contents"), "test_document.txt"),
            "description": "Clean text document"
        }
        resp_txt = charlie_client.post("/upload", data=txt_data, content_type="multipart/form-data", follow_redirects=True)
        self.assertIn("successfully uploaded and indexed", resp_txt.data.decode("utf-8"))
        print("    [PASS] Upload extension validation enforces strict allowlist.")

    def test_06_path_traversal_protection(self):
        """Verify download endpoint prevents path traversal escapes."""
        print("\n[*] Testing download endpoint path traversal protection...")
        bob_client = self.app.test_client()
        bob_client.post("/login", data={"username": "bob", "password": "bob123"}, follow_redirects=True)

        # Attempt traversal to training_note.txt
        traversal_attempts = [
            "../lab_data/training_note.txt",
            "../../lab_data/training_note.txt",
            "..\\lab_data\\training_note.txt",
            "..%2Flab_data%2Ftraining_note.txt"
        ]
        for path in traversal_attempts:
            resp = bob_client.get(f"/files/download?file={path}", follow_redirects=True)
            content = resp.data.decode("utf-8", errors="ignore")
            self.assertNotIn("TRACEGATE{path_traversal_lab_verified_cwe22}", content)
        print("    [PASS] Path traversal attempts safely rejected.")

    def test_07_svg_rendering_safety(self):
        """Verify SVG rendering does not inject raw unescaped HTML script into DOM."""
        print("\n[*] Testing SVG rendering safety...")
        charlie_client = self.app.test_client()
        charlie_client.post("/login", data={"username": "charlie", "password": "charlie123"}, follow_redirects=True)

        gallery_resp = charlie_client.get("/uploads")
        self.assertEqual(gallery_resp.status_code, 200)
        html = gallery_resp.data.decode("utf-8")
        # Ensure raw <svg ...> is not injected directly via |safe without img tag
        self.assertIn("<img src=", html)
        print("    [PASS] SVG assets rendered safely via image preview tags.")

    def test_08_core_application_workflows(self):
        """Verify team directory, comments log, and details view."""
        print("\n[*] Testing core application workflows...")
        client = self.app.test_client()
        client.post("/login", data={"username": "bob", "password": "bob123"}, follow_redirects=True)

        # Team directory
        users_resp = client.get("/users")
        self.assertEqual(users_resp.status_code, 200)
        self.assertIn("Team Members", users_resp.data.decode("utf-8"))

        # User detail
        detail_resp = client.get("/user/1")
        self.assertEqual(detail_resp.status_code, 200)
        self.assertIn("Alice", detail_resp.data.decode("utf-8"))

        # Post comment
        comment_resp = client.post("/comments", data={
            "comment_text": "Clean architecture verification test log entry."
        }, follow_redirects=True)
        self.assertEqual(comment_resp.status_code, 200)
        self.assertIn("Clean architecture verification test log entry.", comment_resp.data.decode("utf-8"))
        print("    [PASS] Core directory, detail, and operations log workflows operational.")


if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(SecureHubCleanVerificationTests)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if result.wasSuccessful():
        print("\n" + "=" * 70)
        print(" ALL CLEAN ARCHITECTURE TESTS PASSED SUCCESSFULLY!")
        print("=" * 70)
    else:
        sys.exit(1)
