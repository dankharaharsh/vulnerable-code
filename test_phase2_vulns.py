"""
SecureHub VAPT Lab — Phase 2 Verification Suite (Vulnerabilities 1–8)
Verifies that vulnerabilities 1 through 8 are active and verifiable,
while normal application features and legitimate workflows remain intact.
"""

import io
import sys
import unittest
from app import app, get_db
from reset_lab import reset_environment


class Phase2VulnerabilityVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n" + "=" * 70)
        print(" VERIFYING PHASE 2 VULNERABILITIES (1–8)")
        print("=" * 70)
        reset_environment()

    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    # -------------------------------------------------------------------------
    # 0. Baseline Legitimate Workflows
    # -------------------------------------------------------------------------
    def test_00_legitimate_authentication_and_navigation(self):
        """Verify normal authentication and dashboard navigation remain fully functional."""
        print("\n[*] Testing baseline legitimate authentication and workflows...")
        resp = self.client.post("/login", data={
            "username": "bob",
            "password": "bob123"
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Welcome back, Bob Brown!", resp.data.decode("utf-8"))

        # Verify pages load
        dash_resp = self.client.get("/dashboard")
        self.assertEqual(dash_resp.status_code, 200)

        users_resp = self.client.get("/users")
        self.assertEqual(users_resp.status_code, 200)

        profile_resp = self.client.get("/profile")
        self.assertEqual(profile_resp.status_code, 200)

        logout_resp = self.client.get("/logout", follow_redirects=True)
        self.assertIn("signed out successfully", logout_resp.data.decode("utf-8"))
        print("    [PASS] Legitimate login, dashboard, user directory, profile, and logout functional.")

    # -------------------------------------------------------------------------
    # 1. VULN-01: Authentication Bypass (SQL Injection)
    # -------------------------------------------------------------------------
    def test_01_vuln_authentication_bypass_sqli(self):
        """Verify authentication bypass via SQL injection payload."""
        print("\n[*] Testing VULN-01: Authentication Bypass (SQL Injection)...")
        client = self.app.test_client()
        resp = client.post("/login", data={
            "username": "admin' --",
            "password": "arbitrary_wrong_password"
        }, follow_redirects=True)

        self.assertEqual(resp.status_code, 200)
        with client.session_transaction() as sess:
            self.assertEqual(sess.get("username"), "admin")
            self.assertEqual(sess.get("role"), "admin")
        self.assertIn("Welcome back", resp.data.decode("utf-8"))
        print("    [PASS] VULN-01 Verified: SQL Injection bypassed password authentication for admin.")

    # -------------------------------------------------------------------------
    # 2. VULN-02: 2FA Implementation Bypass
    # -------------------------------------------------------------------------
    def test_02_vuln_2fa_implementation_bypass(self):
        """Verify 2FA challenge can be bypassed by directly requesting protected routes."""
        print("\n[*] Testing VULN-02: 2FA Implementation Bypass...")
        alice_client = self.app.test_client()

        # Alice logs in with valid primary credentials (2FA enabled)
        login_resp = alice_client.post("/login", data={
            "username": "alice",
            "password": "alice123"
        })
        self.assertEqual(login_resp.status_code, 302)
        self.assertIn("/2fa", login_resp.headers["Location"])

        # Check session: user_id is set, but 2fa_verified is False
        with alice_client.session_transaction() as sess:
            self.assertIsNotNone(sess.get("user_id"))
            self.assertFalse(sess.get("2fa_verified"))

        # Bypass: Navigate directly to /dashboard without submitting 2FA token
        dash_resp = alice_client.get("/dashboard")
        self.assertEqual(dash_resp.status_code, 200)
        self.assertIn("Welcome back, Alice Anderson!", dash_resp.data.decode("utf-8"))
        print("    [PASS] VULN-02 Verified: 2FA state not enforced by server-side authorization.")

    # -------------------------------------------------------------------------
    # 3. VULN-03: Rate Limiting & Credential Stuffing Prevention
    # -------------------------------------------------------------------------
    def test_03_vuln_rate_limiting_absence(self):
        """Verify login allows rapid repeated failed attempts without throttling or lockout."""
        print("\n[*] Testing VULN-03: Rate Limiting & Credential Stuffing Prevention...")
        client = self.app.test_client()
        attempts = 12
        for i in range(attempts):
            resp = client.post("/login", data={
                "username": "charlie",
                "password": f"wrong_password_{i}"
            })
            self.assertEqual(resp.status_code, 200)
            self.assertIn("Invalid username or password.", resp.data.decode("utf-8"))

        # Subsequent legitimate login immediately succeeds (no account lockout)
        valid_resp = client.post("/login", data={
            "username": "charlie",
            "password": "charlie123"
        }, follow_redirects=True)
        self.assertEqual(valid_resp.status_code, 200)
        self.assertIn("Welcome back, Charlie Carter!", valid_resp.data.decode("utf-8"))
        print(f"    [PASS] VULN-03 Verified: {attempts} failed attempts permitted without delay or lockout.")

    # -------------------------------------------------------------------------
    # 4. VULN-04: Username & Account Enumeration
    # -------------------------------------------------------------------------
    def test_04_vuln_account_enumeration(self):
        """Verify recovery endpoint leaks account existence via distinct responses."""
        print("\n[*] Testing VULN-04: Username & Account Enumeration...")
        client = self.app.test_client()

        # Fetch CAPTCHA code from session
        client.get("/forgot-password")
        with client.session_transaction() as sess:
            captcha_code = sess.get("recovery_captcha")

        # 1. Query existing user
        resp_existing = client.post("/forgot-password", data={
            "identity": "bob",
            "captcha": captcha_code
        }, follow_redirects=True)
        existing_html = resp_existing.data.decode("utf-8")

        # Refresh CAPTCHA for second query
        client.get("/forgot-password")
        with client.session_transaction() as sess:
            captcha_code2 = sess.get("recovery_captcha")

        # 2. Query non-existent user
        resp_nonexistent = client.post("/forgot-password", data={
            "identity": "unknown_user_9999",
            "captcha": captcha_code2
        }, follow_redirects=True)
        nonexistent_html = resp_nonexistent.data.decode("utf-8")

        self.assertIn("Recovery instructions and verification code have been dispatched to bob@training.local", existing_html)
        self.assertIn("does not exist in our corporate directory", nonexistent_html)
        self.assertNotEqual(existing_html, nonexistent_html)
        print("    [PASS] VULN-04 Verified: Distinct observable responses expose valid accounts.")

    # -------------------------------------------------------------------------
    # 5. VULN-05: CAPTCHA Security & Bypass on Recovery Form
    # -------------------------------------------------------------------------
    def test_05_vuln_captcha_bypass(self):
        """Verify CAPTCHA validation can be bypassed by omitting the captcha parameter."""
        print("\n[*] Testing VULN-05: CAPTCHA Security & Bypass on Recovery Form...")
        client = self.app.test_client()
        client.get("/forgot-password")

        # 1. Incorrect CAPTCHA submitted -> Rejected
        fail_resp = client.post("/forgot-password", data={
            "identity": "bob",
            "captcha": "WRONG_CODE"
        }, follow_redirects=True)
        self.assertIn("Security verification failed", fail_resp.data.decode("utf-8"))

        # 2. Bypass: Omit the 'captcha' parameter entirely -> Accepted!
        bypass_resp = client.post("/forgot-password", data={
            "identity": "bob"
            # 'captcha' parameter omitted entirely
        }, follow_redirects=True)
        self.assertEqual(bypass_resp.status_code, 200)
        self.assertIn("Verify Recovery Code", bypass_resp.data.decode("utf-8"))
        self.assertIn("Recovery instructions and verification code have been dispatched", bypass_resp.data.decode("utf-8"))
        print("    [PASS] VULN-05 Verified: Omitting captcha field completely bypassed verification.")

    # -------------------------------------------------------------------------
    # 6. VULN-06: OTP / Recovery Code Brute-Force & Insufficient Throttling
    # -------------------------------------------------------------------------
    def test_06_vuln_otp_brute_force(self):
        """Verify 4-digit OTP allows unlimited rapid verification attempts without lockout."""
        print("\n[*] Testing VULN-06: OTP / Recovery Code Brute-Force & Insufficient Throttling...")
        client = self.app.test_client()

        # Initiate recovery for bob
        client.post("/forgot-password", data={"identity": "bob"}, follow_redirects=True)

        # Retrieve expected OTP from DB
        with self.app.app_context():
            db = get_db()
            bob_row = db.execute("SELECT recovery_code FROM users WHERE username = 'bob'").fetchone()
            actual_code = bob_row["recovery_code"]
            self.assertEqual(len(actual_code), 4)

        # Submit 10 consecutive incorrect guesses
        for guess in range(10):
            wrong_code = f"000{guess}" if f"000{guess}" != actual_code else "9999"
            resp = client.post("/verify-recovery", data={"code": wrong_code}, follow_redirects=True)
            self.assertIn("Invalid recovery verification code", resp.data.decode("utf-8"))

        # Submit correct OTP after repeated failures -> Still valid!
        success_resp = client.post("/verify-recovery", data={"code": actual_code}, follow_redirects=True)
        self.assertEqual(success_resp.status_code, 200)
        self.assertIn("Set New Password", success_resp.data.decode("utf-8"))

        # Complete reset password workflow
        reset_resp = client.post("/reset-password", data={
            "new_password": "new_bob_password123",
            "confirm_password": "new_bob_password123"
        }, follow_redirects=True)
        self.assertIn("password has been reset successfully", reset_resp.data.decode("utf-8"))

        # Verify Bob can log in with new password
        new_login = client.post("/login", data={
            "username": "bob",
            "password": "new_bob_password123"
        }, follow_redirects=True)
        self.assertIn("Welcome back, Bob Brown!", new_login.data.decode("utf-8"))
        print("    [PASS] VULN-06 Verified: 4-digit OTP permits unlimited attempts and successful reset.")

    # -------------------------------------------------------------------------
    # 7. VULN-07: Session Fixation & Post-Auth Identifier Regeneration
    # -------------------------------------------------------------------------
    def test_07_vuln_session_fixation(self):
        """Verify pre-authentication session identifier is preserved post-authentication."""
        print("\n[*] Testing VULN-07: Session Fixation & Post-Auth Identifier Regeneration...")
        client = self.app.test_client()

        # Step 1: Pre-auth request generates session_id
        client.get("/login")
        with client.session_transaction() as pre_sess:
            pre_auth_session_id = pre_sess.get("session_id")
        self.assertIsNotNone(pre_auth_session_id)

        # Step 2: Authenticate as bob
        client.post("/login", data={"username": "bob", "password": "new_bob_password123"}, follow_redirects=True)

        # Step 3: Verify session_id was NOT regenerated
        with client.session_transaction() as post_sess:
            post_auth_session_id = post_sess.get("session_id")

        self.assertEqual(pre_auth_session_id, post_auth_session_id)
        print("    [PASS] VULN-07 Verified: Pre-auth session identifier retained post-authentication.")

    # -------------------------------------------------------------------------
    # 8. VULN-08: Credential Caching & Form Autocomplete Directive
    # -------------------------------------------------------------------------
    def test_08_vuln_credential_caching_and_autocomplete(self):
        """Verify login allows credential caching and autocomplete directives."""
        print("\n[*] Testing VULN-08: Credential Caching & Form Autocomplete Directive...")
        resp = self.client.get("/login")
        self.assertEqual(resp.status_code, 200)

        # Cache-Control lacks no-store and permits caching
        cache_control = resp.headers.get("Cache-Control", "")
        self.assertIn("public", cache_control)
        self.assertNotIn("no-store", cache_control)

        # Form contains autocomplete="on"
        html = resp.data.decode("utf-8")
        self.assertIn('autocomplete="on"', html)
        print("    [PASS] VULN-08 Verified: Form autocomplete='on' and Cache-Control lacks no-store.")


if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(Phase2VulnerabilityVerificationTests)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if result.wasSuccessful():
        print("\n" + "=" * 70)
        print(" ALL 8 PHASE 2 VULNERABILITIES VERIFIED SUCCESSFULLY!")
        print("=" * 70)
        sys.exit(0)
    else:
        sys.exit(1)
