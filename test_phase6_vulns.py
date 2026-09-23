"""
Automated Test Suite for Phase 6 (Vulnerabilities 34–41)
SecureHub VAPT Training Lab
"""

import unittest
import sqlite3
from app import app, DATABASE_PATH
from reset_lab import reset_environment


class Phase6VulnerabilitiesTestCase(unittest.TestCase):
    def setUp(self):
        reset_environment()
        self.app = app
        self.client = self.app.test_client()
        self.app.testing = True

    def login(self, username, password):
        return self.client.post("/login", data={
            "username": username,
            "password": password
        }, follow_redirects=True)

    # -------------------------------------------------------------------------
    # VULN-34: Price & Currency Manipulation via Parameter Tampering
    # -------------------------------------------------------------------------
    def test_vuln_34_price_parameter_tampering(self):
        """Verify checkout accepts client-tampered price parameters."""
        self.login("bob", "bob123")
        # Direct checkout with manipulated unit_price of $0.05
        res = self.client.post("/store/checkout", data={
            "product_id": 1,
            "quantity": 2,
            "unit_price": "0.05",
            "currency": "EUR"
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)

        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        order = conn.execute("SELECT * FROM orders WHERE user_id = 2 ORDER BY id DESC LIMIT 1").fetchone()
        conn.close()

        self.assertIsNotNone(order)
        # Expected total is 2 * 0.05 = 0.10, NOT 2 * 49.99 = 99.98
        self.assertAlmostEqual(order["total"], 0.10, places=2)
        self.assertEqual(order["currency"], "EUR")

    # -------------------------------------------------------------------------
    # VULN-35: Negative Quantity & Integer Underflow Logic Flaws
    # -------------------------------------------------------------------------
    def test_vuln_35_negative_quantity_underflow(self):
        """Verify cart update accepts negative quantity and produces negative subtotal."""
        self.login("bob", "bob123")
        # Add item first
        self.client.post("/store/cart/add", data={"product_id": 1, "quantity": 1})
        
        # Update with negative quantity
        res = self.client.post("/store/cart/update", data={
            "product_id": 1,
            "quantity": -3
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        
        # Verify negative subtotal is present in cart page
        self.assertIn(b"-149.97", res.data)

    # -------------------------------------------------------------------------
    # VULN-36: Promo Voucher Replay & Concurrent Race Conditions
    # -------------------------------------------------------------------------
    def test_vuln_36_promo_voucher_replay(self):
        """Verify single-use voucher SAVE50 can be replayed across multiple orders."""
        self.login("bob", "bob123")
        
        # Order 1 with voucher
        self.client.post("/store/cart/add", data={"product_id": 2, "quantity": 1})
        self.client.post("/store/cart/apply-voucher", data={"voucher_code": "SAVE50"}, follow_redirects=True)
        res1 = self.client.post("/store/checkout", data={"currency": "USD"}, follow_redirects=True)
        self.assertEqual(res1.status_code, 200)

        # Order 2 using the same single-use voucher SAVE50
        self.client.post("/store/cart/add", data={"product_id": 2, "quantity": 1})
        res_voucher = self.client.post("/store/cart/apply-voucher", data={"voucher_code": "SAVE50"}, follow_redirects=True)
        self.assertIn(b"SAVE50", res_voucher.data)
        self.assertIn(b"applied", res_voucher.data)
        
        res2 = self.client.post("/store/checkout", data={"currency": "USD"}, follow_redirects=True)
        self.assertEqual(res2.status_code, 200)

        conn = sqlite3.connect(DATABASE_PATH)
        orders = conn.execute("SELECT * FROM orders WHERE user_id = 2 AND discount = 50.0").fetchall()
        conn.close()
        self.assertGreaterEqual(len(orders), 2)

    # -------------------------------------------------------------------------
    # VULN-37: Vertical Privilege Escalation on Administrative Functions
    # -------------------------------------------------------------------------
    def test_vuln_37_vertical_privilege_escalation(self):
        """Verify standard user can trigger admin backup routine without admin role."""
        self.login("bob", "bob123")  # bob is a standard user
        res = self.client.post("/admin/system/backup", follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"System configuration backup", res.data)

        conn = sqlite3.connect(DATABASE_PATH)
        log = conn.execute("SELECT * FROM audit_logs WHERE event_type = 'SYSTEM_BACKUP_INITIATED' AND actor_username = 'bob'").fetchone()
        conn.close()
        self.assertIsNotNone(log)

    # -------------------------------------------------------------------------
    # VULN-38: Parameter Tampering on User Role & Permission Assignment
    # -------------------------------------------------------------------------
    def test_vuln_38_role_parameter_tampering(self):
        """Verify standard user can elevate their role to admin via profile update."""
        self.login("charlie", "charlie123")  # charlie is standard user
        res = self.client.post("/profile/edit", data={
            "user_id": 3,
            "display_name": "Charlie Super Admin",
            "phone": "+1 555 999 8888",
            "address": "HQ Server Room",
            "bio": "Elevated admin privileges.",
            "role": "admin"
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)

        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        user = conn.execute("SELECT role FROM users WHERE id = 3").fetchone()
        conn.close()
        self.assertEqual(user["role"], "admin")

    # -------------------------------------------------------------------------
    # VULN-39: Audit Trail Event Log Tampering / Deletion
    # -------------------------------------------------------------------------
    def test_vuln_39_audit_log_deletion(self):
        """Verify authenticated user can delete audit trail entries."""
        self.login("bob", "bob123")
        res = self.client.post("/audit-logs/delete", data={"log_id": 1}, follow_redirects=True)
        self.assertEqual(res.status_code, 200)

        conn = sqlite3.connect(DATABASE_PATH)
        log = conn.execute("SELECT * FROM audit_logs WHERE id = 1").fetchone()
        conn.close()
        self.assertIsNone(log)

    # -------------------------------------------------------------------------
    # VULN-40: General Information Disclosure via System Banners & Headers
    # -------------------------------------------------------------------------
    def test_vuln_40_information_disclosure_banners_and_endpoint(self):
        """Verify diagnostics endpoint and response headers disclose internal tech stack."""
        res = self.client.get("/system/info")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("python_version", data)
        self.assertIn("sqlite_version", data)
        self.assertIn("active_endpoints", data)

        # Response headers check
        self.assertIn("SecureHub-Internal", res.headers.get("Server", ""))
        self.assertIn("Flask/3.0.3", res.headers.get("X-Powered-By", ""))

    # -------------------------------------------------------------------------
    # VULN-41: Insecure Transport Security / HTTPS / HSTS
    # -------------------------------------------------------------------------
    def test_vuln_41_insecure_transport_hsts(self):
        """Verify HSTS header is missing and SESSION_COOKIE_SECURE is False."""
        self.assertFalse(self.app.config.get("SESSION_COOKIE_SECURE", True))
        
        res = self.client.get("/login")
        self.assertNotIn("Strict-Transport-Security", res.headers)


if __name__ == "__main__":
    unittest.main()
