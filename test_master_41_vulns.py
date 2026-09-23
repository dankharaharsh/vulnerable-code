"""
SecureHub VAPT Training Lab — Master 41-Vulnerability Quality Assurance & Verification Runner
Executes comprehensive automated testing for all 41 approved intentional vulnerabilities.
"""

import sys
import unittest
from reset_lab import reset_environment

from test_phase2_vulns import Phase2VulnerabilityVerificationTests
from test_phase3_vulns import Phase3VulnerabilityVerificationTests
from test_phase4_vulns import Phase4VulnerabilityVerificationTests
from test_phase5_vulns import Phase5VulnerabilityVerificationTests
from test_phase6_vulns import Phase6VulnerabilitiesTestCase


def run_comprehensive_audit():
    print("=" * 80)
    print(" SECUREHUB VAPT TRAINING LAB — 41/41 COMPREHENSIVE VULNERABILITY QA AUDIT")
    print("=" * 80)
    
    suite = unittest.TestSuite()
    
    # Load all 41 tests across all phases
    phase2_tests = [
        "test_01_vuln_authentication_bypass_sqli",
        "test_02_vuln_2fa_implementation_bypass",
        "test_03_vuln_rate_limiting_absence",
        "test_04_vuln_account_enumeration",
        "test_05_vuln_captcha_bypass",
        "test_06_vuln_otp_brute_force",
        "test_07_vuln_session_fixation",
        "test_08_vuln_credential_caching_and_autocomplete",
    ]
    for t in phase2_tests:
        suite.addTest(Phase2VulnerabilityVerificationTests(t))

    phase3_tests = [
        "test_09_weak_password_policy",
        "test_10_email_verification_bypass",
        "test_11_mass_account_creation",
        "test_12_predictable_reset_token",
        "test_13_password_reset_authorization_hijack",
        "test_14_insufficient_token_expiration",
        "test_15_password_reset_poisoning_host_header",
        "test_16_reset_token_reuse",
        "test_17_session_termination_on_password_reset",
    ]
    for t in phase3_tests:
        suite.addTest(Phase3VulnerabilityVerificationTests(t))

    phase4_tests = [
        "test_18_idor_profile_update",
        "test_19_arbitrary_file_upload_extension",
        "test_20_current_password_verification_bypass",
        "test_21_csrf_sensitive_action",
        "test_22_stored_xss_bio",
        "test_23_mime_magic_spoofing",
        "test_24_stored_xss_svg_upload",
        "test_25_hardcoded_api_key_and_plaintext_pat",
        "test_26_active_session_termination_bypass",
    ]
    for t in phase4_tests:
        suite.addTest(Phase4VulnerabilityVerificationTests(t))

    phase5_tests = [
        "test_27_bola_analytics_widget_metrics",
        "test_28_sqli_dashboard_timeframe_filter",
        "test_29_reflected_xss_search",
        "test_30_sensitive_info_disclosure_activity",
        "test_31_sqli_search_filter",
        "test_32_search_index_leakage",
        "test_33_path_traversal_download",
    ]
    for t in phase5_tests:
        suite.addTest(Phase5VulnerabilityVerificationTests(t))

    phase6_tests = [
        "test_vuln_34_price_parameter_tampering",
        "test_vuln_35_negative_quantity_underflow",
        "test_vuln_36_promo_voucher_replay",
        "test_vuln_37_vertical_privilege_escalation",
        "test_vuln_38_role_parameter_tampering",
        "test_vuln_39_audit_log_deletion",
        "test_vuln_40_information_disclosure_banners_and_endpoint",
        "test_vuln_41_insecure_transport_hsts",
    ]
    for t in phase6_tests:
        suite.addTest(Phase6VulnerabilitiesTestCase(t))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 80)
    print(f" AUDIT SUMMARY: {result.testsRun - len(result.failures) - len(result.errors)} / {result.testsRun} Vulnerabilities Verified")
    print("=" * 80)

    if result.wasSuccessful():
        print("[SUCCESS] All 41 intentional vulnerabilities verified and operational!")
        return 0
    else:
        print("[FAILURE] Some vulnerabilities failed verification!")
        return 1


if __name__ == "__main__":
    sys.exit(run_comprehensive_audit())
