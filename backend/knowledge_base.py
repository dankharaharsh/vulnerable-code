"""
Tracegate Controlled Security Knowledge Base & Relevance Scoring Engine.
Maps standardized VAPT security tests to page categories, visible UI features,
and contextual triggers without generic hallucinations or unverified CVEs.
"""

from typing import List, Dict, Any, Optional, Tuple
import re

# Comprehensive catalog of standardized web application security tests
SECURITY_KNOWLEDGE_BASE: List[Dict[str, Any]] = [
    # -------------------------------------------------------------------------
    # 1. AUTHENTICATION & LOGIN TESTS
    # -------------------------------------------------------------------------
    {
        "id": "auth-sqli-bypass",
        "name": "Authentication Bypass (SQL Injection / Logic Flaws)",
        "category": "Authentication",
        "description": "Evaluate whether authentication controls can be bypassed using SQL injection payloads or logical manipulation.",
        "testing_objective": "Test login inputs with boolean tautologies, string termination, and null byte sequences to assess backend credential verification.",
        "cwe": "CWE-287",
        "default_priority": "CRITICAL",
        "relevant_pages": ["Login / Sign-in", "Sign-up / Registration", "Admin Dashboard / Admin Panel"],
        "relevant_features": ["Username input", "Password input", "Sign in button", "Admin login"],
        "keywords": ["auth", "login", "password", "sign in", "credentials", "sqli", "bypass"]
    },
    {
        "id": "auth-rate-limiting",
        "name": "Rate Limiting & Credential Stuffing Prevention",
        "category": "Authentication",
        "description": "Assess automated brute-force protection and progressive rate limiting on authentication endpoints.",
        "testing_objective": "Send repeated login requests to verify whether IP-based throttling, progressive delays, or CAPTCHA triggers activate.",
        "cwe": "CWE-307",
        "default_priority": "HIGH",
        "relevant_pages": ["Login / Sign-in", "Forgot Password / Password Reset", "Sign-up / Registration"],
        "relevant_features": ["Login form", "Submit button", "Password field", "Forgot password"],
        "keywords": ["brute", "rate limit", "throttle", "stuffing", "password", "lockout"]
    },
    {
        "id": "auth-username-enum",
        "name": "Username & Account Enumeration",
        "category": "Authentication",
        "description": "Check whether response error codes, body messages, or response times reveal existing accounts.",
        "testing_objective": "Submit known vs. non-existent usernames and compare HTTP response codes, timing differentials, and error messages.",
        "cwe": "CWE-204",
        "default_priority": "HIGH",
        "relevant_pages": ["Login / Sign-in", "Forgot Password / Password Reset", "Sign-up / Registration"],
        "relevant_features": ["Email field", "Username field", "Recovery input", "Validation feedback"],
        "keywords": ["enumeration", "username", "email", "timing", "account exists"]
    },
    {
        "id": "auth-session-fixation",
        "name": "Session Fixation & Post-Auth Identifier Regeneration",
        "category": "Session Management",
        "description": "Verify that pre-authentication session tokens are destroyed and regenerated upon successful authentication.",
        "testing_objective": "Inspect session cookies before and after sign-in to verify that session identifiers are securely rotated.",
        "cwe": "CWE-384",
        "default_priority": "MEDIUM",
        "relevant_pages": ["Login / Sign-in", "Sign-up / Registration", "Home / Dashboard"],
        "relevant_features": ["Session cookie", "Sign in action", "Remember me"],
        "keywords": ["session", "fixation", "cookie", "rotate", "pre-auth"]
    },
    {
        "id": "auth-autocomplete",
        "name": "Credential Caching & Form Autocomplete Directive",
        "category": "Client-Side Security",
        "description": "Verify that sensitive password and card inputs use appropriate autocomplete and cache-control directives.",
        "testing_objective": "Inspect form tag and password input DOM attributes for autocomplete='off' or 'new-password' compliance.",
        "cwe": "CWE-524",
        "default_priority": "LOW",
        "relevant_pages": ["Login / Sign-in", "Checkout / Payment", "Forgot Password / Password Reset"],
        "relevant_features": ["Password input", "Credit card field", "CVV input"],
        "keywords": ["autocomplete", "cache", "browser memory", "password field"]
    },

    # -------------------------------------------------------------------------
    # 2. REGISTRATION & ACCOUNT CREATION TESTS
    # -------------------------------------------------------------------------
    {
        "id": "reg-weak-password",
        "name": "Weak Password Policy & Insufficient Complexity Enforcement",
        "category": "Authentication",
        "description": "Test server-side enforcement of password length, character variety, and common password blocklists.",
        "testing_objective": "Submit trivial passwords (e.g., '123456', 'password') to ensure server rejects weak credentials.",
        "cwe": "CWE-521",
        "default_priority": "HIGH",
        "relevant_pages": ["Sign-up / Registration", "Forgot Password / Password Reset", "Account / Profile"],
        "relevant_features": ["New password field", "Confirm password", "Registration form"],
        "keywords": ["password policy", "weak password", "complexity", "registration", "signup"]
    },
    {
        "id": "reg-email-verification-bypass",
        "name": "Email Verification & Account Activation Bypass",
        "category": "Authentication",
        "description": "Assess whether unverified accounts can access authenticated resources without completing verification.",
        "testing_objective": "Attempt navigating directly to authenticated dashboard endpoints without clicking activation link.",
        "cwe": "CWE-287",
        "default_priority": "HIGH",
        "relevant_pages": ["Sign-up / Registration"],
        "relevant_features": ["Email field", "Activation notice", "Sign up button"],
        "keywords": ["activation", "verify", "email confirmation", "unverified"]
    },
    {
        "id": "reg-bot-automation",
        "name": "Automated Account Mass Creation (Lack of CAPTCHA/Throttling)",
        "category": "Authentication",
        "description": "Determine whether mass registration attacks can exhaust server resources or create fraudulent bot accounts.",
        "testing_objective": "Script sequential sign-up requests to test whether CAPTCHA or progressive velocity checks enforce boundaries.",
        "cwe": "CWE-799",
        "default_priority": "MEDIUM",
        "relevant_pages": ["Sign-up / Registration"],
        "relevant_features": ["Sign up form", "Terms checkbox", "Register button"],
        "keywords": ["bot", "mass registration", "captcha", "automation", "spam accounts"]
    },

    # -------------------------------------------------------------------------
    # 3. FORGOT PASSWORD & RECOVERY TESTS
    # -------------------------------------------------------------------------
    {
        "id": "rec-token-entropy",
        "name": "Predictable Password Reset Token & Insufficient Entropy",
        "category": "Cryptography",
        "description": "Check whether password recovery tokens are predictable, sequential, or have insufficient length/entropy.",
        "testing_objective": "Generate multiple reset tokens and analyze pseudo-random randomness, timestamps, or hashing patterns.",
        "cwe": "CWE-330",
        "default_priority": "CRITICAL",
        "relevant_pages": ["Forgot Password / Password Reset"],
        "relevant_features": ["Reset email input", "Token input field", "Reset submission button"],
        "keywords": ["reset token", "entropy", "predictable", "recovery link", "token brute force"]
    },
    {
        "id": "rec-host-header-injection",
        "name": "Password Reset Poisoning via Host Header Injection",
        "category": "Injection",
        "description": "Evaluate if altering the HTTP Host header poisons password reset emails with attacker domains.",
        "testing_objective": "Intercept reset request and supply a modified Host or X-Forwarded-Host header; inspect the generated link.",
        "cwe": "CWE-644",
        "default_priority": "HIGH",
        "relevant_pages": ["Forgot Password / Password Reset"],
        "relevant_features": ["Reset request form", "Submit button"],
        "keywords": ["host header", "poisoning", "reset link", "domain injection"]
    },
    {
        "id": "rec-session-invalidation",
        "name": "Session Termination on Password Reset",
        "category": "Session Management",
        "description": "Ensure all existing concurrent sessions are terminated globally after completing a password reset.",
        "testing_objective": "Log in on two separate browser sessions, reset password on one, and test if the second session is revoked.",
        "cwe": "CWE-613",
        "default_priority": "MEDIUM",
        "relevant_pages": ["Forgot Password / Password Reset", "Account / Profile", "Settings / Security Settings"],
        "relevant_features": ["Password change section", "Security settings"],
        "keywords": ["session termination", "revoke", "concurrent sessions", "password reset"]
    },
    {
        "id": "rec-token-reuse",
        "name": "Reset Token Reuse & Lack of Single-Use Enforcement",
        "category": "Authentication",
        "description": "Verify whether password reset tokens can be reused multiple times after initial redemption.",
        "testing_objective": "Complete a password reset flow using a valid token, then attempt to replay the final reset request using the identical token.",
        "cwe": "CWE-640",
        "default_priority": "HIGH",
        "relevant_pages": ["Forgot Password / Password Reset"],
        "relevant_features": ["Reset token", "Password reset submission", "Recovery link"],
        "keywords": ["token reuse", "single use", "replay", "token expiration"]
    },
    {
        "id": "rec-token-expiry",
        "name": "Insufficient Token Expiration & Prolonged Lifetime",
        "category": "Session Management",
        "description": "Verify that password reset tokens expire within a short security window (e.g. 15-30 minutes).",
        "testing_objective": "Generate a reset token and attempt redemption after varying intervals to confirm token invalidation.",
        "cwe": "CWE-613",
        "default_priority": "HIGH",
        "relevant_pages": ["Forgot Password / Password Reset"],
        "relevant_features": ["Reset link", "Recovery email", "Token field"],
        "keywords": ["expiration", "lifetime", "validity window", "token timeout"]
    },
    {
        "id": "rec-captcha-bypass",
        "name": "CAPTCHA Security & Bypass on Recovery Form",
        "category": "Authentication",
        "description": "Assess whether automated password recovery requests can bypass CAPTCHA controls via direct API calls or missing validation.",
        "testing_objective": "Omit or manipulate the captcha_response parameter or replay requests with an expired CAPTCHA token to verify enforcement.",
        "cwe": "CWE-804",
        "default_priority": "HIGH",
        "relevant_pages": ["Forgot Password / Password Reset", "Sign-up / Registration", "Login / Sign-in"],
        "relevant_features": ["CAPTCHA", "reCAPTCHA", "hCaptcha", "Security challenge", "Bot protection"],
        "keywords": ["captcha", "recaptcha", "hcaptcha", "bot", "puzzle", "challenge"]
    },
    {
        "id": "rec-otp-security",
        "name": "OTP / Recovery Code Brute-Force & Insufficient Throttling",
        "category": "Authentication",
        "description": "Determine whether numerical OTP or recovery codes can be brute-forced due to missing rate limits or predictable generation.",
        "testing_objective": "Send repeated recovery verification attempts with sequential OTP codes to test server-side lockout and rate limiting.",
        "cwe": "CWE-307",
        "default_priority": "HIGH",
        "relevant_pages": ["Forgot Password / Password Reset", "Login / Sign-in", "Settings / Security Settings"],
        "relevant_features": ["OTP", "OTP field", "Verification code", "One-time password", "SMS code"],
        "keywords": ["otp", "one-time password", "verification code", "sms code", "pin", "6-digit"]
    },
    {
        "id": "rec-reset-authz",
        "name": "Password Reset Authorization & Account Hijacking",
        "category": "Authorization",
        "description": "Ensure an attacker cannot swap the target username or identifier during the reset confirmation step to take over another user account.",
        "testing_objective": "Tamper with target account parameters (e.g. user_id, email, username) during final password submission to confirm authorization binding.",
        "cwe": "CWE-640",
        "default_priority": "CRITICAL",
        "relevant_pages": ["Forgot Password / Password Reset"],
        "relevant_features": ["Reset form", "New password input", "Confirm button"],
        "keywords": ["password reset", "account takeover", "reset authorization", "binding"]
    },

    # -------------------------------------------------------------------------
    # 4. ACCOUNT / PROFILE TESTS
    # -------------------------------------------------------------------------
    {
        "id": "profile-idor",
        "name": "Insecure Direct Object References (IDOR) on Profile Update",
        "category": "Authorization",
        "description": "Assess whether user account details or preferences can be modified for another user by manipulating identifiers.",
        "testing_objective": "Intercept profile update POST/PUT request and replace user_id / account_id parameter with target account identifier.",
        "cwe": "CWE-639",
        "default_priority": "CRITICAL",
        "relevant_pages": ["Account / Profile", "Settings / Security Settings"],
        "relevant_features": ["User ID", "Profile form", "Account settings", "Save changes"],
        "keywords": ["idor", "authorization", "user_id", "profile", "account", "another user", "bola"]
    },
    {
        "id": "profile-csrf",
        "name": "Cross-Site Request Forgery (CSRF) on Sensitive Actions",
        "category": "Access Control",
        "description": "Verify anti-CSRF token enforcement and SameSite cookie attributes on state-changing user actions.",
        "testing_objective": "Craft a cross-origin form request modifying email or password without a valid CSRF token to check validation.",
        "cwe": "CWE-352",
        "default_priority": "HIGH",
        "relevant_pages": ["Account / Profile", "Settings / Security Settings", "Checkout / Payment"],
        "relevant_features": ["Email update", "Password change", "Save button", "Toggle switch"],
        "keywords": ["csrf", "samesite", "token", "forgery", "state changing"]
    },
    {
        "id": "profile-stored-xss",
        "name": "Stored Cross-Site Scripting (XSS) in Bio & Profile Fields",
        "category": "Input Validation",
        "description": "Check if user-supplied profile details (name, bio, website) are rendered without contextual output encoding.",
        "testing_objective": "Inject script payloads (e.g., `<script>`, `<img src=x onerror=...>`) into bio and display name fields.",
        "cwe": "CWE-79",
        "default_priority": "HIGH",
        "relevant_pages": ["Account / Profile", "Admin Dashboard / Admin Panel"],
        "relevant_features": ["Bio textarea", "Display name input", "Website URL field"],
        "keywords": ["stored xss", "bio", "display name", "html injection", "polyglot"]
    },
    {
        "id": "profile-pass-verification-bypass",
        "name": "Current Password Verification Bypass on Sensitive Updates",
        "category": "Authentication",
        "description": "Ensure that changing email address or password strictly mandates and verifies current password proof.",
        "testing_objective": "Remove or tamper with the 'current_password' field in the update request to test whether validation is enforced server-side.",
        "cwe": "CWE-287",
        "default_priority": "HIGH",
        "relevant_pages": ["Account / Profile", "Settings / Security Settings"],
        "relevant_features": ["Current password input", "Change password section", "Email change field"],
        "keywords": ["current password", "verification bypass", "unattended session", "re-authenticate", "password", "password change", "change password"]
    },

    # -------------------------------------------------------------------------
    # 5. SETTINGS & SECURITY CONTROLS TESTS
    # -------------------------------------------------------------------------
    {
        "id": "sett-2fa-bypass",
        "name": "Two-Factor Authentication (2FA) Implementation Bypass",
        "category": "Authentication",
        "description": "Assess whether 2FA verification can be bypassed via direct URL navigation, token manipulation, or response tampering.",
        "testing_objective": "Intercept 2FA challenge response and modify response payload (e.g. {'success': true}) or navigate directly to endpoint.",
        "cwe": "CWE-288",
        "default_priority": "CRITICAL",
        "relevant_pages": ["Settings / Security Settings", "Login / Sign-in"],
        "relevant_features": ["2FA toggle", "TOTP code input", "Two-factor settings"],
        "keywords": ["2fa", "mfa", "two-factor", "totp", "otp", "bypass 2fa"]
    },
    {
        "id": "sett-api-token-exposure",
        "name": "Hardcoded API Key & Insecure Personal Access Token Storage",
        "category": "Data Protection",
        "description": "Inspect whether API tokens or webhook secrets are permanently masked after generation.",
        "testing_objective": "Verify that API secrets are only shown once upon creation and not exposed in subsequent GET requests or browser storage.",
        "cwe": "CWE-312",
        "default_priority": "HIGH",
        "relevant_pages": ["Settings / Security Settings", "Admin Dashboard / Admin Panel"],
        "relevant_features": ["API key management", "Token display", "Generate token button"],
        "keywords": ["api key", "token", "secret", "masked", "credential exposure"]
    },
    {
        "id": "sett-session-management",
        "name": "Active Sessions Termination & Remote Logout Enforcement",
        "category": "Session Management",
        "description": "Test whether 'Log out of all devices' correctly invalidates active JWT tokens or database sessions immediately.",
        "testing_objective": "Trigger global logout from session settings and test whether cached tokens in second browser continue to be accepted.",
        "cwe": "CWE-613",
        "default_priority": "MEDIUM",
        "relevant_pages": ["Settings / Security Settings"],
        "relevant_features": ["Active sessions list", "Revoke session button", "Devices table"],
        "keywords": ["active sessions", "terminate sessions", "remote logout", "jwt revocation"]
    },

    # -------------------------------------------------------------------------
    # 6. DASHBOARD & ANALYTICS TESTS
    # -------------------------------------------------------------------------
    {
        "id": "dash-metric-tampering",
        "name": "BOLA / IDOR on Analytical Widget Metrics Endpoints",
        "category": "Authorization",
        "description": "Assess if tenant or user-specific metrics can be fetched by querying other organization IDs.",
        "testing_objective": "Inspect XHR / API calls feeding dashboard charts and attempt replacing tenant_id or org_id with arbitrary identifiers.",
        "cwe": "CWE-639",
        "default_priority": "CRITICAL",
        "relevant_pages": ["Home / Dashboard", "Admin Dashboard / Admin Panel"],
        "relevant_features": ["Metrics cards", "Analytics graph", "KPI summary", "Timeframe selector"],
        "keywords": ["dashboard", "analytics", "metrics", "tenant", "org_id", "charts", "kpi"]
    },
    {
        "id": "dash-sensitive-data-leak",
        "name": "Sensitive Information Disclosure in Activity Logs & Recent Feeds",
        "category": "Information Disclosure",
        "description": "Check whether recent activity widgets disclose sensitive user emails, internal IPs, or transaction details.",
        "testing_objective": "Inspect recent activity JSON responses for over-fetching of unredacted PII or internal system telemetry.",
        "cwe": "CWE-200",
        "default_priority": "MEDIUM",
        "relevant_pages": ["Home / Dashboard", "Admin Dashboard / Admin Panel"],
        "relevant_features": ["Activity feed", "Recent events list", "Notification bell"],
        "keywords": ["activity feed", "recent transactions", "pii", "over-fetching", "disclosure"]
    },
    {
        "id": "dash-filter-injection",
        "name": "SQL / NoSQL Injection in Dashboard Timeframe & Widget Filters",
        "category": "Injection",
        "description": "Test date ranges, status filters, and group-by parameters for database injection flaws.",
        "testing_objective": "Inject SQL syntax into timeframe parameters (e.g., date_from=2026-01-01' OR 1=1--) and observe backend responses.",
        "cwe": "CWE-89",
        "default_priority": "HIGH",
        "relevant_pages": ["Home / Dashboard", "Search / Search Results", "Admin Dashboard / Admin Panel"],
        "relevant_features": ["Date filter dropdown", "Category selector", "Export button"],
        "keywords": ["filter", "date range", "analytics filter", "injection", "query"]
    },

    # -------------------------------------------------------------------------
    # 7. SEARCH & FILTERING TESTS
    # -------------------------------------------------------------------------
    {
        "id": "search-reflected-xss",
        "name": "Reflected Cross-Site Scripting (XSS) in Search Results",
        "category": "Input Validation",
        "description": "Evaluate if user search queries are echoed into the DOM or HTML response without sanitization.",
        "testing_objective": "Submit query payloads (e.g. '><script>alert(1)</script>) and inspect the returned DOM structure for unencoded execution.",
        "cwe": "CWE-79",
        "default_priority": "HIGH",
        "relevant_pages": ["Search / Search Results", "Home / Dashboard"],
        "relevant_features": ["Search input bar", "Search submit button", "Results header ('Results for...')"],
        "keywords": ["search", "query", "results for", "reflected xss", "script injection"]
    },
    {
        "id": "search-sqli",
        "name": "SQL Injection in Search & Faceted Filter Parameters",
        "category": "Injection",
        "description": "Test search text inputs, sorting parameters (ORDER BY), and pagination limits for SQL injection.",
        "testing_objective": "Inject union-based and blind SQL injection payloads into search query, sort order, and page offset parameters.",
        "cwe": "CWE-89",
        "default_priority": "CRITICAL",
        "relevant_pages": ["Search / Search Results"],
        "relevant_features": ["Search input", "Sort dropdown (Price, Name)", "Category facets", "Pagination"],
        "keywords": ["search sqli", "order by", "filter injection", "union select", "pagination"]
    },
    {
        "id": "search-authz-leak",
        "name": "Unauthorized Data Exposure via Search Index Leakage",
        "category": "Authorization",
        "description": "Check if search indexing bypasses object-level access controls and surfaces private or restricted records.",
        "testing_objective": "Execute wildcard search terms as an unprivileged user and check if private files, draft items, or admin records appear.",
        "cwe": "CWE-639",
        "default_priority": "HIGH",
        "relevant_pages": ["Search / Search Results"],
        "relevant_features": ["Search bar", "Filter list", "Item result count"],
        "keywords": ["search authorization", "index leak", "private records", "drafts", "restricted search"]
    },

    # -------------------------------------------------------------------------
    # 8. FILE UPLOAD TESTS
    # -------------------------------------------------------------------------
    {
        "id": "upload-unrestricted-ext",
        "name": "Arbitrary File Upload via Unrestricted Extension Validation",
        "category": "File Handling",
        "description": "Test whether executable scripts (PHP, JSP, ASPX, HTML, SVG) can be uploaded and executed.",
        "testing_objective": "Upload files with executable extensions, double extensions (.php.jpg), or null byte tricks (.php%00.png) to test server handling.",
        "cwe": "CWE-434",
        "default_priority": "CRITICAL",
        "relevant_pages": ["File Upload", "Account / Profile"],
        "relevant_features": ["File dropzone", "Browse file button", "Upload button", "Avatar upload"],
        "keywords": ["upload", "file extension", "executable", "webshell", "attachment", "dropzone"]
    },
    {
        "id": "upload-content-type-spoof",
        "name": "MIME-Type & Magic Byte Validation Spoofing",
        "category": "File Handling",
        "description": "Verify server-side inspection of binary magic bytes rather than trusting client-supplied Content-Type headers.",
        "testing_objective": "Upload a malicious script with an image MIME-Type header (Content-Type: image/png) to test content inspection.",
        "cwe": "CWE-434",
        "default_priority": "HIGH",
        "relevant_pages": ["File Upload", "Account / Profile"],
        "relevant_features": ["Upload area", "Allowed formats label"],
        "keywords": ["mime type", "magic bytes", "content-type", "spoof", "file validation"]
    },
    {
        "id": "upload-path-traversal",
        "name": "Path Traversal & Destination Storage Directory Escapes",
        "category": "File Handling",
        "description": "Assess if filename parameters containing path traversal sequences write files outside designated upload storage.",
        "testing_objective": "Supply filenames containing traversal sequences (e.g., `../../../../var/www/shell.php`) in multipart headers.",
        "cwe": "CWE-22",
        "default_priority": "CRITICAL",
        "relevant_pages": ["File Upload"],
        "relevant_features": ["File dropzone", "Upload queue", "File list"],
        "keywords": ["path traversal", "directory traversal", "filename injection", "arbitrary write"]
    },
    {
        "id": "upload-svg-xss",
        "name": "Stored XSS via Malicious SVG Image Upload",
        "category": "Input Validation",
        "description": "Determine if SVG image uploads containing embedded JavaScript execute upon direct rendering in the browser.",
        "testing_objective": "Upload an SVG file containing an embedded `<script>` or onload attribute; browse directly to image URL.",
        "cwe": "CWE-79",
        "default_priority": "HIGH",
        "relevant_pages": ["File Upload", "Account / Profile"],
        "relevant_features": ["Avatar upload", "Attachment zone", "Image preview"],
        "keywords": ["svg", "stored xss svg", "image xss", "vector image"]
    },

    # -------------------------------------------------------------------------
    # 9. CHECKOUT & PAYMENT TESTS
    # -------------------------------------------------------------------------
    {
        "id": "pay-price-tampering",
        "name": "Price & Currency Manipulation via Parameter Tampering",
        "category": "Business Logic",
        "description": "Assess whether unit prices, total amounts, or currency codes can be manipulated in client-to-server payloads.",
        "testing_objective": "Intercept checkout payment request and modify price parameter (e.g., 'price=0.01' or negative amounts).",
        "cwe": "CWE-472",
        "default_priority": "CRITICAL",
        "relevant_pages": ["Checkout / Payment"],
        "relevant_features": ["Price breakdown", "Order total", "Credit card form", "Pay button"],
        "keywords": ["price manipulation", "checkout", "payment", "amount tampering", "currency", "order total"]
    },
    {
        "id": "pay-quantity-tampering",
        "name": "Negative Quantity & Integer Underflow Logic Flaws",
        "category": "Business Logic",
        "description": "Test order processing logic against negative quantities, zero quantities, or large integer overflows.",
        "testing_objective": "Submit cart / order requests with negative item quantities (e.g. quantity=-1) to test deduction and total recalculation.",
        "cwe": "CWE-840",
        "default_priority": "HIGH",
        "relevant_pages": ["Checkout / Payment"],
        "relevant_features": ["Item quantity", "Order summary", "Cart table"],
        "keywords": ["quantity", "integer overflow", "cart tampering", "negative quantity"]
    },
    {
        "id": "pay-voucher-replay",
        "name": "Promo Voucher Replay & Concurrent Race Conditions",
        "category": "Race Condition",
        "description": "Assess if discount vouchers or promotional codes can be redeemed multiple times concurrently.",
        "testing_objective": "Dispatch multiple simultaneous redemption requests for single-use discount coupon to test transactional locking.",
        "cwe": "CWE-362",
        "default_priority": "HIGH",
        "relevant_pages": ["Checkout / Payment"],
        "relevant_features": ["Discount code input", "Apply coupon button", "Promo banner"],
        "keywords": ["coupon", "voucher", "promo code", "race condition", "discount replay"]
    },
    {
        "id": "pay-order-idor",
        "name": "Order Receipt & Payment Details IDOR",
        "category": "Authorization",
        "description": "Determine if confirmation receipts or invoice PDFs can be accessed by altering the order number.",
        "testing_objective": "Modify order_id in order confirmation URLs or invoice download endpoints to inspect unauthorized customer details.",
        "cwe": "CWE-639",
        "default_priority": "HIGH",
        "relevant_pages": ["Checkout / Payment"],
        "relevant_features": ["Order ID", "Receipt link", "Invoice download"],
        "keywords": ["order receipt", "invoice", "payment idor", "order confirmation"]
    },

    # -------------------------------------------------------------------------
    # 10. ADMIN DASHBOARD & MANAGEMENT TESTS
    # -------------------------------------------------------------------------
    {
        "id": "admin-vertical-priv-esc",
        "name": "Vertical Privilege Escalation on Administrative Functions",
        "category": "Authorization",
        "description": "Assess whether unprivileged users can access administrative endpoints directly via URL or API call.",
        "testing_objective": "Attempt to invoke administrative endpoints (e.g., /api/admin/users/delete) using an ordinary authenticated user token.",
        "cwe": "CWE-269",
        "default_priority": "CRITICAL",
        "relevant_pages": ["Admin Dashboard / Admin Panel"],
        "relevant_features": ["Admin user table", "Role selector", "System toggles", "Bulk actions"],
        "keywords": ["privilege escalation", "admin panel", "role", "rbac", "vertical priv esc", "unauthorized admin"]
    },
    {
        "id": "admin-role-tampering",
        "name": "Parameter Tampering on User Role & Permission Assignment",
        "category": "Access Control",
        "description": "Test if role assignment requests can be intercepted to grant 'Superuser' or 'Admin' privileges.",
        "testing_objective": "Submit profile or user modification request with added 'role': 'admin' or 'is_admin': true attributes.",
        "cwe": "CWE-285",
        "default_priority": "CRITICAL",
        "relevant_pages": ["Admin Dashboard / Admin Panel"],
        "relevant_features": ["Role dropdown", "Permission matrix", "Assign role button"],
        "keywords": ["role tampering", "assign role", "permissions", "admin role", "privilege assignment"]
    },
    {
        "id": "admin-audit-tampering",
        "name": "Audit Trail & Event Log Tampering / Deletion",
        "category": "Audit Logging",
        "description": "Verify whether administrative audit logs are strictly append-only and protected against deletion or suppression.",
        "testing_objective": "Test whether audit records can be cleared or truncated using unauthorized DELETE/PUT HTTP requests.",
        "cwe": "CWE-778",
        "default_priority": "HIGH",
        "relevant_pages": ["Admin Dashboard / Admin Panel"],
        "relevant_features": ["Audit logs tab", "Event viewer", "System maintenance toggles"],
        "keywords": ["audit log", "event log", "log tampering", "audit suppression", "activity records"]
    },

    # -------------------------------------------------------------------------
    # 11. GENERAL / AMBIGUOUS FALLBACK TESTS
    # -------------------------------------------------------------------------
    {
        "id": "gen-info-disclosure",
        "name": "General Information Disclosure & Server Header Leakage",
        "category": "Information Disclosure",
        "description": "Inspect HTTP response headers, debug comments, and source code for exposed backend versions or secrets.",
        "testing_objective": "Inspect server response headers (Server, X-Powered-By) and HTML source code for leaked internal architecture details.",
        "cwe": "CWE-200",
        "default_priority": "LOW",
        "relevant_pages": ["Unknown / Ambiguous"],
        "relevant_features": ["Page layout"],
        "keywords": ["info disclosure", "server header", "debug", "metadata", "unknown", "ambiguous"]
    },
    {
        "id": "gen-transport-security",
        "name": "Insecure Transport Security & Missing Security Headers",
        "category": "Transport Security",
        "description": "Verify the presence and configuration of HTTPS, HSTS, Content-Security-Policy, and X-Content-Type-Options.",
        "testing_objective": "Inspect HTTP response headers to confirm Strict-Transport-Security and CSP headers are properly enforced.",
        "cwe": "CWE-319",
        "default_priority": "LOW",
        "relevant_pages": ["Unknown / Ambiguous"],
        "relevant_features": ["Page layout"],
        "keywords": ["hsts", "https", "transport security", "headers", "csp", "unknown", "ambiguous"]
    }
]

# Supported Canonical Page Categories Mapping
CANONICAL_PAGE_CATEGORIES = {
    "login": "Login / Sign-in Page",
    "registration": "Sign-up / Registration Page",
    "forgot_password": "Forgot Password / Password Reset Page",
    "profile": "Account / Profile Page",
    "settings": "Settings / Security Settings Page",
    "dashboard": "Home / Dashboard Page",
    "search": "Search / Search Results Page",
    "file_upload": "File Upload Page",
    "checkout": "Checkout / Payment Page",
    "admin_panel": "Admin Dashboard / Admin Panel",
    "ambiguous": "Unknown / Ambiguous"
}

def normalize_page_type(page_type: Optional[str]) -> str:
    """Normalizes various user or AI inputs into canonical category names."""
    if not page_type or page_type.lower() in ["auto detect", "auto", "detect", ""]:
        return "Auto Detect"

    pt = page_type.strip()
    pt_lower = pt.lower()

    # 1. Exact canonical matches
    for slug, canonical in CANONICAL_PAGE_CATEGORIES.items():
        if pt_lower == canonical.lower() or pt_lower == slug:
            return canonical

    # 2. Check admin explicitly first so "admin dashboard" never becomes "home / dashboard"
    if "admin" in pt_lower:
        return CANONICAL_PAGE_CATEGORIES["admin_panel"]

    # 3. Check specific keywords in priority order
    if "forgot" in pt_lower or "reset" in pt_lower or "recovery" in pt_lower:
        return CANONICAL_PAGE_CATEGORIES["forgot_password"]
    if "sign-up" in pt_lower or "signup" in pt_lower or "register" in pt_lower or "registration" in pt_lower:
        return CANONICAL_PAGE_CATEGORIES["registration"]
    if "login" in pt_lower or "sign-in" in pt_lower or "signin" in pt_lower:
        return CANONICAL_PAGE_CATEGORIES["login"]
    if "profile" in pt_lower or "account" in pt_lower:
        return CANONICAL_PAGE_CATEGORIES["profile"]
    if "setting" in pt_lower or "security setting" in pt_lower:
        return CANONICAL_PAGE_CATEGORIES["settings"]
    if "upload" in pt_lower or "file" in pt_lower:
        return CANONICAL_PAGE_CATEGORIES["file_upload"]
    if "checkout" in pt_lower or "payment" in pt_lower or "cart" in pt_lower:
        return CANONICAL_PAGE_CATEGORIES["checkout"]
    if "search" in pt_lower:
        return CANONICAL_PAGE_CATEGORIES["search"]
    if "dashboard" in pt_lower or "home" in pt_lower:
        return CANONICAL_PAGE_CATEGORIES["dashboard"]
    if "ambiguous" in pt_lower or "unknown" in pt_lower:
        return CANONICAL_PAGE_CATEGORIES["ambiguous"]

    return pt

def get_candidate_tests_for_page(page_type: str) -> List[Dict[str, Any]]:
    """Retrieves tests from the knowledge base that are designated for this page type."""
    canonical = normalize_page_type(page_type)
    candidates = []
    for test in SECURITY_KNOWLEDGE_BASE:
        for rp in test["relevant_pages"]:
            rp_norm = normalize_page_type(rp)
            if rp_norm == canonical or rp.lower() in page_type.lower() or page_type.lower() in rp.lower():
                if canonical == CANONICAL_PAGE_CATEGORIES["dashboard"] and "Admin" in rp and "Home" not in rp:
                    continue
                if canonical == CANONICAL_PAGE_CATEGORIES["admin_panel"] and "Home" in rp and "Admin" not in rp:
                    continue
                candidates.append(test)
                break
    return candidates

def calculate_test_relevance(
    test: Dict[str, Any],
    page_type: str,
    detected_elements: List[str],
    user_context: str
) -> Tuple[int, str]:
    """
    Computes a relevance score (0 to 5) for a candidate test.
    Returns (score, evidence_reason)

    Score tiers:
    0 = Not relevant
    1 = Very weak
    2 = Low
    3 = Moderately relevant
    4 = Highly relevant
    5 = Strongly relevant (directly triggered by visible feature or user focus)
    """
    score = 0
    reasons = []

    ctx_lower = (user_context or "").lower()
    elements_text = " ".join(detected_elements).lower()

    # 1. Base page category relevance
    is_page_match = any(rp.lower() in page_type.lower() or page_type.lower() in rp.lower() for rp in test["relevant_pages"])
    if is_page_match:
        score += 3
        reasons.append(f"Standard risk area for {page_type}")

    # 2. Check if user context explicitly asked to focus on this test/category
    context_hit = any(re.search(r'\b' + re.escape(kw) + r'\b', ctx_lower) for kw in test["keywords"])
    if context_hit:
        score += 2
        reasons.append("User requested focus on this security control")

    # 3. Check if visible UI elements match test requirements
    feature_hit = any(rf.lower() in elements_text for rf in test["relevant_features"])
    if feature_hit:
        score += 1
        matched_feature = next((rf for rf in test["relevant_features"] if rf.lower() in elements_text), "UI elements")
        reasons.append(f"Directly relevant to visible '{matched_feature}'")

    # Strict Negative Filtering:
    # If the test is File Upload, but the page is Profile and neither avatar upload nor file keywords exist, reduce score
    if test["category"] == "File Handling" and "File Upload" not in page_type:
        if "avatar" not in elements_text and "upload" not in elements_text and "upload" not in ctx_lower:
            score = 0

    # If the test is Payment, but the page is not Checkout, ensure payment elements or keywords exist
    if test["category"] in ["Business Logic", "Race Condition"] and "Checkout" not in page_type:
        if "price" not in elements_text and "payment" not in ctx_lower and "cart" not in elements_text:
            score = 0

    score = min(5, max(0, score))
    reason_str = "; ".join(reasons) if reasons else f"Recommended assessment procedure for {test['category']} controls."
    return score, reason_str

def build_curated_checklist(
    page_type: str,
    detected_elements: Optional[List[str]] = None,
    user_context: str = "",
    min_relevance: int = 3
) -> List[Dict[str, Any]]:
    """
    Constructs a controlled, evidence-based VAPT checklist.
    Filters candidate tests by relevance score >= min_relevance.
    Orders results strictly CRITICAL -> HIGH -> MEDIUM -> LOW, with relevant/context-requested tests prioritized.
    """
    PRIORITY_WEIGHTS = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    if detected_elements is None:
        detected_elements = []

    canonical_page = normalize_page_type(page_type)
    candidates = get_candidate_tests_for_page(canonical_page)
    if not candidates and canonical_page != page_type:
        candidates = get_candidate_tests_for_page(page_type)

    # If candidates empty (e.g. Unknown / Ambiguous or unrecognized category), grab general items
    if not candidates:
        candidates = [t for t in SECURITY_KNOWLEDGE_BASE if "Unknown / Ambiguous" in t["relevant_pages"]]

    filtered_checklist = []
    for test in candidates:
        rel_score, evidence_reason = calculate_test_relevance(test, canonical_page, detected_elements, user_context)
        if rel_score >= min_relevance or (canonical_page == "Unknown / Ambiguous" and rel_score >= 1):
            priority = test["default_priority"]
            if "User requested focus on this security control" in evidence_reason:
                # Promote priority when user explicitly focused on this control in Additional Context
                priority = "CRITICAL"

            item = {
                "id": test["id"],
                "name": test["name"],
                "priority": priority,
                "reason": evidence_reason,
                "testing_objective": test["testing_objective"],
                "cwe": test["cwe"],
                "source": "AI",
                "status": "NOT_TESTED",
                "finding": None
            }
            filtered_checklist.append((PRIORITY_WEIGHTS.get(item["priority"], 99), -rel_score, item))

    # Sort by priority then relevance
    filtered_checklist.sort(key=lambda x: (x[0], x[1]))
    return [entry[2] for entry in filtered_checklist]

# =============================================================================
# STRUCTURED FINDING TEMPLATES & ENRICHMENT ENGINE
# =============================================================================

FINDING_TEMPLATES_BY_CWE: Dict[str, Dict[str, Any]] = {
    "CWE-89": {
        "finding_name": "SQL Injection in Data Query Parameter",
        "cwe": "CWE-89",
        "cvss_score": 8.8,
        "priority": "CRITICAL",
        "description": "The application fails to properly parameterize user-supplied input before incorporating it into backend database query routines.",
        "impact": "An unauthorized attacker can read sensitive records from the database, bypass authentication, extract user credentials or customer data, and potentially execute administrative database operations.",
        "reproduction_steps": "1. Navigate to the functional input interface.\n2. Submit parameter test input with boolean or quote boundary syntax.\n3. Observe unexpected database error syntax or altered response records indicating query concatenation.\n4. Confirm differential database responses.",
        "poc_text": "GET /api/v1/search?q=%27%20UNION%20SELECT%20id%2Cusername%2Cpassword_hash%20FROM%20users-- HTTP/1.1\nHost: target.app\nAccept: application/json\n\n--> HTTP/1.1 200 OK\n{\"results\": [{\"id\": 1, \"username\": \"admin\", \"data\": \"hash_dump\"}]}",
        "remediation": "Use parameterized queries (prepared statements) or an Object-Relational Mapper (ORM) with parameterized placeholders for all SQL queries. Never concatenate untrusted user input directly into SQL strings. Implement input validation using strict allowlists.",
        "mitigation": "Enforce least-privilege database user account permissions (web application account should not possess DROP, ALTER, or superuser permissions). Deploy Web Application Firewall (WAF) inspection rules.",
        "status": "Open"
    },
    "CWE-79": {
        "finding_name": "Cross-Site Scripting (XSS) Vulnerability",
        "cwe": "CWE-79",
        "cvss_score": 7.5,
        "priority": "HIGH",
        "description": "User-supplied input is accepted and rendered directly in the web browser Document Object Model (DOM) without adequate contextual output encoding or HTML sanitization.",
        "impact": "An attacker can execute arbitrary script in the victim browser session, hijack authenticated session tokens, perform unauthorized actions, or conduct page defacement.",
        "reproduction_steps": "1. Submit test payload `<script>console.log('XSS_POC')</script>` or `<img src=x onerror=console.log(1)>` in input.\n2. Trigger rendering of the input value in a target view.\n3. Confirm script executes in the client session context.",
        "poc_text": "POST /api/v1/content HTTP/1.1\nHost: target.app\nContent-Type: application/json\n\n{\"field\": \"<img src=x onerror=console.log(document.domain)>\"}\n\n--> HTTP/1.1 200 OK (Rendered unescaped in DOM)",
        "remediation": "Apply context-aware contextual output encoding (HTML body, attribute, JavaScript variable) before rendering user data. If rich text is required, sanitize markup using DOMPurify with an explicit safe-tag whitelist.",
        "mitigation": "Implement a strict Content Security Policy (CSP) header (e.g. Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-...'). Mark session cookies with HttpOnly and SameSite flags.",
        "status": "Open"
    },
    "CWE-639": {
        "finding_name": "Insecure Direct Object Reference (IDOR)",
        "cwe": "CWE-639",
        "cvss_score": 8.5,
        "priority": "HIGH",
        "description": "The application references sensitive objects (user accounts, orders, records) directly by client-supplied identifiers without enforcing server-side authorization checks comparing user identity to resource ownership.",
        "impact": "Authenticated users can view, modify, or delete sensitive records belonging to other users or organizations across the platform.",
        "reproduction_steps": "1. Log in as test user A with ID 101.\n2. Observe API request targeting `/api/records/101`.\n3. Alter ID parameter to 102 (belonging to test user B) and replay request.\n4. Observe that the server returns user B's confidential record with HTTP 200 OK.",
        "poc_text": "GET /api/v1/records/102 HTTP/1.1\nHost: target.app\nAuthorization: Bearer <user_a_token>\n\n--> HTTP/1.1 200 OK\n{\"record_id\": 102, \"owner\": \"user_b\", \"sensitive_data\": \"Confidential Info\"}",
        "remediation": "Enforce server-side authorization checks on every object reference. Validate that the authenticated session identity possesses ownership or authorized access to the requested entity before returning data.",
        "mitigation": "Use indirect reference maps or unguessable cryptographically secure UUIDv4 identifiers rather than sequential integer IDs; enforce centralized authorization middleware (ABAC/RBAC).",
        "status": "Open"
    },
    "CWE-352": {
        "finding_name": "Cross-Site Request Forgery (CSRF) on State-Changing Action",
        "cwe": "CWE-352",
        "cvss_score": 7.5,
        "priority": "HIGH",
        "description": "State-changing operations (such as updating profile information, email, or configuration) do not validate anti-CSRF tokens and rely on ambient browser cookies lacking strict SameSite attributes.",
        "impact": "An attacker can induce an authenticated victim into executing unwanted actions (such as changing email address or password) via third-party malicious sites.",
        "reproduction_steps": "1. Log in as an authenticated user.\n2. Construct an external web page containing an auto-submitting form targeting the sensitive action.\n3. Open the external page in the victim browser.\n4. Confirm that the state-changing action executes successfully using ambient cookies.",
        "poc_text": "<form action=\"https://target.app/api/user/settings\" method=\"POST\">\n  <input type=\"hidden\" name=\"email\" value=\"attacker@evil.com\" />\n</form>\n<script>document.forms[0].submit();</script>",
        "remediation": "Implement unpredictable, cryptographically generated anti-CSRF synchronization tokens for all state-changing endpoints (POST, PUT, DELETE). Set SameSite=Lax or SameSite=Strict on all session cookies.",
        "mitigation": "Require re-authentication (current password confirmation) before executing high-impact account modifications.",
        "status": "Open"
    },
    "CWE-434": {
        "finding_name": "Unrestricted File Upload Vulnerability",
        "cwe": "CWE-434",
        "cvss_score": 9.8,
        "priority": "CRITICAL",
        "description": "The file upload handler does not properly restrict uploaded file extensions, does not validate file magic bytes server-side, and stores uploaded files within an executable or web-accessible directory.",
        "impact": "Attackers can upload server-executable scripts or malicious HTML files, resulting in Remote Code Execution (RCE), host compromise, or persistent defacement.",
        "reproduction_steps": "1. Navigate to the file upload dropzone.\n2. Upload a test file with an executable extension or dual extension.\n3. Observe that the server accepts the upload with HTTP 201 Created and provides an accessible path.\n4. Request the uploaded file directly to assess execution behavior.",
        "poc_text": "POST /api/v1/upload HTTP/1.1\nHost: target.app\nContent-Type: multipart/form-data; boundary=----BoundaryX\n\n------BoundaryX\nContent-Disposition: form-data; name=\"file\"; filename=\"test_exec.jsp\"\n\n<executed_server_script>\n------BoundaryX--\n\n--> HTTP/1.1 201 Created\n{\"url\": \"/uploads/test_exec.jsp\"}",
        "remediation": "Enforce a strict whitelist of permitted file extensions (e.g. .png, .jpg, .pdf). Verify file contents using server-side magic byte inspection. Store files outside the web root or in an isolated private cloud storage bucket (AWS S3) with generated random filenames.",
        "mitigation": "Configure the web server to disable script execution in the upload directory; serve user-uploaded files with Content-Disposition: attachment and X-Content-Type-Options: nosniff headers.",
        "status": "Open"
    },
    "CWE-307": {
        "finding_name": "Missing Rate Limiting & Automated Attack Susceptibility",
        "cwe": "CWE-307",
        "cvss_score": 7.5,
        "priority": "HIGH",
        "description": "The target endpoint does not enforce rate limiting or throttling on repetitive requests, allowing automated credential stuffing, brute-force testing, or resource exhaustion.",
        "impact": "Unauthorized credential compromise through automated password guessing, resource exhaustion, or SMS/email flooding.",
        "reproduction_steps": "1. Intercept a target request (e.g. login, OTP verification, or reset request).\n2. Send 100 consecutive requests in rapid succession using an automated script.\n3. Observe that all requests receive responses without HTTP 429 throttling or progressive delays.",
        "poc_text": "Repeated burst requests: 100/100 requests processed with HTTP 200/401.\nNo HTTP 429 Too Many Requests returned; no exponential backoff or captcha triggered.",
        "remediation": "Implement rate limiting using a token-bucket or sliding-window counter (e.g. max 5 failed attempts per 15 minutes per IP and username). Return HTTP 429 Too Many Requests with a Retry-After header once limits are exceeded.",
        "mitigation": "Enforce multi-factor authentication (MFA); implement edge-layer bot mitigation and CAPTCHA challenges after repeated failures.",
        "status": "Open"
    },
    "CWE-287": {
        "finding_name": "Improper Authentication & Verification Bypass",
        "cwe": "CWE-287",
        "cvss_score": 8.5,
        "priority": "HIGH",
        "description": "Authentication mechanisms fail to securely verify user identity, allowing authentication bypass, session hijacking, or unauthorized access to protected application functions.",
        "impact": "Account takeover, unauthorized access to user data, and failure of authentication boundaries.",
        "reproduction_steps": "1. Attempt accessing protected endpoints with missing, manipulated, or expired authentication tokens.\n2. Observe that the server fails to reject the request and grants access.\n3. Confirm authentication boundary failure.",
        "poc_text": "GET /api/v1/protected HTTP/1.1\nHost: target.app\nAuthorization: Bearer <tampered_token>\n\n--> HTTP/1.1 200 OK (Access granted without valid token verification)",
        "remediation": "Ensure all protected endpoints rigorously validate authentication tokens, verify cryptographic signatures using strong keys, and check token revocation status before fulfilling requests.",
        "mitigation": "Use standardized authentication frameworks (OAuth 2.0 / OIDC) rather than custom verification logic; enforce short-lived access tokens with secure refresh token rotation.",
        "status": "Open"
    },
    "CWE-330": {
        "finding_name": "Use of Insufficiently Random Values in Security Tokens",
        "cwe": "CWE-330",
        "cvss_score": 8.8,
        "priority": "CRITICAL",
        "description": "Security-sensitive tokens (such as password reset tokens, verification PINs, or session identifiers) are generated using predictable algorithms or insufficient entropy, enabling token prediction.",
        "impact": "Attackers can predict or brute-force valid tokens, enabling account takeover and unauthorized session assumption.",
        "reproduction_steps": "1. Request multiple consecutive reset tokens for test accounts.\n2. Analyze token randomness, length, and sequencing.\n3. Confirm predictability or low entropy allowing brute-force prediction.",
        "poc_text": "Consecutive tokens generated:\nToken 1: 1042-8821\nToken 2: 1042-8822\nToken 3: 1042-8823 (Predictable sequential progression observed)",
        "remediation": "Generate all security tokens using a cryptographically secure pseudo-random number generator (CSPRNG) with at least 128 bits of entropy. Enforce single-use invalidation upon consumption.",
        "mitigation": "Apply strict rate limiting and short expiration windows (max 15 minutes) on token redemption.",
        "status": "Open"
    },
    "CWE-472": {
        "finding_name": "Client-Side Parameter Tampering & Price Manipulation",
        "cwe": "CWE-472",
        "cvss_score": 8.8,
        "priority": "CRITICAL",
        "description": "The application trusts client-submitted financial, quantity, or price parameters without authoritative server-side recalculation.",
        "impact": "Attackers can purchase goods or services for arbitrary or zero amounts, resulting in direct financial loss.",
        "reproduction_steps": "1. Add item to cart and proceed to payment submission.\n2. Intercept payment request and alter price parameter.\n3. Forward request and verify that server confirms transaction at tampered price.",
        "poc_text": "POST /api/v1/charge HTTP/1.1\nContent-Type: application/json\n\n{\"item_id\": 42, \"price\": 1.00, \"quantity\": 1}\n\n--> HTTP/1.1 200 OK (Charged at $1.00 instead of catalog price)",
        "remediation": "Always calculate prices, totals, and discounts server-side by looking up item records directly from the database catalog before processing transactions.",
        "mitigation": "Log all pricing discrepancies and implement fraud alerts for anomalous transaction amounts.",
        "status": "Open"
    },
    "CWE-269": {
        "finding_name": "Vertical Privilege Escalation via Unchecked Privileged Endpoints",
        "cwe": "CWE-269",
        "cvss_score": 9.1,
        "priority": "CRITICAL",
        "description": "Administrative routes and management APIs fail to enforce role-based access control (RBAC), allowing standard authenticated users to execute administrative functions.",
        "impact": "Complete takeover of administrative functions, user role alteration, and unauthorized access to organizational data.",
        "reproduction_steps": "1. Log in as a standard non-administrative user.\n2. Send a request directly to the administrative endpoint.\n3. Verify that the action executes with HTTP 200 OK without role restriction.",
        "poc_text": "POST /api/admin/users/promote HTTP/1.1\nAuthorization: Bearer <standard_user_token>\nContent-Type: application/json\n\n{\"user_id\": 1042, \"role\": \"admin\"}\n\n--> HTTP/1.1 200 OK",
        "remediation": "Enforce role-based authorization checks at the API gateway or controller layer for every administrative endpoint. Verify user permissions before executing privileged actions.",
        "mitigation": "Adopt centralized authorization policies (ABAC/RBAC) and maintain immutable audit logs for all administrative operations.",
        "status": "Open"
    }
}

def get_finding_template_for_test(test_id: str, test_name: Optional[str] = None, cwe: Optional[str] = None) -> Dict[str, Any]:
    """
    Returns a structured finding template with technical observation, impact,
    reproduction steps, monospaced PoC, tailored remediation, and defensive mitigation.
    """
    clean_name = test_name or test_id.replace("-", " ").title()
    resolved_cwe = cwe

    # Look up test in knowledge base to grab default metadata if available
    matched_test = None
    for t in SECURITY_KNOWLEDGE_BASE:
        if t["id"] == test_id or (test_name and t["name"].lower() == test_name.lower()):
            matched_test = t
            break

    if matched_test:
        clean_name = matched_test["name"]
        resolved_cwe = resolved_cwe or matched_test.get("cwe")
        priority = matched_test.get("default_priority", "HIGH")
    else:
        priority = "HIGH"

    # Check if we have a tailored CWE template
    if resolved_cwe and resolved_cwe in FINDING_TEMPLATES_BY_CWE:
        tmpl = dict(FINDING_TEMPLATES_BY_CWE[resolved_cwe])
        tmpl["finding_name"] = f"{clean_name} Vulnerability"
        return tmpl

    # Default structured fallback
    return {
        "finding_name": f"{clean_name} Vulnerability",
        "cwe": resolved_cwe or "CWE-200",
        "cvss_score": 7.5,
        "priority": priority,
        "description": f"During security evaluation of the {clean_name} control, improper verification or anomalous response behavior was observed on the target interface.",
        "impact": "An unauthorized attacker can leverage this condition to circumvent intended security controls, access unauthorized functionality, or disclose confidential metadata.",
        "reproduction_steps": f"1. Identify the target interface responsible for {clean_name}.\n2. Intercept the corresponding HTTP request using a security proxy.\n3. Submit crafted boundary test values or parameter manipulations.\n4. Observe unexpected status codes or response bodies indicating control failure.",
        "poc_text": "GET /api/v1/resource HTTP/1.1\nHost: target.app\nAuthorization: Bearer <session_token>\n\n--> HTTP/1.1 200 OK (Unvalidated control response returned)",
        "remediation": f"Implement strict server-side validation, authentication, and authorization verification for {clean_name}. Ensure that all inputs are validated against strict allowlists and access controls are strictly enforced on the server.",
        "mitigation": "Enforce defense-in-depth controls including centralized security middleware, comprehensive audit logging, and automated security regression testing.",
        "status": "Open"
    }
