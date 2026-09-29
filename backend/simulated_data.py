from backend.schemas import VaptAnalysisResponse, ChecklistItem, PriorityEnum

def get_simulated_response(scenario: str) -> VaptAnalysisResponse:
    if scenario == "ambiguous":
        return VaptAnalysisResponse(
            page_type="Unknown / Ambiguous",
            confidence=0.32,
            detected_elements=["Unidentified graphical layout", "Non-standard UI components"],
            detected_functionalities=["Unspecified Interface"],
            ambiguity_notes="The provided image does not clearly correspond to any of the 10 supported web application categories (e.g. login, registration, checkout, dashboard, settings). Please provide a screenshot containing visible web forms, input fields, navigation controls, or identifiable application workflows.",
            checklist=[
                ChecklistItem(
                    id="info-disc-ambiguous",
                    name="General Information Disclosure",
                    priority=PriorityEnum.LOW,
                    reason="Due to ambiguous page content, verify that sensitive metadata or debug comments are not leaked.",
                    testing_objective="Inspect page source code and headers for exposed server versions, tokens, or internal paths.",
                    cwe="CWE-200",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="transport-sec-ambiguous",
                    name="Insecure Transport Security (HTTPS/HSTS)",
                    priority=PriorityEnum.LOW,
                    reason="Verify basic web communications encryption regardless of interface type.",
                    testing_objective="Confirm the interface enforces HTTPS and secure transport header attributes.",
                    cwe="CWE-319",
                    source="AI",
                    status="NOT_TESTED"
                )
            ]
        )

    elif scenario == "admin_panel":
        return VaptAnalysisResponse(
            page_type="Admin Dashboard / Admin Panel",
            confidence=0.96,
            detected_elements=[
                "Administrative user table with action buttons",
                "Role / Privilege assignment dropdowns (Admin, Superuser, Viewer)",
                "System configuration and maintenance toggles",
                "Audit logs / event viewer tab",
                "Bulk action bar (Delete Users, Export All Records)"
            ],
            detected_functionalities=[
                "User Role & Access Administration",
                "System Configuration & Maintenance",
                "Audit Log Inspection",
                "Bulk Data Operations"
            ],
            checklist=[
                ChecklistItem(
                    id="admin-broken-authz",
                    name="Broken Vertical Access Control (Privilege Escalation)",
                    priority=PriorityEnum.CRITICAL,
                    reason="Administrative panel endpoints must strictly enforce role-based access control (RBAC) on the backend for all API routes.",
                    testing_objective="Access administrative endpoints and functions using standard non-privileged user session tokens.",
                    cwe="CWE-285",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="admin-bulk-idor",
                    name="IDOR in Bulk User Management Actions",
                    priority=PriorityEnum.HIGH,
                    reason="Modifying, suspending, or deleting accounts via admin interfaces often transmits target user identifiers in payload arrays.",
                    testing_objective="Tamper with user IDs in bulk delete/modify requests to alter accounts beyond authorized jurisdiction.",
                    cwe="CWE-639",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="admin-audit-tamper",
                    name="Audit Log Tampering & Log Injection",
                    priority=PriorityEnum.HIGH,
                    reason="Admins and attacker accounts may attempt to forge log events or inject malicious scripts into audit viewers.",
                    testing_objective="Inject CRLF sequences and HTML/script payloads into logged action descriptions.",
                    cwe="CWE-117",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="admin-csrf-config",
                    name="CSRF on Sensitive Configuration Toggles",
                    priority=PriorityEnum.MEDIUM,
                    reason="Critical admin state modifications (e.g. enabling debug mode, toggling registrations) must require anti-CSRF protection.",
                    testing_objective="Verify whether administrative configuration endpoints validate anti-CSRF tokens or allow state changes via forged cross-site requests.",
                    cwe="CWE-352",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="admin-sensitive-info",
                    name="Excessive Sensitive Information Disclosure",
                    priority=PriorityEnum.MEDIUM,
                    reason="Admin debug panels and user tables often expose unmasked PII, API tokens, or server system paths.",
                    testing_objective="Inspect API responses for unmasked credentials, database connection strings, and plaintext tokens in user objects.",
                    cwe="CWE-200",
                    source="AI",
                    status="NOT_TESTED"
                )
            ]
        )

    elif scenario == "checkout":
        return VaptAnalysisResponse(
            page_type="Checkout / Payment Page",
            confidence=0.97,
            detected_elements=[
                "Order items summary and pricing breakdown",
                "Coupon / Promo code input and apply button",
                "Shipping & Billing address form fields",
                "Payment method selector (Credit Card, PayPal, Crypto)",
                "Cardholder Name, Card Number, Expiration, and CVV fields",
                "'Place Order' / 'Complete Payment' submission button"
            ],
            detected_functionalities=[
                "Order Processing & Price Calculation",
                "Promotional Discount Application",
                "Payment Gateway Transaction Processing",
                "Customer Billing Information Handling"
            ],
            checklist=[
                ChecklistItem(
                    id="checkout-price-tampering",
                    name="Price & Quantity Parameter Tampering (Business Logic Flaw)",
                    priority=PriorityEnum.CRITICAL,
                    reason="Checkout endpoints often calculate or transmit order totals, unit prices, or currencies via client-side parameters.",
                    testing_objective="Intercept checkout POST requests and modify price parameters, currency codes, or pass negative quantity values.",
                    cwe="CWE-472",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="checkout-coupon-race",
                    name="Race Condition on Coupon & Discount Codes",
                    priority=PriorityEnum.HIGH,
                    reason="Discounts and one-time vouchers are vulnerable to concurrent request collisions before state locking occurs.",
                    testing_objective="Send simultaneous parallel requests applying the same single-use discount coupon to verify transaction locking.",
                    cwe="CWE-362",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="checkout-gateway-callback",
                    name="Payment Gateway Callback Manipulation / Signature Bypass",
                    priority=PriorityEnum.HIGH,
                    reason="Third-party payment gateways redirect back to callback URLs; forged responses can mark orders as paid.",
                    testing_objective="Test whether callback webhooks verify HMAC signatures and whether order status can be updated without valid payment confirmation.",
                    cwe="CWE-347",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="checkout-pan-exposure",
                    name="Insecure Cardholder Data Storage & Transmission (PCI-DSS)",
                    priority=PriorityEnum.MEDIUM,
                    reason="Credit card numbers and CVV codes must not be logged or transmitted in unencrypted form or stored in server application logs.",
                    testing_objective="Check browser local storage, server logs, and API network payloads for unmasked Primary Account Numbers (PAN) and CVVs.",
                    cwe="CWE-312",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="checkout-address-xss",
                    name="Stored XSS in Shipping / Billing Address Fields",
                    priority=PriorityEnum.LOW,
                    reason="Address fields are rendered in administrative shipping consoles and invoice generators.",
                    testing_objective="Submit HTML encoding and script payloads in Address Line 1, City, and Delivery Instructions.",
                    cwe="CWE-79",
                    source="AI",
                    status="NOT_TESTED"
                )
            ]
        )

    elif scenario == "search":
        return VaptAnalysisResponse(
            page_type="Search / Search Results Page",
            confidence=0.95,
            detected_elements=[
                "Global search input bar with autocomplete dropdown",
                "Filter facets (Categories, Price range, Date, Rating)",
                "Sorting parameter selector (Relevance, Price, Newest)",
                "Pagination navigation controls (Pages 1, 2, 3... Next)",
                "Search results counter ('Found 142 results for ...')"
            ],
            detected_functionalities=[
                "User Search Query Processing",
                "Faceted Filtering & Sorting",
                "Pagination State Handling"
            ],
            checklist=[
                ChecklistItem(
                    id="search-reflected-xss",
                    name="Reflected Cross-Site Scripting (XSS) in Search Query",
                    priority=PriorityEnum.HIGH,
                    reason="Search terms are almost universally reflected back to the user in headings like 'Results for: <query>'.",
                    testing_objective="Inject polyglot script payloads and HTML tags into the 'q' or 'search' parameter to test contextual output encoding.",
                    cwe="CWE-79",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="search-sqli-filters",
                    name="SQL / NoSQL / Elasticsearch Injection in Facet Filters",
                    priority=PriorityEnum.HIGH,
                    reason="Filter parameters (category, sort, range) are frequently concatenated directly into database or search engine queries.",
                    testing_objective="Supply SQL injection syntax, NoSQL operator payloads (e.g. $ne, $regex), or Lucene syntax into filter parameters.",
                    cwe="CWE-89",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="search-pagination-dos",
                    name="Denial of Service via Unbounded Pagination Limits",
                    priority=PriorityEnum.MEDIUM,
                    reason="Manipulating 'limit' or 'page_size' parameters to extreme values can cause memory exhaustion on database queries.",
                    testing_objective="Supply excessively large integers or negative values in the 'limit' parameter (e.g. limit=1000000) to assess resource consumption.",
                    cwe="CWE-400",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="search-autocomplete-ssrf",
                    name="Server-Side Request Forgery (SSRF) via Autocomplete Webhook",
                    priority=PriorityEnum.MEDIUM,
                    reason="Autocomplete widgets sometimes query external indexing APIs or microservices using user-supplied query strings.",
                    testing_objective="Assess whether search suggestion requests can be tricked into resolving loopback (127.0.0.1) or cloud metadata (169.254.169.254) addresses.",
                    cwe="CWE-918",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="search-wildcard-exposure",
                    name="Unauthorized Information Disclosure via Wildcard Queries",
                    priority=PriorityEnum.LOW,
                    reason="Search mechanisms may reveal unlisted, hidden, or other users' confidential items when querying wildcards ('%').",
                    testing_objective="Submit wildcard characters (*, %) and verify if restricted items or drafted records are returned in results.",
                    cwe="CWE-200",
                    source="AI",
                    status="NOT_TESTED"
                )
            ]
        )

    elif scenario == "dashboard":
        return VaptAnalysisResponse(
            page_type="Home / Dashboard Page",
            confidence=0.94,
            detected_elements=[
                "Top navigation bar with search bar and user profile dropdown",
                "Metric cards (Active Users, Monthly Revenue, Storage Used)",
                "Recent Activities data table",
                "Quick Actions toolbar (Upload File, Add Member, Generate Report)",
                "Embedded interactive charts & graph widgets"
            ],
            detected_functionalities=[
                "Data Aggregation & Metrics Reporting",
                "Quick Action Shortcuts (File Upload, User Creation)",
                "Search & Filter across Activity Feeds"
            ],
            checklist=[
                ChecklistItem(
                    id="dash-idor-metrics",
                    name="Insecure Direct Object References (IDOR) in Dashboard Widgets",
                    priority=PriorityEnum.CRITICAL,
                    reason="Widgets load summary statistics via background API calls using tenant IDs, org IDs, or account parameters.",
                    testing_objective="Tamper with organization and user identifiers in widget data endpoints to view other accounts' confidential analytics.",
                    cwe="CWE-639",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="dash-ssrf-widgets",
                    name="Server-Side Request Forgery (SSRF) via Custom Dashboard Feeds",
                    priority=PriorityEnum.HIGH,
                    reason="Dashboards allowing custom RSS feeds, webhook status URLs, or remote charts can be induced to query internal network services.",
                    testing_objective="Configure dashboard feed endpoints with internal IP addresses (e.g., 127.0.0.1, 169.254.169.254) to assess SSRF controls.",
                    cwe="CWE-918",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="dash-stored-xss-activity",
                    name="Stored XSS in Recent Activity Feed / Event Logs",
                    priority=PriorityEnum.HIGH,
                    reason="Activity tables render logs generated across the application, such as filenames, user agents, or transaction memos.",
                    testing_objective="Perform actions with script-injected names or descriptions and verify if the dashboard renders them without HTML encoding.",
                    cwe="CWE-79",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="dash-broken-authz-actions",
                    name="Broken Function-Level Authorization on Quick Actions",
                    priority=PriorityEnum.MEDIUM,
                    reason="Quick action buttons (e.g. Generate Report, Add Member) may bypass frontend permission checks.",
                    testing_objective="Execute quick action API requests under a low-privilege read-only role to test server-side authorization enforcement.",
                    cwe="CWE-285",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="dash-sensitive-cache",
                    name="Sensitive Data Exposure via Client-Side Caching",
                    priority=PriorityEnum.LOW,
                    reason="Dashboard summary data cached in browser storage or without 'Cache-Control: no-store' headers can persist across shared terminals.",
                    testing_objective="Inspect browser Cache-Control headers and local storage for persisted financial and PII metrics.",
                    cwe="CWE-524",
                    source="AI",
                    status="NOT_TESTED"
                )
            ]
        )

    elif scenario == "settings":
        return VaptAnalysisResponse(
            page_type="Settings / Security Settings Page",
            confidence=0.96,
            detected_elements=[
                "Two-Factor Authentication (2FA / TOTP) setup and QR code area",
                "Session Management panel with 'Active Sessions' and 'Log Out All Devices'",
                "Security notification preferences checkboxes",
                "Password expiration & complexity settings",
                "API Key & Personal Access Token generation interface"
            ],
            detected_functionalities=[
                "Two-Factor Authentication Lifecycle",
                "Active Session Invalidation & Device Management",
                "API Token Provisioning & Scope Assignment"
            ],
            checklist=[
                ChecklistItem(
                    id="settings-2fa-bypass",
                    name="Two-Factor Authentication (2FA) Implementation Bypass",
                    priority=PriorityEnum.CRITICAL,
                    reason="Enabling or disabling 2FA often suffers from logic bypasses, lack of current password confirmation, or reusable recovery codes.",
                    testing_objective="Assess whether 2FA can be disabled without supplying the current password or valid OTP, and check if recovery codes are single-use.",
                    cwe="CWE-287",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="settings-csrf-toggles",
                    name="Cross-Site Request Forgery (CSRF) on Security Settings Toggles",
                    priority=PriorityEnum.HIGH,
                    reason="Modifying email alerts, disabling 2FA, or generating API tokens must strictly require anti-CSRF protection.",
                    testing_objective="Craft cross-site state-changing requests to verify if security settings can be modified without valid CSRF tokens.",
                    cwe="CWE-352",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="settings-session-invalidation",
                    name="Flawed Session Revocation on 'Log Out All Devices'",
                    priority=PriorityEnum.HIGH,
                    reason="Clicking 'Revoke Sessions' must invalidate server-side session stores (Redis/database) and blacklist JWTs.",
                    testing_objective="Use an existing session cookie from another device after invoking 'Log Out All Devices' to verify backend invalidation.",
                    cwe="CWE-613",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="settings-token-scope",
                    name="Privilege Escalation via API Token Scope Tampering",
                    priority=PriorityEnum.MEDIUM,
                    reason="Generating API tokens with custom permission checkboxes may accept unvalidated high-privilege scopes in request payloads.",
                    testing_objective="Attempt creating an API token with elevated admin scopes (e.g. scope=admin:all) from a standard user account.",
                    cwe="CWE-269",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="settings-delete-bypass",
                    name="Account Deletion Re-authentication Bypass",
                    priority=PriorityEnum.MEDIUM,
                    reason="Account deletion must require password confirmation to avoid account takeover via unattended browser sessions.",
                    testing_objective="Submit account deletion requests with omitted or empty password confirmation fields.",
                    cwe="CWE-306",
                    source="AI",
                    status="NOT_TESTED"
                )
            ]
        )

    elif scenario == "file_upload":
        return VaptAnalysisResponse(
            page_type="File Upload Page",
            confidence=0.96,
            detected_elements=[
                "Drag-and-drop file upload target area",
                "File selector button ('Choose File')",
                "Allowed extensions indicator (PDF, PNG, DOCX)",
                "Maximum file size label (10MB)",
                "Submit / Process Document button"
            ],
            detected_functionalities=[
                "Document & Binary Ingestion",
                "File Extension & MIME Validation",
                "Server-Side File Parsing & Storage"
            ],
            checklist=[
                ChecklistItem(
                    id="upload-webshell",
                    name="Unrestricted File Upload (Web Shell Execution)",
                    priority=PriorityEnum.CRITICAL,
                    reason="The application allows users to upload files to the server. If extensions and MIME types are not strictly validated, arbitrary code execution may occur.",
                    testing_objective="Assess whether executable files (.php, .jsp, .aspx, .phtml, polyglot files) can be uploaded and executed in the destination directory.",
                    cwe="CWE-434",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="upload-antivirus",
                    name="Malicious Content & Antivirus Evasion",
                    priority=PriorityEnum.HIGH,
                    reason="Uploaded documents may contain embedded macros, malware, or malicious SVG scripts that execute in other users' browsers.",
                    testing_objective="Verify whether uploaded files undergo antivirus scanning, MIME-type content sniffing, and SVG XSS payload sanitation.",
                    cwe="CWE-509",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="upload-ssrf-xxe",
                    name="Server-Side Request Forgery (SSRF) / XXE via File Processing",
                    priority=PriorityEnum.HIGH,
                    reason="Document parsers (e.g., XML, PDF, DOCX generators) often fetch remote resources or parse external DTD entities.",
                    testing_objective="Test for XML External Entity (XXE) injection and SSRF during file parsing and preview generation.",
                    cwe="CWE-611",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="upload-path-traversal",
                    name="Path Traversal & Filename Tampering",
                    priority=PriorityEnum.MEDIUM,
                    reason="User-controlled filenames may contain directory traversal sequences (e.g., '../../shell.php') or null bytes.",
                    testing_objective="Check if original filenames are preserved without sanitization or if the server overrides filenames with cryptographically random UUIDs.",
                    cwe="CWE-22",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="upload-zip-bomb",
                    name="Denial of Service via File Size & Zip Bombs",
                    priority=PriorityEnum.LOW,
                    reason="Large or nested compressed files can consume excessive server memory and disk space.",
                    testing_objective="Verify server-side file size limits and decompression bomb protections.",
                    cwe="CWE-400",
                    source="AI",
                    status="NOT_TESTED"
                )
            ]
        )

    elif scenario == "registration":
        return VaptAnalysisResponse(
            page_type="Sign-up / Registration Page",
            confidence=0.94,
            detected_elements=[
                "Full Name input field",
                "Email address input field",
                "Username input field",
                "Password field with strength meter",
                "Confirm Password field",
                "Terms & Conditions checkbox",
                "Create Account button"
            ],
            detected_functionalities=[
                "User Account Creation",
                "Password Policy Validation",
                "Email Verification Initiation"
            ],
            checklist=[
                ChecklistItem(
                    id="reg-account-enum",
                    name="Account Enumeration via Registration",
                    priority=PriorityEnum.HIGH,
                    reason="Registration endpoints often reveal whether an email or username already exists in the system through differential responses.",
                    testing_objective="Check whether registration error messages, response timing, or status codes differ when submitting existing vs new usernames.",
                    cwe="CWE-204",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="reg-weak-password",
                    name="Weak Password Policy Enforcement",
                    priority=PriorityEnum.HIGH,
                    reason="If password complexity requirements are enforced only client-side, weak or compromised passwords can be registered.",
                    testing_objective="Bypass client-side JavaScript validation and submit common, leaked, or single-character passwords directly to the API.",
                    cwe="CWE-521",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="reg-mass-registration",
                    name="Automated Mass Registration / Rate Limiting",
                    priority=PriorityEnum.HIGH,
                    reason="Without rate limiting or effective CAPTCHA, adversaries can register thousands of bot accounts.",
                    testing_objective="Assess whether repeated registration submissions trigger rate limiting, CAPTCHA challenges, or IP throttling.",
                    cwe="CWE-307",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="reg-stored-xss",
                    name="Cross-Site Scripting (Stored XSS) in Profile Fields",
                    priority=PriorityEnum.MEDIUM,
                    reason="Name and username input fields will be stored and rendered across administrative and user dashboards.",
                    testing_objective="Test for HTML entity encoding and script injection payloads within the Name and Username fields.",
                    cwe="CWE-79",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="reg-insecure-verification",
                    name="Insecure Email Verification Workflow",
                    priority=PriorityEnum.MEDIUM,
                    reason="Verification tokens must be cryptographically secure and unguessable to prevent unauthorized account activation.",
                    testing_objective="Analyze activation link tokens for entropy, expiration intervals, and single-use invalidation.",
                    cwe="CWE-640",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="reg-priv-escalation",
                    name="Privilege Escalation via Parameter Tampering",
                    priority=PriorityEnum.LOW,
                    reason="Hidden or unvalidated parameters such as 'role', 'isAdmin', or 'tier' may be accepted during registration.",
                    testing_objective="Attempt mass assignment by injecting elevated role attributes into the registration payload.",
                    cwe="CWE-915",
                    source="AI",
                    status="NOT_TESTED"
                )
            ]
        )

    elif scenario == "forgot_password":
        return VaptAnalysisResponse(
            page_type="Forgot Password / Password Reset Page",
            confidence=0.97,
            detected_elements=[
                "Email or Username recovery input field",
                "Security CAPTCHA verification widget",
                "Send Reset Link button",
                "Return to Login link"
            ],
            detected_functionalities=[
                "Password Reset Initiation",
                "Token Dispatch via Email",
                "Automated Bot Defense"
            ],
            checklist=[
                ChecklistItem(
                    id="forgot-host-header-poisoning",
                    name="Host Header Poisoning for Password Reset Poisoning",
                    priority=PriorityEnum.CRITICAL,
                    reason="Password reset emails frequently construct the password reset link using the HTTP Host header from the request.",
                    testing_objective="Manipulate the Host and X-Forwarded-Host headers to determine if the generated reset token is directed to an attacker-controlled server.",
                    cwe="CWE-644",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="forgot-account-enum",
                    name="Account Enumeration via Differential Responses",
                    priority=PriorityEnum.HIGH,
                    reason="Differential messages (e.g. 'Email not found' vs 'Reset link sent') disclose whether an account exists.",
                    testing_objective="Verify whether identical generic responses (e.g. 'If this email exists, a link has been sent') are returned for both valid and invalid targets.",
                    cwe="CWE-204",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="forgot-token-predictability",
                    name="Brute-Force & Reset Token Predictability",
                    priority=PriorityEnum.HIGH,
                    reason="Weak token generation (e.g., timestamps, sequential numbers, or short OTP codes) allows unauthorized password resets.",
                    testing_objective="Assess reset token entropy, length, and susceptibility to mathematical prediction or brute-force enumeration.",
                    cwe="CWE-330",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="forgot-rate-limiting",
                    name="Rate Limiting on Password Reset Requests",
                    priority=PriorityEnum.MEDIUM,
                    reason="Lack of rate limiting enables email bombing, SMS exhaustion, and denial of service against legitimate users.",
                    testing_objective="Assess whether the application restricts repeated reset requests for the same account or IP address.",
                    cwe="CWE-307",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="forgot-token-invalidation",
                    name="Reset Token Invalidation & Session Termination",
                    priority=PriorityEnum.MEDIUM,
                    reason="Tokens must be strictly one-time-use and invalidated immediately upon password change or token expiration.",
                    testing_objective="Verify whether reset tokens remain valid after usage or if existing active sessions are terminated upon password reset.",
                    cwe="CWE-613",
                    source="AI",
                    status="NOT_TESTED"
                )
            ]
        )

    elif scenario == "profile":
        return VaptAnalysisResponse(
            page_type="Account / Profile Page",
            confidence=0.93,
            detected_elements=[
                "Profile Avatar image with upload/change button",
                "Username & Display Name fields",
                "Email address field (read-only or editable)",
                "Biography textarea",
                "Change Password section (Current Password, New Password)",
                "Two-Factor Authentication (2FA) toggle",
                "Save Changes button"
            ],
            detected_functionalities=[
                "User Profile Data Management",
                "Avatar Media Upload",
                "Credentials & Password Update"
            ],
            checklist=[
                ChecklistItem(
                    id="profile-idor",
                    name="Insecure Direct Object References (IDOR) on Profile Update",
                    priority=PriorityEnum.CRITICAL,
                    reason="Profile update requests often pass user IDs, account numbers, or UUIDs in request parameters or paths.",
                    testing_objective="Attempt modifying another user's profile details, email address, or preferences by changing identifier parameters.",
                    cwe="CWE-639",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="profile-csrf",
                    name="Cross-Site Request Forgery (CSRF) on Sensitive Actions",
                    priority=PriorityEnum.HIGH,
                    reason="State-changing operations (email modification, password update, account deletion) must be protected against CSRF.",
                    testing_objective="Verify the presence, validation, and anti-tampering strength of CSRF tokens and SameSite cookie attributes.",
                    cwe="CWE-352",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="profile-stored-xss",
                    name="Stored Cross-Site Scripting (XSS) in Bio & Profile Fields",
                    priority=PriorityEnum.HIGH,
                    reason="Profile fields like Bio, Name, and Website are rendered to other users or administrators.",
                    testing_objective="Inject polyglot script payloads and HTML formatting into editable profile fields to test output encoding.",
                    cwe="CWE-79",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="profile-current-pass-bypass",
                    name="Current Password Verification Bypass",
                    priority=PriorityEnum.MEDIUM,
                    reason="Changing password or email must strictly verify the user's current password to prevent unauthorized takeover via unattended sessions.",
                    testing_objective="Check whether removing or tampering with the 'current_password' parameter allows unauthorized password changes.",
                    cwe="CWE-287",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="profile-avatar-upload",
                    name="Profile Avatar Upload Validation",
                    priority=PriorityEnum.MEDIUM,
                    reason="Avatar uploads could allow SVG-based XSS, oversized image DoS, or arbitrary file execution.",
                    testing_objective="Assess image content re-encoding, file dimension validation, and storage location isolation.",
                    cwe="CWE-434",
                    source="AI",
                    status="NOT_TESTED"
                )
            ]
        )

    elif scenario == "login":
        return VaptAnalysisResponse(
            page_type="Login / Sign-in Page",
            confidence=0.95,
            detected_elements=[
                "Username or Email input field",
                "Password input field with show/hide toggle",
                "'Remember Me' checkbox",
                "Sign In / Log In primary action button",
                "'Forgot Password?' link",
                "SSO / OAuth login buttons"
            ],
            detected_functionalities=[
                "User Authentication",
                "Session Initiation",
                "Credential Recovery Linkage",
                "OAuth / Single Sign-On"
            ],
            checklist=[
                ChecklistItem(
                    id="login-auth-bypass",
                    name="Authentication Bypass (SQL Injection / Logic Flaws)",
                    priority=PriorityEnum.CRITICAL,
                    reason="Authentication mechanisms must strictly validate credentials against database injection and logical bypasses.",
                    testing_objective="Assess whether authentication controls can be bypassed using SQL injection payloads, null byte injection, or boolean logic manipulation.",
                    cwe="CWE-287",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="login-rate-limiting",
                    name="Rate Limiting & Credential Stuffing Prevention",
                    priority=PriorityEnum.HIGH,
                    reason="Authentication endpoints are prime targets for automated credential stuffing and brute-force dictionary attacks.",
                    testing_objective="Assess whether repeated authentication attempts trigger IP throttling, account lockouts, or progressive delays.",
                    cwe="CWE-307",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="login-username-enum",
                    name="Username / Account Enumeration",
                    priority=PriorityEnum.HIGH,
                    reason="Differential error messages or response timing can reveal whether a username or email is registered in the system.",
                    testing_objective="Compare response bodies, HTTP status codes, and server response times between valid and invalid usernames.",
                    cwe="CWE-204",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="login-insecure-transport",
                    name="Insecure Transport & Sensitive Data Exposure",
                    priority=PriorityEnum.MEDIUM,
                    reason="Credentials must be transmitted over encrypted channels (HTTPS) with secure cookie flags.",
                    testing_objective="Verify that login POST requests enforce HTTPS, HSTS, and that sensitive headers or credentials are not cached.",
                    cwe="CWE-319",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="login-session-fixation",
                    name="Session Fixation & Session Management",
                    priority=PriorityEnum.MEDIUM,
                    reason="Upon successful authentication, the server must issue a new session identifier rather than reusing pre-authentication sessions.",
                    testing_objective="Check whether session identifiers change before and after user authentication.",
                    cwe="CWE-384",
                    source="AI",
                    status="NOT_TESTED"
                ),
                ChecklistItem(
                    id="login-autocomplete",
                    name="Password Field Caching & Autocomplete Policy",
                    priority=PriorityEnum.LOW,
                    reason="Unrestricted caching may store credentials in shared or public workstation browser memory.",
                    testing_objective="Inspect form input attributes for appropriate autocomplete and cache-control directives.",
                    cwe="CWE-524",
                    source="AI",
                    status="NOT_TESTED"
                )
            ]
        )

    else:
        # Fallback for any unknown or ambiguous scenario - NEVER default to Login!
        return get_simulated_response("ambiguous")
