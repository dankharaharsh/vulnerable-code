"""
Tracegate Governance, Risk, and Compliance (GRC) Framework Mapping Engine.

Provides deterministic, authoritative technical reference mappings from assessment findings
and CWE classifications to industry standards:
- NIST Cybersecurity Framework (CSF) 2.0
- ISO/IEC 27001:2022 (Annex A Controls)
- AICPA SOC 2 Trust Services Criteria (TSC 2017 / 2022 Trust Services Criteria)
- OWASP Web Security Testing Guide (WSTG v4.2)
- PCI DSS v4.0 (Payment Card Industry Data Security Standard)

Includes the mandatory statutory reference disclaimer, domain gap aggregation,
and vulnerability-specific root causes, remediations, SIEM alerts, and developer validation.
"""

from typing import Dict, Any, List, Optional
import re

MANDATORY_GRC_DISCLAIMER = (
    "Framework and control mappings are provided as technical reference mappings based on the assessment findings. "
    "They do not by themselves constitute a certification, attestation, legal opinion, or formal determination of "
    "regulatory compliance."
)

# Standard GRC Framework Descriptions
FRAMEWORKS_METADATA = {
    "nist_csf": {
        "name": "NIST Cybersecurity Framework (CSF) 2.0",
        "short_name": "NIST CSF 2.0",
        "publisher": "National Institute of Standards and Technology (NIST)",
        "version": "2.0 (2024)",
        "url": "https://www.nist.gov/cyberframework"
    },
    "iso_27001": {
        "name": "ISO/IEC 27001:2022 Information Security Management",
        "short_name": "ISO/IEC 27001:2022",
        "publisher": "International Organization for Standardization (ISO) / IEC",
        "version": "2022 Edition (Annex A Controls)",
        "url": "https://www.iso.org/standard/27001"
    },
    "soc2": {
        "name": "AICPA SOC 2 Trust Services Criteria (TSC)",
        "short_name": "SOC 2 TSC",
        "publisher": "American Institute of Certified Public Accountants (AICPA)",
        "version": "2017 / 2022 TSC Alignment",
        "url": "https://www.aicpa-cima.com"
    },
    "owasp_wstg": {
        "name": "OWASP Web Security Testing Guide",
        "short_name": "OWASP WSTG v4.2",
        "publisher": "Open Web Application Security Project (OWASP)",
        "version": "v4.2 (2020-2023)",
        "url": "https://owasp.org/www-project-web-security-testing-guide/"
    },
    "pci_dss": {
        "name": "PCI Data Security Standard (PCI DSS)",
        "short_name": "PCI DSS v4.0",
        "publisher": "Payment Card Industry Security Standards Council (PCI SSC)",
        "version": "v4.0.1 (2024)",
        "url": "https://www.pcisecuritystandards.org"
    }
}

# Authoritative CWE-to-Framework Catalog with tailored engineering guidance
CWE_FRAMEWORK_CATALOG: Dict[str, Dict[str, Any]] = {
    "CWE-89": {
        "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "domain": "Input Validation & Database Security",
        "control_gap": "Absence of parameterized database queries and insufficient validation of user-controlled inputs before interpreter execution.",
        "technical_root_cause": "Dynamic concatenation of untrusted client input into database query strings without binding parameters or utilizing prepared statements, allowing attackers to manipulate SQL execution logic and extract or modify backend data.",
        "remediation": "Refactor all database queries to use parameterized queries (prepared statements) or an established Object-Relational Mapping (ORM) framework with safe binding. Never concatenate user input directly into SQL strings. Restrict database user account privileges to the minimum required tables and procedures (least privilege).",
        "mitigation": "Deploy a Web Application Firewall (WAF) with updated SQL injection inspection signatures. Implement strict egress filtering on database instances to prevent outbound data exfiltration or out-of-band DNS/HTTP interactions.",
        "siem_detection": "Configure WAF and web server access logs to alert on SQL metacharacters, UNION SELECT patterns, sleep/benchmark functions, or comment syntax (-- and /*) in URL parameters and request bodies. Ingest database driver error logs into SIEM and trigger alerts on sudden spikes in SQL syntax errors or database access exceptions from specific client IPs.",
        "developer_validation": "Write automated unit and integration tests asserting that inputs containing SQL escape characters (e.g. single quotes, double quotes, semicolons, and OR 1=1) are treated strictly as literal strings and return 0 unexpected records. Verify that no database syntax error or internal table structure is revealed in error responses.",
        "nist": {
            "control_id": "PR.PS-01",
            "category": "Protect: Platform Security",
            "description": "Applications are developed, evaluated, and maintained securely across the system lifecycle."
        },
        "iso": {
            "control_id": "A.8.28",
            "category": "Technological Controls",
            "title": "Secure Coding",
            "description": "Secure coding principles are applied to software development to prevent injection flaws."
        },
        "soc2": {
            "criteria_id": "CC6.6",
            "principle": "Common Criteria: Logical Access Boundaries",
            "description": "The entity implements logical boundaries and technological defenses to protect against unauthorized inputs."
        },
        "wstg": {
            "test_id": "WSTG-INPV-05",
            "title": "Testing for SQL Injection",
            "category": "Input Validation Testing"
        },
        "pci": {
            "requirement_id": "6.2.4",
            "title": "Software Development Vulnerability Defenses",
            "description": "Software is developed to prevent injection flaws (including SQL injection)."
        }
    },
    "CWE-79": {
        "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "domain": "Client-Side Security & Output Encoding",
        "control_gap": "Inadequate contextual output encoding and browser execution boundary controls allowing unauthorized script execution.",
        "technical_root_cause": "User-supplied input is reflected or stored and rendered into the Document Object Model (DOM) or HTML response without context-aware output encoding, allowing execution of arbitrary client-side JavaScript in victims' browser contexts.",
        "remediation": "Apply context-dependent output encoding (HTML body, HTML attribute, JavaScript variable, CSS, URL parameter) using standard encoding libraries (e.g., OWASP Java Encoder, DOMPurify for client-side HTML rendering). Adopt frontend frameworks (React, Angular) that perform automatic contextual escaping by default.",
        "mitigation": "Deploy a robust Content Security Policy (CSP) header with 'default-src 'self'', restricting script execution to explicit nonces or hashes and blocking 'unsafe-inline' and 'unsafe-eval'. Ensure session cookies are set with the 'HttpOnly' attribute to prevent exfiltration via script access.",
        "siem_detection": "Monitor WAF logs for script injection patterns (<script>, onerror=, onload=, javascript: URIs) and encoded payloads. Configure CSP violation reporting (report-uri or report-to directive) to ingest browser CSP reports directly into the SIEM and alert on repeated violation attempts.",
        "developer_validation": "Write automated integration tests passing XSS attack vectors (<script>alert(1)</script>, '><img src=x onerror=prompt(1)>) through the API; assert that returned responses are safely entity-encoded (e.g., &lt;script&gt;) and that raw HTML tags are never rendered into executable contexts.",
        "nist": {
            "control_id": "PR.PS-01",
            "category": "Protect: Platform Security",
            "description": "Applications are evaluated and secured against injection and client execution vulnerabilities."
        },
        "iso": {
            "control_id": "A.8.28",
            "category": "Technological Controls",
            "title": "Secure Coding",
            "description": "Secure coding practices ensure context-aware output encoding and content security policies."
        },
        "soc2": {
            "criteria_id": "CC6.6",
            "principle": "Logical Access Boundaries",
            "description": "The entity restricts unauthorized code execution and cross-origin data exposure."
        },
        "wstg": {
            "test_id": "WSTG-INPV-01",
            "title": "Testing for Reflected Cross Site Scripting",
            "category": "Input Validation Testing"
        },
        "pci": {
            "requirement_id": "6.2.4",
            "title": "Software Development Vulnerability Defenses",
            "description": "Software is developed to prevent cross-site scripting (XSS) attacks."
        }
    },
    "CWE-639": {
        "name": "Authorization Bypass Through User-Controlled Key ('Insecure Direct Object References')",
        "domain": "Broken Object Level Authorization (BOLA / IDOR)",
        "control_gap": "Lack of server-side object-level access control checks when accessing records via user-supplied identifiers.",
        "technical_root_cause": "The application relies on client-provided object identifiers (e.g., user IDs, document IDs, account numbers) to retrieve resources from storage without verifying that the authenticated session possesses ownership or authorized tenancy rights to that specific object.",
        "remediation": "Enforce mandatory server-side authorization checks on every state-changing and data-retrieval request. Verify that the authenticated subject ID (from session or verified JWT claim) possesses permission to access the target object ID before querying or modifying the database. Consider utilizing non-enumerable UUIDv4 keys or indirect reference maps.",
        "mitigation": "Adopt a centralized Policy Enforcement Point (PEP) middleware or Attribute-Based Access Control (ABAC) layer to validate tenancy boundaries across all microservices and API endpoints.",
        "siem_detection": "Configure application audit logging to log authenticated user IDs alongside accessed resource IDs. Configure SIEM correlation rules to detect enumeration patterns: e.g., a single user session or IP issuing sequential requests to incrementing numeric resource IDs within short time windows.",
        "developer_validation": "Implement multi-tenant integration tests utilizing two distinct authenticated test personas (User A and User B). Have User A attempt to read, update, and delete resources created by User B; assert that the API strictly returns HTTP 403 Forbidden or 404 Not Found in all cases.",
        "nist": {
            "control_id": "PR.AA-05",
            "category": "Protect: Access Control",
            "description": "Access permissions, entitlements, and authorizations are managed and enforced according to least privilege."
        },
        "iso": {
            "control_id": "A.8.3",
            "category": "Technological Controls",
            "title": "Information Access Restriction",
            "description": "Access to information and application system functions is restricted in accordance with the access control policy."
        },
        "soc2": {
            "criteria_id": "CC6.1",
            "principle": "Logical Access Controls",
            "description": "Logical access controls restrict access to protected data to authorized users."
        },
        "wstg": {
            "test_id": "WSTG-ATHZ-04",
            "title": "Testing for Insecure Direct Object References",
            "category": "Authorization Testing"
        },
        "pci": {
            "requirement_id": "7.2",
            "title": "Access Restrictions Based on Business Need to Know",
            "description": "Access to system components and data is strictly limited to authorized personas."
        }
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "domain": "Server-Side Request Handling & Network Boundaries",
        "control_gap": "Absence of strict destination allowlisting and network-level isolation for user-controlled outbound URL fetches.",
        "technical_root_cause": "The application backend initiates network requests to external URLs provided by client requests without restricting destination protocols, resolving hostnames to private IP spaces, or preventing requests to internal infrastructure and cloud metadata services.",
        "remediation": "Enforce a strict whitelist of permitted remote protocols (e.g. HTTPS only) and approved target hostnames or domains. Resolve DNS and strictly block all private, non-routable IP addresses (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16; loopback 127.0.0.0/8; link-local 169.254.169.254; IPv6 ::1). Disable HTTP redirection handling in the client HTTP library.",
        "mitigation": "Isolate the network namespace of application pods or servers handling outbound fetching. Implement strict firewall egress filtering to prevent servers from accessing internal services, databases, or cloud metadata endpoints (169.254.169.254).",
        "siem_detection": "Configure host and network firewall logging to alert on outbound connection attempts from web servers to private subnets or link-local metadata addresses (169.254.169.254). Ingest DNS logs to flag queries attempting to resolve private domain zones or DNS rebinding services.",
        "developer_validation": "Write automated unit tests against the URL validation service passing loopback addresses (127.0.0.1, localhost), link-local cloud metadata (http://169.254.169.254/latest/meta-data), and RFC 1918 IPs. Assert that the validator throws an explicit security exception and halts execution before initiating any socket connection.",
        "nist": {
            "control_id": "PR.AC-05",
            "category": "Protect: Network Integrity",
            "description": "Network boundaries and egress communications are monitored and constrained."
        },
        "iso": {
            "control_id": "A.8.20",
            "category": "Technological Controls",
            "title": "Network Security",
            "description": "Network perimeters are monitored and access to internal segments is strictly controlled."
        },
        "soc2": {
            "criteria_id": "CC6.6",
            "principle": "Logical Access Boundaries",
            "description": "Logical perimeter boundaries prevent unauthorized network requests to internal systems."
        },
        "wstg": {
            "test_id": "WSTG-INPV-19",
            "title": "Testing for Server-Side Request Forgery",
            "category": "Input Validation Testing"
        },
        "pci": {
            "requirement_id": "1.3",
            "title": "Network Access Controls",
            "description": "Network access to and from system components is restricted to authorized traffic."
        }
    },
    "CWE-287": {
        "name": "Improper Authentication",
        "domain": "Authentication & Identity Management",
        "control_gap": "Flawed credential verification or token validation logic allowing unauthenticated actors to assume identity.",
        "technical_root_cause": "Flaws in credential verification, unverified JWT signatures (e.g. accepting 'alg: none' or mismatched keys), or missing validation of session integrity allowing unauthenticated actors to bypass authentication barriers.",
        "remediation": "Enforce strong cryptographic authentication mechanisms. For JWT implementations, enforce strict algorithm whitelisting (RS256 or HS256 with strong keys), verify signatures on every request, enforce token expiration ('exp'), and validate issuer ('iss') and audience ('aud') claims.",
        "mitigation": "Enforce Multi-Factor Authentication (MFA) across all user and administrative accounts. Implement account lockout policies and anomalous login detection.",
        "siem_detection": "Ingest authentication logs into SIEM. Alert on sudden spikes in failed logins, logins using unrecognized token headers or missing signatures, and impossible travel velocity between authenticated sessions.",
        "developer_validation": "Write automated unit tests verifying that tokens with tampered payloads, expired timestamps, or modified cryptographic signatures are rejected with HTTP 401 Unauthorized. Verify that requests missing authentication headers are immediately rejected.",
        "nist": {
            "control_id": "PR.AA-01",
            "category": "Protect: Identity Management",
            "description": "Identities and credentials are authenticated and managed across user lifecycles."
        },
        "iso": {
            "control_id": "A.8.5",
            "category": "Technological Controls",
            "title": "Secure Authentication",
            "description": "Secure authentication technologies and procedures are implemented based on risk."
        },
        "soc2": {
            "criteria_id": "CC6.1",
            "principle": "Logical Access Controls",
            "description": "The entity implements logical access security software and authentication controls."
        },
        "wstg": {
            "test_id": "WSTG-ATHN-01",
            "title": "Testing for Credentials Transported over an Encrypted Channel",
            "category": "Authentication Testing"
        },
        "pci": {
            "requirement_id": "8.3",
            "title": "Strong Authentication Architecture",
            "description": "Strong authentication systems and multi-factor mechanisms protect system access."
        }
    },
    "CWE-288": {
        "name": "Authentication Bypass Using an Alternate Path or Channel",
        "domain": "Authentication & Identity Management",
        "control_gap": "Alternative routing or unverified 2FA parameters permit full authentication bypass.",
        "technical_root_cause": "Secondary authentication steps (such as MFA or email OTP verification) can be bypassed by directly navigating to protected downstream endpoints, manipulating state parameters, or failing to enforce intermediate authentication state on the backend.",
        "remediation": "Enforce a unified state machine for multi-step authentication. Restrict access to authenticated resources until all authentication factors have been successfully validated. Store intermediate authentication state in secure, server-side sessions rather than client-controlled tokens.",
        "mitigation": "Implement centralized authorization middleware that verifies full MFA completion before routing requests to any protected business logic or administrative endpoints.",
        "siem_detection": "Alert on requests reaching protected application routes where the associated user session lacks the requisite multi-factor verification flag. Monitor for direct API calls to post-login handlers without preceding 2FA verification steps.",
        "developer_validation": "Write automated end-to-end tests attempting to access authenticated dashboard endpoints using a partially authenticated session (primary credentials verified, 2FA pending); assert that the server strictly responds with HTTP 403 or redirects to the 2FA challenge.",
        "nist": {
            "control_id": "PR.AA-03",
            "category": "Protect: Identity & Access Management",
            "description": "Users, devices, and other assets are authenticated with multi-factor authentication."
        },
        "iso": {
            "control_id": "A.8.5",
            "category": "Technological Controls",
            "title": "Secure Authentication",
            "description": "Robust authentication methods ensure multi-factor enforcement without alternative bypass routes."
        },
        "soc2": {
            "criteria_id": "CC6.2",
            "principle": "User Authentication & MFA",
            "description": "Prior to issuing system credentials and session rights, identity is verified."
        },
        "wstg": {
            "test_id": "WSTG-ATHN-07",
            "title": "Testing for Two-Factor Authentication Weaknesses",
            "category": "Authentication Testing"
        },
        "pci": {
            "requirement_id": "8.3.1",
            "title": "Multi-Factor Authentication (MFA)",
            "description": "MFA is implemented for all non-console administrative access and access into sensitive environments."
        }
    },
    "CWE-22": {
        "name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "domain": "File Handling & Resource Access",
        "control_gap": "Failure to neutralize directory traversal sequences in file parameters leading to unauthorized file read/write.",
        "technical_root_cause": "The application constructs filesystem paths using unsanitized user input without canonicalization or bounding checks, allowing relative path sequences (../ or ..\\) to access files outside the designated root directory.",
        "remediation": "Do not accept raw file paths from client input. Use indirect identifiers (e.g. index numbers or UUIDs mapped in a database). If filenames must be accepted, canonicalize the path using standard platform methods (e.g., Path.resolve() / os.path.realpath()) and verify that the resulting canonical path begins strictly with the intended base directory.",
        "mitigation": "Run the application process under a dedicated low-privilege service account with chroot or container jail restrictions. Grant read permissions only to the specific directories required for application operation.",
        "siem_detection": "Configure web server and WAF rules to detect directory traversal patterns (%2e%2e%2f, ..%2f, ..\\) in query parameters and request URIs. Ingest host OS audit logs to detect access denials from the application process against system directories (/etc, /windows).",
        "developer_validation": "Implement unit tests passing directory traversal payloads (../../../../etc/passwd, ..\\..\\..\\windows\\win.ini, %2e%2e%2f) to file retrieval endpoints; verify that the application returns HTTP 400 Bad Request or 404 Not Found and does not disclose file content.",
        "nist": {
            "control_id": "PR.AA-05",
            "category": "Protect: Access Control",
            "description": "Access permissions and resource paths are strictly bounded to prevent path traversal."
        },
        "iso": {
            "control_id": "A.8.3",
            "category": "Technological Controls",
            "title": "Information Access Restriction",
            "description": "Access to filesystem directories and operating system resources is strictly restricted."
        },
        "soc2": {
            "criteria_id": "CC6.1",
            "principle": "Logical Access Controls",
            "description": "Logical access protections prevent access to underlying host assets."
        },
        "wstg": {
            "test_id": "WSTG-FILE-01",
            "title": "Testing Directory Traversal File Include",
            "category": "Input Validation Testing"
        },
        "pci": {
            "requirement_id": "6.2.4",
            "title": "Software Development Vulnerability Defenses",
            "description": "Applications prevent unauthorized file manipulation and arbitrary pathname traversal."
        }
    },
    "CWE-434": {
        "name": "Unrestricted Upload of File with Dangerous Type",
        "domain": "File Handling & Input Validation",
        "control_gap": "Permissive file extension or MIME verification allowing executable scripts to be uploaded and executed.",
        "technical_root_cause": "The file upload handler validates file extensions using client-supplied headers or inadequate blacklists, permitting users to upload executable server-side scripts (.php, .jsp, .aspx, .exe) or SVG files containing malicious scripts.",
        "remediation": "Implement strict allowlist-based file extension verification. Verify the file's content by inspecting its magic bytes (file signature) rather than trusting the client-supplied Content-Type header. Store uploaded files in an isolated object storage service (e.g. AWS S3, Azure Blob) or a dedicated directory mounted with the 'noexec' flag.",
        "mitigation": "Serve user-uploaded files from a separate, cookieless domain with the 'Content-Disposition: attachment' and 'X-Content-Type-Options: nosniff' headers. Integrate automated antivirus and malware scanning into the upload ingestion pipeline.",
        "siem_detection": "Log all file upload operations including client IP, authenticated user, uploaded filename, computed SHA-256 hash, and detected MIME type. Alert on uploads containing double extensions (e.g., file.php.jpg) or mismatch between file extension and detected magic bytes.",
        "developer_validation": "Write automated integration tests attempting to upload executable scripts (.php, .jsp, .sh, .exe, .svg with script tags). Assert that the upload endpoint rejects the files with HTTP 400 or 422 and that files are never accessible via executable web paths.",
        "nist": {
            "control_id": "PR.PS-01",
            "category": "Protect: Platform Security",
            "description": "Software mechanisms restrict execution of unauthorized payloads and enforce file content security."
        },
        "iso": {
            "control_id": "A.8.7",
            "category": "Technological Controls",
            "title": "Protection Against Malware",
            "description": "Protection against malicious code is implemented for user-uploaded content."
        },
        "soc2": {
            "criteria_id": "CC6.8",
            "principle": "Malware & Threat Defense",
            "description": "The entity implements controls to prevent unauthorized software and payload execution."
        },
        "wstg": {
            "test_id": "WSTG-FILE-08",
            "title": "Testing for Unrestricted File Upload",
            "category": "Input Validation Testing"
        },
        "pci": {
            "requirement_id": "6.2.4",
            "title": "Software Development Vulnerability Defenses",
            "description": "Controls prevent the upload and execution of unauthorized and malicious code."
        }
    },
    "CWE-524": {
        "name": "Use of Cache-Containing Sensitive Information",
        "domain": "Data Protection & Caching Controls",
        "control_gap": "Missing Cache-Control: no-store headers on authenticated endpoints exposing sensitive session data.",
        "technical_root_cause": "HTTP response headers on endpoints serving sensitive personal, financial, or session data omit defensive cache directives, permitting intermediate proxies, shared gateways, or local browser caches to persist sensitive information unencrypted.",
        "remediation": "Configure the web server or application framework to emit 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' and 'Pragma: no-cache' on all authenticated or sensitive response endpoints.",
        "mitigation": "Implement global security header middleware across the API gateway to automatically attach defensive caching and privacy headers to all non-static responses.",
        "siem_detection": "Periodically scan API responses via synthetic monitoring or proxy telemetry to verify the presence of 'Cache-Control: no-store' headers on authenticated endpoints.",
        "developer_validation": "Write automated test cases verifying that responses from sensitive endpoints (e.g., profile, billing, authentication) include 'Cache-Control: no-store' and 'Pragma: no-cache' headers in their HTTP response headers.",
        "nist": {
            "control_id": "PR.DS-01",
            "category": "Protect: Data Security",
            "description": "Data-at-rest and cached intermediate data are protected according to organizational policies."
        },
        "iso": {
            "control_id": "A.8.10",
            "category": "Technological Controls",
            "title": "Information Deletion & Caching",
            "description": "Data stored in intermediate browser storage and reverse proxy caches is controlled."
        },
        "soc2": {
            "criteria_id": "CC6.7",
            "principle": "Data Transmission & Storage",
            "description": "Data is protected during transmission and intermediate storage against unauthorized exposure."
        },
        "wstg": {
            "test_id": "WSTG-ATHN-06",
            "title": "Testing for Browser Cache Weaknesses",
            "category": "Authentication Testing"
        },
        "pci": {
            "requirement_id": "8.2.2",
            "title": "Protection of User Authentication Credentials",
            "description": "Authentication credentials and cardholder data are not stored in unencrypted client caches."
        }
    },
    "CWE-204": {
        "name": "Observable Response Discrepancy ('Account Enumeration')",
        "domain": "Authentication & Identity Management",
        "control_gap": "Divergent HTTP status codes or timing responses reveal valid account usernames.",
        "technical_root_cause": "The application returns noticeably different error messages (e.g., 'User not found' vs 'Incorrect password') or exhibits significant response timing differences during login or password reset operations, enabling attackers to harvest valid account usernames.",
        "remediation": "Standardize all authentication and password recovery responses to use generic messaging (e.g. 'If an account exists for this address, instructions have been sent' or 'Invalid credentials'). Ensure response timing is normalized across both existing and non-existent accounts by executing constant-time password hashing simulations.",
        "mitigation": "Enforce strict IP and account-level rate limiting and CAPTCHA challenges on authentication and password recovery endpoints.",
        "siem_detection": "Configure SIEM to monitor for high volumes of distinct username lookups originating from a single client IP or ASN within short timeframes (indicating automated user enumeration sweeps).",
        "developer_validation": "Write integration tests querying login and password reset endpoints with both valid and invalid usernames; assert that returned HTTP status codes, JSON response structures, and user-facing messages are identical.",
        "nist": {
            "control_id": "PR.AA-01",
            "category": "Protect: Identity Management",
            "description": "Identity verification endpoints provide uniform responses to avoid account disclosure."
        },
        "iso": {
            "control_id": "A.8.5",
            "category": "Technological Controls",
            "title": "Secure Authentication",
            "description": "Authentication responses do not leak valid username or user existence status."
        },
        "soc2": {
            "criteria_id": "CC6.1",
            "principle": "Logical Access Controls",
            "description": "User enumeration vectors are neutralized to prevent targeted credential attacks."
        },
        "wstg": {
            "test_id": "WSTG-IDNT-04",
            "title": "Testing for Account Enumeration and Guessable User Account",
            "category": "Identity Management Testing"
        },
        "pci": {
            "requirement_id": "8.2.3",
            "title": "Strong Password & Authentication Security",
            "description": "Logon and recovery procedures do not disclose whether accounts exist."
        }
    },
    "CWE-307": {
        "name": "Improper Restriction of Excessive Authentication Attempts",
        "domain": "Authentication & Rate Limiting",
        "control_gap": "Absence of IP or account-level throttling on login, password reset, or OTP verification endpoints.",
        "technical_root_cause": "The authentication or OTP verification endpoints do not enforce rate limiting or account lockout, allowing automated scripts to execute high-volume brute-force or credential-stuffing attacks without throttling.",
        "remediation": "Implement multi-layered rate limiting at the API gateway and application levels (e.g. maximum 5 failed attempts per account per 15-minute window; IP-based rate limiting). Implement progressive delays and account lockout or verification challenges (CAPTCHA / MFA prompt) upon repeated failures.",
        "mitigation": "Deploy bot detection and credential-stuffing defense solutions (e.g. Cloudflare Turnstile, AWS WAF Fraud Control) on all public authentication surfaces.",
        "siem_detection": "Configure SIEM alerts on HTTP 429 Too Many Requests thresholds and repeated failed login events exceeding 5 attempts within 5 minutes against single accounts or from single IP addresses.",
        "developer_validation": "Write an automated integration test issuing N+1 consecutive failed login attempts within the rate limiting window. Assert that request N+1 receives HTTP 429 Too Many Requests with a valid 'Retry-After' header.",
        "nist": {
            "control_id": "DE.AE-02",
            "category": "Detect: Anomalies & Events",
            "description": "Repeated failed authentication attempts are detected, rate-limited, and analyzed."
        },
        "iso": {
            "control_id": "A.8.5",
            "category": "Technological Controls",
            "title": "Secure Authentication",
            "description": "Systems limit consecutive failed login attempts and protect against brute-force attacks."
        },
        "soc2": {
            "criteria_id": "CC7.2",
            "principle": "Security Incident Monitoring & Protection",
            "description": "The entity monitors security anomalies and throttles brute-force authorization events."
        },
        "wstg": {
            "test_id": "WSTG-ATHN-03",
            "title": "Testing for Weak Lock Out Mechanism",
            "category": "Authentication Testing"
        },
        "pci": {
            "requirement_id": "8.3.4",
            "title": "Account Lockout Defense",
            "description": "Accounts are temporarily locked or rate-limited after multiple consecutive failed attempts."
        }
    },
    "CWE-384": {
        "name": "Session Fixation",
        "domain": "Session Management & Request Integrity",
        "control_gap": "Failure to renew session tokens upon user authentication, allowing session hijacking.",
        "technical_root_cause": "The application retains the existing pre-authentication session identifier after a user successfully authenticates, allowing an attacker who pre-set or observed the anonymous session cookie to hijack the authenticated session.",
        "remediation": "Ensure that the application invalidates the existing pre-authentication session and issues a completely new, cryptographically random session identifier immediately upon successful user login or privilege level elevation.",
        "mitigation": "Set all session cookies with 'Secure', 'HttpOnly', and 'SameSite=Lax' (or 'Strict') flags. Implement idle and absolute session expiration timers.",
        "siem_detection": "Monitor session lifecycle events in application logs; flag instances where authenticated sessions maintain pre-login session IDs.",
        "developer_validation": "Write an automated test that captures the session cookie before login, performs authentication, and asserts that the post-login session cookie value is strictly different from the pre-login cookie.",
        "nist": {
            "control_id": "PR.AA-03",
            "category": "Protect: Identity Management",
            "description": "Session identifiers are renewed upon privilege elevation and authenticated state change."
        },
        "iso": {
            "control_id": "A.8.5",
            "category": "Technological Controls",
            "title": "Secure Authentication",
            "description": "Session tokens are securely issued, rotated, and terminated."
        },
        "soc2": {
            "criteria_id": "CC6.1",
            "principle": "Logical Access Controls",
            "description": "Session identifiers are protected against pre-authentication fixation and hijacking."
        },
        "wstg": {
            "test_id": "WSTG-SESS-03",
            "title": "Testing for Session Fixation",
            "category": "Session Management Testing"
        },
        "pci": {
            "requirement_id": "8.2",
            "title": "User Identification & Session Control",
            "description": "Sessions are invalidated and renegotiated upon successful user authentication."
        }
    },
    "CWE-352": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "domain": "Session Management & Request Integrity",
        "control_gap": "Missing anti-CSRF tokens or SameSite cookie protections on state-changing POST/PUT requests.",
        "technical_root_cause": "The application executes state-changing actions (e.g. modifying email, changing passwords, transferring funds) based solely on automatically submitted browser credentials (cookies) without verifying request provenance via an unpredictable anti-CSRF token.",
        "remediation": "Implement cryptographically strong, unpredictable anti-CSRF tokens (synchronizer token pattern or encrypted token pattern) for all state-changing HTTP requests (POST, PUT, DELETE, PATCH). Verify the token on the server before processing the request.",
        "mitigation": "Configure all session and authentication cookies with the 'SameSite=Lax' or 'SameSite=Strict' attribute to prevent browsers from sending cookies with cross-site requests. Enforce custom request headers (e.g. 'X-Requested-With' or 'Sec-Fetch-Site: same-origin') for API endpoints.",
        "siem_detection": "Monitor WAF and web server logs for missing or mismatched CSRF tokens on state-changing API endpoints; alert on sudden spikes in CSRF token validation failures.",
        "developer_validation": "Write an automated integration test executing state-changing POST requests (1) without the CSRF token and (2) with an invalid CSRF token; assert that the application returns HTTP 403 Forbidden in both scenarios.",
        "nist": {
            "control_id": "PR.AA-05",
            "category": "Protect: Access Control",
            "description": "State-changing actions require explicit user authorization and anti-forgery validation."
        },
        "iso": {
            "control_id": "A.8.28",
            "category": "Technological Controls",
            "title": "Secure Coding",
            "description": "Web applications employ anti-CSRF mechanisms to validate request provenance."
        },
        "soc2": {
            "criteria_id": "CC6.6",
            "principle": "Logical Access Boundaries",
            "description": "The entity protects against cross-origin forged transactions."
        },
        "wstg": {
            "test_id": "WSTG-SESS-05",
            "title": "Testing for Cross Site Request Forgery",
            "category": "Session Management Testing"
        },
        "pci": {
            "requirement_id": "6.2.4",
            "title": "Software Development Vulnerability Defenses",
            "description": "Software is developed to prevent cross-site request forgery (CSRF)."
        }
    },
    "CWE-200": {
        "name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "domain": "Information Disclosure & Sensitive Data Exposure",
        "control_gap": "Verbose stack traces, internal server headers, or unredacted system telemetry exposed to end users.",
        "technical_root_cause": "The application returns detailed internal system error messages, database stack traces, or diagnostic headers (e.g., Server, X-Powered-By) to clients, disclosing technical architecture, database schemas, and framework versions to potential attackers.",
        "remediation": "Disable detailed error messages and debug mode in production environments. Implement generic global exception handlers returning sanitized error responses with reference IDs for internal logging. Strip identifying server banners (Server, X-Powered-By, X-AspNet-Version) at the reverse proxy level.",
        "mitigation": "Enforce automated secret and sensitive data masking in application logging frameworks and API responses.",
        "siem_detection": "Configure synthetic endpoint monitoring to scan HTTP response headers and bodies for leaked stack traces, SQL error strings, or identifying server banners.",
        "developer_validation": "Write automated unit tests triggering application exceptions (e.g. 404, 500); assert that response bodies contain only generic error messages and do not include stack traces, file paths, or framework version identifiers.",
        "nist": {
            "control_id": "PR.DS-01",
            "category": "Protect: Data Security",
            "description": "Sensitive organizational and technical data is protected from unauthorized exposure."
        },
        "iso": {
            "control_id": "A.8.12",
            "category": "Technological Controls",
            "title": "Data Leakage Prevention",
            "description": "Measures are applied to prevent the unauthorized disclosure of sensitive data."
        },
        "soc2": {
            "criteria_id": "CC6.7",
            "principle": "Data Transmission & Storage",
            "description": "Information is protected against inadvertent disclosure in web responses."
        },
        "wstg": {
            "test_id": "WSTG-INFO-05",
            "title": "Review Webpage Content for Information Leakage",
            "category": "Information Gathering"
        },
        "pci": {
            "requirement_id": "3.4",
            "title": "Protection of Sensitive Data",
            "description": "Sensitive application metadata and configuration details are masked from public view."
        }
    },
    "CWE-269": {
        "name": "Improper Privilege Management",
        "domain": "Access Control & Privilege Authorization",
        "control_gap": "Privilege escalation vectors permit low-privileged accounts to access administrative features.",
        "technical_root_cause": "The application fails to re-verify user role memberships or permissions on server-side administrative endpoints, relying instead on client-side UI visibility or unenforced URL parameters.",
        "remediation": "Implement a centralized role-based access control (RBAC) verification filter on all administrative endpoints. Check the user's validated role in the session on every request before executing administrative actions. Deny by default.",
        "mitigation": "Enforce the principle of least privilege across all administrative roles and separate administrative interfaces into isolated network zones or administrative subdomains.",
        "siem_detection": "Alert on requests to administrative paths (/admin, /manage) originating from accounts without administrative privileges. Flag any sudden changes to user role attributes in the database.",
        "developer_validation": "Write automated API integration tests authenticating as a standard user role and attempting to execute administrative actions (e.g., delete user, export audit log); assert that the application returns HTTP 403 Forbidden.",
        "nist": {
            "control_id": "PR.AA-05",
            "category": "Protect: Access Control",
            "description": "Privileged access rights are restricted and validated on every privileged operation."
        },
        "iso": {
            "control_id": "A.8.3",
            "category": "Technological Controls",
            "title": "Information Access Restriction",
            "description": "Access to administrative and sensitive functions is restricted to authorized roles."
        },
        "soc2": {
            "criteria_id": "CC6.3",
            "principle": "Role-Based Access Control",
            "description": "Role-based access controls prevent unauthorized escalation to administrative capabilities."
        },
        "wstg": {
            "test_id": "WSTG-ATHZ-02",
            "title": "Testing for Bypassing Authorization Schema",
            "category": "Authorization Testing"
        },
        "pci": {
            "requirement_id": "7.2",
            "title": "Access Restrictions Based on Business Need to Know",
            "description": "Privilege levels are enforced so that users cannot perform unauthorized administrative tasks."
        }
    },
    "CWE-798": {
        "name": "Use of Hard-coded Credentials",
        "domain": "Secrets Management & Credential Hygiene",
        "control_gap": "Embedded cryptographic keys, database credentials, or API tokens discovered in application code or client bundles.",
        "technical_root_cause": "Development teams store plaintext credentials, API keys, private keys, or tokens directly in source code or client-side assets, making them vulnerable to extraction through decompilation, repository access, or browser inspection.",
        "remediation": "Immediately revoke and rotate all exposed credentials. Remove hard-coded secrets from the codebase and Git history. Store secrets in a dedicated secrets manager (e.g. HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) and inject them at runtime via secure environment variables.",
        "mitigation": "Integrate automated pre-commit hooks and CI/CD pipeline scanners (e.g. Gitleaks, Trufflehog) to block code commits containing secret patterns.",
        "siem_detection": "Monitor cloud audit logs and API gateway logs for unusual access patterns or geographic anomalies involving rotated or compromised credentials.",
        "developer_validation": "Run automated static analysis (SAST) and secret scanning tools in the CI pipeline; assert that zero hard-coded credential patterns or API tokens exist in committed source code.",
        "nist": {
            "control_id": "PR.PS-01",
            "category": "Protect: Platform Security",
            "description": "Hard-coded secrets are prohibited; secrets are injected via secure key vaults."
        },
        "iso": {
            "control_id": "A.8.24",
            "category": "Technological Controls",
            "title": "Use of Cryptography",
            "description": "Cryptographic keys and secrets are protected against exposure in source code."
        },
        "soc2": {
            "criteria_id": "CC6.1",
            "principle": "Logical Access Controls",
            "description": "Authentication credentials are managed securely without hard-coding in source repositories."
        },
        "wstg": {
            "test_id": "WSTG-INFO-05",
            "title": "Review Webpage Content for Information Leakage",
            "category": "Information Gathering"
        },
        "pci": {
            "requirement_id": "8.6",
            "title": "Management of System and Application Accounts",
            "description": "Application secrets and service credentials are kept confidential and not hard-coded."
        }
    },
    "CWE-601": {
        "name": "URL Redirection to Untrusted Site ('Open Redirect')",
        "domain": "Input Validation & Navigation Controls",
        "control_gap": "Unvalidated redirect destinations allow redirection to arbitrary external domains.",
        "technical_root_cause": "The application accepts an external URL parameter (e.g., returnUrl, next) and passes it directly to an HTTP redirect response (301/302) without validating that the target is a relative local path or an approved domain.",
        "remediation": "Avoid accepting external URLs for redirection. Use relative URL paths only, or validate target URLs against a strict whitelist of approved domains. Discard any URL beginning with '//' or containing unexpected protocol schemes.",
        "mitigation": "Present an intermediate user confirmation page ('You are leaving this site') before navigating to any external link.",
        "siem_detection": "Monitor web server access logs for redirect parameters containing external domain strings (http://, https://, //evil.com).",
        "developer_validation": "Write automated unit tests verifying that passing external domains (e.g. https://evil.com, //evil.com) to redirect handlers results in a redirect to a default safe local landing page or returns HTTP 400.",
        "nist": {
            "control_id": "PR.PS-01",
            "category": "Protect: Platform Security",
            "description": "Applications prevent unauthorized redirects and external destination manipulation."
        },
        "iso": {
            "control_id": "A.8.28",
            "category": "Technological Controls",
            "title": "Secure Coding",
            "description": "Application logic enforces destination validation on external redirects."
        },
        "soc2": {
            "criteria_id": "CC6.6",
            "principle": "Logical Access Boundaries",
            "description": "Boundary protections prevent redirection of user sessions to unvetted external destinations."
        },
        "wstg": {
            "test_id": "WSTG-CLNT-04",
            "title": "Testing for Client-Side URL Redirect",
            "category": "Client-Side Testing"
        },
        "pci": {
            "requirement_id": "6.2.4",
            "title": "Software Development Vulnerability Defenses",
            "description": "Applications prevent open redirection and unauthorized user diversion."
        }
    },
    "CWE-78": {
        "name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "domain": "Input Validation & System Execution",
        "control_gap": "Direct execution of shell commands incorporating unsanitized user-supplied parameters.",
        "technical_root_cause": "Application code constructs operating system command strings using untrusted client input and executes them via system shells without neutralization or parameter binding.",
        "remediation": "Avoid invoking shell interpreters from application code. Use native programming language APIs and libraries instead of operating system shell commands. If system commands are unavoidable, use parameterized process execution APIs (e.g. subprocess.run() with shell=False) without shell invocation.",
        "mitigation": "Run application containers in read-only filesystems with dropped capabilities and mandatory access control (AppArmor/SELinux).",
        "siem_detection": "Configure host-based endpoint detection (EDR) to alert on unexpected process spawns (sh, bash, cmd.exe, powershell.exe) originating from web server worker processes.",
        "developer_validation": "Write automated tests asserting that shell metacharacters (; & | ` $ > <) in input parameters are rejected with HTTP 400 and never result in subshell execution.",
        "nist": {
            "control_id": "PR.PS-01",
            "category": "Protect: Platform Security",
            "description": "Platform mechanisms prevent unauthorized operating system command execution."
        },
        "iso": {
            "control_id": "A.8.28",
            "category": "Technological Controls",
            "title": "Secure Coding",
            "description": "Secure coding practices eliminate OS command injection vectors."
        },
        "soc2": {
            "criteria_id": "CC6.8",
            "principle": "Malware & Threat Defense",
            "description": "Controls restrict unauthorized execution of operating system commands."
        },
        "wstg": {
            "test_id": "WSTG-INPV-12",
            "title": "Testing for Command Injection",
            "category": "Input Validation Testing"
        },
        "pci": {
            "requirement_id": "6.2.4",
            "title": "Software Development Vulnerability Defenses",
            "description": "Software is developed to prevent operating system command injection flaws."
        }
    }
}

# Generic fallback mapping for any unlisted CWE
DEFAULT_FALLBACK_MAPPING = {
    "name": "Security Control Weakness",
    "domain": "Application Security & Defensive Architecture",
    "control_gap": "Identified weakness in application logic or security configuration requiring baseline hardening.",
    "technical_root_cause": "Insufficient security controls or defensive verification in application architecture, allowing behavior outside baseline security requirements.",
    "remediation": "Apply standard secure coding practices and defensive architecture patterns to address the identified vulnerability class. Implement strict input validation, least-privilege access, and defense-in-depth controls.",
    "mitigation": "Enforce web application firewall inspection, principle of least privilege, and comprehensive logging across the target component.",
    "siem_detection": "Monitor application event logs and web traffic for anomalies or unexpected request parameters related to this endpoint.",
    "developer_validation": "Develop automated unit and regression test cases verifying that inputs violating security specifications are safely handled without application failure.",
    "nist": {
        "control_id": "PR.PS-01",
        "category": "Protect: Platform Security",
        "description": "Applications are maintained and secured in alignment with secure engineering practices."
    },
    "iso": {
        "control_id": "A.8.28",
        "category": "Technological Controls",
        "title": "Secure Coding",
        "description": "Secure coding practices are enforced across the software engineering lifecycle."
    },
    "soc2": {
        "criteria_id": "CC6.6",
        "principle": "Logical Access Boundaries",
        "description": "The entity deploys security defenses to protect systems against operational vulnerabilities."
    },
    "wstg": {
        "test_id": "WSTG-INPV-01",
        "title": "General Web Application Security Testing",
        "category": "Application Security Testing"
    },
    "pci": {
        "requirement_id": "6.2.4",
        "title": "Software Development Vulnerability Defenses",
        "description": "Software is engineered to eliminate common security flaws prior to deployment."
    }
}

def extract_cwe_id(text: Optional[str]) -> Optional[str]:
    """Extracts standard CWE identifier (e.g., 'CWE-89') from freeform string."""
    if not text:
        return None
    match = re.search(r"\b(CWE-\d+)\b", str(text).upper())
    if match:
        return match.group(1)
    num_match = re.search(r"\b(\d{2,4})\b", str(text))
    if num_match:
        cand = f"CWE-{num_match.group(1)}"
        if cand in CWE_FRAMEWORK_CATALOG:
            return cand
    return None


# Authoritative structured remediation and business impact guidance
STRUCTURED_GUIDANCE_BY_CWE: Dict[str, Dict[str, str]] = {
    "CWE-89": {
        "business_impact": "Unauthorized extraction, modification, or deletion of backend database records, potentially compromising confidential customer data, financial transactions, and administrative credentials, leading to significant compliance exposure under data protection laws.",
        "defense_in_depth": "Enforce strict least-privilege database user permissions, run database instances in isolated private subnets with egress filtering, and deploy continuous database activity monitoring (DAM).",
        "root_problem": "Untrusted user input is incorporated directly into database query statements via dynamic string interpolation without parameterized binding.",
        "required_code_change": "Replace dynamic string concatenation with parameterized SQL queries, prepared statements, or ORM parameter binding.",
        "security_control": "Enforce strict separation between executable query code and user-supplied data at the database driver boundary.",
        "implementation_guidance": "Bind all variables using parameterized interfaces (e.g., db.query('SELECT * FROM users WHERE id = ?', [id])). Never build SQL statements with string formatting.",
        "regression_testing": "Submit benign inputs, malformed syntax, and SQL metacharacters (' OR 1=1--, sleep()). Confirm query semantics do not change and syntax errors are suppressed."
    },
    "CWE-79": {
        "business_impact": "Execution of arbitrary client-side JavaScript within authenticated victim sessions, enabling session hijacking, sensitive document and token theft, unauthorized state-changing actions, or client portal defacement.",
        "defense_in_depth": "Deploy a restrictive Content Security Policy (CSP) with nonce-based script whitelisting ('default-src \'self\''), set HttpOnly and SameSite=Lax/Strict on session cookies, and enable X-Content-Type-Options: nosniff.",
        "root_problem": "Untrusted user input reaches the browser rendering context without contextual output encoding or safe sanitization.",
        "required_code_change": "Implement context-aware HTML entity and attribute encoding before reflecting user-supplied content into web pages or DOM elements.",
        "security_control": "Neutralize executable client-side markup before browser interpretation and rendering.",
        "implementation_guidance": "Use established contextual encoding libraries (e.g., DOMPurify for client-side HTML or framework auto-escaping in React/Angular/Vue). Never use dangerouslySetInnerHTML or unescaped template tags.",
        "regression_testing": "Submit payloads containing <script>, <img onerror>, and event handlers. Verify responses are safely entity-encoded and cannot execute in the browser DOM."
    },
    "CWE-639": {
        "business_impact": "Horizontal or vertical privilege escalation allowing unauthorized actors to view, tamper with, or delete sensitive records, user profiles, or transactional orders belonging to other accounts.",
        "defense_in_depth": "Adopt indirect reference maps (session-scoped random tokens) or UUIDv4 identifiers, and deploy centralized Policy Enforcement Point (PEP) middleware across all API endpoints.",
        "root_problem": "The application retrieves or modifies sensitive resources based on client-controlled identifiers without verifying authenticated session ownership.",
        "required_code_change": "Enforce server-side object-level ownership authorization before querying, updating, or returning the requested record.",
        "security_control": "Authorize resource access based on authenticated session context rather than client-supplied keys.",
        "implementation_guidance": "Derive the user ID from the verified server-side session or JWT claims. Query records using compound constraints (e.g., WHERE id = :id AND user_id = :auth_user_id). Return HTTP 403 Forbidden or 404 Not Found on ownership failure.",
        "regression_testing": "Execute cross-tenant access tests: User A requests User B's record ID and assert HTTP 403 Forbidden. Verify legitimate owners retain normal access."
    },
    "CWE-918": {
        "business_impact": "Exploitation of server trust relationships to pivot into internal networks, query cloud metadata endpoints (e.g., AWS 169.254.169.254), or access unauthenticated internal microservices and databases.",
        "defense_in_depth": "Isolate outbound network routing with strict egress firewall rules, disable HTTP redirect following on backend HTTP clients, and require IMDSv2 with session token headers.",
        "root_problem": "The server fetches remote resources using user-supplied URLs without restricting destination IP addresses or network ranges.",
        "required_code_change": "Validate and resolve user-supplied URLs against an allowlist, explicitly blocking private, loopback, and link-local IP ranges.",
        "security_control": "Prevent application servers from initiating requests to internal, non-routable, or sensitive cloud infrastructure addresses.",
        "implementation_guidance": "Resolve destination hostnames to IP addresses before initiating connections; abort connections targeting RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback (127.0.0.0/8), or link-local (169.254.0.0/16) ranges.",
        "regression_testing": "Submit requests targeting http://127.0.0.1, http://169.254.169.254, and internal hostnames. Confirm requests are blocked with an invalid destination error."
    },
    "CWE-287": {
        "business_impact": "Unauthorized access to user accounts, administrative interfaces, and sensitive customer functionality without supplying legitimate authentication credentials.",
        "defense_in_depth": "Implement continuous session anomaly detection, enforce device fingerprinting, and apply IP-based rate limiting on authentication routes.",
        "root_problem": "Authentication completion and credential verification states are not enforced server-side before granting privileged session access.",
        "required_code_change": "Enforce rigorous server-side authentication state validation; invalidate unauthenticated requests and issue secure session tokens only upon successful credential verification.",
        "security_control": "Verify identity credentials on the server before establishing authenticated session boundaries.",
        "implementation_guidance": "Use standard cryptographic password hashing (Argon2id, bcrypt with cost >= 12), validate session tokens server-side on every request, and deny access on unauthenticated routes.",
        "regression_testing": "Submit requests with omitted, malformed, or expired authentication tokens. Assert HTTP 401 Unauthorized."
    },
    "CWE-288": {
        "business_impact": "Bypass of primary authentication or multi-factor authentication (MFA/2FA), permitting attackers to compromise accounts despite two-factor protection.",
        "defense_in_depth": "Implement step-up authentication for high-risk operations, log all authentication stage transitions, and alert on out-of-order authentication attempts.",
        "root_problem": "The application permits access to authenticated routes via alternative endpoints or flawed logic without completing required 2FA verification.",
        "required_code_change": "Enforce server-side authentication stage progression; require validated 2FA before issuing the final authenticated session.",
        "security_control": "Ensure multi-factor verification cannot be circumvented through alternative routes or client-manipulated parameters.",
        "implementation_guidance": "Issue temporary pre-auth tokens restricted strictly to the 2FA verification route; upgrade to full session credentials only upon successful OTP/FIDO2 verification.",
        "regression_testing": "Test direct access to protected endpoints with valid credentials but omitted/invalid 2FA. Assert access is denied until 2FA completes."
    },
    "CWE-22": {
        "business_impact": "Unauthorized reading of sensitive operating system files (/etc/passwd, win.ini), application source code, configuration files, or database credentials.",
        "defense_in_depth": "Execute application processes in a sandboxed chroot jail or container with read-only root filesystems and minimal file permissions.",
        "root_problem": "User-supplied file paths or filenames containing directory traversal sequences (../ or ..\\) are resolved without containment validation.",
        "required_code_change": "Canonicalize resolved paths and verify they reside strictly within the designated base storage directory.",
        "security_control": "Enforce strict filesystem path containment for all file lookup operations.",
        "implementation_guidance": "Use canonical path resolution (e.g., Path.resolve() in Python/Node.js) and verify that resolved_path.startswith(base_dir). Alternatively, map file keys to server-managed identifiers.",
        "regression_testing": "Submit path traversal sequences (../../etc/passwd, %2e%2e%2f). Confirm requests are rejected and files outside the base directory are inaccessible."
    },
    "CWE-434": {
        "business_impact": "Remote code execution via uploaded server-executable scripts (.jsp, .php, .asp) or stored cross-site scripting via uploaded SVG/HTML files, leading to full server compromise.",
        "defense_in_depth": "Store uploaded files on an isolated domain (e.g., dedicated S3 bucket) with execution permissions disabled (noexec mount) and serve with Content-Disposition: attachment.",
        "root_problem": "The application accepts file uploads without verifying file extensions, MIME types, or binary contents on the server side.",
        "required_code_change": "Implement server-side file extension allowlisting, binary magic-byte inspection, and randomized storage filenames.",
        "security_control": "Ensure uploaded files cannot be executed or interpreted as executable code by the web server.",
        "implementation_guidance": "Validate extensions against a strict allowlist (e.g., .png, .jpg, .pdf). Verify file headers match the expected MIME type. Store files outside the web root with generated UUID filenames.",
        "regression_testing": "Attempt uploads of executable files (.php, .jsp, .exe, .svg with scripts, double extensions like shell.php.jpg). Verify uploads are rejected or stored safely as inert binaries."
    },
    "CWE-524": {
        "business_impact": "Exposure of sensitive credentials or payment card details on shared or public workstations via browser autocomplete cache.",
        "defense_in_depth": "Enforce short idle session timeouts and clear sensitive fields from the DOM upon form submission.",
        "root_problem": "Sensitive password or cardholder input fields do not explicitly disable browser caching or autocomplete.",
        "required_code_change": "Add autocomplete='off' or autocomplete='new-password' attributes and Cache-Control: no-store headers on sensitive forms.",
        "security_control": "Prevent browser caching and credential persistence on client devices.",
        "implementation_guidance": "Set autocomplete='current-password' or autocomplete='off' on sensitive form fields, and return Cache-Control: no-store, no-cache, must-revalidate on sensitive pages.",
        "regression_testing": "Verify HTML markup contains appropriate autocomplete attributes and HTTP response headers include Cache-Control: no-store."
    },
    "CWE-204": {
        "business_impact": "Enables attackers to map valid user accounts, email addresses, or phone numbers to target in credential stuffing or phishing campaigns.",
        "defense_in_depth": "Enforce uniform response timing and CAPTCHA challenges on public registration and password recovery endpoints.",
        "root_problem": "The application returns observable differences in response messages or status codes when an account exists versus when it does not.",
        "required_code_change": "Standardize response messages, HTTP status codes, and execution timing across existing and non-existing accounts.",
        "security_control": "Prevent differentiation of valid versus invalid accounts through application responses.",
        "implementation_guidance": "Return a uniform message for password reset and registration (e.g., 'If an account exists with that email, instructions have been sent').",
        "regression_testing": "Submit password reset requests for valid and invalid accounts; assert that response status, message, and response time are indistinguishable."
    },
    "CWE-307": {
        "business_impact": "Account takeover via brute-force credential stuffing, password guessing, or SMS/email OTP exhaustion attacks.",
        "defense_in_depth": "Implement progressive delays, CAPTCHA challenges after failed attempts, and account lockout policies.",
        "root_problem": "Authentication and verification endpoints lack throttling on repeated requests.",
        "required_code_change": "Implement IP and account-based rate limiting on all authentication and sensitive endpoints.",
        "security_control": "Restrict the frequency of authentication attempts from any single client or against any single account.",
        "implementation_guidance": "Use distributed in-memory token-bucket rate limiters (e.g., Redis). Return HTTP 429 Too Many Requests with a Retry-After header.",
        "regression_testing": "Send bursts of 50+ rapid authentication attempts. Verify that requests beyond the limit receive HTTP 429."
    },
    "CWE-384": {
        "business_impact": "Session hijacking if an attacker pre-sets a known session ID in a victim's browser and waits for the victim to authenticate.",
        "defense_in_depth": "Enforce cookie security flags (Secure, HttpOnly, SameSite=Strict) and short absolute session lifetimes.",
        "root_problem": "The application does not regenerate the session identifier upon successful user authentication.",
        "required_code_change": "Invalidate the pre-authentication session identifier and issue a newly generated session ID upon login.",
        "security_control": "Ensure session tokens established prior to authentication cannot be used post-authentication.",
        "implementation_guidance": "Call session.regenerate() or session.invalidate() immediately upon successful credential validation before setting auth flags.",
        "regression_testing": "Record the session cookie before login; authenticate successfully; verify that the session cookie value has changed."
    },
    "CWE-352": {
        "business_impact": "Enables unauthorized state-changing actions (password changes, profile updates, fund transfers) triggered by third-party websites without user consent.",
        "defense_in_depth": "Set SameSite=Lax or SameSite=Strict on session cookies and require re-authentication for sensitive actions.",
        "root_problem": "State-changing POST/PUT/DELETE requests rely solely on ambient session credentials without an unpredictable anti-CSRF token.",
        "required_code_change": "Implement synchronized anti-CSRF tokens for all state-changing forms and API endpoints.",
        "security_control": "Validate that state-changing requests originate intentionally from the authentic user application.",
        "implementation_guidance": "Issue a cryptographically random, per-session CSRF token in forms or custom headers (X-CSRF-Token) and validate it server-side on every mutative request.",
        "regression_testing": "Submit state-changing requests without the CSRF token or with an invalid token; confirm the server returns HTTP 403 Forbidden."
    },
    "CWE-78": {
        "business_impact": "Complete remote host takeover, arbitrary operating system command execution with web server privileges, and lateral network movement.",
        "defense_in_depth": "Execute processes in restricted containers with minimal binary tools, read-only filesystems, and strict AppArmor/SELinux profiles.",
        "root_problem": "Untrusted user input is passed directly to system shell interpreters (sh, bash, cmd.exe) without parameterization.",
        "required_code_change": "Eliminate shell execution; use native programming language APIs or parameterized process execution without a shell.",
        "security_control": "Prevent untrusted input from modifying operating system process execution arguments.",
        "implementation_guidance": "Use subprocess.run(['command', arg1, arg2], shell=False). Never invoke system commands via string interpolation or with shell=True.",
        "regression_testing": "Submit input containing shell metacharacters (; | & ` $()). Confirm the input is treated as literal data and no secondary commands execute."
    },
    "CWE-798": {
        "business_impact": "Complete compromise of backend infrastructure, third-party services, or database access through reverse-engineered or committed credentials.",
        "defense_in_depth": "Implement automated pre-commit secret scanning (Gitleaks, Trufflehog) in CI/CD pipelines and configure short-lived dynamic credentials.",
        "root_problem": "Cryptographic keys, database passwords, or API tokens are hardcoded into application source files or client-accessible assets.",
        "required_code_change": "Remove hardcoded credentials from source code; load secrets at runtime via environment variables or a dedicated secrets manager.",
        "security_control": "Keep all secret material isolated from application codebases and revision control systems.",
        "implementation_guidance": "Store credentials in a secure key vault (HashiCorp Vault, AWS Secrets Manager) and inject them at startup via environment variables. Immediately rotate exposed keys.",
        "regression_testing": "Run automated secret scanners against source repositories and build artifacts to ensure zero plaintext tokens or keys exist."
    },
    "CWE-601": {
        "business_impact": "Facilitates high-credibility phishing attacks by redirecting users from trusted application domains to malicious external sites.",
        "defense_in_depth": "Display an intermediate redirect warning page when directing users to external domains.",
        "root_problem": "The application redirects users based on unvalidated target URLs passed in request parameters.",
        "required_code_change": "Validate redirect targets against an approved relative path or domain allowlist.",
        "security_control": "Ensure redirection destinations are strictly controlled and verified before issuing HTTP 302 responses.",
        "implementation_guidance": "Only allow relative URLs starting with a single '/' (rejecting '//'). If absolute URLs are needed, validate against a strict domain whitelist.",
        "regression_testing": "Submit external redirect targets (https://evil.com, //evil.com, javascript:). Confirm the application rejects the redirect or redirects to the default home page."
    }
}


def get_vulnerability_guidance(cwe_id: str) -> Dict[str, str]:
    """Returns structured remediation components, defense-in-depth, and business impact for a CWE."""
    cwe_norm = (cwe_id or "").upper().strip()
    if not cwe_norm.startswith("CWE-"):
        num = re.search(r"\d+", cwe_norm)
        cwe_norm = f"CWE-{num.group(0)}" if num else "CWE-693"
    return STRUCTURED_GUIDANCE_BY_CWE.get(cwe_norm, {
        "business_impact": "Potential security boundary degradation, unauthorized data exposure, or control failure impacting the organization's compliance and operational posture.",
        "defense_in_depth": "Enforce principle of least privilege, deploy WAF boundary filtering, and maintain centralized audit logging across the affected service.",
        "root_problem": "Application input validation or access control boundaries do not sufficiently verify untrusted input or state.",
        "required_code_change": "Implement defensive verification logic and enforce strict server-side validation on untrusted parameters.",
        "security_control": "Verify and sanitize all inputs and enforce explicit authorization checks before state transitions.",
        "implementation_guidance": "Adopt standard secure coding patterns, framework-provided defensive controls, and defensive programming libraries.",
        "regression_testing": "Execute automated positive and negative test cases verifying that invalid inputs are handled safely without application failure."
    })

def map_finding_to_grc_frameworks(
    finding: Dict[str, Any],
    is_pci_in_scope: bool = True
) -> Dict[str, Any]:
    """
    Deterministically maps a single finding to NIST CSF 2.0, ISO 27001:2022,
    SOC 2 TSC, OWASP WSTG v4.2, and PCI DSS v4.0 based on its CWE classification,
    title, or test_id.

    Supports conditional PCI DSS scoping: if target environment is not a Cardholder
    Data Environment (CDE), marks PCI DSS as not applicable or out-of-scope.
    """
    cwe_cand = (
        extract_cwe_id(finding.get("cwe")) or
        extract_cwe_id(finding.get("cwe_id")) or
        extract_cwe_id(finding.get("finding_name")) or
        extract_cwe_id(finding.get("description"))
    )

    if not cwe_cand:
        # Check title heuristics
        title_lower = (finding.get("finding_name") or finding.get("title") or "").lower()
        if "sql" in title_lower or "injection" in title_lower:
            cwe_cand = "CWE-89"
        elif "xss" in title_lower or "scripting" in title_lower:
            cwe_cand = "CWE-79"
        elif "idor" in title_lower or "direct object" in title_lower or "bola" in title_lower:
            cwe_cand = "CWE-639"
        elif "ssrf" in title_lower or ("request forgery" in title_lower and "server" in title_lower):
            cwe_cand = "CWE-918"
        elif "upload" in title_lower:
            cwe_cand = "CWE-434"
        elif "traversal" in title_lower or "path" in title_lower:
            cwe_cand = "CWE-22"
        elif "cache" in title_lower or "caching" in title_lower:
            cwe_cand = "CWE-524"
        elif "2fa" in title_lower or "mfa" in title_lower or "two-factor" in title_lower:
            cwe_cand = "CWE-288"
        elif "rate" in title_lower or "brute" in title_lower:
            cwe_cand = "CWE-307"
        elif "redirect" in title_lower:
            cwe_cand = "CWE-601"
        elif "command" in title_lower:
            cwe_cand = "CWE-78"
        elif "csrf" in title_lower:
            cwe_cand = "CWE-352"
        elif "enumeration" in title_lower or "discrepancy" in title_lower:
            cwe_cand = "CWE-204"
        elif "secret" in title_lower or "credential" in title_lower or "api key" in title_lower:
            cwe_cand = "CWE-798"
        elif "auth" in title_lower:
            cwe_cand = "CWE-287"

    is_catalog_match = cwe_cand in CWE_FRAMEWORK_CATALOG
    entry = CWE_FRAMEWORK_CATALOG.get(cwe_cand, DEFAULT_FALLBACK_MAPPING)
    effective_cwe = cwe_cand or "CWE-693"
    effective_cwe_name = entry.get("name", "Protection Mechanism Failure")
    review_status = "CONFIRMED" if is_catalog_match else "REVIEW_REQUIRED"

    # Conditional PCI DSS mapping
    if is_pci_in_scope:
        pci_data = dict(entry["pci"])
        pci_data["applicability"] = "IN_SCOPE"
    else:
        pci_data = {
            "requirement_id": "N/A",
            "title": "Not Applicable",
            "description": "Target environment not identified as a Cardholder Data Environment (CDE). PCI DSS v4.0 controls apply only where cardholder data is processed, stored, or transmitted.",
            "applicability": "OUT_OF_SCOPE"
        }

    guidance = get_vulnerability_guidance(effective_cwe)

    return {
        "cwe_id": effective_cwe,
        "cwe_name": effective_cwe_name,
        "domain": entry["domain"],
        "control_gap": entry["control_gap"],
        "technical_root_cause": entry.get("technical_root_cause", entry["control_gap"]),
        "remediation": entry.get("remediation", ""),
        "mitigation": entry.get("mitigation", ""),
        "defense_in_depth": guidance.get("defense_in_depth", ""),
        "business_impact": guidance.get("business_impact", ""),
        "structured_remediation": {
            "root_problem": guidance.get("root_problem", ""),
            "required_code_change": guidance.get("required_code_change", ""),
            "security_control": guidance.get("security_control", ""),
            "implementation_guidance": guidance.get("implementation_guidance", ""),
            "regression_testing": guidance.get("regression_testing", "")
        },
        "siem_detection": entry.get("siem_detection", ""),
        "developer_validation": entry.get("developer_validation", ""),
        "review_status": review_status,
        "nist": entry["nist"],
        "iso": entry["iso"],
        "soc2": entry["soc2"],
        "wstg": entry["wstg"],
        "pci": pci_data
    }

def aggregate_security_control_gaps(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Groups findings into technical security domains to provide CISOs, auditors,
    and GRC analysts with an executive-level summary of observed control gaps.
    """
    domains: Dict[str, Dict[str, Any]] = {}

    for f in findings:
        grc = f.get("grc_mappings") or map_finding_to_grc_frameworks(f)
        domain = grc.get("domain", "Application Security & Defensive Architecture")
        prio = (f.get("priority") or f.get("severity") or "HIGH").upper()
        vuln_id = f.get("report_vuln_id") or f.get("vuln_id") or f.get("id") or "VULN"

        if domain not in domains:
            domains[domain] = {
                "domain": domain,
                "findings": [],
                "finding_ids": [],
                "control_gap": grc.get("control_gap", ""),
                "max_severity": prio,
                "nist_controls": set(),
                "iso_controls": set(),
                "soc2_controls": set()
            }

        d = domains[domain]
        d["findings"].append(f)
        d["finding_ids"].append(vuln_id)
        d["nist_controls"].add(grc["nist"]["control_id"])
        d["iso_controls"].add(grc["iso"]["control_id"])
        d["soc2_controls"].add(grc["soc2"]["criteria_id"])

        # Track highest severity in domain
        prio_weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0, "INFO": 0}
        if prio_weight.get(prio, 0) > prio_weight.get(d["max_severity"], 0):
            d["max_severity"] = prio

    res = []
    for dname, data in sorted(domains.items(), key=lambda x: len(x[1]["findings"]), reverse=True):
        res.append({
            "domain": dname,
            "count": len(data["findings"]),
            "finding_ids": data["finding_ids"],
            "max_severity": data["max_severity"],
            "control_gap": data["control_gap"],
            "nist_summary": ", ".join(sorted(data["nist_controls"])),
            "iso_summary": ", ".join(sorted(data["iso_controls"])),
            "soc2_summary": ", ".join(sorted(data["soc2_controls"]))
        })
    return res
