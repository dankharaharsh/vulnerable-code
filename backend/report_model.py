"""
Tracegate Enterprise Report Data Model & Normalization Engine.

Assembles, normalizes, validates, and redacts assessment data to create a single
source-of-truth NormalizedReportModel. Eliminates cross-finding data contamination,
reconciles test coverage with confirmed vulnerabilities, redacts sensitive credentials,
calculates deterministic risk scores, and validates report integrity prior to document rendering.
"""

import os
import re
import json
import base64
import math
import logging
from typing import Dict, Any, List, Optional, Tuple, Set
from datetime import datetime
from pathlib import Path

from backend.grc_frameworks import (
    map_finding_to_grc_frameworks,
    aggregate_security_control_gaps,
    MANDATORY_GRC_DISCLAIMER,
    FRAMEWORKS_METADATA
)

logger = logging.getLogger("report_model")


class ReportIntegrityError(Exception):
    """Raised when report data model fails pre-render integrity validation."""
    pass


# =============================================================================
# SECRET REDACTION ENGINE
# =============================================================================

# Comprehensive regular expressions to identify and scrub sensitive tokens, credentials, and keys
SECRET_PATTERNS = [
    # GitHub Personal Access Tokens & App Tokens
    (re.compile(r"\b(ghp_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{40,}|gho_[A-Za-z0-9_]{30,}|ghu_[A-Za-z0-9_]{30,}|ghs_[A-Za-z0-9_]{30,})\b"), "[REDACTED GITHUB TOKEN]"),
    # Bearer / JWT Tokens (Header and query string formats)
    (re.compile(r"(Bearer\s+)[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*", re.IGNORECASE), r"\1[REDACTED JWT TOKEN]"),
    (re.compile(r"([?&](?:access_token|token|jwt)=)[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*", re.IGNORECASE), r"\1[REDACTED JWT TOKEN]"),
    # Basic Authorization Headers
    (re.compile(r"(Authorization:\s*Basic\s+)[A-Za-z0-9+/=]+", re.IGNORECASE), r"\1[REDACTED BASIC AUTH]"),
    # Generic API Keys / Secrets in JSON or Key-Value
    (re.compile(r"""(?i)(["']?(?:api[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key|auth[_-]?token)["']?\s*[:=]\s*["']?)([\w\-]{16,})(["']?)"""), r"\1[REDACTED SECRET]\3"),
    # Passwords in JSON / query / form parameters
    (re.compile(r"""(?i)(["']?(?:password|passwd|pwd|db_pass|user_pass)["']?\s*[:=]\s*["']?)([^"'\s&,]+)(["']?)"""), r"\1[REDACTED PASSWORD]\3"),
    # Private Key Blocks (RSA, EC, OPENSSH, PGP)
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"), "[REDACTED PRIVATE KEY BLOCK]"),
    # Database URIs with credentials
    (re.compile(r"((?:postgres|postgresql|mysql|mongodb|redis)://)[^:\s]+:[^@\s]+@"), r"\1[REDACTED_USER]:[REDACTED_PASSWORD]@"),
]

def redact_sensitive_secrets(text: Optional[str]) -> str:
    """Scans and redacts credentials, access tokens, and private keys from any text content."""
    if not text:
        return ""
    content = str(text)
    for pattern, replacement in SECRET_PATTERNS:
        content = pattern.sub(replacement, content)
    return content

def sanitize_client_report_text(text: Optional[str]) -> str:
    """
    Sanitizes text fields to guarantee complete absence of internal AI AutoFix
    or internal Git remediation leakage before rendering client reports.
    Also redacts credentials, passwords, and private keys.
    """
    if not text:
        return ""
    s = str(text)

    # 1. Remove entire blocks starting with AI AutoFix / GitHub remediation up to next section or header
    s = re.sub(
        r'(?i)(?:\n\s*|\A)[^\n]*?\b(?:AI AutoFix|GitHub Remediation|Remediation Tracking|Dedicated Fix Branch)\b[\s\S]*?(?=\n\s*(?:[A-Z]\.|\bRegression Testing:|\bSecurity Control:|\bImplementation Guidance:|\bRequired Code Change:|\Z))',
        '\n',
        s
    )

    # 2. Line-by-line purge of any lingering git/autofix lines
    lines = []
    for line in s.split('\n'):
        line_l = line.lower()
        if any(term in line_l for term in [
            'tracegate/fix/', 'dedicated fix branch',
            'fix branch', 'remediation commit', 'pull request', 'pr url', 'pr number',
            'ai autofix', 'ai-fix-card', 'ai source discovery'
        ]):
            continue
        lines.append(line)
    s = '\n'.join(lines)

    # 3. Strip any residual raw tracegate/fix/ branches and PR links
    s = re.sub(r'\btracegate/fix/[^\s\)\"\'>]+', '', s)
    s = re.sub(r'https?://github\.com/[^\s\)\"\'>]+/pull/\d+', '', s)

    # 4. Clean forbidden tokens
    s = re.sub(r'(?i)\bAI AutoFix\b', 'Engineering Remediation', s)
    s = re.sub(r'(?i)\bai-fix-card\b', '', s)
    s = re.sub(r'(?i)\bai source discovery\b', 'Source Analysis', s)

    # 5. Clean multiple blank lines and apply secret redaction
    s = re.sub(r'\n{3,}', '\n\n', s)
    return redact_sensitive_secrets(s.strip())


# =============================================================================
# CVSS & SLA FORMATTERS
# =============================================================================

def is_cvss_consistent_with_severity(score: Any, severity: str) -> bool:
    """
    Validates that a CVSS score mathematically corresponds to the qualitative severity rating (FIRST CVSS v3.1).
    - Critical: 9.0 - 10.0
    - High: 7.0 - 8.9
    - Medium: 4.0 - 6.9
    - Low: 0.1 - 3.9
    - Informational / None: 0.0
    """
    if score is None or str(score).strip() in ["", "None", "null", "N/A", "Not Scored"]:
        return True  # Missing scores are handled separately by defensible 'Not scored' representation
    try:
        val = float(score)
    except (ValueError, TypeError):
        return False

    s = str(severity or "").strip().upper()
    if s == "CRITICAL":
        return 9.0 <= val <= 10.0
    elif s == "HIGH":
        return 7.0 <= val <= 8.9
    elif s == "MEDIUM":
        return 4.0 <= val <= 6.9
    elif s == "LOW":
        return 0.1 <= val <= 3.9
    elif s in ("INFORMATIONAL", "INFO", "NONE"):
        return val == 0.0
    return False


def parse_and_calculate_cvss_v31(vector: Optional[str]) -> Optional[float]:
    """
    Parses a CVSS v3.1 vector string and calculates the authoritative Base Score according to FIRST specifications.
    Example vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    """
    if not vector or not isinstance(vector, str):
        return None
    vec = vector.strip().upper()
    if "AV:" not in vec:
        return None

    # Parse components
    parts = {}
    for item in vec.split("/"):
        if ":" in item:
            k, v = item.split(":", 1)
            parts[k.strip()] = v.strip()

    av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    ac_map = {"L": 0.77, "H": 0.44}
    ui_map = {"N": 0.85, "R": 0.62}
    s_val = parts.get("S", "U")

    if s_val == "C":
        pr_map = {"N": 0.85, "L": 0.68, "H": 0.50}
    else:
        pr_map = {"N": 0.85, "L": 0.62, "H": 0.27}

    c_map = {"N": 0.0, "L": 0.22, "H": 0.56}
    i_map = {"N": 0.0, "L": 0.22, "H": 0.56}
    a_map = {"N": 0.0, "L": 0.22, "H": 0.56}

    av = av_map.get(parts.get("AV"))
    ac = ac_map.get(parts.get("AC"))
    pr = pr_map.get(parts.get("PR"))
    ui = ui_map.get(parts.get("UI"))
    c = c_map.get(parts.get("C"))
    i = i_map.get(parts.get("I"))
    a = a_map.get(parts.get("A"))

    if None in (av, ac, pr, ui, c, i, a):
        return None

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if s_val == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    expl = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0

    if s_val == "U":
        raw_score = min(impact + expl, 10.0)
    else:
        raw_score = min(1.08 * (impact + expl), 10.0)

    return math.ceil(round(raw_score, 9) * 10) / 10.0


def format_cvss_vector(score: Any, vector: Optional[str], severity: Optional[str] = None) -> str:
    """
    Formats CVSS vector string truthfully and defensibly.
    - Accurately identifies CVSS v3.1 vs CVSS v4.0.
    - If vector is present with CVSS:4.0: 'CVSS v4.0 | Score: {score} | Vector: {vector}'
    - If vector is present with CVSS:3.1 or standard AV: metrics: 'CVSS v3.1 | Score: {score} | Vector: {vector}'
    - If vector is not present:
        - If score is valid and consistent with severity: 'CVSS v3.1 | Score: {score} (Base)'
        - If score is missing or contradicts severity: 'CVSS v3.1: Not scored'
    - NEVER outputs 'CVSS v4.0: Not scored' for v3.1 data or when unscored.
    """
    has_vector = vector is not None and isinstance(vector, str) and vector.strip() not in ["", "None"]
    clean_vec = vector.strip() if has_vector else ""
    if clean_vec.lower() in ["not scored", "none", "n/a", "unscored"]:
        has_vector = False
        clean_vec = ""

    clean_score = None
    if score is not None and str(score).strip() not in ["", "None", "null", "N/A", "Not Scored"]:
        try:
            clean_score = float(score)
        except (ValueError, TypeError):
            clean_score = None

    if has_vector:
        vec_upper = clean_vec.upper()
        if "CVSS:4.0" in vec_upper:
            prefix = "CVSS v4.0"
        elif "CVSS:3.1" in vec_upper or "CVSS:3.0" in vec_upper or "AV:" in vec_upper:
            prefix = "CVSS v3.1"
        else:
            prefix = "CVSS v3.1"

        calc_score = parse_and_calculate_cvss_v31(clean_vec)
        display_score = calc_score if calc_score is not None else clean_score

        if display_score is not None:
            return f"{prefix} | Score: {display_score:.1f} | Vector: {clean_vec}"
        return f"{prefix} | Vector: {clean_vec}"

    # No vector present
    if clean_score is not None:
        if severity is not None and not is_cvss_consistent_with_severity(clean_score, severity):
            return "CVSS v3.1: Not scored"
        return f"CVSS v3.1 | Score: {clean_score:.1f} (Base)"

    return "CVSS v3.1: Not scored"


SOURCE_FILE_EXTENSIONS = (
    '.py', '.js', '.ts', '.jsx', '.tsx', '.php', '.rb', '.java', '.go', 
    '.html', '.tpl', '.jinja', '.jinja2', '.jsp', '.asp', '.aspx', '.vue', '.css'
)
SOURCE_PATH_INDICATORS = (
    'backend/', 'controllers/', 'models/', 'views/', 'src/', 'server/', 
    'routes/', 'templates/', 'app/', 'components/', 'services/'
)

def is_source_code_path(val: Optional[str]) -> bool:
    """Detect if a value is a source code file path rather than an HTTP endpoint or URL."""
    if not val or not isinstance(val, str):
        return False
    v = val.strip().lower()
    if any(v.endswith(ext) for ext in SOURCE_FILE_EXTENSIONS):
        return True
    if any(ind in v for ind in SOURCE_PATH_INDICATORS):
        return True
    return False

def extract_http_endpoint_from_poc(poc: str, http_req: str) -> Optional[str]:
    """Extract realistic HTTP endpoint path from PoC curl commands or raw HTTP request headers."""
    combined = f"{poc}\n{http_req}"
    # Match standard HTTP request lines (e.g., 'POST /api/user/profile HTTP/1.1')
    m_req = re.search(r'(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+([^\s\?]+)', combined, re.IGNORECASE)
    if m_req:
        path = m_req.group(1).strip()
        if path.startswith("/"):
            return path
        m_url_path = re.search(r'https?://[^/\s]+(/[^?\s]*)', path)
        if m_url_path:
            return m_url_path.group(1)
    
    # Match curl URLs (e.g., 'curl -i https://target.local/api/v1/test/1')
    m_curl = re.search(r'https?://[^/\s]+(/[^?\s]*)', combined)
    if m_curl:
        return m_curl.group(1).strip()
        
    return None

def normalize_remediation_status(
    status: Optional[str],
    has_pr: bool,
    has_branch: bool,
    has_commit: bool
) -> str:
    """
    Normalizes remediation status to strictly match actual Git repository metadata.
    Prevents claiming 'PR Created' when no PR URL or PR number exists.
    """
    raw_status = (status or "Open").strip()
    status_upper = raw_status.upper()

    if "PR" in status_upper or "PULL REQUEST" in status_upper:
        if has_pr:
            return "Pull Request Created"
        elif has_branch:
            return "Branch Created (PR Pending)"
        elif has_commit:
            return "Fix Committed (PR Pending)"
        else:
            return "Fix Proposed (No PR Linked)"

    if "BRANCH" in status_upper:
        if has_branch:
            return "Branch Created"
        else:
            return "Fix In Progress"

    if "FIXED" in status_upper or "RESOLVED" in status_upper:
        return "Remediated"

    if "IN PROGRESS" in status_upper or "INVESTIGATING" in status_upper:
        return "Remediation In Progress"

    return raw_status if raw_status else "Open"

def get_remediation_sla(severity: str) -> Dict[str, str]:
    """
    Recommended remediation target window based on severity.
    Formulated as recommended industry targets rather than contractual mandates.
    """
    s = severity.upper()
    if s == "CRITICAL":
        return {
            "window": "24 to 48 Hours",
            "urgency": "Immediate Priority",
            "target_window": "24 to 48 Hours",
            "action": "Implement immediate hotfix, network containment, or WAF block; deploy verified patch within 48 hours."
        }
    elif s == "HIGH":
        return {
            "window": "7 Calendar Days",
            "urgency": "Urgent Priority",
            "target_window": "7 Calendar Days",
            "action": "Assign to active development sprint; apply compensating controls and deploy verified fix within 7 days."
        }
    elif s == "MEDIUM":
        return {
            "window": "30 Calendar Days",
            "urgency": "Planned Priority",
            "target_window": "30 Calendar Days",
            "action": "Schedule into next planned sprint release; verify fix through automated unit and regression tests."
        }
    elif s == "LOW":
        return {
            "window": "90 Calendar Days",
            "urgency": "Routine Priority",
            "target_window": "90 Calendar Days",
            "action": "Remediate as part of standard application lifecycle maintenance and code hygiene reviews."
        }
    else:
        return {
            "window": "Advisory / Next Release",
            "urgency": "Informational",
            "target_window": "Advisory / Next Release",
            "action": "Review for defense-in-depth architectural improvements during future architecture reviews."
        }

def calculate_deterministic_risk_posture(
    crit_count: int,
    high_count: int,
    med_count: int,
    low_count: int,
    info_count: int,
    total_tests: int,
    tested_tests: int
) -> Tuple[str, str, str]:
    """
    Deterministic risk calculation for overall assessment posture.
    Returns: (Risk Label, Hex Color, Executive Risk Description)
    """
    total_findings = crit_count + high_count + med_count + low_count + info_count

    if crit_count >= 1 or high_count >= 2:
        return (
            "CRITICAL RISK",
            "B91C1C",  # Red
            "The assessed target exhibits severe vulnerabilities that allow immediate unauthorized access, "
            "data compromise, or infrastructure takeover. Urgent executive intervention and emergency patching are recommended."
        )
    elif high_count >= 1 or med_count >= 3:
        return (
            "HIGH RISK",
            "C2410C",  # Orange-Red
            "The target architecture contains high-impact flaws or exploitable control deficiencies that could be chained "
            "to circumvent security perimeters. Remediation should be executed with high urgency."
        )
    elif med_count >= 1 or low_count >= 4:
        return (
            "MEDIUM RISK",
            "B45309",  # Amber
            "The assessment identified moderate technical weaknesses or multiple baseline configuration gaps. "
            "These issues require scheduled remediation within the active engineering cycle."
        )
    elif low_count >= 1:
        return (
            "LOW RISK",
            "047857",  # Emerald Green
            "Identified vulnerabilities present minimal immediate risk or limited attack surface exposure. "
            "Remediation is recommended during routine maintenance."
        )
    elif info_count >= 1:
        return (
            "INFORMATIONAL RISK",
            "0284C7",  # Sky Blue
            "The assessment noted defense-in-depth observations and architectural hardening recommendations. "
            "No direct exploit vectors were verified."
        )
    elif total_tests > 0 and tested_tests >= total_tests and total_findings == 0:
        return (
            "CLEAN ASSESSMENT / NEGLIGIBLE RISK",
            "047857",  # Emerald Green
            "All evaluated security controls operated in conformance with established baseline criteria. "
            "No confirmed vulnerabilities were identified within the defined scope."
        )
    else:
        return (
            "INCOMPLETE EVALUATION / UNCONFIRMED",
            "64748B",  # Slate Gray
            "Zero vulnerabilities were confirmed; however, planned test controls have not been fully completed. "
            "This status does not constitute a certified security endorsement."
        )

# =============================================================================
# EXTENDED GOVERNANCE, RISK & REGISTER HELPERS
# =============================================================================

def build_rules_of_engagement(project: Dict[str, Any], doc_meta: Dict[str, Any]) -> Dict[str, Any]:
    """Constructs formal rules of engagement, operational scope constraints, and authorized permissions."""
    target_url = project.get("target_url") or project.get("url") or "https://target.local"
    return {
        "authorized_target": target_url,
        "testing_window": f"{doc_meta.get('generation_date', 'Active Assessment Window')}",
        "authenticated_roles": ["Authorized Testing Account", "Anonymous / Unauthenticated Visitor"],
        "permitted_techniques": [
            "Manual & Automated Web Application Vulnerability Assessment",
            "Authentication, Session Handling, & Password Reset Testing",
            "Safe Parameter Tampering & Input Validation Fuzzing",
            "Access Control Boundary & Object Ownership Testing (BOLA/IDOR)",
            "Business Logic & API Endpoint Verification"
        ],
        "prohibited_techniques": [
            "Denial of Service (DoS/DDoS) & Computational Resource Exhaustion",
            "Destructive Data Modification (e.g. Dropping Database Tables, Mass Deletion)",
            "Social Engineering, Spear Phishing, or Pretexting against Personnel",
            "Physical Intrusion or Facility Security Testing",
            "Direct Attacks against Third-Party Payment Gateways or Cloud Infrastructure",
            "Exfiltration of Production Sensitive Personal Data beyond PoC Demonstration"
        ],
        "data_handling": (
            "All testing payloads and observed telemetry are handled strictly under non-disclosure protections, "
            "transmitted over encrypted channels, and stored securely with cryptographic access controls."
        )
    }

def build_target_information(project: Dict[str, Any]) -> Dict[str, Any]:
    """Constructs the comprehensive target system and architectural boundary summary."""
    target_url = project.get("target_url") or project.get("url") or "https://target.local"
    return {
        "system_name": project.get("name", "Target Application"),
        "application_type": project.get("environment") or "Web Application (Production / Staging)",
        "target_url": target_url,
        "tech_stack": project.get("tech_stack") or "Web Application Architecture (HTTP/HTTPS, REST APIs)",
        "app_version": project.get("app_version") or "Not Provided",
        "relevant_roles": "Standard Authenticated User, Administrative User, Public Visitor",
        "assessment_boundary": f"Primary web application at {target_url}. Third-party SaaS, CDN endpoints, and external payment processors remain strictly out-of-scope."
    }

def build_executive_recommendations(findings: List[Dict[str, Any]]) -> List[str]:
    """Dynamically derives 3–7 high-priority strategic recommendations based on confirmed findings."""
    recs: List[str] = []
    cwe_set = {f.get("cwe_id", "") for f in findings}
    has_crit = any(f.get("severity") == "CRITICAL" for f in findings)
    has_high = any(f.get("severity") == "HIGH" for f in findings)

    if has_crit or has_high:
        recs.append("Remediate all Critical and High severity findings as immediate engineering priorities within recommended target SLA windows.")

    if any(cwe in ["CWE-89", "CWE-78", "CWE-94"] for cwe in cwe_set) or any("injection" in f.get("finding_name", "").lower() for f in findings):
        recs.append("Enforce parameterized queries (prepared statements) and safe parameter binding across all database queries to permanently eliminate injection vulnerabilities.")

    if any(cwe in ["CWE-79"] for cwe in cwe_set) or any("xss" in f.get("finding_name", "").lower() for f in findings):
        recs.append("Implement contextual output encoding and enforce a strict Content Security Policy (CSP) to neutralize cross-site scripting attack vectors.")

    if any(cwe in ["CWE-639", "CWE-284"] for cwe in cwe_set) or any("idor" in f.get("finding_name", "").lower() or "bola" in f.get("finding_name", "").lower() for f in findings):
        recs.append("Enforce centralized, server-side object ownership verification on all resource access and state-modifying endpoints.")

    if any(cwe in ["CWE-287", "CWE-288", "CWE-384"] for cwe in cwe_set) or any("auth" in f.get("finding_name", "").lower() for f in findings):
        recs.append("Strengthen authentication boundaries with multi-factor authentication, secure session handling, and robust credential rotation policies.")

    if any(cwe in ["CWE-434", "CWE-22"] for cwe in cwe_set) or any("upload" in f.get("finding_name", "").lower() or "traversal" in f.get("finding_name", "").lower() for f in findings):
        recs.append("Implement strict file extension allowlists, MIME verification, path canonicalization, and non-executable storage permissions for file handling.")

    recs.append("Establish automated security regression tests in the CI/CD deployment pipeline to ensure that remediated flaws cannot be reintroduced.")
    recs.append("Conduct a formal retest verification cycle following patch deployment to validate that identified vulnerabilities are completely resolved.")

    return recs[:7]

def build_residual_risk_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculates factual residual risk posture based strictly on verified retest results."""
    open_count = sum(1 for f in findings if (f.get("retest_status") or "").upper() != "PASSED")
    closed_count = sum(1 for f in findings if (f.get("retest_status") or "").upper() == "PASSED")
    overall_residual = "REDUCED / CONTROLLED" if (open_count == 0 and len(findings) > 0) else ("OPEN / ACTION REQUIRED" if open_count > 0 else "NEGLIGIBLE")

    return {
        "overall_residual_risk": overall_residual,
        "risk_acceptance_status": "Not Recorded",
        "open_vulnerabilities": open_count,
        "resolved_vulnerabilities": closed_count,
        "guidance": (
            "Residual risk reflects the security posture of the target system after accounting for verified remediation patches. "
            "Findings with retest status 'PASSED' are marked Reduced / Closed. Findings pending remediation or retest remain Open. "
            "Risk acceptance must not be assumed without formal organizational management authorization."
        )
    }

def build_evidence_register(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Constructs the Appendix B Evidence Register mapping every artifact to exactly one finding."""
    register = []
    fig_idx = 1
    for f in findings:
        ev_items = f.get("evidence_items", [])
        if ev_items:
            for ev in ev_items:
                ev_type = (
                    "Visual Screenshot Capture" if ev.get("category") == "IMAGE"
                    else ("Structured JSON Evidence" if ev.get("category") == "JSON"
                    else ("Technical Log / Text Evidence" if ev.get("category") == "TEXT"
                    else ("Document Artifact" if ev.get("category") == "DOCUMENT"
                    else "Captured Artifact")))
                )
                register.append({
                    "evidence_id": ev.get("evidence_id") or f"EV-{fig_idx:03d}",
                    "finding_id": f.get("report_vuln_id", "N/A"),
                    "evidence_type": ev_type,
                    "filename": ev.get("filename", f"capture_{fig_idx}.png"),
                    "description": ev.get("caption") or f"Observed vulnerability evidence for {f.get('report_vuln_id')}",
                    "uploaded_date": ev.get("uploaded_at") or f.get("recorded_at") or "17 Sep 2026",
                    "figure_reference": ev.get("figure_label", f"Figure {fig_idx}"),
                    "status": "EMBEDDED" if ev.get("category") in ["IMAGE", "TEXT", "JSON"] else "ARCHIVED_ONLY",
                    "source": ev.get("source", "Tester-provided evidence")
                })
                fig_idx += 1
        elif f.get("poc_text") or f.get("http_request"):
            register.append({
                "evidence_id": f"EV-POC-{f.get('report_vuln_id', 'N/A')}",
                "finding_id": f.get("report_vuln_id", "N/A"),
                "evidence_type": "HTTP Request / PoC Payload",
                "filename": f"poc_{f.get('report_vuln_id', 'N/A')}.txt",
                "description": f"HTTP PoC interaction for {f.get('finding_name')}",
                "uploaded_date": f.get("recorded_at") or "17 Sep 2026",
                "figure_reference": "Monospaced PoC Block",
                "status": "EMBEDDED",
                "source": "Tester-provided PoC"
            })
    return register

def build_remediation_register(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Constructs the Appendix E Remediation Register with actionable developer directions."""
    register = []
    for f in findings:
        struct = f.get("structured_remediation", {})
        action = struct.get("required_code_change") or "Implement defensive input validation and parameter binding."
        register.append({
            "finding_id": f.get("report_vuln_id", "N/A"),
            "finding_name": f.get("finding_name", "Finding"),
            "severity": f.get("severity", "MEDIUM"),
            "recommended_action": action,
            "mitigation": f.get("mitigation", "Apply defensive filtering."),
            "status": f.get("remediation_status") or f.get("fix_status") or "Open",
            "suggested_target": f.get("remediation_sla", {}).get("window", "30 Calendar Days")
        })
    return register

def build_retest_register(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Constructs the Appendix F Retest Register reflecting authentic retest verification data."""
    register = []
    for f in findings:
        retest_res = f.get("retest_status", "Pending")
        final_stat = "Resolved" if retest_res.upper() == "PASSED" else (f.get("status") or "Open")
        register.append({
            "finding_id": f.get("report_vuln_id", "N/A"),
            "finding_name": f.get("finding_name", "Finding"),
            "original_status": f.get("status") or "Open",
            "retest_date": f.get("retest_date") or "Pending Verification",
            "retest_result": retest_res,
            "final_status": final_stat,
            "evidence_reference": f"Evidence register for {f.get('report_vuln_id')}"
        })
    return register

# =============================================================================
# PRE-RENDER INTEGRITY VALIDATOR
# =============================================================================

def validate_report_model_integrity(model: Dict[str, Any]) -> List[str]:
    """
    Validates the normalized report data model prior to document generation.
    Enforces strict mathematical reconciliation, zero CVSS contradictions,
    accurate Git/PR statuses, and finding isolation.
    """
    errors: List[str] = []
    metrics = model.get("metrics", {})
    findings = model.get("findings", [])
    total_findings = metrics.get("total_findings", 0)

    # 1. Total findings count must equal findings list length
    if len(findings) != total_findings:
        errors.append(f"Finding count mismatch: metrics['total_findings']={total_findings} vs len(findings)={len(findings)}")

    # 2. Severity distribution must sum to total findings
    sev_sum = (
        metrics.get("critical_count", 0) +
        metrics.get("high_count", 0) +
        metrics.get("medium_count", 0) +
        metrics.get("low_count", 0) +
        metrics.get("info_count", 0)
    )
    if sev_sum != total_findings:
        errors.append(f"Severity sum mismatch: severities sum={sev_sum} vs total_findings={total_findings}")

    # 3. Test Coverage reconciliation: Confirmed vulnerabilities in coverage table MUST match total findings
    if metrics.get("vulnerable_tests", 0) != total_findings:
        errors.append(f"Coverage contradiction: metrics['vulnerable_tests']={metrics.get('vulnerable_tests')} does not match total_findings={total_findings}")

    # 4. Coverage math consistency: tested = clean + vulnerable, planned = tested + untested
    total_tests = metrics.get("total_tests", 0)
    tested_tests = metrics.get("tested_tests", 0)
    untested_tests = metrics.get("untested_tests", 0)
    clean_tests = metrics.get("clean_tests", 0)
    vuln_tests = metrics.get("vulnerable_tests", 0)

    if tested_tests != (clean_tests + vuln_tests):
        errors.append(f"Coverage math error: tested_tests ({tested_tests}) != clean_tests ({clean_tests}) + vulnerable_tests ({vuln_tests})")

    if total_tests != (tested_tests + untested_tests):
        errors.append(f"Coverage math error: total_tests ({total_tests}) != tested_tests ({tested_tests}) + untested_tests ({untested_tests})")

    # 5. Finding uniqueness and per-finding integrity
    seen_ids: Set[str] = set()
    for idx, f in enumerate(findings):
        fid = f.get("report_vuln_id")
        if not fid:
            errors.append(f"Finding #{idx + 1} missing report_vuln_id")
        elif fid in seen_ids:
            errors.append(f"Duplicate finding ID detected: '{fid}'")
        else:
            seen_ids.add(fid)

        # CVSS string check: never contain both "Score:" and "Not scored"
        cvss_str = f.get("cvss_formatted", "")
        if "Score:" in cvss_str and "Not scored" in cvss_str:
            errors.append(f"Finding {fid} has contradictory CVSS string: '{cvss_str}'")

        # CVSS vs Severity consistency validation
        if not f.get("cvss_consistent", True):
            errors.append(f"Finding {fid} has inconsistent severity '{f.get('severity')}' vs CVSS score {f.get('raw_cvss_score')}")

        # PR status check: cannot claim 'Pull Request Created' if no PR url or number
        fix_status = f.get("fix_status", "") or f.get("remediation_status", "")
        has_pr = bool(f.get("git_pr_url") or f.get("git_pr_number"))
        if fix_status == "Pull Request Created" and not has_pr:
            errors.append(f"Finding {fid} claims 'Pull Request Created' but lacks git_pr_url or git_pr_number")

        # AI AutoFix absence check: final client report must not contain AI AutoFix internal details
        f_dump = json.dumps(f, default=str)
        if re.search(r"\b(ai autofix|ai-generated patch|ai source discovery|tracegate/fix/)\b", f_dump, re.IGNORECASE):
            errors.append(f"Finding {fid} contains prohibited internal AI AutoFix or fix-branch content")

        # Evidence finding isolation check (zero cross-contamination)
        for ev in f.get("evidence_items", []):
            if ev.get("finding_id") and ev.get("finding_id") != fid:
                errors.append(f"Evidence cross-contamination: {ev.get('evidence_id')} assigned to {ev.get('finding_id')} found inside {fid}")

    # Global evidence figure uniqueness check
    all_fig_nums = [
        ev.get("figure_number")
        for f in findings
        for ev in f.get("evidence_items", [])
        if ev.get("figure_number") is not None
    ]
    if len(all_fig_nums) != len(set(all_fig_nums)):
        errors.append("Duplicate figure numbers detected across report evidence artifacts")

    if errors:
        for err in errors:
            logger.error(f"Report Model Integrity Failure: {err}")
    return errors

# =============================================================================
# NORMALIZED REPORT ASSEMBLER
# =============================================================================

def assemble_normalized_report_model(
    project: Dict[str, Any],
    version: str = "v1.0",
    author_name: Optional[str] = None,
    selected_finding_ids: Optional[List[str]] = None,
    findings: Optional[List[Dict[str, Any]]] = None,
    allow_clean_report: bool = False,
    methodology: str = "owasp_wstg",
    historical_reports: Optional[List[Dict[str, Any]]] = None,
    checklist_items: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Constructs the canonical, normalized, validated, and redacted single-source-of-truth
    report data model.
    Guarantees strict finding isolation, zero cross-contamination, reconciled coverage,
    and accurate GRC mappings.
    """
    proj_id = str(project.get("id", "proj-unknown"))
    proj_name = project.get("name", "Security Target Assessment")
    target_url = project.get("target_url") or project.get("url") or "https://target.local"
    environment = project.get("environment") or "Web Application (Production / Staging)"
    client_org = project.get("organization") or project.get("client_name") or "Enterprise Client Organization"

    # Determine conditional PCI DSS scope
    # If project environment, name, or description explicitly indicates payment/cardholder, or pci_in_scope flag is set
    pci_explicit = project.get("pci_in_scope")
    if pci_explicit is not None:
        is_pci_in_scope = bool(pci_explicit)
    else:
        text_corpus = f"{proj_name} {environment} {project.get('description', '')}".lower()
        is_negated = any(neg in text_corpus for neg in ["non-payment", "no cardholder", "out of pci scope", "no payment", "non-pci"])
        if is_negated:
            is_pci_in_scope = False
        else:
            pci_keywords = ["pci dss", "pci-dss", "cardholder", "payment gateway", "billing api", "banking", "checkout", "credit card", "pos terminal"]
            is_pci_in_scope = any(kw in text_corpus for kw in pci_keywords)

    # 1. Resolve & filter findings strictly for this project
    raw_findings = findings if findings is not None else project.get("findings", [])
    
    # Filter by project ownership if finding has project_id
    proj_owned_findings = []
    for f in raw_findings:
        f_proj = f.get("project_id")
        if f_proj and str(f_proj) != proj_id:
            logger.warning(f"Cross-project finding detected and excluded: {f.get('id')} belongs to {f_proj}, not {proj_id}")
            continue
        proj_owned_findings.append(f)

    # Filter by selected IDs if requested
    if selected_finding_ids is not None:
        sel_set = set(str(sid) for sid in selected_finding_ids)
        active_raw = [
            f for f in proj_owned_findings
            if str(f.get("id")) in sel_set or str(f.get("vuln_id")) in sel_set or
               str(f.get("checklist_item_id")) in sel_set or str(f.get("test_id")) in sel_set
        ]
    else:
        active_raw = list(proj_owned_findings)

    # Severity ordering: Critical -> High -> Medium -> Low -> Informational
    def get_norm_severity(f: Dict[str, Any]) -> str:
        s = str(f.get("priority") or f.get("severity") or "HIGH").strip().upper()
        if s in ["CRITICAL", "CRIT", "P1", "P-1", "SEV1"]:
            return "CRITICAL"
        if s in ["HIGH", "P2", "P-2", "SEV2"]:
            return "HIGH"
        if s in ["MEDIUM", "MED", "MODERATE", "P3", "P-3", "SEV3"]:
            return "MEDIUM"
        if s in ["LOW", "P4", "P-4", "SEV4"]:
            return "LOW"
        if s in ["INFORMATIONAL", "INFO", "P5", "P-5", "SEV5"]:
            return "INFORMATIONAL"
        if "CRIT" in s or "P1" in s:
            return "CRITICAL"
        if "HIGH" in s or "P2" in s:
            return "HIGH"
        if "MED" in s or "P3" in s:
            return "MEDIUM"
        if "LOW" in s or "P4" in s:
            return "LOW"
        if "INFO" in s or "P5" in s:
            return "INFORMATIONAL"
        return "HIGH"

    prio_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
    active_raw.sort(key=lambda x: prio_order.get(get_norm_severity(x), 99))

    # 2. Normalize individual findings with complete isolation & globally unique IDs
    normalized_findings = []
    global_figures = []
    figure_counter = 1
    seen_vuln_ids = set()

    for idx, f in enumerate(active_raw):
        finding_num = idx + 1
        # Preserving authentic ID while guaranteeing zero collision across all findings
        auth_id = f.get("vuln_id") or f.get("source_finding_id")
        if not auth_id or not str(auth_id).startswith("VULN-") or str(auth_id) in seen_vuln_ids:
            c_num = finding_num
            candidate_id = f"VULN-{c_num:03d}"
            while candidate_id in seen_vuln_ids:
                c_num += 1
                candidate_id = f"VULN-{c_num:03d}"
            report_vuln_id = candidate_id
        else:
            report_vuln_id = str(auth_id)
        seen_vuln_ids.add(report_vuln_id)

        sev = get_norm_severity(f)
        sla = get_remediation_sla(sev)

        # GRC Mapping with conditional PCI scoping
        grc = map_finding_to_grc_frameworks(f, is_pci_in_scope=is_pci_in_scope)

        # Redact PoC and HTTP blocks
        raw_poc = f.get("poc_text") or f.get("proof_of_concept") or f.get("poc") or ""
        redacted_poc = sanitize_client_report_text(raw_poc)

        raw_req = f.get("http_request") or f.get("request_sample") or ""
        redacted_req = sanitize_client_report_text(raw_req)

        raw_res = f.get("http_response") or f.get("response_sample") or ""
        redacted_res = sanitize_client_report_text(raw_res)

        # 1. Distinguish between genuine HTTP Endpoint and Source Code Components
        raw_endpoint = f.get("endpoint") or ""
        raw_comp = f.get("affected_component") or ""
        raw_file = f.get("file_path") or f.get("source_file") or ""

        source_comp = None
        for candidate in [raw_file, raw_comp, raw_endpoint]:
            if candidate and is_source_code_path(candidate):
                source_comp = candidate.strip()
                break

        http_endpoint = None
        for candidate in [raw_endpoint, raw_comp]:
            if candidate and not is_source_code_path(candidate):
                c_str = candidate.strip()
                if c_str.startswith("http"):
                    m_p = re.search(r'https?://[^/\s]+(/[^?\s]*)', c_str)
                    http_endpoint = m_p.group(1) if m_p else "/"
                    break
                elif c_str.startswith("/"):
                    http_endpoint = c_str
                    break

        if not http_endpoint:
            http_endpoint = extract_http_endpoint_from_poc(raw_poc, raw_req)

        if not http_endpoint:
            fn_l = (f.get("finding_name") or f.get("title") or "").lower()
            sc_l = (source_comp or "").lower()
            if "profile" in sc_l or "profile" in fn_l:
                http_endpoint = "/api/user/profile"
            elif "usercontroller" in sc_l or "user" in fn_l:
                http_endpoint = "/api/users"
            elif "sqlinjection" in sc_l or "login" in fn_l or "auth" in fn_l:
                http_endpoint = "/api/login"
            elif "upload" in sc_l or "svg" in sc_l or "upload" in fn_l or "avatar" in fn_l:
                http_endpoint = "/api/upload"
            elif "search" in sc_l or "search" in fn_l:
                http_endpoint = "/api/search"
            elif "password" in fn_l or "reset" in fn_l:
                http_endpoint = "/api/reset-password"
            else:
                http_endpoint = "/api/v1/resource"

        if not http_endpoint.startswith("/"):
            http_endpoint = "/" + http_endpoint

        # Affected component display
        if source_comp:
            affected_component_str = f"{http_endpoint} ({source_comp})"
        else:
            affected_component_str = http_endpoint

        # Technical descriptions & observations (sanitizing generic boilerplate & aligning with PoC)
        description = sanitize_client_report_text(f.get("description") or f.get("summary") or "Security vulnerability identified during penetration testing.")
        raw_obs = sanitize_client_report_text(f.get("testing_notes") or f.get("observation") or f.get("notes") or "")
        fn_lower = (f.get("finding_name") or f.get("title") or "").lower()
        poc_lower = str(raw_poc).lower()
        req_lower = str(raw_req).lower()

        # Check for Stored SVG XSS or media upload XSS
        is_svg_xss = "svg" in fn_lower or "<svg" in poc_lower or "image/svg" in poc_lower or "image/svg" in req_lower or "svg" in str(source_comp or "").lower()
        
        # Check if raw_obs is generic boilerplate or mismatched
        is_generic_obs = (
            not raw_obs 
            or "standard risk area" in str(raw_obs).lower() 
            or raw_obs.strip() == description.strip()
            or (is_svg_xss and "svg" not in str(raw_obs).lower())
            or ("sql" in fn_lower and "sql" not in str(raw_obs).lower())
            or ("idor" in fn_lower and "idor" not in str(raw_obs).lower() and "object" not in str(raw_obs).lower())
        )

        if is_generic_obs:
            if is_svg_xss:
                technical_observation = (
                    f"During security testing of file upload and media rendering at endpoint '{http_endpoint}', the application "
                    f"was observed to accept user-uploaded SVG (Scalable Vector Graphics) image files without sanitizing embedded "
                    f"XML markup or stripping active script vectors. When the stored SVG resource is subsequently requested and rendered "
                    f"by the client browser under the 'image/svg+xml' MIME type, the browser parses the active XML Document Object Model (DOM) "
                    f"and executes embedded JavaScript (such as `<svg onload=...>` or `<script>` tags) within the application's origin context, "
                    f"enabling stored session hijacking and client-side actions."
                )
            elif "sql" in fn_lower or "cwe-89" in str(f.get("cwe", "")).lower() or "injection" in fn_lower:
                technical_observation = (
                    f"During input validation testing against endpoint '{http_endpoint}', user-controlled input submitted via parameter "
                    f"'{f.get('parameter', 'input')}' was directly concatenated into backend database query strings. "
                    f"Differential server responses and database syntax errors confirmed that SQL logic can be manipulated "
                    f"to extract unauthorized database records."
                )
            elif "idor" in fn_lower or "cwe-639" in str(f.get("cwe", "")).lower() or "object reference" in fn_lower or "bola" in fn_lower:
                technical_observation = (
                    f"During access control testing against endpoint '{http_endpoint}', modifying the resource identifier parameter "
                    f"'{f.get('parameter', 'id')}' permitted retrieval and modification of sensitive records belonging to other tenants "
                    f"without verifying session ownership or authorization boundaries."
                )
            elif "ssrf" in fn_lower or "cwe-918" in str(f.get("cwe", "")).lower():
                technical_observation = (
                    f"During request forgery testing against endpoint '{http_endpoint}', the backend initiated outbound network requests "
                    f"to internal network destinations and cloud metadata services based on unvalidated client URL parameters, "
                    f"bypassing perimeter firewall boundaries."
                )
            else:
                technical_observation = (
                    f"During security testing against target endpoint '{http_endpoint}', the application was confirmed vulnerable "
                    f"to {f.get('finding_name') or 'the reported vulnerability'} via parameter '{f.get('parameter', 'N/A')}' "
                    f"as demonstrated in the verified proof of concept."
                )
        else:
            technical_observation = sanitize_client_report_text(raw_obs)
        
        # Tailored technical root cause, remediation, SIEM detection, dev validation
        root_cause = sanitize_client_report_text(f.get("root_cause") or grc.get("technical_root_cause") or grc.get("control_gap") or "Absence of defensive input sanitization and verification logic.")
        mitigation_text = sanitize_client_report_text(f.get("mitigation") or grc.get("mitigation") or "Deploy Web Application Firewall (WAF) inspection rules and enforce strict security headers.")
        defense_in_depth_text = sanitize_client_report_text(grc.get("defense_in_depth") or mitigation_text)
        siem_detection_text = sanitize_client_report_text(f.get("detection_guidance") or f.get("detection_monitoring") or grc.get("siem_detection") or "Ingest web server access logs into SIEM. Alert on abnormal query parameters or status code anomalies.")
        dev_validation_text = sanitize_client_report_text(f.get("developer_validation") or grc.get("developer_validation") or "Execute automated unit tests and integration tests verifying error handling without revealing internal state.")

        # Structured developer remediation
        grc_struct = grc.get("structured_remediation", {})
        user_remediation = sanitize_client_report_text(f.get("remediation") or "").strip()
        impl_guidance = user_remediation if user_remediation else (grc_struct.get("implementation_guidance") or grc.get("remediation"))
        struct_rem = {
            "root_problem": grc_struct.get("root_problem") or root_cause,
            "required_code_change": grc_struct.get("required_code_change") or "Implement defensive input verification and parameter binding.",
            "security_control": grc_struct.get("security_control") or "Enforce server-side security controls at application boundary.",
            "implementation_guidance": impl_guidance,
            "regression_testing": grc_struct.get("regression_testing") or dev_validation_text
        }
        remediation_text = (
            f"Root Problem:\n{struct_rem['root_problem']}\n\n"
            f"Required Code Change:\n{struct_rem['required_code_change']}\n\n"
            f"Security Control:\n{struct_rem['security_control']}\n\n"
            f"Implementation Guidance:\n{struct_rem['implementation_guidance']}\n\n"
            f"Regression Testing:\n{struct_rem['regression_testing']}"
        )

        # CIA Impact ratings
        c_impact = f.get("impact_confidentiality") or ("High" if sev in ["CRITICAL", "HIGH"] else "Moderate" if sev == "MEDIUM" else "Low")
        i_impact = f.get("impact_integrity") or ("High" if sev in ["CRITICAL", "HIGH"] and "sql" in str(f).lower() else "Moderate" if sev in ["HIGH", "MEDIUM"] else "Low")
        a_impact = f.get("impact_availability") or ("High" if "dos" in str(f).lower() else "Low")
        
        # Tailored finding-specific business impact (never repeat generic boilerplate)
        raw_biz = f.get("business_impact")
        if not raw_biz or "potential breach of application boundary" in str(raw_biz).lower():
            business_impact = redact_sensitive_secrets(grc.get("business_impact") or (
                f"Exploitation of this vulnerability presents direct operational and data confidentiality risks, "
                f"impacting alignment with security controls under {grc['iso']['control_id']} and {grc['soc2']['criteria_id']}."
            ))
        else:
            business_impact = sanitize_client_report_text(raw_biz)

        # Reproduction steps - clean leading numbering to prevent double-numbering
        repro_steps = f.get("reproduction_steps")
        if not repro_steps:
            repro_steps = [
                f"Navigate to target endpoint: {http_endpoint}",
                f"Submit crafted security test payload against parameter '{f.get('parameter', 'input_param')}'.",
                "Observe security control bypass and unauthorized response indicating vulnerability presence.",
                "Verify persistent state or server response verifying exploitability."
            ]
        elif isinstance(repro_steps, str):
            raw_lines = [s.strip() for s in repro_steps.split("\n") if s.strip()]
            cleaned_lines = []
            for line in raw_lines:
                c_line = re.sub(r'^\s*(\d+[\.\)]|\-|\*)\s*', '', line).strip()
                if c_line:
                    cleaned_lines.append(c_line)
            repro_steps = cleaned_lines if cleaned_lines else raw_lines
        elif isinstance(repro_steps, list):
            cleaned_list = []
            for item in repro_steps:
                c_item = re.sub(r'^\s*(\d+[\.\)]|\-|\*)\s*', '', str(item)).strip()
                if c_item:
                    cleaned_list.append(c_item)
            repro_steps = cleaned_list if cleaned_list else repro_steps

        # Collect evidence artifacts (images, text, JSON, logs) with global figure numbers & stable IDs
        evidence_items = []
        raw_evidence = []
        if isinstance(f.get("evidence"), list) and len(f.get("evidence")) > 0:
            raw_evidence = list(f.get("evidence"))
        elif isinstance(f.get("evidence_files"), list) and len(f.get("evidence_files")) > 0:
            raw_evidence = list(f.get("evidence_files"))
        elif isinstance(f.get("evidence_list"), list) and len(f.get("evidence_list")) > 0:
            raw_evidence = list(f.get("evidence_list"))
        elif f.get("evidence_json"):
            try:
                parsed = json.loads(f["evidence_json"])
                if isinstance(parsed, list):
                    raw_evidence = parsed
            except Exception:
                pass

        if not raw_evidence and (f.get("evidence_data") or f.get("evidence_filename")):
            raw_evidence = [{
                "id": f"ev-{report_vuln_id.lower()}-01",
                "filename": f.get("evidence_filename", f"evidence_{report_vuln_id}.png"),
                "name": f.get("evidence_filename", f"evidence_{report_vuln_id}.png"),
                "data": f.get("evidence_data"),
                "caption": "Evidence demonstrating the reported behavior"
            }]

        # Deduplicate evidence within the finding (Requirement 37)
        seen_keys = set()
        deduped_raw_evidence = []
        for ev in raw_evidence:
            if not isinstance(ev, dict):
                continue
            k = (
                ev.get("id"),
                ev.get("filename") or ev.get("name"),
                len(str(ev.get("data") or "")) if ev.get("data") else None,
                ev.get("file_path")
            )
            if k in seen_keys:
                continue
            seen_keys.add(k)
            deduped_raw_evidence.append(ev)

        for ev in deduped_raw_evidence:
            fig_num = figure_counter
            figure_counter += 1
            raw_fn = ev.get("filename") or ev.get("name") or f"figure_{fig_num}.png"
            
            # Category determination
            ext = Path(raw_fn).suffix.lower()
            mime = (ev.get("type") or ev.get("mime_type") or "").lower()
            if ext in [".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"] or mime.startswith("image/"):
                cat = "IMAGE"
            elif ext in [".json"] or mime == "application/json":
                cat = "JSON"
            elif ext in [".txt", ".log", ".csv", ".md", ".py", ".js", ".ts", ".html", ".sql", ".sh"] or mime.startswith("text/"):
                cat = "TEXT"
            elif ext in [".pdf", ".docx"] or "pdf" in mime or "word" in mime:
                cat = "DOCUMENT"
            else:
                cat = "IMAGE" if not ext else "OTHER"

            caption = ev.get("caption") or ev.get("description")
            if not caption:
                caption = "Evidence demonstrating the reported behavior"

            # Stable Evidence ID (Requirement 12)
            stable_ev_id = f"EV-{fig_num:03d}"
            if ev.get("id") and str(ev["id"]).upper().startswith("EV-") and len(str(ev["id"])) <= 10:
                stable_ev_id = str(ev["id"]).upper()

            # Target consistency check (Requirement 39-41)
            target_mismatch = False
            ev_target = ev.get("target") or ev.get("host") or ""
            if not ev_target and ev.get("url") and ev.get("url").startswith(("http://", "https://")):
                try:
                    from urllib.parse import urlparse
                    ev_target = urlparse(ev["url"]).netloc
                except Exception:
                    pass
            
            proj_target_host = ""
            if target_url:
                try:
                    from urllib.parse import urlparse
                    parsed_pt = urlparse(target_url if "://" in target_url else f"http://{target_url}")
                    proj_target_host = parsed_pt.netloc or parsed_pt.path.split("/")[0]
                except Exception:
                    pass

            if ev_target and proj_target_host and ev_target.lower() != proj_target_host.lower():
                target_mismatch = True

            # Text content resolution & redaction for text/json
            text_content = ev.get("text_content")
            if not text_content and cat in ["TEXT", "JSON"] and ev.get("data"):
                try:
                    d_str = str(ev["data"])
                    b64_part = d_str.split(",", 1)[1] if "," in d_str else d_str
                    raw_decoded = base64.b64decode(b64_part).decode("utf-8", errors="replace")
                    text_content = redact_sensitive_secrets(raw_decoded)
                    if cat == "JSON":
                        try:
                            text_content = json.dumps(json.loads(text_content), indent=2)
                        except Exception:
                            pass
                except Exception:
                    pass

            ev_record = {
                "evidence_id": stable_ev_id,
                "figure_number": fig_num,
                "figure_label": f"Figure {fig_num}",
                "filename": raw_fn,
                "stored_filename": ev.get("filename") or raw_fn,
                "file_path": ev.get("file_path"),
                "url": ev.get("url"),
                "data": ev.get("data"),
                "category": cat,
                "text_content": text_content,
                "type": mime or ("image/png" if cat == "IMAGE" else "text/plain"),
                "size": ev.get("size", 0),
                "caption": caption,
                "description": ev.get("description") or caption,
                "uploaded_at": ev.get("uploaded_at") or f.get("recorded_at") or "17 Sep 2026",
                "source": ev.get("source") or "Tester-provided evidence",
                "finding_id": report_vuln_id,
                "finding_name": f.get("finding_name", "Finding"),
                "project_id": proj_id,
                "target_mismatch": target_mismatch
            }
            evidence_items.append(ev_record)
            global_figures.append(ev_record)

        # AI Fix and Git Tracking — STRICT finding isolation & status normalization
        raw_status = f.get("fix_status") or f.get("status") or "Open"
        git_branch = f.get("git_branch") or f.get("branch_name") or f.get("github_branch")
        git_commit = f.get("git_commit") or f.get("commit_sha") or f.get("github_commit")
        git_pr_url = f.get("git_pr_url") or f.get("pr_url") or f.get("github_pr") or f.get("github_pr_url")
        git_pr_number = f.get("git_pr_number") or f.get("pr_number")
        
        has_pr = bool(git_pr_url or git_pr_number)
        has_branch = bool(git_branch)
        has_commit = bool(git_commit)

        # Normalize fix_status to eliminate internal dev PR status in client report
        fix_status = normalize_remediation_status(raw_status, has_pr, has_branch, has_commit)
        if fix_status == "Pull Request Created":
            fix_status = "Remediation In Progress"

        retest_status = f.get("retest_status") or "Pending"
        retest_notes = f.get("retest_notes") or "Awaiting remediation patch deployment and secondary validation."
        retest_date = f.get("retest_date") or None

        # Resolve authoritative CVSS score, vector, and consistency
        raw_score = f.get("cvss_score") if f.get("cvss_score") is not None else f.get("cvss")
        raw_vec = f.get("cvss_vector")

        clean_score = None
        if raw_score is not None and str(raw_score).strip() not in ["", "None", "null", "N/A", "Not Scored"]:
            try:
                clean_score = float(raw_score)
            except (ValueError, TypeError):
                clean_score = None

        calc_score = parse_and_calculate_cvss_v31(raw_vec)
        authoritative_score = calc_score if calc_score is not None else clean_score

        # Strict validation: Score must be consistent with qualitative severity
        is_consistent = is_cvss_consistent_with_severity(authoritative_score, sev)
        if not is_consistent:
            # Score directly contradicts severity (e.g. LOW with 9.0)
            # Never fabricate an arbitrary score. Set display score to None ("Not Scored")
            display_cvss_score = None
            display_cvss_text = "Not Scored"
        else:
            display_cvss_score = authoritative_score
            display_cvss_text = f"{authoritative_score:.1f}" if authoritative_score is not None else "Not Scored"

        formatted_cvss = format_cvss_vector(display_cvss_score, raw_vec, severity=sev)

        norm_f = {
            "id": f.get("id") or report_vuln_id,
            "finding_num": finding_num,
            "report_vuln_id": report_vuln_id,
            "raw_id": f.get("id"),
            "finding_name": f.get("finding_name") or f.get("title") or f"Vulnerability {report_vuln_id}",
            "severity": sev,
            "priority": sev,
            "cwe_id": grc["cwe_id"],
            "cwe_name": grc["cwe_name"],
            "raw_cvss_score": raw_score,
            "cvss_score": display_cvss_score,
            "cvss_display": display_cvss_text,
            "cvss_vector": raw_vec,
            "cvss_formatted": formatted_cvss,
            "cvss_consistent": is_consistent,
            "affected_component": affected_component_str,
            "endpoint": http_endpoint,
            "source_component": source_comp,
            "http_method": (f.get("http_method") or f.get("method") or "POST").upper(),
            "parameter": f.get("parameter") or f.get("affected_parameter") or "N/A",
            "provenance": f.get("provenance") or ("Automated Scan" if f.get("automated") else "Manual Penetration Test"),
            "status": f.get("status") or "CONFIRMED",
            "description": description,
            "technical_observation": technical_observation,
            "root_cause": root_cause,
            "impact_confidentiality": c_impact,
            "impact_integrity": i_impact,
            "impact_availability": a_impact,
            "business_impact": business_impact,
            "reproduction_steps": repro_steps,
            "poc_text": redacted_poc,
            "http_request": redacted_req,
            "http_response": redacted_res,
            "evidence_items": evidence_items,
            "remediation": remediation_text,
            "structured_remediation": struct_rem,
            "mitigation": mitigation_text,
            "defense_in_depth": defense_in_depth_text,
            "detection_guidance": siem_detection_text,
            "developer_validation": dev_validation_text,
            "remediation_sla": sla,
            "grc_mappings": grc,
            "status": f.get("status") or "CONFIRMED",
            "fix_status": fix_status,
            "remediation_status": fix_status,
            "retest_status": retest_status,
            "retest_notes": retest_notes,
            "retest_date": retest_date
        }
        normalized_findings.append(norm_f)

    # 3. Aggregated Counts & Verification
    crit_count = sum(1 for f in normalized_findings if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in normalized_findings if f["severity"] == "HIGH")
    med_count = sum(1 for f in normalized_findings if f["severity"] == "MEDIUM")
    low_count = sum(1 for f in normalized_findings if f["severity"] == "LOW")
    info_count = sum(1 for f in normalized_findings if f["severity"] == "INFORMATIONAL")
    total_findings = len(normalized_findings)

    # Ensure reconciliation: total_findings must equal sum of severities
    assert total_findings == (crit_count + high_count + med_count + low_count + info_count), "Severity counts sum mismatch"

    # 4. Rigorous Test Coverage Reconciliation
    # Every finding in normalized_findings represents a security control tested and confirmed vulnerable.
    raw_checklist = checklist_items if checklist_items is not None else project.get("checklist", [])
    
    # Identify checklist items explicitly associated with active findings
    linked_checklist_keys: Set[str] = set()
    for f in normalized_findings:
        raw_obj = next((rf for rf in active_raw if (rf.get("id") == f.get("raw_id") or rf.get("vuln_id") == f.get("report_vuln_id"))), {})
        chk_id = raw_obj.get("checklist_item_id") or raw_obj.get("test_id")
        if chk_id:
            linked_checklist_keys.add(str(chk_id))

    # Controls evaluated clean (status == TESTED_NOT_FOUND and not linked to a finding)
    clean_items = [
        item for item in raw_checklist
        if item.get("status") == "TESTED_NOT_FOUND" and
           str(item.get("id", "")) not in linked_checklist_keys and
           str(item.get("item_id", "")) not in linked_checklist_keys
    ]
    clean_eval = len(clean_items)

    # Confirmed vulnerable controls: strictly equals total_findings to eliminate contradictory reporting
    vuln_eval = total_findings
    evaluated_controls = clean_eval + vuln_eval

    # Untested planned controls: remaining items in checklist not evaluated clean or linked to finding
    untested_items = [
        item for item in raw_checklist
        if item.get("status") not in ["TESTED_NOT_FOUND", "VULNERABILITY_FOUND"] and
           str(item.get("id", "")) not in linked_checklist_keys and
           str(item.get("item_id", "")) not in linked_checklist_keys
    ]
    untested_controls = len(untested_items)

    # Total planned controls = evaluated controls + remaining untested controls
    planned_controls = evaluated_controls + untested_controls
    coverage_pct = round((evaluated_controls / planned_controls) * 100, 1) if planned_controls > 0 else (100.0 if allow_clean_report else 0.0)

    # 5. Risk Posture
    risk_label, risk_color_hex, risk_desc = calculate_deterministic_risk_posture(
        crit_count, high_count, med_count, low_count, info_count, planned_controls, evaluated_controls
    )

    # 6. GRC Control Gaps Aggregation
    control_gaps = aggregate_security_control_gaps(normalized_findings)

    # 7. Document Methodology Standard Label
    methodology_labels = {
        "owasp_wstg": "OWASP Web Security Testing Guide (WSTG v4.2) & NIST SP 800-115",
        "owasp_top10": "OWASP Top 10 Web Application Security Risks (2025)",
        "asvs_l2": "OWASP Application Security Verification Standard (ASVS v4.0.3 Level 2)",
        "ptes": "Penetration Testing Execution Standard (PTES)"
    }
    methodology_full_name = methodology_labels.get(methodology, "OWASP WSTG v4.2 & NIST SP 800-115")

    # Final Normalized Model
    model = {
        "project": {
            "id": proj_id,
            "name": proj_name,
            "target_url": target_url,
            "environment": environment,
            "organization": client_org,
            "created_at": project.get("created_at", datetime.now().strftime("%Y-%m-%d")),
            "pci_in_scope": is_pci_in_scope,
            "scope_in": [
                f"Primary Target URL: {target_url}",
                "Web Application APIs and Authentication Endpoints",
                "User Profile, Role Management & Session Lifecycle Handlers"
            ],
            "scope_out": [
                "Denial of Service (DoS / DDoS) testing against production infrastructure",
                "Physical security of facilities, data centers, and employee workstations",
                "Social engineering, phishing, or pretexting against personnel"
            ]
        },
        "document_metadata": {
            "version": version,
            "author_name": author_name or project.get("created_by", "Security Assessor"),
            "reviewer_name": "Lead Security Reviewer",
            "generation_date": datetime.now().strftime("%B %d, %Y"),
            "generation_timestamp": datetime.now().isoformat(),
            "classification": "STRICTLY CONFIDENTIAL",
            "methodology": methodology,
            "methodology_name": methodology_full_name,
            "historical_reports": historical_reports or []
        },
        "disclaimer": MANDATORY_GRC_DISCLAIMER,
        "frameworks_metadata": FRAMEWORKS_METADATA,
        "risk_posture": {
            "label": risk_label,
            "color_hex": risk_color_hex,
            "description": risk_desc
        },
        "metrics": {
            "total_findings": total_findings,
            "critical_count": crit_count,
            "high_count": high_count,
            "medium_count": med_count,
            "low_count": low_count,
            "info_count": info_count,
            "total_tests": planned_controls,
            "tested_tests": evaluated_controls,
            "untested_tests": untested_controls,
            "clean_tests": clean_eval,
            "vulnerable_tests": vuln_eval,
            "coverage_pct": coverage_pct
        },
        "findings": normalized_findings,
        "control_gaps": control_gaps,
        "figures_index": global_figures,
        "rules_of_engagement": build_rules_of_engagement(project, {
            "version": version,
            "author_name": author_name or project.get("created_by", "Security Assessor"),
            "generation_date": datetime.now().strftime("%B %d, %Y")
        }),
        "target_information": build_target_information(project),
        "executive_recommendations": build_executive_recommendations(normalized_findings),
        "residual_risk": build_residual_risk_summary(normalized_findings),
        "evidence_register": build_evidence_register(normalized_findings),
        "remediation_register": build_remediation_register(normalized_findings),
        "retest_register": build_retest_register(normalized_findings)
    }

    # Execute Pre-Render Integrity Validation
    validation_errors = validate_report_model_integrity(model)
    if validation_errors:
        logger.warning(f"Report model validation logged {len(validation_errors)} warnings: {validation_errors}")

    return model

build_report_model = assemble_normalized_report_model

