import re
from enum import Enum
from typing import List, Optional, Any, Dict, Union
from pydantic import BaseModel, Field, field_validator, model_validator


class PriorityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class FindingRecord(BaseModel):
    id: Optional[str] = Field(None, description="Unique identifier for the finding record")
    vuln_id: Optional[str] = Field(None, description="Sequential vulnerability identifier, e.g. VULN-001")
    finding_name: str = Field(..., description="Name or title of the confirmed vulnerability finding")
    severity_source: Optional[str] = Field("AI", description="Origin of severity rating: 'AI' or 'USER_OVERRIDE'")
    description: Optional[str] = Field(None, description="Observation or explanation of the security issue")
    affected_url: Optional[str] = Field(None, description="Target application URL affected")
    affected_endpoint: Optional[str] = Field(None, description="Vulnerable API or web endpoint")
    affected_component: Optional[str] = Field(None, description="Affected UI element, parameter, or module")
    testing_notes: Optional[str] = Field(None, description="Steps taken or notes on reproducing the issue")
    poc_text: Optional[str] = Field(None, description="Proof of concept payload, request/response snippet, or notes")
    evidence_filename: Optional[str] = Field(None, description="Optional uploaded evidence file name")
    evidence_data: Optional[str] = Field(None, description="Optional base64 data URI of uploaded evidence screenshot")
    priority: Optional[PriorityEnum] = Field(PriorityEnum.HIGH, description="Severity / Priority")
    cwe: Optional[str] = Field(None, description="CWE identifier, e.g. CWE-89")
    cvss_score: Optional[float] = Field(7.5, description="CVSS v3.1 base score, e.g. 8.5")
    impact: Optional[str] = Field(None, description="Technical and business impact of the vulnerability")
    reproduction_steps: Optional[str] = Field(None, description="Step-by-step reproduction instructions")
    remediation: Optional[str] = Field(None, description="Specific technical code or configuration remediation")
    mitigation: Optional[str] = Field(None, description="Defense-in-depth architectural mitigation")
    status: Optional[str] = Field("Open", description="Finding lifecycle status: Open, In Progress, Remediated")
    fix_status: Optional[str] = Field("NOT_STARTED", description="AI Fix status: NOT_STARTED, FIX_PROPOSED, FIX_APPLIED, PR_CREATED, MANUALLY_REMEDIATED")
    github_fix: Optional[dict] = Field(None, description="GitHub commit and Pull Request tracking metadata")
    ai_fix: Optional[Dict[str, Any]] = Field(None, description="AI AutoFix metadata (branch, commit_sha, pr_url, status, etc.)")
    recorded_at: Optional[str] = Field(None, description="Timestamp when finding was recorded")

    @field_validator("priority", mode="before")
    @classmethod
    def validate_priority(cls, v: Any) -> Any:
        if isinstance(v, str):
            s = v.strip().upper()
            if s in ("P1", "P-1", "SEV 1", "SEV-1", "CRITICAL", "CRIT", "VERY HIGH"):
                return PriorityEnum.CRITICAL
            elif s in ("P2", "P-2", "SEV 2", "SEV-2", "HIGH", "IMPORTANT"):
                return PriorityEnum.HIGH
            elif s in ("P3", "P-3", "SEV 3", "SEV-3", "MEDIUM", "MED", "MODERATE"):
                return PriorityEnum.MEDIUM
            elif s in ("P4", "P-4", "SEV 4", "SEV-4", "LOW", "MINOR"):
                return PriorityEnum.LOW
            elif s in ("P5", "P-5", "SEV 5", "SEV-5", "INFORMATIONAL", "INFO", "NOTE"):
                return PriorityEnum.INFORMATIONAL
        return v


class ChecklistItem(BaseModel):
    id: str = Field(..., description="Unique identifier for the checklist item")
    name: str = Field(..., description="Vulnerability or security test name")
    priority: PriorityEnum = Field(..., description="Test priority: CRITICAL, HIGH, MEDIUM, or LOW")
    reason: str = Field(..., description="Brief explanation of why this test is relevant to the visible functionality")
    testing_objective: str = Field(..., description="Specific objective of what the security learner/tester should assess")
    cwe: Optional[str] = Field(None, description="CWE identifier where reasonably applicable, e.g. CWE-287")
    source: str = Field("AI", description="Origin of item: 'AI', 'USER', or 'USER_MODIFIED'")
    status: str = Field("NOT_TESTED", description="Testing status: 'NOT_TESTED', 'TESTED_NOT_FOUND', or 'VULNERABILITY_FOUND'")
    finding: Optional[FindingRecord] = Field(None, description="Associated finding details if a vulnerability was confirmed")


class VaptAnalysisResponse(BaseModel):
    page_type: str = Field(..., description="Identified type of page/functionality out of the 10 supported categories or 'Unknown / Ambiguous'")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    detected_elements: List[str] = Field(default_factory=list, description="List of visible UI elements and user-controlled inputs identified")
    detected_functionalities: List[str] = Field(default_factory=list, description="List of discrete functionalities identified, e.g. Search, File Upload")
    security_relevant_features: List[str] = Field(default_factory=list, description="Security-relevant functionalities identified")
    visible_signals: List[str] = Field(default_factory=list, description="Visual signals extracted from screenshot justifying classification")
    visible_functionality: List[str] = Field(default_factory=list, description="Visible UI controls and functionalities extracted from screenshot")
    visible_security_signals: List[str] = Field(default_factory=list, description="Visible security signals extracted from screenshot")
    image_quality: Optional[str] = Field("GOOD", description="Image quality: 'GOOD', 'LIMITED', 'UNREADABLE'")
    image_dimensions: Optional[Dict[str, int]] = Field(None, description="Image dimensions {width, height}")
    ambiguity_notes: Optional[str] = Field(None, description="Explanation or recommendation if the page is ambiguous or unknown")
    checklist: List[ChecklistItem] = Field(..., description="Prioritized list of potential VAPT security tests")
    selected_page_type: Optional[str] = Field(None, description="Page type hint selected by user, if any")
    page_type_conflict: bool = Field(False, description="Deprecated; always False in simplified architecture")
    conflict_reason: Optional[str] = Field(None, description="Deprecated; always None in simplified architecture")
    request_id: Optional[str] = Field(None, description="Echoed client request ID for stale response protection")
    image_hash: Optional[str] = Field(None, description="SHA256 image fingerprint")
    analysis_mode: Optional[str] = Field("AI", description="Analysis mode: 'AI' or 'KNOWLEDGE_BASE_FALLBACK'")
    success: bool = Field(True, description="Indicates whether checklist generation succeeded")
    visual_analysis_available: bool = Field(True, description="Whether visual analysis was available")


class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, description="Project / Assessment Name")
    target_url: str = Field(..., min_length=1, description="Target Application URL")
    description: Optional[str] = Field("", description="Scope and description")
    scope_notes: Optional[str] = Field("", description="Optional testing notes or boundaries")
    notes: Optional[str] = Field(None, description="Alias for scope_notes")
    environment: Optional[str] = Field("Web Application (Staging)", description="Environment")
    created_by: Optional[str] = Field("Security Learner", description="Author")


class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    target_url: Optional[str] = None
    description: Optional[str] = None
    scope_notes: Optional[str] = None
    notes: Optional[str] = None
    environment: Optional[str] = None
    status: Optional[str] = None


class ChecklistItemUpdate(BaseModel):
    name: Optional[str] = None
    priority: Optional[PriorityEnum] = None
    reason: Optional[str] = None
    testing_objective: Optional[str] = None
    cwe: Optional[str] = None


class StatusUpdate(BaseModel):
    status: str = Field(..., description="Status: NOT_TESTED, TESTED_NOT_FOUND, or VULNERABILITY_FOUND")


class CustomChecklistItemCreate(BaseModel):
    name: str = Field(..., description="Test Name")
    priority: PriorityEnum = Field(PriorityEnum.HIGH, description="Priority")
    reason: Optional[str] = Field(None, description="Why relevant")
    testing_objective: Optional[str] = Field(None, description="Testing objective")
    cwe: Optional[str] = Field(None, description="CWE identifier")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        trimmed = v.strip() if v else ""
        if len(trimmed) < 3:
            raise ValueError("Test name must be at least 3 characters long.")
        if len(trimmed) > 200:
            raise ValueError("Test name must not exceed 200 characters.")
        return trimmed

    @field_validator("cwe")
    @classmethod
    def validate_cwe(cls, v: Optional[str]) -> Optional[str]:
        if not v or not str(v).strip():
            return None
        trimmed = str(v).strip().upper()
        if not re.match(r"^CWE-\d+$", trimmed):
            raise ValueError("CWE identifier must follow the format 'CWE-###' (e.g. CWE-639, CWE-89).")
        return trimmed


class FindingCreate(BaseModel):
    finding_name: str = Field(..., min_length=1, description="Finding Name / Title")
    vuln_id: Optional[str] = Field(None, description="Sequential vulnerability identifier, e.g. VULN-001")
    severity_source: Optional[str] = Field("AI", description="Origin of severity rating: 'AI' or 'USER_OVERRIDE'")
    affected_url: Optional[str] = Field(None, description="Target application URL affected")
    affected_endpoint: Optional[str] = Field(None, description="Vulnerable API or web endpoint")
    affected_component: Optional[str] = Field(None, description="Affected UI element, parameter, or module")
    observation: Optional[str] = Field(None, description="Natural-language observation of what was found")
    description: Optional[str] = Field("", description="Description / Observation")
    testing_notes: Optional[str] = Field("", description="Testing steps and reproduction notes")
    poc_text: Optional[str] = Field("", description="PoC payload or request/response details")
    evidence: Optional[List[Dict[str, Any]]] = Field(default_factory=list, description="List of attached PoC evidence items")
    evidence_filename: Optional[str] = Field(None, description="Filename of attached evidence")
    evidence_data: Optional[Any] = Field(None, description="Attached evidence data, filename, or legacy string")
    priority: Optional[PriorityEnum] = Field(PriorityEnum.HIGH, description="Severity / Priority")
    cwe: Optional[str] = Field(None, description="CWE identifier, e.g. CWE-89")
    cvss_score: Optional[float] = Field(None, description="CVSS v3.1 base score, e.g. 8.5")
    impact: Optional[str] = Field(None, description="Technical and business impact")
    reproduction_steps: Optional[str] = Field(None, description="Step-by-step reproduction instructions")
    remediation: Optional[str] = Field(None, description="Specific technical code or configuration remediation")
    mitigation: Optional[str] = Field(None, description="Defense-in-depth architectural mitigation")
    status: Optional[str] = Field("Open", description="Finding lifecycle status: Open, In Progress, Remediated")
    fix_status: Optional[str] = Field("NOT_STARTED", description="AI Fix status: NOT_STARTED, FIX_PROPOSED, FIX_APPLIED, PR_CREATED, MANUALLY_REMEDIATED")
    github_fix: Optional[dict] = Field(None, description="GitHub commit and Pull Request tracking metadata")
    ai_fix: Optional[Dict[str, Any]] = Field(None, description="AI AutoFix metadata")


class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, description="Username")
    email: str = Field(..., min_length=5, description="Email address")
    password: str = Field(..., min_length=6, description="Password")
    full_name: Optional[str] = Field("Security Learner", description="Full display name")


class UserLogin(BaseModel):
    username_or_email: str = Field(..., min_length=3, description="Username or email")
    password: str = Field(..., min_length=1, description="Password")


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    full_name: str
    role: str
    created_at: str
    name: Optional[str] = None
    two_factor_enabled: Optional[bool] = False
    two_factor_enabled_at: Optional[str] = None
    two_factor_last_verified_at: Optional[str] = None

    @model_validator(mode="after")
    def populate_name(self) -> "UserResponse":
        if not self.name:
            self.name = self.full_name
        return self


class AuthTokenResponse(BaseModel):
    access_token: Optional[str] = None
    token: Optional[str] = None
    token_type: Optional[str] = "bearer"
    user: Optional[UserResponse] = None
    requires_2fa: Optional[bool] = False
    temp_token: Optional[str] = None
    message: Optional[str] = None


class TwoFactorStatusResponse(BaseModel):
    enabled: bool
    enabled_at: Optional[str] = None
    last_verified_at: Optional[str] = None
    recovery_codes_remaining: int = 0


class TwoFactorSetupResponse(BaseModel):
    secret: str
    qr_code: str
    manual_entry_key: str
    expires_at: str
    issuer: str = "Tracegate Security Platform"


class TwoFactorVerifySetupRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=6, description="6-digit TOTP code")


class TwoFactorVerifySetupResponse(BaseModel):
    success: bool
    message: str
    recovery_codes: List[str]


class TwoFactorLoginVerifyRequest(BaseModel):
    temp_token: str = Field(..., min_length=10, description="Temporary 2FA challenge token")
    code: Optional[str] = Field(None, description="6-digit TOTP code")
    recovery_code: Optional[str] = Field(None, description="Single-use backup recovery code")


class TwoFactorDisableRequest(BaseModel):
    password: str = Field(..., min_length=1, description="Account password for confirmation")
    code: Optional[str] = Field(None, description="6-digit TOTP code or recovery code")


class TwoFactorRegenerateRecoveryRequest(BaseModel):
    password: str = Field(..., min_length=1, description="Account password for confirmation")
    code: str = Field(..., min_length=6, max_length=6, description="6-digit TOTP code")


class TwoFactorRegenerateRecoveryResponse(BaseModel):
    success: bool
    message: str
    recovery_codes: List[str]


class ForgotPasswordRequest(BaseModel):
    email: str = Field(..., min_length=3, description="Registered account email")


class ForgotPasswordResponse(BaseModel):
    message: str


class VerifyResetOtpRequest(BaseModel):
    email: str = Field(..., min_length=3, description="Registered account email")
    otp: str = Field(..., min_length=6, max_length=6, description="6-digit verification code")


class VerifyResetOtpResponse(BaseModel):
    message: str
    reset_authorization: str


class ResetPasswordRequest(BaseModel):
    token: Optional[str] = Field(None, description="Password reset authorization token (legacy)")
    reset_authorization: Optional[str] = Field(None, description="Server-issued password reset authorization token")
    new_password: str = Field(..., min_length=8, description="New account password (min 8 characters)")
    confirm_password: Optional[str] = Field(None, description="Confirm new password")


class PasswordResetResponse(BaseModel):
    message: str
    reset_token: Optional[str] = None



class ReportCreate(BaseModel):
    title: Optional[str] = Field("Penetration Testing Assessment Report", description="Report title")
    author: Optional[str] = Field(None, description="Assessor name")
    author_name: Optional[str] = Field(None, description="Assessor name alias")
    version: Optional[str] = Field(None, description="Report version, e.g. v1.0")
    selected_finding_ids: Optional[List[str]] = Field(None, description="Confirmed finding IDs selected for report")
    methodology: Optional[str] = Field("owasp_wstg", description="Assessment methodology")
    allow_clean_report: Optional[bool] = Field(False, description="Allow generating clean assessment report if 0 findings")


class ReportRecord(BaseModel):
    id: str
    project_id: str
    version: str
    report_title: str
    file_path: str
    filename: Optional[str] = None
    total_findings: int
    findings_count: Optional[int] = None
    crit_count: int
    high_count: int
    med_count: int
    low_count: int
    info_count: Optional[int] = 0
    selected_finding_ids: Optional[List[str]] = None
    created_by: str
    author_name: Optional[str] = None
    created_at: str
    download_url: str
    docx_download_url: Optional[str] = None
    pdf_download_url: Optional[str] = None
    file_path_pdf: Optional[str] = None
    pdf_available: Optional[bool] = False


class CandidateFindingItem(BaseModel):
    id: Optional[str] = None
    source_finding_id: Optional[str] = None
    title: str
    severity: str = "MEDIUM"
    cwe: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    description: Optional[str] = None
    observation: Optional[str] = None
    impact: Optional[str] = None
    security_impact: Optional[str] = None
    business_impact: Optional[str] = None
    affected_url: Optional[str] = None
    affected_component: Optional[str] = None
    steps_to_reproduce: Optional[str] = None
    poc: Optional[str] = None
    poc_text: Optional[str] = None
    remediation: Optional[str] = None
    mitigation: Optional[str] = None
    root_cause: Optional[str] = None
    detection_monitoring: Optional[str] = None
    developer_validation: Optional[str] = None
    evidence: Optional[List[Dict[str, Any]]] = None
    retest_status: Optional[str] = "PENDING"
    status: Optional[str] = "Open"
    github_branch: Optional[str] = None
    github_commit: Optional[str] = None
    github_pr: Optional[str] = None
    source: Optional[str] = "IMPORTED_REPORT"
    source_document_id: Optional[str] = None
    source_document_name: Optional[str] = None
    extraction_quality: Optional[str] = "HIGH"
    duplicate_warning: Optional[str] = None
    duplicate_of_id: Optional[str] = None
    is_duplicate: Optional[bool] = False
    selected: Optional[bool] = True


class ReportParseImportResponse(BaseModel):
    source_document_id: str
    source_document_name: str
    total_candidates: int
    candidate_findings: List[CandidateFindingItem]
    summary: Optional[Dict[str, Any]] = None


class ReportImportFindingsRequest(BaseModel):
    source_document_id: Optional[str] = None
    source_document_name: Optional[str] = None
    candidate_findings: List[CandidateFindingItem]



# =============================================================================
# GITHUB AI FIX / CODE CONNECTOR SCHEMAS
# =============================================================================

class GitHubStatusResponse(BaseModel):
    configured: bool = True
    connected: bool = False
    username: Optional[str] = None
    rate_limit: Optional[int] = 5000
    rate_limit_remaining: Optional[int] = 4980
    mode: str = "mock"  # "live" or "mock"
    token_preview: Optional[str] = None
    scopes: List[str] = []


class GitHubConnectRequest(BaseModel):
    token: Optional[str] = Field(None, description="Personal Access Token (handled securely on server only)")
    username: Optional[str] = None
    mode: Optional[str] = Field("mock", description="Connection mode: 'mock' or 'live'")


class GitHubRepoItem(BaseModel):
    name: str
    full_name: str
    default_branch: str
    description: Optional[str] = None
    private: bool = False


class MultiFilePatchItem(BaseModel):
    path: str
    file_sha: Optional[str] = None
    after_sha: Optional[str] = None
    before_code: str = ""
    after_code: str = ""
    diff_unified: str = ""
    changes: List[str] = Field(default_factory=list)
    reason: str = ""
    symbols: List[str] = Field(default_factory=list)
    validation: Optional[Dict[str, Any]] = None
    lines_added: Optional[int] = 0
    lines_removed: Optional[int] = 0
    finding_ids: List[str] = Field(default_factory=list)


class GitHubAnalyzeCodeRequest(BaseModel):
    request_id: Optional[str] = Field(None, description="Client-generated unique UUID for request tracing")
    finding_id: str = Field(..., description="Vulnerability finding ID")
    project_id: Optional[str] = Field(None, description="Project ID containing the finding")
    repository: Optional[str] = Field(None, description="Repository full name, e.g. owner/repo")
    repo: Optional[str] = Field(None, description="Repository full name alias")
    branch: str = Field("main", description="Target branch")
    file_path: Optional[str] = Field(None, description="Affected source file path")
    selected_files: Optional[List[str]] = Field(None, description="List of multiple selected source file paths")
    code_snippet: Optional[str] = Field(None, description="Optional user-provided vulnerable source code snippet")
    developer_instructions: Optional[str] = Field(None, description="Optional developer instructions or architectural constraints")
    source_commit_sha: Optional[str] = Field(None, description="Baseline commit SHA to detect source changes")


class GitHubCodeAnalysisResponse(BaseModel):
    success: bool = Field(True, description="Whether a safe, semantic code remediation was successfully generated")
    request_id: Optional[str] = None
    finding_id: str
    vuln_id: Optional[str] = None
    finding_title: Optional[str] = None
    cwe: Optional[str] = None
    repo: Optional[str] = None
    branch: Optional[str] = None
    file: Optional[str] = None
    file_path: str = ""
    original_code: Optional[str] = None
    proposed_code: Optional[str] = None
    before_code: Optional[str] = None
    after_code: Optional[str] = None
    before_content: Optional[str] = None
    after_content: Optional[str] = None
    root_cause: Optional[str] = None
    vulnerable_lines: Optional[Dict[str, int]] = None
    vulnerable_region: Optional[Dict[str, int]] = None
    security_property_missing: Optional[str] = None
    fix_strategy: Optional[str] = None
    required_fix_strategy: Optional[str] = None
    patch: Optional[str] = None
    changes: List[str] = Field(default_factory=list, description="List of discrete changes applied to remediate the vulnerability")
    preserved_logic: List[str] = Field(default_factory=list, description="Existing application logic explicitly preserved")
    potential_side_effects: List[str] = Field(default_factory=list, description="Potential side effects or compatibility notes")
    is_relevant_file: bool = Field(True, description="Whether the selected source file is relevant to the vulnerability finding")
    reason: Optional[str] = Field(None, description="Detailed explanation if the file is deemed irrelevant or fix cannot be safely generated")
    security_impact: Optional[str] = Field(None, description="Security impact and risk mitigation description")
    testing_recommendation: Optional[str] = Field(None, description="Recommended manual and automated testing steps to verify fix")
    retest_checklist: List[str] = Field(default_factory=list, description="Step-by-step verification checklist items for retesting")
    file_sha: Optional[str] = Field(None, description="SHA hash of the original source file at analysis time")
    unified_diff: Optional[str] = None
    diff_unified: Optional[str] = None
    explanation: str = ""
    testing_steps: Optional[str] = None
    safety_notes: Optional[str] = None
    validation: Optional[Dict[str, Any]] = None
    fix_confidence: Optional[str] = "HIGH"
    fix_quality_score: Optional[Union[Dict[str, Any], float]] = None
    dependencies_changed: bool = False
    workflow_files_changed: bool = False
    revision_count: int = 0
    developer_instructions: Optional[str] = None
    patch_status: Optional[str] = "PATCH_VALIDATED"  # PATCH_VALIDATED, PATCH_REJECTED, PATCH_PROPOSED, NO_RELEVANT_SOURCE_FOUND, EMPTY_PATCH
    source_commit_sha: Optional[str] = None
    files: List[MultiFilePatchItem] = Field(default_factory=list)
    selected_sources: List[DiscoveredSourceItem] = Field(default_factory=list)
    candidate_sources: List[DiscoveredSourceItem] = Field(default_factory=list)
    discovery_status: Optional[str] = None
    remediation_summary: Optional[Dict[str, Any]] = None
    finding_traceability: List[Dict[str, Any]] = Field(default_factory=list)
    file_traceability: List[Dict[str, Any]] = Field(default_factory=list)
    clusters: List[Dict[str, Any]] = Field(default_factory=list)
    remediationRunId: Optional[str] = None
    projectId: Optional[str] = None
    repository: Optional[str] = None
    sourceCommit: Optional[str] = None
    findings: Optional[List[Dict[str, Any]]] = None
    finding_results: List[Dict[str, Any]] = Field(default_factory=list)
    summary: Optional[Dict[str, Any]] = None
    commitSha: Optional[str] = None
    prNumber: Optional[int] = None
    prUrl: Optional[str] = None



class GitHubApplyFixRequest(BaseModel):
    finding_id: str = Field(..., description="Vulnerability finding ID")
    project_id: Optional[str] = None
    repository: Optional[str] = Field(None, description="Repository full name")
    repo: Optional[str] = Field(None, description="Repository alias")
    base_branch: str = Field("main", description="Base branch to fork from")
    target_branch: Optional[str] = Field(None, description="Target branch")
    fix_branch: Optional[str] = Field(None, description="Fix branch name, defaults to tracegate/fix/{vuln_id}")
    file_path: Optional[str] = Field(None, description="Source code file path")
    file_sha: Optional[str] = Field(None, description="File SHA hash at analysis time to guarantee write consistency")
    fixed_code: Optional[str] = Field(None, description="Remediated code content")
    proposed_code: Optional[str] = Field(None, description="Proposed remediated code")
    diff_or_fixed_code: Optional[str] = Field(None, description="Remediated code or diff")
    diff_unified: Optional[str] = None
    explanation: Optional[str] = None
    security_impact: Optional[str] = None
    commit_message: Optional[str] = Field(None, description="Custom commit message")
    developer_instructions: Optional[str] = None
    files: Optional[List[MultiFilePatchItem]] = Field(None, description="List of multi-file patch items to apply simultaneously")
    create_pr: Optional[bool] = Field(False, description="Whether to automatically create a Pull Request after committing the fix")
    pr_title: Optional[str] = Field(None, description="Optional custom Pull Request title")
    pr_body: Optional[str] = Field(None, description="Optional custom Pull Request body")
    run_id: Optional[str] = Field(None, description="Optional active remediation run ID to link PR metadata")
    source_commit_sha: Optional[str] = Field(None, description="Verified base branch commit SHA at analysis time")
    auto_recover: Optional[bool] = Field(True, description="Whether to automatically safe-refresh and recover if source changed without conflict")


class GitHubApplyFixResponse(BaseModel):
    success: bool
    branch_name: Optional[str] = None
    fix_branch: Optional[str] = None
    commit_sha: str
    commit_message: str
    validation_status: str = "PASSED"
    validation_details: Any = None
    fix_id: Optional[str] = None
    pr_number: Optional[int] = None
    pr_url: Optional[str] = None
    source_refreshed: Optional[bool] = False
    conflict_details: Optional[Dict[str, Any]] = None
    refreshed_data: Optional[Dict[str, Any]] = None
    post_write_verification: Optional[Dict[str, Any]] = None
    file_verifications: Optional[List[Dict[str, Any]]] = None


class AIFixCheckSourceRequest(BaseModel):
    repo: str
    branch: str = "main"
    source_commit_sha: Optional[str] = None
    file_sha: Optional[str] = None
    file_path: Optional[str] = None
    files: Optional[List[MultiFilePatchItem]] = None


class AIFixCheckSourceResponse(BaseModel):
    is_changed: bool
    current_head_sha: str
    expected_head_sha: Optional[str] = None
    changed_files: List[str] = Field(default_factory=list)
    has_conflict: bool = False
    conflict_details: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None


class AIFixSafeRefreshRequest(BaseModel):
    repo: str
    branch: str = "main"
    finding_id: str
    project_id: Optional[str] = None
    source_commit_sha: Optional[str] = None
    file_sha: Optional[str] = None
    file_path: Optional[str] = None
    files: Optional[List[MultiFilePatchItem]] = None
    developer_instructions: Optional[str] = None


class AIFixSafeRefreshResponse(BaseModel):
    success: bool
    status: str = "REFRESHED"
    message: str = ""
    source_refreshed: bool = False
    current_head_sha: Optional[str] = None
    conflict_details: Optional[Dict[str, Any]] = None
    analysis: Optional[Any] = None


class GitHubCreatePRRequest(BaseModel):
    finding_id: str = Field(..., description="Vulnerability finding ID")
    repository: Optional[str] = Field(None, description="Repository full name")
    repo: Optional[str] = Field(None, description="Repository alias")
    fix_branch: str = Field(..., description="Branch containing the fix")
    base_branch: str = Field("main", description="Target merge branch")
    title: Optional[str] = Field(None, description="PR Title")
    body: Optional[str] = Field(None, description="PR Description")
    fix_id: Optional[str] = None
    project_id: Optional[str] = Field(None, description="Active Project / Assessment ID")
    run_id: Optional[str] = Field(None, description="Optional active remediation run ID to link PR metadata")


class GitHubCreatePRResponse(BaseModel):
    success: bool = True
    pr_number: int
    pr_url: str
    title: str
    body: Optional[str] = None
    status: str = "Open"
    fix_id: Optional[str] = None
    head_branch: Optional[str] = None
    base_branch: Optional[str] = None
    head_sha: Optional[str] = None
    base_sha: Optional[str] = None
    reused: Optional[bool] = False


class GitHubTreeItem(BaseModel):
    path: str
    mode: Optional[str] = "100644"
    type: str  # "blob" or "tree"
    sha: Optional[str] = None
    size: Optional[int] = None
    url: Optional[str] = None


class GitHubRepoTreeResponse(BaseModel):
    repo: str
    branch: str
    tree: List[GitHubTreeItem]
    truncated: bool = False


class GitHubFileContentResponse(BaseModel):
    repo: str
    branch: str
    path: str
    sha: str
    size: int
    content: str
    encoding: str = "utf-8"


class SourceLocationSymbol(BaseModel):
    name: str
    kind: str = "function"  # function, class, route, method, variable
    line_start: Optional[int] = None
    line_end: Optional[int] = None


class DiscoveredSourceItem(BaseModel):
    path: str
    layer: str = "source"  # route, controller, service, middleware, model, template, config, source
    language: str = "Unknown"
    symbols: List[SourceLocationSymbol] = Field(default_factory=list)
    relevance_score: int = 0
    confidence: str = "LOW"  # HIGH, MEDIUM, LOW
    reasons: List[str] = Field(default_factory=list)
    preview_snippet: Optional[str] = None


class AIFixDiscoverFileRequest(BaseModel):
    finding_id: str = Field(..., description="Vulnerability finding ID")
    project_id: Optional[str] = None
    repository: Optional[str] = None
    repo: Optional[str] = None
    branch: str = "main"


class AIFixDiscoverFileResponse(BaseModel):
    finding_id: str
    project_id: Optional[str] = None
    file_path: Optional[str] = None
    discovered_file: Optional[str] = None
    confidence: float = 0.0
    reason: str
    preview_snippet: Optional[str] = None
    matching_candidates: List[Dict[str, Any]] = Field(default_factory=list)
    repository: Optional[str] = None
    branch: Optional[str] = "main"
    source_commit_sha: Optional[str] = None
    discovery_status: str = "COMPLETED"
    selected_sources: List[DiscoveredSourceItem] = Field(default_factory=list)
    candidate_sources: List[DiscoveredSourceItem] = Field(default_factory=list)
    selection_source: str = "AUTOMATIC"
    summary: str = ""


class AIFixDiscoverSourceRequest(BaseModel):
    finding_id: str = Field(..., description="Vulnerability finding ID")
    project_id: Optional[str] = None
    repository: Optional[str] = None
    repo: Optional[str] = None
    branch: str = "main"
    finding_name: Optional[str] = None
    title: Optional[str] = None
    cwe: Optional[str] = None
    affected_endpoint: Optional[str] = None
    parameter: Optional[str] = None
    observation: Optional[str] = None
    description: Optional[str] = None
    developer_instructions: Optional[str] = None


class AIFixDiscoverSourceResponse(BaseModel):
    finding_id: str
    project_id: Optional[str] = None
    repository: str
    branch: str = "main"
    source_commit_sha: str = "main"
    discovery_status: str = "COMPLETED"  # COMPLETED, NO_MATCH, ERROR
    selected_sources: List[DiscoveredSourceItem] = Field(default_factory=list)
    candidate_sources: List[DiscoveredSourceItem] = Field(default_factory=list)
    summary: str = ""
    selection_source: str = "AUTOMATIC"  # AUTOMATIC, USER_MODIFIED
    # Backwards compatibility fields
    file_path: Optional[str] = None
    discovered_file: Optional[str] = None
    confidence: float = 0.0
    reason: str = ""
    preview_snippet: Optional[str] = None
    matching_candidates: List[Dict[str, Any]] = Field(default_factory=list)


class AIFixSaveSourceSelectionRequest(BaseModel):
    finding_id: str = Field(..., description="Vulnerability finding ID")
    project_id: Optional[str] = None
    repository: Optional[str] = None
    repo: Optional[str] = None
    branch: str = "main"
    selected_paths: List[str] = Field(default_factory=list)
    source_commit_sha: Optional[str] = None


class AIFixReviseRequest(BaseModel):
    finding_id: str = Field(..., description="Vulnerability finding ID")
    project_id: Optional[str] = None
    repository: Optional[str] = None
    repo: Optional[str] = None
    branch: str = "main"
    file_path: str
    current_diff: Optional[str] = None
    original_code: Optional[str] = None
    current_proposed_code: Optional[str] = None
    developer_instructions: Optional[str] = Field(None, description="Developer revision instructions and constraints")
    revision_instructions: Optional[str] = None
    revision_count: Optional[int] = 1


class AIFixRejectRequest(BaseModel):
    finding_id: str = Field(..., description="Vulnerability finding ID")
    repository: Optional[str] = None
    repo: Optional[str] = None
    reason: Optional[str] = Field(None, description="Rejection reason or notes")


class AIFixRejectResponse(BaseModel):
    success: bool
    status: str = "REJECTED"
    message: str
    finding_id: str


class AIFixMergePRRequest(BaseModel):
    finding_id: str = Field(..., description="Vulnerability finding ID")
    repository: Optional[str] = None
    repo: Optional[str] = None
    pr_number: int
    fix_id: Optional[str] = None


class AIFixMergePRResponse(BaseModel):
    success: bool
    merged: bool
    message: str
    sha: Optional[str] = None
    merge_commit_sha: Optional[str] = None
    merged_at: Optional[str] = None
    status: str = "MERGED"


class AIFixRetestRequest(BaseModel):
    finding_id: Optional[str] = None
    fix_id: Optional[str] = None
    project_id: Optional[str] = None
    assessment_id: Optional[str] = None
    result: str = "PASS"  # "PASS" or "FAIL"
    notes: Optional[str] = None
    checklist_items: Optional[List[Dict[str, Any]]] = None
    async_certificate: Optional[bool] = False


class AIFixRetestResponse(BaseModel):
    success: bool = True
    finding_id: str
    fix_id: Optional[str] = None
    result: str
    status: str
    retest_status: str
    notes: Optional[str] = None
    updated_at: str
    finding: Optional[Dict[str, Any]] = None
    certificate: Optional[Dict[str, Any]] = None
    certificate_job_id: Optional[str] = None
    certificate_eligible: Optional[bool] = None
    blocking_reason: Optional[str] = None
    eligibility: Optional[Dict[str, Any]] = None
    assessment_id: Optional[str] = None


class AIFixRecordItem(BaseModel):
    id: str
    project_id: str
    finding_id: str
    repository: str
    base_branch: str
    fix_branch: str
    file_path: str
    file_sha: Optional[str] = None
    commit_sha: Optional[str] = None
    commit_message: Optional[str] = None
    pr_number: Optional[int] = None
    pr_url: Optional[str] = None
    pr_status: str = "Open"
    diff_unified: Optional[str] = None
    explanation: Optional[str] = None
    security_impact: Optional[str] = None
    changes: List[str] = Field(default_factory=list)
    retest_checklist: List[str] = Field(default_factory=list)
    retest_status: str = "PENDING"
    retest_notes: Optional[str] = None
    retested_at: Optional[str] = None
    status: str = "PROPOSED"
    revision_count: int = 0
    created_at: str
    updated_at: str


class RepositoryScanRequest(BaseModel):
    repository: Optional[str] = Field(None, description="Repository full name, e.g. owner/repo")
    repo: Optional[str] = Field(None, description="Repository alias")
    branch: str = Field("main", description="Target branch")
    project_id: Optional[str] = Field(None, description="Project ID to register findings under")
    auto_register: bool = Field(True, description="Automatically register detected vulnerabilities into project findings")


class DetectedVulnerabilityItem(BaseModel):
    id: Optional[str] = None
    vuln_id: str
    finding_name: str
    title: Optional[str] = None
    cwe: str
    severity: str
    cvss_score: float
    file_path: str
    line_number: Optional[int] = None
    vulnerable_snippet: str = ""
    description: str
    remediation: str
    mitigation: Optional[str] = None
    poc_text: Optional[str] = None
    status: str = "CONFIRMED"


class RepositoryScanResponse(BaseModel):
    success: bool = True
    repository: str
    branch: str
    scanned_files_count: int
    vulnerabilities_detected_count: int
    findings: List[DetectedVulnerabilityItem] = Field(default_factory=list)
    summary: str


class BatchPatchRequest(BaseModel):
    repository: Optional[str] = Field(None, description="Repository full name")
    repo: Optional[str] = Field(None, description="Repository alias")
    branch: str = Field("main", description="Target branch")
    project_id: Optional[str] = Field(None, description="Project ID containing findings")
    finding_ids: Optional[List[str]] = Field(None, description="Optional list of specific finding IDs to remediate. If None or empty, all findings are patched.")
    selected_files: Optional[List[str]] = Field(None, description="Optional list of scoped source files")
    developer_instructions: Optional[str] = None
    request_id: Optional[str] = None


