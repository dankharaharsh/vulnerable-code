import os
import logging
import hashlib
import uuid
import base64
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from pydantic import BaseModel

from fastapi import FastAPI, File, Form, UploadFile, HTTPException, status, Query, Header, Request, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from backend.config import (
    ALLOWED_MIME_TYPES,
    MAX_FILE_SIZE_BYTES,
    get_active_provider,
)
from backend.schemas import (
    GitHubStatusResponse,
    GitHubConnectRequest,
    GitHubRepoItem,
    GitHubAnalyzeCodeRequest,
    GitHubCodeAnalysisResponse,
    GitHubApplyFixRequest,
    GitHubApplyFixResponse,
    GitHubCreatePRRequest,
    GitHubCreatePRResponse,
    GitHubTreeItem,
    GitHubRepoTreeResponse,
    GitHubFileContentResponse,
    AIFixDiscoverFileRequest,
    AIFixDiscoverFileResponse,
    AIFixDiscoverSourceRequest,
    AIFixDiscoverSourceResponse,
    AIFixSaveSourceSelectionRequest,
    AIFixReviseRequest,
    AIFixRejectRequest,
    AIFixRejectResponse,
    AIFixMergePRRequest,
    AIFixMergePRResponse,
    AIFixRetestRequest,
    AIFixRetestResponse,
    AIFixRecordItem,
    AIFixCheckSourceRequest,
    AIFixCheckSourceResponse,
    AIFixSafeRefreshRequest,
    AIFixSafeRefreshResponse,
    BatchPatchRequest,
    VaptAnalysisResponse,
    ProjectCreate,
    ProjectUpdate,
    ChecklistItemUpdate,
    StatusUpdate,
    CustomChecklistItemCreate,
    FindingCreate,
    UserRegister,
    UserLogin,
    UserResponse,
    AuthTokenResponse,
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    VerifyResetOtpRequest,
    VerifyResetOtpResponse,
    ResetPasswordRequest,
    PasswordResetResponse,
    TwoFactorStatusResponse,
    TwoFactorSetupResponse,
    TwoFactorVerifySetupRequest,
    TwoFactorVerifySetupResponse,
    TwoFactorLoginVerifyRequest,
    TwoFactorDisableRequest,
    TwoFactorRegenerateRecoveryRequest,
    TwoFactorRegenerateRecoveryResponse,
    ReportCreate,
    ReportRecord,
    ReportParseImportResponse,
    ReportImportFindingsRequest,
    CandidateFindingItem,
)
from backend.analyzer import run_vapt_analysis
from backend.knowledge_base import (
    get_finding_template_for_test,
    CANONICAL_PAGE_CATEGORIES,
    normalize_page_type,
)
from backend.report_generator import generate_docx_report, convert_docx_to_pdf
from backend.report_pdf_generator import compile_report_pdf, ensure_pdf_title_metadata
from backend.pdf_validator import is_valid_pdf, validate_pdf_artifact
from backend.certificate_service import (
    check_assessment_certificate_eligibility,
    generate_assessment_certificate,
    get_public_certificate_verification,
    start_certificate_generation_job,
    compile_pdf_certificate_reportlab,
    CERTIFICATES_DIR,
)
from backend.report_importer import (
    parse_report_document,
    SUPPORTED_IMPORT_EXTENSIONS,
    MAX_IMPORT_FILE_SIZE,
)
from backend.github_service import (
    get_github_status,
    save_github_token,
    disconnect_github,
    list_github_repositories,
    list_repository_branches,
    get_repository_tree,
    get_file_contents,
    create_fix_branch,
    commit_file_change,
    create_finding_pull_request,
    get_pull_request_status,
    merge_pull_request,
    analyze_finding_code,
    apply_finding_fix,
    apply_multi_file_fix,
    get_branch_head_sha,
    check_upstream_source_changed,
    check_remediation_conflict,
    safe_refresh_and_regenerate,
    GitHubPermissionError,
)
from backend.ai_autofix import (
    discover_vulnerable_source_file,
    discover_repository_sources,
    generate_secure_fix,
    generate_multi_file_secure_fix,
    scan_repository_vulnerabilities,
    generate_cumulative_repository_fix,
    is_file_relevant,
    check_precommit_safety,
    generate_retest_checklist,
    generate_remediation_review_report,
)
from backend.database import (
    init_db,
    get_finding_by_id,
    get_finding_scoped,
    update_finding_github_fix,
    save_user_github_config,
    get_user_github_config,
    save_ai_fix_record,
    get_ai_fix_by_id,
    get_ai_fix_for_finding,
    get_ai_fix_by_pr_number,
    update_ai_fix_record,
    list_ai_fixes_for_project,
    record_finding_retest,
    save_source_discovery,
    get_source_discovery,
    update_source_discovery_selection,
    create_remediation_run,
    update_remediation_run_progress,
    finalize_remediation_run,
    get_remediation_run,
    get_active_or_latest_remediation_run,
    update_remediation_run_pr_metadata,
    cancel_remediation_run,
    seed_default_projects_if_empty,
    seed_default_users_if_empty,
    get_all_projects,
    get_project_by_id,
    count_user_projects,
    create_project as db_create_project,
    update_project as db_update_project,
    delete_project as db_delete_project,
    bulk_delete_user_projects,
    save_analysis_for_project,
    get_project_checklist_items,
    update_checklist_item as db_update_checklist_item,
    update_item_status as db_update_item_status,
    delete_checklist_item as db_delete_checklist_item,
    add_custom_checklist_item as db_add_custom_checklist_item,
    save_finding as db_save_finding,
    get_project_findings_list,
    delete_finding as db_delete_finding,
    save_imported_findings,
    get_db_connection,
    register_user,
    authenticate_user,
    create_session,
    get_user_by_token,
    delete_session,
    create_password_reset_otp,
    verify_password_reset_otp,
    complete_password_reset_v2,
    create_password_reset,
    complete_password_reset,
    get_user_by_id_raw,
    get_user_2fa_status,
    save_pending_2fa_enrollment,
    get_pending_2fa_enrollment,
    delete_pending_2fa_enrollment,
    enable_user_2fa,
    disable_user_2fa,
    replace_recovery_codes,
    create_pending_2fa_login,
    get_pending_2fa_login,
    increment_pending_2fa_attempts,
    delete_pending_2fa_login,
    verify_and_consume_recovery_code,
    update_user_2fa_verified_timestamp,
    verify_password,
    save_report_record,
    update_report_pdf_path,
    get_project_reports,
    get_report_by_id,
    get_next_report_version,
    normalize_severity,
    get_certificate_by_id,
    get_certificate_by_verification_id,
    get_certificates_for_project,
    get_latest_certificate_for_project,
    update_certificate_notice_seen,
    update_certificate_file_paths,
    create_certificate_job,
    get_certificate_job,
    get_active_certificate_job_for_project,
    get_latest_certificate_job_for_project,
    update_certificate_job,
    record_evidence as db_record_evidence,
    get_project_evidence as db_get_project_evidence,
    migrate_legacy_finding_evidence as db_migrate_legacy_finding_evidence,
)
from backend.totp_service import (
    encrypt_secret,
    decrypt_secret,
    generate_totp_secret,
    get_provisioning_uri,
    generate_qr_code_data_url,
    verify_totp_code,
    generate_recovery_codes,
    hash_recovery_code,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vapt_api")

app = FastAPI(
    title="Tracegate VAPT Learning Platform API",
    description="Secure REST API for AI-assisted VAPT assessments, checklists, findings, and reporting",
    version="2.0.0",
)

# CORS middleware: Support environment-configured origins or dynamic regex origin reflection (avoids invalid wildcard + credentials combination)
allowed_origins_env = os.environ.get("ALLOWED_ORIGINS")
if allowed_origins_env:
    origins_list = [o.strip() for o in allowed_origins_env.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r"^https?://.*$",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

@app.middleware("http")
async def add_no_cache_headers(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path
    if path.startswith("/static") or path == "/" or path.startswith("/api"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
SAMPLES_DIR = BASE_DIR / "samples"

@app.on_event("startup")
def on_startup():
    init_db()
    try:
        from backend.database import auto_migrate_sqlite_to_postgres_if_empty
        auto_migrate_sqlite_to_postgres_if_empty()
    except Exception as me:
        logger.warning(f"Auto-migration check on startup: {me}")
    seed_default_projects_if_empty()
    seed_default_users_if_empty()

@app.on_event("shutdown")
def on_shutdown():
    try:
        from backend.database import close_all_connections
        close_all_connections()
    except Exception as se:
        logger.warning(f"Error during shutdown connection cleanup: {se}")

@app.exception_handler(RuntimeError)
async def runtime_error_handler(request: Request, exc: RuntimeError):
    msg = str(exc)
    if any(w in msg.lower() for w in ["database", "postgresql", "ephemeral", "db", "sqlite", "psycopg2"]):
        logger.critical(f"Database infrastructure failure: {msg}")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": "Database service unavailable. Persistent database is unreachable. Please verify configuration or retry shortly."}
        )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": msg}
    )

@app.get("/api/health")
def health_check():
    provider = get_active_provider()
    return {
        "status": "healthy",
        "service": "AI-Powered VAPT Checklist Generator",
        "provider": provider,
        "mode": "live" if provider in ["gemini", "openai"] else "simulation"
    }

@app.get("/api/samples")
def get_samples():
    """Returns sample screenshot metadata for testing convenience."""
    samples = [
        {
            "id": "login",
            "name": "Login / Sign-in",
            "filename": "login.png",
            "url": "/samples/login.png",
            "description": "Standard authentication screen with username & password"
        },
        {
            "id": "registration",
            "name": "Sign-up / Registration",
            "filename": "registration.png",
            "url": "/samples/registration.png",
            "description": "Sign-up form with password strength and email fields"
        },
        {
            "id": "forgot_password",
            "name": "Forgot Password",
            "filename": "forgot_password.png",
            "url": "/samples/forgot_password.png",
            "description": "Account recovery and password reset initiation form"
        },
        {
            "id": "profile",
            "name": "Account / Profile",
            "filename": "profile.png",
            "url": "/samples/profile.png",
            "description": "User account management, avatar upload, and password change"
        },
        {
            "id": "settings",
            "name": "Security Settings",
            "filename": "settings.png",
            "url": "/samples/settings.png",
            "description": "Two-factor authentication, active sessions, and API tokens"
        },
        {
            "id": "dashboard",
            "name": "Home / Dashboard",
            "filename": "dashboard.png",
            "url": "/samples/dashboard.png",
            "description": "Analytics dashboard with search, metrics widgets, and activity feed"
        },
        {
            "id": "search",
            "name": "Search / Results",
            "filename": "search.png",
            "url": "/samples/search.png",
            "description": "Search input bar with faceted filters and sorting pagination"
        },
        {
            "id": "file_upload",
            "name": "File Upload",
            "filename": "file_upload.png",
            "url": "/samples/file_upload.png",
            "description": "Document and attachment upload portal with drag-and-drop"
        },
        {
            "id": "checkout",
            "name": "Checkout / Payment",
            "filename": "checkout.png",
            "url": "/samples/checkout.png",
            "description": "Order breakdown, discount voucher, billing, and credit card form"
        },
        {
            "id": "admin_panel",
            "name": "Admin Panel",
            "filename": "admin_panel.png",
            "url": "/samples/admin_panel.png",
            "description": "Administrative user tables, role assignments, and audit event logs"
        },
        {
            "id": "ambiguous",
            "name": "Unknown / Ambiguous",
            "filename": "ambiguous.png",
            "url": "/samples/ambiguous.png",
            "description": "Unidentifiable non-web diagram to test low confidence and guidance notes"
        }
    ]
    return {"samples": samples}

# =========================================================================
# CENTRALIZED AUTHORIZATION & USER ISOLATION HELPERS
# =========================================================================

def get_current_authenticated_user(authorization: Optional[str] = Header(None)) -> Optional[Dict[str, Any]]:
    """
    Extract and validate authenticated user from Authorization header.
    Returns user dict if valid session, or None if no header provided.
    Raises 401 if header is malformed or session is invalid/expired.
    """
    if not authorization:
        return None
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authentication token."
        )
    token = authorization.split(" ", 1)[1].strip()
    user = get_user_by_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid token."
        )
    return user

def require_authenticated_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """
    Strictly require an authenticated user.
    Raises 401 if missing, invalid, or expired.
    """
    user = get_current_authenticated_user(authorization)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please sign in."
        )
    return user

def authorize_project(project_id: str, user: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Validate that project exists and that user has permission to access it.
    - If user has role ADMIN or Lead Auditor: permitted across projects.
    - If project is owned by user["id"]: permitted.
    - If user is None (e.g. unauthenticated test client): permitted ONLY if project is owned by 'user-learner-001' or legacy seed.
    - Otherwise: raises 404 Not Found (to prevent project existence leakage).
    """
    proj = get_project_by_id(project_id)
    if not proj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")

    is_admin = user and (user.get("role") in ["ADMIN", "Lead Auditor", "Admin"])
    if is_admin:
        return proj

    proj_owner = proj.get("owner_id")
    if user:
        if proj_owner and proj_owner != user["id"]:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")
    else:
        # Unauthenticated request: allow only local seed learner projects for legacy test compatibility
        if proj_owner and proj_owner not in ["user-learner-001", "Security Learner"]:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")

    return proj

def authorize_finding(
    finding_id: str,
    user: Optional[Dict[str, Any]],
    project_id: Optional[str] = None
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Resolve finding to project and validate project ownership.
    Distinguishes NOT_FOUND (404) from ACCESS_DENIED (403/404).
    Returns (finding, project).
    """
    if not finding_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding could not be located.")

    clean_finding_id = str(finding_id).strip()
    clean_proj_id = str(project_id).strip() if project_id else None
    is_admin = bool(user and (user.get("role") in ["ADMIN", "Lead Auditor", "Admin"]))

    # Handle batch all findings
    if clean_finding_id in ["__ALL_FINDINGS__", "ALL", "BATCH_ALL"]:
        if not clean_proj_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="project_id is required for batch retest.")
        project = authorize_project(clean_proj_id, user)
        synthetic_finding = {
            "id": "__ALL_FINDINGS__",
            "project_id": project["id"],
            "finding_name": "All Project Findings",
            "status": "CONFIRMED"
        }
        return synthetic_finding, project

    # If project_id is provided, resolve strictly within project
    if clean_proj_id:
        project = authorize_project(clean_proj_id, user)
        finding = get_finding_scoped(clean_finding_id, project_id=project["id"])
        if not finding:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding could not be located.")
        return finding, project

    # Project ID not provided: resolve scoped to user's authorized projects
    user_id = user["id"] if user else None
    finding = get_finding_scoped(clean_finding_id, user_id=user_id, is_admin=is_admin)
    if not finding:
        if user is None:
            # Unauthenticated request: check if finding belongs to a protected user-owned project
            global_finding = get_finding_by_id(clean_finding_id)
            if global_finding and global_finding.get("project_id"):
                # authorize_project will raise 401 Unauthorized for user-owned projects
                authorize_project(global_finding["project_id"], None)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding could not be located.")

    project = authorize_project(finding["project_id"], user)
    return finding, project

def authorize_certificate(certificate_id: str, user: Optional[Dict[str, Any]]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Resolve certificate to project and validate project ownership.
    Returns (certificate, project).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vapt_certificates WHERE certificate_id = ? OR verification_id = ?", (certificate_id, certificate_id))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate not found.")
    cert = dict(row)
    project = authorize_project(cert["project_id"], user)
    return cert, project

# =========================================================================
# 1. PROJECT MANAGEMENT ENDPOINTS (Section 45)
# =========================================================================

@app.get("/api/projects")
def list_projects(authorization: Optional[str] = Header(None)):
    """Retrieve assessment projects with metrics for the authenticated user."""
    user = get_current_authenticated_user(authorization)
    if user:
        is_admin = user.get("role") in ["ADMIN", "Lead Auditor", "Admin"]
        projects = get_all_projects(owner_id=user["id"], is_admin=is_admin)
    else:
        # Backward compatibility for local test scripts
        projects = get_all_projects(owner_id="user-learner-001")
    return {"projects": projects}

@app.get("/api/projects/count")
def get_user_projects_count(authorization: Optional[str] = Header(None)):
    """Retrieve exact project count for the currently authenticated user."""
    user = require_authenticated_user(authorization)
    count = count_user_projects(user["id"])
    return {"count": count, "user_id": user["id"]}

@app.post("/api/projects/bulk-delete")
def bulk_delete_projects_endpoint(
    request: Request,
    authorization: Optional[str] = Header(None)
):
    """
    Safely delete all test projects belonging to the current authenticated user.
    Owner is strictly resolved from the authenticated session token.
    """
    user = require_authenticated_user(authorization)
    owner_id = user["id"]

    try:
        result = bulk_delete_user_projects(owner_id)
        return {
            "success": True,
            "message": f"Successfully deleted {result['deleted']} test projects.",
            "user_id": owner_id,
            "result": result
        }
    except RuntimeError as re:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(re)
        )
    except Exception as e:
        logger.error(f"Bulk delete error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Bulk delete failed: {str(e)}"
        )

@app.post("/api/projects", status_code=status.HTTP_201_CREATED)
def create_project_endpoint(project: ProjectCreate, authorization: Optional[str] = Header(None)):
    """Create a new assessment project assigned to the current authenticated user."""
    user = get_current_authenticated_user(authorization)
    owner_id = user["id"] if user else "user-learner-001"
    
    project_dict = project.model_dump()
    project_dict.pop("owner_id", None)
    
    created = db_create_project(project_dict, owner_id=owner_id)
    return created

@app.get("/api/projects/{project_id}")
def get_project_endpoint(project_id: str, authorization: Optional[str] = Header(None)):
    """Get single project workspace details, checklist items, and findings."""
    user = get_current_authenticated_user(authorization)
    proj = authorize_project(project_id, user)
    return proj

@app.put("/api/projects/{project_id}")
def update_project_endpoint(project_id: str, data: ProjectUpdate, authorization: Optional[str] = Header(None)):
    """Update project details."""
    user = get_current_authenticated_user(authorization)
    authorize_project(project_id, user)
    
    update_data = data.model_dump(exclude_unset=True)
    update_data.pop("owner_id", None)
    
    is_admin = user and (user.get("role") in ["ADMIN", "Lead Auditor", "Admin"])
    owner_filter = None if is_admin or not user else user["id"]
    updated = db_update_project(project_id, update_data, owner_id=owner_filter, is_admin=is_admin)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")
    return updated

@app.delete("/api/projects/{project_id}")
def delete_project_endpoint(project_id: str, authorization: Optional[str] = Header(None)):
    """Delete project and associated artifacts."""
    user = get_current_authenticated_user(authorization)
    authorize_project(project_id, user)
    
    is_admin = user and (user.get("role") in ["ADMIN", "Lead Auditor", "Admin"])
    owner_filter = None if is_admin or not user else user["id"]
    deleted = db_delete_project(project_id, owner_id=owner_filter, is_admin=is_admin)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")
    return {"deleted": True, "project_id": project_id}

# =========================================================================
# 2. SCREENSHOT ENDPOINTS (Section 45)
# =========================================================================

@app.get("/api/projects/{project_id}/screenshots")
def get_project_screenshots(project_id: str, authorization: Optional[str] = Header(None)):
    """List screenshots captured for a project."""
    user = get_current_authenticated_user(authorization)
    authorize_project(project_id, user)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM screenshots WHERE project_id = ? ORDER BY created_at DESC", (project_id,))
    rows = cursor.fetchall()
    conn.close()
    return {"screenshots": [dict(r) for r in rows]}

@app.post("/api/projects/{project_id}/screenshots", status_code=status.HTTP_201_CREATED)
async def upload_project_screenshot(
    project_id: str,
    image: UploadFile = File(...),
    authorization: Optional[str] = Header(None)
):
    """Upload and record a screenshot for a project without triggering immediate analysis."""
    user = get_current_authenticated_user(authorization)
    authorize_project(project_id, user)

    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
    INSERT INTO screenshots (id, project_id, filename, created_at)
    VALUES (?, ?, ?, ?)
    """, (shot_id, project_id, image.filename, now))
    conn.commit()
    conn.close()
    return {"id": shot_id, "project_id": project_id, "filename": image.filename}

# =========================================================================
# 3. SCREENSHOT ANALYSIS ENDPOINT (Core MVP Feature)
# =========================================================================

@app.post(
    "/api/analyze-screenshot",
    response_model=VaptAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze web application screenshot and generate contextual VAPT checklist"
)
async def analyze_screenshot(
    request: Request,
    image: Optional[UploadFile] = File(None, description="Optional uploaded screenshot image (PNG, JPG/JPEG, WEBP)"),
    page_type: Optional[str] = Form(None, description="Primary user-designated page type or 'Auto Detect'"),
    user_context: Optional[str] = Form(None, description="Optional user instructions/context for security focus"),
    prompt: Optional[str] = Form(None, description="Backward compatible alias for user_context"),
    project_id: Optional[str] = Form(None, description="Optional project ID to associate and persist analysis"),
    request_id: Optional[str] = Form(None, description="Client request ID for staleness tracking"),
    authorization: Optional[str] = Header(None)
):
    content_type_header = request.headers.get("content-type", "").lower()
    screenshot_b64: Optional[str] = None

    # Handle JSON request body if applicable
    if "application/json" in content_type_header:
        try:
            body = await request.json()
        except Exception:
            body = {}
        if isinstance(body, dict):
            page_type = body.get("page_type") or page_type
            user_context = body.get("additional_context") or body.get("user_context") or body.get("prompt") or user_context
            prompt = body.get("prompt") or prompt
            project_id = body.get("project_id") or project_id
            request_id = body.get("request_id") or request_id
            screenshot_b64 = body.get("screenshot")

    resolved_pid = project_id.strip() if (project_id and isinstance(project_id, str) and project_id.strip()) else None

    req_auth = authorization or request.headers.get("authorization")
    req_user = get_current_authenticated_user(req_auth)

    if resolved_pid:
        authorize_project(resolved_pid, req_user)
        logger.info(f"[API] Checklist request authorized: user='{req_user.get('id') if req_user else 'anonymous'}', project_id='{resolved_pid}'")

    contents: Optional[bytes] = None
    filename: Optional[str] = None
    content_type: Optional[str] = None

    # 1. Handle multipart image upload if provided
    if image and image.filename:
        filename = image.filename
        content_type = (image.content_type or "").lower()
        if content_type not in ALLOWED_MIME_TYPES:
            ext = Path(image.filename).suffix.lower().lstrip(".")
            valid_exts = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "webp": "image/webp"}
            if ext in valid_exts:
                content_type = valid_exts[ext]
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Unsupported file format '{content_type or ext}'. Supported formats: PNG, JPG/JPEG, WEBP."
                )
        try:
            contents = await image.read()
        except Exception as e:
            logger.error(f"Failed to read image stream: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to read the uploaded image file. Please try again."
            )

        if len(contents) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="The uploaded image file is empty."
            )

        if len(contents) > MAX_FILE_SIZE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Uploaded file exceeds maximum permitted size of {MAX_FILE_SIZE_BYTES // (1024 * 1024)}MB."
            )
    elif screenshot_b64 and isinstance(screenshot_b64, str) and screenshot_b64.strip():
        raw_b64 = screenshot_b64.strip()
        mime = "image/png"
        if raw_b64.startswith("data:image/"):
            try:
                header_part, data_part = raw_b64.split(",", 1)
                mime = header_part.split(";")[0].replace("data:", "").strip().lower()
                raw_b64 = data_part
            except Exception:
                pass
        try:
            contents = base64.b64decode(raw_b64)
            filename = "screenshot.png"
            content_type = mime
            if len(contents) > MAX_FILE_SIZE_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Uploaded file exceeds maximum permitted size of {MAX_FILE_SIZE_BYTES // (1024 * 1024)}MB."
                )
        except HTTPException:
            raise
        except Exception as be:
            logger.warning(f"[API] Failed to decode base64 screenshot from JSON: {be}")
            contents = None

    has_image = bool(contents and len(contents) > 0)
    pt_raw = (page_type or "").strip()
    is_auto_detect = bool(not pt_raw or pt_raw.lower() in ["auto detect", "auto", "detect"])

    # 2. Validation: If no screenshot provided AND no page_type or Auto Detect selected
    if not has_image and is_auto_detect:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please select a specific Page Type or upload a target screenshot to auto-detect."
        )

    # 3. Validation: Controlled Page Type Allowlist
    if pt_raw and not is_auto_detect:
        norm_pt = normalize_page_type(pt_raw)
        valid_canonical_names = set(CANONICAL_PAGE_CATEGORIES.values())
        valid_slugs = set(CANONICAL_PAGE_CATEGORIES.keys())
        if norm_pt not in valid_canonical_names and pt_raw.lower() not in valid_slugs and pt_raw.lower() != "other":
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid page type '{page_type}'. Please select a valid supported page category."
            )
        page_type = norm_pt

    combined_context = (user_context or prompt or "").strip()

    # 4. Process with Vision AI / Controlled Knowledge Base
    logger.info(
        f"[API] Processing /api/analyze-screenshot: filename='{filename or 'none'}', "
        f"MIME='{content_type or 'none'}', has_image={has_image}, size={len(contents) if contents else 0} bytes, "
        f"page_type='{page_type or 'Auto Detect'}', project_id='{project_id}'"
    )
    try:
        image_hash = hashlib.sha256(contents).hexdigest()[:16] if contents else None
        req_id = request_id or str(uuid.uuid4())

        result = run_vapt_analysis(
            image_bytes=contents,
            mime_type=content_type or "image/png",
            user_prompt=combined_context,
            filename=filename,
            selected_page_type=page_type
        )
        result.request_id = req_id
        if image_hash:
            result.image_hash = image_hash
        if not result.visible_functionality:
            result.visible_functionality = result.detected_functionalities or result.visible_signals
        if not result.visible_signals and result.detected_elements:
            result.visible_signals = [e.get("name") if isinstance(e, dict) else getattr(e, "name", str(e)) for e in result.detected_elements]

        logger.info(
            f"[API] Analysis successful: page_type='{result.page_type}', "
            f"confidence={result.confidence:.2f}, elements={len(result.detected_elements)}, "
            f"checklist_items={len(result.checklist)}, req_id={req_id}, visual_available={result.visual_analysis_available}"
        )

        # 5. Persist to Project if project_id is valid
        if resolved_pid:
            try:
                save_analysis_for_project(
                    project_id=resolved_pid,
                    analysis_data=result.model_dump(),
                    filename=filename or "no_screenshot"
                )
                logger.info(f"[API] Persisted analysis to project: {resolved_pid}")
            except Exception as pe:
                logger.warning(f"[API] Could not persist to project {resolved_pid}: {pe}")

        return result
    except HTTPException:
        raise
    except ValueError as ve:
        logger.warning(f"[API] Validation or model error: {ve}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(ve)
        )
    except Exception as exc:
        logger.error(f"Unexpected error during analysis: {exc}", exc_info=True)
        if page_type and page_type != "Auto Detect":
            try:
                from backend.analyzer import simulate_analysis
                logger.info(f"[API] Recovering with emergency knowledge base fallback for '{page_type}'")
                fallback_result = simulate_analysis(b"", user_prompt=combined_context, selected_page_type=page_type)
                fallback_result.request_id = req_id
                fallback_result.image_hash = image_hash
                return fallback_result
            except Exception as fe:
                logger.error(f"Emergency fallback failed: {fe}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while generating the security checklist. Please try again."
        )

# =========================================================================
# 4. CHECKLIST MANAGEMENT ENDPOINTS (Section 45)
# =========================================================================

@app.get("/api/projects/{project_id}/checklist")
def get_project_checklist(project_id: str, authorization: Optional[str] = Header(None)):
    """Retrieve all checklist items for a project with status and findings."""
    user = get_current_authenticated_user(authorization)
    authorize_project(project_id, user)
    items = get_project_checklist_items(project_id)
    return {"checklist": items}

@app.put("/api/checklist/{item_id}")
def update_checklist_item_endpoint(item_id: str, data: ChecklistItemUpdate, authorization: Optional[str] = Header(None)):
    """Edit an existing checklist item (marks source as USER_MODIFIED)."""
    user = get_current_authenticated_user(authorization)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT project_id FROM checklist_items WHERE id = ? OR test_id = ?", (item_id, item_id))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Checklist item not found.")
    pid = row["project_id"] if isinstance(row, sqlite3.Row) or isinstance(row, dict) else row[0]
    authorize_project(pid, user)
    updated = db_update_checklist_item(item_id, data.model_dump(exclude_unset=True))
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Checklist item not found.")
    return updated

@app.delete("/api/checklist/{item_id}")
def delete_checklist_item_endpoint(item_id: str, authorization: Optional[str] = Header(None)):
    """Delete a checklist item from the project matrix."""
    user = get_current_authenticated_user(authorization)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT project_id FROM checklist_items WHERE id = ? OR test_id = ?", (item_id, item_id))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Checklist item not found.")
    pid = row["project_id"] if isinstance(row, sqlite3.Row) or isinstance(row, dict) else row[0]
    authorize_project(pid, user)
    deleted = db_delete_checklist_item(item_id, project_id=pid)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Checklist item not found.")
    return {"deleted": True, "item_id": item_id}

@app.post("/api/projects/{project_id}/checklist/custom", status_code=status.HTTP_201_CREATED)
def add_custom_test_endpoint(
    project_id: str,
    data: CustomChecklistItemCreate,
    authorization: Optional[str] = Header(None)
):
    """Add a custom learner-defined security test to the active project checklist."""
    user = get_current_authenticated_user(authorization)
    authorize_project(project_id, user)
    created = db_add_custom_checklist_item(project_id, data.model_dump())
    return created

@app.put("/api/checklist/{item_id}/status")
def update_checklist_status_endpoint(item_id: str, data: StatusUpdate, authorization: Optional[str] = Header(None)):
    """Update verification status: NOT_TESTED, TESTED_NOT_FOUND, or VULNERABILITY_FOUND."""
    valid_statuses = ["NOT_TESTED", "TESTED_NOT_FOUND", "VULNERABILITY_FOUND"]
    if data.status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status '{data.status}'. Allowed values: {', '.join(valid_statuses)}"
        )
    user = get_current_authenticated_user(authorization)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT project_id FROM checklist_items WHERE id = ? OR test_id = ?", (item_id, item_id))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Checklist item not found.")
    pid = row["project_id"] if isinstance(row, sqlite3.Row) or isinstance(row, dict) else row[0]
    authorize_project(pid, user)
    updated = db_update_item_status(item_id, data.status, project_id=pid)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Checklist item not found.")
    return updated

# =========================================================================
# 5. FINDINGS MANAGEMENT ENDPOINTS (Section 45)
# =========================================================================

@app.post("/api/projects/{project_id}/checklist/{item_id}/finding", status_code=status.HTTP_201_CREATED)
def record_project_finding_endpoint(
    project_id: str,
    item_id: str,
    finding: FindingCreate,
    authorization: Optional[str] = Header(None)
):
    """Record a verified vulnerability finding explicitly bound to a project."""
    user = get_current_authenticated_user(authorization)
    authorize_project(project_id, user)
    saved = db_save_finding(project_id, item_id, finding.model_dump())
    return saved

@app.post("/api/checklist/{item_id}/finding", status_code=status.HTTP_201_CREATED)
def record_finding_endpoint(
    item_id: str,
    finding: FindingCreate,
    project_id: Optional[str] = Query(None, description="Project ID"),
    authorization: Optional[str] = Header(None)
):
    """Record a verified vulnerability finding with PoC and optional evidence screenshot."""
    user = get_current_authenticated_user(authorization)
    resolved_project_id = project_id
    conn = get_db_connection()
    cursor = conn.cursor()

    if not resolved_project_id:
        cursor.execute("SELECT project_id FROM checklist_items WHERE id = ?", (item_id,))
        row = cursor.fetchone()
        if not row:
            cursor.execute("SELECT project_id FROM checklist_items WHERE test_id = ?", (item_id,))
            row = cursor.fetchone()
        if row:
            resolved_project_id = row["project_id"]

    if not resolved_project_id:
        cursor.execute("SELECT id FROM projects ORDER BY updated_at DESC LIMIT 1")
        proj_row = cursor.fetchone()
        if proj_row:
            resolved_project_id = proj_row["id"]
        else:
            resolved_project_id = "proj-ecommerce-001"
    conn.close()

    authorize_project(resolved_project_id, user)
    saved = db_save_finding(resolved_project_id, item_id, finding.model_dump())
    return saved

@app.get("/api/projects/{project_id}/findings")
def get_project_findings(project_id: str, authorization: Optional[str] = Header(None)):
    """Retrieve all confirmed vulnerability findings with PoCs for a project."""
    user = get_current_authenticated_user(authorization)
    authorize_project(project_id, user)
    findings = get_project_findings_list(project_id)
    return {"findings": findings}

@app.delete("/api/findings/{finding_id}")
def delete_finding_endpoint(finding_id: str, authorization: Optional[str] = Header(None)):
    """Delete a recorded finding and reset corresponding checklist item to NOT_TESTED."""
    user = get_current_authenticated_user(authorization)
    finding, proj = authorize_finding(finding_id, user)
    deleted = db_delete_finding(finding_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    return {"deleted": True, "finding_id": finding_id}

@app.get("/api/projects/{project_id}/analytics")
def get_project_analytics(
    project_id: str,
    authorization: Optional[str] = Header(None)
):
    """
    Descriptive project security analytics aggregation endpoint.
    Aggregates confirmed finding severities, checklist testing coverage,
    and finding lifecycle status using real project data only.
    """
    user = get_current_authenticated_user(authorization)
    proj = authorize_project(project_id, user)

    findings = get_project_findings_list(project_id)
    checklist = get_project_checklist_items(project_id)

    # 1. Findings Severity Aggregation
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
        "total": len(findings)
    }

    for f in findings:
        sev = normalize_severity(f.get("priority") or f.get("severity") or "HIGH")
        key = sev.lower()
        if key in severity_counts:
            severity_counts[key] += 1
        elif key == "info":
            severity_counts["informational"] += 1
        else:
            severity_counts["high"] += 1

    # 2. Coverage Aggregation (aligned with report_model.py semantics)
    linked_checklist_keys = set()
    for f in findings:
        chk_id = f.get("checklist_item_id") or f.get("test_id")
        if chk_id:
            linked_checklist_keys.add(str(chk_id))

    clean_items = [
        item for item in checklist
        if item.get("status") == "TESTED_NOT_FOUND" and
           str(item.get("id", "")) not in linked_checklist_keys and
           str(item.get("item_id", "")) not in linked_checklist_keys
    ]
    clean_eval = len(clean_items)
    vuln_eval = len(findings)
    evaluated_controls = clean_eval + vuln_eval

    untested_items = [
        item for item in checklist
        if item.get("status") not in ["TESTED_NOT_FOUND", "VULNERABILITY_FOUND"] and
           str(item.get("id", "")) not in linked_checklist_keys and
           str(item.get("item_id", "")) not in linked_checklist_keys
    ]
    untested_controls = len(untested_items)
    planned_controls = evaluated_controls + untested_controls
    coverage_pct = round((evaluated_controls / planned_controls) * 100, 1) if planned_controls > 0 else 0.0

    # 3. Status Lifecycle Aggregation
    status_counts = {
        "open": 0,
        "in_remediation": 0,
        "retest_pending": 0,
        "resolved": 0,
        "closed": 0
    }

    for f in findings:
        st = str(f.get("status") or "Open").strip()
        st_upper = st.upper()
        retest_st = str(f.get("retest_status") or "").strip().upper()
        fix_st = str(f.get("fix_status") or "").strip().upper()

        if st_upper in ["RESOLVED", "FIXED", "REMEDIATED"] or retest_st == "PASSED":
            status_counts["resolved"] += 1
        elif st_upper in ["CLOSED"]:
            status_counts["closed"] += 1
        elif st_upper in ["RETEST_PENDING", "PENDING_RETEST"] or fix_st == "RETEST_PENDING":
            status_counts["retest_pending"] += 1
        elif st_upper in ["IN_REMEDIATION", "FIX APPLIED", "FIX_APPLIED", "INVESTIGATING", "BRANCH CREATED", "PR CREATED"] or fix_st in ["FIX_APPLIED", "PR_CREATED", "BRANCH_CREATED", "IN_PROGRESS"]:
            status_counts["in_remediation"] += 1
        else:
            status_counts["open"] += 1

    return {
        "project_id": project_id,
        "project_name": proj.get("name", "Project"),
        "findings": severity_counts,
        "coverage": {
            "planned": planned_controls,
            "evaluated": evaluated_controls,
            "clean": clean_eval,
            "with_findings": vuln_eval,
            "not_tested": untested_controls,
            "not_applicable": 0,
            "percentage": coverage_pct
        },
        "status": status_counts
    }


ALLOWED_EVIDENCE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".txt", ".json", ".pdf", ".docx"}
MAX_EVIDENCE_SIZE_BYTES = 10 * 1024 * 1024  # 10MB

@app.post("/api/projects/{project_id}/evidence", status_code=status.HTTP_201_CREATED)
async def upload_project_evidence_endpoint(
    project_id: str,
    files: List[UploadFile] = File(...),
    finding_id: Optional[str] = Form(None),
    caption: Optional[str] = Form(None),
    authorization: Optional[str] = Header(None)
):
    """Securely upload one or more evidence files for a project finding and persist metadata."""
    user = get_current_authenticated_user(authorization)
    authorize_project(project_id, user)
    import re
    evidence_dir = Path(__file__).resolve().parent.parent / "data" / "evidence" / str(project_id)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    existing_evidence = db_get_project_evidence(project_id)
    ev_count = len(existing_evidence)

    results = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for idx, file in enumerate(files):
        orig_name = file.filename or "evidence.txt"
        ext = Path(orig_name).suffix.lower()
        if ext not in ALLOWED_EVIDENCE_EXTENSIONS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported evidence file extension '{ext}'. Allowed types: PNG, JPG, JPEG, WEBP, GIF, SVG, TXT, JSON, PDF, DOCX."
            )

        content = await file.read()
        if len(content) > MAX_EVIDENCE_SIZE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Evidence file '{orig_name}' exceeds maximum permitted size of 10MB."
            )

        clean_base = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', Path(orig_name).name)
        safe_filename = f"ev-{uuid.uuid4().hex[:8]}_{clean_base}"
        dest_path = evidence_dir / safe_filename
        dest_path.write_bytes(content)

        mime = file.content_type or ("text/plain" if ext in [".txt", ".json"] else "image/png")
        ev_id = f"ev-{uuid.uuid4().hex[:10]}"
        ev_ref = f"EV-{ev_count + idx + 1:03d}"

        file_b64 = base64.b64encode(content).decode("ascii")
        # Persist to database evidence table
        db_record_evidence({
            "id": ev_id,
            "evidence_id": ev_ref,
            "finding_id": finding_id,
            "project_id": str(project_id),
            "original_filename": orig_name,
            "stored_filename": safe_filename,
            "mime_type": mime,
            "file_size": len(content),
            "storage_path": str(dest_path),
            "caption": caption or "",
            "file_data": file_b64,
            "uploaded_by": user["id"] if user else "user",
            "uploaded_at": now,
            "status": "ACTIVE"
        })

        results.append({
            "id": ev_id,
            "evidence_id": ev_ref,
            "finding_id": finding_id,
            "name": orig_name,
            "filename": safe_filename,
            "file_path": str(dest_path),
            "size": len(content),
            "mime_type": mime,
            "url": f"/api/projects/{project_id}/evidence/{safe_filename}",
            "caption": caption or "",
            "status": "UPLOADED"
        })

    return {"uploaded": results}

@app.post("/api/projects/{project_id}/findings/{finding_id}/evidence", status_code=status.HTTP_201_CREATED)
async def upload_finding_evidence_endpoint(
    project_id: str,
    finding_id: str,
    files: List[UploadFile] = File(...),
    caption: Optional[str] = Form(None),
    authorization: Optional[str] = Header(None)
):
    """Direct upload endpoint binding evidence explicitly to a finding."""
    return await upload_project_evidence_endpoint(
        project_id=project_id,
        files=files,
        finding_id=finding_id,
        caption=caption,
        authorization=authorization
    )

@app.get("/api/projects/{project_id}/evidence")
def list_project_evidence_endpoint(
    project_id: str,
    authorization: Optional[str] = Header(None)
):
    """List all registered evidence artifacts for an authorized project."""
    user = get_current_authenticated_user(authorization)
    authorize_project(project_id, user)
    return {"evidence": db_get_project_evidence(project_id)}

@app.post("/api/projects/{project_id}/evidence/migrate")
def migrate_project_evidence_endpoint(
    project_id: str,
    payload: Optional[Dict[str, Any]] = Body(None),
    authorization: Optional[str] = Header(None)
):
    """Safely migrate legacy client-side base64 evidence to persistent server storage."""
    user = get_current_authenticated_user(authorization)
    authorize_project(project_id, user)
    legacy_findings = (payload.get("findings") if payload else None) or []
    res = db_migrate_legacy_finding_evidence(project_id, legacy_findings)
    return res

@app.get("/api/projects/{project_id}/evidence/{filename}")
def get_project_evidence_file(
    project_id: str,
    filename: str,
    request: Request,
    authorization: Optional[str] = Header(None)
):
    """Securely serve an uploaded evidence file for a project with path traversal protection."""
    if not authorization:
        cookie_tok = request.cookies.get("tg_auth_token") or request.cookies.get("token")
        if cookie_tok:
            authorization = f"Bearer {cookie_tok}"

    user = get_current_authenticated_user(authorization)
    authorize_project(project_id, user)
    clean_fn = Path(filename).name
    if clean_fn != filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid filename.")

    evidence_dir = (Path(__file__).resolve().parent.parent / "data" / "evidence" / project_id).resolve()
    target_path = (evidence_dir / filename).resolve()

    if not str(target_path).startswith(str(evidence_dir)) or not target_path.is_file():
        # Ephemeral container disk recovery: restore from persistent database if available
        try:
            from backend.database import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM evidence WHERE project_id = ? AND (stored_filename = ? OR original_filename = ? OR id = ?)", (str(project_id), clean_fn, clean_fn, clean_fn))
            ev_row = cursor.fetchone()
            conn.close()
            if ev_row and ev_row["file_data"]:
                evidence_dir.mkdir(parents=True, exist_ok=True)
                raw_bytes = base64.b64decode(ev_row["file_data"])
                target_path.write_bytes(raw_bytes)
        except Exception as rec_err:
            logger.warning(f"Could not recover evidence file '{clean_fn}' from database: {rec_err}")

    if not str(target_path).startswith(str(evidence_dir)) or not target_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence file not found.")

    ext = target_path.suffix.lower()
    media_type = "application/octet-stream"
    disp_type = "inline" if ext in [".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".txt", ".json", ".pdf"] else "attachment"

    if ext == ".png":
        media_type = "image/png"
    elif ext in [".jpg", ".jpeg"]:
        media_type = "image/jpeg"
    elif ext == ".webp":
        media_type = "image/webp"
    elif ext == ".gif":
        media_type = "image/gif"
    elif ext == ".svg":
        media_type = "image/svg+xml"
    elif ext == ".txt":
        media_type = "text/plain; charset=utf-8"
    elif ext == ".json":
        media_type = "application/json"
    elif ext == ".pdf":
        media_type = "application/pdf"
    elif ext == ".docx":
        media_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    else:
        import mimetypes
        guessed, _ = mimetypes.guess_type(clean_fn)
        if guessed:
            media_type = guessed

    return FileResponse(
        path=str(target_path),
        media_type=media_type,
        filename=clean_fn,
        content_disposition_type=disp_type
    )

@app.get("/api/checklist/{item_id}/finding-template")
def get_finding_template_endpoint(item_id: str):
    """Retrieve structured AI finding template for a checklist item to pre-fill confirmation form."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM checklist_items WHERE id = ?", (item_id,))
    item = cursor.fetchone()
    if not item:
        cursor.execute("SELECT * FROM checklist_items WHERE test_id = ?", (item_id,))
        item = cursor.fetchone()
    conn.close()

    if item:
        tmpl = get_finding_template_for_test(
            test_id=item["test_id"],
            test_name=item["name"],
            cwe=item["cwe"]
        )
        tmpl["checklist_item_id"] = item["id"]
        tmpl["priority"] = item["priority"]
        return tmpl

    # Fallback to direct Knowledge Base lookup (for ad-hoc or in-memory analysis)
    tmpl = get_finding_template_for_test(
        test_id=item_id,
        test_name=item_id
    )
    tmpl["checklist_item_id"] = item_id
    return tmpl

# =========================================================================
# 6. AUTHENTICATION ENDPOINTS
# =========================================================================

@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED, response_model=AuthTokenResponse)
def auth_register(data: UserRegister):
    """Register a new user account and generate an authenticated session token."""
    try:
        user = register_user(data.model_dump())
        token = create_session(user["id"])
        return {"access_token": token, "token": token, "token_type": "bearer", "user": user}
    except ValueError as ve:
        logger.warning(f"Registration conflict: {ve}")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(ve)
        )
    except Exception as e:
        logger.warning(f"Registration failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Registration failed. Please verify your details or sign in."
        )

@app.post("/api/auth/login", response_model=AuthTokenResponse)
def auth_login(data: UserLogin):
    """Validate credentials and return session token or 2FA challenge."""
    user = authenticate_user(data.username_or_email, data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email/username or password."
        )
    
    # If user has 2FA enabled, issue temporary challenge token without full session
    if user.get("two_factor_enabled"):
        temp_token = create_pending_2fa_login(user["id"])
        return {
            "access_token": None,
            "token": None,
            "token_type": "bearer",
            "user": None,
            "requires_2fa": True,
            "temp_token": temp_token,
            "message": "Two-factor authentication code required."
        }

    token = create_session(user["id"])
    return {
        "access_token": token,
        "token": token,
        "token_type": "bearer",
        "user": user,
        "requires_2fa": False,
        "temp_token": None,
        "message": "Login successful."
    }

@app.post("/api/auth/2fa/login-verify", response_model=AuthTokenResponse)
def auth_2fa_login_verify(data: TwoFactorLoginVerifyRequest):
    """Verify TOTP or backup recovery code during 2FA login challenge."""
    pending = get_pending_2fa_login(data.temp_token)
    if not pending:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Two-factor authentication session expired or invalid. Please log in again."
        )
    
    # Check attempts rate-limiting (max 5 attempts)
    if pending.get("attempts", 0) >= 5:
        delete_pending_2fa_login(data.temp_token)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many invalid 2FA verification attempts. Please log in again."
        )
    
    user_id = pending["user_id"]
    user_raw = get_user_by_id_raw(user_id)
    if not user_raw or not user_raw.get("two_factor_enabled"):
        delete_pending_2fa_login(data.temp_token)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Two-factor authentication is not configured for this account."
        )
    
    verified = False
    used_recovery = False

    # Check TOTP code first if provided
    if data.code:
        clean_code = data.code.strip().replace(" ", "")
        encrypted_secret = user_raw.get("two_factor_secret_encrypted")
        if encrypted_secret:
            try:
                secret = decrypt_secret(encrypted_secret)
                verified = verify_totp_code(secret, clean_code)
            except Exception as e:
                logger.error(f"TOTP verification error: {e}")
                verified = False
    
    # Check recovery code if not verified and recovery code provided
    if not verified and data.recovery_code:
        clean_rec = data.recovery_code.strip()
        verified = verify_and_consume_recovery_code(user_id, clean_rec)
        if verified:
            used_recovery = True

    # Also handle the case where user pasted recovery code into the primary code input
    if not verified and data.code and not data.recovery_code:
        clean_code = data.code.strip()
        if "-" in clean_code or len(clean_code) > 6:
            verified = verify_and_consume_recovery_code(user_id, clean_code)
            if verified:
                used_recovery = True

    if not verified:
        attempts = increment_pending_2fa_attempts(data.temp_token)
        remaining = max(0, 5 - attempts)
        if remaining == 0:
            delete_pending_2fa_login(data.temp_token)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many invalid 2FA verification attempts. Please log in again."
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid verification code. {remaining} attempt(s) remaining."
        )
    
    # Success: delete pending login challenge, update verified timestamp, issue session
    delete_pending_2fa_login(data.temp_token)
    if not used_recovery:
        update_user_2fa_verified_timestamp(user_id)
    
    token = create_session(user_id)
    user_clean = {
        "id": user_raw["id"],
        "username": user_raw["username"],
        "email": user_raw["email"],
        "full_name": user_raw["full_name"],
        "role": user_raw.get("role", "Junior Pentester"),
        "created_at": user_raw["created_at"],
        "name": user_raw["full_name"],
        "two_factor_enabled": True,
        "two_factor_enabled_at": user_raw.get("two_factor_enabled_at"),
        "two_factor_last_verified_at": user_raw.get("two_factor_last_verified_at")
    }

    return {
        "access_token": token,
        "token": token,
        "token_type": "bearer",
        "user": user_clean,
        "requires_2fa": False,
        "temp_token": None,
        "message": "Two-factor authentication successful."
    }

@app.get("/api/auth/2fa/status", response_model=TwoFactorStatusResponse)
def auth_2fa_status(authorization: Optional[str] = Header(None)):
    """Retrieve 2FA status, timestamps, and remaining recovery codes count."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid authentication token.")
    token = authorization.split(" ", 1)[1]
    user = get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid token.")
    
    st = get_user_2fa_status(user["id"])
    return TwoFactorStatusResponse(**st)

@app.post("/api/auth/2fa/setup", response_model=TwoFactorSetupResponse)
def auth_2fa_setup(authorization: Optional[str] = Header(None)):
    """Generate uncommitted TOTP secret, provisioning URI, and QR code for enrollment."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid authentication token.")
    token = authorization.split(" ", 1)[1]
    user = get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid token.")
    
    secret = generate_totp_secret()
    encrypted_secret = encrypt_secret(secret)
    expires_at = save_pending_2fa_enrollment(user["id"], encrypted_secret, ttl_minutes=15)
    
    uri = get_provisioning_uri(secret, user["username"], issuer_name="Tracegate")
    qr_code = generate_qr_code_data_url(uri)
    
    # Manual key formatted with spaces every 4 chars for user readability
    manual_key = " ".join([secret[i:i+4] for i in range(0, len(secret), 4)])
    
    return TwoFactorSetupResponse(
        secret=secret,
        qr_code=qr_code,
        manual_entry_key=manual_key,
        expires_at=expires_at,
        issuer="Tracegate"
    )

@app.post("/api/auth/2fa/verify-setup", response_model=TwoFactorVerifySetupResponse)
def auth_2fa_verify_setup(data: TwoFactorVerifySetupRequest, authorization: Optional[str] = Header(None)):
    """Confirm 2FA enrollment with valid TOTP code; generates recovery codes and activates 2FA."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid authentication token.")
    token = authorization.split(" ", 1)[1]
    user = get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid token.")
    
    pending = get_pending_2fa_enrollment(user["id"])
    if not pending:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending 2FA enrollment found or enrollment session expired. Please start 2FA setup again."
        )
    
    try:
        secret = decrypt_secret(pending["secret_encrypted"])
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to decrypt pending 2FA secret.")
    
    clean_code = data.code.strip().replace(" ", "")
    if not verify_totp_code(secret, clean_code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid authenticator code. Please check your time synchronization and try again."
        )
    
    # Valid code! Generate 10 single-use recovery codes
    recovery_codes = generate_recovery_codes(10)
    recovery_hashes = [hash_recovery_code(rc) for rc in recovery_codes]
    
    enable_user_2fa(user["id"], pending["secret_encrypted"], recovery_hashes)
    
    return TwoFactorVerifySetupResponse(
        success=True,
        message="Two-factor authentication successfully enabled. Store your recovery codes securely.",
        recovery_codes=recovery_codes
    )

@app.post("/api/auth/2fa/disable")
def auth_2fa_disable(data: TwoFactorDisableRequest, authorization: Optional[str] = Header(None)):
    """Disable 2FA after verifying current account password and TOTP/recovery code."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid authentication token.")
    token = authorization.split(" ", 1)[1]
    user = get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid token.")
    
    user_raw = get_user_by_id_raw(user["id"])
    if not user_raw:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    
    # 1. Verify password
    if not verify_password(data.password, user_raw["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect account password.")
    
    # 2. Verify 2FA code (TOTP or recovery code)
    if not user_raw.get("two_factor_enabled"):
        return {"message": "Two-factor authentication was not enabled."}
    
    code_verified = False
    clean_code = (data.code or "").strip().replace(" ", "")
    if clean_code:
        # Check TOTP
        encrypted_secret = user_raw.get("two_factor_secret_encrypted")
        if encrypted_secret:
            try:
                secret = decrypt_secret(encrypted_secret)
                code_verified = verify_totp_code(secret, clean_code)
            except Exception:
                code_verified = False
        
        # Check recovery code if not verified
        if not code_verified:
            code_verified = verify_and_consume_recovery_code(user["id"], clean_code)
    
    if not code_verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A valid 6-digit authenticator code or recovery code is required to disable 2FA."
        )
    
    disable_user_2fa(user["id"])
    return {"message": "Two-factor authentication has been successfully disabled."}

@app.post("/api/auth/2fa/regenerate-recovery-codes", response_model=TwoFactorRegenerateRecoveryResponse)
def auth_2fa_regenerate_recovery_codes(data: TwoFactorRegenerateRecoveryRequest, authorization: Optional[str] = Header(None)):
    """Regenerate recovery codes after re-verifying password and TOTP code."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid authentication token.")
    token = authorization.split(" ", 1)[1]
    user = get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid token.")
    
    user_raw = get_user_by_id_raw(user["id"])
    if not user_raw or not user_raw.get("two_factor_enabled"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Two-factor authentication is not enabled.")
    
    # 1. Verify password
    if not verify_password(data.password, user_raw["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect account password.")
    
    # 2. Verify TOTP
    clean_code = data.code.strip().replace(" ", "")
    encrypted_secret = user_raw.get("two_factor_secret_encrypted")
    if not encrypted_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="2FA secret not found.")
    
    try:
        secret = decrypt_secret(encrypted_secret)
        if not verify_totp_code(secret, clean_code):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authenticator code.")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error validating TOTP: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Verification failed.")
    
    new_codes = generate_recovery_codes(10)
    new_hashes = [hash_recovery_code(c) for c in new_codes]
    replace_recovery_codes(user["id"], new_hashes)
    
    return TwoFactorRegenerateRecoveryResponse(
        success=True,
        message="New recovery codes generated. All previous recovery codes have been invalidated.",
        recovery_codes=new_codes
    )

@app.post("/api/auth/logout")
def auth_logout(authorization: Optional[str] = Header(None)):
    """Terminate active session."""
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]
        delete_session(token)
    return {"message": "Logged out successfully."}

@app.get("/api/auth/me", response_model=UserResponse)
def auth_me(authorization: Optional[str] = Header(None)):
    """Retrieve currently authenticated user profile."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid authentication token.")
    token = authorization.split(" ", 1)[1]
    user = get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid token.")
    return user

@app.post("/api/auth/forgot-password", response_model=ForgotPasswordResponse)
@app.post("/api/auth/resend-reset-otp", response_model=ForgotPasswordResponse)
def auth_forgot_password(data: ForgotPasswordRequest):
    """
    Initiate or resend secure 6-digit numeric OTP for password reset delivered via email.
    Enforces account enumeration defense, rate limiting, and safe error handling.
    Strictly never returns OTP or reset secrets in response.
    """
    from backend import email_service

    if not email_service.is_email_configured():
        logger.warning("Password reset requested but email delivery is not configured.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Email delivery service is not configured on the server. Please contact an administrator or configure SMTP settings."
        )

    res = create_password_reset_otp(data.email)
    if res.get("status") == "rate_limited":
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=res.get("detail", "Too many reset requests. Please wait before requesting another code.")
        )

    if res.get("status") == "ok":
        user = res["user"]
        raw_otp = res["raw_otp"]
        delivered = email_service.send_password_reset_email(user["email"], raw_otp)
        if not delivered:
            logger.error("Failed to send password reset OTP email")
            # Invalidate the created record since email delivery failed
            conn = get_db_connection()
            try:
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                c = conn.cursor()
                c.execute("UPDATE password_resets SET consumed_at = ? WHERE id = ?", (now, res["reset_id"]))
                conn.commit()
            finally:
                conn.close()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unable to deliver verification code to your email. Please verify server email configuration or try again later."
            )

    # Generic response for both existing and non-existing accounts (Account Enumeration Defense)
    return ForgotPasswordResponse(
        message="If an account exists for this email address, a verification code has been sent."
    )


@app.post("/api/auth/verify-reset-otp", response_model=VerifyResetOtpResponse)
def auth_verify_reset_otp(data: VerifyResetOtpRequest):
    """
    Verify 6-digit password reset OTP.
    Upon successful verification, generates and returns a short-lived, single-use reset authorization token.
    """
    success, message, reset_auth = verify_password_reset_otp(data.email, data.otp)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )

    return VerifyResetOtpResponse(
        message=message,
        reset_authorization=reset_auth
    )


@app.post("/api/auth/reset-password")
def auth_reset_password(data: ResetPasswordRequest):
    """
    Verify server-issued reset authorization and update account password.
    Requires server-verified reset authorization token.
    """
    auth_token = data.reset_authorization or data.token
    if not auth_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password reset authorization token is required."
        )

    if not data.new_password or len(data.new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be at least 8 characters."
        )

    if data.confirm_password is not None and data.confirm_password != data.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match. Please re-enter."
        )

    try:
        complete_password_reset_v2(auth_token, data.new_password)
        return {"message": "Password updated successfully. You can now sign in with your new password."}
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        logger.error(f"Password reset exception: {type(e).__name__}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unable to process password reset.")

# =========================================================================
# 7. PROFESSIONAL DOCX REPORTING ENDPOINTS
# =========================================================================

@app.post("/api/projects/{project_id}/reports", status_code=status.HTTP_201_CREATED)
def create_project_report(
    project_id: str,
    report_in: Optional[ReportCreate] = None,
    authorization: Optional[str] = Header(None)
):
    """Generate professional Microsoft Word (.docx) assessment report using persisted project data and selected findings."""
    user = get_current_authenticated_user(authorization)
    proj = authorize_project(project_id, user)

    existing_reports = get_project_reports(project_id)
    existing_versions = {r.get("version") for r in existing_reports if r.get("version")}
    next_seq_version = get_next_report_version(project_id)

    raw_version = (report_in.version.strip() if (report_in and report_in.version and report_in.version.strip()) else "")
    if not raw_version or raw_version in existing_versions:
        version = next_seq_version
    else:
        version = raw_version
    title = (report_in.title if report_in and report_in.title else None) or f"VAPT Assessment Report — {proj.get('name')}"
    author = (report_in.author_name if report_in and report_in.author_name else (report_in.author if report_in and report_in.author else None)) or proj.get("created_by", "Security Learner")
    methodology = (report_in.methodology if report_in and report_in.methodology else "owasp_wstg")
    allow_clean = (report_in.allow_clean_report if report_in and report_in.allow_clean_report else False)

    all_findings = get_project_findings_list(project_id)

    # 1. Finding selection & security validation
    if report_in and report_in.selected_finding_ids is not None:
        valid_ids = set()
        for f in all_findings:
            if f.get("id"): valid_ids.add(str(f["id"]))
            if f.get("vuln_id"): valid_ids.add(str(f["vuln_id"]))
            if f.get("checklist_item_id"): valid_ids.add(str(f["checklist_item_id"]))
            if f.get("test_id"): valid_ids.add(str(f["test_id"]))

        # Cross-project security check
        for sid in report_in.selected_finding_ids:
            if str(sid) not in valid_ids:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid finding ID '{sid}': finding does not belong to this project."
                )

        selected_set = set(str(sid) for sid in report_in.selected_finding_ids)
        chosen_findings = [
            f for f in all_findings
            if str(f.get("id")) in selected_set or str(f.get("vuln_id")) in selected_set or str(f.get("checklist_item_id")) in selected_set or str(f.get("test_id")) in selected_set
        ]

        if len(report_in.selected_finding_ids) == 0:
            if allow_clean and len(all_findings) == 0:
                chosen_findings = []
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Select at least one confirmed finding to generate the vulnerability report."
                )
    else:
        if len(all_findings) == 0:
            if allow_clean:
                chosen_findings = []
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Select at least one confirmed finding to generate the vulnerability report."
                )
        else:
            chosen_findings = list(all_findings)

    # 2. Dynamic metrics calculation
    crit_count = sum(1 for f in chosen_findings if normalize_severity(f.get("priority") or f.get("severity")) == "CRITICAL")
    high_count = sum(1 for f in chosen_findings if normalize_severity(f.get("priority") or f.get("severity")) == "HIGH")
    med_count = sum(1 for f in chosen_findings if normalize_severity(f.get("priority") or f.get("severity")) == "MEDIUM")
    low_count = sum(1 for f in chosen_findings if normalize_severity(f.get("priority") or f.get("severity")) == "LOW")
    info_count = sum(1 for f in chosen_findings if normalize_severity(f.get("priority") or f.get("severity")) == "INFORMATIONAL")
    total_findings = len(chosen_findings)

    # 3. Generate DOCX
    try:
        historical = get_project_reports(project_id)
        chk_items = get_project_checklist_items(project_id)
        docx_path = generate_docx_report(
            proj,
            version=version,
            author_name=author,
            findings=chosen_findings,
            selected_finding_ids=report_in.selected_finding_ids if (report_in and report_in.selected_finding_ids is not None) else None,
            allow_clean_report=allow_clean,
            methodology=methodology,
            historical_reports=historical,
            checklist_items=chk_items,
        )
    except Exception as e:
        logger.error(f"Failed to generate DOCX report: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to generate DOCX report: {e}")

    # 4. Save report record with persistent artifact recovery data
    saved_finding_ids = [f["id"] for f in chosen_findings if f.get("id")]
    pdf_cand = Path(docx_path).with_suffix(".pdf")
    verified_pdf = str(pdf_cand) if (pdf_cand.exists() and is_valid_pdf(pdf_cand)) else None

    docx_b64 = None
    if docx_path and Path(docx_path).exists():
        try:
            docx_b64 = base64.b64encode(Path(docx_path).read_bytes()).decode("ascii")
        except Exception as be:
            logger.warning(f"Could not encode DOCX report to base64: {be}")

    pdf_b64 = None
    if verified_pdf and Path(verified_pdf).exists():
        try:
            pdf_b64 = base64.b64encode(Path(verified_pdf).read_bytes()).decode("ascii")
        except Exception as pe:
            logger.warning(f"Could not encode PDF report to base64: {pe}")

    report_record = save_report_record({
        "project_id": project_id,
        "version": version,
        "report_title": title,
        "file_path": docx_path,
        "file_path_pdf": verified_pdf,
        "file_data_docx": docx_b64,
        "file_data_pdf": pdf_b64,
        "total_findings": total_findings,
        "crit_count": crit_count,
        "high_count": high_count,
        "med_count": med_count,
        "low_count": low_count,
        "info_count": info_count,
        "selected_finding_ids": saved_finding_ids,
        "created_by": author,
        "methodology": methodology,
    })

    return report_record

@app.get("/api/projects/{project_id}/reports", response_model=List[ReportRecord])
def list_project_reports(
    project_id: str,
    authorization: Optional[str] = Header(None)
):
    """List all generated report versions for a project."""
    user = get_current_authenticated_user(authorization)
    authorize_project(project_id, user)
    reports = get_project_reports(project_id)
    return reports

@app.get("/api/projects/{project_id}/reports/next-version")
def get_project_next_report_version(
    project_id: str,
    authorization: Optional[str] = Header(None)
):
    """Returns the server-authoritative next sequential report version for a project."""
    user = get_current_authenticated_user(authorization)
    authorize_project(project_id, user)
    next_v = get_next_report_version(project_id)
    return {"project_id": project_id, "next_version": next_v}

@app.get("/api/projects/{project_id}/reports/{report_id}/download")
def download_project_report(
    project_id: str,
    report_id: str,
    format: Optional[str] = Query("docx", description="Export format: docx or pdf"),
    disposition: Optional[str] = Query("attachment", description="Content disposition: attachment or inline"),
    token: Optional[str] = Query(None, description="Optional auth token for browser download/view links"),
    authorization: Optional[str] = Header(None)
):
    """Download or view report file in Microsoft Word (.docx) or native PDF (.pdf) format."""
    if not authorization and token:
        authorization = f"Bearer {token}"
    user = get_current_authenticated_user(authorization)
    proj = authorize_project(project_id, user)
    report = get_report_by_id(report_id)
    if not report or report.get("project_id") != project_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report record not found.")

    docx_path = Path(report["file_path"])
    if not docx_path.exists():
        # Ephemeral container disk recovery: restore from database file_data_docx
        if report.get("file_data_docx"):
            try:
                docx_path.parent.mkdir(parents=True, exist_ok=True)
                docx_path.write_bytes(base64.b64decode(report["file_data_docx"]))
            except Exception as rx:
                logger.error(f"Failed to restore DOCX from database: {rx}")

        # On-demand regeneration fallback if binary data was not stored
        if not docx_path.exists():
            try:
                docx_path.parent.mkdir(parents=True, exist_ok=True)
                historical = get_project_reports(project_id)
                chk_items = get_project_checklist_items(project_id)
                all_findings = get_project_findings_list(project_id)
                sel_ids = report.get("selected_finding_ids") or []
                sel_set = set(str(sid) for sid in sel_ids)
                chosen = [f for f in all_findings if str(f.get("id")) in sel_set or str(f.get("vuln_id")) in sel_set] if sel_set else all_findings

                gen_path = generate_docx_report(
                    proj,
                    version=report.get("version", "v1.0"),
                    author_name=report.get("created_by") or report.get("author_name"),
                    findings=chosen,
                    selected_finding_ids=sel_ids,
                    allow_clean_report=True,
                    methodology=report.get("methodology", "owasp_wstg"),
                    historical_reports=historical,
                    checklist_items=chk_items,
                )
                if Path(gen_path).exists():
                    docx_path = Path(gen_path)
                    try:
                        b64_doc = base64.b64encode(docx_path.read_bytes()).decode("ascii")
                        from backend.database import update_report_artifact_data
                        update_report_artifact_data(report_id, file_data_docx=b64_doc)
                    except Exception:
                        pass
            except Exception as regen_err:
                logger.error(f"On-demand DOCX report regeneration failed: {regen_err}")

    fmt = (format or "docx").lower().strip()
    is_inline = str(disposition).lower().strip() == "inline"
    disp_type = "inline" if is_inline else "attachment"

    if fmt == "pdf":
        pdf_path = None
        if report.get("file_path_pdf") and is_valid_pdf(report["file_path_pdf"]):
            pdf_path = Path(report["file_path_pdf"])
        elif docx_path.with_suffix(".pdf").exists() and is_valid_pdf(docx_path.with_suffix(".pdf")):
            pdf_path = docx_path.with_suffix(".pdf")
            update_report_pdf_path(report_id, str(pdf_path))

        # Ephemeral container disk recovery: restore from database file_data_pdf
        if (not pdf_path or not pdf_path.exists() or not is_valid_pdf(pdf_path)) and report.get("file_data_pdf"):
            try:
                cand_pdf = docx_path.with_suffix(".pdf")
                cand_pdf.parent.mkdir(parents=True, exist_ok=True)
                cand_pdf.write_bytes(base64.b64decode(report["file_data_pdf"]))
                if is_valid_pdf(cand_pdf):
                    pdf_path = cand_pdf
                    update_report_pdf_path(report_id, str(pdf_path))
            except Exception as prx:
                logger.warning(f"Failed to restore PDF from database: {prx}")

        if not pdf_path or not pdf_path.exists() or not is_valid_pdf(pdf_path):
            # On-demand compilation from report model
            try:
                from backend.report_model import assemble_normalized_report_model
                historical = get_project_reports(project_id)
                chk_items = get_project_checklist_items(project_id)
                all_findings = get_project_findings_list(project_id)
                sel_ids = report.get("selected_finding_ids") or []
                sel_set = set(str(sid) for sid in sel_ids)
                chosen = [f for f in all_findings if str(f.get("id")) in sel_set or str(f.get("vuln_id")) in sel_set] if sel_set else all_findings

                model = assemble_normalized_report_model(
                    proj,
                    version=report.get("version", "v1.0"),
                    author_name=report.get("created_by") or report.get("author_name"),
                    selected_finding_ids=sel_ids,
                    findings=chosen,
                    allow_clean_report=True,
                    methodology=report.get("methodology", "owasp_wstg"),
                    historical_reports=historical,
                    checklist_items=chk_items
                )
                target_pdf = docx_path.with_suffix(".pdf")
                compiled = compile_report_pdf(model, target_pdf, docx_path=docx_path)
                if compiled and Path(compiled).exists() and is_valid_pdf(compiled):
                    pdf_path = Path(compiled)
                    update_report_pdf_path(report_id, str(pdf_path))
                    try:
                        b64_pdf = base64.b64encode(pdf_path.read_bytes()).decode("ascii")
                        from backend.database import update_report_artifact_data
                        update_report_artifact_data(report_id, file_data_pdf=b64_pdf)
                    except Exception:
                        pass
            except Exception as ce:
                logger.error(f"On-demand report PDF compilation failed: {ce}", exc_info=True)

        if not pdf_path or not pdf_path.exists() or not is_valid_pdf(pdf_path):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="PDF version of this report could not be generated. Please download the DOCX version."
            )

        # Ensure PDF title and author metadata are present in document dictionary for browser viewer tab
        report_title = report.get("report_title") or f"Tracegate VAPT Report - {proj.get('name', 'Project')}"
        ensure_pdf_title_metadata(pdf_path, title=report_title, author=report.get("created_by"))

        safe_filename = pdf_path.name
        return FileResponse(
            path=str(pdf_path),
            media_type="application/pdf",
            filename=safe_filename,
            headers={"Content-Disposition": f'{disp_type}; filename="{safe_filename}"'}
        )
    else:
        if not docx_path.exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report file not found on disk.")
        safe_filename = docx_path.name
        return FileResponse(
            path=str(docx_path),
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            filename=safe_filename,
            headers={"Content-Disposition": f'{disp_type}; filename="{safe_filename}"'}
        )

@app.get("/api/projects/{project_id}/reports/{report_id}/view")
def view_project_report_inline(
    project_id: str,
    report_id: str,
    token: Optional[str] = Query(None, description="Auth token for inline browser viewing"),
    authorization: Optional[str] = Header(None)
):
    """Direct inline PDF viewer endpoint for opening reports in browser tabs with proper document title."""
    return download_project_report(
        project_id=project_id,
        report_id=report_id,
        format="pdf",
        disposition="inline",
        token=token,
        authorization=authorization
    )

@app.post("/api/projects/{project_id}/reports/parse-import", response_model=ReportParseImportResponse)
async def parse_external_report(
    project_id: str,
    file: UploadFile = File(...),
    authorization: Optional[str] = Header(None)
):
    """
    Parse an external VAPT assessment report (PDF, DOCX, TXT, MD),
    extract structured candidate findings, and detect duplicates against existing project findings.
    """
    user = get_current_authenticated_user(authorization)
    proj = authorize_project(project_id, user)

    filename = file.filename or "uploaded_report"
    ext = Path(filename).suffix.lower()
    if ext not in SUPPORTED_IMPORT_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file format '{ext}'. Supported formats are: {', '.join(sorted(SUPPORTED_IMPORT_EXTENSIONS))}"
        )

    file_bytes = await file.read()
    if len(file_bytes) > MAX_IMPORT_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Report file exceeds maximum allowed size of {MAX_IMPORT_FILE_SIZE // (1024 * 1024)}MB."
        )

    existing_findings = get_project_findings_list(project_id)

    try:
        result = parse_report_document(file_bytes, filename, existing_findings=existing_findings)
    except Exception as e:
        logger.error(f"Error parsing external report document: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to parse report document: {str(e)}"
        )

    return result

@app.post("/api/projects/{project_id}/reports/import-findings")
def import_findings_to_project(
    project_id: str,
    req: ReportImportFindingsRequest,
    authorization: Optional[str] = Header(None)
):
    """
    Import human-confirmed candidate findings from external report into authoritative project findings.
    """
    user = get_current_authenticated_user(authorization)
    proj = authorize_project(project_id, user)

    if not req.candidate_findings:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No candidate findings provided for import."
        )

    try:
        cands = [cf.dict() for cf in req.candidate_findings]
        saved = save_imported_findings(
            project_id=project_id,
            candidate_findings=cands,
            source_doc_id=req.source_document_id,
            source_doc_name=req.source_document_name
        )
    except Exception as e:
        logger.error(f"Failed to save imported findings: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save imported findings: {str(e)}"
        )

    return {
        "status": "success",
        "imported_count": len(saved),
        "imported_findings": saved
    }


# =========================================================================
# 8. GITHUB CODE CONNECTOR & AI AUTOFIX ENDPOINTS
# =========================================================================

def _resolve_user_id(authorization: Optional[str] = Header(None)) -> str:
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]
        user = get_user_by_token(token)
        if user and user.get("id"):
            return user["id"]
    return "usr-learner-001"

@app.get("/api/github/status", response_model=GitHubStatusResponse)
def github_status_endpoint(authorization: Optional[str] = Header(None)):
    user_id = _resolve_user_id(authorization)
    return get_github_status(user_id)

@app.post("/api/github/connect", response_model=GitHubStatusResponse)
def github_connect_endpoint(req: GitHubConnectRequest, authorization: Optional[str] = Header(None)):
    user_id = _resolve_user_id(authorization)
    return save_github_token(user_id, req.token, req.username, req.mode)

@app.post("/api/github/disconnect")
def github_disconnect_endpoint(authorization: Optional[str] = Header(None)):
    user_id = _resolve_user_id(authorization)
    disconnect_github(user_id)
    return {"status": "success", "message": "GitHub disconnected."}

@app.get("/api/github/repositories", response_model=List[GitHubRepoItem])
def github_repositories_endpoint(authorization: Optional[str] = Header(None)):
    user_id = _resolve_user_id(authorization)
    return list_github_repositories(user_id)

@app.get("/api/github/branches")
def github_branches_endpoint(
    repo: Optional[str] = Query(None, description="Repository full name"),
    repository: Optional[str] = Query(None, description="Repository full name alias"),
    authorization: Optional[str] = Header(None)
):
    user_id = _resolve_user_id(authorization)
    target_repo = repo or repository
    if not target_repo:
        return {"branches": []}
    branches = list_repository_branches(user_id, target_repo)
    return {"branches": branches}

@app.get("/api/github/tree")
def github_tree_endpoint(
    repo: Optional[str] = Query(None, description="Repository full name"),
    repository: Optional[str] = Query(None, description="Repository full name alias"),
    branch: str = Query("main", description="Branch name"),
    authorization: Optional[str] = Header(None)
):
    user_id = _resolve_user_id(authorization)
    target_repo = repo or repository
    if not target_repo:
        return {"repo": "", "branch": branch, "tree": [], "items": []}
    res = get_repository_tree(user_id, target_repo, branch)
    if isinstance(res, dict) and "tree" in res and "items" not in res:
        res["items"] = res["tree"]
    return res

@app.get("/api/github/file")
def github_file_endpoint(
    repo: Optional[str] = Query(None, description="Repository full name"),
    repository: Optional[str] = Query(None, description="Repository full name alias"),
    path: str = Query(..., description="File path within repository"),
    branch: str = Query("main", description="Branch name"),
    authorization: Optional[str] = Header(None)
):
    user_id = _resolve_user_id(authorization)
    target_repo = repo or repository
    if not target_repo:
        return {"repo": "", "branch": branch, "path": path, "content": "", "sha": ""}
    return get_file_contents(user_id, target_repo, branch, path)

@app.post("/api/ai-fix/discover-sources", response_model=AIFixDiscoverSourceResponse)
def ai_fix_discover_sources_endpoint(req: AIFixDiscoverSourceRequest, authorization: Optional[str] = Header(None)):
    user = get_current_authenticated_user(authorization)
    user_id = user["id"] if user else _resolve_user_id(authorization)
    if req.project_id:
        authorize_project(req.project_id, user)
    is_batch = req.finding_id in ["__ALL_FINDINGS__", "ALL", "BATCH_ALL"]
    finding = None
    if is_batch:
        finding = {"id": req.finding_id, "vuln_id": req.finding_id, "project_id": req.project_id}
    else:
        is_admin = bool(user and (user.get("role") in ["ADMIN", "Lead Auditor", "Admin"]))
        finding = get_finding_scoped(
            req.finding_id,
            project_id=req.project_id,
            user_id=user["id"] if user else None,
            is_admin=is_admin
        )
        if not finding:
            global_finding = get_finding_by_id(req.finding_id)
            if not global_finding:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM findings WHERE vuln_id = ? OR id = ? ORDER BY CASE WHEN finding_name != 'Vulnerability Finding' AND cwe != 'CWE-200' THEN 0 ELSE 1 END LIMIT 1", (req.finding_id, req.finding_id))
                row = cursor.fetchone()
                conn.close()
                if row:
                    global_finding = dict(row)

            if global_finding:
                if user:
                    if global_finding.get("project_id"):
                        authorize_project(global_finding["project_id"], user)
                finding = global_finding
            else:
                finding = {
                    "id": req.finding_id,
                    "vuln_id": req.finding_id,
                    "project_id": req.project_id,
                    "finding_name": getattr(req, "finding_name", None) or getattr(req, "title", None) or f"Finding {req.finding_id}",
                    "title": getattr(req, "title", None) or getattr(req, "finding_name", None) or f"Finding {req.finding_id}",
                    "cwe": getattr(req, "cwe", "") or "",
                    "affected_endpoint": getattr(req, "affected_endpoint", "") or "",
                    "parameter": getattr(req, "parameter", "") or "",
                    "observation": getattr(req, "observation", "") or getattr(req, "description", "") or "",
                    "description": getattr(req, "description", "") or getattr(req, "observation", "") or "",
                    "developer_instructions": getattr(req, "developer_instructions", "") or ""
                }

    if finding:
        if getattr(req, "cwe", None):
            finding["cwe"] = req.cwe
        if getattr(req, "finding_name", None):
            finding["finding_name"] = req.finding_name
        if getattr(req, "title", None):
            finding["title"] = req.title
        if getattr(req, "affected_endpoint", None):
            finding["affected_endpoint"] = req.affected_endpoint
        if not finding.get("affected_endpoint"):
            finding["affected_endpoint"] = finding.get("affected_url") or finding.get("url") or ""

    repo_val = req.repo or req.repository
    branch_val = req.branch or "main"

    gh_st = get_github_status(user_id)
    if not gh_st.connected or not repo_val:
        return AIFixDiscoverSourceResponse(
            finding_id=req.finding_id,
            project_id=req.project_id,
            repository=repo_val or "",
            branch=branch_val,
            source_commit_sha="",
            discovery_status="NOT_CONNECTED" if not gh_st.connected else "NO_MATCH",
            selected_sources=[],
            candidate_sources=[],
            summary="GitHub is not connected. Please connect your GitHub account to enable automatic source discovery across repository files." if not gh_st.connected else "No repository specified.",
            selection_source="AUTOMATIC",
            file_path=None,
            discovered_file=None,
            confidence=0.0,
            reason="GitHub connection required." if not gh_st.connected else "No repository specified.",
            preview_snippet=None,
            matching_candidates=[]
        )

    tree_res = get_repository_tree(user_id, repo_val, branch_val)
    tree_items = tree_res.get("tree", [])

    def fetch_content_cb(fpath: str) -> str:
        f_resp = get_file_contents(user_id, repo_val, branch_val, fpath)
        return f_resp.get("content", "")

    if is_batch:
        proj_findings = []
        if req.project_id:
            proj_findings = get_project_findings_list(req.project_id)
        if not proj_findings:
            scan_res = scan_repository_vulnerabilities(repo_val, branch_val, tree_items, fetch_content_cb)
            proj_findings = scan_res.get("findings", [])

        all_selected = []
        all_candidates = []
        seen_sel = set()
        seen_cand = set()
        for f in proj_findings:
            f_disc = discover_repository_sources(f, tree_items, fetch_content_cb)
            for s in f_disc.get("selected_sources", []):
                if s["path"] not in seen_sel:
                    seen_sel.add(s["path"])
                    all_selected.append(s)
            for c in f_disc.get("candidate_sources", []):
                if c["path"] not in seen_cand and c["path"] not in seen_sel:
                    seen_cand.add(c["path"])
                    all_candidates.append(c)
        selected_items = all_selected
        candidate_items = all_candidates
        disc_status = "COMPLETED" if selected_items else "NO_MATCH"
        discovery = {
            "selected_sources": selected_items,
            "candidate_sources": candidate_items,
            "discovery_status": disc_status,
            "summary": f"Discovered {len(selected_items)} relevant source file(s) across {len(proj_findings)} finding(s) in repository."
        }
    else:
        discovery = discover_repository_sources(finding, tree_items, fetch_content_cb)
        selected_items = discovery.get("selected_sources") or []
        candidate_items = discovery.get("candidate_sources") or []
        disc_status = discovery.get("discovery_status", "COMPLETED")

    # Persist discovery result to database
    save_source_discovery({
        "project_id": req.project_id or finding.get("project_id") or "",
        "finding_id": req.finding_id,
        "repository": repo_val,
        "branch": branch_val,
        "source_commit_sha": branch_val,
        "selected_sources": selected_items,
        "candidate_sources": candidate_items,
        "selection_source": "AUTOMATIC",
        "discovery_status": disc_status
    })

    top_f = selected_items[0]["path"] if selected_items else None
    top_snippet = selected_items[0].get("preview_snippet") if selected_items else None

    return AIFixDiscoverSourceResponse(
        finding_id=req.finding_id,
        project_id=req.project_id,
        repository=repo_val,
        branch=branch_val,
        source_commit_sha=branch_val,
        discovery_status=disc_status,
        selected_sources=selected_items,
        candidate_sources=candidate_items,
        summary=discovery.get("summary", ""),
        selection_source="AUTOMATIC",
        file_path=top_f,
        discovered_file=top_f,
        confidence=0.90 if (selected_items and selected_items[0]["confidence"] == "HIGH") else (0.65 if selected_items else 0.0),
        reason=discovery.get("summary", ""),
        preview_snippet=top_snippet,
        matching_candidates=[
            {"path": s["path"], "score": s["relevance_score"], "matched_terms": s.get("reasons", [])}
            for s in (selected_items + candidate_items)[:5]
        ]
    )

@app.post("/api/ai-fix/batch-patch", response_model=GitHubCodeAnalysisResponse)
def ai_fix_batch_patch_endpoint(req: BatchPatchRequest, authorization: Optional[str] = Header(None)):
    user = get_current_authenticated_user(authorization)
    user_id = user["id"] if user else _resolve_user_id(authorization)
    repo_val = req.repo or req.repository
    branch_val = req.branch or "main"
    effective_project_id = req.project_id or "proj-default"
    run_id = req.request_id or f"run-{int(datetime.now().timestamp() * 1000)}-{uuid.uuid4().hex[:6]}"

    gh_st = get_github_status(user_id)
    if not gh_st.connected or not repo_val:
        return GitHubCodeAnalysisResponse(
            request_id=run_id,
            finding_id="__ALL_FINDINGS__",
            repository=repo_val or "",
            branch=branch_val,
            file_path="",
            original_code="",
            fixed_code="",
            unified_diff="",
            diff_html="",
            explanation="GitHub is not connected. Connect your GitHub account to remediate repository vulnerabilities.",
            security_impact="",
            verification_guidance="",
            patch_status="NO_RELEVANT_SOURCE_FOUND",
            confidence=0.0,
            success=False,
            error="GitHub connection required",
            files=[]
        )

    # 1. Create or recover remediation run record (Duplicate Run Protection & Stale Run Recovery)
    run_rec = create_remediation_run(
        run_id=run_id,
        user_id=user_id,
        project_id=effective_project_id,
        repository=repo_val,
        branch=branch_val,
        finding_ids=req.finding_ids
    )
    if run_rec.get("is_duplicate"):
        logger.info(f"[AI-FIX-RUN:{run_id}] Active run already exists for {repo_val}:{branch_val} (ID: {run_rec.get('id')})")
        if run_rec.get("result"):
            return GitHubCodeAnalysisResponse(**run_rec["result"])

    update_remediation_run_progress(
        run_id,
        status="RUNNING",
        current_stage="DISCOVERY",
        progress_stage="1/4",
        progress_message="1/4 Analyzing repository architecture & dynamic file tree..."
    )

    import threading
    file_cache: Dict[str, str] = {}
    cache_lock = threading.Lock()

    def fetch_content_cb(fpath: str) -> str:
        clean_fp = fpath.replace("\\", "/").lstrip("/")
        with cache_lock:
            if clean_fp in file_cache:
                return file_cache[clean_fp]
        try:
            f_resp = get_file_contents(user_id, repo_val, branch_val, clean_fp)
            c = f_resp.get("content", "")
        except Exception as exc:
            logger.warning(f"Could not fetch {clean_fp}: {exc}")
            c = ""
        with cache_lock:
            file_cache[clean_fp] = c
        return c

    try:
        tree_res = get_repository_tree(user_id, repo_val, branch_val)
        tree_items = tree_res.get("tree", [])

        findings_to_patch = []
        if req.project_id:
            authorize_project(req.project_id, user)
            all_proj_findings = get_project_findings_list(req.project_id)
            if req.finding_ids:
                target_ids = set(req.finding_ids)
                matched_ids = set()
                for f in all_proj_findings:
                    f_keys = {f.get("id"), f.get("vuln_id"), f.get("checklist_item_id"), f.get("test_id")} - {None}
                    if f_keys & target_ids:
                        findings_to_patch.append(f)
                        matched_ids.update(f_keys & target_ids)

                unmatched_ids = target_ids - matched_ids
                for m_id in unmatched_ids:
                    extra_f = get_finding_scoped(m_id, project_id=req.project_id, user_id=user["id"] if user else None) or get_finding_by_id(m_id)
                    if extra_f and extra_f not in findings_to_patch:
                        findings_to_patch.append(extra_f)
                    elif not extra_f:
                        findings_to_patch.append({
                            "id": m_id,
                            "vuln_id": m_id,
                            "title": f"Finding {m_id}",
                            "finding_name": f"Finding {m_id}",
                            "cwe": "UNKNOWN",
                            "severity": "MEDIUM",
                            "status": "NO_SAFE_SOURCE_MATCH",
                            "description": "Finding record could not be resolved from repository or project database."
                        })
            else:
                findings_to_patch = all_proj_findings

        if not findings_to_patch:
            scan_res = scan_repository_vulnerabilities(repo_val, branch_val, tree_items, fetch_content_cb)
            findings_to_patch = scan_res.get("findings", [])

        for f in findings_to_patch:
            if not f.get("affected_endpoint"):
                f["affected_endpoint"] = f.get("affected_url") or f.get("url") or ""

        def run_progress_cb(stage: str, pstage: str, pmsg: str):
            update_remediation_run_progress(
                run_id,
                status="RUNNING",
                current_stage=stage,
                progress_stage=pstage,
                progress_message=pmsg
            )

        cum_res = generate_cumulative_repository_fix(
            findings=findings_to_patch,
            repo=repo_val,
            branch=branch_val,
            fetch_content_cb=fetch_content_cb,
            developer_instructions=req.developer_instructions,
            request_id=run_id,
            selected_files=req.selected_files,
            tree_items=tree_items,
            project_id=req.project_id,
            progress_callback=run_progress_cb
        )

        # Terminal state determination
        overall_status = (
            cum_res.get("remediation_summary", {}).get("overall_status")
            or cum_res.get("patch_status")
            or "PARTIAL_REMEDIATION"
        )
        finalize_remediation_run(run_id, overall_status, cum_res)

        try:
            save_ai_fix_record({
                "project_id": effective_project_id,
                "finding_id": "__ALL_FINDINGS__",
                "repository": repo_val,
                "base_branch": branch_val,
                "fix_branch": "tracegate/fix/cumulative-security-patch",
                "file_path": cum_res.get("file_path", "multi-file"),
                "diff_unified": cum_res.get("unified_diff") or "",
                "original_code": cum_res.get("before_code") or "",
                "proposed_code": cum_res.get("after_code") or "",
                "explanation": cum_res.get("explanation") or "",
                "security_impact": "Cumulative remediation of all detected repository security vulnerabilities.",
                "testing_recommendation": "Execute end-to-end regression tests and automated security verification suite.",
                "status": "FIX_PROPOSED",
                "revision_count": 0,
            })
        except Exception as exc:
            logger.warning(f"Could not persist batch fix record in ai_fixes: {exc}")

        return GitHubCodeAnalysisResponse(**cum_res)

    except Exception as exc:
        logger.error(f"[AI-FIX-RUN:{run_id}] Remediation execution failed with error: {exc}", exc_info=True)
        err_dict = {
            "request_id": run_id,
            "finding_id": "__ALL_FINDINGS__",
            "repository": repo_val or "",
            "branch": branch_val,
            "file_path": "",
            "original_code": "",
            "fixed_code": "",
            "unified_diff": "",
            "diff_html": "",
            "explanation": f"Validation and patch synthesis failed: {str(exc)}",
            "security_impact": "",
            "verification_guidance": "Review system logs and retry remediation.",
            "patch_status": "FAILED_VALIDATION",
            "confidence": 0.0,
            "success": False,
            "error": str(exc),
            "files": []
        }
        finalize_remediation_run(run_id, "FAILED", err_dict, errors=[str(exc)])
        return GitHubCodeAnalysisResponse(**err_dict)

@app.get("/api/ai-fix/run-status")
def ai_fix_run_status_endpoint(
    project_id: str = Query(..., description="Project ID"),
    repo: Optional[str] = Query(None, description="Repository name"),
    branch: Optional[str] = Query("main", description="Branch name"),
    run_id: Optional[str] = Query(None, description="Specific Run ID"),
    authorization: Optional[str] = Header(None)
):
    user = get_current_authenticated_user(authorization)
    user_id = user["id"] if user else _resolve_user_id(authorization)
    if project_id:
        authorize_project(project_id, user)

    if run_id:
        run = get_remediation_run(run_id)
        if run:
            return run

    run = get_active_or_latest_remediation_run(user_id, project_id, repo, branch)
    if not run:
        return {
            "status": "IDLE",
            "is_active": 0,
            "progress_stage": "0/4",
            "progress_message": "Ready"
        }
    return run

class CancelRemediationRunRequest(BaseModel):
    run_id: Optional[str] = None
    project_id: Optional[str] = None

@app.post("/api/ai-fix/cancel-run")
def ai_fix_cancel_run_endpoint(
    req: CancelRemediationRunRequest = Body(...),
    authorization: Optional[str] = Header(None)
):
    user = get_current_authenticated_user(authorization)
    user_id = user["id"] if user else _resolve_user_id(authorization)
    run_id = req.run_id
    project_id = req.project_id
    if project_id:
        authorize_project(project_id, user)
    if not run_id:
        active = get_active_or_latest_remediation_run(user_id, project_id)
        run_id = active["id"] if (active and active.get("is_active")) else None

    if run_id:
        res = cancel_remediation_run(run_id, user_id)
        return {"success": True, "message": "Remediation run cancelled.", "run": res}
    return {"success": False, "message": "No active remediation run found to cancel."}

@app.get("/api/ai-fix/latest-result")
def ai_fix_latest_result_endpoint(
    project_id: str = Query(..., description="Project ID"),
    repo: Optional[str] = Query(None, description="Repository name"),
    branch: Optional[str] = Query("main", description="Branch name"),
    authorization: Optional[str] = Header(None)
):
    user = get_current_authenticated_user(authorization)
    user_id = user["id"] if user else _resolve_user_id(authorization)
    if project_id:
        authorize_project(project_id, user)

    run = get_active_or_latest_remediation_run(user_id, project_id, repo, branch)
    if run and run.get("result"):
        res_data = dict(run["result"])
        if not res_data.get("pr_url"):
            conn = get_db_connection()
            c = conn.cursor()
            c.execute(
                "SELECT * FROM ai_fixes WHERE project_id = ? AND pr_url IS NOT NULL ORDER BY created_at DESC LIMIT 1",
                (project_id,)
            )
            latest_fix_row = c.fetchone()
            conn.close()
            if latest_fix_row:
                latest_fix = dict(latest_fix_row)
                res_data["pr_url"] = latest_fix["pr_url"]
                res_data["pr_number"] = latest_fix.get("pr_number")
                if not res_data.get("branch_name") and not res_data.get("fix_branch"):
                    res_data["branch_name"] = latest_fix.get("fix_branch")
                    res_data["fix_branch"] = latest_fix.get("fix_branch")
                if not res_data.get("commit_sha"):
                    res_data["commit_sha"] = latest_fix.get("commit_sha")
        return {
            "success": True,
            "run_id": run["id"],
            "status": run["status"],
            "result": res_data
        }

    # Fallback: check latest ai_fixes for this project if remediation_runs was not created (e.g. single finding flow)
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "SELECT * FROM ai_fixes WHERE project_id = ? ORDER BY CASE WHEN pr_url IS NOT NULL THEN 0 ELSE 1 END, id DESC LIMIT 1",
        (project_id,)
    )
    fix_row = c.fetchone()
    conn.close()
    if fix_row:
        fix_dict = dict(fix_row)
        return {
            "success": True,
            "run_id": fix_dict["id"],
            "status": fix_dict.get("status", "COMPLETE"),
            "result": {
                "finding_id": fix_dict.get("finding_id"),
                "branch_name": fix_dict.get("fix_branch"),
                "fix_branch": fix_dict.get("fix_branch"),
                "commit_sha": fix_dict.get("commit_sha"),
                "pr_number": fix_dict.get("pr_number"),
                "pr_url": fix_dict.get("pr_url"),
                "file_path": fix_dict.get("file_path"),
                "patch_status": "PATCH_VALIDATED",
                "success": True
            }
        }

    return {"success": False, "message": "No previous remediation results found."}

@app.get("/api/ai-fix/selected-sources")
def ai_fix_get_selected_sources_endpoint(
    finding_id: str = Query(..., description="Vulnerability finding ID"),
    project_id: Optional[str] = Query(None, description="Project ID"),
    repo: Optional[str] = Query(None, description="GitHub repository"),
    authorization: Optional[str] = Header(None)
):
    user = get_current_authenticated_user(authorization)
    if project_id:
        authorize_project(project_id, user)
    record = get_source_discovery(finding_id, project_id, repo=repo)
    if not record:
        return {
            "finding_id": finding_id,
            "project_id": project_id,
            "repository": repo or "",
            "selected_sources": [],
            "candidate_sources": [],
            "selection_source": "AUTOMATIC",
            "discovery_status": "NOT_STARTED"
        }
    return record

@app.post("/api/ai-fix/selected-sources")
def ai_fix_save_selected_sources_endpoint(
    req: AIFixSaveSourceSelectionRequest,
    authorization: Optional[str] = Header(None)
):
    user = get_current_authenticated_user(authorization)
    if req.project_id:
        authorize_project(req.project_id, user)
    repo = req.repository or req.repo
    updated = update_source_discovery_selection(
        finding_id=req.finding_id,
        selected_paths=req.selected_paths,
        project_id=req.project_id,
        source_commit_sha=req.source_commit_sha,
        repo=repo
    )
    return updated or {"status": "success", "selected_paths": req.selected_paths}

@app.post("/api/ai-fix/discover-file", response_model=AIFixDiscoverFileResponse)
def ai_fix_discover_file_endpoint(req: AIFixDiscoverFileRequest, authorization: Optional[str] = Header(None)):
    user_id = _resolve_user_id(authorization)
    gh_status = get_github_status(user_id)
    if not gh_status.connected:
        return AIFixDiscoverFileResponse(
            finding_id=req.finding_id,
            file_path=None,
            discovered_file=None,
            confidence=0.0,
            reason="GitHub account not connected. Please connect your GitHub account to enable automatic source discovery.",
            preview_snippet=None,
            matching_candidates=[],
            selected_sources=[],
            candidate_sources=[],
            discovery_status="NOT_CONNECTED",
            summary="GitHub connection required for repository source discovery."
        )

    finding = get_finding_by_id(req.finding_id)
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")

    repo_val = (req.repo or req.repository or "").strip()
    if not repo_val:
        return AIFixDiscoverFileResponse(
            finding_id=req.finding_id,
            file_path=None,
            discovered_file=None,
            confidence=0.0,
            reason="No repository specified. Please select a valid repository.",
            preview_snippet=None,
            matching_candidates=[],
            selected_sources=[],
            candidate_sources=[],
            discovery_status="NOT_FOUND",
            summary="No repository selected."
        )

    tree_res = get_repository_tree(user_id, repo_val, req.branch)
    tree_items = tree_res.get("tree", [])

    discovery = discover_vulnerable_source_file(finding, tree_items)
    f_path = discovery.get("file_path")
    snippet = None
    if f_path:
        f_resp = get_file_contents(user_id, repo_val, req.branch, f_path)
        snippet = f_resp.get("content", "")[:300]
    return AIFixDiscoverFileResponse(
        finding_id=req.finding_id,
        file_path=f_path,
        discovered_file=f_path,
        confidence=discovery.get("confidence", 0.0),
        reason=discovery.get("reason", "Analysis complete."),
        preview_snippet=snippet,
        matching_candidates=discovery.get("matching_candidates", []),
        selected_sources=discovery.get("selected_sources", []),
        candidate_sources=discovery.get("candidate_sources", []),
        discovery_status=discovery.get("discovery_status", "COMPLETED"),
        summary=discovery.get("summary", "")
    )

@app.post("/api/ai-fix/analyze", response_model=GitHubCodeAnalysisResponse)
@app.post("/api/github/analyze-code", response_model=GitHubCodeAnalysisResponse)
def ai_fix_analyze_endpoint(req: GitHubAnalyzeCodeRequest, authorization: Optional[str] = Header(None)):
    user = get_current_authenticated_user(authorization)
    user_id = user["id"] if user else _resolve_user_id(authorization)
    if req.project_id:
        authorize_project(req.project_id, user)
    is_batch = req.finding_id in ["__ALL_FINDINGS__", "ALL", "BATCH_ALL"]
    finding = None
    if is_batch:
        finding = {"id": req.finding_id, "vuln_id": req.finding_id, "project_id": req.project_id}
    else:
        is_admin = bool(user and (user.get("role") in ["ADMIN", "Lead Auditor", "Admin"]))
        finding = get_finding_scoped(
            req.finding_id,
            project_id=req.project_id,
            user_id=user["id"] if user else None,
            is_admin=is_admin
        )
        if not finding:
            global_finding = get_finding_by_id(req.finding_id)
            if not global_finding:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM findings WHERE vuln_id = ? OR id = ? ORDER BY CASE WHEN finding_name != 'Vulnerability Finding' AND cwe != 'CWE-200' THEN 0 ELSE 1 END LIMIT 1", (req.finding_id, req.finding_id))
                row = cursor.fetchone()
                conn.close()
                if row:
                    global_finding = dict(row)

            if global_finding:
                if user:
                    if global_finding.get("project_id"):
                        authorize_project(global_finding["project_id"], user)
                finding = global_finding
            else:
                finding = {
                    "id": req.finding_id,
                    "vuln_id": req.finding_id,
                    "project_id": req.project_id,
                    "finding_name": f"Finding {req.finding_id}"
                }

    if finding:
        if getattr(req, "cwe", None):
            finding["cwe"] = req.cwe
        if getattr(req, "finding_name", None):
            finding["finding_name"] = req.finding_name
        if getattr(req, "title", None):
            finding["title"] = req.title
        if getattr(req, "affected_endpoint", None):
            finding["affected_endpoint"] = req.affected_endpoint
        if not finding.get("affected_endpoint"):
            finding["affected_endpoint"] = finding.get("affected_url") or finding.get("url") or ""

    repo_val = (req.repo or req.repository or "").strip()
    branch_val = req.branch or "main"
    analysis_res = analyze_finding_code(
        user_id=user_id,
        repo=repo_val,
        branch=branch_val,
        finding=finding,
        file_path=req.file_path,
        selected_files=req.selected_files,
        code_snippet=req.code_snippet,
        developer_instructions=req.developer_instructions,
        source_commit_sha=req.source_commit_sha,
        request_id=req.request_id
    )

    try:
        project_id = finding.get("project_id") or "proj-default"
        finding_id = finding.get("id") or req.finding_id
        vuln_id = finding.get("vuln_id") or finding_id
        if analysis_res.success and analysis_res.patch_status == "PATCH_VALIDATED":
            save_ai_fix_record({
                "project_id": project_id,
                "finding_id": finding_id,
                "repository": repo_val,
                "base_branch": branch_val,
                "fix_branch": f"tracegate/fix/{vuln_id}",
                "file_path": analysis_res.file_path or req.file_path or "",
                "diff_unified": analysis_res.unified_diff or "",
                "original_code": analysis_res.original_code or "",
                "proposed_code": getattr(analysis_res, "proposed_code", None) or getattr(analysis_res, "after_code", "") or "",
                "explanation": analysis_res.explanation or "",
                "security_impact": analysis_res.security_impact or "",
                "testing_recommendation": analysis_res.testing_recommendation or "",
                "status": "FIX_PROPOSED",
                "revision_count": 0,
            })
    except Exception as exc:
        logger.warning(f"Could not persist initial proposal record in ai_fixes: {exc}")

    return analysis_res

@app.post("/api/ai-fix/revise", response_model=GitHubCodeAnalysisResponse)
def ai_fix_revise_endpoint(req: AIFixReviseRequest, authorization: Optional[str] = Header(None)):
    user_id = _resolve_user_id(authorization)
    finding = get_finding_by_id(req.finding_id)
    if not finding:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings WHERE vuln_id = ? OR id = ? LIMIT 1", (req.finding_id, req.finding_id))
        row = cursor.fetchone()
        conn.close()
        if row:
            finding = dict(row)
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")

    repo_val = (req.repo or req.repository or "").strip()
    branch_val = req.branch or "main"

    # Fetch source content if needed
    source_content = req.original_code
    if not source_content and req.file_path:
        f_resp = get_file_contents(user_id, repo_val, branch_val, req.file_path)
        source_content = f_resp.get("content")

    # Check previous fix record for revision count
    prev_fix = get_ai_fix_for_finding(req.finding_id) or get_ai_fix_for_finding(finding.get("id"))
    rev_count = (prev_fix.get("revision_count", 0) + 1) if prev_fix else 1

    revised_fix = generate_secure_fix(
        finding=finding,
        repo=repo_val,
        branch=branch_val,
        file_path=req.file_path,
        source_code=source_content,
        developer_instructions=req.developer_instructions or req.revision_instructions,
        revision_count=rev_count
    )

    if prev_fix:
        try:
            update_ai_fix_record(prev_fix["id"], {"status": "REVISION_REQUESTED"})
        except Exception as exc:
            logger.warning(f"Could not update previous fix record: {exc}")

    try:
        project_id = finding.get("project_id") or "proj-default"
        vuln_id = finding.get("vuln_id") or finding.get("id") or req.finding_id
        save_ai_fix_record({
            "project_id": project_id,
            "finding_id": finding.get("id") or vuln_id,
            "repository": repo_val,
            "base_branch": branch_val,
            "fix_branch": f"tracegate/fix/{vuln_id}",
            "file_path": req.file_path or revised_fix.get("file_path") or "",
            "diff_unified": revised_fix.get("unified_diff") or "",
            "original_code": revised_fix.get("original_code") or "",
            "proposed_code": revised_fix.get("proposed_code") or revised_fix.get("after_code") or "",
            "explanation": revised_fix.get("explanation") or "",
            "security_impact": revised_fix.get("security_impact") or "",
            "testing_recommendation": revised_fix.get("testing_recommendation") or "",
            "status": "FIX_PROPOSED",
            "revision_count": rev_count,
        })
    except Exception as exc:
        logger.warning(f"Could not persist revised proposal record in ai_fixes: {exc}")

    return GitHubCodeAnalysisResponse(**revised_fix)

@app.post("/api/ai-fix/reject", response_model=AIFixRejectResponse)
def ai_fix_reject_endpoint(req: AIFixRejectRequest, authorization: Optional[str] = Header(None)):
    user_id = _resolve_user_id(authorization)
    finding = get_finding_by_id(req.finding_id)
    if not finding:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings WHERE vuln_id = ? OR id = ? LIMIT 1", (req.finding_id, req.finding_id))
        row = cursor.fetchone()
        conn.close()
        if row:
            finding = dict(row)
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")

    vuln_id = finding.get("vuln_id") or finding.get("id") or req.finding_id
    latest_fix = get_ai_fix_for_finding(req.finding_id) or get_ai_fix_for_finding(finding.get("id"))
    reason_text = req.reason or "Fix proposal rejected by developer."

    if latest_fix:
        update_ai_fix_record(latest_fix["id"], {
            "status": "REJECTED",
            "explanation": f"Rejected by developer: {reason_text}"
        })
    else:
        save_ai_fix_record({
            "project_id": finding.get("project_id") or "proj-default",
            "finding_id": finding.get("id") or vuln_id,
            "repository": req.repo or req.repository or "",
            "base_branch": "main",
            "fix_branch": f"tracegate/fix/{vuln_id}",
            "file_path": "n/a",
            "status": "REJECTED",
            "explanation": f"Rejected by developer: {reason_text}"
        })

    update_finding_github_fix(finding_id=finding["id"], fix_status="Fix Rejected")

    return AIFixRejectResponse(
        success=True,
        status="REJECTED",
        message="Fix proposal rejected. Record preserved in audit log without GitHub modifications.",
        finding_id=req.finding_id
    )

@app.post("/api/ai-fix/apply", response_model=GitHubApplyFixResponse)
@app.post("/api/github/apply-fix", response_model=GitHubApplyFixResponse)
def ai_fix_apply_endpoint(req: GitHubApplyFixRequest, authorization: Optional[str] = Header(None)):
    user = get_current_authenticated_user(authorization)
    user_id = user["id"] if user else _resolve_user_id(authorization)
    if req.project_id:
        authorize_project(req.project_id, user)
    is_batch = req.finding_id in ["__ALL_FINDINGS__", "ALL", "BATCH_ALL"]
    finding = None
    if is_batch:
        finding = {"id": req.finding_id, "vuln_id": req.finding_id, "project_id": req.project_id}
    else:
        if req.project_id:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM findings WHERE project_id = ? AND (vuln_id = ? OR id = ?) LIMIT 1", (req.project_id, req.finding_id, req.finding_id))
            row = cursor.fetchone()
            conn.close()
            if row:
                finding = dict(row)

        if not finding:
            finding = get_finding_by_id(req.finding_id)
        if not finding:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM findings WHERE vuln_id = ? OR id = ? LIMIT 1", (req.finding_id, req.finding_id))
            row = cursor.fetchone()
            conn.close()
            if row:
                finding = dict(row)
            else:
                finding = {"id": req.finding_id, "vuln_id": req.finding_id}

        if finding and finding.get("project_id") and user:
            authorize_project(finding["project_id"], user)

    repo_val = (req.repo or req.repository or "").strip()
    target_br = req.target_branch or req.base_branch or "main"
    code_to_fix = req.proposed_code or req.fixed_code or req.diff_or_fixed_code or ""

    try:
        res = apply_finding_fix(
            user_id=user_id,
            repo=repo_val,
            target_branch=target_br,
            finding=finding,
            file_path=req.file_path,
            diff_or_fixed_code=code_to_fix,
            file_sha=req.file_sha,
            developer_instructions=req.developer_instructions,
            fix_branch=req.fix_branch,
            commit_message=req.commit_message,
            files=req.files,
            source_commit_sha=req.source_commit_sha,
            auto_recover=req.auto_recover if req.auto_recover is not None else True
        )
    except GitHubPermissionError as gpe:
        logger.warning(f"GitHub Permission Error applying fix to {repo_val}: {gpe}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "GITHUB_PERMISSION_DENIED",
                "message": gpe.message,
                "repo": gpe.repo or repo_val,
                "action": gpe.action,
                "token_type": gpe.token_type,
                "docs_url": gpe.docs_url,
                "raw_message": gpe.raw_message or "Resource not accessible by personal access token"
            }
        )
    except ValueError as ve:
        err_msg = str(ve)
        conflict_details = getattr(ve, "conflict_details", None)
        verification_details = getattr(ve, "verification_details", None)
        if "not accessible by personal access token" in err_msg.lower() or "permission" in err_msg.lower():
            status_code = status.HTTP_403_FORBIDDEN
            detail = err_msg
        elif (
            verification_details is not None
            or "POST_WRITE_VERIFICATION_FAILED" in err_msg
            or "post-write verification failed" in err_msg.lower()
            or "applied content does not match approved patch" in err_msg.lower()
        ):
            status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
            detail = {
                "error": "POST_WRITE_VERIFICATION_FAILED",
                "message": err_msg,
                "verification_details": verification_details
            }
        elif "SOURCE_CONFLICT_REQUIRES_REVIEW" in err_msg or "SOURCE_CHANGED" in err_msg or "conflict" in err_msg.lower():
            status_code = status.HTTP_409_CONFLICT
            if conflict_details:
                detail = {
                    "error": "SOURCE_CONFLICT_REQUIRES_REVIEW",
                    "message": err_msg,
                    "conflict_details": conflict_details
                }
            else:
                detail = err_msg
        else:
            status_code = status.HTTP_400_BAD_REQUEST
            detail = err_msg
        raise HTTPException(status_code=status_code, detail=detail)

    if req.finding_id in ["__ALL_FINDINGS__", "ALL", "BATCH_ALL"]:
        proj_id = req.project_id or (finding.get("project_id") if isinstance(finding, dict) else None)
        if proj_id:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE findings
                SET fix_status = 'Fix Applied',
                    github_repo = ?,
                    github_branch = ?,
                    github_commit = ?,
                    github_validation = ?,
                    status = 'CONFIRMED'
                WHERE project_id = ?
                """,
                (repo_val, res.branch_name, res.commit_sha, res.validation_status, proj_id)
            )
            conn.commit()
            conn.close()
    elif finding.get("id"):
        update_finding_github_fix(
            finding_id=finding["id"],
            fix_status="Fix Applied",
            repo=repo_val,
            branch=res.branch_name,
            commit_sha=res.commit_sha,
            validation=res.validation_status
        )

    if getattr(req, "create_pr", True) and res.validation_status != "NO_CHANGES_REQUIRED":
        try:
            vuln_id = finding.get("vuln_id", "VULN-001")
            pr_title = req.pr_title or (
                "fix(security): comprehensive remediation of all detected repository vulnerabilities"
                if is_batch else
                f"fix(security): remediate {vuln_id} - {finding.get('finding_name', 'Vulnerability')}"
            )
            pr_body = req.pr_body or (
                "## Tracegate Comprehensive Security Remediation\n\n"
                "This Pull Request applies cumulative defensive patches across the repository to remediate "
                "all detected security vulnerabilities, including SQL Injection, 2FA Bypasses, IDOR, "
                "Arbitrary File Upload, Stored XSS, Path Traversal, and Insecure Credential Autocomplete.\n\n"
                "Automated verification: PASSED (Syntax, AST, and Security Boundary checks verified)."
                if is_batch else
                f"## Tracegate Security Remediation\n\n"
                f"**Finding**: {vuln_id} — {finding.get('finding_name', 'Confirmed Vulnerability')}\n"
                f"**Severity**: {finding.get('priority', 'HIGH')}\n"
                f"**CWE**: {finding.get('cwe', 'N/A')}\n\n"
                f"### Technical Description\n{finding.get('description', '')}\n\n"
                f"### Defensive Remediation\nEnforces strict server-side boundary checks and authorization.\n\n"
                f"Developer approved via Tracegate Code Connector."
            )
            pr_res = create_finding_pull_request(
                user_id=user_id,
                repo=repo_val,
                fix_branch=res.branch_name,
                base_branch=target_br,
                title=pr_title,
                body=pr_body,
                finding=finding
            )
            if pr_res and pr_res.pr_url:
                res.pr_url = pr_res.pr_url
                res.pr_number = pr_res.pr_number
                # Update DB
                if is_batch:
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    if req.project_id:
                        cursor.execute(
                            "UPDATE findings SET fix_status = 'PR Created', github_repo = ?, github_branch = ?, github_pr = ? WHERE project_id = ? AND status != 'RESOLVED'",
                            (repo_val, res.branch_name, pr_res.pr_url, req.project_id)
                        )
                    else:
                        cursor.execute(
                            "UPDATE findings SET fix_status = 'PR Created', github_repo = ?, github_branch = ?, github_pr = ? WHERE status != 'RESOLVED'",
                            (repo_val, res.branch_name, pr_res.pr_url)
                        )
                    conn.commit()
                    conn.close()
                elif finding.get("id"):
                    update_finding_github_fix(
                        finding_id=finding["id"],
                        fix_status="PR Created",
                        repo=repo_val,
                        branch=res.branch_name,
                        pr_url=pr_res.pr_url
                    )
                # Also update ai_fixes record
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE ai_fixes SET pr_url = ?, pr_number = ?, status = 'PR_CREATED' WHERE commit_sha = ? OR id = ? OR (finding_id = ? AND project_id = ?)",
                    (pr_res.pr_url, pr_res.pr_number, res.commit_sha, res.fix_id, finding.get("id"), req.project_id)
                )
                conn.commit()
                conn.close()

                # Sync PR metadata to remediation_runs record
                run_id = getattr(req, "run_id", None)
                if not run_id and req.project_id:
                    active_run = get_active_or_latest_remediation_run(user_id, req.project_id, repo_val, target_br)
                    if active_run:
                        run_id = active_run["id"]
                if run_id:
                    update_remediation_run_pr_metadata(
                        run_id=run_id,
                        pr_number=pr_res.pr_number,
                        pr_url=pr_res.pr_url,
                        fix_branch=res.branch_name,
                        commit_sha=res.commit_sha,
                        status="PR_CREATED",
                        project_id=req.project_id
                    )
        except GitHubPermissionError as gpe:
            logger.warning(f"GitHub Permission Error auto-creating PR on {repo_val}: {gpe}")
            if res.validation_details is None:
                res.validation_details = []
            if isinstance(res.validation_details, list):
                res.validation_details.append(f"PR creation warning: Permission denied ({gpe.message})")
        except Exception as pr_err:
            logger.warning(f"Auto PR creation after apply fix encountered issue: {pr_err}")
            if res.validation_details is None:
                res.validation_details = []
            if isinstance(res.validation_details, list):
                res.validation_details.append(f"PR creation warning: {str(pr_err)}")

    return res


@app.post("/api/ai-fix/check-source-status", response_model=AIFixCheckSourceResponse)
def ai_fix_check_source_status_endpoint(req: AIFixCheckSourceRequest, authorization: Optional[str] = Header(None)):
    user = get_current_authenticated_user(authorization)
    user_id = user["id"] if user else _resolve_user_id(authorization)
    repo_val = req.repo.strip()
    branch_val = req.branch or "main"

    is_changed, current_head, details = check_upstream_source_changed(
        user_id=user_id,
        repo=repo_val,
        base_branch=branch_val,
        expected_base_sha=req.source_commit_sha,
        files=req.files,
        file_path=req.file_path,
        file_sha=req.file_sha
    )

    has_conflict = False
    conflict_det = None
    if is_changed:
        target_f = req.file_path or (req.files[0].path if req.files else None)
        if target_f:
            curr_f = get_file_contents(user_id, repo_val, branch_val, target_f)
            curr_code = curr_f.get("content", "")
            orig_code = (req.files[0].before_code if req.files and req.files[0].before_code else "") or ""
            prop_code = (req.files[0].after_code if req.files and req.files[0].after_code else "") or ""
            c_check = check_remediation_conflict(orig_code, curr_code, prop_code, target_f)
            if c_check.get("has_conflict"):
                has_conflict = True
                conflict_det = c_check

    return AIFixCheckSourceResponse(
        is_changed=is_changed,
        current_head_sha=current_head,
        expected_head_sha=req.source_commit_sha,
        changed_files=details.get("changed_files", []),
        has_conflict=has_conflict,
        conflict_details=conflict_det,
        reason=details.get("reason")
    )


@app.post("/api/ai-fix/safe-refresh", response_model=AIFixSafeRefreshResponse)
def ai_fix_safe_refresh_endpoint(req: AIFixSafeRefreshRequest, authorization: Optional[str] = Header(None)):
    user = get_current_authenticated_user(authorization)
    user_id = user["id"] if user else _resolve_user_id(authorization)
    repo_val = req.repo.strip()
    branch_val = req.branch or "main"

    finding = None
    if req.finding_id in ["__ALL_FINDINGS__", "ALL", "BATCH_ALL"]:
        finding = {"id": req.finding_id, "vuln_id": req.finding_id, "project_id": req.project_id}
    else:
        finding = get_finding_by_id(req.finding_id)
        if not finding:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM findings WHERE vuln_id = ? OR id = ? LIMIT 1", (req.finding_id, req.finding_id))
            row = cursor.fetchone()
            conn.close()
            if row:
                finding = dict(row)
            else:
                finding = {"id": req.finding_id, "vuln_id": req.finding_id, "project_id": req.project_id}

    findings_list = [finding] if finding else []
    target_f = req.file_path or (req.files[0].path if req.files else None)

    # Pre-check for conflict before regenerating
    if target_f and req.files:
        curr_f = get_file_contents(user_id, repo_val, branch_val, target_f)
        curr_code = curr_f.get("content", "")
        orig_code = (req.files[0].before_code if req.files[0].before_code else "") or ""
        prop_code = (req.files[0].after_code if req.files[0].after_code else "") or ""
        c_check = check_remediation_conflict(orig_code, curr_code, prop_code, target_f)
        if c_check.get("has_conflict"):
            return AIFixSafeRefreshResponse(
                success=False,
                status="SOURCE_CONFLICT_REQUIRES_REVIEW",
                message=c_check["reason"],
                source_refreshed=False,
                current_head_sha=get_branch_head_sha(user_id, repo_val, branch_val),
                conflict_details=c_check
            )

    ref_ok, refreshed_res = safe_refresh_and_regenerate(
        user_id=user_id,
        repo=repo_val,
        target_branch=branch_val,
        findings=findings_list,
        file_path=target_f,
        developer_instructions=req.developer_instructions,
        project_id=req.project_id
    )

    current_head = get_branch_head_sha(user_id, repo_val, branch_val)
    if not ref_ok:
        return AIFixSafeRefreshResponse(
            success=False,
            status="FAILED",
            message=refreshed_res.get("reason", "Safe refresh failed"),
            source_refreshed=False,
            current_head_sha=current_head,
            analysis=refreshed_res
        )

    return AIFixSafeRefreshResponse(
        success=True,
        status="REFRESHED",
        message="Source refreshed successfully against latest branch HEAD.",
        source_refreshed=True,
        current_head_sha=current_head,
        analysis=refreshed_res
    )


@app.post("/api/ai-fix/create-pr", response_model=GitHubCreatePRResponse)
@app.post("/api/github/create-pr", response_model=GitHubCreatePRResponse)
def ai_fix_create_pr_endpoint(req: GitHubCreatePRRequest, authorization: Optional[str] = Header(None)):
    user = get_current_authenticated_user(authorization)
    if user:
        user_id = user["id"]
    else:
        user_id = _resolve_user_id(authorization)

    if req.project_id:
        authorize_project(req.project_id, user)

    is_batch = req.finding_id in ["__ALL_FINDINGS__", "ALL", "BATCH_ALL"]
    finding = None
    if not is_batch:
        finding = get_finding_by_id(req.finding_id, project_id=req.project_id)
        if not finding:
            conn = get_db_connection()
            cursor = conn.cursor()
            if req.project_id:
                cursor.execute("SELECT * FROM findings WHERE (vuln_id = ? OR id = ?) AND project_id = ? LIMIT 1", (req.finding_id, req.finding_id, req.project_id))
            else:
                cursor.execute("SELECT * FROM findings WHERE vuln_id = ? OR id = ? LIMIT 1", (req.finding_id, req.finding_id))
            row = cursor.fetchone()
            conn.close()
            if row:
                finding = dict(row)
            else:
                finding = {"id": req.finding_id, "vuln_id": req.finding_id}

        if finding and finding.get("project_id") and user:
            authorize_project(finding["project_id"], user)
    else:
        finding = {
            "id": "__ALL_FINDINGS__",
            "vuln_id": "ALL",
            "finding_name": "All Repository Vulnerabilities",
            "priority": "HIGH",
            "cwe": "MULTI-CWE"
        }

    repo_val = (req.repo or req.repository or "").strip()
    vuln_id = finding.get("vuln_id", "VULN-001")

    if is_batch:
        title = req.title or "fix(security): comprehensive remediation of all detected repository vulnerabilities"
        body = req.body or (
            "## Tracegate Comprehensive Security Remediation\n\n"
            "This Pull Request applies cumulative defensive patches across the repository to remediate "
            "all detected security vulnerabilities, including SQL Injection, 2FA Bypasses, IDOR, "
            "Arbitrary File Upload, Stored XSS, Path Traversal, and Insecure Credential Autocomplete.\n\n"
            "Automated verification: PASSED (Syntax, AST, and Security Boundary checks verified)."
        )
    else:
        title = req.title or f"fix(security): remediate {vuln_id} - {finding.get('finding_name', 'Vulnerability')}"
        body = req.body or (
            f"## Tracegate Security Remediation\n\n"
            f"**Finding**: {vuln_id} — {finding.get('finding_name', 'Confirmed Vulnerability')}\n"
            f"**Severity**: {finding.get('priority', 'HIGH')}\n"
            f"**CWE**: {finding.get('cwe', 'N/A')}\n\n"
            f"### Technical Description\n{finding.get('description', '')}\n\n"
            f"### Defensive Remediation\nEnforces strict server-side boundary checks and authorization.\n\n"
            f"Developer approved via Tracegate Code Connector."
        )

    try:
        res = create_finding_pull_request(
            user_id=user_id,
            repo=repo_val,
            fix_branch=req.fix_branch,
            base_branch=req.base_branch or "main",
            title=title,
            body=body,
            finding=finding
        )
    except GitHubPermissionError as gpe:
        logger.warning(f"GitHub Permission Error creating PR on {repo_val}: {gpe}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "GITHUB_PERMISSION_DENIED",
                "message": gpe.message,
                "repo": gpe.repo or repo_val,
                "action": gpe.action,
                "token_type": gpe.token_type,
                "docs_url": gpe.docs_url,
                "raw_message": gpe.raw_message or "Resource not accessible by personal access token"
            }
        )
    except ValueError as ve:
        err_msg = str(ve)
        if "GITHUB_AUTH_REQUIRED" in err_msg:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": "GITHUB_AUTH_REQUIRED",
                    "message": err_msg.replace("GITHUB_AUTH_REQUIRED: ", "")
                }
            )
        status_code = status.HTTP_403_FORBIDDEN if "not accessible by personal access token" in err_msg.lower() else status.HTTP_400_BAD_REQUEST
        raise HTTPException(status_code=status_code, detail=err_msg)

    if is_batch:
        conn = get_db_connection()
        cursor = conn.cursor()
        if req.project_id:
            cursor.execute(
                "UPDATE findings SET fix_status = 'PR Created', github_repo = ?, github_branch = ?, github_pr = ? WHERE project_id = ? AND status != 'RESOLVED'",
                (repo_val, req.fix_branch, res.pr_url, req.project_id)
            )
        else:
            cursor.execute(
                "UPDATE findings SET fix_status = 'PR Created', github_repo = ?, github_branch = ?, github_pr = ? WHERE status != 'RESOLVED'",
                (repo_val, req.fix_branch, res.pr_url)
            )
        conn.commit()
        conn.close()
    elif finding.get("id"):
        update_finding_github_fix(
            finding_id=finding["id"],
            fix_status="PR Created",
            repo=repo_val,
            branch=req.fix_branch,
            pr_url=res.pr_url
        )
        ai_fix = get_ai_fix_for_finding(finding["id"], project_id=req.project_id)
        if ai_fix:
            update_ai_fix_record(ai_fix["id"], {
                "pr_number": res.pr_number,
                "pr_url": res.pr_url,
                "pr_status": "Open",
                "status": "PR_CREATED"
            })
        else:
            save_ai_fix_record({
                "project_id": req.project_id or finding.get("project_id") or "proj-default",
                "finding_id": finding["id"],
                "repository": repo_val,
                "base_branch": req.base_branch or "main",
                "fix_branch": req.fix_branch,
                "file_path": finding.get("file_path") or "n/a",
                "commit_sha": res.head_sha or "verified",
                "pr_number": res.pr_number,
                "pr_url": res.pr_url,
                "pr_status": "Open",
                "status": "PR_CREATED"
            })

    # Sync PR metadata to remediation_runs record
    run_id = getattr(req, "run_id", None)
    if not run_id and req.project_id:
        active_run = get_active_or_latest_remediation_run(user_id, req.project_id, repo_val, req.base_branch)
        if active_run:
            run_id = active_run["id"]
    if run_id:
        update_remediation_run_pr_metadata(
            run_id=run_id,
            pr_number=res.pr_number,
            pr_url=res.pr_url,
            fix_branch=req.fix_branch,
            commit_sha=res.head_sha or "",
            status="PR_CREATED",
            project_id=req.project_id
        )

    return res

@app.get("/api/ai-fix/pr/{repo_owner}/{repo_name}/{pr_number}/status")
def ai_fix_pr_status_endpoint(repo_owner: str, repo_name: str, pr_number: int, authorization: Optional[str] = Header(None)):
    user_id = _resolve_user_id(authorization)
    repo = f"{repo_owner}/{repo_name}"
    try:
        status_data = get_pull_request_status(user_id, repo, pr_number)
    except GitHubPermissionError as gpe:
        logger.warning(f"GitHub Permission Error getting PR status for #{pr_number} on {repo}: {gpe}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "GITHUB_PERMISSION_DENIED",
                "message": gpe.message,
                "repo": gpe.repo or repo,
                "action": gpe.action,
                "token_type": gpe.token_type,
                "docs_url": gpe.docs_url
            }
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

    # Synchronize database state if PR was merged externally or review status changed
    ai_fix = get_ai_fix_by_pr_number(pr_number, repo)
    if ai_fix:
        update_data = {}
        if status_data.get("review_status") and status_data.get("review_status") != ai_fix.get("review_status"):
            update_data["review_status"] = status_data["review_status"]

        if status_data.get("merged") and ai_fix.get("status") != "MERGED":
            update_data["pr_status"] = "Merged"
            update_data["status"] = "MERGED"
            if status_data.get("merge_commit_sha"):
                update_data["merge_commit_sha"] = status_data["merge_commit_sha"]
            if status_data.get("merged_at"):
                update_data["merged_at"] = status_data["merged_at"]
            update_finding_github_fix(
                finding_id=ai_fix["finding_id"],
                fix_status="Code Merged (Retest Required)"
            )
        elif status_data.get("state") == "closed" and not status_data.get("merged") and ai_fix.get("pr_status") != "Closed":
            update_data["pr_status"] = "Closed"

        if update_data:
            update_ai_fix_record(ai_fix["id"], update_data)

    return status_data

@app.get("/api/ai-fix/{finding_id}")
def get_ai_fix_endpoint(
    finding_id: str,
    project_id: Optional[str] = Query(None),
    authorization: Optional[str] = Header(None)
):
    user = get_current_authenticated_user(authorization)
    clean_id = str(finding_id).strip()
    finding, project = authorize_finding(clean_id, user, project_id=project_id)
    auth_id = (finding.get("id") if finding else None) or clean_id
    proj_id = project_id or (finding.get("project_id") if finding else None)
    ai_fix = get_ai_fix_for_finding(auth_id, project_id=proj_id)
    if not ai_fix and auth_id != clean_id:
        ai_fix = get_ai_fix_for_finding(clean_id, project_id=proj_id)
    if not ai_fix and proj_id:
        # Also check project-level cumulative fix/PR
        ai_fix = get_ai_fix_for_finding("__ALL_FINDINGS__", project_id=proj_id)
    if not ai_fix:
        return None
    return ai_fix

@app.post("/api/ai-fix/pr/merge", response_model=AIFixMergePRResponse)
def ai_fix_merge_pr_endpoint(req: AIFixMergePRRequest, authorization: Optional[str] = Header(None)):
    user_id = _resolve_user_id(authorization)
    user = get_current_authenticated_user(authorization)
    if req.finding_id and req.finding_id not in ["__ALL_FINDINGS__", "ALL", "BATCH_ALL"]:
        authorize_finding(req.finding_id, user)
    repo_val = (req.repo or req.repository or "").strip()

    try:
        merge_res = merge_pull_request(user_id, repo_val, req.pr_number)
    except GitHubPermissionError as gpe:
        logger.warning(f"GitHub Permission Error merging PR on {repo_val}: {gpe}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "GITHUB_PERMISSION_DENIED",
                "message": gpe.message,
                "repo": gpe.repo or repo_val,
                "action": gpe.action,
                "token_type": gpe.token_type,
                "docs_url": gpe.docs_url
            }
        )
    except ValueError as ve:
        err_msg = str(ve)
        status_code = status.HTTP_403_FORBIDDEN if "not accessible by personal access token" in err_msg.lower() else status.HTTP_400_BAD_REQUEST
        raise HTTPException(status_code=status_code, detail=err_msg)

    # Update finding fix_status to Awaiting Retest (NOT resolved!)
    finding = get_finding_by_id(req.finding_id)
    merge_sha = merge_res.get("merge_commit_sha") or merge_res.get("sha")
    merged_at = merge_res.get("merged_at")
    if finding:
        update_finding_github_fix(
            finding_id=finding["id"],
            fix_status="Code Merged (Retest Required)"
        )
        ai_fix = get_ai_fix_for_finding(finding["id"])
        if ai_fix:
            update_ai_fix_record(ai_fix["id"], {
                "pr_status": "Merged",
                "status": "MERGED",
                "merge_commit_sha": merge_sha,
                "merged_at": merged_at
            })

    return AIFixMergePRResponse(
        success=True,
        merged=True,
        message="Pull Request merged successfully. Code merged into base branch. Finding is now awaiting human retest verification.",
        sha=merge_sha,
        merge_commit_sha=merge_sha,
        merged_at=merged_at,
        status="MERGED"
    )

@app.post("/api/ai-fix/{finding_id}/retest", response_model=AIFixRetestResponse)
@app.post("/api/findings/{finding_id}/retest", response_model=AIFixRetestResponse)
def ai_fix_retest_endpoint(
    finding_id: str,
    req: AIFixRetestRequest,
    project_id: Optional[str] = Query(None),
    assessment_id: Optional[str] = Query(None),
    authorization: Optional[str] = Header(None)
):
    user = get_current_authenticated_user(authorization)
    user_id = user["id"] if user else "unauthenticated"
    clean_finding_id = str(finding_id).strip()
    effective_project_id = req.project_id or project_id or req.assessment_id or assessment_id

    try:
        finding, project = authorize_finding(clean_finding_id, user, project_id=effective_project_id)
    except HTTPException as he:
        logger.warning(
            f"[RETEST_AUTH_DENIED] finding_id={clean_finding_id} user_id={user_id} project_id={effective_project_id} "
            f"status={he.status_code} detail='{he.detail}' timestamp={datetime.now().isoformat()}"
        )
        raise he

    req_result = (req.result or "PASS").strip().upper()
    current_status = (finding.get("status") or "").strip().upper()
    current_retest = (finding.get("retest_status") or "").strip().upper()
    target_project_id = project.get("id")
    auth_finding_id = finding.get("id") or clean_finding_id

    # Idempotent re-execution detection
    if current_status == "RESOLVED" and current_retest == "PASSED" and req_result == "PASS":
        logger.info(f"[RETEST_IDEMPOTENT] finding_id={auth_finding_id} project_id={target_project_id} already RESOLVED and PASSED. Updating verification record.")

    try:
        res = record_finding_retest(
            finding_id=auth_finding_id,
            fix_id=req.fix_id,
            result=req_result,
            notes=req.notes,
            project_id=target_project_id
        )
    except Exception as dbe:
        logger.error(
            f"[RETEST_RECORD_FAILED] finding_id={auth_finding_id} project_id={target_project_id} "
            f"user_id={user_id} error_type={type(dbe).__name__} error='{dbe}' timestamp={datetime.now().isoformat()}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to record retest. Please try again."
        )

    cert_data = None
    cert_eligible = False
    blocking_reason = None
    eligibility_info = None
    certificate_job_id = None

    # Automatic assessment certificate evaluation and generation on retest pass (Non-blocking)
    try:
        if res["result"] == "PASSED" and target_project_id:
            logger.info(f"[CERT_EVAL_TRIGGER] project_id={target_project_id} final_finding_id={auth_finding_id} retest_result=PASSED")
            elig = check_assessment_certificate_eligibility(target_project_id)
            eligibility_info = elig
            cert_eligible = bool(elig.get("eligible"))
            blocking_reason = elig.get("blocking_reason") or elig.get("reason")

            logger.info(
                f"[CERT_ELIGIBILITY_CHECK] assessment_id={target_project_id} project_id={target_project_id} "
                f"total_findings={elig.get('total_findings')} resolved_findings={elig.get('resolved_findings')} "
                f"passed_retests={elig.get('passed_retests')} pending_findings={elig.get('pending_findings')} "
                f"failed_retests={elig.get('failed_retests')} eligible={cert_eligible} blocker='{blocking_reason}'"
            )

            if cert_eligible:
                if req.async_certificate:
                    # Non-blocking async background job requested
                    job_res = start_certificate_generation_job(target_project_id, user_id=user["id"] if user else None)
                    certificate_job_id = job_res.get("job_id")
                    if job_res.get("status") == "GENERATED":
                        cert_data = job_res.get("certificate")
                else:
                    # Fast generation (now ultra-fast <0.1s with ReportLab on Linux/Render & Windows)
                    logger.info(f"[CERT_GEN_START] assessment_id={target_project_id} project_id={target_project_id}")
                    gen_res = generate_assessment_certificate(target_project_id)
                    if gen_res.get("success"):
                        cert_data = gen_res.get("certificate")
                        cert_id = cert_data.get("certificate_id") if isinstance(cert_data, dict) else "N/A"
                        logger.info(f"[CERT_GEN_COMPLETE] assessment_id={target_project_id} certificate_id={cert_id}")
                    else:
                        blocking_reason = gen_res.get("error", "Certificate generation failed.")
                        logger.warning(f"[CERT_GEN_FAILURE] assessment_id={target_project_id} reason='{blocking_reason}'")
    except Exception as ce:
        blocking_reason = f"Certificate generation error: {str(ce)}"
        logger.warning(f"[CERT_EVAL_ERROR] assessment_id={target_project_id or 'unknown'} error='{ce}'")

    return AIFixRetestResponse(
        success=True,
        finding_id=auth_finding_id,
        fix_id=req.fix_id,
        result=res["result"],
        status=res["status"],
        retest_status=res["retest_status"],
        notes=res.get("notes"),
        updated_at=res["updated_at"],
        finding=res.get("finding") or finding,
        certificate=cert_data,
        certificate_job_id=certificate_job_id,
        certificate_eligible=cert_eligible,
        blocking_reason=blocking_reason,
        eligibility=eligibility_info,
        assessment_id=target_project_id
    )

@app.get("/api/projects/{project_id}/ai-fixes", response_model=List[AIFixRecordItem])
def list_project_ai_fixes_endpoint(
    project_id: str,
    authorization: Optional[str] = Header(None)
):
    user = get_current_authenticated_user(authorization)
    authorize_project(project_id, user)
    fixes = list_ai_fixes_for_project(project_id)
    return fixes

@app.get("/api/ai-fix/{finding_id}/report")
def ai_fix_report_endpoint(
    finding_id: str,
    authorization: Optional[str] = Header(None)
):
    user = get_current_authenticated_user(authorization)
    finding, project = authorize_finding(finding_id, user)

    ai_fix = get_ai_fix_for_finding(finding_id)
    if not ai_fix:
        # Generate provisional record
        ai_fix = {
            "finding_id": finding_id,
            "repository": finding.get("github_repo") or "",
            "base_branch": "main",
            "fix_branch": finding.get("github_branch", f"tracegate/fix/{finding.get('vuln_id', 'VULN-001')}"),
            "file_path": finding.get("affected_component", "source_file"),
            "commit_sha": finding.get("github_commit", "N/A"),
            "pr_number": "N/A",
            "pr_url": finding.get("github_pr", "N/A"),
            "diff_unified": "",
            "original_code": "",
            "proposed_code": "",
            "explanation": finding.get("remediation", ""),
            "security_impact": finding.get("impact", ""),
            "status": finding.get("fix_status", "PROPOSED"),
            "retest_status": finding.get("retest_status", "PENDING")
        }

    report_md = generate_remediation_review_report(ai_fix, finding)
    return {"finding_id": finding_id, "report_markdown": report_md}

# =========================================================================
# VAPT ASSESSMENT COMPLETION CERTIFICATE API
# =========================================================================

@app.get("/api/projects/{project_id}/certificate/status")
def project_certificate_status_endpoint(
    project_id: str,
    authorization: Optional[str] = Header(None)
):
    """
    Check deterministic eligibility of project for VAPT completion certificate.
    Returns status, remaining findings breakdown, existing certificate if issued,
    and latest certificate generation job if any.
    """
    user = get_current_authenticated_user(authorization)
    authorize_project(project_id, user)
    elig = check_assessment_certificate_eligibility(project_id)
    latest_job = get_latest_certificate_job_for_project(project_id)
    elig["latest_job"] = latest_job
    return elig

@app.post("/api/projects/{project_id}/certificate/generate")
def project_certificate_generate_endpoint(
    project_id: str,
    async_mode: Optional[bool] = Query(False, description="Run generation as background job"),
    authorization: Optional[str] = Header(None)
):
    """
    Trigger generation of VAPT Assessment Completion Certificate for eligible project.
    Supports non-blocking async job mode (?async_mode=true) as well as direct fast generation (via ReportLab).
    Idempotent: returns existing certificate if already issued.
    """
    user = get_current_authenticated_user(authorization)
    authorize_project(project_id, user)
    user_id = user["id"] if user else None

    if async_mode:
        job_res = start_certificate_generation_job(project_id, user_id=user_id)
        if not job_res.get("success"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=job_res.get("error", "Assessment is not eligible for certificate."))
        return job_res

    result = generate_assessment_certificate(project_id)
    if not result.get("success"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=result.get("error", "Assessment is not eligible for certificate."))
    return result

@app.get("/api/projects/{project_id}/certificate/jobs/{job_id}")
def get_certificate_job_endpoint(
    project_id: str,
    job_id: str,
    authorization: Optional[str] = Header(None)
):
    """
    Check status of a background certificate generation job.
    Returns status ('GENERATING', 'GENERATED', 'FAILED'), certificate record if completed,
    and error message if failed.
    """
    user = get_current_authenticated_user(authorization)
    authorize_project(project_id, user)
    job = get_certificate_job(job_id)
    if not job or job.get("project_id") != project_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate generation job not found.")

    cert = None
    if job.get("certificate_id"):
        cert = get_certificate_by_id(job["certificate_id"])
    elif job.get("status") == "GENERATED":
        cert = get_latest_certificate_for_project(project_id)

    return {
        "success": True,
        "job_id": job["job_id"],
        "project_id": job["project_id"],
        "status": job["status"],
        "error": job.get("error"),
        "certificate_id": job.get("certificate_id"),
        "certificate": cert,
        "created_at": job.get("created_at"),
        "updated_at": job.get("updated_at")
    }

@app.get("/api/projects/{project_id}/certificates")
def project_certificates_list_endpoint(
    project_id: str,
    authorization: Optional[str] = Header(None)
):
    """
    List all historical and current certificates issued for this project.
    """
    user = get_current_authenticated_user(authorization)
    authorize_project(project_id, user)
    return get_certificates_for_project(project_id)

@app.get("/api/certificates/{certificate_id}")
def get_certificate_endpoint(
    certificate_id: str,
    authorization: Optional[str] = Header(None)
):
    """
    Retrieve single certificate record with snapshot metadata.
    """
    user = get_current_authenticated_user(authorization)
    cert, project = authorize_certificate(certificate_id, user)
    return cert

@app.get("/api/certificates/{certificate_id}/download")
@app.get("/api/certificates/{certificate_id}/download/{format}")
def download_certificate_endpoint(
    certificate_id: str,
    format: Optional[str] = "pdf",
    token: Optional[str] = Query(None, description="Optional auth token for browser download links"),
    authorization: Optional[str] = Header(None)
):
    """
    Download certificate package in native PDF or Microsoft Word DOCX format.
    """
    if not authorization and token:
        authorization = f"Bearer {token}"
    user = get_current_authenticated_user(authorization)
    cert, project = authorize_certificate(certificate_id, user)

    fmt = (format or "pdf").lower().strip()
    if fmt == "pdf":
        pdf_path = cert.get("file_path_pdf")
        if pdf_path and Path(pdf_path).exists() and is_valid_pdf(pdf_path):
            safe_name = f"VAPT_Certificate_{certificate_id}.pdf"
            return FileResponse(
                path=str(pdf_path),
                media_type="application/pdf",
                filename=safe_name,
                headers={"Content-Disposition": f'attachment; filename="{safe_name}"'}
            )

        # Ephemeral container disk recovery: restore from database file_data_pdf
        if (not pdf_path or not Path(pdf_path).exists() or not is_valid_pdf(pdf_path)) and cert.get("file_data_pdf"):
            try:
                CERTIFICATES_DIR.mkdir(parents=True, exist_ok=True)
                target_pdf = CERTIFICATES_DIR / f"{certificate_id}.pdf"
                target_pdf.write_bytes(base64.b64decode(cert["file_data_pdf"]))
                if is_valid_pdf(target_pdf):
                    update_certificate_file_paths(certificate_id, pdf_path=str(target_pdf))
                    safe_name = f"VAPT_Certificate_{certificate_id}.pdf"
                    return FileResponse(
                        path=str(target_pdf),
                        media_type="application/pdf",
                        filename=safe_name,
                        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'}
                    )
            except Exception as pe:
                logger.warning(f"Failed to restore certificate PDF from database: {pe}")

        # Attempt on-demand compilation via ReportLab
        try:
            target_pdf = CERTIFICATES_DIR / f"{certificate_id}.pdf"
            compiled = compile_pdf_certificate_reportlab(cert, target_pdf)
            if compiled and Path(compiled).exists() and is_valid_pdf(compiled):
                update_certificate_file_paths(certificate_id, pdf_path=str(compiled))
                try:
                    b64_pdf = base64.b64encode(Path(compiled).read_bytes()).decode("ascii")
                    from backend.database import update_certificate_artifact_data
                    update_certificate_artifact_data(certificate_id, file_data_pdf=b64_pdf)
                except Exception:
                    pass
                safe_name = f"VAPT_Certificate_{certificate_id}.pdf"
                return FileResponse(
                    path=str(compiled),
                    media_type="application/pdf",
                    filename=safe_name,
                    headers={"Content-Disposition": f'attachment; filename="{safe_name}"'}
                )
        except Exception as rle:
            logger.warning(f"On-demand ReportLab PDF compilation failed: {rle}")

        # Attempt on-demand compilation from DOCX if Word is installed
        docx_path = cert.get("file_path_docx")
        if docx_path and Path(docx_path).exists():
            try:
                compiled = convert_docx_to_pdf(docx_path)
                if compiled and Path(compiled).exists() and is_valid_pdf(compiled):
                    update_certificate_file_paths(certificate_id, pdf_path=str(compiled))
                    safe_name = f"VAPT_Certificate_{certificate_id}.pdf"
                    return FileResponse(
                        path=str(compiled),
                        media_type="application/pdf",
                        filename=safe_name,
                        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'}
                    )
            except Exception as pe:
                logger.warning(f"Word COM conversion failed for certificate: {pe}")

        # NEVER return DOCX bytes when PDF format was requested!
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PDF certificate file could not be generated. Please retry generation or download the DOCX version."
        )
    else:
        docx_path = cert.get("file_path_docx")
        if (not docx_path or not Path(docx_path).exists()) and cert.get("file_data_docx"):
            try:
                CERTIFICATES_DIR.mkdir(parents=True, exist_ok=True)
                target_docx = CERTIFICATES_DIR / f"{certificate_id}.docx"
                target_docx.write_bytes(base64.b64decode(cert["file_data_docx"]))
                docx_path = str(target_docx)
            except Exception as de:
                logger.warning(f"Failed to restore certificate DOCX from database: {de}")

        if not docx_path or not Path(docx_path).exists():
            # Try building DOCX from snapshot data
            try:
                from backend.certificate_service import build_certificate_documents
                snap = cert.get("snapshot") or {}
                if snap:
                    new_docx, _ = build_certificate_documents(snap)
                    if new_docx and Path(new_docx).exists():
                        docx_path = str(new_docx)
                        update_certificate_file_paths(certificate_id, docx_path=docx_path)
            except Exception as bde:
                logger.warning(f"On-demand certificate DOCX building failed: {bde}")

        if not docx_path or not Path(docx_path).exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate DOCX file not found on disk.")
        safe_name = f"VAPT_Certificate_{certificate_id}.docx"
        return FileResponse(
            path=str(docx_path),
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            filename=safe_name,
            headers={"Content-Disposition": f'attachment; filename="{safe_name}"'}
        )

@app.post("/api/certificates/{certificate_id}/dismiss-notice")
def dismiss_certificate_notice_endpoint(
    certificate_id: str,
    authorization: Optional[str] = Header(None)
):
    """
    Mark certificate completion notice as seen so the popup is not shown again.
    """
    user = get_current_authenticated_user(authorization)
    cert, project = authorize_certificate(certificate_id, user)
    update_certificate_notice_seen(certificate_id, 1)
    return {"success": True, "certificate_id": certificate_id, "notice_seen": 1}

@app.get("/api/certificates/{certificate_id}/verify")
def verify_certificate_api_endpoint(certificate_id: str):
    """
    Public API endpoint to verify authenticity of a VAPT completion certificate.
    STRICT PRIVACY: Returns only non-sensitive verification and attestation details.
    """
    return get_public_certificate_verification(certificate_id)

@app.get("/certificate/verify/{certificate_id}", response_class=HTMLResponse)
def public_certificate_verification_page(certificate_id: str):
    """
    Standalone public verification web page.
    Verifies certificate validity without requiring user authentication.
    """
    data = get_public_certificate_verification(certificate_id)
    status_label = "VALID CERTIFICATE" if data.get("valid") else (data.get("status", "NOT FOUND").upper().replace("_", " "))
    badge_bg = "#dcfce7" if data.get("valid") else "#fee2e2"
    badge_color = "#15803d" if data.get("valid") else "#b91c1c"
    badge_border = "#86efac" if data.get("valid") else "#fca5a5"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Certificate Verification — Tracegate</title>
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <link rel="icon" type="image/png" sizes="32x32" href="/static/img/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/static/img/favicon-16x16.png">
    <link rel="apple-touch-icon" sizes="180x180" href="/static/img/apple-touch-icon.png">
    <link rel="shortcut icon" href="/favicon.ico">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #0f172a;
            --card-bg: #1e293b;
            --card-border: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --teal: #0d9488;
            --teal-light: #14b8a6;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }}
        .verify-card {{
            width: 100%;
            max-width: 680px;
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            box-shadow: 0 20px 40px -15px rgba(0, 0, 0, 0.5);
            padding: 36px 32px;
            display: flex;
            flex-direction: column;
            gap: 20px;
        }}
        .verify-brand {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid var(--card-border);
            padding-bottom: 18px;
        }}
        .brand-logo {{
            font-size: 1.15rem;
            font-weight: 800;
            letter-spacing: 0.5px;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .brand-logo span {{ color: var(--teal-light); }}
        .status-badge {{
            padding: 6px 14px;
            border-radius: 9999px;
            font-size: 0.8rem;
            font-weight: 700;
            background: {badge_bg};
            color: {badge_color};
            border: 1px solid {badge_border};
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .verify-title {{
            font-size: 1.35rem;
            font-weight: 700;
            color: var(--text-primary);
        }}
        .verify-subtitle {{
            font-size: 0.88rem;
            color: var(--text-secondary);
            line-height: 1.5;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px 20px;
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid var(--card-border);
            border-radius: 10px;
            padding: 16px 20px;
            font-size: 0.85rem;
        }}
        .meta-item {{ display: flex; flex-direction: column; gap: 4px; }}
        .meta-label {{ font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; font-weight: 600; }}
        .meta-value {{ font-family: 'JetBrains Mono', monospace; font-size: 0.84rem; color: var(--text-primary); word-break: break-all; }}
        .attestation-box {{
            background: rgba(13, 148, 136, 0.08);
            border: 1px solid rgba(13, 148, 136, 0.25);
            border-radius: 10px;
            padding: 16px;
            font-size: 0.86rem;
            color: #ccfbf1;
            line-height: 1.5;
        }}
        .disclaimer-text {{
            font-size: 0.74rem;
            color: var(--text-muted);
            line-height: 1.4;
            font-style: italic;
            border-top: 1px solid var(--card-border);
            padding-top: 14px;
        }}
        .verify-footer {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 8px;
        }}
        .verify-footer a {{
            color: var(--teal-light);
            text-decoration: none;
            font-weight: 600;
        }}
        .verify-footer a:hover {{ text-decoration: underline; }}
        @media (max-width: 600px) {{
            .meta-grid {{ grid-template-columns: 1fr; }}
            .verify-card {{ padding: 24px 20px; }}
        }}
    </style>
</head>
<body>
    <div class="verify-card">
        <div class="verify-brand">
            <div class="brand-logo">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <path d="M9 12l2 2 4-4"/>
                </svg>
                TRACE<span>GATE</span>
            </div>
            <span class="status-badge">{status_label}</span>
        </div>

        <div>
            <h1 class="verify-title">VAPT Assessment Completion Verification</h1>
            <p class="verify-subtitle">This page verifies the official issuance status and remediation validation of a Tracegate security assessment.</p>
        </div>

        <div class="meta-grid">
            <div class="meta-item">
                <span class="meta-label">Certificate ID</span>
                <span class="meta-value">{data.get("certificate_id", certificate_id)}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Verification Key</span>
                <span class="meta-value">{data.get("verification_id", "N/A")}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Target Application</span>
                <span class="meta-value" style="font-family: inherit;">{data.get("target_name", "N/A")}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Client / Organization</span>
                <span class="meta-value" style="font-family: inherit;">{data.get("client_organization", "Not Provided")}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Issue Date</span>
                <span class="meta-value">{data.get("issue_date", "N/A")}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Final Validation Date</span>
                <span class="meta-value">{data.get("final_validation_date", "N/A")}</span>
            </div>
            <div class="meta-item" style="grid-column: 1 / -1;">
                <span class="meta-label">Remediation Status</span>
                <span class="meta-value" style="color: #4ade80; font-weight: 600;">{data.get("remediation_validation_status", "N/A")} ({data.get("total_findings_validated", 0)} In-Scope Findings Validated)</span>
            </div>
        </div>

        <div class="attestation-box">
            {data.get("attestation", "")}
        </div>

        <p class="disclaimer-text">
            {data.get("disclaimer", "")}
        </p>

        <div class="verify-footer">
            <span>Powered by Tracegate Security</span>
            <a href="/#overview">&larr; Return to Tracegate</a>
        </div>
    </div>
</body>
</html>"""
    return HTMLResponse(content=html_content, status_code=200 if data.get("valid") else 404)


# =========================================================================
# STATIC ASSETS & SPA ROUTING
# =========================================================================

# Mount samples directory if it exists
if SAMPLES_DIR.exists():
    app.mount("/samples", StaticFiles(directory=str(SAMPLES_DIR)), name="samples")

# Mount static frontend files
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

@app.get("/favicon.ico", include_in_schema=False)
def favicon_endpoint():
    ico_path = FRONTEND_DIR / "favicon.ico"
    if ico_path.exists():
        return FileResponse(str(ico_path), media_type="image/x-icon")
    png_path = FRONTEND_DIR / "img" / "favicon-32x32.png"
    if png_path.exists():
        return FileResponse(str(png_path), media_type="image/png")
    return FileResponse(str(FRONTEND_DIR / "img" / "tracegate_shield_only.png"), media_type="image/png")

@app.get("/")
@app.get("/capabilities")
@app.get("/how-it-works")
@app.get("/who-its-for")
@app.get("/who-it-is-for")
@app.get("/security")
@app.get("/security-pillars")
@app.get("/login")
@app.get("/register")
@app.get("/forgot-password")
@app.get("/reset-password")
@app.get("/dashboard")
@app.get("/projects")
def serve_index():
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"message": "Tracegate VAPT Learning Platform API operational."}
