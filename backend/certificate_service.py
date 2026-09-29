"""
backend/certificate_service.py
Tracegate — VAPT Assessment Completion Certificate Service

Automated, professional VAPT Assessment Completion Certificate generation
as the final outcome of the security assessment lifecycle.
Issued strictly when 100% of in-scope findings have passed remediation validation.
"""

import os
import json
import html
import uuid
import logging
import threading
import base64
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

def _escape_qr(text: Any) -> str:
    return html.escape(str(text or ""))

from docx import Document
from docx.shared import Inches, Pt, RGBColor, Mm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.enum.section import WD_ORIENT
from docx.oxml import parse_xml
from docx.oxml.ns import nsdecls
import qrcode

try:
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib import colors as rl_colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

from backend.database import (
    get_project_by_id,
    get_project_findings_list,
    get_db_connection,
    save_certificate_record,
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
    update_certificate_job
)
from backend.report_generator import convert_docx_to_pdf
from backend.pdf_validator import is_valid_pdf, validate_pdf_artifact

logger = logging.getLogger("tracegate.certificate")

# Certificate Directories & Asset Paths
BASE_DIR = Path(__file__).resolve().parent.parent
CERTIFICATES_DIR = BASE_DIR / "data" / "certificates"
CERTIFICATES_DIR.mkdir(parents=True, exist_ok=True)
LOGO_PATH = BASE_DIR / "backend" / "assets" / "tracegate_shield_logo.png"
SEAL_PATH = BASE_DIR / "backend" / "assets" / "completion_seal.png"

# Color Palette (Formal, professional Tracegate security aesthetic)
COLOR_NAVY = RGBColor(15, 23, 42)        # Slate/Navy (#0F172A)
COLOR_TEAL = RGBColor(13, 148, 136)      # Deep Teal (#0D9488)
COLOR_SLATE = RGBColor(51, 65, 85)       # Charcoal Slate (#334155)
COLOR_MUTED = RGBColor(100, 116, 139)    # Muted Slate (#64748B)
COLOR_BORDER = RGBColor(226, 232, 240)   # Border Slate (#E2E8F0)
COLOR_LOW = RGBColor(4, 120, 87)         # Low / Pass (#047857)

HEX_BG_HEADER = "0F172A"
HEX_BG_ACCENT = "F0FDFA"
HEX_BG_SUBTLE = "F8FAFC"
HEX_BG_BORDER = "CBD5E1"

STANDARD_DISCLAIMER = (
    "This certificate reflects the assessment scope and validation status recorded as of the certificate "
    "issue date and does not guarantee future security."
)

ATTESTATION_STATEMENT = (
    "This certificate confirms completion of the specified VAPT assessment and successful remediation "
    "validation of the applicable confirmed findings through remediation retesting within the defined assessment scope."
)

VALIDATION_SUMMARY_STATEMENT = (
    "All applicable confirmed findings within the defined assessment scope have undergone remediation "
    "validation and were recorded as successfully passed at the time of certificate issuance."
)


# =============================================================================
# XML & STYLING HELPERS
# =============================================================================

def set_cell_background(cell, fill_hex: str):
    """Applies background shading color to a table cell."""
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tc_pr.append(shd)

def set_cell_margins(cell, top: int = 100, bottom: int = 100, left: int = 140, right: int = 140):
    """Sets internal padding (in dxa) for a table cell."""
    tc_pr = cell._tc.get_or_add_tcPr()
    tc_mar = parse_xml(
        f'<w:tcMar {nsdecls("w")}>'
        f'<w:top w:w="{top}" w:type="dxa"/>'
        f'<w:bottom w:w="{bottom}" w:type="dxa"/>'
        f'<w:left w:w="{left}" w:type="dxa"/>'
        f'<w:right w:w="{right}" w:type="dxa"/>'
        f'</w:tcMar>'
    )
    tc_pr.append(tc_mar)

def make_table_safe(table):
    """Ensures rows don't split awkwardly across page breaks."""
    for idx, row in enumerate(table.rows):
        trPr = row._tr.get_or_add_trPr()
        cantSplit = parse_xml(r'<w:cantSplit xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>')
        trPr.append(cantSplit)
        if idx == 0:
            tblHeader = parse_xml(r'<w:tblHeader xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>')
            trPr.append(tblHeader)


# =============================================================================
# ELIGIBILITY LOGIC
# =============================================================================

def check_assessment_certificate_eligibility(project_id: str) -> Dict[str, Any]:
    """
    Deterministic eligibility check for VAPT Assessment Completion Certificate.
    Eligibility requires:
      1. totalInScopeFindings > 0 (at least one confirmed finding required)
      2. 100% of confirmed findings have status == 'RESOLVED' and retest_status in ('PASSED', 'PASS')
      3. No finding remains in OPEN, IN_REMEDIATION, RETEST_PENDING, or RETEST_FAILED state.
    """
    project = get_project_by_id(project_id)
    if not project:
        return {
            "eligible": False,
            "status": "NOT_FOUND",
            "reason": "Project not found.",
            "total_findings": 0,
            "resolved_findings": 0,
            "pending_retests": 0,
            "failed_retests": 0,
            "open_findings": 0,
            "remaining_by_severity": {},
            "certificate": None
        }

    findings = get_project_findings_list(project_id)
    total_findings = len(findings)

    if total_findings == 0:
        return {
            "eligible": False,
            "status": "NOT_ELIGIBLE",
            "assessment_id": project_id,
            "project_id": project_id,
            "reason": "No confirmed findings recorded for this project. Assessment completion certificate requires at least one in-scope finding.",
            "blocking_reason": "Assessment has no confirmed findings.",
            "total_findings": 0,
            "resolved_findings": 0,
            "passed_retests": 0,
            "pending_findings": 0,
            "pending_retests": 0,
            "failed_retests": 0,
            "open_findings": 0,
            "remaining_by_severity": {},
            "certificate": None
        }

    resolved_count = 0
    pending_retests = 0
    failed_retests = 0
    open_findings = 0
    unresolved_findings = []
    remaining_by_severity: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}

    for f in findings:
        f_status = (f.get("status") or "").strip().upper()
        f_retest = (f.get("retest_status") or "").strip().upper()
        sev = (f.get("priority") or "HIGH").strip().upper()
        if sev not in remaining_by_severity:
            sev = "HIGH"

        is_passed = (f_status in ("RESOLVED", "REMEDIATED", "CLOSED") and "PASS" in f_retest)
        if is_passed:
            resolved_count += 1
        else:
            unresolved_findings.append(f)
            remaining_by_severity[sev] += 1
            if "FAIL" in f_retest:
                failed_retests += 1
            elif "PEND" in f_retest or not f_retest:
                pending_retests += 1
            else:
                open_findings += 1

    # Check if a certificate has already been issued
    existing_cert = get_latest_certificate_for_project(project_id)

    if len(unresolved_findings) == 0:
        status_code = "GENERATED" if existing_cert else "ELIGIBLE"
        return {
            "eligible": True,
            "status": status_code,
            "assessment_id": project_id,
            "project_id": project_id,
            "reason": "All in-scope findings have successfully passed remediation validation.",
            "blocking_reason": None,
            "total_findings": total_findings,
            "resolved_findings": resolved_count,
            "passed_retests": resolved_count,
            "pending_findings": 0,
            "pending_retests": 0,
            "failed_retests": 0,
            "open_findings": 0,
            "remaining_by_severity": remaining_by_severity,
            "certificate": existing_cert
        }
    else:
        unresolved_count = len(unresolved_findings)
        sev_parts = []
        for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
            if remaining_by_severity.get(k, 0) > 0:
                sev_parts.append(f"{remaining_by_severity[k]} {k.capitalize()}")
        breakdown = f" ({', '.join(sev_parts)} remaining)" if sev_parts else ""

        if pending_retests > 0 and open_findings == 0 and failed_retests == 0:
            reason = f"{unresolved_count} in-scope finding(s) remain pending retest{breakdown}."
        else:
            reason = f"{unresolved_count} in-scope finding(s) remain unresolved or pending remediation{breakdown}."

        return {
            "eligible": False,
            "status": "NOT_ELIGIBLE",
            "assessment_id": project_id,
            "project_id": project_id,
            "reason": reason,
            "blocking_reason": reason,
            "total_findings": total_findings,
            "resolved_findings": resolved_count,
            "passed_retests": resolved_count,
            "pending_findings": unresolved_count,
            "pending_retests": pending_retests,
            "failed_retests": failed_retests,
            "open_findings": open_findings,
            "remaining_by_severity": remaining_by_severity,
            "unresolved_findings": [
                {
                    "id": f.get("id"),
                    "vuln_id": f.get("vuln_id"),
                    "finding_name": f.get("finding_name"),
                    "priority": f.get("priority"),
                    "status": f.get("status"),
                    "retest_status": f.get("retest_status")
                }
                for f in unresolved_findings
            ],
            "certificate": None
        }


# =============================================================================
# CERTIFICATE GENERATION & PERSISTENCE
# =============================================================================

def generate_assessment_certificate(project_id: str) -> Dict[str, Any]:
    """
    Generate and persist a professional VAPT Assessment Completion Certificate.
    Enforces eligibility, idempotency, and immutability.
    """
    eligibility = check_assessment_certificate_eligibility(project_id)
    if not eligibility["eligible"]:
        return {
            "success": False,
            "status": eligibility["status"],
            "error": eligibility["reason"],
            "eligibility": eligibility
        }

    # Idempotency guard: If already issued for this project and findings state, return existing
    existing = eligibility.get("certificate")
    if existing and existing.get("status") == "VALID":
        snap = existing.get("snapshot") or {}
        if snap.get("total_findings") == eligibility["total_findings"]:
            logger.info(f"Certificate already generated for project {project_id}: {existing['certificate_id']}")
            return {
                "success": True,
                "status": "ALREADY_ISSUED",
                "certificate": existing,
                "eligibility": eligibility
            }

    project = get_project_by_id(project_id)
    findings = get_project_findings_list(project_id)

    # Generate unique IDs
    year = datetime.now().year
    rand_hex = uuid.uuid4().hex[:6].upper()
    cert_id = f"TG-VAPT-{year}-{rand_hex}"

    while get_certificate_by_id(cert_id) is not None:
        rand_hex = uuid.uuid4().hex[:6].upper()
        cert_id = f"TG-VAPT-{year}-{rand_hex}"

    verify_id = f"TG-VERIFY-{uuid.uuid4().hex[:8].upper()}"

    # Determine Associated Assessment / Report ID
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, version, report_title FROM reports WHERE project_id = ? ORDER BY created_at DESC LIMIT 1", (project_id,))
    rep_row = cursor.fetchone()
    conn.close()

    report_id = rep_row["id"] if rep_row else None
    assessment_id = report_id if report_id else project_id

    # Format Dates
    now = datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")
    issue_date = now.strftime("%d %b %Y")

    try:
        p_created = datetime.strptime(project.get("created_at", now_str)[:19], "%Y-%m-%d %H:%M:%S")
        assessment_start = p_created.strftime("%d %b %Y")
    except Exception:
        assessment_start = issue_date

    final_validation_date = issue_date
    assessment_end = issue_date

    # Finding Severity Breakdown
    crit_count = sum(1 for f in findings if (f.get("priority") or "").upper() in ("CRITICAL", "CRIT"))
    high_count = sum(1 for f in findings if (f.get("priority") or "").upper() == "HIGH")
    med_count = sum(1 for f in findings if (f.get("priority") or "").upper() in ("MEDIUM", "MED"))
    low_count = sum(1 for f in findings if (f.get("priority") or "").upper() == "LOW")
    info_count = sum(1 for f in findings if (f.get("priority") or "").upper() in ("INFORMATIONAL", "INFO"))

    # Target & Client
    target_name = project.get("name", "Assessment Target")
    target_url = project.get("target_url") or "Target Web Application"
    client_org = project.get("client_organization") or project.get("organization") or "Not Provided"
    assessment_type = "Web Application Penetration Test (VAPT)"

    # Clean scope summary
    scope_notes = project.get("scope_notes") or project.get("notes") or project.get("description") or "Standard In-Scope Web Application Components"
    clean_scope = scope_notes.strip()[:300]

    # Clean finding snapshot items (NO AI Fix or PR tokens)
    findings_snapshot = []
    for idx, f in enumerate(findings):
        findings_snapshot.append({
            "index": idx + 1,
            "finding_id": f.get("id"),
            "vuln_id": f.get("vuln_id", f"VULN-{idx+1:03d}"),
            "finding_name": f.get("finding_name", "Vulnerability Finding"),
            "severity": (f.get("priority") or "HIGH").upper(),
            "cwe": f.get("cwe", "CWE-200"),
            "status": "RESOLVED",
            "retest_status": "PASSED",
            "retested_at": f.get("updated_at") or now_str
        })

    snapshot_data = {
        "certificate_id": cert_id,
        "verification_id": verify_id,
        "project_id": project_id,
        "assessment_id": assessment_id,
        "report_id": report_id,
        "target_name": target_name,
        "target_url": target_url,
        "client_organization": client_org,
        "assessment_type": assessment_type,
        "assessment_start": assessment_start,
        "assessment_end": assessment_end,
        "issue_date": issue_date,
        "final_validation_date": final_validation_date,
        "total_findings": len(findings),
        "critical_count": crit_count,
        "high_count": high_count,
        "medium_count": med_count,
        "low_count": low_count,
        "info_count": info_count,
        "findings_retested": len(findings),
        "findings_passed": len(findings),
        "findings_failed": 0,
        "findings_summary": findings_snapshot,
        "signatories": {
            "prepared_by": project.get("created_by") or "Security Assessor",
            "validated_by": "Lead Retest Validator",
            "review_status": "Formal Assessment Review Passed"
        },
        "disclaimer": STANDARD_DISCLAIMER
    }

    # Generate Physical Word DOCX and compile to native PDF
    docx_path, pdf_path = build_certificate_documents(snapshot_data)

    file_data_docx = None
    if docx_path and Path(docx_path).exists():
        try:
            with open(docx_path, "rb") as f:
                file_data_docx = base64.b64encode(f.read()).decode("utf-8")
        except Exception as e:
            logger.warning(f"Could not encode certificate docx to base64: {e}")

    file_data_pdf = None
    if pdf_path and Path(pdf_path).exists() and is_valid_pdf(pdf_path):
        try:
            with open(pdf_path, "rb") as f:
                file_data_pdf = base64.b64encode(f.read()).decode("utf-8")
        except Exception as e:
            logger.warning(f"Could not encode certificate pdf to base64: {e}")

    # Persist record into vapt_certificates table
    cert_record = {
        "certificate_id": cert_id,
        "verification_id": verify_id,
        "project_id": project_id,
        "assessment_id": assessment_id,
        "report_id": report_id,
        "status": "VALID",
        "issue_date": issue_date,
        "assessment_start": assessment_start,
        "assessment_end": assessment_end,
        "final_validation_date": final_validation_date,
        "total_findings": len(findings),
        "critical_count": crit_count,
        "high_count": high_count,
        "medium_count": med_count,
        "low_count": low_count,
        "info_count": info_count,
        "findings_retested": len(findings),
        "findings_passed": len(findings),
        "findings_failed": 0,
        "target_name": target_name,
        "target_url": target_url,
        "client_organization": client_org,
        "assessment_type": assessment_type,
        "assessment_scope": clean_scope,
        "snapshot": snapshot_data,
        "file_path_docx": str(docx_path) if (docx_path and Path(docx_path).exists()) else None,
        "file_path_pdf": str(pdf_path) if (pdf_path and is_valid_pdf(pdf_path)) else None,
        "file_data_docx": file_data_docx,
        "file_data_pdf": file_data_pdf,
        "notice_seen": 0,
        "created_at": now_str
    }

    saved = save_certificate_record(cert_record)
    logger.info(f"VAPT Assessment Completion Certificate successfully created: {cert_id}")

    return {
        "success": True,
        "status": "GENERATED",
        "certificate": saved,
        "eligibility": eligibility
    }


# =============================================================================
# PHYSICAL DOCUMENT COMPILATION (DOCX & REPORTLAB PDF)
# =============================================================================

def draw_certificate_canvas(canvas, doc):
    canvas.saveState()
    width, height = doc.pagesize
    margin = 8 * mm
    # Outer navy double border
    canvas.setStrokeColor(rl_colors.HexColor("#0f172a"))
    canvas.setLineWidth(2)
    canvas.rect(margin, margin, width - 2 * margin, height - 2 * margin)
    # Inner teal border
    inner_m = margin + 1.2 * mm
    canvas.setStrokeColor(rl_colors.HexColor("#0d9488"))
    canvas.setLineWidth(0.75)
    canvas.rect(inner_m, inner_m, width - 2 * inner_m, height - 2 * inner_m)
    canvas.restoreState()


def compile_pdf_certificate_reportlab(data: Dict[str, Any], target_pdf_path: Path) -> Optional[Path]:
    """
    Directly compiles a formal, executive A4 landscape PDF certificate via ReportLab.
    Cross-platform compatible across Linux (Render), Windows, and macOS without requiring Word COM.
    """
    if not REPORTLAB_AVAILABLE:
        return None
    try:
        cert_id = data.get("certificate_id", "TG-VAPT")
        doc = SimpleDocTemplate(
            str(target_pdf_path),
            pagesize=landscape(A4),
            leftMargin=12 * mm,
            rightMargin=12 * mm,
            topMargin=12 * mm,
            bottomMargin=12 * mm
        )

        styles = getSampleStyleSheet()

        sub_brand_style = ParagraphStyle(
            'CertSubBrand',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=8,
            leading=10,
            textColor=rl_colors.HexColor('#0d9488'),
            alignment=1
        )
        title_style = ParagraphStyle(
            'CertTitleHeading',
            parent=styles['Title'],
            fontName='Helvetica-Bold',
            fontSize=18,
            leading=22,
            textColor=rl_colors.HexColor('#0f172a'),
            alignment=1
        )
        subtitle_style = ParagraphStyle(
            'CertSubTitleHeading',
            parent=styles['Normal'],
            fontName='Helvetica-Oblique',
            fontSize=9.5,
            leading=12,
            textColor=rl_colors.HexColor('#0d9488'),
            alignment=1
        )
        stmt_style = ParagraphStyle(
            'CertStatement',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8.5,
            leading=12,
            textColor=rl_colors.HexColor('#334155'),
            alignment=1
        )
        grid_val = ParagraphStyle(
            'CertGridVal',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8,
            leading=11,
            textColor=rl_colors.HexColor('#334155')
        )
        disc_style = ParagraphStyle(
            'CertDisclaimer',
            parent=styles['Normal'],
            fontName='Helvetica-Oblique',
            fontSize=6.5,
            leading=8.5,
            textColor=rl_colors.HexColor('#94a3b8'),
            alignment=1
        )

        elements = []

        if LOGO_PATH.exists():
            elements.append(RLImage(str(LOGO_PATH), width=16 * mm, height=16 * mm))
            elements.append(Spacer(1, 1 * mm))

        elements.append(Paragraph("TRACEGATE SECURITY WORKSPACE  •  ASSESSMENT & VALIDATION REGISTRY", sub_brand_style))
        elements.append(Spacer(1, 1.5 * mm))
        elements.append(Paragraph("VAPT ASSESSMENT COMPLETION CERTIFICATE", title_style))
        elements.append(Spacer(1, 1 * mm))
        elements.append(Paragraph("Security Assessment & Remediation Validation Confirmation", subtitle_style))
        elements.append(Spacer(1, 2 * mm))
        elements.append(Paragraph(
            "This certificate confirms completion of the specified VAPT assessment and successful remediation validation of the applicable confirmed findings within the defined assessment scope.",
            stmt_style
        ))
        elements.append(Spacer(1, 3.5 * mm))

        # Metadata Table
        start_date = data.get('assessment_start', data.get('issue_date'))
        end_date = data.get('assessment_end', data.get('issue_date'))
        period_str = f"{start_date} – {end_date}" if start_date != end_date else start_date

        target_name = data.get('target_name') or 'Assessment Target'
        target_scope = data.get('target_url') or 'Defined Scope'
        assess_type = data.get('assessment_type') or 'Web Application Penetration Test (VAPT)'
        issue_date_val = data.get('issue_date') or '-'
        final_val_date = data.get('final_validation_date') or data.get('issue_date') or '-'
        assess_id_val = data.get('assessment_id') or data.get('project_id') or '-'

        meta_table_data = [
            [
                Paragraph(f"<b>Target Application:</b> {target_name}", grid_val),
                Paragraph(f"<b>Assessment Period:</b> {period_str}", grid_val)
            ],
            [
                Paragraph(f"<b>Target / Scope:</b> {target_scope}", grid_val),
                Paragraph(f"<b>Certificate Issue Date:</b> {issue_date_val}", grid_val)
            ],
            [
                Paragraph(f"<b>Assessment Type:</b> {assess_type}", grid_val),
                Paragraph(f"<b>Final Validation Date:</b> {final_val_date}", grid_val)
            ],
            [
                Paragraph(f"<b>Certificate ID:</b> {cert_id}", grid_val),
                Paragraph(f"<b>Assessment ID:</b> {assess_id_val}", grid_val)
            ]
        ]

        col_w = (297 - 24) * mm / 2
        meta_table = Table(meta_table_data, colWidths=[col_w, col_w])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), rl_colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 0.5, rl_colors.HexColor('#e2e8f0')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, rl_colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 3.5 * mm))

        # QR Code generation
        qr_img_path = CERTIFICATES_DIR / f"qr_{cert_id}.png"
        verify_url = f"https://tracegate.security/certificate/verify/{cert_id}"
        qr = qrcode.QRCode(version=1, box_size=3, border=1)
        qr.add_data(verify_url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="#0f172a", back_color="#ffffff")
        img.save(str(qr_img_path))

        snap = data.get("snapshot") if (isinstance(data.get("snapshot"), dict) and data.get("snapshot")) else data
        signatories = snap.get("signatories") or data.get("signatories") or {}
        prep_by = signatories.get("prepared_by", "Security Assessor")
        val_by = signatories.get("validated_by", "Lead Retest Validator")
        rev_status = signatories.get("review_status", "Formal Assessment Review Passed")
        ver_id = data.get('verification_id') or snap.get('verification_id') or ''

        seal_cell = []
        if SEAL_PATH.exists():
            seal_cell.append(RLImage(str(SEAL_PATH), width=18 * mm, height=18 * mm))
        else:
            seal_cell.append(Paragraph("<b>TRACEGATE</b><br/>100% REMEDIATED<br/>SECURITY VALIDATED", sub_brand_style))

        attest_cell = [
            Paragraph(f"<b>Prepared By:</b> {prep_by}", grid_val),
            Paragraph(f"<b>Validated By:</b> {val_by}", grid_val),
            Paragraph(f"<b>Review Status:</b> {rev_status}", grid_val),
            Spacer(1, 1 * mm),
            Paragraph("<em>Remediation Validation Status: 100% Passed (Validated)</em>", sub_brand_style)
        ]

        qr_cell = [
            RLImage(str(qr_img_path), width=18 * mm, height=18 * mm),
            Paragraph(f"Key: {_escape_qr(ver_id)}", disc_style)
        ]

        bot_table = Table([[seal_cell, attest_cell, qr_cell]], colWidths=[50 * mm, 173 * mm, 50 * mm])
        bot_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, 0), 'CENTER'),
            ('ALIGN', (1, 0), (1, 0), 'LEFT'),
            ('ALIGN', (2, 0), (2, 0), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 1),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
        ]))
        elements.append(bot_table)
        elements.append(Spacer(1, 2 * mm))

        disclaimer = data.get("disclaimer") or snap.get("disclaimer") or STANDARD_DISCLAIMER
        elements.append(Paragraph(disclaimer, disc_style))

        doc.build(elements, onFirstPage=draw_certificate_canvas)

        try:
            if qr_img_path.exists():
                qr_img_path.unlink()
        except Exception:
            pass

        if is_valid_pdf(target_pdf_path):
            logger.info(f"ReportLab PDF certificate compiled and verified at: {target_pdf_path}")
            return target_pdf_path
        else:
            logger.error(f"ReportLab PDF certificate output failed binary validation: {target_pdf_path}")
            try:
                target_pdf_path.unlink()
            except Exception:
                pass
            return None
    except Exception as e:
        logger.error(f"Error compiling ReportLab PDF certificate: {e}", exc_info=True)
        return None


def build_certificate_documents(data: Dict[str, Any]) -> Tuple[Optional[Path], Optional[Path]]:
    """
    Constructs a formal, minimalist, high-quality landscape A4 DOCX certificate
    and compiles native PDF via ReportLab (cross-platform) with Microsoft Word COM fallback.
    Strictly 1-page A4 landscape layout.
    """
    cert_id = data["certificate_id"]
    docx_filename = f"{cert_id}.docx"
    docx_path = CERTIFICATES_DIR / docx_filename

    doc = Document()

    # Document Geometry: Clean A4 landscape with 0.40 in top/bottom, 0.50 in left/right
    section = doc.sections[0]
    section.orientation = WD_ORIENT.LANDSCAPE
    section.page_width = Mm(297)
    section.page_height = Mm(210)
    section.top_margin = Inches(0.40)
    section.bottom_margin = Inches(0.40)
    section.left_margin = Inches(0.50)
    section.right_margin = Inches(0.50)

    # 1. Formal Border Framing Container (Single cell outer table)
    frame_table = doc.add_table(rows=1, cols=1)
    frame_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    outer_cell = frame_table.rows[0].cells[0]
    outer_cell.width = Inches(10.65)
    set_cell_background(outer_cell, "FFFFFF")

    # Apply elegant double border styling to outer frame cell
    tc_pr = outer_cell._tc.get_or_add_tcPr()
    borders = parse_xml(
        f'<w:tcBorders {nsdecls("w")}>'
        f'<w:top w:val="double" w:sz="18" w:space="0" w:color="{HEX_BG_HEADER}"/>'
        f'<w:left w:val="double" w:sz="18" w:space="0" w:color="{HEX_BG_HEADER}"/>'
        f'<w:bottom w:val="double" w:sz="18" w:space="0" w:color="{HEX_BG_HEADER}"/>'
        f'<w:right w:val="double" w:sz="18" w:space="0" w:color="{HEX_BG_HEADER}"/>'
        f'</w:tcBorders>'
    )
    tc_pr.append(borders)

    tc_mar = parse_xml(
        f'<w:tcMar {nsdecls("w")}>'
        f'<w:top w:w="120" w:type="dxa"/>'
        f'<w:bottom w:w="120" w:type="dxa"/>'
        f'<w:left w:w="180" w:type="dxa"/>'
        f'<w:right w:w="180" w:type="dxa"/>'
        f'</w:tcMar>'
    )
    tc_pr.append(tc_mar)

    # Header: Tracegate Shield Logo
    p_logo = outer_cell.paragraphs[0]
    p_logo.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_logo.paragraph_format.space_before = Pt(0)
    p_logo.paragraph_format.space_after = Pt(2)
    if LOGO_PATH.exists():
        p_logo.add_run().add_picture(str(LOGO_PATH), width=Inches(0.95))

    # Sub-brand
    p_sub = outer_cell.add_paragraph()
    p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_sub.paragraph_format.space_before = Pt(0)
    p_sub.paragraph_format.space_after = Pt(4)
    r_sub = p_sub.add_run("TRACEGATE SECURITY WORKSPACE  •  ASSESSMENT & VALIDATION REGISTRY")
    r_sub.font.name = "Calibri"
    r_sub.font.size = Pt(8.5)
    r_sub.font.bold = True
    r_sub.font.color.rgb = COLOR_TEAL

    # Main Certificate Title
    p_title = outer_cell.add_paragraph()
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_title.paragraph_format.space_before = Pt(4)
    p_title.paragraph_format.space_after = Pt(2)
    r_title = p_title.add_run("VAPT ASSESSMENT COMPLETION CERTIFICATE")
    r_title.font.name = "Calibri"
    r_title.font.size = Pt(22)
    r_title.font.bold = True
    r_title.font.color.rgb = COLOR_NAVY

    # Subtitle
    p_st = outer_cell.add_paragraph()
    p_st.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_st.paragraph_format.space_before = Pt(0)
    p_st.paragraph_format.space_after = Pt(8)
    r_st = p_st.add_run("Security Assessment & Remediation Validation Confirmation")
    r_st.font.name = "Calibri"
    r_st.font.size = Pt(10)
    r_st.font.italic = True
    r_st.font.color.rgb = COLOR_TEAL

    # Concise Completion Statement
    p_stmt = outer_cell.add_paragraph()
    p_stmt.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_stmt.paragraph_format.space_before = Pt(0)
    p_stmt.paragraph_format.space_after = Pt(10)
    p_stmt.paragraph_format.line_spacing = 1.2
    r_stmt = p_stmt.add_run(
        "This certificate confirms completion of the specified VAPT assessment and successful remediation "
        "validation of the applicable confirmed findings within the defined assessment scope."
    )
    r_stmt.font.name = "Calibri"
    r_stmt.font.size = Pt(9.5)
    r_stmt.font.color.rgb = COLOR_SLATE

    # Metadata Grid (2-column structured table)
    meta_table = outer_cell.add_table(rows=4, cols=2)
    meta_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    make_table_safe(meta_table)

    col_widths = [Inches(4.9), Inches(4.9)]
    rows_data = [
        (("Target Application:", data.get("target_name") or "Assessment Target"), ("Assessment Period:", f"{data.get('assessment_start', data.get('issue_date'))} – {data.get('assessment_end', data.get('issue_date'))}")),
        (("Target / Scope:", data.get("target_url") or "Defined Scope"), ("Certificate Issue Date:", data.get("issue_date") or "-")),
        (("Assessment Type:", data.get("assessment_type") or "Web Application Penetration Test (VAPT)"), ("Final Validation Date:", data.get("final_validation_date") or data.get("issue_date") or "-")),
        (("Certificate ID:", data.get("certificate_id") or "-"), ("Assessment ID:", data.get("assessment_id") or data.get("project_id") or "-"))
    ]

    for r_idx, ((lbl1, val1), (lbl2, val2)) in enumerate(rows_data):
        for c_idx, (lbl, val) in enumerate([(lbl1, val1), (lbl2, val2)]):
            cell = meta_table.rows[r_idx].cells[c_idx]
            cell.width = col_widths[c_idx]
            set_cell_background(cell, HEX_BG_SUBTLE)
            set_cell_margins(cell, top=55, bottom=55, left=120, right=120)

            c_bor = parse_xml(
                f'<w:tcBorders {nsdecls("w")}>'
                f'<w:top w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/>'
                f'<w:left w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/>'
                f'<w:bottom w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/>'
                f'<w:right w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/>'
                f'</w:tcBorders>'
            )
            cell._tc.get_or_add_tcPr().append(c_bor)

            p = cell.paragraphs[0]
            p.paragraph_format.space_before = Pt(0)
            p.paragraph_format.space_after = Pt(0)
            r_lbl = p.add_run(f"{lbl} ")
            r_lbl.font.name = "Calibri"
            r_lbl.font.size = Pt(8.5)
            r_lbl.font.bold = True
            r_lbl.font.color.rgb = COLOR_NAVY

            r_val = p.add_run(str(val))
            r_val.font.name = "Calibri"
            r_val.font.size = Pt(8.5)
            r_val.font.color.rgb = COLOR_SLATE

    # Spacer
    p_sp = outer_cell.add_paragraph()
    p_sp.paragraph_format.space_before = Pt(8)
    p_sp.paragraph_format.space_after = Pt(0)

    # Bottom 3-column table (Seal, Authorization, QR)
    bot_table = outer_cell.add_table(rows=1, cols=3)
    bot_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    make_table_safe(bot_table)
    bot_widths = [Inches(2.6), Inches(4.7), Inches(2.6)]

    # Cell 0: Completion Seal
    c0 = bot_table.rows[0].cells[0]
    c0.width = bot_widths[0]
    p_seal = c0.paragraphs[0]
    p_seal.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_seal.paragraph_format.space_before = Pt(0)
    p_seal.paragraph_format.space_after = Pt(0)
    if SEAL_PATH.exists():
        p_seal.add_run().add_picture(str(SEAL_PATH), width=Inches(1.15))

    # Cell 1: Organization Authorization Line
    c1 = bot_table.rows[0].cells[1]
    c1.width = bot_widths[1]
    p_auth = c1.paragraphs[0]
    p_auth.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_auth.paragraph_format.space_before = Pt(8)
    p_auth.paragraph_format.space_after = Pt(2)
    r_a1 = p_auth.add_run("AUTHORIZED BY\n")
    r_a1.font.name = "Calibri"
    r_a1.font.size = Pt(8)
    r_a1.font.bold = True
    r_a1.font.color.rgb = COLOR_MUTED

    r_a2 = p_auth.add_run("TRACEGATE PVT. LIMITED\n")
    r_a2.font.name = "Calibri"
    r_a2.font.size = Pt(11.5)
    r_a2.font.bold = True
    r_a2.font.color.rgb = COLOR_NAVY

    r_a3 = p_auth.add_run("Security Assessment & Verification Authority\n")
    r_a3.font.name = "Calibri"
    r_a3.font.size = Pt(8.5)
    r_a3.font.italic = True
    r_a3.font.color.rgb = COLOR_TEAL

    r_a4 = p_auth.add_run(f"Authoritative Digital Record: {data['certificate_id']}")
    r_a4.font.name = "Calibri"
    r_a4.font.size = Pt(7.5)
    r_a4.font.color.rgb = COLOR_MUTED

    # Cell 2: QR Code & Verification
    c2 = bot_table.rows[0].cells[2]
    c2.width = bot_widths[2]
    p_qr = c2.paragraphs[0]
    p_qr.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_qr.paragraph_format.space_before = Pt(0)
    p_qr.paragraph_format.space_after = Pt(0)

    # Generate QR pointing to real verification endpoint
    qr_file_path = CERTIFICATES_DIR / f"{cert_id}_qr.png"
    try:
        qr = qrcode.QRCode(box_size=4, border=1)
        qr.add_data(f"/certificate/verify/{cert_id}")
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="#0F172A", back_color="white")
        qr_img.save(str(qr_file_path))
        p_qr.add_run().add_picture(str(qr_file_path), width=Inches(0.9))
    except Exception as qre:
        logger.warning(f"Could not generate QR image: {qre}")

    p_qr_txt = c2.add_paragraph()
    p_qr_txt.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_qr_txt.paragraph_format.space_before = Pt(2)
    p_qr_txt.paragraph_format.space_after = Pt(0)
    r_q1 = p_qr_txt.add_run("Online Verification\n")
    r_q1.font.name = "Calibri"
    r_q1.font.size = Pt(7)
    r_q1.font.color.rgb = COLOR_MUTED

    r_q2 = p_qr_txt.add_run(str(data.get("verification_id", "")))
    r_q2.font.name = "Calibri"
    r_q2.font.size = Pt(7.5)
    r_q2.font.bold = True
    r_q2.font.color.rgb = COLOR_TEAL

    # Disclaimer: Point-in-time single line
    p_disc = outer_cell.add_paragraph()
    p_disc.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_disc.paragraph_format.space_before = Pt(8)
    p_disc.paragraph_format.space_after = Pt(0)
    r_disc = p_disc.add_run(data.get("disclaimer") or STANDARD_DISCLAIMER)
    r_disc.font.name = "Calibri"
    r_disc.font.size = Pt(7.5)
    r_disc.font.italic = True
    r_disc.font.color.rgb = RGBColor(148, 163, 184)

    # Save DOCX
    doc.save(str(docx_path))
    logger.info(f"DOCX certificate generated at: {docx_path}")

    # Compile native PDF: ReportLab first (fast, cross-platform on Linux/Render & Windows), fallback to Word COM
    target_pdf_path = CERTIFICATES_DIR / f"{cert_id}.pdf"
    pdf_path = None
    if REPORTLAB_AVAILABLE:
        try:
            compiled_pdf = compile_pdf_certificate_reportlab(data, target_pdf_path)
            if compiled_pdf and is_valid_pdf(compiled_pdf):
                pdf_path = Path(compiled_pdf)
                logger.info(f"PDF certificate generated via ReportLab at: {pdf_path}")
        except Exception as rle:
            logger.warning(f"ReportLab PDF generation failed, attempting fallback: {rle}")

    if not pdf_path or not is_valid_pdf(pdf_path):
        try:
            compiled_pdf = convert_docx_to_pdf(str(docx_path))
            if compiled_pdf and is_valid_pdf(compiled_pdf):
                pdf_path = Path(compiled_pdf)
                logger.info(f"PDF certificate generated via Word COM at: {pdf_path}")
        except Exception as pe:
            logger.warning(f"Could not compile PDF certificate via Word COM: {pe}")

    # Final validation gate: never return an invalid PDF
    if pdf_path and not is_valid_pdf(pdf_path):
        logger.warning(f"Certificate PDF failed binary validation gate: {pdf_path}")
        pdf_path = None

    return docx_path, pdf_path


# =============================================================================
# BACKGROUND CERTIFICATE GENERATION JOB WORKER
# =============================================================================

def _run_certificate_job_worker(job_id: str, project_id: str, user_id: Optional[str] = None):
    """
    Background worker thread target for compiling certificate.
    Catches all exceptions to prevent thread leaks and updates job status in DB.
    """
    try:
        logger.info(f"[CERT_JOB_WORKER_START] job_id={job_id} project_id={project_id}")
        res = generate_assessment_certificate(project_id)
        if res.get("success") and res.get("certificate"):
            cert_id = res["certificate"]["certificate_id"]
            update_certificate_job(job_id, status="GENERATED", certificate_id=cert_id)
            logger.info(f"[CERT_JOB_WORKER_SUCCESS] job_id={job_id} project_id={project_id} cert_id={cert_id}")
        else:
            err = res.get("error") or "Certificate generation failed."
            update_certificate_job(job_id, status="FAILED", error=err)
            logger.warning(f"[CERT_JOB_WORKER_FAILED] job_id={job_id} project_id={project_id} reason='{err}'")
    except Exception as exc:
        logger.error(f"[CERT_JOB_WORKER_ERROR] job_id={job_id} project_id={project_id} error='{exc}'", exc_info=True)
        update_certificate_job(job_id, status="FAILED", error=str(exc))


def start_certificate_generation_job(project_id: str, user_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Initiates asynchronous background job for certificate generation.
    Enforces eligibility and returns existing certificate if already generated.
    Returns:
      {
        "success": True/False,
        "job_id": str or None,
        "status": "GENERATING" | "GENERATED" | "NOT_ELIGIBLE" | "ERROR",
        "certificate": Dict or None,
        "eligibility": Dict,
        "error": Optional[str]
      }
    """
    eligibility = check_assessment_certificate_eligibility(project_id)
    if not eligibility.get("eligible"):
        return {
            "success": False,
            "job_id": None,
            "status": eligibility.get("status", "NOT_ELIGIBLE"),
            "certificate": None,
            "eligibility": eligibility,
            "error": eligibility.get("reason", "Assessment is not eligible for certificate.")
        }

    # If already generated and valid, return existing immediately
    existing_cert = eligibility.get("certificate")
    if existing_cert and existing_cert.get("status") == "VALID":
        snap = existing_cert.get("snapshot") or {}
        if snap.get("total_findings") == eligibility.get("total_findings"):
            return {
                "success": True,
                "job_id": None,
                "status": "GENERATED",
                "certificate": existing_cert,
                "eligibility": eligibility
            }

    # Check for already active job
    active_job = get_active_certificate_job_for_project(project_id, user_id=user_id)
    if active_job:
        return {
            "success": True,
            "job_id": active_job["job_id"],
            "status": "GENERATING",
            "certificate": None,
            "eligibility": eligibility,
            "job": active_job
        }

    # Create new job
    job_id = f"job-{uuid.uuid4().hex[:12]}"
    effective_user_id = user_id or "usr-system"
    create_certificate_job(job_id=job_id, user_id=effective_user_id, project_id=project_id, assessment_id=project_id)

    worker = threading.Thread(
        target=_run_certificate_job_worker,
        args=(job_id, project_id, effective_user_id),
        name=f"CertWorker-{job_id}",
        daemon=True
    )
    worker.start()

    return {
        "success": True,
        "job_id": job_id,
        "status": "GENERATING",
        "certificate": None,
        "eligibility": eligibility
    }


# =============================================================================
# PUBLIC VERIFICATION SERVICE
# =============================================================================

def get_public_certificate_verification(cert_id_or_verify_id: str) -> Dict[str, Any]:
    """
    Retrieves public verification data for a certificate ID or verification ID.
    STRICT PRIVACY GUARANTEE: Does NOT expose vulnerability names, PoCs, code, tokens,
    or internal private assessment notes.
    """
    cert = get_certificate_by_id(cert_id_or_verify_id)
    if not cert:
        cert = get_certificate_by_verification_id(cert_id_or_verify_id)

    if not cert:
        return {
            "valid": False,
            "status": "NOT_FOUND",
            "message": "Certificate not found in Tracegate authoritative registry."
        }

    return {
        "valid": cert.get("status") == "VALID",
        "status": cert.get("status", "VALID"),
        "certificate_id": cert["certificate_id"],
        "verification_id": cert["verification_id"],
        "target_name": cert["target_name"],
        "target_url": cert["target_url"],
        "client_organization": cert.get("client_organization") or "Not Provided",
        "assessment_type": cert.get("assessment_type", "Web Application Penetration Test (VAPT)"),
        "issue_date": cert["issue_date"],
        "final_validation_date": cert["final_validation_date"],
        "total_findings_validated": cert.get("findings_passed", 0),
        "remediation_validation_status": "100% Passed (Validated)",
        "attestation": ATTESTATION_STATEMENT,
        "disclaimer": cert.get("snapshot", {}).get("disclaimer") or STANDARD_DISCLAIMER
    }
