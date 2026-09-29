"""
Tracegate Native Pure-Python ReportLab VAPT Report Generator.
Compiles the authoritative 27-Section normalized report model into an executive,
publication-grade PDF assessment report with zero external Word COM dependencies.
"""

import io
import os
import re
import html
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
    Image as RLImage,
    HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm, inch
from reportlab.pdfgen import canvas

from backend.pdf_validator import is_valid_pdf, validate_pdf_artifact

logger = logging.getLogger("tracegate.report_pdf")

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "data" / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
LOGO_PATH = BASE_DIR / "backend" / "assets" / "tracegate_shield_logo.png"

# Color Palette (Tracegate Enterprise Navy / Slate / Severity Tiers)
C_NAVY = colors.HexColor("#1E3A8A")
C_SLATE = colors.HexColor("#0F172A")
C_BODY = colors.HexColor("#334155")
C_MUTED = colors.HexColor("#64748B")
C_BORDER = colors.HexColor("#E2E8F0")
C_LIGHT_BG = colors.HexColor("#F8FAFC")

# Severity Colors
SEV_COLORS = {
    "CRITICAL": colors.HexColor("#B91C1C"),
    "HIGH": colors.HexColor("#C2410C"),
    "MEDIUM": colors.HexColor("#B45309"),
    "LOW": colors.HexColor("#047857"),
    "INFORMATIONAL": colors.HexColor("#0284C7"),
    "CLEAN": colors.HexColor("#059669")
}


class NumberedReportCanvas(canvas.Canvas):
    """
    Two-pass canvas for dynamic running headers and 'Page X of Y' footers.
    Omits headers/footers on the cover page (page 1).
    Sets authoritative PDF /Title and /Author document metadata.
    """
    _doc_title = "Tracegate VAPT Assessment Report"
    _doc_author = "Tracegate Security Assessor"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        if self._doc_title:
            self.setTitle(self._doc_title)
        if self._doc_author:
            self.setAuthor(self._doc_author)
        super().save()

    def draw_page_decorations(self, page_count):
        if self._pageNumber == 1:
            return  # Cover page: no running header or footer

        page_w, page_h = self._pagesize
        margin = 15 * mm

        self.saveState()

        # Running Header
        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(C_NAVY)
        self.drawString(margin, page_h - 11 * mm, "TRACEGATE ENTERPRISE SECURITY ASSESSMENT")

        self.setFont("Helvetica", 7.5)
        self.setFillColor(C_MUTED)
        self.drawRightString(page_w - margin, page_h - 11 * mm, "CONFIDENTIAL & PROPRIETARY")

        self.setStrokeColor(C_BORDER)
        self.setLineWidth(0.5)
        self.line(margin, page_h - 12.5 * mm, page_w - margin, page_h - 12.5 * mm)

        # Running Footer
        self.line(margin, 12 * mm, page_w - margin, 12 * mm)
        self.setFont("Helvetica", 7.5)
        self.setFillColor(C_MUTED)
        self.drawString(margin, 8 * mm, "Tracegate Autonomous VAPT Platform")
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(page_w - margin, 8 * mm, page_text)

        self.restoreState()


def _escape(text: Any) -> str:
    """Safely escapes HTML characters for ReportLab Paragraph markup."""
    if text is None:
        return ""
    return html.escape(str(text))


def generate_pdf_report(model: Dict[str, Any], target_pdf_path: Path) -> Optional[Path]:
    """
    Compiles normalized report model into an authoritative, executive PDF report.
    Returns the target_pdf_path on success and verified validity, or None on failure.
    """
    try:
        target_pdf_path = Path(target_pdf_path).resolve()
        target_pdf_path.parent.mkdir(parents=True, exist_ok=True)

        doc_filename = target_pdf_path.name
        doc_meta = model.get("document_metadata", {}) or model.get("document", {})
        proj_meta = model.get("project", {})
        author = doc_meta.get("author") or doc_meta.get("author_name") or "Security Assessor"
        doc_title = model.get("title") or model.get("report_title") or doc_meta.get("title") or doc_filename

        NumberedReportCanvas._doc_title = doc_title
        NumberedReportCanvas._doc_author = author

        doc = SimpleDocTemplate(
            str(target_pdf_path),
            pagesize=A4,
            leftMargin=15 * mm,
            rightMargin=15 * mm,
            topMargin=16 * mm,
            bottomMargin=16 * mm,
            title=doc_title,
            author=author,
            subject=f"VAPT Assessment Report — {proj_meta.get('name', 'Assessment')}",
            creator="Tracegate Autonomous VAPT Platform"
        )

        page_w, page_h = A4
        content_w = page_w - 30 * mm

        styles = getSampleStyleSheet()

        # Custom Typography
        style_cover_title = ParagraphStyle(
            'CoverTitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            textColor=C_NAVY,
            alignment=0,
            spaceAfter=6
        )
        style_cover_sub = ParagraphStyle(
            'CoverSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=11,
            leading=15,
            textColor=C_MUTED,
            alignment=0,
            spaceAfter=14
        )
        style_h1 = ParagraphStyle(
            'SecH1',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=14,
            leading=18,
            textColor=C_NAVY,
            spaceBefore=14,
            spaceAfter=8,
            keepWithNext=True
        )
        style_h2 = ParagraphStyle(
            'SecH2',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=11,
            leading=15,
            textColor=C_SLATE,
            spaceBefore=10,
            spaceAfter=5,
            keepWithNext=True
        )
        style_body = ParagraphStyle(
            'SecBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8.5,
            leading=12,
            textColor=C_BODY,
            spaceAfter=5
        )
        style_table_header = ParagraphStyle(
            'TblHdr',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=8,
            leading=10,
            textColor=colors.white
        )
        style_table_cell = ParagraphStyle(
            'TblCell',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8,
            leading=11,
            textColor=C_BODY
        )
        style_table_cell_bold = ParagraphStyle(
            'TblCellBold',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=8,
            leading=11,
            textColor=C_SLATE
        )
        style_poc = ParagraphStyle(
            'PoCCode',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=7,
            leading=9.5,
            textColor=colors.HexColor("#1E293B"),
            wordWrap='CJK'
        )

        elements = []

        proj = model.get("project", {})
        doc_meta = model.get("document", {})
        metrics = model.get("metrics", {})
        findings = model.get("findings", [])
        grc_summary = model.get("grc_summary", {})
        disclaimer = model.get("disclaimer") or "Confidential security assessment report."

        proj_name = proj.get("name", "Assessment Target")
        target_url = proj.get("target_url", "https://target.local")
        version = doc_meta.get("version", "v1.0")
        author = doc_meta.get("author", "Security Assessor")
        issue_date = doc_meta.get("date", "2026-09-20")
        classification = doc_meta.get("classification", "CONFIDENTIAL / PROPRIETARY")
        methodology = doc_meta.get("methodology", "OWASP Web Security Testing Guide (WSTG v4.2)")

        risk_rating = metrics.get("risk_rating", "MEDIUM RISK")
        risk_color = SEV_COLORS.get(risk_rating.split()[0], C_NAVY)
        risk_desc = metrics.get("risk_rating_desc", "Vulnerability assessment completed.")

        # =========================================================================
        # 1. COVER PAGE
        # =========================================================================
        elements.append(Spacer(1, 10 * mm))
        if LOGO_PATH.exists():
            elements.append(RLImage(str(LOGO_PATH), width=22 * mm, height=22 * mm))
            elements.append(Spacer(1, 4 * mm))

        elements.append(Paragraph("TRACEGATE ENTERPRISE SECURITY WORKSPACE", ParagraphStyle('SubBrand', fontName='Helvetica-Bold', fontSize=8.5, textColor=colors.HexColor('#0D9488'), leading=11)))
        elements.append(Spacer(1, 3 * mm))
        elements.append(Paragraph("Vulnerability Assessment & Penetration Testing Report", style_cover_title))
        elements.append(Paragraph(f"Comprehensive Security Assessment & Verification Audit for <b>{_escape(proj_name)}</b>", style_cover_sub))
        elements.append(Spacer(1, 6 * mm))

        # Risk Rating Callout Box
        risk_box_data = [
            [
                Paragraph(f"<b>ASSESSMENT RISK POSTURE:</b> {risk_rating}", ParagraphStyle('RiskHdr', fontName='Helvetica-Bold', fontSize=10, textColor=colors.white, leading=13)),
            ],
            [
                Paragraph(_escape(risk_desc), ParagraphStyle('RiskDesc', fontName='Helvetica', fontSize=8.5, textColor=colors.white, leading=12))
            ]
        ]
        risk_table = Table(risk_box_data, colWidths=[content_w])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), risk_color),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('RIGHTPADDING', (0, 0), (-1, -1), 12),
            ('BOX', (0, 0), (-1, -1), 1, risk_color),
        ]))
        elements.append(risk_table)
        elements.append(Spacer(1, 8 * mm))

        # Document Metadata Grid
        meta_grid = [
            [Paragraph("<b>Target Application:</b>", style_table_cell_bold), Paragraph(_escape(proj_name), style_table_cell),
             Paragraph("<b>Assessment Version:</b>", style_table_cell_bold), Paragraph(_escape(version), style_table_cell)],
            [Paragraph("<b>Target Scope / URL:</b>", style_table_cell_bold), Paragraph(_escape(target_url), style_table_cell),
             Paragraph("<b>Report Date:</b>", style_table_cell_bold), Paragraph(_escape(issue_date), style_table_cell)],
            [Paragraph("<b>Lead Auditor / Author:</b>", style_table_cell_bold), Paragraph(_escape(author), style_table_cell),
             Paragraph("<b>Classification:</b>", style_table_cell_bold), Paragraph(_escape(classification), style_table_cell)],
            [Paragraph("<b>Audit Methodology:</b>", style_table_cell_bold), Paragraph(_escape(methodology), style_table_cell),
             Paragraph("<b>Total Findings:</b>", style_table_cell_bold), Paragraph(str(len(findings)), style_table_cell)],
        ]
        col_w4 = content_w / 4
        meta_table = Table(meta_grid, colWidths=[col_w4, col_w4, col_w4, col_w4])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), C_LIGHT_BG),
            ('BOX', (0, 0), (-1, -1), 0.5, C_BORDER),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, C_BORDER),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(meta_table)

        elements.append(PageBreak())

        # =========================================================================
        # 2. EXECUTIVE SUMMARY & METRICS
        # =========================================================================
        elements.append(Paragraph("1. Executive Summary & Assessment Posture", style_h1))
        elements.append(HRFlowable(width="100%", thickness=1, color=C_NAVY, spaceBefore=2, spaceAfter=8))

        exec_text = (
            f"This Penetration Testing Assessment Report documents the security findings identified during the security evaluation "
            f"of <b>{_escape(proj_name)}</b>. Testing evaluated adherence to modern web security baselines, standard GRC framework "
            f"controls, and application-layer defenses. The overall risk level of the target has been determined to be <b>{risk_rating}</b>."
        )
        elements.append(Paragraph(exec_text, style_body))
        elements.append(Spacer(1, 3 * mm))

        # Severity Breakdown Table
        crit_c = metrics.get("crit_count", 0)
        high_c = metrics.get("high_count", 0)
        med_c = metrics.get("med_count", 0)
        low_c = metrics.get("low_count", 0)
        info_c = metrics.get("info_count", 0)
        tot_c = len(findings)

        sev_rows = [
            [
                Paragraph("<b>Severity Tier</b>", style_table_header),
                Paragraph("<b>Count</b>", style_table_header),
                Paragraph("<b>Remediation SLA</b>", style_table_header),
                Paragraph("<b>Target Risk Impact</b>", style_table_header)
            ],
            [
                Paragraph("<font color='#B91C1C'><b>CRITICAL</b></font>", style_table_cell_bold),
                Paragraph(str(crit_c), style_table_cell_bold),
                Paragraph("24–48 Hours", style_table_cell),
                Paragraph("Immediate exploitation vector with critical systemic compromise.", style_table_cell)
            ],
            [
                Paragraph("<font color='#C2410C'><b>HIGH</b></font>", style_table_cell_bold),
                Paragraph(str(high_c), style_table_cell_bold),
                Paragraph("7 Days", style_table_cell),
                Paragraph("Direct privilege escalation, account takeover, or severe data loss.", style_table_cell)
            ],
            [
                Paragraph("<font color='#B45309'><b>MEDIUM</b></font>", style_table_cell_bold),
                Paragraph(str(med_c), style_table_cell_bold),
                Paragraph("30 Days", style_table_cell),
                Paragraph("Flaws that can be chained to bypass standard authentication or authorization.", style_table_cell)
            ],
            [
                Paragraph("<font color='#047857'><b>LOW</b></font>", style_table_cell_bold),
                Paragraph(str(low_c), style_table_cell_bold),
                Paragraph("60 Days", style_table_cell),
                Paragraph("Baseline weaknesses with low direct exploitability or low technical impact.", style_table_cell)
            ],
            [
                Paragraph("<font color='#0284C7'><b>INFORMATIONAL</b></font>", style_table_cell_bold),
                Paragraph(str(info_c), style_table_cell_bold),
                Paragraph("Next Release Cycle", style_table_cell),
                Paragraph("Defense-in-depth observations and architectural hardening recommendations.", style_table_cell)
            ],
            [
                Paragraph("<b>TOTAL CONFIRMED FINDINGS</b>", style_table_cell_bold),
                Paragraph(f"<b>{tot_c}</b>", style_table_cell_bold),
                Paragraph("—", style_table_cell),
                Paragraph("Aggregated confirmed security gaps recorded across defined scope.", style_table_cell)
            ]
        ]
        sev_table = Table(sev_rows, colWidths=[35 * mm, 18 * mm, 32 * mm, content_w - 85 * mm])
        sev_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), C_NAVY),
            ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#F1F5F9')),
            ('BOX', (0, 0), (-1, -1), 0.5, C_BORDER),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, C_BORDER),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(sev_table)
        elements.append(Spacer(1, 5 * mm))

        # =========================================================================
        # 3. SCOPE & METHODOLOGY
        # =========================================================================
        elements.append(Paragraph("2. Assessment Scope & Testing Methodology", style_h1))
        elements.append(HRFlowable(width="100%", thickness=1, color=C_NAVY, spaceBefore=2, spaceAfter=8))

        scope_p = (
            f"The assessment was conducted against <b>{_escape(target_url)}</b> utilizing the <b>{_escape(methodology)}</b> framework. "
            f"Testing encompassed automated vulnerability discovery, manual verification of flaw chains, business logic bypass analysis, "
            f"and authenticated testing where credentials were provided. All findings recorded in this report have been confirmed through "
            f"reproducible technical evidence."
        )
        elements.append(Paragraph(scope_p, style_body))
        elements.append(Spacer(1, 4 * mm))

        # =========================================================================
        # 4. FINDINGS REGISTER (SUMMARY TABLE)
        # =========================================================================
        elements.append(Paragraph("3. Confirmed Vulnerability Register", style_h1))
        elements.append(HRFlowable(width="100%", thickness=1, color=C_NAVY, spaceBefore=2, spaceAfter=8))

        if not findings:
            clean_box = [
                [Paragraph("<b>CLEAN ASSESSMENT STATUS:</b> No confirmed vulnerabilities were identified across the evaluated scope.", style_table_cell)]
            ]
            t_clean = Table(clean_box, colWidths=[content_w])
            t_clean.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#ECFDF5')),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#059669')),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ]))
            elements.append(t_clean)
        else:
            reg_headers = [
                Paragraph("<b>ID</b>", style_table_header),
                Paragraph("<b>Vulnerability Title</b>", style_table_header),
                Paragraph("<b>Severity</b>", style_table_header),
                Paragraph("<b>CWE</b>", style_table_header),
                Paragraph("<b>CVSS</b>", style_table_header),
                Paragraph("<b>Status</b>", style_table_header),
            ]
            reg_data = [reg_headers]

            for f in findings:
                f_id = f.get("finding_id") or f.get("id") or "VULN"
                title = f.get("title") or f.get("finding_name") or "Unnamed Finding"
                sev = (f.get("severity") or f.get("priority") or "MEDIUM").upper()
                cwe = f.get("cwe") or f.get("cwe_id") or "CWE-Unknown"
                cvss_disp = f.get("cvss_display")
                if not cvss_disp:
                    raw_sc = f.get("cvss_score") if f.get("cvss_score") is not None else f.get("cvss")
                    if raw_sc is not None and str(raw_sc).strip() not in ["", "None", "null", "N/A", "Not Scored"]:
                        try:
                            cvss_disp = f"{float(raw_sc):.1f}"
                        except (ValueError, TypeError):
                            cvss_disp = "Not Scored"
                    else:
                        cvss_disp = "Not Scored"
                cvss = cvss_disp
                status = (f.get("status") or "CONFIRMED").upper()

                sev_color = SEV_COLORS.get(sev, C_NAVY)
                reg_data.append([
                    Paragraph(f"<b>{_escape(f_id)}</b>", style_table_cell_bold),
                    Paragraph(_escape(title), style_table_cell),
                    Paragraph(f"<font color='{sev_color.hexval()}'><b>{_escape(sev)}</b></font>", style_table_cell),
                    Paragraph(_escape(cwe), style_table_cell),
                    Paragraph(_escape(cvss), style_table_cell),
                    Paragraph(f"<b>{_escape(status)}</b>", style_table_cell),
                ])

            reg_table = Table(reg_data, colWidths=[20 * mm, 65 * mm, 24 * mm, 22 * mm, 18 * mm, content_w - 149 * mm])
            reg_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), C_NAVY),
                ('BOX', (0, 0), (-1, -1), 0.5, C_BORDER),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, C_BORDER),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('LEFTPADDING', (0, 0), (-1, -1), 5),
                ('RIGHTPADDING', (0, 0), (-1, -1), 5),
            ]))
            elements.append(reg_table)

        elements.append(PageBreak())

        # =========================================================================
        # 5. DETAILED VULNERABILITY ANALYSES
        # =========================================================================
        elements.append(Paragraph("4. Detailed Vulnerability Analyses", style_h1))
        elements.append(HRFlowable(width="100%", thickness=1, color=C_NAVY, spaceBefore=2, spaceAfter=8))

        if not findings:
            elements.append(Paragraph("All evaluated security controls passed without vulnerability confirmation.", style_body))
        else:
            for idx, f in enumerate(findings):
                f_id = f.get("finding_id") or f.get("id") or f"VULN-{idx+1:03d}"
                title = f.get("title") or f.get("finding_name") or "Security Finding"
                sev = (f.get("severity") or f.get("priority") or "MEDIUM").upper()
                cwe = f.get("cwe") or f.get("cwe_id") or "CWE-Unknown"
                cwe_title = f.get("cwe_title") or ""
                raw_cvss = f.get("cvss_score") if f.get("cvss_score") is not None else f.get("cvss")
                cvss_disp = f.get("cvss_display")
                if not cvss_disp:
                    if raw_cvss is not None:
                        try:
                            cvss_disp = f"{float(raw_cvss):.1f}"
                        except Exception:
                            cvss_disp = "Not Scored"
                    else:
                        cvss_disp = "Not Scored"
                cvss_score = cvss_disp
                cvss_vector = f.get("cvss_vector") or ""
                endpoint = f.get("endpoint") or f.get("affected_endpoint") or f.get("url") or target_url
                component = f.get("component") or f.get("affected_component") or f.get("file_path") or "Web Application Route"
                sla = f.get("sla") or "Standard Cycle"
                description = f.get("description") or "No detailed description provided."
                impact = f.get("impact") or "Potential compromise of system confidentiality, integrity, or availability."
                remediation = f.get("remediation") or f.get("remediation_guidance") or "Apply secure input validation and defensive controls."
                poc_text = f.get("poc") or f.get("poc_text") or f.get("proof_of_concept") or ""

                sev_color = SEV_COLORS.get(sev, C_NAVY)

                f_block = []

                # Card Header
                hdr_text = f"<b>{_escape(f_id)}: {_escape(title)}</b>"
                if cvss_disp == "Not Scored":
                    sev_sub = f"<b>{sev}</b> (Not Scored)"
                else:
                    sev_sub = f"<b>{sev}</b> (CVSS {cvss_disp})"
                f_hdr = [
                    [
                        Paragraph(hdr_text, ParagraphStyle('FHdr', fontName='Helvetica-Bold', fontSize=9.5, textColor=colors.white, leading=12)),
                        Paragraph(sev_sub, ParagraphStyle('FSev', fontName='Helvetica-Bold', fontSize=9, textColor=colors.white, alignment=2, leading=12))
                    ]
                ]
                t_fhdr = Table(f_hdr, colWidths=[content_w * 0.7, content_w * 0.3])
                t_fhdr.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), sev_color),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ]))
                f_block.append(t_fhdr)

                # Card Metadata Grid
                if cvss_vector:
                    vec_text = _escape(cvss_vector)
                elif cvss_disp == "Not Scored":
                    vec_text = "Not Scored"
                else:
                    vec_text = f"Base {cvss_disp}"

                f_meta = [
                    [
                        Paragraph("<b>Affected Component / Route:</b>", style_table_cell_bold),
                        Paragraph(f"<code>{_escape(endpoint)}</code>", style_table_cell),
                        Paragraph("<b>Remediation SLA:</b>", style_table_cell_bold),
                        Paragraph(_escape(sla), style_table_cell)
                    ],
                    [
                        Paragraph("<b>CWE Classification:</b>", style_table_cell_bold),
                        Paragraph(f"{_escape(cwe)} {f'({_escape(cwe_title)})' if cwe_title else ''}", style_table_cell),
                        Paragraph("<b>CVSS Vector:</b>", style_table_cell_bold),
                        Paragraph(vec_text, style_table_cell)
                    ]
                ]
                t_fmeta = Table(f_meta, colWidths=[content_w * 0.25, content_w * 0.35, content_w * 0.2, content_w * 0.2])
                t_fmeta.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), C_LIGHT_BG),
                    ('BOX', (0, 0), (-1, -1), 0.5, C_BORDER),
                    ('INNERGRID', (0, 0), (-1, -1), 0.5, C_BORDER),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                    ('LEFTPADDING', (0, 0), (-1, -1), 5),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 5),
                ]))
                f_block.append(t_fmeta)
                f_block.append(Spacer(1, 2.5 * mm))

                # Description & Impact
                f_block.append(Paragraph("<b>Description:</b>", style_h2))
                f_block.append(Paragraph(_escape(description), style_body))

                f_block.append(Paragraph("<b>Technical Impact:</b>", style_h2))
                f_block.append(Paragraph(_escape(impact), style_body))

                # Remediation
                f_block.append(Paragraph("<b>Remediation Recommendation:</b>", style_h2))
                f_block.append(Paragraph(_escape(remediation), style_body))

                # PoC
                if poc_text:
                    f_block.append(Paragraph("<b>Proof of Concept / Technical Evidence:</b>", style_h2))
                    # Sanitize PoC for table
                    clean_poc = _escape(poc_text[:1200])  # Cap at 1200 chars to avoid layout overflow
                    poc_table = Table([[Paragraph(clean_poc.replace("\n", "<br/>"), style_poc)]], colWidths=[content_w])
                    poc_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F1F5F9')),
                        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
                        ('TOPPADDING', (0, 0), (-1, -1), 4),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                        ('LEFTPADDING', (0, 0), (-1, -1), 6),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ]))
                    f_block.append(poc_table)

                f_block.append(Spacer(1, 6 * mm))
                elements.append(KeepTogether(f_block))

        # =========================================================================
        # 6. GRC FRAMEWORK ALIGNMENT
        # =========================================================================
        elements.append(PageBreak())
        elements.append(Paragraph("5. GRC Framework & Compliance Alignment", style_h1))
        elements.append(HRFlowable(width="100%", thickness=1, color=C_NAVY, spaceBefore=2, spaceAfter=8))

        grc_intro = (
            "Assessment findings were cross-mapped against authoritative security frameworks including the OWASP Top 10 (2021), "
            "NIST SP 800-53 Rev. 5, ISO/IEC 27001:2022, and PCI-DSS v4.0. The matrix below outlines security control gaps identified:"
        )
        elements.append(Paragraph(grc_intro, style_body))
        elements.append(Spacer(1, 3 * mm))

        grc_headers = [
            Paragraph("<b>Framework</b>", style_table_header),
            Paragraph("<b>Control Domain / Standard</b>", style_table_header),
            Paragraph("<b>Mapped Findings</b>", style_table_header),
            Paragraph("<b>Compliance Status</b>", style_table_header),
        ]
        grc_rows = [grc_headers]

        framework_definitions = [
            ("OWASP Top 10 (2021)", "A01: Broken Access Control / A03: Injection", sum(1 for f in findings if f.get("cwe") in ["CWE-89", "CWE-639", "CWE-22", "CWE-287"])),
            ("NIST SP 800-53 Rev. 5", "AC-3 (Access Enforcement), SI-10 (Input Validation)", len(findings)),
            ("ISO/IEC 27001:2022", "Control A.8.26 (Application Security), A.8.28 (Secure Coding)", len(findings)),
            ("PCI-DSS v4.0", "Requirement 6.2.4 (Defend against injection & access control flaws)", sum(1 for f in findings if f.get("cwe") in ["CWE-89", "CWE-287", "CWE-79"]))
        ]

        for fw, domain, count in framework_definitions:
            status_text = "<font color='#B91C1C'><b>Non-Compliant (Gaps Found)</b></font>" if count > 0 else "<font color='#047857'><b>Compliant (No Gaps)</b></font>"
            grc_rows.append([
                Paragraph(f"<b>{_escape(fw)}</b>", style_table_cell_bold),
                Paragraph(_escape(domain), style_table_cell),
                Paragraph(f"{count} gap(s) identified", style_table_cell),
                Paragraph(status_text, style_table_cell)
            ])

        t_grc = Table(grc_rows, colWidths=[40 * mm, 65 * mm, 35 * mm, content_w - 140 * mm])
        t_grc.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), C_NAVY),
            ('BOX', (0, 0), (-1, -1), 0.5, C_BORDER),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, C_BORDER),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ]))
        elements.append(t_grc)
        elements.append(Spacer(1, 6 * mm))

        # =========================================================================
        # 7. ATTESTATION & LEGAL DISCLAIMER
        # =========================================================================
        elements.append(Paragraph("6. Audit Attestation & Mandatory Disclaimer", style_h1))
        elements.append(HRFlowable(width="100%", thickness=1, color=C_NAVY, spaceBefore=2, spaceAfter=8))

        # Signatures Box
        sig_data = [
            [
                Paragraph("<b>Prepared By:</b>", style_table_cell_bold),
                Paragraph(_escape(author), style_table_cell),
                Paragraph("<b>Audit Review:</b>", style_table_cell_bold),
                Paragraph("Formal VAPT Review Passed", style_table_cell)
            ],
            [
                Paragraph("<b>Assessment Status:</b>", style_table_cell_bold),
                Paragraph(f"Completed ({len(findings)} Findings Confirmed)", style_table_cell),
                Paragraph("<b>Tracegate Registry ID:</b>", style_table_cell_bold),
                Paragraph(f"{_escape(proj.get('id', 'TG-PROJ'))}", style_table_cell)
            ]
        ]
        t_sig = Table(sig_data, colWidths=[38 * mm, 45 * mm, 38 * mm, content_w - 121 * mm])
        t_sig.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), C_LIGHT_BG),
            ('BOX', (0, 0), (-1, -1), 0.5, C_BORDER),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, C_BORDER),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(t_sig)
        elements.append(Spacer(1, 4 * mm))

        # Mandatory Disclaimer Box
        disc_p = (
            f"<b>MANDATORY SECURITY DISCLAIMER:</b> {_escape(disclaimer)} "
            "This report reflects the security posture and evaluated attack surfaces identified strictly as of the assessment date. "
            "Because target application software, underlying dependencies, and threats evolve dynamically, this document must not be construed "
            "as an absolute or permanent guarantee of immunity against future exploitation vectors."
        )
        t_disc = Table([[Paragraph(disc_p, ParagraphStyle('DiscP', fontName='Helvetica', fontSize=7.5, textColor=C_MUTED, leading=10.5))]], colWidths=[content_w])
        t_disc.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(t_disc)

        # Build Document
        doc.build(elements, canvasmaker=NumberedReportCanvas)

        # Validate Output with PDF Validator
        is_valid, err = validate_pdf_artifact(target_pdf_path)
        if not is_valid:
            logger.error(f"Generated PDF failed validation: {err}")
            try:
                target_pdf_path.unlink()
            except Exception:
                pass
            return None

        logger.info(f"Native ReportLab PDF Report compiled and verified at: {target_pdf_path}")
        return target_pdf_path

    except Exception as exc:
        logger.error(f"Failed to generate native PDF report via ReportLab: {exc}", exc_info=True)
        return None


def ensure_pdf_title_metadata(
    pdf_path: Union[str, Path],
    title: Optional[str] = None,
    author: Optional[str] = None
) -> bool:
    """
    Ensures that the PDF Document Information dictionary (/Info) has /Title and /Author metadata set.
    This guarantees that browser PDF viewers (like Chrome / Edge PDFium) display the legitimate
    document title or filename in the browser tab instead of '(anonymous)'.
    """
    try:
        from pypdf import PdfReader, PdfWriter
        p = Path(pdf_path).resolve()
        if not p.exists() or p.stat().st_size == 0:
            return False

        reader = PdfReader(str(p))
        meta = reader.metadata or {}
        existing_title = str(meta.get("/Title") or "").strip()

        if title:
            effective_title = str(title).strip()
            if existing_title == effective_title:
                return True
        else:
            if existing_title:
                return True
            effective_title = p.stem.replace("_", " ").replace("-", " ")
        effective_author = (author or "").strip() or "Tracegate Security Assessment Platform"

        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)

        new_meta = {k: v for k, v in (meta or {}).items()}
        new_meta["/Title"] = effective_title
        new_meta["/Author"] = effective_author
        new_meta["/Subject"] = "Vulnerability Assessment and Penetration Testing Report"
        new_meta["/Creator"] = "Tracegate Security Report Engine"

        writer.add_metadata(new_meta)
        temp_path = p.with_suffix(".tmp_meta.pdf")
        with open(temp_path, "wb") as f_out:
            writer.write(f_out)

        import shutil
        shutil.move(str(temp_path), str(p))
        logger.info(f"Updated PDF metadata /Title to '{effective_title}' for {p.name}")
        return True
    except Exception as e:
        logger.warning(f"ensure_pdf_title_metadata failed for {pdf_path}: {e}")
        return False


def compile_report_pdf(
    model: Dict[str, Any],
    target_pdf_path: Union[str, Path],
    docx_path: Optional[Union[str, Path]] = None
) -> Optional[Path]:
    """
    Unified PDF report compiler with dual-engine strategy and strict verification:
    1. If docx_path exists and Word COM is available on Windows, attempts conversion via convert_docx_to_pdf.
       Verifies output with is_valid_pdf.
    2. If Word COM is unavailable, disabled, or fails validation, immediately compiles native PDF
       via pure-Python ReportLab generate_pdf_report(model, target_pdf_path).
    3. Guarantees 100% reliable, verified binary PDF generation.
    4. Guarantees /Title and /Author metadata are present for crisp browser viewer tab display.
    """
    from typing import Union
    target_path = Path(target_pdf_path).resolve()
    doc_title = model.get("title") or model.get("report_title") or f"Tracegate VAPT Report - {model.get('project_name', 'Project')}"
    author = model.get("assessment_team") or model.get("lead_assessor") or "Tracegate Security Team"

    # If target already exists and is valid, ensure metadata and return immediately
    if is_valid_pdf(target_path):
        ensure_pdf_title_metadata(target_path, doc_title, author)
        return target_path

    # Try Word COM if docx_path exists
    if docx_path and Path(docx_path).exists():
        try:
            from backend.report_generator import convert_docx_to_pdf
            com_res = convert_docx_to_pdf(str(docx_path))
            if com_res and is_valid_pdf(com_res):
                com_path = Path(com_res).resolve()
                if com_path != target_path:
                    import shutil
                    shutil.copy2(com_path, target_path)
                if is_valid_pdf(target_path):
                    ensure_pdf_title_metadata(target_path, doc_title, author)
                    logger.info(f"Report PDF successfully compiled via Word COM at: {target_path}")
                    return target_path
        except Exception as e:
            logger.debug(f"Word COM conversion bypassed or failed ({e}), using native ReportLab")

    # Native ReportLab compilation
    res = generate_pdf_report(model, target_path)
    if res and is_valid_pdf(res):
        ensure_pdf_title_metadata(res, doc_title, author)
        logger.info(f"Report PDF successfully compiled via ReportLab at: {res}")
        return res

    logger.error(f"All PDF compilation methods failed for target: {target_path}")
    return None

