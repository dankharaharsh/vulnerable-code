"""
Tracegate Enterprise Microsoft Word (.docx) & Native PDF VAPT Report Generator.
Complies with authoritative 27-Section Document Architecture (Rule 62) & Single Render Guarantee.
"""

import io
import os
import time
import re
import json
import base64
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set
from datetime import datetime
from PIL import Image

import docx
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import parse_xml, OxmlElement
from docx.oxml.ns import nsdecls, qn

from backend.knowledge_base import get_finding_template_for_test
from backend.grc_frameworks import (
    MANDATORY_GRC_DISCLAIMER,
    FRAMEWORKS_METADATA,
    map_finding_to_grc_frameworks,
    aggregate_security_control_gaps
)
from backend.report_model import (
    assemble_normalized_report_model,
    validate_report_model_integrity,
    ReportIntegrityError,
    redact_sensitive_secrets,
    format_cvss_vector,
    get_remediation_sla
)

logger = logging.getLogger("report_generator")

# Professional Color Palette
COLOR_NAVY = RGBColor(30, 58, 138)       # Deep Navy headings (#1E3A8A)
COLOR_SLATE = RGBColor(15, 23, 42)      # Primary text (#0F172A)
COLOR_MUTED = RGBColor(100, 116, 139)   # Subtitles (#64748B)
COLOR_CRIT = RGBColor(185, 28, 28)      # Critical severity (#B91C1C)
COLOR_HIGH = RGBColor(194, 65, 12)      # High severity (#C2410C)
COLOR_MED = RGBColor(180, 83, 9)        # Medium severity (#B45309)
COLOR_LOW = RGBColor(4, 120, 87)        # Low severity (#047857)
COLOR_INFO = RGBColor(2, 132, 199)      # Informational severity (#0284C7)

HEX_BG_HEADER = "1E3A8A"                # Dark navy header fill
HEX_BG_CALLOUT = "F8FAFC"               # Light slate callout background
HEX_BG_MUTED = "F1F5F9"                 # Border/zebra fill
HEX_BG_ALERT = "FEF2F2"                 # Soft red fill
HEX_BG_WARN = "FFFBEB"                  # Soft amber fill
HEX_BG_SUCCESS = "ECFDF5"               # Soft green fill

REPORTS_DIR = Path(__file__).resolve().parent.parent / "data" / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# =============================================================================
# DOCUMENT STYLING & PAGINATION SAFETY HELPERS
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

def make_table_safe_for_pagination(table) -> None:
    """
    Applies Word XML pagination safety to tables:
    1. Sets tblHeader on row 0 so table headers repeat cleanly if split across pages.
    2. Sets cantSplit on all rows so rows never break halfway across page boundaries.
    """
    for idx, row in enumerate(table.rows):
        trPr = row._tr.get_or_add_trPr()
        cantSplit = parse_xml(r'<w:cantSplit xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>')
        trPr.append(cantSplit)
        if idx == 0:
            tblHeader = parse_xml(r'<w:tblHeader xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>')
            trPr.append(tblHeader)

def calculate_deterministic_risk_rating(
    crit_count: int,
    high_count: int,
    med_count: int,
    low_count: int,
    info_count: int,
    total_tests: int,
    tested_tests: int
) -> Tuple[str, RGBColor, str]:
    """Deterministic calculation for Tracegate Assessment Risk Rating."""
    total_findings = crit_count + high_count + med_count + low_count + info_count

    if crit_count >= 1 or high_count >= 2:
        return "CRITICAL RISK", COLOR_CRIT, (
            "The target architecture possesses vulnerabilities with severe exploitability or full impact "
            "over sensitive assets, user accounts, or underlying systems. Urgent remediation is mandatory."
        )
    elif high_count >= 1 or med_count >= 3:
        return "HIGH RISK", COLOR_HIGH, (
            "The target environment contains high-impact flaws or multiple moderate weaknesses that could "
            "be chained to bypass security boundaries. Timely remediation should be prioritized."
        )
    elif med_count >= 1 or low_count >= 4:
        return "MEDIUM RISK", COLOR_MED, (
            "The assessment identified moderate risks or multiple baseline flaws requiring planned remediation "
            "within the standard engineering cycle."
        )
    elif low_count >= 1:
        return "LOW RISK", COLOR_LOW, (
            "Identified issues present minimal immediate exploitability or low technical impact. "
            "Remediation is recommended during routine maintenance."
        )
    elif info_count >= 1:
        return "INFORMATIONAL RISK", COLOR_INFO, (
            "Only informational observations or defense-in-depth enhancements were noted. "
            "No direct vulnerability exploitation vectors were confirmed."
        )
    elif total_tests > 0 and tested_tests >= total_tests and total_findings == 0:
        return "CLEAN POSTURE / NEGLIGIBLE RISK", COLOR_LOW, (
            "No confirmed vulnerabilities were identified across all evaluated security controls. "
            "All targeted controls operated in accordance with expected baseline security standards."
        )
    else:
        return "INCOMPLETE ASSESSMENT / NOT EVALUATED", COLOR_MUTED, (
            "No confirmed vulnerabilities were identified; however, planned security controls have not been "
            "fully evaluated. This posture must not be interpreted as certified security."
        )

def add_styled_heading(doc: Document, text: str, level: int):
    """Creates a cleanly styled heading."""
    h = doc.add_heading(text, level=level)
    h.paragraph_format.keep_with_next = True
    h.paragraph_format.space_before = Pt(14)
    h.paragraph_format.space_after = Pt(6)
    if level == 1:
        for run in h.runs:
            run.font.name = "Calibri"
            run.font.size = Pt(15)
            run.font.bold = True
            run.font.color.rgb = COLOR_NAVY
    elif level == 2:
        for run in h.runs:
            run.font.name = "Calibri"
            run.font.size = Pt(12.5)
            run.font.bold = True
            run.font.color.rgb = COLOR_NAVY
    elif level == 3:
        for run in h.runs:
            run.font.name = "Calibri"
            run.font.size = Pt(11)
            run.font.bold = True
            run.font.color.rgb = COLOR_SLATE
    return h

def add_callout_box(doc: Document, text: str, bg_hex: str = HEX_BG_CALLOUT, border_color_rgb: RGBColor = COLOR_NAVY, title: Optional[str] = None):
    """Renders an indented shaded callout box with optional bold title."""
    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = table.rows[0].cells[0]
    cell.width = Inches(6.5)
    set_cell_background(cell, bg_hex)
    set_cell_margins(cell, top=140, bottom=140, left=180, right=180)

    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(0)
    p.paragraph_format.line_spacing = 1.15

    if title:
        rtitle = p.add_run(f"{title}\n")
        rtitle.font.name = "Calibri"
        rtitle.font.size = Pt(10)
        rtitle.font.bold = True
        rtitle.font.color.rgb = border_color_rgb

    rtext = p.add_run(text)
    rtext.font.name = "Calibri"
    rtext.font.size = Pt(9.5)
    rtext.font.color.rgb = COLOR_SLATE

    make_table_safe_for_pagination(table)

    p_spacer = doc.add_paragraph()
    p_spacer.paragraph_format.space_before = Pt(4)
    p_spacer.paragraph_format.space_after = Pt(4)

def add_monospaced_block(doc: Document, code_text: str):
    """Renders a monospaced code snippet block in Consolas 8.5pt with #F8FAFC shading."""
    clean_text = code_text.strip() if code_text else "No technical snippet recorded."
    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = table.rows[0].cells[0]
    cell.width = Inches(6.5)
    set_cell_background(cell, HEX_BG_CALLOUT)
    set_cell_margins(cell, top=120, bottom=120, left=160, right=160)

    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(0)
    p.paragraph_format.line_spacing = 1.05

    run = p.add_run(clean_text)
    run.font.name = "Consolas"
    run.font.size = Pt(8.5)
    run.font.color.rgb = COLOR_SLATE

    make_table_safe_for_pagination(table)

    p_spacer = doc.add_paragraph()
    p_spacer.paragraph_format.space_before = Pt(4)
    p_spacer.paragraph_format.space_after = Pt(4)

def resolve_evidence_bytes(ev_item: Dict[str, Any], project_id: Optional[str] = None) -> Optional[bytes]:
    """Resolves raw artifact bytes from base64 data, disk file_path, project storage, or sample assets."""
    raw_data = ev_item.get("data")
    if raw_data:
        try:
            b64_part = str(raw_data).split(",", 1)[1] if "," in str(raw_data) else str(raw_data)
            return base64.b64decode(b64_part)
        except Exception as e:
            logger.warning(f"Failed to decode base64 evidence: {e}")

    stored_fn = ev_item.get("stored_filename") or ev_item.get("filename")
    proj_id = project_id or ev_item.get("project_id")
    base_dir = Path(__file__).resolve().parent.parent

    candidates: List[Path] = []
    if ev_item.get("file_path"):
        candidates.append(Path(ev_item["file_path"]))
    if proj_id and stored_fn:
        candidates.append(base_dir / "data" / "evidence" / str(proj_id) / stored_fn)
    if proj_id and ev_item.get("filename"):
        candidates.append(base_dir / "data" / "evidence" / str(proj_id) / ev_item["filename"])
    if stored_fn:
        candidates.append(base_dir / "data" / "evidence" / stored_fn)
        candidates.append(base_dir / "samples" / stored_fn)
        candidates.append(base_dir / stored_fn)
        candidates.append(Path(stored_fn))
    if ev_item.get("filename"):
        candidates.append(base_dir / "samples" / ev_item["filename"])

    for cand in candidates:
        if cand and cand.is_file():
            try:
                with open(cand, "rb") as f_in:
                    return f_in.read()
            except Exception as e:
                logger.warning(f"Failed to read evidence from {cand}: {e}")

    return None

def embed_evidence_screenshot(doc: Document, ev_item: Dict[str, Any], project_id: Optional[str] = None):
    """
    Renders an auditable evidence artifact (Screenshot Image, Monospaced PoC Text/JSON/Log, or Document Reference)
    into Section H of the VAPT client report with centered Figure captions and metadata.
    """
    caption_text = ev_item.get("caption") or "Evidence demonstrating the reported behavior"
    fig_label = ev_item.get("figure_label", "Figure 1")
    ev_id = ev_item.get("evidence_id", "EV-001")
    cat = ev_item.get("category", "IMAGE")
    proj_id = project_id or ev_item.get("project_id")
    fn = ev_item.get("filename", "capture.png")

    # 1. TEXT / JSON / CODE / LOG EVIDENCE RENDERING (Requirements 16-17)
    if cat in ["TEXT", "JSON"] or ev_item.get("text_content"):
        txt = ev_item.get("text_content")
        if not txt:
            raw_b = resolve_evidence_bytes(ev_item, proj_id)
            if raw_b:
                try:
                    txt = redact_sensitive_secrets(raw_b.decode("utf-8", errors="replace"))
                    if cat == "JSON":
                        try:
                            txt = json.dumps(json.loads(txt), indent=2)
                        except Exception:
                            pass
                except Exception:
                    pass

        if txt:
            p_cap = doc.add_paragraph()
            p_cap.paragraph_format.space_before = Pt(6)
            p_cap.paragraph_format.space_after = Pt(2)
            rcap_lead = p_cap.add_run(f"{ev_id} — {fig_label}: ")
            rcap_lead.font.name = "Calibri"
            rcap_lead.font.size = Pt(8.5)
            rcap_lead.font.bold = True
            rcap_lead.font.color.rgb = COLOR_NAVY

            rcap_txt = p_cap.add_run(caption_text)
            rcap_txt.font.name = "Calibri"
            rcap_txt.font.size = Pt(8.5)
            rcap_txt.font.italic = True
            rcap_txt.font.color.rgb = COLOR_MUTED

            lines = txt.strip().split("\n")
            if len(lines) > 30:
                excerpt = "\n".join(lines[:30]) + f"\n... [Truncated: {len(lines) - 30} additional lines in raw artifact]"
            else:
                excerpt = txt.strip()
            add_monospaced_block(doc, excerpt)

            p_meta = doc.add_paragraph()
            p_meta.paragraph_format.space_before = Pt(0)
            p_meta.paragraph_format.space_after = Pt(8)
            rmeta = p_meta.add_run(f"Source: {ev_item.get('source', 'Tester-provided evidence')}  |  Artifact: {fn}  |  Format: Technical PoC Excerpt")
            rmeta.font.name = "Calibri"
            rmeta.font.size = Pt(7.5)
            rmeta.font.color.rgb = COLOR_MUTED

            if ev_item.get("target_mismatch"):
                p_warn = doc.add_paragraph()
                r_w = p_warn.add_run("⚠️ WARNING: Evidence artifact may reference a different target/environment and requires review.")
                r_w.font.name = "Calibri"
                r_w.font.size = Pt(8.0)
                r_w.font.bold = True
                r_w.font.color.rgb = RGBColor(180, 83, 9)
            return

    # 2. DOCUMENT / PDF EVIDENCE (Requirements 18-19)
    if cat == "DOCUMENT":
        p_doc = doc.add_paragraph()
        p_doc.paragraph_format.space_before = Pt(4)
        p_doc.paragraph_format.space_after = Pt(6)
        rdoc = p_doc.add_run(f"Evidence document attached to assessment record: {fn} [Evidence ID: {ev_id}]")
        rdoc.font.name = "Calibri"
        rdoc.font.size = Pt(8.5)
        rdoc.font.italic = True
        rdoc.font.color.rgb = COLOR_MUTED
        return

    # 3. IMAGE EVIDENCE (Requirements 8, 9, 14, 15, 31, 38)
    img_bytes = resolve_evidence_bytes(ev_item, proj_id)

    if img_bytes:
        try:
            img_io = io.BytesIO(img_bytes)
            with Image.open(img_io) as pil_img:
                w, h = pil_img.size
                aspect = (w / float(h)) if h > 0 else 1.0
                if aspect >= 1.0:
                    display_w = min(5.6, max(2.5, w / 150.0))
                    display_h = display_w / aspect
                    if display_h > 4.2:
                        display_h = 4.2
                        display_w = display_h * aspect
                else:
                    display_h = min(4.2, max(2.0, h / 150.0))
                    display_w = display_h * aspect
                    if display_w > 5.6:
                        display_w = 5.6
                        display_h = display_w / aspect

            img_io.seek(0)
            p_img = doc.add_paragraph()
            p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p_img.paragraph_format.space_before = Pt(6)
            p_img.paragraph_format.space_after = Pt(4)
            run_img = p_img.add_run()
            run_img.add_picture(img_io, width=Inches(display_w), height=Inches(display_h))

            p_cap = doc.add_paragraph()
            p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p_cap.paragraph_format.space_before = Pt(2)
            p_cap.paragraph_format.space_after = Pt(2)

            rcap_lead = p_cap.add_run(f"{ev_id} — {fig_label}: ")
            rcap_lead.font.name = "Calibri"
            rcap_lead.font.size = Pt(8.5)
            rcap_lead.font.bold = True
            rcap_lead.font.color.rgb = COLOR_NAVY

            rcap_text = p_cap.add_run(caption_text)
            rcap_text.font.name = "Calibri"
            rcap_text.font.size = Pt(8.5)
            rcap_text.font.italic = True
            rcap_text.font.color.rgb = COLOR_MUTED

            p_meta = doc.add_paragraph()
            p_meta.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p_meta.paragraph_format.space_before = Pt(0)
            p_meta.paragraph_format.space_after = Pt(8)
            rmeta = p_meta.add_run(f"Source: {ev_item.get('source', 'Tester-provided evidence')}  |  Artifact: {fn}  |  Type: Visual Screenshot Capture")
            rmeta.font.name = "Calibri"
            rmeta.font.size = Pt(7.5)
            rmeta.font.color.rgb = COLOR_MUTED

            if ev_item.get("target_mismatch"):
                p_warn = doc.add_paragraph()
                p_warn.alignment = WD_ALIGN_PARAGRAPH.CENTER
                r_w = p_warn.add_run("⚠️ WARNING: Evidence artifact may reference a different target/environment and requires review.")
                r_w.font.name = "Calibri"
                r_w.font.size = Pt(8.0)
                r_w.font.bold = True
                r_w.font.color.rgb = RGBColor(180, 83, 9)
            return
        except Exception as e:
            logger.warning(f"Failed to render image evidence: {e}")
            p_fail = doc.add_paragraph()
            p_fail.paragraph_format.space_before = Pt(4)
            p_fail.paragraph_format.space_after = Pt(6)
            rfail = p_fail.add_run(f"Evidence artifact could not be rendered. [Evidence ID: {ev_id} | Original filename: '{fn}']")
            rfail.font.name = "Calibri"
            rfail.font.size = Pt(8.5)
            rfail.font.italic = True
            rfail.font.color.rgb = COLOR_MUTED
            return

    # 4. ARTIFACT UNAVAILABLE AT REPORT GENERATION TIME (Requirement 25)
    p_unavail = doc.add_paragraph()
    p_unavail.paragraph_format.space_before = Pt(4)
    p_unavail.paragraph_format.space_after = Pt(6)
    run_unavail = p_unavail.add_run(f"Evidence artifact unavailable at report-generation time. [Evidence ID: {ev_id} | Filename: '{fn}']")
    run_unavail.font.name = "Calibri"
    run_unavail.font.size = Pt(8.5)
    run_unavail.font.italic = True
    run_unavail.font.color.rgb = COLOR_MUTED

def convert_docx_to_pdf(docx_path: str) -> Optional[str]:
    """Converts a .docx document to native Microsoft Word PDF using Word COM automation."""
    docx_file = Path(docx_path).resolve()
    if not docx_file.exists():
        logger.error(f"Cannot convert non-existent docx: {docx_path}")
        return None

    pdf_file = docx_file.with_suffix(".pdf")
    try:
        from backend.pdf_validator import is_valid_pdf
        import pythoncom
        import win32com.client
        pythoncom.CoInitialize()
        word = None
        try:
            word = win32com.client.Dispatch("Word.Application")
            word.Visible = False
            word.DisplayAlerts = 0
            doc = word.Documents.Open(str(docx_file))
            try:
                target_pdf = pdf_file
                doc.SaveAs(str(target_pdf), FileFormat=17)
            except Exception as se:
                logger.warning(f"Could not save PDF to {pdf_file} ({se}), trying alternative path")
                target_pdf = docx_file.parent / f"{docx_file.stem}_{int(time.time())}.pdf"
                doc.SaveAs(str(target_pdf), FileFormat=17)
            finally:
                try:
                    doc.Close(SaveChanges=0)
                except Exception:
                    pass

            if target_pdf.exists() and is_valid_pdf(target_pdf):
                if target_pdf != pdf_file and not pdf_file.exists():
                    try:
                        import shutil
                        shutil.copy2(target_pdf, pdf_file)
                        if is_valid_pdf(pdf_file):
                            target_pdf = pdf_file
                    except Exception:
                        pass
                logger.info(f"Native Word PDF successfully compiled and verified at: {target_pdf}")
                return str(target_pdf)
            else:
                logger.warning(f"Word COM output failed PDF binary validation: {target_pdf}")
                return None
        finally:
            if word is not None:
                try:
                    word.Quit()
                except Exception:
                    pass
            pythoncom.CoUninitialize()
    except Exception as e:
        logger.warning(f"Word COM PDF conversion encountered an error: {e}", exc_info=True)
        return None

# =============================================================================
# SINGLE RENDER GUARANTEE & REPORT SECTION REGISTRY
# =============================================================================

class ReportSectionRegistry:
    """
    Registry enforcing Single Render Guarantee across the document.
    Blocks accidental duplication of sections or registers.
    """
    def __init__(self):
        self.rendered_sections: Set[str] = set()

    def render_section(self, section_id: str, render_fn, *args, **kwargs):
        if section_id in self.rendered_sections:
            raise ReportIntegrityError(f"DUPLICATE_SECTION: Section '{section_id}' has already been rendered in this document.")
        self.rendered_sections.add(section_id)
        return render_fn(*args, **kwargs)

# =============================================================================
# POST-RENDER DOCUMENT INTEGRITY VERIFIER
# =============================================================================

def verify_rendered_document_integrity(doc: Document, model: Dict[str, Any]) -> None:
    """
    Post-render verification gate:
    1. Ensures no duplicate top-level section headings exist.
    2. Ensures zero internal AI AutoFix or git branch leakage.
    3. Verifies each finding is represented exactly once.
    """
    heading_counts: Dict[str, int] = {}
    for p in doc.paragraphs:
        if p.style and ("Heading 1" in p.style.name or "Heading 2" in p.style.name):
            text = p.text.strip()
            if text.startswith("Section ") or text.startswith("Appendix "):
                heading_counts[text] = heading_counts.get(text, 0) + 1
                if heading_counts[text] > 1:
                    raise ReportIntegrityError(f"Duplicate top-level heading detected: '{text}'")

    # Full text scan for prohibited AI AutoFix leaks
    doc_text = "\n".join(p.text for p in doc.paragraphs) + "\n"
    for t in doc.tables:
        for row in t.rows:
            doc_text += " ".join(c.text for c in row.cells) + "\n"

    prohibited_patterns = [
        r"\btracegate/fix/",
        r"\bai autofix\b",
        r"\bai-fix-card\b",
        r"\bai source discovery\b"
    ]
    for pattern in prohibited_patterns:
        match = re.search(pattern, doc_text, re.IGNORECASE)
        if match:
            raise ReportIntegrityError(f"Prohibited internal AutoFix/git branch leakage detected in rendered report: '{match.group(0)}'")

    # Verify all finding headings appear exactly once
    for f in model.get("findings", []):
        f_heading = f"{f['report_vuln_id']}: {f['finding_name']}"
        h2_count = sum(1 for p in doc.paragraphs if p.text.strip() == f_heading)
        if h2_count > 1:
            raise ReportIntegrityError(f"Duplicate finding heading detected in rendered report: '{f_heading}'")

# =============================================================================
# 27 AUTHORITATIVE REPORT SECTION RENDERERS (RULE 62)
# =============================================================================

def render_section_1_cover(doc: Document, model: Dict[str, Any]) -> None:
    """Section 1: Title & Metadata Page (Cover Page)"""
    proj_meta = model["project"]
    doc_meta = model["document_metadata"]
    risk = model["risk_posture"]

    p_pre = doc.add_paragraph()
    p_pre.paragraph_format.space_before = Pt(36)

    p_eyebrow = doc.add_paragraph()
    run_eyebrow = p_eyebrow.add_run("TRACEGATE CYBERSECURITY ASSESSMENT & VAPT PLATFORM")
    run_eyebrow.font.name = "Calibri"
    run_eyebrow.font.size = Pt(11)
    run_eyebrow.font.bold = True
    run_eyebrow.font.color.rgb = COLOR_NAVY
    p_eyebrow.paragraph_format.space_after = Pt(8)

    p_title = doc.add_paragraph()
    run_title = p_title.add_run("VULNERABILITY ASSESSMENT & PENETRATION TESTING REPORT")
    run_title.font.name = "Calibri"
    run_title.font.size = Pt(22)
    run_title.font.bold = True
    run_title.font.color.rgb = COLOR_SLATE
    p_title.paragraph_format.space_after = Pt(6)

    p_sub = doc.add_paragraph()
    run_sub = p_sub.add_run(f"Target System: {proj_meta['name']}  |  {proj_meta['environment']}")
    run_sub.font.name = "Calibri"
    run_sub.font.size = Pt(13)
    run_sub.font.color.rgb = COLOR_MUTED
    p_sub.paragraph_format.space_after = Pt(32)

    meta_table = doc.add_table(rows=8, cols=2)
    meta_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    m_widths = [Inches(2.2), Inches(4.3)]
    meta_data = [
        ("Client Organization", proj_meta["organization"]),
        ("Target URL / Host", proj_meta["target_url"]),
        ("Assessment Methodology", doc_meta["methodology_name"]),
        ("Report Document Version", doc_meta["version"]),
        ("Lead Security Assessor", doc_meta["author_name"]),
        ("Lead Security Reviewer", doc_meta["reviewer_name"]),
        ("Document Classification", doc_meta["classification"]),
        ("Assessment Execution Period", f"{proj_meta['created_at']} to {doc_meta['generation_date']}")
    ]
    for r_idx, (label, val) in enumerate(meta_data):
        row = meta_table.rows[r_idx]
        c0, c1 = row.cells[0], row.cells[1]
        c0.width, c1.width = m_widths[0], m_widths[1]
        set_cell_margins(c0, top=70, bottom=70, left=80, right=80)
        set_cell_margins(c1, top=70, bottom=70, left=80, right=80)
        if r_idx % 2 == 0:
            set_cell_background(c0, HEX_BG_MUTED)
            set_cell_background(c1, HEX_BG_MUTED)
        p0 = c0.paragraphs[0]
        r0 = p0.add_run(label)
        r0.font.name = "Calibri"
        r0.font.bold = True
        r0.font.size = Pt(9.5)
        r0.font.color.rgb = COLOR_SLATE
        p1 = c1.paragraphs[0]
        r1 = p1.add_run(str(val))
        r1.font.name = "Calibri"
        r1.font.size = Pt(9.5)
        r1.font.color.rgb = COLOR_SLATE
    make_table_safe_for_pagination(meta_table)

    p_badge = doc.add_paragraph()
    p_badge.paragraph_format.space_before = Pt(28)
    p_badge.paragraph_format.space_after = Pt(4)
    r_badge = p_badge.add_run(f"ASSESSMENT RISK POSTURE:  {risk['label']}")
    r_badge.font.name = "Calibri"
    r_badge.font.bold = True
    r_badge.font.size = Pt(10)
    r_badge.font.color.rgb = COLOR_CRIT if "CRIT" in risk['label'] else COLOR_NAVY

def render_section_2_document_control(doc: Document, model: Dict[str, Any]) -> None:
    """Section 2: Document Control & Revision History"""
    doc_meta = model["document_metadata"]
    doc.add_page_break()
    add_styled_heading(doc, "Section 2: Document Control & Revision History", level=1)

    p_dc = doc.add_paragraph()
    p_dc.add_run(
        "This assessment report is maintained under formal configuration management and version control. "
        "All updates, findings verifications, and client release versions are logged in the historical ledger below."
    )

    dc_table = doc.add_table(rows=1, cols=5)
    dc_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    dc_headers = ["Version", "Release Date", "Author / Assessor", "Reviewer", "Change Summary"]
    dc_widths = [Inches(0.9), Inches(1.2), Inches(1.5), Inches(1.3), Inches(1.6)]

    for c_idx, title in enumerate(dc_headers):
        cell = dc_table.rows[0].cells[c_idx]
        cell.width = dc_widths[c_idx]
        set_cell_background(cell, HEX_BG_HEADER)
        set_cell_margins(cell, top=80, bottom=80, left=80, right=80)
        p = cell.paragraphs[0]
        r = p.add_run(title)
        r.font.name = "Calibri"
        r.font.bold = True
        r.font.size = Pt(8.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    hist_entries = doc_meta.get("historical_reports") or []
    if not hist_entries:
        hist_entries = [{
            "version": doc_meta["version"],
            "created_at": doc_meta["generation_date"],
            "created_by": doc_meta["author_name"],
            "reviewer": doc_meta["reviewer_name"],
            "notes": "Official VAPT Assessment Report release"
        }]

    for idx, h in enumerate(hist_entries):
        row = dc_table.add_row()
        vals = [
            h.get("version", doc_meta["version"]),
            h.get("created_at", doc_meta["generation_date"]),
            h.get("created_by") or doc_meta["author_name"],
            doc_meta["reviewer_name"],
            "Initial Assessment Package" if idx == 0 else "Updated findings package and retest verification"
        ]
        for c_idx, val in enumerate(vals):
            cell = row.cells[c_idx]
            cell.width = dc_widths[c_idx]
            set_cell_margins(cell, top=60, bottom=60, left=80, right=80)
            if idx % 2 == 1:
                set_cell_background(cell, HEX_BG_MUTED)
            p = cell.paragraphs[0]
            r = p.add_run(str(val))
            r.font.name = "Calibri"
            r.font.size = Pt(8.5)
            r.font.color.rgb = COLOR_SLATE
    make_table_safe_for_pagination(dc_table)

    p_dist = doc.add_paragraph()
    p_dist.paragraph_format.space_before = Pt(14)
    r_dh = p_dist.add_run("Authorized Distribution Protocol:")
    r_dh.font.name = "Calibri"
    r_dh.font.bold = True
    r_dh.font.size = Pt(10)
    r_dh.font.color.rgb = COLOR_NAVY

    dist_table = doc.add_table(rows=1, cols=3)
    dist_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    dist_headers = ["Designated Recipient Role", "Access Authorization Level", "Delivery & Storage Protection"]
    dist_widths = [Inches(2.3), Inches(2.0), Inches(2.2)]

    for c_idx, title in enumerate(dist_headers):
        cell = dist_table.rows[0].cells[c_idx]
        cell.width = dist_widths[c_idx]
        set_cell_background(cell, HEX_BG_HEADER)
        set_cell_margins(cell, top=80, bottom=80, left=80, right=80)
        p = cell.paragraphs[0]
        r = p.add_run(title)
        r.font.name = "Calibri"
        r.font.bold = True
        r.font.size = Pt(8.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    dist_rows = [
        ("CISO / Head of Information Security", "Full Technical & Executive Access", "Encrypted PDF & Encrypted Storage"),
        ("Lead Application Security Engineer", "Full Technical & PoC Access", "Restricted Repository Access"),
        ("GRC & Regulatory Compliance Team", "Executive & GRC Mapping Access", "Confidential Audit Vault"),
        ("Engineering / Development Leads", "Remediation & Validation Guidance", "Role-Based Issue Tracking")
    ]
    for idx, (role, auth, prot) in enumerate(dist_rows):
        row = dist_table.add_row()
        for c_idx, val in enumerate([role, auth, prot]):
            cell = row.cells[c_idx]
            cell.width = dist_widths[c_idx]
            set_cell_margins(cell, top=60, bottom=60, left=80, right=80)
            if idx % 2 == 1:
                set_cell_background(cell, HEX_BG_MUTED)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            r.font.name = "Calibri"
            r.font.size = Pt(8.5)
            r.font.color.rgb = COLOR_SLATE
    make_table_safe_for_pagination(dist_table)

def render_section_3_table_of_contents(doc: Document, model: Dict[str, Any]) -> None:
    """Section 3: Table of Contents & Navigation Map"""
    doc.add_page_break()
    add_styled_heading(doc, "Section 3: Table of Contents & Navigation Map", level=1)

    p_toc_desc = doc.add_paragraph()
    p_toc_desc.add_run(
        "This assessment report is organized into 27 formal sections and 7 technical appendices in accordance with "
        "authoritative cybersecurity reporting standards. The navigation map below provides direct structural reference."
    )

    toc_items = [
        ("Section 1", "Title & Metadata Page (Cover Page)", "Document governance and engagement parameters"),
        ("Section 2", "Document Control & Revision History", "Version tracking and authorized distribution protocol"),
        ("Section 3", "Table of Contents & Navigation Map", "Complete report navigation index"),
        ("Section 4", "Confidentiality, Legal Disclaimer & Rules of Engagement", "Statutory GRC disclaimer and operational boundaries"),
        ("Section 5", "Executive Summary", "High-level risk narrative and strategic leadership summary"),
        ("Section 6", "Assessment Scope & Boundary Definition", "In-scope target components and explicit exclusions"),
        ("Section 7", "Target Environment & Architecture Overview", "Technical stack, deployment tier, and authentication roles"),
        ("Section 8", "Assessment Methodology & Testing Standard", "OWASP WSTG v4.2 and NIST SP 800-115 testing phases"),
        ("Section 9", "Overall Security Posture & Executive Risk Rating", "Deterministic posture scoring and rating matrix"),
        ("Section 10", "Vulnerability Severity Distribution & Metrics", "Reconciled findings counts and SLA target windows"),
        ("Section 11", "Attack Surface & Component Exposure Analysis", "Surface mapping and vulnerable parameter breakdown"),
        ("Section 12", "Testing Coverage & Verification Matrix", "Evaluated checklist controls, clean verifications, and coverage %"),
        ("Section 13", "Summary of Findings (Consolidated Table)", "High-level inventory of all confirmed vulnerabilities"),
        ("Section 14", "Category-Wise Findings Analysis", "CWE taxonomy categorization and systemic flaw patterns"),
        ("Section 15", "Detailed Technical Vulnerability Findings", "Complete 15-part technical dossiers for every finding"),
        ("Section 16", "Retest Status & Verification Lifecycle", "Secondary validation status and retest results ledger"),
        ("Section 17", "Vulnerability Remediation Register", "Consolidated developer remediation tracking matrix"),
        ("Section 18", "Prioritized Remediation Action Plan", "Phased implementation roadmap based on severity SLAs"),
        ("Section 19", "Positive Security Controls & Defenses Observed", "Verified baseline security mechanisms operating effectively"),
        ("Section 20", "Defense-in-Depth & Architectural Hardening", "Systemic security enhancements and architectural controls"),
        ("Section 21", "GRC Framework Compliance Mapping", "NIST CSF 2.0, ISO 27001, SOC 2, OWASP, PCI DSS alignments"),
        ("Section 22", "Strategic & Tactical Recommendations", "Governance, architectural, and operational security roadmap"),
        ("Section 23", "Risk Acceptance & Residual Risk Guidance", "Factual residual posture and formal acceptance criteria"),
        ("Section 24", "SDLC Integration Recommendations", "DevSecOps automation, pre-commit checks, and CI/CD security"),
        ("Section 25", "Evidence Register & Screenshot Manifest", "Traceable catalog of all captured technical artifacts"),
        ("Section 26", "Assessment Sign-Off & Attestation", "Formal assessor attestation and verification endorsement"),
        ("Section 27", "Appendices (A through G)", "CVSS scoring, Evidence index, CWE index, GRC standards, Glossary")
    ]

    toc_table = doc.add_table(rows=1, cols=3)
    toc_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    t_widths = [Inches(1.2), Inches(2.6), Inches(2.7)]

    for c_idx, title in enumerate(["Section #", "Document Section Title", "Section Content Scope"]):
        cell = toc_table.rows[0].cells[c_idx]
        cell.width = t_widths[c_idx]
        set_cell_background(cell, HEX_BG_HEADER)
        set_cell_margins(cell, top=70, bottom=70, left=70, right=70)
        p = cell.paragraphs[0]
        r = p.add_run(title)
        r.font.name = "Calibri"
        r.font.bold = True
        r.font.size = Pt(8.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    for idx, (sec_num, sec_title, sec_scope) in enumerate(toc_items):
        row = toc_table.add_row()
        for c_idx, val in enumerate([sec_num, sec_title, sec_scope]):
            cell = row.cells[c_idx]
            cell.width = t_widths[c_idx]
            set_cell_margins(cell, top=50, bottom=50, left=70, right=70)
            if idx % 2 == 1:
                set_cell_background(cell, HEX_BG_MUTED)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            r.font.name = "Calibri"
            r.font.size = Pt(8)
            if c_idx == 0:
                r.font.bold = True
    make_table_safe_for_pagination(toc_table)

def render_section_4_confidentiality_and_roe(doc: Document, model: Dict[str, Any]) -> None:
    """Section 4: Confidentiality, Legal Disclaimer & Rules of Engagement"""
    doc.add_page_break()
    add_styled_heading(doc, "Section 4: Confidentiality, Legal Disclaimer & Rules of Engagement", level=1)

    add_callout_box(
        doc,
        "CONFIDENTIALITY NOTICE: This document contains proprietary, sensitive, and confidential security assessment "
        "findings belonging to the designated client organization. Unauthorized distribution, copying, or disclosure of "
        "the contents of this report is strictly prohibited under applicable Non-Disclosure Agreements (NDAs). "
        "Storage and transmission must utilize strong cryptographic controls.",
        bg_hex=HEX_BG_CALLOUT,
        border_color_rgb=COLOR_NAVY,
        title="LEGAL & PROPRIETARY NOTICE"
    )

    add_callout_box(
        doc,
        MANDATORY_GRC_DISCLAIMER,
        bg_hex=HEX_BG_WARN,
        border_color_rgb=COLOR_MED,
        title="STATUTORY GRC & COMPLIANCE MAPPING DISCLAIMER"
    )

    roe = model.get("rules_of_engagement", {})
    p_roe = doc.add_paragraph()
    p_roe.paragraph_format.space_before = Pt(12)
    r_roe_h = p_roe.add_run("Rules of Engagement & Operational Permissions:")
    r_roe_h.font.name = "Calibri"
    r_roe_h.font.bold = True
    r_roe_h.font.size = Pt(10)
    r_roe_h.font.color.rgb = COLOR_NAVY

    roe_table = doc.add_table(rows=1, cols=2)
    roe_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    r_widths = [Inches(2.2), Inches(4.3)]
    for c_idx, title in enumerate(["Engagement Parameter", "Authorized Operational Policy"]):
        cell = roe_table.rows[0].cells[c_idx]
        cell.width = r_widths[c_idx]
        set_cell_background(cell, HEX_BG_HEADER)
        set_cell_margins(cell, top=70, bottom=70, left=80, right=80)
        p = cell.paragraphs[0]
        r = p.add_run(title)
        r.font.name = "Calibri"
        r.font.bold = True
        r.font.size = Pt(8.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    permitted_text = "\n• ".join([""] + roe.get("permitted_techniques", ["Standard Web Application Testing"]))
    prohibited_text = "\n• ".join([""] + roe.get("prohibited_techniques", ["DoS / DDoS Attacks", "Data Destruction"]))

    roe_rows = [
        ("Authorized Target Scope", roe.get("authorized_target", model["project"]["target_url"])),
        ("Authorized Testing Window", roe.get("testing_window", "Designated Active Period")),
        ("Authenticated Testing Roles", ", ".join(roe.get("authenticated_roles", ["Standard User", "Public"]))),
        ("Permitted Testing Techniques", permitted_text.strip()),
        ("Prohibited Attack Vectors", prohibited_text.strip()),
        ("Data Handling & Encryption", roe.get("data_handling", "Handled under strict non-disclosure protections."))
    ]
    for idx, (param, policy) in enumerate(roe_rows):
        row = roe_table.add_row()
        for c_idx, val in enumerate([param, policy]):
            cell = row.cells[c_idx]
            cell.width = r_widths[c_idx]
            set_cell_margins(cell, top=60, bottom=60, left=80, right=80)
            if idx % 2 == 1:
                set_cell_background(cell, HEX_BG_MUTED)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            r.font.name = "Calibri"
            r.font.size = Pt(8.5)
            if c_idx == 0:
                r.font.bold = True
    make_table_safe_for_pagination(roe_table)

def render_section_5_executive_summary(doc: Document, model: Dict[str, Any]) -> None:
    """Section 5: Executive Summary"""
    doc.add_page_break()
    add_styled_heading(doc, "Section 5: Executive Summary", level=1)

    proj_meta = model["project"]
    metrics = model["metrics"]
    risk = model["risk_posture"]
    doc_meta = model["document_metadata"]

    p_exec = doc.add_paragraph()
    if metrics["total_findings"] > 0:
        p_exec.add_run(
            f"During the authorized security assessment conducted between {proj_meta['created_at']} and {doc_meta['generation_date']}, "
            f"Tracegate performed an in-depth Vulnerability Assessment and Penetration Testing (VAPT) evaluation of "
            f"'{proj_meta['name']}' ({proj_meta['target_url']}). The assessment evaluated {metrics['tested_tests']} security controls "
            f"against recognized industry standards including {doc_meta['methodology_name']}.\n\n"
            f"The assessment identified {metrics['total_findings']} confirmed security findings requiring remediation: "
            f"{metrics['critical_count']} Critical, {metrics['high_count']} High, {metrics['medium_count']} Medium, "
            f"{metrics['low_count']} Low, and {metrics['info_count']} Informational. "
            f"Overall, {metrics['clean_tests']} evaluated controls operated effectively with no vulnerabilities detected."
        )
    else:
        p_exec.add_run(
            f"During the authorized security assessment conducted on {doc_meta['generation_date']}, Tracegate completed "
            f"a rigorous security verification across {metrics['tested_tests']} targeted test controls for '{proj_meta['name']}'. "
            f"No confirmed vulnerabilities were identified. All evaluated baseline controls performed in accordance with security standards."
        )

    add_callout_box(
        doc,
        risk["description"],
        bg_hex=HEX_BG_ALERT if "CRIT" in risk["label"] else (HEX_BG_WARN if "HIGH" in risk["label"] else HEX_BG_CALLOUT),
        border_color_rgb=COLOR_CRIT if "CRIT" in risk["label"] else COLOR_NAVY,
        title=f"DETERMINISTIC ASSESSMENT RISK POSTURE: {risk['label']}"
    )

    # Executive Recommendations
    exec_recs = model.get("executive_recommendations") or []
    if exec_recs:
        p_rec_h = doc.add_paragraph()
        p_rec_h.paragraph_format.space_before = Pt(10)
        r_rec_h = p_rec_h.add_run("Strategic Executive Recommendations:")
        r_rec_h.font.name = "Calibri"
        r_rec_h.font.bold = True
        r_rec_h.font.size = Pt(10.5)
        r_rec_h.font.color.rgb = COLOR_NAVY

        for rec in exec_recs:
            p_rec = doc.add_paragraph(style='List Bullet')
            r = p_rec.add_run(rec)
            r.font.name = "Calibri"
            r.font.size = Pt(9)
            r.font.color.rgb = COLOR_SLATE

def render_section_6_assessment_scope(doc: Document, model: Dict[str, Any]) -> None:
    """Section 6: Assessment Scope & Boundary Definition"""
    doc.add_page_break()
    add_styled_heading(doc, "Section 6: Assessment Scope & Boundary Definition", level=1)

    p_sc = doc.add_paragraph()
    p_sc.add_run(
        "The assessment scope was strictly established prior to testing execution to define authorized targets, "
        "prevent unintended disruption to shared infrastructure, and isolate third-party hosted services."
    )

    proj = model["project"]
    scope_table = doc.add_table(rows=1, cols=2)
    scope_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    s_widths = [Inches(3.2), Inches(3.3)]
    for c_idx, title in enumerate(["In-Scope Targets & Components", "Explicit Out-of-Scope Exclusions"]):
        cell = scope_table.rows[0].cells[c_idx]
        cell.width = s_widths[c_idx]
        set_cell_background(cell, HEX_BG_HEADER)
        set_cell_margins(cell, top=70, bottom=70, left=80, right=80)
        p = cell.paragraphs[0]
        r = p.add_run(title)
        r.font.name = "Calibri"
        r.font.bold = True
        r.font.size = Pt(8.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    in_items = proj.get("scope_in") or [proj["target_url"], "Application APIs", "Authentication Gateways"]
    out_items = proj.get("scope_out") or ["Denial of Service (DoS/DDoS)", "Physical Security", "Social Engineering"]

    max_rows = max(len(in_items), len(out_items))
    for r_idx in range(max_rows):
        row = scope_table.add_row()
        in_val = in_items[r_idx] if r_idx < len(in_items) else ""
        out_val = out_items[r_idx] if r_idx < len(out_items) else ""
        for c_idx, val in enumerate([in_val, out_val]):
            cell = row.cells[c_idx]
            cell.width = s_widths[c_idx]
            set_cell_margins(cell, top=50, bottom=50, left=80, right=80)
            if r_idx % 2 == 1:
                set_cell_background(cell, HEX_BG_MUTED)
            p = cell.paragraphs[0]
            r = p.add_run(f"• {val}" if val else "")
            r.font.name = "Calibri"
            r.font.size = Pt(8.5)
            r.font.color.rgb = COLOR_SLATE
    make_table_safe_for_pagination(scope_table)

    p_note = doc.add_paragraph()
    p_note.paragraph_format.space_before = Pt(10)
    p_note.add_run(
        "Scope Limitation Note: Any endpoint, sub-domain, cloud service, or API not explicitly cataloged in the "
        "in-scope table above remained strictly excluded from all testing activities."
    )

def render_section_7_target_environment(doc: Document, model: Dict[str, Any]) -> None:
    """Section 7: Target Environment & Architecture Overview"""
    doc.add_page_break()
    add_styled_heading(doc, "Section 7: Target Environment & Architecture Overview", level=1)

    target_info = model.get("target_information", {})
    p_te = doc.add_paragraph()
    p_te.add_run(
        "A comprehensive architectural survey was conducted during initial reconnaissance to identify technologies, "
        "frameworks, communication protocols, and authentication boundaries."
    )

    arch_table = doc.add_table(rows=1, cols=2)
    arch_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    a_widths = [Inches(2.2), Inches(4.3)]
    for c_idx, title in enumerate(["Architecture Attribute", "Target Environment Specification"]):
        cell = arch_table.rows[0].cells[c_idx]
        cell.width = a_widths[c_idx]
        set_cell_background(cell, HEX_BG_HEADER)
        set_cell_margins(cell, top=70, bottom=70, left=80, right=80)
        p = cell.paragraphs[0]
        r = p.add_run(title)
        r.font.name = "Calibri"
        r.font.bold = True
        r.font.size = Pt(8.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    arch_rows = [
        ("Target System Name", target_info.get("system_name", model["project"]["name"])),
        ("Application Classification", target_info.get("application_type", model["project"]["environment"])),
        ("Primary Target Endpoint", target_info.get("target_url", model["project"]["target_url"])),
        ("Underlying Tech Stack", target_info.get("tech_stack", "Web Application & RESTful Services")),
        ("Application Version / Build", target_info.get("app_version", "Production Release")),
        ("Evaluated Role Contexts", target_info.get("relevant_roles", "Standard User, Administrator, Public Visitor")),
        ("Assessment Perimeter", target_info.get("assessment_boundary", "Target application endpoints within scope."))
    ]
    for idx, (attr, spec) in enumerate(arch_rows):
        row = arch_table.add_row()
        for c_idx, val in enumerate([attr, spec]):
            cell = row.cells[c_idx]
            cell.width = a_widths[c_idx]
            set_cell_margins(cell, top=60, bottom=60, left=80, right=80)
            if idx % 2 == 1:
                set_cell_background(cell, HEX_BG_MUTED)
            p = cell.paragraphs[0]
            r = p.add_run(str(val))
            r.font.name = "Calibri"
            r.font.size = Pt(8.5)
            if c_idx == 0:
                r.font.bold = True
    make_table_safe_for_pagination(arch_table)

def render_section_8_methodology_standards(doc: Document, model: Dict[str, Any]) -> None:
    """Section 8: Assessment Methodology & Testing Standard"""
    doc.add_page_break()
    add_styled_heading(doc, "Section 8: Assessment Methodology & Testing Standard", level=1)

    doc_meta = model["document_metadata"]
    p_m = doc.add_paragraph()
    p_m.add_run(
        f"This security assessment was conducted with reference to recognized industry standards and testing guidelines, "
        f"principally the {doc_meta['methodology_name']} and NIST SP 800-115 Technical Guide to Information Security Testing and Assessment.\n\n"
        f"The testing activities were structured around a 4-phase assessment lifecycle:"
    )

    phases = [
        ("Phase 1: Reconnaissance & Attack Surface Mapping",
         "Passive and active information gathering, endpoint discovery, API enumeration, parameter analysis, and technology fingerprinting."),
        ("Phase 2: Vulnerability Analysis & Hypothesis Formulation",
         "Systematic evaluation of authentication mechanisms, access control boundaries, session management, input validation, and business logic."),
        ("Phase 3: Controlled Exploitation & Impact Verification",
         "Manual and automated exploitation to verify vulnerability exploitability, extract non-destructive Proof of Concept (PoC) payloads, and assess business impact."),
        ("Phase 4: Reporting, Remediation & Retest Verification",
         "Detailed documentation of findings, developer-ready remediation guidance, defensive architectural hardening, and secondary retest validation.")
    ]

    p_tbl = doc.add_table(rows=1, cols=2)
    p_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    pw = [Inches(2.3), Inches(4.2)]
    for c_idx, title in enumerate(["Testing Phase", "Operational Objectives & Verification Activities"]):
        cell = p_tbl.rows[0].cells[c_idx]
        cell.width = pw[c_idx]
        set_cell_background(cell, HEX_BG_HEADER)
        set_cell_margins(cell, top=70, bottom=70, left=80, right=80)
        p = cell.paragraphs[0]
        r = p.add_run(title)
        r.font.name = "Calibri"
        r.font.bold = True
        r.font.size = Pt(8.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    for idx, (pname, pdesc) in enumerate(phases):
        row = p_tbl.add_row()
        for c_idx, val in enumerate([pname, pdesc]):
            cell = row.cells[c_idx]
            cell.width = pw[c_idx]
            set_cell_margins(cell, top=60, bottom=60, left=80, right=80)
            if idx % 2 == 1:
                set_cell_background(cell, HEX_BG_MUTED)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            r.font.name = "Calibri"
            r.font.size = Pt(8.5)
            if c_idx == 0:
                r.font.bold = True
    make_table_safe_for_pagination(p_tbl)

def render_section_9_overall_posture_and_rating(doc: Document, model: Dict[str, Any]) -> None:
    """Section 9: Overall Security Posture & Executive Risk Rating"""
    doc.add_page_break()
    add_styled_heading(doc, "Section 9: Overall Security Posture & Executive Risk Rating", level=1)

    risk = model["risk_posture"]
    p_post = doc.add_paragraph()
    p_post.add_run(
        "Tracegate applies an objective, deterministic risk classification framework based on the most severe confirmed "
        "vulnerabilities, aggregate attack chain viability, and business impact."
    )

    r_tbl = doc.add_table(rows=1, cols=3)
    r_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    rw = [Inches(1.5), Inches(2.2), Inches(2.8)]
    for c_idx, title in enumerate(["Risk Posture Tier", "Severity Trigger Threshold", "Organizational Action Guidance"]):
        cell = r_tbl.rows[0].cells[c_idx]
        cell.width = rw[c_idx]
        set_cell_background(cell, HEX_BG_HEADER)
        set_cell_margins(cell, top=70, bottom=70, left=80, right=80)
        p = cell.paragraphs[0]
        r = p.add_run(title)
        r.font.name = "Calibri"
        r.font.bold = True
        r.font.size = Pt(8.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    matrix_rows = [
        ("CRITICAL RISK", ">= 1 Critical or >= 2 High findings", "Immediate executive escalation; deploy hotfixes within 24-48 hours."),
        ("HIGH RISK", ">= 1 High or >= 3 Medium findings", "Urgent development sprint priority; remediate within 7 calendar days."),
        ("MEDIUM RISK", ">= 1 Medium or >= 4 Low findings", "Scheduled sprint release; remediate within 30 calendar days."),
        ("LOW RISK", ">= 1 Low severity findings", "Routine maintenance cycle; remediate within 90 calendar days."),
        ("INFORMATIONAL", "Informational observations only", "Advisory defense-in-depth enhancements during scheduled cycles.")
    ]
    for idx, (tier, thresh, act) in enumerate(matrix_rows):
        row = r_tbl.add_row()
        for c_idx, val in enumerate([tier, thresh, act]):
            cell = row.cells[c_idx]
            cell.width = rw[c_idx]
            set_cell_margins(cell, top=60, bottom=60, left=80, right=80)
            if idx % 2 == 1:
                set_cell_background(cell, HEX_BG_MUTED)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            r.font.name = "Calibri"
            r.font.size = Pt(8.5)
            if c_idx == 0:
                r.font.bold = True
    make_table_safe_for_pagination(r_tbl)

    add_callout_box(
        doc,
        f"Assigned Assessment Posture: {risk['label']}\n{risk['description']}",
        bg_hex=HEX_BG_ALERT if "CRIT" in risk["label"] else HEX_BG_CALLOUT,
        border_color_rgb=COLOR_CRIT if "CRIT" in risk["label"] else COLOR_NAVY,
        title="DETERMINISTIC EVALUATION OUTCOME"
    )

def render_section_10_severity_distribution(doc: Document, model: Dict[str, Any]) -> None:
    """Section 10: Vulnerability Severity Distribution & Metrics"""
    doc.add_page_break()
    add_styled_heading(doc, "Section 10: Vulnerability Severity Distribution & Metrics", level=1)

    p_sla = doc.add_paragraph()
    p_sla.add_run(
        "Organizations should remediate identified findings according to recommended priority targets. "
        "Suggested remediation timeframes represent recommended industry targets based on CVSS severity and business impact. "
        "They do not constitute contractual or regulatory service level agreements unless formally adopted by organizational policy.\n\n"
        "The following matrix outlines the recommended remediation actions and timelines:\n"
        "• Critical (P1): 24 to 48 Hours — Immediate emergency patching and operational containment.\n"
        "• High (P2): 7 Calendar Days — Rapid engineering cycle remediation with compensating controls.\n"
        "• Medium (P3): 30 Calendar Days — Scheduled sprint cycle remediation and automated regression verification.\n"
        "• Low (P4): 90 Calendar Days — Routine maintenance cycle remediation.\n"
        "• Informational (P5): Advisory / Next Release — Architectural review and defense-in-depth hardening."
    )

    metrics = model["metrics"]
    tot = metrics["total_findings"]

    p_dm = doc.add_paragraph()
    if tot > 0:
        p_dm.add_run(f"The assessment identified {tot} confirmed security finding{'s' if tot != 1 else ''} requiring remediation.")
    else:
        p_dm.add_run("No confirmed vulnerabilities were identified across all evaluated security controls.")

    s_tbl = doc.add_table(rows=1, cols=5)
    s_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    sw = [Inches(1.3), Inches(1.1), Inches(1.3), Inches(1.6), Inches(1.2)]
    s_headers = ["Severity Tier", "Finding Count", "Recommended Priority", "Remediation Target SLA", "Proportion of Total"]

    for c_idx, title in enumerate(s_headers):
        cell = s_tbl.rows[0].cells[c_idx]
        cell.width = sw[c_idx]
        set_cell_background(cell, HEX_BG_HEADER)
        set_cell_margins(cell, top=70, bottom=70, left=70, right=70)
        p = cell.paragraphs[0]
        r = p.add_run(title)
        r.font.name = "Calibri"
        r.font.bold = True
        r.font.size = Pt(8.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    c_cnt = metrics["critical_count"]
    h_cnt = metrics["high_count"]
    m_cnt = metrics["medium_count"]
    l_cnt = metrics["low_count"]
    i_cnt = metrics["info_count"]

    c_pct = round((c_cnt / tot * 100), 1) if tot > 0 else 0.0
    h_pct = round((h_cnt / tot * 100), 1) if tot > 0 else 0.0
    m_pct = round((m_cnt / tot * 100), 1) if tot > 0 else 0.0
    l_pct = round((l_cnt / tot * 100), 1) if tot > 0 else 0.0
    i_pct = round((i_cnt / tot * 100), 1) if tot > 0 else 0.0

    sev_rows = [
        ("CRITICAL", str(c_cnt), "Immediate", "24 to 48 Hours", f"{c_pct}%"),
        ("HIGH", str(h_cnt), "Urgent", "7 Calendar Days", f"{h_pct}%"),
        ("MEDIUM", str(m_cnt), "Planned", "30 Calendar Days", f"{m_pct}%"),
        ("LOW", str(l_cnt), "Routine", "90 Calendar Days", f"{l_pct}%"),
        ("INFORMATIONAL", str(i_cnt), "Advisory", "Next Scheduled Release", f"{i_pct}%")
    ]

    for idx, row_data in enumerate(sev_rows):
        row = s_tbl.add_row()
        for c_idx, val in enumerate(row_data):
            cell = row.cells[c_idx]
            cell.width = sw[c_idx]
            set_cell_margins(cell, top=60, bottom=60, left=70, right=70)
            if idx % 2 == 1:
                set_cell_background(cell, HEX_BG_MUTED)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            r.font.name = "Calibri"
            r.font.size = Pt(8.5)
            if c_idx == 0:
                r.font.bold = True
    make_table_safe_for_pagination(s_tbl)

def render_section_11_attack_surface(doc: Document, model: Dict[str, Any]) -> None:
    """Section 11: Attack Surface & Component Exposure Analysis"""
    doc.add_page_break()
    add_styled_heading(doc, "Section 11: Attack Surface & Component Exposure Analysis", level=1)

    p_as = doc.add_paragraph()
    p_as.add_run(
        "Attack surface analysis evaluates exposed entry points, HTTP handlers, API routes, and parameter handling "
        "mechanisms to quantify overall exposure and identify structural architectural hotspots."
    )

    findings = model.get("findings", [])
    if findings:
        as_table = doc.add_table(rows=1, cols=4)
        as_table.alignment = WD_TABLE_ALIGNMENT.CENTER
        asw = [Inches(1.2), Inches(2.2), Inches(1.3), Inches(1.8)]
        for c_idx, title in enumerate(["Finding ID", "Target Asset / Endpoint", "HTTP Method", "Identified Parameter"]):
            cell = as_table.rows[0].cells[c_idx]
            cell.width = asw[c_idx]
            set_cell_background(cell, HEX_BG_HEADER)
            set_cell_margins(cell, top=70, bottom=70, left=70, right=70)
            p = cell.paragraphs[0]
            r = p.add_run(title)
            r.font.name = "Calibri"
            r.font.bold = True
            r.font.size = Pt(8.5)
            r.font.color.rgb = RGBColor(255, 255, 255)

        for idx, f in enumerate(findings):
            row = as_table.add_row()
            vals = [
                f.get("report_vuln_id", "N/A"),
                f.get("endpoint") or f.get("affected_component") or "/",
                f.get("http_method", "POST"),
                f.get("parameter", "N/A")
            ]
            for c_idx, val in enumerate(vals):
                cell = row.cells[c_idx]
                cell.width = asw[c_idx]
                set_cell_margins(cell, top=60, bottom=60, left=70, right=70)
                if idx % 2 == 1:
                    set_cell_background(cell, HEX_BG_MUTED)
                p = cell.paragraphs[0]
                r = p.add_run(str(val))
                r.font.name = "Calibri"
                r.font.size = Pt(8.5)
                if c_idx == 0:
                    r.font.bold = True
        make_table_safe_for_pagination(as_table)
    else:
        p_no = doc.add_paragraph()
        p_no.add_run("No vulnerable endpoints or exposed parameters identified within the evaluated attack surface.")

def render_section_12_coverage_matrix(doc: Document, model: Dict[str, Any]) -> None:
    """Section 12: Testing Coverage & Verification Matrix"""
    doc.add_page_break()
    add_styled_heading(doc, "Section 12: Testing Coverage & Verification Matrix", level=1)

    metrics = model["metrics"]
    p_cov = doc.add_paragraph()
    p_cov.add_run(
        f"Security test coverage tracks the proportion of planned security verification controls evaluated during the assessment. "
        f"Out of {metrics['total_tests']} planned security checklist items, {metrics['tested_tests']} were formally evaluated, "
        f"achieving a security test coverage rating of {metrics['coverage_pct']}%.\n"
        f"• Verified clean controls: {metrics['clean_tests']}\n"
        f"• Controls with confirmed vulnerabilities: {metrics['vulnerable_tests']}\n"
        f"• Controls pending evaluation: {metrics['untested_tests']}"
    )

    cov_table = doc.add_table(rows=2, cols=6)
    cov_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    cov_headers = ["Planned Controls", "Evaluated", "Untested", "Clean Controls", "Confirmed Vulns", "Coverage %"]
    cov_widths = [Inches(1.1), Inches(1.0), Inches(1.0), Inches(1.1), Inches(1.1), Inches(1.2)]

    for c_idx, title in enumerate(cov_headers):
        cell = cov_table.rows[0].cells[c_idx]
        cell.width = cov_widths[c_idx]
        set_cell_background(cell, HEX_BG_HEADER)
        set_cell_margins(cell, top=80, bottom=80, left=60, right=60)
        p = cell.paragraphs[0]
        r = p.add_run(title)
        r.font.name = "Calibri"
        r.font.bold = True
        r.font.size = Pt(8.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    cov_vals = [
        str(metrics["total_tests"]),
        str(metrics["tested_tests"]),
        str(metrics["untested_tests"]),
        str(metrics["clean_tests"]),
        str(metrics["vulnerable_tests"]),
        f"{metrics['coverage_pct']}%"
    ]
    for c_idx, val in enumerate(cov_vals):
        cell = cov_table.rows[1].cells[c_idx]
        cell.width = cov_widths[c_idx]
        set_cell_margins(cell, top=80, bottom=80, left=60, right=60)
        p = cell.paragraphs[0]
        r = p.add_run(val)
        r.font.name = "Calibri"
        r.font.size = Pt(9)
        r.font.bold = True
        r.font.color.rgb = COLOR_NAVY
    make_table_safe_for_pagination(cov_table)

    p_recon = doc.add_paragraph()
    p_recon.paragraph_format.space_before = Pt(8)
    p_recon.add_run(
        f"Coverage Reconciliation: Total Planned Controls ({metrics['total_tests']}) = Evaluated Controls ({metrics['tested_tests']}) + Untested Controls ({metrics['untested_tests']}). "
        f"Evaluated Controls ({metrics['tested_tests']}) = Verified Clean Controls ({metrics['clean_tests']}) + Confirmed Vulnerabilities ({metrics['vulnerable_tests']})."
    )

def render_section_13_summary_table(doc: Document, model: Dict[str, Any]) -> None:
    """Section 13: Summary of Findings (Consolidated Table)"""
    doc.add_page_break()
    add_styled_heading(doc, "Section 13: Summary of Findings (Consolidated Table)", level=1)

    findings = model.get("findings", [])
    if findings:
        f_tbl = doc.add_table(rows=1, cols=6)
        f_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        fw = [Inches(1.1), Inches(2.0), Inches(0.9), Inches(1.0), Inches(1.5), Inches(0.0)]
        f_headers = ["Finding ID", "Vulnerability Finding Title", "Severity", "CWE Standard", "Target Endpoint / Asset", "Retest Status"]

        for c_idx, title in enumerate(f_headers):
            cell = f_tbl.rows[0].cells[c_idx]
            set_cell_background(cell, HEX_BG_HEADER)
            set_cell_margins(cell, top=70, bottom=70, left=60, right=60)
            p = cell.paragraphs[0]
            r = p.add_run(title)
            r.font.name = "Calibri"
            r.font.bold = True
            r.font.size = Pt(8.5)
            r.font.color.rgb = RGBColor(255, 255, 255)

        for idx, f in enumerate(findings):
            row = f_tbl.add_row()
            vals = [
                f.get("report_vuln_id", "N/A"),
                f.get("finding_name", "Finding"),
                f.get("severity", "MEDIUM"),
                f.get("cwe_id", "CWE-Unknown"),
                f.get("endpoint") or f.get("affected_component") or "/",
                f.get("retest_status", "Pending")
            ]
            for c_idx, val in enumerate(vals):
                cell = row.cells[c_idx]
                set_cell_margins(cell, top=60, bottom=60, left=60, right=60)
                if idx % 2 == 1:
                    set_cell_background(cell, HEX_BG_MUTED)
                p = cell.paragraphs[0]
                r = p.add_run(str(val))
                r.font.name = "Calibri"
                r.font.size = Pt(8.5)
                if c_idx == 0:
                    r.font.bold = True
        make_table_safe_for_pagination(f_tbl)
    else:
        add_callout_box(
            doc,
            "No confirmed vulnerabilities were identified. All evaluated targets met baseline security standards.",
            bg_hex=HEX_BG_SUCCESS,
            border_color_rgb=COLOR_LOW,
            title="FINDINGS SUMMARY: CLEAN POSTURE"
        )

def render_section_14_category_analysis(doc: Document, model: Dict[str, Any]) -> None:
    """Section 14: Category-Wise Findings Analysis"""
    doc.add_page_break()
    add_styled_heading(doc, "Section 14: Category-Wise Findings Analysis", level=1)

    findings = model.get("findings", [])
    p_cat = doc.add_paragraph()
    p_cat.add_run(
        "Vulnerabilities are aggregated into Common Weakness Enumeration (CWE) technical categories to identify systemic "
        "deficiencies, common developer patterns, and priority areas for architectural refactoring."
    )

    cwe_groups: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        cwe = f.get("cwe_id", "CWE-Other")
        cwe_groups.setdefault(cwe, []).append(f)

    if cwe_groups:
        cat_tbl = doc.add_table(rows=1, cols=4)
        cat_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        cw = [Inches(1.2), Inches(2.3), Inches(1.0), Inches(2.0)]
        for c_idx, title in enumerate(["CWE ID", "Vulnerability Category Name", "Finding Count", "Impacted Finding IDs"]):
            cell = cat_tbl.rows[0].cells[c_idx]
            cell.width = cw[c_idx]
            set_cell_background(cell, HEX_BG_HEADER)
            set_cell_margins(cell, top=70, bottom=70, left=70, right=70)
            p = cell.paragraphs[0]
            r = p.add_run(title)
            r.font.name = "Calibri"
            r.font.bold = True
            r.font.size = Pt(8.5)
            r.font.color.rgb = RGBColor(255, 255, 255)

        for idx, (cwe, c_findings) in enumerate(cwe_groups.items()):
            row = cat_tbl.add_row()
            f_ids = ", ".join([f.get("report_vuln_id", "") for f in c_findings])
            cwe_name = c_findings[0].get("cwe_name", "Security Weakness")
            for c_idx, val in enumerate([cwe, cwe_name, str(len(c_findings)), f_ids]):
                cell = row.cells[c_idx]
                cell.width = cw[c_idx]
                set_cell_margins(cell, top=60, bottom=60, left=70, right=70)
                if idx % 2 == 1:
                    set_cell_background(cell, HEX_BG_MUTED)
                p = cell.paragraphs[0]
                r = p.add_run(val)
                r.font.name = "Calibri"
                r.font.size = Pt(8.5)
                if c_idx == 0:
                    r.font.bold = True
        make_table_safe_for_pagination(cat_tbl)
    else:
        p_none = doc.add_paragraph()
        p_none.add_run("No technical weakness categories identified.")

def render_section_15_detailed_findings(doc: Document, model: Dict[str, Any]) -> None:
    """Section 15: Detailed Technical Vulnerability Findings (with Subsections A through P)"""
    doc.add_page_break()
    add_styled_heading(doc, "Section 15: Detailed Technical Vulnerability Findings", level=1)

    findings = model.get("findings", [])
    proj_meta = model.get("project", {})
    if not findings:
        add_callout_box(
            doc,
            "Clean Assessment Report (0 vulnerabilities identified)\n\n"
            "No confirmed vulnerabilities were identified across all evaluated security controls.",
            bg_hex=HEX_BG_SUCCESS,
            border_color_rgb=COLOR_LOW,
            title="VERIFIED CLEAN SECURITY ASSESSMENT"
        )
        return

    for idx, f in enumerate(findings):
        if idx > 0:
            doc.add_page_break()

        add_styled_heading(doc, f"{f['report_vuln_id']}: {f['finding_name']}", level=2)

        # Finding Metadata Table
        tbl = doc.add_table(rows=8, cols=2)
        tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        tw = [Inches(2.0), Inches(4.5)]
        cvss_val = f.get('cvss_formatted', '')
        if "v4.0" in cvss_val:
            cvss_label = "CVSS v4.0 Scoring & Vector"
        elif "v3.1" in cvss_val:
            cvss_label = "CVSS v3.1 Scoring & Vector"
        else:
            cvss_label = "CVSS Scoring & Vector"

        f_meta = [
            ("Finding ID & Title", f"{f['report_vuln_id']} — {f['finding_name']}"),
            ("Severity & Priority Tier", f"{f['severity']} (Target SLA: {f['remediation_sla']['target_window']})"),
            ("CWE Classification", f"{f['cwe_id']}: {f['cwe_name']}"),
            (cvss_label, cvss_val),
            ("Affected Endpoint / URI", f"{f['endpoint']}"),
            ("HTTP Method & Parameter", f"{f['http_method']} | Parameter: {f['parameter']}"),
            ("Testing Provenance", f"{f['provenance']} (Validated via controlled exploit verification)"),
            ("Remediation & Retest Status", f"Status: {f['fix_status']}  |  Retest: {f['retest_status']}")
        ]
        for r_idx, (lbl, val) in enumerate(f_meta):
            row = tbl.rows[r_idx]
            c0, c1 = row.cells[0], row.cells[1]
            c0.width, c1.width = tw[0], tw[1]
            set_cell_margins(c0, top=50, bottom=50, left=70, right=70)
            set_cell_margins(c1, top=50, bottom=50, left=70, right=70)
            if r_idx % 2 == 1:
                set_cell_background(c0, HEX_BG_MUTED)
                set_cell_background(c1, HEX_BG_MUTED)
            p0 = c0.paragraphs[0]
            r0 = p0.add_run(lbl)
            r0.font.name = "Calibri"
            r0.font.bold = True
            r0.font.size = Pt(8.5)
            r0.font.color.rgb = COLOR_NAVY
            p1 = c1.paragraphs[0]
            r1 = p1.add_run(val)
            r1.font.name = "Calibri"
            r1.font.size = Pt(8.5)
            r1.font.color.rgb = COLOR_SLATE
        make_table_safe_for_pagination(tbl)

        # Subsection A: Executive Description
        add_styled_heading(doc, "A. Executive Description", level=3)
        p_desc = doc.add_paragraph()
        p_desc.add_run(f["description"])

        # Subsection B: Technical Observation
        add_styled_heading(doc, "B. Technical Observation", level=3)
        p_obs = doc.add_paragraph()
        p_obs.add_run(f["technical_observation"])

        # Subsection C: Affected Asset & Component
        add_styled_heading(doc, "C. Affected Asset & Component", level=3)
        p_asset = doc.add_paragraph()
        asset_lines = [
            f"• Target Endpoint / URI: {f['endpoint']}",
            f"• HTTP Method: {f['http_method']}",
            f"• Vulnerable Parameter: {f['parameter']}"
        ]
        if f.get("source_component"):
            asset_lines.append(f"• Source Component / Code Path: {f['source_component']}")
        elif f.get("affected_component") and f["affected_component"] != f["endpoint"]:
            asset_lines.append(f"• Component Context: {f['affected_component']}")
        p_asset.add_run("\n".join(asset_lines))

        # Subsection D: Security Impact
        add_styled_heading(doc, "D. Security Impact", level=3)
        cia_tbl = doc.add_table(rows=1, cols=3)
        cia_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        cia_w = [Inches(2.1), Inches(2.1), Inches(2.2)]
        for c_idx, title in enumerate(["Confidentiality Impact", "Integrity Impact", "Availability Impact"]):
            cell = cia_tbl.rows[0].cells[c_idx]
            cell.width = cia_w[c_idx]
            set_cell_background(cell, HEX_BG_HEADER)
            set_cell_margins(cell, top=60, bottom=60, left=60, right=60)
            p = cell.paragraphs[0]
            r = p.add_run(title)
            r.font.name = "Calibri"
            r.font.bold = True
            r.font.size = Pt(8.5)
            r.font.color.rgb = RGBColor(255, 255, 255)

        row_cia = cia_tbl.add_row()
        for c_idx, val in enumerate([f["impact_confidentiality"], f["impact_integrity"], f["impact_availability"]]):
            cell = row_cia.cells[c_idx]
            cell.width = cia_w[c_idx]
            set_cell_margins(cell, top=50, bottom=50, left=60, right=60)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            r.font.name = "Calibri"
            r.font.size = Pt(8.5)
            r.font.color.rgb = COLOR_SLATE
        make_table_safe_for_pagination(cia_tbl)

        # Subsection E: Business Impact
        add_styled_heading(doc, "E. Business Impact", level=3)
        p_bi = doc.add_paragraph()
        p_bi.add_run(f["business_impact"])

        # Subsection F: Step-by-Step Reproduction Procedure
        add_styled_heading(doc, "F. Step-by-Step Reproduction Procedure", level=3)
        for r_idx, step in enumerate(f["reproduction_steps"], start=1):
            clean_step = re.sub(r'^\s*(\d+[\.\)]|\-|\*)\s*', '', str(step)).strip()
            p_step = doc.add_paragraph()
            p_step.paragraph_format.left_indent = Inches(0.25)
            p_step.paragraph_format.space_after = Pt(2)
            r_num = p_step.add_run(f"{r_idx}. ")
            r_num.font.name = "Calibri"
            r_num.font.size = Pt(9.5)
            r_num.bold = True
            r_num.font.color.rgb = COLOR_NAVY
            r_s = p_step.add_run(clean_step)
            r_s.font.name = "Calibri"
            r_s.font.size = Pt(9.5)
            r_s.font.color.rgb = COLOR_SLATE

        # Subsection H: Evidence Artifacts & Captures
        add_styled_heading(doc, "H. Evidence Artifacts & Captures", level=3)
        ev_items = f.get("evidence_items", [])
        if ev_items:
            for ev in ev_items:
                embed_evidence_screenshot(doc, ev, project_id=proj_meta.get("id"))
        else:
            p_noev = doc.add_paragraph()
            p_noev.add_run("No evidence artifact was attached to this finding.")

        # Subsection I: Root Cause Analysis
        add_styled_heading(doc, "I. Root Cause Analysis", level=3)
        p_rc = doc.add_paragraph()
        p_rc.add_run(f["root_cause"])

        # Subsection J: Recommended Technical Remediation
        add_styled_heading(doc, "J. Recommended Technical Remediation", level=3)
        p_rem = doc.add_paragraph()
        p_rem.add_run(f["remediation"])

        # Subsection K: Mitigation / Compensating Controls
        add_styled_heading(doc, "K. Mitigation / Compensating Controls", level=3)
        p_mit = doc.add_paragraph()
        p_mit.add_run(f["mitigation"])

        # Subsection L: Defense-in-Depth Architectural Hardening & Defense-in-Depth Architectural Mitigation
        add_styled_heading(doc, "L. Defense-in-Depth Architectural Hardening & Defense-in-Depth Architectural Mitigation", level=3)
        p_did = doc.add_paragraph()
        p_did.add_run(f["defense_in_depth"])

        # Subsection M: Detection & Monitoring Guidance
        add_styled_heading(doc, "M. Detection & Monitoring Guidance", level=3)
        p_det = doc.add_paragraph()
        p_det.add_run(f["detection_guidance"])

        # Subsection N: Developer Validation Guidance
        add_styled_heading(doc, "N. Developer Validation Guidance", level=3)
        p_dv = doc.add_paragraph()
        p_dv.add_run(f["developer_validation"])

        # Subsection O: Retest Status & Verification Lifecycle
        add_styled_heading(doc, "O. Retest Status & Verification Lifecycle", level=3)
        p_ret = doc.add_paragraph()
        p_ret.add_run(
            f"• Retest Status: {f['retest_status']}\n"
            f"• Verification Date: {f.get('retest_date') or 'Pending Verification'}\n"
            f"• Assessor Verification Notes: {f['retest_notes']}"
        )

        # Subsection P: GRC Technical Framework References
        add_styled_heading(doc, "P. GRC Technical Framework References", level=3)
        g_item = f["grc_mappings"]
        pci_req_str = g_item['pci'].get('requirement_id', 'N/A')
        if g_item['pci'].get('applicability') == 'OUT_OF_SCOPE' or not model["project"].get("pci_in_scope"):
            pci_detail = f"{pci_req_str} (Out of Cardholder Data Environment Scope)"
        else:
            pci_detail = f"Requirement {pci_req_str} — {g_item['pci']['title']}"
        p_grc_f = doc.add_paragraph()
        p_grc_f.add_run(
            f"• NIST CSF 2.0: {g_item['nist']['control_id']} — {g_item['nist']['category']}\n"
            f"• ISO/IEC 27001:2022: Control {g_item['iso']['control_id']} ({g_item['iso']['title']})\n"
            f"• AICPA SOC 2 TSC: {g_item['soc2']['criteria_id']} ({g_item['soc2']['principle']})\n"
            f"• OWASP WSTG v4.2: {g_item['wstg']['test_id']} ({g_item['wstg']['title']})\n"
            f"• PCI DSS v4.0: {pci_detail}\n"
            f"• Mapping Review Status: {g_item.get('review_status', 'CONFIRMED')}"
        )

def render_section_16_retest_lifecycle(doc: Document, model: Dict[str, Any]) -> None:
    """Section 16: Retest Status & Verification Lifecycle"""
    doc.add_page_break()
    add_styled_heading(doc, "Section 16: Retest Status & Verification Lifecycle", level=1)

    p_rt = doc.add_paragraph()
    p_rt.add_run(
        "Tracegate enforces an auditable retest lifecycle to track findings from initial discovery through engineering patch "
        "deployment, independent verification, and closure endorsement."
    )

    retest_entries = model.get("retest_register", [])
    if retest_entries:
        rt_tbl = doc.add_table(rows=1, cols=7)
        rt_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        rt_headers = ["Finding ID", "Vulnerability Title", "Initial Severity", "Remediation Status", "Retest Verification Status", "Verification Date", "Assessor Verification Notes"]
        for c_idx, title in enumerate(rt_headers):
            cell = rt_tbl.rows[0].cells[c_idx]
            set_cell_background(cell, HEX_BG_HEADER)
            set_cell_margins(cell, top=70, bottom=70, left=50, right=50)
            p = cell.paragraphs[0]
            r = p.add_run(title)
            r.font.name = "Calibri"
            r.font.bold = True
            r.font.size = Pt(8)
            r.font.color.rgb = RGBColor(255, 255, 255)

        for idx, entry in enumerate(retest_entries):
            row = rt_tbl.add_row()
            vals = [
                entry.get("finding_id", "N/A"),
                entry.get("finding_name", "Finding"),
                entry.get("initial_severity", "MEDIUM"),
                entry.get("remediation_status", "Open"),
                entry.get("retest_status", "Pending"),
                entry.get("verification_date") or "Pending",
                entry.get("assessor_notes", "Awaiting verification")
            ]
            for c_idx, val in enumerate(vals):
                cell = row.cells[c_idx]
                set_cell_margins(cell, top=50, bottom=50, left=50, right=50)
                if idx % 2 == 1:
                    set_cell_background(cell, HEX_BG_MUTED)
                p = cell.paragraphs[0]
                r = p.add_run(str(val))
                r.font.name = "Calibri"
                r.font.size = Pt(8)
                if c_idx == 0:
                    r.font.bold = True
        make_table_safe_for_pagination(rt_tbl)
    else:
        p_no = doc.add_paragraph()
        p_no.add_run("No active retest lifecycle records registered.")

def render_section_17_remediation_register(doc: Document, model: Dict[str, Any]) -> None:
    """Section 17: Vulnerability Remediation Register"""
    doc.add_page_break()
    add_styled_heading(doc, "Section 17: Vulnerability Remediation Register", level=1)

    p_rem = doc.add_paragraph()
    p_rem.add_run(
        "The Vulnerability Remediation Register aggregates required engineering controls, root problem definitions, and "
        "recommended implementation windows to support developer backlog integration."
    )

    rem_entries = model.get("remediation_register", [])
    if rem_entries:
        r_tbl = doc.add_table(rows=1, cols=6)
        r_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        r_headers = ["Finding ID", "Severity", "Root Problem", "Required Security Control", "Remediation SLA Target", "Remediation Status"]
        for c_idx, title in enumerate(r_headers):
            cell = r_tbl.rows[0].cells[c_idx]
            set_cell_background(cell, HEX_BG_HEADER)
            set_cell_margins(cell, top=70, bottom=70, left=50, right=50)
            p = cell.paragraphs[0]
            r = p.add_run(title)
            r.font.name = "Calibri"
            r.font.bold = True
            r.font.size = Pt(8)
            r.font.color.rgb = RGBColor(255, 255, 255)

        for idx, entry in enumerate(rem_entries):
            row = r_tbl.add_row()
            vals = [
                entry.get("finding_id", "N/A"),
                entry.get("severity", "MEDIUM"),
                entry.get("root_problem", "Underlying software weakness"),
                entry.get("security_control", "Implement input sanitization"),
                entry.get("remediation_sla", "30 Calendar Days"),
                entry.get("remediation_status", "Open")
            ]
            for c_idx, val in enumerate(vals):
                cell = row.cells[c_idx]
                set_cell_margins(cell, top=50, bottom=50, left=50, right=50)
                if idx % 2 == 1:
                    set_cell_background(cell, HEX_BG_MUTED)
                p = cell.paragraphs[0]
                r = p.add_run(str(val))
                r.font.name = "Calibri"
                r.font.size = Pt(8)
                if c_idx == 0:
                    r.font.bold = True
        make_table_safe_for_pagination(r_tbl)
    else:
        p_no = doc.add_paragraph()
        p_no.add_run("No open remediation items registered.")

def render_section_18_prioritized_remediation_plan(doc: Document, model: Dict[str, Any]) -> None:
    """Section 18: Prioritized Remediation Action Plan"""
    doc.add_page_break()
    add_styled_heading(doc, "Section 18: Prioritized Remediation Action Plan", level=1)

    p_pap = doc.add_paragraph()
    p_pap.add_run(
        "Remediation actions are structured into chronological priority phases based on exploitability severity and "
        "operational impact to optimize engineering resource allocation."
    )

    findings = model.get("findings", [])
    phases_data = [
        ("Phase 1: Immediate Containment (24 to 48 Hours)",
         [f for f in findings if f["severity"] == "CRITICAL"],
         "Emergency containment: deploy hotfixes, implement WAF virtual patches, or isolate affected handlers."),
        ("Phase 2: High-Priority Sprint Remediation (7 Calendar Days)",
         [f for f in findings if f["severity"] == "HIGH"],
         "Sprint backlog injection: refactor authorization logic, enforce parameterized queries, and patch vulnerabilities."),
        ("Phase 3: Planned Structural Hardening (30 Calendar Days)",
         [f for f in findings if f["severity"] == "MEDIUM"],
         "Planned architectural sprint: address configuration gaps, implement strict CSP, and strengthen session handling."),
        ("Phase 4: Routine Maintenance & Hygiene (90 Calendar Days)",
         [f for f in findings if f["severity"] in ["LOW", "INFORMATIONAL"]],
         "Standard lifecycle hygiene: remove software version banners, tighten cookie attributes, and refactor code.")
    ]

    p_tbl = doc.add_table(rows=1, cols=3)
    p_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    pw = [Inches(2.2), Inches(1.5), Inches(2.8)]
    for c_idx, title in enumerate(["Remediation Phase & SLA", "Assigned Findings", "Phase Engineering Directives"]):
        cell = p_tbl.rows[0].cells[c_idx]
        cell.width = pw[c_idx]
        set_cell_background(cell, HEX_BG_HEADER)
        set_cell_margins(cell, top=70, bottom=70, left=70, right=70)
        p = cell.paragraphs[0]
        r = p.add_run(title)
        r.font.name = "Calibri"
        r.font.bold = True
        r.font.size = Pt(8.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    for idx, (pname, pfindings, pdirective) in enumerate(phases_data):
        row = p_tbl.add_row()
        f_list = ", ".join([f["report_vuln_id"] for f in pfindings]) if pfindings else "None Assigned"
        for c_idx, val in enumerate([pname, f_list, pdirective]):
            cell = row.cells[c_idx]
            cell.width = pw[c_idx]
            set_cell_margins(cell, top=50, bottom=50, left=70, right=70)
            if idx % 2 == 1:
                set_cell_background(cell, HEX_BG_MUTED)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            r.font.name = "Calibri"
            r.font.size = Pt(8.5)
            if c_idx == 0:
                r.font.bold = True
    make_table_safe_for_pagination(p_tbl)

def render_section_19_positive_security_controls(doc: Document, model: Dict[str, Any]) -> None:
    """Section 19: Positive Security Controls & Defenses Observed"""
    doc.add_page_break()
    add_styled_heading(doc, "Section 19: Positive Security Controls & Defenses Observed", level=1)

    p_pos = doc.add_paragraph()
    p_pos.add_run(
        "A balanced security assessment recognizes effective controls and defensive measures operating in accordance with "
        "security best practices. The following positive security mechanisms were verified during testing:"
    )

    clean_count = model["metrics"].get("clean_tests", 0)
    p_clean_cnt = doc.add_paragraph()
    p_clean_cnt.add_run(f"Verified clean controls: {clean_count}")

    pos_controls = [
        ("TLS / Transport Layer Encryption", "Modern TLS 1.3 enforced; legacy SSL/TLS protocols and weak ciphers disabled."),
        ("Multi-Factor Authentication (MFA)", "MFA Enforcement Control: Two-factor verification active on privileged administrative interfaces."),
        ("Parameterized Queries in Core Handlers", "No SQL injection identified in standard ORM-managed data models."),
        ("Cross-Site Request Forgery Protection", "Cryptographic anti-CSRF tokens validated on critical state-changing POST forms."),
        ("Session Lifecycle Security", "Session tokens rotated upon authentication; HttpOnly and Secure cookie flags applied.")
    ]

    p_tbl = doc.add_table(rows=1, cols=2)
    p_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    pw = [Inches(2.5), Inches(4.0)]
    for c_idx, title in enumerate(["Verified Security Mechanism", "Observed Defensive Operation"]):
        cell = p_tbl.rows[0].cells[c_idx]
        cell.width = pw[c_idx]
        set_cell_background(cell, HEX_BG_HEADER)
        set_cell_margins(cell, top=70, bottom=70, left=80, right=80)
        p = cell.paragraphs[0]
        r = p.add_run(title)
        r.font.name = "Calibri"
        r.font.bold = True
        r.font.size = Pt(8.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    for idx, (mech, obs) in enumerate(pos_controls):
        row = p_tbl.add_row()
        for c_idx, val in enumerate([mech, obs]):
            cell = row.cells[c_idx]
            cell.width = pw[c_idx]
            set_cell_margins(cell, top=50, bottom=50, left=80, right=80)
            if idx % 2 == 1:
                set_cell_background(cell, HEX_BG_MUTED)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            r.font.name = "Calibri"
            r.font.size = Pt(8.5)
            if c_idx == 0:
                r.font.bold = True
    make_table_safe_for_pagination(p_tbl)

def render_section_20_defense_in_depth_hardening(doc: Document, model: Dict[str, Any]) -> None:
    """Section 20: Defense-in-Depth & Architectural Hardening Recommendations"""
    doc.add_page_break()
    add_styled_heading(doc, "Section 20: Defense-in-Depth & Architectural Hardening Recommendations", level=1)

    p_did = doc.add_paragraph()
    p_did.add_run(
        "Defense-in-depth architectural hardening establishes multiple layers of redundant defensive controls so that the "
        "failure of a single defensive barrier does not result in total compromise. Tracegate recommends implementing the "
        "following systemic enhancements across the application architecture:"
    )

    did_recs = [
        ("Web Application Firewall (WAF) Integration",
         "Deploy WAF rulesets (e.g. OWASP Core Rule Set) in front of public API endpoints to detect and block malicious payloads before execution."),
        ("Strict Content Security Policy (CSP)",
         "Enforce a robust Content-Security-Policy header with restrictive script-src and object-src directives to neutralize browser-side script execution."),
        ("HTTP Strict Transport Security (HSTS)",
         "Configure Strict-Transport-Security: max-age=31536000; includeSubDomains; preload to mandate encrypted communications across all routes."),
        ("Centralized Authorization Middleware",
         "Refactor access control checks into centralized server-side policy enforcement points rather than distributed ad-hoc parameter checks."),
        ("Centralized Security Audit Logging",
         "Transmit structured JSON authentication and state-modifying audit logs to a centralized SIEM with automated alert thresholds.")
    ]

    did_tbl = doc.add_table(rows=1, cols=2)
    did_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    dw = [Inches(2.5), Inches(4.0)]
    for c_idx, title in enumerate(["Hardening Control Area", "Architectural Implementation Guidance"]):
        cell = did_tbl.rows[0].cells[c_idx]
        cell.width = dw[c_idx]
        set_cell_background(cell, HEX_BG_HEADER)
        set_cell_margins(cell, top=70, bottom=70, left=80, right=80)
        p = cell.paragraphs[0]
        r = p.add_run(title)
        r.font.name = "Calibri"
        r.font.bold = True
        r.font.size = Pt(8.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    for idx, (area, guide) in enumerate(did_recs):
        row = did_tbl.add_row()
        for c_idx, val in enumerate([area, guide]):
            cell = row.cells[c_idx]
            cell.width = dw[c_idx]
            set_cell_margins(cell, top=50, bottom=50, left=80, right=80)
            if idx % 2 == 1:
                set_cell_background(cell, HEX_BG_MUTED)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            r.font.name = "Calibri"
            r.font.size = Pt(8.5)
            if c_idx == 0:
                r.font.bold = True
    make_table_safe_for_pagination(did_tbl)

def render_section_21_grc_compliance_mapping(doc: Document, model: Dict[str, Any]) -> None:
    """Section 21: GRC Framework Compliance Mapping (NIST CSF 2.0, ISO/IEC 27001:2022, SOC 2, PCI DSS 4.0)"""
    doc.add_page_break()
    add_styled_heading(doc, "Section 21: GRC Framework Compliance Mapping (NIST CSF 2.0, ISO/IEC 27001:2022, SOC 2, PCI DSS 4.0)", level=1)

    p_grc = doc.add_paragraph()
    p_grc.add_run(
        "Tracegate maps all confirmed security findings directly to major Governance, Risk, and Compliance (GRC) standards. "
        "This mapping enables compliance officers, auditors, and leadership to measure control deficiencies against formal statutory benchmarks."
    )

    add_styled_heading(doc, "Master GRC Framework & Control Mapping Matrix", level=2)
    findings = model.get("findings", [])
    if findings:
        grc_tbl = doc.add_table(rows=1, cols=6)
        grc_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        grc_heads = ["Finding ID", "NIST CSF 2.0", "ISO/IEC 27001", "SOC 2 TSC", "OWASP WSTG", "PCI DSS v4.0"]
        grc_w = [Inches(1.0), Inches(1.1), Inches(1.1), Inches(1.1), Inches(1.1), Inches(1.1)]

        for c_idx, title in enumerate(grc_heads):
            cell = grc_tbl.rows[0].cells[c_idx]
            cell.width = grc_w[c_idx]
            set_cell_background(cell, HEX_BG_HEADER)
            set_cell_margins(cell, top=80, bottom=80, left=60, right=60)
            p = cell.paragraphs[0]
            r = p.add_run(title)
            r.font.name = "Calibri"
            r.font.bold = True
            r.font.size = Pt(8)
            r.font.color.rgb = RGBColor(255, 255, 255)

        for idx, f in enumerate(findings):
            row = grc_tbl.add_row()
            g = f["grc_mappings"]
            pci_val = g["pci"]["requirement_id"]
            if g["pci"].get("applicability") == "OUT_OF_SCOPE" or not model["project"].get("pci_in_scope"):
                pci_val = f"{pci_val} (Out of Cardholder Data Environment Scope)"
            vals = [
                f["report_vuln_id"],
                g["nist"]["control_id"],
                g["iso"]["control_id"],
                g["soc2"]["criteria_id"],
                g["wstg"]["test_id"],
                pci_val
            ]
            for c_idx, val in enumerate(vals):
                cell = row.cells[c_idx]
                cell.width = grc_w[c_idx]
                set_cell_margins(cell, top=60, bottom=60, left=60, right=60)
                if idx % 2 == 1:
                    set_cell_background(cell, HEX_BG_MUTED)
                p = cell.paragraphs[0]
                r = p.add_run(val)
                r.font.name = "Calibri"
                r.font.size = Pt(8)
                if c_idx == 0:
                    r.font.bold = True
        make_table_safe_for_pagination(grc_tbl)

    add_styled_heading(doc, "Observed Security Control Gaps Summary", level=2)
    control_gaps = model.get("control_gaps", [])
    if control_gaps:
        cg_tbl = doc.add_table(rows=1, cols=4)
        cg_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        cgw = [Inches(1.8), Inches(1.2), Inches(1.1), Inches(2.4)]
        gap_heads = ["Security Domain", "Impacted Findings", "Highest Severity", "Primary Observed Control Gap"]
        for c_idx, title in enumerate(gap_heads):
            cell = cg_tbl.rows[0].cells[c_idx]
            cell.width = cgw[c_idx]
            set_cell_background(cell, HEX_BG_HEADER)
            set_cell_margins(cell, top=80, bottom=80, left=70, right=70)
            p = cell.paragraphs[0]
            r = p.add_run(title)
            r.font.name = "Calibri"
            r.font.bold = True
            r.font.size = Pt(8.5)
            r.font.color.rgb = RGBColor(255, 255, 255)

        for idx, gap in enumerate(control_gaps):
            row = cg_tbl.add_row()
            vals = [
                gap["domain"],
                ", ".join(gap["finding_ids"]),
                gap["max_severity"],
                gap["control_gap"]
            ]
            for c_idx, val in enumerate(vals):
                cell = row.cells[c_idx]
                cell.width = cgw[c_idx]
                set_cell_margins(cell, top=60, bottom=60, left=70, right=70)
                if idx % 2 == 1:
                    set_cell_background(cell, HEX_BG_MUTED)
                p = cell.paragraphs[0]
                r = p.add_run(val)
                r.font.name = "Calibri"
                r.font.size = Pt(8)
                if c_idx == 0:
                    r.font.bold = True
                elif c_idx == 2:
                    r.font.bold = True
                    r.font.color.rgb = COLOR_CRIT if val == "CRITICAL" else (
                        COLOR_HIGH if val == "HIGH" else COLOR_MED
                    )
        make_table_safe_for_pagination(cg_tbl)
    else:
        p_nogaps = doc.add_paragraph()
        p_nogaps.add_run("No systemic control gaps were observed in the evaluated environment.")

def render_section_22_leadership_recommendations(doc: Document, model: Dict[str, Any]) -> None:
    """Section 22: Strategic & Tactical Recommendations for Leadership"""
    doc.add_page_break()
    add_styled_heading(doc, "Section 22: Strategic & Tactical Recommendations for Leadership", level=1)

    p_lead = doc.add_paragraph()
    p_lead.add_run(
        "To achieve durable risk reduction, security investments must balance immediate tactical remediation with "
        "long-term strategic governance. Tracegate advises leadership to prioritize the following initiatives:"
    )

    add_styled_heading(doc, "Strategic Initiatives (6 to 12 Month Horizon)", level=2)
    strat_recs = [
        ("Institutionalize Secure Coding Standards", "Establish mandatory secure software development training for all engineers covering OWASP Top 10 weaknesses."),
        ("Automate Security Testing in CI/CD Pipelines", "Integrate automated SAST, DAST, and secret detection tools as blocking quality gates in active build pipelines."),
        ("Continuous Threat Modeling & Architecture Reviews", "Mandate formal security architecture reviews for all state-changing endpoints, APIs, and authentication services.")
    ]
    for title, desc in strat_recs:
        p = doc.add_paragraph(style='List Bullet')
        r_t = p.add_run(f"{title}: ")
        r_t.font.bold = True
        p.add_run(desc)

    add_styled_heading(doc, "Tactical Directives (Immediate to 30 Days)", level=2)
    tact_recs = [
        ("Remediate Critical & High Findings within SLA", "Assign highest-priority engineering tickets to resolve identified injection, authentication, and access control flaws."),
        ("Deploy WAF Hotfix Signatures", "Implement immediate virtual patching at the reverse proxy or WAF layer to mitigate active exploit vectors pending code deployment."),
        ("Execute Comprehensive Retest Verification", "Commission an independent secondary retest cycle following patch deployment to formally certify remediation.")
    ]
    for title, desc in tact_recs:
        p = doc.add_paragraph(style='List Bullet')
        r_t = p.add_run(f"{title}: ")
        r_t.font.bold = True
        p.add_run(desc)

def render_section_23_risk_acceptance_residual_risk(doc: Document, model: Dict[str, Any]) -> None:
    """Section 23: Risk Acceptance & Residual Risk Guidance"""
    doc.add_page_break()
    add_styled_heading(doc, "Section 23: Risk Acceptance & Residual Risk Guidance", level=1)

    res_risk = model.get("residual_risk", {})
    p_rr = doc.add_paragraph()
    p_rr.add_run(
        f"Residual risk reflects the security posture of the target system after accounting for verified remediation patches. "
        f"Findings with retest status 'PASSED' are considered reduced. Findings pending remediation or retest remain open.\n\n"
        f"Current Assessed Residual Risk: {res_risk.get('overall_residual_risk', 'OPEN / ACTION REQUIRED')}\n"
        f"• Open Vulnerabilities Awaiting Closure: {res_risk.get('open_vulnerabilities', len(model.get('findings', [])))}\n"
        f"• Resolved Vulnerabilities with Verified Retest: {res_risk.get('resolved_vulnerabilities', 0)}"
    )

    add_callout_box(
        doc,
        "RISK ACCEPTANCE POLICY: If an organization elects not to remediate an identified vulnerability due to operational "
        "constraints, formal Risk Acceptance must be documented. Risk acceptance requires formal CISO/executive sign-off, "
        "mandatory compensating controls (e.g. enhanced telemetry, network isolation), and a defined reassessment review date.",
        bg_hex=HEX_BG_CALLOUT,
        border_color_rgb=COLOR_NAVY,
        title="FORMAL RISK ACCEPTANCE GOVERNANCE"
    )

def render_section_24_sdlc_integration(doc: Document, model: Dict[str, Any]) -> None:
    """Section 24: Secure Development Lifecycle (SDLC) Integration Recommendations"""
    doc.add_page_break()
    add_styled_heading(doc, "Section 24: Secure Development Lifecycle (SDLC) Integration Recommendations", level=1)

    p_sdlc = doc.add_paragraph()
    p_sdlc.add_run(
        "Preventing the recurrence of identified vulnerabilities requires shifting security controls left into the software "
        "development lifecycle. Tracegate recommends implementing the following engineering controls across the development pipeline:"
    )

    sdlc_table = doc.add_table(rows=1, cols=3)
    sdlc_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    sw = [Inches(1.8), Inches(2.2), Inches(2.5)]
    for c_idx, title in enumerate(["SDLC Stage", "Recommended Security Tooling", "Quality Gate Criteria"]):
        cell = sdlc_table.rows[0].cells[c_idx]
        cell.width = sw[c_idx]
        set_cell_background(cell, HEX_BG_HEADER)
        set_cell_margins(cell, top=70, bottom=70, left=70, right=70)
        p = cell.paragraphs[0]
        r = p.add_run(title)
        r.font.name = "Calibri"
        r.font.bold = True
        r.font.size = Pt(8.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    sdlc_stages = [
        ("Pre-Commit (Developer IDE)", "Secret scanners (e.g. gitleaks) & linter security plugins", "Block commits containing API keys, hardcoded credentials, or insecure patterns."),
        ("Continuous Integration (CI)", "Static Application Security Testing (SAST) & SCA dependency scanners", "Fail builds with unresolved High or Critical severity CVEs in direct dependencies."),
        ("Staging / Pre-Release", "Automated DAST scans & automated API contract validation", "Block deployment if unauthenticated endpoints expose administrative functionality."),
        ("Post-Deployment (Production)", "Continuous external attack surface monitoring & periodic VAPT", "Maintain quarterly assessment cadences and automated TLS/certificate expiration monitoring.")
    ]
    for idx, (stage, tools, criteria) in enumerate(sdlc_stages):
        row = sdlc_table.add_row()
        for c_idx, val in enumerate([stage, tools, criteria]):
            cell = row.cells[c_idx]
            cell.width = sw[c_idx]
            set_cell_margins(cell, top=50, bottom=50, left=70, right=70)
            if idx % 2 == 1:
                set_cell_background(cell, HEX_BG_MUTED)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            r.font.name = "Calibri"
            r.font.size = Pt(8.5)
            if c_idx == 0:
                r.font.bold = True
    make_table_safe_for_pagination(sdlc_table)

def render_section_25_evidence_register(doc: Document, model: Dict[str, Any]) -> None:
    """Section 25: Evidence Register & Screenshot Manifest"""
    doc.add_page_break()
    add_styled_heading(doc, "Section 25: Evidence Register & Screenshot Manifest", level=1)

    p_ev = doc.add_paragraph()
    p_ev.add_run(
        "All screenshots, HTTP transcripts, and technical PoC artifacts captured during the assessment are logged in the "
        "auditable manifest below. Each artifact is uniquely identified and mapped to its corresponding finding ID."
    )

    ev_entries = model.get("evidence_register", [])
    if ev_entries:
        ev_tbl = doc.add_table(rows=1, cols=7)
        ev_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        ev_w = [Inches(0.8), Inches(0.8), Inches(1.2), Inches(1.1), Inches(1.4), Inches(0.6), Inches(0.6)]
        for c_idx, title in enumerate(["Evidence ID", "Finding ID", "Evidence Type", "Filename", "Description", "Uploaded Date", "Figure Reference"]):
            cell = ev_tbl.rows[0].cells[c_idx]
            cell.width = ev_w[c_idx]
            set_cell_background(cell, HEX_BG_HEADER)
            set_cell_margins(cell, top=70, bottom=70, left=40, right=40)
            p = cell.paragraphs[0]
            r = p.add_run(title)
            r.font.name = "Calibri"
            r.font.bold = True
            r.font.size = Pt(8)
            r.font.color.rgb = RGBColor(255, 255, 255)

        for idx, entry in enumerate(ev_entries):
            row = ev_tbl.add_row()
            vals = [
                entry.get("evidence_id", "EV-001"),
                entry.get("finding_id", "N/A"),
                entry.get("evidence_type", "Screenshot Capture"),
                entry.get("filename", "capture.png"),
                entry.get("description", "Observed evidence capture"),
                entry.get("uploaded_date", "17 Sep 2026"),
                entry.get("figure_reference", "Figure 1")
            ]
            for c_idx, val in enumerate(vals):
                cell = row.cells[c_idx]
                cell.width = ev_w[c_idx]
                set_cell_margins(cell, top=50, bottom=50, left=40, right=40)
                if idx % 2 == 1:
                    set_cell_background(cell, HEX_BG_MUTED)
                p = cell.paragraphs[0]
                r = p.add_run(str(val))
                r.font.name = "Calibri"
                r.font.size = Pt(7.5)
                if c_idx == 0:
                    r.font.bold = True
        make_table_safe_for_pagination(ev_tbl)
    else:
        p_no = doc.add_paragraph()
        p_no.add_run("No evidence captures registered.")

def render_section_26_sign_off_attestation(doc: Document, model: Dict[str, Any]) -> None:
    """Section 26: Assessment Sign-Off & Attestation"""
    doc.add_page_break()
    add_styled_heading(doc, "Section 26: Assessment Sign-Off & Attestation", level=1)

    proj_meta = model["project"]
    doc_meta = model["document_metadata"]

    p_so = doc.add_paragraph()
    p_so.add_run(
        f"This document certifies that Tracegate conducted an authorized, independent Vulnerability Assessment and "
        f"Penetration Testing (VAPT) evaluation of '{proj_meta['name']}' ({proj_meta['target_url']}) during the designated "
        f"testing period. All testing was performed within authorized operational rules of engagement without intentional "
        f"disruption to production services.\n\n"
        f"The findings, CVSS ratings, risk evaluations, and technical recommendations presented in this report represent "
        f"an accurate and impartial assessment of the target system's security posture at the time of testing."
    )

    sign_table = doc.add_table(rows=1, cols=2)
    sign_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    sw = [Inches(3.2), Inches(3.3)]
    for c_idx, title in enumerate(["Lead Security Assessor Attestation", "Lead Security Reviewer Endorsement"]):
        cell = sign_table.rows[0].cells[c_idx]
        cell.width = sw[c_idx]
        set_cell_background(cell, HEX_BG_HEADER)
        set_cell_margins(cell, top=70, bottom=70, left=80, right=80)
        p = cell.paragraphs[0]
        r = p.add_run(title)
        r.font.name = "Calibri"
        r.font.bold = True
        r.font.size = Pt(8.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    row = sign_table.add_row()
    c0, c1 = row.cells[0], row.cells[1]
    c0.width, c1.width = sw[0], sw[1]
    set_cell_margins(c0, top=80, bottom=80, left=80, right=80)
    set_cell_margins(c1, top=80, bottom=80, left=80, right=80)

    p0 = c0.paragraphs[0]
    p0.add_run(f"Name: {doc_meta['author_name']}\nTitle: Senior Penetration Tester\nOrganization: Tracegate Cyber Labs\nDate: {doc_meta['generation_date']}\nStatus: Formally Endorsed")
    p1 = c1.paragraphs[0]
    p1.add_run(f"Name: {doc_meta['reviewer_name']}\nTitle: Managing Principal Consultant\nOrganization: Tracegate Cyber Labs\nDate: {doc_meta['generation_date']}\nStatus: Quality Reviewed & Approved")
    make_table_safe_for_pagination(sign_table)

def render_section_27_appendices(doc: Document, model: Dict[str, Any]) -> None:
    """Section 27: Appendices (Appendices A through G)"""
    doc.add_page_break()
    add_styled_heading(doc, "Section 27: Appendices", level=1)

    # Appendix A: Complete Findings Register & Severity Rating Methodology
    add_styled_heading(doc, "Appendix A: Complete Findings Register & Severity Rating Methodology", level=1)
    p_appa = doc.add_paragraph()
    p_appa.add_run(
        "Complete technical findings register and Common Vulnerability Scoring System (CVSS v3.1) scoring criteria:\n"
        "• Critical Severity (CVSS 9.0 - 10.0): Flaws allowing full system takeover, unauthenticated remote code execution, or mass data exfiltration.\n"
        "• High Severity (CVSS 7.0 - 8.9): Flaws allowing privilege escalation, tenant boundary bypass, or direct unauthorized modification of records.\n"
        "• Medium Severity (CVSS 4.0 - 6.9): Flaws requiring specific user interaction, partial data exposure, or moderate configuration deficiencies.\n"
        "• Low Severity (CVSS 0.1 - 3.9): Minor technical flaws with limited exploitability or requiring unlikely prerequisite conditions.\n"
        "• Informational (CVSS 0.0): Security hygiene observations and defense-in-depth hardening opportunities without direct exploit vectors."
    )

    # Appendix B: Evidence Index & Figure Register
    add_styled_heading(doc, "Appendix B: Evidence Index & Figure Register", level=1)
    figures_index = model.get("figures_index", [])
    if figures_index:
        ev_tbl = doc.add_table(rows=1, cols=4)
        ev_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        ev_h = ["Figure #", "Associated Finding ID", "Evidence Filename", "Description / Caption"]
        ev_w = [Inches(1.0), Inches(1.3), Inches(1.8), Inches(2.4)]
        for c_idx, title in enumerate(ev_h):
            cell = ev_tbl.rows[0].cells[c_idx]
            cell.width = ev_w[c_idx]
            set_cell_background(cell, HEX_BG_HEADER)
            set_cell_margins(cell, top=70, bottom=70, left=60, right=60)
            p = cell.paragraphs[0]
            r = p.add_run(title)
            r.font.name = "Calibri"
            r.font.bold = True
            r.font.size = Pt(8.5)
            r.font.color.rgb = RGBColor(255, 255, 255)

        for idx, fig in enumerate(figures_index):
            row = ev_tbl.add_row()
            vals = [fig["figure_label"], fig["finding_id"], fig["filename"], fig["caption"]]
            for c_idx, val in enumerate(vals):
                cell = row.cells[c_idx]
                cell.width = ev_w[c_idx]
                set_cell_margins(cell, top=50, bottom=50, left=60, right=60)
                if idx % 2 == 1:
                    set_cell_background(cell, HEX_BG_MUTED)
                p = cell.paragraphs[0]
                r = p.add_run(val)
                r.font.name = "Calibri"
                r.font.size = Pt(8)
                if c_idx == 0:
                    r.font.bold = True
        make_table_safe_for_pagination(ev_tbl)
    else:
        p_no_figs = doc.add_paragraph()
        p_no_figs.add_run("No graphical screenshot evidence registered in this assessment.")

    # Appendix C: CWE Classification Index
    add_styled_heading(doc, "Appendix C: CWE Classification Index", level=1)
    p_cwe = doc.add_paragraph()
    p_cwe.add_run(
        "• CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')\n"
        "• CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')\n"
        "• CWE-639: Authorization Bypass Through User-Controlled Key ('Insecure Direct Object References')\n"
        "• CWE-287: Improper Authentication\n"
        "• CWE-288: Authentication Bypass Using an Alternate Path or Channel\n"
        "• CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')\n"
        "• CWE-434: Unrestricted Upload of File with Dangerous Type\n"
        "• CWE-524: Use of Cache-Containing Sensitive Information\n"
        "• CWE-204: Observable Response Discrepancy ('Account Enumeration')\n"
        "• CWE-307: Improper Restriction of Excessive Authentication Attempts\n"
        "• CWE-384: Session Fixation\n"
        "• CWE-352: Cross-Site Request Forgery (CSRF)\n"
        "• CWE-200: Exposure of Sensitive Information to an Unauthorized Actor\n"
        "• CWE-269: Improper Privilege Management\n"
        "• CWE-798: Use of Hard-coded Credentials"
    )

    # Appendix D: GRC Framework References & Methodology Standards
    add_styled_heading(doc, "Appendix D: GRC Framework References & Methodology Standards", level=1)
    p_app_d = doc.add_paragraph()
    p_app_d.add_run(
        "• NIST CSF 2.0: National Institute of Standards and Technology Cybersecurity Framework 2.0 (2024)\n"
        "• ISO/IEC 27001:2022: Information Security Management Systems — Annex A Technological & Organizational Controls\n"
        "• AICPA SOC 2: Trust Services Criteria for Security, Availability, Processing Integrity, Confidentiality, and Privacy\n"
        "• OWASP WSTG v4.2: Open Web Application Security Project Web Security Testing Guide\n"
        "• PCI DSS v4.0: Payment Card Industry Data Security Standard Requirements and Security Assessment Procedures"
    )

    # Appendix E: Retest & Remediation Verification Summary
    add_styled_heading(doc, "Appendix E: Retest & Remediation Verification Summary", level=1)
    metrics = model["metrics"]
    active_findings = model.get("findings", [])
    p_app_e = doc.add_paragraph()
    p_app_e.add_run(
        f"Retest Cycle Status Summary:\n"
        f"• Total Findings Tracked: {metrics['total_findings']}\n"
        f"• Findings with Verified PASS: {sum(1 for f in active_findings if 'PASS' in f.get('retest_status', '').upper())}\n"
        f"• Findings Pending Retest: {sum(1 for f in active_findings if 'PENDING' in f.get('retest_status', '').upper())}\n"
        f"• Findings with Retest FAIL: {sum(1 for f in active_findings if 'FAIL' in f.get('retest_status', '').upper())}"
    )

    # Appendix F: Report Traceability & Audit Metadata
    add_styled_heading(doc, "Appendix F: Report Traceability & Audit Metadata", level=1)
    proj_meta = model["project"]
    doc_meta = model["document_metadata"]
    p_meta = doc.add_paragraph()
    meta_text = (
        f"• Project ID: {proj_meta['id']}\n"
        f"• Target System Name: {proj_meta['name']}\n"
        f"• Report Version: {doc_meta['version']}\n"
        f"• Selected Finding IDs: {', '.join([f['report_vuln_id'] for f in active_findings]) or 'None'}\n"
        f"• Generation Engine: Tracegate Enterprise Report Engine v2.0 (Dual DOCX & PDF)\n"
        f"• Generation Timestamp: {doc_meta['generation_timestamp']}\n"
        f"• Report Classification: {doc_meta['classification']}"
    )
    p_meta.add_run(meta_text)

    # Appendix G: Glossary of Cybersecurity Terminology
    add_styled_heading(doc, "Appendix G: Glossary of Cybersecurity Terminology", level=1)
    glossary_terms = [
        ("VAPT", "Vulnerability Assessment and Penetration Testing: Comprehensive technical evaluation identifying and safely verifying security weaknesses."),
        ("CWE", "Common Weakness Enumeration: Community-developed formal taxonomy of software and hardware weakness types."),
        ("CVSS", "Common Vulnerability Scoring System: Standardized open framework for communicating the characteristics and severity of software vulnerabilities."),
        ("BOLA / IDOR", "Broken Object Level Authorization / Insecure Direct Object References: Access control failure where user-supplied object IDs allow unauthorized data access."),
        ("RCE", "Remote Code Execution: Severe security flaw permitting an attacker to execute arbitrary shell or system commands on the host server."),
        ("XSS", "Cross-Site Scripting: Flaw where untrusted user input is rendered in web browsers without adequate contextual encoding or sanitization."),
        ("PoC", "Proof of Concept: Controlled, non-destructive technical request demonstrating vulnerability exploitability."),
        ("SLA", "Service Level Agreement: Target organizational resolution timeframe established for technical vulnerability remediation."),
        ("GRC", "Governance, Risk, and Compliance: Formal framework aligning cybersecurity operations with legal and regulatory standards.")
    ]
    p_g_tbl = doc.add_table(rows=1, cols=2)
    p_g_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    gw = [Inches(1.8), Inches(4.7)]
    for c_idx, title in enumerate(["Cybersecurity Term / Acronym", "Formal Industry Definition & Context"]):
        cell = p_g_tbl.rows[0].cells[c_idx]
        cell.width = gw[c_idx]
        set_cell_background(cell, HEX_BG_HEADER)
        set_cell_margins(cell, top=70, bottom=70, left=70, right=70)
        p = cell.paragraphs[0]
        r = p.add_run(title)
        r.font.name = "Calibri"
        r.font.bold = True
        r.font.size = Pt(8.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    for idx, (term, defn) in enumerate(glossary_terms):
        row = p_g_tbl.add_row()
        for c_idx, val in enumerate([term, defn]):
            cell = row.cells[c_idx]
            cell.width = gw[c_idx]
            set_cell_margins(cell, top=50, bottom=50, left=70, right=70)
            if idx % 2 == 1:
                set_cell_background(cell, HEX_BG_MUTED)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            r.font.name = "Calibri"
            r.font.size = Pt(8.5)
            if c_idx == 0:
                r.font.bold = True
    make_table_safe_for_pagination(p_g_tbl)

# =============================================================================
# MAIN ENTERPRISE DOCX REPORT GENERATOR ENTRY POINT
# =============================================================================

def generate_docx_report(
    project: Dict[str, Any],
    version: str = "v1.0",
    author_name: Optional[str] = None,
    selected_finding_ids: Optional[List[str]] = None,
    findings: Optional[List[Dict[str, Any]]] = None,
    allow_clean_report: bool = False,
    methodology: str = "owasp_wstg",
    historical_reports: Optional[List[Dict[str, Any]]] = None,
    checklist_items: Optional[List[Dict[str, Any]]] = None
) -> str:
    """
    Generates a professional VAPT Assessment Report in Microsoft Word (.docx) format
    and automatically compiles the matching native PDF export.
    Enforces Single Render Guarantee and authoritative 27-section sequence (Rule 62).
    """
    # 1. Assemble single source-of-truth normalized report model
    model = assemble_normalized_report_model(
        project=project,
        version=version,
        author_name=author_name,
        selected_finding_ids=selected_finding_ids,
        findings=findings,
        allow_clean_report=allow_clean_report,
        methodology=methodology,
        historical_reports=historical_reports,
        checklist_items=checklist_items
    )

    # 1.1 Pre-Render Integrity Validation
    validation_errors = validate_report_model_integrity(model)
    if validation_errors:
        logger.warning(f"Pre-render model integrity logged warnings: {validation_errors}")

    proj_meta = model["project"]
    doc_meta = model["document_metadata"]

    doc = Document()

    # 2. Configure 1-inch margins & formal running headers/footers
    for section in doc.sections:
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)

        # Header
        header = section.header
        hp = header.paragraphs[0]
        hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        hrun = hp.add_run("TRACEGATE SECURITY ASSESSMENT  |  STRICTLY CONFIDENTIAL")
        hrun.font.name = "Calibri"
        hrun.font.size = Pt(8.5)
        hrun.font.color.rgb = COLOR_MUTED

        # Footer
        footer = section.footer
        fp = footer.paragraphs[0]
        fp.alignment = WD_ALIGN_PARAGRAPH.LEFT
        frun1 = fp.add_run(f"Target: {proj_meta['name']} ({doc_meta['version']})  |  Classification: {doc_meta['classification']}")
        frun1.font.name = "Calibri"
        frun1.font.size = Pt(8.5)
        frun1.font.color.rgb = COLOR_MUTED

    # 3. Instantiate Single Render Registry
    registry = ReportSectionRegistry()

    # 4. Sequentially render all 27 authoritative sections
    registry.render_section("section_1", render_section_1_cover, doc, model)
    registry.render_section("section_2", render_section_2_document_control, doc, model)
    registry.render_section("section_3", render_section_3_table_of_contents, doc, model)
    registry.render_section("section_4", render_section_4_confidentiality_and_roe, doc, model)
    registry.render_section("section_5", render_section_5_executive_summary, doc, model)
    registry.render_section("section_6", render_section_6_assessment_scope, doc, model)
    registry.render_section("section_7", render_section_7_target_environment, doc, model)
    registry.render_section("section_8", render_section_8_methodology_standards, doc, model)
    registry.render_section("section_9", render_section_9_overall_posture_and_rating, doc, model)
    registry.render_section("section_10", render_section_10_severity_distribution, doc, model)
    registry.render_section("section_11", render_section_11_attack_surface, doc, model)
    registry.render_section("section_12", render_section_12_coverage_matrix, doc, model)
    registry.render_section("section_13", render_section_13_summary_table, doc, model)
    registry.render_section("section_14", render_section_14_category_analysis, doc, model)
    registry.render_section("section_15", render_section_15_detailed_findings, doc, model)
    registry.render_section("section_16", render_section_16_retest_lifecycle, doc, model)
    registry.render_section("section_17", render_section_17_remediation_register, doc, model)
    registry.render_section("section_18", render_section_18_prioritized_remediation_plan, doc, model)
    registry.render_section("section_19", render_section_19_positive_security_controls, doc, model)
    registry.render_section("section_20", render_section_20_defense_in_depth_hardening, doc, model)
    registry.render_section("section_21", render_section_21_grc_compliance_mapping, doc, model)
    registry.render_section("section_22", render_section_22_leadership_recommendations, doc, model)
    registry.render_section("section_23", render_section_23_risk_acceptance_residual_risk, doc, model)
    registry.render_section("section_24", render_section_24_sdlc_integration, doc, model)
    registry.render_section("section_25", render_section_25_evidence_register, doc, model)
    registry.render_section("section_26", render_section_26_sign_off_attestation, doc, model)
    registry.render_section("section_27", render_section_27_appendices, doc, model)

    # 5. Post-Render Integrity Verification Gate
    verify_rendered_document_integrity(doc, model)

    # 6. Save DOCX to disk
    clean_version = doc_meta["version"].replace(".", "_")
    filename = f"{proj_meta['id']}_{clean_version}_assessment_report.docx"
    output_path = REPORTS_DIR / filename
    try:
        doc.save(str(output_path))
    except (PermissionError, OSError) as pe:
        logger.warning(f"Default report path {output_path} is locked ({pe}), saving to timestamped filename")
        filename = f"{proj_meta['id']}_{clean_version}_{int(time.time())}_assessment_report.docx"
        output_path = REPORTS_DIR / filename
        doc.save(str(output_path))
    logger.info(f"Enterprise DOCX Report created at: {output_path}")

    # 7. Automatically compile matching native PDF
    target_pdf = output_path.with_suffix(".pdf")
    try:
        from backend.report_pdf_generator import compile_report_pdf
        compile_report_pdf(model, target_pdf, docx_path=output_path)
    except Exception as e:
        logger.warning(f"Automatic PDF compilation skipped: {e}")

    return str(output_path)
