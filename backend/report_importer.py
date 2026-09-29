"""
Tracegate External VAPT Report Parser and Ingestion Subsystem.
Parses external security assessment reports in PDF, DOCX, TXT, and Markdown formats,
segments text into candidate vulnerability records, extracts structured technical fields,
performs duplicate detection against existing project findings, and prepares candidates
for human-in-the-loop review and selective project import.
"""

import io
import re
import uuid
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import pypdf
import docx

logger = logging.getLogger("report_importer")

SUPPORTED_IMPORT_EXTENSIONS = {".pdf", ".docx", ".txt", ".md"}
MAX_IMPORT_FILE_SIZE = 20 * 1024 * 1024  # 20MB

CWE_COMMON_MAPPINGS = {
    "sql injection": "CWE-89",
    "sqli": "CWE-89",
    "cross-site scripting": "CWE-79",
    "xss": "CWE-79",
    "idor": "CWE-639",
    "insecure direct object reference": "CWE-639",
    "broken object level authorization": "CWE-639",
    "bola": "CWE-639",
    "csrf": "CWE-352",
    "cross-site request forgery": "CWE-352",
    "ssrf": "CWE-918",
    "server-side request forgery": "CWE-918",
    "command injection": "CWE-78",
    "os command injection": "CWE-78",
    "rce": "CWE-94",
    "remote code execution": "CWE-94",
    "path traversal": "CWE-22",
    "directory traversal": "CWE-22",
    "file upload": "CWE-434",
    "unrestricted file upload": "CWE-434",
    "broken authentication": "CWE-287",
    "authentication bypass": "CWE-287",
    "2fa": "CWE-288",
    "two-factor": "CWE-288",
    "brute force": "CWE-307",
    "rate limit": "CWE-307",
    "security header": "CWE-693",
    "missing security header": "CWE-693",
    "information disclosure": "CWE-200",
    "sensitive data exposure": "CWE-200",
    "cors": "CWE-942",
    "open redirect": "CWE-601",
    "jwt": "CWE-345",
    "price manipulation": "CWE-390",
    "parameter tampering": "CWE-472",
    "enumeration": "CWE-204",
    "account enumeration": "CWE-204",
    "username enumeration": "CWE-204",
    "autocomplete": "CWE-524",
    "credential caching": "CWE-524",
    "caching": "CWE-524"
}

NON_FINDING_SECTION_KEYWORDS = [
    "table of contents", "executive summary", "risk rating", "findings severity matrix",
    "slas", "assessment scope", "target architecture", "testing methodology",
    "security standards", "security test coverage", "coverage & statistics",
    "summary of confirmed vulnerabilities", "prioritized remediation action plan",
    "retest & validation lifecycle", "assessment conclusion", "formal sign-off",
    "conclusion", "appendices", "document control", "scope of assessment",
    "executive overview", "methodology & security standards"
]

def extract_text_from_pdf(file_bytes: bytes) -> str:
    """Extract textual content page-by-page from an uploaded PDF file."""
    try:
        reader = pypdf.PdfReader(io.BytesIO(file_bytes))
        pages_text = []
        for i, page in enumerate(reader.pages):
            txt = page.extract_text() or ""
            if txt.strip():
                pages_text.append(f"--- Page {i + 1} ---\n" + txt)
        return "\n\n".join(pages_text)
    except Exception as e:
        logger.error(f"Failed to extract text from PDF: {e}")
        raise ValueError(f"Could not parse PDF document: {e}")

def extract_text_from_docx(file_bytes: bytes) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Extract textual content from an uploaded Word DOCX preserving exact document order
    between headings, paragraphs, and tables, and extract structured finding summary rows.
    Returns (ordered_full_text, summary_table_findings).
    """
    try:
        doc = docx.Document(io.BytesIO(file_bytes))
        sections = []
        summary_table_findings = []

        for child in doc.element.body.iterchildren():
            if child.tag.endswith('p'):
                p = docx.text.paragraph.Paragraph(child, doc)
                txt = p.text.strip()
                if txt:
                    if p.style and "Heading" in p.style.name:
                        sections.append(f"## {txt}")
                    else:
                        sections.append(txt)
            elif child.tag.endswith('tbl'):
                t = docx.table.Table(child, doc)
                table_lines = []
                headers = [c.text.strip().replace('\n', ' ') for c in t.rows[0].cells] if t.rows else []

                # Check if this table is the Summary of Confirmed Vulnerabilities
                is_vuln_summary = False
                lower_headers = [h.lower() for h in headers]
                if any("finding" in h or "vuln" in h for h in lower_headers) and any("severity" in h or "cwe" in h for h in lower_headers):
                    is_vuln_summary = True

                for r_idx, row in enumerate(t.rows):
                    row_cells = [cell.text.strip().replace('\n', ' ') for cell in row.cells]
                    table_lines.append(" | ".join(row_cells))

                    if is_vuln_summary and r_idx > 0 and len(row_cells) >= 3:
                        # Format: Finding ID | Vulnerability Title | Severity | CWE | Status | Retest
                        v_id = row_cells[0].strip()
                        v_title = row_cells[1].strip() if len(row_cells) > 1 else ""
                        v_sev = row_cells[2].strip() if len(row_cells) > 2 else "MEDIUM"
                        v_cwe = row_cells[3].strip() if len(row_cells) > 3 else "CWE-200"
                        v_status = row_cells[4].strip() if len(row_cells) > 4 else "Open"
                        v_retest = row_cells[5].strip() if len(row_cells) > 5 else "PENDING"
                        if v_id and v_title:
                            summary_table_findings.append({
                                "source_finding_id": v_id,
                                "title": v_title,
                                "severity": normalize_severity(v_sev),
                                "cwe": v_cwe if v_cwe.upper().startswith("CWE-") else "CWE-200",
                                "status": v_status,
                                "retest_status": v_retest
                            })

                if table_lines:
                    sections.append("\n" + "\n".join(table_lines) + "\n")

        return "\n\n".join(sections), summary_table_findings
    except Exception as e:
        logger.error(f"Failed to extract text from DOCX: {e}")
        raise ValueError(f"Could not parse DOCX document: {e}")

def extract_text_from_txt_or_md(file_bytes: bytes) -> str:
    """Extract text from plaintext or markdown file with multi-encoding fallback."""
    for enc in ["utf-8", "utf-8-sig", "latin-1", "cp1252"]:
        try:
            return file_bytes.decode(enc)
        except UnicodeDecodeError:
            continue
    return file_bytes.decode("utf-8", errors="replace")

def normalize_severity(raw_sev: str) -> str:
    """Normalize arbitrary severity strings to Tracegate's 5 standard severities."""
    s = (raw_sev or "").strip().upper()
    if s in ["CRITICAL", "CRIT", "P1", "P-1", "SEV1", "SEV 1", "SEV-1"]:
        return "CRITICAL"
    if s in ["HIGH", "P2", "P-2", "SEV2", "SEV 2", "SEV-2"]:
        return "HIGH"
    if s in ["MEDIUM", "MED", "MODERATE", "P3", "P-3", "SEV3", "SEV 3", "SEV-3"]:
        return "MEDIUM"
    if s in ["LOW", "P4", "P-4", "SEV4", "SEV 4", "SEV-4"]:
        return "LOW"
    if s in ["INFORMATIONAL", "INFO", "P5", "P-5", "SEV5", "SEV 5", "SEV-5"]:
        return "INFORMATIONAL"
    if any(k in s for k in ["CRIT", "VERY HIGH", "P1", "P-1", "SEV1", "SEV 1", "SEV-1"]):
        return "CRITICAL"
    elif any(k in s for k in ["HIGH", "P2", "P-2", "IMPORTANT", "SEV2", "SEV 2", "SEV-2"]):
        return "HIGH"
    elif any(k in s for k in ["MED", "MODERATE", "P3", "P-3", "SEV3", "SEV 3", "SEV-3"]):
        return "MEDIUM"
    elif any(k in s for k in ["LOW", "P4", "P-4", "MINOR", "SEV4", "SEV 4", "SEV-4"]):
        return "LOW"
    elif any(k in s for k in ["INFO", "BEST PRACTICE", "NOTE", "P5", "P-5", "SEV5", "SEV 5", "SEV-5"]):
        return "INFORMATIONAL"
    return "MEDIUM"

def segment_report_text(full_text: str) -> List[str]:
    """
    Segment document text into discrete potential vulnerability blocks based on
    heading structures, numbered finding markers, and vulnerability section headers.
    Filters out non-finding document sections and table rows with pipe delimiters.
    """
    pattern = r'(?i)(?:^|\n)(?=(?:#{1,4}\s+)(?:(?:vuln|sec|finding|vulnerability|issue|defect|item)[-\s#]*\d+(?:\s*[:\-]|\s*\.|\s*\n)|\d+\.\s+(?:critical|high|medium|low|informational|[a-z0-9\s\-]+(?:vulnerability|injection|flaw|issue|bypass|disclosure|idor|xss|sqli|traversal|overflow|tampering|deserialization))|vulnerability\s+name[:\s]|finding\s+title[:\s]|\[(?:critical|high|medium|low|info)\])|(?:(?:vuln|sec|finding|vulnerability|issue|defect|item)[-\s#]*\d+(?:\s*[:\-]|\s*\.|\s*\n)|vulnerability\s+name[:\s]|finding\s+title[:\s]|\[(?:critical|high|medium|low|info)\]|\d+\.\s+(?:critical|high|medium|low|informational)\b|\d+\.\s+(?!(?:observe|click|send|intercept|submit|open|verify|check|inspect|review|test|inject|run|execute|access|navigate|enter|modify|browse|replace)\b)[a-z0-9\s\-]{1,60}?(?:vulnerability|injection|flaw|issue|bypass|disclosure|idor|xss|sqli|traversal|overflow|tampering|deserialization)\s*(?:[:\-]\s*|\s*$)))'

    parts = re.split(pattern, full_text, flags=re.MULTILINE)
    cleaned_chunks = []

    for idx, chunk in enumerate(parts):
        c = chunk.strip()
        if len(c) < 40:
            continue
        first_line = c.splitlines()[0].lower()
        first_line_clean = re.sub(r'^[#*\s\-\d\.]+', '', first_line).strip()

        # Discard non-finding document sections (e.g. executive summary, table of contents)
        if any(kw in first_line_clean for kw in NON_FINDING_SECTION_KEYWORDS):
            continue

        # If this is the preamble chunk before the first split and there are multiple chunks,
        # it is only a finding if it actually begins with a finding heading
        if idx == 0 and len(parts) > 1:
            if not re.search(r'(?i)^(?:#{1,4}\s+)?(?:vuln|sec|finding|vulnerability|issue|defect|item)[-\s#]*\d+', c):
                continue

        # Retain chunks with explicit finding attributes
        if re.search(r'(?i)(?:vuln|sec|finding|vulnerability|issue|defect|item)[-\s#]*\d+', first_line) or \
           any(w in c.lower() for w in ["vulnerability", "cwe-", "cvss", "remediation", "proof of concept", "poc"]):
            cleaned_chunks.append(c)

    # Fallback to markdown headings if initial pattern caught nothing
    if not cleaned_chunks and len(full_text.strip()) > 50:
        md_chunks = re.split(r'\n\s*#{1,3}\s+', full_text)
        for mc in md_chunks:
            mc = mc.strip()
            if len(mc) > 40:
                first_line = mc.splitlines()[0].lower()
                first_line_clean = re.sub(r'^[#*\s\-\d\.]+', '', first_line).strip()
                if any(kw in first_line_clean for kw in NON_FINDING_SECTION_KEYWORDS):
                    continue
                if any(w in mc.lower() for w in ["vulnerability", "finding", "issue", "cwe", "severity", "poc", "remediation", "impact"]):
                    cleaned_chunks.append(mc)

    if not cleaned_chunks and len(full_text.strip()) > 30:
        cleaned_chunks.append(full_text.strip())

    return cleaned_chunks

def parse_candidate_finding(
    chunk: str,
    chunk_index: int = 1,
    doc_id: str = "",
    doc_name: str = ""
) -> Optional[Dict[str, Any]]:
    """
    Parse a segmented text chunk into a structured candidate finding dictionary.
    Extracts all 15 technical fields: title, severity, CWE, CVSS, executive description,
    technical observation, component/URL, security impact, business impact, reproduction steps,
    monospaced PoC snippet, evidence, root cause, remediation recommendation, defense-in-depth
    mitigation, detection/monitoring, developer validation, and retest/Git tracking.
    """
    lines = [line.strip() for line in chunk.splitlines() if line.strip()]
    if not lines:
        return None

    first_line = lines[0]
    first_line_clean = re.sub(r'^[#*\s\-]+', '', first_line)

    # Check for document section headers mistakenly passed through
    check_lower = re.sub(r'^[#*\s\-\d\.]+', '', first_line_clean.lower()).strip()
    if any(kw in check_lower for kw in NON_FINDING_SECTION_KEYWORDS):
        return None

    # Extract source finding ID (e.g. VULN-001, SEC-001, FINDING-1, CVE-2024-...)
    source_finding_id = None
    id_match = re.search(r'(?i)\b(VULN[-\s#]*\d+|SEC[-\s#]*\d+|FINDING[-\s#]*\d+|ISSUE[-\s#]*\d+|CVE-\d{4}-\d+)\b', first_line_clean)
    if id_match:
        source_finding_id = id_match.group(1).upper().replace(" ", "")

    # Clean title
    title = first_line_clean
    title = re.sub(r'(?i)^(?:vuln|sec|finding|vulnerability|issue|defect|item)[-\s#]*\d+[:\s\-]*', '', title).strip()
    title = re.sub(r'^\d+\.\s*', '', title).strip()
    title = re.sub(r'(?i)\[(critical|high|medium|low|info|p[1-5])\]\s*', '', title).strip()
    if not title or len(title) < 3:
        title = f"Security Finding #{chunk_index}"

    # Metadata table parsing (e.g. 2-row table below heading)
    # Severity | CWE | CVSS v3.1 | Remediation Status | Source
    meta_sev = None
    meta_cwe = None
    meta_cvss = None
    meta_status = None

    table_match = re.search(r'(?i)Severity\s*\|\s*CWE.*?\n\s*([A-Za-z0-9_\-]+(?:\s+[A-Za-z0-9_\-]+)?)\s*\|\s*(CWE-\d+)\s*\|\s*(\d+(?:\.\d+)?)\s*\|\s*([^|\n]+)', chunk)
    if table_match:
        meta_sev = normalize_severity(table_match.group(1))
        meta_cwe = table_match.group(2).upper()
        try:
            meta_cvss = float(table_match.group(3))
        except ValueError:
            pass
        meta_status = table_match.group(4).strip()
    else:
        sev_kv = re.search(r'(?i)Severity(?:\s*&\s*Priority(?:\s*Tier)?)?\s*\|\s*([A-Za-z0-9_\-]+)', chunk)
        if sev_kv:
            meta_sev = normalize_severity(sev_kv.group(1))
        cwe_kv = re.search(r'(?i)CWE(?:\s*Classification)?\s*\|\s*(CWE-\d+)', chunk)
        if cwe_kv:
            meta_cwe = cwe_kv.group(1).upper()
        cvss_kv = re.search(r'(?i)CVSS.*?\b(?:Score|Scoring|Vector)\b.*?\|\s*(?:Score:\s*)?(\d+(?:\.\d+)?)', chunk)
        if cvss_kv:
            try:
                meta_cvss = float(cvss_kv.group(1))
            except ValueError:
                pass
        st_kv = re.search(r'(?i)Remediation(?:\s*&\s*Retest)?\s*Status\s*\|\s*(?:Status:\s*)?([^|\n]+)', chunk)
        if st_kv:
            meta_status = st_kv.group(1).strip()

    # 1. Severity extraction
    if meta_sev:
        severity = meta_sev
    else:
        sev_match = re.search(r'(?i)\b(?:severity(?:\s*&\s*priority(?:\s*tier)?)?|priority|risk\s*rating|risk\s*level|severity\s*level)\b\s*[:=\-|]?\s*([A-Za-z0-9_\-]+(?:\s+[A-Za-z0-9_\-]+)?)', chunk)
        if sev_match:
            severity = normalize_severity(sev_match.group(1))
        else:
            tag_match = re.search(r'(?i)\[(CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL|INFO|P[1-5]|P-[1-5])\]', chunk)
            if tag_match:
                severity = normalize_severity(tag_match.group(1))
            elif "critical" in chunk.lower()[:300]:
                severity = "CRITICAL"
            elif "high" in chunk.lower()[:300]:
                severity = "HIGH"
            elif "low" in chunk.lower()[:300]:
                severity = "LOW"
            elif "informational" in chunk.lower()[:300] or "info" in chunk.lower()[:300]:
                severity = "INFORMATIONAL"
            else:
                severity = "MEDIUM"

    # 2. CWE extraction
    cwe = None
    if meta_cwe:
        cwe = meta_cwe
    else:
        cwe_match = re.search(r'(?i)\b(CWE-\d+)\b', chunk)
        if cwe_match:
            cwe = cwe_match.group(1).upper()
        else:
            lower_chunk = chunk.lower()
            for kw, mapped_cwe in CWE_COMMON_MAPPINGS.items():
                if kw in lower_chunk or kw in title.lower():
                    cwe = mapped_cwe
                    break
    if not cwe:
        cwe = "CWE-200"

    # 3. CVSS score
    cvss = None
    if meta_cvss is not None:
        cvss = meta_cvss
    else:
        cvss_match = re.search(r'(?i)CVSS(?:\s*v[23](?:\.[01])?)?(?:\s*Base)?(?:\s*Score)?[:\s]+(\d+(?:\.\d+)?)', chunk)
        if cvss_match:
            try:
                cvss = float(cvss_match.group(1))
            except ValueError:
                cvss = None
    if cvss is None:
        cvss = 9.0 if severity == "CRITICAL" else 7.5 if severity == "HIGH" else 5.0 if severity == "MEDIUM" else 3.0 if severity == "LOW" else 0.0

    # 4. Helper to extract section text supporting prefixes like 'A. ', 'B. ', '##', or '1. '
    def extract_section_text(keywords: List[str]) -> str:
        kw_pattern = '|'.join(keywords)
        pattern = r'(?i)(?:^|\n)(?:[#*]{1,4}\s*)?(?:[A-O]\.|\d+\.)?\s*(?:' + kw_pattern + r')[:\s\-]*(.*?)(?=\n(?:[#*]{1,4}\s*)?(?:[A-O]\.|\d+\.)?\s*(?:vulnerability|description|observation|technical|impact|security\s*impact|business\s*impact|steps|reproduction|poc|proof|evidence|root\s*cause|remediation|mitigation|recommendation|detection|developer|lifecycle|retest)|$)'
        m = re.search(pattern, chunk, flags=re.DOTALL)
        if m and m.group(1):
            text = (m.group(1) or "").strip()
            text = re.sub(r'^[\-:\s]+', '', text).strip()
            return text
        return ""

    description = extract_section_text([
        "vulnerability description & technical observation", "vulnerability description",
        "description", "details", "overview", "technical observation", "observation"
    ])
    sec_impact = extract_section_text([
        "security impact", "technical impact", "security & technical impact"
    ])
    biz_impact = extract_section_text([
        "business impact", "business & operational impact"
    ])
    impact = extract_section_text([
        "business & technical impact", "impact", "consequences"
    ])
    if not impact:
        if sec_impact and biz_impact:
            impact = f"Security Impact: {sec_impact}\n\nBusiness Impact: {biz_impact}"
        else:
            impact = sec_impact or biz_impact

    steps = extract_section_text([
        "step-by-step reproduction procedure", "reproduction procedure",
        "steps to reproduce", "reproduction steps", "reproduction",
        "testing procedure", "testing steps"
    ])
    remediation = extract_section_text([
        "recommended technical remediation", "technical remediation",
        "remediation", "recommendation", "suggested fix", "solution", "mitigation guidance"
    ])
    mitigation = extract_section_text([
        "defense-in-depth architectural mitigation", "defense-in-depth mitigation",
        "defense-in-depth", "architectural mitigation", "mitigation"
    ])
    root_cause = extract_section_text([
        "root cause analysis", "root cause", "underlying defect", "vulnerability cause"
    ])
    detection = extract_section_text([
        "detection & monitoring guidance", "detection & monitoring", "detection", "monitoring"
    ])
    validation = extract_section_text([
        "developer validation guidance", "developer validation", "validation guidance", "developer testing"
    ])

    # 5. Extract PoC snippet
    poc = extract_section_text([
        "proof of concept (poc) request / payload snippet", "proof of concept",
        "proof of concept (poc)", "poc request", "poc payload", "poc", "payload", "reproduction payload"
    ])
    if not poc:
        code_block_match = re.search(r'```(?:[a-zA-Z]*\n)?(.*?)```', chunk, flags=re.DOTALL)
        if code_block_match:
            poc = code_block_match.group(1).strip()
    if not poc:
        # Check for HTTP request callout table or raw HTTP request
        http_match = re.search(r'(?:(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+/[^\s]+\s+HTTP/1\.[01].*?)(?=\n\n|\n[A-Z]\.|$)', chunk, flags=re.DOTALL)
        if http_match:
            poc = http_match.group(0).strip()

    # 6. Affected URL / Component
    url = ""
    url_match = re.search(r'(?i)(?:affected\s*(?:url|path|endpoint(?:\s*/\s*uri)?)|target\s*(?:url|endpoint(?:\s*/\s*uri)?)|url)\s*[:=\-|]\s*([https?://\S+|/\S+]+)', chunk)
    if url_match:
        url = url_match.group(1).strip()
    else:
        if poc:
            poc_url_match = re.search(r'(?:GET|POST|PUT|DELETE|PATCH)\s+([/\S]+)', poc)
            if poc_url_match:
                url = poc_url_match.group(1).strip()
        if not url:
            path_match = re.search(r'(/(?:api|v1|v2|auth|users|account|admin|profile|checkout|search|upload|login)[a-zA-Z0-9_/\-\.]*)', chunk)
            if path_match:
                url = path_match.group(1).strip()

    component = ""
    comp_match = re.search(r'(?i)(?:affected\s*component|component|module|service)[:\s]+([A-Za-z0-9_\-\s/]+)', chunk)
    if comp_match:
        lines = comp_match.group(1).strip().splitlines()
        if lines:
            component = lines[0].strip()
    if not component:
        if url:
            component = url.split("?")[0]
        else:
            component = "Web Application Surface"

    # 7. Git Fix & Retest Extraction
    git_branch = None
    branch_match = re.search(r'(?i)Dedicated Fix Branch[:\s]+(\S+)', chunk)
    if branch_match:
        git_branch = branch_match.group(1).strip()

    git_commit = None
    commit_match = re.search(r'(?i)Remediation Commit SHA[:\s]+([a-f0-9]+)', chunk)
    if commit_match:
        git_commit = commit_match.group(1).strip()

    git_pr = None
    pr_match = re.search(r'(?i)Pull Request[:\s]+(https?://\S+)', chunk)
    if pr_match:
        git_pr = pr_match.group(1).strip()

    retest_st = "PENDING"
    retest_match = re.search(r'(?i)Retest Status[:\s]+([A-Za-z_]+)', chunk)
    if retest_match:
        retest_st = retest_match.group(1).strip().upper()

    # 8. Evidence filenames / Figures
    evidence = []
    fig_matches = re.findall(r'(?i)Figure\s*\d+:.*?\((?:[^()]*\s*-\s*)?([^()]+?\.(?:png|jpg|jpeg|webp|gif))\)', chunk)
    for fm in fig_matches:
        evidence.append({"name": fm.strip(), "filename": fm.strip(), "type": "image/png"})

    if not description:
        non_header_lines = [l for l in lines[1:] if not re.match(r'(?i)^(severity|cwe|cvss|component|url|date|status)[:\s]', l)]
        if non_header_lines:
            description = " ".join(non_header_lines[:4])
        else:
            description = f"{title} observed in target scope."

    # Discard non-finding chunks lacking any explicit attributes
    has_explicit_sev = bool(meta_sev or sev_match or tag_match)
    has_explicit_cwe = bool(meta_cwe or (cwe and cwe != "CWE-200"))
    has_explicit_poc = bool(poc)
    has_explicit_remed = bool(remediation)
    if not (has_explicit_sev or has_explicit_cwe or has_explicit_poc or has_explicit_remed):
        return None

    quality = "HIGH"
    if not poc and not steps:
        quality = "MEDIUM"
    if not impact and not remediation:
        quality = "LOW" if quality == "MEDIUM" else "MEDIUM"

    cand_id = f"cand-{uuid.uuid4().hex[:8]}"

    return {
        "id": cand_id,
        "source_finding_id": source_finding_id or f"VULN-{chunk_index:03d}",
        "title": title,
        "severity": severity,
        "cwe": cwe,
        "cvss_score": cvss,
        "description": description,
        "observation": description,
        "impact": impact or f"Exploitation of {title} compromises application confidentiality, integrity, or availability.",
        "security_impact": sec_impact,
        "business_impact": biz_impact,
        "affected_url": url or "/api",
        "affected_component": component,
        "steps_to_reproduce": steps or "1. Access vulnerable endpoint.\n2. Supply test payload.\n3. Observe anomalous behavior.",
        "poc": poc or f"GET {url or '/api/vulnerable'} HTTP/1.1\nHost: target.app\nUser-Agent: Tracegate-Audit",
        "poc_text": poc or f"GET {url or '/api/vulnerable'} HTTP/1.1\nHost: target.app\nUser-Agent: Tracegate-Audit",
        "remediation": remediation or f"Enforce input validation, parameterized queries, and strict access controls for {title}.",
        "mitigation": mitigation or "Apply defense-in-depth architectural controls and continuous security regression monitoring.",
        "root_cause": root_cause,
        "detection_monitoring": detection,
        "developer_validation": validation,
        "status": meta_status or "Open",
        "retest_status": retest_st,
        "github_branch": git_branch,
        "github_commit": git_commit,
        "github_pr": git_pr,
        "evidence": evidence,
        "source": "IMPORTED_REPORT",
        "source_document_id": doc_id,
        "source_document_name": doc_name,
        "extraction_quality": quality,
        "is_duplicate": False,
        "duplicate_match": None
    }

def detect_duplicates(candidate_findings: List[Dict[str, Any]], existing_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Identify potential duplicate findings by comparing candidates against
    existing project findings using title tokens, CWE classification, and URL/component matches.
    """
    for cand in candidate_findings:
        cand_title = (cand.get("title") or "").lower().strip()
        cand_cwe = (cand.get("cwe") or "").upper().strip()
        cand_url = (cand.get("affected_url") or "").lower().strip()
        cand_comp = (cand.get("affected_component") or "").lower().strip()
        cand_tokens = set(re.findall(r'\w+', cand_title))

        is_dup = False
        match_info = None

        for ex in existing_findings:
            ex_title = (ex.get("finding_name") or ex.get("title") or "").lower().strip()
            ex_cwe = (ex.get("cwe") or "").upper().strip()
            ex_url = (ex.get("affected_url") or "").lower().strip()
            ex_comp = (ex.get("affected_component") or "").lower().strip()
            ex_tokens = set(re.findall(r'\w+', ex_title))

            if cand_title == ex_title:
                is_dup = True
                match_info = {"id": ex["id"], "vuln_id": ex.get("vuln_id"), "title": ex.get("finding_name", ex_title), "reason": "Exact Title Match"}
                break

            if cand_tokens and ex_tokens:
                overlap = len(cand_tokens & ex_tokens) / max(len(cand_tokens | ex_tokens), 1)
                if overlap > 0.65:
                    is_dup = True
                    match_info = {"id": ex["id"], "vuln_id": ex.get("vuln_id"), "title": ex.get("finding_name", ex_title), "reason": "High Title Similarity"}
                    break

            if cand_cwe and ex_cwe and cand_cwe == ex_cwe and cand_cwe != "CWE-200":
                if (cand_url and ex_url and cand_url == ex_url) or (cand_comp and ex_comp and cand_comp == ex_comp and cand_comp != "Web Application Surface"):
                    is_dup = True
                    match_info = {"id": ex["id"], "vuln_id": ex.get("vuln_id"), "title": ex.get("finding_name", ex_title), "reason": "Matching CWE & Component"}
                    break

        cand["is_duplicate"] = is_dup
        cand["duplicate_match"] = match_info
        if is_dup and match_info:
            cand["duplicate_warning"] = f"Potential duplicate of existing finding: {match_info.get('title')} ({match_info.get('reason')})"
            cand["duplicate_of_id"] = match_info.get("id")
        else:
            cand["duplicate_warning"] = None
            cand["duplicate_of_id"] = None

    return candidate_findings

def parse_report_document(
    file_bytes: bytes,
    filename: str,
    existing_findings: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Main entry point for external VAPT report parsing.
    Validates format, extracts text and tables, segments into candidate findings,
    correlates summary table rows, and runs duplicate detection against existing project findings.
    """
    ext = Path(filename).suffix.lower()
    if ext not in SUPPORTED_IMPORT_EXTENSIONS:
        raise ValueError(f"Unsupported file extension '{ext}'. Supported formats: PDF, DOCX, TXT, MD.")

    if len(file_bytes) > MAX_IMPORT_FILE_SIZE:
        raise ValueError(f"Uploaded report file exceeds maximum permitted size of {MAX_IMPORT_FILE_SIZE // (1024 * 1024)}MB.")

    summary_findings = []
    if ext == ".pdf":
        full_text = extract_text_from_pdf(file_bytes)
    elif ext == ".docx":
        full_text, summary_findings = extract_text_from_docx(file_bytes)
    else:
        full_text = extract_text_from_txt_or_md(file_bytes)

    if not full_text or not full_text.strip():
        raise ValueError("The uploaded report file contains no readable text or is empty.")

    doc_id = f"doc-{uuid.uuid4().hex[:8]}"
    chunks = segment_report_text(full_text)
    candidate_findings = []

    for idx, chunk in enumerate(chunks):
        parsed = parse_candidate_finding(
            chunk,
            chunk_index=idx + 1,
            doc_id=doc_id,
            doc_name=filename
        )
        if parsed:
            candidate_findings.append(parsed)

    # Fallback: If segmentation caught no detailed chunks but summary table was detected
    if not candidate_findings and summary_findings:
        for s_idx, sf in enumerate(summary_findings):
            cid = f"cand-{uuid.uuid4().hex[:8]}"
            candidate_findings.append({
                "id": cid,
                "source_finding_id": sf.get("source_finding_id") or f"VULN-{s_idx + 1:03d}",
                "title": sf.get("title") or f"Vulnerability {s_idx + 1}",
                "severity": sf.get("severity") or "MEDIUM",
                "cwe": sf.get("cwe") or "CWE-200",
                "cvss_score": 9.0 if sf.get("severity") == "CRITICAL" else 7.5 if sf.get("severity") == "HIGH" else 5.0,
                "description": f"Imported finding from assessment summary: {sf.get('title')}",
                "observation": f"Imported finding from assessment summary: {sf.get('title')}",
                "impact": f"Exploitation of {sf.get('title')} compromises target environment security controls.",
                "affected_url": "/api",
                "affected_component": "Target Scope",
                "steps_to_reproduce": "1. Review assessment report notes.\n2. Recreate reported test vector.",
                "poc": f"GET /api HTTP/1.1\nHost: target.app\nUser-Agent: Tracegate-Audit",
                "poc_text": f"GET /api HTTP/1.1\nHost: target.app\nUser-Agent: Tracegate-Audit",
                "remediation": f"Remediate {sf.get('title')} per security best practices and organizational guidelines.",
                "mitigation": "Enforce defense-in-depth architectural mitigations.",
                "status": sf.get("status") or "Open",
                "retest_status": sf.get("retest_status") or "PENDING",
                "evidence": [],
                "source": "IMPORTED_REPORT",
                "source_document_id": doc_id,
                "source_document_name": filename,
                "extraction_quality": "MEDIUM",
                "is_duplicate": False,
                "duplicate_match": None
            })

    if existing_findings:
        candidate_findings = detect_duplicates(candidate_findings, existing_findings)

    logger.info(f"Parsed report '{filename}': extracted {len(candidate_findings)} candidate findings from {len(chunks)} text chunks.")

    return {
        "source_document_id": doc_id,
        "source_document_name": filename,
        "total_candidates": len(candidate_findings),
        "candidate_findings": candidate_findings,
        "full_text": full_text,
        "summary": {
            "critical": sum(1 for c in candidate_findings if (c.get("severity") or "").upper() == "CRITICAL"),
            "high": sum(1 for c in candidate_findings if (c.get("severity") or "").upper() == "HIGH"),
            "medium": sum(1 for c in candidate_findings if (c.get("severity") or "").upper() == "MEDIUM"),
            "low": sum(1 for c in candidate_findings if (c.get("severity") or "").upper() == "LOW"),
            "informational": sum(1 for c in candidate_findings if (c.get("severity") or "").upper() in ["INFORMATIONAL", "INFO"]),
            "duplicates": sum(1 for c in candidate_findings if c.get("is_duplicate")),
        }
    }
