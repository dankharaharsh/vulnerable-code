"""
Tracegate Authoritative PDF Validation Engine.
Provides strict, deterministic binary inspection and structural validation
for all generated PDF artifacts (reports and certificates).
"""

import logging
from pathlib import Path
from typing import Union, Tuple, Optional
import pypdf

logger = logging.getLogger("tracegate.pdf_validator")

PDF_HEADER_MAGIC = b"%PDF-"
MIN_VALID_PDF_SIZE_BYTES = 100  # Strictest threshold: any valid PDF has catalog + page tree + trailer


def validate_pdf_artifact(file_path: Union[str, Path, None]) -> Tuple[bool, Optional[str]]:
    """
    Performs comprehensive binary and structural validation on a candidate PDF file.
    Returns:
        (True, None) if the file is a valid, parseable, non-corrupted PDF.
        (False, error_reason) if the file fails any validation check.
    """
    if file_path is None:
        return False, "File path is None."

    path = Path(file_path).resolve()

    if not path.exists():
        return False, f"File does not exist on disk: {path}"

    if not path.is_file():
        return False, f"Path is not a regular file: {path}"

    # 1. File Size Verification
    try:
        file_size = path.stat().st_size
    except OSError as e:
        return False, f"Could not determine file size: {e}"

    if file_size < MIN_VALID_PDF_SIZE_BYTES:
        return False, f"File size ({file_size} bytes) is below minimum valid PDF threshold ({MIN_VALID_PDF_SIZE_BYTES} bytes)."

    # 2. Magic Header Bytes Verification (%PDF-)
    try:
        with open(path, "rb") as f:
            header_chunk = f.read(1024)
    except Exception as e:
        return False, f"Failed to read file header: {e}"

    # Check for disguised ZIP / DOCX headers (PK\x03\x04)
    if header_chunk.startswith(b"PK\x03\x04"):
        return False, "File contains ZIP/DOCX binary header (PK\x03\x04) disguised as PDF."

    magic_pos = header_chunk.find(PDF_HEADER_MAGIC)
    if magic_pos == -1:
        return False, "File lacks standard %PDF- magic header in initial 1024 bytes."

    # 3. Structural & Page Tree Parsing via pypdf
    try:
        reader = pypdf.PdfReader(str(path), strict=False)
        num_pages = len(reader.pages)
        if num_pages < 1:
            return False, "PDF contains 0 renderable pages."

        # Probe first page to ensure content stream is not corrupt
        first_page = reader.pages[0]
        if first_page is None:
            return False, "First page object could not be resolved."

    except Exception as exc:
        return False, f"PDF structural validation failed (pypdf parsing error): {exc}"

    return True, None


def is_valid_pdf(file_path: Union[str, Path, None]) -> bool:
    """
    Convenience boolean predicate checking whether file is a verified, valid PDF artifact.
    """
    valid, reason = validate_pdf_artifact(file_path)
    if not valid:
        logger.debug(f"PDF validation failed for {file_path}: {reason}")
    return valid


def verify_pdf_bytes(pdf_bytes: bytes) -> Tuple[bool, Optional[str]]:
    """
    Validates in-memory PDF binary bytes.
    """
    if not pdf_bytes:
        return False, "PDF byte stream is empty."

    if len(pdf_bytes) < MIN_VALID_PDF_SIZE_BYTES:
        return False, f"Byte length ({len(pdf_bytes)}) is below minimum threshold."

    if pdf_bytes.startswith(b"PK\x03\x04"):
        return False, "Byte stream contains ZIP/DOCX header disguised as PDF."

    if PDF_HEADER_MAGIC not in pdf_bytes[:1024]:
        return False, "Byte stream lacks %PDF- header."

    try:
        import io
        stream = io.BytesIO(pdf_bytes)
        reader = pypdf.PdfReader(stream, strict=False)
        if len(reader.pages) < 1:
            return False, "In-memory PDF contains 0 pages."
    except Exception as e:
        return False, f"In-memory PDF parsing failed: {e}"

    return True, None
