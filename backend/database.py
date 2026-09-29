import os
import sqlite3
import json
import logging
import uuid
import threading
import base64
import re
import shutil
import hashlib
import hmac
import secrets
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timedelta

logger = logging.getLogger("vapt_db")

ENVIRONMENT = os.environ.get("ENVIRONMENT", "").strip().lower()
IS_RENDER = os.environ.get("RENDER", "").strip().lower() == "true"
IS_PRODUCTION = (ENVIRONMENT in ("production", "prod")) or IS_RENDER

db_path_env = os.environ.get("TRACEGATE_DB_PATH") or os.environ.get("DATABASE_PATH")
if db_path_env:
    DB_PATH = Path(db_path_env)
    DB_DIR = DB_PATH.parent
    DB_DIR.mkdir(parents=True, exist_ok=True)
else:
    DB_DIR = Path(__file__).resolve().parent.parent / "data"
    DB_DIR.mkdir(parents=True, exist_ok=True)
    DB_PATH = DB_DIR / "tracegate.db"

DATABASE_URL = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

IS_POSTGRES = bool(DATABASE_URL and DATABASE_URL.startswith("postgresql://"))

def get_database_url() -> Optional[str]:
    url = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL") or DATABASE_URL
    if url and url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    return url

def is_production_mode() -> bool:
    env = os.environ.get("ENVIRONMENT", "").strip().lower()
    is_rnd = os.environ.get("RENDER", "").strip().lower() == "true"
    return (env in ("production", "prod")) or is_rnd or IS_PRODUCTION

def is_postgres_configured() -> bool:
    url = get_database_url()
    return bool(url and url.startswith("postgresql://"))


class CompatibleRow:
    """Row wrapper providing both dictionary and positional access, matching sqlite3.Row."""
    def __init__(self, description, values):
        self._keys = [d[0] for d in description] if description else []
        self._values = list(values)
        self._mapping = dict(zip(self._keys, self._values))

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return self._mapping[key]

    def get(self, key, default=None):
        return self._mapping.get(key, default)

    def keys(self):
        return self._keys

    def values(self):
        return self._values

    def items(self):
        return self._mapping.items()

    def __iter__(self):
        return iter(self._keys)

    def __len__(self):
        return len(self._keys)

    def __contains__(self, key):
        return key in self._mapping

    def __repr__(self):
        return f"<CompatibleRow {self._mapping}>"

def _replace_placeholders(sql: str) -> str:
    """Replace '?' with '%s' in SQL queries, ignoring string literals."""
    tokens = []
    in_single_quote = False
    in_double_quote = False
    for ch in sql:
        if ch == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
            tokens.append(ch)
        elif ch == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
            tokens.append(ch)
        elif ch == '?' and not in_single_quote and not in_double_quote:
            tokens.append('%s')
        else:
            tokens.append(ch)
    return "".join(tokens)

def _translate_sqlite_to_postgres(sql: str) -> str:
    cleaned = sql.strip()

    # PRAGMAs
    if re.match(r"(?i)^PRAGMA\s+foreign_keys", cleaned):
        return "SELECT 1"
    if re.match(r"(?i)^PRAGMA\s+journal_mode", cleaned):
        return "SELECT 1"
    if re.match(r"(?i)^PRAGMA\s+busy_timeout", cleaned):
        return "SELECT 1"

    m_info = re.match(r"(?i)^PRAGMA\s+table_info\((['\"]?)([a-zA-Z0-9_]+)\1\)", cleaned)
    if m_info:
        tbl = m_info.group(2).lower()
        return f"SELECT column_name AS name FROM information_schema.columns WHERE LOWER(table_name) = '{tbl}'"

    # sqlite_master queries
    if "sqlite_master" in cleaned.lower():
        return "SELECT '' AS sql WHERE 1=0"

    # SQLite datetime('now') -> CURRENT_TIMESTAMP
    cleaned = re.sub(r"(?i)datetime\(\s*['\"]now['\"]\s*\)", "CURRENT_TIMESTAMP", cleaned)

    # INSERT OR IGNORE INTO -> INSERT INTO ... ON CONFLICT DO NOTHING
    if re.search(r"(?i)INSERT\s+OR\s+IGNORE\s+INTO", cleaned):
        cleaned = re.sub(r"(?i)INSERT\s+OR\s+IGNORE\s+INTO", "INSERT INTO", cleaned)
        cleaned = cleaned.rstrip("; \t\n") + " ON CONFLICT DO NOTHING"

    return _replace_placeholders(cleaned)

class PostgresCursorWrapper:
    def __init__(self, raw_cursor):
        self.raw_cursor = raw_cursor

    def execute(self, sql: str, params=None):
        translated = _translate_sqlite_to_postgres(sql)
        if params is not None:
            if not isinstance(params, (list, tuple)):
                params = (params,)
            return self.raw_cursor.execute(translated, params)
        else:
            return self.raw_cursor.execute(translated)

    def executemany(self, sql: str, seq_of_params):
        translated = _translate_sqlite_to_postgres(sql)
        return self.raw_cursor.executemany(translated, seq_of_params)

    def fetchone(self):
        row = self.raw_cursor.fetchone()
        if row is None:
            return None
        return CompatibleRow(self.raw_cursor.description, row)

    def fetchall(self):
        desc = self.raw_cursor.description
        return [CompatibleRow(desc, r) for r in self.raw_cursor.fetchall()]

    def fetchmany(self, size=None):
        desc = self.raw_cursor.description
        rows = self.raw_cursor.fetchmany(size) if size else self.raw_cursor.fetchmany()
        return [CompatibleRow(desc, r) for r in rows]

    def close(self):
        return self.raw_cursor.close()

    @property
    def rowcount(self):
        return self.raw_cursor.rowcount

    @property
    def description(self):
        return self.raw_cursor.description

    def __iter__(self):
        desc = self.raw_cursor.description
        for row in self.raw_cursor:
            yield CompatibleRow(desc, row)

class PostgresConnectionWrapper:
    def __init__(self, raw_conn, pool=None):
        self.raw_conn = raw_conn
        self.pool = pool
        self.row_factory = None
        self._closed = False

    def cursor(self):
        return PostgresCursorWrapper(self.raw_conn.cursor())

    def execute(self, sql: str, params=None):
        cur = self.cursor()
        cur.execute(sql, params)
        return cur

    def commit(self):
        return self.raw_conn.commit()

    def rollback(self):
        return self.raw_conn.rollback()

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self.pool is not None:
            try:
                if not self.raw_conn.closed:
                    self.raw_conn.rollback()
            except Exception:
                pass
            try:
                self.pool.putconn(self.raw_conn)
            except Exception as e:
                logger.warning(f"Error returning connection to pool: {e}")
        else:
            try:
                self.raw_conn.close()
            except Exception:
                pass


_pg_pool = None
_pg_pool_lock = threading.Lock()

def get_pg_pool():
    global _pg_pool
    if _pg_pool is None:
        with _pg_pool_lock:
            if _pg_pool is None:
                import psycopg2
                from psycopg2 import pool
                db_url = get_database_url()
                if not db_url:
                    raise RuntimeError("DATABASE_URL / POSTGRES_URL is not configured for PostgreSQL pool.")
                
                conn_kwargs = {}
                # Enforce sslmode=require for non-local hosts (Render, AWS, Supabase, Neon) unless explicitly set
                if "sslmode=" not in db_url and not any(h in db_url for h in ["localhost", "127.0.0.1", "testserver"]):
                    conn_kwargs["sslmode"] = "require"

                max_conn = int(os.environ.get("DB_POOL_MAX", "20"))
                min_conn = int(os.environ.get("DB_POOL_MIN", "1"))
                try:
                    _pg_pool = pool.ThreadedConnectionPool(min_conn, max_conn, db_url, **conn_kwargs)
                    logger.info(f"PostgreSQL connection pool initialized (min={min_conn}, max={max_conn})")
                except Exception as e:
                    if "sslmode" in conn_kwargs:
                        try:
                            _pg_pool = pool.ThreadedConnectionPool(min_conn, max_conn, db_url)
                            logger.info(f"PostgreSQL connection pool initialized without sslmode (min={min_conn}, max={max_conn})")
                        except Exception as e2:
                            logger.error(f"Failed to initialize PostgreSQL connection pool: {e2}")
                            raise e2
                    else:
                        logger.error(f"Failed to initialize PostgreSQL connection pool: {e}")
                        raise e
    return _pg_pool

def close_all_connections():
    global _pg_pool
    if _pg_pool is not None:
        try:
            _pg_pool.closeall()
            logger.info("All PostgreSQL pool connections closed.")
        except Exception as e:
            logger.warning(f"Error closing PostgreSQL connection pool: {e}")
        _pg_pool = None

def get_db_connection():
    # 1. Enforce strict production safety: Never run ephemeral SQLite in production
    if is_production_mode() and not is_postgres_configured():
        msg = (
            "CRITICAL CONFIGURATION ERROR: Production environment detected (RENDER=true or ENVIRONMENT=production), "
            "but DATABASE_URL / POSTGRES_URL is not configured. Ephemeral local SQLite is strictly prohibited in "
            "production to prevent project and user data loss across container redeployments."
        )
        logger.critical(msg)
        raise RuntimeError(msg)

    # 2. PostgreSQL persistent connection via connection pool
    if is_postgres_configured():
        try:
            pool = get_pg_pool()
            raw_conn = pool.getconn()
            if raw_conn.closed:
                pool.putconn(raw_conn, close=True)
                raw_conn = pool.getconn()
            else:
                try:
                    with raw_conn.cursor() as test_cur:
                        test_cur.execute("SELECT 1")
                except Exception:
                    try:
                        pool.putconn(raw_conn, close=True)
                    except Exception:
                        pass
                    raw_conn = pool.getconn()
            return PostgresConnectionWrapper(raw_conn, pool=pool)
        except Exception as e:
            logger.error(f"Failed to connect to PostgreSQL at DATABASE_URL: {e}")
            if is_production_mode() or os.environ.get("STRICT_DB", "").lower() in ("true", "1"):
                raise RuntimeError(
                    f"CRITICAL: Failed to connect to production PostgreSQL database at DATABASE_URL: {e}. "
                    "Refusing silent fallback to ephemeral SQLite to prevent data loss."
                ) from e
            raise RuntimeError(
                f"Failed to connect to configured PostgreSQL database: {e}. "
                "Check DATABASE_URL or unset it to use local SQLite development."
            ) from e

    # 3. Development SQLite connection
    conn = sqlite3.connect(str(DB_PATH), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn

def normalize_severity(raw_sev: Any) -> str:
    """Normalize arbitrary severity strings or priority levels (e.g. P1, P-1, CRIT, SEV-1) to standard 5 levels."""
    if not raw_sev:
        return "HIGH"
    s = str(raw_sev).strip().upper()
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

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Projects table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS projects (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        target_url TEXT NOT NULL,
        description TEXT,
        scope_notes TEXT,
        environment TEXT DEFAULT 'Web Application (Staging)',
        status TEXT DEFAULT 'IN_PROGRESS',
        created_by TEXT DEFAULT 'Security Learner',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        owner_id TEXT
    )
    """)

    # Projects column migrations
    cursor.execute("PRAGMA table_info(projects)")
    existing_proj_cols = [r["name"] for r in cursor.fetchall()]
    if "owner_id" not in existing_proj_cols:
        cursor.execute("ALTER TABLE projects ADD COLUMN owner_id TEXT")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_projects_owner_id ON projects(owner_id)")

    # 2. Screenshots table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS screenshots (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        filename TEXT NOT NULL,
        file_path TEXT,
        page_type TEXT,
        confidence REAL DEFAULT 0.0,
        created_at TEXT NOT NULL,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
    )
    """)

    # 3. Checklists table (active analysis metadata per project)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS checklists (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        screenshot_id TEXT,
        page_type TEXT NOT NULL,
        confidence REAL DEFAULT 0.0,
        detected_elements_json TEXT,
        detected_functionalities_json TEXT,
        ambiguity_notes TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
    )
    """)

    # 4. Checklist items table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS checklist_items (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        checklist_id TEXT,
        test_id TEXT NOT NULL,
        name TEXT NOT NULL,
        priority TEXT NOT NULL,
        reason TEXT NOT NULL,
        testing_objective TEXT NOT NULL,
        cwe TEXT,
        source TEXT DEFAULT 'AI',
        status TEXT DEFAULT 'NOT_TESTED',
        sort_order INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
    )
    """)

    # 5. Findings table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        checklist_item_id TEXT,
        finding_name TEXT NOT NULL,
        description TEXT,
        testing_notes TEXT,
        poc_text TEXT,
        evidence_filename TEXT,
        evidence_data TEXT,
        priority TEXT DEFAULT 'HIGH',
        cwe TEXT,
        cvss_score REAL DEFAULT 7.5,
        impact TEXT,
        reproduction_steps TEXT,
        remediation TEXT,
        mitigation TEXT,
        status TEXT DEFAULT 'Open',
        recorded_at TEXT NOT NULL,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
    )
    """)

    # Column migrations for existing findings table if columns missing
    cursor.execute("PRAGMA table_info(findings)")
    existing_finding_cols = [r["name"] for r in cursor.fetchall()]
    for col_name, col_def in [
        ("vuln_id", "TEXT"),
        ("severity_source", "TEXT DEFAULT 'AI'"),
        ("affected_url", "TEXT"),
        ("affected_endpoint", "TEXT"),
        ("affected_component", "TEXT"),
        ("cwe", "TEXT"),
        ("cvss_score", "REAL DEFAULT 7.5"),
        ("impact", "TEXT"),
        ("reproduction_steps", "TEXT"),
        ("remediation", "TEXT"),
        ("mitigation", "TEXT"),
        ("status", "TEXT DEFAULT 'Open'"),
        ("fix_status", "TEXT DEFAULT 'NOT_STARTED'"),
        ("github_repo", "TEXT"),
        ("github_branch", "TEXT"),
        ("github_commit", "TEXT"),
        ("github_pr", "TEXT"),
        ("github_validation", "TEXT"),
        ("ai_fix_json", "TEXT"),
        ("observation", "TEXT"),
        ("evidence_json", "TEXT"),
        ("source", "TEXT DEFAULT 'CHECKLIST'"),
        ("source_document_id", "TEXT"),
        ("source_document_name", "TEXT"),
        ("retest_status", "TEXT DEFAULT 'PENDING'"),
        ("retest_notes", "TEXT"),
        ("retested_at", "TEXT")
    ]:
        if col_name not in existing_finding_cols:
            cursor.execute(f"ALTER TABLE findings ADD COLUMN {col_name} {col_def}")

    # 5b. User GitHub configurations table (secure server-side storage)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_github_configs (
        user_id TEXT PRIMARY KEY,
        token TEXT,
        mode TEXT DEFAULT 'mock',
        username TEXT,
        updated_at TEXT NOT NULL
    )
    """)

    # 5c. AI Fixes & GitHub code remediation tracking table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ai_fixes (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        finding_id TEXT NOT NULL,
        repository TEXT NOT NULL,
        base_branch TEXT NOT NULL DEFAULT 'main',
        fix_branch TEXT NOT NULL,
        file_path TEXT NOT NULL,
        file_sha TEXT,
        commit_sha TEXT,
        commit_message TEXT,
        pr_number INTEGER,
        pr_url TEXT,
        pr_status TEXT DEFAULT 'Open',
        diff_unified TEXT,
        original_code TEXT,
        proposed_code TEXT,
        changes_json TEXT,
        explanation TEXT,
        security_impact TEXT,
        testing_recommendation TEXT,
        retest_checklist_json TEXT,
        retest_status TEXT DEFAULT 'PENDING',
        retest_notes TEXT,
        retested_at TEXT,
        status TEXT DEFAULT 'PROPOSED',
        revision_count INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
        FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
    )
    """)

    # 5d. Source discovery & multi-file mapping tracking table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS source_discovery_results (
        id TEXT PRIMARY KEY,
        project_id TEXT,
        finding_id TEXT NOT NULL,
        repository TEXT NOT NULL,
        branch TEXT NOT NULL DEFAULT 'main',
        source_commit_sha TEXT NOT NULL DEFAULT 'main',
        selected_sources_json TEXT NOT NULL,
        candidate_sources_json TEXT NOT NULL,
        selection_source TEXT DEFAULT 'AUTOMATIC',
        discovery_status TEXT DEFAULT 'COMPLETED',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """)

    # 5e. AI AutoFix Remediation Runs & Execution Lifecycle Tracking
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS remediation_runs (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        repository TEXT NOT NULL,
        branch TEXT NOT NULL DEFAULT 'main',
        finding_ids_json TEXT NOT NULL DEFAULT '[]',
        status TEXT NOT NULL DEFAULT 'RUN_CREATED',
        current_stage TEXT NOT NULL DEFAULT 'INITIALIZING',
        progress_stage TEXT NOT NULL DEFAULT '1/4',
        progress_message TEXT NOT NULL DEFAULT '',
        started_at TEXT NOT NULL,
        finished_at TEXT,
        updated_at TEXT NOT NULL,
        result_json TEXT,
        errors_json TEXT,
        is_active INTEGER NOT NULL DEFAULT 1
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_remediation_runs_proj_user ON remediation_runs (project_id, user_id, is_active)")

    # 6. Reports table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reports (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        version TEXT NOT NULL,
        report_title TEXT NOT NULL,
        file_path TEXT NOT NULL,
        total_findings INTEGER DEFAULT 0,
        crit_count INTEGER DEFAULT 0,
        high_count INTEGER DEFAULT 0,
        med_count INTEGER DEFAULT 0,
        low_count INTEGER DEFAULT 0,
        info_count INTEGER DEFAULT 0,
        selected_finding_ids TEXT,
        created_by TEXT DEFAULT 'Security Learner',
        created_at TEXT NOT NULL,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
    )
    """)

    cursor.execute("PRAGMA table_info(reports)")
    existing_report_cols = [r["name"] for r in cursor.fetchall()]
    for col_name, col_def in [
        ("info_count", "INTEGER DEFAULT 0"),
        ("selected_finding_ids", "TEXT"),
        ("methodology", "TEXT DEFAULT 'owasp_wstg'"),
        ("metadata_json", "TEXT"),
        ("file_path_pdf", "TEXT"),
        ("file_data_docx", "TEXT"),
        ("file_data_pdf", "TEXT"),
    ]:
        if col_name not in existing_report_cols:
            cursor.execute(f"ALTER TABLE reports ADD COLUMN {col_name} {col_def}")

    # 6b. VAPT Assessment Completion Certificates table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vapt_certificates (
        certificate_id TEXT PRIMARY KEY,
        verification_id TEXT UNIQUE NOT NULL,
        project_id TEXT NOT NULL,
        assessment_id TEXT NOT NULL,
        report_id TEXT,
        status TEXT NOT NULL DEFAULT 'VALID',
        issue_date TEXT NOT NULL,
        assessment_start TEXT,
        assessment_end TEXT,
        final_validation_date TEXT NOT NULL,
        total_findings INTEGER NOT NULL,
        critical_count INTEGER DEFAULT 0,
        high_count INTEGER DEFAULT 0,
        medium_count INTEGER DEFAULT 0,
        low_count INTEGER DEFAULT 0,
        info_count INTEGER DEFAULT 0,
        findings_retested INTEGER NOT NULL,
        findings_passed INTEGER NOT NULL,
        findings_failed INTEGER NOT NULL DEFAULT 0,
        target_name TEXT NOT NULL,
        target_url TEXT NOT NULL,
        client_organization TEXT DEFAULT 'Not Provided',
        assessment_type TEXT DEFAULT 'Web Application Penetration Test (VAPT)',
        assessment_scope TEXT,
        snapshot_json TEXT NOT NULL,
        file_path_docx TEXT,
        file_path_pdf TEXT,
        notice_seen INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
    )
    """)

    cursor.execute("PRAGMA table_info(vapt_certificates)")
    existing_cert_cols = [r["name"] for r in cursor.fetchall()]
    for col_name, col_def in [
        ("notice_seen", "INTEGER DEFAULT 0"),
        ("file_path_docx", "TEXT"),
        ("file_path_pdf", "TEXT"),
        ("file_data_docx", "TEXT"),
        ("file_data_pdf", "TEXT"),
    ]:
        if col_name not in existing_cert_cols:
            cursor.execute(f"ALTER TABLE vapt_certificates ADD COLUMN {col_name} {col_def}")

    cursor.execute("PRAGMA table_info(ai_fixes)")
    existing_fix_cols = [r["name"] for r in cursor.fetchall()]
    for col_name, col_def in [
        ("merge_commit_sha", "TEXT"),
        ("merged_at", "TEXT"),
        ("review_status", "TEXT DEFAULT 'PENDING'")
    ]:
        if col_name not in existing_fix_cols:
            cursor.execute(f"ALTER TABLE ai_fixes ADD COLUMN {col_name} {col_def}")

    # 7. Users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT DEFAULT 'Junior Pentester',
        created_at TEXT NOT NULL
    )
    """)

    # 8. Sessions table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    # 9. Password Resets table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS password_resets (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        token_hash TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used_at TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token_hash)")

    # 9b. Password Resets table OTP migrations
    cursor.execute("PRAGMA table_info(password_resets)")
    existing_pr_cols = [r["name"] for r in cursor.fetchall()]
    for col_name, col_def in [
        ("otp_hash", "TEXT"),
        ("attempts", "INTEGER DEFAULT 0"),
        ("consumed_at", "TEXT"),
        ("reset_token_hash", "TEXT"),
        ("verified_at", "TEXT"),
        ("email", "TEXT")
    ]:
        if col_name not in existing_pr_cols:
            cursor.execute(f"ALTER TABLE password_resets ADD COLUMN {col_name} {col_def}")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_password_resets_reset_token ON password_resets(reset_token_hash)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_password_resets_otp ON password_resets(user_id, otp_hash)")


    # 10. Users table 2FA column migrations
    cursor.execute("PRAGMA table_info(users)")
    existing_user_cols = [r["name"] for r in cursor.fetchall()]
    for col_name, col_def in [
        ("two_factor_enabled", "INTEGER DEFAULT 0"),
        ("two_factor_secret_encrypted", "TEXT"),
        ("two_factor_enabled_at", "TEXT"),
        ("two_factor_last_verified_at", "TEXT")
    ]:
        if col_name not in existing_user_cols:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}")

    # 11. Two-Factor Pending Enrollments table (unconfirmed setup secrets)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS two_factor_pending_enrollments (
        user_id TEXT PRIMARY KEY,
        secret_encrypted TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    # 12. Two-Factor Recovery Codes table (SHA-256 hashed single-use recovery codes)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS two_factor_recovery_codes (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        used_at TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_2fa_recovery_user ON two_factor_recovery_codes(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_2fa_recovery_hash ON two_factor_recovery_codes(user_id, code_hash)")

    # 13. Two-Factor Pending Logins table (temporary challenge tokens)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS two_factor_pending_logins (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        attempts INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_2fa_pending_logins_user ON two_factor_pending_logins(user_id)")

    # 14. Priority normalization migration (P1-P5 to standard CRITICAL-INFORMATIONAL)
    try:
        cursor.execute("UPDATE findings SET priority = 'CRITICAL' WHERE UPPER(TRIM(priority)) IN ('P1', 'P-1', 'CRIT', 'SEV1', 'SEV 1', 'SEV-1')")
        cursor.execute("UPDATE findings SET priority = 'HIGH' WHERE UPPER(TRIM(priority)) IN ('P2', 'P-2', 'SEV2', 'SEV 2', 'SEV-2')")
        cursor.execute("UPDATE findings SET priority = 'MEDIUM' WHERE UPPER(TRIM(priority)) IN ('P3', 'P-3', 'MED', 'SEV3', 'SEV 3', 'SEV-3')")
        cursor.execute("UPDATE findings SET priority = 'LOW' WHERE UPPER(TRIM(priority)) IN ('P4', 'P-4', 'SEV4', 'SEV 4', 'SEV-4')")
        cursor.execute("UPDATE findings SET priority = 'INFORMATIONAL' WHERE UPPER(TRIM(priority)) IN ('P5', 'P-5', 'INFO', 'SEV5', 'SEV 5', 'SEV-5')")

        cursor.execute("UPDATE checklist_items SET priority = 'CRITICAL' WHERE UPPER(TRIM(priority)) IN ('P1', 'P-1', 'CRIT', 'SEV1', 'SEV 1', 'SEV-1')")
        cursor.execute("UPDATE checklist_items SET priority = 'HIGH' WHERE UPPER(TRIM(priority)) IN ('P2', 'P-2', 'SEV2', 'SEV 2', 'SEV-2')")
        cursor.execute("UPDATE checklist_items SET priority = 'MEDIUM' WHERE UPPER(TRIM(priority)) IN ('P3', 'P-3', 'MED', 'SEV3', 'SEV 3', 'SEV-3')")
        cursor.execute("UPDATE checklist_items SET priority = 'LOW' WHERE UPPER(TRIM(priority)) IN ('P4', 'P-4', 'SEV4', 'SEV 4', 'SEV-4')")
        cursor.execute("UPDATE checklist_items SET priority = 'INFORMATIONAL' WHERE UPPER(TRIM(priority)) IN ('P5', 'P-5', 'INFO', 'SEV5', 'SEV 5', 'SEV-5')")
    except Exception as mig_err:
        logger.warning(f"Priority migration warning: {mig_err}")

    # 15. Evidence artifacts table (persistent server storage)
    cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='evidence'")
    ev_tbl_row = cursor.fetchone()
    if ev_tbl_row and "REFERENCES findings" in ev_tbl_row["sql"]:
        cursor.execute("DROP TABLE evidence")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS evidence (
        id TEXT PRIMARY KEY,
        evidence_id TEXT,
        finding_id TEXT,
        project_id TEXT NOT NULL,
        checklist_item_id TEXT,
        original_filename TEXT NOT NULL,
        stored_filename TEXT NOT NULL,
        mime_type TEXT NOT NULL,
        file_size INTEGER DEFAULT 0,
        storage_path TEXT NOT NULL,
        caption TEXT,
        description TEXT,
        uploaded_by TEXT,
        uploaded_at TEXT NOT NULL,
        status TEXT DEFAULT 'ACTIVE',
        file_data TEXT,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_evidence_project_id ON evidence(project_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_evidence_finding_id ON evidence(finding_id)")

    cursor.execute("PRAGMA table_info(evidence)")
    ev_cols = [r["name"] for r in cursor.fetchall()]
    if "file_data" not in ev_cols:
        cursor.execute("ALTER TABLE evidence ADD COLUMN file_data TEXT")

    # 16. Certificate Generation Jobs table (background asynchronous execution)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS certificate_jobs (
        job_id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        assessment_id TEXT,
        status TEXT NOT NULL DEFAULT 'GENERATING',
        certificate_id TEXT,
        error TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cert_jobs_project ON certificate_jobs(project_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cert_jobs_user ON certificate_jobs(user_id)")

    conn.commit()
    conn.close()
    logger.info(f"Database initialized at {DB_PATH}")

# =========================================================================
# PROJECT CRUD
# =========================================================================

_bulk_delete_lock = threading.Lock()

def get_all_projects(owner_id: Optional[str] = None, is_admin: bool = False) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    if is_admin or owner_id == "*":
        cursor.execute("SELECT * FROM projects ORDER BY updated_at DESC")
    elif owner_id is not None:
        cursor.execute("SELECT * FROM projects WHERE owner_id = ? ORDER BY updated_at DESC", (owner_id,))
    else:
        cursor.execute("SELECT * FROM projects ORDER BY updated_at DESC")
    rows = cursor.fetchall()
    projects = []
    for r in rows:
        p = dict(r)
        p["notes"] = p.get("scope_notes", "")
        # Fetch metrics
        metrics = get_project_metrics(p["id"], conn)
        p.update(metrics)
        projects.append(p)
    conn.close()
    return projects

def count_user_projects(owner_id: str) -> int:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM projects WHERE owner_id = ?", (owner_id,))
        row = cursor.fetchone()
        return row[0] if row else 0
    finally:
        conn.close()

def get_project_by_id(project_id: str, owner_id: Optional[str] = None, is_admin: bool = False) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None
    proj = dict(row)
    if owner_id and not is_admin:
        if proj.get("owner_id") != owner_id:
            conn.close()
            return None
    proj["notes"] = proj.get("scope_notes", "")
    proj.update(get_project_metrics(project_id, conn))
    
    # Also fetch active checklist items and findings
    proj["checklist"] = get_project_checklist_items(project_id, conn)
    proj["findings"] = get_project_findings_list(project_id, conn)
    conn.close()
    return proj

def create_project(data: Dict[str, Any], owner_id: Optional[str] = None) -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    proj_id = data.get("id") or f"proj-{int(datetime.now().timestamp()*1000)}"
    notes_val = data.get("scope_notes") or data.get("notes", "")
    assigned_owner = owner_id or data.get("owner_id") or "user-learner-001"
    cursor.execute("""
    INSERT INTO projects (id, name, target_url, description, scope_notes, environment, status, created_by, created_at, updated_at, owner_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        proj_id,
        data.get("name", "Untitled Project"),
        data.get("target_url", "https://target.app"),
        data.get("description", ""),
        notes_val,
        data.get("environment", "Web Application (Staging)"),
        data.get("status", "IN_PROGRESS"),
        data.get("created_by", "Security Learner"),
        data.get("created_at", now),
        now,
        assigned_owner
    ))
    conn.commit()
    conn.close()
    return get_project_by_id(proj_id)

def update_project(project_id: str, data: Dict[str, Any], owner_id: Optional[str] = None, is_admin: bool = False) -> Optional[Dict[str, Any]]:
    current = get_project_by_id(project_id, owner_id=owner_id, is_admin=is_admin)
    if not current:
        return None

    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # If notes passed instead of scope_notes, normalize
    if "notes" in data and "scope_notes" not in data:
        data["scope_notes"] = data["notes"]
        
    fields = []
    vals = []
    # Note: owner_id is strictly immutable in standard project updates
    for k in ["name", "target_url", "description", "scope_notes", "environment", "status"]:
        if k in data and data[k] is not None:
            fields.append(f"{k} = ?")
            vals.append(data[k])
    if fields:
        fields.append("updated_at = ?")
        vals.append(now)
        vals.append(project_id)
        cursor.execute(f"UPDATE projects SET {', '.join(fields)} WHERE id = ?", vals)
        conn.commit()
    conn.close()
    return get_project_by_id(project_id)

def delete_project(project_id: str, owner_id: Optional[str] = None, is_admin: bool = False) -> bool:
    current = get_project_by_id(project_id, owner_id=owner_id, is_admin=is_admin)
    if not current:
        return False

    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Clean up physical report files (.docx, .pdf) from disk
    try:
        cursor.execute("SELECT file_path FROM reports WHERE project_id = ?", (project_id,))
        for row in cursor.fetchall():
            fp = row["file_path"] if isinstance(row, sqlite3.Row) or isinstance(row, dict) else row[0]
            if fp and os.path.exists(fp):
                try:
                    os.remove(fp)
                    logger.info(f"Deleted physical report file on project deletion: {fp}")
                except Exception as fe:
                    logger.warning(f"Could not remove report file {fp}: {fe}")
    except Exception as e:
        logger.warning(f"Error querying reports for file cleanup: {e}")

    # 2. Clean up physical certificate files (.docx, .pdf) from disk
    try:
        cursor.execute("SELECT file_path_docx, file_path_pdf FROM vapt_certificates WHERE project_id = ?", (project_id,))
        for row in cursor.fetchall():
            for col in ["file_path_docx", "file_path_pdf"]:
                try:
                    fp = row[col] if (isinstance(row, sqlite3.Row) or isinstance(row, dict)) and col in row.keys() else None
                except Exception:
                    fp = None
                if fp and os.path.exists(fp):
                    try:
                        os.remove(fp)
                        logger.info(f"Deleted physical certificate file on project deletion: {fp}")
                    except Exception as fe:
                        logger.warning(f"Could not remove certificate file {fp}: {fe}")
    except Exception as e:
        logger.warning(f"Error querying certificates for file cleanup: {e}")

    # 3. Clean up any attached evidence files on disk & directory
    try:
        ev_dir = Path(__file__).resolve().parent.parent / "data" / "evidence" / str(project_id)
        if ev_dir.exists() and ev_dir.is_dir():
            shutil.rmtree(ev_dir, ignore_errors=True)
            logger.info(f"Deleted physical evidence directory on project deletion: {ev_dir}")
        cursor.execute("SELECT evidence_filename FROM findings WHERE project_id = ?", (project_id,))
        for row in cursor.fetchall():
            ef = row["evidence_filename"] if isinstance(row, sqlite3.Row) or isinstance(row, dict) else row[0]
            if ef and os.path.exists(ef):
                try:
                    os.remove(ef)
                except Exception:
                    pass
    except Exception as ev_err:
        logger.warning(f"Error cleaning up evidence files: {ev_err}")

    # 4. Clean up source discovery tracking records & evidence metadata
    try:
        cursor.execute("DELETE FROM source_discovery_results WHERE project_id = ?", (project_id,))
    except Exception:
        pass
    try:
        cursor.execute("DELETE FROM evidence WHERE project_id = ?", (project_id,))
    except Exception:
        pass

    # 5. Cascading delete from database
    cursor.execute("PRAGMA foreign_keys = ON")
    cursor.execute("DELETE FROM projects WHERE id = ?", (project_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def bulk_delete_user_projects(owner_id: str) -> Dict[str, Any]:
    """
    Safely delete all projects owned by the specified user, cascading through
    all child records, reports, certificates, evidence, and disk artifacts.
    Protected with concurrency lock to prevent duplicate concurrent runs.
    """
    if not owner_id:
        return {"total": 0, "deleted": 0, "failed": 0, "skipped": 0, "remaining": 0, "failures": []}

    if not _bulk_delete_lock.acquire(blocking=False):
        raise RuntimeError("A project cleanup operation is currently in progress. Please wait.")

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, name FROM projects WHERE owner_id = ?", (owner_id,))
        rows = cursor.fetchall()
        conn.close()

        total = len(rows)
        deleted = 0
        failed = 0
        failures = []

        for row in rows:
            pid = row["id"] if isinstance(row, sqlite3.Row) or isinstance(row, dict) else row[0]
            try:
                success = delete_project(pid, owner_id=owner_id)
                if success:
                    deleted += 1
                else:
                    failed += 1
                    failures.append({"project_id": pid, "error": "Project not found or deletion returned false"})
            except Exception as ex:
                logger.error(f"Error during bulk deletion of project {pid}: {ex}")
                failed += 1
                failures.append({"project_id": pid, "error": str(ex)})

        return {
            "total": total,
            "deleted": deleted,
            "failed": failed,
            "skipped": 0,
            "remaining": total - deleted,
            "failures": failures
        }
    finally:
        _bulk_delete_lock.release()

def get_project_metrics(project_id: str, conn=None) -> Dict[str, Any]:
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM checklist_items WHERE project_id = ?", (project_id,))
    total_tests = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM checklist_items WHERE project_id = ? AND status != 'NOT_TESTED'", (project_id,))
    completed_tests = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM checklist_items WHERE project_id = ? AND status = 'VULNERABILITY_FOUND'", (project_id,))
    vulns_found = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM checklist_items WHERE project_id = ? AND status = 'TESTED_NOT_FOUND'", (project_id,))
    not_found = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM findings WHERE project_id = ?", (project_id,))
    total_findings = cursor.fetchone()[0]

    if close_conn:
        conn.close()

    remaining = max(0, total_tests - completed_tests)
    pct = round((completed_tests / total_tests * 100)) if total_tests > 0 else 0
    return {
        "total_tests": total_tests,
        "completed_tests": completed_tests,
        "vulns_found": vulns_found,
        "not_found": not_found,
        "remaining_tests": remaining,
        "progress_pct": pct,
        "total_findings": total_findings
    }

# =========================================================================
# CHECKLIST & ITEMS CRUD
# =========================================================================

def save_analysis_for_project(project_id: str, analysis_data: Dict[str, Any], filename: Optional[str] = None) -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. Record screenshot
    screenshot_id = f"shot-{int(datetime.now().timestamp()*1000)}"
    cursor.execute("""
    INSERT INTO screenshots (id, project_id, filename, page_type, confidence, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        screenshot_id,
        project_id,
        filename or "uploaded_screenshot.png",
        analysis_data.get("page_type", "Unknown / Ambiguous"),
        analysis_data.get("confidence", 0.0),
        now
    ))

    # 2. Record checklist container
    checklist_id = f"chk-{int(datetime.now().timestamp()*1000)}"
    cursor.execute("""
    INSERT INTO checklists (id, project_id, screenshot_id, page_type, confidence, detected_elements_json, detected_functionalities_json, ambiguity_notes, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        checklist_id,
        project_id,
        screenshot_id,
        analysis_data.get("page_type", "Unknown / Ambiguous"),
        analysis_data.get("confidence", 0.0),
        json.dumps(analysis_data.get("detected_elements", [])),
        json.dumps(analysis_data.get("detected_functionalities", []) or analysis_data.get("security_relevant_features", [])),
        analysis_data.get("ambiguity_notes"),
        now
    ))

    # 3. Replace or append checklist items
    # We clear prior items for this project to ensure freshness for the new screen
    cursor.execute("DELETE FROM checklist_items WHERE project_id = ?", (project_id,))

    items = analysis_data.get("checklist", [])
    for idx, item in enumerate(items):
        raw_id = item.get("id") or f"test-{idx}"
        item_id = f"{project_id}_{raw_id}"
        item["id"] = item_id
        cursor.execute("""
        INSERT INTO checklist_items (id, project_id, checklist_id, test_id, name, priority, reason, testing_objective, cwe, source, status, sort_order, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            item_id,
            project_id,
            checklist_id,
            raw_id,
            item.get("name", "Security Test"),
            item.get("priority", "MEDIUM"),
            item.get("reason", ""),
            item.get("testing_objective", ""),
            item.get("cwe"),
            item.get("source", "AI"),
            item.get("status", "NOT_TESTED"),
            idx,
            now
        ))

    # Touch project updated_at
    cursor.execute("UPDATE projects SET updated_at = ? WHERE id = ?", (now, project_id))
    conn.commit()
    conn.close()

    return get_project_by_id(project_id)

def get_project_checklist_items(project_id: str, conn=None) -> List[Dict[str, Any]]:
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True
    cursor = conn.cursor()
    cursor.execute("""
    SELECT ci.*, f.id as finding_id, f.finding_name, f.description as finding_desc, f.observation as finding_observation,
           f.poc_text, f.evidence_filename, f.evidence_data, f.evidence_json
    FROM checklist_items ci
    LEFT JOIN findings f ON ci.id = f.checklist_item_id
    WHERE ci.project_id = ?
    ORDER BY ci.sort_order ASC, ci.created_at ASC
    """, (project_id,))
    rows = cursor.fetchall()
    items = []
    for r in rows:
        d = dict(r)
        if d.get("finding_id"):
            ev_list = []
            if d.get("evidence_json"):
                try:
                    ev_list = json.loads(d["evidence_json"])
                except Exception:
                    ev_list = []
            if not ev_list and (d.get("evidence_filename") or d.get("evidence_data")):
                ev_list = [{
                    "name": d.get("evidence_filename") or "evidence.png",
                    "data": d.get("evidence_data"),
                    "type": "image/png"
                }]
            d["finding"] = {
                "id": d["finding_id"],
                "finding_name": d["finding_name"],
                "observation": d.get("finding_observation") or d.get("finding_desc") or "",
                "description": d.get("finding_desc") or d.get("finding_observation") or "",
                "poc_text": d["poc_text"],
                "evidence_filename": d["evidence_filename"],
                "evidence_data": d["evidence_data"],
                "evidence": ev_list
            }
        else:
            d["finding"] = None
        d["priority"] = normalize_severity(d.get("priority"))
        items.append(d)

    if close_conn:
        conn.close()
    return items

def update_checklist_item(item_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    fields = []
    vals = []
    for k in ["name", "priority", "reason", "testing_objective", "cwe"]:
        if k in data:
            fields.append(f"{k} = ?")
            if k == "priority":
                vals.append(normalize_severity(data[k]))
            else:
                vals.append(data[k])
    if fields:
        fields.append("source = 'USER_MODIFIED'")
        vals.append(item_id)
        cursor.execute(f"UPDATE checklist_items SET {', '.join(fields)} WHERE id = ?", vals)
        conn.commit()

    cursor.execute("SELECT * FROM checklist_items WHERE id = ?", (item_id,))
    row = cursor.fetchone()
    conn.close()
    res = dict(row) if row else None
    if res:
        res["priority"] = normalize_severity(res.get("priority"))
    return res

def update_item_status(item_id: str, status: str, project_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    if project_id:
        cursor.execute("UPDATE checklist_items SET status = ? WHERE id = ? AND project_id = ?", (status, item_id, project_id))
        if status == "TESTED_NOT_FOUND":
            cursor.execute("DELETE FROM findings WHERE checklist_item_id = ? AND project_id = ?", (item_id, project_id))
        cursor.execute("SELECT * FROM checklist_items WHERE id = ? AND project_id = ?", (item_id, project_id))
    else:
        cursor.execute("UPDATE checklist_items SET status = ? WHERE id = ?", (status, item_id))
        if status == "TESTED_NOT_FOUND":
            cursor.execute("DELETE FROM findings WHERE checklist_item_id = ?", (item_id,))
        cursor.execute("SELECT * FROM checklist_items WHERE id = ?", (item_id,))
    conn.commit()
    row = cursor.fetchone()
    conn.close()
    res = dict(row) if row else None
    if res:
        res["priority"] = normalize_severity(res.get("priority"))
    return res

def delete_checklist_item(item_id: str, project_id: Optional[str] = None) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    if project_id:
        cursor.execute("DELETE FROM findings WHERE checklist_item_id = ? AND project_id = ?", (item_id, project_id))
        cursor.execute("DELETE FROM checklist_items WHERE id = ? AND project_id = ?", (item_id, project_id))
    else:
        cursor.execute("DELETE FROM findings WHERE checklist_item_id = ?", (item_id,))
        cursor.execute("DELETE FROM checklist_items WHERE id = ?", (item_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def add_custom_checklist_item(project_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    item_id = f"custom-{int(datetime.now().timestamp()*1000)}"
    name = (data.get("name") or "Custom Security Test").strip()
    priority = normalize_severity(data.get("priority") or "HIGH")
    reason = (data.get("reason") or "").strip() or "Learner-defined custom test procedure."
    testing_objective = (data.get("testing_objective") or "").strip() or "Verify security control enforcement and validate expected behavior."
    cwe = (data.get("cwe") or "").strip()

    cursor.execute("""
    INSERT INTO checklist_items (id, project_id, checklist_id, test_id, name, priority, reason, testing_objective, cwe, source, status, sort_order, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'USER', 'NOT_TESTED', 0, ?)
    """, (
        item_id,
        project_id,
        None,
        item_id,
        name,
        priority,
        reason,
        testing_objective,
        cwe,
        now
    ))
    cursor.execute("UPDATE projects SET updated_at = ? WHERE id = ?", (now, project_id))
    conn.commit()
    cursor.execute("SELECT * FROM checklist_items WHERE id = ?", (item_id,))
    row = cursor.fetchone()
    conn.close()
    res = dict(row) if row else {}
    res["finding"] = None
    return res

# =========================================================================
# FINDINGS CRUD
# =========================================================================

def save_finding(project_id: Any, item_id: Optional[str] = None, finding_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    from backend.knowledge_base import get_finding_template_for_test

    if isinstance(project_id, dict):
        finding_data = project_id
        item_id = finding_data.get("checklist_item_id")
        project_id = finding_data.get("project_id")

    if finding_data is None:
        finding_data = {}

    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    finding_id = finding_data.get("id") or f"find-{int(datetime.now().timestamp()*1000)}"

    cursor.execute("SELECT COUNT(*) FROM findings WHERE project_id = ?", (project_id,))
    cnt = cursor.fetchone()[0]
    vuln_id = finding_data.get("vuln_id") or f"VULN-{cnt + 1:03d}"

    item_row = None
    if item_id:
        if project_id:
            cursor.execute("UPDATE checklist_items SET status = 'VULNERABILITY_FOUND' WHERE id = ? AND project_id = ?", (item_id, project_id))
            cursor.execute("DELETE FROM findings WHERE checklist_item_id = ? AND project_id = ?", (item_id, project_id))
            cursor.execute("SELECT * FROM checklist_items WHERE id = ? AND project_id = ?", (item_id, project_id))
            item_row = cursor.fetchone()
            if not item_row:
                cursor.execute("SELECT * FROM checklist_items WHERE test_id = ? AND project_id = ?", (item_id, project_id))
                item_row = cursor.fetchone()
        else:
            cursor.execute("UPDATE checklist_items SET status = 'VULNERABILITY_FOUND' WHERE id = ?", (item_id,))
            cursor.execute("DELETE FROM findings WHERE checklist_item_id = ?", (item_id,))
            cursor.execute("SELECT * FROM checklist_items WHERE id = ?", (item_id,))
            item_row = cursor.fetchone()

    # Automatic finding enrichment for any blank fields
    cwe_val = finding_data.get("cwe") or (item_row["cwe"] if item_row else None)
    name_val = finding_data.get("finding_name") or (item_row["name"] if item_row else "Confirmed Vulnerability")
    priority_val = normalize_severity(finding_data.get("priority") or finding_data.get("severity") or (item_row["priority"] if item_row else "HIGH"))
    severity_source_val = finding_data.get("severity_source") or "AI"

    tmpl = get_finding_template_for_test(item_id or name_val, test_name=name_val, cwe=cwe_val)

    observation_val = (finding_data.get("observation") or "").strip()
    desc_input = (finding_data.get("description") or "").strip()
    desc_val = observation_val or desc_input or tmpl.get("description", "")
    notes_val = finding_data.get("testing_notes") or tmpl.get("reproduction_steps", "")
    poc_val = finding_data.get("poc_text") or tmpl.get("poc_text", "")
    impact_val = finding_data.get("impact") or tmpl.get("impact", "")
    repro_val = finding_data.get("reproduction_steps") or tmpl.get("reproduction_steps", "")
    remed_val = finding_data.get("remediation") or tmpl.get("remediation", "")
    mitig_val = finding_data.get("mitigation") or tmpl.get("mitigation", "")
    raw_cvss = finding_data.get("cvss_score")
    if raw_cvss is None:
        raw_cvss = tmpl.get("cvss_score")
    cvss_val = None
    if raw_cvss is not None:
        try:
            cand_cvss = float(raw_cvss)
            from backend.report_model import is_cvss_consistent_with_severity
            if is_cvss_consistent_with_severity(cand_cvss, priority_val):
                cvss_val = cand_cvss
            else:
                logger.warning(f"Inconsistent CVSS {cand_cvss} for priority {priority_val} in finding '{name_val}'. Storing as None to prevent misleading severity contradiction.")
                cvss_val = None
        except Exception:
            cvss_val = None
    status_val = finding_data.get("status") or "Open"
    fix_status_val = finding_data.get("fix_status") or "NOT_STARTED"

    # Multi-file evidence handling & persistence
    evidence_items = finding_data.get("evidence") or []
    if not evidence_items and (finding_data.get("evidence_filename") or finding_data.get("evidence_data")):
        evidence_items = [{
            "name": finding_data.get("evidence_filename") or "evidence.png",
            "data": finding_data.get("evidence_data"),
            "type": "image/png"
        }]

    evidence_dir = Path(__file__).resolve().parent.parent / "data" / "evidence" / str(project_id)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    # Deduplicate input evidence items (Requirement 37: accidental duplicates)
    deduped_input_items = []
    seen_evidence_keys = set()
    for itm in evidence_items:
        if not isinstance(itm, dict):
            continue
        k = (
            itm.get("id"),
            itm.get("name") or itm.get("filename"),
            hashlib.sha256(str(itm.get("data") or "").encode("utf-8")).hexdigest() if itm.get("data") else itm.get("file_path")
        )
        if k in seen_evidence_keys:
            continue
        seen_evidence_keys.add(k)
        deduped_input_items.append(itm)
    evidence_items = deduped_input_items

    clean_evidence_items = []
    for idx, itm in enumerate(evidence_items):
        ev_id = itm.get("id") or f"ev-{uuid.uuid4().hex[:10]}"
        ev_ref = itm.get("evidence_id") or f"EV-{idx + 1:03d}"
        orig_name = itm.get("name") or itm.get("original_filename") or itm.get("filename") or "evidence.png"
        clean_base = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', Path(orig_name).name)
        stored_fn = itm.get("filename") or itm.get("stored_filename")
        if not stored_fn or stored_fn == orig_name:
            stored_fn = f"ev-{uuid.uuid4().hex[:8]}_{clean_base}"

        dest_path = Path(itm.get("file_path")) if itm.get("file_path") else (evidence_dir / stored_fn)
        size_bytes = itm.get("size") or itm.get("file_size") or 0
        raw_data = itm.get("data")

        # If data is a base64 string, persist to disk if not already existing
        if raw_data and isinstance(raw_data, str) and (raw_data.startswith("data:") or len(raw_data) > 100):
            try:
                b64_part = raw_data.split(",", 1)[1] if "," in raw_data else raw_data
                b_content = base64.b64decode(b64_part)
                if not dest_path.exists() or dest_path.stat().st_size == 0:
                    dest_path.write_bytes(b_content)
                size_bytes = len(b_content)
            except Exception as b64_err:
                logger.warning(f"Error decoding base64 evidence: {b64_err}")

        # If file exists on disk and size is 0, update size
        if dest_path.exists() and size_bytes == 0:
            try:
                size_bytes = dest_path.stat().st_size
            except Exception:
                pass

        rel_url = itm.get("url") or f"/api/projects/{project_id}/evidence/{stored_fn}"
        mime_type = itm.get("type") or itm.get("mime_type") or "image/png"

        # Record metadata into evidence table
        ev_file_data = itm.get("data") or itm.get("file_data") or ""
        try:
            cursor.execute("""
            INSERT INTO evidence (
                id, evidence_id, finding_id, project_id, checklist_item_id,
                original_filename, stored_filename, mime_type, file_size, storage_path,
                caption, description, uploaded_by, uploaded_at, status, file_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (id) DO UPDATE SET
                evidence_id = EXCLUDED.evidence_id,
                finding_id = EXCLUDED.finding_id,
                project_id = EXCLUDED.project_id,
                checklist_item_id = EXCLUDED.checklist_item_id,
                original_filename = EXCLUDED.original_filename,
                stored_filename = EXCLUDED.stored_filename,
                mime_type = EXCLUDED.mime_type,
                file_size = EXCLUDED.file_size,
                storage_path = EXCLUDED.storage_path,
                caption = EXCLUDED.caption,
                description = EXCLUDED.description,
                uploaded_by = EXCLUDED.uploaded_by,
                uploaded_at = EXCLUDED.uploaded_at,
                status = EXCLUDED.status,
                file_data = CASE WHEN EXCLUDED.file_data IS NOT NULL AND EXCLUDED.file_data != '' THEN EXCLUDED.file_data ELSE evidence.file_data END
            """, (
                ev_id,
                ev_ref,
                finding_id,
                str(project_id),
                item_id,
                orig_name,
                stored_fn,
                mime_type,
                size_bytes,
                str(dest_path),
                itm.get("caption") or "",
                itm.get("description") or "",
                finding_data.get("uploaded_by") or "user",
                now,
                "ACTIVE",
                ev_file_data
            ))
        except Exception as ev_insert_err:
            logger.warning(f"Error inserting evidence record: {ev_insert_err}")

        clean_item = {
            "id": ev_id,
            "evidence_id": ev_ref,
            "name": orig_name,
            "filename": stored_fn,
            "file_path": str(dest_path),
            "size": size_bytes,
            "mime_type": mime_type,
            "type": mime_type,
            "url": rel_url,
            "caption": itm.get("caption") or "",
            "status": "ACTIVE"
        }
        # Retain tiny data only for unit test assertions (if len < 512)
        if raw_data and len(str(raw_data)) < 512:
            clean_item["data"] = raw_data
        clean_evidence_items.append(clean_item)

    # Link any previously uploaded unassociated evidence for this project with matching filenames
    if clean_evidence_items:
        try:
            for ci in clean_evidence_items:
                cursor.execute("""
                UPDATE evidence
                SET finding_id = ?, checklist_item_id = ?
                WHERE project_id = ? AND (finding_id IS NULL OR finding_id = '')
                  AND (stored_filename = ? OR original_filename = ? OR id = ?)
                """, (finding_id, item_id, str(project_id), ci["filename"], ci["name"], ci["id"]))
        except Exception as link_err:
            logger.warning(f"Error linking unassociated evidence: {link_err}")

    first_ef = clean_evidence_items[0]["name"] if clean_evidence_items else finding_data.get("evidence_filename")
    first_ed = clean_evidence_items[0].get("url") or clean_evidence_items[0].get("filename") if clean_evidence_items else finding_data.get("evidence_data")
    if clean_evidence_items and clean_evidence_items[0].get("data"):
        first_ed = clean_evidence_items[0]["data"]

    evidence_json_str = json.dumps(clean_evidence_items)

    source_val = finding_data.get("source") or "CHECKLIST"
    source_doc_id = finding_data.get("source_document_id")
    source_doc_name = finding_data.get("source_document_name")
    retest_status_val = finding_data.get("retest_status") or "PENDING"
    retest_notes_val = finding_data.get("retest_notes") or ""

    cursor.execute("""
    INSERT INTO findings (
        id, project_id, checklist_item_id, vuln_id, finding_name, severity_source,
        affected_url, affected_endpoint, affected_component, description, observation, testing_notes,
        poc_text, evidence_filename, evidence_data, evidence_json, priority, cwe, cvss_score,
        impact, reproduction_steps, remediation, mitigation, status, fix_status,
        github_repo, github_branch, github_commit, github_pr, github_validation,
        source, source_document_id, source_document_name, retest_status, retest_notes, recorded_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        finding_id,
        project_id,
        item_id,
        vuln_id,
        name_val,
        severity_source_val,
        finding_data.get("affected_url") or finding_data.get("target_url"),
        finding_data.get("affected_endpoint") or finding_data.get("endpoint") or finding_data.get("component"),
        finding_data.get("affected_component") or finding_data.get("component"),
        desc_val,
        observation_val or desc_val,
        notes_val,
        poc_val,
        first_ef,
        first_ed,
        evidence_json_str,
        priority_val,
        cwe_val or tmpl.get("cwe", "CWE-200"),
        cvss_val,
        impact_val,
        repro_val,
        remed_val,
        mitig_val,
        status_val,
        fix_status_val,
        finding_data.get("github_repo"),
        finding_data.get("github_branch"),
        finding_data.get("github_commit"),
        finding_data.get("github_pr"),
        finding_data.get("github_validation"),
        source_val,
        source_doc_id,
        source_doc_name,
        retest_status_val,
        retest_notes_val,
        now
    ))

    cursor.execute("UPDATE projects SET updated_at = ? WHERE id = ?", (now, project_id))
    conn.commit()
    cursor.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
    row = cursor.fetchone()
    conn.close()
    d = dict(row)
    ev_list = []
    if d.get("evidence_json"):
        try:
            ev_list = json.loads(d["evidence_json"])
        except Exception:
            ev_list = []
    if not ev_list and (d.get("evidence_filename") or d.get("evidence_data")):
        ev_list = [{"name": d.get("evidence_filename") or "evidence.png", "data": d.get("evidence_data"), "type": "image/png"}]
    d["evidence"] = ev_list
    d["observation"] = d.get("observation") or d.get("description") or ""
    d["source"] = d.get("source") or "CHECKLIST"
    d["source_document_id"] = d.get("source_document_id")
    d["source_document_name"] = d.get("source_document_name")
    d["retest_status"] = d.get("retest_status") or "PENDING"
    d["retest_notes"] = d.get("retest_notes") or ""
    d["github_fix"] = {
        "repository": d.get("github_repo"),
        "branch": d.get("github_branch"),
        "commit": d.get("github_commit"),
        "pull_request": d.get("github_pr"),
        "pr_url": d.get("github_pr"),
        "validation_status": d.get("github_validation")
    }
    d["ai_fix"] = d["github_fix"]
    d["priority"] = normalize_severity(d.get("priority"))
    d["severity"] = d["priority"]
    return d

def save_imported_findings(
    project_id: str,
    candidate_findings: List[Dict[str, Any]],
    source_doc_id: Optional[str] = None,
    source_doc_name: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Persist confirmed candidate findings from an external VAPT report into the project's authoritative findings.
    Assigns unique finding IDs, establishes traceable provenance, and updates project timestamps.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()

    cursor.execute("SELECT COUNT(*) FROM findings WHERE project_id = ?", (project_id,))
    existing_count = cursor.fetchone()[0]

    imported_records = []
    for idx, cand in enumerate(candidate_findings):
        fid = cand.get("id") or f"find-import-{int(datetime.now().timestamp() * 1000)}-{uuid.uuid4().hex[:6]}"
        vuln_id = f"VULN-{existing_count + idx + 1:03d}"
        name = (cand.get("title") or cand.get("finding_name") or "Imported Security Finding").strip()
        priority = normalize_severity(cand.get("severity") or cand.get("priority") or "HIGH")
        cwe = cand.get("cwe") or "CWE-200"
        cvss = cand.get("cvss_score") or (9.0 if priority == "CRITICAL" else 7.5 if priority == "HIGH" else 5.0 if priority == "MEDIUM" else 3.0 if priority == "LOW" else 0.0)
        desc = cand.get("description") or ""
        obs = cand.get("observation") or desc
        imp = cand.get("impact") or ""
        repro = cand.get("steps_to_reproduce") or cand.get("reproduction_steps") or cand.get("testing_notes") or ""
        poc = cand.get("poc") or cand.get("poc_text") or ""
        remed = cand.get("remediation") or ""
        mitig = cand.get("mitigation") or ""
        url = cand.get("affected_url") or ""
        comp = cand.get("affected_component") or ""
        status_val = cand.get("status") or "Open"
        
        evidence_list = cand.get("evidence") or []
        first_ef = None
        first_ed = None
        if evidence_list:
            first_ef = evidence_list[0].get("name") or evidence_list[0].get("filename")
            first_ed = evidence_list[0].get("data") or evidence_list[0].get("url")
        ev_json = json.dumps(evidence_list)

        cursor.execute("""
        INSERT INTO findings (
            id, project_id, checklist_item_id, vuln_id, finding_name, severity_source,
            affected_url, affected_endpoint, affected_component, description, observation, testing_notes,
            poc_text, evidence_filename, evidence_data, evidence_json, priority, cwe, cvss_score,
            impact, reproduction_steps, remediation, mitigation, status, fix_status,
            source, source_document_id, source_document_name, retest_status, retest_notes, recorded_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            fid, project_id, cand.get("checklist_item_id"), vuln_id, name, "IMPORTED",
            url, url, comp, desc, obs, repro,
            poc, first_ef, first_ed, ev_json, priority, cwe, cvss,
            imp, repro, remed, mitig, status_val, cand.get("fix_status") or "NOT_STARTED",
            "IMPORTED_REPORT", source_doc_id, source_doc_name, cand.get("retest_status") or "PENDING", cand.get("retest_notes") or "", now
        ))

        imported_records.append({
            "id": fid,
            "project_id": project_id,
            "vuln_id": vuln_id,
            "finding_name": name,
            "priority": priority,
            "cwe": cwe,
            "cvss_score": cvss,
            "affected_url": url,
            "affected_component": comp,
            "description": desc,
            "observation": obs,
            "impact": imp,
            "reproduction_steps": repro,
            "poc_text": poc,
            "remediation": remed,
            "mitigation": mitig,
            "evidence": evidence_list,
            "evidence_filename": first_ef,
            "evidence_data": first_ed,
            "status": status_val,
            "fix_status": "NOT_STARTED",
            "source": "IMPORTED_REPORT",
            "source_document_id": source_doc_id,
            "source_document_name": source_doc_name,
            "retest_status": "PENDING",
            "retest_notes": "",
            "recorded_at": now
        })

    cursor.execute("UPDATE projects SET updated_at = ? WHERE id = ?", (now, project_id))
    conn.commit()
    conn.close()
    return imported_records

def get_project_findings_list(project_id: str, conn=None) -> List[Dict[str, Any]]:
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True
    cursor = conn.cursor()
    cursor.execute("""
    SELECT f.*, ci.test_id as test_id, ci.name as test_name, COALESCE(f.cwe, ci.cwe) as resolved_cwe, ci.priority as item_priority
    FROM findings f
    LEFT JOIN checklist_items ci ON f.checklist_item_id = ci.id
    WHERE f.project_id = ?
    ORDER BY f.recorded_at DESC
    """, (project_id,))
    rows = cursor.fetchall()
    findings = []
    for r in rows:
        d = dict(r)
        if not d.get("test_id"):
            d["test_id"] = d.get("checklist_item_id")
        if not d.get("cwe") and d.get("resolved_cwe"):
            d["cwe"] = d["resolved_cwe"]
        if not d.get("vuln_id"):
            d["vuln_id"] = f"VULN-{len(findings) + 1:03d}"
        ev_list = []
        if d.get("evidence_json"):
            try:
                ev_list = json.loads(d["evidence_json"])
            except Exception:
                ev_list = []
        if not ev_list and (d.get("evidence_filename") or d.get("evidence_data")):
            ev_list = [{"name": d.get("evidence_filename") or "evidence.png", "data": d.get("evidence_data"), "type": "image/png"}]
        d["evidence"] = ev_list
        d["observation"] = d.get("observation") or d.get("description") or ""
        d["source"] = d.get("source") or "CHECKLIST"
        d["source_document_id"] = d.get("source_document_id")
        d["source_document_name"] = d.get("source_document_name")
        d["retest_status"] = d.get("retest_status") or "PENDING"
        d["retest_notes"] = d.get("retest_notes") or ""
        d["github_fix"] = {
            "repository": d.get("github_repo"),
            "branch": d.get("github_branch"),
            "commit": d.get("github_commit"),
            "pull_request": d.get("github_pr"),
            "pr_url": d.get("github_pr"),
            "validation_status": d.get("github_validation")
        }
        d["ai_fix"] = d["github_fix"]
        d["priority"] = normalize_severity(d.get("priority"))
        d["severity"] = d["priority"]
        findings.append(d)
    if close_conn:
        conn.close()
    return findings

def _hydrate_finding_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    if not d.get("cwe") and d.get("resolved_cwe"):
        d["cwe"] = d["resolved_cwe"]
    ev_list = []
    if d.get("evidence_json"):
        try:
            ev_list = json.loads(d["evidence_json"])
        except Exception:
            ev_list = []
    if not ev_list and (d.get("evidence_filename") or d.get("evidence_data")):
        ev_list = [{"name": d.get("evidence_filename") or "evidence.png", "data": d.get("evidence_data"), "type": "image/png"}]
    d["evidence"] = ev_list
    d["observation"] = d.get("observation") or d.get("description") or ""
    d["github_fix"] = {
        "repository": d.get("github_repo"),
        "branch": d.get("github_branch"),
        "commit": d.get("github_commit"),
        "pull_request": d.get("github_pr"),
        "pr_url": d.get("github_pr"),
        "validation_status": d.get("github_validation")
    }
    d["ai_fix"] = d["github_fix"]
    d["priority"] = normalize_severity(d.get("priority"))
    d["severity"] = d["priority"]
    return d

def get_finding_by_id(finding_id: str, project_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    if not finding_id:
        return None
    finding_id = str(finding_id).strip()
    conn = get_db_connection()
    cursor = conn.cursor()
    row = None
    if project_id:
        proj_id = str(project_id).strip()
        cursor.execute("""
        SELECT f.*, ci.name as test_name, COALESCE(f.cwe, ci.cwe) as resolved_cwe
        FROM findings f
        LEFT JOIN checklist_items ci ON f.checklist_item_id = ci.id
        WHERE f.id = ? AND f.project_id = ?
        LIMIT 1
        """, (finding_id, proj_id))
        row = cursor.fetchone()
        if not row:
            cursor.execute("""
            SELECT f.*, ci.name as test_name, COALESCE(f.cwe, ci.cwe) as resolved_cwe
            FROM findings f
            LEFT JOIN checklist_items ci ON f.checklist_item_id = ci.id
            WHERE f.vuln_id = ? AND f.project_id = ?
            LIMIT 1
            """, (finding_id, proj_id))
            row = cursor.fetchone()
    else:
        cursor.execute("""
        SELECT f.*, ci.name as test_name, COALESCE(f.cwe, ci.cwe) as resolved_cwe
        FROM findings f
        LEFT JOIN checklist_items ci ON f.checklist_item_id = ci.id
        WHERE f.id = ?
        LIMIT 1
        """, (finding_id,))
        row = cursor.fetchone()
        if not row:
            cursor.execute("""
            SELECT f.*, ci.name as test_name, COALESCE(f.cwe, ci.cwe) as resolved_cwe
            FROM findings f
            LEFT JOIN checklist_items ci ON f.checklist_item_id = ci.id
            WHERE f.vuln_id = ?
            LIMIT 1
            """, (finding_id,))
            row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return _hydrate_finding_dict(dict(row))

def get_finding_scoped(
    finding_id: str,
    project_id: Optional[str] = None,
    user_id: Optional[str] = None,
    is_admin: bool = False
) -> Optional[Dict[str, Any]]:
    """
    Authoritative finding lookup adhering strictly to user and project boundaries.
    """
    if not finding_id:
        return None
    finding_id = str(finding_id).strip()
    conn = get_db_connection()
    cursor = conn.cursor()
    row = None

    if project_id:
        proj_id = str(project_id).strip()
        cursor.execute("""
        SELECT f.*, ci.name as test_name, COALESCE(f.cwe, ci.cwe) as resolved_cwe
        FROM findings f
        LEFT JOIN checklist_items ci ON f.checklist_item_id = ci.id
        WHERE (f.id = ? OR f.vuln_id = ?) AND f.project_id = ?
        ORDER BY CASE WHEN f.finding_name != 'Vulnerability Finding' AND f.cwe != 'CWE-200' THEN 0 ELSE 1 END, f.recorded_at DESC
        LIMIT 1
        """, (finding_id, finding_id, proj_id))
        row = cursor.fetchone()
    elif is_admin:
        cursor.execute("""
        SELECT f.*, ci.name as test_name, COALESCE(f.cwe, ci.cwe) as resolved_cwe
        FROM findings f
        LEFT JOIN checklist_items ci ON f.checklist_item_id = ci.id
        WHERE (f.id = ? OR f.vuln_id = ?)
        ORDER BY CASE WHEN f.finding_name != 'Vulnerability Finding' AND f.cwe != 'CWE-200' THEN 0 ELSE 1 END, f.recorded_at DESC
        LIMIT 1
        """, (finding_id, finding_id))
        row = cursor.fetchone()
    elif user_id:
        uid = str(user_id).strip()
        cursor.execute("""
        SELECT f.*, ci.name as test_name, COALESCE(f.cwe, ci.cwe) as resolved_cwe
        FROM findings f
        JOIN projects p ON f.project_id = p.id
        LEFT JOIN checklist_items ci ON f.checklist_item_id = ci.id
        WHERE (f.id = ? OR f.vuln_id = ?) AND (p.owner_id = ? OR p.owner_id IS NULL OR p.owner_id IN ('user-learner-001', 'Security Learner'))
        ORDER BY CASE WHEN f.finding_name != 'Vulnerability Finding' AND f.cwe != 'CWE-200' THEN 0 ELSE 1 END, f.recorded_at DESC
        LIMIT 1
        """, (finding_id, finding_id, uid))
        row = cursor.fetchone()
    else:
        cursor.execute("""
        SELECT f.*, ci.name as test_name, COALESCE(f.cwe, ci.cwe) as resolved_cwe
        FROM findings f
        JOIN projects p ON f.project_id = p.id
        LEFT JOIN checklist_items ci ON f.checklist_item_id = ci.id
        WHERE (f.id = ? OR f.vuln_id = ?) AND (p.owner_id IS NULL OR p.owner_id IN ('user-learner-001', 'Security Learner'))
        ORDER BY CASE WHEN f.finding_name != 'Vulnerability Finding' AND f.cwe != 'CWE-200' THEN 0 ELSE 1 END, f.recorded_at DESC
        LIMIT 1
        """, (finding_id, finding_id))
        row = cursor.fetchone()

    conn.close()
    if not row:
        return None
    return _hydrate_finding_dict(dict(row))

def update_finding_github_fix(
    finding_id: str,
    fix_status: str,
    repo: Optional[str] = None,
    branch: Optional[str] = None,
    commit: Optional[str] = None,
    pr: Optional[str] = None,
    validation: Optional[str] = None,
    commit_sha: Optional[str] = None,
    pr_url: Optional[str] = None,
    **kwargs
) -> Optional[Dict[str, Any]]:
    actual_commit = commit or commit_sha
    actual_pr = pr or pr_url
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    UPDATE findings SET
        fix_status = COALESCE(?, fix_status),
        github_repo = COALESCE(?, github_repo),
        github_branch = COALESCE(?, github_branch),
        github_commit = COALESCE(?, github_commit),
        github_pr = COALESCE(?, github_pr),
        github_validation = COALESCE(?, github_validation)
    WHERE id = ? OR vuln_id = ?
    """, (fix_status, repo, branch, actual_commit, actual_pr, validation, finding_id, finding_id))
    conn.commit()
    conn.close()
    return get_finding_by_id(finding_id)

def update_finding_ai_fix(finding_id: str, ai_fix_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Update AI AutoFix metadata on finding."""
    status_val = ai_fix_data.get("status") or ai_fix_data.get("fix_status") or "Fix Applied"
    return update_finding_github_fix(
        finding_id=finding_id,
        fix_status=status_val,
        repo=ai_fix_data.get("repository") or ai_fix_data.get("repo"),
        branch=ai_fix_data.get("branch"),
        commit_sha=ai_fix_data.get("commit_sha") or ai_fix_data.get("commit"),
        pr_url=ai_fix_data.get("pr_url") or ai_fix_data.get("pull_request"),
        validation=ai_fix_data.get("validation_status") or ai_fix_data.get("validation")
    )

def save_user_github_config(user_id: str, token: Optional[str], mode: str = "mock", username: Optional[str] = None):
    if not user_id:
        return
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
    INSERT INTO user_github_configs (user_id, token, mode, username, updated_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET
        token = excluded.token,
        mode = excluded.mode,
        username = excluded.username,
        updated_at = excluded.updated_at
    """, (user_id, token, mode, username, now))
    conn.commit()
    conn.close()

def get_user_github_config(user_id: str) -> Optional[Dict[str, Any]]:
    if not user_id:
        return None
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user_github_configs WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def delete_finding(finding_id: str) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT checklist_item_id FROM findings WHERE id = ?", (finding_id,))
    row = cursor.fetchone()
    if row and row["checklist_item_id"]:
        cursor.execute("UPDATE checklist_items SET status = 'NOT_TESTED' WHERE id = ?", (row["checklist_item_id"],))

    try:
        cursor.execute("UPDATE evidence SET finding_id = NULL, status = 'UNASSOCIATED' WHERE finding_id = ?", (finding_id,))
    except Exception:
        pass

    cursor.execute("DELETE FROM findings WHERE id = ?", (finding_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def record_evidence(data: Dict[str, Any]) -> Dict[str, Any]:
    """Insert or update an evidence record in persistent database storage."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ev_id = data.get("id") or f"ev-{uuid.uuid4().hex[:10]}"
    ev_file_data = data.get("file_data") or data.get("data") or ""
    cursor.execute("""
    INSERT INTO evidence (
        id, evidence_id, finding_id, project_id, checklist_item_id,
        original_filename, stored_filename, mime_type, file_size, storage_path,
        caption, description, uploaded_by, uploaded_at, status, file_data
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT (id) DO UPDATE SET
        evidence_id = EXCLUDED.evidence_id,
        finding_id = EXCLUDED.finding_id,
        project_id = EXCLUDED.project_id,
        checklist_item_id = EXCLUDED.checklist_item_id,
        original_filename = EXCLUDED.original_filename,
        stored_filename = EXCLUDED.stored_filename,
        mime_type = EXCLUDED.mime_type,
        file_size = EXCLUDED.file_size,
        storage_path = EXCLUDED.storage_path,
        caption = EXCLUDED.caption,
        description = EXCLUDED.description,
        uploaded_by = EXCLUDED.uploaded_by,
        uploaded_at = EXCLUDED.uploaded_at,
        status = EXCLUDED.status,
        file_data = CASE WHEN EXCLUDED.file_data IS NOT NULL AND EXCLUDED.file_data != '' THEN EXCLUDED.file_data ELSE evidence.file_data END
    """, (
        ev_id,
        data.get("evidence_id") or "EV-001",
        data.get("finding_id") or None,
        str(data.get("project_id")),
        data.get("checklist_item_id"),
        data.get("original_filename") or data.get("name") or "evidence.png",
        data.get("stored_filename") or data.get("filename") or "evidence.png",
        data.get("mime_type") or data.get("type") or "image/png",
        data.get("file_size") or data.get("size") or 0,
        str(data.get("storage_path") or data.get("file_path") or ""),
        data.get("caption") or "",
        data.get("description") or "",
        data.get("uploaded_by") or "user",
        data.get("uploaded_at") or now,
        data.get("status") or "ACTIVE",
        ev_file_data
    ))
    conn.commit()
    cursor.execute("SELECT * FROM evidence WHERE id = ?", (ev_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else data

def get_project_evidence(project_id: str) -> List[Dict[str, Any]]:
    """Retrieve all evidence metadata records for a project."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT e.*, f.finding_name, f.vuln_id
    FROM evidence e
    LEFT JOIN findings f ON e.finding_id = f.id
    WHERE e.project_id = ?
    ORDER BY e.uploaded_at DESC
    """, (str(project_id),))
    rows = cursor.fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        d["url"] = f"/api/projects/{project_id}/evidence/{d['stored_filename']}"
        results.append(d)
    return results

def get_finding_evidence(finding_id: str) -> List[Dict[str, Any]]:
    """Retrieve all evidence metadata records associated with a finding."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT * FROM evidence WHERE finding_id = ? ORDER BY uploaded_at ASC
    """, (finding_id,))
    rows = cursor.fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        d["url"] = f"/api/projects/{d['project_id']}/evidence/{d['stored_filename']}"
        results.append(d)
    return results

def migrate_legacy_finding_evidence(project_id: str, legacy_findings: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Safely extract legacy base64 evidence from findings and persist to server disk & database."""
    if not legacy_findings:
        conn_f = get_db_connection()
        cursor_f = conn_f.cursor()
        cursor_f.execute("SELECT * FROM findings WHERE project_id = ?", (project_id,))
        legacy_findings = [dict(r) for r in cursor_f.fetchall()]
        conn_f.close()

    if not legacy_findings or not project_id:
        return {"migrated_findings": 0, "migrated_evidence": 0, "migrated_count": 0, "status": "NO_OP"}

    evidence_dir = Path(__file__).resolve().parent.parent / "data" / "evidence" / str(project_id)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    migrated_findings_count = 0
    migrated_evidence_count = 0

    for f in legacy_findings:
        fid = f.get("id")
        if not fid:
            continue

        raw_evidence = f.get("evidence") or []
        if not raw_evidence and f.get("evidence_json"):
            try:
                raw_evidence = json.loads(f["evidence_json"])
            except Exception:
                raw_evidence = []
        if not raw_evidence and (f.get("evidence_filename") or f.get("evidence_data")):
            raw_evidence = [{
                "name": f.get("evidence_filename") or "evidence.png",
                "data": f.get("evidence_data"),
                "type": "image/png"
            }]

        clean_evidence = []
        has_heavy = False

        for idx, itm in enumerate(raw_evidence):
            raw_data = itm.get("data")
            orig_name = itm.get("name") or itm.get("original_filename") or itm.get("filename") or f"evidence_{idx+1}.png"
            clean_base = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', Path(orig_name).name)
            stored_fn = itm.get("filename") or itm.get("stored_filename")
            if not stored_fn or stored_fn == orig_name:
                stored_fn = f"ev-{uuid.uuid4().hex[:8]}_{clean_base}"

            dest_path = evidence_dir / stored_fn
            size_bytes = itm.get("size") or itm.get("file_size") or 0

            if raw_data and isinstance(raw_data, str) and (raw_data.startswith("data:") or len(raw_data) > 100):
                has_heavy = True
                try:
                    b64_part = raw_data.split(",", 1)[1] if "," in raw_data else raw_data
                    b_content = base64.b64decode(b64_part)
                    if not dest_path.exists() or dest_path.stat().st_size == 0:
                        dest_path.write_bytes(b_content)
                    size_bytes = len(b_content)
                    migrated_evidence_count += 1
                except Exception as b_err:
                    logger.warning(f"Failed to decode legacy base64 in migration: {b_err}")

            if dest_path.exists() and size_bytes == 0:
                size_bytes = dest_path.stat().st_size

            ev_id = itm.get("id") or f"ev-{uuid.uuid4().hex[:10]}"
            ev_ref = itm.get("evidence_id") or f"EV-{idx+1:03d}"
            mime_type = itm.get("type") or itm.get("mime_type") or "image/png"
            rel_url = f"/api/projects/{project_id}/evidence/{stored_fn}"

            ev_file_data = b64_part if (raw_data and isinstance(raw_data, str)) else (itm.get("data") or itm.get("file_data") or "")
            cursor.execute("""
            INSERT INTO evidence (
                id, evidence_id, finding_id, project_id, checklist_item_id,
                original_filename, stored_filename, mime_type, file_size, storage_path,
                caption, description, uploaded_by, uploaded_at, status, file_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (id) DO UPDATE SET
                evidence_id = EXCLUDED.evidence_id,
                finding_id = EXCLUDED.finding_id,
                project_id = EXCLUDED.project_id,
                checklist_item_id = EXCLUDED.checklist_item_id,
                original_filename = EXCLUDED.original_filename,
                stored_filename = EXCLUDED.stored_filename,
                mime_type = EXCLUDED.mime_type,
                file_size = EXCLUDED.file_size,
                storage_path = EXCLUDED.storage_path,
                caption = EXCLUDED.caption,
                description = EXCLUDED.description,
                uploaded_by = EXCLUDED.uploaded_by,
                uploaded_at = EXCLUDED.uploaded_at,
                status = EXCLUDED.status,
                file_data = CASE WHEN EXCLUDED.file_data IS NOT NULL AND EXCLUDED.file_data != '' THEN EXCLUDED.file_data ELSE evidence.file_data END
            """, (
                ev_id, ev_ref, fid, str(project_id), f.get("checklist_item_id") or f.get("test_id"),
                orig_name, stored_fn, mime_type, size_bytes, str(dest_path),
                itm.get("caption") or "", itm.get("description") or "", "migration", now, "ACTIVE",
                ev_file_data
            ))

            clean_evidence.append({
                "id": ev_id,
                "evidence_id": ev_ref,
                "name": orig_name,
                "filename": stored_fn,
                "file_path": str(dest_path),
                "size": size_bytes,
                "mime_type": mime_type,
                "type": mime_type,
                "url": rel_url,
                "caption": itm.get("caption") or "",
                "status": "ACTIVE"
            })

        if has_heavy:
            migrated_findings_count += 1
            # Update findings table with clean evidence
            first_ef = clean_evidence[0]["name"] if clean_evidence else None
            first_ed = clean_evidence[0]["url"] if clean_evidence else None
            cursor.execute("""
            UPDATE findings SET
                evidence_filename = COALESCE(?, evidence_filename),
                evidence_data = ?,
                evidence_json = ?
            WHERE id = ?
            """, (first_ef, first_ed, json.dumps(clean_evidence), fid))

    conn.commit()
    conn.close()
    return {
        "migrated_findings": migrated_findings_count,
        "migrated_evidence": migrated_evidence_count,
        "migrated_count": migrated_evidence_count,
        "status": "SUCCESS"
    }

# =========================================================================
# AI FIXES & REMEDIATION AUDIT CRUD
# =========================================================================

def _hydrate_ai_fix_row(row_dict: Dict[str, Any]) -> Dict[str, Any]:
    d = dict(row_dict)
    if d.get("changes_json"):
        try:
            d["changes"] = json.loads(d["changes_json"])
        except Exception:
            d["changes"] = []
    else:
        d["changes"] = []

    if d.get("retest_checklist_json"):
        try:
            d["retest_checklist"] = json.loads(d["retest_checklist_json"])
        except Exception:
            d["retest_checklist"] = []
    else:
        d["retest_checklist"] = []
    return d

def save_ai_fix_record(data: Dict[str, Any]) -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fix_id = data.get("id") or f"fix-{int(datetime.now().timestamp() * 1000)}-{uuid.uuid4().hex[:6]}"

    proj_id = data.get("project_id") or "proj-default"
    finding_id = data.get("finding_id") or "find-default"

    cursor.execute("SELECT id FROM projects WHERE id = ?", (proj_id,))
    if not cursor.fetchone():
        cursor.execute("INSERT OR IGNORE INTO projects (id, name, target_url, created_at, updated_at) VALUES (?, ?, ?, ?, ?)", (proj_id, "Default Project", "https://localhost", now, now))
        conn.commit()

    cursor.execute("SELECT id FROM findings WHERE id = ? OR vuln_id = ?", (finding_id, finding_id))
    if not cursor.fetchone():
        cursor.execute("INSERT OR IGNORE INTO findings (id, project_id, vuln_id, finding_name, priority, cwe, status, fix_status, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (finding_id, proj_id, finding_id, "Vulnerability Finding", "HIGH", "CWE-200", "Open", "NOT_STARTED", now))
        conn.commit()

    changes_raw = data.get("changes") or []
    changes_json = json.dumps(changes_raw) if isinstance(changes_raw, list) else (data.get("changes_json") or "[]")

    checklist_raw = data.get("retest_checklist") or []
    checklist_json = json.dumps(checklist_raw) if isinstance(checklist_raw, list) else (data.get("retest_checklist_json") or "[]")

    cursor.execute("""
    INSERT INTO ai_fixes (
        id, project_id, finding_id, repository, base_branch, fix_branch,
        file_path, file_sha, commit_sha, commit_message, pr_number, pr_url, pr_status,
        diff_unified, original_code, proposed_code, changes_json, explanation,
        security_impact, testing_recommendation, retest_checklist_json,
        retest_status, retest_notes, retested_at, status, revision_count,
        created_at, updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        fix_id,
        data["project_id"],
        data["finding_id"],
        data.get("repository") or data.get("repo") or "tracegate-lab/ecommerce-platform",
        data.get("base_branch") or "main",
        data.get("fix_branch") or f"tracegate/fix/{data['finding_id']}",
        data.get("file_path") or "",
        data.get("file_sha"),
        data.get("commit_sha"),
        data.get("commit_message"),
        data.get("pr_number"),
        data.get("pr_url"),
        data.get("pr_status") or "Open",
        data.get("diff_unified") or data.get("unified_diff") or "",
        data.get("original_code") or data.get("before_code") or "",
        data.get("proposed_code") or data.get("after_code") or "",
        changes_json,
        data.get("explanation") or "",
        data.get("security_impact") or "",
        data.get("testing_recommendation") or "",
        checklist_json,
        data.get("retest_status") or "PENDING",
        data.get("retest_notes") or "",
        data.get("retested_at"),
        data.get("status") or "PROPOSED",
        data.get("revision_count", 0),
        now,
        now
    ))
    conn.commit()
    cursor.execute("SELECT * FROM ai_fixes WHERE id = ?", (fix_id,))
    row = cursor.fetchone()
    conn.close()
    return _hydrate_ai_fix_row(dict(row))

def get_ai_fix_by_id(fix_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ai_fixes WHERE id = ?", (fix_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return _hydrate_ai_fix_row(dict(row))

def get_ai_fix_for_finding(finding_id: str, project_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    if project_id:
        cursor.execute(
            """
            SELECT * FROM ai_fixes 
            WHERE (finding_id = ? OR finding_id = (SELECT vuln_id FROM findings WHERE id = ? AND project_id = ? LIMIT 1))
              AND project_id = ? 
            ORDER BY CASE WHEN pr_number IS NOT NULL AND pr_number != 'N/A' THEN 0 ELSE 1 END,
                     revision_count DESC, updated_at DESC, rowid DESC 
            LIMIT 1
            """,
            (finding_id, finding_id, project_id, project_id)
        )
    else:
        cursor.execute(
            """
            SELECT * FROM ai_fixes 
            WHERE finding_id = ? 
            ORDER BY CASE WHEN pr_number IS NOT NULL AND pr_number != 'N/A' THEN 0 ELSE 1 END,
                     revision_count DESC, updated_at DESC, rowid DESC 
            LIMIT 1
            """,
            (finding_id,)
        )
    row = cursor.fetchone()

    # Fallback for bulk remediation: check if project has a batch PR covering this finding
    if not row and project_id and finding_id not in ["__ALL_FINDINGS__", "ALL"]:
        cursor.execute("SELECT github_pr FROM findings WHERE (id = ? OR vuln_id = ?) AND project_id = ? LIMIT 1", (finding_id, finding_id, project_id))
        f_row = cursor.fetchone()
        if f_row and f_row["github_pr"]:
            cursor.execute(
                """
                SELECT * FROM ai_fixes 
                WHERE project_id = ? AND pr_number IS NOT NULL 
                ORDER BY updated_at DESC, rowid DESC LIMIT 1
                """,
                (project_id,)
            )
            row = cursor.fetchone()

    conn.close()
    if not row:
        return None
    return _hydrate_ai_fix_row(dict(row))

def get_ai_fix_by_pr_number(pr_number: int, repo: Optional[str] = None) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    if repo:
        cursor.execute("SELECT * FROM ai_fixes WHERE pr_number = ? AND repository = ? ORDER BY updated_at DESC, rowid DESC LIMIT 1", (pr_number, repo))
    else:
        cursor.execute("SELECT * FROM ai_fixes WHERE pr_number = ? ORDER BY updated_at DESC, rowid DESC LIMIT 1", (pr_number,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return _hydrate_ai_fix_row(dict(row))

def update_ai_fix_record(fix_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    changes_json = None
    if "changes" in data:
        changes_json = json.dumps(data["changes"]) if isinstance(data["changes"], list) else data["changes"]

    checklist_json = None
    if "retest_checklist" in data:
        checklist_json = json.dumps(data["retest_checklist"]) if isinstance(data["retest_checklist"], list) else data["retest_checklist"]

    cursor.execute("""
    UPDATE ai_fixes SET
        repository = COALESCE(?, repository),
        base_branch = COALESCE(?, base_branch),
        fix_branch = COALESCE(?, fix_branch),
        file_path = COALESCE(?, file_path),
        file_sha = COALESCE(?, file_sha),
        commit_sha = COALESCE(?, commit_sha),
        commit_message = COALESCE(?, commit_message),
        pr_number = COALESCE(?, pr_number),
        pr_url = COALESCE(?, pr_url),
        pr_status = COALESCE(?, pr_status),
        diff_unified = COALESCE(?, diff_unified),
        original_code = COALESCE(?, original_code),
        proposed_code = COALESCE(?, proposed_code),
        changes_json = COALESCE(?, changes_json),
        explanation = COALESCE(?, explanation),
        security_impact = COALESCE(?, security_impact),
        testing_recommendation = COALESCE(?, testing_recommendation),
        retest_checklist_json = COALESCE(?, retest_checklist_json),
        retest_status = COALESCE(?, retest_status),
        retest_notes = COALESCE(?, retest_notes),
        retested_at = COALESCE(?, retested_at),
        status = COALESCE(?, status),
        revision_count = COALESCE(?, revision_count),
        merge_commit_sha = COALESCE(?, merge_commit_sha),
        merged_at = COALESCE(?, merged_at),
        review_status = COALESCE(?, review_status),
        updated_at = ?
    WHERE id = ?
    """, (
        data.get("repository") or data.get("repo"),
        data.get("base_branch"),
        data.get("fix_branch"),
        data.get("file_path"),
        data.get("file_sha"),
        data.get("commit_sha"),
        data.get("commit_message"),
        data.get("pr_number"),
        data.get("pr_url"),
        data.get("pr_status"),
        data.get("diff_unified") or data.get("unified_diff"),
        data.get("original_code") or data.get("before_code"),
        data.get("proposed_code") or data.get("after_code"),
        changes_json,
        data.get("explanation"),
        data.get("security_impact"),
        data.get("testing_recommendation"),
        checklist_json,
        data.get("retest_status"),
        data.get("retest_notes"),
        data.get("retested_at"),
        data.get("status"),
        data.get("revision_count"),
        data.get("merge_commit_sha"),
        data.get("merged_at"),
        data.get("review_status"),
        now,
        fix_id
    ))
    conn.commit()
    cursor.execute("SELECT * FROM ai_fixes WHERE id = ?", (fix_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return _hydrate_ai_fix_row(dict(row))

def list_ai_fixes_for_project(project_id: str) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ai_fixes WHERE project_id = ? ORDER BY updated_at DESC", (project_id,))
    rows = cursor.fetchall()
    conn.close()
    return [_hydrate_ai_fix_row(dict(r)) for r in rows]

def record_finding_retest(
    finding_id: str,
    fix_id: Optional[str] = None,
    result: str = "PASS",
    notes: Optional[str] = None,
    project_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Record tester retest verification.
    PASS -> finding.status = 'RESOLVED', retest_status = 'PASSED'.
    FAIL -> finding.status = 'REOPENED', retest_status = 'FAILED'.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    normalized_res = (result or "PASS").strip().upper()
    is_pass = "PASS" in normalized_res

    target_finding_status = "RESOLVED" if is_pass else "REOPENED"
    target_fix_status = "RESOLVED" if is_pass else "RETEST_FAILED"
    retest_stat = "PASSED" if is_pass else "FAILED"
    retest_notes_val = notes.strip() if (notes is not None and isinstance(notes, str)) else notes

    is_batch = finding_id in ["__ALL_FINDINGS__", "ALL", "BATCH_ALL"]

    try:
        # Check available columns in findings for backward-compatibility
        cursor.execute("PRAGMA table_info(findings)")
        f_cols = {r["name"] for r in cursor.fetchall()}
        has_retested_at = "retested_at" in f_cols

        resolved_project_id = project_id

        if is_batch:
            if not resolved_project_id:
                # Find project from fix_id if possible
                if fix_id:
                    cursor.execute("SELECT project_id FROM ai_fixes WHERE id = ? LIMIT 1", (fix_id,))
                    p_row = cursor.fetchone()
                    if p_row:
                        resolved_project_id = p_row["project_id"]

            if resolved_project_id:
                # Batch update all findings in the project
                if retest_notes_val is not None:
                    if has_retested_at:
                        cursor.execute("""
                        UPDATE findings SET
                            status = ?,
                            fix_status = ?,
                            retest_status = ?,
                            retest_notes = ?,
                            retested_at = ?
                        WHERE project_id = ?
                        """, (target_finding_status, target_fix_status, retest_stat, retest_notes_val, now, resolved_project_id))
                    else:
                        cursor.execute("""
                        UPDATE findings SET
                            status = ?,
                            fix_status = ?,
                            retest_status = ?,
                            retest_notes = ?
                        WHERE project_id = ?
                        """, (target_finding_status, target_fix_status, retest_stat, retest_notes_val, resolved_project_id))
                else:
                    if has_retested_at:
                        cursor.execute("""
                        UPDATE findings SET
                            status = ?,
                            fix_status = ?,
                            retest_status = ?,
                            retested_at = ?
                        WHERE project_id = ?
                        """, (target_finding_status, target_fix_status, retest_stat, now, resolved_project_id))
                    else:
                        cursor.execute("""
                        UPDATE findings SET
                            status = ?,
                            fix_status = ?,
                            retest_status = ?
                        WHERE project_id = ?
                        """, (target_finding_status, target_fix_status, retest_stat, resolved_project_id))

                # Batch update ai_fixes in the project
                cursor.execute("""
                UPDATE ai_fixes SET
                    retest_status = ?,
                    retest_notes = ?,
                    retested_at = ?,
                    status = ?,
                    updated_at = ?
                WHERE project_id = ?
                """, (retest_stat, retest_notes_val or "", now, target_finding_status, now, resolved_project_id))

        else:
            # Individual finding update
            if resolved_project_id:
                if retest_notes_val is not None:
                    if has_retested_at:
                        cursor.execute("""
                        UPDATE findings SET
                            status = ?,
                            fix_status = ?,
                            retest_status = ?,
                            retest_notes = ?,
                            retested_at = ?
                        WHERE (id = ? OR vuln_id = ?) AND project_id = ?
                        """, (target_finding_status, target_fix_status, retest_stat, retest_notes_val, now, finding_id, finding_id, resolved_project_id))
                    else:
                        cursor.execute("""
                        UPDATE findings SET
                            status = ?,
                            fix_status = ?,
                            retest_status = ?,
                            retest_notes = ?
                        WHERE (id = ? OR vuln_id = ?) AND project_id = ?
                        """, (target_finding_status, target_fix_status, retest_stat, retest_notes_val, finding_id, finding_id, resolved_project_id))
                else:
                    if has_retested_at:
                        cursor.execute("""
                        UPDATE findings SET
                            status = ?,
                            fix_status = ?,
                            retest_status = ?,
                            retested_at = ?
                        WHERE (id = ? OR vuln_id = ?) AND project_id = ?
                        """, (target_finding_status, target_fix_status, retest_stat, now, finding_id, finding_id, resolved_project_id))
                    else:
                        cursor.execute("""
                        UPDATE findings SET
                            status = ?,
                            fix_status = ?,
                            retest_status = ?
                        WHERE (id = ? OR vuln_id = ?) AND project_id = ?
                        """, (target_finding_status, target_fix_status, retest_stat, finding_id, finding_id, resolved_project_id))
            else:
                if retest_notes_val is not None:
                    if has_retested_at:
                        cursor.execute("""
                        UPDATE findings SET
                            status = ?,
                            fix_status = ?,
                            retest_status = ?,
                            retest_notes = ?,
                            retested_at = ?
                        WHERE id = ? OR vuln_id = ?
                        """, (target_finding_status, target_fix_status, retest_stat, retest_notes_val, now, finding_id, finding_id))
                    else:
                        cursor.execute("""
                        UPDATE findings SET
                            status = ?,
                            fix_status = ?,
                            retest_status = ?,
                            retest_notes = ?
                        WHERE id = ? OR vuln_id = ?
                        """, (target_finding_status, target_fix_status, retest_stat, retest_notes_val, finding_id, finding_id))
                else:
                    if has_retested_at:
                        cursor.execute("""
                        UPDATE findings SET
                            status = ?,
                            fix_status = ?,
                            retest_status = ?,
                            retested_at = ?
                        WHERE id = ? OR vuln_id = ?
                        """, (target_finding_status, target_fix_status, retest_stat, now, finding_id, finding_id))
                    else:
                        cursor.execute("""
                        UPDATE findings SET
                            status = ?,
                            fix_status = ?,
                            retest_status = ?
                        WHERE id = ? OR vuln_id = ?
                        """, (target_finding_status, target_fix_status, retest_stat, finding_id, finding_id))

            # Update ai_fixes record if present
            if fix_id:
                if retest_notes_val is not None:
                    cursor.execute("""
                    UPDATE ai_fixes SET
                        retest_status = ?,
                        retest_notes = ?,
                        retested_at = ?,
                        status = ?,
                        updated_at = ?
                    WHERE id = ?
                    """, (retest_stat, retest_notes_val, now, target_finding_status, now, fix_id))
                else:
                    cursor.execute("""
                    UPDATE ai_fixes SET
                        retest_status = ?,
                        retested_at = ?,
                        status = ?,
                        updated_at = ?
                    WHERE id = ?
                    """, (retest_stat, now, target_finding_status, now, fix_id))
            else:
                if retest_notes_val is not None:
                    cursor.execute("""
                    UPDATE ai_fixes SET
                        retest_status = ?,
                        retest_notes = ?,
                        retested_at = ?,
                        status = ?,
                        updated_at = ?
                    WHERE finding_id = ?
                    """, (retest_stat, retest_notes_val, now, target_finding_status, now, finding_id))
                else:
                    cursor.execute("""
                    UPDATE ai_fixes SET
                        retest_status = ?,
                        retested_at = ?,
                        status = ?,
                        updated_at = ?
                    WHERE finding_id = ?
                    """, (retest_stat, now, target_finding_status, now, finding_id))

            # If project_id not supplied, resolve project_id from finding
            if not resolved_project_id:
                cursor.execute("SELECT project_id FROM findings WHERE id = ? OR vuln_id = ? LIMIT 1", (finding_id, finding_id))
                f_row = cursor.fetchone()
                if f_row:
                    resolved_project_id = f_row["project_id"]

        if resolved_project_id:
            cursor.execute("UPDATE projects SET updated_at = ? WHERE id = ?", (now, resolved_project_id))

        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"[RETEST_DB_ERROR] finding_id={finding_id} project_id={project_id} error={e}")
        raise e
    finally:
        conn.close()

    if is_batch:
        updated_finding = {
            "id": "__ALL_FINDINGS__",
            "project_id": resolved_project_id,
            "status": target_finding_status,
            "fix_status": target_fix_status,
            "retest_status": retest_stat,
            "retest_notes": retest_notes_val or "",
            "updated_at": now
        }
        saved_notes = retest_notes_val or ""
    else:
        updated_finding = get_finding_by_id(finding_id, project_id=resolved_project_id)
        saved_notes = ""
        if updated_finding and updated_finding.get("retest_notes"):
            saved_notes = updated_finding["retest_notes"]
        elif retest_notes_val is not None:
            saved_notes = retest_notes_val

    return {
        "finding_id": finding_id,
        "project_id": resolved_project_id,
        "fix_id": fix_id,
        "result": retest_stat,
        "status": target_finding_status,
        "retest_status": retest_stat,
        "notes": saved_notes,
        "updated_at": now,
        "finding": updated_finding
    }

# =========================================================================
# SOURCE DISCOVERY PERSISTENCE (PHASE 1)
# =========================================================================

def _hydrate_source_discovery_row(row_dict: Dict[str, Any]) -> Dict[str, Any]:
    if not row_dict:
        return {}
    d = dict(row_dict)
    for field in ("selected_sources_json", "candidate_sources_json"):
        val = d.get(field)
        key = "selected_sources" if field == "selected_sources_json" else "candidate_sources"
        if val and isinstance(val, str):
            try:
                d[key] = json.loads(val)
            except Exception:
                d[key] = []
        elif key not in d:
            d[key] = []
    return d

def save_source_discovery(data: Dict[str, Any]) -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    disc_id = data.get("id") or f"disc-{uuid.uuid4().hex[:12]}"
    project_id = data.get("project_id") or "proj-default"
    finding_id = data["finding_id"]
    repo = data.get("repository") or data.get("repo") or "tracegate-lab/ecommerce-platform"
    branch = data.get("branch") or "main"
    sha = data.get("source_commit_sha") or "main"
    sel_json = json.dumps(data.get("selected_sources", []))
    cand_json = json.dumps(data.get("candidate_sources", []))
    sel_src = data.get("selection_source", "AUTOMATIC")
    status = data.get("discovery_status", "COMPLETED")

    cursor.execute("""
    SELECT id FROM source_discovery_results 
    WHERE (finding_id = ? OR finding_id IN (SELECT vuln_id FROM findings WHERE id = ?))
      AND project_id = ?
    LIMIT 1
    """, (finding_id, finding_id, project_id))
    existing = cursor.fetchone()

    if existing:
        disc_id = existing["id"]
        cursor.execute("""
        UPDATE source_discovery_results SET
            repository = ?,
            branch = ?,
            source_commit_sha = ?,
            selected_sources_json = ?,
            candidate_sources_json = ?,
            selection_source = ?,
            discovery_status = ?,
            updated_at = ?
        WHERE id = ?
        """, (repo, branch, sha, sel_json, cand_json, sel_src, status, now, disc_id))
    else:
        cursor.execute("""
        INSERT INTO source_discovery_results (
            id, project_id, finding_id, repository, branch,
            source_commit_sha, selected_sources_json, candidate_sources_json,
            selection_source, discovery_status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (disc_id, project_id, finding_id, repo, branch, sha, sel_json, cand_json, sel_src, status, now, now))

    conn.commit()
    cursor.execute("SELECT * FROM source_discovery_results WHERE id = ?", (disc_id,))
    row = cursor.fetchone()
    conn.close()
    return _hydrate_source_discovery_row(dict(row))

def get_source_discovery(finding_id: str, project_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    if project_id:
        cursor.execute("""
        SELECT * FROM source_discovery_results 
        WHERE (finding_id = ? OR finding_id IN (SELECT vuln_id FROM findings WHERE id = ?))
          AND project_id = ?
        ORDER BY updated_at DESC LIMIT 1
        """, (finding_id, finding_id, project_id))
    else:
        cursor.execute("""
        SELECT * FROM source_discovery_results 
        WHERE finding_id = ? OR finding_id IN (SELECT vuln_id FROM findings WHERE id = ?)
        ORDER BY updated_at DESC LIMIT 1
        """, (finding_id, finding_id))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return _hydrate_source_discovery_row(dict(row))

def update_source_discovery_selection(
    finding_id: str,
    selected_paths: List[str],
    project_id: Optional[str] = None,
    source_commit_sha: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    disc = get_source_discovery(finding_id, project_id)
    if not disc:
        # Create minimal record if none exists yet
        disc = save_source_discovery({
            "project_id": project_id or "proj-default",
            "finding_id": finding_id,
            "repository": "tracegate-lab/ecommerce-platform",
            "branch": "main",
            "source_commit_sha": source_commit_sha or "main",
            "selected_sources": [],
            "candidate_sources": [],
            "selection_source": "USER_MODIFIED"
        })

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    old_selected = disc.get("selected_sources", [])
    old_candidates = disc.get("candidate_sources", [])
    path_map = {item["path"]: item for item in (old_selected + old_candidates) if isinstance(item, dict) and "path" in item}

    new_selected = []
    for p in selected_paths:
        if p in path_map:
            item = dict(path_map[p])
            item["confidence"] = "HIGH"
            item["relevance_score"] = max(item.get("relevance_score", 0), 85)
            reasons = list(item.get("reasons", []))
            if "Manually selected by developer" not in reasons:
                reasons.append("Manually selected by developer")
            item["reasons"] = reasons
            new_selected.append(item)
        else:
            new_selected.append({
                "path": p,
                "layer": "source",
                "language": os.path.splitext(p)[1].lstrip(".") or "Unknown",
                "symbols": [],
                "relevance_score": 90,
                "confidence": "HIGH",
                "reasons": ["Manually selected by developer"]
            })

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    UPDATE source_discovery_results SET
        selected_sources_json = ?,
        selection_source = 'USER_MODIFIED',
        source_commit_sha = COALESCE(?, source_commit_sha),
        updated_at = ?
    WHERE id = ?
    """, (json.dumps(new_selected), source_commit_sha, now, disc["id"]))
    conn.commit()
    cursor.execute("SELECT * FROM source_discovery_results WHERE id = ?", (disc["id"],))
    row = cursor.fetchone()
    conn.close()
    return _hydrate_source_discovery_row(dict(row))

# =========================================================================
# SEEDING DEFAULT STARTER PROJECTS
# =========================================================================

def seed_default_projects_if_empty():
    if is_production_mode():
        logger.info("Production mode detected: skipping default starter project seeding.")
        return
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM projects")
    count = cursor.fetchone()[0]
    if count > 0:
        conn.close()
        return

    logger.info("Seeding initial starter projects into development database...")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    starter_projects = [
        {
            "id": "proj-ecommerce-001",
            "name": "E-Commerce Gateway & Auth Audit",
            "target_url": "https://shop.tracegate.lab",
            "description": "Authorized penetration test assessing user registration, multi-factor authentication, and payment handling.",
            "scope_notes": "Scope includes checkout, account reset, and cart endpoints.",
            "environment": "Web Application (Staging)",
            "status": "IN_PROGRESS",
            "created_by": "Security Learner",
            "created_at": "2026-08-28 10:00:00",
            "updated_at": "2026-09-03 16:30:00"
        },
        {
            "id": "proj-health-002",
            "name": "Patient Records EHR API Audit",
            "target_url": "https://ehr-api.medlab.test",
            "description": "Compliance assessment for HIPAA/OWASP ASVS patient record search and attachment upload endpoints.",
            "scope_notes": "Test API tokens provided in lab environment.",
            "environment": "API & Microservices",
            "status": "COMPLETED",
            "created_by": "Security Learner",
            "created_at": "2026-08-15 09:00:00",
            "updated_at": "2026-08-30 18:00:00"
        },
        {
            "id": "proj-fintech-003",
            "name": "Cloud Banking Admin Panel Review",
            "target_url": "https://admin.fintech-vault.stage",
            "description": "Role-based access control (RBAC) and audit log tampering assessment for internal financial staff.",
            "scope_notes": "Admin credentials provided for testing least-privilege.",
            "environment": "Web Application (Production)",
            "status": "NEEDS_REVIEW",
            "created_by": "Security Learner",
            "created_at": "2026-09-01 11:30:00",
            "updated_at": "2026-09-04 08:45:00"
        }
    ]

    for p in starter_projects:
        cursor.execute("""
        INSERT INTO projects (id, name, target_url, description, scope_notes, environment, status, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (p["id"], p["name"], p["target_url"], p["description"], p["scope_notes"], p["environment"], p["status"], p["created_by"], p["created_at"], p["updated_at"]))

    # Seed starter finding for proj-ecommerce-001
    finding_id = "find-ecommerce-001"
    cursor.execute("""
    INSERT INTO findings (id, project_id, checklist_item_id, finding_name, description, testing_notes, poc_text, evidence_filename, priority, recorded_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        finding_id,
        "proj-ecommerce-001",
        None,
        "Broken Authentication on Password Reset",
        "Password reset tokens do not expire upon use and have insufficient entropy (4-digit numeric pin).",
        "Requested reset token via /forgot-password, intercepted response, brute forced 4-digit code within 200 requests.",
        'POST /api/v1/auth/reset HTTP/1.1\nHost: shop.tracegate.lab\nContent-Type: application/json\n\n{"token": "1042", "new_password": "pwnedPass!"} -> 200 OK',
        "reset_token_bruteforce.png",
        "CRITICAL",
        "2026-09-02 14:22:00"
    ))

    conn.commit()
    conn.close()
    seed_default_users_if_empty()
    logger.info("Default starter projects and users seeded successfully.")

# =========================================================================
# AUTHENTICATION & SESSIONS CRUD
# =========================================================================

import hashlib
import secrets
from datetime import timedelta

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    salt_bytes = bytes.fromhex(salt)
    derived = hashlib.scrypt(password.encode("utf-8"), salt=salt_bytes, n=16384, r=8, p=1)
    return f"scrypt$16384$8$1${salt}${derived.hex()}"

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        if not stored_hash:
            return False
        if stored_hash.startswith("scrypt$"):
            parts = stored_hash.split("$")
            if len(parts) == 6:
                _, n_str, r_str, p_str, salt_hex, hash_hex = parts
                n = int(n_str)
                r = int(r_str)
                p = int(p_str)
                salt_bytes = bytes.fromhex(salt_hex)
                computed = hashlib.scrypt(password.encode("utf-8"), salt=salt_bytes, n=n, r=r, p=p).hex()
                return secrets.compare_digest(computed, hash_hex)
        # Legacy fallback: salt$sha256_hash
        if "$" in stored_hash:
            salt, pw_hash = stored_hash.split("$", 1)
            expected = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
            return secrets.compare_digest(expected, pw_hash)
        return False
    except Exception:
        return False

def is_legacy_hash(stored_hash: str) -> bool:
    return not stored_hash.startswith("scrypt$")

def register_user(data: Dict[str, Any]) -> Dict[str, Any]:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        clean_username = data["username"].strip().lower()
        clean_email = data["email"].strip().lower()

        # Explicit uniqueness pre-check to give clean feedback and prevent concurrency locks
        cursor.execute("SELECT id, username, email FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?", (clean_username, clean_email))
        existing = cursor.fetchone()
        if existing:
            if existing["username"].lower() == clean_username:
                raise ValueError("Username already taken. Please choose another username.")
            else:
                raise ValueError("Email already registered. Please sign in or use another email.")

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        user_id = f"user-{int(datetime.now().timestamp()*1000)}-{uuid.uuid4().hex[:6]}"
        pw_hash = hash_password(data["password"])
        full_name = data.get("full_name") or data.get("name") or "Security Learner"
        role = data.get("role", "Junior Pentester")

        cursor.execute("""
        INSERT INTO users (id, username, email, password_hash, full_name, role, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            clean_username,
            clean_email,
            pw_hash,
            full_name,
            role,
            now
        ))
        conn.commit()
        cursor.execute("SELECT id, username, email, full_name, role, created_at FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        res = dict(row)
        res["name"] = res["full_name"]
        return res
    finally:
        conn.close()

def authenticate_user(username_or_email: str, password: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        clean_val = username_or_email.strip().lower()
        cursor.execute("SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?", (clean_val, clean_val))
        user = cursor.fetchone()
        if not user:
            return None
        
        stored_hash = user["password_hash"]
        if verify_password(password, stored_hash):
            # Auto-upgrade legacy sha256 to modern scrypt
            if is_legacy_hash(stored_hash):
                try:
                    new_hash = hash_password(password)
                    cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user["id"]))
                    conn.commit()
                except Exception as ex:
                    logger.warning(f"Failed to auto-upgrade legacy hash for user {user['id']}: {ex}")
            
            u = dict(user)
            u.pop("password_hash", None)
            u.pop("two_factor_secret_encrypted", None)
            u["name"] = u.get("full_name", "")
            u["two_factor_enabled"] = bool(u.get("two_factor_enabled", 0))
            return u
        return None
    finally:
        conn.close()

def create_session(user_id: str) -> str:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        token = secrets.token_hex(32)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        expires = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
        INSERT INTO sessions (token, user_id, created_at, expires_at)
        VALUES (?, ?, ?, ?)
        """, (token, user_id, now, expires))
        conn.commit()
        return token
    finally:
        conn.close()

def get_user_by_token(token: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
        SELECT u.id, u.username, u.email, u.full_name, u.role, u.created_at,
               u.two_factor_enabled, u.two_factor_enabled_at, u.two_factor_last_verified_at
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token = ? AND s.expires_at > ?
        """, (token, now))
        row = cursor.fetchone()
        if row:
            d = dict(row)
            d["name"] = d.get("full_name", "")
            d["two_factor_enabled"] = bool(d.get("two_factor_enabled", 0))
            return d
        return None
    finally:
        conn.close()

def delete_session(token: str) -> bool:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
        deleted = cursor.rowcount > 0
        conn.commit()
        return deleted
    finally:
        conn.close()

def delete_user_sessions(user_id: str) -> int:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        count = cursor.rowcount
        conn.commit()
        return count
    finally:
        conn.close()

def create_password_reset_otp(email: str) -> Dict[str, Any]:
    """
    Generate a cryptographically secure 6-digit numeric OTP with SHA-256 hashing,
    10-minute expiration, rate limiting (60s cooldown, max 5/hr), and single-active-OTP enforcement.
    Does NOT reveal account existence directly to external callers.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        clean_email = email.strip().lower()
        cursor.execute("SELECT id, email, username FROM users WHERE LOWER(email) = ?", (clean_email,))
        user = cursor.fetchone()
        if not user:
            # Dummy timing calculation to equalize response timing
            hashlib.sha256(f"dummy_salt_{clean_email}".encode()).hexdigest()
            return {"status": "user_not_found"}

        user_id = user["id"]
        now = datetime.now()
        now_str = now.strftime("%Y-%m-%d %H:%M:%S")

        # 1. Rate limiting - Cooldown: must wait at least 60 seconds between OTP requests
        cutoff_cooldown = (now - timedelta(seconds=60)).strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            SELECT created_at FROM password_resets 
            WHERE user_id = ? AND created_at > ? AND consumed_at IS NULL
            ORDER BY created_at DESC LIMIT 1
        """, (user_id, cutoff_cooldown))
        if cursor.fetchone():
            return {
                "status": "rate_limited",
                "detail": "Please wait 60 seconds before requesting another verification code."
            }

        # 2. Rate limiting - Hourly limit: maximum 5 OTP requests per hour
        cutoff_hourly = (now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            SELECT COUNT(*) as cnt FROM password_resets 
            WHERE user_id = ? AND created_at > ?
        """, (user_id, cutoff_hourly))
        hourly_row = cursor.fetchone()
        if hourly_row and hourly_row["cnt"] >= 5:
            return {
                "status": "rate_limited",
                "detail": "Too many verification code requests. Please try again later."
            }

        # 3. Invalidate previously active OTPs for this user
        cursor.execute("""
            UPDATE password_resets 
            SET consumed_at = ? 
            WHERE user_id = ? AND consumed_at IS NULL
        """, (now_str, user_id))

        # 4. Generate cryptographically secure 6-digit numeric OTP (000000 - 999999)
        raw_otp = f"{secrets.randbelow(1_000_000):06d}"
        otp_hash = hashlib.sha256(raw_otp.encode("utf-8")).hexdigest()
        expires_at = (now + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
        reset_id = f"rst-{secrets.token_hex(8)}"

        cursor.execute("""
            INSERT INTO password_resets (
                id, user_id, email, otp_hash, token_hash, reset_token_hash, expires_at, used_at, created_at, attempts, consumed_at
            ) VALUES (?, ?, ?, ?, '', NULL, ?, NULL, ?, 0, NULL)
        """, (reset_id, user_id, user["email"], otp_hash, expires_at, now_str))
        conn.commit()

        return {
            "status": "ok",
            "user": dict(user),
            "raw_otp": raw_otp,
            "reset_id": reset_id,
            "expires_at": expires_at
        }
    finally:
        conn.close()


def verify_password_reset_otp(email: str, otp: str) -> Tuple[bool, str, Optional[str]]:
    """
    Verify the 6-digit OTP using constant-time comparison, enforce max 5 attempts,
    check expiration, and on success issue a short-lived, single-use reset authorization token.
    """
    clean_email = email.strip().lower()
    clean_otp = str(otp).strip()

    if not clean_otp or len(clean_otp) != 6 or not clean_otp.isdigit():
        return False, "Invalid verification code. Code must be 6 digits.", None

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, email FROM users WHERE LOWER(email) = ?", (clean_email,))
        user = cursor.fetchone()
        if not user:
            hashlib.sha256(clean_otp.encode()).hexdigest()
            return False, "Invalid or expired verification code.", None

        user_id = user["id"]
        now = datetime.now()
        now_str = now.strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""
            SELECT * FROM password_resets 
            WHERE user_id = ? AND consumed_at IS NULL AND verified_at IS NULL
            ORDER BY created_at DESC LIMIT 1
        """, (user_id,))
        record = cursor.fetchone()
        if not record:
            return False, "No active verification code found. Please request a new code.", None

        # 1. Check expiration
        if record["expires_at"] <= now_str:
            cursor.execute("UPDATE password_resets SET consumed_at = ? WHERE id = ?", (now_str, record["id"]))
            conn.commit()
            return False, "Your verification code has expired. Please request a new code.", None

        # 2. Check attempt count
        current_attempts = record["attempts"] or 0
        if current_attempts >= 5:
            cursor.execute("UPDATE password_resets SET consumed_at = ? WHERE id = ?", (now_str, record["id"]))
            conn.commit()
            return False, "Too many incorrect attempts. This verification code has been invalidated. Please request a new code.", None

        # 3. Increment attempt counter
        new_attempts = current_attempts + 1
        cursor.execute("UPDATE password_resets SET attempts = ? WHERE id = ?", (new_attempts, record["id"]))

        # 4. Constant-time hash comparison
        computed_hash = hashlib.sha256(clean_otp.encode("utf-8")).hexdigest()
        stored_hash = record["otp_hash"] or ""
        if not hmac.compare_digest(stored_hash, computed_hash):
            conn.commit()
            remaining = 5 - new_attempts
            if remaining > 0:
                return False, f"Invalid verification code. {remaining} attempt(s) remaining.", None
            else:
                cursor.execute("UPDATE password_resets SET consumed_at = ? WHERE id = ?", (now_str, record["id"]))
                conn.commit()
                return False, "Too many incorrect attempts. This verification code has been invalidated. Please request a new code.", None

        # 5. Success: Issue cryptographically secure, single-use reset authorization token
        reset_auth = f"rst-auth-{secrets.token_urlsafe(32)}"
        auth_hash = hashlib.sha256(reset_auth.encode("utf-8")).hexdigest()
        auth_expires = (now + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""
            UPDATE password_resets 
            SET verified_at = ?, reset_token_hash = ?, token_hash = ?, expires_at = ?
            WHERE id = ?
        """, (now_str, auth_hash, auth_hash, auth_expires, record["id"]))
        conn.commit()

        return True, "Verification code confirmed.", reset_auth
    finally:
        conn.close()


def complete_password_reset_v2(reset_auth: str, new_password: str) -> bool:
    """
    Validate server-issued reset authorization, verify OTP confirmation state,
    hash new password, update user credentials, and invalidate sessions and OTP records.
    """
    if not new_password or len(new_password) < 8:
        raise ValueError("New password must be at least 8 characters.")

    auth_token = reset_auth.strip()
    auth_hash = hashlib.sha256(auth_token.encode("utf-8")).hexdigest()
    now = datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM password_resets 
            WHERE (reset_token_hash = ? OR token_hash = ?)
        """, (auth_hash, auth_hash))
        record = cursor.fetchone()
        if not record:
            raise ValueError("Invalid or unknown password reset authorization.")

        if record["consumed_at"] is not None or record["used_at"] is not None:
            raise ValueError("This password reset authorization has already been used.")

        if record["expires_at"] <= now_str:
            raise ValueError("This password reset authorization has expired. Please request a new code.")

        if not record["verified_at"] and not record["token_hash"]:
            raise ValueError("Password reset authorization has not been verified via OTP.")

        user_id = record["user_id"]
        new_hash = hash_password(new_password)

        # Update user password
        cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))

        # Invalidate this authorization record
        cursor.execute("UPDATE password_resets SET consumed_at = ?, used_at = ? WHERE id = ?", (now_str, now_str, record["id"]))

        # Invalidate any remaining reset records for this user
        cursor.execute("UPDATE password_resets SET consumed_at = ? WHERE user_id = ? AND consumed_at IS NULL", (now_str, user_id))

        # Invalidate active user sessions
        cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.commit()
        return True
    finally:
        conn.close()


# Legacy wrappers for backward compatibility
def create_password_reset(email: str) -> Optional[Tuple[str, str]]:
    """Legacy helper: generates an OTP-backed reset record."""
    res = create_password_reset_otp(email)
    if res.get("status") != "ok":
        return None
    return res["raw_otp"], res["user"]["email"]


def validate_reset_token(raw_token: str) -> Dict[str, Any]:
    """Legacy helper: checks token validity."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        token_hash = hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("SELECT * FROM password_resets WHERE (reset_token_hash = ? OR token_hash = ?)", (token_hash, token_hash))
        record = cursor.fetchone()
        if not record:
            return {"valid": False, "reason": "Invalid or unknown password reset token."}
        if record["consumed_at"] is not None or record["used_at"] is not None:
            return {"valid": False, "reason": "This password reset token has already been used."}
        if record["expires_at"] <= now_str:
            return {"valid": False, "reason": "This password reset token has expired. Please request a new one."}
        return {"valid": True, "record": dict(record)}
    finally:
        conn.close()


def complete_password_reset(raw_token: str, new_password: str) -> bool:
    """Legacy helper: completes password reset using token."""
    return complete_password_reset_v2(raw_token, new_password)


def seed_default_users_if_empty():
    init_db()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        if count > 0:
            return

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        default_users = [
            {
                "id": "user-learner-001",
                "username": "learner",
                "email": "learner@tracegate.lab",
                "password": "Password123!",
                "full_name": "Security Learner",
                "role": "Junior Pentester"
            },
            {
                "id": "user-admin-001",
                "username": "admin",
                "email": "admin@tracegate.lab",
                "password": "AdminPassword123!",
                "full_name": "Lead Security Assessor",
                "role": "Lead Auditor"
            }
        ]
        for u in default_users:
            cursor.execute("""
            INSERT INTO users (id, username, email, password_hash, full_name, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (u["id"], u["username"], u["email"], hash_password(u["password"]), u["full_name"], u["role"], now))
        conn.commit()
        logger.info("Default user accounts seeded (learner & admin).")
    finally:
        conn.close()

# =========================================================================
# TWO-FACTOR AUTHENTICATION (TOTP) CRUD
# =========================================================================

def get_user_by_id_raw(user_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def get_user_2fa_status(user_id: str) -> Dict[str, Any]:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT two_factor_enabled, two_factor_enabled_at, two_factor_last_verified_at FROM users WHERE id = ?", (user_id,))
        user_row = cursor.fetchone()
        if not user_row:
            return {"enabled": False, "enabled_at": None, "last_verified_at": None, "recovery_codes_remaining": 0}
        
        cursor.execute("SELECT COUNT(*) FROM two_factor_recovery_codes WHERE user_id = ? AND used_at IS NULL", (user_id,))
        rec_count = cursor.fetchone()[0]

        return {
            "enabled": bool(user_row["two_factor_enabled"]),
            "enabled_at": user_row["two_factor_enabled_at"],
            "last_verified_at": user_row["two_factor_last_verified_at"],
            "recovery_codes_remaining": rec_count
        }
    finally:
        conn.close()

def save_pending_2fa_enrollment(user_id: str, secret_encrypted: str, ttl_minutes: int = 15) -> str:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        now = datetime.now()
        now_str = now.strftime("%Y-%m-%d %H:%M:%S")
        expires_str = (now + timedelta(minutes=ttl_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT INTO two_factor_pending_enrollments (user_id, secret_encrypted, created_at, expires_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT (user_id) DO UPDATE SET
                secret_encrypted = EXCLUDED.secret_encrypted,
                created_at = EXCLUDED.created_at,
                expires_at = EXCLUDED.expires_at
        """, (user_id, secret_encrypted, now_str, expires_str))
        conn.commit()
        return expires_str
    finally:
        conn.close()

def get_pending_2fa_enrollment(user_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            SELECT * FROM two_factor_pending_enrollments
            WHERE user_id = ? AND expires_at > ?
        """, (user_id, now_str))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def delete_pending_2fa_enrollment(user_id: str) -> bool:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM two_factor_pending_enrollments WHERE user_id = ?", (user_id,))
        deleted = cursor.rowcount > 0
        conn.commit()
        return deleted
    finally:
        conn.close()

def enable_user_2fa(user_id: str, secret_encrypted: str, recovery_code_hashes: List[str]) -> bool:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            UPDATE users
            SET two_factor_enabled = 1,
                two_factor_secret_encrypted = ?,
                two_factor_enabled_at = ?,
                two_factor_last_verified_at = ?
            WHERE id = ?
        """, (secret_encrypted, now_str, now_str, user_id))
        
        cursor.execute("DELETE FROM two_factor_pending_enrollments WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM two_factor_recovery_codes WHERE user_id = ?", (user_id,))
        
        for ch in recovery_code_hashes:
            rec_id = f"rc-{secrets.token_hex(8)}"
            cursor.execute("""
                INSERT INTO two_factor_recovery_codes (id, user_id, code_hash, used_at, created_at)
                VALUES (?, ?, ?, NULL, ?)
            """, (rec_id, user_id, ch, now_str))
        
        conn.commit()
        return True
    finally:
        conn.close()

def disable_user_2fa(user_id: str) -> bool:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users
            SET two_factor_enabled = 0,
                two_factor_secret_encrypted = NULL,
                two_factor_enabled_at = NULL,
                two_factor_last_verified_at = NULL
            WHERE id = ?
        """, (user_id,))
        cursor.execute("DELETE FROM two_factor_pending_enrollments WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM two_factor_recovery_codes WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM two_factor_pending_logins WHERE user_id = ?", (user_id,))
        conn.commit()
        return True
    finally:
        conn.close()

def replace_recovery_codes(user_id: str, recovery_code_hashes: List[str]) -> bool:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("DELETE FROM two_factor_recovery_codes WHERE user_id = ?", (user_id,))
        for ch in recovery_code_hashes:
            rec_id = f"rc-{secrets.token_hex(8)}"
            cursor.execute("""
                INSERT INTO two_factor_recovery_codes (id, user_id, code_hash, used_at, created_at)
                VALUES (?, ?, ?, NULL, ?)
            """, (rec_id, user_id, ch, now_str))
        conn.commit()
        return True
    finally:
        conn.close()

def create_pending_2fa_login(user_id: str, ttl_minutes: int = 5) -> str:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM two_factor_pending_logins WHERE user_id = ?", (user_id,))
        
        token = f"2fa_pend_{secrets.token_urlsafe(32)}"
        now = datetime.now()
        now_str = now.strftime("%Y-%m-%d %H:%M:%S")
        expires_str = (now + timedelta(minutes=ttl_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        
        cursor.execute("""
            INSERT INTO two_factor_pending_logins (token, user_id, attempts, created_at, expires_at)
            VALUES (?, ?, 0, ?, ?)
        """, (token, user_id, now_str, expires_str))
        conn.commit()
        return token
    finally:
        conn.close()

def get_pending_2fa_login(token: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            SELECT * FROM two_factor_pending_logins
            WHERE token = ? AND expires_at > ?
        """, (token, now_str))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def increment_pending_2fa_attempts(token: str) -> int:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE two_factor_pending_logins SET attempts = attempts + 1 WHERE token = ?", (token,))
        cursor.execute("SELECT attempts FROM two_factor_pending_logins WHERE token = ?", (token,))
        row = cursor.fetchone()
        conn.commit()
        return row[0] if row else 999
    finally:
        conn.close()

def delete_pending_2fa_login(token: str) -> bool:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM two_factor_pending_logins WHERE token = ?", (token,))
        deleted = cursor.rowcount > 0
        conn.commit()
        return deleted
    finally:
        conn.close()

def verify_and_consume_recovery_code(user_id: str, raw_code: str) -> bool:
    if not raw_code:
        return False
    from backend.totp_service import hash_recovery_code
    code_hash = hash_recovery_code(raw_code)
    
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id FROM two_factor_recovery_codes
            WHERE user_id = ? AND code_hash = ? AND used_at IS NULL
            LIMIT 1
        """, (user_id, code_hash))
        row = cursor.fetchone()
        if not row:
            return False
        
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("UPDATE two_factor_recovery_codes SET used_at = ? WHERE id = ?", (now_str, row["id"]))
        cursor.execute("UPDATE users SET two_factor_last_verified_at = ? WHERE id = ?", (now_str, user_id))
        conn.commit()
        return True
    finally:
        conn.close()

def update_user_2fa_verified_timestamp(user_id: str):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("UPDATE users SET two_factor_last_verified_at = ? WHERE id = ?", (now_str, user_id))
        conn.commit()
    finally:
        conn.close()

# =========================================================================
# REPORTS CRUD
# =========================================================================

def _hydrate_report_row(row_dict: Any) -> Dict[str, Any]:
    if not row_dict:
        return {}
    d = dict(row_dict)
    d["download_url"] = f"/api/projects/{d['project_id']}/reports/{d['id']}/download"
    d["docx_download_url"] = f"/api/projects/{d['project_id']}/reports/{d['id']}/download?format=docx"
    d["pdf_download_url"] = f"/api/projects/{d['project_id']}/reports/{d['id']}/download?format=pdf"
    d["filename"] = Path(d["file_path"]).name if d.get("file_path") else f"{d['project_id']}_{d['version']}.docx"
    d["author_name"] = d.get("created_by", "Security Learner")
    d["findings_count"] = d.get("total_findings", 0)
    d["info_count"] = d.get("info_count", 0)

    # Validate PDF artifact on disk
    from backend.pdf_validator import is_valid_pdf
    pdf_path = d.get("file_path_pdf")
    if not pdf_path and d.get("file_path"):
        cand = Path(d["file_path"]).with_suffix(".pdf")
        if cand.exists():
            pdf_path = str(cand)

    if pdf_path and is_valid_pdf(pdf_path):
        d["file_path_pdf"] = str(pdf_path)
        d["pdf_available"] = True
    else:
        d["pdf_available"] = False

    if d.get("selected_finding_ids") and isinstance(d["selected_finding_ids"], str):
        try:
            d["selected_finding_ids"] = json.loads(d["selected_finding_ids"])
        except Exception:
            d["selected_finding_ids"] = []
    else:
        d["selected_finding_ids"] = d.get("selected_finding_ids") or []
    return d

_REPORT_SAVE_LOCK = threading.Lock()

def get_next_report_version(project_id: str, cursor: Optional[sqlite3.Cursor] = None) -> str:
    """
    Computes the server-authoritative next sequential report version (e.g. v1.0 -> v2.0 -> v3.0)
    for a given project by inspecting all existing versions recorded for that project.
    """
    close_conn = False
    conn = None
    if cursor is None:
        conn = get_db_connection()
        cursor = conn.cursor()
        close_conn = True

    try:
        cursor.execute("SELECT version FROM reports WHERE project_id = ?", (project_id,))
        rows = cursor.fetchall()
        max_major = 0
        for r in rows:
            v_val = r["version"] if isinstance(r, sqlite3.Row) else r[0]
            if v_val:
                m = re.search(r"(\d+)(?:\.(\d+))?", str(v_val))
                if m:
                    try:
                        maj = int(m.group(1))
                        if maj > max_major:
                            max_major = maj
                    except Exception:
                        pass
        return f"v{max_major + 1}.0"
    finally:
        if close_conn and conn:
            conn.close()

def save_report_record(data: Dict[str, Any]) -> Dict[str, Any]:
    with _REPORT_SAVE_LOCK:
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rep_id = data.get("id") or f"rep-{int(datetime.now().timestamp()*1000)}"
        sel_ids = data.get("selected_finding_ids")
        sel_ids_json = json.dumps(sel_ids) if isinstance(sel_ids, list) else (sel_ids or "[]")
        pdf_path = data.get("file_path_pdf")
        project_id = data["project_id"]

        # Ensure server-authoritative sequential versioning without duplicates
        cursor.execute("SELECT version FROM reports WHERE project_id = ?", (project_id,))
        existing_versions = {r["version"] for r in cursor.fetchall() if r["version"]}
        req_version = data.get("version")
        if not req_version or req_version in existing_versions:
            req_version = get_next_report_version(project_id, cursor=cursor)
            data["version"] = req_version

        cursor.execute("PRAGMA table_info(reports)")
        cols = [r["name"] for r in cursor.fetchall()]
        fields = [
            "id", "project_id", "version", "report_title", "file_path",
            "total_findings", "crit_count", "high_count", "med_count", "low_count", "info_count",
            "selected_finding_ids", "created_by", "methodology", "created_at"
        ]
        values = [
            rep_id,
            project_id,
            req_version,
            data.get("report_title", "Penetration Testing Assessment Report"),
            data["file_path"],
            data.get("total_findings", 0),
            data.get("crit_count", 0),
            data.get("high_count", 0),
            data.get("med_count", 0),
            data.get("low_count", 0),
            data.get("info_count", 0),
            sel_ids_json,
            data.get("created_by", "Security Learner"),
            data.get("methodology", "owasp_wstg"),
            now
        ]
        if "file_path_pdf" in cols:
            fields.append("file_path_pdf")
            values.append(pdf_path)
        if "file_data_docx" in cols:
            fields.append("file_data_docx")
            values.append(data.get("file_data_docx"))
        if "file_data_pdf" in cols:
            fields.append("file_data_pdf")
            values.append(data.get("file_data_pdf"))

        placeholders = ", ".join(["?"] * len(fields))
        col_names = ", ".join(fields)
        cursor.execute(f"INSERT INTO reports ({col_names}) VALUES ({placeholders})", values)
        conn.commit()
        cursor.execute("SELECT * FROM reports WHERE id = ?", (rep_id,))
        row = cursor.fetchone()
        conn.close()
        return _hydrate_report_row(row)

def update_report_artifact_data(report_id: str, file_data_docx: Optional[str] = None, file_data_pdf: Optional[str] = None) -> bool:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(reports)")
        cols = [r["name"] for r in cursor.fetchall()]
        updates = []
        vals = []
        if file_data_docx and "file_data_docx" in cols:
            updates.append("file_data_docx = ?")
            vals.append(file_data_docx)
        if file_data_pdf and "file_data_pdf" in cols:
            updates.append("file_data_pdf = ?")
            vals.append(file_data_pdf)
        if updates:
            vals.append(report_id)
            cursor.execute(f"UPDATE reports SET {', '.join(updates)} WHERE id = ?", vals)
            conn.commit()
            return True
        return False
    finally:
        conn.close()

def update_report_pdf_path(report_id: str, pdf_path: str) -> bool:
    """Updates verified file_path_pdf for a report record."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(reports)")
    cols = [r["name"] for r in cursor.fetchall()]
    if "file_path_pdf" not in cols:
        cursor.execute("ALTER TABLE reports ADD COLUMN file_path_pdf TEXT")
    cursor.execute("UPDATE reports SET file_path_pdf = ? WHERE id = ?", (str(pdf_path), report_id))
    conn.commit()
    updated = cursor.rowcount > 0
    conn.close()
    return updated

def get_project_reports(project_id: str) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM reports WHERE project_id = ? ORDER BY created_at DESC", (project_id,))
    rows = cursor.fetchall()
    conn.close()
    return [_hydrate_report_row(r) for r in rows]

def get_report_by_id(report_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM reports WHERE id = ?", (report_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return _hydrate_report_row(row)

# =============================================================================
# SOURCE DISCOVERY & MULTI-FILE REPOSITORY PERSISTENCE
# =============================================================================

def _hydrate_source_discovery_row(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    for field in ["selected_sources", "candidate_sources"]:
        json_field = f"{field}_json"
        if json_field in d and isinstance(d[json_field], str):
            try:
                d[field] = json.loads(d[json_field])
            except Exception:
                d[field] = []
        else:
            d[field] = d.get(field) or []
    d["selection_mode"] = d.get("selection_source") or "AUTOMATIC"
    d["repo"] = d.get("repository") or ""
    return d

def save_source_discovery(data: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
    if data is None:
        data = kwargs
    elif isinstance(data, dict) and kwargs:
        data = {**data, **kwargs}
    elif not isinstance(data, dict):
        data = kwargs

    conn = get_db_connection()
    cursor = conn.cursor()
    record_id = data.get("id") or str(uuid.uuid4())
    now = datetime.now().isoformat()
    project_id = data.get("project_id", "")
    finding_id = data.get("finding_id", "")
    repository = data.get("repository") or data.get("repo") or ""
    branch = data.get("branch", "main")
    source_commit_sha = data.get("source_commit_sha", "main")

    selected_sources = data.get("selected_sources") or []
    candidate_sources = data.get("candidate_sources") or []
    selection_source = data.get("selection_mode") or data.get("selection_source", "AUTOMATIC")
    discovery_status = data.get("discovery_status", "COMPLETED")

    # Serialize items cleanly, converting Pydantic models to dict if needed
    clean_sel = [s.model_dump() if hasattr(s, "model_dump") else (s.dict() if hasattr(s, "dict") else s) for s in selected_sources]
    clean_cand = [c.model_dump() if hasattr(c, "model_dump") else (c.dict() if hasattr(c, "dict") else c) for c in candidate_sources]
    sel_json = json.dumps(clean_sel)
    cand_json = json.dumps(clean_cand)

    # Scoped query to prevent cross-project or cross-repo cache collisions
    if repository and project_id:
        cursor.execute("SELECT id FROM source_discovery_results WHERE finding_id = ? AND repository = ? AND project_id = ?", (finding_id, repository, project_id))
    elif repository:
        cursor.execute("SELECT id FROM source_discovery_results WHERE finding_id = ? AND repository = ?", (finding_id, repository))
    elif project_id:
        cursor.execute("SELECT id FROM source_discovery_results WHERE finding_id = ? AND project_id = ?", (finding_id, project_id))
    else:
        cursor.execute("SELECT id FROM source_discovery_results WHERE finding_id = ?", (finding_id,))
    existing = cursor.fetchone()
    if existing:
        record_id = existing["id"]
        cursor.execute("""
            UPDATE source_discovery_results
            SET project_id = ?, repository = ?, branch = ?, source_commit_sha = ?,
                selected_sources_json = ?, candidate_sources_json = ?,
                selection_source = ?, discovery_status = ?, updated_at = ?
            WHERE id = ?
        """, (project_id, repository, branch, source_commit_sha, sel_json, cand_json, selection_source, discovery_status, now, record_id))
    else:
        cursor.execute("""
            INSERT INTO source_discovery_results (
                id, project_id, finding_id, repository, branch, source_commit_sha,
                selected_sources_json, candidate_sources_json, selection_source,
                discovery_status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (record_id, project_id, finding_id, repository, branch, source_commit_sha, sel_json, cand_json, selection_source, discovery_status, now, now))
    conn.commit()
    cursor.execute("SELECT * FROM source_discovery_results WHERE id = ?", (record_id,))
    row = cursor.fetchone()
    conn.close()
    return _hydrate_source_discovery_row(row) if row else {}

def get_source_discovery(finding_id: str, project_id: Optional[str] = None, repo: Optional[str] = None) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    if repo and project_id:
        cursor.execute("SELECT * FROM source_discovery_results WHERE finding_id = ? AND repository = ? AND project_id = ?", (finding_id, repo, project_id))
    elif repo:
        cursor.execute("SELECT * FROM source_discovery_results WHERE finding_id = ? AND repository = ?", (finding_id, repo))
    elif project_id:
        cursor.execute("SELECT * FROM source_discovery_results WHERE finding_id = ? AND project_id = ?", (finding_id, project_id))
    else:
        cursor.execute("SELECT * FROM source_discovery_results WHERE finding_id = ?", (finding_id,))
    row = cursor.fetchone()
    conn.close()
    return _hydrate_source_discovery_row(row) if row else None

def update_source_discovery_selection(
    finding_id: str,
    selected_paths: List[str],
    project_id: Optional[str] = None,
    source_commit_sha: Optional[str] = None,
    repo: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    existing = get_source_discovery(finding_id, project_id=project_id, repo=repo)
    now = datetime.utcnow().isoformat()
    if not existing:
        new_record = {
            "finding_id": finding_id,
            "project_id": project_id or "",
            "repository": repo or "",
            "branch": "main",
            "source_commit_sha": source_commit_sha or "main",
            "selected_sources": [{"path": p, "layer": "source", "language": "Unknown", "confidence": "MANUAL", "relevance_score": 100, "reasons": ["Manually selected by developer"]} for p in selected_paths],
            "candidate_sources": [],
            "selection_source": "USER_MODIFIED",
            "discovery_status": "COMPLETED"
        }
        return save_source_discovery(new_record)

    curr_selected = existing.get("selected_sources") or []
    curr_candidates = existing.get("candidate_sources") or []
    all_known_items = {item["path"]: item for item in (curr_selected + curr_candidates) if isinstance(item, dict) and "path" in item}

    new_selected = []
    for p in selected_paths:
        if p in all_known_items:
            new_selected.append(all_known_items[p])
        else:
            new_selected.append({
                "path": p,
                "layer": "source",
                "language": "Unknown",
                "confidence": "MANUAL",
                "relevance_score": 100,
                "reasons": ["Manually selected by developer"]
            })

    selected_paths_set = set(selected_paths)
    new_candidates = [item for item in (curr_selected + curr_candidates) if isinstance(item, dict) and item.get("path") not in selected_paths_set]

    existing["selected_sources"] = new_selected
    existing["candidate_sources"] = new_candidates
    existing["selection_source"] = "USER_MODIFIED"
    if repo:
        existing["repository"] = repo
    if source_commit_sha:
        existing["source_commit_sha"] = source_commit_sha
    return save_source_discovery(existing)

# =========================================================================
# AI AUTOFIX REMEDIATION RUNS & LIFECYCLE RECOVERY PERSISTENCE
# =========================================================================

def _hydrate_remediation_run(row_dict: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not row_dict:
        return None
    d = dict(row_dict)
    for json_field, target_key in [
        ("finding_ids_json", "finding_ids"),
        ("result_json", "result"),
        ("errors_json", "errors")
    ]:
        raw = d.get(json_field)
        if raw and isinstance(raw, str):
            try:
                d[target_key] = json.loads(raw)
            except Exception:
                d[target_key] = [] if "ids" in target_key or "errors" in target_key else {}
        else:
            d[target_key] = [] if "ids" in target_key or "errors" in target_key else None
    return d

def _parse_run_datetime(dt_str: Optional[str]) -> Optional[datetime]:
    if not dt_str:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(dt_str.split("+")[0].split("Z")[0], fmt)
        except Exception:
            continue
    return None

def create_remediation_run(
    run_id: str,
    user_id: str,
    project_id: str,
    repository: str,
    branch: str = "main",
    finding_ids: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Creates a new remediation run with strict duplicate run prevention
    and automatic stale run recovery.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    now_dt = datetime.now()
    now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")

    # 1. Check for existing active runs for this user/project/repo
    cursor.execute("""
        SELECT * FROM remediation_runs
        WHERE user_id = ? AND project_id = ? AND repository = ? AND branch = ? AND is_active = 1
        ORDER BY started_at DESC LIMIT 1
    """, (user_id, project_id, repository, branch))
    active_row = cursor.fetchone()

    if active_row:
        active_dict = dict(active_row)
        upd_dt = _parse_run_datetime(active_dict.get("updated_at"))
        # Stale run recovery: if running > 90 seconds without progress, recover it
        if upd_dt and (now_dt - upd_dt).total_seconds() > 90:
            cursor.execute("""
                UPDATE remediation_runs
                SET status = 'REVIEW_REQUIRED',
                    current_stage = 'FAILED',
                    progress_message = 'Previous remediation run stopped unexpectedly.',
                    is_active = 0,
                    finished_at = ?,
                    updated_at = ?
                WHERE id = ?
            """, (now_str, now_str, active_dict["id"]))
            conn.commit()
        else:
            # Active run is still alive and fresh: prevent duplicate run
            conn.close()
            hydrated = _hydrate_remediation_run(active_dict)
            hydrated["is_duplicate"] = True
            return hydrated

    # 2. Insert new remediation run
    fids = finding_ids or []
    fids_json = json.dumps(fids)
    cursor.execute("""
        INSERT INTO remediation_runs (
            id, user_id, project_id, repository, branch,
            finding_ids_json, status, current_stage, progress_stage,
            progress_message, started_at, updated_at, is_active
        ) VALUES (?, ?, ?, ?, ?, ?, 'RUN_CREATED', 'INITIALIZING', '1/4',
                  '1/4 Analyzing repository architecture & dynamic file tree...',
                  ?, ?, 1)
    """, (run_id, user_id, project_id, repository, branch, fids_json, now_str, now_str))
    conn.commit()

    cursor.execute("SELECT * FROM remediation_runs WHERE id = ?", (run_id,))
    new_row = cursor.fetchone()
    conn.close()
    hydrated = _hydrate_remediation_run(dict(new_row))
    hydrated["is_duplicate"] = False
    return hydrated

_last_run_progress: Dict[str, Tuple[str, str, str, str, Optional[str]]] = {}

def update_remediation_run_progress(
    run_id: str,
    status: str,
    current_stage: str,
    progress_stage: str,
    progress_message: str,
    errors: Optional[List[str]] = None
) -> Optional[Dict[str, Any]]:
    errs_json = json.dumps(errors) if errors else None
    progress_key = (status, current_stage, progress_stage, progress_message, errs_json)

    # Suppress redundant disk writes when progress state is unchanged
    if _last_run_progress.get(run_id) == progress_key:
        return get_remediation_run(run_id)

    _last_run_progress[run_id] = progress_key
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if errs_json is not None:
        cursor.execute("""
            UPDATE remediation_runs
            SET status = ?, current_stage = ?, progress_stage = ?, progress_message = ?,
                errors_json = ?, updated_at = ?
            WHERE id = ?
        """, (status, current_stage, progress_stage, progress_message, errs_json, now_str, run_id))
    else:
        cursor.execute("""
            UPDATE remediation_runs
            SET status = ?, current_stage = ?, progress_stage = ?, progress_message = ?, updated_at = ?
            WHERE id = ?
        """, (status, current_stage, progress_stage, progress_message, now_str, run_id))
    conn.commit()

    cursor.execute("SELECT * FROM remediation_runs WHERE id = ?", (run_id,))
    row = cursor.fetchone()
    conn.close()
    return _hydrate_remediation_run(dict(row)) if row else None

def finalize_remediation_run(
    run_id: str,
    status: str,
    result_dict: Dict[str, Any],
    errors: Optional[List[str]] = None
) -> Optional[Dict[str, Any]]:
    _last_run_progress.pop(run_id, None)
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    res_json = json.dumps(result_dict)
    errs_json = json.dumps(errors) if errors else None

    cursor.execute("""
        UPDATE remediation_runs
        SET status = ?, current_stage = 'FINALIZED', progress_stage = '4/4',
            progress_message = 'Remediation run completed.',
            result_json = ?, errors_json = COALESCE(?, errors_json),
            is_active = 0, finished_at = ?, updated_at = ?
        WHERE id = ?
    """, (status, res_json, errs_json, now_str, now_str, run_id))
    conn.commit()

    cursor.execute("SELECT * FROM remediation_runs WHERE id = ?", (run_id,))
    row = cursor.fetchone()
    conn.close()
    return _hydrate_remediation_run(dict(row)) if row else None

def update_remediation_run_pr_metadata(
    run_id: Optional[str],
    pr_number: int,
    pr_url: str,
    fix_branch: str,
    commit_sha: str,
    status: str = "PR_CREATED",
    project_id: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Persists Pull Request metadata into remediation_runs table and updates lifecycle status.
    Ensures PR information survives browser refresh, backend restart, and deployment.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    target_run = None
    if run_id:
        cursor.execute("SELECT * FROM remediation_runs WHERE id = ?", (run_id,))
        target_run = cursor.fetchone()
    if not target_run and project_id:
        cursor.execute(
            "SELECT * FROM remediation_runs WHERE project_id = ? ORDER BY started_at DESC LIMIT 1",
            (project_id,)
        )
        target_run = cursor.fetchone()

    if not target_run:
        conn.close()
        return None

    actual_run_id = target_run["id"]
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    raw_res = target_run["result_json"]
    res_dict = {}
    if raw_res:
        try:
            res_dict = json.loads(raw_res)
        except Exception:
            res_dict = {}

    res_dict["pr_number"] = pr_number
    res_dict["pr_url"] = pr_url
    res_dict["fix_branch"] = fix_branch
    res_dict["commit_sha"] = commit_sha
    res_dict["pr_status"] = "Open"
    if "remediation_summary" in res_dict and isinstance(res_dict["remediation_summary"], dict):
        res_dict["remediation_summary"]["pr_number"] = pr_number
        res_dict["remediation_summary"]["pr_url"] = pr_url
        res_dict["remediation_summary"]["fix_branch"] = fix_branch
        res_dict["remediation_summary"]["commit_sha"] = commit_sha

    new_res_json = json.dumps(res_dict)
    msg = f"GitHub Pull Request #{pr_number} created successfully: {pr_url}"

    cursor.execute("""
        UPDATE remediation_runs
        SET status = ?, current_stage = 'PR_CREATED', progress_stage = '4/4',
            progress_message = ?, result_json = ?, updated_at = ?
        WHERE id = ?
    """, (status, msg, new_res_json, now_str, actual_run_id))
    conn.commit()

    cursor.execute("SELECT * FROM remediation_runs WHERE id = ?", (actual_run_id,))
    updated_row = cursor.fetchone()
    conn.close()
    return _hydrate_remediation_run(dict(updated_row)) if updated_row else None


def get_remediation_run(run_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM remediation_runs WHERE id = ?", (run_id,))
    row = cursor.fetchone()
    conn.close()
    return _hydrate_remediation_run(dict(row)) if row else None

def get_active_or_latest_remediation_run(
    user_id: str,
    project_id: str,
    repository: Optional[str] = None,
    branch: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    now_dt = datetime.now()
    now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")

    # 1. Look for active run
    query = "SELECT * FROM remediation_runs WHERE user_id = ? AND project_id = ? AND is_active = 1"
    params = [user_id, project_id]
    if repository:
        query += " AND repository = ?"
        params.append(repository)
    if branch:
        query += " AND branch = ?"
        params.append(branch)
    query += " ORDER BY started_at DESC LIMIT 1"

    cursor.execute(query, tuple(params))
    active_row = cursor.fetchone()

    if active_row:
        active_dict = dict(active_row)
        upd_dt = _parse_run_datetime(active_dict.get("updated_at"))
        # Stale run check: > 90s
        if upd_dt and (now_dt - upd_dt).total_seconds() > 90:
            cursor.execute("""
                UPDATE remediation_runs
                SET status = 'REVIEW_REQUIRED',
                    current_stage = 'FAILED',
                    progress_message = 'Previous remediation run stopped unexpectedly.',
                    is_active = 0,
                    finished_at = ?,
                    updated_at = ?
                WHERE id = ?
            """, (now_str, now_str, active_dict["id"]))
            conn.commit()
            active_dict["status"] = "REVIEW_REQUIRED"
            active_dict["current_stage"] = "FAILED"
            active_dict["progress_message"] = "Previous remediation run stopped unexpectedly."
            active_dict["is_active"] = 0
            conn.close()
            return _hydrate_remediation_run(active_dict)
        conn.close()
        return _hydrate_remediation_run(active_dict)

    # 2. Look for latest run (completed or partial)
    query2 = "SELECT * FROM remediation_runs WHERE user_id = ? AND project_id = ?"
    params2 = [user_id, project_id]
    if repository:
        query2 += " AND repository = ?"
        params2.append(repository)
    if branch:
        query2 += " AND branch = ?"
        params2.append(branch)
    query2 += " ORDER BY started_at DESC LIMIT 1"

    cursor.execute(query2, tuple(params2))
    latest_row = cursor.fetchone()
    conn.close()
    return _hydrate_remediation_run(dict(latest_row)) if latest_row else None

def cancel_remediation_run(run_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        UPDATE remediation_runs
        SET status = 'CANCELLED', current_stage = 'CANCELLED',
            progress_message = 'Remediation run cancelled by user.',
            is_active = 0, finished_at = ?, updated_at = ?
        WHERE id = ? AND user_id = ?
    """, (now_str, now_str, run_id, user_id))
    conn.commit()

    cursor.execute("SELECT * FROM remediation_runs WHERE id = ?", (run_id,))
    row = cursor.fetchone()
    conn.close()
    return _hydrate_remediation_run(dict(row)) if row else None

# =========================================================================
# VAPT ASSESSMENT COMPLETION CERTIFICATE PERSISTENCE
# =========================================================================

def _hydrate_certificate_row(row_dict: Dict[str, Any]) -> Dict[str, Any]:
    if not row_dict:
        return {}
    d = dict(row_dict)
    if d.get("snapshot_json") and isinstance(d["snapshot_json"], str):
        try:
            d["snapshot"] = json.loads(d["snapshot_json"])
        except Exception:
            d["snapshot"] = {}
    else:
        d["snapshot"] = {}
    return d

def save_certificate_record(cert_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Persist an immutable VAPT Assessment Completion Certificate record.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    snap_json = cert_data.get("snapshot_json")
    if not snap_json and "snapshot" in cert_data:
        snap_json = json.dumps(cert_data["snapshot"], indent=2)

    cursor.execute("PRAGMA table_info(vapt_certificates)")
    cols = [r["name"] for r in cursor.fetchall()]
    fields = [
        "certificate_id", "verification_id", "project_id", "assessment_id", "report_id",
        "status", "issue_date", "assessment_start", "assessment_end", "final_validation_date",
        "total_findings", "critical_count", "high_count", "medium_count", "low_count", "info_count",
        "findings_retested", "findings_passed", "findings_failed", "target_name", "target_url",
        "client_organization", "assessment_type", "assessment_scope", "snapshot_json",
        "file_path_docx", "file_path_pdf", "notice_seen", "created_at", "updated_at"
    ]
    values = [
        cert_data["certificate_id"],
        cert_data["verification_id"],
        cert_data["project_id"],
        cert_data.get("assessment_id", cert_data["project_id"]),
        cert_data.get("report_id"),
        cert_data.get("status", "VALID"),
        cert_data.get("issue_date", now[:10]),
        cert_data.get("assessment_start", now[:10]),
        cert_data.get("assessment_end", now[:10]),
        cert_data.get("final_validation_date", now[:10]),
        cert_data.get("total_findings", 0),
        cert_data.get("critical_count", 0),
        cert_data.get("high_count", 0),
        cert_data.get("medium_count", 0),
        cert_data.get("low_count", 0),
        cert_data.get("info_count", 0),
        cert_data.get("findings_retested", 0),
        cert_data.get("findings_passed", 0),
        cert_data.get("findings_failed", 0),
        cert_data.get("target_name", "Web Target"),
        cert_data.get("target_url", ""),
        cert_data.get("client_organization", "Not Provided"),
        cert_data.get("assessment_type", "Web Application Penetration Test (VAPT)"),
        cert_data.get("assessment_scope", ""),
        snap_json or "{}",
        cert_data.get("file_path_docx"),
        cert_data.get("file_path_pdf"),
        cert_data.get("notice_seen", 0),
        cert_data.get("created_at", now),
        now
    ]
    if "file_data_docx" in cols:
        fields.append("file_data_docx")
        values.append(cert_data.get("file_data_docx"))
    if "file_data_pdf" in cols:
        fields.append("file_data_pdf")
        values.append(cert_data.get("file_data_pdf"))

    placeholders = ", ".join(["?"] * len(fields))
    col_names = ", ".join(fields)
    cursor.execute(f"INSERT INTO vapt_certificates ({col_names}) VALUES ({placeholders})", values)
    conn.commit()
    conn.close()
    return get_certificate_by_id(cert_data["certificate_id"])

def update_certificate_artifact_data(certificate_id: str, file_data_docx: Optional[str] = None, file_data_pdf: Optional[str] = None) -> bool:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(vapt_certificates)")
        cols = [r["name"] for r in cursor.fetchall()]
        updates = []
        vals = []
        if file_data_docx and "file_data_docx" in cols:
            updates.append("file_data_docx = ?")
            vals.append(file_data_docx)
        if file_data_pdf and "file_data_pdf" in cols:
            updates.append("file_data_pdf = ?")
            vals.append(file_data_pdf)
        if updates:
            vals.append(certificate_id)
            cursor.execute(f"UPDATE vapt_certificates SET {', '.join(updates)} WHERE certificate_id = ?", vals)
            conn.commit()
            return True
        return False
    finally:
        conn.close()

def auto_migrate_sqlite_to_postgres_if_empty() -> Dict[str, Any]:
    """
    Safely migrates existing local SQLite data into PostgreSQL if:
    1. PostgreSQL is configured (is_postgres_configured() is True)
    2. PostgreSQL is currently empty (0 projects and 0 users)
    3. The local SQLite database file exists and contains user/project records
    Uses ON CONFLICT DO NOTHING to guarantee complete non-destructiveness.
    """
    if not is_postgres_configured():
        return {"migrated": False, "reason": "Not PostgreSQL"}
    
    if not DB_PATH.exists():
        return {"migrated": False, "reason": "SQLite file does not exist"}

    try:
        pg_conn = get_db_connection()
        pg_cur = pg_conn.cursor()
        pg_cur.execute("SELECT COUNT(*) FROM projects")
        pg_proj_count = pg_cur.fetchone()[0]
        pg_cur.execute("SELECT COUNT(*) FROM users")
        pg_user_count = pg_cur.fetchone()[0]
        
        # If PostgreSQL already contains users or projects, do not auto-migrate
        if pg_proj_count > 0 or pg_user_count > 0:
            pg_conn.close()
            return {"migrated": False, "reason": f"PostgreSQL already contains data ({pg_proj_count} projects, {pg_user_count} users)"}
        
        logger.info("Empty PostgreSQL database detected on startup. Starting safe auto-migration from local SQLite...")
        
        sqlite_conn = sqlite3.connect(str(DB_PATH))
        sqlite_conn.row_factory = sqlite3.Row
        sqlite_cur = sqlite_conn.cursor()

        tables_order = [
            ("users", "id"),
            ("sessions", "token"),
            ("password_resets", "id"),
            ("two_factor_pending_enrollments", "id"),
            ("two_factor_recovery_codes", "id"),
            ("two_factor_pending_logins", "id"),
            ("user_github_configs", "user_id"),
            ("projects", "id"),
            ("screenshots", "id"),
            ("checklists", "id"),
            ("checklist_items", "id"),
            ("findings", "id"),
            ("evidence", "id"),
            ("reports", "id"),
            ("vapt_certificates", "certificate_id"),
            ("ai_fixes", "id"),
            ("source_discovery_results", "id"),
            ("certificate_jobs", "job_id"),
        ]

        migration_summary = {}

        for tbl, pk in tables_order:
            sqlite_cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (tbl,))
            if not sqlite_cur.fetchone():
                continue
            
            sqlite_cur.execute(f"SELECT * FROM {tbl}")
            rows = sqlite_cur.fetchall()
            if not rows:
                migration_summary[tbl] = 0
                continue
            
            migrated_count = 0
            for r in rows:
                col_names = r.keys()
                cols_str = ", ".join(col_names)
                placeholders = ", ".join(["%s"] * len(col_names))
                vals = [r[k] for k in col_names]
                sql = f"INSERT INTO {tbl} ({cols_str}) VALUES ({placeholders}) ON CONFLICT ({pk}) DO NOTHING"
                try:
                    pg_cur.raw_cursor.execute(sql, vals)
                    migrated_count += 1
                except Exception as row_err:
                    logger.warning(f"Error migrating row in {tbl}: {row_err}")
            
            pg_conn.commit()
            migration_summary[tbl] = migrated_count
            logger.info(f"Auto-migrated {migrated_count} records for table '{tbl}' to PostgreSQL.")

        sqlite_conn.close()
        pg_conn.close()
        logger.info("Auto-migration from SQLite to PostgreSQL completed successfully.")
        return {"migrated": True, "summary": migration_summary}
    except Exception as e:
        logger.error(f"Auto-migration from SQLite to PostgreSQL encountered an error: {e}", exc_info=True)
        return {"migrated": False, "error": str(e)}

def get_certificate_by_id(certificate_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vapt_certificates WHERE certificate_id = ?", (certificate_id,))
    row = cursor.fetchone()
    conn.close()
    return _hydrate_certificate_row(row) if row else None

def get_certificate_by_verification_id(verification_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vapt_certificates WHERE verification_id = ?", (verification_id,))
    row = cursor.fetchone()
    conn.close()
    return _hydrate_certificate_row(row) if row else None

def get_certificates_for_project(project_id: str) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vapt_certificates WHERE project_id = ? ORDER BY created_at DESC", (project_id,))
    rows = cursor.fetchall()
    conn.close()
    return [_hydrate_certificate_row(r) for r in rows]

def get_latest_certificate_for_project(project_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vapt_certificates WHERE project_id = ? AND status = 'VALID' ORDER BY created_at DESC LIMIT 1", (project_id,))
    row = cursor.fetchone()
    conn.close()
    return _hydrate_certificate_row(row) if row else None

def update_certificate_notice_seen(certificate_id: str, seen: int = 1) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("UPDATE vapt_certificates SET notice_seen = ?, updated_at = ? WHERE certificate_id = ?", (seen, now, certificate_id))
    conn.commit()
    conn.close()
    return True

def update_certificate_file_paths(certificate_id: str, docx_path: Optional[str] = None, pdf_path: Optional[str] = None) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fields = ["updated_at = ?"]
    vals = [now]
    if docx_path is not None:
        fields.append("file_path_docx = ?")
        vals.append(docx_path)
    if pdf_path is not None:
        fields.append("file_path_pdf = ?")
        vals.append(pdf_path)
    vals.append(certificate_id)
    cursor.execute(f"UPDATE vapt_certificates SET {', '.join(fields)} WHERE certificate_id = ?", vals)
    conn.commit()
    conn.close()
    return True

# =============================================================================
# CERTIFICATE JOBS CRUD
# =============================================================================

def create_certificate_job(job_id: str, user_id: str, project_id: str, assessment_id: Optional[str] = None) -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
    INSERT INTO certificate_jobs (job_id, user_id, project_id, assessment_id, status, error, created_at, updated_at)
    VALUES (?, ?, ?, ?, 'GENERATING', NULL, ?, ?)
    """, (job_id, user_id, project_id, assessment_id or project_id, now, now))
    conn.commit()
    conn.close()
    return {
        "job_id": job_id,
        "user_id": user_id,
        "project_id": project_id,
        "assessment_id": assessment_id or project_id,
        "status": "GENERATING",
        "certificate_id": None,
        "error": None,
        "created_at": now,
        "updated_at": now
    }

def get_certificate_job(job_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM certificate_jobs WHERE job_id = ?", (job_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_active_certificate_job_for_project(project_id: str, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    if user_id:
        cursor.execute("""
        SELECT * FROM certificate_jobs
        WHERE project_id = ? AND user_id = ? AND status = 'GENERATING'
        ORDER BY created_at DESC LIMIT 1
        """, (project_id, user_id))
    else:
        cursor.execute("""
        SELECT * FROM certificate_jobs
        WHERE project_id = ? AND status = 'GENERATING'
        ORDER BY created_at DESC LIMIT 1
        """, (project_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_latest_certificate_job_for_project(project_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT * FROM certificate_jobs
    WHERE project_id = ?
    ORDER BY created_at DESC LIMIT 1
    """, (project_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def update_certificate_job(job_id: str, status: str, certificate_id: Optional[str] = None, error: Optional[str] = None) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fields = ["status = ?", "updated_at = ?"]
    vals = [status, now]
    if certificate_id is not None:
        fields.append("certificate_id = ?")
        vals.append(certificate_id)
    if error is not None:
        fields.append("error = ?")
        vals.append(error)
    vals.append(job_id)
    cursor.execute(f"UPDATE certificate_jobs SET {', '.join(fields)} WHERE job_id = ?", vals)
    conn.commit()
    conn.close()
    return get_certificate_job(job_id)


