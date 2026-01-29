"""
SQLite-based state store for CVE deduplication.

Maintains persistent records of processed CVE IDs to prevent
duplicate advisory generation and email delivery.
"""

import sqlite3
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import contextmanager
import threading

import structlog

logger = structlog.get_logger(__name__)


class CVEStore:
    """
    SQLite-based persistent store for CVE processing state.
    
    Provides thread-safe operations for tracking which CVEs have been
    processed and emailed, along with run logging for audit purposes.
    """
    
    SCHEMA = """
    -- Processed CVEs table
    CREATE TABLE IF NOT EXISTS processed_cves (
        cve_id TEXT PRIMARY KEY,
        first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        processed_at TIMESTAMP,
        emailed_at TIMESTAMP,
        advisory_hash TEXT,
        kev_status INTEGER DEFAULT 0,
        cvss_score REAL,
        severity TEXT,
        title TEXT,
        error_message TEXT
    );
    
    -- Run logs table
    CREATE TABLE IF NOT EXISTS run_logs (
        run_id TEXT PRIMARY KEY,
        started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ended_at TIMESTAMP,
        status TEXT DEFAULT 'running',
        cves_collected INTEGER DEFAULT 0,
        cves_new INTEGER DEFAULT 0,
        cves_processed INTEGER DEFAULT 0,
        cves_emailed INTEGER DEFAULT 0,
        errors TEXT
    );
    
    -- Indexes for efficient queries
    CREATE INDEX IF NOT EXISTS idx_processed_at ON processed_cves(processed_at);
    CREATE INDEX IF NOT EXISTS idx_emailed_at ON processed_cves(emailed_at);
    CREATE INDEX IF NOT EXISTS idx_kev_status ON processed_cves(kev_status);
    CREATE INDEX IF NOT EXISTS idx_run_status ON run_logs(status);
    CREATE INDEX IF NOT EXISTS idx_run_started ON run_logs(started_at);
    """
    
    def __init__(self, db_path: str):
        """
        Initialize the CVE store.
        
        Args:
            db_path: Path to the SQLite database file.
        """
        self.db_path = Path(db_path)
        self._local = threading.local()
        
        # Ensure directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize schema
        self._init_schema()
        
        logger.info("cve_store_initialized", db_path=str(self.db_path))
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get thread-local database connection."""
        if not hasattr(self._local, 'connection') or self._local.connection is None:
            self._local.connection = sqlite3.connect(
                str(self.db_path),
                detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
                timeout=30.0
            )
            self._local.connection.row_factory = sqlite3.Row
            # Enable foreign keys and WAL mode for better concurrency
            self._local.connection.execute("PRAGMA foreign_keys = ON")
            self._local.connection.execute("PRAGMA journal_mode = WAL")
        return self._local.connection
    
    @contextmanager
    def _transaction(self):
        """Context manager for database transactions."""
        conn = self._get_connection()
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise
    
    def _init_schema(self):
        """Initialize database schema."""
        with self._transaction() as conn:
            conn.executescript(self.SCHEMA)
    
    def is_processed(self, cve_id: str) -> bool:
        """
        Check if a CVE has been processed (advisory generated and emailed).
        
        Args:
            cve_id: CVE identifier to check.
        
        Returns:
            True if the CVE has been fully processed and emailed.
        """
        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT emailed_at FROM processed_cves WHERE cve_id = ?",
            (cve_id,)
        )
        row = cursor.fetchone()
        return row is not None and row["emailed_at"] is not None
    
    def is_known(self, cve_id: str) -> bool:
        """
        Check if a CVE is known (seen before, but may not be fully processed).
        
        Args:
            cve_id: CVE identifier to check.
        
        Returns:
            True if the CVE has been seen before.
        """
        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT 1 FROM processed_cves WHERE cve_id = ?",
            (cve_id,)
        )
        return cursor.fetchone() is not None
    
    def mark_seen(
        self,
        cve_id: str,
        kev_status: bool = False,
        cvss_score: Optional[float] = None,
        severity: Optional[str] = None,
        title: Optional[str] = None
    ):
        """
        Mark a CVE as seen (first stage of processing).
        
        Args:
            cve_id: CVE identifier.
            kev_status: Whether the CVE is in CISA KEV.
            cvss_score: CVSS score if available.
            severity: Severity level if available.
            title: Vulnerability title if available.
        """
        with self._transaction() as conn:
            conn.execute(
                """
                INSERT INTO processed_cves (cve_id, kev_status, cvss_score, severity, title)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    kev_status = COALESCE(excluded.kev_status, kev_status),
                    cvss_score = COALESCE(excluded.cvss_score, cvss_score),
                    severity = COALESCE(excluded.severity, severity),
                    title = COALESCE(excluded.title, title)
                """,
                (cve_id, int(kev_status), cvss_score, severity, title)
            )
        logger.debug("cve_marked_seen", cve_id=cve_id)
    
    def mark_processed(self, cve_id: str, advisory_hash: Optional[str] = None):
        """
        Mark a CVE as processed (advisory generated).
        
        Args:
            cve_id: CVE identifier.
            advisory_hash: Hash of the generated advisory content.
        """
        with self._transaction() as conn:
            conn.execute(
                """
                UPDATE processed_cves 
                SET processed_at = ?, advisory_hash = ?
                WHERE cve_id = ?
                """,
                (datetime.now(timezone.utc), advisory_hash, cve_id)
            )
        logger.debug("cve_marked_processed", cve_id=cve_id)
    
    def mark_emailed(self, cve_id: str):
        """
        Mark a CVE as emailed (advisory sent).
        
        Args:
            cve_id: CVE identifier.
        """
        with self._transaction() as conn:
            conn.execute(
                """
                UPDATE processed_cves 
                SET emailed_at = ?
                WHERE cve_id = ?
                """,
                (datetime.now(timezone.utc), cve_id)
            )
        logger.info("cve_marked_emailed", cve_id=cve_id)
    
    def mark_error(self, cve_id: str, error_message: str):
        """
        Mark a CVE as having encountered an error.
        
        Args:
            cve_id: CVE identifier.
            error_message: Error description.
        """
        with self._transaction() as conn:
            conn.execute(
                """
                UPDATE processed_cves 
                SET error_message = ?
                WHERE cve_id = ?
                """,
                (error_message, cve_id)
            )
        logger.warning("cve_marked_error", cve_id=cve_id, error=error_message)
    
    def get_pending_cves(self) -> List[str]:
        """
        Get CVE IDs that were seen but not yet emailed.
        
        Returns:
            List of CVE IDs pending email delivery.
        """
        conn = self._get_connection()
        cursor = conn.execute(
            """
            SELECT cve_id FROM processed_cves 
            WHERE emailed_at IS NULL AND error_message IS NULL
            ORDER BY first_seen_at
            """
        )
        return [row["cve_id"] for row in cursor.fetchall()]
    
    def get_failed_cves(self) -> List[Dict[str, Any]]:
        """
        Get CVEs that encountered errors.
        
        Returns:
            List of dicts with cve_id and error_message.
        """
        conn = self._get_connection()
        cursor = conn.execute(
            """
            SELECT cve_id, error_message, first_seen_at 
            FROM processed_cves 
            WHERE error_message IS NOT NULL
            ORDER BY first_seen_at DESC
            """
        )
        return [dict(row) for row in cursor.fetchall()]
    
    def get_stats(self) -> Dict[str, int]:
        """
        Get processing statistics.
        
        Returns:
            Dict with counts of total, processed, emailed, and failed CVEs.
        """
        conn = self._get_connection()
        
        total = conn.execute("SELECT COUNT(*) FROM processed_cves").fetchone()[0]
        processed = conn.execute(
            "SELECT COUNT(*) FROM processed_cves WHERE processed_at IS NOT NULL"
        ).fetchone()[0]
        emailed = conn.execute(
            "SELECT COUNT(*) FROM processed_cves WHERE emailed_at IS NOT NULL"
        ).fetchone()[0]
        failed = conn.execute(
            "SELECT COUNT(*) FROM processed_cves WHERE error_message IS NOT NULL"
        ).fetchone()[0]
        kev_count = conn.execute(
            "SELECT COUNT(*) FROM processed_cves WHERE kev_status = 1"
        ).fetchone()[0]
        
        return {
            "total_seen": total,
            "processed": processed,
            "emailed": emailed,
            "failed": failed,
            "kev_listed": kev_count
        }
    
    # Run logging methods
    
    def start_run(self, run_id: str) -> str:
        """
        Record the start of a processing run.
        
        Args:
            run_id: Unique identifier for this run.
        
        Returns:
            The run_id.
        """
        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO run_logs (run_id) VALUES (?)",
                (run_id,)
            )
        logger.info("run_started", run_id=run_id)
        return run_id
    
    def update_run(
        self,
        run_id: str,
        cves_collected: Optional[int] = None,
        cves_new: Optional[int] = None,
        cves_processed: Optional[int] = None,
        cves_emailed: Optional[int] = None
    ):
        """
        Update run statistics.
        
        Args:
            run_id: Run identifier.
            cves_collected: Total CVEs collected from sources.
            cves_new: New CVEs (not previously processed).
            cves_processed: CVEs with advisories generated.
            cves_emailed: CVEs with emails sent.
        """
        updates = []
        values = []
        
        if cves_collected is not None:
            updates.append("cves_collected = ?")
            values.append(cves_collected)
        if cves_new is not None:
            updates.append("cves_new = ?")
            values.append(cves_new)
        if cves_processed is not None:
            updates.append("cves_processed = ?")
            values.append(cves_processed)
        if cves_emailed is not None:
            updates.append("cves_emailed = ?")
            values.append(cves_emailed)
        
        if updates:
            values.append(run_id)
            with self._transaction() as conn:
                conn.execute(
                    f"UPDATE run_logs SET {', '.join(updates)} WHERE run_id = ?",
                    values
                )
    
    def end_run(self, run_id: str, status: str = "completed", errors: Optional[str] = None):
        """
        Record the end of a processing run.
        
        Args:
            run_id: Run identifier.
            status: Final status (completed, failed, partial).
            errors: Error messages if any.
        """
        with self._transaction() as conn:
            conn.execute(
                """
                UPDATE run_logs 
                SET ended_at = ?, status = ?, errors = ?
                WHERE run_id = ?
                """,
                (datetime.utcnow(), status, errors, run_id)
            )
        logger.info("run_ended", run_id=run_id, status=status)
    
    def get_last_run(self) -> Optional[Dict[str, Any]]:
        """
        Get the most recent completed run.
        
        Returns:
            Dict with run details or None if no runs exist.
        """
        conn = self._get_connection()
        cursor = conn.execute(
            """
            SELECT * FROM run_logs 
            WHERE status = 'completed'
            ORDER BY ended_at DESC 
            LIMIT 1
            """
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def get_recent_runs(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recent processing runs.
        
        Args:
            limit: Maximum number of runs to return.
        
        Returns:
            List of run details dicts.
        """
        conn = self._get_connection()
        cursor = conn.execute(
            """
            SELECT * FROM run_logs 
            ORDER BY started_at DESC 
            LIMIT ?
            """,
            (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]
    
    def close(self):
        """Close the database connection."""
        if hasattr(self._local, 'connection') and self._local.connection:
            self._local.connection.close()
            self._local.connection = None


def compute_advisory_hash(content: str) -> str:
    """
    Compute a hash of advisory content for deduplication.
    
    Args:
        content: Advisory text content.
    
    Returns:
        SHA256 hash of the content.
    """
    return hashlib.sha256(content.encode('utf-8')).hexdigest()
