"""SQLite persistence for ScanneX findings, evidence traces, and patch audit logs."""

import json
import sqlite3
from pathlib import Path
from typing import Optional
from scannex.db.models import Finding, FindingStatus


class FindingsStore:
    """Thread-safe SQLite store for finding state transitions and evidence logs."""

    def __init__(self, db_path: Path | str = ":memory:"):
        self.db_path = str(db_path)
        self._mem_conn: Optional[sqlite3.Connection] = None
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        else:
            self._mem_conn = sqlite3.connect(":memory:")
            self._mem_conn.row_factory = sqlite3.Row
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._mem_conn is not None:
            return self._mem_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create tables if they do not exist."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    file_path TEXT NOT NULL,
                    line_number INTEGER NOT NULL,
                    vuln_type TEXT NOT NULL,
                    cwe TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    sink_code TEXT,
                    source TEXT NOT NULL,
                    status TEXT NOT NULL,
                    verifier_notes TEXT,
                    data_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_status ON findings (status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity)")
            conn.commit()

    def save_finding(self, finding: Finding) -> None:
        """Insert or update a finding and its serialized metadata."""
        data_json = finding.model_dump_json()
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO findings (
                    id, file_path, line_number, vuln_type, cwe, severity,
                    title, description, sink_code, source, status,
                    verifier_notes, data_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    file_path = excluded.file_path,
                    line_number = excluded.line_number,
                    vuln_type = excluded.vuln_type,
                    cwe = excluded.cwe,
                    severity = excluded.severity,
                    title = excluded.title,
                    description = excluded.description,
                    sink_code = excluded.sink_code,
                    source = excluded.source,
                    status = excluded.status,
                    verifier_notes = excluded.verifier_notes,
                    data_json = excluded.data_json,
                    updated_at = excluded.updated_at
            """, (
                finding.id,
                finding.file_path,
                finding.line_number,
                finding.vuln_type,
                finding.cwe,
                finding.severity.value,
                finding.title,
                finding.description,
                finding.sink_code,
                finding.source,
                finding.status.value,
                finding.verifier_notes,
                data_json,
                finding.created_at,
                finding.updated_at
            ))
            conn.commit()

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        """Retrieve a finding by its ID."""
        with self._get_connection() as conn:
            cur = conn.execute("SELECT data_json FROM findings WHERE id = ?", (finding_id,))
            row = cur.fetchone()
            if not row:
                return None
            return Finding.model_validate_json(row["data_json"])

    def list_findings(self, status: Optional[FindingStatus] = None) -> list[Finding]:
        """List findings, optionally filtered by status."""
        query = "SELECT data_json FROM findings"
        params = ()
        if status:
            query += " WHERE status = ?"
            params = (status.value,)
        query += " ORDER BY line_number ASC"

        with self._get_connection() as conn:
            cur = conn.execute(query, params)
            return [Finding.model_validate_json(row["data_json"]) for row in cur.fetchall()]

    def get_summary(self) -> dict[str, Any]:
        """Compute summary counts by status and severity."""
        with self._get_connection() as conn:
            status_counts = {}
            for row in conn.execute("SELECT status, count(*) as cnt FROM findings GROUP BY status"):
                status_counts[row["status"]] = row["cnt"]

            severity_counts = {}
            for row in conn.execute("SELECT severity, count(*) as cnt FROM findings GROUP BY severity"):
                severity_counts[row["severity"]] = row["cnt"]

            total_row = conn.execute("SELECT count(*) as total FROM findings").fetchone()
            total = total_row["total"] if total_row else 0

            return {
                "total": total,
                "by_status": status_counts,
                "by_severity": severity_counts,
            }

    def clear(self) -> None:
        """Clear all findings from the database."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM findings")
            conn.commit()
