"""
R3V3R53//F0RG3 — Batch Directory/Corpus Scanner & SQLite Artifact Knowledge Base (§03.1 #1 & #11)
Recursively scans directories or extracted firmware filesystems for executable artifacts,
executes the 12-stage pipeline, and indexes all findings and hashes into a local SQLite database.
"""

import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from reverse_forge.correlation_engine import CorrelationEngine
from reverse_forge.pipeline import AutonomyLevel, PipelineStateMachine


class ArtifactKnowledgeBase:
    """Persistent SQLite storage for analyzed artifacts, hashes, and CWE/CVSS findings."""

    def __init__(self, db_path: str = "reverse_forge_kb.sqlite"):
        self.db_path = os.path.abspath(db_path)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS artifacts (
                    sha256 TEXT PRIMARY KEY,
                    filename TEXT NOT NULL,
                    original_path TEXT NOT NULL,
                    detected_format TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    overall_posture TEXT NOT NULL,
                    total_findings INTEGER NOT NULL,
                    critical_count INTEGER NOT NULL,
                    high_count INTEGER NOT NULL,
                    medium_count INTEGER NOT NULL,
                    low_count INTEGER NOT NULL,
                    ingested_utc TEXT NOT NULL,
                    report_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    artifact_sha256 TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    cwe_id TEXT NOT NULL,
                    cvss_score REAL NOT NULL,
                    confidence TEXT NOT NULL,
                    function_symbol TEXT NOT NULL,
                    address_or_offset TEXT NOT NULL,
                    FOREIGN KEY (artifact_sha256) REFERENCES artifacts(sha256)
                )
                """
            )
            conn.commit()

    def store_pipeline_result(
        self,
        pipeline_state: Dict[str, Any],
        original_path: str,
        detected_format: str,
        size_bytes: int,
    ) -> None:
        sha256 = str(pipeline_state.get("sha256", ""))
        if not sha256:
            return
        report_json = pipeline_state.get("report_json", {})
        exec_sum = report_json.get("executive_summary", {})
        findings = report_json.get("findings", [])
        now_utc = datetime.now(timezone.utc).isoformat()

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO artifacts (
                    sha256, filename, original_path, detected_format, size_bytes,
                    overall_posture, total_findings, critical_count, high_count,
                    medium_count, low_count, ingested_utc, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(sha256) DO UPDATE SET
                    filename=excluded.filename,
                    original_path=excluded.original_path,
                    detected_format=excluded.detected_format,
                    overall_posture=excluded.overall_posture,
                    total_findings=excluded.total_findings,
                    critical_count=excluded.critical_count,
                    high_count=excluded.high_count,
                    medium_count=excluded.medium_count,
                    low_count=excluded.low_count,
                    ingested_utc=excluded.ingested_utc,
                    report_json=excluded.report_json
                """,
                (
                    sha256,
                    str(pipeline_state.get("artifact", os.path.basename(original_path))),
                    os.path.abspath(original_path),
                    detected_format,
                    int(size_bytes),
                    str(exec_sum.get("overall_posture", "UNKNOWN")),
                    int(exec_sum.get("total_findings", len(findings))),
                    int(exec_sum.get("critical_count", 0)),
                    int(exec_sum.get("high_count", 0)),
                    int(exec_sum.get("medium_count", 0)),
                    int(exec_sum.get("low_count", 0)),
                    now_utc,
                    json.dumps(report_json),
                ),
            )
            conn.execute("DELETE FROM findings WHERE artifact_sha256 = ?", (sha256,))
            for f in findings:
                conn.execute(
                    """
                    INSERT INTO findings (
                        artifact_sha256, finding_id, title, cwe_id,
                        cvss_score, confidence, function_symbol, address_or_offset
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sha256,
                        str(f.get("finding_id", "")),
                        str(f.get("title", "")),
                        str(f.get("cwe_id", "")),
                        float(f.get("cvss_score", 0.0)),
                        str(f.get("confidence", "")),
                        str(f.get("function_symbol", "")),
                        str(f.get("address_or_offset", "")),
                    ),
                )
            conn.commit()

    def query_findings(
        self,
        cwe_id: Optional[str] = None,
        min_cvss: float = 0.0,
    ) -> List[Dict[str, Any]]:
        query = """
            SELECT f.artifact_sha256, a.filename, a.detected_format,
                   f.finding_id, f.title, f.cwe_id, f.cvss_score,
                   f.confidence, f.function_symbol, f.address_or_offset
            FROM findings f
            JOIN artifacts a ON a.sha256 = f.artifact_sha256
            WHERE f.cvss_score >= ?
        """
        params: List[Any] = [float(min_cvss)]
        if cwe_id:
            query += " AND UPPER(f.cwe_id) = UPPER(?)"
            params.append(cwe_id.strip())
        query += " ORDER BY f.cvss_score DESC, a.filename ASC"

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    def get_corpus_summary(self) -> Dict[str, Any]:
        with self._connect() as conn:
            art_rows = conn.execute(
                """
                SELECT sha256, filename, detected_format, size_bytes,
                       overall_posture, total_findings, critical_count, high_count
                FROM artifacts
                ORDER BY critical_count DESC, high_count DESC, total_findings DESC
                """
            ).fetchall()
            cwe_rows = conn.execute(
                """
                SELECT cwe_id, COUNT(*) as count
                FROM findings
                GROUP BY cwe_id
                ORDER BY count DESC
                """
            ).fetchall()

        artifacts_list = [dict(r) for r in art_rows]
        fmt_counts: Dict[str, int] = {}
        for a in artifacts_list:
            fmt = a["detected_format"]
            fmt_counts[fmt] = fmt_counts.get(fmt, 0) + 1

        return {
            "database_path": self.db_path,
            "total_indexed_artifacts": len(artifacts_list),
            "format_breakdown": fmt_counts,
            "cwe_distribution": {r["cwe_id"]: r["count"] for r in cwe_rows},
            "artifacts": artifacts_list,
        }


class BatchCorpusScanner:
    """Recursively discovers binary artifacts in a directory and executes the 12-stage pipeline."""

    IGNORED_DIRS = {".git", "__pycache__", ".reverse_forge_workspace", ".extracted_layers", "node_modules", ".venv"}

    def __init__(
        self,
        kb: Optional[ArtifactKnowledgeBase] = None,
        workspace_dir: Optional[str] = None,
    ):
        self.kb = kb or ArtifactKnowledgeBase()
        self.workspace_dir = workspace_dir
        self.ce = CorrelationEngine()

    def scan_directory(
        self,
        target_dir: str,
        max_files: int = 50,
        binary_formats_only: bool = True,
    ) -> Dict[str, Any]:
        abs_dir = os.path.abspath(target_dir)
        if not os.path.isdir(abs_dir):
            raise NotADirectoryError(f"Directory not found: {abs_dir}")

        scanned = []
        skipped = 0

        for root, dirs, files in os.walk(abs_dir):
            dirs[:] = [d for d in sorted(dirs) if d not in self.IGNORED_DIRS]
            for file in sorted(files):
                if len(scanned) >= max_files:
                    break
                full_path = os.path.join(root, file)
                if not os.path.isfile(full_path) or os.path.islink(full_path):
                    continue
                try:
                    with open(full_path, "rb") as f:
                        header = f.read(64)
                except Exception:
                    skipped += 1
                    continue

                fmt = self.ce.identify_format(header)
                if binary_formats_only and fmt == "Unknown":
                    skipped += 1
                    continue

                sm = PipelineStateMachine(
                    full_path,
                    autonomy_level=AutonomyLevel.AUTONOMOUS,
                    workspace_dir=self.workspace_dir,
                )
                state = sm.run_all()
                sz = os.path.getsize(full_path)
                self.kb.store_pipeline_result(state, full_path, sm.format_name, sz)
                scanned.append({
                    "filename": file,
                    "path": full_path,
                    "format": sm.format_name,
                    "sha256": state.get("sha256"),
                    "findings_count": len(state.get("report_json", {}).get("findings", [])),
                })
            if len(scanned) >= max_files:
                break

        summary = self.kb.get_corpus_summary()
        summary["last_batch_scanned_count"] = len(scanned)
        summary["last_batch_skipped_non_binary"] = skipped
        return summary
