"""
R3V3R53//F0RG3 — Provenance & Working-Copy Isolation Engine (§01, §03.1, §04)
Manages cryptographic integrity, read-only working copy sandboxing, and scope authorization.
"""

import hashlib
import json
import os
import shutil
import stat
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class ArtifactProvenance:
    artifact_name: str
    original_path: str
    working_copy_path: str
    file_size_bytes: int
    sha256: str
    md5: str
    sha1: str
    ingest_timestamp_utc: str
    in_scope: bool
    scope_target_pattern: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class ScopeLedger:
    """Enforces authorization boundaries and rules of engagement."""

    def __init__(self, allowed_patterns: Optional[List[str]] = None, allow_all: bool = False):
        self.allowed_patterns = allowed_patterns or []
        self.allow_all = allow_all
        self.audit_log: List[Dict[str, Any]] = []

    def is_authorized(self, target_identifier: str) -> bool:
        if self.allow_all:
            authorized = True
        elif not self.allowed_patterns:
            authorized = False
        else:
            normalized = os.path.basename(target_identifier).lower()
            authorized = any(
                pat.lower() in normalized or normalized.endswith(pat.lower())
                for pat in self.allowed_patterns
            )

        self.audit_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": target_identifier,
            "authorized": authorized,
            "rules": self.allowed_patterns,
        })
        return authorized


class ProvenanceManager:
    """Creates isolated non-destructive working copies and records provenance."""

    def __init__(self, workspace_root: Optional[str] = None):
        self.workspace_root = os.path.abspath(workspace_root or os.path.join(os.getcwd(), ".reverse_forge_workspace"))
        self.working_copies_dir = os.path.join(self.workspace_root, "working_copies")
        self.ledger_file = os.path.join(self.workspace_root, "provenance_ledger.json")
        os.makedirs(self.working_copies_dir, exist_ok=True)

    @staticmethod
    def compute_hashes(filepath: str) -> Dict[str, str]:
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()

        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
                md5.update(chunk)
                sha1.update(chunk)

        return {
            "sha256": sha256.hexdigest(),
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
        }

    def ingest_artifact(
        self,
        artifact_path: str,
        scope_ledger: Optional[ScopeLedger] = None,
        extra_meta: Optional[Dict[str, Any]] = None,
    ) -> ArtifactProvenance:
        abs_original = os.path.abspath(artifact_path)
        if not os.path.exists(abs_original):
            raise FileNotFoundError(f"Artifact does not exist: {abs_original}")

        hashes = self.compute_hashes(abs_original)
        basename = os.path.basename(abs_original)
        isolated_filename = f"{hashes['sha256'][:12]}_{basename}"
        working_path = os.path.join(self.working_copies_dir, isolated_filename)

        # Copy byte-for-byte to working space
        shutil.copy2(abs_original, working_path)

        # Mark working copy as read-only on disk to guarantee non-destructive analysis
        os.chmod(working_path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)

        in_scope = True
        scope_rule = "*"
        if scope_ledger:
            in_scope = scope_ledger.is_authorized(basename)
            scope_rule = ",".join(scope_ledger.allowed_patterns) or ("ALL" if scope_ledger.allow_all else "NONE")

        provenance = ArtifactProvenance(
            artifact_name=basename,
            original_path=abs_original,
            working_copy_path=working_path,
            file_size_bytes=os.path.getsize(abs_original),
            sha256=hashes["sha256"],
            md5=hashes["md5"],
            sha1=hashes["sha1"],
            ingest_timestamp_utc=datetime.now(timezone.utc).isoformat(),
            in_scope=in_scope,
            scope_target_pattern=scope_rule,
            metadata=extra_meta or {},
        )

        self._record_to_ledger(provenance)
        return provenance

    def _record_to_ledger(self, prov: ArtifactProvenance) -> None:
        records = []
        if os.path.exists(self.ledger_file):
            try:
                with open(self.ledger_file, "r", encoding="utf-8") as f:
                    records = json.load(f)
            except Exception:
                records = []

        records.append(asdict(prov))
        with open(self.ledger_file, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)

    def verify_working_copy_integrity(self, provenance: ArtifactProvenance) -> bool:
        """Confirm working copy has not been altered or tampered with."""
        if not os.path.exists(provenance.working_copy_path):
            return False
        current_hashes = self.compute_hashes(provenance.working_copy_path)
        return current_hashes["sha256"] == provenance.sha256
