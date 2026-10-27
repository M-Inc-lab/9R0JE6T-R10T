"""
R3V3R53//F0RG3 — Provenance & Working-Copy Isolation Engine (§01, §03.1, §04)
Manages cryptographic integrity, read-only working copy sandboxing, and scope authorization.
"""

import hashlib
import json
import os
import shutil
import stat
import fnmatch
from enum import Enum
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Union


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


class ActionPermission(str, Enum):
    """Fine-grained permission classes for reverse-engineering actions (§03.2, Phase C)."""
    READ_HASH = "read_hash"
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_SANDBOX = "dynamic_sandbox"
    NETWORK_ACCESS = "network_access"
    MODIFY_ARTIFACT = "modify_artifact"
    EXTERNAL_SERVICE = "external_service"
    EXPORT_REPORT = "export_report"
    DESTRUCTIVE_OP = "destructive_op"


class ScopeLedger:
    """
    Enforces authorization boundaries, canonical resource resolution, and rules of engagement.
    Implements fail-closed security (§01, §03.2, Phase C).
    """

    def __init__(
        self,
        allowed_patterns: Optional[List[str]] = None,
        allowed_paths: Optional[List[str]] = None,
        allowed_actions: Optional[Dict[str, List[ActionPermission]]] = None,
        default_actions: Optional[List[ActionPermission]] = None,
        allow_all: bool = False,
    ):
        self.allowed_patterns = allowed_patterns or []
        self.allowed_paths = [os.path.realpath(os.path.abspath(p)) for p in (allowed_paths or [])]
        self.allow_all = allow_all
        self.allowed_actions = allowed_actions or {}
        self.default_actions = default_actions or [
            ActionPermission.READ_HASH,
            ActionPermission.STATIC_ANALYSIS,
        ]
        self.audit_log: List[Dict[str, Any]] = []

    def is_authorized(
        self,
        target_identifier: str,
        action: Union[ActionPermission, str] = ActionPermission.READ_HASH,
    ) -> bool:
        """
        Verify if the given target identifier and action are strictly authorized.
        Canonicalizes paths, prevents directory traversal / symlink escapes,
        and enforces fine-grained permission gates.
        """
        if isinstance(action, str):
            try:
                action = ActionPermission(action)
            except ValueError:
                action = ActionPermission.READ_HASH

        # 1. Reject path traversal indicators and null bytes immediately
        if not target_identifier or "\x00" in target_identifier or "../" in target_identifier or "..\\" in target_identifier:
            self._record_audit(target_identifier or "empty", action, authorized=False, reason="Path traversal or invalid payload rejected")
            return False

        if self.allow_all:
            self._record_audit(target_identifier, action, authorized=True, reason="Allow-all override active")
            return True

        # If no patterns or paths are configured, fail closed
        if not self.allowed_patterns and not self.allowed_paths:
            self._record_audit(target_identifier, action, authorized=False, reason="Empty scope policy (fail-closed)")
            return False

        # 2. Canonical path check
        target_real: Optional[str] = None
        if os.path.exists(target_identifier):
            target_real = os.path.realpath(os.path.abspath(target_identifier))
        elif os.path.isabs(target_identifier):
            target_real = os.path.realpath(target_identifier)
        else:
            target_real = os.path.realpath(os.path.abspath(target_identifier))

        # Check export destination constraints
        if action in (ActionPermission.EXPORT_REPORT, ActionPermission.MODIFY_ARTIFACT, ActionPermission.DESTRUCTIVE_OP) and target_real:
            blocked_system_roots = ("/etc", "/boot", "/root", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/sys", "/proc")
            for br in blocked_system_roots:
                if target_real == br or target_real.startswith(br + os.sep):
                    self._record_audit(target_identifier, action, authorized=False, reason="Operation inside protected system directory blocked")
                    return False

        path_matched = False
        if target_real and self.allowed_paths:
            for allowed_p in self.allowed_paths:
                # Target must match exactly or reside within an allowed directory tree
                if target_real == allowed_p or target_real.startswith(allowed_p.rstrip(os.sep) + os.sep):
                    path_matched = True
                    break

        # 3. Pattern / Identifier check (exact match or fnmatch over canonical basename)
        pattern_matched = False
        target_base = os.path.basename(target_identifier)
        for pat in self.allowed_patterns:
            pat_clean = pat.strip()
            if target_base.lower() == pat_clean.lower() or fnmatch.fnmatch(target_base.lower(), pat_clean.lower()):
                pattern_matched = True
                break

        # If allowed_paths is configured, target MUST be contained within allowed directory tree
        if self.allowed_paths:
            if not path_matched:
                self._record_audit(target_identifier, action, authorized=False, reason="Target path outside allowed directory bounds")
                return False
            in_scope = pattern_matched if self.allowed_patterns else True
        else:
            in_scope = pattern_matched
        if not in_scope:
            self._record_audit(target_identifier, action, authorized=False, reason="Target not in scope")
            return False

        # 4. Action-specific permission enforcement
        # Sensitive actions (DYNAMIC_SANDBOX, NETWORK_ACCESS, MODIFY_ARTIFACT) require explicit grant
        permitted_actions = self.allowed_actions.get(target_base, self.default_actions)
        if action not in permitted_actions:
            self._record_audit(
                target_identifier,
                action,
                authorized=False,
                reason=f"Action '{action.value}' not granted for target",
            )
            return False

        self._record_audit(target_identifier, action, authorized=True, reason="Authorized")
        return True

    def _record_audit(
        self,
        target_identifier: str,
        action: ActionPermission,
        authorized: bool,
        reason: str,
    ) -> None:
        self.audit_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": target_identifier,
            "action": action.value if hasattr(action, "value") else str(action),
            "authorized": authorized,
            "reason": reason,
            "rules": self.allowed_patterns,
            "allowed_paths": self.allowed_paths,
        })


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

        # If a previous read-only working copy exists, make it writable/removable before refreshing
        if os.path.exists(working_path):
            os.chmod(working_path, stat.S_IWRITE | stat.S_IREAD)
            os.remove(working_path)

        # Copy byte-for-byte to working space
        shutil.copy2(abs_original, working_path)

        # Mark working copy as read-only on disk to guarantee non-destructive analysis
        os.chmod(working_path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)

        in_scope = True
        scope_rule = "*"
        if scope_ledger:
            in_scope = scope_ledger.is_authorized(abs_original)
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
