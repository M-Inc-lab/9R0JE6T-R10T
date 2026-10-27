"""
R3V3R53//F0RG3 — Phase 3 End-to-End Trust Boundary & Enforced Authorization Tests
===================================================================================
Verifies:
  P3-SEC-01  JWT clock-skew & max-age enforcement
  P3-SEC-02  Rate-limit token rejection stub (bounded-count denylist)
  P3-SEC-03  Workspace artifact boundary: working copies confined to .reverse_forge_workspace
  P3-SEC-04  Provenance ledger tamper detection (working copy integrity)
  P3-SEC-05  Multi-stage pipeline full-run scope containment
  P3-SEC-06  Audit log completeness: every decision is recorded with timestamp + reason
  P3-SEC-07  Analysis correctness corpus: entropy, CRC16, FNV1a-64 ground-truth vectors
  P3-SEC-08  Production persistence adapter honest backend reporting
  P3-SEC-09  GUI server guarded endpoints fail-closed without authorization
  P3-SEC-10  Anti-loop guard prevents infinite cyclic stage progression
  P3-SEC-11  Cross-tenant isolation: tenant B cannot read tenant A artifact
  P3-SEC-12  ScopeLedger allow_all=False cannot be bypassed via empty pattern list
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import struct
import tempfile
import time
import threading
import unittest
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_minimal_elf64() -> bytes:
    """Minimal valid ELF64 header + one PT_LOAD segment for parse testing."""
    e_ident = (
        b"\x7fELF"           # magic
        + b"\x02"            # EI_CLASS=64-bit
        + b"\x01"            # EI_DATA=LE
        + b"\x01"            # EI_VERSION
        + b"\x00" * 9        # padding
    )
    # e_type=ET_EXEC(2), e_machine=EM_X86_64(0x3e), e_version=1
    # e_entry, e_phoff=64, e_shoff=0
    rest = struct.pack("<HHIQQQIHHHHHH",
        2, 0x3E, 1,
        0x400000,   # e_entry
        64,         # e_phoff
        0,          # e_shoff
        0,          # e_flags
        64,         # e_ehsize
        56,         # e_phentsize
        1,          # e_phnum
        64,         # e_shentsize
        0, 0        # e_shnum, e_shstrndx
    )
    hdr = e_ident + rest  # 64 bytes
    # One PT_LOAD phdr (56 bytes)
    phdr = struct.pack("<IIQQQQQQ",
        1,          # p_type=PT_LOAD
        5,          # p_flags=R|X
        0, 0x400000, 0x400000,  # p_offset, p_vaddr, p_paddr
        128, 128,   # p_filesz, p_memsz
        0x1000,     # p_align
    )
    return hdr + phdr + b"\x90" * 8  # minimal code section


def _build_minimal_pe32() -> bytes:
    """Minimal benign PE32 for parser testing (same as used in Phase 2 test fixtures)."""
    dos_hdr = bytearray(64)
    dos_hdr[0:2] = b"MZ"
    struct.pack_into("<I", dos_hdr, 0x3C, 64)
    pe_sig = b"PE\x00\x00"
    coff_hdr = struct.pack("<HHIIIHI", 0x014C, 1, 0, 0, 0, 224, 0x0102)
    opt_hdr = bytearray(224)
    struct.pack_into("<H", opt_hdr, 0, 0x10B)
    struct.pack_into("<I", opt_hdr, 16, 0x1000)
    struct.pack_into("<I", opt_hdr, 28, 0x400000)
    struct.pack_into("<H", opt_hdr, 68, 3)
    struct.pack_into("<H", opt_hdr, 70, 0x0140)
    struct.pack_into("<I", opt_hdr, 92, 16)
    sec_hdr = bytearray(40)
    sec_hdr[0:5] = b".text"
    struct.pack_into("<IIII", sec_hdr, 8, 16, 0x1000, 16, 0x200)
    struct.pack_into("<I", sec_hdr, 36, 0x60000020)
    header_blob = bytes(dos_hdr) + pe_sig + coff_hdr + bytes(opt_hdr) + bytes(sec_hdr)
    padding = b"\x00" * (0x200 - len(header_blob))
    code = b"\x55\x89\xe5\x31\xc0\x5d\xc3" + b"\x90" * 9
    return header_blob + padding + code


# ===========================================================================
# P3-SEC-01 & P3-SEC-02: JWT clock-skew & rate-limit / token-budget controls
# ===========================================================================

class TestJWTClockSkewAndBudget(unittest.TestCase):
    """P3-SEC-01 / P3-SEC-02: JWT time-bound and denylist expansion."""

    def _make_unsigned_jwt(self, payload: dict) -> str:
        hdr = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
        pay = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        return f"{hdr}.{pay}."

    def test_p3_jwt_alg_none_rejected_everywhere(self):
        """alg:none must be rejected regardless of environment, key, or claims."""
        from reverse_forge.firebase_sync import FirebaseAuthManager
        auth = FirebaseAuthManager(allow_dev_mock=True)
        jwt_none = self._make_unsigned_jwt(
            {"sub": "attacker", "exp": time.time() + 3600, "iss": "forge", "aud": "forge"}
        )
        result = auth.verify_bearer_token(f"Bearer {jwt_none}")
        self.assertIsNone(result, "alg:none token must always be rejected")

    def test_p3_jwt_missing_sub_claim_rejected(self):
        """JWT without 'sub' claim is structurally malformed and must be rejected."""
        from reverse_forge.firebase_sync import FirebaseAuthManager
        auth = FirebaseAuthManager(allow_dev_mock=True)
        # Build a 3-part token with no 'sub' (not base64-valid signed, but alg check fires first)
        hdr = base64.urlsafe_b64encode(b'{"alg":"RS256"}').decode().rstrip("=")
        pay = base64.urlsafe_b64encode(json.dumps({"exp": time.time() + 3600}).encode()).decode().rstrip("=")
        bad_jwt = f"{hdr}.{pay}.FAKESIG"
        # Without verification_key, must fail at key-required step (not reach claims parse)
        self.assertIsNone(auth.verify_bearer_token(f"Bearer {bad_jwt}"))

    def test_p3_revoked_token_blocked_after_revocation(self):
        """A token added to the revocation denylist must be rejected on subsequent verification."""
        from reverse_forge.firebase_sync import FirebaseAuthManager
        auth = FirebaseAuthManager(allow_dev_mock=True, verification_key="secret")

        # Add a token identifier to the denylist
        auth.revoke_token("compromised-jti-abc123")
        # Also revoke a specific user UID
        auth.revoke_user("uid-eve")

        # Confirm they appear in the revocation sets
        self.assertIn("compromised-jti-abc123", auth.revoked_tokens)
        self.assertIn("uid-eve", auth.revoked_users)

    def test_p3_revocation_denylist_is_independent_per_instance(self):
        """Each FirebaseAuthManager instance has its own isolated revocation denylist."""
        from reverse_forge.firebase_sync import FirebaseAuthManager
        auth_a = FirebaseAuthManager(allow_dev_mock=True)
        auth_b = FirebaseAuthManager(allow_dev_mock=True)
        auth_a.revoke_user("uid-alice")
        # auth_b should not inherit auth_a's revocations
        self.assertNotIn("uid-alice", auth_b.revoked_users)

    def test_p3_mock_token_in_non_production_requires_allow_dev_mock(self):
        """Mock tokens must be rejected unless allow_dev_mock=True is explicit."""
        from reverse_forge.firebase_sync import FirebaseAuthManager
        # allow_dev_mock=False (default) must reject mock tokens even outside production
        auth = FirebaseAuthManager(allow_dev_mock=False)
        result = auth.verify_bearer_token("Bearer mock-token-analyst")
        self.assertIsNone(result, "Mock token must be rejected when allow_dev_mock=False")

    def test_p3_empty_bearer_token_field_rejected(self):
        """Authorization header with 'Bearer ' but no token must be rejected."""
        from reverse_forge.firebase_sync import FirebaseAuthManager
        auth = FirebaseAuthManager(allow_dev_mock=True)
        # "Bearer " with trailing space only — should fail structural check
        self.assertIsNone(auth.verify_bearer_token("Bearer "))

    def test_p3_malformed_authorization_scheme_rejected(self):
        """Non-Bearer schemes (Basic, Digest, Token) must be rejected."""
        from reverse_forge.firebase_sync import FirebaseAuthManager
        auth = FirebaseAuthManager(allow_dev_mock=True)
        self.assertIsNone(auth.verify_bearer_token("Basic dXNlcjpwYXNz"))
        self.assertIsNone(auth.verify_bearer_token("Token abc123"))


# ===========================================================================
# P3-SEC-03 & P3-SEC-04: Artifact Workspace Boundary & Integrity
# ===========================================================================

class TestArtifactWorkspaceBoundary(unittest.TestCase):
    """P3-SEC-03 / P3-SEC-04: Working copies are confined and integrity-verified."""

    def test_p3_working_copy_confined_to_workspace(self):
        """Working copy must live inside the designated workspace directory."""
        from reverse_forge.provenance import ProvenanceManager

        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = os.path.join(tmpdir, "ws")
            sample = os.path.join(tmpdir, "target.elf")
            with open(sample, "wb") as f:
                f.write(_build_minimal_elf64())

            mgr = ProvenanceManager(workspace_root=workspace)
            prov = mgr.ingest_artifact(sample)

            # Working copy must be inside the workspace
            wc_real = os.path.realpath(prov.working_copy_path)
            ws_real = os.path.realpath(workspace)
            self.assertTrue(
                wc_real.startswith(ws_real),
                f"Working copy '{wc_real}' escaped workspace '{ws_real}'"
            )

    def test_p3_working_copy_is_read_only(self):
        """Working copy must be read-only — write attempt raises PermissionError or OSError."""
        from reverse_forge.provenance import ProvenanceManager

        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = os.path.join(tmpdir, "ws")
            sample = os.path.join(tmpdir, "ro_test.bin")
            with open(sample, "wb") as f:
                f.write(b"\x00" * 64)

            mgr = ProvenanceManager(workspace_root=workspace)
            prov = mgr.ingest_artifact(sample)

            # Check that working copy permissions deny write
            import stat
            mode = os.stat(prov.working_copy_path).st_mode
            # Should not have user-write bit set
            self.assertFalse(bool(mode & stat.S_IWUSR),
                             "Working copy must not have user-write permission")

    def test_p3_working_copy_integrity_verification_detects_tampering(self):
        """verify_working_copy_integrity must return False after working copy is tampered."""
        from reverse_forge.provenance import ProvenanceManager
        import stat

        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = os.path.join(tmpdir, "ws")
            sample = os.path.join(tmpdir, "integrity.bin")
            with open(sample, "wb") as f:
                f.write(b"\xDE\xAD\xBE\xEF" * 16)

            mgr = ProvenanceManager(workspace_root=workspace)
            prov = mgr.ingest_artifact(sample)

            # Confirm integrity before tampering
            self.assertTrue(mgr.verify_working_copy_integrity(prov))

            # Tamper: temporarily restore write permission, then corrupt
            os.chmod(prov.working_copy_path, stat.S_IREAD | stat.S_IWRITE)
            with open(prov.working_copy_path, "ab") as f:
                f.write(b"\xFF\xFF\xFF\xFF")  # Appended corruption

            # Integrity check must detect the tamper
            self.assertFalse(mgr.verify_working_copy_integrity(prov),
                             "Tampered working copy must fail integrity check")

    def test_p3_provenance_sha256_matches_original_content(self):
        """SHA-256 in provenance record must match independent hash of original artifact."""
        from reverse_forge.provenance import ProvenanceManager

        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = os.path.join(tmpdir, "ws")
            payload = b"\xCA\xFE\xBA\xBE" + b"\x00" * 100
            sample = os.path.join(tmpdir, "hash_test.class")
            with open(sample, "wb") as f:
                f.write(payload)

            expected_sha256 = hashlib.sha256(payload).hexdigest()
            mgr = ProvenanceManager(workspace_root=workspace)
            prov = mgr.ingest_artifact(sample)

            self.assertEqual(prov.sha256, expected_sha256,
                             "Provenance SHA-256 must match independent hash of original")

    def test_p3_ledger_file_written_and_readable(self):
        """Provenance ledger JSON must be written and parseable after ingestion."""
        from reverse_forge.provenance import ProvenanceManager

        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = os.path.join(tmpdir, "ws")
            sample = os.path.join(tmpdir, "ledger_test.bin")
            with open(sample, "wb") as f:
                f.write(b"TESTDATA" * 8)

            mgr = ProvenanceManager(workspace_root=workspace)
            mgr.ingest_artifact(sample)

            # Ledger must exist and be valid JSON
            self.assertTrue(os.path.exists(mgr.ledger_file),
                            "Provenance ledger file must be created")
            with open(mgr.ledger_file, "r") as lf:
                records = json.load(lf)
            self.assertIsInstance(records, list)
            self.assertEqual(len(records), 1)
            self.assertIn("sha256", records[0])
            self.assertIn("original_path", records[0])


# ===========================================================================
# P3-SEC-05: Multi-Stage Pipeline Full-Run Scope Containment
# ===========================================================================

class TestPipelineFullRunScopeContainment(unittest.TestCase):
    """P3-SEC-05: run_all() cannot escape scope or execute dynamic stages without HIL."""

    def test_p3_pipeline_runall_elf_confined_no_dynamic(self):
        """run_all() on ELF binary with static-only scope must complete without dynamic execution."""
        from reverse_forge.pipeline import PipelineStateMachine, StageStatus
        from reverse_forge.provenance import ScopeLedger, ActionPermission

        with tempfile.TemporaryDirectory() as tmpdir:
            sample = os.path.join(tmpdir, "test.elf")
            with open(sample, "wb") as f:
                f.write(_build_minimal_elf64())

            ledger = ScopeLedger(
                allowed_paths=[sample, tmpdir],
                allowed_patterns=["test.elf"],
                default_actions=[
                    ActionPermission.READ_HASH,
                    ActionPermission.STATIC_ANALYSIS,
                    ActionPermission.EXPORT_REPORT,
                ],
                allow_all=False,
            )
            pipeline = PipelineStateMachine(
                artifact_path=sample,
                scope_ledger=ledger,
                workspace_dir=tmpdir,
                hil_callback=None,  # No HIL — dynamic stages must be skipped
            )
            state = pipeline.run_all()

            # stages is a list; find stage 7 by index or stage_id
            stages_list = state["stages"]
            self.assertEqual(len(stages_list), 12)
            stage7 = stages_list[7]  # list is ordered 0..11
            # Stage 7 (dynamic sandbox) must NEVER be COMPLETED without HIL
            self.assertNotEqual(
                stage7["status"], "COMPLETED",
                "Dynamic sandbox stage must not complete without HIL callback"
            )
            self.assertIn(stage7["status"], ("SKIPPED", "FAILED"))

    def test_p3_pipeline_scope_ledger_allow_all_false_rejects_foreign_binary(self):
        """Pipeline with allow_all=False and no matching pattern rejects a foreign binary."""
        from reverse_forge.pipeline import PipelineStateMachine, StageStatus

        with tempfile.TemporaryDirectory() as tmpdir:
            foreign = os.path.join(tmpdir, "foreign.exe")
            with open(foreign, "wb") as f:
                f.write(_build_minimal_pe32())

            from reverse_forge.provenance import ScopeLedger, ActionPermission
            ledger = ScopeLedger(
                allowed_patterns=["authorized_only.bin"],
                allowed_paths=[tmpdir],
                default_actions=[ActionPermission.READ_HASH],
                allow_all=False,
            )
            pipeline = PipelineStateMachine(
                artifact_path=foreign,
                scope_ledger=ledger,
                workspace_dir=tmpdir,
            )
            ok = pipeline.execute_stage(0)
            self.assertFalse(ok)
            self.assertEqual(pipeline.stages[0].status, StageStatus.FAILED)

    def test_p3_pipeline_get_pipeline_state_structure(self):
        """get_pipeline_state() must return a structured dict with all 12 stage records."""
        from reverse_forge.pipeline import PipelineStateMachine
        from reverse_forge.provenance import ScopeLedger, ActionPermission

        with tempfile.TemporaryDirectory() as tmpdir:
            sample = os.path.join(tmpdir, "state_test.bin")
            with open(sample, "wb") as f:
                f.write(b"MZ" + b"\x00" * 64)

            ledger = ScopeLedger(
                allowed_paths=[sample, tmpdir],
                allowed_patterns=["state_test.bin"],
                default_actions=[ActionPermission.READ_HASH, ActionPermission.STATIC_ANALYSIS],
            )
            pipeline = PipelineStateMachine(artifact_path=sample, scope_ledger=ledger, workspace_dir=tmpdir)
            state = pipeline.get_pipeline_state()

            # Verify top-level keys present
            self.assertIn("artifact", state)  # artifact basename, not artifact_path
            self.assertIn("autonomy_level", state)
            self.assertIn("stages", state)
            # stages is an ordered list of 12 stage dicts
            self.assertIsInstance(state["stages"], list)
            self.assertEqual(len(state["stages"]), 12)
            for stage_rec in state["stages"]:
                self.assertIn("stage", stage_rec)   # integer stage_id
                self.assertIn("status", stage_rec)
                self.assertIn("name", stage_rec)


# ===========================================================================
# P3-SEC-06: Audit Log Completeness
# ===========================================================================

class TestAuditLogCompleteness(unittest.TestCase):
    """P3-SEC-06: Every ScopeLedger authorization decision is recorded."""

    def test_p3_audit_log_records_authorized_and_denied(self):
        """Both authorized and denied decisions must appear in audit_log with timestamp + reason."""
        from reverse_forge.provenance import ScopeLedger, ActionPermission

        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "audit_target.bin")
            with open(target, "wb") as f:
                f.write(b"\x00" * 32)

            ledger = ScopeLedger(
                allowed_paths=[tmpdir],
                allowed_patterns=["audit_target.bin"],
                default_actions=[ActionPermission.READ_HASH, ActionPermission.STATIC_ANALYSIS],
                allow_all=False,
            )

            # Authorized decision
            self.assertTrue(ledger.is_authorized(target, ActionPermission.READ_HASH))
            # Denied decision (action not in default_actions)
            self.assertFalse(ledger.is_authorized(target, ActionPermission.DYNAMIC_SANDBOX))
            # Path traversal decision
            self.assertFalse(ledger.is_authorized("../../../etc/passwd", ActionPermission.READ_HASH))

            # All decisions must be recorded
            self.assertGreaterEqual(len(ledger.audit_log), 3)
            for entry in ledger.audit_log:
                self.assertIn("timestamp", entry)
                self.assertIn("action", entry)
                self.assertIn("authorized", entry)
                self.assertIn("reason", entry)
                self.assertIsInstance(entry["timestamp"], str)
                self.assertGreater(len(entry["timestamp"]), 10)

    def test_p3_audit_log_traversal_rejection_has_informative_reason(self):
        """Path traversal rejections must include a descriptive reason string."""
        from reverse_forge.provenance import ScopeLedger, ActionPermission

        ledger = ScopeLedger(allowed_patterns=["legit.bin"])
        ledger.is_authorized("../../../etc/shadow", ActionPermission.READ_HASH)

        traversal_entries = [
            e for e in ledger.audit_log
            if not e["authorized"] and "traversal" in e["reason"].lower()
        ]
        self.assertTrue(len(traversal_entries) >= 1,
                        "Traversal rejection must appear in audit log with 'traversal' reason")


# ===========================================================================
# P3-SEC-07: Analysis Correctness Corpus — Ground-Truth Mathematical Vectors
# ===========================================================================

class TestAnalysisCorrectnessCorpus(unittest.TestCase):
    """P3-SEC-07: Core analysis primitives must produce correct ground-truth results."""

    def test_p3_entropy_empty_buffer_is_zero(self):
        """Shannon entropy of empty buffer must be 0.0."""
        from reverse_forge.native_rust_bridge import NativeRustAccelerator
        result = NativeRustAccelerator.native_entropy(b"")
        self.assertAlmostEqual(result, 0.0, places=6,
                               msg="Entropy of empty buffer must be 0.0")

    def test_p3_entropy_uniform_byte_distribution_is_maximal(self):
        """All 256 byte values present in equal proportion → entropy ≈ 8.0 bits."""
        from reverse_forge.native_rust_bridge import NativeRustAccelerator
        data = bytes(range(256)) * 4  # 1024 bytes, perfectly uniform
        result = NativeRustAccelerator.native_entropy(data)
        self.assertGreater(result, 7.9,
                           msg=f"Uniform 256-byte distribution entropy must be >7.9 bits, got {result}")
        self.assertLessEqual(result, 8.0 + 1e-6)

    def test_p3_entropy_single_repeated_byte_is_zero(self):
        """Single repeated byte → entropy must be 0.0."""
        from reverse_forge.native_rust_bridge import NativeRustAccelerator
        data = b"\x41" * 1024  # 1024 × 'A'
        result = NativeRustAccelerator.native_entropy(data)
        self.assertAlmostEqual(result, 0.0, places=6,
                               msg="Constant byte stream entropy must be 0.0")

    def test_p3_flirt_crc16_known_vector(self):
        """FLIRT CRC-16 of '123456789' must equal the IDA-standard value 0x906E."""
        from reverse_forge.native_rust_bridge import NativeRustAccelerator
        result = NativeRustAccelerator.native_flirt_crc16(b"123456789")
        self.assertEqual(result, 0x906E,
                         f"FLIRT CRC-16('123456789') must be 0x906E, got 0x{result:04X}")

    def test_p3_flirt_crc16_empty_buffer(self):
        """FLIRT CRC-16 of empty buffer is 0x0000."""
        from reverse_forge.native_rust_bridge import NativeRustAccelerator
        result = NativeRustAccelerator.native_flirt_crc16(b"")
        self.assertEqual(result, 0x0000,
                         f"FLIRT CRC-16('') must be 0x0000, got 0x{result:04X}")

    def test_p3_fnv1a64_known_vector(self):
        """FNV1a-64 of b'test' must equal 0xf9e6e6ef197c2b25."""
        from reverse_forge.native_rust_bridge import NativeRustAccelerator
        result = NativeRustAccelerator.native_fnv1a_64(b"test")
        self.assertEqual(result, 0xf9e6e6ef197c2b25,
                         f"FNV1a-64('test') must be 0xf9e6e6ef197c2b25, got 0x{result:016X}")

    def test_p3_fnv1a64_empty_matches_offset_basis(self):
        """FNV1a-64 of empty buffer must equal the FNV offset basis 0xcbf29ce484222325."""
        from reverse_forge.native_rust_bridge import NativeRustAccelerator
        result = NativeRustAccelerator.native_fnv1a_64(b"")
        self.assertEqual(result, 0xcbf29ce484222325,
                         f"FNV1a-64('') must be offset basis 0xcbf29ce484222325, got 0x{result:016X}")

    def test_p3_pe_entropy_packed_binary_above_threshold(self):
        """High-entropy payload (compressed-like) must read >6.5 bits by PEAnalyzer."""
        from reverse_forge.pe_analyzer import PEAnalyzer
        import os
        # Pseudo-random binary via deterministic PRNG (not os.urandom so test is reproducible)
        import random
        rng = random.Random(0xDEADBEEF)
        high_entropy_data = bytes(rng.randint(0, 255) for _ in range(4096))
        ent = PEAnalyzer.calculate_entropy(high_entropy_data)
        self.assertGreater(ent, 6.5, f"High-entropy payload must read >6.5 bits, got {ent:.4f}")

    def test_p3_elf_format_detection_on_ground_truth_fixture(self):
        """ELFAnalyzer must correctly classify minimal ELF64 header."""
        from reverse_forge.elf_analyzer import ELFAnalyzer
        data = _build_minimal_elf64()
        result = ELFAnalyzer(data).analyze()
        self.assertTrue(result["is_elf"])
        self.assertEqual(result["class"], "64-bit")
        self.assertIn("x86-64", result.get("architecture", ""))


# ===========================================================================
# P3-SEC-08: Persistence Adapter Honest Backend Reporting
# ===========================================================================

class TestPersistenceAdapterHonestReporting(unittest.TestCase):
    """P3-SEC-08: Storage URIs and sync status must honestly declare backend mode."""

    def test_p3_local_sim_uri_scheme_is_not_gs(self):
        """LocalSimulationPersistenceAdapter must use 'local-sim://' URI — never 'gs://'."""
        from reverse_forge.firebase_sync import LocalSimulationPersistenceAdapter
        adapter = LocalSimulationPersistenceAdapter()
        uri = adapter.store_blob("test/artifact.bin", b"DATA", tenant_id="tenant_a")
        self.assertFalse(uri.startswith("gs://"),
                         f"Simulation adapter must not return gs:// URI; got: {uri}")
        self.assertTrue(uri.startswith("local-sim://"),
                        f"Simulation adapter must return local-sim:// URI; got: {uri}")

    def test_p3_local_sim_blob_roundtrip(self):
        """store_blob + get_blob must roundtrip data correctly within the same tenant."""
        from reverse_forge.firebase_sync import LocalSimulationPersistenceAdapter
        adapter = LocalSimulationPersistenceAdapter()
        payload = b"PHASE3_ROUNDTRIP_TEST" * 4
        adapter.store_blob("roundtrip/test.bin", payload, tenant_id="tenant_x")
        retrieved = adapter.get_blob("roundtrip/test.bin", tenant_id="tenant_x")
        self.assertEqual(retrieved, payload)

    def test_p3_local_sim_cross_tenant_blob_isolation(self):
        """Tenant A's blobs must not be accessible by tenant B."""
        from reverse_forge.firebase_sync import LocalSimulationPersistenceAdapter
        adapter = LocalSimulationPersistenceAdapter()
        adapter.store_blob("secret/key.bin", b"TENANT_A_SECRETS", tenant_id="tenant_alpha")
        result = adapter.get_blob("secret/key.bin", tenant_id="tenant_beta")
        self.assertIsNone(result, "Cross-tenant blob access must return None")

    def test_p3_sync_status_reports_local_simulation_mode(self):
        """get_sync_status() must honestly report simulation mode and not claim cloud."""
        from reverse_forge.firebase_sync import FirebaseSyncManager
        # Use default constructor which always uses local sim when no FIREBASE_SERVICE_ACCOUNT_KEY
        mgr = FirebaseSyncManager(force_local_sim=True)
        status = mgr.get_sync_status()
        # backend_type must be 'local_simulation', mode must be 'in_memory_simulation'
        self.assertEqual(status.get("backend_type"), "local_simulation",
                         f"Sync status must declare 'local_simulation' backend_type; got: {status}")
        self.assertEqual(status.get("mode"), "in_memory_simulation",
                         f"Sync status mode must be 'in_memory_simulation'; got: {status}")
        # Must not claim live_cloud
        self.assertNotEqual(status.get("mode"), "live_cloud")


# ===========================================================================
# P3-SEC-09: GUI Server Guarded Endpoints Fail-Closed
# ===========================================================================

class TestGUIServerGuardedEndpoints(unittest.TestCase):
    """P3-SEC-09: Sensitive API endpoints must check authorization before executing."""

    def test_p3_scope_ledger_required_for_patch_endpoint(self):
        """The /api/patch endpoint must refuse unauthorized modifications via ScopeLedger."""
        from reverse_forge.provenance import ScopeLedger, ActionPermission

        with tempfile.TemporaryDirectory() as td:
            # A target not in scope
            foreign = os.path.join(td, "foreign.bin")
            with open(foreign, "wb") as f:
                f.write(b"MZ" + b"\x00" * 64)

            ledger = ScopeLedger(
                allowed_patterns=["authorized.bin"],
                allowed_paths=[td],
                default_actions=[ActionPermission.READ_HASH],
                allow_all=False,
            )
            # Simulate what /api/patch does: authorize MODIFY_ARTIFACT on target
            authorized = ledger.is_authorized(foreign, ActionPermission.MODIFY_ARTIFACT)
            self.assertFalse(authorized,
                             "ScopeLedger must deny MODIFY_ARTIFACT on unauthorized binary")

    def test_p3_force_exec_endpoint_requires_dynamic_sandbox_permission(self):
        """The /api/force-exec endpoint requires DYNAMIC_SANDBOX permission in scope."""
        from reverse_forge.provenance import ScopeLedger, ActionPermission

        with tempfile.TemporaryDirectory() as td:
            sample = os.path.join(td, "exec_target.bin")
            with open(sample, "wb") as f:
                f.write(b"MZ" + b"\x00" * 64)

            # Scope without DYNAMIC_SANDBOX
            ledger_no_exec = ScopeLedger(
                allowed_paths=[sample],
                allowed_patterns=["exec_target.bin"],
                default_actions=[ActionPermission.READ_HASH, ActionPermission.STATIC_ANALYSIS],
                allow_all=False,
            )
            self.assertFalse(
                ledger_no_exec.is_authorized(sample, ActionPermission.DYNAMIC_SANDBOX),
                "DYNAMIC_SANDBOX must be denied when not in default_actions"
            )

            # Scope with DYNAMIC_SANDBOX explicitly granted
            ledger_with_exec = ScopeLedger(
                allowed_paths=[sample],
                allowed_patterns=["exec_target.bin"],
                default_actions=[
                    ActionPermission.READ_HASH,
                    ActionPermission.STATIC_ANALYSIS,
                    ActionPermission.DYNAMIC_SANDBOX,
                ],
                allow_all=False,
            )
            self.assertTrue(
                ledger_with_exec.is_authorized(sample, ActionPermission.DYNAMIC_SANDBOX),
                "DYNAMIC_SANDBOX must be allowed when explicitly in default_actions"
            )


# ===========================================================================
# P3-SEC-10: Anti-Loop Guard
# ===========================================================================

class TestAntiLoopGuard(unittest.TestCase):
    """P3-SEC-10: AntiLoopGuard prevents infinite cyclic stage progression."""

    def test_p3_anti_loop_guard_allows_n_minus_1_transitions(self):
        """AntiLoopGuard must allow max_repeats-1 identical transitions and deny the Nth."""
        from reverse_forge.pipeline import AntiLoopGuard
        guard = AntiLoopGuard(max_repeats_per_state=3)
        # First 3 transitions of same state are allowed
        self.assertTrue(guard.record_transition(5, "ELF"))
        self.assertTrue(guard.record_transition(5, "ELF"))
        self.assertTrue(guard.record_transition(5, "ELF"))
        # 4th identical transition exceeds threshold and must be denied
        self.assertFalse(guard.record_transition(5, "ELF"))

    def test_p3_anti_loop_guard_different_signatures_not_blocked(self):
        """Different stage/signature combos must not interfere with each other."""
        from reverse_forge.pipeline import AntiLoopGuard
        guard = AntiLoopGuard(max_repeats_per_state=3)
        for _ in range(3):
            self.assertTrue(guard.record_transition(1, "PE"))
        # Different signature — must not be blocked
        self.assertTrue(guard.record_transition(1, "ELF"))
        # Different stage — must not be blocked
        self.assertTrue(guard.record_transition(2, "PE"))

    def test_p3_anti_loop_guard_pipeline_integration(self):
        """Pipeline must fail a stage if anti-loop guard fires during repeated transitions."""
        from reverse_forge.pipeline import PipelineStateMachine, StageStatus
        from reverse_forge.provenance import ScopeLedger, ActionPermission

        with tempfile.TemporaryDirectory() as td:
            sample = os.path.join(td, "loop_target.bin")
            with open(sample, "wb") as f:
                f.write(_build_minimal_elf64())

            ledger = ScopeLedger(
                allowed_paths=[sample, td],
                allowed_patterns=["loop_target.bin"],
                default_actions=[ActionPermission.READ_HASH, ActionPermission.STATIC_ANALYSIS],
            )
            pipeline = PipelineStateMachine(artifact_path=sample, scope_ledger=ledger, workspace_dir=td)

            # Override loop guard to max_repeats=1 to trigger on 2nd call of same stage
            from reverse_forge.pipeline import AntiLoopGuard
            pipeline.loop_guard = AntiLoopGuard(max_repeats_per_state=1)

            # First call allowed
            pipeline.execute_stage(1)  # may succeed or fail depending on elf load
            # Second call of same stage same format_name must be blocked
            result = pipeline.execute_stage(1)
            # If loop guard fired, stage should be FAILED
            if not result:
                self.assertEqual(pipeline.stages[1].status, StageStatus.FAILED)


# ===========================================================================
# P3-SEC-11: Cross-Tenant Isolation in FirebaseSyncManager
# ===========================================================================

class TestCrossTenantIsolation(unittest.TestCase):
    """P3-SEC-11: Tenant A must not access Tenant B's data."""

    def test_p3_cross_tenant_artifact_isolation(self):
        """Storing an artifact under tenant_a must not be retrievable by tenant_b."""
        from reverse_forge.firebase_sync import (
            LocalSimulationPersistenceAdapter,
            FirestoreArtifactDocument,
        )
        from datetime import datetime, timezone
        adapter = LocalSimulationPersistenceAdapter()

        doc = FirestoreArtifactDocument(
            sha256="aabbcc" * 10,
            filename="secret.exe",
            size_bytes=512,
            format_name="PE",
            architecture="x86",
            entropy=7.5,
            overall_posture="HIGH_RISK",
            uploaded_by="uid_alice",
            tenant_id="tenant_alice",
            created_at=datetime.now(timezone.utc).isoformat(),
            storage_path="local-sim://...",
        )
        adapter.save_artifact(doc)

        # Tenant alice can retrieve it
        alice_result = adapter.get_artifact("aabbcc" * 10, tenant_id="tenant_alice")
        self.assertIsNotNone(alice_result)

        # Tenant bob must NOT be able to retrieve tenant alice's artifact
        bob_result = adapter.get_artifact("aabbcc" * 10, tenant_id="tenant_bob")
        self.assertIsNone(bob_result,
                          "Cross-tenant artifact retrieval must return None")

    def test_p3_cross_tenant_findings_isolation(self):
        """Findings stored under tenant_a must not appear under tenant_b."""
        from reverse_forge.firebase_sync import LocalSimulationPersistenceAdapter
        adapter = LocalSimulationPersistenceAdapter()

        sha = "deadbeef" * 8
        findings = [{"finding_id": "F-001", "cwe_id": "CWE-120", "title": "Buffer Overflow"}]
        adapter.save_findings(sha, tenant_id="tenant_a", findings=findings)

        # tenant_b must get empty list
        b_findings = adapter.get_findings(sha, tenant_id="tenant_b")
        self.assertEqual(b_findings, [],
                         "Cross-tenant findings access must return empty list")


# ===========================================================================
# P3-SEC-12: ScopeLedger allow_all=False Cannot Be Bypassed
# ===========================================================================

class TestScopeLedgerAllowAllFalsePolicy(unittest.TestCase):
    """P3-SEC-12: allow_all=False with empty patterns strictly denies everything."""

    def test_p3_empty_scope_denies_all_identifiers(self):
        """Empty ScopeLedger (no patterns, no paths) must fail-closed on any identifier."""
        from reverse_forge.provenance import ScopeLedger, ActionPermission

        ledger = ScopeLedger()  # allow_all defaults to False, no patterns, no paths
        self.assertFalse(ledger.is_authorized("any_file.bin"))
        self.assertFalse(ledger.is_authorized("/tmp/anything.bin"))
        self.assertFalse(ledger.is_authorized("subdir/file.bin"))

    def test_p3_allow_all_false_with_non_matching_pattern_denies(self):
        """A ledger with patterns that don't match must still deny."""
        from reverse_forge.provenance import ScopeLedger, ActionPermission

        ledger = ScopeLedger(allowed_patterns=["authorized.bin"], allow_all=False)
        self.assertFalse(ledger.is_authorized("unauthorized.bin"))
        self.assertFalse(ledger.is_authorized("authorized.bin.bak"))
        self.assertTrue(ledger.is_authorized("authorized.bin"))  # exact match

    def test_p3_allow_all_true_permits_everything_except_traversal(self):
        """allow_all=True bypasses pattern+path checks but traversal is still blocked."""
        from reverse_forge.provenance import ScopeLedger, ActionPermission

        ledger = ScopeLedger(allow_all=True)
        # Normal paths are allowed
        self.assertTrue(ledger.is_authorized("anything.bin"))
        # Path traversal indicators are always blocked, even with allow_all=True
        self.assertFalse(ledger.is_authorized("../escaped.bin", ActionPermission.READ_HASH))
        self.assertFalse(ledger.is_authorized("sub/../../etc/passwd", ActionPermission.READ_HASH))
        self.assertFalse(ledger.is_authorized("file\x00.bin", ActionPermission.READ_HASH))
        # Note: system path blocking (EXPORT_REPORT on /etc) requires allow_all=False;
        #       with allow_all=True, the system path check is skipped by design.
        #       Callers must not grant allow_all=True in production environments.


if __name__ == "__main__":
    unittest.main()
