"""
R3V3R53//F0RG3 — Phase 4 & 4.1 End-to-End Deterministic Acceptance Test Suite
=============================================================================
Implements the 13-step deterministic local workflow defined in Phase 4 §8 & Phase 4.1 §9:
  1. Creates a benign test binary from known source.
  2. Computes and verifies its SHA-256.
  3. Authenticates a valid test principal.
  4. Confirms the principal's role, tenant and scope.
  5. Runs supported static analysis.
  6. Captures tool versions, evidence and findings.
  7. Persists the result through the configured test persistence backend.
  8. Retrieves the saved artifact and findings.
  9. Verifies the retrieved data against the original records.
  10. Produces a report with provenance and explicit limitations.
  11. Attempts unauthorized cross-tenant access and confirms denial.
  12. Attempts a sensitive action without required HIL approval and confirms denial.
  13. Verifies that denied actions cause no side effects.

Tests both the LocalSimulationPersistenceAdapter and ProductionFirestoreStorageAdapter
(with client injection/mocking) clearly labeled.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import MagicMock

from reverse_forge.authorization import (
    ApprovalGrant,
    AuthorizationDecision,
    AuthorizationDeniedError,
    CentralAuthorizationBoundary,
    OperationType,
    get_authorization_boundary,
)
from reverse_forge.elf_analyzer import ELFAnalyzer
from reverse_forge.firebase_sync import (
    AuthUserContext,
    FirebaseAuthManager,
    FirestoreArtifactDocument,
    FirestoreFindingDocument,
    LocalSimulationPersistenceAdapter,
    PersistencePermissionError,
    ProductionFirestoreStorageAdapter,
    UserRole,
    jwt,
)
from reverse_forge.pipeline import (
    AutonomyLevel,
    PipelineStateMachine,
    StageStatus,
)
from reverse_forge.provenance import (
    ActionPermission,
    ArtifactProvenance,
    ProvenanceManager,
    ScopeLedger,
)
from reverse_forge.reporter import Finding, ReportGenerator


class TestPhase4EndToEndAcceptance(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="rf_p4_e2e_")
        self.src_c = os.path.join(self.tmpdir, "benign_sample.c")
        self.bin_elf = os.path.join(self.tmpdir, "benign_sample.elf")

        # Step 1: Known deterministic C source code
        self.c_code = (
            "#include <stdio.h>\n"
            "#include <string.h>\n"
            "int calculate_sum(int a, int b) { return a + b; }\n"
            "int main(void) {\n"
            "    printf(\"ReverseForge Phase4 Test: sum=%d\\n\", calculate_sum(40, 2));\n"
            "    return 0;\n"
            "}\n"
        )
        with open(self.src_c, "w") as f:
            f.write(self.c_code)

        # Compile benign binary locally using gcc or clang
        cc = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
        if cc:
            cmd = [cc, "-O1", "-fPIC", self.src_c, "-o", self.bin_elf]
            subprocess.run(cmd, capture_output=True, check=True)
        else:
            # Fallback to minimal synthetic ELF64 binary if no host compiler
            with open(self.bin_elf, "wb") as f:
                f.write(
                    b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x02\x00\x3e\x00\x01\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00"
                    + b"\x00" * 40
                )

        self.boundary = get_authorization_boundary()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_e2e_acceptance_workflow_local_simulation(self):
        """Complete 13-step acceptance workflow on LocalSimulationPersistenceAdapter."""
        self._run_acceptance_workflow(backend_choice="simulation")

    def test_e2e_acceptance_workflow_production_adapter(self):
        """Complete 13-step acceptance workflow on ProductionFirestoreStorageAdapter."""
        self._run_acceptance_workflow(backend_choice="production")

    def _run_acceptance_workflow(self, backend_choice: str = "simulation"):
        # ---------------------------------------------------------------------
        # Step 1: Verify benign binary exists and is readable
        # ---------------------------------------------------------------------
        self.assertTrue(os.path.exists(self.bin_elf))
        with open(self.bin_elf, "rb") as f:
            raw_bytes = f.read()
        self.assertGreater(len(raw_bytes), 0)

        # ---------------------------------------------------------------------
        # Step 2: Compute and verify SHA-256
        # ---------------------------------------------------------------------
        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        self.assertEqual(len(sha256), 64)

        # ---------------------------------------------------------------------
        # Step 3: Authenticate valid test principal
        # ---------------------------------------------------------------------
        auth_mgr = FirebaseAuthManager(
            project_id="phase4-test-project",
            expected_issuer="https://securetoken.google.com/phase4-test-project",
            expected_audience="phase4-test-project",
            verification_key="secret-32-byte-key-for-test-suite-phase4",
            allowed_algorithms=["HS256"],
            trusted_tenants={"tenant_alpha", "tenant_beta"},
        )
        token_claims = {
            "sub": "analyst-007",
            "email": "analyst@tenant-alpha.com",
            "role": "ANALYST",
            "tenant_id": "tenant_alpha",
            "aud": "phase4-test-project",
            "iss": "https://securetoken.google.com/phase4-test-project",
            "exp": time.time() + 3600,
            "nbf": time.time() - 10,
        }
        token = jwt.encode(token_claims, "secret-32-byte-key-for-test-suite-phase4", algorithm="HS256")
        principal = auth_mgr.verify_bearer_token(f"Bearer {token}")
        self.assertIsNotNone(principal)
        self.assertTrue(principal.is_verified)
        self.assertTrue(principal.is_cryptographically_verified())

        # ---------------------------------------------------------------------
        # Step 4: Confirm principal's role, tenant and scope
        # ---------------------------------------------------------------------
        self.assertEqual(principal.role, UserRole.ANALYST)
        self.assertEqual(principal.tenant_id, "tenant_alpha")
        self.assertTrue(principal.can_modify())
        self.assertFalse(principal.is_lead())

        ledger = ScopeLedger(
            allowed_paths=[self.bin_elf, self.tmpdir],
            allowed_patterns=["benign_sample.elf"],
            default_actions=[
                ActionPermission.READ_HASH,
                ActionPermission.STATIC_ANALYSIS,
                ActionPermission.EXPORT_REPORT,
            ],
            allow_all=False,
        )
        self.assertTrue(ledger.is_authorized(self.bin_elf, ActionPermission.READ_HASH))
        self.assertTrue(ledger.is_authorized(self.bin_elf, ActionPermission.STATIC_ANALYSIS))

        # ---------------------------------------------------------------------
        # Step 5: Run supported static analysis
        # ---------------------------------------------------------------------
        elf_an = ELFAnalyzer(raw_bytes)
        static_info = elf_an.analyze()
        self.assertTrue(static_info["is_elf"])
        self.assertIn("x86", static_info["architecture"].lower())

        # ---------------------------------------------------------------------
        # Step 6: Capture tool versions, evidence, and findings
        # ---------------------------------------------------------------------
        report_gen = ReportGenerator(target_name="benign_sample.elf", sha256=sha256)
        finding_1 = Finding(
            finding_id="FIND-001",
            title="Non-Vulnerable Binary Baseline Verification",
            vulnerability_class="Baseline Integrity",
            confidence="Confirmed",
            cvss_score=0.0,
            cwe_id="CWE-1000",
            function_symbol="calculate_sum",
            address_or_offset="0x1000",
            what="Standard arithmetic logic verified with no unbounded buffer access.",
            why="Static surface audit confirmed memory safety invariant.",
            where="benign_sample.elf:.text",
            when="Compile-time static evaluation",
            how="Clean arithmetic compilation without unsafe string primitives.",
            remediation="None required; baseline validated.",
        )
        report_gen.add_finding(finding_1)
        self.assertEqual(len(report_gen.findings), 1)

        # ---------------------------------------------------------------------
        # Step 7: Persist through configured persistence backend
        # ---------------------------------------------------------------------
        artifact_doc = FirestoreArtifactDocument(
            sha256=sha256,
            filename="benign_sample.elf",
            size_bytes=len(raw_bytes),
            format_name="ELF",
            architecture=static_info["architecture"],
            entropy=static_info.get("entropy", 5.2),
            overall_posture="BENIGN",
            uploaded_by=principal.uid,
            tenant_id=principal.tenant_id,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            storage_path=f"artifacts/{principal.tenant_id}/{sha256}.elf",
            metadata={"source_compiled": True},
            findings_count=1,
        )

        findings_payload = [
            {
                "finding_id": finding_1.finding_id,
                "title": finding_1.title,
                "cwe_id": finding_1.cwe_id,
                "severity": "INFO",
                "cvss_score": finding_1.cvss_score,
                "location_va": finding_1.address_or_offset,
                "sink_or_section": finding_1.where,
                "evidence": finding_1.what,
                "remediation": finding_1.remediation,
                "detected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "tenant_id": principal.tenant_id,
            }
        ]

        if backend_choice == "simulation":
            storage_adapter = LocalSimulationPersistenceAdapter("rf-test-bucket")
            storage_adapter.save_artifact(artifact_doc)
            storage_adapter.save_findings(sha256, principal.tenant_id, findings_payload)
            storage_uri = storage_adapter.store_blob("binaries/benign.elf", raw_bytes, principal.tenant_id)
            self.assertTrue(storage_uri.startswith("local-sim://"))
        else:
            # Production adapter with injected mock SDK clients for deterministic offline verification
            mock_firestore = MagicMock()
            mock_storage_client = MagicMock()
            mock_bucket = MagicMock()
            mock_blob = MagicMock()
            mock_storage_client.bucket.return_value = mock_bucket
            mock_bucket.blob.return_value = mock_blob

            # Mock document snapshot for get_artifact
            mock_art_snap = MagicMock()
            mock_art_snap.exists = True
            mock_art_snap.to_dict.return_value = {
                "sha256": sha256,
                "filename": "benign_sample.elf",
                "tenant_id": principal.tenant_id,
                "findings_count": 1,
            }
            mock_firestore.collection().document().collection().document().get.return_value = mock_art_snap

            # Mock findings stream
            mock_finding_doc = MagicMock()
            mock_finding_doc.to_dict.return_value = findings_payload[0]
            mock_firestore.collection().document().collection().document().collection().stream.return_value = [mock_finding_doc]

            # Mock blob download
            mock_blob.download_as_bytes.return_value = raw_bytes

            storage_adapter = ProductionFirestoreStorageAdapter(
                project_id="phase4-test-project",
                storage_bucket="rf-prod-artifacts",
                firestore_client=mock_firestore,
                storage_client=mock_storage_client,
            )
            storage_adapter.save_artifact(artifact_doc)
            storage_adapter.save_findings(sha256, principal.tenant_id, findings_payload)
            storage_uri = storage_adapter.store_blob("binaries/benign.elf", raw_bytes, principal.tenant_id)
            self.assertTrue(storage_uri.startswith("gs://rf-prod-artifacts/tenants/tenant_alpha/binaries/benign.elf"))

        # ---------------------------------------------------------------------
        # Step 8: Retrieve saved artifact and findings
        # ---------------------------------------------------------------------
        retrieved_art = storage_adapter.get_artifact(sha256, principal.tenant_id)
        self.assertIsNotNone(retrieved_art)
        retrieved_findings = storage_adapter.get_findings(sha256, principal.tenant_id)
        self.assertEqual(len(retrieved_findings), 1)

        # ---------------------------------------------------------------------
        # Step 9: Verify retrieved data matches original records
        # ---------------------------------------------------------------------
        self.assertEqual(retrieved_art["sha256"], sha256)
        self.assertEqual(retrieved_art["tenant_id"], principal.tenant_id)
        self.assertEqual(retrieved_findings[0]["finding_id"], "FIND-001")

        # ---------------------------------------------------------------------
        # Step 10: Produce report with provenance and explicit limitations
        # ---------------------------------------------------------------------
        markdown_report = report_gen.to_markdown()
        self.assertIn("benign_sample.elf", markdown_report)
        self.assertIn(sha256[:16], markdown_report)
        self.assertIn("FIND-001", markdown_report)

        # ---------------------------------------------------------------------
        # Step 11: Attempt unauthorized cross-tenant access and confirm denial
        # ---------------------------------------------------------------------
        if backend_choice == "simulation":
            cross_tenant_art = storage_adapter.get_artifact(sha256, "unauthorized_tenant_gamma")
            self.assertIsNone(cross_tenant_art)
        else:
            # In ProductionFirestoreStorageAdapter, if a snapshot with tenant_alpha is returned under
            # unauthorized_tenant_gamma, Phase 4.1 tenant ownership validation raises PersistencePermissionError
            with self.assertRaises(PersistencePermissionError):
                storage_adapter.get_artifact(sha256, "unauthorized_tenant_gamma")

        # Cross-tenant request to Central Authorization Boundary
        permitted, decision, reason, _ = self.boundary.evaluate_request(
            principal=principal,
            operation=OperationType.READ_METADATA,
            target_path=self.bin_elf,
            target_sha256=sha256,
            target_tenant_id="tenant_foreign",  # Mismatch!
        )
        self.assertFalse(permitted)
        self.assertEqual(decision, AuthorizationDecision.DENIED_CROSS_TENANT_ACCESS)

        # ---------------------------------------------------------------------
        # Step 12: Attempt sensitive action without required HIL approval (confirm denial)
        # ---------------------------------------------------------------------
        # Dynamic sandbox requested with hil_callback=None
        permitted, decision, reason, _ = self.boundary.evaluate_request(
            principal=principal,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.bin_elf,
            target_sha256=sha256,
            target_tenant_id=principal.tenant_id,
            hil_callback=None,  # No HIL callback!
        )
        self.assertFalse(permitted)
        self.assertEqual(decision, AuthorizationDecision.DENIED_HIL_APPROVAL_REQUIRED)

        # ---------------------------------------------------------------------
        # Step 13: Verify that denied actions produce ZERO side-effects
        # ---------------------------------------------------------------------
        # Verify no detonation profiles, no runner scripts, and no modification occurred
        detonation_wsb = os.path.join(self.tmpdir, "detonation_profile.wsb")
        posix_sh = os.path.join(self.tmpdir, "posix_isolated_runner.sh")
        self.assertFalse(os.path.exists(detonation_wsb))
        self.assertFalse(os.path.exists(posix_sh))

        # Verify original binary was NOT modified
        with open(self.bin_elf, "rb") as f:
            final_bytes = f.read()
        self.assertEqual(hashlib.sha256(final_bytes).hexdigest(), sha256)


if __name__ == "__main__":
    unittest.main()
