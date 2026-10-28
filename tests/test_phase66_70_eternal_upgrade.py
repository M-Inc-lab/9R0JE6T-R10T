"""
R3V3R53//F0RG3 — Phases 66–70 (`v11.0.0-eternal`) Comprehensive Test Suite
Verifies:
  - Phase 66: Pure-Python PE Data Directories, DllCharacteristics Mitigations, NB10 & ELF Build-ID / Debuginfod
  - Phase 67: Full ModR/M+SIB+Disp/RIP-Relative Multi-Arch Disassembler, Multi-Block SSA & Address-Aware Scripting API
  - Phase 68: Automated CWE Vulnerability & Exploit Primitive Scanner Engine (CWE-120, CWE-78, CWE-134, CWE-190, CWE-415, CWE-416, CWE-693)
  - Phase 69: Persistent GDB RSP Stepping, Live Web Binary Patching (`POST /api/patch`) & Vuln Scan (`GET /api/vulns`)
  - Phase 70: CLI/REPL `vuln-scan` Command & `v11.0.0-eternal` (70 Phases, 64 Internal Engines) Diagnostics
"""

import json
import os
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import urllib.request
import unittest

import reverse_forge as forge
from reverse_forge.pe_analyzer import PEAnalyzer
from reverse_forge.pdb_symbol_engine import PDBSymbolEngine
from reverse_forge.recursive_disassembler import RecursiveDescentDisassembler
from reverse_forge.unified_decompiler_pipeline import UnifiedDecompilerPipeline
from reverse_forge.vuln_scanner_engine import BinaryVulnerabilityScannerEngine
from reverse_forge.gui_server import GUIWorkbenchHandler


class TestPhase66PurePythonPEDirectoriesAndPDBUpgrade(unittest.TestCase):
    def test_pure_python_pe64_mitigations_and_data_directories(self):
        # Construct a valid minimal PE32+ (64-bit) with DllCharacteristics (ASLR 0x40 | DEP 0x100 | CFG 0x4000 = 0x4140)
        pe = bytearray(0x600)
        pe[0:2] = b"MZ"
        struct.pack_into("<I", pe, 0x3C, 0x80)
        pe[0x80:0x84] = b"PE\x00\x00"
        # COFF header: machine=0x8664, num_sections=1, opt_hdr_size=0xF0 (240), chars=0x22
        struct.pack_into("<HHIIIHH", pe, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x0022)
        opt = 0x98
        struct.pack_into("<H", pe, opt, 0x20B)  # PE32+
        struct.pack_into("<I", pe, opt + 16, 0x1000)  # AddressOfEntryPoint
        struct.pack_into("<Q", pe, opt + 24, 0x140000000)  # ImageBase
        struct.pack_into("<HH", pe, opt + 68, 3, 0x4160)  # Subsystem=CUI, DllChars=ASLR|HighEntropy|DEP|CFG
        struct.pack_into("<I", pe, opt + 108, 16)  # NumberOfRvaAndSizes=16
        # Security Directory (index 4) non-zero -> Authenticode present
        struct.pack_into("<II", pe, opt + 112 + (4 * 8), 0x400, 0x80)
        # Section header at opt + 0xF0 = 0x188
        sec = 0x188
        pe[sec : sec + 6] = b".text\x00"
        struct.pack_into("<IIII", pe, sec + 8, 0x200, 0x1000, 0x200, 0x200)
        struct.pack_into("<I", pe, sec + 36, 0x60000020)

        rep = PEAnalyzer(bytes(pe)).analyze()
        self.assertTrue(rep["is_pe"])
        self.assertTrue(rep["mitigations"]["ASLR"])
        self.assertTrue(rep["mitigations"]["HighEntropyVA"])
        self.assertTrue(rep["mitigations"]["DEP_NX"])
        self.assertTrue(rep["mitigations"]["ControlFlowGuard_CFG"])
        self.assertTrue(rep["has_authenticode_signature"])
        self.assertIn("SECURITY", rep["data_directories"])

    def test_pdb_nb10_and_elf_build_id_debuginfod_and_local_cache(self):
        eng = PDBSymbolEngine()
        # 1. NB10 PDB 2.0 record
        nb10_blob = b"MZ" + b"\x00" * 32 + b"NB10" + struct.pack("<III", 0, 0x65432100, 3) + b"legacy_app.pdb\x00"
        rec_nb = eng.extract_codeview_rsds(nb10_blob)
        self.assertTrue(rec_nb.present)
        self.assertEqual(rec_nb.signature, "NB10")
        self.assertEqual(rec_nb.pdb_filename, "legacy_app.pdb")
        self.assertIn("654321003", rec_nb.symbol_server_url)

        # 2. ELF GNU Build-ID note -> debuginfod URL
        build_id_bytes = bytes.fromhex("0123456789abcdef0123456789abcdef01234567")
        elf_blob = b"\x7fELF" + b"\x00" * 16 + b"\x04\x00\x00\x00\x14\x00\x00\x00\x03\x00\x00\x00GNU\x00" + build_id_bytes
        rec_elf = eng.extract_codeview_rsds(elf_blob)
        self.assertTrue(rec_elf.present)
        self.assertEqual(rec_elf.signature, "NT_GNU_BUILD_ID")
        self.assertIn("debuginfod.elfutils.org/buildid/0123456789abcdef", rec_elf.debuginfod_url)


class TestPhase67ModRMDisassemblerMultiBlockSSAAndScriptingAPI(unittest.TestCase):
    def test_x64_modrm_memory_disp_rip_relative_and_0f_opcodes(self):
        dis = RecursiveDescentDisassembler(arch="x64")
        # 48 89 45 F8       -> mov qword ptr [rbp - 0x8], rax
        # 48 8B 47 18       -> mov rax, qword ptr [rdi + 0x18]
        # 48 8D 3D 20 01 00 00 -> lea rdi, [rip + 0x120]
        # 0F 05             -> syscall
        # C9                -> leave
        # C3                -> ret
        code = bytes.fromhex("488945f8 488b4718 488d3d20010000 0f05 c9 c3")
        ins_map = dis.disassemble_recursive(code, base_va=0x401000)
        self.assertEqual(ins_map[0x401000].mnemonic, "mov")
        self.assertIn("[rbp - 0x8], rax", ins_map[0x401000].op_str)
        self.assertEqual(ins_map[0x401004].mnemonic, "mov")
        self.assertIn("rax, qword ptr [rdi + 0x18]", ins_map[0x401004].op_str)
        self.assertEqual(ins_map[0x401008].mnemonic, "lea")
        self.assertIn("[rip + 0x120]", ins_map[0x401008].op_str)
        self.assertEqual(ins_map[0x40100F].mnemonic, "syscall")
        self.assertEqual(ins_map[0x401011].mnemonic, "leave")
        self.assertEqual(ins_map[0x401012].mnemonic, "ret")

    def test_unified_pipeline_recovers_struct_from_asm_memory_offsets(self):
        # Function that reads/writes [rdi + 0x8] and [rdi + 0x18] then returns
        code = bytes.fromhex("55 4889e5 488b4708 48894718 5d c3")
        res = UnifiedDecompilerPipeline(arch="x64").decompile_function_bytes(code, base_va=0x401000)
        self.assertGreaterEqual(len(res.inferred_structs), 1)
        self.assertIn("typedef struct struct_recovered_rdi_401000", res.final_c_code)
        self.assertIn("field_08", res.final_c_code)
        self.assertIn("field_18", res.final_c_code)

    def test_scripting_api_decompile_target_address_and_live_patch_refresh(self):
        # Build binary with two distinct subroutines at offset 0x0 (VA 0x401000) and offset 0x20 (VA 0x401020)
        fn1 = bytes.fromhex("55 4889e5 b8 01000000 5d c3")
        fn2 = bytes.fromhex("55 4889e5 488b4710 5d c3")
        blob = fn1.ljust(0x20, b"\x90") + fn2.ljust(0x40, b"\x90")
        ws = forge.from_bytes(blob, name="dual_func.bin")
        c_sub = ws.decompile(0x20)
        self.assertIn("sub_20", c_sub)
        self.assertIn("struct_recovered_rdi_20", c_sub)

        # Patch offset 0 and verify dossier SHA-256 updates immediately
        sha_before = ws.dossier["sha256"]
        ws.patch(0, b"\x90", description="NOP prologue")
        sha_after = ws.dossier["sha256"]
        self.assertNotEqual(sha_before, sha_after)
        ws.undo_patch()
        self.assertEqual(ws.dossier["sha256"], sha_before)


class TestPhase68CWEVulnerabilityScannerEngine(unittest.TestCase):
    def test_detects_buffer_overflow_command_injection_int_overflow_uaf_double_free_and_rwx(self):
        scanner = BinaryVulnerabilityScannerEngine()
        insns = [
            (0x401000, "imul", "rdi, rsi"),
            (0x401004, "call", "malloc"),           # CWE-190 Integer Overflow -> Alloc
            (0x401009, "mov", "rdi, rax"),
            (0x40100C, "call", "free"),             # First free(rdi)
            (0x401011, "mov", "rax, [rdi + 0x8]"),  # CWE-416 Use-After-Free
            (0x401015, "mov", "rdi, rbx"),
            (0x401018, "call", "free"),
            (0x40101D, "call", "free"),             # CWE-415 Double-Free
            (0x401022, "mov", "rdi, [rbp - 0x20]"),
            (0x401026, "call", "printf"),           # CWE-134 Uncontrolled Format String
        ]
        rep = scanner.scan_binary(
            binary_bytes=b"\x00strcpy\x00system\x00",
            imported_symbols=["strcpy", "system"],
            sections=[{"name": ".rwx_shell", "virtual_address": "0x405000", "writable": True, "executable": True}],
            mitigations={"ASLR": False, "DEP_NX": False},
            instructions=insns,
        )
        cwes = {f.cwe_id for f in rep.findings}
        self.assertIn("CWE-120", cwes)  # strcpy
        self.assertIn("CWE-78", cwes)   # system
        self.assertIn("CWE-190", cwes)  # imul -> malloc
        self.assertIn("CWE-416", cwes)  # UAF
        self.assertIn("CWE-415", cwes)  # Double-Free
        self.assertIn("CWE-134", cwes)  # Format string
        self.assertIn("CWE-693", cwes)  # RWX section & mitigations
        self.assertEqual(rep.overall_risk_rating, "CRITICAL")


class TestPhase69To70LiveWebPatchingPersistentDebuggerAndEternalCLI(unittest.TestCase):
    def test_web_live_patch_vulns_and_persistent_debugger_stepping(self):
        class QuietServer(socketserver.TCPServer):
            allow_reuse_address = True

        GUIWorkbenchHandler.active_debugger = None
        httpd = QuietServer(("127.0.0.1", 0), GUIWorkbenchHandler)
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()

        try:
            base_url = f"http://127.0.0.1:{port}"
            sample = b"MZ" + b"\x90" * 62 + b"PE\x00\x00" + b"\x74\x06\x55\x48\x89\xe5\x31\xc0\x5d\xc3" + b"\x00strcpy\x00"
            with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
                tf.write(sample)
                sample_path = tf.name

            # 1. GET /api/vulns detects strcpy CWE-120
            with urllib.request.urlopen(f"{base_url}/api/vulns?path={sample_path}") as r_v:
                v_doc = json.loads(r_v.read().decode("utf-8"))
            self.assertEqual(v_doc["status"], "ok")
            self.assertGreaterEqual(v_doc["vulnerabilities_count"], 1)

            # 2. POST /api/patch requires verified Bearer JWT and single-use HIL ApprovalGrant
            from reverse_forge.gui_server import firebase_sync
            from reverse_forge.firebase_sync import jwt
            from reverse_forge.authorization import ApprovalIssuer, HILKeyRing, OperationType, reset_authorization_boundary
            from reverse_forge.provenance import ProvenanceManager
            import time as _time
            jwt_secret = "phase69_jwt_secret_32_bytes_minimum_length!!"
            hil_secret = "phase69_hil_secret_32_bytes_minimum_length!!"
            firebase_sync.auth.verification_key = jwt_secret
            firebase_sync.auth.allowed_algorithms = ["HS256"]
            ring = HILKeyRing(keys={"default": hil_secret}, active_key_id="default")
            reset_authorization_boundary(signing_key=ring)
            token = jwt.encode(
                {
                    "sub": "analyst_p69",
                    "email": "analyst@lab.local",
                    "role": "ANALYST",
                    "tenant_id": "default_tenant",
                    "iss": firebase_sync.auth.expected_issuer,
                    "aud": firebase_sync.auth.expected_audience,
                    "exp": _time.time() + 3600,
                },
                jwt_secret,
                algorithm="HS256",
            )
            principal = firebase_sync.auth.verify_bearer_token(f"Bearer {token}")
            target_sha = ProvenanceManager.compute_hashes(sample_path)["sha256"]
            grant = ApprovalIssuer(key_ring=ring).issue_grant(
                approver=principal,
                operation=OperationType.MODIFY_ARTIFACT,
                target_path=sample_path,
                target_sha256=target_sha,
                tenant_id="default_tenant",
                parameters={"offset": "68", "operation": "invert"},
            )
            patch_req = urllib.request.Request(
                f"{base_url}/api/patch?path={sample_path}",
                data=json.dumps({"offset": "68", "operation": "invert", "approval_grant": grant.to_dict()}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token}",
                },
                method="POST",
            )
            with urllib.request.urlopen(patch_req) as r_p:
                p_doc = json.loads(r_p.read().decode("utf-8"))
            self.assertEqual(p_doc["status"], "ok")
            self.assertEqual(p_doc["transaction"]["original_bytes_hex"], "74")
            self.assertEqual(p_doc["transaction"]["patched_bytes_hex"], "75")

            # 3. Persistent /api/debug advances RIP across consecutive calls
            with urllib.request.urlopen(f"{base_url}/api/debug?action=step") as r_d1:
                d1 = json.loads(r_d1.read().decode("utf-8"))
            with urllib.request.urlopen(f"{base_url}/api/debug?action=step") as r_d2:
                d2 = json.loads(r_d2.read().decode("utf-8"))
            self.assertNotEqual(d1["snapshot"]["rip"], d2["snapshot"]["rip"])
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_eternal_cli_doctor_and_vuln_scan(self):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        proc = subprocess.run(
            [sys.executable, "-m", "reverse_forge.cli", "doctor"],
            cwd=repo_root,
            capture_output=True, text=True, check=True,
        )
        doc = json.loads(proc.stdout)
        self.assertIn(doc["version"], ("11.0.0-eternal", "12.0.0-apex-omni", "13.0.0-vanguard", "14.0.0-transcendent", "15.0.0-rust-titan", "16.0.0-omni-rust", "17.0.0-rust-dominion", "18.0.0-rust-sovereign", "19.0.0-rust-singularity", "20.0.0-rust-omega", "21.0.0-rust-apex", "22.0.0-rust-eternal", "23.0.0-rust-zenith", "24.0.0-rust-omni-complete", "25.0.0-rust-transcendent", "26.0.0-rust-bicentennial"))
        self.assertGreaterEqual(doc["phases_implemented"], 70)
        self.assertGreaterEqual(doc["internal_engines_count"], 64)
        self.assertEqual(doc["internal_engines_status"], "ALL_READY")

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
            tf.write(b"MZ" + b"\x90" * 64 + b"\x00gets\x00system\x00")
            tmp_path = tf.name
        try:
            v_proc = subprocess.run(
                [sys.executable, "-m", "reverse_forge.cli", "vuln-scan", "-i", tmp_path],
                cwd=repo_root,
                capture_output=True, text=True, check=True,
            )
            v_out = json.loads(v_proc.stdout)
            self.assertGreaterEqual(v_out["vulnerabilities_count"], 2)
            self.assertEqual(v_out["risk_rating"], "CRITICAL")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)



    def test_patches_1_to_4_z3_binding_colab_tls_and_requirements_sync(self):
        import ssl
        import warnings
        from gpu_client import ColabGPUClient, CleartextTokenSecurityWarning, build_verified_ssl_context
        from connect_colab import validate_endpoint_url
        from reverse_forge.smt_solver_engine import PathConstraint, SMTSolverEngine, z3

        # PATCH 1: z3 module is bound and non-linear bitwise constraints solve accurately
        self.assertIsNotNone(z3)
        smt = SMTSolverEngine()
        sat_res = smt.solve_constraints([
            PathConstraint(var="k", op="BIT_AND_EQ", value=0x1040, modulus_or_mask=0x1040),
            PathConstraint(var="k", op="MOD_EQ", value=0, modulus_or_mask=16),
        ])
        self.assertEqual(sat_res.status, "SAT")
        self.assertEqual(sat_res.model["k"] & 0x1040, 0x1040)

        # Impossible bitwise constraint (1-bit outside mask) immediately detected as UNSAT
        unsat_res = smt.solve_constraints([
            PathConstraint(var="k", op="BIT_AND_EQ", value=0x00FF, modulus_or_mask=0x000F),
        ])
        self.assertEqual(unsat_res.status, "UNSAT")

        # Verify cli.py doctor reports z3: true
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        doc_proc = subprocess.run(
            [sys.executable, "-m", "reverse_forge.cli", "doctor"],
            cwd=repo_root,
            capture_output=True, text=True, check=True,
        )
        doc_data = json.loads(doc_proc.stdout)
        self.assertTrue(doc_data["optional_python_bindings"]["z3"])

        # PATCH 2: Explicit SSL hostname & certificate verification + block remote HTTP Bearer token leak
        ssl_ctx = build_verified_ssl_context()
        self.assertTrue(ssl_ctx.check_hostname)
        self.assertEqual(ssl_ctx.verify_mode, ssl.CERT_REQUIRED)

        with warnings.catch_warnings(record=True) as w_rec:
            warnings.simplefilter("always")
            # Remote HTTP with a Bearer token must be blocked to prevent cleartext token leakage
            with self.assertRaises(ValueError):
                ColabGPUClient(endpoint="http://remote-tunnel.ngrok.io", token="secret_bearer_123", allow_http=True)
            with self.assertRaises(ValueError):
                validate_endpoint_url("http://remote-tunnel.ngrok.io", allow_http=True, token="secret_bearer_123")
            # Loopback HTTP emits CleartextTokenSecurityWarning
            validate_endpoint_url("http://127.0.0.1:8000", allow_http=True)
            self.assertTrue(any(issubclass(w.category, CleartextTokenSecurityWarning) for w in w_rec))

        # PATCH 3 & PATCH 4: requirements.txt, pyproject.toml, requirements.lock, and .git tracking
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(repo_root, "requirements.txt"), "r", encoding="utf-8") as rf:
            req_txt = rf.read()
        for pkg in ("z3-solver", "fastmcp", "fastapi", "uvicorn", "pydantic"):
            self.assertIn(pkg, req_txt)
        self.assertTrue(os.path.exists(os.path.join(repo_root, "requirements.lock")))
        self.assertTrue(os.path.isdir(os.path.join(repo_root, ".git")))


if __name__ == "__main__":
    unittest.main()
