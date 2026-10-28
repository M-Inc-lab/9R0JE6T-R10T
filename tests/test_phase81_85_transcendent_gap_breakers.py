"""
R3V3R53//F0RG3 — Phases 81–85 (`v14.0.0-transcendent`) Gap-Breaker Test Suite
Verifies how Reverse-Forge moves past traditional single-tool limitations:
  - Phase 81: Under-Constrained Force-Execution & Auto-Paging CPU Micro-Visor (`UnderConstrainedMicroVisor`)
  - Phase 82: Multi-Decompiler AST Fusion, Pre-Deobfuscation & Visor Verification (`MultiDecompilerFusionEngine`)
  - Phase 83: Deep ECMA-335 `.NET CLR` `#~` Table Bitmask & `#US` UTF-16LE Heap Parser (`BytecodeManagedEngine`)
  - Phase 84: Windows Minidump (`MDMP`), ELF `ET_CORE` & In-Memory PE Unmapper (`LiveMemoryAndDumpEngine`)
  - Phase 85: Web Studio (`/api/force-exec`, `/api/decompile-fuse`, `/api/memory-dump`) & CLI (`14.0.0-transcendent`, 85 Phases, 74 Engines)
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

from reverse_forge.underconstrained_visor_engine import UnderConstrainedMicroVisor
from reverse_forge.multi_decompiler_fusion_engine import MultiDecompilerFusionEngine
from reverse_forge.bytecode_clr_dex_wasm_engine import BytecodeManagedEngine
from reverse_forge.live_memory_dump_engine import LiveMemoryAndDumpEngine
from reverse_forge.gui_server import GUIWorkbenchHandler


class TestPhase81UnderConstrainedForceExecutionVisor(unittest.TestCase):
    def test_auto_paging_unmapped_struct_deref_and_forced_multi_branch_exploration(self):
        # 0x401000: mov rax, qword ptr [rdi + 0x20]  (48 8b 47 20) -> unmapped shadow struct deref!
        # 0x401004: cmp eax, 0                       (83 f8 00)
        # 0x401007: je  0x401010                     (74 07)       -> branch 1 jumps to 0x401010 (returns 0), branch 2 falls through (returns 0x1337)
        # 0x401009: mov eax, 0x1337                  (b8 37 13 00 00)
        # 0x40100E: ret                              (c3)
        # 0x40100F: nop                              (90)
        # 0x401010: xor eax, eax                     (31 c0)
        # 0x401012: ret                              (c3)
        code = bytes.fromhex("488b4720 83f800 7407 b837130000 c3 90 31c0 c3")
        visor = UnderConstrainedMicroVisor(arch="x64", base_va=0x401000)
        rep = visor.force_execute_function(code, max_steps_per_path=32, max_paths=4)

        self.assertGreaterEqual(rep.auto_paged_faults_recovered, 1)
        self.assertGreaterEqual(rep.total_paths_explored, 2)
        return_vals = {p.return_rax for p in rep.explored_paths}
        # Both the normal return (0x0) and the hidden branch return (0x1337) must be discovered!
        self.assertIn("0x0", return_vals)
        self.assertIn("0x1337", return_vals)


class TestPhase82MultiDecompilerFusionEngine(unittest.TestCase):
    def test_multi_decompiler_consensus_fusion_and_visor_banner(self):
        code = bytes.fromhex("55 4889e5 488b4710 b82a000000 5d c3")
        rep = MultiDecompilerFusionEngine().decompile_with_fusion(code, base_va=0x401000, func_name="verify_license")
        self.assertEqual(rep.dynamic_visor_verified_return, "0x2a")
        self.assertGreaterEqual(rep.consensus_confidence, 0.90)
        self.assertIn("Verified Return:    RAX = 0x2a", rep.fused_consensus_c)
        self.assertIn("struct_recovered_rdi_401000", rep.fused_consensus_c)


class TestPhase83ECMA335MetadataTablesAndUSHeap(unittest.TestCase):
    def test_dotnet_ecma335_table_bitmask_and_us_utf16_heap_recovery(self):
        # Build a .NET CLR BSJB metadata root with 2 streams: '#~' (offset 64, size 48) and '#US' (offset 112, size 64)
        bsjb_hdr = (
            b"BSJB"
            + struct.pack("<HHII", 1, 1, 0, 12)
            + b"v4.0.30319\x00\x00"
            + struct.pack("<HH", 0, 2)  # flags=0, num_streams=2
            + struct.pack("<II", 64, 48) + b"#~\x00\x00"
            + struct.pack("<II", 112, 64) + b"#US\x00"
        )
        bsjb_padded = bsjb_hdr.ljust(64, b"\x00")

        # ECMA-335 #~ stream at offset 64:
        # Valid bitmask has Module (bit 0), TypeDef (bit 2), MethodDef (bit 6) -> mask = (1<<0) | (1<<2) | (1<<6) = 0x45
        tilde_stream = (
            struct.pack("<IBBBBQ", 0, 2, 0, 0, 1, (1 << 0) | (1 << 2) | (1 << 6))
            + struct.pack("<Q", 0)
            + struct.pack("<III", 1, 4, 12)  # Module=1, TypeDef=4, MethodDef=12
        ).ljust(48, b"\x00")

        # #US stream at offset 112: initial 0x00 + length-prefixed UTF-16LE "AesKey256" + 0x00 terminal byte
        utf16_payload = "AesKey256".encode("utf-16le") + b"\x00"
        us_stream = (b"\x00" + bytes([len(utf16_payload)]) + utf16_payload).ljust(64, b"\x00")

        cil_prefix = b"\x72\x01\x00\x00\x70\x2a"  # ldstr 0x70000001; ret
        full_blob = cil_prefix.ljust(32, b"\x00") + bsjb_padded + tilde_stream + us_stream

        rep = BytecodeManagedEngine().analyze_binary(full_blob)
        self.assertEqual(rep.runtime_format, "DOTNET_CLR")
        self.assertEqual(rep.ecma335_metadata_tables["Module"], 1)
        self.assertEqual(rep.ecma335_metadata_tables["TypeDef"], 4)
        self.assertEqual(rep.ecma335_metadata_tables["MethodDef"], 12)
        self.assertIn("AesKey256", rep.user_strings_us_heap)
        self.assertIn('Console.WriteLine("AesKey256");', rep.decompiled_pseudocode)


class TestPhase84To85MinidumpPEUnmapperAndTranscendentCLI(unittest.TestCase):
    def test_mdmp_parser_and_in_memory_pe_unmapper(self):
        eng = LiveMemoryAndDumpEngine()
        # 1. Construct a Windows Minidump (MDMP) with 2 streams (SystemInfoStream=7, Memory64ListStream=9)
        mdmp = (
            b"MDMP"
            + struct.pack("<IIIIIQ", 0xA793, 2, 32, 0, 1700000000, 0)
            + struct.pack("<III", 7, 56, 64)
            + struct.pack("<III", 9, 128, 120)
            + b"\x00" * 64
        )
        r_mdmp = eng.analyze_dump(mdmp)
        self.assertEqual(r_mdmp.dump_format, "WINDOWS_MINIDUMP_MDMP")
        self.assertEqual(len(r_mdmp.streams_or_segments), 2)
        self.assertEqual(r_mdmp.streams_or_segments[0].stream_name, "SystemInfoStream")

        # 2. Construct a memory-dumped PE where VirtualAddress=0x1000 but PointerToRawData=0x200
        pe = bytearray(0x400)
        pe[0:2] = b"MZ"
        struct.pack_into("<I", pe, 0x3C, 0x80)
        pe[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<HHIIIHH", pe, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
        sec_off = 0x84 + 20 + 0xF0
        pe[sec_off : sec_off + 6] = b".text\x00"
        struct.pack_into("<IIII", pe, sec_off + 8, 0x200, 0x1000, 0x200, 0x200)

        fixed_pe, was_fixed = eng.unmap_memory_pe_to_disk_pe(bytes(pe))
        self.assertTrue(was_fixed)
        _, vaddr, _, new_raw_ptr = struct.unpack_from("<IIII", fixed_pe, sec_off + 8)
        self.assertEqual(new_raw_ptr, vaddr)

    def test_transcendent_cli_doctor_and_web_endpoints(self):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        doc_proc = subprocess.run(
            [sys.executable, "-m", "reverse_forge.cli", "doctor"],
            cwd=repo_root,
            capture_output=True, text=True, check=True,
        )
        doc = json.loads(doc_proc.stdout)
        self.assertIn(doc["version"], ("14.0.0-transcendent", "15.0.0-rust-titan", "16.0.0-omni-rust", "17.0.0-rust-dominion", "18.0.0-rust-sovereign", "19.0.0-rust-singularity", "20.0.0-rust-omega", "21.0.0-rust-apex", "22.0.0-rust-eternal", "23.0.0-rust-zenith", "24.0.0-rust-omni-complete", "25.0.0-rust-transcendent", "26.0.0-rust-bicentennial"))
        self.assertGreaterEqual(doc["phases_implemented"], 85)
        self.assertGreaterEqual(doc["internal_engines_count"], 74)
        self.assertEqual(doc["internal_engines_status"], "ALL_READY")

        class QuietServer(socketserver.TCPServer):
            allow_reuse_address = True

        httpd = QuietServer(("127.0.0.1", 0), GUIWorkbenchHandler)
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        try:
            with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
                tf.write(b"MZ" + b"\x90" * 62 + b"PE\x00\x00" + bytes.fromhex("488b4720 83f800 7407 b837130000 c3 90 31c0 c3"))
                tmp_path = tf.name

            base_url = f"http://127.0.0.1:{port}"
            from reverse_forge.gui_server import firebase_sync
            from reverse_forge.firebase_sync import jwt
            from reverse_forge.authorization import ApprovalIssuer, HILKeyRing, OperationType, reset_authorization_boundary
            from reverse_forge.provenance import ProvenanceManager
            import time as _time
            jwt_secret = "phase85_jwt_secret_32_bytes_minimum_length!!"
            hil_secret = "phase85_hil_secret_32_bytes_minimum_length!!"
            firebase_sync.auth.verification_key = jwt_secret
            firebase_sync.auth.allowed_algorithms = ["HS256"]
            ring = HILKeyRing(keys={"default": hil_secret}, active_key_id="default")
            reset_authorization_boundary(signing_key=ring)
            token = jwt.encode(
                {
                    "sub": "analyst_p85",
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
            target_sha = ProvenanceManager.compute_hashes(tmp_path)["sha256"]
            grant = ApprovalIssuer(key_ring=ring).issue_grant(
                approver=principal,
                operation=OperationType.DYNAMIC_SANDBOX,
                target_path=tmp_path,
                target_sha256=target_sha,
                tenant_id="default_tenant",
                parameters={"path": os.path.realpath(tmp_path)},
            )
            fe_req = urllib.request.Request(
                f"{base_url}/api/force-exec?path={tmp_path}",
                headers={
                    "Authorization": f"Bearer {token}",
                    "X-HIL-Approval-Grant": json.dumps(grant.to_dict()),
                },
            )
            with urllib.request.urlopen(fe_req) as r_fe:
                fe_doc = json.loads(r_fe.read().decode("utf-8"))
            self.assertEqual(fe_doc["status"], "ok")
            self.assertGreaterEqual(fe_doc["visor_report"]["total_paths_explored"], 1)

            with urllib.request.urlopen(f"{base_url}/api/decompile-fuse?path={tmp_path}") as r_df:
                df_doc = json.loads(r_df.read().decode("utf-8"))
            self.assertEqual(df_doc["status"], "ok")
            self.assertIn("Verified Return:", df_doc["fusion_report"]["fused_consensus_c"])
        finally:
            httpd.shutdown()
            httpd.server_close()
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
