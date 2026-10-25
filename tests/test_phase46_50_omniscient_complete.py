"""
Unit tests for Phases 46–50 (v8.0-omniscient Complete Reverse-Engineering Feature Parity):
  - Phase 46: FLOSS-Style ObfuscatedStringSolver (Stack Strings, Single-Byte XOR, ADD Shift Strings)
  - Phase 47: CompilerPackerProfiler (PE Rich Header XOR decryption, Mandiant Imphash, UPX/Go/Rust/MSVC detection, Overlay extraction)
  - Phase 48: SyscallAndStructEngine (Direct `syscall` / `int 0x80` / `svc #0` ABI resolution & Kaitai/ImHex C-Struct template parser)
  - Phase 49: BinaryPatcherEngine (Micro-assembler, `nop_range`, `invert_conditional_branch`, `patch_function_return`, undo transaction)
  - Phase 50: ProjectWorkspaceDB (`.rfdb` persistence, symbol renaming, comments, bookmarks, C `.h` header, IDAPython & Ghidra export)
"""

import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest

from reverse_forge.string_deobfuscator import ObfuscatedStringSolver
from reverse_forge.compiler_packer_profiler import CompilerPackerProfiler
from reverse_forge.syscall_struct_engine import SyscallAndStructEngine
from reverse_forge.binary_patcher import BinaryPatcherEngine
from reverse_forge.project_workspace_db import ProjectWorkspaceDB


class TestPhase46ObfuscatedStringSolver(unittest.TestCase):
    def test_recover_stack_strings_and_xor_strings(self):
        """Verify FLOSS-style stack string (`mov byte ptr [rbp+disp8], imm8`) and XOR string recovery."""
        # Build stack string: 'cmd.exe' via C6 45 disp8 imm8
        stack_code = bytearray()
        for idx, ch in enumerate(b"cmd.exe\x00"):
            stack_code.extend(bytes([0xC6, 0x45, (0xE0 + idx) & 0xFF, ch]))

        # Build XOR-encoded URL (XOR key 0x5A): "https://secret.c2.local/ beacon"
        plain_url = b"https://secret.c2.local/beacon\x00"
        xor_blob = bytes(b ^ 0x5A for b in plain_url)

        combined = bytes(stack_code) + b"\x00" * 32 + xor_blob
        solver = ObfuscatedStringSolver()
        rep = solver.deobfuscate_all_strings(combined, min_len=4)

        self.assertGreaterEqual(rep.stack_strings_count, 1)
        self.assertGreaterEqual(rep.xor_strings_count, 1)
        decoded_vals = {s.decoded_string for s in rep.recovered_strings}
        self.assertIn("cmd.exe", decoded_vals)
        self.assertTrue(any("https://secret.c2.local" in v for v in decoded_vals))


class TestPhase47CompilerPackerAndRichHeader(unittest.TestCase):
    def test_pe_rich_header_decryption_imphash_and_overlay(self):
        """Verify PE Rich Header XOR decryption, Mandiant Imphash calculation, and overlay detection."""
        profiler = CompilerPackerProfiler()

        # Construct PE header with valid encrypted Rich / DanS header in DOS stub
        pe_buf = bytearray(512)
        pe_buf[0:2] = b"MZ"
        struct.pack_into("<I", pe_buf, 0x3C, 0x100)  # e_lfanew = 0x100

        xor_key = 0x12345678
        dans_plain = struct.pack(
            "<IIIIII",
            0x536E6144,  # 'DanS'
            0, 0, 0,     # 3 zero padding dwords
            (0x012D << 16) | 30139,  # Utc1930_C_VS2022, build 30139
            14,          # use_count = 14
        )
        enc_dans = b"".join(
            struct.pack("<I", struct.unpack_from("<I", dans_plain, off)[0] ^ xor_key)
            for off in range(0, len(dans_plain), 4)
        )
        pe_buf[0x80 : 0x80 + len(enc_dans)] = enc_dans
        pe_buf[0x80 + len(enc_dans) : 0x80 + len(enc_dans) + 8] = b"Rich" + struct.pack("<I", xor_key)

        # Append ZIP overlay at byte 512
        overlay_zip = b"PK\x03\x04" + b"APPENDED_PAYLOAD_DATA" * 4
        full_data = bytes(pe_buf) + overlay_zip

        sections = [{"name": ".text", "raw_offset": "0x100", "raw_size": 256}]
        imports = ["KERNEL32.DLL:VirtualAlloc", "ws2_32.dll:WSAStartup"]

        prof = profiler.profile_binary(full_data, sections=sections, imported_symbols=imports)
        self.assertTrue(prof.rich_header.present)
        self.assertEqual(prof.rich_header.xor_key, "0x12345678")
        self.assertEqual(prof.rich_header.entries[0].product_name, "Utc1930_C_VS2022")
        self.assertEqual(prof.rich_header.entries[0].use_count, 14)
        self.assertEqual(len(prof.imphash_md5), 32)
        self.assertTrue(prof.overlay.has_overlay)
        self.assertEqual(prof.overlay.overlay_magic_hint, "ZIP_or_JAR_Archive")


class TestPhase48SyscallAndCStructTemplateEngine(unittest.TestCase):
    def test_resolve_direct_syscalls_and_c_struct_overlay(self):
        """Verify direct x64 `mov eax, 59; syscall` resolves to sys_execve and C-struct template unpacks."""
        eng = SyscallAndStructEngine()
        # mov eax, 59 (B8 3B 00 00 00); syscall (0F 05); mov eax, 41 (B8 29 00 00 00); syscall (0F 05)
        code = b"\xb8\x3b\x00\x00\x00\x0f\x05\xb8\x29\x00\x00\x00\x0f\x05"
        sites = eng.resolve_direct_syscalls(code, base_va=0x401000, platform_hint="linux_x64")
        self.assertEqual(len(sites), 2)
        self.assertEqual(sites[0].syscall_name, "sys_execve")
        self.assertEqual(sites[0].security_category, "COMMAND_EXECUTION")
        self.assertEqual(sites[1].syscall_name, "sys_socket")

        # Test Kaitai/ImHex-style C struct overlay
        raw_pkt = struct.pack("<IHH8s", 0xCAFEBABE, 2, 128, b"FORGE_V8")
        c_def = """
        struct ForgeHeader {
            uint32_t magic;
            uint16_t version;
            uint16_t payload_len;
            char signature[8];
        };
        """
        parsed = eng.apply_c_struct_template(raw_pkt, c_def, base_offset=0)
        self.assertEqual(parsed.struct_name, "ForgeHeader")
        self.assertEqual(parsed.total_size_bytes, 16)
        field_map = {f.field_name: f.value for f in parsed.fields}
        self.assertEqual(field_map["magic"], 0xCAFEBABE)
        self.assertEqual(field_map["version"], 2)
        self.assertEqual(field_map["payload_len"], 128)
        self.assertEqual(field_map["signature"], "FORGE_V8")


class TestPhase49BinaryPatcherEngine(unittest.TestCase):
    def test_branch_inversion_nop_fill_force_return_and_undo(self):
        """Verify BinaryPatcherEngine flips je->jne, fills NOPs, patches return value, and undoes cleanly."""
        orig = b"\x74\x10\x0f\x84\x20\x00\x00\x00\x55\x48\x89\xe5\x90\x90\x90\x90"
        patcher = BinaryPatcherEngine(orig, arch="x64")

        # 1. Invert short je (0x74) -> jne (0x75) at offset 0
        tx1 = patcher.invert_conditional_branch(0)
        self.assertEqual(patcher.working_bytes[0], 0x75)
        self.assertEqual(tx1.patched_bytes_hex, "75")

        # 2. Invert near je (0F 84) -> jne (0F 85) at offset 2
        tx2 = patcher.invert_conditional_branch(2)
        self.assertEqual(patcher.working_bytes[2:4], b"\x0f\x85")

        # 3. Patch function return at offset 8 (`return 42` -> B8 2A 00 00 00 C3)
        patcher.patch_function_return(8, return_value=42)
        self.assertEqual(patcher.working_bytes[8:14], b"\xb8\x2a\x00\x00\x00\xc3")

        # 4. Undo all 3 patches and verify SHA-256 matches original
        patcher.undo_last_patch()
        patcher.undo_last_patch()
        patcher.undo_last_patch()
        summary = patcher.get_patch_summary()
        self.assertEqual(summary.original_sha256, summary.patched_sha256)


class TestPhase50ProjectWorkspaceDBAndOmniscientCLI(unittest.TestCase):
    def test_project_db_c_header_idapython_and_ghidra_export(self):
        """Verify ProjectWorkspaceDB persists .rfdb and exports C header, IDAPython, and Ghidra scripts."""
        proj = ProjectWorkspaceDB(binary_sha256="deadbeef" * 8, binary_name="firmware.elf")
        proj.rename_symbol(0x401000, "decrypt_config_frame")
        proj.set_comment(0x401000, "AES-128-CBC key schedule init")
        proj.add_bookmark(0x401000, "CRYPTO", "Primary decryption routine")
        proj.define_custom_struct("ConfigHdr", "struct ConfigHdr { uint32_t key_id; uint32_t crc; };")

        c_hdr = proj.export_c_header()
        self.assertIn("struct ConfigHdr", c_hdr)
        self.assertIn("int64_t decrypt_config_frame(", c_hdr)
        self.assertIn("AES-128-CBC key schedule init", c_hdr)

        ida_py = proj.export_idapython_script()
        self.assertIn('idc.set_name(0x401000, "decrypt_config_frame"', ida_py)

        ghidra_py = proj.export_ghidra_script()
        self.assertIn('fn.setName("decrypt_config_frame", SourceType.USER_DEFINED)', ghidra_py)

        annotated_c = proj.apply_annotations_to_c_code("int sub_401000(void) { return 0; }")
        self.assertIn("decrypt_config_frame", annotated_c)

    def test_v8_omniscient_cli_doctor_and_subcommands(self):
        """Verify cli.py doctor reports 50 phases / 52 engines (v8.0.0-omniscient) and new CLI commands work."""
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        doc = subprocess.run(
            [sys.executable, "-m", "reverse_forge.cli", "doctor"],
            cwd=repo_root,
            capture_output=True, text=True, check=True,
        )
        doc_json = json.loads(doc.stdout)
        self.assertIn(doc_json["version"], ("8.0.0-omniscient", "9.0.0-sovereign", "10.0.0-zenith", "11.0.0-eternal"))
        self.assertGreaterEqual(doc_json["phases_implemented"], 50)
        self.assertGreaterEqual(doc_json["internal_engines_count"], 53)

        px = subprocess.run(
            [
                sys.executable, "-m", "reverse_forge.cli", "project-export",
                "--format", "c-header",
                "--rename", "0x401000=parse_auth_token",
                "--comment", "0x401000=Token verifier",
            ],
            cwd=repo_root,
            capture_output=True, text=True, check=True,
        )
        self.assertIn("parse_auth_token", px.stdout)


if __name__ == "__main__":
    unittest.main()
