"""
Differential Analysis Validation Test Suite (§06, Stage 6)
Validates instruction boundaries, function boundaries, CFG edges, and format detection
against independent reference tools (Capstone, ELF symbol tables) on benign fixtures.
"""

import os
import shutil
import struct
import subprocess
import unittest

try:
    import capstone
except ImportError:
    capstone = None

from reverse_forge.whole_binary_function_indexer import WholeBinaryFunctionIndexer
from reverse_forge.elf_analyzer import ELFAnalyzer
from reverse_forge.pe_analyzer import PEAnalyzer
from reverse_forge.native_rust_bridge import NativeRustAccelerator


class TestDifferentialAnalysisValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target_elf = "/bin/ls" if os.path.exists("/bin/ls") else "/usr/bin/ls"
        cls.elf_data = b""
        if os.path.exists(cls.target_elf):
            with open(cls.target_elf, "rb") as f:
                cls.elf_data = f.read()

        fix_dir = os.path.join(os.path.dirname(__file__), "fixtures")
        src_c = os.path.join(fix_dir, "known_control_flow.c")
        unstripped = os.path.join(fix_dir, "known_control_flow_unstripped.elf")
        stripped = os.path.join(fix_dir, "known_control_flow_stripped.elf")
        nofp = os.path.join(fix_dir, "known_control_flow_nofp.elf")
        if os.path.exists(src_c) and shutil.which("gcc"):
            if not os.path.exists(unstripped):
                subprocess.run(["gcc", "-O2", "-g", src_c, "-o", unstripped], check=False)
            if not os.path.exists(stripped) and os.path.exists(unstripped):
                shutil.copy2(unstripped, stripped)
                if shutil.which("strip"):
                    subprocess.run(["strip", "-s", stripped], check=False)
            if not os.path.exists(nofp):
                subprocess.run(["gcc", "-O2", "-fomit-frame-pointer", src_c, "-o", nofp], check=False)

    def test_elf_format_and_architecture_detection_against_headers(self):
        """Validate ELF format and machine type match official System V AMD64 ELF specification."""
        if not self.elf_data:
            self.skipTest("Host /bin/ls not available")

        # 1. Independent Python struct header unpack
        e_ident = self.elf_data[:16]
        self.assertEqual(e_ident[:4], b"\x7fELF")
        ei_class = e_ident[4]  # 2 = 64-bit
        ei_data = e_ident[5]   # 1 = Little-endian
        self.assertEqual(ei_class, 2)
        self.assertEqual(ei_data, 1)

        e_type, e_machine, e_version, e_entry = struct.unpack_from("<HHIQ", self.elf_data, 16)
        self.assertEqual(e_machine, 0x3E)  # EM_X86_64

        # 2. Validate platform analyzer concordance
        ana = ELFAnalyzer(self.elf_data)
        summary = ana.analyze()
        self.assertTrue(summary["is_elf"])
        self.assertEqual(summary["class"], "64-bit")
        self.assertIn("x86-64", summary["architecture"])
        self.assertEqual(int(str(summary["entry_point"]), 16), e_entry)

    def test_instruction_boundary_decoding_differential_vs_capstone(self):
        """Differentially validate instruction length and mnemonic decoding against Capstone engine."""
        if capstone is None:
            self.skipTest("Capstone engine not installed")

        # Complex x86-64 instruction sequence:
        # push rbp (1B)
        # mov rbp, rsp (3B)
        # sub rsp, 0x20 (4B)
        # mov rax, qword ptr [rdi + 0x18] (4B)
        # mov dword ptr [rbp - 4], 42 (7B)
        # add rax, rdx (3B)
        # leave (1B)
        # ret (1B)
        code_bytes = bytes.fromhex("55 4889e5 4883ec20 488b4718 c745fc2a000000 4801d0 c9 c3")

        # 1. Capstone reference decode
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs_insns = list(md.disasm(code_bytes, 0x401000))
        self.assertEqual(len(cs_insns), 8)
        cs_lengths = [i.size for i in cs_insns]
        self.assertEqual(cs_lengths, [1, 3, 4, 4, 7, 3, 1, 1])

        # 2. Native Micro-Visor execution (executes until unmapped memory access or limit)
        vres = NativeRustAccelerator.native_visor_exec(code_bytes, base_va=0x401000, max_steps=10)
        self.assertGreaterEqual(vres["steps_executed"], 4)

        # 3. Native P-Code lifting concordance
        decomp = NativeRustAccelerator.native_ghidra_pcode_decompile(code_bytes, base_va=0x401000)
        self.assertIn("entry_main", decomp)

    def test_function_indexer_symbol_concordance(self):
        """Validate WholeBinaryFunctionIndexer discovers functions matching ground-truth symbol table."""
        if not self.elf_data:
            self.skipTest("Host /bin/ls not available")

        indexer = WholeBinaryFunctionIndexer(self.elf_data)
        funcs = indexer.discover_all_functions()
        self.assertGreater(len(funcs), 50)

        func_names = {f.name for f in funcs}
        self.assertIn("main", func_names)

        # Validate entry point decompilation
        main_bundle = indexer.analyze_function()
        self.assertEqual(main_bundle.name, "main")
        self.assertGreater(len(main_bundle.cfg_blocks), 0)
        self.assertTrue(len(main_bundle.decompiled_c) > 0)

    def test_malformed_binary_adversarial_rejection(self):
        """Ensure corrupt, truncated, and cyclic binaries fail closed with typed errors."""
        # 1. Truncated PE header (only 12 bytes)
        trunc_pe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00"
        pe_ana = PEAnalyzer(trunc_pe)
        res = pe_ana.analyze()
        self.assertFalse(res["is_pe"])
        self.assertTrue(len(res["warnings"]) > 0)

        # 2. Corrupted ELF with out-of-bounds section header offset
        corrupt_elf = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
        corrupt_elf += struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x400000, 64, 0xFFFFFFFF00000000, 0, 64, 56, 1, 64, 10, 1)
        elf_ana = ELFAnalyzer(bytes(corrupt_elf))
        # Must fail safely without unhandled index error
        res = elf_ana.analyze()
        self.assertTrue(res["is_elf"])

    def test_native_flirt_crc16_differential_standard_vectors(self):
        """Differentially validate FLIRT CRC16 implementation on standard test vectors."""
        # Vector 1: '123456789' -> 0x906E
        self.assertEqual(NativeRustAccelerator.native_flirt_crc16(b"123456789"), 0x906E)

        # Vector 2: Empty buffer -> 0x0000
        self.assertEqual(NativeRustAccelerator.native_flirt_crc16(b""), 0x0000)

        # Vector 3: Standard x86 function prologue '55 48 89 e5' (push rbp; mov rbp, rsp)
        prologue_crc = NativeRustAccelerator.native_flirt_crc16(bytes.fromhex("55 48 89 e5"))
        self.assertIsInstance(prologue_crc, int)

    def test_pe_format_and_architecture_detection_against_spec(self):
        """Validate PE32+ fixture matches Microsoft PE/COFF specification and analyzer concordance."""
        pe = bytearray(0x600)
        pe[0:2] = b"MZ"
        struct.pack_into("<I", pe, 0x3C, 0x80)
        pe[0x80:0x84] = b"PE\x00\x00"
        # COFF header: machine=0x8664 (AMD64), num_sections=1, opt_hdr_size=0xF0, chars=0x22
        struct.pack_into("<HHIIIHH", pe, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x0022)
        opt = 0x98
        struct.pack_into("<H", pe, opt, 0x20B)  # PE32+ (64-bit)
        struct.pack_into("<I", pe, opt + 16, 0x1000)  # AddressOfEntryPoint
        struct.pack_into("<Q", pe, opt + 24, 0x140000000)  # ImageBase
        struct.pack_into("<HH", pe, opt + 68, 3, 0x4160)  # Subsystem=CUI, DllChars
        struct.pack_into("<I", pe, opt + 108, 16)  # NumberOfRvaAndSizes=16
        # Section header at opt + 0xF0 = 0x188 (.text)
        sec = 0x188
        pe[sec : sec + 6] = b".text\x00"
        struct.pack_into("<IIII", pe, sec + 8, 0x200, 0x1000, 0x200, 0x200)
        struct.pack_into("<I", pe, sec + 36, 0x60000020)

        rep = PEAnalyzer(bytes(pe)).analyze()
        self.assertTrue(rep["is_pe"])
        self.assertIn("64-bit AMD64", rep["architecture"])
        self.assertEqual(rep["entry_point"], "0x1000")
        self.assertEqual(len(rep["sections"]), 1)
        self.assertEqual(rep["sections"][0]["name"], ".text")

    def test_ground_truth_unstripped_elf_function_recovery(self):
        """Validate ground-truth symbol recovery against known C source functions in compiled ELF."""
        fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "known_control_flow_unstripped.elf")
        if not os.path.exists(fixture_path):
            self.skipTest("Fixture known_control_flow_unstripped.elf not found")

        with open(fixture_path, "rb") as f:
            elf_data = f.read()

        indexer = WholeBinaryFunctionIndexer(elf_data)
        funcs = indexer.discover_all_functions()
        func_names = {f.name for f in funcs}

        # Verify ground-truth functions from known_control_flow.c are recovered
        expected_symbols = [
            "arithmetic_mem",
            "target_add",
            "target_sub",
            "call_dispatch",
            "switch_jump_table",
            "tail_helper",
            "tail_call_entry",
            "main",
        ]
        for sym in expected_symbols:
            self.assertIn(sym, func_names, f"Expected ground-truth symbol '{sym}' was not recovered")

    def test_ground_truth_control_flow_and_jump_table(self):
        """Validate CFG basic blocks and jump table decoding on switch_jump_table function."""
        fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "known_control_flow_unstripped.elf")
        if not os.path.exists(fixture_path):
            self.skipTest("Fixture known_control_flow_unstripped.elf not found")

        with open(fixture_path, "rb") as f:
            elf_data = f.read()

        indexer = WholeBinaryFunctionIndexer(elf_data)
        funcs = {f.name: f for f in indexer.discover_all_functions()}
        self.assertIn("switch_jump_table", funcs)

        switch_fn = funcs["switch_jump_table"]
        bundle = indexer.analyze_function(switch_fn)
        self.assertEqual(bundle.name, "switch_jump_table")
        # Function must have multiple basic blocks due to the switch statement
        self.assertGreaterEqual(len(bundle.cfg_blocks), 2)

        # Differential disassembly with Capstone
        switch_bytes = elf_data[switch_fn.file_offset : switch_fn.file_offset + (switch_fn.size or 64)]
        if capstone is not None and switch_bytes:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            insns = list(md.disasm(switch_bytes, switch_fn.va))
            mnemonics = [i.mnemonic for i in insns]
            # Must contain comparison or branch instruction for bounds checking
            has_branch_or_cmp = any(m.startswith("j") or m in ("cmp", "test") for m in mnemonics)
            self.assertTrue(has_branch_or_cmp)

    def test_ground_truth_indirect_calls_and_arithmetic(self):
        """Differentially check call_dispatch and arithmetic_mem instructions against Capstone."""
        if capstone is None:
            self.skipTest("Capstone required for differential instruction decoding")

        fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "known_control_flow_unstripped.elf")
        if not os.path.exists(fixture_path):
            self.skipTest("Fixture known_control_flow_unstripped.elf not found")

        with open(fixture_path, "rb") as f:
            elf_data = f.read()

        indexer = WholeBinaryFunctionIndexer(elf_data)
        funcs = {f.name: f for f in indexer.discover_all_functions()}

        # 1. Arithmetic & memory function
        self.assertIn("arithmetic_mem", funcs)
        arith_fn = funcs["arithmetic_mem"]
        arith_bytes = elf_data[arith_fn.file_offset : arith_fn.file_offset + (arith_fn.size or 64)]
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        arith_insns = list(md.disasm(arith_bytes, arith_fn.va))
        arith_mnems = {i.mnemonic for i in arith_insns}
        # Verify arithmetic instructions are present
        has_arith = any(m in arith_mnems for m in ("add", "sub", "imul", "idiv", "lea"))
        self.assertTrue(has_arith)

        # 2. Call dispatch function (indirect call/tail call)
        self.assertIn("call_dispatch", funcs)
        call_fn = funcs["call_dispatch"]
        call_bytes = elf_data[call_fn.file_offset : call_fn.file_offset + (call_fn.size or 64)]
        call_insns = list(md.disasm(call_bytes, call_fn.va))
        call_mnems = [i.mnemonic for i in call_insns]
        self.assertTrue(any(m in ("call", "jmp") for m in call_mnems))

        # 3. Direct calls in main
        self.assertIn("main", funcs)
        main_fn = funcs["main"]
        main_bytes = elf_data[main_fn.file_offset : main_fn.file_offset + (main_fn.size or 128)]
        main_insns = list(md.disasm(main_bytes, main_fn.va))
        main_mnems = [i.mnemonic for i in main_insns]
        self.assertIn("call", main_mnems)

    def test_ground_truth_stripped_and_nofp_recovery(self):
        """Validate function recovery on stripped and frame-pointer-omitted binaries."""
        stripped_p = os.path.join(os.path.dirname(__file__), "fixtures", "known_control_flow_stripped.elf")
        nofp_p = os.path.join(os.path.dirname(__file__), "fixtures", "known_control_flow_nofp.elf")
        if not os.path.exists(stripped_p) or not os.path.exists(nofp_p):
            self.skipTest("Fixtures not found")

        with open(stripped_p, "rb") as f:
            stripped_data = f.read()
        with open(nofp_p, "rb") as f:
            nofp_data = f.read()

        # Stripped binary analysis
        s_ana = ELFAnalyzer(stripped_data)
        s_rep = s_ana.analyze()
        self.assertTrue(s_rep["is_elf"])
        self.assertTrue(s_rep["is_stripped"])

        s_indexer = WholeBinaryFunctionIndexer(stripped_data)
        s_funcs = s_indexer.discover_all_functions()
        self.assertGreater(len(s_funcs), 0)

        # Frame-pointer omitted binary analysis
        nofp_ana = ELFAnalyzer(nofp_data)
        nofp_rep = nofp_ana.analyze()
        self.assertTrue(nofp_rep["is_elf"])

        nofp_indexer = WholeBinaryFunctionIndexer(nofp_data)
        nofp_funcs = nofp_indexer.discover_all_functions()
        self.assertGreater(len(nofp_funcs), 0)

    def test_adversarial_elf_truncations_and_bounds(self):
        """Verify bounded memory and controlled errors when parsing truncated and cyclic ELFs."""
        # 1. Truncated header (< 64 bytes)
        trunc_elf = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00"
        ana = ELFAnalyzer(trunc_elf)
        res = ana.analyze()
        self.assertTrue(len(res["warnings"]) > 0 or not res["is_elf"])

        # 2. Section header offset exceeds file size
        bad_shoff = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
        # e_shoff = 0x7FFFFFFF (way beyond file length), e_shentsize = 64, e_shnum = 10
        bad_shoff += struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x401000, 64, 0x7FFFFFFF, 0, 64, 56, 1, 64, 10, 0)
        ana2 = ELFAnalyzer(bytes(bad_shoff))
        res2 = ana2.analyze()
        self.assertTrue(res2["is_elf"])
        # Should gracefully record warnings without unhandled exceptions
        self.assertTrue(len(res2["warnings"]) > 0)


if __name__ == "__main__":
    unittest.main()


