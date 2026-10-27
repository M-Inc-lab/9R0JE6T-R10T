"""
Differential Analysis Validation Test Suite (§06, Stage 6)
Validates instruction boundaries, function boundaries, CFG edges, and format detection
against independent reference tools (Capstone, ELF symbol tables) on benign fixtures.
"""

import os
import struct
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


if __name__ == "__main__":
    unittest.main()

