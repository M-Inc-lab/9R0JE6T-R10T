"""
Tests for Phase 17 & 18: Native Micro-Decompiler and Pointer Alias Engine.
"""

import unittest

from reverse_forge.decompiler_engine import BasicBlock, MicroDecompilerEngine
from reverse_forge.pointer_alias_engine import PointerAliasEngine


class TestPhase17MicroDecompiler(unittest.TestCase):
    def setUp(self):
        self.decompiler = MicroDecompilerEngine()

    def test_cfg_construction_with_conditional_branch(self):
        # Synthetic assembly instructions:
        # 0x1000: mov eax, 1
        # 0x1005: cmp eax, 0
        # 0x1008: jne 0x1015
        # 0x100A: mov edx, 0
        # 0x100F: jmp 0x1020
        # 0x1015: mov edx, 1
        # 0x1020: ret
        insns = [
            (0x1000, "mov", "eax, 1"),
            (0x1005, "cmp", "eax, 0"),
            (0x1008, "jne", "0x1015"),
            (0x100A, "mov", "edx, 0"),
            (0x100F, "jmp", "0x1020"),
            (0x1015, "mov", "edx, 1"),
            (0x1020, "ret", ""),
        ]
        blocks = self.decompiler.build_cfg(insns)
        self.assertGreaterEqual(len(blocks), 3)
        self.assertIn(0x1000, blocks)
        self.assertIn(0x1015, blocks)
        self.assertIn(0x1020, blocks)

        # Decompile to C
        decomp = self.decompiler.decompile_cfg_to_c("test_func", 0x1000, blocks)
        self.assertIn("int test_func", decomp.c_source)
        self.assertIn("return result;", decomp.c_source)
        self.assertIn("var_eax", decomp.local_variables)

    def test_decompile_raw_bytes_fallback(self):
        # Benign x86 prologue & epilogue
        raw = b"\x55\x89\xe5\x31\xc0\x5d\xc3"
        decomp = self.decompiler.decompile_raw_bytes(raw, base_addr=0x401000)
        self.assertIn("int sub_401000", decomp.c_source)
        self.assertGreaterEqual(decomp.total_blocks, 1)


class TestPhase18PointerAliasEngine(unittest.TestCase):
    def setUp(self):
        self.engine = PointerAliasEngine()

    def test_use_after_free_detection(self):
        self.engine.record_allocation("p1", "0x401000", size_expr="128")
        self.engine.record_alias("p2", "p1")
        self.engine.record_free("p1", "0x401050")
        self.engine.record_dereference("p2", "0x401080", is_write=True)

        self.assertEqual(len(self.engine.defects), 1)
        defect = self.engine.defects[0]
        self.assertEqual(defect.defect_type, "USE_AFTER_FREE")
        self.assertEqual(defect.cwe, "CWE-416")
        self.assertEqual(defect.pointer_var, "p2")
        self.assertEqual(defect.alloc_site, "0x401000")

    def test_double_free_detection(self):
        self.engine.record_allocation("ptr_a", "0x402000", size_expr="64")
        self.engine.record_free("ptr_a", "0x402020")
        self.engine.record_free("ptr_a", "0x402040")

        self.assertEqual(len(self.engine.defects), 1)
        defect = self.engine.defects[0]
        self.assertEqual(defect.defect_type, "DOUBLE_FREE")
        self.assertEqual(defect.cwe, "CWE-415")


if __name__ == "__main__":
    unittest.main()
