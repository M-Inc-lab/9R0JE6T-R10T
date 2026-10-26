"""
Unit tests for Phases 36–40 (v5.0-omega Frontier Expansion):
  - Phase 36: Mixed Boolean-Arithmetic (MBA) Truth-Table Deobfuscator, Opaque Predicates & OLLVM Unflattener
  - Phase 37: C++ RTTI, VTable & Class Hierarchy Reconstructor (Itanium ABI & MSVC ABI)
  - Phase 38: Bare-Metal Firmware Base-Address & RTOS Scanner (Pointer-String & Cortex-M Vector Table)
  - Phase 39: DWARF / .eh_frame Call Frame Information (CIE/FDE) Stripped Function Boundary Parser
  - Phase 40: Differential Execution Trace & Crash Root-Cause Aligner + CLI Integration
"""

import json
import os
import struct
import subprocess
import sys
import unittest

from reverse_forge.decompiler_engine import BasicBlock
from reverse_forge.deobfuscation_engine import DeobfuscationEngine
from reverse_forge.cpp_rtti_engine import CppRTTIEngine
from reverse_forge.firmware_base_engine import FirmwareBaseEngine
from reverse_forge.unwind_frame_engine import UnwindFrameEngine
from reverse_forge.trace_diff_engine import TraceDiffEngine, TraceStep


class TestPhase36MBADeobfuscationAndOLLVM(unittest.TestCase):
    def test_mba_truth_table_simplification(self):
        """Verify linear MBA expressions simplify to exact canonical arithmetic/bitwise forms."""
        eng = DeobfuscationEngine()
        r1 = eng.simplify_mba_expression("(x ^ y) + 2 * (x & y)")
        self.assertTrue(r1.is_simplified)
        self.assertTrue(r1.equivalence_verified)
        self.assertEqual(r1.simplified_expr, "x + y")

        r2 = eng.simplify_mba_expression("(a | b) - (a & b)")
        self.assertTrue(r2.is_simplified)
        self.assertEqual(r2.simplified_expr, "a ^ b")

    def test_opaque_predicate_detection(self):
        """Verify invariant number-theoretic opaque predicates are classified as ALWAYS_TRUE / ALWAYS_FALSE."""
        eng = DeobfuscationEngine()
        op_true = eng.detect_opaque_predicate("(x * (x + 1)) % 2 == 0")
        self.assertEqual(op_true.classification, "ALWAYS_TRUE")

        op_false = eng.detect_opaque_predicate("(x * (x + 1)) % 2 == 1")
        self.assertEqual(op_false.classification, "ALWAYS_FALSE")

    def test_ollvm_control_flow_unflattening(self):
        """Verify OLLVM state-machine dispatcher loop is bypassed and worker blocks connect directly."""
        b_entry = BasicBlock(
            start_addr=0x1000,
            end_addr=0x1008,
            instructions=[(0x1000, "mov", "ecx, 0xAA01"), (0x1004, "jmp", "0x2000")],
            successors=[0x2000],
            predecessors=[],
        )
        b_disp = BasicBlock(
            start_addr=0x2000,
            end_addr=0x2010,
            instructions=[
                (0x2000, "cmp", "ecx, 0xAA01"),
                (0x2004, "je", "0x3000"),
                (0x2008, "cmp", "ecx, 0xAA02"),
                (0x200C, "je", "0x4000"),
            ],
            successors=[0x3000, 0x4000],
            predecessors=[0x1000, 0x3000],
        )
        b_worker1 = BasicBlock(
            start_addr=0x3000,
            end_addr=0x3008,
            instructions=[(0x3000, "add", "eax, 1"), (0x3004, "mov", "ecx, 0xAA02")],
            successors=[0x2000],
            predecessors=[0x2000],
        )
        b_worker2 = BasicBlock(
            start_addr=0x4000,
            end_addr=0x4004,
            instructions=[(0x4000, "ret", "")],
            successors=[],
            predecessors=[0x2000],
        )
        rep = DeobfuscationEngine().unflatten_ollvm_cfg(
            {0x1000: b_entry, 0x2000: b_disp, 0x3000: b_worker1, 0x4000: b_worker2},
            state_reg="ecx",
        )
        self.assertEqual(rep.dispatcher_block, 0x2000)
        self.assertIn((0x1000, 0x3000), rep.recovered_transitions)
        self.assertIn((0x3000, 0x4000), rep.recovered_transitions)
        self.assertEqual(rep.blocks[0x1000].successors, [0x3000])
        self.assertEqual(rep.blocks[0x3000].successors, [0x4000])


class TestPhase37CppRTTIAndVTableReconstructor(unittest.TestCase):
    def test_itanium_and_msvc_rtti_reconstruction(self):
        """Verify Itanium ABI symbols and MSVC .?AV descriptors reconstruct C++ classes and vtables."""
        rtti = CppRTTIEngine()
        self.assertEqual(
            rtti.demangle_itanium_symbol("_ZN3Sec12CipherEngine7decryptEPKci"),
            "Sec::CipherEngine::decrypt(const char *, int)",
        )
        blob = b"\x00_ZTV12CipherEngine\x00.?AVPacketFilter@NetCore@@\x00"
        rep = rtti.analyze_binary_rtti(
            blob,
            symbol_list=["_ZN12CipherEngine7decryptEPKci"],
            inheritance_hints={"CipherEngine": ["BaseCrypto"]},
        )
        self.assertGreaterEqual(rep.total_classes_recovered, 2)
        self.assertGreaterEqual(rep.itanium_classes, 1)
        self.assertGreaterEqual(rep.msvc_classes, 1)
        cls_names = {c.class_name for c in rep.classes}
        self.assertIn("CipherEngine", cls_names)
        self.assertIn("PacketFilter", cls_names)
        cipher_cls = [c for c in rep.classes if c.class_name == "CipherEngine"][0]
        self.assertIn("CipherEngine_vtable_t", cipher_cls.c_struct_definition)
        self.assertIn("BaseCrypto", cipher_cls.c_struct_definition)


class TestPhase38FirmwareBaseAddressEngine(unittest.TestCase):
    def test_cortex_m_firmware_base_and_rtos_detection(self):
        """Verify bare-metal STM32/Cortex-M firmware blob base address 0x08000000 is inferred."""
        # Build synthetic 256-byte STM32 firmware image loaded at 0x08000000
        # Offset 0x00: Initial SP = 0x20004000, Reset_Handler = 0x08000041 (Thumb bit set)
        # Offset 0x80: String "FreeRTOS v10.4\x00"
        # Offset 0xA0: Pointer table referencing 0x08000080 and 0x08000090
        buf = bytearray(256)
        struct.pack_into("<II", buf, 0x00, 0x20004000, 0x08000041)
        s1 = b"FreeRTOS v10.4\x00"
        s2 = b"UART_INIT_OK\x00"
        buf[0x80:0x80 + len(s1)] = s1
        buf[0x90:0x90 + len(s2)] = s2
        struct.pack_into("<II", buf, 0xC0, 0x08000080, 0x08000090)

        rep = FirmwareBaseEngine().scan_firmware_base(bytes(buf))
        self.assertEqual(rep.best_base_address, 0x08000000)
        self.assertIn("FreeRTOS", rep.detected_rtos_signatures)
        self.assertGreaterEqual(rep.top_candidates[0].pointer_string_matches, 2)


class TestPhase39UnwindFrameEngine(unittest.TestCase):
    def test_parse_eh_frame_cie_and_fde_records(self):
        """Verify .eh_frame CIE and FDE records recover stripped function start, range, and CFA stack size."""
        # Construct valid CIE (length=12, cie_id=0) + FDE (length=20, cie_ptr=20, init_loc=0x401100, range=0x48, DW_CFA_def_cfa_offset 64)
        cie_body = struct.pack("<I", 0) + b"\x01\x00\x01\x78\x10\x0c\x07\x08"
        cie_record = struct.pack("<I", len(cie_body)) + cie_body

        # FDE: cie_id != 0, initial_location = 0x401100, address_range = 0x48, instructions: 0x0E (DW_CFA_def_cfa_offset) + ULEB128(64)=0x40
        fde_body = struct.pack("<IiI", 16, 0x401100, 0x48) + b"\x00\x0e\x40\x00"
        fde_record = struct.pack("<I", len(fde_body)) + fde_body

        eh_bytes = cie_record + fde_record + struct.pack("<I", 0)
        rep = UnwindFrameEngine().parse_eh_frame_bytes(eh_bytes, section_vaddr=0x402000)
        self.assertEqual(rep.cie_count, 1)
        self.assertEqual(rep.fde_count, 1)
        fn = rep.recovered_functions[0]
        self.assertEqual(fn.initial_location, 0x401100)
        self.assertEqual(fn.address_range, 0x48)
        self.assertEqual(fn.end_location, 0x401148)
        self.assertEqual(fn.stack_frame_size, 64)


class TestPhase40TraceDiffEngineAndOmegaCLI(unittest.TestCase):
    def test_differential_trace_alignment_and_divergence_root_cause(self):
        """Verify TraceDiffEngine isolates the exact divergence instruction and register delta."""
        base_trace = [
            TraceStep(0x401000, "mov rdi, rax", {"rdi": 16}),
            TraceStep(0x401004, "cmp rdi, 256", {"rdi": 16, "zf": 0}),
            TraceStep(0x401008, "jbe 0x401020", {"rdi": 16}),
            TraceStep(0x401020, "call safe_copy", {"rdi": 16}),
        ]
        crash_trace = [
            TraceStep(0x401000, "mov rdi, rax", {"rdi": 1024}),
            TraceStep(0x401004, "cmp rdi, 256", {"rdi": 1024, "zf": 0}),
            TraceStep(0x401008, "jbe 0x401020", {"rdi": 1024}),
            TraceStep(0x40100C, "call unchecked_overflow_path", {"rdi": 1024}),
        ]
        rep = TraceDiffEngine().align_and_diff_traces(base_trace, crash_trace)
        self.assertEqual(rep.shared_prefix_length, 3)
        self.assertEqual(rep.divergence_point_address, 0x401008)
        self.assertEqual(rep.baseline_next_address, 0x401020)
        self.assertEqual(rep.divergent_next_address, 0x40100C)
        self.assertEqual(rep.register_deltas_at_divergence["rdi"], (16, 1024))
        self.assertEqual(rep.unique_divergent_addresses, [0x40100C])

    def test_phase36_to_40_cli_commands_and_doctor_40_phases(self):
        """Verify cli.py doctor reports 40 phases / 43 engines and new v5.0 CLI commands work."""
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        doc = subprocess.run(
            [sys.executable, "-m", "reverse_forge.cli", "doctor"],
            cwd=repo_root,
            capture_output=True, text=True, check=True,
        )
        doc_json = json.loads(doc.stdout)
        self.assertTrue(doc_json["version"] in ("5.0.0-omega", "6.0.0-quantum", "7.0.0-singularity", "8.0.0-omniscient", "9.0.0-sovereign", "10.0.0-zenith", "11.0.0-eternal", "12.0.0-apex-omni", "13.0.0-vanguard", "14.0.0-transcendent", "15.0.0-rust-titan", "16.0.0-omni-rust", "17.0.0-rust-dominion", "18.0.0-rust-sovereign", "19.0.0-rust-singularity", "20.0.0-rust-omega", "21.0.0-rust-apex", "22.0.0-rust-eternal", "23.0.0-rust-zenith", "24.0.0-rust-omni-complete", "25.0.0-rust-transcendent", "26.0.0-rust-bicentennial"))
        self.assertGreaterEqual(doc_json["phases_implemented"], 40)
        self.assertGreaterEqual(doc_json["internal_engines_count"], 43)

        mba_run = subprocess.run(
            [sys.executable, "-m", "reverse_forge.cli", "deobfuscate-mba", "--expr", "(x ^ y) + 2 * (x & y)"],
            cwd=repo_root,
            capture_output=True, text=True, check=True,
        )
        self.assertIn("x + y", mba_run.stdout)

        td_run = subprocess.run(
            [
                sys.executable, "-m", "reverse_forge.cli", "trace-diff",
                "--base-addrs", "0x401000,0x401004,0x401020",
                "--div-addrs", "0x401000,0x401004,0x401099",
            ],
            cwd=repo_root,
            capture_output=True, text=True, check=True,
        )
        self.assertIn("divergence_point_address", td_run.stdout)


if __name__ == "__main__":
    unittest.main()
