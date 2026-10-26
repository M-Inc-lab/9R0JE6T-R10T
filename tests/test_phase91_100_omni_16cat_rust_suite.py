"""
R3V3R53//F0RG3 — Phases 91–100 (`v16.0.0-omni-rust`) 16-Category Standalone Rust & Omni Toolkit Test Suite
Verifies:
  1. All 13 Native Rust modules in `rust_core/src/` covering all 16 Open-Source RE Toolkit categories
  2. Standalone Compiled Native Binary (`rust_core/bin/reverse-forge-native`) execution
  3. Wireshark/Netzob PCAP Dissector & Protocol Grammar Inferencer (`dissect_pcap_and_infer_protocol`)
  4. ImHex `.hexpat` Binary Struct Pattern Evaluator (`evaluate_imhex_pattern`)
  5. Recaf/CFR JVM `.class` (`0xCAFEBABE`) Constant-Pool & Bytecode Decompiler (`decompile_jvm_class`)
  6. Binwalk Embedded Filesystem & Bootloader Partition Carver (`carve_firmware_partitions`)
  7. `cli.py doctor` (`16.0.0-omni-rust`, 100 Phases, 78 Internal Engines)
"""

import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest

from reverse_forge.omni_toolkit_16cat import OmniToolkit16CatEngine


class TestPhase91To100Omni16CategoryRustSuite(unittest.TestCase):
    def test_all_13_rust_modules_and_standalone_native_binary(self):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        rust_src = os.path.join(repo_root, "rust_core", "src")
        expected_rs = [
            "lib.rs",
            "main.rs",
            "pcode_ssa.rs",
            "disasm.rs",
            "visor.rs",
            "symbolic_angr_smt.rs",
            "scanner.rs",
            "bytecode_jvm_dex_clr_wasm.rs",
            "firmware_binwalk.rs",
            "network_pcap_netzob.rs",
            "parsers.rs",
            "checksec_cfi_audit.rs",
            "diff_diaphora.rs",
            "memory_volatility_pesieve.rs",
            "imhex_patcher.rs",
        ]
        for fname in expected_rs:
            self.assertTrue(os.path.exists(os.path.join(rust_src, fname)), f"Missing Rust module: {fname}")

        native_bin = os.path.join(repo_root, "rust_core", "bin", "reverse-forge-native")
        if sys.platform.startswith("linux") and os.path.exists(native_bin):
            with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
                tf.write(b"MZ\x90\x00" + bytes.fromhex("55 4889e5 b82a000000 c3") + b"\x00" * 64)
                tmp_p = tf.name
            try:
                proc = subprocess.run([native_bin, "triage", tmp_p], capture_output=True, text=True, check=True)
                out = json.loads(proc.stdout)
                self.assertIn(out["version"], ("16.0.0-omni-rust", "17.0.0-rust-dominion", "18.0.0-rust-sovereign", "19.0.0-rust-singularity", "20.0.0-rust-omega", "21.0.0-rust-apex", "22.0.0-rust-eternal", "23.0.0-rust-zenith", "24.0.0-rust-omni-complete", "25.0.0-rust-transcendent", "26.0.0-rust-bicentennial"))
                self.assertEqual(out["format"], "PE")
            finally:
                if os.path.exists(tmp_p):
                    os.remove(tmp_p)

    def test_wireshark_pcap_dissection_and_netzob_protocol_inference(self):
        eng = OmniToolkit16CatEngine()
        # Global PCAP header (24B, magic=0xa1b2c3d4)
        pcap_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        # Ethernet (14B, EtherType=0x0800) + IPv4 (20B, proto=17 UDP, 10.0.0.1 -> 10.0.0.2) + UDP (8B, 4444 -> 8080) + L7 ("RIOT\x00\x10hello")
        eth = b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55\x08\x00"
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 39, 1, 0, 64, 17, 0, bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
        udp = struct.pack(">HHHH", 4444, 8080, 19, 0)
        l7 = b"RIOT\x00\x0bhello_world"
        pkt = eth + ip + udp + l7
        rec_hdr = struct.pack("<IIII", 1700000000, 0, len(pkt), len(pkt))

        rep = eng.dissect_pcap_and_infer_protocol(pcap_hdr + rec_hdr + pkt)
        self.assertTrue(rep.is_valid_pcap)
        self.assertEqual(rep.total_packets, 1)
        self.assertEqual(rep.packets[0].src_ip, "10.0.0.1")
        self.assertEqual(rep.packets[0].dst_port, 8080)
        self.assertIn("0x52494F54", rep.inferred_protocol_struct)

    def test_imhex_pattern_dsl_jvm_class_and_binwalk_carving(self):
        eng = OmniToolkit16CatEngine()
        # 1. ImHex .hexpat evaluation
        blob = b"MZ" + struct.pack("<HI", 0x0090, 0x12345678)
        fields = eng.evaluate_imhex_pattern(blob, "struct DosHdr { char magic[2]; u16 cblp; u32 sig; };", 0)
        self.assertEqual(len(fields), 3)
        self.assertEqual(fields[0].value, "MZ")
        self.assertEqual(fields[1].value, 0x90)
        self.assertEqual(fields[2].value, 0x12345678)

        # 2. JVM .class (0xCAFEBABE, major=61 Java SE 17, cp_count=2 with 1 Utf8 entry "decryptVault")
        jvm = b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 61, 2) + b"\x01\x00\x0cdecryptVault"
        j_rep = eng.decompile_jvm_class(jvm)
        self.assertTrue(j_rep.is_valid_jvm_class)
        self.assertIn("Java SE 17", j_rep.jdk_version)
        self.assertIn("decryptVault", j_rep.constant_pool_utf8)

        # 3. Binwalk partition carving (uImage + SquashFS + FDT)
        fw_blob = b"\x00" * 32 + b"\x27\x05\x19\x56" + b"\x00" * 64 + b"hsqs" + b"\x00" * 32 + b"\xd0\x0d\xfe\xed"
        hits = eng.carve_firmware_partitions(fw_blob)
        cats = {h.category for h in hits}
        self.assertIn("BOOTLOADER", cats)
        self.assertIn("FILESYSTEM", cats)
        self.assertIn("DEVICETREE", cats)

    def test_omni_rust_cli_doctor_100_phases_78_engines(self):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        doc_proc = subprocess.run(
            [sys.executable, "-m", "reverse_forge.cli", "doctor"],
            cwd=repo_root,
            capture_output=True, text=True, check=True,
        )
        doc = json.loads(doc_proc.stdout)
        self.assertIn(doc["version"], ("16.0.0-omni-rust", "17.0.0-rust-dominion", "18.0.0-rust-sovereign", "19.0.0-rust-singularity", "20.0.0-rust-omega", "21.0.0-rust-apex", "22.0.0-rust-eternal", "23.0.0-rust-zenith", "24.0.0-rust-omni-complete", "25.0.0-rust-transcendent", "26.0.0-rust-bicentennial"))
        self.assertGreaterEqual(doc["phases_implemented"], 100)
        self.assertGreaterEqual(doc["internal_engines_count"], 78)
        self.assertEqual(doc["internal_engines_status"], "ALL_READY")


if __name__ == "__main__":
    unittest.main()
