import os
import subprocess
import unittest
import reverse_forge


class TestPhase171To180RustOmniCompleteWave8(unittest.TestCase):
    def test_wave8_open_source_rust_modules_present_and_complete(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        expected = {
            "rust_core/src/open_source_wireshark_zeek_netzob.rs": ["NetzobFieldKind", "align_protocol_messages_nw", "dissect_l7_packet_rust"],
            "rust_core/src/open_source_binwalk_fdt_firmware.rs": ["parse_fdt_dtb_header", "extract_cpio_newc_entries", "parse_squashfs_superblock"],
            "rust_core/src/open_source_imhex_pattern_lang.rs": ["ImHexEvaluatedField", "evaluate_imhex_pattern_script"],
            "rust_core/src/open_source_pwndbg_heap_x64dbg.rs": ["PtmallocChunk", "demangle_safe_link", "audit_tcache_fastbin_list", "encode_x64_dr7_watchpoint"],
        }
        for rel, symbols in expected.items():
            full = os.path.join(root, rel)
            self.assertTrue(os.path.isfile(full), f"Missing {rel}")
            with open(full, "r", encoding="utf-8") as f:
                src = f.read()
            self.assertGreater(len(src.splitlines()), 95)
            for sym in symbols:
                self.assertIn(sym, src)

    def test_standalone_native_binary_wave8_commands_and_version(self):
        self.assertIn(reverse_forge.__version__, ("24.0.0-rust-omni-complete", "25.0.0-rust-transcendent", "26.0.0-rust-bicentennial",))
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        bin_path = os.path.join(root, "rust_core", "bin", "reverse-forge-native")
        self.assertTrue(os.path.isfile(bin_path))

        doc = subprocess.check_output([bin_path, "doctor"], text=True)
        self.assertTrue(any(v in doc for v in ("24.0.0-rust-omni-complete", "25.0.0-rust-transcendent", "26.0.0-rust-bicentennial")))
        self.assertIn("\"phases\":", doc)
        self.assertIn("\"rust_modules\":", doc)

        for cmd, expected_engine in [
            ("netzob-l7", "open_source_wireshark_zeek_netzob"),
            ("fdt-cpio", "open_source_binwalk_fdt_firmware"),
            ("imhex-eval", "open_source_imhex_pattern_lang"),
            ("pwndbg-heap", "open_source_pwndbg_heap_x64dbg"),
        ]:
            out = subprocess.check_output([bin_path, cmd], text=True)
            self.assertIn(expected_engine, out)


if __name__ == "__main__":
    unittest.main()
