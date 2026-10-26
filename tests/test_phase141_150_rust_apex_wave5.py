import os
import subprocess
import unittest
import reverse_forge


class TestPhase141To150RustApexWave5(unittest.TestCase):
    def test_wave5_open_source_rust_modules_present_and_complete(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        expected = {
            "rust_core/src/open_source_unicorn_softmmu.rs": ["UnicornSoftMmu", "SoftMmuTlbEntry", "context_save", "context_restore"],
            "rust_core/src/open_source_ghidra_typefactory.rs": ["InferredCStruct", "synthesize_c_structs_from_pcode", "to_c_declaration"],
            "rust_core/src/open_source_diaphora_bindiff_wl.rs": ["WlCfgGraph", "compute_wl_subtree_histogram", "compute_machoc_hash", "compare_functions_wl_bindiff"],
            "rust_core/src/open_source_galileo_cfi_gadget_auditor.rs": ["GalileoTrieNode", "audit_binary_cfi_galileo_trie", "GalileoCfiAuditReport"],
        }
        for rel, symbols in expected.items():
            full = os.path.join(root, rel)
            self.assertTrue(os.path.isfile(full), f"Missing {rel}")
            with open(full, "r", encoding="utf-8") as f:
                src = f.read()
            self.assertGreater(len(src.splitlines()), 100)
            for sym in symbols:
                self.assertIn(sym, src)

    def test_standalone_native_binary_wave5_commands_and_version(self):
        self.assertIn(reverse_forge.__version__, ("21.0.0-rust-apex", "22.0.0-rust-eternal", "23.0.0-rust-zenith", "24.0.0-rust-omni-complete", "25.0.0-rust-transcendent", "26.0.0-rust-bicentennial",))
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        bin_path = os.path.join(root, "rust_core", "bin", "reverse-forge-native")
        self.assertTrue(os.path.isfile(bin_path))

        doc = subprocess.check_output([bin_path, "doctor"], text=True)
        self.assertTrue(any(v in doc for v in ("21.0.0-rust-apex", "22.0.0-rust-eternal", "23.0.0-rust-zenith", "24.0.0-rust-omni-complete", "25.0.0-rust-transcendent", "26.0.0-rust-bicentennial")))
        self.assertIn("\"phases\":", doc)
        self.assertIn("\"rust_modules\":", doc)

        for cmd, expected_engine in [
            ("softmmu", "open_source_unicorn_softmmu"),
            ("typefactory", "open_source_ghidra_typefactory"),
            ("wl-bindiff", "open_source_diaphora_bindiff_wl"),
            ("galileo-cfi", "open_source_galileo_cfi_gadget_auditor"),
        ]:
            out = subprocess.check_output([bin_path, cmd], text=True)
            self.assertIn(expected_engine, out)


if __name__ == "__main__":
    unittest.main()
