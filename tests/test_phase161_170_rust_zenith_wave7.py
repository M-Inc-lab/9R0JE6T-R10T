import os
import subprocess
import unittest
import reverse_forge


class TestPhase161To170RustZenithWave7(unittest.TestCase):
    def test_wave7_open_source_rust_modules_present_and_complete(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        expected = {
            "rust_core/src/open_source_volatility3_memory.rs": ["Ia32eTranslation", "translate_ia32e_va", "scan_kernel_pool_tags_and_dkom"],
            "rust_core/src/open_source_pesieve_hollowshunter.rs": ["PeSievePatchKind", "scan_module_pesieve_integrity", "PeSieveScanReport"],
            "rust_core/src/open_source_triton_symcc_dse.rs": ["TritonDseEngine", "SymCcAstNode", "solve_symcc_branch_flip"],
            "rust_core/src/open_source_retdec_jumptable.rs": ["RecoveredSwitchTable", "recover_switch_jumptable", "to_c_switch_code"],
        }
        for rel, symbols in expected.items():
            full = os.path.join(root, rel)
            self.assertTrue(os.path.isfile(full), f"Missing {rel}")
            with open(full, "r", encoding="utf-8") as f:
                src = f.read()
            self.assertGreater(len(src.splitlines()), 80)
            for sym in symbols:
                self.assertIn(sym, src)

    def test_standalone_native_binary_wave7_commands_and_version(self):
        self.assertIn(reverse_forge.__version__, ("23.0.0-rust-zenith", "24.0.0-rust-omni-complete", "25.0.0-rust-transcendent", "26.0.0-rust-bicentennial",))
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        bin_path = os.path.join(root, "rust_core", "bin", "reverse-forge-native")
        self.assertTrue(os.path.isfile(bin_path))

        doc = subprocess.check_output([bin_path, "doctor"], text=True)
        self.assertTrue(any(v in doc for v in ("23.0.0-rust-zenith", "24.0.0-rust-omni-complete", "25.0.0-rust-transcendent", "26.0.0-rust-bicentennial")))
        self.assertIn("\"phases\":", doc)
        self.assertIn("\"rust_modules\":", doc)

        for cmd, expected_engine in [
            ("volatility3", "open_source_volatility3_memory"),
            ("pesieve", "open_source_pesieve_hollowshunter"),
            ("triton-dse", "open_source_triton_symcc_dse"),
            ("retdec-switch", "open_source_retdec_jumptable"),
        ]:
            out = subprocess.check_output([bin_path, cmd], text=True)
            self.assertIn(expected_engine, out)


if __name__ == "__main__":
    unittest.main()
