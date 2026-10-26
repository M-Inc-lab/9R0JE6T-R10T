import os
import subprocess
import unittest
import reverse_forge


class TestPhase131To140RustOmegaWave4(unittest.TestCase):
    def test_wave4_open_source_rust_modules_present_and_complete(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        expected = {
            "rust_core/src/open_source_rizin_esil.rs": ["RzEsilVM", "eval_esil", "lift_and_exec_esil_x86_64"],
            "rust_core/src/open_source_angr_vex_claripy.rs": ["VexIRSB", "lift_x86_64_to_vex_irsb", "ClaripySolver"],
            "rust_core/src/open_source_yara_ahocorasick_capa.rs": ["YaraAhoCorasickAutomaton", "build_failure_links", "CapaStatement"],
            "rust_core/src/open_source_jadx_ilspy_ast.rs": ["JadxRegion", "decompile_dalvik_via_jadx_regions", "decompile_cil_via_ilspy_ast"],
        }
        for rel, symbols in expected.items():
            full = os.path.join(root, rel)
            self.assertTrue(os.path.isfile(full), f"Missing {rel}")
            with open(full, "r", encoding="utf-8") as f:
                src = f.read()
            self.assertGreater(len(src.splitlines()), 140)
            for sym in symbols:
                self.assertIn(sym, src)

    def test_standalone_native_binary_wave4_commands_and_version(self):
        self.assertIn(reverse_forge.__version__, ("20.0.0-rust-omega", "21.0.0-rust-apex", "22.0.0-rust-eternal", "23.0.0-rust-zenith", "24.0.0-rust-omni-complete", "25.0.0-rust-transcendent", "26.0.0-rust-bicentennial",))
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        bin_path = os.path.join(root, "rust_core", "bin", "reverse-forge-native")
        self.assertTrue(os.path.isfile(bin_path))

        doc = subprocess.check_output([bin_path, "doctor"], text=True)
        self.assertTrue(any(v in doc for v in ("20.0.0-rust-omega", "21.0.0-rust-apex", "22.0.0-rust-eternal", "23.0.0-rust-zenith", "24.0.0-rust-omni-complete", "25.0.0-rust-transcendent", "26.0.0-rust-bicentennial")))
        self.assertIn("\"phases\":", doc)
        self.assertIn("\"rust_modules\":", doc)

        for cmd, expected_engine in [
            ("esil", "open_source_rizin_esil"),
            ("vex-lift", "open_source_angr_vex_claripy"),
            ("yara-ac", "open_source_yara_ahocorasick_capa"),
            ("jadx-ilspy", "open_source_jadx_ilspy_ast"),
        ]:
            out = subprocess.check_output([bin_path, cmd], text=True)
            self.assertIn(expected_engine, out)


if __name__ == "__main__":
    unittest.main()
