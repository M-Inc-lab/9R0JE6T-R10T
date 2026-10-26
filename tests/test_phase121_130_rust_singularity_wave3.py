import os
import subprocess
import unittest
import reverse_forge


class TestPhase121To130RustSingularityWave3(unittest.TestCase):
    def test_wave3_rust_modules_and_open_source_sleigh_zydis_present(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        expected = [
            "rust_core/src/web_studio_server.rs",
            "rust_core/src/repl_canvas_corpus_gdb.rs",
            "rust_core/src/open_source_sleigh_zydis_capstone.rs",
        ]
        for rel in expected:
            full = os.path.join(root, rel)
            self.assertTrue(os.path.isfile(full), f"Missing {rel}")
            with open(full, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertGreater(len(content.splitlines()), 180)

        with open(os.path.join(root, "rust_core/src/open_source_sleigh_zydis_capstone.rs"), "r", encoding="utf-8") as f:
            sleigh_src = f.read()
        self.assertIn("sleigh_lift_arm64", sleigh_src)
        self.assertIn("sleigh_lift_riscv_mixed", sleigh_src)
        self.assertIn("zydis_decode_x86_64", sleigh_src)
        self.assertIn("assemble_multi_arch_rust", sleigh_src)

    def test_standalone_native_binary_wave3_commands_and_version(self):
        self.assertIn(reverse_forge.__version__, ("19.0.0-rust-singularity", "20.0.0-rust-omega", "21.0.0-rust-apex", "22.0.0-rust-eternal", "23.0.0-rust-zenith", "24.0.0-rust-omni-complete", "25.0.0-rust-transcendent", "26.0.0-rust-bicentennial",))
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        bin_path = os.path.join(root, "rust_core", "bin", "reverse-forge-native")
        self.assertTrue(os.path.isfile(bin_path))

        doc = subprocess.check_output([bin_path, "doctor"], text=True)
        self.assertTrue(any(v in doc for v in ("19.0.0-rust-singularity", "20.0.0-rust-omega", "21.0.0-rust-apex", "22.0.0-rust-eternal", "23.0.0-rust-zenith", "24.0.0-rust-omni-complete", "25.0.0-rust-transcendent", "26.0.0-rust-bicentennial")))
        self.assertIn("\"phases\":", doc)

        sleigh_out = subprocess.check_output([bin_path, "sleigh-lift"], text=True)
        self.assertIn("open_source_sleigh_zydis_capstone", sleigh_out)

        simhash_out = subprocess.check_output([bin_path, "simhash"], text=True)
        self.assertIn("rust_simhash_64", simhash_out)


if __name__ == "__main__":
    unittest.main()
