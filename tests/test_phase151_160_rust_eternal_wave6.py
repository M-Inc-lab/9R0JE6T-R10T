import os
import subprocess
import unittest
import reverse_forge


class TestPhase151To160RustEternalWave6(unittest.TestCase):
    def test_wave6_open_source_rust_modules_present_and_complete(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        expected = {
            "rust_core/src/open_source_frida_stalker_gum.rs": ["StalkerInstrumentedBlock", "relocate_x86_64_insn", "compile_stalker_basic_block", "build_gum_inline_trampoline"],
            "rust_core/src/open_source_wabt_binaryen_wasm.rs": ["read_uleb128", "read_sleb128", "decompile_wasm_via_wabt_binaryen"],
            "rust_core/src/open_source_lief_binary_builder.rs": ["LiefSectionSpec", "rebuild_binary_with_lief_section", "build_lief_import_table_bytes"],
            "rust_core/src/open_source_cfr_fernflower_jvm.rs": ["JvmExceptionRange", "decompile_jvm_via_cfr_fernflower", "lambda$bootstrap_"],
        }
        for rel, symbols in expected.items():
            full = os.path.join(root, rel)
            self.assertTrue(os.path.isfile(full), f"Missing {rel}")
            with open(full, "r", encoding="utf-8") as f:
                src = f.read()
            self.assertGreater(len(src.splitlines()), 110)
            for sym in symbols:
                self.assertIn(sym, src)

    def test_standalone_native_binary_wave6_commands_and_version(self):
        self.assertIn(reverse_forge.__version__, ("22.0.0-rust-eternal", "23.0.0-rust-zenith", "24.0.0-rust-omni-complete", "25.0.0-rust-transcendent", "26.0.0-rust-bicentennial",))
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        bin_path = os.path.join(root, "rust_core", "bin", "reverse-forge-native")
        self.assertTrue(os.path.isfile(bin_path))

        doc = subprocess.check_output([bin_path, "doctor"], text=True)
        self.assertTrue(any(v in doc for v in ("22.0.0-rust-eternal", "23.0.0-rust-zenith", "24.0.0-rust-omni-complete", "25.0.0-rust-transcendent", "26.0.0-rust-bicentennial")))
        self.assertIn("\"phases\":", doc)
        self.assertIn("\"rust_modules\":", doc)

        for cmd, expected_engine in [
            ("frida-stalker", "open_source_frida_stalker_gum"),
            ("wabt-wasm", "open_source_wabt_binaryen_wasm"),
            ("lief-builder", "open_source_lief_binary_builder"),
            ("cfr-jvm", "open_source_cfr_fernflower_jvm"),
        ]:
            out = subprocess.check_output([bin_path, cmd], text=True)
            self.assertIn(expected_engine, out)


if __name__ == "__main__":
    unittest.main()
