import os
import subprocess
import unittest
import reverse_forge


class TestPhase181To190RustTranscendentWave9(unittest.TestCase):
    def test_wave9_open_source_rust_modules_present_and_complete(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        expected = {
            "rust_core/src/open_source_apktool_androguard_axml.rs": ["DecodedAxmlManifest", "decode_android_axml_manifest", "RES_XML_TYPE"],
            "rust_core/src/open_source_de4dot_asmresolver_dotnet.rs": ["DecryptedDotNetString", "decrypt_dotnet_us_stream_strings", "inline_de4dot_proxy_calls"],
            "rust_core/src/open_source_dwarf5_pdb_type_tree.rs": ["DwarfCompilationUnitHeader", "parse_dwarf_cu_header", "decode_dwarf_die_stream"],
            "rust_core/src/open_source_bsdiff_xdelta_patch.rs": ["BsdiffPatchContainer", "bsdiff_compute_delta", "bspatch_apply_delta"],
        }
        for rel, symbols in expected.items():
            full = os.path.join(root, rel)
            self.assertTrue(os.path.isfile(full), f"Missing {rel}")
            with open(full, "r", encoding="utf-8") as f:
                src = f.read()
            self.assertGreater(len(src.splitlines()), 80)
            for sym in symbols:
                self.assertIn(sym, src)

    def test_standalone_native_binary_wave9_commands_and_version(self):
        self.assertIn(reverse_forge.__version__, ("25.0.0-rust-transcendent", "26.0.0-rust-bicentennial",))
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        bin_path = os.path.join(root, "rust_core", "bin", "reverse-forge-native")
        self.assertTrue(os.path.isfile(bin_path))

        doc = subprocess.check_output([bin_path, "doctor"], text=True)
        self.assertTrue(any(v in doc for v in ("25.0.0-rust-transcendent", "26.0.0-rust-bicentennial")))
        self.assertIn("\"phases\":", doc)
        self.assertIn("\"rust_modules\":", doc)

        for cmd, expected_engine in [
            ("axml-decode", "open_source_apktool_androguard_axml"),
            ("de4dot-net", "open_source_de4dot_asmresolver_dotnet"),
            ("dwarf5-die", "open_source_dwarf5_pdb_type_tree"),
            ("bsdiff-delta", "open_source_bsdiff_xdelta_patch"),
        ]:
            out = subprocess.check_output([bin_path, cmd], text=True)
            self.assertIn(expected_engine, out)


if __name__ == "__main__":
    unittest.main()
