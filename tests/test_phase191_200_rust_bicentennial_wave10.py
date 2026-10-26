import os
import subprocess
import unittest
import reverse_forge


class TestPhase191To200RustBicentennialWave10(unittest.TestCase):
    def test_wave10_open_source_rust_modules_present_and_complete(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        expected = {
            "rust_core/src/open_source_die_packer_detector.rs": ["DieDetectionHit", "compare_die_ep_signature", "scan_die_compiler_packer_signatures"],
            "rust_core/src/open_source_rr_panda_timetravel.rs": ["RrTimeTravelTimeline", "reverse_stepi", "find_last_memory_writer"],
            "rust_core/src/open_source_qbdi_dynamorio_trace.rs": ["DrcovBasicBlockEntry", "QbdiShadowFrame", "run_qbdi_drcov_shadow_trace"],
            "rust_core/src/open_source_master_orchestrator.rs": ["OmniMasterAuditDossier", "run_omni_rust_master_audit", "to_json"],
        }
        for rel, symbols in expected.items():
            full = os.path.join(root, rel)
            self.assertTrue(os.path.isfile(full), f"Missing {rel}")
            with open(full, "r", encoding="utf-8") as f:
                src = f.read()
            self.assertGreater(len(src.splitlines()), 70)
            for sym in symbols:
                self.assertIn(sym, src)

    def test_standalone_native_binary_wave10_commands_and_version(self):
        self.assertIn(reverse_forge.__version__, ("26.0.0-rust-bicentennial",))
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        bin_path = os.path.join(root, "rust_core", "bin", "reverse-forge-native")
        self.assertTrue(os.path.isfile(bin_path))

        doc = subprocess.check_output([bin_path, "doctor"], text=True)
        self.assertIn("26.0.0-rust-bicentennial", doc)
        self.assertIn("\"phases\": 200", doc)
        self.assertIn("\"rust_modules\": 55", doc)

        for cmd, expected_engine in [
            ("die-scan", "open_source_die_packer_detector"),
            ("rr-timetravel", "open_source_rr_panda_timetravel"),
            ("qbdi-drcov", "open_source_qbdi_dynamorio_trace"),
            ("omni-audit", "open_source_master_orchestrator"),
        ]:
            out = subprocess.check_output([bin_path, cmd], text=True)
            self.assertIn(expected_engine, out)


if __name__ == "__main__":
    unittest.main()
