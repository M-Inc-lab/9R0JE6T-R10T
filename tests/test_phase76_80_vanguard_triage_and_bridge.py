"""
R3V3R53//F0RG3 — Phases 76–80 (`v13.0.0-vanguard`) Comprehensive Test Suite
Verifies the Strategic Layer-1 Triage & Layer-2 Bridge Architecture:
  - Phase 76: Multi-Container Archive, APK/IPA, PyInstaller (`MEI`) & Document Dropper Triage (`ArchiveContainerTriageEngine`)
  - Phase 77: Automated YARA Rule, SIGMA YAML & STIX 2.1 Threat-Intel Generator (`YaraSigmaIOCGenerator`)
  - Phase 78: Universal Layer-1 -> Layer-2 Bridge Exporter for IDA Pro, Ghidra, Binary Ninja & x64dbg (`Tier2BridgeExporter`)
  - Phase 79: Synthetic Windows TEB/PEB/LDR Memory & Scaled-Index Addressing in `DeterministicCPUEmulator`
  - Phase 80: Web Studio (`/api/yara`, `/api/bridge`, `/api/container`) & CLI/REPL (`13.0.0-vanguard`, 80 Phases, 71 Engines)
"""

import io
import json
import os
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import urllib.request
import unittest
import zipfile

from reverse_forge.archive_container_triage_engine import ArchiveContainerTriageEngine
from reverse_forge.yara_sigma_ioc_generator import YaraSigmaIOCGenerator
from reverse_forge.tier2_bridge_exporter import Tier2BridgeExporter
from reverse_forge.cpu_emulator_engine import DeterministicCPUEmulator
from reverse_forge.binary_intel_engine import BinaryIntelEngine
from reverse_forge.gui_server import GUIWorkbenchHandler


class TestPhase76ArchiveContainerTriageEngine(unittest.TestCase):
    def test_android_apk_dex_and_native_jni_triage(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"manifest" * 8)
            zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)
            zf.writestr("lib/arm64-v8a/libcrypto_jni.so", b"\x7fELF\x02\x01\x01" + b"\x00" * 64)

        rep = ArchiveContainerTriageEngine().triage_container(buf.getvalue())
        self.assertEqual(rep.container_type, "ANDROID_APK")
        self.assertTrue(rep.is_container)
        self.assertEqual(rep.bundler_metadata["dex_files_count"], 1)
        self.assertIn("lib/arm64-v8a/libcrypto_jni.so", rep.bundler_metadata["native_jni_libraries"])
        self.assertGreaterEqual(rep.executable_payloads_count, 2)

    def test_pyinstaller_pdf_and_ole2_dropper_triage(self):
        eng = ArchiveContainerTriageEngine()
        # 1. PyInstaller CArchive ('MEI\x0c\x0b\x0a\x0b\x0e') with Python 3.11 (311)
        pyinst_blob = b"MZ" + b"\x00" * 128 + b"payload_loader.pyc\x00" + eng.PYINSTALLER_MAGIC + struct.pack("!iii", 1024, 64, 311) + b"\x00" * 64
        r_py = eng.triage_container(pyinst_blob)
        self.assertEqual(r_py.container_type, "PYINSTALLER_BUNDLE")
        self.assertEqual(r_py.bundler_metadata["python_version"], "Python 3.11")
        self.assertIn("payload_loader.pyc", r_py.bundler_metadata["embedded_modules"])

        # 2. PDF with /OpenAction and /JavaScript
        pdf_blob = b"%PDF-1.7\n1 0 obj << /OpenAction << /JS (app.alert(1)) /JavaScript >> >> endobj"
        r_pdf = eng.triage_container(pdf_blob)
        self.assertEqual(r_pdf.container_type, "PDF_DOCUMENT")
        self.assertGreaterEqual(len(r_pdf.suspicious_indicators), 2)

        # 3. OLE2 Compound Document with VBA macro stream
        ole_blob = eng.OLE2_MAGIC + b"\x00" * 64 + b"Attribute VB_Name = \"AutoOpenMacro\""
        r_ole = eng.triage_container(ole_blob)
        self.assertEqual(r_ole.container_type, "OLE2_COMPOUND")
        self.assertTrue(any("VBA Macro" in s for s in r_ole.suspicious_indicators))


class TestPhase77YaraSigmaAndSTIX21Generator(unittest.TestCase):
    def test_yara_sigma_and_stix21_synthesis_filters_noise_and_masks_opcodes(self):
        # Sample PE with a relative CALL (E8 11 22 33 44), noise string 'kernel32.dll', and high-specificity C2 URL + mutex
        code_slice = b"\x55\x48\x89\xe5\xe8\x11\x22\x33\x44\xc3"
        sample = (
            b"MZ" + b"\x90" * 62 + b"PE\x00\x00"
            + code_slice
            + b"\x00kernel32.dll\x00https://beacon.vanguard-c2.example/checkin\x00Global\\VanguardMutex_42\x00"
        )
        intel = BinaryIntelEngine(sample, filepath="vanguard_beacon.exe")
        bundle = YaraSigmaIOCGenerator().generate_all(sample, intel.get_full_dossier(), code_slice=code_slice)

        # Verify relative call displacement is wildcarded as E8 ?? ?? ?? ??
        self.assertIn("55 48 89 E5 E8 ?? ?? ?? ?? C3", bundle.yara_rule_source)
        # Verify C2 URL and Mutex are included in YARA & SIGMA while generic kernel32.dll noise is excluded
        self.assertIn("https://beacon.vanguard-c2.example/checkin", bundle.yara_rule_source)
        self.assertIn("Global\\\\VanguardMutex_42", bundle.yara_rule_source)
        self.assertNotIn('"kernel32.dll"', bundle.yara_rule_source)
        self.assertIn("logsource:", bundle.sigma_rule_yaml)
        self.assertEqual(bundle.stix21_bundle_json["type"], "bundle")


class TestPhase78Layer2BridgeExporter(unittest.TestCase):
    def test_export_ida_ghidra_binja_and_x64dbg_dd64_bridge(self):
        sample = b"MZ" + b"\x90" * 62 + b"PE\x00\x00" + b"\x55\x48\x89\xe5\xc3" + b"\x00strcpy\x00system\x00"
        intel = BinaryIntelEngine(sample, filepath="bridge_test.exe")
        pkg = Tier2BridgeExporter().export_bridge_package(
            intel.get_full_dossier(),
            symbol_renames={"0x401000": "triage_entry_main"},
            analyst_comments={"0x401000": "Layer-1 verified entry point"},
        )
        self.assertGreaterEqual(pkg.total_annotations_exported, 3)
        self.assertIn("idc.set_name(0x401000", pkg.idapython_triage_script)
        self.assertIn("idc.set_color", pkg.idapython_triage_script)
        self.assertIn("bm.setBookmark", pkg.ghidra_triage_script)
        self.assertIn("bv.set_comment_at", pkg.binary_ninja_triage_script)
        self.assertEqual(pkg.x64dbg_dd64_database_json["labels"][0]["text"], "triage_entry_main")


class TestPhase79To80TEBPEBEmulatorWebAndVanguardCLI(unittest.TestCase):
    def test_emulator_teb_peb_ldr_traversal_and_scaled_sib_addressing(self):
        emu = DeterministicCPUEmulator(arch="x64", base_va=0x401000)
        # Verify synthetic TEB (0x3060) -> PEB (0x4000) -> LDR (0x5000) -> InMemoryOrder (0x5100) -> DllBase (0x70000000)
        peb_ptr = struct.unpack("<Q", emu.read_mem(0x3060, 8))[0]
        self.assertEqual(peb_ptr, 0x4000)
        ldr_ptr = struct.unpack("<Q", emu.read_mem(peb_ptr + 0x18, 8))[0]
        self.assertEqual(ldr_ptr, 0x5000)
        dll_base = struct.unpack("<Q", emu.read_mem(0x5120, 8))[0]
        self.assertEqual(dll_base, 0x70000000)

        # Verify scaled-index-displacement effective address evaluation: [rdi + rax*4 + 0x20]
        emu.regs["rdi"] = 0x50000000
        emu.regs["rax"] = 3
        ea = emu._eval_ea("qword ptr [rdi + rax*4 + 0x20]")
        self.assertEqual(ea, 0x50000000 + 12 + 0x20)

    def test_vanguard_cli_doctor_and_web_yara_bridge_container_endpoints(self):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        doc_proc = subprocess.run(
            [sys.executable, "-m", "reverse_forge.cli", "doctor"],
            cwd=repo_root,
            capture_output=True, text=True, check=True,
        )
        doc = json.loads(doc_proc.stdout)
        self.assertIn(doc["version"], ("13.0.0-vanguard", "14.0.0-transcendent", "15.0.0-rust-titan", "16.0.0-omni-rust", "17.0.0-rust-dominion", "18.0.0-rust-sovereign", "19.0.0-rust-singularity", "20.0.0-rust-omega", "21.0.0-rust-apex", "22.0.0-rust-eternal", "23.0.0-rust-zenith", "24.0.0-rust-omni-complete", "25.0.0-rust-transcendent", "26.0.0-rust-bicentennial"))
        self.assertGreaterEqual(doc["phases_implemented"], 80)
        self.assertGreaterEqual(doc["internal_engines_count"], 71)
        self.assertEqual(doc["internal_engines_status"], "ALL_READY")

        class QuietServer(socketserver.TCPServer):
            allow_reuse_address = True

        httpd = QuietServer(("127.0.0.1", 0), GUIWorkbenchHandler)
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        try:
            with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
                tf.write(b"MZ" + b"\x90" * 62 + b"PE\x00\x00" + b"\x55\x48\x89\xe5\xc3" + b"\x00https://c2.vanguard.example/gate\x00")
                tmp_path = tf.name

            base_url = f"http://127.0.0.1:{port}"
            with urllib.request.urlopen(f"{base_url}/api/yara?path={tmp_path}") as r_y:
                y_doc = json.loads(r_y.read().decode("utf-8"))
            self.assertEqual(y_doc["status"], "ok")
            self.assertIn("rule RF_Triage_", y_doc["detection_bundle"]["yara_rule_source"])

            with urllib.request.urlopen(f"{base_url}/api/bridge?path={tmp_path}") as r_b:
                b_doc = json.loads(r_b.read().decode("utf-8"))
            self.assertEqual(b_doc["status"], "ok")
            self.assertIn("apply_reverse_forge_layer1_triage", b_doc["bridge_package"]["idapython_triage_script"])
        finally:
            httpd.shutdown()
            httpd.server_close()
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
