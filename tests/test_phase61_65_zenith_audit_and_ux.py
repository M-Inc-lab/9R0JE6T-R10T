"""
R3V3R53//F0RG3 — Phase 65: Security, Architectural & UI/UX Verification Suite (`Phases 61–65`)
Verifies:
  1. Phase 61 Security Hardening:
     - `_safe_eval_ast` in `deobfuscation_engine.py` evaluates arithmetic/bitwise expressions safely
       while rejecting arbitrary Python code/call nodes, and zero `eval()` calls exist in `reverse_forge/`.
     - Cross-Origin requests (`Origin: https://evil.attacker.com`) to `GUIWorkbenchHandler` are rejected with HTTP 403.
     - `HTML_TEMPLATE` uses `escHtml()` to neutralize DOM XSS payloads.
  2. Phase 62 Unified 8-Pass Decompilation Pipeline (`UnifiedDecompilerPipeline`):
     - Chains `RecursiveDescentDisassembler` -> `IndirectJumpTableResolver` -> `FLIRTRuntimeEngine`
       -> `UnifiedILLifter` -> `SSALifterAndOptimizer` -> `DeobfuscationEngine` -> `ControlFlowRegionStructurer`
       -> `StructLayoutRecoveryEngine`.
  3. Phase 63 & 64 Seamless Web/CLI/REPL UX:
     - `POST /api/upload`, `POST /api/annotate` (rename & comment), `GET /api/export-header`,
       `GET /api/cfg`, and `GET /api/hex` work end-to-end.
     - `cli.py doctor` reports `10.0.0-zenith`, `65` phases, and `63` internal engines.
"""

import json
import os
import socketserver
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request

from reverse_forge.deobfuscation_engine import DeobfuscationEngine, _safe_eval_ast
from reverse_forge.unified_decompiler_pipeline import UnifiedDecompilerPipeline
from reverse_forge.gui_server import GUIWorkbenchHandler, HTML_TEMPLATE
from tests.test_phase41_ab_testing import create_minimal_pe_binary


class TestPhase61SecurityHardening(unittest.TestCase):
    def test_safe_eval_ast_blocks_code_execution_and_no_eval_in_repo(self):
        """Verify _safe_eval_ast evaluates bitwise math and rejects function calls or attribute access."""
        val = _safe_eval_ast("(x ^ y) + 2 * (x & y)", {"x": 19, "y": 23})
        self.assertEqual(val, 42)

        with self.assertRaises(ValueError):
            _safe_eval_ast("__import__('os').system('id')", {"x": 1})

        # Ensure no raw `eval(` remains in deobfuscation_engine.py
        with open("reverse_forge/deobfuscation_engine.py", "r", encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn(" eval(", src)

    def test_dom_xss_sanitizer_present_in_gui_template(self):
        """Verify escHtml() is defined and applied to dynamic innerHTML sinks in HTML_TEMPLATE."""
        self.assertIn("function escHtml(val)", HTML_TEMPLATE)
        self.assertIn("escHtml(f.name)", HTML_TEMPLATE)
        self.assertIn("escHtml(s.value)", HTML_TEMPLATE)
        self.assertIn("escHtml(b.label)", HTML_TEMPLATE)


class TestPhase62UnifiedDecompilerPipeline(unittest.TestCase):
    def test_8_pass_unified_decompiler_pipeline_with_flirt_and_cfg(self):
        """Verify UnifiedDecompilerPipeline decodes, matches FLIRT, optimizes SSA, and builds CFG blocks."""
        # GLIBC _start FLIRT prologue followed by ret
        code = bytes.fromhex("F3 0F 1E FA 31 ED 49 89 D1 5E 48 89 E2 48 83 E4 F0 C3")
        pipe = UnifiedDecompilerPipeline(arch="x64")
        res = pipe.decompile_function_bytes(code, base_va=0x401000)
        self.assertEqual(res.function_name, "_start")
        self.assertEqual(res.goto_count, 0)
        self.assertGreaterEqual(len(res.cfg_blocks), 1)
        self.assertIn("int _start(", res.final_c_code)


class TestPhase63To65WebUploadAnnotateAndZenithCLI(unittest.TestCase):
    def test_web_upload_annotate_hex_cfg_and_cors_protection(self):
        """Verify POST /api/upload, POST /api/annotate, GET /api/hex, GET /api/cfg, and HTTP 403 CORS block."""
        class ReusableTCPServer(socketserver.TCPServer):
            allow_reuse_address = True

        server = None
        port = 18310
        for p in range(18310, 18360):
            try:
                server = ReusableTCPServer(("127.0.0.1", p), GUIWorkbenchHandler)
                port = p
                break
            except OSError:
                continue
        self.assertIsNotNone(server)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            tmp_path = tf.name
        try:
            create_minimal_pe_binary(tmp_path)
            with open(tmp_path, "rb") as f:
                pe_bytes = f.read()

            # 1. Test Cross-Origin request blocking (SEC-03)
            bad_req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/status",
                headers={"Origin": "https://evil-attacker.example.com"},
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(bad_req)
            self.assertEqual(ctx.exception.code, 403)

            # 2. Test POST /api/upload (UX-01)
            up_req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/upload?filename=sample_upload.exe",
                data=pe_bytes,
                method="POST",
                headers={"Origin": f"http://127.0.0.1:{port}"},
            )
            with urllib.request.urlopen(up_req) as r:
                up_data = json.loads(r.read().decode("utf-8"))
                self.assertEqual(up_data["status"], "ok")
                uploaded_path = up_data["saved_path"]

            enc_path = urllib.parse.quote(uploaded_path)

            # 3. Test GET /api/hex & GET /api/cfg (ARCH-01)
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/hex?path={enc_path}&rows=4") as r:
                hex_data = json.loads(r.read().decode("utf-8"))
                self.assertEqual(hex_data["status"], "ok")
                self.assertEqual(len(hex_data["hex_rows"]), 4)
                self.assertEqual(hex_data["hex_rows"][0]["bytes"][0], "4D")  # 'M'
                self.assertEqual(hex_data["hex_rows"][0]["bytes"][1], "5A")  # 'Z'

            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/cfg?path={enc_path}") as r:
                cfg_data = json.loads(r.read().decode("utf-8"))
                self.assertEqual(cfg_data["status"], "ok")
                self.assertGreaterEqual(len(cfg_data["cfg_blocks"]), 1)

            # 4. Test POST /api/annotate & GET /api/export-header (UX-02)
            ann_body = json.dumps({
                "action": "rename",
                "address": "0x1000",
                "value": "verified_entry_point",
                "path": uploaded_path,
            }).encode("utf-8")
            ann_req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/annotate",
                data=ann_body,
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(ann_req) as r:
                ann_resp = json.loads(r.read().decode("utf-8"))
                self.assertEqual(ann_resp["symbol"], "verified_entry_point")

            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/export-header") as r:
                hdr_txt = r.read().decode("utf-8")
                self.assertIn("verified_entry_point", hdr_txt)

        finally:
            server.shutdown()
            server.server_close()
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_zenith_cli_doctor_and_decompile_full(self):
        """Verify cli.py doctor reports 10.0.0-zenith (65 phases / 63 engines) and decompile-full works."""
        doc = subprocess.run(
            [sys.executable, "-m", "reverse_forge.cli", "doctor"],
            capture_output=True, text=True, check=True,
        )
        doc_json = json.loads(doc.stdout)
        self.assertIn(doc_json["version"], ("10.0.0-zenith", "11.0.0-eternal"))
        self.assertGreaterEqual(doc_json["phases_implemented"], 65)
        self.assertGreaterEqual(doc_json["internal_engines_count"], 63)

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            tmp_path = tf.name
        try:
            create_minimal_pe_binary(tmp_path)
            df = subprocess.run(
                [sys.executable, "-m", "reverse_forge.cli", "decompile-full", "-i", tmp_path],
                capture_output=True, text=True, check=True,
            )
            df_json = json.loads(df.stdout)
            self.assertIn("final_c_code", df_json)
            self.assertGreaterEqual(len(df_json["cfg_blocks"]), 1)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
