"""
Unit tests for Phases 43–45 (v7.0-singularity Core Intelligence, Stateful TUI, Live Web API & Desktop App):
  - Phase 43: BinaryIntelEngine (CAPA Capability Matcher, RIP-Relative/CALL Xrefs, 14-Format Data Inspector, Wildcard Pattern Search, Smart Query & Dossier)
  - Phase 44: Stateful REPL Session (`load`, auto `-i` injection) & Live Web Workbench `/api/analyze`, `/api/inspect`, `/api/query`, `/api/decompile`
  - Phase 45: Cross-Platform Desktop Studio (`build_desktop_workspace_model` & CLI `desktop-app --mode headless-json`)
"""

import json
import os
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.request

from reverse_forge.binary_intel_engine import BinaryIntelEngine
from reverse_forge.desktop_app import build_desktop_workspace_model
from reverse_forge.gui_server import GUIWorkbenchHandler
from reverse_forge.repl import Session
from tests.test_phase41_ab_testing import create_minimal_pe_binary


class TestPhase43BinaryIntelEngine(unittest.TestCase):
    def _build_rich_pe_sample(self) -> bytes:
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            tmp_path = tf.name
        try:
            create_minimal_pe_binary(tmp_path)
            with open(tmp_path, "rb") as f:
                base_pe = bytearray(f.read())
            # Inject x64 CALL rel32 (E8 10 00 00 00) and RIP-relative LEA (48 8D 05 09 00 00 00) at entry offset 512
            base_pe[512:517] = b"\xe8\x10\x00\x00\x00"
            base_pe[517:524] = b"\x48\x8d\x05\x09\x00\x00\x00"
            # Place ASCII string at 524 + 9 = 533
            msg = b"https://telemetry.reverse-forge.local/api\x00"
            base_pe[533:533 + len(msg)] = msg
            return bytes(base_pe)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_detect_capabilities_and_smart_query(self):
        """Verify CAPA-style capability detection and smart_query intent classification."""
        data = self._build_rich_pe_sample()
        intel = BinaryIntelEngine(data)
        caps = intel.detect_capabilities()
        self.assertGreaterEqual(len(caps), 1)
        cap_ids = {c.capability_id for c in caps}
        self.assertIn("CAP-NET-001", cap_ids)

        q_net = intel.smart_query("network")
        self.assertEqual(q_net.intent_classified, "BEHAVIORAL_CAPABILITY_QUERY")
        self.assertGreaterEqual(q_net.total_matches, 1)

        q_addr = intel.smart_query("0x1000")
        self.assertEqual(q_addr.intent_classified, "ADDRESS_DATA_INSPECTION")
        self.assertEqual(q_addr.total_matches, 1)

    def test_extract_xrefs_and_14_format_data_inspector(self):
        """Verify CALL_REL32 and RIP_RELATIVE_LEA cross-references and 14-type Data Inspector."""
        data = self._build_rich_pe_sample()
        intel = BinaryIntelEngine(data)
        xrefs = intel.extract_all_xrefs()
        xref_types = {x.xref_type for x in xrefs}
        self.assertIn("CALL_REL32", xref_types)
        self.assertIn("RIP_RELATIVE_LEA", xref_types)
        lea_xref = [x for x in xrefs if x.xref_type == "RIP_RELATIVE_LEA"][0]
        self.assertIn("https://telemetry.reverse-forge.local", lea_xref.resolved_target_preview)

        insp = intel.inspect_offset(533)
        self.assertIn("https://telemetry", insp.ascii_string)
        self.assertEqual(insp.containing_section, ".text")
        self.assertIsNotNone(insp.guid_uuid)

    def test_find_wildcard_hex_and_string_patterns(self):
        """Verify wildcard hex pattern ('E8 10 ?? 00 00') and ASCII string search."""
        data = self._build_rich_pe_sample()
        intel = BinaryIntelEngine(data)
        hex_hits = intel.find_patterns("E8 10 ?? 00 00")
        self.assertGreaterEqual(len(hex_hits), 1)
        self.assertEqual(hex_hits[0].match_type, "HEX_PATTERN")

        str_hits = intel.find_patterns("telemetry.reverse-forge")
        self.assertGreaterEqual(len(str_hits), 1)
        self.assertEqual(str_hits[0].match_type, "ASCII_STRING")


class TestPhase44LiveWebAPIAndStatefulREPL(unittest.TestCase):
    def test_gui_server_analyze_inspect_query_and_decompile_endpoints(self):
        """Verify live /api/analyze, /api/inspect, /api/query, and /api/decompile endpoints."""
        class ReusableTCPServer(socketserver.TCPServer):
            allow_reuse_address = True

        server = None
        port = 18210
        for p in range(18210, 18260):
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
            enc = urllib.parse.quote(tmp_path)

            # 1. /api/analyze
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/analyze?path={enc}") as r:
                body = json.loads(r.read().decode("utf-8"))
                self.assertEqual(body["status"], "ok")
                self.assertEqual(body["dossier"]["format"], "PE")

            # 2. /api/inspect
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/inspect?path={enc}&offset=0x200") as r:
                body = json.loads(r.read().decode("utf-8"))
                self.assertEqual(body["status"], "ok")
                self.assertIn("uint32_le", body["inspection"])

            # 3. /api/query
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/query?path={enc}&q=Hello") as r:
                body = json.loads(r.read().decode("utf-8"))
                self.assertEqual(body["status"], "ok")
                self.assertGreaterEqual(body["answer"]["total_matches"], 1)

            # 4. /api/decompile (regression test for previous AttributeError crash)
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/decompile?path={enc}") as r:
                body = json.loads(r.read().decode("utf-8"))
                self.assertEqual(body["status"], "ok")
                self.assertIn("c_source", body)
                self.assertGreaterEqual(body["blocks_count"], 1)
        finally:
            server.shutdown()
            server.server_close()
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_stateful_repl_session_load_binary(self):
        """Verify REPL Session loads target binary and populates BinaryIntelEngine context."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            tmp_path = tf.name
        try:
            create_minimal_pe_binary(tmp_path)
            sess = Session()
            ok = sess.load_binary(tmp_path)
            self.assertTrue(ok)
            self.assertEqual(sess.target_path, os.path.abspath(tmp_path))
            self.assertEqual(sess.target_intel.format_name, "PE")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


class TestPhase45DesktopAppAndCLISubcommands(unittest.TestCase):
    def test_desktop_workspace_model_and_new_cli_commands(self):
        """Verify DesktopWorkspaceModel builder and CLI dossier/capabilities/inspect/ask/desktop-app."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            tmp_path = tf.name
        try:
            create_minimal_pe_binary(tmp_path)
            model = build_desktop_workspace_model(tmp_path)
            self.assertEqual(model.format_name, "PE")
            self.assertEqual(len(model.sections), 2)
            self.assertTrue(len(model.hex_lines) > 0)

            for subcmd, extra in [
                ("dossier", []),
                ("capabilities", []),
                ("xrefs", []),
                ("inspect", ["--offset", "0x200"]),
                ("ask", ["--query", "Hello"]),
                ("desktop-app", ["--mode", "headless-json"]),
            ]:
                proc = subprocess.run(
                    [sys.executable, "-m", "reverse_forge.cli", subcmd, "-i", tmp_path] + extra,
                    capture_output=True, text=True, check=True,
                )
                out_json = json.loads(proc.stdout)
                self.assertIsInstance(out_json, dict)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
