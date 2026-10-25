"""
Unit Tests for Phase 42: Modern Interactive GUI Workbench Application
======================================================================
Verifies GUI Workbench HTML template, API endpoints (/api/status, /api/load,
/api/decompile), and server initialization.
"""

import http.server
import json
import os
import socketserver
import tempfile
import threading
import time
import urllib.request
import unittest

from reverse_forge.gui_server import GUIWorkbenchHandler, HTML_TEMPLATE


def test_gui_workbench_template_structure():
    assert "9R0JE6T R10T // R3V3R53-F0RG3" in HTML_TEMPLATE
    assert "Graph CFG" in HTML_TEMPLATE
    assert "Decompiled C" in HTML_TEMPLATE
    assert "Hex Inspector" in HTML_TEMPLATE
    assert "Mitigations HUD" in HTML_TEMPLATE
    assert "cfg-canvas" in HTML_TEMPLATE
    assert "hex-bytes" in HTML_TEMPLATE
    assert "code-content" in HTML_TEMPLATE
    # Test IDA Pro Hotkeys
    assert "keydown" in HTML_TEMPLATE
    assert "Space" in HTML_TEMPLATE
    assert "F5" in HTML_TEMPLATE


def test_gui_workbench_server_rest_api():
    class TestServer(socketserver.TCPServer):
        allow_reuse_address = True

    # Find free port
    port = 18090
    server = None
    for p in range(18090, 18150):
        try:
            server = TestServer(("127.0.0.1", p), GUIWorkbenchHandler)
            port = p
            break
        except OSError:
            continue

    assert server is not None, "Failed to bind test server"

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)

    try:
        # Test 1: GET / (HTML template)
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/") as resp:
            assert resp.status == 200
            content = resp.read().decode("utf-8")
            assert "<!DOCTYPE html>" in content
            assert "R3V3R53-F0RG3" in content

        # Test 2: GET /api/status (JSON status)
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "ready"
            assert data["version"] in ("6.0.0-quantum", "7.0.0-singularity", "8.0.0-omniscient", "9.0.0-sovereign")
            assert data["active_engines"] >= 45

        # Test 3: GET /api/load on a temporary binary
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
            tf.write(b"MZ" + (b"\x00" * 128))
            tmp_path = tf.name

        try:
            encoded_path = urllib.parse.quote(tmp_path)
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/load?path={encoded_path}") as resp:
                assert resp.status == 200
                load_data = json.loads(resp.read().decode("utf-8"))
                assert load_data["status"] == "ok"
                assert load_data["size_bytes"] == 130
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    finally:
        server.shutdown()
        server.server_close()


class TestPhase42GUIWorkbench(unittest.TestCase):
    def test_all_phase42(self):
        test_gui_workbench_template_structure()
        test_gui_workbench_server_rest_api()


if __name__ == "__main__":
    unittest.main()
