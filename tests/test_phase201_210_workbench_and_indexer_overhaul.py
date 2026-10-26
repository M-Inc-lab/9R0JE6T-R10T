import json
import os
import socketserver
import threading
import urllib.request
import unittest

from reverse_forge.gui_server import GUIWorkbenchHandler, HTML_TEMPLATE
from reverse_forge.whole_binary_function_indexer import WholeBinaryFunctionIndexer


class TestPhase201To210WorkbenchAndIndexerOverhaul(unittest.TestCase):
    def test_gui_template_has_zero_window_prompts_and_4pane_split_ide(self):
        self.assertNotIn("prompt(", HTML_TEMPLATE)
        self.assertNotIn("alert(", HTML_TEMPLATE)
        self.assertIn("left-center-pane", HTML_TEMPLATE)
        self.assertIn("right-center-pane", HTML_TEMPLATE)
        self.assertIn("bottom-dock", HTML_TEMPLATE)
        self.assertIn("irtab-pcode", HTML_TEMPLATE)
        self.assertIn("irtab-esil", HTML_TEMPLATE)
        self.assertIn("irtab-vex", HTML_TEMPLATE)
        self.assertIn("selectAndDecompileFunction", HTML_TEMPLATE)

    def test_whole_binary_function_indexer_and_api_function_endpoint(self):
        target_bin = "/bin/ls" if os.path.exists("/bin/ls") else None
        if target_bin:
            with open(target_bin, "rb") as f:
                data = f.read()
            idx = WholeBinaryFunctionIndexer(data)
            funcs = idx.discover_all_functions()
            self.assertGreater(len(funcs), 50)
            self.assertEqual(funcs[0].name, "main")
            bundle = idx.analyze_function()
            self.assertEqual(bundle.name, "main")
            self.assertIn("setlocale", bundle.decompiled_c)
            self.assertIn("bindtextdomain", bundle.decompiled_c)
            self.assertIn("coreutils", bundle.decompiled_c)

        class QuietServer(socketserver.TCPServer):
            allow_reuse_address = True

        httpd = QuietServer(("127.0.0.1", 0), GUIWorkbenchHandler)
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        try:
            base_url = f"http://127.0.0.1:{port}"
            with urllib.request.urlopen(f"{base_url}/api/native-rust?cmd=omni-audit") as r_nr:
                nr_doc = json.loads(r_nr.read().decode("utf-8"))
            self.assertEqual(nr_doc["status"], "ok")
            self.assertEqual(nr_doc["command"], "omni-audit")

            if target_bin:
                with urllib.request.urlopen(f"{base_url}/api/function?path={target_bin}&addr=0x4730") as r_fn:
                    fn_doc = json.loads(r_fn.read().decode("utf-8"))
                self.assertEqual(fn_doc["status"], "ok")
                self.assertIn("decompiled_c", fn_doc["function"])
                self.assertIn("pcode_ssa_text", fn_doc["function"])
                self.assertIn("rizin_esil_text", fn_doc["function"])
                self.assertIn("angr_vex_text", fn_doc["function"])
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
