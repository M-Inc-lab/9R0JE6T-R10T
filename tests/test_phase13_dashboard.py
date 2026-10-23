"""
Tests for Phase 13: Interactive HTML5 & SVG Reverse-Engineering Workbench Generator.
"""

import os
import tempfile
import unittest

from reverse_forge.pipeline import AutonomyLevel, PipelineStateMachine
from reverse_forge.visual_dashboard import DashboardGenerator


class TestPhase13VisualDashboard(unittest.TestCase):
    def test_svg_call_graph_rendering(self):
        edges = [("entry", "getenv"), ("entry", "strcpy"), ("getenv", "parse_cfg")]
        svg = DashboardGenerator.render_svg_call_graph(edges)
        self.assertIn("<svg", svg)
        self.assertIn("getenv", svg)
        self.assertIn("strcpy", svg)

    def test_html_dashboard_generation_and_xss_escaping(self):
        fake_state = {
            "artifact": "<script>alert('xss')</script>.exe",
            "sha256": "deadbeef" * 8,
            "stages": [
                {"stage": 0, "name": "Input", "status": "COMPLETED", "summary": "OK <img src=x onerror=alert(1)>"}
            ],
            "report_json": {
                "executive_summary": {"overall_posture": "HIGH RISK"},
                "findings": [
                    {
                        "finding_id": "VULN-XSS",
                        "title": "Test <script>evil()</script>",
                        "vulnerability_class": "Memory",
                        "confidence": "Confirmed",
                        "cvss_score": 8.5,
                        "cwe_id": "CWE-120",
                        "function_symbol": "main -> strcpy",
                        "address_or_offset": "0x401000",
                        "what": "Unbounded copy",
                        "why": "Missing check",
                        "remediation": "Use strncpy_s",
                    }
                ],
            },
        }
        static_meta = {
            "mitigations": {"nx": True, "pie": False},
            "sections": [{"name": ".text<script>", "virtual_address": "0x1000", "raw_offset": "0x200", "raw_size": 512, "entropy": 6.1, "executable": True}],
            "imported_symbols": ["getenv", "strcpy"],
        }
        html_doc = DashboardGenerator.generate_html_dashboard(fake_state, static_metadata=static_meta)
        self.assertIn("<!DOCTYPE html>", html_doc)
        self.assertNotIn("<script>alert", html_doc)
        self.assertNotIn("<script>evil", html_doc)
        self.assertNotIn("<img src=x", html_doc)
        self.assertIn("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;.exe", html_doc)

    def test_pipeline_write_dashboard_end_to_end(self):
        if os.path.exists("/bin/ls"):
            with tempfile.TemporaryDirectory() as tmpdir:
                out_html = os.path.join(tmpdir, "ls_workbench.html")
                sm = PipelineStateMachine("/bin/ls", autonomy_level=AutonomyLevel.AUTONOMOUS, workspace_dir=tmpdir)
                sm.run_all()
                written = DashboardGenerator.write_dashboard_from_pipeline(sm, out_html)
                self.assertTrue(os.path.exists(written))
                with open(written, "r", encoding="utf-8") as f:
                    content = f.read()
                self.assertIn("R3V3R53//F0RG3 Interactive Workbench", content)
                self.assertIn("<svg", content)


if __name__ == "__main__":
    unittest.main()
