"""
Unit & Integration Test Suite for Intent-Driven Reverse Engineering Platform
(`test_intent_investigation_platform.py`)
"""

import ctypes
import json
import os
import tempfile
import time
import unittest
from typing import Any, Dict

from reverse_forge.capability_registry import (
    CapabilityRegistry,
    IntegrationStrategy,
    LicenseType,
    ToolCategory,
    capability_registry,
)
from reverse_forge.intent_engine import (
    IntentCompiler,
    InvestigationObjectiveType,
    InvestigationSpecification,
    intent_compiler,
)
from reverse_forge.investigation_workflow import (
    HypothesisStatus,
    InvestigationState,
    InvestigationWorkflowEngine,
    investigation_engine,
)


class TestCapabilityRegistry(unittest.TestCase):
    """Test suite for Open-Source Capability Registry and Provenance Tracker."""

    def setUp(self) -> None:
        self.registry = CapabilityRegistry()

    def test_registry_seeding(self) -> None:
        tools = self.registry.get_all_capabilities()
        self.assertGreaterEqual(len(tools), 10)
        tool_ids = [t.tool_id for t in tools]
        self.assertIn("rust_zero_copy_parser", tool_ids)
        self.assertIn("ghidra_pcode_ssa", tool_ids)
        self.assertIn("underconstrained_visor", tool_ids)
        self.assertIn("datalog_vsa_taint", tool_ids)
        self.assertIn("yara_sigma_synthesizer", tool_ids)

    def test_filter_by_category(self) -> None:
        decomp_tools = self.registry.get_by_category(ToolCategory.DECOMPILATION)
        self.assertGreaterEqual(len(decomp_tools), 1)
        self.assertEqual(decomp_tools[0].category, ToolCategory.DECOMPILATION)

        sandbox_tools = self.registry.get_by_category(ToolCategory.EMULATION_SANDBOX)
        self.assertTrue(any(t.tool_id == "underconstrained_visor" for t in sandbox_tools))

    def test_target_matching(self) -> None:
        # Match ELF x86_64
        elf_tools = self.registry.find_matching_tools("ELF", "x86_64")
        self.assertGreater(len(elf_tools), 5)

        # Match PE x86
        pe_tools = self.registry.find_matching_tools("PE", "x86")
        self.assertGreater(len(pe_tools), 5)

    def test_export_catalog_provenance(self) -> None:
        catalog = self.registry.export_catalog()
        self.assertIsInstance(catalog, dict)
        tools = catalog.get("tools", [])
        self.assertIsInstance(tools, list)
        self.assertGreater(len(tools), 5)
        for item in tools:
            self.assertIn("tool_id", item)
            self.assertIn("name", item)
            self.assertIn("repository_url", item)
            self.assertIn("pinned_commit", item)
            self.assertIn("license", item)
            self.assertIn("strategy", item)
            self.assertIn("security_review_status", item)


class TestIntentCompiler(unittest.TestCase):
    """Test suite for Natural Language Intent Understanding and Objective Compilation."""

    def setUp(self) -> None:
        self.compiler = IntentCompiler()
        self.target = "/bin/ls" if os.path.exists("/bin/ls") else __file__

    def test_intent_classification_vulnerability(self) -> None:
        spec = self.compiler.compile(
            "Investigate possible heap buffer overflow vulnerability in user input parsing",
            self.target,
        )
        self.assertEqual(spec.objective_type, InvestigationObjectiveType.VULNERABILITY_RESEARCH)
        self.assertIn("rust_zero_copy_parser", spec.candidate_tools)
        self.assertIn("datalog_vsa_taint", spec.candidate_tools)
        self.assertFalse(spec.requires_dynamic_execution)

    def test_intent_classification_config_extraction(self) -> None:
        spec = self.compiler.compile(
            "Extract embedded configuration, c2 server domain and encryption keys",
            self.target,
        )
        self.assertEqual(spec.objective_type, InvestigationObjectiveType.CONFIG_EXTRACTION)
        self.assertFalse(spec.requires_dynamic_execution)

    def test_intent_classification_crash_root_cause(self) -> None:
        spec = self.compiler.compile(
            "Determine the root cause of sigsegv crash and faulting memory dereference",
            self.target,
        )
        self.assertEqual(spec.objective_type, InvestigationObjectiveType.CRASH_ROOT_CAUSE)
        self.assertTrue(spec.requires_dynamic_execution)
        self.assertTrue(spec.requires_hil_approval)

    def test_intent_classification_suspicious_behavior(self) -> None:
        spec = self.compiler.compile(
            "Analyze suspicious malware behavior, anti-debug evasion, and persistence",
            self.target,
        )
        self.assertEqual(spec.objective_type, InvestigationObjectiveType.SUSPICIOUS_BEHAVIOR)
        self.assertTrue(spec.requires_dynamic_execution)
        self.assertTrue(spec.requires_hil_approval)

    def test_intent_classification_data_flow(self) -> None:
        spec = self.compiler.compile(
            "Trace data flow from network packet input to sensitive file write sink",
            self.target,
        )
        self.assertEqual(spec.objective_type, InvestigationObjectiveType.DATA_FLOW_TRACING)

    def test_specification_serialization(self) -> None:
        spec = self.compiler.compile("Map all functions and architecture layout", self.target)
        d = spec.to_dict()
        self.assertEqual(d["objective_type"], "ARCHITECTURE_MAPPING")
        self.assertIsInstance(d["candidate_tools"], list)
        self.assertIsInstance(d["questions_to_answer"], list)


class TestInvestigationWorkflowEngine(unittest.TestCase):
    """Test suite for 9-Stage Adaptive Investigation Lifecycle and HIL Gating."""

    def setUp(self) -> None:
        self.engine = InvestigationWorkflowEngine()
        self.target = "/bin/ls" if os.path.exists("/bin/ls") else __file__

    def test_static_lifecycle_to_completion(self) -> None:
        state = self.engine.create_investigation(
            "Verify input validation checks and bounds sanitization",
            self.target,
        )
        self.assertEqual(state.status, "INITIALIZED")
        self.assertEqual(state.current_stage_idx, 1)

        # Run to completion
        final_state = self.engine.run_to_completion_or_hil(state.investigation_id, max_steps=12)
        self.assertEqual(final_state.status, "COMPLETED")
        self.assertGreater(len(final_state.evidence), 3)
        self.assertGreater(len(final_state.hypotheses), 0)
        self.assertIn("yara_rule", final_state.deliverables)
        self.assertIn("sigma_yaml", final_state.deliverables)

    def test_hil_safety_gate_blocking_and_approval(self) -> None:
        # Crash root cause requires dynamic execution -> triggers HIL gate
        state = self.engine.create_investigation(
            "Find root cause of crash and memory fault",
            self.target,
        )
        self.assertTrue(state.spec.requires_dynamic_execution)
        self.assertTrue(state.spec.requires_hil_approval)

        # Run until paused
        paused_state = self.engine.run_to_completion_or_hil(state.investigation_id, max_steps=8)
        self.assertEqual(paused_state.status, "BLOCKED_HIL")
        self.assertIsNotNone(paused_state.hil_pending_request)
        self.assertEqual(paused_state.current_stage_idx, 5)

        # Operator grants approval
        resumed_state = self.engine.submit_hil_decision(
            state.investigation_id,
            action="dynamic_execution",
            decision="APPROVE_SANDBOXED",
            operator="lead_architect",
        )
        self.assertEqual(resumed_state.status, "RUNNING")
        self.assertEqual(resumed_state.current_stage_idx, 6)

        # Continue execution to completion
        final_state = self.engine.run_to_completion_or_hil(state.investigation_id, max_steps=8)
        self.assertEqual(final_state.status, "COMPLETED")
        self.assertIn("underconstrained_visor", [e.source_tool_id for e in final_state.evidence.values()])

    def test_hil_safety_gate_rejection_static_pivot(self) -> None:
        state = self.engine.create_investigation(
            "Analyze suspicious stealth evasion in binary",
            self.target,
        )
        paused_state = self.engine.run_to_completion_or_hil(state.investigation_id, max_steps=8)
        self.assertEqual(paused_state.status, "BLOCKED_HIL")

        # Operator rejects dynamic execution -> pivots to static only
        pivoted_state = self.engine.submit_hil_decision(
            state.investigation_id,
            action="dynamic_execution",
            decision="REJECT_STATIC_ONLY",
            operator="security_analyst",
        )
        self.assertEqual(pivoted_state.current_stage_idx, 7) # Slices to stage 7 directly

        final_state = self.engine.run_to_completion_or_hil(state.investigation_id, max_steps=8)
        self.assertEqual(final_state.status, "COMPLETED")
        # Ensure underconstrained_visor was NEVER executed
        self.assertNotIn("underconstrained_visor", [e.source_tool_id for e in final_state.evidence.values()])


class TestRustNativeIntentEngineFFI(unittest.TestCase):
    """Test C-ABI FFI integration with the compiled Rust shared library."""

    def setUp(self) -> None:
        lib_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "rust_core",
            "target",
            "release",
            "libreverse_forge_core.so",
        )
        self.lib_path = lib_path
        self.has_lib = os.path.exists(lib_path)

    def test_rust_intent_classifier_ffi(self) -> None:
        if not self.has_lib:
            self.skipTest(f"Compiled Rust shared library not found: {self.lib_path}")

        lib = ctypes.CDLL(self.lib_path)
        lib.rf_rust_intent_classify.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        lib.rf_rust_intent_classify.restype = ctypes.c_size_t

        intent = b"Find buffer overflow vulnerability in memory processing"
        out_buf = ctypes.create_string_buffer(512)
        ret_len = lib.rf_rust_intent_classify(intent, len(intent), out_buf, 512)

        self.assertGreater(ret_len, 0)
        res_json = json.loads(out_buf.value.decode("utf-8"))
        self.assertEqual(res_json["objective"], "VULNERABILITY_RESEARCH")
        self.assertGreater(res_json["confidence"], 0.6)


class TestIntentRESTApiEndpoints(unittest.TestCase):
    """Test suite for GUI Server REST API endpoints."""

    @classmethod
    def setUpClass(cls) -> None:
        import threading
        from reverse_forge.gui_server import GUIWorkbenchHandler, ThreadedServer
        cls.server = ThreadedServer(("127.0.0.1", 0), GUIWorkbenchHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def test_get_capabilities_api(self) -> None:
        import urllib.request
        req = urllib.request.Request(f"{self.base_url}/api/capabilities")
        req.add_header("Origin", "http://127.0.0.1")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "ok")
            self.assertGreaterEqual(data["total_capabilities"], 10)

    def test_post_investigate_compile_api(self) -> None:
        import urllib.request
        req = urllib.request.Request(
            f"{self.base_url}/api/investigate/compile",
            data=json.dumps({
                "intent": "Find buffer overflow in stack memory",
                "path": "/bin/ls"
            }).encode("utf-8"),
            headers={"Content-Type": "application/json", "Origin": "http://127.0.0.1"}
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "ok")
            self.assertEqual(data["spec"]["objective_type"], "VULNERABILITY_RESEARCH")

    def test_post_investigate_start_and_status_api(self) -> None:
        import urllib.request
        req = urllib.request.Request(
            f"{self.base_url}/api/investigate/start",
            data=json.dumps({
                "intent": "Map important functions and architecture layout",
                "path": "/bin/ls"
            }).encode("utf-8"),
            headers={"Content-Type": "application/json", "Origin": "http://127.0.0.1"}
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "ok")
            inv_id = data["investigation_id"]

        # Check status
        st_req = urllib.request.Request(f"{self.base_url}/api/investigate/status?id={inv_id}")
        st_req.add_header("Origin", "http://127.0.0.1")
        with urllib.request.urlopen(st_req) as resp:
            self.assertEqual(resp.status, 200)
            st_data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(st_data["status"], "ok")
            self.assertEqual(st_data["state"]["investigation_id"], inv_id)


if __name__ == "__main__":
    unittest.main()
