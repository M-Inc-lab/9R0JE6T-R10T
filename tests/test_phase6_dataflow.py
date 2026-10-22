"""
Tests for Phase 6: Call-Graph, Data-Flow Reachability & Memory Taint Analysis.
"""

import unittest

from reverse_forge.dataflow_engine import DataFlowGraph, TaintPath


class TestPhase6DataFlowEngine(unittest.TestCase):
    def setUp(self):
        self.dfg = DataFlowGraph()

    def test_direct_caller_cooccurrence_taint(self):
        # Function 'handle_client' calls both 'recv' (source) and 'strcpy' (sink)
        self.dfg.add_edge("handle_client", "recv")
        self.dfg.add_edge("handle_client", "strcpy")

        flows = self.dfg.analyze_source_to_sink_flows()
        self.assertGreaterEqual(len(flows), 1)
        strcpy_flows = [f for f in flows if f.sink_name == "strcpy"]
        self.assertEqual(len(strcpy_flows), 1)
        self.assertEqual(strcpy_flows[0].cwe, "CWE-120")
        self.assertEqual(strcpy_flows[0].path_confidence, "PROBABLE")

    def test_multi_hop_path_discovery(self):
        # A -> B -> C -> system
        self.dfg.add_edge("read_input", "recv")
        self.dfg.add_edge("recv", "process_buffer")
        self.dfg.add_edge("process_buffer", "dispatch_command")
        self.dfg.add_edge("dispatch_command", "system")

        paths = self.dfg.find_all_paths("recv", "system")
        self.assertGreaterEqual(len(paths), 1)
        self.assertEqual(paths[0], ["recv", "process_buffer", "dispatch_command", "system"])

        flows = self.dfg.analyze_source_to_sink_flows()
        sys_flows = [f for f in flows if f.sink_name == "system" and f.path_confidence == "CONFIRMED"]
        self.assertEqual(len(sys_flows), 1)
        self.assertEqual(sys_flows[0].cwe, "CWE-78")

    def test_cycle_prevention(self):
        # Cyclic graph: A -> B -> C -> A
        self.dfg.add_edge("fn_A", "fn_B")
        self.dfg.add_edge("fn_B", "fn_C")
        self.dfg.add_edge("fn_C", "fn_A")

        paths = self.dfg.find_all_paths("fn_A", "target_not_exist")
        self.assertEqual(paths, [])


if __name__ == "__main__":
    unittest.main()
