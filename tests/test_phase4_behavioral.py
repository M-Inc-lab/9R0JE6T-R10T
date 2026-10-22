"""
Tests for Phase 4: Sandboxed Behavioral Telemetry & Static-to-Dynamic Correlation.
"""

import json
import os
import tempfile
import unittest

from reverse_forge.behavioral_engine import (
    BehavioralTelemetryEngine,
    CrashEvent,
    FileEvent,
    NetworkEvent,
    ProcessEvent,
    RegistryEvent,
)
from reverse_forge.windows_sandbox import WindowsSandbox


class TestPhase4BehavioralTelemetry(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.b_engine = BehavioralTelemetryEngine()

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_record_and_correlate_runtime_events(self):
        # 1. Add Network Event
        self.b_engine.record_network_event(NetworkEvent(
            timestamp="2026-10-23T00:00:00Z",
            source_ip="192.168.1.10",
            source_port=54321,
            destination_ip="198.51.100.23",
            destination_port=4444,
            protocol="TCP",
            data_summary="Encrypted beaconing"
        ))

        # 2. Add Registry Persistence Event
        self.b_engine.record_registry_event(RegistryEvent(
            timestamp="2026-10-23T00:00:01Z",
            key_path=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            value_name="UpdaterSvc",
            operation="SET_VALUE",
            process_name="sample.exe"
        ))

        # 3. Add Crash Event
        self.b_engine.record_crash_event(CrashEvent(
            timestamp="2026-10-23T00:00:02Z",
            process_name="sample.exe",
            fault_address="0x00401122",
            exception_code="0xC0000005"
        ))

        static_context = {
            "strings": {
                "ips": ["198.51.100.23"],
                "urls": ["http://198.51.100.23/c2"]
            }
        }

        matches = self.b_engine.correlate_with_static_analysis(static_context)
        self.assertGreaterEqual(len(matches), 3)

        summary = self.b_engine.generate_behavioral_summary()
        self.assertTrue(summary["suspicious_indicators"]["persistence_attempted"])
        self.assertTrue(summary["suspicious_indicators"]["c2_network_traffic"])
        self.assertTrue(summary["suspicious_indicators"]["access_violation_crashes"])

    def test_ingest_json_trace(self):
        trace_data = {
            "processes": [
                {
                    "timestamp": "2026-10-23T00:00:00Z",
                    "pid": 1234,
                    "parent_pid": 1000,
                    "image_path": r"C:\Analysis\target.exe",
                    "command_line": "target.exe --run",
                    "action": "SPAWNED"
                }
            ],
            "files": [],
            "registry": [],
            "network": [],
            "crashes": []
        }
        trace_path = os.path.join(self.tmp_dir.name, "trace.json")
        with open(trace_path, "w", encoding="utf-8") as f:
            json.dump(trace_data, f)

        counts = self.b_engine.ingest_json_trace(trace_path)
        self.assertEqual(counts["processes"], 1)
        self.assertEqual(len(self.b_engine.process_events), 1)

    def test_sandbox_telemetry_collector_script_generation(self):
        ps1_path = os.path.join(self.tmp_dir.name, "collector.ps1")
        res_path = WindowsSandbox.generate_telemetry_collector_script(ps1_path, "target.exe", duration_sec=5)
        self.assertTrue(os.path.exists(res_path))
        with open(res_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("target.exe", content)
        self.assertIn("ConvertTo-Json", content)


if __name__ == "__main__":
    unittest.main()
